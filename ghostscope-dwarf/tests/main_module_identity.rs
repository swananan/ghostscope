use ghostscope_dwarf::{DwarfAnalyzer, ModuleDefaultPolicy, ModuleLoadingEvent};
use object::Object;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

struct Target(std::process::Child);

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn compile_target(directory: &Path, name: &str, shared: bool) -> std::path::PathBuf {
    let source = directory.join("target.c");
    std::fs::write(
        &source,
        "#include <unistd.h>\nint value = 7;\nint main(void) { write(STDOUT_FILENO, \"ready\\n\", 6); for (;;) pause(); }\n",
    )
    .unwrap();
    let binary = directory.join(name);
    let mut compiler = Command::new("cc");
    compiler.args(["-g", "-O0"]);
    if shared {
        compiler.args(["-shared", "-fPIC"]);
    } else {
        compiler.arg("-no-pie");
    }
    let output = compiler
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    binary
}

fn start_target(binary: &Path) -> Target {
    let mut target = Target(
        Command::new(binary)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut ready = String::new();
    BufReader::new(target.0.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert_eq!(
        ready, "ready\n",
        "target should finish startup before discovery"
    );
    target
}

fn assert_default_module(analyzer: &DwarfAnalyzer, binary: &Path) {
    assert_eq!(
        Path::new(&analyzer.get_main_executable().unwrap().path),
        binary
    );
    assert_eq!(
        analyzer
            .resolve_address_module(None, None, ModuleDefaultPolicy::MainExecutableOnly)
            .unwrap(),
        binary
    );
    assert!(analyzer.get_executable_file_info().is_some());
    assert!(analyzer
        .get_shared_library_info()
        .iter()
        .all(|module| Path::new(&module.library_path) != binary));
}

#[tokio::test]
async fn explicit_target_identity_does_not_depend_on_filename() {
    let directory = tempfile::tempdir().unwrap();
    for (name, shared) in [("worker.software", false), ("plugin.so", true)] {
        let binary = compile_target(directory.path(), name, shared);
        let analyzer = DwarfAnalyzer::from_exec_path(&binary).await.unwrap();
        assert_default_module(&analyzer, &binary);
    }
}

#[tokio::test]
async fn pid_default_module_comes_from_the_process_executable() {
    let directory = tempfile::tempdir().unwrap();
    let binary = compile_target(directory.path(), "worker.software", false);
    let target = start_target(&binary);
    let analyzer = DwarfAnalyzer::from_pid(target.0.id()).await.unwrap();
    assert_default_module(&analyzer, &binary);
    assert_eq!(analyzer.get_module_stats().executable_modules, 1);
    let bytes = std::fs::read(&binary).unwrap();
    let elf = object::File::parse(bytes.as_slice()).unwrap();
    assert_eq!(
        analyzer.get_executable_file_info().unwrap().entry_point,
        Some(elf.entry()),
        "a non-PIE executable has zero load bias, despite its nonzero mapping base"
    );
}

#[tokio::test]
async fn pid_default_module_recovers_after_its_path_is_restored() {
    for remove_before_load in [true, false] {
        let directory = tempfile::tempdir().unwrap();
        let binary = compile_target(directory.path(), "worker.software", false);
        let backup = directory.path().join("backup");
        std::fs::hard_link(&binary, &backup).unwrap();
        let target = start_target(&binary);

        // Remove the path either before discovery or just after loading its ELF.
        // Both leave main identity unresolved, but only the first needs a new module.
        if remove_before_load {
            std::fs::remove_file(&binary).unwrap();
        }
        let callback_binary = binary.clone();
        let mut analyzer =
            DwarfAnalyzer::from_pid_parallel_with_progress(target.0.id(), move |event| {
                if let ModuleLoadingEvent::LoadingCompleted { module_path, .. } = event {
                    if !remove_before_load && Path::new(&module_path) == callback_binary {
                        std::fs::remove_file(&callback_binary).unwrap();
                    }
                }
            })
            .await
            .unwrap();
        assert!(analyzer.get_main_executable().is_none());
        assert_eq!(
            analyzer.module_paths().contains(&binary),
            !remove_before_load
        );

        // Restore the same inode while the original process continues running.
        std::fs::hard_link(&backup, &binary).unwrap();
        assert!(DwarfAnalyzer::module_paths_equivalent(
            &binary,
            format!("/proc/{}/exe", target.0.id())
        ));
        let runtime_modules = DwarfAnalyzer::discover_pid_runtime_modules(target.0.id()).unwrap();
        let loaded = analyzer
            .refresh_pid_runtime_modules_with_config_and_debuginfod(
                runtime_modules,
                &[],
                false,
                None,
                |_| {},
            )
            .await
            .unwrap();
        assert_eq!(loaded, usize::from(remove_before_load));
        assert_default_module(&analyzer, &binary);
        assert_eq!(analyzer.get_module_stats().executable_modules, 1);
    }
}

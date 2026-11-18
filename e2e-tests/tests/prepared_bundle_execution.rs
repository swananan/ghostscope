//! Prepared bundles have an unprivileged producer and a DWARF-free consumer.
mod common;

use anyhow::{ensure, Context, Result};
use common::sandbox::SandboxHandle;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const SCRIPT: &str = r#"trace bundle_probe { print "BUNDLE value={} global={} pid={} tid={}", value, bundle_global, $pid, $tid; }"#;

struct Fixture {
    directory: tempfile::TempDir,
    binary: PathBuf,
    debug: PathBuf,
    config: PathBuf,
    ghostscope: PathBuf,
    diagnostics: bool,
}

impl Fixture {
    fn new(perf: bool) -> Result<Self> {
        let directory = tempfile::tempdir_in("/tmp")?;
        // Root-run e2e deliberately prepares as nobody, without BPF capabilities.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?;
        let source = directory.path().join("target.c");
        let binary = directory.path().join("target");
        let debug = directory.path().join("target.debug");
        fs::write(
            &source,
            r#"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
volatile int bundle_global = 73;
__attribute__((noinline)) void bundle_probe(int value) {
    asm volatile("" : : "r"(value) : "memory");
}
void *worker(void *arg) {
    int value = *(int *)arg;
    for (;;) { bundle_probe(value); usleep(10000); }
    return 0;
}
int main(int argc, char **argv) {
    int value = argc > 1 ? atoi(argv[1]) : 42;
    int worker_value = value + 1;
    pthread_t thread;
    pthread_create(&thread, 0, worker, &worker_value);
    worker(&value);
    return 0;
}
"#,
        )?;
        successful(
            Command::new("cc")
                .args(["-g", "-O0", "-pthread", "-Wl,--build-id"])
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .output()?,
        )?;
        successful(
            Command::new("objcopy")
                .arg("--only-keep-debug")
                .arg(&binary)
                .arg(&debug)
                .output()?,
        )?;
        successful(
            Command::new("strip")
                .arg("--strip-debug")
                .arg(&binary)
                .output()?,
        )?;
        successful(
            Command::new("objcopy")
                .arg("--add-gnu-debuglink=target.debug")
                .arg(&binary)
                .current_dir(directory.path())
                .output()?,
        )?;
        let config = directory.path().join("config.toml");
        fs::write(&config, format!("[general]\nenable_logging = false\n[ebpf]\nforce_perf_event_array = {perf}\n[dwarf.debuginfod]\nenabled = \"off\"\n"))?;
        let (binary_command, args) = SandboxHandle::host().ghostscope_command()?;
        ensure!(args.is_empty(), "expected a direct host executable");
        let ghostscope = directory.path().join("ghostscope");
        // Keep writable executable descriptors out of this multithreaded test
        // process: another test can fork while fs::copy holds the destination
        // open, retaining that writer until exec and causing ETXTBSY here.
        successful(
            Command::new("cp")
                .arg("--")
                .arg(binary_command)
                .arg(&ghostscope)
                .output()?,
        )?;
        fs::set_permissions(&ghostscope, fs::Permissions::from_mode(0o755))?;
        Ok(Self {
            directory,
            binary,
            debug,
            config,
            ghostscope,
            diagnostics: false,
        })
    }

    fn script(&self) -> String {
        if self.diagnostics {
            SCRIPT.replace("$pid, $tid;", "$pid, $tid; print bundle_large;")
        } else {
            SCRIPT.to_owned()
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.ghostscope);
        command.current_dir(self.directory.path());
        command
    }

    fn prepare(&self, script: &str, bundle: &Path) -> Result<Output> {
        self.prepare_with_modules(script, bundle, &[])
    }

    fn prepare_with_modules(
        &self,
        script: &str,
        bundle: &Path,
        modules: &[PathBuf],
    ) -> Result<Output> {
        let mut command = self.command();
        command
            .arg("prepare")
            .arg("-t")
            .arg(&self.binary)
            .arg("--script")
            .arg(script)
            .arg("--config")
            .arg(&self.config)
            .arg("-o")
            .arg(bundle);
        for module in modules {
            command.arg("--module").arg(module);
        }
        // SAFETY: geteuid has no arguments or memory effects.
        if unsafe { libc::geteuid() } == 0 {
            command.gid(65534).uid(65534);
        }
        command
            .output()
            .context("could not execute unprivileged prepare")
    }
}

fn successful(output: Output) -> Result<String> {
    ensure!(
        output.status.success(),
        "command failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capture(fixture: &Fixture, pid: u32, bundle: Option<&Path>) -> Result<(String, Duration)> {
    let out_path = fixture.directory.path().join("stdout");
    let err_path = fixture.directory.path().join("stderr");
    let mut command = fixture.command();
    if let Some(bundle) = bundle {
        command.arg("run-bundle").arg(bundle);
    } else {
        command
            .arg("-t")
            .arg(&fixture.binary)
            .arg("--script")
            .arg(fixture.script())
            .arg("--config")
            .arg(&fixture.config)
            .args([
                "--no-log",
                "--no-save-llvm-ir",
                "--no-save-ebpf",
                "--no-save-ast",
            ]);
    }
    command
        .args([
            "-p",
            &pid.to_string(),
            "--no-status",
            "--script-output",
            if fs::read_to_string(&fixture.config)?.contains("force_perf_event_array = true") {
                "plain"
            } else {
                "pretty"
            },
            "--emit-ready-marker",
            "BUNDLE_READY",
        ])
        .stdout(Stdio::from(File::create(&out_path)?))
        .stderr(Stdio::from(File::create(&err_path)?));
    let started = Instant::now();
    let mut child = ChildGuard(command.spawn()?);
    let mut ready_after = None;
    let deadline = started + Duration::from_secs(60);
    let output = loop {
        let output = fs::read_to_string(&out_path)?;
        if output.contains("BUNDLE_READY") && ready_after.is_none() {
            ready_after = Some(started.elapsed());
        }
        if ready_after.is_some()
            && output.contains("value=42 global=73")
            && output.contains("value=43 global=73")
        {
            break output;
        }
        if let Some(status) = child.0.try_wait()? {
            anyhow::bail!(
                "tracer exited {status}: {output}\n{}",
                fs::read_to_string(&err_path)?
            );
        }
        ensure!(
            Instant::now() < deadline,
            "timed out: {output}\n{}",
            fs::read_to_string(&err_path)?
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    common::termination::send_sigterm(child.0.id(), "bundle tracer")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "tracer failed shutdown: {}",
                fs::read_to_string(&err_path)?
            );
            break;
        }
        ensure!(Instant::now() < deadline, "tracer failed to shut down");
        std::thread::sleep(Duration::from_millis(10));
    }
    let stderr = fs::read_to_string(&err_path)?;
    ensure!(
        !fixture.diagnostics
            || stderr
                .lines()
                .filter(|line| line.contains("Display note")
                    && line.contains("bundle_large")
                    && line.contains("capture-budget"))
                .count()
                == 1,
        "expected exactly one static display diagnostic: {stderr}"
    );
    ensure!(
        !output.contains("Display note"),
        "diagnostics leaked into stdout: {output}"
    );
    for line in output.lines().filter(|line| line.contains("BUNDLE value=")) {
        ensure!(line.contains(&format!(" pid={pid} ")), "wrong PID: {line}");
        ensure!(
            !line.contains("value=99") && !line.contains("value=100"),
            "unrelated process was traced: {line}"
        );
    }
    Ok((output, ready_after.context("missing ready marker")?))
}

fn host_topology() -> Result<bool> {
    Ok(SandboxHandle::default_ghostscope()?.is_host_backend()
        && SandboxHandle::default_target()?.is_host_backend())
}

fn wait_for_bundle_output(
    tracer: &mut ChildGuard,
    stdout: &Path,
    stderr: &Path,
    expected: impl Fn(&str) -> bool,
) -> Result<String> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let output = fs::read_to_string(stdout)?;
        if let Some(status) = tracer.0.try_wait()? {
            anyhow::bail!(
                "bundle tracer exited {status}: {output}\n{}",
                fs::read_to_string(stderr)?
            );
        }
        if expected(&output) {
            return Ok(output);
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for bundle output: {output}\n{}",
            fs::read_to_string(stderr)?
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

const MULTI_MODULE_SCRIPT: &str = r#"
trace bundle_probe { print "MAIN value={} global={} pid={}", value, bundle_global, $pid; }
trace shared_probe { print "LIB value={} global={} pid={}", value, shared_global, $pid; }
"#;

struct MultiModuleFixture {
    base: Fixture,
    libraries: Vec<PathBuf>,
    loader: PathBuf,
    gate: PathBuf,
}

impl MultiModuleFixture {
    fn new(perf: bool) -> Result<Self> {
        let base = Fixture::new(perf)?;
        let dir = base.directory.path();
        let mut libraries = Vec::new();
        for (name, global) in [("a", 101), ("b", 202)] {
            let source = dir.join(format!("libbundle_{name}.c"));
            let library = dir.join(format!("libbundle_{name}.so"));
            // Same function/global names, distinct DWARF scopes and runtime bases.
            fs::write(
                &source,
                format!(
                    r#"
static volatile int shared_global = {global};
__attribute__((noinline)) void shared_probe(int value) {{
    asm volatile("" : : "r"(value), "r"(shared_global) : "memory");
}}
"#
                ),
            )?;
            successful(
                Command::new("cc")
                    .args(["-g", "-O0", "-fPIC", "-shared", "-Wl,--build-id"])
                    .arg(&source)
                    .arg("-o")
                    .arg(&library)
                    .output()?,
            )?;
            split_debug(&library)?;
            libraries.push(library);
        }
        let source = dir.join("target.c");
        fs::write(
            &source,
            r#"
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#ifndef ONLY_LIBRARY
volatile int bundle_global = 73;
__attribute__((noinline)) void bundle_probe(int value) {
    asm volatile("" : : "r"(value), "r"(bundle_global) : "memory");
}
#endif
int main(int argc, char **argv) {
    if (argc != 5 && argc != 6) return 2;
    int value = atoi(argv[1]);
    while (access(argv[4], F_OK) != 0) usleep(10000);
    void *a = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    void *b = argc == 5 ? dlopen(argv[3], RTLD_NOW | RTLD_LOCAL) : 0;
    if (!a || (argc == 5 && !b)) return 3;
    void (*probe_a)(int) = dlsym(a, "shared_probe");
    void (*probe_b)(int) = b ? dlsym(b, "shared_probe") : 0;
    if (!probe_a || (b && !probe_b)) return 4;
    int phase = 0;
    for (;;) {
        /* Optional gate exercises an absent, loaded, then unloaded secondary. */
        if (argc == 6) {
            int wanted = access(argv[5], F_OK) == 0;
            if (wanted && !b) {
                b = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
                if (!b) return 3;
                probe_b = dlsym(b, "shared_probe");
                if (!probe_b) return 4;
                phase = 1;
            } else if (!wanted && b) {
                dlclose(b);
                b = 0;
                probe_b = 0;
                phase = 2;
            }
        }
        int current = value + phase * 100;
#ifndef ONLY_LIBRARY
        bundle_probe(current);
#endif
        probe_a(current + 1);
        if (probe_b) probe_b(current + 2);
        usleep(10000);
    }
}
"#,
        )?;
        let loader = dir.join("independent-loader");
        for (binary, only_library) in [(&base.binary, false), (&loader, true)] {
            let mut cc = Command::new("cc");
            cc.args(["-g", "-O0", "-Wl,--build-id"]);
            if only_library {
                cc.arg("-DONLY_LIBRARY");
            }
            successful(cc.arg(&source).args(["-ldl", "-o"]).arg(binary).output()?)?;
            split_debug(binary)?;
        }
        let gate = dir.join("load-libraries");
        Ok(Self {
            base,
            libraries,
            loader,
            gate,
        })
    }

    fn start(&self, value: i32, only_library: bool) -> Result<ChildGuard> {
        Ok(ChildGuard(
            Command::new(if only_library {
                &self.loader
            } else {
                &self.base.binary
            })
            .arg(value.to_string())
            .args(&self.libraries)
            .arg(&self.gate)
            .spawn()?,
        ))
    }

    fn remove_debug_inputs(&self) -> Result<()> {
        for entry in fs::read_dir(self.base.directory.path())? {
            let path = entry?.path();
            if matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("c" | "debug")
            ) {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }
}

fn split_debug(binary: &Path) -> Result<()> {
    let debug = binary.with_file_name(format!(
        "{}.debug",
        binary
            .file_name()
            .context("binary filename")?
            .to_string_lossy()
    ));
    successful(
        Command::new("objcopy")
            .arg("--only-keep-debug")
            .arg(binary)
            .arg(&debug)
            .output()?,
    )?;
    successful(
        Command::new("strip")
            .arg("--strip-debug")
            .arg(binary)
            .output()?,
    )?;
    successful(
        Command::new("objcopy")
            .arg(format!("--add-gnu-debuglink={}", debug.display()))
            .arg(binary)
            .output()?,
    )?;
    Ok(())
}

#[test]
fn test_prepared_bundle_multiple_modules_and_late_dlopen() -> Result<()> {
    common::init();
    if !host_topology()?
        || !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi
    {
        return Ok(());
    }
    for perf in [false, true] {
        let mut fixture = MultiModuleFixture::new(perf)?;
        let bundle = fixture.base.directory.path().join("multi.gsb");
        successful(fixture.base.prepare_with_modules(
            MULTI_MODULE_SCRIPT,
            &bundle,
            &fixture.libraries,
        )?)?;
        let contents: serde_json::Value = serde_json::from_slice(&fs::read(&bundle)?)?;
        ensure!(
            contents["modules"]
                .as_array()
                .context("module table")?
                .len()
                == 3,
            "missing prepared module"
        );
        for module in 0..3 {
            ensure!(
                contents["probes"]
                    .as_array()
                    .context("probe table")?
                    .iter()
                    .any(|probe| probe["module"] == module),
                "missing probe for module {module}"
            );
        }
        fixture.remove_debug_inputs()?;
        // Relocate a library and remove its original path: runtime must use the
        // matching override for both attachment and offset discovery.
        let relocated = fixture.base.directory.path().join("relocated-b.so");
        successful(
            Command::new("cp")
                .arg("--")
                .arg(&fixture.libraries[1])
                .arg(&relocated)
                .output()?,
        )?;
        fs::remove_file(&fixture.libraries[1])?;
        fixture.libraries[1] = relocated.clone();
        for pid_mode in [true, false] {
            let _ = fs::remove_file(&fixture.gate);
            let existing = if pid_mode {
                Some(fixture.start(42, false)?)
            } else {
                None
            };
            let unrelated = if pid_mode {
                Some(fixture.start(99, false)?)
            } else {
                None
            };
            let stdout = fixture.base.directory.path().join("multi.stdout");
            let stderr = fixture.base.directory.path().join("multi.stderr");
            let mut command = fixture.base.command();
            command
                .arg("run-bundle")
                .arg(&bundle)
                .arg("--module-path")
                .arg(format!("libbundle_b.so={}", relocated.display()))
                .args([
                    "--no-status",
                    "--script-output",
                    "plain",
                    "--emit-ready-marker",
                    "BUNDLE_READY",
                ]);
            if let Some(target) = &existing {
                command.arg("-p").arg(target.0.id().to_string());
            } else {
                command.arg("-t").arg(&fixture.base.binary);
            }
            let mut tracer = ChildGuard(
                command
                    .stdout(Stdio::from(File::create(&stdout)?))
                    .stderr(Stdio::from(File::create(&stderr)?))
                    .spawn()?,
            );
            wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
                s.contains("BUNDLE_READY")
            })?;
            // Both DSOs are first mapped after the tracer is ready, even in -p mode.
            fs::write(&fixture.gate, b"go")?;
            let target = if let Some(existing) = existing {
                existing
            } else {
                fixture.start(42, false)?
            };
            let pid = target.0.id();
            let output = wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
                s.contains(&format!("MAIN value=42 global=73 pid={pid}"))
                    && s.contains(&format!("LIB value=43 global=101 pid={pid}"))
                    && s.contains(&format!("LIB value=44 global=202 pid={pid}"))
            })?;
            if let Some(unrelated) = &unrelated {
                ensure!(
                    !output.contains(&format!("pid={}", unrelated.0.id())),
                    "PID scope leaked: {output}"
                );
            }
            drop(target);
            if !pid_mode {
                // This executable is absent from the bundle and does not map its
                // primary target. Secondary module discovery must be independent.
                for value in [84, 126] {
                    let loader = fixture.start(value, true)?;
                    let pid = loader.0.id();
                    wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
                        s.contains(&format!("LIB value={} global=101 pid={pid}", value + 1))
                            && s.contains(&format!("LIB value={} global=202 pid={pid}", value + 2))
                    })?;
                }
            }
            common::termination::send_sigterm(tracer.0.id(), "multi-module bundle tracer")?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(status) = tracer.0.try_wait()? {
                    ensure!(
                        status.success(),
                        "tracer shutdown failed: {}",
                        fs::read_to_string(&stderr)?
                    );
                    break;
                }
                ensure!(Instant::now() < deadline, "tracer failed to shut down");
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
    Ok(())
}

#[test]
fn test_prepared_bundle_keeps_other_modules_across_dlopen_and_dlclose() -> Result<()> {
    common::init();
    if !host_topology()?
        || !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi
    {
        return Ok(());
    }
    let fixture = MultiModuleFixture::new(false)?;
    let bundle = fixture.base.directory.path().join("partial.gsb");
    successful(fixture.base.prepare_with_modules(
        MULTI_MODULE_SCRIPT,
        &bundle,
        &fixture.libraries,
    )?)?;
    fixture.remove_debug_inputs()?;
    let stdout = fixture.base.directory.path().join("partial.stdout");
    let stderr = fixture.base.directory.path().join("partial.stderr");
    let mut tracer = ChildGuard(
        fixture
            .base
            .command()
            .arg("run-bundle")
            .arg(&bundle)
            .arg("-t")
            .arg(&fixture.base.binary)
            .args([
                "--no-status",
                "--script-output",
                "plain",
                "--emit-ready-marker",
                "BUNDLE_READY",
            ])
            .stdout(Stdio::from(File::create(&stdout)?))
            .stderr(Stdio::from(File::create(&stderr)?))
            .spawn()?,
    );
    wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
        s.contains("BUNDLE_READY")
    })?;
    let secondary_gate = fixture.base.directory.path().join("load-second");
    fs::write(&fixture.gate, b"go")?;
    let target = ChildGuard(
        Command::new(&fixture.base.binary)
            .arg("42")
            .args(&fixture.libraries)
            .arg(&fixture.gate)
            .arg(&secondary_gate)
            .spawn()?,
    );
    let pid = target.0.id();
    for phase in 0..3 {
        match phase {
            1 => fs::write(&secondary_gate, b"load")?,
            2 => fs::remove_file(&secondary_gate)?,
            _ => {}
        }
        let value = 42 + phase * 100;
        wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
            s.contains(&format!("MAIN value={value} global=73 pid={pid}"))
                && s.contains(&format!("LIB value={} global=101 pid={pid}", value + 1))
                && (phase != 1
                    || s.contains(&format!("LIB value={} global=202 pid={pid}", value + 2)))
        })?;
    }
    common::termination::send_sigterm(tracer.0.id(), "partial-module bundle tracer")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = tracer.0.try_wait()? {
            ensure!(
                status.success(),
                "bundle tracer shutdown failed: {}",
                fs::read_to_string(&stderr)?
            );
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "bundle tracer failed to shut down"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}

#[test]
fn test_prepared_bundle_checks_every_module_before_attachment() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    let fixture = MultiModuleFixture::new(false)?;
    let bundle = fixture.base.directory.path().join("multi.gsb");
    let duplicate = fixture.base.prepare_with_modules(
        MULTI_MODULE_SCRIPT,
        &bundle,
        &[fixture.libraries[0].clone(), fixture.libraries[0].clone()],
    )?;
    ensure!(
        !duplicate.status.success() && !bundle.exists(),
        "duplicate module was accepted"
    );
    ensure!(
        String::from_utf8_lossy(&duplicate.stderr).contains("duplicate module"),
        "unexpected duplicate error"
    );
    successful(fixture.base.prepare_with_modules(
        MULTI_MODULE_SCRIPT,
        &bundle,
        &fixture.libraries,
    )?)?;
    let original = fs::read(&bundle)?;
    for (pointer, value, expected) in [
        (
            "/modules/2/sha256",
            serde_json::json!(vec![0; 32]),
            "identity mismatch",
        ),
        (
            "/modules/2/cookie",
            serde_json::from_slice::<serde_json::Value>(&original)?["modules"][1]["cookie"].clone(),
            "duplicate module cookie",
        ),
        (
            "/probes/0/module",
            serde_json::json!(3),
            "invalid probe module index",
        ),
    ] {
        let mut contents: serde_json::Value = serde_json::from_slice(&original)?;
        *contents
            .pointer_mut(pointer)
            .context("missing bundle field")? = value;
        let bad = fixture.base.directory.path().join("bad.gsb");
        fs::write(&bad, serde_json::to_vec(&contents)?)?;
        let output = fixture
            .base
            .command()
            .arg("run-bundle")
            .arg(&bad)
            .arg("-t")
            .arg(&fixture.base.binary)
            .args(["--emit-ready-marker", "BUNDLE_READY"])
            .output()?;
        ensure!(
            !output.status.success(),
            "invalid secondary module accepted"
        );
        ensure!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "unexpected error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        ensure!(
            !String::from_utf8_lossy(&output.stdout).contains("BUNDLE_READY"),
            "attached invalid bundle"
        );
    }
    fs::remove_file(&fixture.libraries[1])?;
    let output = fixture
        .base
        .command()
        .arg("run-bundle")
        .arg(&bundle)
        .arg("-t")
        .arg(&fixture.base.binary)
        .output()?;
    ensure!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("cannot resolve bundle module"),
        "missing secondary module accepted"
    );
    Ok(())
}

#[test]
fn test_prepared_bundle_target_mode_traces_late_start_and_restart() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    if !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi {
        eprintln!("bundle target-mode test requires multi-uprobe support");
        return Ok(());
    }
    for perf in [false, true] {
        let fixture = Fixture::new(perf)?;
        let bundle = fixture.directory.path().join("trace.gsb");
        successful(fixture.prepare(SCRIPT, &bundle)?)?;
        fs::remove_file(&fixture.debug)?;
        fs::remove_file(fixture.directory.path().join("target.c"))?;

        // Identical bytes at another inode must not become part of this attachment.
        let other_binary = fixture.directory.path().join("other-target");
        successful(
            Command::new("cp")
                .arg("--")
                .arg(&fixture.binary)
                .arg(&other_binary)
                .output()?,
        )?;
        let _unrelated = ChildGuard(Command::new(&other_binary).arg("99").spawn()?);
        let stdout = fixture.directory.path().join("target-mode.stdout");
        let stderr = fixture.directory.path().join("target-mode.stderr");
        let mut tracer = ChildGuard(
            fixture
                .command()
                .arg("run-bundle")
                .arg(&bundle)
                // Exercise relative path resolution as well as PID-free attachment.
                .args([
                    "-t",
                    "./target",
                    "--no-status",
                    "--script-output",
                    "plain",
                    "--emit-ready-marker",
                    "BUNDLE_READY",
                ])
                .stdout(Stdio::from(File::create(&stdout)?))
                .stderr(Stdio::from(File::create(&stderr)?))
                .spawn()?,
        );
        // No process maps the target inode yet: readiness must not require a PID.
        wait_for_bundle_output(&mut tracer, &stdout, &stderr, |s| {
            s.contains("BUNDLE_READY")
        })?;
        let mut pids = Vec::new();
        for value in [42, 84] {
            let target = ChildGuard(
                Command::new(&fixture.binary)
                    .arg(value.to_string())
                    .spawn()?,
            );
            let pid = target.0.id();
            pids.push(pid);
            wait_for_bundle_output(&mut tracer, &stdout, &stderr, |output| {
                [value, value + 1]
                    .into_iter()
                    .all(|v| output.contains(&format!("BUNDLE value={v} global=73 pid={pid} ")))
            })?;
            // Keep the tracer alive while the first process exits and a new one starts.
            drop(target);
        }
        common::termination::send_sigterm(tracer.0.id(), "target-mode bundle tracer")?;
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = tracer.0.try_wait()? {
                ensure!(
                    status.success(),
                    "bundle tracer failed shutdown: {}",
                    fs::read_to_string(&stderr)?
                );
                break;
            }
            ensure!(
                Instant::now() < deadline,
                "bundle tracer failed to shut down"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = fs::read_to_string(&stdout)?;
        for line in output.lines().filter(|line| line.contains("BUNDLE value=")) {
            ensure!(
                pids.iter()
                    .any(|pid| line.contains(&format!(" pid={pid} "))),
                "unrelated process was traced: {line}"
            );
            ensure!(
                !line.contains("value=99") && !line.contains("value=100"),
                "unrelated inode was traced: {line}"
            );
        }
    }
    Ok(())
}

#[test]
fn test_prepared_bundle_unprivileged_roundtrip_without_debug_info() -> Result<()> {
    common::init();
    if !host_topology()? {
        eprintln!("prepared bundle MVP is host-only; skipping positive cases outside host->host");
        return Ok(());
    }
    for perf in [false, true] {
        let fixture = Fixture::new(perf)?;
        let bundle = fixture.directory.path().join("trace.gsb");
        successful(fixture.prepare(SCRIPT, &bundle)?)?;
        let target = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
        let unrelated = ChildGuard(Command::new(&fixture.binary).arg("99").spawn()?);
        if !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi
        {
            // Older supported GhostScope kernels cannot run this bundle profile.
            // Still exercise offline preparation and the explicit refusal path.
            let output = fixture
                .command()
                .arg("run-bundle")
                .arg(&bundle)
                .arg("-p")
                .arg(target.0.id().to_string())
                .output()?;
            ensure!(
                !output.status.success(),
                "unsupported kernel accepted a bundle"
            );
            ensure!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("requires process-scoped multi-uprobe"),
                "unexpected capability error: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            writeln!(std::io::stderr(), "prepared bundle: verified unsupported-kernel rejection; positive attach coverage requires process-scoped multi-uprobes")?;
            continue;
        }
        let mut normal_times = Vec::new();
        for _ in 0..3 {
            normal_times.push(capture(&fixture, target.0.id(), None)?.1);
        }
        // The compiled producer needs this file. The prepared consumer must not.
        fs::remove_file(&fixture.debug)?;
        let mut bundle_times = Vec::new();
        for _ in 0..3 {
            bundle_times.push(capture(&fixture, target.0.id(), Some(&bundle))?.1);
        }
        drop(target);
        let second = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
        capture(&fixture, second.0.id(), Some(&bundle))?;
        drop(unrelated);
        normal_times.sort();
        bundle_times.sort();
        // Direct stderr keeps benchmark evidence visible even without --nocapture.
        writeln!(std::io::stderr(), "prepared bundle perf={perf}: median of 3 normal ready={}ms, bundle ready={}ms (small split-DWARF C fixture)", normal_times[1].as_millis(), bundle_times[1].as_millis())?;
    }
    Ok(())
}

#[test]
fn test_prepared_bundle_rejects_backtrace_mismatch_and_overwrite() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    let fixture = Fixture::new(false)?;
    let bundle = fixture.directory.path().join("trace.gsb");
    let rejected = fixture.prepare("trace bundle_probe { if true { bt; } }", &bundle)?;
    ensure!(!rejected.status.success(), "backtrace was accepted");
    ensure!(
        String::from_utf8_lossy(&rejected.stderr).contains("does not support bt/backtrace"),
        "unexpected failure: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    ensure!(!bundle.exists(), "failed preparation published a bundle");
    successful(fixture.prepare(SCRIPT, &bundle)?)?;
    let original = fs::read(&bundle)?;
    ensure!(
        !fixture.prepare(SCRIPT, &bundle)?.status.success(),
        "existing bundle was overwritten"
    );
    ensure!(fs::read(&bundle)? == original, "existing bundle changed");

    let target = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
    for (field, value, expected) in [
        ("/format_version", serde_json::json!(999), "format version"),
        ("/format_version", serde_json::json!(1), "format version"),
        (
            "/architecture",
            serde_json::json!("unsupported"),
            "architecture mismatch",
        ),
        (
            "/ghostscope_version",
            serde_json::json!("0.0.0"),
            "version mismatch",
        ),
        (
            "/modules/0/sha256",
            serde_json::json!(vec![0; 32]),
            "identity mismatch",
        ),
        (
            "/probes/0/module",
            serde_json::json!(1),
            "invalid probe module index",
        ),
    ] {
        let mut contents: serde_json::Value = serde_json::from_slice(&original)?;
        *contents
            .pointer_mut(field)
            .context("missing bundle field")? = value;
        let path = fixture.directory.path().join("bad.gsb");
        fs::write(&path, serde_json::to_vec(&contents)?)?;
        for pid_mode in [false, true] {
            let mut command = fixture.command();
            command.arg("run-bundle").arg(&path);
            if pid_mode {
                command.arg("-p").arg(target.0.id().to_string());
            } else {
                command.arg("-t").arg(&fixture.binary);
            }
            let output = command.output()?;
            ensure!(
                !output.status.success(),
                "invalid {field} accepted (pid_mode={pid_mode})"
            );
            ensure!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "unexpected {field} error: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    let output = fixture
        .command()
        .arg("run-bundle")
        .arg(&bundle)
        .arg("-p")
        .arg(std::process::id().to_string())
        .output()?;
    ensure!(!output.status.success(), "unmapped target accepted");
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains("not mapped"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn test_prepared_bundle_replays_static_diagnostics() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    if !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi {
        eprintln!("static bundle diagnostics test requires process-scoped multi-uprobes");
        return Ok(());
    }
    for perf in [false, true] {
        let mut fixture = Fixture::new(perf)?;
        fixture.diagnostics = true;
        let source = fixture.directory.path().join("diagnostics.rs");
        fs::write(
            &source,
            r#"
use std::cell::Cell;
#[no_mangle] pub static mut bundle_global: i32 = 73;
#[no_mangle] pub static mut bundle_large: Cell<String> = Cell::new(String::new());
#[inline(never)] #[no_mangle] pub fn bundle_probe(value: i32) { std::hint::black_box(value); std::hint::black_box(unsafe { bundle_global }); }
fn worker(value: i32) { loop { bundle_probe(value); std::thread::sleep(std::time::Duration::from_millis(10)); } }
fn main() {
    unsafe { bundle_large = Cell::new(String::from("cell value")); }
    std::thread::spawn(|| worker(43));
    worker(42);
}
"#,
        )?;
        successful(
            Command::new("rustc")
                .args(["-g", "--edition=2021"])
                .arg(&source)
                .arg("-o")
                .arg(&fixture.binary)
                .output()?,
        )?;
        let config =
            fs::read_to_string(&fixture.config)?.replace("[ebpf]", "[ebpf]\nmem_dump_cap = 24");
        fs::write(&fixture.config, config)?;
        let bundle = fixture.directory.path().join("diagnostics.gsb");
        let preparation = successful(fixture.prepare(&fixture.script(), &bundle)?)?;
        ensure!(
            preparation.contains("capture-budget"),
            "fixture produced no static diagnostic: {preparation}"
        );
        let target = ChildGuard(Command::new(&fixture.binary).spawn()?);
        capture(&fixture, target.0.id(), None)?;
        capture(&fixture, target.0.id(), Some(&bundle))?;
    }
    Ok(())
}

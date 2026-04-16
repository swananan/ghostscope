mod common;

use common::{
    fixture_compiler_available, init,
    runner::GhostscopeRunner,
    targets::{TargetHandle, TargetLauncher},
    FixtureCompiler,
};
use ghostscope_dwarf::{ComputeStep, MemoryAccessSize};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_NAME: &str = "entry_value_recovery_program";
const FIXTURE_SOURCE: &str = "entry_value_recovery_program.c";
const POST_CALL_TRACE_LINE: u32 = 21;

static CLANG_FIXTURE: OnceLock<Result<PathBuf, String>> = OnceLock::new();

struct LoggedTarget {
    target: TargetHandle,
    temp_dir: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl LoggedTarget {
    async fn terminate_and_collect(self) -> anyhow::Result<(String, String)> {
        self.target.terminate().await?;
        let stdout = read_log_file(&self.stdout_log)?;
        let stderr = read_log_file(&self.stderr_log)?;
        let _ = fs::remove_dir_all(&self.temp_dir);
        Ok((stdout, stderr))
    }
}

fn should_skip_for_ebpf_env(exit_code: i32, stderr: &str) -> bool {
    exit_code != 0
        && (stderr.contains("BPF_PROG_LOAD")
            || stderr.contains("needs elevated privileges")
            || stderr.contains("cap_bpf"))
}

fn compile_entry_value_recovery_program_clang() -> anyhow::Result<PathBuf> {
    let result = CLANG_FIXTURE.get_or_init(|| {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(FIXTURE_NAME);
        let binary = base.join("entry_value_recovery_program_clang_dwarf5");
        let output = StdCommand::new("make")
            .arg("clean")
            .current_dir(&base)
            .output();
        if let Err(e) = output {
            return Err(format!("failed to run make clean for {FIXTURE_NAME}: {e}"));
        }

        let output = std::process::Command::new("make")
            .arg("all")
            .arg("CC=clang")
            .arg("CFLAGS=-Wall -Wextra -gdwarf-5 -O3")
            .arg("BINARY=entry_value_recovery_program_clang_dwarf5")
            .arg("OBJ=entry_value_recovery_program_clang_dwarf5.o")
            .current_dir(&base)
            .output();

        match output {
            Ok(output) if output.status.success() => Ok(binary),
            Ok(output) => Err(format!(
                "failed to compile {FIXTURE_NAME} clang fixture: {}",
                String::from_utf8_lossy(&output.stderr)
            )),
            Err(e) => Err(format!("failed to run make for {FIXTURE_NAME}: {e}")),
        }
    });

    result.clone().map_err(|e| anyhow::anyhow!(e))
}

async fn spawn_logged_target(binary_path: &Path) -> anyhow::Result<LoggedTarget> {
    let base = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture binary has no parent dir"))?;
    let temp_dir = create_runtime_log_dir(base)?;
    let stdout_log = temp_dir.join("target.stdout");
    let stderr_log = temp_dir.join("target.stderr");
    let wrapper_path = temp_dir.join("launch_target.sh");
    let wrapper = format!(
        "#!/usr/bin/env bash
set -euo pipefail
cd {base}
exec {binary} >>{stdout} 2>>{stderr}
",
        base = shell_quote(base),
        binary = shell_quote(binary_path),
        stdout = shell_quote(&stdout_log),
        stderr = shell_quote(&stderr_log),
    );
    fs::write(&wrapper_path, wrapper)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper_path, perms)?;
    }
    let target = TargetLauncher::binary(&wrapper_path)
        .current_dir(base)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(LoggedTarget {
        target,
        temp_dir,
        stdout_log,
        stderr_log,
    })
}

fn create_runtime_log_dir(base: &Path) -> anyhow::Result<PathBuf> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = base.join(format!(".ghostscope-entry-value-runtime-{unique}"));
    fs::create_dir(&path)?;
    Ok(path)
}

fn read_log_file(path: &Path) -> anyhow::Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(err.into()),
    }
}

fn shell_quote(path: &Path) -> String {
    let raw = path.display().to_string();
    format!("'{}'", raw.replace('\'', "'\"'\"'"))
}

#[tokio::test]
async fn test_post_call_entry_value_recovers_state_members_at_runtime() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping entry_value runtime test because clang is unavailable");
        return Ok(());
    }

    let binary_path = compile_entry_value_recovery_program_clang()?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, POST_CALL_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE}"
    );

    let target = spawn_logged_target(&binary_path).await?;
    let script = format!(
        "trace {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE} {{
    print \"POSTCALL:{{}}:{{}}\", state.total_bytes, state.stream_id;
}}
"
    );
    let (exit_code, ghostscope_stdout, ghostscope_stderr) = GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target.target)
        .timeout_secs(4)
        .enable_sysmon_shared_lib(false)
        .run()
        .await?;
    let (target_stdout, target_stderr) = target.terminate_and_collect().await?;

    if should_skip_for_ebpf_env(exit_code, &ghostscope_stderr) {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope stderr={ghostscope_stderr} ghostscope stdout={ghostscope_stdout} target stderr={target_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("ExprError"),
        "Expected exact post-call entry_value recovery. STDOUT: {ghostscope_stdout}
STDERR: {ghostscope_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("<optimized out>"),
        "Post-call entry_value should not be optimized out. STDOUT: {ghostscope_stdout}
STDERR: {ghostscope_stderr}"
    );

    let actual_re = Regex::new(r"ACTUAL:([0-9-]+):([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let mut actual_by_seed = HashMap::new();
    for caps in actual_re.captures_iter(&target_stdout) {
        actual_by_seed.insert(
            caps[1].parse::<i64>()?,
            (
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
                caps[4].parse::<i64>()?,
            ),
        );
    }
    anyhow::ensure!(
        !actual_by_seed.is_empty(),
        "fixture stdout did not contain ACTUAL lines: {target_stdout}"
    );

    let trace_re = Regex::new(r"POSTCALL:([0-9-]+):([0-9-]+)")?;
    let mut seen = 0;
    for caps in trace_re.captures_iter(&ghostscope_stdout) {
        let total_bytes = caps[1].parse::<i64>()?;
        let stream_id = caps[2].parse::<i64>()?;
        assert!(
            actual_by_seed
                .values()
                .any(|actual| actual.0 == total_bytes && actual.1 == stream_id),
            "missing ACTUAL record for total_bytes={total_bytes}, stream_id={stream_id}; target stdout={target_stdout}"
        );
        seen += 1;
    }

    assert!(
        seen >= 2,
        "Expected multiple post-call trace events. GhostScope STDOUT: {ghostscope_stdout}
Target STDOUT: {target_stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_recover_caller_frame_exposes_pc_and_callee_saved_steps() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping caller-frame recovery test because clang is unavailable");
        return Ok(());
    }

    let binary_path = compile_entry_value_recovery_program_clang()?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, POST_CALL_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE}"
    );

    let recovery = analyzer
        .recover_caller_frame(&addrs[0], &[3, 16])?
        .ok_or_else(|| anyhow::anyhow!("no caller-frame recovery returned"))?;

    assert_eq!(recovery.return_address_register, 16);
    assert!(
        recovery.caller_pc_steps.iter().any(|step| matches!(
            step,
            ComputeStep::Dereference {
                size: MemoryAccessSize::U64
            }
        )),
        "caller_pc_steps should load the caller PC from memory: {:?}",
        recovery.caller_pc_steps
    );
    assert!(
        recovery
            .caller_pc_steps
            .iter()
            .any(|step| matches!(step, ComputeStep::PushConstant(_))),
        "caller_pc_steps should include a CFA-relative offset: {:?}",
        recovery.caller_pc_steps
    );
    let rbx_steps = recovery
        .register_recovery_steps
        .get(&3)
        .ok_or_else(|| anyhow::anyhow!("missing rbx recovery steps"))?;
    assert!(
        rbx_steps.iter().any(|step| matches!(
            step,
            ComputeStep::Dereference {
                size: MemoryAccessSize::U64
            }
        )),
        "rbx should recover from the caller stack slot at the post-call PC: {rbx_steps:?}"
    );

    Ok(())
}

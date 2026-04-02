//! -t (target path) mode globals tests
//! Includes both pre-start targets and late-start (GhostScope first) scenarios

mod common;

use common::{init, FIXTURES};
use ghostscope_process::is_shared_object;
use regex::Regex;
use serial_test::serial;
use std::env;
use std::path::Path;
use std::time::Duration;

fn visible_pid_for_target(target: &common::targets::TargetHandle) -> anyhow::Result<u32> {
    target.visible_pid_from(&common::sandbox::SandboxHandle::default_ghostscope()?)
}

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target_path: &std::path::Path,
) -> anyhow::Result<(i32, String, String)> {
    let enable_sysmon = is_shared_object(target_path);
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .with_target(target_path)
        .timeout_secs(timeout_secs)
        .enable_sysmon_shared_lib(enable_sysmon)
        .run()
        .await
}

async fn spawn_globals_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("globals_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

fn prepare_late_start_launcher(
    binary_path: &Path,
) -> anyhow::Result<common::sandbox::SandboxHandle> {
    // Late-start tests rely on the launcher process starting promptly after GhostScope.
    // Pre-build the executable in the default target sandbox up front so the later
    // spawn does not burn most of the timeout compiling inside docker.
    common::targets::ensure_target_binary_ready_for_default_sandbox(binary_path)
}

fn ghostscope_log_path() -> anyhow::Result<std::path::PathBuf> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve workspace root for ghostscope.log"))?
        .join("ghostscope.log"))
}

fn skip_if_nested_t_mode_unsupported() -> bool {
    let target_mode = match env::var("E2E_TARGET_MODE") {
        Ok(value) => value,
        Err(env::VarError::NotPresent) => return false,
        Err(err) => {
            eprintln!("continuing nested -t test despite unreadable E2E_TARGET_MODE: {err}");
            return false;
        }
    };
    let nested_child_container = matches!(
        target_mode.trim().to_ascii_lowercase().as_str(),
        "child-container" | "child" | "nested" | "descendant"
    );
    if !nested_child_container {
        return false;
    }

    // Nested child-container `-t` is intentionally unsupported for now.
    // The current `-t` implementation relies on target-path / sysmon lifecycle
    // maintenance anchored in GhostScope's current `/proc` view, while nested
    // child-container targets introduce a second PID namespace below that view.
    // Without a stable, shared runtime-pid -> outer `/proc` pid mapping source,
    // these tests are not a reliable correctness signal, so skip the entire
    // nested `-t` suite instead of depending on CLI-only heuristics.
    eprintln!(
        "skipping nested child-container -t test: nested target-path mode is \
         currently unsupported because proc offsets and runtime lifecycle \
         maintenance stay anchored in the outer container /proc pid view"
    );
    true
}

// Late-start helper: run GhostScope first, wait until the CLI reports it has
// finished compile/load/attach, then start the target process.
async fn run_ghostscope_then_start_target_after_ready(
    runner: common::runner::GhostscopeRunner,
    launcher_exe: &Path,
) -> anyhow::Result<(i32, String, String, common::targets::TargetHandle, u32)> {
    let (exit_code, stdout, stderr, (target, pid)) = runner
        .run_after_ready(|| async {
            let target = spawn_globals_program(launcher_exe).await?;
            let pid = visible_pid_for_target(&target)?;
            Ok((target, pid))
        })
        .await?;

    Ok((exit_code, stdout, stderr, target, pid))
}

async fn run_ghostscope_then_start_exe(
    script_content: &str,
    timeout_secs: u64,
    target_path: &std::path::Path,
    launcher_exe: &std::path::Path,
) -> anyhow::Result<(i32, String, String, common::targets::TargetHandle, u32)> {
    run_ghostscope_then_start_target_after_ready(
        common::runner::GhostscopeRunner::new()
            .with_script(script_content)
            .with_target(target_path)
            .timeout_secs(timeout_secs),
        launcher_exe,
    )
    .await
}

// ---------------------------------
// Pre-start (-t) tests (target first)
// ---------------------------------

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_executable_globals_prints() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let target = spawn_globals_program(&binary_path).await?;
    let pid = visible_pid_for_target(&target)?;

    let script = r#"
trace globals_program.c:32 {
    print "PID:{} GY:{}", $pid, G_STATE.inner.y;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 5, &binary_path).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let re = Regex::new(r"PID:([0-9]+) GY:([0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                vals.push(c[2].parse().unwrap_or(0.0));
            }
        }
    }
    let mut uniq: Vec<f64> = Vec::new();
    for v in vals.into_iter() {
        if uniq
            .last()
            .copied()
            .map(|u| (u - v).abs() < 1e-9)
            .unwrap_or(false)
        {
            continue;
        }
        uniq.push(v);
    }
    if uniq.len() >= 2 {
        let d = ((uniq[1] - uniq[0]) * 100.0).round() as i64;
        assert_eq!(
            d, 50,
            "G_STATE.inner.y should +0.5 per tick. STDOUT: {stdout}"
        );
    } else {
        assert!(
            !uniq.is_empty(),
            "No events for target PID. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_library_globals_prints() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let lib_path = bin_dir.join("libgvars.so");
    let target = spawn_globals_program(&binary_path).await?;
    let pid = visible_pid_for_target(&target)?;

    let script = r#"
trace lib_tick {
    print "PID:{} LC:{}", $pid, LIB_STATE.counter;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 2, &lib_path).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let re = Regex::new(r"PID:([0-9]+) LC:([0-9]+)").unwrap();
    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                vals.push(c[2].parse().unwrap_or(0));
            }
        }
    }
    let mut uniq: Vec<i64> = Vec::new();
    for v in vals.into_iter() {
        if uniq.last().copied() == Some(v) {
            continue;
        }
        uniq.push(v);
    }
    if uniq.len() >= 2 {
        let d = uniq[1] - uniq[0];
        assert_eq!(
            d, 2,
            "LIB_STATE.counter should +2 per tick. STDOUT: {stdout}"
        );
    } else {
        assert!(
            !uniq.is_empty(),
            "No events for target PID. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_executable_rodata_and_struct_pretty() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let target = spawn_globals_program(&binary_path).await?;
    let pid = visible_pid_for_target(&target)?;

    // At line 26, aliases (s, ls, gm, etc.) are initialized
    let script = r#"
trace globals_program.c:26 {
    print "PID:{} GM:{:s.32}", $pid, gm;   // rodata string (explicit string format)
    print *s;                              // struct pretty print (deref pointer)
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 2, &binary_path).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Verify we saw our PID and the expected GM string for that PID (quoted or unquoted)
    let re = Regex::new(r#"PID:([0-9]+) GM:([^\r\n]+)"#).unwrap();
    let mut saw_gm_for_pid = false;
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                let s = c[2].trim();
                if s.contains("Hello, Global!") {
                    saw_gm_for_pid = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_gm_for_pid,
        "Expected GM string for our PID. STDOUT: {stdout}"
    );

    assert!(
        stdout.contains("GlobalState {"),
        "Expected pretty struct output. STDOUT: {stdout}"
    );

    Ok(())
}

// ---------------------------------
// Late-start (-t) tests (GhostScope first)
// ---------------------------------

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_executable_late_start_globals_prints() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    // GhostScope starts first (-t points to the executable), then we start the process
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let script = r#"
trace globals_program.c:32 {
    print "PID:{} GY:{}", $pid, G_STATE.inner.y;
}
"#;

    let (exit_code, stdout, stderr, target, pid) = run_ghostscope_then_start_exe(
        script,
        3,            // allow some time for sysmon -> prefill -> events
        &binary_path, // -t target
        &binary_path, // launcher (the same executable)
    )
    .await?;

    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let re = Regex::new(r"PID:([0-9]+) GY:([0-9]+(?:\.[0-9]+)?)").unwrap();
    let mut vals: Vec<f64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                vals.push(c[2].parse().unwrap_or(0.0));
            }
        }
    }
    let mut uniq: Vec<f64> = Vec::new();
    for v in vals.into_iter() {
        if uniq
            .last()
            .copied()
            .map(|u| (u - v).abs() < 1e-9)
            .unwrap_or(false)
        {
            continue;
        }
        uniq.push(v);
    }
    if uniq.len() >= 2 {
        let d = ((uniq[1] - uniq[0]) * 100.0).round() as i64;
        assert_eq!(
            d, 50,
            "Late-start: G_STATE.inner.y should +0.5 per tick. STDOUT: {stdout}"
        );
    } else {
        assert!(
            !uniq.is_empty(),
            "Late-start: No events for our PID {pid}. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_library_late_start_globals_prints() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    // -t points to libgvars.so; GhostScope first, then we run the executable which loads the lib
    // only after GhostScope reports its late-start hooks are ready.
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let _target_sandbox_guard = prepare_late_start_launcher(&binary_path)?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let lib_path = bin_dir.join("libgvars.so");
    let script = r#"
trace lib_tick {
    print "PID:{} LC:{}", $pid, LIB_STATE.counter;
}
"#;

    let (exit_code, stdout, stderr, target, pid) = run_ghostscope_then_start_target_after_ready(
        common::runner::GhostscopeRunner::new()
            .with_script(script)
            .with_target(&lib_path)
            .timeout_secs(12)
            .enable_sysmon_shared_lib(true),
        &binary_path,
    )
    .await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let re = Regex::new(r"PID:([0-9]+) LC:([0-9]+)").unwrap();
    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                vals.push(c[2].parse().unwrap_or(0));
            }
        }
    }
    let mut uniq: Vec<i64> = Vec::new();
    for v in vals.into_iter() {
        if uniq.last().copied() == Some(v) {
            continue;
        }
        uniq.push(v);
    }
    if uniq.len() >= 2 {
        let d = uniq[1] - uniq[0];
        assert_eq!(
            d, 2,
            "Late-start: LIB_STATE.counter should +2 per tick. STDOUT: {stdout}"
        );
    } else {
        let log_dump = tokio::fs::read_to_string(ghostscope_log_path()?)
            .await
            .unwrap_or_else(|_| "<ghostscope.log unavailable>".to_string());
        let msg =
            format!("Late-start: No events for our PID {pid}. STDOUT: {stdout}. LOG: {log_dump}");
        assert!(!uniq.is_empty(), "{}", msg);
    }
    let _ = tokio::fs::remove_file(ghostscope_log_path()?).await;
    Ok(())
}

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_executable_late_start_rodata_and_struct_pretty() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    // At line 26, aliases (s, ls, gm, etc.) are initialized
    let script = r#"
trace globals_program.c:26 {
    print "PID:{} GM:{:s.32}", $pid, gm;   // rodata string
    print *s;                              // struct pretty print
}
"#;

    let (exit_code, stdout, stderr, target, pid) =
        run_ghostscope_then_start_exe(script, 3, &binary_path, &binary_path).await?;

    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Verify we saw our PID and the expected GM string for that PID
    let re = Regex::new(r#"PID:([0-9]+) GM:([^\r\n]+)"#).unwrap();
    let mut saw_gm_for_pid = false;
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            let ev_pid: u32 = c[1].parse().unwrap_or(0);
            if ev_pid == pid {
                let s = c[2].trim();
                if s.contains("Hello, Global!") {
                    saw_gm_for_pid = true;
                    break;
                }
            }
        }
    }
    assert!(
        saw_gm_for_pid,
        "Late-start: Expected GM string for our PID. STDOUT: {stdout}"
    );

    assert!(
        stdout.contains("GlobalState {"),
        "Late-start: Expected pretty struct output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
#[serial(globals_target)]
async fn test_t_mode_library_late_start_without_sysmon_offsets_unavailable() -> anyhow::Result<()> {
    init();
    if skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let _target_sandbox_guard = prepare_late_start_launcher(&binary_path)?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let lib_path = bin_dir.join("libgvars.so");
    let script = r#"
trace lib_tick {
    print "PID:{} SCALAR={}", $pid, LIB_STATE.counter;
    print "PID:{} STRUCT_Y={}", $pid, LIB_STATE.inner.y;
    print "PID:{} ARRAY0={}", $pid, LIB_STATE.array[0];
    print "PID:{} RODATA={}", $pid, lib_message;
    print "PID:{} MEMDUMP={:x.4}", $pid, lib_pattern;
    if memcmp(lib_message, hex("4c"), 1) { print "PID:{} CMP_OK", $pid; }
    print "PID:{} AFTER_CMP", $pid;
    print "PID:{} TAIL", $pid;
}
"#;

    let (exit_code, stdout, stderr, target, pid) = run_ghostscope_then_start_target_after_ready(
        common::runner::GhostscopeRunner::new()
            .with_script(script)
            .with_target(&lib_path)
            .timeout_secs(8)
            .enable_sysmon_shared_lib(false),
        &binary_path,
    )
    .await?;

    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let pid_marker = format!("PID:{pid}");
    let target_stdout = stdout
        .lines()
        .filter(|line| line.contains(&pid_marker))
        .collect::<Vec<_>>()
        .join("\n");
    let mut scalar_ok = false;
    let mut struct_ok = false;
    let mut array_ok = false;
    let mut rodata_ok = false;
    let mut memdump_ok = false;

    for line in stdout.lines() {
        if !line.contains(&pid_marker) {
            continue;
        }
        if line.contains("SCALAR=<proc offsets unavailable>") {
            scalar_ok = true;
        }
        if line.contains("STRUCT_Y=<proc offsets unavailable>") {
            struct_ok = true;
        }
        if line.contains("ARRAY0=<proc offsets unavailable>") {
            array_ok = true;
        }
        if line.contains("RODATA=<proc offsets unavailable>") {
            rodata_ok = true;
        }
        if line.contains("MEMDUMP=<proc offsets unavailable>") {
            memdump_ok = true;
        }
    }

    assert!(
        scalar_ok,
        "Expected SCALAR offsets unavailable for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        struct_ok,
        "Expected STRUCT_Y offsets unavailable for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        array_ok,
        "Expected ARRAY0 offsets unavailable for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        rodata_ok,
        "Expected RODATA offsets unavailable for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        memdump_ok,
        "Expected MEMDUMP offsets unavailable for PID {pid}. STDOUT: {stdout}"
    );

    assert!(
        stdout.contains("ExprError"),
        "Expected ExprError line from memcmp failure. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains(&format!("PID:{pid} AFTER_CMP")),
        "Expected AFTER_CMP marker for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains(&format!("PID:{pid} TAIL")),
        "Expected TAIL marker for PID {pid}. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains(&format!("PID:{pid} CMP_OK")),
        "memcmp should not succeed without offsets. STDOUT: {stdout}"
    );
    assert!(
        !target_stdout.contains("read_user failed"),
        "Should not surface raw read_user errors for PID {pid}. STDOUT: {stdout}"
    );

    let _ = tokio::fs::remove_file(ghostscope_log_path()?).await;

    Ok(())
}

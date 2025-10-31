//! -t (target path) mode globals tests
//! Includes both pre-start targets and late-start (GhostScope first) scenarios

mod common;

use common::{init, FIXTURES};
use ghostscope_process::is_shared_object;
use regex::Regex;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

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

// Late-start helper: run GhostScope first, then start the target process after a delay
async fn run_ghostscope_then_start_exe(
    script_content: &str,
    timeout_secs: u64,
    target_path: &std::path::Path,
    launcher_exe: &std::path::Path,
    launch_delay_ms: u64,
) -> anyhow::Result<(i32, String, String, tokio::process::Child, u32)> {
    // Spawn GhostScope in the background
    let runner = common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .with_target(target_path)
        .timeout_secs(timeout_secs);
    let gs_task = tokio::spawn(async move { runner.run().await });

    // Start target process after a small delay
    tokio::time::sleep(Duration::from_millis(launch_delay_ms)).await;
    let bin_dir = launcher_exe.parent().unwrap().to_path_buf();
    let prog = Command::new(launcher_exe)
        .current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID for late-start target"))?;

    // Wait for GhostScope to finish (timeout-based)
    let (exit_code, stdout, stderr) = gs_task
        .await
        .map_err(|e| anyhow::anyhow!("GhostScope task join error: {e}"))??;

    Ok((exit_code, stdout, stderr, prog, pid))
}

// ---------------------------------
// Pre-start (-t) tests (target first)
// ---------------------------------

#[tokio::test]
async fn test_t_mode_executable_globals_prints() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID for -t exec"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace globals_program.c:32 {
    print "PID:{} GY:{}", $pid, G_STATE.inner.y;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 5, &binary_path).await?;
    let _ = prog.kill().await.is_ok();
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
async fn test_t_mode_library_globals_prints() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let lib_path = bin_dir.join("libgvars.so");
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID for -t lib"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace lib_tick {
    print "PID:{} LC:{}", $pid, LIB_STATE.counter;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 2, &lib_path).await?;
    let _ = prog.kill().await.is_ok();
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
async fn test_t_mode_executable_rodata_and_struct_pretty() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let mut prog = Command::new(&binary_path)
        .current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID for -t rodata/struct"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // At line 26, aliases (s, ls, gm, etc.) are initialized
    let script = r#"
trace globals_program.c:26 {
    print "PID:{} GM:{:s.32}", $pid, gm;   // rodata string (explicit string format)
    print *s;                              // struct pretty print (deref pointer)
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 2, &binary_path).await?;
    let _ = prog.kill().await.is_ok();
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
async fn test_t_mode_executable_late_start_globals_prints() -> anyhow::Result<()> {
    init();

    // GhostScope starts first (-t points to the executable), then we start the process
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let script = r#"
trace globals_program.c:32 {
    print "PID:{} GY:{}", $pid, G_STATE.inner.y;
}
"#;

    let (exit_code, stdout, stderr, mut prog, pid) = run_ghostscope_then_start_exe(
        script,
        3,            // allow some time for sysmon -> prefill -> events
        &binary_path, // -t target
        &binary_path, // launcher (the same executable)
        500,          // start target 0.5s after GhostScope
    )
    .await?;

    let _ = prog.kill().await.is_ok();
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
            "Late-start: No events for our PID. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_t_mode_library_late_start_globals_prints() -> anyhow::Result<()> {
    init();

    // -t points to libgvars.so; GhostScope first, then we run the executable which loads the lib
    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    let lib_path = bin_dir.join("libgvars.so");
    let script = r#"
trace lib_tick {
    print "PID:{} LC:{}", $pid, LIB_STATE.counter;
}
"#;

    // Spawn GhostScope with saving + trace logs enabled
    let gs_task = {
        let target = lib_path.clone();
        let sc = script.to_string();
        tokio::spawn(async move {
            common::runner::GhostscopeRunner::new()
                .with_script(&sc)
                .with_target(&target)
                .timeout_secs(12)
                .with_log_level("trace")
                .enable_sysmon_shared_lib(true)
                .run()
                .await
        })
    };

    // Start the target process after a short delay
    tokio::time::sleep(Duration::from_millis(700)).await;
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID for -t lib late-start"))?;

    // Wait for GhostScope to finish
    let (exit_code, stdout, stderr) = gs_task
        .await
        .map_err(|e| anyhow::anyhow!("GhostScope task join error: {e}"))??;
    let _ = prog.kill().await.is_ok();
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
        assert!(
            !uniq.is_empty(),
            "Late-start: No events for our PID. STDOUT: {stdout}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_t_mode_executable_late_start_rodata_and_struct_pretty() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
    // At line 26, aliases (s, ls, gm, etc.) are initialized
    let script = r#"
trace globals_program.c:26 {
    print "PID:{} GM:{:s.32}", $pid, gm;   // rodata string
    print *s;                              // struct pretty print
}
"#;

    let (exit_code, stdout, stderr, mut prog, pid) =
        run_ghostscope_then_start_exe(script, 3, &binary_path, &binary_path, 500).await?;

    let _ = prog.kill().await.is_ok();
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
async fn test_t_mode_library_late_start_without_sysmon_offsets_unavailable() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("globals_program")?;
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

    let gs_task = {
        let target = lib_path.clone();
        let sc = script.to_string();
        tokio::spawn(async move {
            common::runner::GhostscopeRunner::new()
                .with_script(&sc)
                .with_target(&target)
                .timeout_secs(8)
                .enable_sysmon_shared_lib(false)
                .run()
                .await
        })
    };

    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut prog = Command::new(&binary_path)
        .current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog.id().ok_or_else(|| {
        anyhow::anyhow!("Failed to get PID for late-start shared lib without sysmon")
    })?;

    let (exit_code, stdout, stderr) = gs_task
        .await
        .map_err(|e| anyhow::anyhow!("GhostScope task join error: {e}"))??;
    let _ = prog.kill().await.is_ok();

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let pid_marker = format!("PID:{pid}");
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
        !stdout.contains("read_user failed"),
        "Should not surface raw read_user errors. STDOUT: {stdout}"
    );

    Ok(())
}

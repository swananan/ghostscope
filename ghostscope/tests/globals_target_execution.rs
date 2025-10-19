//! -t (target path) mode globals tests
//! Preconditions: target process must be started before GhostScope (no dynamic attach yet)

mod common;
use serial_test::serial;

use common::{init, FIXTURES};
use regex::Regex;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target_path: &std::path::Path,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .with_target(target_path)
        .timeout_secs(timeout_secs)
        .run()
        .await
}

#[serial]
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

#[serial]
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
        run_ghostscope_with_script_for_target(script, 5, &lib_path).await?;
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

#[serial]
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
        run_ghostscope_with_script_for_target(script, 5, &binary_path).await?;
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

// Clippy: allow some lints in tests
#![allow(
    clippy::uninlined_format_args,
    clippy::needless_borrows_for_generic_args,
    dead_code
)]

//! C++ program script execution tests (end-to-end)

mod common;

use common::{init, FIXTURES};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

async fn run_ghostscope_with_script_for_pid(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .with_pid(pid)
        .timeout_secs(timeout_secs)
        .run()
        .await
}

#[tokio::test]
async fn test_cpp_script_print_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Attach at a hot function using DW_AT_name (add), print several globals
    let script = r#"
trace add {
    print "GCNT:{}", g_counter;
    print "SINT:{}", s_internal;
    print "SVAL:{}", s_val;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.0.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    assert!(
        stdout.contains("GCNT:"),
        "Expected GCNT output. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("SINT:"),
        "Expected SINT output. STDOUT: {}",
        stdout
    );
    assert!(
        stdout.contains("SVAL:"),
        "Expected SVAL output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_cpp_script_counter_increments() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let script = r#"
trace add {
    print "CNT:{}", g_counter;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 5, pid).await?;
    let _ = prog.0.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("CNT:") {
            if let Some(num_str) = line[pos + 4..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient CNT events. STDOUT: {}",
        stdout
    );
    let mut non_decreasing = true;
    let mut has_increase = false;
    for w in vals.windows(2) {
        if w[1] < w[0] {
            non_decreasing = false;
            break;
        }
        if w[1] > w[0] {
            has_increase = true;
        }
    }
    assert!(
        non_decreasing,
        "Counter decreased unexpectedly. vals={:?}",
        vals
    );
    assert!(
        has_increase,
        "Counter did not increase across events. vals={:?}",
        vals
    );
    Ok(())
}

#[tokio::test]
async fn test_cpp_script_addresses_and_static_member() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("cpp_complex_program")?;
    let bin_dir = binary_path.parent().unwrap().to_path_buf();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(&bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let script = r#"
trace add {
    print "&GC:{}", &g_counter;  // '{}' prints pointer as hex
    print "SV:{}", s_val;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.0.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    let mut gc_addrs: Vec<String> = Vec::new();
    let mut sv_vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if let Some(pos) = t.find("&GC:") {
            if let Some(ptr) = t[pos + 4..].split_whitespace().next() {
                if ptr.starts_with("0x") {
                    gc_addrs.push(ptr.to_string());
                }
            }
        }
        if let Some(pos) = t.find("SV:") {
            if let Some(num_str) = t[pos + 3..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    sv_vals.push(v);
                }
            }
        }
    }
    assert!(
        gc_addrs.iter().any(|a| a.starts_with("0x")),
        "Expected GC address. STDOUT: {}",
        stdout
    );
    if gc_addrs.len() >= 2 {
        assert_eq!(gc_addrs[0], gc_addrs[1], "Address should be stable.");
    }
    assert!(!sv_vals.is_empty(), "Expected static member value.");
    Ok(())
}

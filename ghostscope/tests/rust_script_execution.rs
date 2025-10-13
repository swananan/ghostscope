//! Rust program script execution tests (end-to-end)

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
async fn test_rust_script_print_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let bin_dir = binary_path.parent().unwrap();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill().is_ok();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // Attach at do_stuff (DW_AT_name likely 'do_stuff'), print Rust globals and a struct field
    let script = r#"
trace do_stuff {
    print "RCNT:{}", G_COUNTER;
    print "CFA:{}", CONFIG.a;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.0.kill().await.is_ok();
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("RCNT:"),
        "Expected RCNT output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CFA:"),
        "Expected CFA output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_counter_increments() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let bin_dir = binary_path.parent().unwrap();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill().is_ok();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let script = r#"
trace do_stuff {
    print "RC:{}", G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 5, pid).await?;
    let _ = prog.0.kill().await.is_ok();
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut vals: Vec<i64> = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("RC:") {
            if let Some(num_str) = line[pos + 3..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(vals.len() >= 2, "Insufficient RC events. STDOUT: {stdout}");
    let mut non_decreasing = true;
    for w in vals.windows(2) {
        if w[1] < w[0] {
            non_decreasing = false;
            break;
        }
    }
    assert!(
        non_decreasing,
        "Counter decreased unexpectedly. vals={vals:?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_rust_script_address_of_global() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let bin_dir = binary_path.parent().unwrap();
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill().is_ok();
        }
    }
    let mut cmd = Command::new(&binary_path);
    cmd.current_dir(bin_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut prog = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let script = r#"
trace do_stuff {
    print "&RC:{}", &G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.0.kill().await.is_ok();
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("&RC:"),
        "Expected address-of output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("0x"),
        "Expected hex address. STDOUT: {stdout}"
    );
    Ok(())
}

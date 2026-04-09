//! Rust program script execution tests (end-to-end)

mod common;

use common::{init, FIXTURES};

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_shared_lib(false)
        .run()
        .await
}

async fn spawn_rust_global_program() -> anyhow::Result<common::targets::TargetHandle> {
    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("rust_global_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_rust_script_print_globals() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    // Attach at do_stuff (DW_AT_name likely 'do_stuff'), print Rust globals and a struct field
    let script = r#"
trace do_stuff {
    print "RCNT:{}", G_COUNTER;
    print "CFA:{}", CONFIG.a;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

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

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace do_stuff {
    print "RC:{}", G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
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

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace do_stuff {
    print "&RC:{}", &G_COUNTER;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
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

#[tokio::test]
async fn test_rust_script_global_enum_as_int() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;

    // Read GLOBAL_ENUM by forcing it into an integer slot via reinterpret cast.
    // This exercises the static-resolution path for globals that only have DW_OP_addr.
    let script = r#"
trace do_stuff {
    print "ENUM_RAW:{}", GLOBAL_ENUM_BITS;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut seen = false;
    for line in stdout.lines() {
        if line.contains("ENUM_RAW:") {
            seen = true;
            break;
        }
    }
    assert!(seen, "Expected ENUM_RAW output. STDOUT: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_rust_script_bss_counter_direct() -> anyhow::Result<()> {
    // Regression coverage: ensure we can read a pure .bss global (G_COUNTER) directly, without
    // relying on DWARF locals or pointer aliases.
    init();

    let target = spawn_rust_global_program().await?;

    let script = r#"
trace touch_globals {
    print "BSSCNT:{}", G_COUNTER;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut vals = Vec::new();
    for line in stdout.lines() {
        if let Some(pos) = line.find("BSSCNT:") {
            if let Some(num_str) = line[pos + "BSSCNT:".len()..].split_whitespace().next() {
                if let Ok(v) = num_str.parse::<i64>() {
                    vals.push(v);
                }
            }
        }
    }
    assert!(
        vals.len() >= 2,
        "Insufficient BSSCNT events. STDOUT: {stdout}"
    );
    for pair in vals.windows(2) {
        assert_eq!(pair[1] - pair[0], 1, "G_COUNTER should +1 per tick");
    }
    Ok(())
}

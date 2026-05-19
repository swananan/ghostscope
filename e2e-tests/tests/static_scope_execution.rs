mod common;

use common::{fixture_compiler_available, init, FixtureCompiler, FIXTURES};
use std::path::Path;
use std::time::Duration;

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

async fn spawn_static_scope_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("static_scope_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_static_scope_clang_dwarf5_runtime_static_addresses() -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping clang DWARF5 static-scope runtime test because clang is unavailable");
        return Ok(());
    }

    let binary_path = FIXTURES
        .get_test_binary_with_compiler("static_scope_program", FixtureCompiler::ClangDwarf5)?;
    let target = spawn_static_scope_program(&binary_path).await?;
    let script = r#"
trace static_scope_program.c:18 {
    print "STATIC_SCOPE:{}:{}:{}", file_scope_static_counter, function_scope_static_counter, regular_local;
    print "STATIC_SCOPE_DIV:{}:{}", file_scope_static_counter / regular_local, function_scope_static_counter / regular_local;
    print "STATIC_FUNC_PTR={:p}", &function_scope_static_counter;
    print "STATIC_FUNC_HEX={:x.0x4}", &function_scope_static_counter;
    if regular_local / 0x2 == 0x2 { print "STATIC_LOCAL_DIV_OK"; }
    if function_scope_static_counter / regular_local >= 0x8 { print "STATIC_FUNC_DIV_OK"; }
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let saw_regular_local = stdout.lines().any(|line| {
        let Some(payload) = line.trim().strip_prefix("STATIC_SCOPE:") else {
            return false;
        };
        let mut fields = payload.split(':');
        matches!(
            (fields.next(), fields.next(), fields.next(), fields.next()),
            (Some(_file_static), Some(_function_static), Some("5"), None)
        )
    });
    assert!(
        saw_regular_local,
        "Expected static-scope values and regular_local=5. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STATIC_FUNC_PTR=0x"),
        "Expected function-scope static pointer formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STATIC_FUNC_HEX="),
        "Expected function-scope static raw memory formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STATIC_SCOPE_DIV:"),
        "Expected static-scope division output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STATIC_LOCAL_DIV_OK"),
        "Expected regular local division marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("STATIC_FUNC_DIV_OK"),
        "Expected function-scope static division marker. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Static-scope runtime tracing should not emit ExprError. STDOUT: {stdout}"
    );
    Ok(())
}

mod common;

use common::{fixture_compiler_available, init, FixtureCompiler, FIXTURES};
use regex::Regex;
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
        .enable_sysmon_shared_lib(false)
        .run()
        .await
}

async fn spawn_partitioned_ranges_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("partitioned_ranges_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_partitioned_ranges_o3_hot_line_runtime_tracing() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("partitioned_ranges_program")?;
    assert_partitioned_ranges_hot_line_runtime_tracing(&binary_path).await
}

#[tokio::test]
async fn test_partitioned_ranges_clang_dwarf5_rnglistx_hot_line_runtime_tracing(
) -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5Rnglistx) {
        eprintln!(
            "Skipping clang rnglistx partitioned-ranges runtime regression: clang is unavailable"
        );
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary_with_compiler(
        "partitioned_ranges_program",
        FixtureCompiler::ClangDwarf5Rnglistx,
    )?;
    assert_partitioned_ranges_hot_line_runtime_tracing(&binary_path).await
}

async fn assert_partitioned_ranges_hot_line_runtime_tracing(
    binary_path: &Path,
) -> anyhow::Result<()> {
    let target = spawn_partitioned_ranges_program(binary_path).await?;
    let script = r#"
trace partitioned_ranges_program.c:42 {
    let next = x + 0x2;
    print "PARTITIONED_X:{}", x;
    print "PARTITIONED_CALC:{}:{}:{}", next, x * 0b11, x + -0o1;
    print "PARTITIONED_DIV:{}:{}:{}", x / 0x2, (x + -0x400) / -0b10, next / 0o3;
    if x > 0 { print "PARTITIONED_OK"; }
    if x + -0x1 >= 0 { print "PARTITIONED_NONNEG"; }
    if next - x == 0b10 { print "PARTITIONED_DELTA_OK"; }
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("PARTITIONED_X:"),
        "Expected partitioned ranges parameter output. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("PARTITIONED_OK"),
        "Expected partitioned ranges hot-line marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("PARTITIONED_NONNEG"),
        "Expected partitioned ranges non-negative arithmetic marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("PARTITIONED_DELTA_OK"),
        "Expected partitioned ranges let/arithmetic marker. STDOUT: {stdout}"
    );
    let value_re = Regex::new(r"PARTITIONED_X:([0-9-]+)")?;
    let calc_re = Regex::new(r"PARTITIONED_CALC:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let values: Vec<i64> = value_re
        .captures_iter(&stdout)
        .map(|caps| caps[1].parse::<i64>())
        .collect::<Result<_, _>>()?;
    let calcs: Vec<(i64, i64, i64)> = calc_re
        .captures_iter(&stdout)
        .map(|caps| {
            Ok((
                caps[1].parse::<i64>()?,
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let div_re = Regex::new(r"PARTITIONED_DIV:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let divs: Vec<(i64, i64, i64)> = div_re
        .captures_iter(&stdout)
        .map(|caps| {
            Ok((
                caps[1].parse::<i64>()?,
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    assert!(
        !values.is_empty() && values.len() == calcs.len() && values.len() == divs.len(),
        "Expected matching partitioned value, arithmetic, and division samples. STDOUT: {stdout}"
    );
    for ((x, (next, triple, prev)), (half, offset_div_neg_2, next_div_3)) in values
        .iter()
        .copied()
        .zip(calcs.iter().copied())
        .zip(divs.iter().copied())
    {
        assert_eq!(next, x + 2, "STDOUT: {stdout}");
        assert_eq!(triple, x * 3, "STDOUT: {stdout}");
        assert_eq!(prev, x - 1, "STDOUT: {stdout}");
        assert_eq!(half, x / 2, "STDOUT: {stdout}");
        assert_eq!(offset_div_neg_2, (x - 1024) / -2, "STDOUT: {stdout}");
        assert_eq!(next_div_3, next / 3, "STDOUT: {stdout}");
    }
    assert!(
        !stdout.contains("ExprError"),
        "Partitioned ranges tracing should not emit ExprError. STDOUT: {stdout}"
    );
    Ok(())
}

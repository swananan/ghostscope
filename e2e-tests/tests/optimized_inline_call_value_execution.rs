mod common;

use common::{init, FIXTURES};
use ghostscope_dwarf::{DirectValueResult, EvaluationResult};
use regex::Regex;
use std::path::Path;
use std::time::Duration;

// Keep this on the first executable line before consume_pair() is called.
const INLINE_BEFORE_CALL_TRACE_LINE: u32 = 20;
// Keep this on the first executable line after consume_pair() returns.
// This is intentionally a negative regression point: at this PC the inline
// parameters have already fallen out of their own location-list coverage, so
// we only assert that GhostScope does not misreport them as consume_pair's
// argument registers. We do not expect post-call value recovery to work until
// full DW_OP_entry_value + caller-side call-site evaluation is implemented.
const INLINE_AFTER_CALL_TRACE_LINE: u32 = 22;

async fn spawn_inline_call_value_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("inline_call_value_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

fn should_skip_for_ebpf_env(exit_code: i32, stderr: &str) -> bool {
    exit_code != 0
        && (stderr.contains("BPF_PROG_LOAD")
            || stderr.contains("needs elevated privileges")
            || stderr.contains("cap_bpf"))
}

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

fn assert_not_internal_call_register_aliases(
    parameters: &[ghostscope_dwarf::VariableWithEvaluation],
    address: u64,
) -> anyhow::Result<()> {
    let original_x = parameters
        .iter()
        .find(|param| param.name == "original_x")
        .ok_or_else(|| anyhow::anyhow!("missing original_x at 0x{:x}", address))?;
    let original_y = parameters
        .iter()
        .find(|param| param.name == "original_y")
        .ok_or_else(|| anyhow::anyhow!("missing original_y at 0x{:x}", address))?;

    assert_ne!(
        original_x.evaluation_result,
        EvaluationResult::DirectValue(DirectValueResult::RegisterValue(5)),
        "original_x aliased consume_pair's first argument register at 0x{address:x}: {parameters:?}"
    );
    assert_ne!(
        original_y.evaluation_result,
        EvaluationResult::DirectValue(DirectValueResult::RegisterValue(4)),
        "original_y aliased consume_pair's second argument register at 0x{address:x}: {parameters:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_have_exact_values_before_internal_call(
) -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let mut analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(
        "inline_call_value_program.c",
        INLINE_BEFORE_CALL_TRACE_LINE,
    );
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE}"
    );
    for module_address in &addrs {
        anyhow::ensure!(
            analyzer.is_inline_at(module_address) == Some(true),
            "Expected inline address at 0x{:x}",
            module_address.address
        );
    }

    let target = spawn_inline_call_value_program(&binary_path).await?;
    let script = format!(
        "trace inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE} {{\n    print \"PRECALL:{{}}:{{}}\", original_x, original_y;\n}}\n"
    );
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 4, &target).await?;
    target.terminate().await?;

    if should_skip_for_ebpf_env(exit_code, &stderr) {
        return Ok(());
    }

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        !stdout.contains("ExprError"),
        "Expected exact inline parameter values on the pre-call line. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stdout.contains("<optimized_out>"),
        "Pre-call inline parameters should not be optimized out. STDOUT: {stdout}\nSTDERR: {stderr}"
    );

    let re = Regex::new(r"PRECALL:([0-9-]+):([0-9-]+)")?;
    let mut seen = 0;
    for caps in re.captures_iter(&stdout) {
        let original_x: i64 = caps[1].parse()?;
        let original_y: i64 = caps[2].parse()?;
        assert_eq!(
            original_x,
            (original_y - 11) * 7,
            "Expected original_x/original_y to match wrapper(seed) on the pre-call line. STDOUT: {stdout}"
        );
        seen += 1;
    }

    assert!(
        seen >= 2,
        "Expected multiple pre-call inline events. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_survive_internal_call_sites() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let mut analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(
        "inline_call_value_program.c",
        INLINE_AFTER_CALL_TRACE_LINE,
    );
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for inline_call_value_program.c:{INLINE_AFTER_CALL_TRACE_LINE}"
    );
    for module_address in &addrs {
        anyhow::ensure!(
            analyzer.is_inline_at(module_address) == Some(true),
            "Expected inline address at 0x{:x}",
            module_address.address
        );
    }
    let query_results = analyzer.query_source_line_best_effort(
        "inline_call_value_program.c",
        INLINE_AFTER_CALL_TRACE_LINE,
    )?;
    anyhow::ensure!(
        !query_results.is_empty(),
        "No query results for inline_call_value_program.c:{INLINE_AFTER_CALL_TRACE_LINE}"
    );
    for result in &query_results {
        assert_not_internal_call_register_aliases(&result.parameters, result.address)?;
    }

    let target = spawn_inline_call_value_program(&binary_path).await?;
    let mut pid_analyzer = ghostscope_dwarf::DwarfAnalyzer::from_pid(target.host_pid()).await?;
    let pid_results = pid_analyzer.query_source_line_best_effort(
        "inline_call_value_program.c",
        INLINE_AFTER_CALL_TRACE_LINE,
    )?;

    anyhow::ensure!(
        !pid_results.is_empty(),
        "No PID-backed query results for inline_call_value_program.c:{INLINE_AFTER_CALL_TRACE_LINE}"
    );
    for result in &pid_results {
        assert_not_internal_call_register_aliases(&result.parameters, result.address)?;
    }
    target.terminate().await?;

    Ok(())
}

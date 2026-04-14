mod common;

use common::{init, FIXTURES};
use ghostscope_dwarf::{DirectValueResult, EvaluationResult};
use std::path::Path;
use std::time::Duration;

// Keep this on the first executable line after consume_pair() returns.
// This is intentionally a negative regression point: at this PC the inline
// parameters have already fallen out of their own location-list coverage, so
// we only assert that GhostScope does not misreport them as consume_pair's
// argument registers. We do not expect post-call value recovery to work until
// full DW_OP_entry_value + caller-side call-site evaluation is implemented.
const INLINE_AFTER_CALL_TRACE_LINE: u32 = 19;
// TODO(positive_test): Add a companion positive test on a pre-call line where
// original_x/original_y are still covered by their own location lists and can
// be asserted with exact values without relying on entry_value support.

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
        "original_x aliased consume_pair's first argument register at 0x{:x}: {:?}",
        address,
        parameters
    );
    assert_ne!(
        original_y.evaluation_result,
        EvaluationResult::DirectValue(DirectValueResult::RegisterValue(4)),
        "original_y aliased consume_pair's second argument register at 0x{:x}: {:?}",
        address,
        parameters
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
    target.terminate().await?;

    anyhow::ensure!(
        !pid_results.is_empty(),
        "No PID-backed query results for inline_call_value_program.c:{INLINE_AFTER_CALL_TRACE_LINE}"
    );
    for result in &pid_results {
        assert_not_internal_call_register_aliases(&result.parameters, result.address)?;
    }

    Ok(())
}

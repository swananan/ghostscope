mod common;

use common::{init, FIXTURES};
use ghostscope_dwarf::VariableLocation;
use regex::Regex;
use std::path::Path;
use std::time::Duration;

// Keep this on the first executable line before consume_pair() is called.
const INLINE_BEFORE_CALL_TRACE_LINE: u32 = 20;
// Keep this on the first executable line after consume_pair() returns.
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
        .enable_sysmon_for_target(false)
        .run()
        .await
}

fn assert_not_internal_call_register_aliases(
    parameters: &[ghostscope_dwarf::VisibleVariable],
    address: u64,
) -> anyhow::Result<()> {
    let original_x = parameters
        .iter()
        .find(|param| param.name == "original_x")
        .ok_or_else(|| anyhow::anyhow!("missing original_x at 0x{address:x}"))?;
    let original_y = parameters
        .iter()
        .find(|param| param.name == "original_y")
        .ok_or_else(|| anyhow::anyhow!("missing original_y at 0x{address:x}"))?;

    assert_ne!(
        original_x.location,
        VariableLocation::RegisterValue { dwarf_reg: 5 },
        "original_x aliased consume_pair's first argument register at 0x{address:x}: {parameters:?}"
    );
    assert_ne!(
        original_y.location,
        VariableLocation::RegisterValue { dwarf_reg: 4 },
        "original_y aliased consume_pair's second argument register at 0x{address:x}: {parameters:?}"
    );

    Ok(())
}

fn assert_parameters_are_live_in_registers(
    parameters: &[ghostscope_dwarf::VisibleVariable],
    address: u64,
) -> anyhow::Result<()> {
    for parameter_name in ["original_x", "original_y"] {
        let parameter = parameters
            .iter()
            .find(|param| param.name == parameter_name)
            .ok_or_else(|| anyhow::anyhow!("missing {parameter_name} at 0x{address:x}"))?;

        assert!(
            !matches!(parameter.location, VariableLocation::OptimizedOut),
            "{parameter_name} should still be live before consume_pair() at 0x{address:x}: {parameters:?}"
        );
        assert!(
            matches!(parameter.location, VariableLocation::RegisterValue { .. }),
            "{parameter_name} should resolve to a direct register value before consume_pair() at 0x{address:x}: {parameters:?}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_are_live_before_internal_call() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
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

    let query_results = analyzer.query_source_line_best_effort(
        "inline_call_value_program.c",
        INLINE_BEFORE_CALL_TRACE_LINE,
    )?;
    anyhow::ensure!(
        !query_results.is_empty(),
        "No query results for inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE}"
    );
    for result in &query_results {
        assert_parameters_are_live_in_registers(&result.parameters, result.address)?;
    }

    let target = spawn_inline_call_value_program(&binary_path).await?;
    let pid_analyzer = ghostscope_dwarf::DwarfAnalyzer::from_pid(target.host_pid()).await?;
    let pid_results = pid_analyzer.query_source_line_best_effort(
        "inline_call_value_program.c",
        INLINE_BEFORE_CALL_TRACE_LINE,
    )?;
    anyhow::ensure!(
        !pid_results.is_empty(),
        "No PID-backed query results for inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE}"
    );
    for result in &pid_results {
        assert_parameters_are_live_in_registers(&result.parameters, result.address)?;
    }
    target.terminate().await?;

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_have_exact_values_before_internal_call(
) -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
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
        "trace inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE} {{\n    print \"PRECALL:{{}}:{{}}\", original_x, original_y;\n    print \"PRECALC:{{}}:{{}}\", original_x + original_y, original_x - original_y;\n    print \"PRECALL_DIV:{{}}:{{}}\", original_x / 0b111, (original_x + -0x40) / -0x4;\n    if original_x == (original_y - 0xb) * 0x7 {{ print \"PRECALL_REL_OK\"; }}\n}}\n"
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
    let calc_re = Regex::new(r"PRECALC:([0-9-]+):([0-9-]+)")?;
    let calc_samples: Vec<(i64, i64)> = calc_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_re = Regex::new(r"PRECALL_DIV:([0-9-]+):([0-9-]+)")?;
    let div_samples: Vec<(i64, i64)> = div_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let precall_samples: Vec<(i64, i64)> = re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    assert!(
        precall_samples.len() == calc_samples.len() && precall_samples.len() == div_samples.len(),
        "Expected matching pre-call value, arithmetic, and division samples. STDOUT: {stdout}"
    );
    for ((original_x, original_y), (sum, diff), (x_div_7, shifted_div_neg_4)) in precall_samples
        .iter()
        .copied()
        .zip(calc_samples.iter().copied())
        .zip(div_samples.iter().copied())
        .map(|((values, calc), div)| (values, calc, div))
    {
        assert_eq!(
            original_x,
            (original_y - 11) * 7,
            "Expected original_x/original_y to match wrapper(seed) on the pre-call line. STDOUT: {stdout}"
        );
        assert_eq!(sum, original_x + original_y, "STDOUT: {stdout}");
        assert_eq!(diff, original_x - original_y, "STDOUT: {stdout}");
        assert_eq!(x_div_7, original_x / 7, "STDOUT: {stdout}");
        assert_eq!(
            shifted_div_neg_4,
            (original_x - 64) / -4,
            "STDOUT: {stdout}"
        );
    }

    assert!(
        precall_samples.len() >= 2,
        "Expected multiple pre-call inline events. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("PRECALL_REL_OK"),
        "Expected pre-call inline computed relation marker. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_optimized_out_local_print_emits_marker_at_runtime() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let query_results = analyzer.query_source_line_best_effort(
        "inline_call_value_program.c",
        INLINE_BEFORE_CALL_TRACE_LINE,
    )?;
    anyhow::ensure!(
        query_results.iter().any(|result| {
            result.variables.iter().any(|variable| {
                variable.name == "local_x"
                    && matches!(variable.location, VariableLocation::OptimizedOut)
            })
        }),
        "Expected local_x to be visible but optimized out at inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE}: {query_results:?}"
    );

    let target = spawn_inline_call_value_program(&binary_path).await?;
    let script = format!(
        "trace inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE} {{\n    print local_x;\n}}\n"
    );
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 4, &target).await?;
    target.terminate().await?;

    if should_skip_for_ebpf_env(exit_code, &stderr) {
        return Ok(());
    }

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("<optimized out>") || stdout.contains("<optimized_out>"),
        "Expected direct print of optimized-out local_x to emit an optimized-out marker. STDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_optimized_out_local_value_expression_is_rejected() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let target = spawn_inline_call_value_program(&binary_path).await?;
    let script = format!(
        "trace inline_call_value_program.c:{INLINE_BEFORE_CALL_TRACE_LINE} {{\n    if local_x == 0 {{ print \"VALUE\"; }}\n}}\n"
    );
    let (_exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 3, &target).await?;
    target.terminate().await?;

    let has_banner = stderr.contains("Script compilation failed")
        || stderr.contains("No uprobe configurations created");
    let has_message =
        stderr.contains("local_x") && stderr.contains("optimized out at the selected probe PC");
    assert!(
        has_banner && has_message,
        "Expected optimized-out local_x to be rejected in a value expression.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_survive_internal_call_sites() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
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
    let pid_analyzer = ghostscope_dwarf::DwarfAnalyzer::from_pid(target.host_pid()).await?;
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

#[tokio::test]
async fn test_entry_value_recovers_outer_parameter_inside_optimized_inline_after_internal_call(
) -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
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

    let target = spawn_inline_call_value_program(&binary_path).await?;
    let script = format!(
        "trace inline_call_value_program.c:{INLINE_AFTER_CALL_TRACE_LINE} {{\n    print \"POSTCALL:{{}}:{{}}\", seed, after_call;\n    print \"POSTCALC:{{}}:{{}}\", seed * 0x7, after_call - 0b111;\n    print \"POSTDIV:{{}}:{{}}\", after_call / 0x5, (after_call + -0x7) / -0x3;\n    if after_call > seed {{ print \"POSTCALL_GT_SEED\"; }}\n}}\n"
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
        "Expected exact entry_value recovery inside the inline body. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stdout.contains("<optimized_out>"),
        "Inline post-call entry_value should not be optimized out. STDOUT: {stdout}\nSTDERR: {stderr}"
    );

    let re = Regex::new(r"POSTCALL:([0-9-]+):([0-9-]+)")?;
    let calc_re = Regex::new(r"POSTCALC:([0-9-]+):([0-9-]+)")?;
    let calc_samples: Vec<(i64, i64)> = calc_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_re = Regex::new(r"POSTDIV:([0-9-]+):([0-9-]+)")?;
    let div_samples: Vec<(i64, i64)> = div_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let postcall_samples: Vec<(i64, i64)> = re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    assert!(
        postcall_samples.len() == calc_samples.len() && postcall_samples.len() == div_samples.len(),
        "Expected matching post-call value, arithmetic, and division samples. STDOUT: {stdout}"
    );
    for ((seed, after_call), (seed_times_7, after_minus_7), (after_div_5, combined_div_neg_3)) in
        postcall_samples
            .iter()
            .copied()
            .zip(calc_samples.iter().copied())
            .zip(div_samples.iter().copied())
            .map(|((values, calc), div)| (values, calc, div))
    {
        let original_x = seed * 7;
        let original_y = seed + 11;
        let combined = (original_x + original_y) * (original_x - original_y);
        assert_eq!(
            after_call,
            combined + 7,
            "Expected seed/after_call to match wrapper(seed) on the first post-call line. STDOUT: {stdout}"
        );
        assert_eq!(seed_times_7, original_x, "STDOUT: {stdout}");
        assert_eq!(after_minus_7, combined, "STDOUT: {stdout}");
        assert_eq!(after_div_5, after_call / 5, "STDOUT: {stdout}");
        assert_eq!(combined_div_neg_3, combined / -3, "STDOUT: {stdout}");
    }

    assert!(
        postcall_samples.len() >= 2,
        "Expected multiple post-call entry_value events. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        stdout.contains("POSTCALL_GT_SEED"),
        "Expected post-call entry_value computed comparison marker. STDOUT: {stdout}"
    );
    Ok(())
}

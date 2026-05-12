mod common;

use common::{init, FIXTURES};
use regex::Regex;
use std::path::Path;
use std::time::Duration;

// Keep this on the first executable line inside add3's inline body.
const INLINE_TRACE_LINE: u32 = 43;
// Keep this on the nested executable line inside consume_state's inline body.
const INLINE_STATE_TRACE_LINE: u32 = 71;

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

async fn spawn_inline_callsite_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("inline_callsite_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_optimized_inline_parameters_preserve_callsite_relationships() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_callsite_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for inline_callsite_program: {}", e))?;
    let addrs =
        analyzer.lookup_addresses_by_source_line("inline_callsite_program.c", INLINE_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for inline_callsite_program.c:{INLINE_TRACE_LINE}"
    );

    // Scenario this test is meant to cover:
    //
    //   dwarfdump inline_callsite_program | rg \
    //     'DW_TAG_(subprogram|inlined_subroutine|formal_parameter|lexical_block)' -A5 -B2
    //
    // This fixture produces an optimized wrapper() that contains an inlined
    // add3(a, b, c) body. The traced source line is inside that inline body,
    // so correct behavior is:
    //   1. we attach to the inlined line successfully
    //   2. we recover all three inline parameters a/b/c
    //   3. nested lexical scope inside the inline body does not disturb that recovery
    //
    //   wrapper
    //     inlined_subroutine
    //       formal_parameter
    //       formal_parameter
    //       formal_parameter
    //       lexical_block
    //
    //   add3
    //     formal_parameter a
    //     formal_parameter b
    //     formal_parameter c
    //     lexical_block
    let target = spawn_inline_callsite_program(&binary_path).await?;
    let script = format!(
        "trace inline_callsite_program.c:{INLINE_TRACE_LINE} {{\n    print \"ARGS:{{}}:{{}}:{{}}\", a, b, c;\n    print \"ARGDIV:{{}}:{{}}:{{}}\", a / 0x2, (b + -0b11) / -0x2, c / 0o3;\n}}\n"
    );
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 4, &target).await?;
    target.terminate().await?;

    if should_skip_for_ebpf_env(exit_code, &stderr) {
        return Ok(());
    }

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let re = Regex::new(r"ARGS:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let div_re = Regex::new(r"ARGDIV:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let arg_samples: Vec<(i64, i64, i64)> = re
        .captures_iter(&stdout)
        .map(|caps| {
            Ok((
                caps[1].parse::<i64>()?,
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let div_samples: Vec<(i64, i64, i64)> = div_re
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
        arg_samples.len() == div_samples.len(),
        "Expected matching inline arg and division samples. STDOUT: {stdout}"
    );
    for ((a, b, c), (a_div_2, b_shift_div_neg_2, c_div_3)) in
        arg_samples.iter().copied().zip(div_samples.iter().copied())
    {
        assert_eq!(b, a + 1, "Expected b == a + 1. STDOUT: {stdout}");
        assert_eq!(c, a + 2, "Expected c == a + 2. STDOUT: {stdout}");
        assert_eq!(a_div_2, a / 2, "STDOUT: {stdout}");
        assert_eq!(b_shift_div_neg_2, (b - 3) / -2, "STDOUT: {stdout}");
        assert_eq!(c_div_3, c / 3, "STDOUT: {stdout}");
    }

    assert!(
        arg_samples.len() >= 2,
        "Expected multiple inline arg events. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_parameters_do_not_degrade_to_expr_errors() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_callsite_program")?;
    let target = spawn_inline_callsite_program(&binary_path).await?;
    // This companion assertion keeps the same inline scenario, but checks the
    // user-visible failure mode: even if attachment succeeds, inline parameter
    // recovery should not degrade into missing values, ExprError, or
    // optimized-out placeholders.
    let script = format!(
        "trace inline_callsite_program.c:{INLINE_TRACE_LINE} {{\n    print \"INLINE_OK:{{}}:{{}}:{{}}\", a, b, c;\n}}\n"
    );
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 4, &target).await?;
    target.terminate().await?;

    if should_skip_for_ebpf_env(exit_code, &stderr) {
        return Ok(());
    }

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("INLINE_OK:"),
        "Expected inline parameter output. STDOUT: {stdout}\nSTDERR: {stderr}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Inline parameter recovery should not emit ExprError. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("<optimized_out>"),
        "Inline parameters should not degrade to optimized-out placeholders. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_struct_member_access_resolves_inline_parameter_names(
) -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_callsite_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for inline_callsite_program: {}", e))?;
    let addrs = analyzer
        .lookup_addresses_by_source_line("inline_callsite_program.c", INLINE_STATE_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for inline_callsite_program.c:{INLINE_STATE_TRACE_LINE}"
    );
    for module_address in &addrs {
        let pc_context = analyzer.resolve_pc(module_address)?;
        let access_path = ghostscope_dwarf::VariableAccessPath::fields(["total_bytes".to_string()]);
        let planned = analyzer
            .plan_variable_access_by_name(&pc_context, "state", &access_path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "exec-path plan_variable_access_by_name failed for 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            planned.is_some(),
            "exec-path plan_variable_access_by_name returned None for 0x{:x}",
            module_address.address
        );
    }

    let target = spawn_inline_callsite_program(&binary_path).await?;
    // The analyzer runs in the host test process, so it must inspect the host PID.
    // `visible_pid_from(observer)` is only correct for processes that actually run
    // inside the observer sandbox, such as GhostScope itself.
    let pid_analyzer = ghostscope_dwarf::DwarfAnalyzer::from_pid(target.host_pid()).await?;
    let pid_addrs = pid_analyzer
        .lookup_addresses_by_source_line("inline_callsite_program.c", INLINE_STATE_TRACE_LINE);
    anyhow::ensure!(
        !pid_addrs.is_empty(),
        "No PID-backed DWARF addresses found for inline_callsite_program.c:{INLINE_STATE_TRACE_LINE}"
    );
    for module_address in &pid_addrs {
        let pc_context = pid_analyzer.resolve_pc(module_address)?;
        let access_path = ghostscope_dwarf::VariableAccessPath::fields(["total_bytes".to_string()]);
        let planned = pid_analyzer
            .plan_variable_access_by_name(&pc_context, "state", &access_path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "pid-backed plan_variable_access_by_name failed for 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            planned.is_some(),
            "pid-backed plan_variable_access_by_name returned None for 0x{:x}",
            module_address.address
        );
    }
    let script = format!(
        "trace inline_callsite_program.c:{INLINE_STATE_TRACE_LINE} {{\n    let dyn_zero = delta - delta;\n    let state_dyn = state + dyn_zero;\n    print \"STATE:{{}}:{{}}\", state.total_bytes, state.stream_id;\n    print \"STATE_DIV:{{}}:{{}}\", state.total_bytes / 0xa, (state.stream_id + -0x10) / -0x7;\n    print \"STATE_DYN:{{}}:{{}}\", state_dyn.total_bytes, state[dyn_zero].stream_id;\n    print \"STATE_DYN_DIV:{{}}:{{}}\", state_dyn.total_bytes / 0xa, state_dyn[dyn_zero].stream_id / 0x1;\n}}\n"
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
        "Inline member access should not emit ExprError. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("<optimized_out>"),
        "Inline member access should not degrade to optimized-out placeholders. STDOUT: {stdout}"
    );

    let re = Regex::new(r"STATE:([0-9-]+):([0-9-]+)")?;
    let div_re = Regex::new(r"STATE_DIV:([0-9-]+):([0-9-]+)")?;
    let dyn_re = Regex::new(r"STATE_DYN:([0-9-]+):([0-9-]+)")?;
    let dyn_div_re = Regex::new(r"STATE_DYN_DIV:([0-9-]+):([0-9-]+)")?;
    let state_samples: Vec<(i64, i64)> = re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_samples: Vec<(i64, i64)> = div_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let dyn_samples: Vec<(i64, i64)> = dyn_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let dyn_div_samples: Vec<(i64, i64)> = dyn_div_re
        .captures_iter(&stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    assert!(
        state_samples.len() == div_samples.len()
            && state_samples.len() == dyn_samples.len()
            && state_samples.len() == dyn_div_samples.len(),
        "Expected matching inline state, dynamic state, and division samples. STDOUT: {stdout}"
    );
    for (
        ((total_bytes, stream_id), (total_div_10, stream_shift_div_neg_7)),
        ((dyn_total, dyn_stream), (dyn_total_div_10, dyn_stream_div_1)),
    ) in state_samples
        .iter()
        .copied()
        .zip(div_samples.iter().copied())
        .zip(
            dyn_samples
                .iter()
                .copied()
                .zip(dyn_div_samples.iter().copied()),
        )
    {
        assert_eq!(
            total_bytes,
            (stream_id - 7) * 10,
            "Expected state.total_bytes == (state.stream_id - 7) * 10. STDOUT: {stdout}"
        );
        assert_eq!(dyn_total, total_bytes, "STDOUT: {stdout}");
        assert_eq!(dyn_stream, stream_id, "STDOUT: {stdout}");
        assert_eq!(total_div_10, total_bytes / 10, "STDOUT: {stdout}");
        assert_eq!(
            stream_shift_div_neg_7,
            (stream_id - 16) / -7,
            "STDOUT: {stdout}"
        );
        assert_eq!(dyn_total_div_10, total_bytes / 10, "STDOUT: {stdout}");
        assert_eq!(dyn_stream_div_1, stream_id, "STDOUT: {stdout}");
    }

    assert!(
        state_samples.len() >= 2,
        "Expected multiple inline struct member events. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_optimized_inline_struct_pointer_memory_formats() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("inline_callsite_program")?;
    let target = spawn_inline_callsite_program(&binary_path).await?;
    let script = format!(
        "trace inline_callsite_program.c:{INLINE_STATE_TRACE_LINE} {{\n    print \"INLINE_STATE_PTR={{:p}}\", state + 0;\n    print \"INLINE_STATE_HEX={{:x.0x8}}\", state + 0;\n    if memcmp(state + 0, hex(\"1400000009000000\"), 0b1000) {{ print \"INLINE_STATE_MEM_OK\"; }}\n}}\n"
    );
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 4, &target).await?;
    target.terminate().await?;

    if should_skip_for_ebpf_env(exit_code, &stderr) {
        return Ok(());
    }

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("INLINE_STATE_PTR=0x"),
        "Expected inline state pointer formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("INLINE_STATE_HEX=14 00 00 00 09 00 00 00"),
        "Expected inline state raw memory bytes. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("INLINE_STATE_MEM_OK"),
        "Expected inline state memcmp marker. STDOUT: {stdout}"
    );

    Ok(())
}

mod common;

use common::{init, OptimizationLevel, FIXTURES};

const TRACE_LINE: u32 = 68;

async fn compile_member_pointer_script(
    script: &str,
    opt_level: OptimizationLevel,
) -> anyhow::Result<ghostscope_compiler::CompilationResult> {
    let binary_path = FIXTURES.get_test_binary_with_opt("member_pointer_program", opt_level)?;
    let mut analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let compile_options = ghostscope_compiler::CompileOptions {
        binary_path_hint: Some(binary_path.to_string_lossy().into_owned()),
        ..Default::default()
    };

    ghostscope_compiler::compile_script(script, &mut analyzer, None, Some(1), &compile_options)
        .map_err(|e| anyhow::anyhow!("compile_script failed: {e}"))
}

#[tokio::test]
async fn test_member_pointer_planner_resolves_o2_chain_accesses() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let mut analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );

    for module_address in &addrs {
        let key_data = analyzer
            .plan_chain_access(
                module_address,
                "h",
                &["key".to_string(), "data".to_string()],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "plan_chain_access failed for h.key.data at 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            key_data.is_some(),
            "plan_chain_access returned None for h.key.data at 0x{:x}",
            module_address.address
        );

        let header_pos = analyzer
            .plan_chain_access(
                module_address,
                "r",
                &["header_in".to_string(), "pos".to_string()],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "plan_chain_access failed for r.header_in.pos at 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            header_pos.is_some(),
            "plan_chain_access returned None for r.header_in.pos at 0x{:x}",
            module_address.address
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_memcmp_infers_len_for_member_pointer_key_data_o2() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let source_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("member_pointer_program has no parent directory"))?
        .join("member_pointer_program.c");
    let script = format!(
        r#"
trace {}:68 {{
    if memcmp(h.key.data, hex("58 2d")) {{ print "HDR_OK"; }}
}}
"#,
        source_path.display()
    );

    let result = compile_member_pointer_script(&script, OptimizationLevel::O2).await?;
    assert!(
        !result.uprobe_configs.is_empty(),
        "expected at least one compiled uprobe config; target_info={} failed_targets={:?}",
        result.target_info,
        result.failed_targets
    );
    Ok(())
}

#[tokio::test]
async fn test_memcmp_infers_len_for_member_pointer_key_data_o0() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::Debug)?;
    let source_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("member_pointer_program has no parent directory"))?
        .join("member_pointer_program.c");
    let script = format!(
        r#"
trace {}:68 {{
    if memcmp(h.key.data, hex("58 2d")) {{ print "HDR_OK"; }}
}}
"#,
        source_path.display()
    );

    let result = compile_member_pointer_script(&script, OptimizationLevel::Debug).await?;
    assert!(
        !result.uprobe_configs.is_empty(),
        "expected at least one compiled uprobe config; target_info={} failed_targets={:?}",
        result.target_info,
        result.failed_targets
    );
    Ok(())
}

#[tokio::test]
async fn test_memcmp_infers_len_for_member_pointer_buffer_pos_o2() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let source_path = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("member_pointer_program has no parent directory"))?
        .join("member_pointer_program.c");
    let script = format!(
        r#"
trace {}:68 {{
    if memcmp(r.header_in.pos, hex("00 01 02")) {{ print "BODY_OK"; }}
}}
"#,
        source_path.display()
    );

    let result = compile_member_pointer_script(&script, OptimizationLevel::O2).await?;
    assert!(
        !result.uprobe_configs.is_empty(),
        "expected at least one compiled uprobe config; target_info={} failed_targets={:?}",
        result.target_info,
        result.failed_targets
    );
    Ok(())
}

#[tokio::test]
async fn test_member_pointer_fixture_builds_each_optimized_variant() -> anyhow::Result<()> {
    init();

    for opt_level in [
        OptimizationLevel::O2,
        OptimizationLevel::O1,
        OptimizationLevel::O3,
    ] {
        let binary_path = FIXTURES.get_test_binary_with_opt("member_pointer_program", opt_level)?;
        anyhow::ensure!(
            binary_path.exists(),
            "expected compiled fixture for {:?} at {}",
            opt_level,
            binary_path.display()
        );
        let _ = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to load DWARF for member_pointer_program {:?}: {e}",
                    opt_level
                )
            })?;
    }

    Ok(())
}

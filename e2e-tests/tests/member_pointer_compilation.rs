mod common;

use common::{init, OptimizationLevel, FIXTURES};

const TRACE_LINE: u32 = 68;
const VALUE_BACKED_AGGREGATE_LINE: u32 = 84;
const SHADOWED_STATE_LINE: u32 = 94;

fn field_path(fields: &[&str]) -> ghostscope_dwarf::VariableAccessPath {
    ghostscope_dwarf::VariableAccessPath::fields(fields.iter().map(|field| (*field).to_string()))
}

async fn compile_member_pointer_script(
    script: &str,
    opt_level: OptimizationLevel,
) -> anyhow::Result<ghostscope_compiler::CompilationResult> {
    compile_member_pointer_script_result(script, opt_level)
        .await?
        .map_err(|e| anyhow::anyhow!("compile_script failed: {e}"))
}

async fn compile_member_pointer_script_result(
    script: &str,
    opt_level: OptimizationLevel,
) -> anyhow::Result<
    std::result::Result<ghostscope_compiler::CompilationResult, ghostscope_compiler::CompileError>,
> {
    let binary_path = FIXTURES.get_test_binary_with_opt("member_pointer_program", opt_level)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let compile_options = ghostscope_compiler::CompileOptions {
        binary_path_hint: Some(binary_path.to_string_lossy().into_owned()),
        ..Default::default()
    };

    Ok(ghostscope_compiler::compile_script(
        script,
        &analyzer,
        None,
        Some(1),
        &compile_options,
    ))
}

async fn compile_member_pointer_failure_message(
    script: &str,
    opt_level: OptimizationLevel,
) -> anyhow::Result<String> {
    match compile_member_pointer_script_result(script, opt_level).await? {
        Ok(result) => {
            anyhow::ensure!(
                result.uprobe_configs.is_empty(),
                "invalid script should not produce uprobe configs: {result:?}"
            );
            anyhow::ensure!(
                !result.failed_targets.is_empty(),
                "invalid script should report failed targets: {result:?}"
            );
            Ok(result
                .failed_targets
                .iter()
                .map(|target| target.error_message.as_str())
                .collect::<Vec<_>>()
                .join("\n"))
        }
        Err(err) => Ok(err.user_message().into_owned()),
    }
}

async fn member_pointer_pc(opt_level: OptimizationLevel) -> anyhow::Result<u64> {
    let binary_path = FIXTURES.get_test_binary_with_opt("member_pointer_program", opt_level)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );
    Ok(addrs[0].address)
}

fn member_pointer_source_path(opt_level: OptimizationLevel) -> anyhow::Result<std::path::PathBuf> {
    let binary_path = FIXTURES.get_test_binary_with_opt("member_pointer_program", opt_level)?;
    Ok(binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("member_pointer_program has no parent directory"))?
        .join("member_pointer_program.c"))
}

#[tokio::test]
async fn test_member_pointer_planner_resolves_o2_chain_accesses() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );

    for module_address in &addrs {
        let pc_context = analyzer.resolve_pc(module_address)?;
        let key_data = analyzer
            .plan_variable_access_by_name(&pc_context, "h", &field_path(&["key", "data"]))
            .map_err(|e| {
                anyhow::anyhow!(
                    "plan_variable_access_by_name failed for h.key.data at 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            key_data.is_some(),
            "plan_variable_access_by_name returned None for h.key.data at 0x{:x}",
            module_address.address
        );

        let header_pos = analyzer
            .plan_variable_access_by_name(&pc_context, "r", &field_path(&["header_in", "pos"]))
            .map_err(|e| {
                anyhow::anyhow!(
                    "plan_variable_access_by_name failed for r.header_in.pos at 0x{:x}: {}",
                    module_address.address,
                    e
                )
            })?;
        anyhow::ensure!(
            header_pos.is_some(),
            "plan_variable_access_by_name returned None for r.header_in.pos at 0x{:x}",
            module_address.address
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_resolve_pc_context_reports_source_and_function() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );

    let ctx = analyzer.resolve_pc(&addrs[0])?;
    assert_eq!(ctx.module, ghostscope_dwarf::ModuleId(0));
    assert_eq!(ctx.pc, addrs[0].address);
    assert_eq!(ctx.normalized_pc, addrs[0].address);
    assert_eq!(ctx.function_name.as_deref(), Some("trace_member_pointer"));
    assert!(ctx.cu.is_some(), "PC context should carry a CU id: {ctx:?}");
    let function = ctx.function.expect("PC context should carry a function id");
    assert_eq!(function.declaration.module, ctx.module);
    assert_eq!(function.declaration.cu, ctx.cu.expect("CU id"));
    assert_eq!(ctx.is_inline, Some(false));
    assert!(
        ctx.inline_chain.is_empty(),
        "non-inline trace point should not report inline frames: {ctx:?}"
    );
    assert_eq!(
        ctx.address_space.module_path.as_deref(),
        Some(binary_path.as_path())
    );

    let line = ctx.line.expect("PC context should include source line");
    assert!(
        line.file_path.ends_with("member_pointer_program.c"),
        "unexpected source file: {}",
        line.file_path
    );
    assert!(
        (TRACE_LINE..=TRACE_LINE + 1).contains(&line.line_number),
        "unexpected source line: {}",
        line.line_number
    );

    Ok(())
}

#[tokio::test]
async fn test_visible_variables_consumes_pc_context() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );

    let ctx = analyzer.resolve_pc(&addrs[0])?;
    let ghostscope_dwarf::VisibleVariablesResult {
        variables,
        diagnostics,
    } = analyzer.visible_variables_with_diagnostics(&ctx)?;

    assert!(
        variables.iter().any(|var| {
            var.name == "r"
                && var.availability.is_available()
                && var.dwarf_type.is_some()
                && !var.is_artificial
        }),
        "expected visible available variable 'r'. Variables: {variables:?}"
    );
    assert!(
        variables.iter().any(|var| {
            var.name == "h"
                && var.availability.is_available()
                && var.dwarf_type.is_some()
                && !var.is_artificial
        }),
        "expected visible available variable 'h'. Variables: {variables:?}"
    );
    assert!(
        diagnostics
            .iter()
            .all(|diagnostic| diagnostic.pc == ctx.normalized_pc),
        "diagnostics should be tied to the queried PC: {diagnostics:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_plan_variable_by_name_uses_pc_context() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("member_pointer_program.c", TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{TRACE_LINE}"
    );

    let ctx = analyzer.resolve_pc(&addrs[0])?;
    let plan = analyzer
        .plan_variable_by_name(&ctx, "r")?
        .ok_or_else(|| anyhow::anyhow!("expected variable read plan for 'r'"))?;

    assert_eq!(plan.name, "r");
    assert!(plan.availability.is_available(), "plan: {plan:?}");
    assert!(plan.dwarf_type.is_some(), "plan: {plan:?}");
    assert!(plan.declaration.is_some(), "plan: {plan:?}");
    assert!(plan.type_id.is_some(), "plan: {plan:?}");
    assert!(!plan.is_artificial, "plan: {plan:?}");
    assert!(analyzer
        .plan_variable_by_name(&ctx, "__ghostscope_missing")?
        .is_none());

    let variable_id = ghostscope_dwarf::VariableId {
        declaration: plan
            .declaration
            .expect("plan_variable_by_name should carry declaration id"),
    };
    let plan_by_id = analyzer
        .plan_variable(&ctx, variable_id)?
        .ok_or_else(|| anyhow::anyhow!("expected variable read plan by id for 'r'"))?;
    assert_eq!(plan_by_id.name, plan.name);
    assert_eq!(plan_by_id.declaration, plan.declaration);
    assert_eq!(plan_by_id.type_id, plan.type_id);

    let id_header_pos = analyzer
        .plan_variable_access(
            &ctx,
            variable_id,
            &ghostscope_dwarf::VariableAccessPath::fields(["header_in", "pos"]),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected id-based access plan for 'r.header_in.pos'"))?;
    assert_eq!(id_header_pos.name, "r.header_in.pos");
    assert!(id_header_pos.availability.is_available());
    assert!(id_header_pos.dwarf_type.is_some());

    let header_pos = analyzer
        .plan_variable_access_by_name(
            &ctx,
            "r",
            &ghostscope_dwarf::VariableAccessPath::fields(["header_in", "pos"]),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected access plan for 'r.header_in.pos'"))?;

    assert_eq!(header_pos.name, "r.header_in.pos");
    assert!(
        header_pos.availability.is_available(),
        "access plan: {header_pos:?}"
    );
    assert!(
        header_pos.dwarf_type.is_some(),
        "access plan should carry final member type: {header_pos:?}"
    );

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
    assert_eq!(
        result.trace_count,
        result.uprobe_configs.len(),
        "trace_count should report generated uprobe configs"
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
async fn test_local_unknown_member_reports_compile_error_o2() -> anyhow::Result<()> {
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
    print r.no_such_member;
}}
"#,
        source_path.display()
    );

    let result = compile_member_pointer_script(&script, OptimizationLevel::O2).await?;
    assert!(
        result.uprobe_configs.is_empty(),
        "invalid member access should not produce uprobe configs: {result:?}"
    );
    assert!(
        !result.failed_targets.is_empty(),
        "invalid member access should report failed targets: {result:?}"
    );
    let message = result
        .failed_targets
        .iter()
        .map(|target| target.error_message.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        message.contains("Unknown member 'no_such_member'"),
        "unexpected compile error: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn test_value_backed_aggregate_member_access_is_rejected_o2() -> anyhow::Result<()> {
    init();

    let source_path = member_pointer_source_path(OptimizationLevel::O2)?;
    let script = format!(
        r#"
trace {}:{VALUE_BACKED_AGGREGATE_LINE} {{
    print s.b;
}}
"#,
        source_path.display()
    );

    let message = compile_member_pointer_failure_message(&script, OptimizationLevel::O2).await?;
    assert!(
        message.contains("value-backed aggregate")
            || message.contains("field/array extraction from aggregate values is not implemented"),
        "unexpected compile error: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn test_value_backed_aggregate_dw_op_piece_surfaces_composite_o2() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for member_pointer_program: {e}"))?;
    let addrs = analyzer
        .lookup_addresses_by_source_line("member_pointer_program.c", VALUE_BACKED_AGGREGATE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for member_pointer_program.c:{VALUE_BACKED_AGGREGATE_LINE}"
    );

    for module_address in &addrs {
        let pc_context = analyzer.resolve_pc(module_address)?;
        let plan = analyzer
            .plan_variable_by_name(&pc_context, "s")?
            .ok_or_else(|| anyhow::anyhow!("expected variable read plan for 's'"))?;

        assert!(
            plan.availability.is_available(),
            "composite variable should remain available at 0x{:x}: {plan:?}",
            module_address.address
        );

        let ghostscope_dwarf::VariableLocation::Pieces(pieces) = &plan.location else {
            panic!(
                "expected DW_OP_piece-backed composite for 's' at 0x{:x}, got {:?}",
                module_address.address, plan.location
            );
        };

        assert_eq!(pieces.len(), 2, "unexpected composite pieces: {pieces:?}");
        for (piece, bit_offset, constant) in [(&pieces[0], 0, 1), (&pieces[1], 32, 2)] {
            assert_eq!(piece.bit_offset, bit_offset);
            assert_eq!(piece.bit_size, 32);
            assert_eq!(
                piece.location.as_ref(),
                &ghostscope_dwarf::VariableLocation::ComputedValue(vec![
                    ghostscope_dwarf::PlanExprOp::LoadRegister(5),
                    ghostscope_dwarf::PlanExprOp::PushConstant(constant),
                    ghostscope_dwarf::PlanExprOp::Add,
                ])
            );
        }

        let materialized =
            plan.materialization_plan(&ghostscope_dwarf::RuntimeCapabilities::default());
        assert_eq!(
            materialized.lowering.kind,
            ghostscope_dwarf::VariableLoweringKind::Composite
        );
        match materialized.materialization {
            ghostscope_dwarf::VariableMaterialization::Composite { pieces } => {
                assert_eq!(pieces.len(), 2);
            }
            other => panic!("expected composite materialization, got {other:?}"),
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_value_backed_aggregate_print_rejects_split_pieces_o2() -> anyhow::Result<()> {
    init();

    let source_path = member_pointer_source_path(OptimizationLevel::O2)?;
    let script = format!(
        r#"
trace {}:{VALUE_BACKED_AGGREGATE_LINE} {{
    print s;
}}
"#,
        source_path.display()
    );

    let message = compile_member_pointer_failure_message(&script, OptimizationLevel::O2).await?;
    assert!(
        message.contains("split across pieces")
            && message.contains("piece reconstruction is not implemented"),
        "unexpected compile error: {message}"
    );
    assert!(
        !message.contains("DW_OP_piece"),
        "DW_OP_piece should lower before compiler rejection: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn test_shadowed_unavailable_inner_variable_is_not_outer_fallback_o2() -> anyhow::Result<()> {
    init();

    let source_path = member_pointer_source_path(OptimizationLevel::O2)?;
    let script = format!(
        r#"
trace {}:{SHADOWED_STATE_LINE} {{
    print state;
}}
"#,
        source_path.display()
    );

    let result = compile_member_pointer_script(&script, OptimizationLevel::O2).await?;
    assert!(
        !result.uprobe_configs.is_empty(),
        "shadowed optimized-out variable should still compile a reporting probe: {result:?}"
    );
    assert!(
        result.failed_targets.is_empty(),
        "optimized-out reporting should not create failed targets: {result:?}"
    );
    for config in &result.uprobe_configs {
        assert_eq!(
            config.trace_context.variable_names,
            vec!["state".to_string()],
            "unexpected trace variable names: {:?}",
            config.trace_context.variable_names
        );
        assert!(
            matches!(
                config.trace_context.types.as_slice(),
                [ghostscope_dwarf::TypeInfo::OptimizedOut { name }] if name == "state"
            ),
            "shadowed inner variable should be marked optimized out, not lowered as the outer value: {:?}",
            config.trace_context.types
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_direct_address_unknown_member_returns_compile_error_o2() -> anyhow::Result<()> {
    init();

    let pc = member_pointer_pc(OptimizationLevel::O2).await?;
    let script = format!(
        r#"
trace 0x{pc:x} {{
    print r.no_such_member;
}}
"#
    );

    let err = compile_member_pointer_script_result(&script, OptimizationLevel::O2)
        .await?
        .expect_err("invalid direct-address member access should fail compile_script");
    let message = err.user_message().into_owned();

    assert!(
        message.contains("Failed targets:"),
        "expected failed-target details in compile error: {message}"
    );
    assert!(
        message.contains(&format!("0x{pc:x}")),
        "expected direct address target in compile error: {message}"
    );
    assert!(
        message.contains("Unknown member 'no_such_member'"),
        "unexpected compile error: {message}"
    );
    Ok(())
}

#[tokio::test]
async fn test_module_address_unknown_member_returns_compile_error_o2() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("member_pointer_program", OptimizationLevel::O2)?;
    let module = binary_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("member_pointer_program has no file name"))?
        .to_string_lossy();
    let pc = member_pointer_pc(OptimizationLevel::O2).await?;
    let script = format!(
        r#"
trace {module}:0x{pc:x} {{
    print r.no_such_member;
}}
"#
    );

    let err = compile_member_pointer_script_result(&script, OptimizationLevel::O2)
        .await?
        .expect_err("invalid module-address member access should fail compile_script");
    let message = err.user_message().into_owned();

    assert!(
        message.contains("Failed targets:"),
        "expected failed-target details in compile error: {message}"
    );
    assert!(
        message.contains(&format!("{module}:0x{pc:x}")),
        "expected module-qualified target in compile error: {message}"
    );
    assert!(
        message.contains("Unknown member 'no_such_member'"),
        "unexpected compile error: {message}"
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

#[tokio::test]
async fn test_complex_bitfield_chain_planner_resolves_member_offsets() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for complex_types_program: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("complex_types_program.c", 15);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for complex_types_program.c:15"
    );

    for module_address in &addrs {
        let pc_context = analyzer.resolve_pc(module_address)?;
        let active = analyzer
            .plan_variable_access_by_name(&pc_context, "c", &field_path(&["active"]))?
            .ok_or_else(|| anyhow::anyhow!("missing plan for c.active at {:?}", module_address))?;
        let flags = analyzer
            .plan_variable_access_by_name(&pc_context, "c", &field_path(&["flags"]))?
            .ok_or_else(|| anyhow::anyhow!("missing plan for c.flags at {:?}", module_address))?;

        let expected_steps = vec![
            ghostscope_dwarf::PlanExprOp::LoadRegister(6),
            ghostscope_dwarf::PlanExprOp::PushConstant(-8),
            ghostscope_dwarf::PlanExprOp::Add,
            ghostscope_dwarf::PlanExprOp::Dereference {
                size: ghostscope_dwarf::MemoryAccessSize::U64,
            },
            ghostscope_dwarf::PlanExprOp::PushConstant(64),
            ghostscope_dwarf::PlanExprOp::Add,
        ];
        let expected_location = ghostscope_dwarf::VariableLocation::ComputedAddress(expected_steps);

        assert_eq!(
            active.location, expected_location,
            "unexpected c.active location at 0x{:x}",
            module_address.address
        );
        assert_eq!(
            flags.location, expected_location,
            "unexpected c.flags location at 0x{:x}",
            module_address.address
        );

        assert_eq!(
            active.dwarf_type,
            Some(ghostscope_dwarf::TypeInfo::BitfieldType {
                underlying_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                    name: "unsigned int".to_string(),
                    size: 4,
                    encoding: 7,
                }),
                bit_offset: 0,
                bit_size: 1,
            }),
            "unexpected c.active type at 0x{:x}",
            module_address.address
        );
        assert_eq!(
            flags.dwarf_type,
            Some(ghostscope_dwarf::TypeInfo::BitfieldType {
                underlying_type: Box::new(ghostscope_dwarf::TypeInfo::BaseType {
                    name: "int".to_string(),
                    size: 4,
                    encoding: 5,
                }),
                bit_offset: 1,
                bit_size: 3,
            }),
            "unexpected c.flags type at 0x{:x}",
            module_address.address
        );
    }

    Ok(())
}

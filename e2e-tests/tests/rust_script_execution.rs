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
        .enable_sysmon_for_target(false)
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
async fn test_rust_tuple_projection_plan_preserves_semantic_identity() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let tuple_path = ghostscope_dwarf::VariableAccessPath::new(vec![
        ghostscope_dwarf::VariableAccessSegment::TupleIndex(0),
    ]);
    let (_, plan) = analyzer
        .plan_global_access_read_plan(&binary_path, "GLOBAL_TUPLE", &tuple_path)?
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_TUPLE.0 read plan"))?;

    assert_eq!(plan.name, "GLOBAL_TUPLE.0");
    assert_eq!(plan.access_path, tuple_path);
    assert!(plan.type_id.is_some(), "plan: {plan:?}");
    let semantic_type = analyzer
        .semantic_type_for_plan(&plan)?
        .ok_or_else(|| anyhow::anyhow!("expected semantic type for GLOBAL_TUPLE.0"))?;
    assert_eq!(semantic_type.id, plan.type_id);
    assert_eq!(
        semantic_type.origin.map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );

    let (_, pair_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "GLOBAL_PAIR",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_PAIR read plan"))?;
    let pair_type = pair_plan
        .dwarf_type
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("expected GLOBAL_PAIR type"))?;
    let layout = analyzer.tuple_member_layout_in_module(&binary_path, pair_type, 1)?;
    assert_eq!(layout.offset, 4);
    assert_eq!(layout.member_type.type_name(), "i32");

    let cast_type = analyzer
        .try_resolve_c_style_semantic_type_spec_in_module(&binary_path, "Pair *")?
        .ok_or_else(|| anyhow::anyhow!("expected semantic Pair pointer type"))?;
    assert_eq!(
        cast_type.origin.as_ref().map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );
    let pointee = analyzer.project_resolved_type(
        &cast_type,
        &ghostscope_dwarf::VariableAccessSegment::Dereference,
        Some(&binary_path),
    )?;
    assert_eq!(
        pointee.layout,
        ghostscope_dwarf::TypeProjectionLayout::Dereference
    );
    assert_eq!(
        pointee.resolved_type.identity.layout_dwarf_id(),
        pair_plan.type_id
    );
    assert!(matches!(
        ghostscope_dwarf::strip_type_aliases(&pointee.resolved_type.summary),
        ghostscope_dwarf::TypeInfo::StructType { name, .. } if name == "Pair"
    ));

    let pair_member = analyzer.project_resolved_type(
        &pointee.resolved_type,
        &ghostscope_dwarf::VariableAccessSegment::TupleIndex(0),
        Some(&binary_path),
    )?;
    assert_eq!(
        pair_member.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { offset: 0 }
    );
    assert_eq!(pair_member.resolved_type.summary.type_name(), "i32");
    assert!(pair_member
        .resolved_type
        .identity
        .layout_dwarf_id()
        .is_some());
    assert_eq!(
        pair_member
            .resolved_type
            .origin
            .map(|origin| origin.language),
        Some(ghostscope_dwarf::SourceLanguage::Rust)
    );

    let (_, message_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_MESSAGE",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_MESSAGE read plan"))?;
    let message_type = analyzer
        .resolved_type_for_plan(&message_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected resolved G_MESSAGE type"))?;
    let value_plan = analyzer
        .value_read_plan(&message_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected Rust &str value read plan"))?;
    assert_eq!(
        value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::Utf8String
    );
    let ghostscope_dwarf::ValueCapturePlan::IndirectBytes { data, length } = value_plan.capture
    else {
        anyhow::bail!("expected indirect byte capture for Rust &str")
    };
    assert_eq!(
        data.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { offset: 0 }
    );
    assert_eq!(
        length.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { offset: 8 }
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_string_value_plan_uses_type_namespace() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;

    let (_, std_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_OWNED_MESSAGE",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_OWNED_MESSAGE read plan"))?;
    let std_type = analyzer
        .resolved_type_for_plan(&std_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected standard String type"))?;
    let std_value_plan = analyzer
        .value_read_plan(&std_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected standard String value plan"))?;
    assert_eq!(
        std_value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::Utf8String
    );

    let (_, user_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_USER_STRING",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_USER_STRING read plan"))?;
    let user_type = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user String type"))?;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined String must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_vec_value_plan_uses_dwarf_type_parameter_and_namespace() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, std_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_VEC_I32",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_VEC_I32 read plan"))?;
    let std_type = analyzer
        .resolved_type_for_plan(&std_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected standard Vec type"))?;
    let value_plan = analyzer
        .value_read_plan(&std_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected standard Vec value plan"))?;

    match &value_plan.presentation {
        ghostscope_dwarf::ValuePresentation::Sequence {
            element_type,
            element_stride,
        } => {
            assert_eq!(*element_stride, 4);
            assert!(matches!(
                element_type.as_ref(),
                ghostscope_dwarf::TypeInfo::BaseType {
                    name,
                    size: 4,
                    encoding,
                } if name == "i32"
                    && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
            ));
        }
        presentation => anyhow::bail!("unexpected Vec presentation: {presentation:?}"),
    }
    let ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
        data,
        length,
        element_stride,
    } = value_plan.capture
    else {
        anyhow::bail!("expected indirect sequence capture for Vec<i32>")
    };
    assert_eq!(element_stride, 4);
    assert!(matches!(
        data.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { .. }
    ));
    assert!(matches!(
        length.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { .. }
    ));

    let (_, user_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_USER_VEC",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_USER_VEC read plan"))?;
    let user_type = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user Vec type"))?;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined Vec must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_vec_deque_value_plan_uses_dwarf_ring_layout() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_VEC_DEQUE_I32",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_VEC_DEQUE_I32 read plan"))?;
    let resolved_type = analyzer
        .resolved_type_for_plan(&read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected standard VecDeque type"))?;
    let value_plan = analyzer
        .value_read_plan(&resolved_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected standard VecDeque value plan"))?;

    match &value_plan.presentation {
        ghostscope_dwarf::ValuePresentation::Sequence {
            element_type,
            element_stride,
        } => {
            assert_eq!(*element_stride, 4);
            assert!(matches!(
                element_type.as_ref(),
                ghostscope_dwarf::TypeInfo::BaseType {
                    name,
                    size: 4,
                    encoding,
                } if name == "i32"
                    && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
            ));
        }
        presentation => anyhow::bail!("unexpected VecDeque presentation: {presentation:?}"),
    }

    let ghostscope_dwarf::ValueCapturePlan::IndirectRingSequence {
        data,
        start,
        length,
        capacity,
        element_stride,
    } = value_plan.capture
    else {
        anyhow::bail!("expected indirect ring capture for VecDeque<i32>")
    };
    assert_eq!(element_stride, 4);
    let length = match *length {
        ghostscope_dwarf::RingSequenceLength::Explicit(length) => length,
        ghostscope_dwarf::RingSequenceLength::End(_) => {
            anyhow::bail!("current VecDeque should expose an explicit length")
        }
    };
    assert!(matches!(
        data.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::PointerType { size: 8, .. }
    ));
    for projection in [&start, &length, &capacity] {
        assert!(matches!(
            projection.layout,
            ghostscope_dwarf::TypeProjectionLayout::Member { .. }
        ));
        assert!(matches!(
            projection.resolved_type.summary,
            ghostscope_dwarf::TypeInfo::BaseType { size: 8, .. }
        ));
    }

    let (_, zst_read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_VEC_DEQUE_UNIT",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_VEC_DEQUE_UNIT read plan"))?;
    let zst_type = analyzer
        .resolved_type_for_plan(&zst_read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected VecDeque<()> type"))?;
    let zst_value_plan = analyzer
        .value_read_plan(&zst_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected VecDeque<()> value plan"))?;
    assert!(matches!(
        zst_value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::Sequence {
            element_stride: 0,
            ..
        }
    ));
    assert!(matches!(
        zst_value_plan.capture,
        ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
            element_stride: 0,
            ..
        }
    ));

    Ok(())
}

#[tokio::test]
async fn test_rust_slice_value_plan_uses_dwarf_pointer_target() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_SLICE_I32",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_SLICE_I32 read plan"))?;
    let resolved_type = analyzer
        .resolved_type_for_plan(&read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected slice type"))?;
    let value_plan = analyzer
        .value_read_plan(&resolved_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected slice value plan"))?;

    match &value_plan.presentation {
        ghostscope_dwarf::ValuePresentation::Sequence {
            element_type,
            element_stride,
        } => {
            assert_eq!(*element_stride, 4);
            assert!(matches!(
                element_type.as_ref(),
                ghostscope_dwarf::TypeInfo::BaseType {
                    name,
                    size: 4,
                    encoding,
                } if name == "i32"
                    && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
            ));
        }
        presentation => anyhow::bail!("unexpected slice presentation: {presentation:?}"),
    }
    let ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
        data,
        length,
        element_stride,
    } = value_plan.capture
    else {
        anyhow::bail!("expected indirect sequence capture for &[i32]")
    };
    assert_eq!(element_stride, 4);
    assert!(matches!(
        data.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::PointerType { size: 8, .. }
    ));
    assert!(matches!(
        length.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::BaseType { size: 8, .. }
    ));

    Ok(())
}

#[tokio::test]
async fn test_rust_nonzero_value_plan_projects_dwarf_scalar() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_NONZERO_U32",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_NONZERO_U32 read plan"))?;
    let resolved_type = analyzer
        .resolved_type_for_plan(&read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected NonZeroU32 type"))?;
    let value_plan = analyzer
        .value_read_plan(&resolved_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected NonZeroU32 value plan"))?;

    assert_eq!(
        value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::Dwarf
    );
    let ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } = value_plan.capture else {
        anyhow::bail!("expected projected value capture for NonZeroU32")
    };
    assert_eq!(
        value.layout,
        ghostscope_dwarf::TypeProjectionLayout::Member { offset: 0 }
    );
    assert!(matches!(
        value.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::BaseType {
            ref name,
            size: 4,
            encoding,
        } if name == "u32"
            && encoding == ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16
    ));

    let parameter_plan = analyzer
        .lookup_function_addresses("observe_nonzero")
        .into_iter()
        .find_map(|address| {
            let context = analyzer.resolve_pc(&address).ok()?;
            analyzer.plan_variable_by_name(&context, "value").ok()?
        })
        .ok_or_else(|| anyhow::anyhow!("expected observe_nonzero value plan"))?;
    let parameter_type = analyzer
        .resolved_type_for_plan(&parameter_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected NonZeroU32 parameter type"))?;
    assert!(matches!(
        analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .map(|plan| plan.capture),
        Some(ghostscope_dwarf::ValueCapturePlan::ProjectedValue { .. })
    ));

    let (_, user_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_USER_NONZERO",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_USER_NONZERO read plan"))?;
    let user_type = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user NonZero type"))?;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined NonZero must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_str_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RSTR:{}:{}:{}", G_MESSAGE, G_EMPTY_MESSAGE, G_NUL_MESSAGE;
    print "RSTR_RAW:{:s}:{:x}", G_MESSAGE, G_MESSAGE;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains(r#"RSTR:"hello from rust":"":"left\0right""#)),
        "Expected Rust str output: {stdout}"
    );
    let expected_raw = concat!(
        "RSTR_RAW:hello from rust:",
        "68 65 6c 6c 6f 20 66 72 6f 6d 20 72 75 73 74"
    );
    assert!(
        stdout.lines().any(|line| line.contains(expected_raw)),
        "Expected raw Rust str output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_string_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RSTRING:{}:{}:{}", G_OWNED_MESSAGE, G_EMPTY_OWNED, G_NUL_OWNED;
    print "RSTRING_RAW:{:s}:{:x}", G_OWNED_MESSAGE, G_OWNED_MESSAGE;
    print "RSTRING_SEPARATOR:{}", G_SEPARATOR_OWNED;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| { line.contains(r#"RSTRING:"owned from rust":"":"owned\0value""#) }),
        "Expected Rust String output: {stdout}"
    );
    let expected_raw = concat!(
        "RSTRING_RAW:owned from rust:",
        "6f 77 6e 65 64 20 66 72 6f 6d 20 72 75 73 74"
    );
    assert!(
        stdout.lines().any(|line| line.contains(expected_raw)),
        "Expected raw Rust String output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains(r#"RSTRING_SEPARATOR:"left = right""#)),
        "Expected Rust String separator output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_vec_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RVEC:{}:{}:{}:{}", G_VEC_U8, G_VEC_I32, G_EMPTY_VEC, G_VEC_UNIT;
    print "RVEC_RAW:{:x}", G_VEC_U8;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| { line.contains("RVEC:[1, 2, 3, 255]:[10, -20, 30, 40]:[]:[(), (), ()]") }),
        "Expected Rust Vec output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RVEC_RAW:01 02 03 ff")),
        "Expected raw Rust Vec output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_vec_deque_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_vec_deque {
    print "RDEQUE:{}:{}:{}", wrapped, contiguous, empty;
}
trace do_stuff {
    print "RDEQUE_ZST:{}", G_VEC_DEQUE_UNIT;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RDEQUE:[10, 20, 30, 40]:[7, 8, 9]:[]")),
        "Expected Rust VecDeque output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RDEQUE_ZST:[(), (), ()]")),
        "Expected Rust VecDeque ZST output: stderr={stderr} stdout={stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_nonzero_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RNONZERO:{}:{}:{}", G_NONZERO_U32, G_NONZERO_I32, G_NONZERO_U128;
}
trace observe_nonzero {
    print "RNONZERO_ARG:{}", value;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let expected_global = concat!("RNONZERO:7:-9:", "340282366920938463463374607431768211454");
    assert!(
        stdout.lines().any(|line| line.contains(expected_global)),
        "Expected Rust NonZero global output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| line.contains("RNONZERO_ARG:23")),
        "Expected Rust NonZero argument output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_vec_deque_respects_element_aligned_cap() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_vec_deque {
    print "RDEQUE_CAP:{}", wrapped;
}
"#;
    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 9
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RDEQUE_CAP:[10, 20] <truncated>")),
        "Expected capped Rust VecDeque output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_vec_respects_element_aligned_cap() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RVEC_CAP:{}", G_VEC_I32;
}
"#;
    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 9
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RVEC_CAP:[10, -20] <truncated>")),
        "Expected element-aligned capped Rust Vec output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_slice_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RSLICE:{}:{}:{}", G_SLICE_I32, G_MUT_SLICE_U16, G_EMPTY_SLICE;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| { line.contains("RSLICE:[7, -8, 9]:[1000, 2000, 65535]:[]") }),
        "Expected Rust slice output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_box_str_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_boxed_str {
    print "RBOX:{}:{}", value, empty;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RBOX:\"boxed from rust\":\"\"")),
        "Expected Rust Box<str> output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_os_string_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_os_string {
    print "ROS:{}:{}:{}", value, invalid, empty;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("ROS:\"os from rust\":\"os\\xffx\":\"\"")),
        "Expected Rust OsString output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_str_respects_mem_dump_cap() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RSTR_CAP:{}", G_MESSAGE;
    print "RSTR_CAP_RAW:{:s}:{:x}", G_MESSAGE, G_MESSAGE;
}
"#;

    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 3
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let cap_line = stdout
        .lines()
        .find(|line| line.contains("RSTR_CAP:"))
        .ok_or_else(|| anyhow::anyhow!("Expected capped Rust str output: {stdout}"))?;
    assert!(
        cap_line.contains(r#"RSTR_CAP:"hel" <truncated>"#),
        "Unexpected capped Rust str output: {cap_line}"
    );
    assert!(
        !cap_line.contains("hell"),
        "Rust str read exceeded mem_dump_cap: {cap_line}"
    );
    let cap_raw_line = stdout
        .lines()
        .find(|line| line.contains("RSTR_CAP_RAW:"))
        .ok_or_else(|| anyhow::anyhow!("Expected raw capped Rust str output: {stdout}"))?;
    assert!(
        cap_raw_line.contains("RSTR_CAP_RAW:hel <truncated>:68 65 6c <truncated>"),
        "Unexpected raw capped Rust str output: {cap_raw_line}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_tuple_fields() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    let pair_index = 1;
    print "RTUP:{}:{}", GLOBAL_TUPLE.0, GLOBAL_TUPLE.1;
    print "RPAIR:{}:{}", GLOBAL_PAIR.0, GLOBAL_PAIR.1;
    print "DPAIR:{}", GLOBAL_PAIRS[pair_index].0;
    print "CPAIR:{}", cast(&GLOBAL_PAIR, "Pair *").0;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.lines().any(|line| {
            line.contains("RTUP:") && (line.contains(":true") || line.contains(":false"))
        }),
        "Expected typed tuple output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            let Some((_, payload)) = line.split_once("RPAIR:") else {
                return false;
            };
            let mut fields = payload.split(':');
            let Some(left) = fields.next() else {
                return false;
            };
            let Some(right) = fields.next() else {
                return false;
            };
            left.trim().parse::<i64>().is_ok()
                && right
                    .split_whitespace()
                    .next()
                    .is_some_and(|value| value.parse::<i64>().is_ok())
        }),
        "Expected typed tuple struct output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );
    assert!(
        stdout.contains("DPAIR:13"),
        "Expected dynamic-index tuple output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.split_once("CPAIR:")
                .and_then(|(_, value)| value.split_whitespace().next())
                .is_some_and(|value| value.parse::<i64>().is_ok())
        }),
        "Expected cast tuple output: {stdout}"
    );

    Ok(())
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

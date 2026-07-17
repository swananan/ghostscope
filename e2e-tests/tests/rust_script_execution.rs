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
async fn test_rust_cell_value_plan_projects_dwarf_value() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_CELL_U32",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_CELL_U32 read plan"))?;
    let resolved_type = analyzer
        .resolved_type_for_plan(&read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected Cell<u32> type"))?;
    let value_plan = analyzer
        .value_read_plan(&resolved_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected Cell<u32> value plan"))?;

    assert_eq!(
        value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::SingleField {
            type_name: "Cell".to_string(),
            field_name: "value".to_string(),
        }
    );
    let ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } = value_plan.capture else {
        anyhow::bail!("expected projected value capture for Cell<u32>")
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

    let (_, pair_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_CELL_PAIR",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_CELL_PAIR read plan"))?;
    let pair_type = analyzer
        .resolved_type_for_plan(&pair_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected Cell<(i32, u16)> type"))?;
    let pair_value = analyzer
        .value_read_plan(&pair_type, Some(&binary_path))?
        .and_then(|plan| match plan.capture {
            ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } => Some(value),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("expected projected pair capture"))?;
    assert!(matches!(
        pair_value.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::StructType { ref members, .. }
            if members.len() == 2
    ));

    let (_, unit_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_CELL_UNIT",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_CELL_UNIT read plan"))?;
    let unit_type = analyzer
        .resolved_type_for_plan(&unit_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected Cell<()> type"))?;
    let unit_value = analyzer
        .value_read_plan(&unit_type, Some(&binary_path))?
        .and_then(|plan| match plan.capture {
            ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } => Some(value),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("expected projected unit capture"))?;
    assert!(matches!(
        unit_value.resolved_type.summary,
        ghostscope_dwarf::TypeInfo::BaseType {
            ref name,
            size: 0,
            ..
        } if name == "()"
    ));

    let (_, user_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_USER_CELL",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_USER_CELL read plan"))?;
    let user_type = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user Cell type"))?;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined Cell must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_ref_cell_value_plan_builds_dwarf_inline_view() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_REF_CELL_IDLE",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_REF_CELL_IDLE read plan"))?;
    let resolved_type = analyzer
        .resolved_type_for_plan(&read_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected RefCell<i32> type"))?;
    let root_size = resolved_type.summary.size();
    let value_plan = analyzer
        .value_read_plan(&resolved_type, Some(&binary_path))?
        .ok_or_else(|| anyhow::anyhow!("expected RefCell<i32> value plan"))?;

    assert_eq!(
        value_plan.presentation,
        ghostscope_dwarf::ValuePresentation::SignedStateStruct {
            state_field: "borrow".to_string(),
            non_negative_label: "borrow".to_string(),
            negative_label: "borrow_mut".to_string(),
        }
    );
    let ghostscope_dwarf::ValueCapturePlan::InlineView { output_type } = value_plan.capture else {
        anyhow::bail!("expected inline semantic view for RefCell<i32>")
    };
    let ghostscope_dwarf::TypeInfo::StructType {
        name,
        size,
        members,
    } = output_type
    else {
        anyhow::bail!("expected RefCell struct view")
    };
    assert_eq!(name, "RefCell");
    assert_eq!(size, root_size);
    let [value, borrow] = members.as_slice() else {
        anyhow::bail!("expected value and borrow fields")
    };
    assert_eq!(value.name, "value");
    assert_eq!(borrow.name, "borrow");
    assert!(matches!(
        ghostscope_dwarf::strip_type_aliases(&value.member_type),
        ghostscope_dwarf::TypeInfo::BaseType {
            name,
            size: 4,
            encoding,
        } if name == "i32"
            && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
    ));
    assert!(matches!(
        ghostscope_dwarf::strip_type_aliases(&borrow.member_type),
        ghostscope_dwarf::TypeInfo::BaseType { size, encoding, .. }
            if matches!(*size, 4 | 8)
                && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
    ));
    let value_end = value.offset + value.member_type.size();
    let borrow_end = borrow.offset + borrow.member_type.size();
    assert!(value_end <= root_size);
    assert!(borrow_end <= root_size);
    assert!(value_end <= borrow.offset || borrow_end <= value.offset);

    let (_, unit_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_REF_CELL_UNIT",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_REF_CELL_UNIT read plan"))?;
    let unit_type = analyzer
        .resolved_type_for_plan(&unit_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected RefCell<()> type"))?;
    let unit_view = analyzer
        .value_read_plan(&unit_type, Some(&binary_path))?
        .and_then(|plan| match plan.capture {
            ghostscope_dwarf::ValueCapturePlan::InlineView { output_type } => Some(output_type),
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("expected RefCell<()> inline view"))?;
    let ghostscope_dwarf::TypeInfo::StructType { members, .. } = unit_view else {
        anyhow::bail!("expected RefCell<()> struct view")
    };
    assert!(matches!(
        ghostscope_dwarf::strip_type_aliases(&members[0].member_type),
        ghostscope_dwarf::TypeInfo::BaseType {
            name,
            size: 0,
            ..
        } if name == "()"
    ));

    let (_, user_plan) = analyzer
        .plan_global_access_read_plan(
            &binary_path,
            "G_USER_REF_CELL",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .ok_or_else(|| anyhow::anyhow!("expected G_USER_REF_CELL read plan"))?;
    let user_type = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user RefCell type"))?;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined RefCell must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_ref_value_plan_builds_dwarf_projected_view() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let ref_context = analyzer
        .lookup_function_addresses("observe_ref_guards")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_ref_guards context"))?;

    for (parameter, expected_value) in [("shared", "i32"), ("mutable", "i32")] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&ref_context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let guard_type = analyzer
            .project_resolved_type(
                &parameter_type,
                &ghostscope_dwarf::VariableAccessSegment::Dereference,
                Some(&binary_path),
            )?
            .resolved_type;
        let value_plan = analyzer
            .value_read_plan(&guard_type, Some(&binary_path))?
            .ok_or_else(|| {
                anyhow::anyhow!("expected {parameter} semantic plan for {guard_type:#?}")
            })?;
        assert_eq!(
            value_plan.presentation,
            ghostscope_dwarf::ValuePresentation::SignedStateStruct {
                state_field: "borrow".to_string(),
                non_negative_label: "borrow".to_string(),
                negative_label: "borrow_mut".to_string(),
            }
        );
        let ghostscope_dwarf::ValueCapturePlan::ProjectedView {
            output_type,
            fields,
        } = value_plan.capture
        else {
            anyhow::bail!("expected projected semantic view for {parameter}")
        };
        let ghostscope_dwarf::TypeInfo::StructType {
            name,
            size,
            members,
        } = output_type
        else {
            anyhow::bail!("expected projected Ref struct")
        };
        assert_eq!(name, "Ref");
        let [value_member, borrow_member] = members.as_slice() else {
            anyhow::bail!("expected projected value and borrow members")
        };
        assert_eq!(value_member.name, "*value");
        assert_eq!(borrow_member.name, "borrow");
        assert_eq!(value_member.offset, 0);
        assert_eq!(borrow_member.offset, value_member.member_type.size());
        assert_eq!(
            size,
            borrow_member.offset + borrow_member.member_type.size()
        );
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&value_member.member_type),
            ghostscope_dwarf::TypeInfo::BaseType { name, size: 4, .. }
                if name == expected_value
        ));
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&borrow_member.member_type),
            ghostscope_dwarf::TypeInfo::BaseType { size, encoding, .. }
                if matches!(*size, 4 | 8)
                    && *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
        ));
        let [value_field, borrow_field] = fields.as_slice() else {
            anyhow::bail!("expected projected value and borrow reads")
        };
        assert_eq!(value_field.output_offset, value_member.offset);
        assert_eq!(borrow_field.output_offset, borrow_member.offset);
        assert!(matches!(
            value_field.value.steps.last(),
            Some(ghostscope_dwarf::ProjectedValueStep::Dereference {
                pointer_size: 4 | 8
            })
        ));
        assert!(borrow_field.value.steps.iter().any(|step| matches!(
            step,
            ghostscope_dwarf::ProjectedValueStep::Dereference {
                pointer_size: 4 | 8
            }
        )));
    }

    let unit_plan = analyzer
        .plan_variable_by_name(&ref_context, "unit")?
        .ok_or_else(|| anyhow::anyhow!("expected unit parameter plan"))?;
    let unit_pointer = analyzer
        .resolved_type_for_plan(&unit_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected unit parameter type"))?;
    let unit_type = analyzer
        .project_resolved_type(
            &unit_pointer,
            &ghostscope_dwarf::VariableAccessSegment::Dereference,
            Some(&binary_path),
        )?
        .resolved_type;
    let unit_view = analyzer
        .value_read_plan(&unit_type, Some(&binary_path))?
        .and_then(|plan| match plan.capture {
            ghostscope_dwarf::ValueCapturePlan::ProjectedView { output_type, .. } => {
                Some(output_type)
            }
            _ => None,
        })
        .ok_or_else(|| anyhow::anyhow!("expected unit Ref projected view"))?;
    let ghostscope_dwarf::TypeInfo::StructType { members, .. } = unit_view else {
        anyhow::bail!("expected unit Ref struct")
    };
    assert_eq!(members[0].member_type.size(), 0);
    assert_eq!(members[1].offset, 0);

    let user_context = analyzer
        .lookup_function_addresses("observe_user_ref")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_user_ref context"))?;
    let user_plan = analyzer
        .plan_variable_by_name(&user_context, "value")?
        .ok_or_else(|| anyhow::anyhow!("expected user Ref parameter plan"))?;
    let user_pointer = analyzer
        .resolved_type_for_plan(&user_plan)?
        .ok_or_else(|| anyhow::anyhow!("expected user Ref parameter type"))?;
    let user_type = analyzer
        .project_resolved_type(
            &user_pointer,
            &ghostscope_dwarf::VariableAccessSegment::Dereference,
            Some(&binary_path),
        )?
        .resolved_type;
    assert!(
        analyzer
            .value_read_plan(&user_type, Some(&binary_path))?
            .is_none(),
        "user-defined Ref must retain DWARF presentation"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_rc_arc_value_plans_follow_dwarf_projected_views() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let context = analyzer
        .lookup_function_addresses("observe_rc_arc")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_rc_arc context"))?;

    for (parameter, expected_name) in [("rc", "Rc"), ("arc", "Arc")] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let value_plan = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .ok_or_else(|| {
                anyhow::anyhow!("expected {parameter} semantic plan for {parameter_type:#?}")
            })?;
        assert_eq!(
            value_plan.presentation,
            ghostscope_dwarf::ValuePresentation::ReferenceCountedStruct {
                strong_field: "strong".to_string(),
                weak_field: "weak".to_string(),
                implicit_weak: 1,
            }
        );
        let ghostscope_dwarf::ValueCapturePlan::ProjectedView {
            output_type,
            fields,
        } = value_plan.capture
        else {
            anyhow::bail!("expected projected semantic view for {parameter}")
        };
        let ghostscope_dwarf::TypeInfo::StructType {
            name,
            size,
            members,
        } = output_type
        else {
            anyhow::bail!("expected projected {expected_name} struct")
        };
        assert_eq!(name, expected_name);
        let [value_member, strong_member, weak_member] = members.as_slice() else {
            anyhow::bail!("expected value and reference-count members")
        };
        assert_eq!(value_member.name, "value");
        assert_eq!(strong_member.name, "strong");
        assert_eq!(weak_member.name, "weak");
        assert_eq!(value_member.offset, 0);
        assert_eq!(strong_member.offset, value_member.member_type.size());
        assert_eq!(
            weak_member.offset,
            strong_member.offset + strong_member.member_type.size()
        );
        assert_eq!(size, weak_member.offset + weak_member.member_type.size());
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&value_member.member_type),
            ghostscope_dwarf::TypeInfo::StructType { name, size: 8, .. }
                if name == "(i32, u16)"
        ));
        for member in [strong_member, weak_member] {
            assert!(matches!(
                ghostscope_dwarf::strip_type_aliases(&member.member_type),
                ghostscope_dwarf::TypeInfo::BaseType { size, encoding, .. }
                    if matches!(*size, 4 | 8)
                        && *encoding
                            == ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16
            ));
        }
        assert_eq!(fields.len(), 3);
        for field in &fields {
            assert!(field.value.steps.iter().any(|step| matches!(
                step,
                ghostscope_dwarf::ProjectedValueStep::Dereference {
                    pointer_size: 4 | 8
                }
            )));
        }
    }

    for parameter in ["rc_unit", "arc_unit"] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let output_type = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .and_then(|plan| match plan.capture {
                ghostscope_dwarf::ValueCapturePlan::ProjectedView { output_type, .. } => {
                    Some(output_type)
                }
                _ => None,
            })
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} projected view"))?;
        let ghostscope_dwarf::TypeInfo::StructType { members, .. } = output_type else {
            anyhow::bail!("expected {parameter} struct view")
        };
        assert_eq!(members[0].member_type.size(), 0);
        assert_eq!(members[1].offset, 0);
    }

    let user_context = analyzer
        .lookup_function_addresses("observe_user_rc_arc")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_user_rc_arc context"))?;
    for parameter in ["rc", "arc"] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&user_context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} plan"))?;
        let parameter_pointer = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} type"))?;
        let parameter_type = analyzer
            .project_resolved_type(
                &parameter_pointer,
                &ghostscope_dwarf::VariableAccessSegment::Dereference,
                Some(&binary_path),
            )?
            .resolved_type;
        assert!(
            analyzer
                .value_read_plan(&parameter_type, Some(&binary_path))?
                .is_none(),
            "user-defined {parameter} must retain DWARF presentation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_rust_hash_collection_plans_follow_dwarf_raw_table_layout() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let context = analyzer
        .lookup_function_addresses("observe_hash_collections")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_hash_collections context"))?;

    for (parameter, is_map) in [("map", true), ("set", false)] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let value_plan = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} semantic plan"))?;
        let ghostscope_dwarf::ValuePresentation::HashTable {
            entry_stride,
            bucket_order,
            occupancy,
            entry,
        } = value_plan.presentation
        else {
            anyhow::bail!("expected {parameter} hash-table presentation")
        };
        assert_eq!(
            bucket_order,
            ghostscope_dwarf::HashTableBucketOrder::Reverse
        );
        assert_eq!(
            occupancy,
            ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear
        );
        match entry {
            ghostscope_dwarf::HashTableEntryPresentation::Map { key, value } => {
                assert!(is_map);
                assert_eq!(entry_stride, 8);
                assert_eq!(key.offset, 0);
                assert_eq!(key.field_type.type_name(), "i32");
                assert_eq!(value.offset, 4);
                assert_eq!(value.field_type.type_name(), "u16");
            }
            ghostscope_dwarf::HashTableEntryPresentation::Set { value } => {
                assert!(!is_map);
                assert_eq!(entry_stride, 4);
                assert_eq!(value.offset, 0);
                assert_eq!(value.field_type.type_name(), "i32");
            }
        }
        let ghostscope_dwarf::ValueCapturePlan::IndirectHashTable {
            control,
            length,
            bucket_mask,
            entry_stride: capture_stride,
            occupancy: capture_occupancy,
            buckets,
            bucket_order: capture_order,
        } = value_plan.capture
        else {
            anyhow::bail!("expected {parameter} bounded hash-table capture")
        };
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&control.resolved_type.summary),
            ghostscope_dwarf::TypeInfo::PointerType { size: 4 | 8, .. }
        ));
        assert!(matches!(
            buckets,
            ghostscope_dwarf::HashTableBucketSource::ReverseFromControl
        ));
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&length.resolved_type.summary),
            ghostscope_dwarf::TypeInfo::BaseType { size: 4 | 8, .. }
        ));
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&bucket_mask.resolved_type.summary),
            ghostscope_dwarf::TypeInfo::BaseType { size: 4 | 8, .. }
        ));
        assert_eq!(capture_stride, entry_stride);
        assert_eq!(capture_occupancy, occupancy);
        assert_eq!(capture_order, bucket_order);
    }

    for (parameter, expected_map) in [("unit_map", true), ("unit_set", false)] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let presentation = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .map(|plan| plan.presentation)
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} semantic plan"))?;
        let ghostscope_dwarf::ValuePresentation::HashTable {
            entry_stride,
            entry,
            ..
        } = presentation
        else {
            anyhow::bail!("expected {parameter} hash-table presentation")
        };
        assert_eq!(entry_stride, 0);
        assert_eq!(
            matches!(
                entry,
                ghostscope_dwarf::HashTableEntryPresentation::Map { .. }
            ),
            expected_map
        );
    }

    let user_context = analyzer
        .lookup_function_addresses("observe_user_hash_collections")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected user hash collection context"))?;
    for parameter in ["map", "set"] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&user_context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} plan"))?;
        let parameter_pointer = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} type"))?;
        let parameter_type = analyzer
            .project_resolved_type(
                &parameter_pointer,
                &ghostscope_dwarf::VariableAccessSegment::Dereference,
                Some(&binary_path),
            )?
            .resolved_type;
        assert!(
            analyzer
                .value_read_plan(&parameter_type, Some(&binary_path))?
                .is_none(),
            "user-defined {parameter} must retain DWARF presentation"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_rust_btree_collection_plans_follow_dwarf_node_layout() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("rust_global_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let context = analyzer
        .lookup_function_addresses("observe_btree_collections")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected observe_btree_collections context"))?;

    for (parameter, is_map) in [("map", true), ("set", false)] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let value_plan = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} semantic plan"))?;
        let ghostscope_dwarf::ValuePresentation::BTree {
            node_capacity,
            entry,
        } = value_plan.presentation
        else {
            anyhow::bail!("expected {parameter} B-Tree presentation")
        };
        assert_eq!(node_capacity, 11);
        match entry {
            ghostscope_dwarf::BTreeEntryPresentation::Map { key, value } => {
                assert!(is_map);
                assert_eq!(key.slot_stride, 4);
                assert_eq!(key.value_offset, 0);
                assert_eq!(key.field_type.type_name(), "i32");
                assert_eq!(value.slot_stride, 2);
                assert_eq!(value.value_offset, 0);
                assert_eq!(value.field_type.type_name(), "u16");
            }
            ghostscope_dwarf::BTreeEntryPresentation::Set { value } => {
                assert!(!is_map);
                assert_eq!(value.slot_stride, 4);
                assert_eq!(value.value_offset, 0);
                assert_eq!(value.field_type.type_name(), "i32");
            }
        }

        let ghostscope_dwarf::ValueCapturePlan::IndirectBTree {
            root_pointer,
            root_height,
            length,
            node_length,
            keys,
            values,
            edges,
            node_capacity: capture_capacity,
        } = value_plan.capture
        else {
            anyhow::bail!("expected {parameter} bounded B-Tree capture")
        };
        assert!(matches!(
            root_pointer.layout,
            ghostscope_dwarf::TypeProjectionLayout::Member { .. }
        ));
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&root_pointer.resolved_type.summary),
            ghostscope_dwarf::TypeInfo::PointerType { size: 8, .. }
        ));
        for scalar in [&root_height, &length] {
            assert!(matches!(
                scalar.layout,
                ghostscope_dwarf::TypeProjectionLayout::Member { .. }
            ));
            assert!(matches!(
                ghostscope_dwarf::strip_type_aliases(&scalar.resolved_type.summary),
                ghostscope_dwarf::TypeInfo::BaseType { size: 8, .. }
            ));
        }
        assert!(matches!(
            ghostscope_dwarf::strip_type_aliases(&node_length.resolved_type.summary),
            ghostscope_dwarf::TypeInfo::BaseType { size: 2, .. }
        ));
        assert_eq!(capture_capacity, node_capacity);
        assert_eq!(keys.slot_stride, 4);
        assert_eq!(values.is_some(), is_map);
        if let Some(values) = values {
            assert_eq!(values.slot_stride, 2);
        }
        assert_eq!(edges.edge_count, node_capacity + 1);
        assert_eq!(edges.slot_stride, 8);
        assert_eq!(edges.pointer_size, 8);
        assert!(edges.pointer_offset < edges.slot_stride);
    }

    for (parameter, expected_map) in [("unit_map", true), ("unit_set", false)] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter plan"))?;
        let parameter_type = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} parameter type"))?;
        let presentation = analyzer
            .value_read_plan(&parameter_type, Some(&binary_path))?
            .map(|plan| plan.presentation)
            .ok_or_else(|| anyhow::anyhow!("expected {parameter} semantic plan"))?;
        let ghostscope_dwarf::ValuePresentation::BTree { entry, .. } = presentation else {
            anyhow::bail!("expected {parameter} B-Tree presentation")
        };
        let (is_map, field_strides) = match entry {
            ghostscope_dwarf::BTreeEntryPresentation::Map { key, value } => {
                (true, vec![key.slot_stride, value.slot_stride])
            }
            ghostscope_dwarf::BTreeEntryPresentation::Set { value } => {
                (false, vec![value.slot_stride])
            }
        };
        assert_eq!(is_map, expected_map);
        assert!(field_strides.into_iter().all(|stride| stride == 0));
    }

    let user_context = analyzer
        .lookup_function_addresses("observe_user_btree_collections")
        .into_iter()
        .find_map(|address| analyzer.resolve_pc(&address).ok())
        .ok_or_else(|| anyhow::anyhow!("expected user B-Tree collection context"))?;
    for parameter in ["map", "set"] {
        let parameter_plan = analyzer
            .plan_variable_by_name(&user_context, parameter)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} plan"))?;
        let parameter_pointer = analyzer
            .resolved_type_for_plan(&parameter_plan)?
            .ok_or_else(|| anyhow::anyhow!("expected user {parameter} type"))?;
        let parameter_type = analyzer
            .project_resolved_type(
                &parameter_pointer,
                &ghostscope_dwarf::VariableAccessSegment::Dereference,
                Some(&binary_path),
            )?
            .resolved_type;
        assert!(
            analyzer
                .value_read_plan(&parameter_type, Some(&binary_path))?
                .is_none(),
            "user-defined {parameter} must retain DWARF presentation"
        );
    }

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
async fn test_rust_script_print_cell_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace do_stuff {
    print "RCELL:{}:{}:{}", G_CELL_U32, G_CELL_PAIR, G_CELL_UNIT;
    print "RCELL_RAW:{:x}", G_CELL_U32;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RCELL:Cell { value: 41 }:Cell { value:")),
        "Expected Rust Cell wrapper output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("RCELL:") && line.contains("__0: -4") && line.contains("__1: 12")
        }),
        "Expected Rust Cell aggregate output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains(":Cell { value: () }")),
        "Expected Rust Cell unit output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RCELL_RAW:29 00 00 00")),
        "Expected raw Rust Cell payload: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_ref_cell_values_and_borrow_states() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_ref_cell_states {
    print "RREFCELL:{}:{}:{}:{}:{}", G_REF_CELL_IDLE,
        G_REF_CELL_SHARED, G_REF_CELL_MUT, G_REF_CELL_PAIR, G_REF_CELL_UNIT;
    print "RREFCELL_RAW:{:x}", G_REF_CELL_SHARED;
    print "RREFCELL_ARG:{}", owned;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RefCell(borrow=0) { value: 17, borrow: 0 }")),
        "Expected idle Rust RefCell output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RefCell(borrow=2) { value: 23, borrow: 2 }")),
        "Expected shared Rust RefCell output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| { line.contains("RefCell(borrow_mut=1) { value: 31, borrow: -1 }") }),
        "Expected mutably borrowed Rust RefCell output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("RREFCELL:") && line.contains("__0: -6") && line.contains("__1: 14")
        }),
        "Expected aggregate Rust RefCell output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("RefCell(borrow=0) { value: (), borrow: 0 }")),
        "Expected zero-sized Rust RefCell output: {stdout}"
    );
    let raw_line = stdout
        .lines()
        .find(|line| line.contains("RREFCELL_RAW:"))
        .ok_or_else(|| anyhow::anyhow!("missing raw RefCell output: {stdout}"))?;
    let (_, raw_payload) = raw_line
        .split_once("RREFCELL_RAW:")
        .ok_or_else(|| anyhow::anyhow!("invalid raw RefCell output: {raw_line}"))?;
    assert!(
        raw_payload.contains("00"),
        "raw payload was empty: {raw_line}"
    );
    assert!(
        !raw_payload.contains("RefCell"),
        "raw specifier used semantic formatting: {raw_line}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains(
                "RREFCELL_ARG:RefCell(borrow=0) \
                           { value: -12, borrow: 0 }",
            )
        }),
        "Expected Rust RefCell argument output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_ref_and_ref_mut_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_ref_guards {
    print "RREF:{}:{}:{}:{}", *shared, *mutable, *pair, *unit;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("Ref(borrow=2) { *value: 23, borrow: 2 }")),
        "Expected shared Rust Ref output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| { line.contains("Ref(borrow_mut=1) { *value: 31, borrow: -1 }") }),
        "Expected Rust RefMut output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("Ref(borrow=1)") && line.contains("__0: -6") && line.contains("__1: 14")
        }),
        "Expected aggregate Rust Ref output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("Ref(borrow=1) { *value: (), borrow: 1 }")),
        "Expected zero-sized Rust Ref output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_rc_and_arc_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_rc_arc {
    print "RRCARC:{}:{}:{}:{}", rc, arc, rc_unit, arc_unit;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.lines().any(|line| {
            line.contains("Rc(strong=3, weak=1)")
                && line.contains("__0: -7")
                && line.contains("__1: 13")
                && line.contains("strong: 3")
                && line.contains("weak: 1")
        }),
        "Expected Rust Rc output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("Arc(strong=3, weak=1)")
                && line.contains("__0: 29")
                && line.contains("__1: 17")
                && line.contains("strong: 3")
                && line.contains("weak: 1")
        }),
        "Expected Rust Arc output: {stdout}"
    );
    assert!(
        stdout
            .lines()
            .any(|line| line.contains("Rc(strong=1, weak=0) { value: (), strong: 1, weak: 0 }")),
        "Expected zero-sized Rust Rc output: {stdout}"
    );
    assert!(
        stdout.lines().any(|line| {
            line.contains("Arc(strong=1, weak=0) { value: (), strong: 1, weak: 0 }")
        }),
        "Expected zero-sized Rust Arc output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_hash_map_and_hash_set_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_hash_collections {
    print "RHASH_MAP:{}", map;
    print "RHASH_SET:{}", set;
    print "RHASH_EMPTY_MAP:{}", empty_map;
    print "RHASH_EMPTY_SET:{}", empty_set;
    print "RHASH_UNIT_MAP:{}", unit_map;
    print "RHASH_UNIT_SET:{}", unit_set;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let map_line = stdout
        .lines()
        .find(|line| line.contains("RHASH_MAP:"))
        .ok_or_else(|| anyhow::anyhow!("missing Rust HashMap output: {stdout}"))?;
    assert!(map_line.contains("HashMap(size=2)"), "{map_line}");
    assert!(map_line.contains("-7: 13"), "{map_line}");
    assert!(map_line.contains("29: 17"), "{map_line}");
    let set_line = stdout
        .lines()
        .find(|line| line.contains("RHASH_SET:"))
        .ok_or_else(|| anyhow::anyhow!("missing Rust HashSet output: {stdout}"))?;
    assert!(set_line.contains("HashSet(size=2)"), "{set_line}");
    assert!(set_line.contains("-9"), "{set_line}");
    assert!(set_line.contains('5'), "{set_line}");
    assert!(
        stdout.contains("RHASH_EMPTY_MAP:HashMap(size=0) {}"),
        "Expected empty Rust HashMap output: {stdout}"
    );
    assert!(
        stdout.contains("RHASH_EMPTY_SET:HashSet(size=0) {}"),
        "Expected empty Rust HashSet output: {stdout}"
    );
    assert!(
        stdout.contains("RHASH_UNIT_MAP:HashMap(size=1) {(): ()}"),
        "Expected ZST Rust HashMap output: {stdout}"
    );
    assert!(
        stdout.contains("RHASH_UNIT_SET:HashSet(size=1) {()}"),
        "Expected ZST Rust HashSet output: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_hash_map_respects_bucket_aligned_cap() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_hash_collections {
    print "RHASH_CAP:{}", map;
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
    let line = stdout
        .lines()
        .find(|line| line.contains("RHASH_CAP:"))
        .ok_or_else(|| anyhow::anyhow!("missing capped Rust HashMap output: {stdout}"))?;
    assert!(line.contains("HashMap(size=2)"), "{line}");
    assert!(line.contains("<truncated>"), "{line}");
    assert!(!line.contains("<INVALID_"), "{line}");
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_btree_map_and_set_values() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_btree_collections {
    print "RBTREE_MAP:{}", map;
    print "RBTREE_SET:{}", set;
    print "RBTREE_EMPTY_MAP:{}", empty_map;
    print "RBTREE_EMPTY_SET:{}", empty_set;
    print "RBTREE_UNIT_MAP:{}", unit_map;
    print "RBTREE_UNIT_SET:{}", unit_set;
    print "RBTREE_RAW:{:x}", map;
}
"#;
    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 90
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
        stdout.contains("RBTREE_MAP:BTreeMap(size=2) {-7: 13, 29: 17}"),
        "Expected Rust BTreeMap output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_SET:BTreeSet(size=2) {-9, 5}"),
        "Expected Rust BTreeSet output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_EMPTY_MAP:BTreeMap(size=0) {}"),
        "Expected empty Rust BTreeMap output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_EMPTY_SET:BTreeSet(size=0) {}"),
        "Expected empty Rust BTreeSet output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_UNIT_MAP:BTreeMap(size=1) {(): ()}"),
        "Expected ZST Rust BTreeMap output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_UNIT_SET:BTreeSet(size=1) {()}"),
        "Expected ZST Rust BTreeSet output: {stdout}"
    );
    assert!(
        stdout.contains("RBTREE_RAW:f9 ff ff ff 0d 00 1d 00 00 00 11 00"),
        "Expected logical raw BTreeMap bytes: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "Invalid payload: {stdout}");
    assert!(
        !stdout.contains("ExprError"),
        "Unexpected ExprError: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_internal_btree_nodes_in_order() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_internal_btree_collections {
    print "RBTREE_INTERNAL_MAP:{}", map;
    print "RBTREE_INTERNAL_SET:{}", set;
}
"#;
    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(
            r#"
[ebpf]
mem_dump_cap = 450
"#,
        )
        .attach_to(&target)
        .timeout_secs(9)
        .enable_sysmon_for_target(false)
        .run()
        .await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    let expected_map = (0_i32..20)
        .map(|key| format!("{key}: {}", key * 3 + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let expected_set = (0_i32..20)
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        stdout.contains(&format!(
            "RBTREE_INTERNAL_MAP:BTreeMap(size=20) {{{expected_map}}}"
        )),
        "Expected complete internal Rust BTreeMap output: {stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "RBTREE_INTERNAL_SET:BTreeSet(size=20) {{{expected_set}}}"
        )),
        "Expected complete internal Rust BTreeSet output: {stdout}"
    );
    assert!(
        !stdout.contains("<truncated>"),
        "Unexpected truncation: {stdout}"
    );
    assert!(!stdout.contains("<INVALID_"), "Invalid payload: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_rust_script_print_deep_btree_keeps_valid_truncated_prefix() -> anyhow::Result<()> {
    init();

    let target = spawn_rust_global_program().await?;
    let script = r#"
trace observe_deep_btree_collections {
    print "RBTREE_DEEP_MAP:{}", map;
    print "RBTREE_DEEP_SET:{}", set;
}
"#;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 9, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    for marker in ["RBTREE_DEEP_MAP:BTreeMap", "RBTREE_DEEP_SET:BTreeSet"] {
        let line = stdout
            .lines()
            .find(|line| line.contains(marker))
            .ok_or_else(|| anyhow::anyhow!("missing {marker} output: {stdout}"))?;
        assert!(line.contains("size=160"), "{line}");
        assert!(line.contains("<truncated>"), "{line}");
        assert!(!line.contains("<INVALID_"), "{line}");
    }
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

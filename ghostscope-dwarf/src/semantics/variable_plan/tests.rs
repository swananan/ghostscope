use super::*;
use crate::core::{AddressExpr, EntryValueCase, MemoryAccessSize, TargetArch};
use crate::StructMember;

fn capabilities(regular_uprobe: bool) -> RuntimeCapabilities {
    RuntimeCapabilities {
        regular_uprobe,
        sleepable_uprobe: false,
        uprobe_multi: false,
        copy_from_user_task: false,
        max_bpf_stack_bytes: 512,
        bounded_loops: true,
        arch: TargetArch::X86_64,
    }
}

fn read_plan(location: VariableLocation) -> VariableReadPlan {
    VariableReadPlan {
        name: "value".to_string(),
        type_name: "int".to_string(),
        access_path: VariableAccessPath::default(),
        module_path: None,
        dwarf_type: None,
        declaration: None,
        type_id: None,
        location,
        availability: Availability::Available,
        scope_depth: 0,
        is_parameter: false,
        is_artificial: false,
        pc_range: None,
        inline_context: None,
        provenance: Provenance::DirectDie,
    }
}

fn typed_read_plan(location: VariableLocation, dwarf_type: TypeInfo) -> VariableReadPlan {
    VariableReadPlan {
        type_name: dwarf_type.type_name(),
        dwarf_type: Some(dwarf_type),
        ..read_plan(location)
    }
}

#[test]
fn lvalue_address_plan_accepts_address_locations_without_type_info() {
    let plan = read_plan(VariableLocation::RegisterAddress {
        dwarf_reg: 6,
        offset: -16,
    });

    let lvalue = plan.lvalue_address_plan();

    assert_eq!(
        lvalue,
        LvalueAddressPlan::Address {
            address: PlannedAddress {
                kind: PlannedAddressKind::RegisterOffset {
                    dwarf_reg: 6,
                    offset: -16
                },
                origin: AddressOrigin::RuntimeDerived,
            }
        }
    );
}

#[test]
fn lvalue_address_plan_rejects_value_backed_locations() {
    let plan = read_plan(VariableLocation::RegisterValue { dwarf_reg: 0 });

    let lvalue = plan.lvalue_address_plan();

    assert!(matches!(
        lvalue,
        LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::AddressClass { .. })
        }
    ));
    match lvalue {
        LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::AddressClass { detail }),
        } => {
            assert!(detail.contains("value-backed"));
        }
        other => panic!("unexpected lvalue availability: {other:?}"),
    }
}

#[test]
fn lvalue_address_plan_rejects_absolute_address_values() {
    let plan = read_plan(VariableLocation::AbsoluteAddressValue(
        AddressExpr::constant(0x2000),
    ));

    let lvalue = plan.lvalue_address_plan();

    match lvalue {
        LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::AddressClass { detail }),
        } => {
            assert!(detail.contains("value-backed"));
        }
        other => panic!("unexpected lvalue availability: {other:?}"),
    }
}

#[test]
fn lvalue_address_plan_rejects_piece_locations() {
    let plan = read_plan(VariableLocation::Pieces(vec![PieceLocation {
        bit_offset: 0,
        bit_size: 32,
        location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
    }]));

    let lvalue = plan.lvalue_address_plan();

    match lvalue {
        LvalueAddressPlan::Unavailable {
            availability: Availability::Unsupported(UnsupportedReason::ExpressionShape { detail }),
        } => {
            assert!(detail.contains("split variable pieces"));
        }
        other => panic!("unexpected lvalue availability: {other:?}"),
    }
}

#[test]
fn lvalue_address_plan_preserves_optimized_out_availability() {
    let plan = VariableReadPlan {
        availability: Availability::OptimizedOut,
        ..read_plan(VariableLocation::OptimizedOut)
    };

    let lvalue = plan.lvalue_address_plan();

    assert_eq!(
        lvalue,
        LvalueAddressPlan::Unavailable {
            availability: Availability::OptimizedOut
        }
    );
}

#[test]
fn register_value_lowers_without_runtime_requirements() {
    let plan = read_plan(VariableLocation::RegisterValue { dwarf_reg: 0 });
    let lowering = plan.bpf_lowering_plan(&capabilities(false));

    assert_eq!(lowering.kind, VariableLoweringKind::DirectValue);
    assert_eq!(lowering.availability, Availability::Available);
    assert!(lowering.requirements.is_empty());
}

#[test]
fn memory_location_requires_user_memory_read() {
    let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
    let lowering = plan.bpf_lowering_plan(&capabilities(false));

    assert_eq!(lowering.kind, VariableLoweringKind::UserMemoryRead);
    assert_eq!(
        lowering.availability,
        Availability::Requires(RuntimeRequirement::UserMemoryRead)
    );
    assert_eq!(
        lowering.requirements,
        vec![RuntimeRequirement::UserMemoryRead]
    );
}

#[test]
fn memory_location_is_available_with_regular_uprobe() {
    let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
    let lowering = plan.bpf_lowering_plan(&capabilities(true));

    assert_eq!(lowering.kind, VariableLoweringKind::UserMemoryRead);
    assert_eq!(lowering.availability, Availability::Available);
    assert_eq!(lowering.helper_mode, HelperMode::ProbeReadUser);
    assert_eq!(lowering.verifier_risk, VerifierRisk::Low);
    assert!(lowering.required_registers.is_empty());
}

#[test]
fn materialization_plan_preserves_link_time_address_origin() {
    let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
    let materialized = plan.materialization_plan(&capabilities(true));

    match materialized.materialization {
        VariableMaterialization::UserMemoryRead { address } => {
            assert_eq!(address.origin, AddressOrigin::LinkTime);
            assert_eq!(address.constant_link_time_address(), Some(0x1000));
            assert_eq!(
                address.kind,
                PlannedAddressKind::Constant { address: 0x1000 }
            );
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_preserves_module_path_origin() {
    let mut plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
    plan.module_path = Some(PathBuf::from("/tmp/libstate.so"));

    let materialized = plan.materialization_plan(&capabilities(true));

    assert_eq!(
        materialized.module_path,
        Some(PathBuf::from("/tmp/libstate.so"))
    );
}

#[test]
fn materialization_plan_converts_register_address_to_address_kind() {
    let plan = read_plan(VariableLocation::RegisterAddress {
        dwarf_reg: 6,
        offset: -16,
    });
    let materialized = plan.materialization_plan(&capabilities(true));

    match materialized.materialization {
        VariableMaterialization::UserMemoryRead { address } => {
            assert_eq!(address.origin, AddressOrigin::RuntimeDerived);
            assert_eq!(
                address.kind,
                PlannedAddressKind::RegisterOffset {
                    dwarf_reg: 6,
                    offset: -16
                }
            );
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_marks_static_base_before_deref() {
    let plan = read_plan(VariableLocation::ComputedAddress(vec![
        PlanExprOp::PushConstant(0x3000),
        PlanExprOp::Dereference {
            size: MemoryAccessSize::U64,
        },
        PlanExprOp::PushConstant(16),
        PlanExprOp::Add,
    ]));
    let materialized = plan.materialization_plan(&capabilities(true));

    match materialized.materialization {
        VariableMaterialization::UserMemoryRead { address } => {
            assert_eq!(address.origin, AddressOrigin::LinkTimeBase);
            match &address.kind {
                PlannedAddressKind::RuntimeComputed { expr } => {
                    assert_eq!(expr.kind(), RuntimeComputedKind::Address);
                }
                other => panic!("unexpected address kind: {other:?}"),
            }
            let (base, tail) = address
                .link_time_base_and_runtime_tail()
                .expect("link-time base");
            assert_eq!(base, 0x3000);
            assert_eq!(tail.len(), 3);
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_preserves_arithmetic_before_first_deref() {
    let plan = read_plan(VariableLocation::ComputedAddress(vec![
        PlanExprOp::PushConstant(0x3000),
        PlanExprOp::PushConstant(8),
        PlanExprOp::Add,
        PlanExprOp::Dereference {
            size: MemoryAccessSize::U64,
        },
    ]));
    let materialized = plan.materialization_plan(&capabilities(true));

    match materialized.materialization {
        VariableMaterialization::UserMemoryRead { address } => {
            assert_eq!(address.origin, AddressOrigin::LinkTimeBase);
            let (base, tail) = address
                .link_time_base_and_runtime_tail()
                .expect("link-time base");
            assert_eq!(base, 0x3000);
            assert_eq!(
                tail,
                &[
                    PlanExprOp::PushConstant(8),
                    PlanExprOp::Add,
                    PlanExprOp::Dereference {
                        size: MemoryAccessSize::U64,
                    },
                ]
            );
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_keeps_absolute_address_value_direct() {
    let plan = read_plan(VariableLocation::AbsoluteAddressValue(
        AddressExpr::constant(0x2000),
    ));
    let materialized = plan.materialization_plan(&capabilities(false));

    match materialized.materialization {
        VariableMaterialization::DirectValue {
            value:
                PlannedValue::AddressValue {
                    address:
                        PlannedAddress {
                            origin: AddressOrigin::LinkTime,
                            kind: PlannedAddressKind::Constant { address: 0x2000 },
                            ..
                        },
                    size: MemoryAccessSize::U64,
                },
        } => {}
        VariableMaterialization::DirectValue { value } => {
            panic!("unexpected direct value: {value:?}");
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_converts_constant_direct_value() {
    let plan = read_plan(VariableLocation::ComputedValue(vec![
        PlanExprOp::PushConstant(42),
    ]));
    let materialized = plan.materialization_plan(&capabilities(false));

    match materialized.materialization {
        VariableMaterialization::DirectValue {
            value:
                PlannedValue::Constant {
                    value: 42,
                    size: MemoryAccessSize::U64,
                },
        } => {}
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_records_direct_value_size_from_type() {
    let byte_type = TypeInfo::BaseType {
        name: "uint8_t".to_string(),
        size: 1,
        encoding: gimli::constants::DW_ATE_unsigned.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::ComputedValue(vec![
            PlanExprOp::LoadRegister(0),
            PlanExprOp::PushConstant(1),
            PlanExprOp::Add,
        ]),
        byte_type,
    );
    let materialized = plan.materialization_plan(&capabilities(false));

    match materialized.materialization {
        VariableMaterialization::DirectValue {
            value:
                PlannedValue::RuntimeComputed {
                    ref expr,
                    result_size: MemoryAccessSize::U8,
                    ..
                },
        } => {
            assert_eq!(expr.kind(), RuntimeComputedKind::Value);
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_converts_register_direct_value() {
    let plan = read_plan(VariableLocation::RegisterValue { dwarf_reg: 6 });
    let materialized = plan.materialization_plan(&capabilities(false));

    match materialized.materialization {
        VariableMaterialization::DirectValue {
            value:
                PlannedValue::RegisterValue {
                    dwarf_reg: 6,
                    size: MemoryAccessSize::U64,
                },
        } => {}
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn materialization_plan_surfaces_piece_locations_without_first_piece_fallback() {
    let plan = read_plan(VariableLocation::Pieces(vec![PieceLocation {
        bit_offset: 0,
        bit_size: 32,
        location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
    }]));
    let materialized = plan.materialization_plan(&capabilities(true));

    match materialized.materialization {
        VariableMaterialization::Composite { pieces } => {
            assert_eq!(pieces.len(), 1);
        }
        other => panic!("unexpected materialization: {other:?}"),
    }
}

#[test]
fn absolute_address_value_lowers_without_user_memory_read() {
    let plan = read_plan(VariableLocation::AbsoluteAddressValue(
        AddressExpr::constant(0x1000),
    ));
    let lowering = plan.bpf_lowering_plan(&capabilities(false));

    assert_eq!(lowering.kind, VariableLoweringKind::DirectValue);
    assert_eq!(lowering.availability, Availability::Available);
    assert!(lowering.requirements.is_empty());
}

#[test]
fn memory_location_prefers_copy_from_user_task_when_available() {
    let mut capabilities = capabilities(false);
    capabilities.sleepable_uprobe = true;
    capabilities.copy_from_user_task = true;
    let plan = read_plan(VariableLocation::Address(AddressExpr::constant(0x1000)));
    let lowering = plan.bpf_lowering_plan(&capabilities);

    assert_eq!(lowering.availability, Availability::Available);
    assert_eq!(lowering.helper_mode, HelperMode::CopyFromUserTask);
}

#[test]
fn register_address_records_required_register() {
    let plan = read_plan(VariableLocation::RegisterAddress {
        dwarf_reg: 6,
        offset: -16,
    });
    let lowering = plan.bpf_lowering_plan(&capabilities(true));

    assert_eq!(lowering.required_registers, vec![6]);
    assert_eq!(lowering.estimated_stack_bytes, 8);
}

#[test]
fn entry_value_steps_surface_caller_frame_and_memory_requirements() {
    let plan = read_plan(VariableLocation::ComputedValue(vec![
        PlanExprOp::EntryValueLookup {
            caller_pc_steps: vec![
                PlanExprOp::LoadRegister(7),
                PlanExprOp::Dereference {
                    size: MemoryAccessSize::U64,
                },
            ],
            cases: vec![EntryValueCase {
                caller_return_pc: 0x10,
                value_steps: vec![PlanExprOp::LoadRegister(5)],
            }],
        },
    ]));
    let lowering = plan.bpf_lowering_plan(&capabilities(true));

    assert_eq!(lowering.availability, Availability::Available);
    assert_eq!(
        lowering.requirements,
        vec![
            RuntimeRequirement::CallerFrame,
            RuntimeRequirement::UserMemoryRead
        ]
    );
    assert_eq!(lowering.required_registers, vec![5, 7]);
    assert_eq!(lowering.verifier_risk, VerifierRisk::RequiresBoundedLoops);
}

#[test]
fn stack_budget_excess_reports_unsupported_availability() {
    let mut capabilities = capabilities(true);
    capabilities.max_bpf_stack_bytes = 16;
    let plan = read_plan(VariableLocation::ComputedValue(vec![
        PlanExprOp::PushConstant(1);
        8
    ]));
    let lowering = plan.bpf_lowering_plan(&capabilities);

    assert!(matches!(
        lowering.availability,
        Availability::Unsupported(UnsupportedReason::ExpressionShape { .. })
    ));
    assert_eq!(
        lowering.verifier_risk,
        VerifierRisk::StackBudgetExceeded {
            estimated: 64,
            max: 16,
        }
    );
}

#[test]
fn field_access_adds_member_offset_and_type() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -32,
        },
        TypeInfo::StructType {
            name: "Request".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "fd".to_string(),
                member_type: int_type.clone(),
                offset: 12,
                bit_offset: None,
                bit_size: None,
            }],
        },
    );

    let access = VariableAccessPath::fields(["fd"]);
    let planned = plan.plan_access_path(&access).expect("field access");

    assert_eq!(planned.name, "value.fd");
    assert_eq!(planned.access_path, access);
    assert_eq!(planned.dwarf_type, Some(int_type));
    assert_eq!(
        planned.location,
        VariableLocation::RegisterAddress {
            dwarf_reg: 6,
            offset: -20,
        }
    );
    assert_eq!(
        planned
            .materialization_plan(&capabilities(true))
            .access_path
            .segments,
        vec![VariableAccessSegment::Field("fd".to_string())]
    );
}

#[test]
fn resolved_tuple_access_uses_dwarf_field_but_preserves_source_path() {
    let int_type = TypeInfo::BaseType {
        name: "i32".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::Address(AddressExpr::constant(0x1000)),
        TypeInfo::StructType {
            name: "Pair".to_string(),
            size: 8,
            members: vec![StructMember {
                name: "__1".to_string(),
                member_type: int_type.clone(),
                offset: 4,
                bit_offset: None,
                bit_size: None,
            }],
        },
    );

    let planned = plan
        .plan_resolved_access_segment(
            &VariableAccessSegment::TupleIndex(1),
            &VariableAccessSegment::Field("__1".to_string()),
        )
        .expect("resolved tuple access");

    assert_eq!(planned.name, "value.1");
    assert_eq!(
        planned.access_path.segments,
        vec![VariableAccessSegment::TupleIndex(1)]
    );
    assert_eq!(planned.dwarf_type, Some(int_type));
    assert_eq!(
        planned.location,
        VariableLocation::Address(AddressExpr::constant(0x1004))
    );
}

#[test]
fn field_access_unknown_member_reports_known_members() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::Address(AddressExpr::constant(0x1000)),
        TypeInfo::StructType {
            name: "Request".to_string(),
            size: 8,
            members: vec![
                StructMember {
                    name: "fd".to_string(),
                    member_type: int_type.clone(),
                    offset: 0,
                    bit_offset: None,
                    bit_size: None,
                },
                StructMember {
                    name: "flags".to_string(),
                    member_type: int_type,
                    offset: 4,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        },
    );

    let err = plan
        .plan_access_path(&VariableAccessPath::fields(["missing"]))
        .expect_err("unknown member should fail");

    assert_eq!(
        err.to_string(),
        "Unknown member 'missing' in struct 'Request' (known members: fd, flags)"
    );
}

#[test]
fn field_access_folds_constant_address_offsets() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::Address(AddressExpr::constant(0x1000)),
        TypeInfo::StructType {
            name: "Request".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "fd".to_string(),
                member_type: int_type,
                offset: 12,
                bit_offset: None,
                bit_size: None,
            }],
        },
    );

    let planned = plan
        .plan_access_path(&VariableAccessPath::fields(["fd"]))
        .expect("field access");

    assert_eq!(
        planned.location,
        VariableLocation::Address(AddressExpr::constant(0x100c))
    );
}

#[test]
fn field_access_rejects_value_backed_aggregates() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let struct_type = TypeInfo::StructType {
        name: "Pair".to_string(),
        size: 8,
        members: vec![StructMember {
            name: "b".to_string(),
            member_type: int_type,
            offset: 4,
            bit_offset: None,
            bit_size: None,
        }],
    };
    let access = VariableAccessPath::fields(["b"]);

    for location in [
        VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
        VariableLocation::RegisterValue { dwarf_reg: 0 },
        VariableLocation::ComputedValue(vec![PlanExprOp::LoadRegister(0)]),
    ] {
        let plan = typed_read_plan(location, struct_type.clone());
        let err = plan
            .plan_access_path(&access)
            .expect_err("value-backed aggregate field access should fail");
        assert!(
            err.downcast_ref::<PlanError>()
                .is_some_and(PlanError::is_value_backed_aggregate_access),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn array_index_rejects_value_backed_aggregates() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let array_type = TypeInfo::ArrayType {
        element_type: Box::new(int_type),
        element_count: Some(2),
        total_size: Some(8),
    };
    let access = VariableAccessPath::new(vec![VariableAccessSegment::ArrayIndex(1)]);

    for location in [
        VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
        VariableLocation::RegisterValue { dwarf_reg: 0 },
        VariableLocation::ComputedValue(vec![PlanExprOp::LoadRegister(0)]),
    ] {
        let plan = typed_read_plan(location, array_type.clone());
        let err = plan
            .plan_access_path(&access)
            .expect_err("value-backed aggregate array access should fail");
        assert!(
            err.downcast_ref::<PlanError>()
                .is_some_and(PlanError::is_value_backed_aggregate_access),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn pointer_field_access_dereferences_then_offsets() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let struct_type = TypeInfo::StructType {
        name: "Node".to_string(),
        size: 16,
        members: vec![StructMember {
            name: "value".to_string(),
            member_type: int_type,
            offset: 8,
            bit_offset: None,
            bit_size: None,
        }],
    };
    let plan = typed_read_plan(
        VariableLocation::RegisterValue { dwarf_reg: 5 },
        TypeInfo::PointerType {
            target_type: Box::new(struct_type),
            size: 8,
        },
    );

    let access = VariableAccessPath::fields(["value"]);
    let planned = plan.plan_access_path(&access).expect("pointer field");

    assert_eq!(
        planned.location,
        VariableLocation::ComputedAddress(vec![
            PlanExprOp::LoadRegister(5),
            PlanExprOp::PushConstant(8),
            PlanExprOp::Add,
        ])
    );
}

#[test]
fn pointer_field_access_from_absolute_address_value_rebases_memory_location() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let struct_type = TypeInfo::StructType {
        name: "Node".to_string(),
        size: 16,
        members: vec![StructMember {
            name: "value".to_string(),
            member_type: int_type,
            offset: 8,
            bit_offset: None,
            bit_size: None,
        }],
    };
    let plan = typed_read_plan(
        VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1000)),
        TypeInfo::PointerType {
            target_type: Box::new(struct_type),
            size: 8,
        },
    );

    let planned = plan
        .plan_access_path(&VariableAccessPath::fields(["value"]))
        .expect("pointer field");

    assert_eq!(
        planned.location,
        VariableLocation::Address(AddressExpr::constant(0x1008))
    );
}

#[test]
fn pointer_field_access_from_computed_value_uses_value_as_address() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let struct_type = TypeInfo::StructType {
        name: "Node".to_string(),
        size: 16,
        members: vec![StructMember {
            name: "value".to_string(),
            member_type: int_type,
            offset: 8,
            bit_offset: None,
            bit_size: None,
        }],
    };
    let plan = typed_read_plan(
        VariableLocation::ComputedValue(vec![PlanExprOp::PushConstant(0x2000)]),
        TypeInfo::PointerType {
            target_type: Box::new(struct_type),
            size: 8,
        },
    );

    let planned = plan
        .plan_access_path(&VariableAccessPath::fields(["value"]))
        .expect("pointer field");

    assert_eq!(
        planned.location,
        VariableLocation::ComputedAddress(vec![
            PlanExprOp::PushConstant(0x2000),
            PlanExprOp::PushConstant(8),
            PlanExprOp::Add,
        ])
    );
}

#[test]
fn pointer_element_index_is_planned_in_dwarf_semantics() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::RegisterValue { dwarf_reg: 5 },
        TypeInfo::PointerType {
            target_type: Box::new(int_type),
            size: 8,
        },
    );

    let planned = plan
        .plan_pointer_element_index(3)
        .expect("pointer element index");

    assert_eq!(planned.name, "value[3]");
    assert_eq!(
        planned.location,
        VariableLocation::ComputedAddress(vec![
            PlanExprOp::LoadRegister(5),
            PlanExprOp::PushConstant(12),
            PlanExprOp::Add,
        ])
    );
}

#[test]
fn pointer_element_index_rejects_aggregate_arithmetic_with_pointer_error() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::Address(AddressExpr::constant(0x1000)),
        TypeInfo::StructType {
            name: "GlobalState".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "counter".to_string(),
                member_type: int_type,
                offset: 0,
                bit_offset: None,
                bit_size: None,
            }],
        },
    );

    let err = plan
        .plan_pointer_element_index(1)
        .expect_err("struct arithmetic must be rejected");
    let plan_error = err
        .downcast_ref::<PlanError>()
        .expect("structured plan error");
    assert!(matches!(
        plan_error,
        PlanError::InvalidPointerArithmetic { type_name }
            if type_name == "struct GlobalState"
    ));
}

#[test]
fn array_index_access_uses_element_stride() {
    let int_type = TypeInfo::BaseType {
        name: "int".to_string(),
        size: 4,
        encoding: gimli::constants::DW_ATE_signed.0 as u16,
    };
    let plan = typed_read_plan(
        VariableLocation::Address(AddressExpr::constant(0x1000)),
        TypeInfo::ArrayType {
            element_type: Box::new(int_type),
            element_count: Some(8),
            total_size: Some(32),
        },
    );

    let access = VariableAccessPath::new(vec![VariableAccessSegment::ArrayIndex(3)]);
    let planned = plan.plan_access_path(&access).expect("array index");

    assert_eq!(planned.name, "value[3]");
    assert_eq!(
        planned.location,
        VariableLocation::Address(AddressExpr::constant(0x100c))
    );
}

use super::*;
use ghostscope_dwarf::{
    DiscriminantRange, DiscriminantValue, HashTableBucketOrder, HashTableBucketSource,
    HashTableEntryPresentation, HashTableFieldPresentation, HashTableOccupancy, MemoryAccessSize,
    ProjectedValueRead, ProjectedValueStep, ProjectedViewField, ResolvedType, StructMember,
    TypeIdentity, TypeInfo, TypeProjection, TypeProjectionLayout, ValueCapturePlan,
    ValueNestedHashTableFieldPlan, ValueNestedPlan, ValueNestedVariantCondition,
    ValueNestedVariantFieldPlan, ValuePresentation, ValueReadPlan,
};

fn projection(size: u64) -> TypeProjection {
    let encoding = ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16;
    TypeProjection {
        layout: TypeProjectionLayout::Member { offset: 0 },
        resolved_type: ResolvedType::new(
            TypeInfo::BaseType {
                name: "metadata".to_string(),
                size,
                encoding,
            },
            TypeIdentity::Unknown,
            None,
        ),
    }
}

#[test]
fn maps_indirect_metadata_size_from_projected_dwarf_type() {
    assert_eq!(
        metadata_access_size(&projection(4), "data").unwrap(),
        MemoryAccessSize::U32
    );
    assert_eq!(
        metadata_access_size(&projection(8), "length").unwrap(),
        MemoryAccessSize::U64
    );
}

#[test]
fn rejects_unsupported_indirect_metadata_size() {
    let projected = projection(3);
    let error = metadata_access_size(&projected, "data").unwrap_err();

    assert!(error.to_string().contains("unsupported DWARF size 3"));
}

#[test]
fn btree_capture_limits_reserve_complete_fixed_node_records() {
    let header = ghostscope_protocol::BTREE_HEADER_SIZE;
    assert_eq!(
        btree_capture_limits(108, 2, 4, Some(2)).unwrap(),
        (3, 108, header + 108)
    );
    assert_eq!(
        btree_capture_limits(107, 2, 4, Some(2)).unwrap(),
        (2, 72, header + 72)
    );

    let zst_record_size = ghostscope_protocol::BTREE_NODE_HEADER_SIZE;
    assert_eq!(
        btree_capture_limits(zst_record_size * 20, 11, 0, Some(0)).unwrap(),
        (16, zst_record_size * 16, header + zst_record_size * 16,)
    );
}

#[test]
fn reads_projected_value_offset_without_assuming_field_names() {
    let mut projected = projection(4);
    projected.layout = TypeProjectionLayout::Member { offset: 12 };

    assert_eq!(
        projected_member_offset(&projected, "projected value").unwrap(),
        12
    );

    projected.layout = TypeProjectionLayout::Dereference;
    let error = projected_member_offset(&projected, "projected value").unwrap_err();
    assert!(error.to_string().contains("must be a member"));
}

#[test]
fn distinguishes_known_zero_sized_types_from_unknown_layouts() {
    let unit = TypeInfo::BaseType {
        name: "()".to_string(),
        size: 0,
        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
    };
    let unknown = TypeInfo::UnknownType {
        name: "T".to_string(),
    };

    assert!(is_known_zero_sized_type(&unit));
    assert!(!is_known_zero_sized_type(&unknown));
}

#[test]
fn inline_view_requires_the_exact_dwarf_root_size() {
    let physical = TypeInfo::StructType {
        name: "Physical".to_string(),
        size: 16,
        members: Vec::new(),
    };
    let view = TypeInfo::StructType {
        name: "Semantic".to_string(),
        size: 16,
        members: Vec::new(),
    };
    assert_eq!(inline_view_data_len(&physical, &view).unwrap(), 16);

    let undersized = TypeInfo::StructType {
        name: "Semantic".to_string(),
        size: 8,
        members: Vec::new(),
    };
    let error = inline_view_data_len(&physical, &undersized).unwrap_err();
    assert!(error
        .to_string()
        .contains("does not match DWARF root size 16"));
}

fn projected_field(
    output_offset: u64,
    summary: TypeInfo,
    steps: Vec<ProjectedValueStep>,
) -> ProjectedViewField {
    ProjectedViewField {
        output_offset,
        value: ProjectedValueRead {
            steps,
            resolved_type: ResolvedType::new(summary, TypeIdentity::Unknown, None),
        },
        capture: ghostscope_dwarf::ProjectedViewFieldCapture::Value,
    }
}

fn output_member(name: &str, member_type: TypeInfo, offset: u64) -> StructMember {
    StructMember {
        name: name.to_string(),
        member_type,
        offset,
        bit_offset: None,
        bit_size: None,
    }
}

#[test]
fn projected_view_uses_exact_output_and_pointer_layouts() {
    let value_type = TypeInfo::BaseType {
        name: "i32".to_string(),
        size: 4,
        encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
    };
    let borrow_type = TypeInfo::BaseType {
        name: "isize".to_string(),
        size: 8,
        encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
    };
    let output_type = TypeInfo::StructType {
        name: "Ref".to_string(),
        size: 12,
        members: vec![
            output_member("*value", value_type.clone(), 0),
            output_member("borrow", borrow_type.clone(), 4),
        ],
    };
    let fields = vec![
        projected_field(
            0,
            value_type,
            vec![
                ProjectedValueStep::Member { offset: 8 },
                ProjectedValueStep::Dereference { pointer_size: 8 },
            ],
        ),
        projected_field(
            4,
            borrow_type,
            vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
        ),
    ];

    let (data_len, sources) = projected_view_source(&output_type, &fields).unwrap();
    assert_eq!(data_len, 12);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].output_offset, 0);
    assert_eq!(sources[0].value_len, 4);
    assert!(matches!(
        sources[0].steps.as_slice(),
        [
            ProjectedViewStep::Member { offset: 8 },
            ProjectedViewStep::Dereference {
                pointer_size: MemoryAccessSize::U64
            }
        ]
    ));
}

#[test]
fn projected_view_accepts_a_dwarf_sized_address_field() {
    let target = TypeInfo::ArrayType {
        element_type: Box::new(TypeInfo::BaseType {
            name: "u8".to_string(),
            size: 1,
            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
        }),
        element_count: None,
        total_size: None,
    };
    let pointer = TypeInfo::PointerType {
        target_type: Box::new(target.clone()),
        size: 8,
    };
    let output_type = TypeInfo::StructType {
        name: "Rc".to_string(),
        size: 8,
        members: vec![output_member("ptr", pointer, 0)],
    };
    let fields = vec![ProjectedViewField {
        output_offset: 0,
        value: ProjectedValueRead {
            steps: vec![
                ProjectedValueStep::Dereference { pointer_size: 8 },
                ProjectedValueStep::Member { offset: 16 },
            ],
            resolved_type: ResolvedType::new(target, TypeIdentity::Unknown, None),
        },
        capture: ghostscope_dwarf::ProjectedViewFieldCapture::Address,
    }];

    let (data_len, sources) = projected_view_source(&output_type, &fields).unwrap();
    assert_eq!(data_len, 8);
    assert_eq!(sources[0].value_len, 8);
    assert_eq!(
        sources[0].capture,
        ghostscope_dwarf::ProjectedViewFieldCapture::Address
    );
}

#[test]
fn projected_view_accepts_packed_zero_sized_fields() {
    let unit = TypeInfo::BaseType {
        name: "()".to_string(),
        size: 0,
        encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
    };
    let borrow = TypeInfo::BaseType {
        name: "isize".to_string(),
        size: 8,
        encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
    };
    let output_type = TypeInfo::StructType {
        name: "Ref".to_string(),
        size: 8,
        members: vec![
            output_member("*value", unit.clone(), 0),
            output_member("borrow", borrow.clone(), 0),
        ],
    };
    let fields = vec![
        projected_field(
            0,
            unit,
            vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
        ),
        projected_field(
            0,
            borrow,
            vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
        ),
    ];

    let (data_len, sources) = projected_view_source(&output_type, &fields).unwrap();
    assert_eq!(data_len, 8);
    assert_eq!(sources[0].value_len, 0);
    assert_eq!(sources[1].output_offset, 0);
}

#[test]
fn projected_view_rejects_invalid_protocol_and_field_layouts() {
    let oversized = TypeInfo::StructType {
        name: "Oversized".to_string(),
        size: u16::MAX as u64 + 1,
        members: Vec::new(),
    };
    let error = projected_view_source(&oversized, &[]).unwrap_err();
    assert!(error.to_string().contains("exceeds the protocol limit"));

    let value_type = TypeInfo::BaseType {
        name: "i32".to_string(),
        size: 4,
        encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
    };
    let overlapping = TypeInfo::StructType {
        name: "Overlap".to_string(),
        size: 6,
        members: vec![
            output_member("left", value_type.clone(), 0),
            output_member("right", value_type.clone(), 2),
        ],
    };
    let fields = vec![
        projected_field(0, value_type.clone(), Vec::new()),
        projected_field(2, value_type.clone(), Vec::new()),
    ];
    let error = projected_view_source(&overlapping, &fields).unwrap_err();
    assert!(error.to_string().contains("overlaps another output member"));

    let output = TypeInfo::StructType {
        name: "Pointer".to_string(),
        size: 4,
        members: vec![output_member("value", value_type.clone(), 0)],
    };
    let fields = vec![projected_field(
        0,
        value_type,
        vec![ProjectedValueStep::Dereference { pointer_size: 3 }],
    )];
    let error = projected_view_source(&output, &fields).unwrap_err();
    assert!(error.to_string().contains("unsupported DWARF size 3"));
}

fn resolved_struct(name: &str, size: u64) -> ResolvedType {
    ResolvedType::new(
        TypeInfo::StructType {
            name: name.to_string(),
            size,
            members: Vec::new(),
        },
        TypeIdentity::Unknown,
        None,
    )
}

fn string_value_plan() -> ValueReadPlan {
    ValueReadPlan {
        root_type: resolved_struct("String", 24),
        presentation: ValuePresentation::Utf8String,
        capture: ValueCapturePlan::IndirectBytes {
            data: projection(8),
            length: projection(8),
            excluded_tail_bytes: 0,
        },
        sequence_element: None,
        hash_table_fields: Vec::new(),
        nested: None,
    }
}

fn nested_string_sequence_plan() -> ValueReadPlan {
    let string = string_value_plan();
    ValueReadPlan {
        root_type: resolved_struct("Vec<String>", 24),
        presentation: ValuePresentation::Sequence {
            element_type: Box::new(string.root_type.summary.clone()),
            element_stride: 24,
        },
        capture: ValueCapturePlan::IndirectSequence {
            data: projection(8),
            length: projection(8),
            element_stride: 24,
        },
        sequence_element: Some(string.root_type.clone()),
        hash_table_fields: Vec::new(),
        nested: Some(ValueNestedPlan::Sequence {
            element: Box::new(string),
        }),
    }
}

fn many_variant_strings_plan(variant_count: usize) -> ValueReadPlan {
    let root_type = resolved_struct("ManyStringVariants", 32);
    let discriminant = output_member(
        "tag",
        TypeInfo::BaseType {
            name: "u8".to_string(),
            size: 1,
            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
        },
        0,
    );
    let fields = (0..variant_count)
        .map(|variant_index| ValueNestedVariantFieldPlan {
            part_index: 0,
            variant_index,
            member_index: 0,
            payload_field_index: 0,
            steps: vec![ProjectedValueStep::Member { offset: 8 }],
            condition: ValueNestedVariantCondition::Discriminant {
                member: discriminant.clone(),
                ranges: vec![DiscriminantRange {
                    start: DiscriminantValue::Unsigned(variant_index as u64),
                    end: DiscriminantValue::Unsigned(variant_index as u64),
                }],
                inverted: false,
            },
            value: Box::new(string_value_plan()),
        })
        .collect();

    ValueReadPlan {
        root_type: root_type.clone(),
        presentation: ValuePresentation::Dwarf,
        capture: ValueCapturePlan::InlineView {
            output_type: root_type.summary,
            fields: Vec::new(),
        },
        sequence_element: None,
        hash_table_fields: Vec::new(),
        nested: Some(ValueNestedPlan::Variant { fields }),
    }
}

fn nested_string_hash_map_plan() -> ValueReadPlan {
    let key = string_value_plan();
    let value = string_value_plan();
    let entry_type = key.root_type.summary.clone();
    ValueReadPlan {
        root_type: resolved_struct("HashMap<String, String>", 48),
        presentation: ValuePresentation::HashTable {
            entry_stride: 48,
            bucket_order: HashTableBucketOrder::Reverse,
            occupancy: HashTableOccupancy::ControlByteHighBitClear,
            entry: HashTableEntryPresentation::Map {
                key: HashTableFieldPresentation {
                    offset: 0,
                    field_type: Box::new(entry_type.clone()),
                },
                value: HashTableFieldPresentation {
                    offset: 24,
                    field_type: Box::new(entry_type),
                },
            },
        },
        capture: ValueCapturePlan::IndirectHashTable {
            control: projection(8),
            length: projection(8),
            bucket_mask: projection(8),
            entry_stride: 48,
            occupancy: HashTableOccupancy::ControlByteHighBitClear,
            buckets: HashTableBucketSource::ReverseFromControl,
            bucket_order: HashTableBucketOrder::Reverse,
        },
        sequence_element: None,
        hash_table_fields: Vec::new(),
        nested: Some(ValueNestedPlan::HashTable {
            fields: vec![
                ValueNestedHashTableFieldPlan {
                    field_index: 0,
                    value: Box::new(key),
                },
                ValueNestedHashTableFieldPlan {
                    field_index: 1,
                    value: Box::new(value),
                },
            ],
        }),
    }
}

#[test]
fn nested_variant_capture_reuses_slots_across_mutually_exclusive_branches() {
    let source = compile_nested_value_source(&many_variant_strings_plan(16), 256, 4)
        .unwrap()
        .expect("mutually exclusive String variants should share one child slot");
    let NestedValueChildrenSource::Variant { fields } = &source.children else {
        panic!("expected nested variant source");
    };
    let child_budget =
        256 - source.root_payload_len - ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE;

    assert_eq!(fields.len(), 16);
    assert_eq!(source.total_len, 256);
    assert!(fields
        .iter()
        .all(|field| field.field.slot_offset == source.root_payload_len));
    assert!(fields
        .iter()
        .all(|field| field.field.child.total_len == child_budget));
}

#[test]
fn nested_sequence_capture_reduces_slots_to_fit_the_byte_budget() {
    let plan = nested_string_sequence_plan();

    let four_slots = compile_nested_value_source(&plan, 256, 4)
        .unwrap()
        .expect("256 bytes should fit four nested String slots");
    let NestedValueChildrenSource::Sequence {
        slot_count,
        element,
        ..
    } = &four_slots.children
    else {
        panic!("expected nested sequence source");
    };
    assert_eq!(*slot_count, 4);
    assert_eq!(element.total_len, 28);
    assert_eq!(four_slots.total_len, 256);

    let one_slot = compile_nested_value_source(&plan, 80, 4)
        .unwrap()
        .expect("80 bytes should fit one nested String slot");
    let NestedValueChildrenSource::Sequence { slot_count, .. } = one_slot.children else {
        panic!("expected nested sequence source");
    };
    assert_eq!(slot_count, 1);
    assert_eq!(one_slot.total_len, 80);
}

#[test]
fn nested_sequence_capture_respects_configured_element_limit() {
    let plan = nested_string_sequence_plan();

    let two_slots = compile_nested_value_source(&plan, 256, 2)
        .unwrap()
        .expect("256 bytes should fit two configured nested String slots");
    let NestedValueChildrenSource::Sequence { slot_count, .. } = two_slots.children else {
        panic!("expected nested sequence source");
    };
    assert_eq!(slot_count, 2);
}

#[test]
fn nested_hash_table_capture_reuses_field_plans_for_bounded_buckets() {
    let plan = nested_string_hash_map_plan();

    let source = compile_nested_value_source(&plan, 512, 4)
        .unwrap()
        .expect("512 bytes should fit four hash-table bucket sidecars");
    let NestedValueChildrenSource::HashTable {
        bucket_count,
        bucket_slot_stride,
        fields,
        ..
    } = &source.children
    else {
        panic!("expected nested hash-table source");
    };
    assert_eq!(*bucket_count, 4);
    assert_eq!(*bucket_slot_stride, 70);
    assert_eq!(fields.len(), 2);
    assert_eq!(source.total_len, 508);

    let tight = compile_nested_value_source(&plan, 256, 4)
        .unwrap()
        .expect("256 bytes should reduce the nested hash-table bucket count");
    let NestedValueChildrenSource::HashTable { bucket_count, .. } = tight.children else {
        panic!("expected nested hash-table source");
    };
    assert_eq!(bucket_count, 2);
    assert_eq!(tight.total_len, 254);

    let configured = compile_nested_value_source(&plan, 512, 2)
        .unwrap()
        .expect("configured nested element limit should retain a valid hash-table plan");
    let NestedValueChildrenSource::HashTable { bucket_count, .. } = configured.children else {
        panic!("expected nested hash-table source");
    };
    assert_eq!(bucket_count, 2);
}

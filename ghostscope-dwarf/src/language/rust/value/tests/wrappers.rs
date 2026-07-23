use super::*;

#[test]
fn recognizes_nonzero_by_namespace_and_unique_member_structure() {
    let current = rust_nonzero_type(
        "NonZero<u32>",
        "outer_from_dwarf",
        "inner_from_dwarf",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );

    assert_eq!(
        resolve_value_layout(&current, Some("core::num::nonzero::NonZero<u32>"),),
        Some(ValueLayout::ProjectedValue {
            value_path: field_path(&["outer_from_dwarf", "inner_from_dwarf"]),
            presentation: ProjectedValuePresentation::Transparent,
        })
    );

    let legacy = rust_legacy_nonzero_type(
        "NonZeroU32",
        "legacy_field_from_dwarf",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );
    assert_eq!(
        resolve_value_layout(&legacy, Some("core::num::nonzero::NonZeroU32"),),
        Some(ValueLayout::ProjectedValue {
            value_path: field_path(&["legacy_field_from_dwarf"]),
            presentation: ProjectedValuePresentation::Transparent,
        })
    );

    let fully_qualified_legacy = rust_legacy_nonzero_type(
        "core::num::NonZeroI64",
        "__0",
        TypeInfo::BaseType {
            name: "i64".to_string(),
            size: 8,
            encoding: gimli::DW_ATE_signed.0 as u16,
        },
        SourceLanguage::Rust,
    );
    assert!(resolve_value_layout(&fully_qualified_legacy, None).is_some());

    let fully_qualified = rust_nonzero_type(
        "core::num::nonzero::NonZero<i128>",
        "__0",
        "__0",
        TypeInfo::BaseType {
            name: "i128".to_string(),
            size: 16,
            encoding: gimli::DW_ATE_signed.0 as u16,
        },
        SourceLanguage::Rust,
    );
    assert!(resolve_value_layout(&fully_qualified, None).is_some());
}

#[test]
fn rejects_nonzero_lookalikes_and_invalid_layouts() {
    let current = rust_nonzero_type(
        "NonZero<u32>",
        "__0",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );
    assert_eq!(
        resolve_value_layout(&current, Some("app::NonZero<u32>")),
        None
    );
    assert_eq!(resolve_value_layout(&current, None), None);

    let legacy = rust_legacy_nonzero_type(
        "NonZeroU32",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );
    assert_eq!(resolve_value_layout(&legacy, Some("app::NonZeroU32")), None);
    assert_eq!(resolve_value_layout(&legacy, None), None);

    let mut invalid = current.clone();
    let TypeInfo::StructType { members, .. } = &mut invalid.summary else {
        unreachable!("test NonZero is a struct")
    };
    members.push(member("extra", unsigned_type("u32", 4), 0));
    assert_eq!(
        resolve_value_layout(&invalid, Some("core::num::nonzero::NonZero<u32>"),),
        None
    );

    let non_rust = rust_nonzero_type(
        "core::num::nonzero::NonZero<u32>",
        "__0",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::C,
    );
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn recognizes_cell_by_namespace_and_dwarf_member_structure() {
    let current = rust_cell_type(
        "Cell<(i32, u16)>",
        "outer_from_dwarf",
        "inner_from_dwarf",
        TypeInfo::StructType {
            name: "(i32, u16)".to_string(),
            size: 8,
            members: vec![
                member("__0", signed_type("i32", 4), 0),
                member("__1", unsigned_type("u16", 2), 4),
            ],
        },
        SourceLanguage::Rust,
    );

    assert_eq!(
        resolve_value_layout(&current, Some("core::cell::Cell<(i32, u16)>")),
        Some(ValueLayout::ProjectedValue {
            value_path: field_path(&["outer_from_dwarf", "inner_from_dwarf"]),
            presentation: ProjectedValuePresentation::SingleField {
                type_name: "Cell",
                field_name: "value",
            },
        })
    );

    let fully_qualified = rust_cell_type(
        "core::cell::Cell<u32>",
        "value",
        "value",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );
    assert!(resolve_value_layout(&fully_qualified, None).is_some());
}

#[test]
fn rejects_cell_lookalikes_and_invalid_layouts() {
    let current = rust_cell_type(
        "Cell<u32>",
        "value",
        "value",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    );
    assert_eq!(resolve_value_layout(&current, Some("app::Cell<u32>")), None);
    assert_eq!(resolve_value_layout(&current, None), None);

    let mut invalid = current.clone();
    let TypeInfo::StructType { members, .. } = &mut invalid.summary else {
        unreachable!("test Cell is a struct")
    };
    let TypeInfo::StructType {
        members: inner_members,
        ..
    } = &mut members[0].member_type
    else {
        unreachable!("test Cell contains a struct")
    };
    inner_members.push(member("extra", unsigned_type("u32", 4), 0));
    assert_eq!(
        resolve_value_layout(&invalid, Some("core::cell::Cell<u32>")),
        None
    );

    let non_rust = rust_cell_type(
        "core::cell::Cell<u32>",
        "value",
        "value",
        unsigned_type("u32", 4),
        SourceLanguage::C,
    );
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn recognizes_ref_cell_with_dwarf_derived_fields_and_widths() {
    let value_type = TypeInfo::StructType {
        name: "(i32, u16)".to_string(),
        size: 8,
        members: vec![
            member("__0", signed_type("i32", 4), 0),
            member("__1", unsigned_type("u16", 2), 4),
        ],
    };
    let current = rust_ref_cell_type(
        RefCellTestLayout {
            name: "RefCell<(i32, u16)>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        value_type,
    );

    assert_eq!(
        resolve_value_layout(&current, Some("core::cell::RefCell<(i32, u16)>")),
        Some(ValueLayout::ProjectedStruct(ProjectedStructLayout {
            type_name: "RefCell",
            fields: vec![
                ProjectedStructField {
                    name: "value",
                    value_path: field_path(&["value", "value_inner_from_dwarf"]),
                },
                ProjectedStructField {
                    name: "borrow",
                    value_path: field_path(&[
                        "borrow",
                        "borrow_cell_inner_from_dwarf",
                        "borrow_inner_from_dwarf",
                    ]),
                },
            ],
            presentation: ProjectedStructPresentation::SignedState {
                state_field: "borrow",
                non_negative_label: "borrow",
                negative_label: "borrow_mut",
            },
        }))
    );

    let narrow = rust_ref_cell_type(
        RefCellTestLayout {
            name: "core::cell::RefCell<u16>",
            root_size: 8,
            value_offset: 0,
            borrow_offset: 4,
            borrow_size: 4,
            language: SourceLanguage::Rust,
        },
        unsigned_type("u16", 2),
    );
    assert!(resolve_value_layout(&narrow, None).is_some());

    let zst = rust_ref_cell_type(
        RefCellTestLayout {
            name: "core::cell::RefCell<()>",
            root_size: 8,
            value_offset: 0,
            borrow_offset: 0,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        TypeInfo::BaseType {
            name: "()".to_string(),
            size: 0,
            encoding: gimli::DW_ATE_unsigned.0 as u16,
        },
    );
    assert!(resolve_value_layout(&zst, None).is_some());
}

#[test]
fn rejects_ref_cell_lookalikes_and_invalid_layouts() {
    let current = rust_ref_cell_type(
        RefCellTestLayout {
            name: "RefCell<u32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        unsigned_type("u32", 4),
    );
    assert_eq!(
        resolve_value_layout(&current, Some("app::RefCell<u32>")),
        None
    );
    assert_eq!(resolve_value_layout(&current, None), None);

    let mut unsigned_borrow = current.clone();
    let TypeInfo::StructType { members, .. } = &mut unsigned_borrow.summary else {
        unreachable!("test RefCell is a struct")
    };
    let TypeInfo::StructType {
        members: cell_members,
        ..
    } = &mut members[0].member_type
    else {
        unreachable!("test borrow field is a struct")
    };
    let TypeInfo::StructType {
        members: inner_members,
        ..
    } = &mut cell_members[0].member_type
    else {
        unreachable!("test borrow wrapper is a struct")
    };
    inner_members[0].member_type = unsigned_type("usize", 8);
    assert_eq!(
        resolve_value_layout(&unsigned_borrow, Some("core::cell::RefCell<u32>")),
        None
    );

    let overlapping = rust_ref_cell_type(
        RefCellTestLayout {
            name: "core::cell::RefCell<u64>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 4,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        unsigned_type("u64", 8),
    );
    assert_eq!(resolve_value_layout(&overlapping, None), None);

    let non_rust = rust_ref_cell_type(
        RefCellTestLayout {
            name: "core::cell::RefCell<u32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            borrow_size: 8,
            language: SourceLanguage::C,
        },
        unsigned_type("u32", 4),
    );
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn recognizes_rc_and_arc_with_dwarf_derived_pointer_wrappers() {
    let expected = |type_name, value_member: &str| {
        let inner_path = vec![
            ProjectedPathSegment::Member("ptr".to_string()),
            ProjectedPathSegment::Member("pointer".to_string()),
            ProjectedPathSegment::UnwrapScalar,
            ProjectedPathSegment::Dereference,
        ];
        let mut value_path = inner_path.clone();
        value_path.push(ProjectedPathSegment::Member(value_member.to_string()));
        let mut strong_path = inner_path.clone();
        strong_path.push(ProjectedPathSegment::Member("strong".to_string()));
        strong_path.push(ProjectedPathSegment::UnwrapScalar);
        let mut weak_path = inner_path;
        weak_path.push(ProjectedPathSegment::Member("weak".to_string()));
        weak_path.push(ProjectedPathSegment::UnwrapScalar);
        ValueLayout::CompositeStruct(CompositeStructLayout {
            type_name,
            fields: vec![
                CompositeStructField {
                    name: "value",
                    value_path,
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::KnownSizedOrZst,
                    ),
                },
                CompositeStructField {
                    name: "strong",
                    value_path: strong_path,
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::UnsignedPointerSizedInteger,
                    ),
                },
                CompositeStructField {
                    name: "weak",
                    value_path: weak_path,
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::UnsignedPointerSizedInteger,
                    ),
                },
            ],
            presentation: ProjectedStructPresentation::ReferenceCounted {
                strong_field: "strong",
                weak_field: "weak",
                implicit_weak: 1,
            },
        })
    };

    let rc = rust_reference_counted_type("Rc<(i32, u16)>", 8, true, SourceLanguage::Rust);
    assert_eq!(
        resolve_value_layout(&rc, Some("alloc::rc::Rc<(i32, u16)>")),
        Some(expected("Rc", "value"))
    );

    let arc = rust_reference_counted_type(
        "alloc::sync::Arc<(i32, u16)>",
        4,
        false,
        SourceLanguage::Rust,
    );
    assert_eq!(
        resolve_value_layout(&arc, None),
        Some(expected("Arc", "data"))
    );
}

#[test]
fn recognizes_rc_and_arc_dst_addresses_from_thin_and_wide_dwarf_pointers() {
    let expected = |type_name, value_member: &str, explicit_metadata| {
        let mut inner_path = vec![
            ProjectedPathSegment::Member("ptr".to_string()),
            ProjectedPathSegment::Member("pointer".to_string()),
        ];
        inner_path.push(if explicit_metadata {
            ProjectedPathSegment::Member("data_ptr".to_string())
        } else {
            ProjectedPathSegment::UnwrapScalar
        });
        inner_path.push(ProjectedPathSegment::Dereference);
        let mut value_path = inner_path.clone();
        value_path.push(ProjectedPathSegment::Member(value_member.to_string()));
        let mut strong_path = inner_path.clone();
        strong_path.push(ProjectedPathSegment::Member("strong".to_string()));
        strong_path.push(ProjectedPathSegment::UnwrapScalar);
        let mut weak_path = inner_path;
        weak_path.push(ProjectedPathSegment::Member("weak".to_string()));
        weak_path.push(ProjectedPathSegment::UnwrapScalar);
        ValueLayout::CompositeStruct(CompositeStructLayout {
            type_name,
            fields: vec![
                CompositeStructField {
                    name: "ptr",
                    value_path,
                    capture: CompositeStructFieldCapture::Address,
                },
                CompositeStructField {
                    name: "strong",
                    value_path: strong_path,
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::UnsignedPointerSizedInteger,
                    ),
                },
                CompositeStructField {
                    name: "weak",
                    value_path: weak_path,
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::UnsignedPointerSizedInteger,
                    ),
                },
            ],
            presentation: ProjectedStructPresentation::ReferenceCounted {
                strong_field: "strong",
                weak_field: "weak",
                implicit_weak: 1,
            },
        })
    };

    for pointer_size in [4, 8] {
        for (type_name, value_member, qualified_name) in [
            ("Rc", "value", "alloc::rc::Rc<str>"),
            ("Arc", "data", "alloc::sync::Arc<str>"),
        ] {
            for explicit_metadata in [false, true] {
                let current = rust_reference_counted_dst_type(
                    &format!("{type_name}<str>"),
                    type_name,
                    value_member,
                    pointer_size,
                    explicit_metadata,
                    SourceLanguage::Rust,
                );
                assert_eq!(
                    resolve_value_layout(&current, Some(qualified_name)),
                    Some(expected(type_name, value_member, explicit_metadata))
                );
            }
        }
    }
}

#[test]
fn recognizes_slice_dst_and_rejects_reference_counted_lookalikes() {
    let lookalike =
        rust_reference_counted_dst_type("Rc<str>", "Rc", "value", 8, true, SourceLanguage::Rust);
    assert_eq!(resolve_value_layout(&lookalike, Some("app::Rc<str>")), None);

    let slice = rust_reference_counted_dst_type(
        "alloc::rc::Rc<[u8]>",
        "Rc",
        "value",
        8,
        true,
        SourceLanguage::Rust,
    );
    assert!(matches!(
        resolve_value_layout(&slice, None),
        Some(ValueLayout::CompositeStruct(CompositeStructLayout {
            fields,
            ..
        })) if fields[0].capture == CompositeStructFieldCapture::Address
    ));

    let non_rust = rust_reference_counted_dst_type(
        "alloc::rc::Rc<str>",
        "Rc",
        "value",
        8,
        true,
        SourceLanguage::C,
    );
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn rejects_rc_arc_lookalikes_and_non_scalar_pointers() {
    let lookalike = rust_reference_counted_type("Rc<i32>", 8, false, SourceLanguage::Rust);
    assert_eq!(resolve_value_layout(&lookalike, Some("app::Rc<i32>")), None);
    assert_eq!(resolve_value_layout(&lookalike, None), None);

    let narrow = rust_reference_counted_type("alloc::rc::Rc<i32>", 2, false, SourceLanguage::Rust);
    assert_eq!(resolve_value_layout(&narrow, None), None);

    let mut fat =
        rust_reference_counted_type("alloc::sync::Arc<str>", 8, false, SourceLanguage::Rust);
    let TypeInfo::StructType { members, .. } = &mut fat.summary else {
        unreachable!("test Arc is a struct")
    };
    let TypeInfo::StructType {
        members: ptr_members,
        ..
    } = &mut members[0].member_type
    else {
        unreachable!("test Arc ptr is a wrapper")
    };
    ptr_members[0].member_type = TypeInfo::StructType {
        name: "fat pointer".to_string(),
        size: 16,
        members: vec![
            member("data", unsigned_type("usize", 8), 0),
            member("length", unsigned_type("usize", 8), 8),
        ],
    };
    assert_eq!(resolve_value_layout(&fat, None), None);

    let non_rust = rust_reference_counted_type("alloc::rc::Rc<i32>", 8, false, SourceLanguage::C);
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn recognizes_ref_guards_with_dwarf_derived_pointer_layouts() {
    let current = rust_ref_type(
        RefTestLayout {
            name: "Ref<(i32, u16)>",
            root_size: 16,
            value_offset: 8,
            borrow_offset: 0,
            value_pointer_size: 8,
            borrow_pointer_size: 8,
            language: SourceLanguage::Rust,
            marker: false,
        },
        TypeInfo::StructType {
            name: "(i32, u16)".to_string(),
            size: 8,
            members: Vec::new(),
        },
    );

    assert_eq!(
        resolve_value_layout(&current, Some("core::cell::Ref<(i32, u16)>")),
        Some(ValueLayout::CompositeStruct(CompositeStructLayout {
            type_name: "Ref",
            fields: vec![
                CompositeStructField {
                    name: "*value",
                    value_path: vec![
                        ProjectedPathSegment::Member("value".to_string()),
                        ProjectedPathSegment::Member("value_pointer_from_dwarf".to_string(),),
                        ProjectedPathSegment::Dereference,
                    ],
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::KnownSizedOrZst,
                    ),
                },
                CompositeStructField {
                    name: "borrow",
                    value_path: vec![
                        ProjectedPathSegment::Member("borrow".to_string()),
                        ProjectedPathSegment::Member("borrow_pointer_from_dwarf".to_string(),),
                        ProjectedPathSegment::Dereference,
                        ProjectedPathSegment::SoleMember,
                        ProjectedPathSegment::SoleMember,
                    ],
                    capture: CompositeStructFieldCapture::Value(
                        ProjectedValueRequirement::SignedPointerSizedInteger,
                    ),
                },
            ],
            presentation: ProjectedStructPresentation::SignedState {
                state_field: "borrow",
                non_negative_label: "borrow",
                negative_label: "borrow_mut",
            },
        }))
    );

    let mut legacy = current.clone();
    let TypeInfo::StructType { members, .. } = &mut legacy.summary else {
        unreachable!("test Ref is a struct")
    };
    let value = members
        .iter_mut()
        .find(|member| member.name == "value")
        .expect("test Ref has a value member");
    let pointer_type = {
        let TypeInfo::StructType { members, .. } = &value.member_type else {
            unreachable!("current test Ref value is a pointer wrapper")
        };
        let [pointer] = members.as_slice() else {
            unreachable!("current test Ref value wrapper has one member")
        };
        pointer.member_type.clone()
    };
    value.member_type = pointer_type;
    let Some(ValueLayout::CompositeStruct(legacy_layout)) =
        resolve_value_layout(&legacy, Some("core::cell::Ref<(i32, u16)>"))
    else {
        panic!("legacy raw-pointer Ref layout should be recognized")
    };
    assert_eq!(
        legacy_layout.fields[0].value_path,
        vec![
            ProjectedPathSegment::Member("value".to_string()),
            ProjectedPathSegment::Dereference,
        ]
    );

    let ref_mut = rust_ref_type(
        RefTestLayout {
            name: "core::cell::RefMut<i32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            value_pointer_size: 8,
            borrow_pointer_size: 8,
            language: SourceLanguage::Rust,
            marker: true,
        },
        signed_type("i32", 4),
    );
    assert!(resolve_value_layout(&ref_mut, None).is_some());
}

#[test]
fn rejects_ref_guard_lookalikes_and_invalid_outer_layouts() {
    let make_ref = |name, language| {
        rust_ref_type(
            RefTestLayout {
                name,
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language,
                marker: false,
            },
            signed_type("i32", 4),
        )
    };
    let current = make_ref("Ref<i32>", SourceLanguage::Rust);
    assert_eq!(resolve_value_layout(&current, Some("app::Ref<i32>")), None);
    assert_eq!(resolve_value_layout(&current, None), None);
    assert_eq!(
        resolve_value_layout(&make_ref("core::cell::Ref<i32>", SourceLanguage::C), None,),
        None
    );

    let overlapping = rust_ref_type(
        RefTestLayout {
            name: "core::cell::Ref<i32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 4,
            value_pointer_size: 8,
            borrow_pointer_size: 8,
            language: SourceLanguage::Rust,
            marker: false,
        },
        signed_type("i32", 4),
    );
    assert_eq!(resolve_value_layout(&overlapping, None), None);

    let mismatched_widths = rust_ref_type(
        RefTestLayout {
            name: "core::cell::Ref<i32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            value_pointer_size: 8,
            borrow_pointer_size: 4,
            language: SourceLanguage::Rust,
            marker: false,
        },
        signed_type("i32", 4),
    );
    assert_eq!(resolve_value_layout(&mismatched_widths, None), None);

    let mut ambiguous_wrapper = make_ref("core::cell::Ref<i32>", SourceLanguage::Rust);
    let TypeInfo::StructType { members, .. } = &mut ambiguous_wrapper.summary else {
        unreachable!("test Ref is a struct")
    };
    let TypeInfo::StructType {
        members: value_members,
        ..
    } = &mut members[1].member_type
    else {
        unreachable!("test Ref value is a wrapper")
    };
    value_members.push(member("extra", signed_type("i32", 4), 0));
    assert_eq!(resolve_value_layout(&ambiguous_wrapper, None), None);
}

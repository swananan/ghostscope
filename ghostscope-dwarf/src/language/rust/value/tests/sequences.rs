use super::*;

#[test]
fn recognizes_rust_str_layout() {
    let current = rust_str_type_64("&str", SourceLanguage::Rust);

    assert_eq!(
        resolve_value_layout(&current, None),
        Some(indirect_contiguous(
            field_path(&["data_ptr"]),
            field_path(&["length"]),
            IndirectSequenceKind::Utf8String,
        ))
    );
}

#[test]
fn recognizes_supported_rust_str_names() {
    for name in ["&mut str", "&'static str", "&'static mut str"] {
        let current = rust_str_type_64(name, SourceLanguage::Rust);

        assert!(
            resolve_value_layout(&current, None).is_some(),
            "name={name}"
        );
    }
}

#[test]
fn recognizes_rust_slice_layout_and_supported_names() {
    for name in [
        "&[i32]",
        "&mut [i32]",
        "&'static [i32]",
        "&'static mut [i32]",
    ] {
        let current = rust_slice_type_64(name, SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["data_ptr"]),
                field_path(&["length"]),
                IndirectSequenceKind::PointerTarget,
            )),
            "name={name}"
        );
    }
}

#[test]
fn does_not_classify_non_slice_reference_name() {
    let current = rust_slice_type_64("&[i32", SourceLanguage::Rust);

    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn recognizes_std_box_str_with_current_and_legacy_type_names() {
    for name in [
        "alloc::boxed::Box<str, alloc::alloc::Global>",
        "alloc::boxed::Box<str>",
    ] {
        let current = rust_str_type_64(name, SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["data_ptr"]),
                field_path(&["length"]),
                IndirectSequenceKind::Utf8String,
            )),
            "name={name}"
        );
    }

    let current = rust_str_type_64("Box<str, alloc::alloc::Global>", SourceLanguage::Rust);
    assert!(resolve_value_layout(
        &current,
        Some("alloc::boxed::Box<str, alloc::alloc::Global>"),
    )
    .is_some());
}

#[test]
fn does_not_classify_box_str_from_another_namespace() {
    let current = rust_str_type_64("Box<str, alloc::alloc::Global>", SourceLanguage::Rust);

    assert_eq!(
        resolve_value_layout(&current, Some("app::Box<str, alloc::alloc::Global>"),),
        None
    );
    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn recognizes_unix_and_windows_os_string_layouts_across_versions() {
    type LayoutCase<'a> = (bool, Option<&'a str>, &'a [&'a str], &'a [&'a str]);

    let cases: &[LayoutCase<'_>] = &[
        (
            true,
            None,
            &[
                "inner", "inner", "buf", "inner", "ptr", "pointer", "pointer",
            ],
            &["inner", "inner", "len"],
        ),
        (
            false,
            None,
            &["inner", "inner", "buf", "ptr", "pointer", "pointer"],
            &["inner", "inner", "len"],
        ),
        (
            true,
            Some("bytes"),
            &[
                "inner", "inner", "bytes", "buf", "inner", "ptr", "pointer", "pointer",
            ],
            &["inner", "inner", "bytes", "len"],
        ),
        (
            false,
            Some("__0"),
            &["inner", "inner", "__0", "buf", "ptr", "pointer", "pointer"],
            &["inner", "inner", "__0", "len"],
        ),
    ];

    for (uses_raw_vec_inner, windows_field, data_fields, length_fields) in cases {
        let current = rust_os_string_type(
            "std::ffi::os_str::OsString",
            8,
            *uses_raw_vec_inner,
            *windows_field,
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(data_fields),
                field_path(length_fields),
                IndirectSequenceKind::ByteString,
            )),
            "raw_vec_inner={uses_raw_vec_inner} windows_field={windows_field:?}"
        );
    }
}

#[test]
fn requires_standard_namespace_for_short_os_string_name() {
    let current = rust_os_string_type("OsString", 8, true, None);

    assert!(resolve_value_layout(&current, Some("std::ffi::os_str::OsString"),).is_some());
    assert_eq!(resolve_value_layout(&current, Some("app::OsString")), None);
    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn recognizes_path_and_path_buf_byte_layouts_from_dwarf() {
    for name in [
        "&std::path::Path",
        "&mut std::path::Path",
        "&'static std::path::Path",
        "&'static mut std::path::Path",
    ] {
        let current = rust_path_ref_type_64(name, SourceLanguage::Rust);
        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["data_ptr"]),
                field_path(&["length"]),
                IndirectSequenceKind::OpaqueByteString,
            )),
            "name={name}"
        );
    }

    for pointer_size in [4, 8] {
        for uses_raw_vec_inner in [false, true] {
            let current = rust_path_buf_type("PathBuf", pointer_size, uses_raw_vec_inner);
            let data_fields = if uses_raw_vec_inner {
                &[
                    "inner", "inner", "inner", "buf", "inner", "ptr", "pointer", "pointer",
                ][..]
            } else {
                &[
                    "inner", "inner", "inner", "buf", "ptr", "pointer", "pointer",
                ][..]
            };
            assert_eq!(
                resolve_value_layout(&current, Some("std::path::PathBuf")),
                Some(indirect_contiguous(
                    field_path(data_fields),
                    field_path(&["inner", "inner", "inner", "len"]),
                    IndirectSequenceKind::ByteString,
                )),
                "pointer_size={pointer_size} raw_vec_inner={uses_raw_vec_inner}"
            );
        }
    }
}

#[test]
fn rejects_path_and_path_buf_lookalikes() {
    let path = rust_path_ref_type_64("&app::Path", SourceLanguage::Rust);
    assert_eq!(resolve_value_layout(&path, None), None);

    let path_buf = rust_path_buf_type("PathBuf", 8, true);
    assert_eq!(resolve_value_layout(&path_buf, Some("app::PathBuf")), None);
    assert_eq!(resolve_value_layout(&path_buf, None), None);

    let non_rust = rust_path_ref_type_64("&std::path::Path", SourceLanguage::C);
    assert_eq!(resolve_value_layout(&non_rust, None), None);
}

#[test]
fn recognizes_32_bit_layout_from_dwarf() {
    let current = rust_str_type(RustStrLayout {
        name: "&str",
        aggregate_size: 8,
        data_offset: 0,
        pointer_size: 4,
        length_offset: 4,
        length_size: 4,
        language: SourceLanguage::Rust,
    });

    assert!(resolve_value_layout(&current, None).is_some());
}

#[test]
fn rejects_mismatched_metadata_widths() {
    let current = rust_str_type(RustStrLayout {
        name: "&str",
        aggregate_size: 16,
        data_offset: 0,
        pointer_size: 8,
        length_offset: 8,
        length_size: 4,
        language: SourceLanguage::Rust,
    });

    assert_eq!(resolve_value_layout(&current, None), None);
    let ValueLayoutResolution::Rejected { adapter, reason } = diagnose_value_layout(&current, None)
    else {
        panic!("recognized &str layout must report a rejection")
    };
    assert_eq!(adapter, "&str");
    assert!(reason.contains("equal nonzero widths"));
}

#[test]
fn rejects_members_outside_aggregate() {
    let current = rust_str_type(RustStrLayout {
        name: "&str",
        aggregate_size: 8,
        data_offset: 0,
        pointer_size: 4,
        length_offset: 6,
        length_size: 4,
        language: SourceLanguage::Rust,
    });

    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn rejects_overlapping_members() {
    let current = rust_str_type(RustStrLayout {
        name: "&str",
        aggregate_size: 8,
        data_offset: 0,
        pointer_size: 4,
        length_offset: 2,
        length_size: 4,
        language: SourceLanguage::Rust,
    });

    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn does_not_apply_rust_adapter_to_other_languages() {
    assert_eq!(
        resolve_value_layout(&rust_str_type_64("&str", SourceLanguage::C), None,),
        None
    );
}

#[test]
fn recognizes_current_std_string_layout() {
    let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);
    let layout =
        resolve_value_layout(&current, Some("alloc::string::String")).expect("String layout");

    assert_eq!(
        layout,
        indirect_contiguous(
            field_path(&["vec", "buf", "inner", "ptr", "pointer", "pointer"]),
            field_path(&["vec", "len"]),
            IndirectSequenceKind::Utf8String,
        )
    );
    let ValueLayout::IndirectSequence(layout) = layout else {
        panic!("String must use indirect sequence layout")
    };
    assert_eq!(
        resolve_member_path(&current.summary, &layout.data_path)
            .expect("data member")
            .offset,
        8
    );
    let IndirectSequenceAddressing::Contiguous { length_path } = &layout.addressing else {
        panic!("String must use contiguous addressing")
    };
    assert_eq!(
        resolve_member_path(&current.summary, length_path)
            .expect("length member")
            .offset,
        16
    );

    let ValueLayoutResolution::Applied { adapter, .. } =
        diagnose_value_layout(&current, Some("alloc::string::String"))
    else {
        panic!("valid std String layout must be applied")
    };
    assert_eq!(adapter, "String");
}

#[test]
fn recognizes_legacy_std_string_pointer_layout() {
    let current = rust_string_type(
        "alloc::string::String",
        SourceLanguage::Rust,
        8,
        false,
        true,
    );

    assert_eq!(
        resolve_value_layout(&current, None),
        Some(indirect_contiguous(
            field_path(&["vec", "buf", "inner", "ptr", "pointer"]),
            field_path(&["vec", "len"]),
            IndirectSequenceKind::Utf8String,
        ))
    );
}

#[test]
fn recognizes_pre_raw_vec_inner_string_layout() {
    let current = rust_string_type(
        "alloc::string::String",
        SourceLanguage::Rust,
        8,
        true,
        false,
    );

    assert_eq!(
        resolve_value_layout(&current, None),
        Some(indirect_contiguous(
            field_path(&["vec", "buf", "ptr", "pointer", "pointer"]),
            field_path(&["vec", "len"]),
            IndirectSequenceKind::Utf8String,
        ))
    );
}

#[test]
fn recognizes_32_bit_std_string_layout_from_dwarf() {
    let current = rust_string_type("alloc::string::String", SourceLanguage::Rust, 4, true, true);

    assert!(resolve_value_layout(&current, None).is_some());
}

#[test]
fn does_not_classify_unrelated_string_type() {
    let current = rust_string_type("app::String", SourceLanguage::Rust, 8, true, true);

    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn does_not_classify_short_string_from_another_namespace() {
    let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);

    assert_eq!(resolve_value_layout(&current, Some("app::String")), None);
    assert_eq!(
        diagnose_value_layout(&current, Some("app::String")),
        ValueLayoutResolution::NotApplicable
    );
}

#[test]
fn does_not_classify_short_string_without_qualified_identity() {
    let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);

    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn recognizes_current_std_vec_layout() {
    let current = rust_vec_type(
        "Vec<i32, alloc::alloc::Global>",
        SourceLanguage::Rust,
        8,
        true,
        true,
    );

    assert_eq!(
        resolve_value_layout(&current, Some("alloc::vec::Vec<i32, alloc::alloc::Global>")),
        Some(indirect_contiguous(
            field_path(&["buf", "inner", "ptr", "pointer", "pointer"]),
            field_path(&["len"]),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ))
    );
}

#[test]
fn recognizes_pre_raw_vec_inner_vec_layout() {
    let current = rust_vec_type(
        "alloc::vec::Vec<i32, alloc::alloc::Global>",
        SourceLanguage::Rust,
        8,
        true,
        false,
    );

    assert_eq!(
        resolve_value_layout(&current, None),
        Some(indirect_contiguous(
            field_path(&["buf", "ptr", "pointer", "pointer"]),
            field_path(&["len"]),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ))
    );
}

#[test]
fn recognizes_vec_deque_layouts_across_rust_versions() {
    let current = rust_vec_deque_type(VecDequeTestLayout {
        name: "VecDeque<i32, alloc::alloc::Global>",
        pointer_size: 8,
        uses_raw_vec_inner: true,
        wraps_capacity: true,
        wraps_head: true,
        uses_legacy_tail: false,
    });
    assert_eq!(
        resolve_value_layout(
            &current,
            Some("alloc::collections::vec_deque::VecDeque<i32, alloc::alloc::Global>"),
        ),
        Some(indirect_ring(
            field_path(&["buf", "inner", "ptr", "pointer", "pointer"]),
            field_path(&["head", "__0"]),
            field_path(&["len"]),
            RingSequenceLengthKind::Explicit,
            field_path(&["buf", "inner", "cap", "__0"]),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ))
    );

    let pre_raw_vec_inner = rust_vec_deque_type(VecDequeTestLayout {
        name: "alloc::collections::vec_deque::VecDeque<i32>",
        pointer_size: 4,
        uses_raw_vec_inner: false,
        wraps_capacity: false,
        wraps_head: false,
        uses_legacy_tail: false,
    });
    assert_eq!(
        resolve_value_layout(&pre_raw_vec_inner, None),
        Some(indirect_ring(
            field_path(&["buf", "ptr", "pointer", "pointer"]),
            field_path(&["head"]),
            field_path(&["len"]),
            RingSequenceLengthKind::Explicit,
            field_path(&["buf", "cap"]),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ))
    );

    let legacy = rust_vec_deque_type(VecDequeTestLayout {
        name: "alloc::collections::vec_deque::VecDeque<i32>",
        pointer_size: 8,
        uses_raw_vec_inner: false,
        wraps_capacity: false,
        wraps_head: false,
        uses_legacy_tail: true,
    });
    assert_eq!(
        resolve_value_layout(&legacy, None),
        Some(indirect_ring(
            field_path(&["buf", "ptr", "pointer", "pointer"]),
            field_path(&["tail"]),
            field_path(&["head"]),
            RingSequenceLengthKind::End,
            field_path(&["buf", "cap"]),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ))
    );
}

#[test]
fn requires_standard_namespace_for_short_vec_deque_name() {
    let current = rust_vec_deque_type(VecDequeTestLayout {
        name: "VecDeque<i32>",
        pointer_size: 8,
        uses_raw_vec_inner: true,
        wraps_capacity: true,
        wraps_head: false,
        uses_legacy_tail: false,
    });

    assert!(resolve_value_layout(
        &current,
        Some("alloc::collections::vec_deque::VecDeque<i32>"),
    )
    .is_some());
    assert_eq!(
        resolve_value_layout(&current, Some("app::VecDeque<i32>")),
        None
    );
    assert_eq!(resolve_value_layout(&current, None), None);
}

#[test]
fn does_not_classify_user_vec_from_another_namespace() {
    let current = rust_vec_type("Vec<i32>", SourceLanguage::Rust, 8, true, true);

    assert_eq!(resolve_value_layout(&current, Some("app::Vec<i32>")), None);
    assert_eq!(resolve_value_layout(&current, None), None);
}

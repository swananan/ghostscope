use super::*;

#[test]
fn qualified_name_lookup_is_limited_to_ambiguous_rust_std_types() {
    assert!(requires_dwarf_qualified_name(&rust_string_type(
        "String",
        SourceLanguage::Rust,
        8,
        true,
        true,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_string_type(
        "alloc::string::String",
        SourceLanguage::Rust,
        8,
        true,
        true,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_string_type(
        "String",
        SourceLanguage::C,
        8,
        true,
        true,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_str_type_64(
        "&str",
        SourceLanguage::Rust,
    )));
    assert!(requires_dwarf_qualified_name(&rust_vec_type(
        "Vec<i32, alloc::alloc::Global>",
        SourceLanguage::Rust,
        8,
        true,
        true,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_vec_type(
        "alloc::vec::Vec<i32, alloc::alloc::Global>",
        SourceLanguage::Rust,
        8,
        true,
        true,
    )));
    assert!(requires_dwarf_qualified_name(&rust_vec_deque_type(
        VecDequeTestLayout {
            name: "VecDeque<i32>",
            pointer_size: 8,
            uses_raw_vec_inner: true,
            wraps_capacity: true,
            wraps_head: false,
            uses_legacy_tail: false,
        },
    )));
    assert!(!requires_dwarf_qualified_name(&rust_vec_deque_type(
        VecDequeTestLayout {
            name: "alloc::collections::vec_deque::VecDeque<i32>",
            pointer_size: 8,
            uses_raw_vec_inner: true,
            wraps_capacity: true,
            wraps_head: false,
            uses_legacy_tail: false,
        },
    )));
    assert!(requires_dwarf_qualified_name(&rust_str_type_64(
        "Box<str, alloc::alloc::Global>",
        SourceLanguage::Rust,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_str_type_64(
        "alloc::boxed::Box<str, alloc::alloc::Global>",
        SourceLanguage::Rust,
    )));
    assert!(requires_dwarf_qualified_name(&rust_os_string_type(
        "OsString", 8, true, None,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_os_string_type(
        "std::ffi::os_str::OsString",
        8,
        true,
        None,
    )));
    assert!(requires_dwarf_qualified_name(&rust_hash_collection_type(
        "HashMap<i32, u16>",
        HashTableKind::Map,
        8,
        true,
        false,
        false,
        SourceLanguage::Rust,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_hash_collection_type(
        "std::collections::hash::map::HashMap<i32, u16>",
        HashTableKind::Map,
        8,
        true,
        false,
        false,
        SourceLanguage::Rust,
    ),));
    assert!(requires_dwarf_qualified_name(&rust_nonzero_type(
        "NonZero<u32>",
        "__0",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_nonzero_type(
        "core::num::nonzero::NonZero<u32>",
        "__0",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(requires_dwarf_qualified_name(&rust_legacy_nonzero_type(
        "NonZeroU32",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_legacy_nonzero_type(
        "core::num::NonZeroU32",
        "__0",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(requires_dwarf_qualified_name(&rust_cell_type(
        "Cell<u32>",
        "value",
        "value",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(!requires_dwarf_qualified_name(&rust_cell_type(
        "core::cell::Cell<u32>",
        "value",
        "value",
        unsigned_type("u32", 4),
        SourceLanguage::Rust,
    )));
    assert!(requires_dwarf_qualified_name(&rust_ref_cell_type(
        RefCellTestLayout {
            name: "RefCell<u32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        unsigned_type("u32", 4),
    )));
    assert!(!requires_dwarf_qualified_name(&rust_ref_cell_type(
        RefCellTestLayout {
            name: "core::cell::RefCell<u32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            borrow_size: 8,
            language: SourceLanguage::Rust,
        },
        unsigned_type("u32", 4),
    )));
    assert!(requires_dwarf_qualified_name(&rust_ref_type(
        RefTestLayout {
            name: "Ref<i32>",
            root_size: 16,
            value_offset: 0,
            borrow_offset: 8,
            value_pointer_size: 8,
            borrow_pointer_size: 8,
            language: SourceLanguage::Rust,
            marker: false,
        },
        signed_type("i32", 4),
    )));
    assert!(!requires_dwarf_qualified_name(&rust_ref_type(
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
    )));
    assert!(requires_dwarf_qualified_name(&rust_reference_counted_type(
        "Rc<i32>",
        8,
        false,
        SourceLanguage::Rust
    )));
    assert!(!requires_dwarf_qualified_name(
        &rust_reference_counted_type("alloc::sync::Arc<i32>", 8, false, SourceLanguage::Rust,)
    ));
}

use super::layout::{field_path, resolve_member_path};
use super::*;
use crate::language::adapter::{
    CompositeStructField, CompositeStructFieldCapture, CompositeStructLayout,
    IndirectSequenceAddressing, IndirectSequenceLayout, ProjectedPathSegment, ProjectedStructField,
    ProjectedStructLayout, ProjectedStructPresentation, ProjectedValueRequirement,
    RingSequenceLengthKind,
};
use crate::language::rust::plan::HashTableBucketLayout;
use crate::{
    CuId, HashTableBucketOrder, HashTableOccupancy, ModuleId, StructMember, TypeIdentity,
    TypeOrigin,
};

mod collections;
mod identity;
mod sequences;
mod wrappers;

struct RustStrLayout<'a> {
    name: &'a str,
    aggregate_size: u64,
    data_offset: u64,
    pointer_size: u64,
    length_offset: u64,
    length_size: u64,
    language: SourceLanguage,
}

fn rust_str_type(layout: RustStrLayout<'_>) -> ResolvedType {
    let byte = TypeInfo::BaseType {
        name: "u8".to_string(),
        size: 1,
        encoding: gimli::DW_ATE_unsigned.0 as u16,
    };
    ResolvedType::new(
        TypeInfo::StructType {
            name: layout.name.to_string(),
            size: layout.aggregate_size,
            members: vec![
                StructMember {
                    name: "data_ptr".to_string(),
                    member_type: TypeInfo::PointerType {
                        target_type: Box::new(byte),
                        size: layout.pointer_size,
                    },
                    offset: layout.data_offset,
                    bit_offset: None,
                    bit_size: None,
                },
                StructMember {
                    name: "length".to_string(),
                    member_type: TypeInfo::BaseType {
                        name: "usize".to_string(),
                        size: layout.length_size,
                        encoding: gimli::DW_ATE_unsigned.0 as u16,
                    },
                    offset: layout.length_offset,
                    bit_offset: None,
                    bit_size: None,
                },
            ],
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language: layout.language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_str_type_64(name: &str, language: SourceLanguage) -> ResolvedType {
    rust_str_type(RustStrLayout {
        name,
        aggregate_size: 16,
        data_offset: 0,
        pointer_size: 8,
        length_offset: 8,
        length_size: 8,
        language,
    })
}

fn rust_c_str_type_64(
    name: &str,
    language: SourceLanguage,
    uses_unsized_array: bool,
) -> ResolvedType {
    let mut current = rust_str_type_64(name, language);
    let TypeInfo::StructType { members, .. } = &mut current.summary else {
        unreachable!("test CStr reference is a struct")
    };
    let TypeInfo::PointerType { target_type, .. } = &mut members[0].member_type else {
        unreachable!("test CStr data_ptr is a pointer")
    };
    let byte = TypeInfo::BaseType {
        name: "i8".to_string(),
        size: 1,
        encoding: gimli::DW_ATE_signed.0 as u16,
    };
    let storage = if uses_unsized_array {
        TypeInfo::ArrayType {
            element_type: Box::new(byte),
            element_count: None,
            total_size: None,
        }
    } else {
        byte
    };
    *target_type = Box::new(TypeInfo::StructType {
        name: "CStr".to_string(),
        size: 0,
        members: vec![member("inner", storage, 0)],
    });
    current
}

fn rust_c_string_type(name: &str, language: SourceLanguage) -> ResolvedType {
    let inner = rust_str_type_64("alloc::boxed::Box<[u8], alloc::alloc::Global>", language);
    let origin = inner.origin;
    ResolvedType::new(
        TypeInfo::StructType {
            name: name.to_string(),
            size: 16,
            members: vec![member("inner", inner.summary, 0)],
        },
        TypeIdentity::Unknown,
        origin,
    )
}

fn rust_path_ref_type_64(name: &str, language: SourceLanguage) -> ResolvedType {
    let mut current = rust_str_type_64(name, language);
    let TypeInfo::StructType { members, .. } = &mut current.summary else {
        unreachable!("test Path reference is a struct")
    };
    let TypeInfo::PointerType { target_type, .. } = &mut members[0].member_type else {
        unreachable!("test Path data_ptr is a pointer")
    };
    *target_type = Box::new(TypeInfo::UnknownType {
        name: "Path".to_string(),
    });
    current
}

fn rust_slice_type_64(name: &str, language: SourceLanguage) -> ResolvedType {
    let mut current = rust_str_type_64(name, language);
    let TypeInfo::StructType { members, .. } = &mut current.summary else {
        unreachable!("test slice is a struct")
    };
    let TypeInfo::PointerType { target_type, .. } = &mut members[0].member_type else {
        unreachable!("test slice data_ptr is a pointer")
    };
    *target_type = Box::new(TypeInfo::BaseType {
        name: "i32".to_string(),
        size: 4,
        encoding: gimli::DW_ATE_signed.0 as u16,
    });
    current
}

fn member(name: &str, member_type: TypeInfo, offset: u64) -> StructMember {
    StructMember {
        name: name.to_string(),
        member_type,
        offset,
        bit_offset: None,
        bit_size: None,
    }
}

fn single_member_struct(name: &str, field: &str, inner: TypeInfo) -> TypeInfo {
    TypeInfo::StructType {
        name: name.to_string(),
        size: inner.size(),
        members: vec![member(field, inner, 0)],
    }
}

fn unsigned_type(name: &str, size: u64) -> TypeInfo {
    TypeInfo::BaseType {
        name: name.to_string(),
        size,
        encoding: gimli::DW_ATE_unsigned.0 as u16,
    }
}

fn signed_type(name: &str, size: u64) -> TypeInfo {
    TypeInfo::BaseType {
        name: name.to_string(),
        size,
        encoding: gimli::DW_ATE_signed.0 as u16,
    }
}

fn indirect_contiguous(
    data_path: Vec<String>,
    length_path: Vec<String>,
    kind: IndirectSequenceKind,
) -> ValueLayout {
    ValueLayout::IndirectSequence(IndirectSequenceLayout::contiguous(
        data_path,
        length_path,
        kind,
    ))
}

fn indirect_ring(
    data_path: Vec<String>,
    start_path: Vec<String>,
    length_path: Vec<String>,
    length_kind: RingSequenceLengthKind,
    capacity_path: Vec<String>,
    kind: IndirectSequenceKind,
) -> ValueLayout {
    ValueLayout::IndirectSequence(IndirectSequenceLayout::ring(
        data_path,
        start_path,
        length_path,
        length_kind,
        capacity_path,
        kind,
    ))
}

fn rust_nonzero_type(
    name: &str,
    outer_field: &str,
    inner_field: &str,
    value_type: TypeInfo,
    language: SourceLanguage,
) -> ResolvedType {
    let inner = single_member_struct("NonZeroInner", inner_field, value_type);
    ResolvedType::new(
        single_member_struct(name, outer_field, inner),
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_cell_type(
    name: &str,
    outer_field: &str,
    inner_field: &str,
    value_type: TypeInfo,
    language: SourceLanguage,
) -> ResolvedType {
    let unsafe_cell = single_member_struct("UnsafeCell", inner_field, value_type);
    ResolvedType::new(
        single_member_struct(name, outer_field, unsafe_cell),
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

struct RefCellTestLayout<'a> {
    name: &'a str,
    root_size: u64,
    value_offset: u64,
    borrow_offset: u64,
    borrow_size: u64,
    language: SourceLanguage,
}

fn rust_ref_cell_type(layout: RefCellTestLayout<'_>, value_type: TypeInfo) -> ResolvedType {
    let value = single_member_struct("UnsafeCell<T>", "value_inner_from_dwarf", value_type);
    let borrow = single_member_struct(
        "Cell<BorrowFlag>",
        "borrow_cell_inner_from_dwarf",
        single_member_struct(
            "UnsafeCell<BorrowFlag>",
            "borrow_inner_from_dwarf",
            signed_type("isize", layout.borrow_size),
        ),
    );
    ResolvedType::new(
        TypeInfo::StructType {
            name: layout.name.to_string(),
            size: layout.root_size,
            members: vec![
                member("borrow", borrow, layout.borrow_offset),
                member("value", value, layout.value_offset),
            ],
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language: layout.language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

struct RefTestLayout<'a> {
    name: &'a str,
    root_size: u64,
    value_offset: u64,
    borrow_offset: u64,
    value_pointer_size: u64,
    borrow_pointer_size: u64,
    language: SourceLanguage,
    marker: bool,
}

fn rust_ref_type(layout: RefTestLayout<'_>, value_type: TypeInfo) -> ResolvedType {
    let value_pointer = TypeInfo::PointerType {
        target_type: Box::new(value_type),
        size: layout.value_pointer_size,
    };
    let borrow_pointer = TypeInfo::PointerType {
        target_type: Box::new(TypeInfo::UnknownType {
            name: "Cell<isize>".to_string(),
        }),
        size: layout.borrow_pointer_size,
    };
    let mut members = vec![
        member(
            "borrow",
            single_member_struct("BorrowRef", "borrow_pointer_from_dwarf", borrow_pointer),
            layout.borrow_offset,
        ),
        member(
            "value",
            single_member_struct("NonNull<T>", "value_pointer_from_dwarf", value_pointer),
            layout.value_offset,
        ),
    ];
    if layout.marker {
        members.push(member(
            "marker",
            TypeInfo::StructType {
                name: "PhantomData<T>".to_string(),
                size: 0,
                members: Vec::new(),
            },
            layout.root_size,
        ));
    }
    ResolvedType::new(
        TypeInfo::StructType {
            name: layout.name.to_string(),
            size: layout.root_size,
            members,
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language: layout.language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_reference_counted_type(
    name: &str,
    pointer_size: u64,
    nested_pointer_wrapper: bool,
    language: SourceLanguage,
) -> ResolvedType {
    let raw_pointer = TypeInfo::PointerType {
        target_type: Box::new(TypeInfo::UnknownType {
            name: "RcOrArcInner<T>".to_string(),
        }),
        size: pointer_size,
    };
    let pointer = if nested_pointer_wrapper {
        single_member_struct("NonZero<*mut T>", "scalar_from_dwarf", raw_pointer)
    } else {
        raw_pointer
    };
    let ptr = TypeInfo::StructType {
        name: "NonNull<Inner<T>>".to_string(),
        size: pointer_size,
        members: vec![member("pointer", pointer, 0)],
    };
    ResolvedType::new(
        TypeInfo::StructType {
            name: name.to_string(),
            size: pointer_size,
            members: vec![
                member("ptr", ptr, 0),
                member(
                    "phantom",
                    TypeInfo::StructType {
                        name: "PhantomData<T>".to_string(),
                        size: 0,
                        members: Vec::new(),
                    },
                    pointer_size,
                ),
            ],
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_reference_counted_dst_type(
    name: &str,
    type_name: &str,
    value_member: &str,
    pointer_size: u64,
    explicit_metadata: bool,
    language: SourceLanguage,
) -> ResolvedType {
    let counter = || {
        single_member_struct(
            "Cell<usize>",
            "value",
            single_member_struct(
                "UnsafeCell<usize>",
                "value",
                unsigned_type("usize", pointer_size),
            ),
        )
    };
    let inner = TypeInfo::StructType {
        name: format!("{type_name}Inner<str>"),
        size: pointer_size * 2,
        members: vec![
            member("strong", counter(), 0),
            member("weak", counter(), pointer_size),
            member(
                value_member,
                TypeInfo::ArrayType {
                    element_type: Box::new(unsigned_type("u8", 1)),
                    element_count: None,
                    total_size: None,
                },
                pointer_size * 2,
            ),
        ],
    };
    let raw_pointer = TypeInfo::PointerType {
        target_type: Box::new(inner),
        size: pointer_size,
    };
    let pointer = if explicit_metadata {
        TypeInfo::StructType {
            name: format!("*const {type_name}Inner<str>"),
            size: pointer_size * 2,
            members: vec![
                member("data_ptr", raw_pointer, 0),
                member("length", unsigned_type("usize", pointer_size), pointer_size),
            ],
        }
    } else {
        raw_pointer
    };
    let ptr = TypeInfo::StructType {
        name: format!("NonNull<{type_name}Inner<str>>"),
        size: pointer.size(),
        members: vec![member("pointer", pointer, 0)],
    };
    ResolvedType::new(
        TypeInfo::StructType {
            name: name.to_string(),
            size: ptr.size(),
            members: vec![member("ptr", ptr, 0)],
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn hash_table_metadata(pointer_size: u64, dedicated_data: bool) -> TypeInfo {
    let control_pointer = TypeInfo::PointerType {
        target_type: Box::new(unsigned_type("u8", 1)),
        size: pointer_size,
    };
    let control = single_member_struct("NonNull<u8>", "pointer", control_pointer);
    let mut members = vec![
        member("bucket_mask", unsigned_type("usize", pointer_size), 0),
        member("ctrl", control, pointer_size),
        member(
            "growth_left",
            unsigned_type("usize", pointer_size),
            pointer_size * 2,
        ),
        member(
            "items",
            unsigned_type("usize", pointer_size),
            pointer_size * 3,
        ),
    ];
    if dedicated_data {
        let entry_pointer = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::UnknownType {
                name: "(K, V)".to_string(),
            }),
            size: pointer_size,
        };
        members.push(member(
            "data",
            single_member_struct("NonNull<(K, V)>", "pointer", entry_pointer),
            pointer_size * 4,
        ));
    }
    TypeInfo::StructType {
        name: "hashbrown::raw::RawTableInner".to_string(),
        size: pointer_size * if dedicated_data { 5 } else { 4 },
        members,
    }
}

fn rust_hash_collection_type(
    name: &str,
    kind: HashTableKind,
    pointer_size: u64,
    nested_metadata: bool,
    dedicated_data: bool,
    legacy_set_wrapper: bool,
    language: SourceLanguage,
) -> ResolvedType {
    let metadata = hash_table_metadata(pointer_size, dedicated_data);
    let raw_table = if nested_metadata {
        TypeInfo::StructType {
            name: "hashbrown::raw::RawTable<(K, V)>".to_string(),
            size: metadata.size(),
            members: vec![member("table", metadata, 0)],
        }
    } else {
        TypeInfo::StructType {
            name: "hashbrown::raw::RawTable<(K, V)>".to_string(),
            size: metadata.size(),
            members: match metadata {
                TypeInfo::StructType { members, .. } => members,
                _ => unreachable!("hash metadata is a struct"),
            },
        }
    };
    let hashbrown_map = TypeInfo::StructType {
        name: "hashbrown::map::HashMap<K, V>".to_string(),
        size: raw_table.size(),
        members: vec![member("table", raw_table, 0)],
    };
    let root = match (kind, legacy_set_wrapper) {
        (HashTableKind::Map, _) => TypeInfo::StructType {
            name: name.to_string(),
            size: hashbrown_map.size(),
            members: vec![member("base", hashbrown_map, 0)],
        },
        (HashTableKind::Set, false) => {
            let hashbrown_set = TypeInfo::StructType {
                name: "hashbrown::set::HashSet<T>".to_string(),
                size: hashbrown_map.size(),
                members: vec![member("map", hashbrown_map, 0)],
            };
            TypeInfo::StructType {
                name: name.to_string(),
                size: hashbrown_set.size(),
                members: vec![member("base", hashbrown_set, 0)],
            }
        }
        (HashTableKind::Set, true) => {
            let std_map = TypeInfo::StructType {
                name: "std::collections::hash::map::HashMap<T, ()>".to_string(),
                size: hashbrown_map.size(),
                members: vec![member("base", hashbrown_map, 0)],
            };
            TypeInfo::StructType {
                name: name.to_string(),
                size: std_map.size(),
                members: vec![member("map", std_map, 0)],
            }
        }
    };
    ResolvedType::new(
        root,
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_135_hash_collection_type(
    name: &str,
    kind: HashTableKind,
    pointer_size: u64,
    language: SourceLanguage,
) -> ResolvedType {
    let hash_word = unsigned_type("usize", pointer_size);
    let raw_pointer = TypeInfo::PointerType {
        target_type: Box::new(hash_word),
        size: pointer_size,
    };
    let unique = TypeInfo::StructType {
        name: "core::ptr::Unique<usize>".to_string(),
        size: pointer_size,
        members: vec![
            member("pointer", raw_pointer, 0),
            member(
                "_marker",
                TypeInfo::StructType {
                    name: "PhantomData<usize>".to_string(),
                    size: 0,
                    members: Vec::new(),
                },
                0,
            ),
        ],
    };
    let hashes = TypeInfo::StructType {
        name: "TaggedHashUintPtr".to_string(),
        size: pointer_size,
        members: vec![member("__0", unique, 0)],
    };
    let marker = TypeInfo::StructType {
        name: "PhantomData<(K, V)>".to_string(),
        size: 0,
        members: Vec::new(),
    };
    let raw_table = TypeInfo::StructType {
        name: "RawTable<K, V>".to_string(),
        size: pointer_size * 3,
        members: vec![
            member("capacity_mask", unsigned_type("usize", pointer_size), 0),
            member("size", unsigned_type("usize", pointer_size), pointer_size),
            member("hashes", hashes, pointer_size * 2),
            member("marker", marker, 0),
        ],
    };
    let map = TypeInfo::StructType {
        name: match kind {
            HashTableKind::Map => name.to_string(),
            HashTableKind::Set => "std::collections::hash::map::HashMap<K, ()>".to_string(),
        },
        size: pointer_size * 5,
        members: vec![
            member(
                "hash_builder",
                TypeInfo::StructType {
                    name: "RandomState".to_string(),
                    size: pointer_size * 2,
                    members: Vec::new(),
                },
                0,
            ),
            member("table", raw_table, pointer_size * 2),
            member(
                "resize_policy",
                TypeInfo::StructType {
                    name: "DefaultResizePolicy".to_string(),
                    size: 0,
                    members: Vec::new(),
                },
                0,
            ),
        ],
    };
    let root = match kind {
        HashTableKind::Map => map,
        HashTableKind::Set => TypeInfo::StructType {
            name: name.to_string(),
            size: map.size(),
            members: vec![member("map", map, 0)],
        },
    };
    ResolvedType::new(
        root,
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 4,
        }),
    )
}

fn rust_btree_collection_type(
    name: &str,
    kind: BTreeKind,
    pointer_size: u64,
    language: SourceLanguage,
) -> ResolvedType {
    let root = TypeInfo::StructType {
        name: "Option<NodeRef<K, V>>".to_string(),
        size: pointer_size * 2,
        members: Vec::new(),
    };
    let map = TypeInfo::StructType {
        name: "alloc::collections::btree::map::BTreeMap<K, V>".to_string(),
        size: pointer_size * 3,
        members: vec![
            member("root", root, 0),
            member(
                "length",
                unsigned_type("usize", pointer_size),
                pointer_size * 2,
            ),
        ],
    };
    let root = match kind {
        BTreeKind::Map => match map {
            TypeInfo::StructType { size, members, .. } => TypeInfo::StructType {
                name: name.to_string(),
                size,
                members,
            },
            _ => unreachable!("test BTreeMap is a struct"),
        },
        BTreeKind::Set => TypeInfo::StructType {
            name: name.to_string(),
            size: map.size(),
            members: vec![member("map", map, 0)],
        },
    };
    ResolvedType::new(
        root,
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_legacy_nonzero_type(
    name: &str,
    field: &str,
    value_type: TypeInfo,
    language: SourceLanguage,
) -> ResolvedType {
    ResolvedType::new(
        single_member_struct(name, field, value_type),
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 4,
        }),
    )
}

fn rust_string_type(
    name: &str,
    language: SourceLanguage,
    pointer_size: u64,
    wraps_raw_pointer: bool,
    uses_raw_vec_inner: bool,
) -> ResolvedType {
    let raw_pointer = TypeInfo::PointerType {
        target_type: Box::new(unsigned_type("u8", 1)),
        size: pointer_size,
    };
    let unique_pointer = if wraps_raw_pointer {
        TypeInfo::StructType {
            name: "core::ptr::non_null::NonNull<u8>".to_string(),
            size: pointer_size,
            members: vec![member("pointer", raw_pointer, 0)],
        }
    } else {
        raw_pointer
    };
    let unique = TypeInfo::StructType {
        name: "core::ptr::unique::Unique<u8>".to_string(),
        size: pointer_size,
        members: vec![member("pointer", unique_pointer, 0)],
    };
    let raw_vec = if uses_raw_vec_inner {
        let raw_vec_inner = TypeInfo::StructType {
            name: "alloc::raw_vec::RawVecInner".to_string(),
            size: pointer_size * 2,
            members: vec![member("ptr", unique, pointer_size)],
        };
        TypeInfo::StructType {
            name: "alloc::raw_vec::RawVec<u8>".to_string(),
            size: pointer_size * 2,
            members: vec![member("inner", raw_vec_inner, 0)],
        }
    } else {
        TypeInfo::StructType {
            name: "alloc::raw_vec::RawVec<u8>".to_string(),
            size: pointer_size * 2,
            members: vec![member("ptr", unique, 0)],
        }
    };
    let vec_type = TypeInfo::StructType {
        name: "Vec<u8, alloc::alloc::Global>".to_string(),
        size: pointer_size * 3,
        members: vec![
            member("buf", raw_vec, 0),
            member(
                "len",
                unsigned_type("usize", pointer_size),
                pointer_size * 2,
            ),
        ],
    };

    ResolvedType::new(
        TypeInfo::StructType {
            name: name.to_string(),
            size: pointer_size * 3,
            members: vec![member("vec", vec_type, 0)],
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

fn rust_vec_type(
    name: &str,
    language: SourceLanguage,
    pointer_size: u64,
    wraps_raw_pointer: bool,
    uses_raw_vec_inner: bool,
) -> ResolvedType {
    let string = rust_string_type(
        "alloc::string::String",
        language,
        pointer_size,
        wraps_raw_pointer,
        uses_raw_vec_inner,
    );
    let TypeInfo::StructType { members, .. } = string.summary else {
        unreachable!("test String is a struct")
    };
    let mut vec_type = members
        .into_iter()
        .next()
        .expect("test String has a Vec member")
        .member_type;
    let TypeInfo::StructType { name: vec_name, .. } = &mut vec_type else {
        unreachable!("test Vec is a struct")
    };
    *vec_name = name.to_string();

    ResolvedType::new(vec_type, TypeIdentity::Unknown, string.origin)
}

fn rust_os_string_type(
    name: &str,
    pointer_size: u64,
    uses_raw_vec_inner: bool,
    windows_vec_field: Option<&str>,
) -> ResolvedType {
    let vec = rust_vec_type(
        "alloc::vec::Vec<u8, alloc::alloc::Global>",
        SourceLanguage::Rust,
        pointer_size,
        true,
        uses_raw_vec_inner,
    );
    let origin = vec.origin;
    let platform_buffer = match windows_vec_field {
        Some(field) => single_member_struct("Wtf8Buf", field, vec.summary),
        None => vec.summary,
    };
    let buffer = single_member_struct("Buf", "inner", platform_buffer);
    let os_string = single_member_struct(name, "inner", buffer);

    ResolvedType::new(os_string, TypeIdentity::Unknown, origin)
}

fn rust_path_buf_type(name: &str, pointer_size: u64, uses_raw_vec_inner: bool) -> ResolvedType {
    let os_string = rust_os_string_type(
        "std::ffi::os_str::OsString",
        pointer_size,
        uses_raw_vec_inner,
        None,
    );
    let origin = os_string.origin;
    let path_buf = single_member_struct(name, "inner", os_string.summary);

    ResolvedType::new(path_buf, TypeIdentity::Unknown, origin)
}

struct VecDequeTestLayout<'a> {
    name: &'a str,
    pointer_size: u64,
    uses_raw_vec_inner: bool,
    wraps_capacity: bool,
    wraps_head: bool,
    uses_legacy_tail: bool,
}

fn rust_vec_deque_type(layout: VecDequeTestLayout<'_>) -> ResolvedType {
    let pointer_size = layout.pointer_size;
    let raw_pointer = TypeInfo::PointerType {
        target_type: Box::new(unsigned_type("u8", 1)),
        size: pointer_size,
    };
    let non_null = single_member_struct("NonNull<u8>", "pointer", raw_pointer);
    let unique = single_member_struct("Unique<u8>", "pointer", non_null);
    let capacity = if layout.wraps_capacity {
        single_member_struct(
            "alloc::raw_vec::Cap",
            "__0",
            unsigned_type("usize", pointer_size),
        )
    } else {
        unsigned_type("usize", pointer_size)
    };
    let raw_vec_storage = TypeInfo::StructType {
        name: "alloc::raw_vec::RawVecInner".to_string(),
        size: pointer_size * 2,
        members: vec![
            member("cap", capacity, 0),
            member("ptr", unique, pointer_size),
        ],
    };
    let raw_vec = if layout.uses_raw_vec_inner {
        single_member_struct("alloc::raw_vec::RawVec<i32>", "inner", raw_vec_storage)
    } else {
        raw_vec_storage
    };
    let head = if layout.wraps_head {
        single_member_struct(
            "alloc::collections::vec_deque::WrappedIndex",
            "__0",
            unsigned_type("usize", pointer_size),
        )
    } else {
        unsigned_type("usize", pointer_size)
    };
    let mut members = if layout.uses_legacy_tail {
        vec![
            member("tail", unsigned_type("usize", pointer_size), 0),
            member("head", head, pointer_size),
        ]
    } else {
        vec![
            member("head", head, 0),
            member("len", unsigned_type("usize", pointer_size), pointer_size),
        ]
    };
    members.push(member("buf", raw_vec, pointer_size * 2));

    ResolvedType::new(
        TypeInfo::StructType {
            name: layout.name.to_string(),
            size: pointer_size * 4,
            members,
        },
        TypeIdentity::Unknown,
        Some(TypeOrigin {
            module: ModuleId(0),
            cu: CuId(0),
            language: SourceLanguage::Rust,
            producer: None,
            dwarf_version: 5,
        }),
    )
}

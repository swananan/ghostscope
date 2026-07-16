use crate::{strip_type_aliases, ResolvedType, SourceLanguage, TypeInfo, ValuePresentation};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndirectBytesLayout {
    pub(crate) data_path: Vec<String>,
    pub(crate) length_path: Vec<String>,
    pub(crate) presentation: ValuePresentation,
}

pub(super) fn requires_dwarf_qualified_name(current: &ResolvedType) -> bool {
    current.origin.as_ref().is_some_and(|origin| {
        origin.language == SourceLanguage::Rust
            && matches!(
                strip_type_aliases(&current.summary),
                TypeInfo::StructType { name, .. } if name == "String"
            )
    })
}

pub(super) fn resolve_value_layout(
    current: &ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> Option<IndirectBytesLayout> {
    if current.origin.as_ref()?.language != SourceLanguage::Rust {
        return None;
    }

    let TypeInfo::StructType { name, .. } = strip_type_aliases(&current.summary) else {
        return None;
    };

    // rustc's bundled GDB printers have treated slice-like DWARF values as
    // `data_ptr` plus `length` since Rust 1.0, without field-name compatibility
    // branches. Older printers also removed explicit `'static` lifetimes before
    // classifying references. These are rustc debuginfo conventions, not Rust
    // ABI guarantees, so retain the language and structural checks around them.
    // See rust-lang/rust's `src/etc/gdb_rust_pretty_printing.py` and
    // `src/etc/gdb_providers.py`.
    if matches!(
        name.as_str(),
        "&str" | "&mut str" | "&'static str" | "&'static mut str"
    ) {
        validate_indirect_bytes_layout(
            &current.summary,
            field_path(&["data_ptr"]),
            field_path(&["length"]),
        )
    // rustc commonly stores only `String` in DW_AT_name and represents
    // `alloc::string` with enclosing namespace DIEs. GDB presents the
    // reconstructed qualified name to its Rust printer. Trust the equivalent
    // TypeId-backed name from the analyzer for identity; the member checks
    // below remain responsible only for version-specific physical layout.
    } else if is_std_string(name, dwarf_qualified_name) {
        rust_string_layout(&current.summary)
    } else {
        None
    }
}

fn is_std_string(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_string_name(name)
        || (name == "String" && dwarf_qualified_name.is_some_and(is_std_string_name))
}

fn is_std_string_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some(module) = path.strip_suffix("::String") else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

fn rust_string_layout(root: &TypeInfo) -> Option<IndirectBytesLayout> {
    // rust-gdb uses `buf.ptr` through Rust 1.81 and `buf.inner.ptr` from
    // Rust 1.82 onward. Keep both paths and validate whichever DWARF exposes.
    const DATA_PATHS: &[&[&str]] = &[
        &["vec", "buf", "inner", "ptr", "pointer"],
        &["vec", "buf", "ptr", "pointer"],
    ];

    let length_path = field_path(&["vec", "len"]);
    for fields in DATA_PATHS {
        let mut data_path = field_path(fields);
        let Some(pointer_or_wrapper) = resolve_member_path(root, &data_path) else {
            continue;
        };

        if matches!(
            strip_type_aliases(pointer_or_wrapper.member_type),
            TypeInfo::PointerType { .. }
        ) {
            if let Some(layout) =
                validate_indirect_bytes_layout(root, data_path, length_path.clone())
            {
                return Some(layout);
            }
            continue;
        }

        // This mirrors rust-gdb's `unwrap_unique_or_non_null`: Rust versions
        // with a NonNull wrapper expose the raw pointer as its first field.
        let TypeInfo::StructType { members, .. } =
            strip_type_aliases(pointer_or_wrapper.member_type)
        else {
            continue;
        };
        let Some(first) = members.first() else {
            continue;
        };
        data_path.push(first.name.clone());
        let Some(raw_pointer) = resolve_member_path(root, &data_path) else {
            continue;
        };
        if matches!(
            strip_type_aliases(raw_pointer.member_type),
            TypeInfo::PointerType { .. }
        ) {
            if let Some(layout) =
                validate_indirect_bytes_layout(root, data_path, length_path.clone())
            {
                return Some(layout);
            }
        }
    }

    None
}

fn field_path(fields: &[&str]) -> Vec<String> {
    fields.iter().map(|field| (*field).to_string()).collect()
}

struct ResolvedMemberPath<'a> {
    offset: u64,
    member_type: &'a TypeInfo,
}

fn resolve_member_path<'a>(root: &'a TypeInfo, path: &[String]) -> Option<ResolvedMemberPath<'a>> {
    let mut current = root;
    let mut offset = 0u64;

    for field in path {
        let TypeInfo::StructType { size, members, .. } = strip_type_aliases(current) else {
            return None;
        };
        let member = members.iter().find(|member| member.name == *field)?;
        let member_size = member.member_type.size();
        let member_end = member.offset.checked_add(member_size)?;
        if member_size == 0
            || member.bit_offset.is_some()
            || member.bit_size.is_some()
            || member_end > *size
        {
            return None;
        }
        offset = offset.checked_add(member.offset)?;
        current = &member.member_type;
    }

    Some(ResolvedMemberPath {
        offset,
        member_type: current,
    })
}

fn validate_indirect_bytes_layout(
    root: &TypeInfo,
    data_path: Vec<String>,
    length_path: Vec<String>,
) -> Option<IndirectBytesLayout> {
    let data = resolve_member_path(root, &data_path)?;
    let length = resolve_member_path(root, &length_path)?;
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = strip_type_aliases(data.member_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: element_size,
        encoding: element_encoding,
        ..
    } = strip_type_aliases(target_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: length_size,
        encoding: length_encoding,
        ..
    } = strip_type_aliases(length.member_type)
    else {
        return None;
    };

    let byte_encoding = *element_encoding == gimli::DW_ATE_unsigned.0 as u16
        || *element_encoding == gimli::DW_ATE_unsigned_char.0 as u16;
    let unsigned_length = *length_encoding == gimli::DW_ATE_unsigned.0 as u16;
    // Aggregate size, member offsets, and metadata widths come from DWARF.
    let aggregate_size = root.size();
    let data_end = data.offset.checked_add(*pointer_size)?;
    let length_end = length.offset.checked_add(*length_size)?;
    let members_overlap = data.offset < length_end && length.offset < data_end;
    if *pointer_size == 0
        || *pointer_size != *length_size
        || *element_size != 1
        || !byte_encoding
        || !unsigned_length
        || data_end > aggregate_size
        || length_end > aggregate_size
        || members_overlap
    {
        return None;
    }

    Some(IndirectBytesLayout {
        data_path,
        length_path,
        presentation: ValuePresentation::Utf8String,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CuId, ModuleId, StructMember, TypeIdentity, TypeOrigin};

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

    fn member(name: &str, member_type: TypeInfo, offset: u64) -> StructMember {
        StructMember {
            name: name.to_string(),
            member_type,
            offset,
            bit_offset: None,
            bit_size: None,
        }
    }

    fn unsigned_type(name: &str, size: u64) -> TypeInfo {
        TypeInfo::BaseType {
            name: name.to_string(),
            size,
            encoding: gimli::DW_ATE_unsigned.0 as u16,
        }
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

    #[test]
    fn recognizes_rust_str_layout() {
        let current = rust_str_type_64("&str", SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(IndirectBytesLayout {
                data_path: field_path(&["data_ptr"]),
                length_path: field_path(&["length"]),
                presentation: ValuePresentation::Utf8String,
            })
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
            IndirectBytesLayout {
                data_path: field_path(&["vec", "buf", "inner", "ptr", "pointer", "pointer",]),
                length_path: field_path(&["vec", "len"]),
                presentation: ValuePresentation::Utf8String,
            }
        );
        assert_eq!(
            resolve_member_path(&current.summary, &layout.data_path)
                .expect("data member")
                .offset,
            8
        );
        assert_eq!(
            resolve_member_path(&current.summary, &layout.length_path)
                .expect("length member")
                .offset,
            16
        );
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
            Some(IndirectBytesLayout {
                data_path: field_path(&["vec", "buf", "inner", "ptr", "pointer",]),
                length_path: field_path(&["vec", "len"]),
                presentation: ValuePresentation::Utf8String,
            })
        );
    }

    #[test]
    fn recognizes_pre_raw_vec_inner_layout() {
        let current = rust_string_type(
            "alloc::string::String",
            SourceLanguage::Rust,
            8,
            true,
            false,
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(IndirectBytesLayout {
                data_path: field_path(&["vec", "buf", "ptr", "pointer", "pointer",]),
                length_path: field_path(&["vec", "len"]),
                presentation: ValuePresentation::Utf8String,
            })
        );
    }

    #[test]
    fn recognizes_32_bit_std_string_layout_from_dwarf() {
        let current =
            rust_string_type("alloc::string::String", SourceLanguage::Rust, 4, true, true);

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
    }

    #[test]
    fn does_not_classify_short_string_without_qualified_identity() {
        let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn qualified_name_lookup_is_limited_to_rust_short_string() {
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
    }
}

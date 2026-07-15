use crate::{strip_type_aliases, ResolvedType, SourceLanguage, TypeInfo, ValuePresentation};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IndirectBytesLayout {
    pub(crate) data_field: &'static str,
    pub(crate) length_field: &'static str,
    pub(crate) presentation: ValuePresentation,
}

pub(super) fn resolve_value_layout(current: &ResolvedType) -> Option<IndirectBytesLayout> {
    if current.origin.as_ref()?.language != SourceLanguage::Rust {
        return None;
    }

    let TypeInfo::StructType {
        name,
        size,
        members,
    } = strip_type_aliases(&current.summary)
    else {
        return None;
    };
    if !matches!(
        name.as_str(),
        "&str" | "&mut str" | "&'static str" | "&'static mut str"
    ) {
        return None;
    }

    // rustc's bundled GDB printers have treated slice-like DWARF values as
    // `data_ptr` plus `length` since Rust 1.0, without field-name compatibility
    // branches. Older printers also removed explicit `'static` lifetimes before
    // classifying references. These are rustc debuginfo conventions, not Rust
    // ABI guarantees, so retain the language and structural checks around them.
    // See rust-lang/rust's `src/etc/gdb_rust_pretty_printing.py` and
    // `src/etc/gdb_providers.py`.
    let data = members.iter().find(|member| member.name == "data_ptr")?;
    let length = members.iter().find(|member| member.name == "length")?;
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = strip_type_aliases(&data.member_type)
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
    } = strip_type_aliases(&length.member_type)
    else {
        return None;
    };

    let byte_encoding = *element_encoding == gimli::DW_ATE_unsigned.0 as u16
        || *element_encoding == gimli::DW_ATE_unsigned_char.0 as u16;
    let unsigned_length = *length_encoding == gimli::DW_ATE_unsigned.0 as u16;
    // Aggregate size, member offsets, and metadata widths come from DWARF.
    let data_end = data.offset.checked_add(*pointer_size)?;
    let length_end = length.offset.checked_add(*length_size)?;
    let members_overlap = data.offset < length_end && length.offset < data_end;
    if *pointer_size == 0
        || *pointer_size != *length_size
        || *element_size != 1
        || !byte_encoding
        || !unsigned_length
        || data.bit_offset.is_some()
        || data.bit_size.is_some()
        || length.bit_offset.is_some()
        || length.bit_size.is_some()
        || data_end > *size
        || length_end > *size
        || members_overlap
    {
        return None;
    }

    Some(IndirectBytesLayout {
        data_field: "data_ptr",
        length_field: "length",
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

    #[test]
    fn recognizes_rust_str_layout() {
        let current = rust_str_type_64("&str", SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current),
            Some(IndirectBytesLayout {
                data_field: "data_ptr",
                length_field: "length",
                presentation: ValuePresentation::Utf8String,
            })
        );
    }

    #[test]
    fn recognizes_supported_rust_str_names() {
        for name in ["&mut str", "&'static str", "&'static mut str"] {
            let current = rust_str_type_64(name, SourceLanguage::Rust);

            assert!(resolve_value_layout(&current).is_some(), "name={name}");
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

        assert!(resolve_value_layout(&current).is_some());
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

        assert_eq!(resolve_value_layout(&current), None);
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

        assert_eq!(resolve_value_layout(&current), None);
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

        assert_eq!(resolve_value_layout(&current), None);
    }

    #[test]
    fn does_not_apply_rust_adapter_to_other_languages() {
        assert_eq!(
            resolve_value_layout(&rust_str_type_64("&str", SourceLanguage::C)),
            None
        );
    }
}

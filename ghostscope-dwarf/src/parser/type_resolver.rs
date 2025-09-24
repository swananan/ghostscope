//! DWARF type resolution utilities

use crate::core::{DwarfType, TypeCache};
use gimli::{EndianSlice, LittleEndian, UnitOffset};
use std::collections::HashMap;
use tracing::debug;

/// DWARF type resolver for parsing and caching type information
#[derive(Debug)]
pub struct TypeResolver {
    type_cache: TypeCache,
}

impl TypeResolver {
    /// Create new type resolver
    pub fn new() -> Self {
        Self {
            type_cache: HashMap::new(),
        }
    }

    /// Resolve type information from a DIE offset
    pub fn resolve_type_at_offset(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
        type_offset: UnitOffset,
    ) -> Option<DwarfType> {
        // Check cache first
        if let Some(cached_type) = self.type_cache.get(&type_offset) {
            return cached_type.clone();
        }

        debug!("Resolving type at offset {:?}", type_offset);

        // Get the type DIE
        let type_entry = match unit.entry(type_offset) {
            Ok(entry) => entry,
            Err(e) => {
                debug!("Failed to get type entry at {:?}: {}", type_offset, e);
                self.type_cache.insert(type_offset, None);
                return None;
            }
        };

        // Parse the type based on its tag
        let dwarf_type = match type_entry.tag() {
            gimli::DW_TAG_base_type => self.parse_base_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_pointer_type => self.parse_pointer_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_array_type => self.parse_array_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                self.parse_struct_type(dwarf, &type_entry, unit)
            }
            gimli::DW_TAG_union_type => self.parse_union_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_enumeration_type => self.parse_enum_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_typedef => self.parse_typedef(dwarf, &type_entry, unit),
            gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => self.parse_qualified_type(dwarf, &type_entry, unit),
            gimli::DW_TAG_subroutine_type => self.parse_function_type(dwarf, &type_entry, unit),
            _ => {
                debug!("Unsupported type tag: {:?}", type_entry.tag());
                None
            }
        };

        // Cache the result
        self.type_cache.insert(type_offset, dwarf_type.clone());
        dwarf_type
    }

    /// Parse base type (int, float, char, etc.)
    fn parse_base_type(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut name = String::new();
        let mut byte_size = 0;
        let mut encoding = gimli::constants::DW_ATE_address; // Default

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_value) = dwarf.attr_string(unit, attr.value()) {
                        name = name_value.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                gimli::DW_AT_encoding => {
                    if let gimli::AttributeValue::Encoding(enc) = attr.value() {
                        encoding = enc;
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            name = format!("unknown_base_type_{byte_size}");
        }

        Some(DwarfType::BaseType {
            name,
            size: byte_size,
            encoding,
        })
    }

    /// Parse pointer type
    fn parse_pointer_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut byte_size = 8; // Default pointer size for 64-bit
        let mut target_type = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        target_type = self.resolve_type_at_offset(dwarf, unit, type_offset);
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        let target = target_type.unwrap_or(DwarfType::UnknownType {
            name: "void".to_string(),
        });

        Some(DwarfType::PointerType {
            target_type: Box::new(target),
            size: byte_size,
        })
    }

    /// Parse array type
    fn parse_array_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut element_type = None;
        let mut total_size = None;
        let mut element_count = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        element_type = self.resolve_type_at_offset(dwarf, unit, type_offset);
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        total_size = Some(size);
                    }
                }
                _ => {}
            }
        }

        // Try to get array bounds from child DIEs
        if let Ok(mut entries) = unit.entries_at_offset(entry.offset()) {
            if let Ok(Some(_)) = entries.next_entry() {
                // Skip current entry
                while let Ok(Some((_, child_entry))) = entries.next_dfs() {
                    if child_entry.tag() == gimli::DW_TAG_subrange_type {
                        let mut child_attrs = child_entry.attrs();
                        while let Ok(Some(attr)) = child_attrs.next() {
                            if attr.name() == gimli::DW_AT_count {
                                if let gimli::AttributeValue::Udata(count) = attr.value() {
                                    element_count = Some(count);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        let element = element_type.unwrap_or(DwarfType::UnknownType {
            name: "unknown".to_string(),
        });

        Some(DwarfType::ArrayType {
            element_type: Box::new(element),
            element_count,
            total_size,
        })
    }

    /// Parse struct/class type
    fn parse_struct_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut name = String::new();
        let mut byte_size = 0;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_value) = dwarf.attr_string(unit, attr.value()) {
                        name = name_value.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            name = format!("anonymous_struct_{byte_size}");
        }

        // TODO: Parse struct members from child DIEs
        Some(DwarfType::StructType {
            name,
            size: byte_size,
            members: Vec::new(),
        })
    }

    /// Parse union type
    fn parse_union_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut name = String::new();
        let mut byte_size = 0;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_value) = dwarf.attr_string(unit, attr.value()) {
                        name = name_value.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            name = format!("anonymous_union_{byte_size}");
        }

        Some(DwarfType::UnionType {
            name,
            size: byte_size,
            members: Vec::new(),
        })
    }

    /// Parse enum type
    fn parse_enum_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut name = String::new();
        let mut byte_size = 4; // Default enum size

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_value) = dwarf.attr_string(unit, attr.value()) {
                        name = name_value.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_byte_size => {
                    if let gimli::AttributeValue::Udata(size) = attr.value() {
                        byte_size = size;
                    }
                }
                _ => {}
            }
        }

        if name.is_empty() {
            name = format!("anonymous_enum_{byte_size}");
        }

        // Treat enum as signed integer base type
        let base_type = DwarfType::BaseType {
            name: "int".to_string(),
            size: byte_size,
            encoding: gimli::constants::DW_ATE_signed,
        };

        Some(DwarfType::EnumType {
            name,
            size: byte_size,
            base_type: Box::new(base_type),
            variants: Vec::new(), // TODO: Parse enum variants
        })
    }

    /// Parse typedef
    fn parse_typedef(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut name = String::new();
        let mut underlying_type = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            match attr.name() {
                gimli::DW_AT_name => {
                    if let Ok(name_value) = dwarf.attr_string(unit, attr.value()) {
                        name = name_value.to_string_lossy().into_owned();
                    }
                }
                gimli::DW_AT_type => {
                    if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                        underlying_type = self.resolve_type_at_offset(dwarf, unit, type_offset);
                    }
                }
                _ => {}
            }
        }

        let underlying = underlying_type.unwrap_or(DwarfType::UnknownType {
            name: "unknown".to_string(),
        });

        Some(DwarfType::TypedefType {
            name,
            underlying_type: Box::new(underlying),
        })
    }

    /// Parse qualified type (const, volatile, restrict)
    fn parse_qualified_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let qualifier = match entry.tag() {
            gimli::DW_TAG_const_type => crate::core::TypeQualifier::Const,
            gimli::DW_TAG_volatile_type => crate::core::TypeQualifier::Volatile,
            gimli::DW_TAG_restrict_type => crate::core::TypeQualifier::Restrict,
            _ => return None,
        };

        let mut underlying_type = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == gimli::DW_AT_type {
                if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                    underlying_type = self.resolve_type_at_offset(dwarf, unit, type_offset);
                    break;
                }
            }
        }

        let underlying = underlying_type.unwrap_or(DwarfType::UnknownType {
            name: "unknown".to_string(),
        });

        Some(DwarfType::QualifiedType {
            qualifier,
            underlying_type: Box::new(underlying),
        })
    }

    /// Parse function type
    fn parse_function_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<DwarfType> {
        let mut return_type = None;

        let mut attrs = entry.attrs();
        while let Ok(Some(attr)) = attrs.next() {
            if attr.name() == gimli::DW_AT_type {
                if let gimli::AttributeValue::UnitRef(type_offset) = attr.value() {
                    return_type = Some(Box::new(self.resolve_type_at_offset(
                        dwarf,
                        unit,
                        type_offset,
                    )?));
                    break;
                }
            }
        }

        // TODO: Parse parameter types from child DIEs

        Some(DwarfType::FunctionType {
            return_type,
            parameters: Vec::new(),
        })
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> usize {
        self.type_cache.len()
    }

    /// Clear cache
    pub fn clear_cache(&mut self) {
        self.type_cache.clear();
    }
}

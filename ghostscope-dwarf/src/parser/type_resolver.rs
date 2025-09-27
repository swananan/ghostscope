//! DWARF type resolution utilities

use crate::{EnumVariant, StructMember, TypeCache, TypeInfo, TypeQualifier};
use gimli::{EndianSlice, LittleEndian, Reader, UnitOffset};
use std::collections::{HashMap, HashSet};
use tracing::debug;

/// DWARF type resolver for parsing and caching type information
#[derive(Debug)]
pub struct TypeResolver {
    type_cache: TypeCache,
    in_progress: HashSet<UnitOffset>,
}

impl TypeResolver {
    /// Create new type resolver
    pub fn new() -> Self {
        Self {
            type_cache: HashMap::new(),
            in_progress: HashSet::new(),
        }
    }

    /// Try to resolve an attribute value to u64 by following references to constant DIEs.
    fn resolve_attr_u64(
        &self,
        _dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
        val: gimli::AttributeValue<EndianSlice<LittleEndian>>,
    ) -> Option<u64> {
        match val {
            gimli::AttributeValue::Udata(v) => Some(v),
            gimli::AttributeValue::Sdata(v) => {
                if v >= 0 {
                    Some(v as u64)
                } else {
                    None
                }
            }
            gimli::AttributeValue::UnitRef(off) => {
                // Follow reference within the same unit and try to find DW_AT_const_value
                if let Ok(entry) = unit.entry(off) {
                    let mut attrs = entry.attrs();
                    while let Ok(Some(attr)) = attrs.next() {
                        if attr.name() == gimli::DW_AT_const_value {
                            match attr.value() {
                                gimli::AttributeValue::Udata(v) => return Some(v),
                                gimli::AttributeValue::Sdata(v) => {
                                    if v >= 0 {
                                        return Some(v as u64);
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                None
            }
            // TODO: handle DebugInfoRef if encountered across units
            _ => None,
        }
    }

    /// Resolve type information from a DIE offset
    pub fn resolve_type_at_offset(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
        type_offset: UnitOffset,
    ) -> Option<TypeInfo> {
        // Check cache first
        if let Some(cached_type) = self.type_cache.get(&type_offset) {
            return cached_type.clone();
        }

        // Detect recursion to avoid infinite loops (e.g., self-referential types)
        if self.in_progress.contains(&type_offset) {
            // Return a shallow placeholder without caching
            return Some(TypeInfo::UnknownType {
                name: "<recursive>".to_string(),
            });
        }

        self.in_progress.insert(type_offset);
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
        // Mark resolution complete
        self.in_progress.remove(&type_offset);
        dwarf_type
    }

    /// Parse base type (int, float, char, etc.)
    fn parse_base_type(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        Some(TypeInfo::BaseType {
            name,
            size: byte_size,
            encoding: encoding.0 as u16,
        })
    }

    /// Parse pointer type
    fn parse_pointer_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        let target = target_type.unwrap_or(TypeInfo::UnknownType {
            name: "void".to_string(),
        });

        Some(TypeInfo::PointerType {
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
    ) -> Option<TypeInfo> {
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
        if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
            if let Ok(root) = tree.root() {
                let mut children = root.children();
                while let Ok(Some(child)) = children.next() {
                    let child_entry = child.entry();
                    if child_entry.tag() == gimli::DW_TAG_subrange_type {
                        let mut child_attrs = child_entry.attrs();
                        let mut count_attr: Option<u64> = None;
                        let mut lower_bound: Option<i64> = None;
                        let mut upper_bound: Option<i64> = None;
                        while let Ok(Some(attr)) = child_attrs.next() {
                            match attr.name() {
                                gimli::DW_AT_count => {
                                    if let Some(c) =
                                        self.resolve_attr_u64(dwarf, unit, attr.value())
                                    {
                                        count_attr = Some(c);
                                    }
                                }
                                gimli::DW_AT_lower_bound => match attr.value() {
                                    gimli::AttributeValue::Udata(v) => lower_bound = Some(v as i64),
                                    gimli::AttributeValue::Sdata(v) => lower_bound = Some(v),
                                    gimli::AttributeValue::UnitRef(off) => {
                                        if let Ok(e2) = unit.entry(off) {
                                            if let Ok(Some(cv)) = e2.attr(gimli::DW_AT_const_value)
                                            {
                                                match cv.value() {
                                                    gimli::AttributeValue::Sdata(v) => {
                                                        lower_bound = Some(v)
                                                    }
                                                    gimli::AttributeValue::Udata(v) => {
                                                        lower_bound = Some(v as i64)
                                                    }
                                                    _ => {}
                                                }
                                            }
                                        }
                                    }
                                    _ => {}
                                },
                                gimli::DW_AT_upper_bound => {
                                    if let Some(v) =
                                        self.resolve_attr_u64(dwarf, unit, attr.value())
                                    {
                                        upper_bound = Some(v as i64);
                                    }
                                }
                                _ => {}
                            }
                        }
                        if let Some(c) = count_attr {
                            element_count = Some(c);
                        } else if let Some(ub) = upper_bound {
                            let lb = lower_bound.unwrap_or(0);
                            let width = ub.saturating_sub(lb) as u64 + 1;
                            element_count = Some(width);
                        }
                    }
                }
            }
        }

        let element = element_type.unwrap_or(TypeInfo::UnknownType {
            name: "unknown".to_string(),
        });

        // If total_size is not provided, try to compute from element_count and element size
        let computed_total_size = if total_size.is_none() {
            if let Some(cnt) = element_count {
                let esize = match &element {
                    TypeInfo::TypedefType {
                        underlying_type, ..
                    } => underlying_type.size(),
                    TypeInfo::QualifiedType {
                        underlying_type, ..
                    } => underlying_type.size(),
                    _ => element.size(),
                };
                Some(esize.saturating_mul(cnt))
            } else {
                None
            }
        } else {
            total_size
        };

        Some(TypeInfo::ArrayType {
            element_type: Box::new(element),
            element_count,
            total_size: computed_total_size,
        })
    }

    /// Parse struct/class type
    fn parse_struct_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        // Parse struct members from child DIEs
        let mut members: Vec<StructMember> = Vec::new();
        if let Ok(mut entries) = unit.entries_at_offset(entry.offset()) {
            // Skip current entry
            if let Ok(Some(_)) = entries.next_entry() {
                while let Ok(Some((_, child_entry))) = entries.next_dfs() {
                    if child_entry.tag() == gimli::DW_TAG_member {
                        let mut m_name = String::new();
                        let mut m_type: Option<TypeInfo> = None;
                        let mut m_offset: u64 = 0;
                        let mut bit_offset: Option<u8> = None;
                        let mut bit_size: Option<u8> = None;

                        let mut child_attrs = child_entry.attrs();
                        while let Ok(Some(m_attr)) = child_attrs.next() {
                            match m_attr.name() {
                                gimli::DW_AT_name => {
                                    if let Ok(nv) = dwarf.attr_string(unit, m_attr.value()) {
                                        m_name = nv.to_string_lossy().into_owned();
                                    }
                                }
                                gimli::DW_AT_type => {
                                    if let gimli::AttributeValue::UnitRef(toff) = m_attr.value() {
                                        m_type = self.resolve_type_at_offset(dwarf, unit, toff);
                                    }
                                }
                                gimli::DW_AT_data_member_location => match m_attr.value() {
                                    gimli::AttributeValue::Udata(v) => m_offset = v,
                                    gimli::AttributeValue::Sdata(v) => m_offset = v as u64,
                                    gimli::AttributeValue::Exprloc(expr) => {
                                        if let Some(off) = Self::eval_member_offset_expr(&expr) {
                                            m_offset = off;
                                        }
                                    }
                                    _ => {}
                                },
                                gimli::DW_AT_bit_offset => {
                                    if let gimli::AttributeValue::Udata(v) = m_attr.value() {
                                        bit_offset = u8::try_from(v).ok();
                                    }
                                }
                                // Some producers use DW_AT_data_bit_offset instead of DW_AT_bit_offset
                                // This is the bit offset measured from the start of the containing object.
                                // Convert it to (byte_offset, bit_offset_within_container).
                                gimli::DW_AT_data_bit_offset => {
                                    if let gimli::AttributeValue::Udata(v) = m_attr.value() {
                                        let bits = v;
                                        let byte_off = bits / 8;
                                        let bit_off = (bits % 8) as u8;
                                        // Set member byte offset based on data_bit_offset
                                        m_offset = byte_off;
                                        // Only set if not already set by DW_AT_bit_offset
                                        if bit_offset.is_none() {
                                            bit_offset = Some(bit_off);
                                        }
                                    }
                                }
                                gimli::DW_AT_bit_size => {
                                    if let gimli::AttributeValue::Udata(v) = m_attr.value() {
                                        bit_size = u8::try_from(v).ok();
                                    }
                                }
                                _ => {}
                            }
                        }

                        if m_name.is_empty() {
                            m_name = format!("member_{}", members.len());
                        }
                        let mut member_type = m_type.unwrap_or(TypeInfo::UnknownType {
                            name: "unknown".to_string(),
                        });
                        // Wrap bitfield as BitfieldType to preserve formatting when printed standalone
                        if let Some(bs) = bit_size {
                            let bo = bit_offset.unwrap_or(0);
                            member_type = TypeInfo::BitfieldType {
                                underlying_type: Box::new(member_type),
                                bit_offset: bo,
                                bit_size: bs,
                            };
                        }

                        members.push(StructMember {
                            name: m_name,
                            member_type,
                            offset: m_offset,
                            bit_offset,
                            bit_size,
                        });
                    }
                }
            }
        }

        // Post-process members to infer array sizes when missing
        if !members.is_empty() {
            // Build a sorted list of offsets for robust next-offset detection
            let mut offsets: Vec<u64> = members.iter().map(|m| m.offset).collect();
            offsets.sort_unstable();
            offsets.dedup();

            let mut adjusted: Vec<StructMember> = Vec::with_capacity(members.len());
            for mut m in members.into_iter() {
                // Find the smallest offset strictly greater than this member's offset
                let next_offset = offsets
                    .iter()
                    .cloned()
                    .filter(|&off| off > m.offset)
                    .min()
                    .unwrap_or(byte_size);

                // Only adjust if this member is an ArrayType with unknown sizes
                if let TypeInfo::ArrayType {
                    element_type,
                    element_count,
                    total_size,
                } = &m.member_type
                {
                    if element_count.is_none() && total_size.is_none() {
                        let avail = next_offset.saturating_sub(m.offset);
                        if avail > 0 {
                            let elem_sz = element_type.size();
                            let mut new_count: Option<u64> = None;
                            if elem_sz > 0 && avail % elem_sz == 0 {
                                new_count = Some(avail / elem_sz);
                            }
                            m.member_type = TypeInfo::ArrayType {
                                element_type: element_type.clone(),
                                element_count: new_count,
                                total_size: Some(avail),
                            };
                        }
                    }
                }
                adjusted.push(m);
            }
            members = adjusted;
        }

        Some(TypeInfo::StructType {
            name,
            size: byte_size,
            members,
        })
    }

    /// Parse union type
    fn parse_union_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        // Parse union members similar to struct
        let mut members: Vec<StructMember> = Vec::new();
        if let Ok(mut entries) = unit.entries_at_offset(entry.offset()) {
            if let Ok(Some(_)) = entries.next_entry() {
                while let Ok(Some((_, child_entry))) = entries.next_dfs() {
                    if child_entry.tag() == gimli::DW_TAG_member {
                        let mut m_name = String::new();
                        let mut m_type: Option<TypeInfo> = None;
                        let mut child_attrs = child_entry.attrs();
                        let mut m_offset: u64 = 0;
                        while let Ok(Some(m_attr)) = child_attrs.next() {
                            match m_attr.name() {
                                gimli::DW_AT_name => {
                                    if let Ok(nv) = dwarf.attr_string(unit, m_attr.value()) {
                                        m_name = nv.to_string_lossy().into_owned();
                                    }
                                }
                                gimli::DW_AT_type => {
                                    if let gimli::AttributeValue::UnitRef(toff) = m_attr.value() {
                                        m_type = self.resolve_type_at_offset(dwarf, unit, toff);
                                    }
                                }
                                gimli::DW_AT_data_member_location => match m_attr.value() {
                                    gimli::AttributeValue::Udata(v) => m_offset = v,
                                    gimli::AttributeValue::Sdata(v) => m_offset = v as u64,
                                    gimli::AttributeValue::Exprloc(expr) => {
                                        if let Some(off) = Self::eval_member_offset_expr(&expr) {
                                            m_offset = off;
                                        }
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }

                        if m_name.is_empty() {
                            m_name = format!("member_{}", members.len());
                        }
                        let member_type = m_type.unwrap_or(TypeInfo::UnknownType {
                            name: "unknown".to_string(),
                        });

                        members.push(StructMember {
                            name: m_name,
                            member_type,
                            offset: m_offset,
                            bit_offset: None,
                            bit_size: None,
                        });
                    }
                }
            }
        }

        Some(TypeInfo::UnionType {
            name,
            size: byte_size,
            members,
        })
    }

    /// Parse enum type
    fn parse_enum_type(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        // Treat enum underlying type as signed integer by default
        let base_type = TypeInfo::BaseType {
            name: "int".to_string(),
            size: byte_size,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        };

        // Parse enum variants
        let mut variants: Vec<EnumVariant> = Vec::new();
        let mut last_value: Option<i64> = None;
        if let Ok(mut entries) = unit.entries_at_offset(entry.offset()) {
            if let Ok(Some(_)) = entries.next_entry() {
                while let Ok(Some((_, child_entry))) = entries.next_dfs() {
                    if child_entry.tag() == gimli::DW_TAG_enumerator {
                        let mut v_name = String::new();
                        let mut v_value: Option<i64> = None;
                        let mut child_attrs = child_entry.attrs();
                        while let Ok(Some(a)) = child_attrs.next() {
                            match a.name() {
                                gimli::DW_AT_name => {
                                    if let Ok(nv) = dwarf.attr_string(unit, a.value()) {
                                        v_name = nv.to_string_lossy().into_owned();
                                    }
                                }
                                gimli::DW_AT_const_value => match a.value() {
                                    gimli::AttributeValue::Udata(v) => v_value = Some(v as i64),
                                    gimli::AttributeValue::Sdata(v) => v_value = Some(v),
                                    // Some producers might encode as Data{1,2,4,8}
                                    gimli::AttributeValue::Data1(d) => {
                                        v_value = Some(d as i8 as i64)
                                    }
                                    gimli::AttributeValue::Data2(d) => {
                                        v_value = Some((d as i16) as i64)
                                    }
                                    gimli::AttributeValue::Data4(d) => {
                                        v_value = Some((d as i32) as i64)
                                    }
                                    gimli::AttributeValue::Data8(d) => v_value = Some(d as i64),
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                        if v_name.is_empty() {
                            v_name = format!("variant_{}", variants.len());
                        }
                        // If no explicit const_value, apply C enum auto-increment rule
                        let resolved_value = match v_value {
                            Some(v) => v,
                            None => last_value.map(|lv| lv + 1).unwrap_or(0),
                        };
                        last_value = Some(resolved_value);
                        variants.push(EnumVariant {
                            name: v_name,
                            value: resolved_value,
                        });
                    }
                }
            }
        }

        Some(TypeInfo::EnumType {
            name,
            size: byte_size,
            base_type: Box::new(base_type),
            variants,
        })
    }

    /// Parse typedef
    fn parse_typedef(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<LittleEndian>>,
    ) -> Option<TypeInfo> {
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

        let underlying = underlying_type.unwrap_or(TypeInfo::UnknownType {
            name: "unknown".to_string(),
        });

        Some(TypeInfo::TypedefType {
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
    ) -> Option<TypeInfo> {
        let qualifier = match entry.tag() {
            gimli::DW_TAG_const_type => TypeQualifier::Const,
            gimli::DW_TAG_volatile_type => TypeQualifier::Volatile,
            gimli::DW_TAG_restrict_type => TypeQualifier::Restrict,
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

        let underlying = underlying_type.unwrap_or(TypeInfo::UnknownType {
            name: "unknown".to_string(),
        });

        Some(TypeInfo::QualifiedType {
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
    ) -> Option<TypeInfo> {
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

        Some(TypeInfo::FunctionType {
            return_type,
            parameters: Vec::new(),
        })
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> usize {
        self.type_cache.len()
    }

    /// Attempt to evaluate DW_AT_data_member_location exprloc to a constant offset.
    /// Supports common patterns like DW_OP_constu/S/DW_OP_plus_uconst with no additional ops.
    fn eval_member_offset_expr(expr: &gimli::Expression<EndianSlice<LittleEndian>>) -> Option<u64> {
        let bytes = expr.0.slice();
        if bytes.is_empty() {
            return None;
        }
        let mut rdr = gimli::EndianSlice::new(bytes, LittleEndian);
        // Read first opcode
        if let Ok(op) = rdr.read_u8() {
            match op {
                // DW_OP_constu (0x10)
                0x10 => {
                    if let Ok(val) = rdr.read_uleb128() {
                        // Ensure no trailing ops
                        if rdr.slice().is_empty() {
                            return Some(val);
                        }
                    }
                }
                // DW_OP_consts (0x11)
                0x11 => {
                    if let Ok(val) = rdr.read_sleb128() {
                        if rdr.slice().is_empty() {
                            return Some(val as u64);
                        }
                    }
                }
                // DW_OP_plus_uconst (0x23)
                0x23 => {
                    if let Ok(val) = rdr.read_uleb128() {
                        if rdr.slice().is_empty() {
                            return Some(val);
                        }
                    }
                }
                _ => {}
            }
        }
        None
    }
}

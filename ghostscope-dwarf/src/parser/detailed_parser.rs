//! Detailed DWARF parser for on-demand traversal and variable resolution
//!
//! This module handles detailed parsing of DWARF tree structures, including:
//! - Tree traversal for variable collection
//! - Variable and parameter DIE parsing
//! - Scope-aware variable resolution

use crate::{
    core::{EvaluationResult, Result},
    parser::ExpressionEvaluator,
    TypeInfo,
};
use gimli::{EndianSlice, LittleEndian, Reader};
// Alias gimli constants to upper-case identifiers to satisfy naming lints without allow attributes
use gimli::constants::{
    DW_AT_byte_size as DW_AT_BYTE_SIZE, DW_AT_encoding as DW_AT_ENCODING, DW_AT_name as DW_AT_NAME,
    DW_AT_type as DW_AT_TYPE, DW_TAG_array_type as DW_TAG_ARRAY_TYPE,
    DW_TAG_base_type as DW_TAG_BASE_TYPE, DW_TAG_class_type as DW_TAG_CLASS_TYPE,
    DW_TAG_const_type as DW_TAG_CONST_TYPE, DW_TAG_enumeration_type as DW_TAG_ENUMERATION_TYPE,
    DW_TAG_pointer_type as DW_TAG_POINTER_TYPE, DW_TAG_restrict_type as DW_TAG_RESTRICT_TYPE,
    DW_TAG_structure_type as DW_TAG_STRUCTURE_TYPE,
    DW_TAG_subroutine_type as DW_TAG_SUBROUTINE_TYPE, DW_TAG_typedef as DW_TAG_TYPEDEF,
    DW_TAG_union_type as DW_TAG_UNION_TYPE, DW_TAG_volatile_type as DW_TAG_VOLATILE_TYPE,
};
use std::collections::HashSet;
// no tracing imports needed here

/// Variable with complete information including EvaluationResult
#[derive(Debug, Clone)]
pub struct VariableWithEvaluation {
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<TypeInfo>,
    pub evaluation_result: EvaluationResult,
    pub scope_depth: usize,
    pub is_parameter: bool,
    pub is_artificial: bool,
}

// Removed full traversal request/context types in shallow mode

/// Detailed DWARF parser for tree traversal and variable collection
#[derive(Debug)]
pub struct DetailedParser {}

impl DetailedParser {
    /// Create new detailed parser
    pub fn new() -> Self {
        Self {}
    }

    /// Attach a cross-CU type name index for faster completion
    pub fn set_type_name_index(&mut self, _index: std::sync::Arc<crate::data::TypeNameIndex>) {}

    // Full type resolution intentionally removed; only shallow type resolution is supported.

    /// Shallow type resolution (no recursive member expansion)
    /// Returns minimal TypeInfo with name/size where possible.
    pub fn resolve_type_shallow_at_offset(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        mut type_offset: gimli::UnitOffset,
    ) -> Option<TypeInfo> {
        let mut visited = std::collections::HashSet::new();
        // Strip typedef/qualifiers chain but keep last typedef name if it's the canonical alias
        let mut alias_name: Option<String> = None;

        let mut step = 0usize;
        const MAX_STEPS: usize = 64;
        loop {
            if step >= MAX_STEPS || !visited.insert(type_offset) {
                return Some(TypeInfo::UnknownType {
                    name: "<depth_limit>".to_string(),
                });
            }
            step += 1;
            let entry = unit.entry(type_offset).ok()?;
            let tag = entry.tag();
            // Utility to read attr string name
            let mut entry_name: Option<String> = None;
            if let Ok(Some(a)) = entry.attr(DW_AT_NAME) {
                if let Ok(s) = dwarf.attr_string(unit, a.value()) {
                    entry_name = Some(s.to_string_lossy().into_owned());
                }
            }
            match tag {
                DW_TAG_TYPEDEF => {
                    if alias_name.is_none() {
                        alias_name = entry_name.clone();
                    }
                    if let Ok(Some(gimli::AttributeValue::UnitRef(off))) =
                        entry.attr_value(DW_AT_TYPE)
                    {
                        type_offset = off;
                        continue;
                    }
                    return Some(TypeInfo::TypedefType {
                        name: alias_name.unwrap_or_else(|| {
                            entry_name.unwrap_or_else(|| "<anon_typedef>".to_string())
                        }),
                        underlying_type: Box::new(TypeInfo::UnknownType {
                            name: "<unknown>".to_string(),
                        }),
                    });
                }
                DW_TAG_CONST_TYPE | DW_TAG_VOLATILE_TYPE | DW_TAG_RESTRICT_TYPE => {
                    if let Ok(Some(gimli::AttributeValue::UnitRef(off))) =
                        entry.attr_value(DW_AT_TYPE)
                    {
                        type_offset = off;
                        continue;
                    }
                    return Some(TypeInfo::QualifiedType {
                        qualifier: crate::TypeQualifier::Const,
                        underlying_type: Box::new(TypeInfo::UnknownType {
                            name: "<unknown>".to_string(),
                        }),
                    });
                }
                DW_TAG_POINTER_TYPE => {
                    let mut byte_size: u64 = 8;
                    if let Ok(Some(a)) = entry.attr(DW_AT_BYTE_SIZE) {
                        if let gimli::AttributeValue::Udata(sz) = a.value() {
                            byte_size = sz;
                        }
                    }
                    // Try to get pointee name without resolving members
                    let mut pointee_name = None;
                    if let Ok(Some(gimli::AttributeValue::UnitRef(toff))) =
                        entry.attr_value(DW_AT_TYPE)
                    {
                        if let Ok(tentry) = unit.entry(toff) {
                            if let Ok(Some(na)) = tentry.attr(DW_AT_NAME) {
                                if let Ok(s) = dwarf.attr_string(unit, na.value()) {
                                    pointee_name = Some(s.to_string_lossy().into_owned());
                                }
                            }
                        }
                    }
                    let target = pointee_name
                        .map(|n| TypeInfo::UnknownType { name: n })
                        .unwrap_or(TypeInfo::UnknownType {
                            name: "void".to_string(),
                        });
                    return Some(TypeInfo::PointerType {
                        target_type: Box::new(target),
                        size: byte_size,
                    });
                }
                DW_TAG_BASE_TYPE => {
                    let name = entry_name.unwrap_or_else(|| "<base>".to_string());
                    let mut byte_size = 0u64;
                    let mut encoding = gimli::constants::DW_ATE_unsigned;
                    let mut attrs = entry.attrs();
                    while let Ok(Some(a)) = attrs.next() {
                        match a.name() {
                            DW_AT_BYTE_SIZE => {
                                if let gimli::AttributeValue::Udata(sz) = a.value() {
                                    byte_size = sz;
                                }
                            }
                            DW_AT_ENCODING => {
                                if let gimli::AttributeValue::Encoding(enc) = a.value() {
                                    encoding = enc;
                                }
                            }
                            _ => {}
                        }
                    }
                    return Some(TypeInfo::BaseType {
                        name,
                        size: byte_size,
                        encoding: encoding.0 as u16,
                    });
                }
                DW_TAG_STRUCTURE_TYPE | DW_TAG_CLASS_TYPE => {
                    let name = entry_name.unwrap_or_else(|| "<anon_struct>".to_string());
                    let mut byte_size = 0u64;
                    if let Ok(Some(a)) = entry.attr(DW_AT_BYTE_SIZE) {
                        if let gimli::AttributeValue::Udata(sz) = a.value() {
                            byte_size = sz;
                        }
                    }
                    // Collect only direct member DIEs
                    let mut members: Vec<crate::StructMember> = Vec::new();
                    if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let ce = child.entry();
                                if ce.tag() == gimli::DW_TAG_member {
                                    // member name
                                    let mut m_name = String::new();
                                    if let Ok(Some(na)) = ce.attr(DW_AT_NAME) {
                                        if let Ok(s) = dwarf.attr_string(unit, na.value()) {
                                            m_name = s.to_string_lossy().into_owned();
                                        }
                                    }
                                    // member type (shallow)
                                    let mut m_type = TypeInfo::UnknownType {
                                        name: "unknown".to_string(),
                                    };
                                    if let Ok(Some(gimli::AttributeValue::UnitRef(toff))) =
                                        ce.attr_value(DW_AT_TYPE)
                                    {
                                        if let Some(ti) =
                                            Self::resolve_type_shallow_at_offset(dwarf, unit, toff)
                                        {
                                            m_type = ti;
                                        }
                                    }
                                    // member offset (simple evaluation)
                                    let mut m_offset: u64 = 0;
                                    if let Ok(Some(ml)) = ce.attr(gimli::DW_AT_data_member_location)
                                    {
                                        match ml.value() {
                                            gimli::AttributeValue::Udata(v) => m_offset = v,
                                            gimli::AttributeValue::Exprloc(expr) => {
                                                // Try to eval simple DW_OP_constu / plus_uconst
                                                if let Some(v) =
                                                    Self::eval_member_offset_expr_local(&expr)
                                                {
                                                    m_offset = v;
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    // bit offsets/sizes (optional)
                                    let mut bit_offset: Option<u8> = None;
                                    let mut bit_size: Option<u8> = None;
                                    if let Ok(Some(bo)) = ce.attr(gimli::DW_AT_bit_offset) {
                                        if let gimli::AttributeValue::Udata(v) = bo.value() {
                                            bit_offset = u8::try_from(v).ok();
                                        }
                                    }
                                    if let Ok(Some(bs)) = ce.attr(gimli::DW_AT_data_bit_offset) {
                                        if let gimli::AttributeValue::Udata(v) = bs.value() {
                                            bit_offset = u8::try_from(v % 8).ok();
                                            m_offset = v / 8;
                                        }
                                    }
                                    if let Ok(Some(bsz)) = ce.attr(gimli::DW_AT_bit_size) {
                                        if let gimli::AttributeValue::Udata(v) = bsz.value() {
                                            bit_size = u8::try_from(v).ok();
                                        }
                                    }
                                    if m_name.is_empty() {
                                        m_name = format!("member_{}", members.len());
                                    }
                                    // Wrap bitfield member type into BitfieldType for standalone printing
                                    let member_type = if let Some(bs) = bit_size {
                                        let bo = bit_offset.unwrap_or(0);
                                        TypeInfo::BitfieldType {
                                            underlying_type: Box::new(m_type),
                                            bit_offset: bo,
                                            bit_size: bs,
                                        }
                                    } else {
                                        m_type
                                    };
                                    members.push(crate::StructMember {
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
                    // Post-process: infer array total_size/element_count when missing (from next member offset or struct size)
                    if !members.is_empty() {
                        // Pre-build sorted offsets
                        let mut offsets: Vec<u64> = members.iter().map(|m| m.offset).collect();
                        offsets.sort_unstable();
                        offsets.dedup();

                        for m in &mut members {
                            // Only for array members with missing size info
                            if let TypeInfo::ArrayType {
                                element_type,
                                element_count,
                                total_size,
                            } = &m.member_type
                            {
                                if element_count.is_none() && total_size.is_none() {
                                    let cur_off = m.offset;
                                    let next_off = offsets
                                        .iter()
                                        .cloned()
                                        .filter(|&o| o > cur_off)
                                        .min()
                                        .unwrap_or(byte_size);
                                    let avail = next_off.saturating_sub(cur_off);
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
                        }
                    }
                    return Some(TypeInfo::StructType {
                        name,
                        size: byte_size,
                        members,
                    });
                }
                DW_TAG_UNION_TYPE => {
                    let name = entry_name.unwrap_or_else(|| "<anon_union>".to_string());
                    let mut byte_size = 0u64;
                    if let Ok(Some(a)) = entry.attr(DW_AT_BYTE_SIZE) {
                        if let gimli::AttributeValue::Udata(sz) = a.value() {
                            byte_size = sz;
                        }
                    }
                    let mut members: Vec<crate::StructMember> = Vec::new();
                    if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let ce = child.entry();
                                if ce.tag() == gimli::DW_TAG_member {
                                    let mut m_name = String::new();
                                    if let Ok(Some(na)) = ce.attr(gimli::DW_AT_name) {
                                        if let Ok(s) = dwarf.attr_string(unit, na.value()) {
                                            m_name = s.to_string_lossy().into_owned();
                                        }
                                    }
                                    let mut m_type = TypeInfo::UnknownType {
                                        name: "unknown".to_string(),
                                    };
                                    if let Ok(Some(gimli::AttributeValue::UnitRef(toff))) =
                                        ce.attr_value(DW_AT_TYPE)
                                    {
                                        if let Some(ti) =
                                            Self::resolve_type_shallow_at_offset(dwarf, unit, toff)
                                        {
                                            m_type = ti;
                                        }
                                    }
                                    if m_name.is_empty() {
                                        m_name = format!("member_{}", members.len());
                                    }
                                    members.push(crate::StructMember {
                                        name: m_name,
                                        member_type: m_type,
                                        offset: 0,
                                        bit_offset: None,
                                        bit_size: None,
                                    });
                                }
                            }
                        }
                    }
                    return Some(TypeInfo::UnionType {
                        name,
                        size: byte_size,
                        members,
                    });
                }
                DW_TAG_ENUMERATION_TYPE => {
                    let name = entry_name.unwrap_or_else(|| "<anon_enum>".to_string());
                    // Parse base type and size
                    let mut byte_size = 0u64;
                    if let Ok(Some(a)) = entry.attr(DW_AT_BYTE_SIZE) {
                        if let gimli::AttributeValue::Udata(sz) = a.value() {
                            byte_size = sz;
                        }
                    }
                    // Default base type as signed int; size from byte_size or 4
                    let mut base_type: TypeInfo = TypeInfo::BaseType {
                        name: "int".to_string(),
                        size: if byte_size > 0 { byte_size } else { 4 },
                        encoding: gimli::constants::DW_ATE_signed.0 as u16,
                    };
                    // If DW_AT_type refers to a base type, resolve it shallowly
                    if let Ok(Some(gimli::AttributeValue::UnitRef(toff))) =
                        entry.attr_value(DW_AT_TYPE)
                    {
                        if let Some(ti) = Self::resolve_type_shallow_at_offset(dwarf, unit, toff) {
                            // Accept only base/qualified/typedef chain base type as enum underlying type
                            base_type = ti;
                            // If enum size missing, use underlying base type size
                            let bs = base_type.size();
                            if byte_size == 0 && bs > 0 {
                                byte_size = bs;
                            }
                        }
                    }
                    // Collect enum variants (one level)
                    let mut variants: Vec<crate::EnumVariant> = Vec::new();
                    if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let ce = child.entry();
                                if ce.tag() == gimli::DW_TAG_enumerator {
                                    let mut v_name = String::new();
                                    if let Ok(Some(na)) = ce.attr(gimli::DW_AT_name) {
                                        if let Ok(s) = dwarf.attr_string(unit, na.value()) {
                                            v_name = s.to_string_lossy().into_owned();
                                        }
                                    }
                                    let mut v_val: i64 = 0;
                                    if let Ok(Some(cv)) = ce.attr(gimli::DW_AT_const_value) {
                                        let signed = match &base_type {
                                            TypeInfo::BaseType { encoding, .. } => {
                                                *encoding
                                                    == gimli::constants::DW_ATE_signed.0 as u16
                                                    || *encoding
                                                        == gimli::constants::DW_ATE_signed_char.0
                                                            as u16
                                            }
                                            TypeInfo::TypedefType {
                                                underlying_type, ..
                                            }
                                            | TypeInfo::QualifiedType {
                                                underlying_type, ..
                                            } => {
                                                matches!(
                                                    &**underlying_type,
                                                    TypeInfo::BaseType { encoding, .. }
                                                        if *encoding == gimli::constants::DW_ATE_signed.0 as u16
                                                            || *encoding
                                                                == gimli::constants::DW_ATE_signed_char.0 as u16
                                                )
                                            }
                                            _ => true,
                                        };
                                        v_val = match cv.value() {
                                            gimli::AttributeValue::Udata(u) => u as i64,
                                            gimli::AttributeValue::Sdata(s) => s,
                                            gimli::AttributeValue::Data1(b) => {
                                                let u = b as u64;
                                                if signed && (u & 0x80) != 0 {
                                                    (u as i8) as i64
                                                } else {
                                                    u as i64
                                                }
                                            }
                                            gimli::AttributeValue::Data2(u) => {
                                                let u = u as u64;
                                                if signed && (u & 0x8000) != 0 {
                                                    (u as i16) as i64
                                                } else {
                                                    u as i64
                                                }
                                            }
                                            gimli::AttributeValue::Data4(u) => {
                                                let u = u as u64;
                                                if signed && (u & 0x8000_0000) != 0 {
                                                    (u as i32) as i64
                                                } else {
                                                    u as i64
                                                }
                                            }
                                            gimli::AttributeValue::Data8(u) => u as i64,
                                            _ => v_val,
                                        };
                                    }
                                    if v_name.is_empty() {
                                        v_name = format!("variant_{}", variants.len());
                                    }
                                    variants.push(crate::EnumVariant {
                                        name: v_name,
                                        value: v_val,
                                    });
                                }
                            }
                        }
                    }
                    return Some(TypeInfo::EnumType {
                        name,
                        size: byte_size,
                        base_type: Box::new(base_type),
                        variants,
                    });
                }
                DW_TAG_ARRAY_TYPE => {
                    // element_type shallow + total_size if available + subrange element_count (one step deeper)
                    let mut elem_type: Option<TypeInfo> = None;
                    if let Ok(Some(gimli::AttributeValue::UnitRef(eoff))) =
                        entry.attr_value(DW_AT_TYPE)
                    {
                        elem_type = Self::resolve_type_shallow_at_offset(dwarf, unit, eoff);
                    }
                    let element_type = Box::new(elem_type.unwrap_or(TypeInfo::UnknownType {
                        name: "<elem>".to_string(),
                    }));
                    let mut total_size: Option<u64> = None;
                    if let Ok(Some(a)) = entry.attr(DW_AT_BYTE_SIZE) {
                        if let gimli::AttributeValue::Udata(sz) = a.value() {
                            total_size = Some(sz);
                        }
                    }
                    // Optional: subrange child yields count/upper_bound
                    let mut element_count: Option<u64> = None;
                    if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
                        if let Ok(root) = tree.root() {
                            let mut children = root.children();
                            while let Ok(Some(child)) = children.next() {
                                let ce = child.entry();
                                if ce.tag() == gimli::DW_TAG_subrange_type {
                                    // Prefer DW_AT_count; fallback to upper_bound (+1)
                                    if let Ok(Some(cv)) = ce.attr(gimli::DW_AT_count) {
                                        match cv.value() {
                                            gimli::AttributeValue::Udata(u) => {
                                                element_count = Some(u);
                                            }
                                            gimli::AttributeValue::Sdata(s) => {
                                                if s >= 0 {
                                                    element_count = Some(s as u64);
                                                }
                                            }
                                            gimli::AttributeValue::Data1(b) => {
                                                element_count = Some(b as u64);
                                            }
                                            gimli::AttributeValue::Data2(u) => {
                                                element_count = Some(u as u64);
                                            }
                                            gimli::AttributeValue::Data4(u) => {
                                                element_count = Some(u as u64);
                                            }
                                            gimli::AttributeValue::Data8(u) => {
                                                element_count = Some(u);
                                            }
                                            _ => {}
                                        }
                                    }
                                    if element_count.is_none() {
                                        if let Ok(Some(ub)) = ce.attr(gimli::DW_AT_upper_bound) {
                                            let ub_v: Option<i64> = match ub.value() {
                                                gimli::AttributeValue::Udata(u) => Some(u as i64),
                                                gimli::AttributeValue::Sdata(s) => Some(s),
                                                gimli::AttributeValue::Data1(b) => Some(b as i64),
                                                gimli::AttributeValue::Data2(u) => Some(u as i64),
                                                gimli::AttributeValue::Data4(u) => Some(u as i64),
                                                gimli::AttributeValue::Data8(u) => Some(u as i64),
                                                _ => None,
                                            };
                                            if let Some(ub_i) = ub_v {
                                                if ub_i >= 0 {
                                                    element_count = Some((ub_i as u64) + 1);
                                                }
                                            }
                                        }
                                    }
                                    // Stop at first subrange
                                    if element_count.is_some() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    // If total_size absent but count + elem size known, compute it
                    if total_size.is_none() {
                        let es = element_type.size();
                        if let Some(cnt) = element_count {
                            if es > 0 {
                                total_size = Some(es * cnt);
                            }
                        }
                    }
                    return Some(TypeInfo::ArrayType {
                        element_type,
                        element_count,
                        total_size,
                    });
                }
                DW_TAG_SUBROUTINE_TYPE => {
                    return Some(TypeInfo::FunctionType {
                        return_type: None,
                        parameters: Vec::new(),
                    });
                }
                _ => {
                    // Fallback: return alias name or entry name
                    let nm = alias_name
                        .or(entry_name)
                        .unwrap_or_else(|| "<unknown>".to_string());
                    return Some(TypeInfo::UnknownType { name: nm });
                }
            }
        }
    }

    /// Local simple evaluator for DW_AT_data_member_location exprloc when it's a constant offset.
    fn eval_member_offset_expr_local(
        expr: &gimli::Expression<EndianSlice<'static, LittleEndian>>,
    ) -> Option<u64> {
        let bytes = expr.0.slice();
        if bytes.is_empty() {
            return None;
        }
        let mut rdr = gimli::EndianSlice::new(bytes, LittleEndian);
        if let Ok(op) = rdr.read_u8() {
            match op {
                0x10 => rdr.read_uleb128().ok(),                   // DW_OP_constu
                0x11 => rdr.read_sleb128().ok().map(|v| v as u64), // DW_OP_consts
                0x23 => rdr.read_uleb128().ok(),                   // DW_OP_plus_uconst
                _ => None,
            }
        } else {
            None
        }
    }

    // Full variable collection and traversal helpers removed in shallow-only mode

    // parse_variable_entry wrapper removed; use parse_variable_entry_with_mode

    /// Parse a variable and optionally skip full DWARF type resolution
    pub fn parse_variable_entry_with_mode(
        &mut self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        scope_depth: usize,
    ) -> Result<Option<VariableWithEvaluation>> {
        // No traversal context retained in shallow mode
        // Resolve basic
        let mut visited = std::collections::HashSet::new();
        let Some(name) = Self::resolve_name_with_origins(entry, unit, dwarf, &mut visited)? else {
            return Ok(None);
        };
        let is_parameter = entry.tag() == gimli::constants::DW_TAG_formal_parameter;
        let type_name = Self::resolve_type_name(entry, unit, dwarf)?;
        let evaluation_result = self.parse_location(entry, unit, dwarf, address, get_cfa)?;
        // Full type resolution disabled in shallow mode
        let dwarf_type = None;
        Ok(Some(VariableWithEvaluation {
            name,
            type_name,
            dwarf_type,
            evaluation_result,
            scope_depth,
            is_parameter,
            is_artificial: false,
        }))
    }

    /// Resolve type name for a variable or type DIE.
    ///
    /// This function follows DW_AT_type chains (pointer/const/array/typedef) and
    /// includes a recursion guard to break true cycles (e.g., typedef A->B->A).
    fn resolve_type_name(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<String> {
        let mut visited_types: HashSet<gimli::UnitOffset> = HashSet::new();
        Self::resolve_type_name_rec(entry, unit, dwarf, &mut visited_types)
    }

    fn resolve_type_name_rec(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<String> {
        // Follow DW_AT_type if present
        let Some(type_off) = Self::resolve_type_ref(entry, unit)? else {
            // As a fallback, try to use the entry's own name if any
            let mut name_visited = HashSet::new();
            if let Some(n) = Self::resolve_name_with_origins(entry, unit, dwarf, &mut name_visited)?
            {
                return Ok(n);
            }
            return Ok("unknown".to_string());
        };

        // Recursion guard: if we've seen this type offset already, break the cycle
        if !visited.insert(type_off) {
            return Ok("<recursive>".to_string());
        }

        let mut tree = unit.entries_tree(Some(type_off))?;
        let type_node = tree.root()?;
        let type_entry = type_node.entry();

        // If this DIE has a name, prefer it directly
        let mut name_visited = HashSet::new();
        if let Some(name) =
            Self::resolve_name_with_origins(type_entry, unit, dwarf, &mut name_visited)?
        {
            return Ok(name);
        }

        // Handle wrapper/indirection DIEs by following their DW_AT_type
        match type_entry.tag() {
            gimli::constants::DW_TAG_pointer_type => {
                let pointee = Self::resolve_type_name_rec(type_entry, unit, dwarf, visited)?;
                Ok(format!("{pointee}*"))
            }
            gimli::constants::DW_TAG_const_type => {
                let base = Self::resolve_type_name_rec(type_entry, unit, dwarf, visited)?;
                Ok(format!("const {base}"))
            }
            gimli::constants::DW_TAG_array_type => {
                let elem = Self::resolve_type_name_rec(type_entry, unit, dwarf, visited)?;
                Ok(format!("{elem}[]"))
            }
            gimli::constants::DW_TAG_typedef => {
                // Use typedef's own name if present; otherwise follow underlying type
                let mut tvisited = HashSet::new();
                if let Some(tname) =
                    Self::resolve_name_with_origins(type_entry, unit, dwarf, &mut tvisited)?
                {
                    Ok(tname)
                } else {
                    Self::resolve_type_name_rec(type_entry, unit, dwarf, visited)
                }
            }
            // Fallback: stringify the DWARF tag
            other => Ok(format!("{other:?}")),
        }
    }

    /// Parse location attribute
    pub fn parse_location(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<EvaluationResult> {
        // Use ExpressionEvaluator for unified logic
        ExpressionEvaluator::evaluate_location(entry, unit, dwarf, address, get_cfa)
    }

    // extract_name removed; call resolve_name_with_origins directly when needed

    /// Get cache statistics from type resolver
    pub fn get_cache_stats(&self) -> usize {
        0
    }

    fn resolve_attr_with_origins(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        attr: gimli::DwAt,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<Option<gimli::AttributeValue<EndianSlice<'static, LittleEndian>>>> {
        if let Some(value) = entry.attr_value(attr)? {
            return Ok(Some(value));
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(gimli::AttributeValue::UnitRef(offset)) = entry.attr_value(origin_attr)? {
                if visited.insert(offset) {
                    let origin_entry = unit.entry(offset)?;
                    if let Some(value) =
                        Self::resolve_attr_with_origins(&origin_entry, unit, attr, visited)?
                    {
                        return Ok(Some(value));
                    }
                }
            }
        }

        Ok(None)
    }

    fn resolve_name_with_origins(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<Option<String>> {
        if let Some(attr) =
            Self::resolve_attr_with_origins(entry, unit, gimli::constants::DW_AT_name, visited)?
        {
            return Self::attr_to_string(attr, unit, dwarf);
        }
        Ok(None)
    }

    fn resolve_type_ref(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<gimli::UnitOffset>> {
        let mut visited = HashSet::new();
        Ok(Self::resolve_attr_with_origins(
            entry,
            unit,
            gimli::constants::DW_AT_type,
            &mut visited,
        )?
        .and_then(|value| match value {
            gimli::AttributeValue::UnitRef(offset) => Some(offset),
            _ => None,
        }))
    }

    fn attr_to_string(
        attr: gimli::AttributeValue<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        if let Ok(attr_string) = dwarf.attr_string(unit, attr) {
            return Ok(Some(attr_string.to_string_lossy().into_owned()));
        }

        if let gimli::AttributeValue::String(s) = attr {
            return Ok(s.to_string().ok().map(|cow| cow.to_owned()));
        }

        Ok(None)
    }

    // resolve_flag_with_origins and entry_pc_matches removed with variable traversal helpers
}

impl Default for DetailedParser {
    fn default() -> Self {
        Self::new()
    }
}

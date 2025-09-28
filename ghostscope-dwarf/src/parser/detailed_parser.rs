//! Detailed DWARF parser for on-demand traversal and variable resolution
//!
//! This module handles detailed parsing of DWARF tree structures, including:
//! - Tree traversal for variable collection
//! - Variable and parameter DIE parsing
//! - Scope-aware variable resolution

use crate::{
    core::{EvaluationResult, Result},
    parser::{ExpressionEvaluator, RangeExtractor, TypeResolver},
    TypeInfo,
};
use gimli::{EndianSlice, LittleEndian};
use std::collections::HashSet;
use tracing::{debug, trace};

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

pub struct VariableCollectionRequest<'abbrev, 'unit, 'vars> {
    pub parent_entry:
        &'unit gimli::DebuggingInformationEntry<'abbrev, 'unit, EndianSlice<'static, LittleEndian>>,
    pub unit: &'unit gimli::Unit<EndianSlice<'static, LittleEndian>>,
    pub dwarf: &'unit gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    pub address: u64,
    pub variables: &'vars mut Vec<VariableWithEvaluation>,
    pub scope_depth: usize,
    pub get_cfa: Option<&'vars dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
}

struct VariableTraversalContext<'unit, 'vars> {
    dwarf: &'unit gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    unit: &'unit gimli::Unit<EndianSlice<'static, LittleEndian>>,
    address: u64,
    get_cfa: Option<&'vars dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
}

/// Detailed DWARF parser for tree traversal and variable collection
#[derive(Debug)]
pub struct DetailedParser {
    type_resolver: TypeResolver,
}

impl DetailedParser {
    /// Create new detailed parser
    pub fn new() -> Self {
        Self {
            type_resolver: TypeResolver::new(),
        }
    }

    /// Expose type resolution at a DIE offset using the internal TypeResolver
    pub fn resolve_type_at_offset(
        &mut self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        type_offset: gimli::UnitOffset,
    ) -> Option<TypeInfo> {
        self.type_resolver
            .resolve_type_at_offset(dwarf, unit, type_offset)
    }

    /// Recursively collect variables visible at the given address within a function
    pub fn collect_variables_in_function(
        &mut self,
        request: VariableCollectionRequest<'_, '_, '_>,
    ) -> Result<()> {
        let VariableCollectionRequest {
            parent_entry,
            unit,
            dwarf,
            address,
            variables,
            scope_depth,
            get_cfa,
        } = request;

        let mut tree = unit.entries_tree(Some(parent_entry.offset()))?;
        let root = tree.root()?;

        let context = VariableTraversalContext {
            dwarf,
            unit,
            address,
            get_cfa,
        };

        self.process_tree_children(&context, root, variables, scope_depth)?;

        Ok(())
    }

    fn process_tree_children(
        &mut self,
        context: &VariableTraversalContext<'_, '_>,
        node: gimli::EntriesTreeNode<EndianSlice<'static, LittleEndian>>,
        variables: &mut Vec<VariableWithEvaluation>,
        scope_depth: usize,
    ) -> Result<()> {
        let mut children = node.children();

        while let Some(child) = children.next()? {
            let entry = child.entry();

            match entry.tag() {
                gimli::constants::DW_TAG_variable | gimli::constants::DW_TAG_formal_parameter => {
                    // Parse the variable
                    if let Some(var) = self.parse_variable_die(entry, context, scope_depth)? {
                        debug!(
                            "Found variable: name='{}', type='{}', is_parameter={}, scope_depth={}",
                            var.name, var.type_name, var.is_parameter, var.scope_depth
                        );
                        variables.push(var);
                    }
                }

                gimli::constants::DW_TAG_lexical_block
                | gimli::constants::DW_TAG_inlined_subroutine => {
                    // Check if this block contains our address
                    let ranges =
                        RangeExtractor::extract_all_ranges(entry, context.unit, context.dwarf)?;
                    let block_contains_address = ranges.is_empty()
                        || ranges.iter().any(|(low, high)| {
                            if low == high {
                                context.address == *low
                            } else {
                                context.address >= *low && context.address < *high
                            }
                        })
                        || Self::entry_pc_matches(
                            entry,
                            context.unit,
                            context.dwarf,
                            context.address,
                        )?;

                    if block_contains_address {
                        trace!(
                            "Processing lexical block that contains address 0x{:x}",
                            context.address
                        );
                        // Recursively process this block's children with increased scope depth
                        self.process_tree_children(context, child, variables, scope_depth + 1)?;
                    } else {
                        debug!(
                            "Skipping lexical block that doesn't contain address 0x{:x}",
                            context.address
                        );
                        // Skip this entire subtree
                    }
                }

                gimli::constants::DW_TAG_subprogram => {
                    // Found a nested function - skip it entirely
                    debug!("Skipping nested function");
                    // The tree iterator automatically skips the subtree when we don't recurse
                }

                _ => {
                    // For other tags, recursively process children
                    self.process_tree_children(context, child, variables, scope_depth)?;
                }
            }
        }

        Ok(())
    }

    /// Parse a variable or parameter DIE
    fn parse_variable_die(
        &mut self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        context: &VariableTraversalContext<'_, '_>,
        scope_depth: usize,
    ) -> Result<Option<VariableWithEvaluation>> {
        let mut visited = HashSet::new();
        let name =
            Self::resolve_name_with_origins(entry, context.unit, context.dwarf, &mut visited)?;

        let name = match name {
            Some(n) => n,
            None => return Ok(None), // Skip unnamed variables
        };

        let is_artificial = Self::resolve_flag_with_origins(
            entry,
            context.unit,
            context.dwarf,
            gimli::constants::DW_AT_artificial,
        )?
        .unwrap_or(false);

        // Check if parameter
        let is_parameter = entry.tag() == gimli::constants::DW_TAG_formal_parameter;

        // Get type information
        let type_name = Self::resolve_type_name(entry, context.unit, context.dwarf)?;

        // Get type reference and resolve full type information
        let dwarf_type =
            Self::resolve_type_ref(entry, context.unit, context.dwarf)?.and_then(|offset| {
                self.type_resolver
                    .resolve_type_at_offset(context.dwarf, context.unit, offset)
            });

        let location_attr = entry.attr_value(gimli::constants::DW_AT_location)?;
        debug!("DW_AT_location raw attr: {:?}", location_attr);
        if let Some(gimli::AttributeValue::LocationListsRef(offset)) = location_attr {
            if let Ok(mut raw_iter) = context.dwarf.raw_locations(context.unit, offset) {
                let mut raw_index = 0;
                while let Ok(Some(raw_entry)) = raw_iter.next() {
                    debug!("  raw_loc[{}]: {:?}", raw_index, raw_entry);
                    raw_index += 1;
                }
            }
        }

        let locviews_attr = entry.attr_value(gimli::constants::DW_AT_GNU_locviews)?;

        if let Some(ref attr) = locviews_attr {
            debug!("DW_AT_GNU_locviews present: {:?}", attr);

            if let gimli::AttributeValue::SecOffset(offset) = *attr {
                let view_offset = offset;
                match context
                    .dwarf
                    .locations(context.unit, gimli::LocationListsOffset(view_offset))
                {
                    Ok(mut views) => {
                        let mut view_index = 0;
                        while let Ok(Some(entry)) = views.next() {
                            debug!(
                                "  locview[{}]: range=0x{:x}-0x{:x} len={} bytes",
                                view_index,
                                entry.range.begin,
                                entry.range.end,
                                entry.range.end.saturating_sub(entry.range.begin)
                            );
                            view_index += 1;
                        }
                    }
                    Err(e) => {
                        debug!(
                            "  Failed to decode locviews at offset 0x{:x}: {:?}",
                            view_offset, e
                        );
                    }
                }
            }
        }

        // Parse location
        let evaluation_result = self.parse_location(
            entry,
            context.unit,
            context.dwarf,
            context.address,
            context.get_cfa,
        )?;

        Ok(Some(VariableWithEvaluation {
            name,
            type_name,
            dwarf_type,
            evaluation_result,
            scope_depth,
            is_parameter,
            is_artificial,
        }))
    }

    /// Resolve type name for a variable
    fn resolve_type_name(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<String> {
        if let Some(offset) = Self::resolve_type_ref(entry, unit, dwarf)? {
            let mut tree = unit.entries_tree(Some(offset))?;
            let type_node = tree.root()?;
            let type_entry = type_node.entry();

            let mut visited = HashSet::new();
            if let Some(name) =
                Self::resolve_name_with_origins(type_entry, unit, dwarf, &mut visited)?
            {
                return Ok(name);
            }

            if type_entry.tag() == gimli::constants::DW_TAG_pointer_type {
                let pointee_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{pointee_type}*"));
            }

            if type_entry.tag() == gimli::constants::DW_TAG_const_type {
                let base_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("const {base_type}"));
            }

            if type_entry.tag() == gimli::constants::DW_TAG_array_type {
                let element_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{element_type}[]"));
            }

            if type_entry.tag() == gimli::constants::DW_TAG_typedef {
                let mut typedef_visited = HashSet::new();
                if let Some(typedef_name) =
                    Self::resolve_name_with_origins(type_entry, unit, dwarf, &mut typedef_visited)?
                {
                    return Ok(typedef_name);
                }
                return Self::resolve_type_name(type_entry, unit, dwarf);
            }

            return Ok(format!("{:?}", type_entry.tag()));
        }

        Ok("unknown".to_string())
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

    /// Extract name from DIE (considering abstract origins/specifications)
    pub fn extract_name(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        Self::resolve_name_with_origins(entry, unit, dwarf, &mut HashSet::new())
    }

    /// Get cache statistics from type resolver
    pub fn get_cache_stats(&self) -> usize {
        self.type_resolver.get_cache_stats()
    }

    #[allow(clippy::only_used_in_recursion)]
    fn resolve_attr_with_origins(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
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
                        Self::resolve_attr_with_origins(&origin_entry, unit, dwarf, attr, visited)?
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
        if let Some(attr) = Self::resolve_attr_with_origins(
            entry,
            unit,
            dwarf,
            gimli::constants::DW_AT_name,
            visited,
        )? {
            return Self::attr_to_string(attr, unit, dwarf);
        }
        Ok(None)
    }

    fn resolve_flag_with_origins(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        attr: gimli::DwAt,
    ) -> Result<Option<bool>> {
        let mut visited = HashSet::new();
        Ok(
            Self::resolve_attr_with_origins(entry, unit, dwarf, attr, &mut visited)?.and_then(
                |value| match value {
                    gimli::AttributeValue::Flag(flag) => Some(flag),
                    _ => None,
                },
            ),
        )
    }

    fn resolve_type_ref(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<gimli::UnitOffset>> {
        let mut visited = HashSet::new();
        Ok(Self::resolve_attr_with_origins(
            entry,
            unit,
            dwarf,
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

    fn entry_pc_matches(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr_value(gimli::constants::DW_AT_entry_pc)? {
            match attr {
                gimli::AttributeValue::Addr(addr) => return Ok(addr == address),
                gimli::AttributeValue::DebugAddrIndex(index) => {
                    let resolved = dwarf.address(unit, index)?;
                    return Ok(resolved == address);
                }
                _ => {}
            }
        }
        Ok(false)
    }
}

impl Default for DetailedParser {
    fn default() -> Self {
        Self::new()
    }
}

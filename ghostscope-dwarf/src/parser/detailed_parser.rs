//! Detailed DWARF parser for on-demand traversal and variable resolution
//!
//! This module handles detailed parsing of DWARF tree structures, including:
//! - Tree traversal for variable collection
//! - Variable and parameter DIE parsing
//! - Scope-aware variable resolution

use crate::{
    core::{DwarfType, EvaluationResult, Result},
    parser::{ExpressionEvaluator, RangeExtractor, TypeResolver},
};
use gimli::{EndianSlice, LittleEndian};
use tracing::{debug, trace};

/// Variable with complete information including EvaluationResult
#[derive(Debug, Clone)]
pub struct VariableWithEvaluation {
    pub name: String,
    pub type_name: String,
    pub dwarf_type: Option<DwarfType>,
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
                        || ranges
                            .iter()
                            .any(|(low, high)| context.address >= *low && context.address < *high);

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
        // Get variable name
        let name = entry
            .attr_value(gimli::constants::DW_AT_name)?
            .and_then(|attr| match attr {
                gimli::AttributeValue::DebugStrRef(offset) => context
                    .dwarf
                    .debug_str
                    .get_str(offset)
                    .ok()?
                    .to_string()
                    .ok(),
                gimli::AttributeValue::String(s) => s.to_string().ok(),
                _ => None,
            });

        let name = match name {
            Some(n) => n.to_string(),
            None => return Ok(None), // Skip unnamed variables
        };

        // Check if artificial (compiler-generated)
        let is_artificial = matches!(
            entry.attr_value(gimli::constants::DW_AT_artificial)?,
            Some(gimli::AttributeValue::Flag(true))
        );

        // Check if parameter
        let is_parameter = entry.tag() == gimli::constants::DW_TAG_formal_parameter;

        // Get type information
        let type_name = Self::resolve_type_name(entry, context.unit, context.dwarf)?;

        // Get type reference and resolve full type information
        let dwarf_type =
            entry
                .attr_value(gimli::constants::DW_AT_type)?
                .and_then(|attr| match attr {
                    gimli::AttributeValue::UnitRef(offset) => self
                        .type_resolver
                        .resolve_type_at_offset(context.dwarf, context.unit, offset),
                    _ => None,
                });

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
        // Try to get type reference
        let type_ref =
            entry
                .attr_value(gimli::constants::DW_AT_type)?
                .and_then(|attr| match attr {
                    gimli::AttributeValue::UnitRef(offset) => Some(offset),
                    _ => None,
                });

        if let Some(offset) = type_ref {
            // Use entries_tree to look up the type DIE
            let mut tree = unit.entries_tree(Some(offset))?;
            let type_node = tree.root()?;
            let type_entry = type_node.entry();

            // Try to get type name
            if let Some(name) = type_entry
                .attr_value(gimli::constants::DW_AT_name)?
                .and_then(|attr| match attr {
                    gimli::AttributeValue::DebugStrRef(str_offset) => {
                        dwarf.debug_str.get_str(str_offset).ok()?.to_string().ok()
                    }
                    gimli::AttributeValue::String(s) => s.to_string().ok(),
                    _ => None,
                })
            {
                return Ok(name.to_string());
            }

            // Handle pointer types
            if type_entry.tag() == gimli::constants::DW_TAG_pointer_type {
                let pointee_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{pointee_type}*"));
            }

            // Handle const types
            if type_entry.tag() == gimli::constants::DW_TAG_const_type {
                let base_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("const {base_type}"));
            }

            // Handle array types
            if type_entry.tag() == gimli::constants::DW_TAG_array_type {
                let element_type = Self::resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{element_type}[]"));
            }

            // Handle typedef
            if type_entry.tag() == gimli::constants::DW_TAG_typedef {
                // First try to get the typedef name
                if let Some(typedef_name) = type_entry
                    .attr_value(gimli::constants::DW_AT_name)?
                    .and_then(|attr| match attr {
                        gimli::AttributeValue::DebugStrRef(str_offset) => {
                            dwarf.debug_str.get_str(str_offset).ok()?.to_string().ok()
                        }
                        gimli::AttributeValue::String(s) => s.to_string().ok(),
                        _ => None,
                    })
                {
                    return Ok(typedef_name.to_string());
                }
                // Otherwise resolve the underlying type
                return Self::resolve_type_name(type_entry, unit, dwarf);
            }

            // Return tag name if no name attribute
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

    /// Extract name from DIE
    pub fn extract_name(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        let name = entry
            .attr_value(gimli::constants::DW_AT_name)?
            .and_then(|attr| match attr {
                gimli::AttributeValue::DebugStrRef(offset) => {
                    dwarf.debug_str.get_str(offset).ok()?.to_string().ok()
                }
                gimli::AttributeValue::String(s) => s.to_string().ok(),
                _ => None,
            })
            .map(|s| s.to_string());

        Ok(name)
    }

    /// Get cache statistics from type resolver
    pub fn get_cache_stats(&self) -> usize {
        self.type_resolver.get_cache_stats()
    }
}

impl Default for DetailedParser {
    fn default() -> Self {
        Self::new()
    }
}

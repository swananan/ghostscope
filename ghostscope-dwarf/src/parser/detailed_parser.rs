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

    /// Create new detailed parser with existing type resolver
    pub fn with_type_resolver(type_resolver: TypeResolver) -> Self {
        Self { type_resolver }
    }

    /// Recursively collect variables visible at the given address within a function
    pub fn collect_variables_in_function(
        &mut self,
        parent_entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
        variables: &mut Vec<VariableWithEvaluation>,
        scope_depth: usize,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<()> {
        // Use entries_tree for proper tree traversal
        let mut tree = unit.entries_tree(Some(parent_entry.offset()))?;
        let root = tree.root()?;

        // Process children of this function
        self.process_tree_children(root, unit, dwarf, address, variables, scope_depth, get_cfa)?;

        Ok(())
    }

    /// Process children nodes in the DWARF tree
    pub fn process_tree_children(
        &mut self,
        node: gimli::EntriesTreeNode<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
        variables: &mut Vec<VariableWithEvaluation>,
        scope_depth: usize,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<()> {
        let mut children = node.children();

        while let Some(child) = children.next()? {
            let entry = child.entry();

            match entry.tag() {
                gimli::constants::DW_TAG_variable | gimli::constants::DW_TAG_formal_parameter => {
                    // Parse the variable
                    if let Some(var) =
                        self.parse_variable_die(entry, unit, dwarf, scope_depth, address, get_cfa)?
                    {
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
                    let ranges = RangeExtractor::extract_all_ranges(entry, unit, dwarf)?;
                    let block_contains_address = ranges.is_empty() || // No range means always visible
                        ranges.iter().any(|(low, high)| address >= *low && address < *high);

                    if block_contains_address {
                        trace!(
                            "Processing lexical block that contains address 0x{:x}",
                            address
                        );
                        // Recursively process this block's children with increased scope depth
                        self.process_tree_children(
                            child,
                            unit,
                            dwarf,
                            address,
                            variables,
                            scope_depth + 1,
                            get_cfa,
                        )?;
                    } else {
                        debug!(
                            "Skipping lexical block that doesn't contain address 0x{:x}",
                            address
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
                    self.process_tree_children(
                        child,
                        unit,
                        dwarf,
                        address,
                        variables,
                        scope_depth,
                        get_cfa,
                    )?;
                }
            }
        }

        Ok(())
    }

    /// Parse a variable or parameter DIE
    pub fn parse_variable_die(
        &mut self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        scope_depth: usize,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Option<VariableWithEvaluation>> {
        // Get variable name
        let name = entry
            .attr_value(gimli::constants::DW_AT_name)?
            .and_then(|attr| match attr {
                gimli::AttributeValue::DebugStrRef(offset) => {
                    dwarf.debug_str.get_str(offset).ok()?.to_string().ok()
                }
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
        let type_name = self.resolve_type_name(entry, unit, dwarf)?;

        // Get type reference and resolve full type information
        let dwarf_type =
            entry
                .attr_value(gimli::constants::DW_AT_type)?
                .and_then(|attr| match attr {
                    gimli::AttributeValue::UnitRef(offset) => self
                        .type_resolver
                        .resolve_type_at_offset(dwarf, unit, offset),
                    _ => None,
                });

        // Parse location
        let evaluation_result = self.parse_location(entry, unit, dwarf, address, get_cfa)?;

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
    pub fn resolve_type_name(
        &self,
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
                let pointee_type = self.resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{}*", pointee_type));
            }

            // Handle const types
            if type_entry.tag() == gimli::constants::DW_TAG_const_type {
                let base_type = self.resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("const {}", base_type));
            }

            // Handle array types
            if type_entry.tag() == gimli::constants::DW_TAG_array_type {
                let element_type = self.resolve_type_name(type_entry, unit, dwarf)?;
                return Ok(format!("{}[]", element_type));
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
                return self.resolve_type_name(type_entry, unit, dwarf);
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

    /// Get type resolver reference
    pub fn type_resolver(&self) -> &TypeResolver {
        &self.type_resolver
    }

    /// Get mutable type resolver reference
    pub fn type_resolver_mut(&mut self) -> &mut TypeResolver {
        &mut self.type_resolver
    }

    /// Get cache statistics from type resolver
    pub fn get_cache_stats(&self) -> usize {
        self.type_resolver.get_cache_stats()
    }

    /// Clear type resolver cache
    pub fn clear_cache(&mut self) {
        self.type_resolver.clear_cache();
    }
}

impl Default for DetailedParser {
    fn default() -> Self {
        Self::new()
    }
}

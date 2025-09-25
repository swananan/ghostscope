//! Real on-demand DWARF resolver implementation
//! This version actually parses DWARF DIEs instead of returning hardcoded data

use crate::{
    core::Result,
    parser::{
        detailed_parser::VariableCollectionRequest, DetailedParser, RangeExtractor,
        VariableWithEvaluation,
    },
};
use gimli::{EndianSlice, LittleEndian};
use tracing::{debug, info};

/// Real on-demand DWARF resolver
#[derive(Debug)]
pub struct OnDemandResolver {
    dwarf: gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
    detailed_parser: DetailedParser,
}

impl OnDemandResolver {
    /// Create new on-demand resolver
    pub fn new(dwarf: gimli::Dwarf<EndianSlice<'static, LittleEndian>>) -> Self {
        let detailed_parser = DetailedParser::new();
        Self {
            dwarf,
            detailed_parser,
        }
    }

    /// Get all variables visible at the given address
    pub fn get_all_variables_at_address(
        &mut self,
        address: u64,
        unit_offset: gimli::DebugInfoOffset,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Vec<VariableWithEvaluation>> {
        info!(
            "OnDemandResolver::get_all_variables_at_address: address=0x{:x}, unit_offset={:?}",
            address, unit_offset
        );

        // Find the compilation unit
        let header = self.dwarf.debug_info.header_from_offset(unit_offset)?;
        let unit = self.dwarf.unit(header)?;

        debug!(
            "Found compilation unit at offset {:?}, address size: {}",
            unit_offset,
            unit.header.address_size()
        );

        let mut variables = Vec::new();
        let mut entries = unit.entries();

        // Find the function containing the address and collect its variables
        while let Some((_, entry)) = entries.next_dfs()? {
            if entry.tag() == gimli::constants::DW_TAG_subprogram {
                // Check if this function contains our address
                let ranges = RangeExtractor::extract_all_ranges(entry, &unit, &self.dwarf)?;
                let contains_address = ranges
                    .iter()
                    .any(|(low, high)| address >= *low && address < *high);

                if contains_address {
                    // Found the containing function
                    let func_name = self
                        .detailed_parser
                        .extract_name(entry, &self.dwarf)?
                        .unwrap_or_else(|| "unknown".to_string());
                    debug!(
                        "Found containing function '{}' for address 0x{:x}",
                        func_name, address
                    );

                    // Now traverse only this function's children
                    self.detailed_parser.collect_variables_in_function(
                        VariableCollectionRequest {
                            parent_entry: entry,
                            unit: &unit,
                            dwarf: &self.dwarf,
                            address,
                            variables: &mut variables,
                            scope_depth: 0, // Start at scope depth 0 for the function
                            get_cfa,
                        },
                    )?;

                    // We found our function, no need to continue
                    break;
                }
            }
        }

        info!(
            "OnDemandResolver: Found {} variables at address 0x{:x}",
            variables.len(),
            address
        );

        // Log the variables we found
        for var in &variables {
            info!(
                "  Variable: name='{}', type='{}', scope_depth={}, location={}",
                var.name, var.type_name, var.scope_depth, var.evaluation_result
            );
        }

        Ok(variables)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        (0, self.detailed_parser.get_cache_stats())
    }
}

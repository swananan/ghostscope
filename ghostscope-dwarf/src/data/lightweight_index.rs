//! Cooked index - lightweight DWARF indexing inspired by GDB
//!
//! This follows GDB's cooked index design:
//! - Extremely lightweight entries (no address ranges stored)
//! - DIE offsets for on-demand parsing
//! - Support for parallel construction with index shards
//! - Fast binary search for symbol lookup

use crate::core::IndexEntry;
use std::collections::{BTreeMap, HashMap};
use tracing::debug;

/// Cooked index - inspired by GDB's cooked_index design
/// Contains lightweight entries for fast symbol lookup
#[derive(Debug)]
pub struct LightweightIndex {
    /// All index entries sorted by name for fast binary search
    /// GDB insight: Single flat vector instead of multiple hash maps
    entries: Vec<IndexEntry>,
    /// Function name -> entry indices (for O(1) function lookup)
    function_map: HashMap<String, Vec<usize>>,
    /// Variable name -> entry indices (for O(1) variable lookup)
    variable_map: HashMap<String, Vec<usize>>,
    /// Address map: start_address -> entry index
    /// Uses BTreeMap for efficient range queries (similar to GDB's addrmap)
    /// Only includes entries with address ranges
    address_map: BTreeMap<u64, usize>,
    /// Total statistics
    total_functions: usize,
    total_variables: usize,
}

impl LightweightIndex {
    /// Create empty cooked index
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            function_map: HashMap::new(),
            variable_map: HashMap::new(),
            address_map: BTreeMap::new(),
            total_functions: 0,
            total_variables: 0,
        }
    }

    /// Build cooked index from parsed data (called from DwarfParser)
    /// Follows GDB's cooked index pattern
    pub fn from_builder_data(
        functions: HashMap<String, Vec<IndexEntry>>,
        variables: HashMap<String, Vec<IndexEntry>>,
    ) -> Self {
        debug!("Building lightweight index from parsed data");

        let mut entries = Vec::new();
        let mut function_map = HashMap::new();
        let mut variable_map = HashMap::new();

        // Add all function entries to flat vector
        let mut total_functions = 0;
        for (name, func_entries) in functions {
            let start_idx = entries.len();
            entries.extend(func_entries);
            let indices: Vec<usize> = (start_idx..entries.len()).collect();
            function_map.insert(name, indices);
            total_functions += entries.len() - start_idx;
        }

        // Add all variable entries to flat vector
        let mut total_variables = 0;
        for (name, var_entries) in variables {
            let start_idx = entries.len();
            entries.extend(var_entries);
            let indices: Vec<usize> = (start_idx..entries.len()).collect();
            variable_map.insert(name, indices);
            total_variables += entries.len() - start_idx;
        }

        // IMPORTANT: Do NOT sort entries! This would invalidate the indices
        // stored in function_map and variable_map
        // GDB uses sorted entries for binary search, but we use HashMap for O(1) lookup

        // Build address map for entries with addresses
        // Now supports multiple ranges per entry
        let mut address_map = BTreeMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            // Add all ranges for this entry to the map
            for (start_addr, _end_addr) in &entry.address_ranges {
                address_map.insert(*start_addr, idx);
            }
        }

        debug!(
            "Built lightweight index: {} functions, {} variables, {} total entries, {} with addresses",
            total_functions, total_variables, entries.len(), address_map.len()
        );

        Self {
            entries,
            function_map,
            variable_map,
            address_map,
            total_functions,
            total_variables,
        }
    }

    /// Get all function names for debugging
    pub fn get_function_names(&self) -> Vec<&String> {
        self.function_map.keys().collect()
    }

    /// Get all variable names for debugging
    pub fn get_variable_names(&self) -> Vec<&String> {
        self.variable_map.keys().collect()
    }

    /// Get total statistics
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.total_functions,
            self.total_variables,
            self.entries.len(),
        )
    }

    /// Find DIE entry by address - returns the DIE containing this address
    /// This is the primary interface for address-based lookups
    pub fn find_die_at_address(&self, address: u64) -> Option<&IndexEntry> {
        tracing::info!("find_die_at_address: looking for address 0x{:x}", address);
        tracing::info!("  Address map has {} entries", self.address_map.len());

        // Find the entry with the largest start address that is <= the query address
        let mut best_match = None;

        for (_addr, &idx) in self.address_map.range(..=address).rev() {
            let entry = &self.entries[idx];

            // Check all ranges for this entry
            for (start, end) in &entry.address_ranges {
                if address >= *start && address < *end {
                    tracing::info!(
                        "  ✓ Found DIE '{}' (tag={:?}) at range 0x{:x}-0x{:x}",
                        entry.name,
                        entry.tag,
                        start,
                        end
                    );
                    best_match = Some(entry);
                    break;
                }
            }

            if best_match.is_some() {
                break;
            }
        }

        if best_match.is_none() {
            tracing::warn!("  No DIE found containing address 0x{:x}", address);
        }

        best_match
    }

    /// Find DIE entries by function name - returns all matching DIEs
    /// Supports multiple implementations (including inline functions)
    pub fn find_dies_by_function_name(&self, name: &str) -> Vec<&IndexEntry> {
        tracing::info!("find_dies_by_function_name: looking for '{}'", name);

        if let Some(indices) = self.function_map.get(name) {
            let entries: Vec<&IndexEntry> = indices.iter().map(|&idx| &self.entries[idx]).collect();

            tracing::info!("  Found {} entries for function '{}'", entries.len(), name);
            for entry in &entries {
                if !entry.address_ranges.is_empty() {
                    let (start, _) = entry.address_ranges[0];
                    tracing::info!(
                        "    - {} at 0x{:x} (inline={}, {} ranges)",
                        entry.name,
                        start,
                        entry.flags.is_inline,
                        entry.address_ranges.len()
                    );
                }
            }

            entries
        } else {
            tracing::info!("  No entries found for function '{}'", name);
            vec![]
        }
    }
}

impl Default for LightweightIndex {
    fn default() -> Self {
        Self::new()
    }
}

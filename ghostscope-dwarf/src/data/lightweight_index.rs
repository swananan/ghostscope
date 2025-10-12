//! Cooked index - lightweight DWARF indexing inspired by GDB
//!
//! This follows GDB's cooked index design:
//! - Extremely lightweight entries (no address ranges stored)
//! - DIE offsets for on-demand parsing
//! - Support for parallel construction with index shards
//! - Fast binary search for symbol lookup

use crate::core::IndexEntry;
use gimli::{DebugInfoOffset, EndianArcSlice, LittleEndian};
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
    /// Type name -> entry indices (struct/class/union/enum) for fast type lookup by name
    type_map: HashMap<String, Vec<usize>>,
    /// Address map: start_address -> entry index
    /// Uses BTreeMap for efficient range queries (similar to GDB's addrmap)
    /// Only includes entries with address ranges
    address_map: BTreeMap<u64, usize>,
    /// Total statistics
    total_functions: usize,
    total_variables: usize,

    /// Optional fast PC→CU map built from entry ranges (start -> (end, cu))
    cu_range_map: BTreeMap<u64, (u64, DebugInfoOffset)>,
    /// Optional per-CU function address map (start -> entry idx)
    func_addr_by_cu: HashMap<DebugInfoOffset, BTreeMap<u64, usize>>,
}

impl LightweightIndex {
    /// Create empty cooked index
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            function_map: HashMap::new(),
            variable_map: HashMap::new(),
            type_map: HashMap::new(),
            address_map: BTreeMap::new(),
            total_functions: 0,
            total_variables: 0,
            cu_range_map: BTreeMap::new(),
            func_addr_by_cu: HashMap::new(),
        }
    }

    /// Build cooked index from parsed data (called from DwarfParser)
    /// Follows GDB's cooked index pattern
    pub fn from_builder_data(
        functions: HashMap<String, Vec<IndexEntry>>,
        variables: HashMap<String, Vec<IndexEntry>>,
        types: HashMap<String, Vec<IndexEntry>>,
    ) -> Self {
        debug!("Building lightweight index from parsed data");

        let mut entries = Vec::new();
        let mut function_map = HashMap::new();
        let mut variable_map = HashMap::new();
        let mut type_map = HashMap::new();

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

        // Add all type entries (struct/class/union/enum)
        for (name, ty_entries) in types {
            let start_idx = entries.len();
            entries.extend(ty_entries);
            let indices: Vec<usize> = (start_idx..entries.len()).collect();
            type_map.insert(name, indices);
        }

        // IMPORTANT: Do NOT sort entries! This would invalidate the indices
        // stored in function_map and variable_map
        // GDB uses sorted entries for binary search, but we use HashMap for O(1) lookup

        // Build address map for entries with addresses
        // Include functions and variables so address-based lookups work for .text and .data/.bss
        let mut address_map = BTreeMap::new();
        for (idx, entry) in entries.iter().enumerate() {
            // Add all ranges for this entry to the map. For variables we expect (addr, addr).
            for (start_addr, _end_addr) in &entry.address_ranges {
                address_map.insert(*start_addr, idx);
            }
            if let Some(entry_pc) = entry.entry_pc {
                address_map.insert(entry_pc, idx);
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
            type_map,
            address_map,
            total_functions,
            total_variables,
            cu_range_map: BTreeMap::new(),
            func_addr_by_cu: HashMap::new(),
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

    /// Internal: iterate type_map entries (name -> indices)
    pub(crate) fn type_map_iter(&self) -> impl Iterator<Item = (&String, &Vec<usize>)> {
        self.type_map.iter()
    }

    /// Internal: get a raw entry by index
    pub(crate) fn entry(&self, idx: usize) -> Option<&IndexEntry> {
        self.entries.get(idx)
    }

    /// Get total statistics
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.total_functions,
            self.total_variables,
            self.entries.len(),
        )
    }

    /// Attach CU range map and per-CU function address map built from entries
    pub fn build_cu_maps(&mut self) {
        let mut cu_map: BTreeMap<u64, (u64, DebugInfoOffset)> = BTreeMap::new();
        let mut per_cu: HashMap<DebugInfoOffset, BTreeMap<u64, usize>> = HashMap::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            let is_func = entry.tag == gimli::constants::DW_TAG_subprogram
                || entry.tag == gimli::constants::DW_TAG_inlined_subroutine;
            if !is_func {
                continue;
            }

            let cu = entry.unit_offset;
            let m = per_cu.entry(cu).or_insert_with(BTreeMap::new);

            for (start, end) in &entry.address_ranges {
                m.insert(*start, idx);
                cu_map.entry(*start).or_insert((*end, cu));
            }
            if let Some(ep) = entry.entry_pc {
                m.insert(ep, idx);
            }
        }

        self.cu_range_map = cu_map;
        self.func_addr_by_cu = per_cu;
    }

    /// Build CU range map from .debug_aranges, if present. Returns true if any ranges were added.
    pub fn build_cu_maps_from_aranges(
        &mut self,
        _dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    ) -> bool {
        // Build CU range map using .debug_aranges if available.
        // This accelerates PC→CU lookups and mirrors how debuggers seed CU maps.
        let mut new_map: BTreeMap<u64, (u64, DebugInfoOffset)> = BTreeMap::new();

        // Iterate arange headers; each corresponds to a single CU.
        let mut headers = _dwarf.debug_aranges.headers();
        loop {
            match headers.next() {
                Ok(Some(header)) => {
                    let cu_off = header.debug_info_offset();
                    let mut entries = header.entries();
                    loop {
                        match entries.next() {
                            Ok(Some(arange)) => {
                                let start = arange.address();
                                let end = arange.range().end;
                                // Keep the widest end for a given start if duplicates appear.
                                match new_map.get_mut(&start) {
                                    Some((existing_end, _)) => {
                                        if end > *existing_end {
                                            *existing_end = end;
                                        }
                                    }
                                    None => {
                                        new_map.insert(start, (end, cu_off));
                                    }
                                }
                            }
                            Ok(None) => break,
                            Err(e) => {
                                // Malformed aranges within this CU; log and abandon this header.
                                tracing::warn!(".debug_aranges entries parse error: {}", e);
                                break;
                            }
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    // Malformed .debug_aranges section; prefer to keep prior entry-based map.
                    tracing::warn!(".debug_aranges headers parse error: {}", e);
                    break;
                }
            }
        }

        if !new_map.is_empty() {
            self.cu_range_map = new_map;
            return true;
        }
        false
    }

    /// Find compilation unit by address using CU range map
    pub fn find_cu_by_address(&self, address: u64) -> Option<DebugInfoOffset> {
        if let Some((_, (end, cu))) = self.cu_range_map.range(..=address).next_back() {
            if address <= *end {
                return Some(*cu);
            }
        }
        None
    }

    /// Find the subprogram DIE that contains the given address (unified: CU-fast path + fallback)
    pub fn find_function_by_address(&self, address: u64) -> Option<&IndexEntry> {
        if let Some(cu) = self.find_cu_by_address(address) {
            if let Some(map) = self.func_addr_by_cu.get(&cu) {
                for (_s, &idx) in map.range(..=address).rev() {
                    let entry = &self.entries[idx];
                    if entry.tag != gimli::constants::DW_TAG_subprogram {
                        continue;
                    }
                    if let Some(entry_pc) = entry.entry_pc {
                        if address == entry_pc {
                            return Some(entry);
                        }
                    }
                    for (start, end) in &entry.address_ranges {
                        let contains = if start == end {
                            address == *start
                        } else {
                            address >= *start && address < *end
                        };
                        if contains {
                            return Some(entry);
                        }
                    }
                }
            }
        }
        // Fallback: scan global function address map
        for (_addr, &idx) in self.address_map.range(..=address).rev() {
            let entry = &self.entries[idx];
            if entry.tag != gimli::constants::DW_TAG_subprogram {
                continue;
            }
            if let Some(entry_pc) = entry.entry_pc {
                if address == entry_pc {
                    return Some(entry);
                }
            }
            for (start, end) in &entry.address_ranges {
                let contains = if start == end {
                    address == *start
                } else {
                    address >= *start && address < *end
                };
                if contains {
                    return Some(entry);
                }
            }
        }
        None
    }

    /// Find DIE entry by address - returns the DIE containing this address
    /// This is the primary interface for address-based lookups
    pub fn find_die_at_address(&self, address: u64) -> Option<&IndexEntry> {
        tracing::debug!("find_die_at_address: looking for address 0x{:x}", address);
        tracing::trace!("  Address map has {} entries", self.address_map.len());

        // Find the entry with the largest start address that is <= the query address
        let mut best_match = None;

        for (_addr, &idx) in self.address_map.range(..=address).rev() {
            let entry = &self.entries[idx];

            if let Some(entry_pc) = entry.entry_pc {
                if address == entry_pc {
                    tracing::debug!(
                        "  ✓ Found DIE '{}' (tag={:?}) at entry_pc 0x{:x}",
                        entry.name,
                        entry.tag,
                        entry_pc
                    );
                    best_match = Some(entry);
                    break;
                }
            }

            // Check all ranges for this entry
            for (start, end) in &entry.address_ranges {
                let contains = if start == end {
                    address == *start
                } else {
                    address >= *start && address < *end
                };

                if contains {
                    tracing::debug!(
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
            tracing::debug!("No DIE found containing address 0x{:x}", address);
        }

        best_match
    }

    // (old global fallback variant removed in favor of unified method above)

    /// Find DIE entries by function name - returns all matching DIEs
    /// Supports multiple implementations (including inline functions)
    pub fn find_dies_by_function_name(&self, name: &str) -> Vec<&IndexEntry> {
        tracing::debug!("find_dies_by_function_name: '{}'", name);

        if let Some(indices) = self.function_map.get(name) {
            let entries: Vec<&IndexEntry> = indices.iter().map(|&idx| &self.entries[idx]).collect();

            tracing::trace!("Found {} entries for function '{}'", entries.len(), name);
            for entry in &entries {
                let display_addr = if entry.flags.is_inline {
                    entry
                        .entry_pc
                        .or_else(|| entry.address_ranges.first().map(|(start, _)| *start))
                } else {
                    entry.address_ranges.first().map(|(start, _)| *start)
                };

                if let Some(addr) = display_addr {
                    tracing::trace!(
                        "    - {} at 0x{:x} (inline={}, {} ranges)",
                        entry.name,
                        addr,
                        entry.flags.is_inline,
                        entry.address_ranges.len()
                    );
                }
            }

            entries
        } else {
            tracing::debug!("No entries found for function '{}'", name);
            vec![]
        }
    }

    /// Find DIE entries by variable name - returns all matching DIEs
    /// Only variables recorded during debug_info parsing are returned.
    pub fn find_variables_by_name(&self, name: &str) -> Vec<&IndexEntry> {
        tracing::debug!("find_variables_by_name: '{}'", name);

        if let Some(indices) = self.variable_map.get(name) {
            indices.iter().map(|&idx| &self.entries[idx]).collect()
        } else {
            tracing::debug!("No entries found for variable '{}'", name);
            vec![]
        }
    }

    // find_types_by_name removed; type resolution should go through TypeNameIndex instead.
}

impl Default for LightweightIndex {
    fn default() -> Self {
        Self::new()
    }
}

//! Cooked index - lightweight DWARF indexing inspired by GDB
//!
//! This follows GDB's cooked index design:
//! - Extremely lightweight entries (no address ranges stored)
//! - DIE offsets for on-demand parsing
//! - Support for parallel construction with index shards
//! - Fast binary search for symbol lookup

use crate::{
    binary::DwarfReader,
    core::{demangle_by_lang, demangled_leaf, IndexEntry},
    semantics::range_contains_pc,
};
use gimli::DebugInfoOffset;
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::debug;

/// Per-CU shard produced during parallel DWARF parsing.
#[derive(Debug, Default)]
pub(crate) struct LightweightIndexShard {
    pub(crate) entries: Vec<IndexEntry>,
    pub(crate) function_map: HashMap<String, Vec<usize>>,
    pub(crate) variable_map: HashMap<String, Vec<usize>>,
    pub(crate) type_map: HashMap<String, Vec<usize>>,
}

impl LightweightIndexShard {
    pub(crate) fn push_function_entry(&mut self, key: String, entry: IndexEntry) {
        let idx = self.entries.len();
        self.entries.push(entry);
        self.function_map.entry(key).or_default().push(idx);
    }

    pub(crate) fn push_variable_entry(&mut self, key: String, entry: IndexEntry) {
        let idx = self.entries.len();
        let leaf_alias = if entry.tag == gimli::constants::DW_TAG_variable
            && (entry.flags.is_linkage
                || crate::core::is_likely_mangled(entry.language, entry.name.as_ref()))
        {
            demangle_by_lang(entry.language, entry.name.as_ref())
                .map(|demangled| demangled_leaf(&demangled))
                .filter(|leaf| leaf != entry.name.as_ref())
        } else {
            None
        };

        self.entries.push(entry);
        self.variable_map.entry(key).or_default().push(idx);
        if let Some(alias) = leaf_alias {
            self.variable_map.entry(alias).or_default().push(idx);
        }
    }

    pub(crate) fn push_type_entry(&mut self, key: String, entry: IndexEntry) {
        let idx = self.entries.len();
        self.entries.push(entry);
        self.type_map.entry(key).or_default().push(idx);
    }

    #[allow(dead_code)]
    fn from_builder_data(
        functions: HashMap<String, Vec<IndexEntry>>,
        variables: HashMap<String, Vec<IndexEntry>>,
        types: HashMap<String, Vec<IndexEntry>>,
    ) -> Self {
        let mut shard = Self::default();

        for (name, func_entries) in functions {
            for entry in func_entries {
                shard.push_function_entry(name.clone(), entry);
            }
        }

        for (name, var_entries) in variables {
            for entry in var_entries {
                shard.push_variable_entry(name.clone(), entry);
            }
        }

        for (name, ty_entries) in types {
            for entry in ty_entries {
                shard.push_type_entry(name.clone(), entry);
            }
        }

        shard
    }
}

#[derive(Debug, Default)]
struct NameIndexShard {
    entry_base: usize,
    function_map: HashMap<String, Vec<usize>>,
    variable_map: HashMap<String, Vec<usize>>,
    type_map: HashMap<String, Vec<usize>>,
}

/// Cooked index - inspired by GDB's cooked_index design
/// Contains lightweight entries for fast symbol lookup
#[derive(Debug)]
pub struct LightweightIndex {
    /// All index entries kept in a flat vector for stable `entry(usize)` access.
    entries: Vec<IndexEntry>,
    /// Per-CU name maps kept as shards to avoid post-parse global merges.
    name_shards: Vec<NameIndexShard>,
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
            name_shards: Vec::new(),
            address_map: BTreeMap::new(),
            total_functions: 0,
            total_variables: 0,
            cu_range_map: BTreeMap::new(),
            func_addr_by_cu: HashMap::new(),
        }
    }

    /// Build cooked index from parsed data (called from DwarfParser)
    /// Follows GDB's cooked index pattern
    #[allow(dead_code)]
    pub fn from_builder_data(
        functions: HashMap<String, Vec<IndexEntry>>,
        variables: HashMap<String, Vec<IndexEntry>>,
        types: HashMap<String, Vec<IndexEntry>>,
    ) -> Self {
        Self::from_shards(vec![LightweightIndexShard::from_builder_data(
            functions, variables, types,
        )])
    }

    /// Build cooked index directly from per-CU shards.
    pub(crate) fn from_shards(shards: Vec<LightweightIndexShard>) -> Self {
        debug!("Building lightweight index from parsed data");

        let total_entry_capacity: usize = shards.iter().map(|shard| shard.entries.len()).sum();
        let mut entries = Vec::with_capacity(total_entry_capacity);
        let mut name_shards = Vec::with_capacity(shards.len());

        for shard in shards {
            let entry_base = entries.len();
            entries.extend(shard.entries);
            name_shards.push(NameIndexShard {
                entry_base,
                function_map: shard.function_map,
                variable_map: shard.variable_map,
                type_map: shard.type_map,
            });
        }

        let mut address_map = BTreeMap::new();
        let mut total_functions = 0;
        let mut total_variables = 0;
        for (idx, entry) in entries.iter().enumerate() {
            match entry.tag {
                gimli::constants::DW_TAG_subprogram
                | gimli::constants::DW_TAG_inlined_subroutine => {
                    total_functions += 1;
                }
                gimli::constants::DW_TAG_variable => {
                    total_variables += 1;
                }
                _ => {}
            }

            // Add all ranges for this entry to the map. For variables we expect (addr, addr).
            for (start_addr, _end_addr) in &entry.address_ranges {
                address_map.insert(*start_addr, idx);
            }
            if let Some(entry_pc) = entry.entry_pc {
                address_map.insert(entry_pc, idx);
            }
        }

        debug!(
            "Built lightweight index: {} function entries, {} variable entries, {} total entries, {} shards, {} with addresses",
            total_functions,
            total_variables,
            entries.len(),
            name_shards.len(),
            address_map.len()
        );

        Self {
            entries,
            name_shards,
            address_map,
            total_functions,
            total_variables,
            cu_range_map: BTreeMap::new(),
            func_addr_by_cu: HashMap::new(),
        }
    }

    fn unique_names<'a>(
        &'a self,
        map_of: impl Fn(&'a NameIndexShard) -> &'a HashMap<String, Vec<usize>>,
    ) -> Vec<&'a String> {
        let mut names = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for shard in &self.name_shards {
            for name in map_of(shard).keys() {
                if seen.insert(name.as_str()) {
                    names.push(name);
                }
            }
        }
        names
    }

    fn entries_for_name<'a>(
        &'a self,
        name: &str,
        map_of: impl Fn(&'a NameIndexShard) -> &'a HashMap<String, Vec<usize>>,
    ) -> Vec<&'a IndexEntry> {
        let mut matches = Vec::new();
        for shard in &self.name_shards {
            if let Some(indices) = map_of(shard).get(name) {
                matches.extend(
                    indices
                        .iter()
                        .filter_map(|&local_idx| self.entries.get(shard.entry_base + local_idx)),
                );
            }
        }
        matches
    }

    /// Get all function names for debugging
    pub fn get_function_names(&self) -> Vec<&String> {
        self.unique_names(|shard| &shard.function_map)
    }

    /// Get all variable names for debugging
    pub fn get_variable_names(&self) -> Vec<&String> {
        self.unique_names(|shard| &shard.variable_map)
    }

    /// Internal: visit type-map entries across all shards.
    pub(crate) fn for_each_type_map_entry(&self, mut visit: impl FnMut(&String, usize, &[usize])) {
        for shard in &self.name_shards {
            for (name, indices) in &shard.type_map {
                visit(name, shard.entry_base, indices);
            }
        }
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
    pub fn build_cu_maps_from_aranges(&mut self, _dwarf: &gimli::Dwarf<DwarfReader>) -> bool {
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
                        let contains = range_contains_pc(*start, *end, address);
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
                let contains = range_contains_pc(*start, *end, address);
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
                let contains = range_contains_pc(*start, *end, address);

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

        let entries = self.entries_for_name(name, |shard| &shard.function_map);
        if !entries.is_empty() {
            tracing::trace!("Found {} entries for function '{}'", entries.len(), name);

            for entry in &entries {
                let display_addr = if entry.is_inline_instance() {
                    entry
                        .validated_entry_pc()
                        .or_else(|| entry.address_ranges.first().map(|(start, _)| *start))
                } else {
                    entry.address_ranges.first().map(|(start, _)| *start)
                };

                if let Some(addr) = display_addr {
                    tracing::trace!(
                        "    - {} at 0x{:x} (role={:?}, inline={}, {} ranges)",
                        entry.name,
                        addr,
                        entry.function_kind(),
                        entry.is_inline_instance(),
                        entry.address_ranges.len()
                    );
                }
            }
        } else {
            tracing::debug!("No entries found for function '{}'", name);
        }

        entries
    }

    /// Find DIE entries by variable name - returns all matching DIEs
    /// Only variables recorded during debug_info parsing are returned.
    pub fn find_variables_by_name(&self, name: &str) -> Vec<&IndexEntry> {
        tracing::debug!("find_variables_by_name: '{}'", name);

        let entries = self.entries_for_name(name, |shard| &shard.variable_map);
        if entries.is_empty() {
            tracing::debug!("No entries found for variable '{}'", name);
        }
        entries
    }
    // find_types_by_name removed; type resolution should go through TypeNameIndex instead.
}

impl Default for LightweightIndex {
    fn default() -> Self {
        Self::new()
    }
}

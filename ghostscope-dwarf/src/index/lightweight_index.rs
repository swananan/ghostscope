//! Cooked index - lightweight DWARF indexing inspired by GDB
//!
//! This follows GDB's cooked index design:
//! - Extremely lightweight entries (no address ranges stored)
//! - DIE offsets for on-demand parsing
//! - Support for parallel construction with index shards
//! - Fast binary search for symbol lookup

use crate::{
    binary::DwarfReader,
    core::{extract_name_fragments, IndexEntry},
    parser::RangeExtractor,
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
    pub(crate) function_fragment_map: HashMap<String, Vec<usize>>,
    pub(crate) variable_map: HashMap<String, Vec<usize>>,
    pub(crate) variable_fragment_map: HashMap<String, Vec<usize>>,
    pub(crate) type_map: HashMap<String, Vec<usize>>,
}

impl LightweightIndexShard {
    pub(crate) fn push_function_entry(&mut self, key: String, entry: IndexEntry) {
        let idx = self.entries.len();
        self.entries.push(entry);
        self.function_map.entry(key).or_default().push(idx);
        Self::push_name_fragments(
            &mut self.function_fragment_map,
            self.entries[idx].name.as_ref(),
            idx,
        );
    }

    pub(crate) fn push_variable_entry(&mut self, key: String, entry: IndexEntry) {
        let idx = self.entries.len();
        self.entries.push(entry);
        self.variable_map.entry(key).or_default().push(idx);
        Self::push_name_fragments(
            &mut self.variable_fragment_map,
            self.entries[idx].name.as_ref(),
            idx,
        );
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

    fn push_name_fragments(fragment_map: &mut HashMap<String, Vec<usize>>, key: &str, idx: usize) {
        for fragment in extract_name_fragments(key) {
            fragment_map.entry(fragment).or_default().push(idx);
        }
    }
}

#[derive(Debug, Default)]
struct NameIndexShard {
    entry_base: usize,
    function_map: HashMap<String, Vec<usize>>,
    function_fragment_map: HashMap<String, Vec<usize>>,
    variable_map: HashMap<String, Vec<usize>>,
    variable_fragment_map: HashMap<String, Vec<usize>>,
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
    /// Address map: representative_address -> entry index
    /// Uses BTreeMap for efficient range queries (similar to GDB's addrmap)
    /// Only includes entries with an address seed
    address_map: BTreeMap<u64, usize>,
    /// Total statistics
    total_functions: usize,
    total_variables: usize,

    /// Optional fast PC→CU map built from aranges or representative-address fallback.
    cu_range_map: BTreeMap<u64, (u64, DebugInfoOffset)>,
    /// Optional per-CU function representative-address map (start -> entry idx)
    func_addr_by_cu: HashMap<DebugInfoOffset, BTreeMap<u64, usize>>,
    /// All function-like entries in each CU for correctness fallback scans.
    func_indices_by_cu: HashMap<DebugInfoOffset, Vec<usize>>,
    /// All function-like entry indices for global fallback scans.
    function_indices: Vec<usize>,
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
            func_indices_by_cu: HashMap::new(),
            function_indices: Vec::new(),
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
                function_fragment_map: shard.function_fragment_map,
                variable_map: shard.variable_map,
                variable_fragment_map: shard.variable_fragment_map,
                type_map: shard.type_map,
            });
        }

        let mut address_map = BTreeMap::new();
        let mut total_functions = 0;
        let mut total_variables = 0;
        let mut func_indices_by_cu: HashMap<DebugInfoOffset, Vec<usize>> = HashMap::new();
        let mut function_indices = Vec::new();
        for (idx, entry) in entries.iter().enumerate() {
            match entry.tag {
                gimli::constants::DW_TAG_subprogram
                | gimli::constants::DW_TAG_inlined_subroutine => {
                    total_functions += 1;
                    function_indices.push(idx);
                    func_indices_by_cu
                        .entry(entry.unit_offset)
                        .or_default()
                        .push(idx);
                }
                gimli::constants::DW_TAG_variable => {
                    total_variables += 1;
                }
                _ => {}
            }

            if let Some(address) = entry.representative_addr.or(entry.entry_pc) {
                address_map.insert(address, idx);
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
            func_indices_by_cu,
            function_indices,
        }
    }

    fn is_function_tag(tag: gimli::DwTag) -> bool {
        matches!(
            tag,
            gimli::constants::DW_TAG_subprogram | gimli::constants::DW_TAG_inlined_subroutine
        )
    }

    fn entry_contains_function_address<F>(
        entry: &IndexEntry,
        address: u64,
        resolve_ranges: &mut F,
    ) -> bool
    where
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        if let Some(entry_pc) = entry.entry_pc {
            if address == entry_pc {
                return true;
            }
        }

        if let Some(ranges) = resolve_ranges(entry) {
            if ranges
                .iter()
                .any(|(start, end)| range_contains_pc(*start, *end, address))
            {
                return true;
            }
        }

        entry.representative_addr == Some(address)
    }

    fn entry_contains_address<F>(entry: &IndexEntry, address: u64, resolve_ranges: &mut F) -> bool
    where
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        if Self::is_function_tag(entry.tag) {
            return Self::entry_contains_function_address(entry, address, resolve_ranges);
        }

        entry.representative_addr == Some(address)
    }

    fn find_matching_function_in_indices<'a, I, F>(
        &'a self,
        indices: I,
        address: u64,
        resolve_ranges: &mut F,
    ) -> Option<&'a IndexEntry>
    where
        I: IntoIterator<Item = usize>,
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        for idx in indices {
            let Some(entry) = self.entries.get(idx) else {
                continue;
            };
            if entry.tag != gimli::constants::DW_TAG_subprogram {
                continue;
            }
            if Self::entry_contains_function_address(entry, address, resolve_ranges) {
                return Some(entry);
            }
        }
        None
    }

    fn find_matching_die_in_indices<'a, I, F>(
        &'a self,
        indices: I,
        address: u64,
        resolve_ranges: &mut F,
    ) -> Option<&'a IndexEntry>
    where
        I: IntoIterator<Item = usize>,
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        for idx in indices {
            let Some(entry) = self.entries.get(idx) else {
                continue;
            };
            if Self::entry_contains_address(entry, address, resolve_ranges) {
                return Some(entry);
            }
        }
        None
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

    fn candidate_indices_for_fragments<'a>(
        &'a self,
        query: &str,
        map_of: impl Fn(&'a NameIndexShard) -> &'a HashMap<String, Vec<usize>>,
    ) -> Vec<usize> {
        let mut fragment_hits: Vec<(String, usize)> = extract_name_fragments(query)
            .into_iter()
            .filter_map(|fragment| {
                let hits = self
                    .name_shards
                    .iter()
                    .map(|shard| map_of(shard).get(&fragment).map_or(0, Vec::len))
                    .sum::<usize>();
                (hits > 0).then_some((fragment, hits))
            })
            .collect();

        if fragment_hits.is_empty() {
            return Vec::new();
        }

        fragment_hits.sort_by_key(|(_, hits)| *hits);

        let mut candidates = self.collect_fragment_indices(&fragment_hits[0].0, &map_of);
        if candidates.is_empty() {
            return Vec::new();
        }

        for (fragment, _) in fragment_hits.iter().skip(1) {
            if candidates.len() <= 1 {
                break;
            }

            let fragment_indices = self.collect_fragment_indices(fragment, &map_of);
            if fragment_indices.is_empty() {
                continue;
            }
            candidates.retain(|idx| fragment_indices.contains(idx));
        }

        let mut ordered: Vec<usize> = candidates.into_iter().collect();
        ordered.sort_unstable();
        ordered
    }

    fn collect_fragment_indices<'a>(
        &'a self,
        fragment: &str,
        map_of: impl Fn(&'a NameIndexShard) -> &'a HashMap<String, Vec<usize>>,
    ) -> HashSet<usize> {
        let mut indices = HashSet::new();
        for shard in &self.name_shards {
            if let Some(local_indices) = map_of(shard).get(fragment) {
                for &local_idx in local_indices {
                    indices.insert(shard.entry_base + local_idx);
                }
            }
        }
        indices
    }

    /// Get all function names for debugging
    pub fn get_function_names(&self) -> Vec<&String> {
        self.unique_names(|shard| &shard.function_map)
    }

    /// Get all variable names for debugging
    pub fn get_variable_names(&self) -> Vec<&String> {
        self.unique_names(|shard| &shard.variable_map)
    }

    pub(crate) fn function_candidate_indices_by_fragment(&self, query: &str) -> Vec<usize> {
        self.candidate_indices_for_fragments(query, |shard| &shard.function_fragment_map)
    }

    pub(crate) fn variable_candidate_indices_by_fragment(&self, query: &str) -> Vec<usize> {
        self.candidate_indices_for_fragments(query, |shard| &shard.variable_fragment_map)
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

    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get total statistics
    pub fn get_stats(&self) -> (usize, usize, usize) {
        (
            self.total_functions,
            self.total_variables,
            self.entries.len(),
        )
    }

    fn insert_cu_range(
        cu_map: &mut BTreeMap<u64, (u64, DebugInfoOffset)>,
        start: u64,
        end: u64,
        cu: DebugInfoOffset,
    ) {
        if start > end {
            return;
        }

        match cu_map.get_mut(&start) {
            Some((existing_end, existing_cu)) => {
                if end > *existing_end {
                    *existing_end = end;
                    *existing_cu = cu;
                }
            }
            None => {
                cu_map.insert(start, (end, cu));
            }
        }
    }

    fn resolve_cu_root_ranges(
        dwarf: &gimli::Dwarf<DwarfReader>,
        cu: DebugInfoOffset,
    ) -> Option<Vec<(u64, u64)>> {
        let header = dwarf.unit_header(cu).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let mut entries = unit.entries();
        let root = entries.next_dfs().ok()??;
        RangeExtractor::extract_all_ranges(root, &unit, dwarf).ok()
    }

    fn resolve_function_ranges(
        dwarf: &gimli::Dwarf<DwarfReader>,
        entry: &IndexEntry,
    ) -> Option<Vec<(u64, u64)>> {
        if !Self::is_function_tag(entry.tag) {
            return None;
        }

        let header = dwarf.unit_header(entry.unit_offset).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let die = unit.entry(entry.die_offset).ok()?;
        RangeExtractor::extract_all_ranges(&die, &unit, dwarf).ok()
    }

    /// Attach CU range map and per-CU function address map built from entries
    pub fn build_cu_maps(&mut self, dwarf: &gimli::Dwarf<DwarfReader>) {
        let mut cu_map: BTreeMap<u64, (u64, DebugInfoOffset)> = BTreeMap::new();
        let mut per_cu: HashMap<DebugInfoOffset, BTreeMap<u64, usize>> = HashMap::new();

        for (idx, entry) in self.entries.iter().enumerate() {
            if !Self::is_function_tag(entry.tag) {
                continue;
            }

            let cu = entry.unit_offset;
            if let Some(address) = entry.representative_addr.or(entry.entry_pc) {
                let m = per_cu.entry(cu).or_insert_with(BTreeMap::new);
                m.insert(address, idx);
            }
        }

        for (&cu, indices) in &self.func_indices_by_cu {
            let root_ranges = Self::resolve_cu_root_ranges(dwarf, cu).unwrap_or_default();
            if !root_ranges.is_empty() {
                for (start, end) in root_ranges {
                    Self::insert_cu_range(&mut cu_map, start, end, cu);
                }
                continue;
            }

            for &idx in indices {
                let Some(entry) = self.entries.get(idx) else {
                    continue;
                };
                let Some(ranges) = Self::resolve_function_ranges(dwarf, entry) else {
                    continue;
                };
                for (start, end) in ranges {
                    Self::insert_cu_range(&mut cu_map, start, end, cu);
                }
            }
        }

        self.cu_range_map = cu_map;
        self.func_addr_by_cu = per_cu;
    }

    /// Build CU range map from .debug_aranges, if present. Returns true if any ranges were added.
    pub fn build_cu_maps_from_aranges(&mut self, _dwarf: &gimli::Dwarf<DwarfReader>) -> bool {
        // Build CU range map using .debug_aranges if available.
        // This accelerates PC→CU lookups and mirrors how debuggers seed CU maps.
        let mut added_any = false;

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
                                Self::insert_cu_range(&mut self.cu_range_map, start, end, cu_off);
                                added_any = true;
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

        added_any
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
    pub fn find_function_by_address<F>(
        &self,
        address: u64,
        mut resolve_ranges: F,
    ) -> Option<&IndexEntry>
    where
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        if let Some(cu) = self.find_cu_by_address(address) {
            if let Some(map) = self.func_addr_by_cu.get(&cu) {
                if let Some(entry) = self.find_matching_function_in_indices(
                    map.range(..=address).rev().map(|(_, &idx)| idx),
                    address,
                    &mut resolve_ranges,
                ) {
                    return Some(entry);
                }
            }
            if let Some(indices) = self.func_indices_by_cu.get(&cu) {
                if let Some(entry) = self.find_matching_function_in_indices(
                    indices.iter().copied(),
                    address,
                    &mut resolve_ranges,
                ) {
                    return Some(entry);
                }
            }
        }

        if let Some(entry) = self.find_matching_function_in_indices(
            self.address_map
                .range(..=address)
                .rev()
                .map(|(_, &idx)| idx),
            address,
            &mut resolve_ranges,
        ) {
            return Some(entry);
        }

        self.find_matching_function_in_indices(
            self.function_indices.iter().copied(),
            address,
            &mut resolve_ranges,
        )
    }

    /// Find DIE entry by address - returns the DIE containing this address
    /// This is the primary interface for address-based lookups
    pub fn find_die_at_address<F>(&self, address: u64, mut resolve_ranges: F) -> Option<&IndexEntry>
    where
        F: FnMut(&IndexEntry) -> Option<Vec<(u64, u64)>>,
    {
        tracing::debug!("find_die_at_address: looking for address 0x{:x}", address);
        tracing::trace!("  Address map has {} entries", self.address_map.len());

        if let Some(entry) = self.find_matching_die_in_indices(
            self.address_map
                .range(..=address)
                .rev()
                .map(|(_, &idx)| idx),
            address,
            &mut resolve_ranges,
        ) {
            tracing::debug!("  ✓ Found DIE '{}' (tag={:?})", entry.name, entry.tag);
            return Some(entry);
        }

        if let Some(entry) =
            self.find_matching_die_in_indices(0..self.entries.len(), address, &mut resolve_ranges)
        {
            tracing::debug!(
                "  ✓ Found DIE '{}' (tag={:?}) via fallback scan",
                entry.name,
                entry.tag
            );
            return Some(entry);
        }

        tracing::debug!("No DIE found containing address 0x{:x}", address);
        None
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
                    entry.entry_pc.or(entry.representative_addr)
                } else {
                    entry.representative_addr.or(entry.entry_pc)
                };

                if let Some(addr) = display_addr {
                    tracing::trace!(
                        "    - {} at 0x{:x} (role={:?}, inline={}, rep={:?})",
                        entry.name,
                        addr,
                        entry.function_kind(),
                        entry.is_inline_instance(),
                        entry.representative_addr
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

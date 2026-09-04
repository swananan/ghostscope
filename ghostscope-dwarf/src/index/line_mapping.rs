//! Pure address→line mapping lookup (no parsing, no file operations)

use crate::{core::LineEntry, path_match};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    ops::Bound,
};

/// Maximum row end seen at or before an address group.
///
/// `LineEntry::end_address == None` means that the row has no known upper
/// bound, so every later prefix containing that row remains unbounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PrefixMaxEnd {
    Finite(u64),
    Unbounded,
}

impl PrefixMaxEnd {
    fn from_end_address(end_address: Option<u64>) -> Self {
        match end_address {
            Some(end_address) => Self::Finite(end_address),
            None => Self::Unbounded,
        }
    }

    fn include(self, end_address: Option<u64>) -> Self {
        match (self, end_address) {
            (Self::Unbounded, _) | (_, None) => Self::Unbounded,
            (Self::Finite(current), Some(end_address)) => Self::Finite(current.max(end_address)),
        }
    }

    fn can_cover(self, address: u64) -> bool {
        match self {
            Self::Finite(end_address) => address < end_address,
            Self::Unbounded => true,
        }
    }
}

/// Pure line mapping table for fast address→line lookup
#[derive(Debug)]
pub struct LineMappingTable {
    /// Compacted line rows sorted by address as a dense lookup base.
    ///
    /// Multiple DWARF line rows can legitimately point at the same PC, for
    /// example inline/header locations sharing one instruction. Keep every row
    /// so source-location selection can score all candidates instead of being
    /// decided by insertion order.
    ///
    /// Keeping the rows in one allocation avoids cloning them into a pointer-
    /// heavy tree and makes address-range scans contiguous.
    entries: Vec<LineEntry>,

    /// Address of every equal-address group in `entries`.
    ///
    /// This is the hot address-search data: binary search touches only a dense
    /// vector of addresses before accessing the selected rows.
    address_group_addresses: Vec<u64>,

    /// Start index of each group in `entries`, parallel to
    /// `address_group_addresses`.
    address_group_starts: Vec<usize>,

    /// Maximum row end at or before each compact address group.
    ///
    /// This lets reverse lookups stop as soon as no earlier compact row can
    /// cover the target address.
    address_group_prefix_max_ends: Vec<PrefixMaxEnd>,

    /// Rows added after the compact base was built.
    ///
    /// Lazy line loading can append one compilation unit at a time. Keeping
    /// those rows in an incremental index avoids moving and re-indexing every
    /// previously loaded row on each append.
    incremental_entries: BTreeMap<u64, Vec<LineEntry>>,

    /// Addresses and prefix maximum row ends for `incremental_entries`.
    ///
    /// These vectors keep miss lookups logarithmic without rebuilding the
    /// compact base whenever another compilation unit is loaded.
    incremental_group_addresses: Vec<u64>,
    incremental_group_prefix_max_ends: Vec<PrefixMaxEnd>,

    /// Number of rows in `incremental_entries`.
    incremental_entry_count: usize,

    /// Path-based reverse mapping: (file_path, line_number) → addresses.
    path_line_to_addresses: HashMap<(String, u64), Vec<u64>>,

    /// Basename to full paths mapping for flexible path matching
    /// e.g., "nginx.c" → ["/home/user/nginx/src/core/nginx.c", ...]
    basename_to_paths: HashMap<String, HashSet<String>>,
}

impl LineMappingTable {
    // from_entries removed; use from_entries_with_scoped_manager to ensure canonical paths

    /// Create from entries, resolving file paths via ScopedFileIndexManager.
    /// This builds canonical path-based indices so basename lookups can take the fast path.
    pub(crate) fn from_entries_with_scoped_manager(
        mut entries: Vec<LineEntry>,
        scoped: &crate::index::ScopedFileIndexManager,
    ) -> Self {
        let mut path_line_to_addresses: HashMap<(String, u64), Vec<u64>> = HashMap::new();
        let mut basename_to_paths: HashMap<String, HashSet<String>> = HashMap::new();

        for e in entries.iter_mut() {
            // Resolve full path if missing, using scoped per-CU file index (DW_AT_comp_dir + line table)
            if e.file_path.is_empty() {
                if let Some(full_path) =
                    scoped.lookup_by_scoped_index(&e.compilation_unit, e.file_index)
                {
                    e.file_path = full_path;
                }
            }

            // Populate path→(line→addresses) only when we have a resolved path
            if !e.file_path.is_empty() {
                path_line_to_addresses
                    .entry((e.file_path.clone(), e.line))
                    .or_default()
                    .push(e.address);

                if let Some(base) = std::path::Path::new(&e.file_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                {
                    basename_to_paths
                        .entry(base.to_string())
                        .or_default()
                        .insert(e.file_path.clone());
                }
            }
        }

        // Stable sorting preserves insertion order for duplicate-address rows,
        // including the source-location lookup's preference for the last row.
        entries.sort_by_key(|entry| entry.address);
        let (address_group_addresses, address_group_starts, address_group_prefix_max_ends) =
            Self::build_address_groups(&entries);

        Self {
            entries,
            address_group_addresses,
            address_group_starts,
            address_group_prefix_max_ends,
            incremental_entries: BTreeMap::new(),
            incremental_group_addresses: Vec::new(),
            incremental_group_prefix_max_ends: Vec::new(),
            incremental_entry_count: 0,
            path_line_to_addresses,
            basename_to_paths,
        }
    }

    fn build_address_groups(entries: &[LineEntry]) -> (Vec<u64>, Vec<usize>, Vec<PrefixMaxEnd>) {
        let mut addresses = Vec::new();
        let mut starts = Vec::new();
        let mut prefix_max_ends = Vec::new();
        let mut previous_address = None;
        let mut prefix_max_end: Option<PrefixMaxEnd> = None;
        for (index, entry) in entries.iter().enumerate() {
            prefix_max_end = Some(match prefix_max_end {
                Some(prefix_max_end) => prefix_max_end.include(entry.end_address),
                None => PrefixMaxEnd::from_end_address(entry.end_address),
            });

            if previous_address != Some(entry.address) {
                addresses.push(entry.address);
                starts.push(index);
                prefix_max_ends.push(prefix_max_end.expect("included current line entry"));
                previous_address = Some(entry.address);
            } else {
                *prefix_max_ends
                    .last_mut()
                    .expect("duplicate address follows an address group") =
                    prefix_max_end.expect("included current line entry");
            }
        }
        (addresses, starts, prefix_max_ends)
    }

    fn build_incremental_address_groups(
        entries: &BTreeMap<u64, Vec<LineEntry>>,
    ) -> (Vec<u64>, Vec<PrefixMaxEnd>) {
        let mut addresses = Vec::with_capacity(entries.len());
        let mut prefix_max_ends = Vec::with_capacity(entries.len());
        let mut prefix_max_end: Option<PrefixMaxEnd> = None;

        for (&address, entries) in entries {
            for entry in entries {
                prefix_max_end = Some(match prefix_max_end {
                    Some(prefix_max_end) => prefix_max_end.include(entry.end_address),
                    None => PrefixMaxEnd::from_end_address(entry.end_address),
                });
            }
            addresses.push(address);
            prefix_max_ends.push(prefix_max_end.expect("incremental address group is non-empty"));
        }

        (addresses, prefix_max_ends)
    }

    fn group_entries(&self, group_index: usize) -> &[LineEntry] {
        let start = self.address_group_starts[group_index];
        let end = self
            .address_group_starts
            .get(group_index + 1)
            .copied()
            .unwrap_or(self.entries.len());
        &self.entries[start..end]
    }

    fn exact_address_group(&self, address: u64) -> Option<usize> {
        self.address_group_addresses.binary_search(&address).ok()
    }

    fn entries_at_address(&self, address: u64) -> impl Iterator<Item = &LineEntry> {
        let compact_entries = self
            .exact_address_group(address)
            .map(|group_index| self.group_entries(group_index))
            .unwrap_or_default();
        compact_entries
            .iter()
            .chain(self.incremental_entries.get(&address).into_iter().flatten())
    }

    /// Iterate every row in address order, including duplicate-PC rows.
    ///
    /// Statement and prologue markers belong to individual DWARF line rows.
    /// GCC column information commonly emits a marked row followed by an
    /// unmarked row at the same PC, so choosing one representative row would
    /// discard the marker.
    fn entries_from(&self, address: u64, inclusive: bool) -> impl Iterator<Item = &LineEntry> {
        let compact_start = self.entries.partition_point(|entry| {
            if inclusive {
                entry.address < address
            } else {
                entry.address <= address
            }
        });
        let lower_bound = if inclusive {
            Bound::Included(address)
        } else {
            Bound::Excluded(address)
        };
        let mut compact = self.entries[compact_start..].iter().peekable();
        let mut incremental = self
            .incremental_entries
            .range((lower_bound, Bound::Unbounded))
            .flat_map(|(_, entries)| entries)
            .peekable();

        std::iter::from_fn(move || {
            let take_compact = match (compact.peek(), incremental.peek()) {
                (Some(compact), Some(incremental)) => compact.address <= incremental.address,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            if take_compact {
                compact.next()
            } else {
                incremental.next()
            }
        })
    }

    fn compact_incremental_entries(&mut self) {
        if self.incremental_entries.is_empty() {
            return;
        }

        let compact_entries = std::mem::take(&mut self.entries);
        let capacity = compact_entries.len() + self.incremental_entry_count;
        let mut compact_entries = compact_entries.into_iter().peekable();
        let mut incremental_entries = std::mem::take(&mut self.incremental_entries)
            .into_values()
            .flatten()
            .peekable();
        let mut merged = Vec::with_capacity(capacity);

        while let (Some(compact), Some(incremental)) =
            (compact_entries.peek(), incremental_entries.peek())
        {
            // Rows already present precede later lazy additions at duplicate
            // addresses, preserving duplicate-row ordering.
            if compact.address <= incremental.address {
                merged.push(compact_entries.next().expect("peeked compact line entry"));
            } else {
                merged.push(
                    incremental_entries
                        .next()
                        .expect("peeked incremental line entry"),
                );
            }
        }
        merged.extend(compact_entries);
        merged.extend(incremental_entries);
        self.entries = merged;
        (
            self.address_group_addresses,
            self.address_group_starts,
            self.address_group_prefix_max_ends,
        ) = Self::build_address_groups(&self.entries);
        self.incremental_group_addresses.clear();
        self.incremental_group_prefix_max_ends.clear();
        self.incremental_entry_count = 0;
    }

    pub(crate) fn extend(&mut self, other: Self) {
        if self.entries.is_empty()
            && self.incremental_entries.is_empty()
            && self.path_line_to_addresses.is_empty()
            && self.basename_to_paths.is_empty()
        {
            *self = other;
            return;
        }

        self.incremental_entry_count += other.entries.len() + other.incremental_entry_count;
        for entry in other.entries {
            self.incremental_entries
                .entry(entry.address)
                .or_default()
                .push(entry);
        }
        for (address, mut entries) in other.incremental_entries {
            self.incremental_entries
                .entry(address)
                .or_default()
                .append(&mut entries);
        }

        for (key, mut addresses) in other.path_line_to_addresses {
            let current = self.path_line_to_addresses.entry(key).or_default();
            current.append(&mut addresses);
            current.sort_unstable();
            current.dedup();
        }
        for (basename, paths) in other.basename_to_paths {
            self.basename_to_paths
                .entry(basename)
                .or_default()
                .extend(paths);
        }

        // Compact geometrically instead of rebuilding on every lazy CU. This
        // bounds the incremental tail below the compact base size, while each
        // row participates in only logarithmically many full merges.
        if self.incremental_entry_count >= self.entries.len().max(1) {
            self.compact_incremental_entries();
        } else {
            (
                self.incremental_group_addresses,
                self.incremental_group_prefix_max_ends,
            ) = Self::build_incremental_address_groups(&self.incremental_entries);
        }
    }

    fn active_representative_entry(entries: &[LineEntry], address: u64) -> Option<&LineEntry> {
        entries
            .iter()
            .rev()
            .find(|entry| entry.contains_address(address))
    }

    /// Find the closest active line row at or before the target address.
    pub(crate) fn lookup_line(&self, address: u64) -> Option<&LineEntry> {
        let mut compact_group = self
            .address_group_addresses
            .partition_point(|&candidate| candidate <= address);
        let mut incremental_group = self
            .incremental_group_addresses
            .partition_point(|&candidate| candidate <= address);
        let mut incremental = self.incremental_entries.range(..=address).rev();

        // Rows from overlapping compilation units can interleave by start
        // address. A later row whose sequence already ended must not hide an
        // earlier row that still covers the target. Prefix maximum ends let
        // each store drop out as soon as none of its remaining rows can cover
        // the target, keeping sequence-gap misses bounded.
        let result = loop {
            if compact_group > 0
                && !self.address_group_prefix_max_ends[compact_group - 1].can_cover(address)
            {
                compact_group = 0;
            }
            if incremental_group > 0
                && !self.incremental_group_prefix_max_ends[incremental_group - 1].can_cover(address)
            {
                incremental_group = 0;
            }

            let compact_group_index = compact_group.checked_sub(1);
            let compact_address =
                compact_group_index.map(|group_index| self.address_group_addresses[group_index]);
            let incremental_address = incremental_group
                .checked_sub(1)
                .map(|group_index| self.incremental_group_addresses[group_index]);

            match (compact_address, incremental_address) {
                (Some(compact_address), Some(incremental_address))
                    if compact_address > incremental_address =>
                {
                    compact_group -= 1;
                    if let Some(entry) = Self::active_representative_entry(
                        self.group_entries(compact_group),
                        address,
                    ) {
                        break Some(entry);
                    }
                }
                (Some(compact_address), Some(incremental_address))
                    if compact_address == incremental_address =>
                {
                    compact_group -= 1;
                    incremental_group -= 1;
                    let (actual_address, incremental_entries) =
                        incremental.next().expect("indexed incremental line group");
                    debug_assert_eq!(*actual_address, incremental_address);
                    if let Some(entry) =
                        Self::active_representative_entry(incremental_entries, address).or_else(
                            || {
                                Self::active_representative_entry(
                                    self.group_entries(compact_group),
                                    address,
                                )
                            },
                        )
                    {
                        break Some(entry);
                    }
                }
                (_, Some(incremental_address)) => {
                    incremental_group -= 1;
                    let (actual_address, entries) =
                        incremental.next().expect("indexed incremental line group");
                    debug_assert_eq!(*actual_address, incremental_address);
                    if let Some(entry) = Self::active_representative_entry(entries, address) {
                        break Some(entry);
                    }
                }
                (Some(_), None) => {
                    compact_group -= 1;
                    if let Some(entry) = Self::active_representative_entry(
                        self.group_entries(compact_group),
                        address,
                    ) {
                        break Some(entry);
                    }
                }
                (None, None) => break None,
            }
        };

        if let Some(entry) = result {
            tracing::debug!(
                "LineMapping::lookup_line: address=0x{:x} -> found entry at 0x{:x}, file='{}', line={}",
                address, entry.address, entry.file_path, entry.line
            );
        } else {
            tracing::debug!(
                "LineMapping::lookup_line: address=0x{:x} -> no entry found",
                address
            );
        }

        result
    }

    /// Find all line entries at exact address (for handling overlapping instructions)
    pub(crate) fn lookup_all_lines_at_address(&self, address: u64) -> Vec<&LineEntry> {
        let active_entries: Vec<_> = self
            .entries_at_address(address)
            .filter(|entry| entry.contains_address(address))
            .collect();
        tracing::debug!(
            "LineMapping::lookup_all_lines_at_address: address=0x{:x} -> {} active entries",
            address,
            active_entries.len()
        );
        active_entries
    }

    /// Lookup addresses by file path and line number
    /// Strategies (fast → slow), avoiding global scans:
    /// 1. Exact full path match (O(1))
    /// 2. Basename candidates + suffix check among those candidates (O(k))
    /// 3. Unique basename match (O(1))
    ///
    /// For consecutive addresses on the same line, returns only the first is_stmt address
    pub(crate) fn lookup_addresses_by_path(&self, file_path: &str, line_number: u64) -> Vec<u64> {
        // Strategy 1: Try exact match first
        if let Some(addresses) = self
            .path_line_to_addresses
            .get(&(file_path.to_string(), line_number))
        {
            tracing::debug!("Found addresses via exact path match: {}", file_path);
            return self.filter_consecutive_addresses(addresses, file_path, line_number);
        }

        // Strategy 2: Basename candidates + suffix check (avoid global scans)
        let basename = path_match::file_name(file_path);
        if let Some(full_paths) = self.basename_to_paths.get(basename) {
            let has_sep = path_match::has_path_separator(file_path);
            if has_sep {
                for full_path in full_paths {
                    if path_match::path_component_suffix_matches(full_path, file_path)
                        || path_match::path_component_suffix_matches(file_path, full_path)
                    {
                        if let Some(addresses) = self
                            .path_line_to_addresses
                            .get(&(full_path.clone(), line_number))
                        {
                            tracing::debug!(
                                "Found addresses via basename+suffix match: {} -> {}",
                                file_path,
                                full_path
                            );
                            return self.filter_consecutive_addresses(
                                addresses,
                                full_path,
                                line_number,
                            );
                        }
                    }
                }
            }
        }

        // Strategy 3: Try basename match
        if let Some(full_paths) = self.basename_to_paths.get(basename) {
            // If there's only one file with this basename, use it
            if full_paths.len() == 1 {
                let full_path = full_paths.iter().next().unwrap();
                if let Some(addresses) = self
                    .path_line_to_addresses
                    .get(&(full_path.clone(), line_number))
                {
                    // Promote this message to info to confirm O(1) basename fast path hits
                    tracing::info!(
                        "LineMapping: unique basename fast path hit: {} -> {} ({} addrs)",
                        basename,
                        full_path,
                        addresses.len()
                    );
                    return self.filter_consecutive_addresses(addresses, full_path, line_number);
                }
            } else {
                // Multiple files with same basename - try to match with partial path (best effort)
                for full_path in full_paths {
                    if path_match::path_component_suffix_matches(full_path, file_path)
                        || path_match::path_component_suffix_matches(file_path, full_path)
                    {
                        if let Some(addresses) = self
                            .path_line_to_addresses
                            .get(&(full_path.clone(), line_number))
                        {
                            tracing::debug!(
                                "Found addresses via basename+path match: {} -> {}",
                                file_path,
                                full_path
                            );
                            return self.filter_consecutive_addresses(
                                addresses,
                                full_path,
                                line_number,
                            );
                        }
                    }
                }
            }
        }

        tracing::debug!("No addresses found for {}:{}", file_path, line_number);
        Vec::new()
    }

    /// Filter consecutive addresses to keep only statement boundaries
    /// This helps avoid setting multiple breakpoints on the same logical line
    fn filter_consecutive_addresses(
        &self,
        addresses: &[u64],
        file_path: &str,
        line_number: u64,
    ) -> Vec<u64> {
        if addresses.is_empty() {
            return Vec::new();
        }

        // Sort addresses
        let mut sorted_addrs = addresses.to_vec();
        sorted_addrs.sort_unstable();
        sorted_addrs.dedup();

        // Group consecutive addresses (within 32 bytes of each other)
        const CONSECUTIVE_THRESHOLD: u64 = 32;
        let mut groups: Vec<Vec<u64>> = Vec::new();
        let mut current_group = vec![sorted_addrs[0]];

        for i in 1..sorted_addrs.len() {
            let addr = sorted_addrs[i];
            let prev_addr = sorted_addrs[i - 1];

            if addr - prev_addr <= CONSECUTIVE_THRESHOLD {
                // Consecutive address, add to current group
                current_group.push(addr);
            } else {
                // New group
                groups.push(current_group);
                current_group = vec![addr];
            }
        }
        if !current_group.is_empty() {
            groups.push(current_group);
        }

        // For each group, prefer is_stmt addresses (like GDB)
        let mut result = Vec::new();
        for group in groups {
            if group.len() == 1 {
                // Single address - check if it's is_stmt
                let addr = group[0];
                let mut entries = self.entries_at_address(addr).peekable();
                if entries.peek().is_some() {
                    if entries.any(|entry| {
                        entry.is_stmt && entry.file_path == file_path && entry.line == line_number
                    }) {
                        result.push(addr);
                    }
                    // Note: Unlike GDB, we still include non-is_stmt single addresses
                    // This is more lenient for cases where compiler didn't mark is_stmt properly
                    else {
                        result.push(addr);
                        tracing::debug!(
                            "Including non-is_stmt address 0x{:x} (single address for this line)",
                            addr
                        );
                    }
                } else {
                    result.push(addr);
                }
            } else {
                // Multiple consecutive addresses - find the first is_stmt address
                let mut selected = None;
                for &addr in &group {
                    if self.entries_at_address(addr).any(|entry| {
                        entry.is_stmt && entry.file_path == file_path && entry.line == line_number
                    }) {
                        selected = Some(addr);
                        break;
                    }
                }

                if let Some(chosen) = selected {
                    // Found is_stmt address - use it (GDB-like behavior)
                    result.push(chosen);
                    tracing::debug!(
                        "Filtered {} consecutive addresses to single is_stmt address 0x{:x}",
                        group.len(),
                        chosen
                    );
                } else {
                    // No is_stmt found - be more lenient than GDB and use first address
                    let chosen = group[0];
                    result.push(chosen);
                    tracing::debug!(
                        "No is_stmt found in {} consecutive addresses, using first 0x{:x} (GDB might reject this line)",
                        group.len(),
                        chosen
                    );
                }
            }
        }

        result
    }

    /// Find the first executable instruction address after function prologue
    /// Assumes the input address is a real function (not inlined)
    /// Returns the best breakpoint location for the function
    pub fn find_first_executable_address(&self, function_start: u64, function_end: u64) -> u64 {
        tracing::debug!(
            "LineMappingTable: finding first executable address for function range [0x{:x}, 0x{:x})",
            function_start,
            function_end
        );

        if function_start >= function_end {
            tracing::debug!(
                "LineMappingTable: invalid or empty function range [0x{:x}, 0x{:x}), using its start",
                function_start,
                function_end
            );
            return function_start;
        }

        // 1. Try DWARF prologue_end flag first
        if let Some(addr) = self.find_prologue_end_from_dwarf(function_start, function_end) {
            tracing::info!(
                "LineMappingTable: found prologue_end at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
            return addr;
        }

        // 2. Fall back to is_stmt=true search
        if let Some(addr) = self.find_next_stmt_address(function_start, function_end) {
            tracing::info!(
                "LineMappingTable: using is_stmt=true address at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
            return addr;
        }

        // 3. Cannot determine prologue end, return original address
        tracing::info!(
            "LineMappingTable: no prologue information found, using original address 0x{:x}",
            function_start
        );
        function_start
    }

    /// Find prologue end using DWARF prologue_end flag
    fn find_prologue_end_from_dwarf(&self, function_start: u64, function_end: u64) -> Option<u64> {
        tracing::debug!(
            "LineMappingTable: searching for prologue_end=true after 0x{:x}",
            function_start
        );

        // A neighboring function can begin immediately after this range. Do
        // not borrow its prologue marker when this function has none.
        for entry in self
            .entries_from(function_start, true)
            .take_while(|entry| entry.address < function_end)
        {
            if entry.prologue_end {
                tracing::debug!(
                    "LineMappingTable: found prologue_end=true at 0x{:x} (line {}, file {})",
                    entry.address,
                    entry.line,
                    entry.file_path
                );
                tracing::debug!(
                    "LineMappingTable: found prologue_end at 0x{:x} (offset +{})",
                    entry.address,
                    entry.address - function_start
                );
                return Some(entry.address);
            }
        }

        tracing::debug!(
            "LineMappingTable: no prologue_end found after 0x{:x}",
            function_start
        );
        None
    }

    /// This is used for prologue detection following GDB's approach
    /// Find the next is_stmt=true address after the given function start address
    fn find_next_stmt_address(&self, function_start: u64, function_end: u64) -> Option<u64> {
        tracing::debug!(
            "LineMappingTable: searching for next is_stmt=true address after 0x{:x}",
            function_start
        );

        // Look for the first is_stmt=true address after function_start, but
        // never cross into a neighboring function.
        for entry in self
            .entries_from(function_start, false)
            .take_while(|entry| entry.address < function_end)
        {
            if entry.is_stmt {
                tracing::debug!(
                    "LineMappingTable: found is_stmt=true at 0x{:x} (line {}, file {})",
                    entry.address,
                    entry.line,
                    entry.file_path
                );
                return Some(entry.address);
            } else {
                // Extra diagnostics to understand why we didn't pick nearer addresses
                tracing::debug!(
                    "LineMappingTable: skipping non-is_stmt at 0x{:x} (offset +{}, line {}, file {}, prologue_end={})",
                    entry.address,
                    entry.address.saturating_sub(function_start),
                    entry.line,
                    entry.file_path,
                    entry.prologue_end
                );
            }
        }

        tracing::debug!(
            "LineMappingTable: no is_stmt=true address found after 0x{:x}",
            function_start
        );
        None
    }

    /// Get all line entries within an address range
    /// Returns an iterator over (address, line_entry) pairs in the specified range
    pub(crate) fn get_entries_in_range(
        &self,
        start_addr: u64,
        end_addr: u64,
    ) -> impl Iterator<Item = (&u64, &LineEntry)> {
        let start = self
            .entries
            .partition_point(|entry| entry.address < start_addr);
        let end = self
            .entries
            .partition_point(|entry| entry.address <= end_addr);
        let mut compact = self.entries[start..end].iter().peekable();
        let mut incremental = self
            .incremental_entries
            .range(start_addr..=end_addr)
            .flat_map(|(_, entries)| entries)
            .peekable();

        std::iter::from_fn(move || {
            let take_compact = match (compact.peek(), incremental.peek()) {
                (Some(compact), Some(incremental)) => compact.address <= incremental.address,
                (Some(_), None) => true,
                (None, Some(_)) => false,
                (None, None) => return None,
            };
            let entry = if take_compact {
                compact.next().expect("peeked compact line entry")
            } else {
                incremental.next().expect("peeked incremental line entry")
            };
            Some((&entry.address, entry))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn line_entry(address: u64, file_path: &str, line: u64, is_stmt: bool) -> LineEntry {
        LineEntry {
            address,
            end_address: None,
            file_path: file_path.to_string(),
            file_index: 1,
            compilation_unit: Arc::from("main.c"),
            line,
            column: 0,
            is_stmt,
            prologue_end: false,
        }
    }

    #[test]
    fn preserves_same_address_line_entries() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/include/header.h", 12, false),
                line_entry(0x1000, "/src/main.c", 42, true),
            ],
            &scoped,
        );

        let entries = table.lookup_all_lines_at_address(0x1000);

        assert_eq!(entries.len(), 2);
        assert!(entries
            .iter()
            .any(|entry| entry.file_path == "/src/include/header.h"));
        assert!(entries.iter().any(|entry| entry.file_path == "/src/main.c"));
    }

    #[test]
    fn lookup_line_uses_representative_row_with_duplicate_address() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/main.c", 42, true),
                line_entry(0x1000, "/src/include/header.h", 12, false),
            ],
            &scoped,
        );

        let entry = table.lookup_line(0x1004).expect("nearest line entry");

        assert_eq!(entry.file_path, "/src/include/header.h");
        assert_eq!(entry.line, 12);
    }

    #[test]
    fn lookup_addresses_by_path_uses_stmt_rows_for_requested_line_only() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/include/header.h", 12, true),
                line_entry(0x1000, "/src/main.c", 42, false),
                line_entry(0x1008, "/src/main.c", 42, true),
            ],
            &scoped,
        );

        assert_eq!(
            table.lookup_addresses_by_path("/src/main.c", 42),
            vec![0x1008]
        );
    }

    #[test]
    fn lookup_addresses_by_path_requires_component_suffix_match() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/myfoo/bar.c", 42, true),
                line_entry(0x2000, "/src/foo/bar.c", 42, true),
            ],
            &scoped,
        );

        assert_eq!(
            table.lookup_addresses_by_path("foo/bar.c", 42),
            vec![0x2000]
        );
    }

    #[test]
    fn lookup_line_does_not_cross_known_row_end() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut first = line_entry(0x1000, "/src/main.c", 10, true);
        first.end_address = Some(0x1010);
        let mut second = line_entry(0x2000, "/src/main.c", 20, true);
        second.end_address = Some(0x2010);
        let table =
            LineMappingTable::from_entries_with_scoped_manager(vec![first, second], &scoped);

        assert_eq!(table.lookup_line(0x100f).map(|entry| entry.line), Some(10));
        assert!(table.lookup_line(0x1010).is_none());
        assert!(table.lookup_line(0x1fff).is_none());
        assert_eq!(table.lookup_line(0x2000).map(|entry| entry.line), Some(20));
    }

    #[test]
    fn lookup_line_scans_past_inactive_row_from_overlapping_sequence() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut outer = line_entry(0x1000, "/src/outer.c", 10, true);
        outer.end_address = Some(0x1100);
        let mut inner = line_entry(0x1040, "/src/inner.c", 20, true);
        inner.end_address = Some(0x1060);
        let table = LineMappingTable::from_entries_with_scoped_manager(vec![outer, inner], &scoped);

        let entry = table
            .lookup_line(0x1080)
            .expect("outer row should remain active after inner sequence ends");

        assert_eq!(entry.file_path, "/src/outer.c");
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn lookup_line_scans_past_inactive_incremental_row() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut outer = line_entry(0x1000, "/src/outer.c", 10, true);
        outer.end_address = Some(0x1100);
        let mut unrelated = line_entry(0x2000, "/src/unrelated.c", 30, true);
        unrelated.end_address = Some(0x2010);
        let mut table =
            LineMappingTable::from_entries_with_scoped_manager(vec![outer, unrelated], &scoped);
        let mut inner = line_entry(0x1040, "/src/inner.c", 20, true);
        inner.end_address = Some(0x1060);
        table.extend(LineMappingTable::from_entries_with_scoped_manager(
            vec![inner],
            &scoped,
        ));

        let entry = table
            .lookup_line(0x1080)
            .expect("compact outer row should survive an inactive incremental row");

        assert_eq!(entry.file_path, "/src/outer.c");
        assert_eq!(entry.address, 0x1000);
    }

    #[test]
    fn lookup_line_prefix_max_ends_bound_compact_and_incremental_misses() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut compact_first = line_entry(0x1000, "/src/base.c", 10, true);
        compact_first.end_address = Some(0x1010);
        let mut compact_duplicate = line_entry(0x1100, "/src/base.c", 11, true);
        compact_duplicate.end_address = Some(0x1180);
        let mut compact_longer_duplicate = line_entry(0x1100, "/src/base.c", 12, true);
        compact_longer_duplicate.end_address = Some(0x1200);
        let mut compact_later = line_entry(0x2000, "/src/base.c", 20, true);
        compact_later.end_address = Some(0x2010);
        let mut table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                compact_first,
                compact_duplicate,
                compact_longer_duplicate,
                compact_later,
            ],
            &scoped,
        );

        let mut incremental_first = line_entry(0x1400, "/src/lazy.c", 14, true);
        incremental_first.end_address = Some(0x1500);
        let mut incremental_later = line_entry(0x1800, "/src/lazy.c", 18, true);
        incremental_later.end_address = Some(0x1810);
        table.extend(LineMappingTable::from_entries_with_scoped_manager(
            vec![incremental_first, incremental_later],
            &scoped,
        ));

        assert_eq!(
            table.address_group_prefix_max_ends,
            vec![
                PrefixMaxEnd::Finite(0x1010),
                PrefixMaxEnd::Finite(0x1200),
                PrefixMaxEnd::Finite(0x2010),
            ]
        );
        assert_eq!(
            table.incremental_group_prefix_max_ends,
            vec![PrefixMaxEnd::Finite(0x1500), PrefixMaxEnd::Finite(0x1810),]
        );
        assert!(table.lookup_line(0x1900).is_none());
    }

    #[test]
    fn lookup_line_prefix_max_end_treats_unknown_end_as_unbounded() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let compact_unbounded = line_entry(0x1000, "/src/base.c", 10, true);
        let mut compact_inactive = line_entry(0x1040, "/src/base.c", 11, true);
        compact_inactive.end_address = Some(0x1060);
        let mut compact_filler = line_entry(0x3000, "/src/base.c", 30, true);
        compact_filler.end_address = Some(0x3010);
        let mut compact_filler_later = line_entry(0x4000, "/src/base.c", 40, true);
        compact_filler_later.end_address = Some(0x4010);
        let mut table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                compact_unbounded,
                compact_inactive,
                compact_filler,
                compact_filler_later,
            ],
            &scoped,
        );

        assert_eq!(
            table.lookup_line(0x1080).map(|entry| entry.address),
            Some(0x1000)
        );
        assert_eq!(
            table.address_group_prefix_max_ends,
            vec![
                PrefixMaxEnd::Unbounded,
                PrefixMaxEnd::Unbounded,
                PrefixMaxEnd::Unbounded,
                PrefixMaxEnd::Unbounded,
            ]
        );

        let incremental_unbounded = line_entry(0x2000, "/src/lazy.c", 20, true);
        let mut incremental_inactive = line_entry(0x2040, "/src/lazy.c", 21, true);
        incremental_inactive.end_address = Some(0x2060);
        table.extend(LineMappingTable::from_entries_with_scoped_manager(
            vec![incremental_unbounded, incremental_inactive],
            &scoped,
        ));

        assert_eq!(
            table.incremental_group_prefix_max_ends,
            vec![PrefixMaxEnd::Unbounded, PrefixMaxEnd::Unbounded]
        );
        assert_eq!(
            table.lookup_line(0x2080).map(|entry| entry.address),
            Some(0x2000)
        );
    }

    #[test]
    fn lookup_line_ignores_zero_length_row() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut zero_length = line_entry(0x1000, "/src/main.c", 10, true);
        zero_length.end_address = Some(0x1000);
        let mut next = line_entry(0x2000, "/src/main.c", 20, true);
        next.end_address = Some(0x2010);
        let table =
            LineMappingTable::from_entries_with_scoped_manager(vec![zero_length, next], &scoped);

        assert!(table.lookup_line(0x1000).is_none());
        assert!(table.lookup_line(0x1fff).is_none());
        assert_eq!(table.lookup_line(0x2000).map(|entry| entry.line), Some(20));
    }

    #[test]
    fn lookup_all_lines_at_address_ignores_zero_length_row() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut zero_length = line_entry(0x1000, "/src/main.c", 10, true);
        zero_length.end_address = Some(0x1000);
        let mut active = line_entry(0x1000, "/src/main.c", 11, true);
        active.end_address = Some(0x1010);
        let table =
            LineMappingTable::from_entries_with_scoped_manager(vec![zero_length, active], &scoped);

        let entries = table.lookup_all_lines_at_address(0x1000);

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].line, 11);
    }

    #[test]
    fn address_lookups_sort_unsorted_input_and_scan_ranges_in_order() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x3000, "/src/main.c", 30, true),
                line_entry(0x1000, "/src/main.c", 10, true),
                line_entry(0x2000, "/src/main.c", 20, true),
            ],
            &scoped,
        );

        assert_eq!(table.lookup_line(0x2000).map(|entry| entry.line), Some(20));
        assert_eq!(
            table
                .get_entries_in_range(0x1000, 0x3000)
                .map(|(address, _)| *address)
                .collect::<Vec<_>>(),
            vec![0x1000, 0x2000, 0x3000]
        );
    }

    #[test]
    fn extend_preserves_existing_then_appended_duplicate_row_order() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut table = LineMappingTable::from_entries_with_scoped_manager(
            vec![line_entry(0x1000, "/src/first.c", 10, true)],
            &scoped,
        );
        let other = LineMappingTable::from_entries_with_scoped_manager(
            vec![line_entry(0x1000, "/src/second.c", 20, true)],
            &scoped,
        );

        table.extend(other);
        table.extend(LineMappingTable::from_entries_with_scoped_manager(
            vec![line_entry(0x1000, "/src/third.c", 30, true)],
            &scoped,
        ));

        let entries = table.lookup_all_lines_at_address(0x1000);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].file_path, "/src/first.c");
        assert_eq!(entries[1].file_path, "/src/second.c");
        assert_eq!(entries[2].file_path, "/src/third.c");
        assert_eq!(table.lookup_line(0x1000).map(|entry| entry.line), Some(30));
    }

    #[test]
    fn repeated_extend_compacts_geometrically_and_keeps_ranges_sorted() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut table = LineMappingTable::from_entries_with_scoped_manager(Vec::new(), &scoped);

        for index in 0..64 {
            let address = 0x1000 + index * 0x40;
            table.extend(LineMappingTable::from_entries_with_scoped_manager(
                vec![line_entry(
                    address,
                    &format!("/src/cu_{index}.c"),
                    index,
                    true,
                )],
                &scoped,
            ));

            let total = index as usize + 1;
            let expected_compact = 1usize << total.ilog2();
            assert_eq!(table.entries.len(), expected_compact);
            assert_eq!(table.incremental_entry_count, total - expected_compact);
            assert!(table.incremental_entry_count < table.entries.len());
        }

        let addresses = table
            .get_entries_in_range(0x1000, 0x2000)
            .map(|(address, _)| *address)
            .collect::<Vec<_>>();
        assert!(addresses.windows(2).all(|window| window[0] <= window[1]));
        assert_eq!(addresses.len(), 64);
        assert_eq!(table.lookup_line(0x1fc0).map(|entry| entry.line), Some(63));
    }

    #[test]
    fn prologue_search_checks_every_row_at_same_address() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut prologue_end = line_entry(0x1010, "/src/main.c", 11, true);
        prologue_end.prologue_end = true;
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/main.c", 10, false),
                prologue_end,
                line_entry(0x1010, "/src/main.c", 11, false),
                line_entry(0x1020, "/src/main.c", 12, true),
            ],
            &scoped,
        );

        assert_eq!(table.find_first_executable_address(0x1000, 0x1030), 0x1010);
    }

    #[test]
    fn statement_search_checks_every_row_at_same_address() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/main.c", 10, false),
                line_entry(0x1010, "/src/main.c", 11, true),
                line_entry(0x1010, "/src/main.c", 11, false),
                line_entry(0x1020, "/src/main.c", 12, true),
            ],
            &scoped,
        );

        assert_eq!(table.find_first_executable_address(0x1000, 0x1030), 0x1010);
    }

    #[test]
    fn prologue_search_merges_compact_and_incremental_addresses() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut compact_prologue = line_entry(0x3000, "/src/base.c", 30, true);
        compact_prologue.prologue_end = true;
        let mut table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/base.c", 10, true),
                compact_prologue,
            ],
            &scoped,
        );
        let mut incremental_prologue = line_entry(0x2000, "/src/lazy.c", 20, true);
        incremental_prologue.prologue_end = true;
        table.extend(LineMappingTable::from_entries_with_scoped_manager(
            vec![incremental_prologue],
            &scoped,
        ));

        assert_eq!(table.find_first_executable_address(0x1000, 0x4000), 0x2000);
    }

    #[test]
    fn prologue_search_does_not_cross_the_function_range() {
        let scoped = crate::index::ScopedFileIndexManager::new();
        let mut next_function_prologue = line_entry(0x1100, "/src/main.c", 20, true);
        next_function_prologue.prologue_end = true;
        let table = LineMappingTable::from_entries_with_scoped_manager(
            vec![
                line_entry(0x1000, "/src/main.c", 10, false),
                line_entry(0x1050, "/src/main.c", 11, false),
                next_function_prologue,
            ],
            &scoped,
        );

        assert_eq!(table.find_first_executable_address(0x1000, 0x1100), 0x1000);
        assert_eq!(table.find_first_executable_address(0x1100, 0x1100), 0x1100);
    }
}

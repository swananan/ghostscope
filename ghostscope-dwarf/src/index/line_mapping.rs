//! Pure address→line mapping lookup (no parsing, no file operations)

use crate::{core::LineEntry, path_match};
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::{
    borrow::Cow,
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

pub(crate) const MAPPED_LINE_ROW_SIZE: usize = 49;
pub(crate) const MAPPED_LINE_PATH_INDEX_SIZE: usize = 4;

pub(crate) fn encode_mapped_line_row(
    entry: &LineEntry,
    path_id: u32,
    compilation_unit_id: u32,
) -> [u8; MAPPED_LINE_ROW_SIZE] {
    let mut row = [0_u8; MAPPED_LINE_ROW_SIZE];
    row[0..8].copy_from_slice(&entry.address.to_le_bytes());
    row[8..16].copy_from_slice(&entry.end_address.unwrap_or_default().to_le_bytes());
    row[16..20].copy_from_slice(&path_id.to_le_bytes());
    row[20..28].copy_from_slice(&entry.file_index.to_le_bytes());
    row[28..32].copy_from_slice(&compilation_unit_id.to_le_bytes());
    row[32..40].copy_from_slice(&entry.line.to_le_bytes());
    row[40..48].copy_from_slice(&entry.column.to_le_bytes());
    row[48] = u8::from(entry.is_stmt)
        | (u8::from(entry.prologue_end) << 1)
        | (u8::from(entry.end_address.is_some()) << 2);
    row
}

/// Pure line mapping table for fast address→line lookup
#[derive(Debug)]
pub struct LineMappingTable {
    /// Complete address to line mapping (built at startup).
    ///
    /// Multiple DWARF line rows can legitimately point at the same PC, for
    /// example inline/header locations sharing one instruction. Keep every row
    /// so source-location selection can score all candidates instead of being
    /// decided by insertion order.
    address_to_line_map: BTreeMap<u64, Vec<LineEntry>>,

    /// Path-based reverse mapping: (file_path, line_number) → addresses
    /// Uses full paths as keys for accurate lookup
    path_line_to_addresses: HashMap<(String, u64), Vec<u64>>,

    /// Basename to full paths mapping for flexible path matching
    /// e.g., "nginx.c" → ["/home/user/nginx/src/core/nginx.c", ...]
    basename_to_paths: HashMap<String, HashSet<String>>,

    mapped: Option<MappedLineMapping>,
}

#[derive(Debug)]
struct MappedLineMapping {
    data: Arc<Mmap>,
    rows_offset: usize,
    row_count: usize,
    path_index_offset: usize,
    path_index_count: usize,
    strings: Arc<[Arc<str>]>,
    path_ids_by_full_path: HashMap<String, u32>,
    path_ids_by_basename: HashMap<String, Vec<u32>>,
}

impl LineMappingTable {
    // from_entries removed; use from_entries_with_scoped_manager to ensure canonical paths

    /// Create from entries, resolving file paths via ScopedFileIndexManager.
    /// This builds canonical path-based indices so basename lookups can take the fast path.
    pub(crate) fn from_entries_with_scoped_manager(
        mut entries: Vec<LineEntry>,
        scoped: &crate::index::ScopedFileIndexManager,
    ) -> Self {
        let mut address_to_line_map: BTreeMap<u64, Vec<LineEntry>> = BTreeMap::new();
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

            // Always populate the address→line map
            address_to_line_map
                .entry(e.address)
                .or_default()
                .push(e.clone());

            // Populate path→(line→addresses) only when we have a resolved path
            if !e.file_path.is_empty() {
                let key = (e.file_path.clone(), e.line);
                path_line_to_addresses
                    .entry(key)
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

        Self {
            address_to_line_map,
            path_line_to_addresses,
            basename_to_paths,
            mapped: None,
        }
    }

    pub(crate) fn from_mapped_cache(
        data: Arc<Mmap>,
        rows_offset: usize,
        row_count: usize,
        path_index_offset: usize,
        path_index_count: usize,
        strings: Arc<[Arc<str>]>,
        line_path_ids: &[u32],
    ) -> Result<Self> {
        checked_section_end(
            rows_offset,
            row_count,
            MAPPED_LINE_ROW_SIZE,
            data.len(),
            "line rows",
        )?;
        checked_section_end(
            path_index_offset,
            path_index_count,
            MAPPED_LINE_PATH_INDEX_SIZE,
            data.len(),
            "line path index",
        )?;

        let mut path_ids_by_full_path = HashMap::new();
        let mut path_ids_by_basename: HashMap<String, Vec<u32>> = HashMap::new();
        for &path_id in line_path_ids {
            let path = strings
                .get(path_id as usize)
                .with_context(|| format!("Line path string ID {path_id} is out of bounds"))?;
            if path.is_empty() {
                continue;
            }
            path_ids_by_full_path.insert(path.to_string(), path_id);
            if let Some(basename) = std::path::Path::new(path.as_ref())
                .file_name()
                .and_then(|name| name.to_str())
            {
                path_ids_by_basename
                    .entry(basename.to_string())
                    .or_default()
                    .push(path_id);
            }
        }
        for ids in path_ids_by_basename.values_mut() {
            ids.sort_unstable();
            ids.dedup();
        }

        Ok(Self {
            address_to_line_map: BTreeMap::new(),
            path_line_to_addresses: HashMap::new(),
            basename_to_paths: HashMap::new(),
            mapped: Some(MappedLineMapping {
                data,
                rows_offset,
                row_count,
                path_index_offset,
                path_index_count,
                strings,
                path_ids_by_full_path,
                path_ids_by_basename,
            }),
        })
    }

    pub(crate) fn cache_entries(&self) -> Vec<Cow<'_, LineEntry>> {
        if let Some(mapped) = &self.mapped {
            return (0..mapped.row_count)
                .filter_map(|index| mapped.row(index).map(Cow::Owned))
                .collect();
        }
        self.address_to_line_map
            .values()
            .flat_map(|entries| entries.iter().map(Cow::Borrowed))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn is_mapped(&self) -> bool {
        self.mapped.is_some()
    }

    fn representative_entry(entries: &[LineEntry]) -> Option<&LineEntry> {
        entries.last()
    }

    /// Find best matching line (closest address <= target address)
    pub(crate) fn lookup_line(&self, address: u64) -> Option<Cow<'_, LineEntry>> {
        if let Some(mapped) = &self.mapped {
            return mapped.lookup_line(address).map(Cow::Owned);
        }
        // Use BTreeMap's range to find the largest address <= target address
        let result = self
            .address_to_line_map
            .range(..=address)
            .next_back()
            .and_then(|(_, entries)| {
                Self::representative_entry(entries).filter(|entry| entry.contains_address(address))
            })
            .map(Cow::Borrowed);

        if let Some(entry) = &result {
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
    pub(crate) fn lookup_all_lines_at_address(&self, address: u64) -> Vec<Cow<'_, LineEntry>> {
        if let Some(mapped) = &self.mapped {
            return mapped
                .rows_at_address(address)
                .into_iter()
                .map(Cow::Owned)
                .collect();
        }
        if let Some(entries) = self.address_to_line_map.get(&address) {
            let active_entries: Vec<_> = entries
                .iter()
                .filter(|entry| entry.contains_address(address))
                .map(Cow::Borrowed)
                .collect();
            tracing::debug!(
                "LineMapping::lookup_all_lines_at_address: address=0x{:x} -> {} active entries",
                address,
                active_entries.len()
            );
            active_entries
        } else {
            tracing::debug!(
                "LineMapping::lookup_all_lines_at_address: address=0x{:x} -> 0 entries",
                address
            );
            Vec::new()
        }
    }

    /// Lookup addresses by file path and line number
    /// Strategies (fast → slow), avoiding global scans:
    /// 1. Exact full path match (O(1))
    /// 2. Basename candidates + suffix check among those candidates (O(k))
    /// 3. Unique basename match (O(1))
    ///
    /// For consecutive addresses on the same line, returns only the first is_stmt address
    pub(crate) fn lookup_addresses_by_path(&self, file_path: &str, line_number: u64) -> Vec<u64> {
        if let Some(mapped) = &self.mapped {
            let Some((addresses, resolved_path)) = mapped.lookup_addresses(file_path, line_number)
            else {
                tracing::debug!("No addresses found for {}:{}", file_path, line_number);
                return Vec::new();
            };
            return self.filter_consecutive_addresses(addresses, &resolved_path, line_number);
        }

        // Strategy 1: Try exact match first
        if let Some(addresses) = self
            .path_line_to_addresses
            .get(&(file_path.to_string(), line_number))
        {
            tracing::debug!("Found addresses via exact path match: {}", file_path);
            return self.filter_consecutive_addresses(addresses.clone(), file_path, line_number);
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
                                addresses.clone(),
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
                    return self.filter_consecutive_addresses(
                        addresses.clone(),
                        full_path,
                        line_number,
                    );
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
                                addresses.clone(),
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
        addresses: Vec<u64>,
        file_path: &str,
        line_number: u64,
    ) -> Vec<u64> {
        if addresses.is_empty() {
            return addresses;
        }

        // Sort addresses
        let mut sorted_addrs = addresses.clone();
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
                let entries = self.lookup_all_lines_at_address(addr);
                if !entries.is_empty() {
                    if entries.iter().any(|entry| {
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
                    let entries = self.lookup_all_lines_at_address(addr);
                    if entries.iter().any(|entry| {
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
    pub fn find_first_executable_address(&self, function_start: u64) -> u64 {
        tracing::debug!(
            "LineMappingTable: finding first executable address for function at 0x{:x}",
            function_start
        );

        // 1. Try DWARF prologue_end flag first
        if let Some(addr) = self.find_prologue_end_from_dwarf(function_start) {
            tracing::info!(
                "LineMappingTable: found prologue_end at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
            return addr;
        }

        // 2. Fall back to is_stmt=true search
        if let Some(addr) = self.find_next_stmt_address(function_start) {
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
    fn find_prologue_end_from_dwarf(&self, function_start: u64) -> Option<u64> {
        tracing::debug!(
            "LineMappingTable: searching for prologue_end=true after 0x{:x}",
            function_start
        );

        if let Some(mapped) = &self.mapped {
            return mapped.find_flagged_address(function_start, 1 << 1);
        }

        let mut best_address: Option<u64> = None;

        // Iterate through addresses starting from function_start
        for (&address, entries) in self.address_to_line_map.range(function_start..) {
            let Some(entry) = Self::representative_entry(entries) else {
                continue;
            };
            if entry.prologue_end {
                tracing::debug!(
                    "LineMappingTable: found prologue_end=true at 0x{:x} (line {}, file {})",
                    address,
                    entry.line,
                    entry.file_path
                );

                match best_address {
                    None => best_address = Some(address),
                    Some(current_best) => {
                        if address < current_best {
                            best_address = Some(address);
                        }
                        break; // Since we're iterating in order, this is the best we'll find
                    }
                }
                break; // Take the first prologue_end we find
            }
        }

        if let Some(addr) = best_address {
            tracing::debug!(
                "LineMappingTable: found prologue_end at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
        } else {
            tracing::debug!(
                "LineMappingTable: no prologue_end found after 0x{:x}",
                function_start
            );
        }

        best_address
    }

    /// This is used for prologue detection following GDB's approach
    /// Find the next is_stmt=true address after the given function start address
    fn find_next_stmt_address(&self, function_start: u64) -> Option<u64> {
        tracing::debug!(
            "LineMappingTable: searching for next is_stmt=true address after 0x{:x}",
            function_start
        );

        if let Some(mapped) = &self.mapped {
            return mapped.find_flagged_address(function_start.saturating_add(1), 1);
        }

        // Look for the first is_stmt=true address after function_start
        for (&address, entries) in self
            .address_to_line_map
            .range((function_start.saturating_add(1))..)
        {
            if let Some(entry) = Self::representative_entry(entries).filter(|entry| entry.is_stmt) {
                tracing::debug!(
                    "LineMappingTable: found is_stmt=true at 0x{:x} (line {}, file {})",
                    address,
                    entry.line,
                    entry.file_path
                );
                return Some(address);
            } else if let Some(entry) = Self::representative_entry(entries) {
                // Extra diagnostics to understand why we didn't pick nearer addresses
                tracing::debug!(
                    "LineMappingTable: skipping non-is_stmt at 0x{:x} (offset +{}, line {}, file {}, prologue_end={})",
                    address,
                    address.saturating_sub(function_start),
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
    ) -> Vec<(u64, Cow<'_, LineEntry>)> {
        if let Some(mapped) = &self.mapped {
            return mapped
                .rows_in_range(start_addr, end_addr)
                .into_iter()
                .map(|entry| (entry.address, Cow::Owned(entry)))
                .collect();
        }
        self.address_to_line_map
            .range(start_addr..=end_addr)
            .flat_map(|(&address, entries)| {
                entries
                    .iter()
                    .map(move |entry| (address, Cow::Borrowed(entry)))
            })
            .collect()
    }
}

impl MappedLineMapping {
    fn row_bytes(&self, index: usize) -> Option<&[u8]> {
        let start = self
            .rows_offset
            .checked_add(index.checked_mul(MAPPED_LINE_ROW_SIZE)?)?;
        self.data
            .get(start..start.checked_add(MAPPED_LINE_ROW_SIZE)?)
    }

    fn row_address(&self, index: usize) -> Option<u64> {
        read_u64(self.row_bytes(index)?, 0)
    }

    fn row_path_id(&self, index: usize) -> Option<u32> {
        read_u32(self.row_bytes(index)?, 16)
    }

    fn row_line(&self, index: usize) -> Option<u64> {
        read_u64(self.row_bytes(index)?, 32)
    }

    fn row_flags(&self, index: usize) -> Option<u8> {
        self.row_bytes(index)?.get(48).copied()
    }

    fn row(&self, index: usize) -> Option<LineEntry> {
        let row = self.row_bytes(index)?;
        let path_id = read_u32(row, 16)? as usize;
        let compilation_unit_id = read_u32(row, 28)? as usize;
        let flags = *row.get(48)?;
        let end_address = read_u64(row, 8)?;
        Some(LineEntry {
            address: read_u64(row, 0)?,
            end_address: (flags & 4 != 0).then_some(end_address),
            file_path: self.strings.get(path_id)?.to_string(),
            file_index: read_u64(row, 20)?,
            compilation_unit: Arc::clone(self.strings.get(compilation_unit_id)?),
            line: read_u64(row, 32)?,
            column: read_u64(row, 40)?,
            is_stmt: flags & 1 != 0,
            prologue_end: flags & 2 != 0,
        })
    }

    fn lower_bound_address(&self, target: u64) -> usize {
        let mut left = 0;
        let mut right = self.row_count;
        while left < right {
            let mid = left + (right - left) / 2;
            if self.row_address(mid).unwrap_or(u64::MAX) < target {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        left
    }

    fn upper_bound_address(&self, target: u64) -> usize {
        let mut left = 0;
        let mut right = self.row_count;
        while left < right {
            let mid = left + (right - left) / 2;
            if self
                .row_address(mid)
                .is_some_and(|address| address <= target)
            {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        left
    }

    fn lookup_line(&self, address: u64) -> Option<LineEntry> {
        let upper = self.upper_bound_address(address);
        let entry = self.row(upper.checked_sub(1)?)?;
        entry.contains_address(address).then_some(entry)
    }

    fn rows_at_address(&self, address: u64) -> Vec<LineEntry> {
        let start = self.lower_bound_address(address);
        let end = self.upper_bound_address(address);
        (start..end)
            .filter_map(|index| self.row(index))
            .filter(|entry| entry.contains_address(address))
            .collect()
    }

    fn rows_in_range(&self, start_address: u64, end_address: u64) -> Vec<LineEntry> {
        let start = self.lower_bound_address(start_address);
        let end = self.upper_bound_address(end_address);
        (start..end).filter_map(|index| self.row(index)).collect()
    }

    fn path_row_index(&self, index: usize) -> Option<usize> {
        let start = self
            .path_index_offset
            .checked_add(index.checked_mul(MAPPED_LINE_PATH_INDEX_SIZE)?)?;
        let bytes = self
            .data
            .get(start..start.checked_add(MAPPED_LINE_PATH_INDEX_SIZE)?)?;
        Some(read_u32(bytes, 0)? as usize)
    }

    fn path_key(&self, index: usize) -> Option<(u32, u64)> {
        let row_index = self.path_row_index(index)?;
        Some((self.row_path_id(row_index)?, self.row_line(row_index)?))
    }

    fn lower_bound_path_line(&self, target: (u32, u64)) -> usize {
        let mut left = 0;
        let mut right = self.path_index_count;
        while left < right {
            let mid = left + (right - left) / 2;
            if self.path_key(mid).unwrap_or((u32::MAX, u64::MAX)) < target {
                left = mid + 1;
            } else {
                right = mid;
            }
        }
        left
    }

    fn addresses_for_path_line(&self, path_id: u32, line: u64) -> Vec<u64> {
        let target = (path_id, line);
        let mut index = self.lower_bound_path_line(target);
        let mut addresses = Vec::new();
        while index < self.path_index_count && self.path_key(index) == Some(target) {
            if let Some(row_index) = self.path_row_index(index) {
                if let Some(address) = self.row_address(row_index) {
                    addresses.push(address);
                }
            }
            index += 1;
        }
        addresses
    }

    fn lookup_addresses(&self, file_path: &str, line: u64) -> Option<(Vec<u64>, String)> {
        if let Some(&path_id) = self.path_ids_by_full_path.get(file_path) {
            let addresses = self.addresses_for_path_line(path_id, line);
            if !addresses.is_empty() {
                return Some((addresses, file_path.to_string()));
            }
        }

        let basename = path_match::file_name(file_path);
        let path_ids = self.path_ids_by_basename.get(basename)?;
        if path_match::has_path_separator(file_path) {
            for &path_id in path_ids {
                let full_path = self.strings.get(path_id as usize)?.as_ref();
                if path_match::path_component_suffix_matches(full_path, file_path)
                    || path_match::path_component_suffix_matches(file_path, full_path)
                {
                    let addresses = self.addresses_for_path_line(path_id, line);
                    if !addresses.is_empty() {
                        return Some((addresses, full_path.to_string()));
                    }
                }
            }
        }

        if path_ids.len() == 1 {
            let path_id = path_ids[0];
            let full_path = self.strings.get(path_id as usize)?.as_ref();
            let addresses = self.addresses_for_path_line(path_id, line);
            if !addresses.is_empty() {
                return Some((addresses, full_path.to_string()));
            }
        }

        for &path_id in path_ids {
            let full_path = self.strings.get(path_id as usize)?.as_ref();
            if path_match::path_component_suffix_matches(full_path, file_path)
                || path_match::path_component_suffix_matches(file_path, full_path)
            {
                let addresses = self.addresses_for_path_line(path_id, line);
                if !addresses.is_empty() {
                    return Some((addresses, full_path.to_string()));
                }
            }
        }
        None
    }

    fn find_flagged_address(&self, start_address: u64, flag_mask: u8) -> Option<u64> {
        let mut index = self.lower_bound_address(start_address);
        while index < self.row_count {
            let address = self.row_address(index)?;
            let end = self.upper_bound_address(address);
            if self.row_flags(end.checked_sub(1)?)? & flag_mask != 0 {
                return Some(address);
            }
            index = end;
        }
        None
    }
}

fn checked_section_end(
    offset: usize,
    count: usize,
    record_size: usize,
    data_len: usize,
    section: &str,
) -> Result<usize> {
    let byte_len = count
        .checked_mul(record_size)
        .with_context(|| format!("Mapped {section} length overflow"))?;
    let end = offset
        .checked_add(byte_len)
        .with_context(|| format!("Mapped {section} offset overflow"))?;
    anyhow::ensure!(
        end <= data_len,
        "Mapped {section} section ends at {end}, beyond file length {data_len}"
    );
    Ok(end)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
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
}

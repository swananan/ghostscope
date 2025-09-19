//! Pure address→line mapping lookup (no parsing, no file operations)

use crate::core::LineEntry;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

/// Pure line mapping table for fast address→line lookup
#[derive(Debug)]
pub struct LineMappingTable {
    /// Complete address to line mapping (built at startup)
    address_to_line_map: BTreeMap<u64, LineEntry>,

    /// Path-based reverse mapping: (file_path, line_number) → addresses
    /// Uses full paths as keys for accurate lookup
    path_line_to_addresses: HashMap<(String, u64), Vec<u64>>,

    /// Basename to full paths mapping for flexible path matching
    /// e.g., "nginx.c" → ["/home/user/nginx/src/core/nginx.c", ...]
    basename_to_paths: HashMap<String, HashSet<String>>,

    /// Legacy file_index mapping (kept for compatibility)
    line_to_addresses_map: HashMap<(u64, u64), Vec<u64>>,

    /// Total line entries count for statistics
    total_entries: usize,
}

impl LineMappingTable {
    /// Create new empty line mapping table
    pub fn new() -> Self {
        Self {
            address_to_line_map: BTreeMap::new(),
            path_line_to_addresses: HashMap::new(),
            basename_to_paths: HashMap::new(),
            line_to_addresses_map: HashMap::new(),
            total_entries: 0,
        }
    }

    /// Create from pre-built line entries map
    pub fn from_btree_map(entries: BTreeMap<u64, LineEntry>) -> Self {
        let total_entries = entries.len();
        let mut path_line_to_addresses = HashMap::new();
        let mut basename_to_paths = HashMap::new();
        let mut line_to_addresses_map = HashMap::new();

        // Build reverse mappings
        for (address, entry) in &entries {
            // Path-based mapping
            let path_key = (entry.file_path.clone(), entry.line);
            path_line_to_addresses
                .entry(path_key)
                .or_insert_with(Vec::new)
                .push(*address);

            // Basename mapping
            if let Some(basename) = Path::new(&entry.file_path)
                .file_name()
                .and_then(|n| n.to_str())
            {
                basename_to_paths
                    .entry(basename.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(entry.file_path.clone());
            }

            // Legacy file_index mapping
            let index_key = (entry.file_index, entry.line);
            line_to_addresses_map
                .entry(index_key)
                .or_insert_with(Vec::new)
                .push(*address);
        }

        Self {
            address_to_line_map: entries,
            path_line_to_addresses,
            basename_to_paths,
            line_to_addresses_map,
            total_entries,
        }
    }

    /// Create from vector of line entries
    pub fn from_entries(entries: Vec<LineEntry>) -> Self {
        let mut address_to_line_map = BTreeMap::new();
        let mut path_line_to_addresses = HashMap::new();
        let mut basename_to_paths = HashMap::new();
        let mut line_to_addresses_map = HashMap::new();

        for entry in &entries {
            address_to_line_map.insert(entry.address, entry.clone());

            // Path-based mapping
            let path_key = (entry.file_path.clone(), entry.line);
            path_line_to_addresses
                .entry(path_key)
                .or_insert_with(Vec::new)
                .push(entry.address);

            // Basename mapping
            if let Some(basename) = Path::new(&entry.file_path)
                .file_name()
                .and_then(|n| n.to_str())
            {
                basename_to_paths
                    .entry(basename.to_string())
                    .or_insert_with(HashSet::new)
                    .insert(entry.file_path.clone());
            }

            // Legacy file_index mapping
            let index_key = (entry.file_index, entry.line);
            line_to_addresses_map
                .entry(index_key)
                .or_insert_with(Vec::new)
                .push(entry.address);
        }

        let total_entries = entries.len();
        Self {
            address_to_line_map,
            path_line_to_addresses,
            basename_to_paths,
            line_to_addresses_map,
            total_entries,
        }
    }

    /// High-performance line lookup with exact address match
    pub fn lookup_line_exact(&self, address: u64) -> Option<&LineEntry> {
        self.address_to_line_map.get(&address)
    }

    /// Find best matching line (closest address <= target address)
    pub fn lookup_line(&self, address: u64) -> Option<&LineEntry> {
        // Use BTreeMap's range to find the largest address <= target address
        let result = self
            .address_to_line_map
            .range(..=address)
            .next_back()
            .map(|(_, entry)| entry);

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

    /// Get total line entry count
    pub fn total_entries(&self) -> usize {
        self.total_entries
    }

    /// Get address range covered
    pub fn address_range(&self) -> Option<(u64, u64)> {
        if self.address_to_line_map.is_empty() {
            return None;
        }

        let min_addr = *self.address_to_line_map.keys().next()?;
        let max_addr = *self.address_to_line_map.keys().next_back()?;
        Some((min_addr, max_addr))
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.address_to_line_map.is_empty()
    }

    /// Lookup addresses by file index and line number (legacy)
    /// Returns all addresses that correspond to the given source line
    pub fn lookup_addresses_by_line(&self, file_index: u64, line_number: u64) -> Vec<u64> {
        self.line_to_addresses_map
            .get(&(file_index, line_number))
            .cloned()
            .unwrap_or_default()
    }

    /// Lookup addresses by file path and line number
    /// Supports multiple matching strategies:
    /// 1. Exact full path match
    /// 2. Suffix match (e.g., "src/core/nginx.c" matches "/home/user/nginx/src/core/nginx.c")
    /// 3. Basename match (e.g., "nginx.c" if unique)
    ///
    /// For consecutive addresses on the same line, returns only the first is_stmt address
    pub fn lookup_addresses_by_path(&self, file_path: &str, line_number: u64) -> Vec<u64> {
        // Strategy 1: Try exact match first
        if let Some(addresses) = self
            .path_line_to_addresses
            .get(&(file_path.to_string(), line_number))
        {
            tracing::debug!("Found addresses via exact path match: {}", file_path);
            return self.filter_consecutive_addresses(addresses.clone());
        }

        // Strategy 2: Try suffix match (for relative paths)
        for ((stored_path, stored_line), addresses) in &self.path_line_to_addresses {
            if *stored_line == line_number
                && (stored_path.ends_with(file_path) || file_path.ends_with(stored_path))
            {
                tracing::debug!(
                    "Found addresses via suffix match: {} matches {}",
                    file_path,
                    stored_path
                );
                return self.filter_consecutive_addresses(addresses.clone());
            }
        }

        // Strategy 3: Try basename match
        let basename = Path::new(file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(file_path);

        if let Some(full_paths) = self.basename_to_paths.get(basename) {
            // If there's only one file with this basename, use it
            if full_paths.len() == 1 {
                let full_path = full_paths.iter().next().unwrap();
                if let Some(addresses) = self
                    .path_line_to_addresses
                    .get(&(full_path.clone(), line_number))
                {
                    tracing::debug!(
                        "Found addresses via unique basename match: {} -> {}",
                        basename,
                        full_path
                    );
                    return self.filter_consecutive_addresses(addresses.clone());
                }
            } else {
                // Multiple files with same basename - try to match with partial path
                for full_path in full_paths {
                    if full_path.contains(file_path) || file_path.contains(basename) {
                        if let Some(addresses) = self
                            .path_line_to_addresses
                            .get(&(full_path.clone(), line_number))
                        {
                            tracing::debug!(
                                "Found addresses via basename+path match: {} -> {}",
                                file_path,
                                full_path
                            );
                            return self.filter_consecutive_addresses(addresses.clone());
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
    fn filter_consecutive_addresses(&self, addresses: Vec<u64>) -> Vec<u64> {
        if addresses.is_empty() {
            return addresses;
        }

        // Sort addresses
        let mut sorted_addrs = addresses.clone();
        sorted_addrs.sort_unstable();

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
                if let Some(entry) = self.address_to_line_map.get(&addr) {
                    if entry.is_stmt {
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
                    if let Some(entry) = self.address_to_line_map.get(&addr) {
                        if entry.is_stmt {
                            selected = Some(addr);
                            break;
                        }
                    }
                }

                if let Some(chosen) = selected {
                    // Found is_stmt address - use it (GDB-like behavior)
                    result.push(chosen);
                    tracing::info!(
                        "Filtered {} consecutive addresses to single is_stmt address 0x{:x}",
                        group.len(),
                        chosen
                    );
                } else {
                    // No is_stmt found - be more lenient than GDB and use first address
                    let chosen = group[0];
                    result.push(chosen);
                    tracing::warn!(
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
            tracing::debug!(
                "LineMappingTable: found prologue_end at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
            return addr;
        }

        // 2. Fall back to is_stmt=true search
        if let Some(addr) = self.find_next_stmt_address(function_start) {
            tracing::debug!(
                "LineMappingTable: using is_stmt=true address at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
            return addr;
        }

        // 3. Cannot determine prologue end, return original address
        tracing::debug!(
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

        let mut best_address: Option<u64> = None;

        // Iterate through addresses starting from function_start
        for (&address, entry) in self.address_to_line_map.range(function_start..) {
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

    /// Find the next is_stmt=true address after the given function start address
    /// This is used for prologue detection following GDB's approach
    fn find_next_stmt_address(&self, function_start: u64) -> Option<u64> {
        tracing::debug!(
            "LineMappingTable: searching for next is_stmt=true address after 0x{:x}",
            function_start
        );

        // Look for the first is_stmt=true address after function_start
        for (&address, entry) in self.address_to_line_map.range((function_start + 1)..) {
            if entry.is_stmt {
                tracing::debug!(
                    "LineMappingTable: found is_stmt=true at 0x{:x} (line {}, file {})",
                    address,
                    entry.line,
                    entry.file_path
                );
                return Some(address);
            }
        }

        tracing::debug!(
            "LineMappingTable: no is_stmt=true address found after 0x{:x}",
            function_start
        );
        None
    }
}

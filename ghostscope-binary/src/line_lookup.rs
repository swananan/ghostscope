use core::cmp::Ordering;
use std::boxed::Box;
use std::collections::HashMap;
use std::string::{String, ToString};
use std::vec::Vec;
use tracing::debug;

/// Address with its position in line table for consecutive instruction detection
#[derive(Debug, Clone)]
pub struct AddressWithPosition {
    pub address: u64,
    pub sequence_index: usize,
    pub row_index: usize,
}

/// Location information for a specific address
#[derive(Debug, Clone)]
pub(crate) struct LineLocation {
    pub address: u64,
    pub file_path: String,
    pub line_number: u32,
    pub column: u32,
}

/// A sequence of line information for a contiguous address range
#[derive(Debug)]
struct LineSequence {
    start: u64,
    end: u64,
    rows: Box<[LineRow]>,
}

/// A single line mapping entry
#[derive(Debug, Clone)]
struct LineRow {
    address: u64,
    file_index: u64,
    line: u32,
    column: u32,
    /// Statement boundary marker - preferred breakpoint location
    is_stmt: bool,
    /// End of function prologue - good place for breakpoints
    prologue_end: bool,
    /// Beginning of function epilogue
    epilogue_begin: bool,
    /// View number for discriminating multiple entries at same address (DWARF 5)
    view: u32,
    /// Discriminator for distinguishing different inline contexts
    discriminator: u32,
}

/// DWARF flags for an address
#[derive(Debug, Clone)]
struct AddressFlags {
    is_stmt: bool,
    prologue_end: bool,
    epilogue_begin: bool,
}

/// Parsed line information for efficient lookup
#[derive(Debug)]
pub(crate) struct LineInfo {
    files: Box<[String]>,
    sequences: Box<[LineSequence]>,
    /// Cache for line-to-address lookups
    line_cache: HashMap<(String, u32), Vec<u64>>,
}

impl LineInfo {
    /// Parse line information from DWARF debug_line section
    /// Based on addr2line's implementation but optimized for line-to-address lookups
    pub fn parse<R: gimli::Reader>(
        unit: &gimli::Unit<R>,
        dwarf: &gimli::Dwarf<R>,
    ) -> Result<Self, gimli::Error> {
        let ilnp = match unit.line_program {
            Some(ref ilnp) => ilnp,
            None => {
                return Ok(LineInfo {
                    files: Box::new([]),
                    sequences: Box::new([]),
                    line_cache: HashMap::new(),
                });
            }
        };

        let mut sequences = Vec::new();
        let mut sequence_rows = Vec::<LineRow>::new();
        let mut rows = ilnp.clone().rows();

        while let Some((_, row)) = rows.next_row()? {
            if row.end_sequence() {
                if let Some(start) = sequence_rows.first().map(|x| x.address) {
                    let end = row.address();
                    let mut rows = Vec::new();
                    core::mem::swap(&mut rows, &mut sequence_rows);
                    sequences.push(LineSequence {
                        start,
                        end,
                        rows: rows.into_boxed_slice(),
                    });
                }
                continue;
            }

            let address = row.address();
            let file_index = row.file_index();
            // Handle line 0 and convert to u32
            let line = row.line().map(|l| l.get()).unwrap_or(0) as u32;
            let column = match row.column() {
                gimli::ColumnType::LeftEdge => 0,
                gimli::ColumnType::Column(x) => x.get() as u32,
            };

            // Extract DWARF statement flags for proper breakpoint placement
            let is_stmt = row.is_stmt();
            let prologue_end = row.prologue_end();
            let epilogue_begin = row.epilogue_begin();

            // Get DWARF 5 fields for inline function discrimination
            let view = row.discriminator() as u32; // Convert to u32
            let discriminator = row.discriminator() as u32; // Convert to u32

            // Key difference from addr2line: we want to collect ALL line mappings
            // for the same address, not just replace them - this preserves inline function context
            sequence_rows.push(LineRow {
                address,
                file_index,
                line,
                column,
                is_stmt,
                prologue_end,
                epilogue_begin,
                view,
                discriminator,
            });
        }

        sequences.sort_by_key(|x| x.start);

        // Parse file information
        let mut files = Vec::new();
        let header = rows.header();

        // Parse file information similar to addr2line
        let dw_unit = gimli::UnitRef::new(dwarf, unit); // Create UnitRef for API compatibility
        match header.file(0) {
            Some(file) => files.push(render_file(dw_unit, file, header, dwarf)?),
            None => files.push(String::from("")), // DWARF version <= 4 may not have 0th index
        }
        let mut index = 1;
        while let Some(file) = header.file(index) {
            files.push(render_file(dw_unit, file, header, dwarf)?);
            index += 1;
        }

        debug!(
            "LineInfo: parsed {} sequences with {} files",
            sequences.len(),
            files.len()
        );

        Ok(LineInfo {
            files: files.into_boxed_slice(),
            sequences: sequences.into_boxed_slice(),
            line_cache: HashMap::new(),
        })
    }

    /// Find all addresses that correspond to a specific line in a file
    /// This is the reverse of the typical addr2line functionality
    pub fn find_addresses_for_line(&mut self, file_path: &str, line_number: u32) -> Vec<u64> {
        let cache_key = (file_path.to_string(), line_number);

        // Check cache first
        if let Some(cached_addresses) = self.line_cache.get(&cache_key) {
            debug!(
                "LineInfo: cache hit for {}:{} -> {} addresses",
                file_path,
                line_number,
                cached_addresses.len()
            );
            return cached_addresses.clone();
        }

        let mut addresses = Vec::new();
        let mut total_rows = 0;
        let mut matches = 0;

        debug!(
            "LineInfo: searching for {}:{} in {} sequences",
            file_path,
            line_number,
            self.sequences.len()
        );

        for sequence in &self.sequences {
            for row in sequence.rows.iter() {
                total_rows += 1;

                if let Some(file) = self.files.get(row.file_index as usize) {
                    if self.files_match(file, file_path) {
                        matches += 1;

                        debug!(
                            "LineInfo: file matched at 0x{:x}, row line: {}, target: {}",
                            row.address, row.line, line_number
                        );

                        if row.line == line_number {
                            debug!(
                                "LineInfo: exact line match at address 0x{:x}, is_stmt: {}, view: {}",
                                row.address, row.is_stmt, row.view
                            );
                            // Following GDB strategy: only add addresses that are statement boundaries
                            if row.is_stmt {
                                addresses.push(row.address);
                            } else {
                                debug!(
                                    "LineInfo: skipping non-statement address 0x{:x}",
                                    row.address
                                );
                            }
                        }
                    }
                }
            }
        }

        // Sort addresses but keep duplicates (needed for inline function context)
        addresses.sort_unstable();

        debug!(
            "LineInfo: search complete - checked {} rows, {} file matches, found {} addresses",
            total_rows,
            matches,
            addresses.len()
        );

        // Filter addresses following GDB-style logic: keep only statement boundaries
        let filtered_addresses = self.filter_addresses_gdb_style(addresses);

        // Cache result
        self.line_cache
            .insert(cache_key, filtered_addresses.clone());
        filtered_addresses
    }

    /// Get addresses with their position information for consecutive instruction detection
    pub fn find_addresses_with_positions(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<AddressWithPosition> {
        let mut address_positions = Vec::new();

        debug!(
            "LineInfo: searching for {}:{} with positions in {} sequences",
            file_path,
            line_number,
            self.sequences.len()
        );

        for (seq_idx, sequence) in self.sequences.iter().enumerate() {
            for (row_idx, row) in sequence.rows.iter().enumerate() {
                if let Some(file) = self.files.get(row.file_index as usize) {
                    if self.files_match(file, file_path) && row.line == line_number && row.is_stmt {
                        address_positions.push(AddressWithPosition {
                            address: row.address,
                            sequence_index: seq_idx,
                            row_index: row_idx,
                        });
                        debug!(
                            "LineInfo: found address 0x{:x} at sequence {} row {} for {}:{}",
                            row.address, seq_idx, row_idx, file_path, line_number
                        );
                    }
                }
            }
        }

        // Sort by address for consistent processing
        address_positions.sort_by_key(|pos| pos.address);
        address_positions
    }

    /// Filter addresses using GDB-style logic: prefer statement boundaries
    /// Based on GDB's find_line_common which ignores non-statement entries
    fn filter_addresses_gdb_style(&self, addresses: Vec<u64>) -> Vec<u64> {
        if addresses.is_empty() {
            return addresses;
        }

        debug!(
            "LineInfo: filtering {} addresses using GDB-style logic (is_stmt only)",
            addresses.len()
        );

        // GDB approach: only keep addresses marked as statement boundaries
        let mut stmt_addresses = Vec::new();

        for &addr in &addresses {
            let flags = self.get_address_flags(addr);
            if flags.is_stmt {
                debug!("LineInfo: keeping address 0x{:x} (is_stmt=true)", addr);
                stmt_addresses.push(addr);
            } else {
                debug!("LineInfo: ignoring address 0x{:x} (is_stmt=false)", addr);
            }
        }

        // If no statement addresses found, return all addresses as fallback
        if stmt_addresses.is_empty() {
            debug!(
                "LineInfo: no statement addresses found, keeping all {} addresses as fallback",
                addresses.len()
            );
            addresses
        } else {
            debug!(
                "LineInfo: filtered to {} statement addresses",
                stmt_addresses.len()
            );
            stmt_addresses
        }
    }

    /// Get DWARF flags for a specific address
    fn get_address_flags(&self, address: u64) -> AddressFlags {
        for sequence in &self.sequences {
            if let Ok(idx) = sequence
                .rows
                .binary_search_by(|row| row.address.cmp(&address))
            {
                let row = &sequence.rows[idx];
                return AddressFlags {
                    is_stmt: row.is_stmt,
                    prologue_end: row.prologue_end,
                    epilogue_begin: row.epilogue_begin,
                };
            }
        }

        // Default flags if not found
        AddressFlags {
            is_stmt: false,
            prologue_end: false,
            epilogue_begin: false,
        }
    }

    /// Find location information for a specific address
    /// Standard addr2line functionality
    pub fn find_location(&self, address: u64) -> Option<LineLocation> {
        for sequence in &self.sequences {
            if address >= sequence.start && address < sequence.end {
                // Binary search within sequence
                let result = sequence.rows.binary_search_by(|row| {
                    if row.address <= address {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });

                let row_index = match result {
                    Ok(i) => i,
                    Err(i) => {
                        if i == 0 {
                            continue;
                        }
                        i - 1
                    }
                };

                if let Some(row) = sequence.rows.get(row_index) {
                    if let Some(file_path) = self.files.get(row.file_index as usize) {
                        return Some(LineLocation {
                            address: row.address,
                            file_path: file_path.clone(),
                            line_number: row.line,
                            column: row.column,
                        });
                    }
                }
            }
        }

        None
    }

    /// Check if two file paths match
    /// Supports both absolute and relative path matching
    fn files_match(&self, dwarf_path: &str, target_path: &str) -> bool {
        // Exact match
        if dwarf_path == target_path {
            return true;
        }

        // Check if target_path is a suffix of dwarf_path (relative matching)
        if let Some(pos) = dwarf_path.rfind(target_path) {
            // Ensure the match is at a proper boundary (start of path or after a '/')
            if pos == 0 || dwarf_path.chars().nth(pos - 1) == Some('/') {
                debug!(
                    "LineInfo: files_match - relative match '{}' ends with '{}' at proper boundary",
                    dwarf_path, target_path
                );
                return true;
            }
        }

        debug!(
            "LineInfo: files_match - no match between '{}' and '{}'",
            dwarf_path, target_path
        );
        false
    }

    /// Get all file paths known to this line info
    pub fn get_files(&self) -> &[String] {
        &self.files
    }

    /// Clear internal caches to free memory
    pub fn clear_cache(&mut self) {
        self.line_cache.clear();
    }
}

/// Line lookup manager that handles multiple compilation units
#[derive(Debug)]
pub(crate) struct LineLookup {
    line_infos: Vec<LineInfo>,
}

impl LineLookup {
    /// Create new line lookup manager
    pub fn new() -> Self {
        LineLookup {
            line_infos: Vec::new(),
        }
    }

    /// Add line information from a compilation unit
    pub fn add_unit_line_info<R: gimli::Reader>(
        &mut self,
        unit: &gimli::Unit<R>,
        dwarf: &gimli::Dwarf<R>,
    ) -> Result<(), gimli::Error> {
        let line_info = LineInfo::parse(unit, dwarf)?;
        debug!(
            "LineLookup: added unit with {} files",
            line_info.get_files().len()
        );
        self.line_infos.push(line_info);
        Ok(())
    }

    /// Get addresses with their position information for consecutive instruction detection
    pub fn find_addresses_with_positions(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<AddressWithPosition> {
        let mut all_positions = Vec::new();

        debug!(
            "LineLookup: searching for {}:{} with positions across {} units",
            file_path,
            line_number,
            self.line_infos.len()
        );

        for (unit_idx, line_info) in self.line_infos.iter().enumerate() {
            let positions = line_info.find_addresses_with_positions(file_path, line_number);
            debug!(
                "LineLookup: unit {} returned {} address positions",
                unit_idx,
                positions.len()
            );

            // Adjust sequence index to be global across all units
            for pos in positions {
                all_positions.push(AddressWithPosition {
                    address: pos.address,
                    sequence_index: pos.sequence_index + unit_idx * 1000, // Make globally unique
                    row_index: pos.row_index,
                });
            }
        }

        // Sort by address for consistent processing
        all_positions.sort_by_key(|pos| pos.address);

        debug!(
            "LineLookup: total {} address positions found for {}:{}",
            all_positions.len(),
            file_path,
            line_number
        );

        all_positions
    }

    /// Filter consecutive addresses based on their position in the line table
    /// Returns addresses with GDB-style consecutive instruction filtering applied
    pub fn find_addresses_for_line_filtered(&self, file_path: &str, line_number: u32) -> Vec<u64> {
        let positions = self.find_addresses_with_positions(file_path, line_number);
        filter_consecutive_line_addresses(positions)
    }

    /// Find location information for a specific address
    pub fn find_location(&self, address: u64) -> Option<LineLocation> {
        for line_info in &self.line_infos {
            if let Some(location) = line_info.find_location(address) {
                return Some(location);
            }
        }
        None
    }

    /// Get all available files across all units
    pub fn get_all_files(&self) -> Vec<String> {
        let mut all_files = Vec::new();
        for line_info in &self.line_infos {
            all_files.extend_from_slice(line_info.get_files());
        }
        all_files.sort();
        all_files.dedup();
        all_files
    }

    /// Find the next is_stmt=true address after the given function start address
    /// This is used for prologue detection following GDB's approach
    pub fn find_next_stmt_address(&self, function_start: u64) -> Option<u64> {
        debug!(
            "LineLookup: searching for next is_stmt=true address after 0x{:x}",
            function_start
        );

        let mut best_address: Option<u64> = None;

        for line_info in &self.line_infos {
            for sequence in &line_info.sequences {
                // Only look in sequences that contain or come after our function start
                if sequence.end <= function_start {
                    continue;
                }

                for row in sequence.rows.iter() {
                    // Look for the first is_stmt=true address after function_start
                    if row.address > function_start && row.is_stmt {
                        debug!(
                            "LineLookup: found is_stmt=true at 0x{:x} (line {}, file index {})",
                            row.address, row.line, row.file_index
                        );

                        match best_address {
                            None => best_address = Some(row.address),
                            Some(current_best) => {
                                if row.address < current_best {
                                    best_address = Some(row.address);
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some(addr) = best_address {
            debug!(
                "LineLookup: found next is_stmt=true address at 0x{:x} (offset +{})",
                addr,
                addr - function_start
            );
        } else {
            debug!(
                "LineLookup: no is_stmt=true address found after 0x{:x}",
                function_start
            );
        }

        best_address
    }

    /// Clear all internal caches
    pub fn clear_caches(&mut self) {
        for line_info in &mut self.line_infos {
            line_info.clear_cache();
        }
    }
}

/// Render file path from DWARF file entry
/// Based on addr2line's render_file function
fn render_file<R: gimli::Reader>(
    dw_unit: gimli::UnitRef<R>,
    file: &gimli::FileEntry<R, R::Offset>,
    header: &gimli::LineProgramHeader<R, R::Offset>,
    _dwarf: &gimli::Dwarf<R>,
) -> Result<String, gimli::Error> {
    let mut path = if let Some(ref comp_dir) = dw_unit.comp_dir {
        comp_dir.to_string_lossy()?.into_owned()
    } else {
        String::new()
    };

    // The directory index 0 is defined to correspond to the compilation unit directory.
    if file.directory_index() != 0 {
        if let Some(directory) = file.directory(header) {
            path_push(
                &mut path,
                dw_unit.attr_string(directory)?.to_string_lossy()?.as_ref(),
            );
        }
    }

    path_push(
        &mut path,
        dw_unit
            .attr_string(file.path_name())?
            .to_string_lossy()?
            .as_ref(),
    );

    Ok(path)
}

/// Helper function to push path components  
/// Based on addr2line's path_push function
fn path_push(path: &mut String, p: &str) {
    if has_forward_slash_root(p) || has_backward_slash_root(p) {
        *path = p.to_string();
    } else {
        let dir_separator = if has_backward_slash_root(path.as_str()) {
            '\\'
        } else {
            '/'
        };

        if !path.is_empty() && !path.ends_with(dir_separator) {
            path.push(dir_separator);
        }
        *path += p;
    }
}

/// Check if the path in the given string has a unix style root
fn has_forward_slash_root(p: &str) -> bool {
    p.starts_with('/') || p.get(1..3) == Some(":/")
}

/// Check if the path in the given string has a windows style root
fn has_backward_slash_root(p: &str) -> bool {
    p.starts_with('\\') || p.get(1..3) == Some(":\\")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_files_match() {
        let line_info = LineInfo {
            files: Box::new([]),
            sequences: Box::new([]),
            line_cache: HashMap::new(),
        };

        // Test exact match
        assert!(line_info.files_match("test.c", "test.c"));

        // Test relative match
        assert!(line_info.files_match("/path/to/test.c", "test.c"));
        assert!(line_info.files_match("/path/to/test.c", "to/test.c"));

        // Test no match
        assert!(!line_info.files_match("other.c", "test.c"));
        assert!(!line_info.files_match("/path/to/other.c", "test.c"));

        // Test boundary conditions
        assert!(!line_info.files_match("/path/to/mytest.c", "test.c"));
        assert!(line_info.files_match("/path/to/test.c", "test.c"));
    }
}

/// Filter consecutive addresses based on their position in the line table
/// This implements GDB-style logic: if addresses are consecutive in the line table,
/// only keep the first one as a breakpoint location
pub fn filter_consecutive_line_addresses(positions: Vec<AddressWithPosition>) -> Vec<u64> {
    if positions.is_empty() {
        return Vec::new();
    }

    let mut filtered = Vec::new();
    let mut i = 0;

    while i < positions.len() {
        let current = &positions[i];
        filtered.push(current.address);

        // Check if subsequent addresses are consecutive in the same sequence
        let mut j = i + 1;
        while j < positions.len() {
            let next = &positions[j];

            // Are they in the same sequence and consecutive rows?
            if next.sequence_index == current.sequence_index
                && next.row_index == current.row_index + (j - i)
            {
                // Consecutive in line table, skip this address
                debug!(
                    "Line breakpoint: filtering consecutive address 0x{:x} (row {} after 0x{:x} at row {})",
                    next.address,
                    next.row_index,
                    current.address,
                    current.row_index
                );
                j += 1;
            } else {
                // Not consecutive, break the loop
                break;
            }
        }

        if j > i + 1 {
            debug!(
                "Line breakpoint: filtered {} consecutive addresses after 0x{:x}, keeping only first",
                j - i - 1,
                current.address
            );
        }

        i = j; // Move to next non-consecutive address
    }

    debug!(
        "Line breakpoint filtering: {} addresses -> {} distinct locations",
        positions.len(),
        filtered.len()
    );

    filtered
}

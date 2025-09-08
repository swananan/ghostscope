use core::cmp::Ordering;
use std::boxed::Box;
use std::collections::HashMap;
use std::string::{String, ToString};
use std::vec::Vec;
use tracing::debug;

/// Location information for a specific address
#[derive(Debug, Clone)]
pub struct LineLocation {
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
}

/// Parsed line information for efficient lookup
#[derive(Debug)]
pub struct LineInfo {
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

            // Key difference from addr2line: we want to collect ALL line mappings
            // for the same address, not just replace them
            sequence_rows.push(LineRow {
                address,
                file_index,
                line,
                column,
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
                                "LineInfo: exact line match! Adding address 0x{:x}",
                                row.address
                            );
                            addresses.push(row.address);
                        }
                    }
                }
            }
        }

        // Remove duplicates and sort
        addresses.sort_unstable();
        addresses.dedup();

        debug!(
            "LineInfo: search complete - checked {} rows, {} file matches, found {} addresses",
            total_rows,
            matches,
            addresses.len()
        );

        // Cache result
        self.line_cache.insert(cache_key, addresses.clone());
        addresses
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
pub struct LineLookup {
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

    /// Find all addresses for a given file and line number
    pub fn find_addresses_for_line(&mut self, file_path: &str, line_number: u32) -> Vec<u64> {
        let mut all_addresses = Vec::new();

        debug!(
            "LineLookup: searching {}:{} across {} units",
            file_path,
            line_number,
            self.line_infos.len()
        );

        for (unit_idx, line_info) in self.line_infos.iter_mut().enumerate() {
            let addresses = line_info.find_addresses_for_line(file_path, line_number);
            debug!(
                "LineLookup: unit {} returned {} addresses",
                unit_idx,
                addresses.len()
            );
            all_addresses.extend(addresses);
        }

        // Remove duplicates and sort
        all_addresses.sort_unstable();
        all_addresses.dedup();

        debug!(
            "LineLookup: total {} unique addresses found for {}:{}",
            all_addresses.len(),
            file_path,
            line_number
        );

        all_addresses
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

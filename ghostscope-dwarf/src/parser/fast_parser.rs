//! Unified DWARF parser - true single-pass parsing

use crate::{
    core::{IndexEntry, Result},
    data::{
        directory_from_index, resolve_file_path, LightweightFileIndex, LightweightIndex,
        LineMappingTable, ScopedFileIndexManager,
    },
    parser::RangeExtractor,
};
use gimli::{EndianSlice, LittleEndian};
use std::collections::HashMap;
use tracing::debug;

/// Compilation unit information with associated directories and files.
#[derive(Debug, Clone)]
pub(crate) struct CompilationUnit {
    /// Base directory for this compilation unit.
    pub base_directory: String,
    /// All include directories for this compilation unit.
    pub include_directories: Vec<String>,
    /// Files within this compilation unit.
    pub files: Vec<SourceFile>,
}

/// Source file information extracted from DWARF debug info.
#[derive(Debug, Clone)]
pub(crate) struct SourceFile {
    /// Directory path (resolved from include_directories).
    pub directory_path: String,
    /// Just the filename (basename).
    pub filename: String,
    /// Full resolved path.
    pub full_path: String,
}

/// Complete result of DWARF parsing
pub(crate) struct DwarfParseResult {
    pub lightweight_index: LightweightIndex,
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
    pub stats: DwarfParseStats,
}

/// Result of line information parsing (for parallel processing)
pub(crate) struct LineParseResult {
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
    pub line_entries_count: usize,
    pub files_count: usize,
}

/// Result of debug information parsing (for parallel processing)
pub(crate) struct DebugParseResult {
    pub lightweight_index: LightweightIndex,
    pub functions_count: usize,
    pub variables_count: usize,
}

/// Parsing statistics for logging and debugging
#[derive(Debug, Clone)]
pub(crate) struct DwarfParseStats {
    pub total_functions: usize,
    pub total_variables: usize,
    pub total_line_entries: usize,
    pub total_files: usize,
}

/// Unified DWARF parser - parses everything in optimized single pass
pub(crate) struct DwarfParser<'a> {
    dwarf: &'a gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
}

/// Internal builder for accumulating parse results
impl<'a> DwarfParser<'a> {
    pub fn new(dwarf: &'a gimli::Dwarf<EndianSlice<'static, LittleEndian>>) -> Self {
        Self { dwarf }
    }

    /// Process single compilation unit - decoupled debug_line and debug_info processing
    // Helper methods (extracted from unified_builder.rs)
    fn extract_name(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_name)? {
            if let Ok(name) = dwarf.attr_string(unit, attr.value()) {
                return Ok(Some(name.to_string_lossy().into_owned()));
            }
        }
        Ok(None)
    }

    fn is_static_symbol(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_external)? {
            if let gimli::AttributeValue::Flag(is_external) = attr.value() {
                return Ok(!is_external);
            }
        }
        Ok(true)
    }

    /// Extract all address ranges from DIE (for functions)
    /// Supports DW_AT_low_pc/high_pc and DW_AT_ranges (returns all ranges)
    fn extract_address_ranges(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Vec<(u64, u64)>> {
        // Use RangeExtractor for unified logic
        RangeExtractor::extract_all_ranges(entry, unit, dwarf)
    }

    /// Extract variable address from DIE
    fn extract_variable_address(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<u64>> {
        let mut attrs = entry.attrs();
        while let Some(attr) = attrs.next()? {
            if attr.name() == gimli::constants::DW_AT_location {
                // Simple case: direct address
                if let gimli::AttributeValue::Addr(addr) = attr.value() {
                    return Ok(Some(addr));
                }
                // TODO: Handle location expressions for more complex cases
            }
        }
        Ok(None)
    }

    // Additional helper methods for GDB-style cooked index

    fn is_main_function(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        name: &str,
    ) -> Result<bool> {
        // Check for DW_AT_main_subprogram attribute
        if entry
            .attr(gimli::constants::DW_AT_main_subprogram)?
            .is_some()
        {
            return Ok(true);
        }

        // Also check common main function names
        Ok(name == "main" || name == "_main")
    }

    fn extract_language(
        &self,
        _dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        _entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Option<gimli::DwLang> {
        // Try to get language from compilation unit
        let mut entries = unit.entries();
        if let Ok(Some((_, cu_entry))) = entries.next_dfs() {
            if cu_entry.tag() == gimli::constants::DW_TAG_compile_unit {
                if let Ok(Some(lang_attr)) = cu_entry.attr(gimli::constants::DW_AT_language) {
                    if let gimli::AttributeValue::Language(lang) = lang_attr.value() {
                        return Some(lang);
                    }
                }
            }
        }
        None
    }

    /// Parse debug_line sections (for parallel processing)
    pub fn parse_line_info(&self, module_path: &str) -> Result<LineParseResult> {
        debug!("Starting debug_line-only parsing for: {}", module_path);

        let mut scoped_file_manager = ScopedFileIndexManager::new();
        let mut line_entries = Vec::new();
        let mut compilation_units = HashMap::new();
        let mut total_files = 0;

        // Parse all compilation units for line information only
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = self.dwarf.unit(header)?;

            if let Some(ref line_program) = unit.line_program {
                // Get compilation unit name
                let cu_name = Self::extract_cu_name_from_dwarf(self.dwarf, &unit)
                    .unwrap_or_else(|| "unknown".to_string());
                let comp_dir = Self::extract_comp_dir_from_dwarf(self.dwarf, &unit);

                // Create lightweight file index for this CU
                let mut file_index = LightweightFileIndex::new(comp_dir, header.version());

                let header = line_program.header();

                // Add directories from line program
                for dir_entry in header.include_directories() {
                    if let Ok(dir_path) = self.dwarf.attr_string(&unit, *dir_entry) {
                        file_index.add_directory(dir_path.to_string_lossy().into_owned());
                    }
                }

                // Add files from line program (minimal storage)
                for (file_idx, file_entry) in header.file_names().iter().enumerate() {
                    let file_index_value = if header.version() >= 5 {
                        file_idx as u64 // DWARF 5: 0-based
                    } else {
                        (file_idx + 1) as u64 // DWARF 4: 1-based
                    };

                    if let Ok(filename) = self.dwarf.attr_string(&unit, file_entry.path_name()) {
                        let dir_index = file_entry.directory_index();
                        file_index.add_file_entry(
                            file_index_value,
                            dir_index,
                            filename.to_string_lossy().into_owned(),
                        );
                    }
                }

                // Build rich compilation unit metadata (directories + files)
                let compilation_unit = Self::extract_file_info_from_line_program_static(
                    self.dwarf,
                    &unit,
                    line_program,
                )?;

                total_files += compilation_unit.files.len();

                compilation_units.insert(cu_name.clone(), compilation_unit);

                // Add to scoped manager
                scoped_file_manager.add_compilation_unit(cu_name.clone(), file_index);

                // Extract line entries (file_index only, file_path resolved later via ScopedFileIndexManager)
                let (line_program, sequences) = line_program.clone().sequences()?;
                for seq in sequences {
                    let mut rows = line_program.resume_from(&seq);
                    while let Some((_, line_row)) = rows.next_row()? {
                        let column = match line_row.column() {
                            gimli::ColumnType::LeftEdge => 0,
                            gimli::ColumnType::Column(x) => x.get(),
                        };

                        // Create LineEntry with file_index only (file_path resolved later via ScopedFileIndexManager)
                        let line_entry = crate::core::LineEntry {
                            address: line_row.address(),
                            file_path: String::new(), // Placeholder, resolved later via ScopedFileIndexManager
                            file_index: line_row.file_index(),
                            compilation_unit: cu_name.clone(),
                            line: line_row.line().map(|l| l.get()).unwrap_or(0),
                            column,
                            is_stmt: line_row.is_stmt(),
                            prologue_end: line_row.prologue_end(),
                            epilogue_begin: line_row.epilogue_begin(),
                            end_sequence: line_row.end_sequence(),
                        };

                        line_entries.push(line_entry);
                    }
                }
            }
        }

        let line_mapping = LineMappingTable::from_entries(line_entries.clone());

        debug!(
            "Completed debug_line parsing for {}: {} line entries, {} files, {} compilation units",
            module_path,
            line_entries.len(),
            total_files,
            compilation_units.len()
        );

        Ok(LineParseResult {
            line_mapping,
            scoped_file_manager,
            compilation_units,
            line_entries_count: line_entries.len(),
            files_count: total_files,
        })
    }

    /// Parse debug_info sections (for parallel processing)
    pub fn parse_debug_info(&self, module_path: &str) -> Result<DebugParseResult> {
        debug!("Starting debug_info-only parsing for: {}", module_path);

        let mut functions: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        let mut variables: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        // Parse all compilation units for debug info only
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = self.dwarf.unit(header)?;

            let unit_offset = match header.offset() {
                gimli::UnitSectionOffset::DebugInfoOffset(offset) => offset,
                _ => continue,
            };

            // Parse DIEs without file path resolution (will be resolved later)
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                match entry.tag() {
                    gimli::constants::DW_TAG_subprogram => {
                        if let Some(name) = self.extract_name(self.dwarf, &unit, entry)? {
                            let flags = crate::core::IndexFlags {
                                is_static: self.is_static_symbol(entry).unwrap_or(false),
                                is_main: self.is_main_function(entry, &name).unwrap_or(false),
                                ..Default::default()
                            };

                            let address_ranges =
                                self.extract_address_ranges(self.dwarf, &unit, entry)?;

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(self.dwarf, &unit, entry),
                                address_ranges: address_ranges.clone(),
                            };

                            functions.entry(name).or_default().push(index_entry);
                        }
                    }
                    gimli::constants::DW_TAG_inlined_subroutine => {
                        if let Some(name) = self.extract_name(self.dwarf, &unit, entry)? {
                            let flags = crate::core::IndexFlags {
                                is_inline: true,
                                ..Default::default()
                            };

                            let address_ranges =
                                self.extract_address_ranges(self.dwarf, &unit, entry)?;

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(self.dwarf, &unit, entry),
                                address_ranges: address_ranges.clone(),
                            };

                            functions.entry(name).or_default().push(index_entry);
                        }
                    }
                    gimli::constants::DW_TAG_variable => {
                        if let Some(name) = self.extract_name(self.dwarf, &unit, entry)? {
                            let flags = crate::core::IndexFlags {
                                is_static: self.is_static_symbol(entry).unwrap_or(false),
                                ..Default::default()
                            };

                            let address_ranges = if flags.is_static {
                                self.extract_variable_address(entry)
                                    .ok()
                                    .flatten()
                                    .map(|addr| vec![(addr, addr)])
                                    .unwrap_or_default()
                            } else {
                                Vec::new()
                            };

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(self.dwarf, &unit, entry),
                                address_ranges,
                            };

                            variables.entry(name).or_default().push(index_entry);
                        }
                    }
                    _ => {} // Skip other DIE types
                }
            }
        }

        let lightweight_index =
            LightweightIndex::from_builder_data(functions.clone(), variables.clone());

        debug!(
            "Completed debug_info parsing for {}: {} functions, {} variables",
            module_path,
            functions.len(),
            variables.len()
        );

        Ok(DebugParseResult {
            lightweight_index,
            functions_count: functions.len(),
            variables_count: variables.len(),
        })
    }

    /// Combine parallel parse results into unified result
    pub fn combine_parallel_results(
        line_result: LineParseResult,
        info_result: DebugParseResult,
        module_path: String,
    ) -> DwarfParseResult {
        debug!("Assembling parallel parse results for: {}", module_path);

        let LineParseResult {
            line_mapping,
            scoped_file_manager,
            compilation_units,
            line_entries_count,
            files_count,
        } = line_result;

        let stats = DwarfParseStats {
            total_functions: info_result.functions_count,
            total_variables: info_result.variables_count,
            total_line_entries: line_entries_count,
            total_files: files_count,
        };

        DwarfParseResult {
            lightweight_index: info_result.lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units,
            stats,
        }
    }

    // ===== Static methods for parallel processing =====

    /// Static version of extract_file_info_from_line_program for parallel use
    fn extract_file_info_from_line_program_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
    ) -> Result<CompilationUnit> {
        let cu_name = Self::extract_cu_name_from_dwarf(dwarf, unit)
            .unwrap_or_else(|| format!("unknown_cu_{:?}", unit.header.offset()));

        debug!("Extracting files from compilation unit: {}", cu_name);

        let header = line_program.header();
        let mut compilation_unit = CompilationUnit {
            base_directory: Self::extract_comp_dir_from_dwarf(dwarf, unit)
                .unwrap_or_else(|| ".".to_string()),
            include_directories: Vec::new(),
            files: Vec::new(),
        };

        // Extract include directories
        compilation_unit.include_directories = header
            .include_directories()
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let path_str = dwarf
                    .attr_string(unit, *path)
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| format!("unknown_dir_{i}"));
                debug!("Include directory [{}]: '{}'", i + 1, path_str);
                path_str
            })
            .collect();

        // Extract file entries
        for (file_index, file_entry) in header.file_names().iter().enumerate() {
            match Self::extract_source_file_static(
                dwarf,
                unit,
                file_index as u64,
                file_entry,
                &cu_name,
                compilation_unit.base_directory.as_str(),
                &compilation_unit.include_directories,
            ) {
                Ok(source_file) => {
                    compilation_unit.files.push(source_file);
                }
                Err(e) => {
                    debug!("Skipping file entry {}: {}", file_index, e);
                }
            }
        }

        debug!(
            "Extracted {} files from compilation unit {}",
            compilation_unit.files.len(),
            cu_name
        );

        Ok(compilation_unit)
    }

    fn extract_cu_name_from_dwarf(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let (_, entry) = entries.next_dfs().ok()??;

        if let Ok(Some(name_attr)) = entry.attr_value(gimli::constants::DW_AT_name) {
            if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                return Some(name.to_string_lossy().into_owned());
            }
        }

        None
    }

    fn extract_comp_dir_from_dwarf(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let (_, entry) = entries.next_dfs().ok()??;

        if let Ok(Some(comp_dir_attr)) = entry.attr_value(gimli::constants::DW_AT_comp_dir) {
            if let Ok(comp_dir) = dwarf.attr_string(unit, comp_dir_attr) {
                return Some(comp_dir.to_string_lossy().into_owned());
            }
        }

        None
    }

    fn extract_source_file_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianSlice<'static, LittleEndian>>,
        compilation_unit: &str,
        base_directory: &str,
        include_directories: &[String],
    ) -> anyhow::Result<SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        let directory_path = directory_from_index(
            unit.header.version(),
            base_directory,
            include_directories,
            dir_index,
        );

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        let full_path = resolve_file_path(
            unit.header.version(),
            base_directory,
            include_directories,
            dir_index,
            &filename,
        );

        debug!(
            "extract_source_file_static: cu='{}', file_index={}, dir_index={}, directory_path='{}', filename='{}', full_path='{}'",
            compilation_unit, file_index, dir_index, directory_path, filename, full_path
        );

        Ok(SourceFile {
            directory_path,
            filename,
            full_path,
        })
    }
}

//! Unified DWARF parser - true single-pass parsing

use crate::{
    core::{IndexEntry, Result},
    data::{
        CompilationUnit, LightweightFileIndex, LightweightIndex, LineMappingTable,
        ScopedFileIndexManager, SourceFile, SourceFileManager,
    },
    parser::RangeExtractor,
};
use gimli::{DebugInfoOffset, EndianSlice, LittleEndian};
use std::collections::HashMap;
use tracing::debug;

/// Complete result of DWARF parsing
pub struct DwarfParseResult {
    pub lightweight_index: LightweightIndex,
    pub line_mapping: LineMappingTable,
    pub source_file_manager: SourceFileManager,
    pub scoped_file_manager: Option<ScopedFileIndexManager>, // New optimized file index
    pub stats: DwarfParseStats,
}

/// Result of line information parsing (for parallel processing)
pub struct LineParseResult {
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub line_entries_count: usize,
    pub files_count: usize,
    pub compilation_units_count: usize,
    pub compilation_unit_names: Vec<String>,
}

/// Result of debug information parsing (for parallel processing)
pub struct DebugParseResult {
    pub lightweight_index: LightweightIndex,
    pub functions_count: usize,
    pub variables_count: usize,
}

/// Parsing statistics for logging and debugging
#[derive(Debug, Clone)]
pub struct DwarfParseStats {
    pub module_path: String,
    pub total_functions: usize,
    pub debug_info_functions: usize,
    pub symbol_table_functions: usize,
    pub total_variables: usize,
    pub total_line_entries: usize,
    pub total_files: usize,
    pub total_compilation_units: usize,
    pub compilation_unit_names: Vec<String>,
}

/// Unified DWARF parser - parses everything in optimized single pass
pub struct DwarfParser<'a> {
    dwarf: &'a gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
}

/// Internal builder for accumulating parse results
struct ParseResultBuilder {
    // For LightweightIndex
    functions: HashMap<String, Vec<IndexEntry>>,
    variables: HashMap<String, Vec<IndexEntry>>,

    // For stats
    total_functions: usize,
    debug_info_functions: usize,
    symbol_table_functions: usize,

    // For LineMappingTable
    line_entries: Vec<crate::core::LineEntry>,

    // For SourceFileManager
    compilation_units: HashMap<String, CompilationUnit>,
    files_by_index: HashMap<(String, u64), SourceFile>,
    total_files: usize,
    total_compilation_units: usize,

    // For ScopedFileIndexManager (optimized)
    scoped_file_manager: ScopedFileIndexManager,

    // For stats
    compilation_unit_names: Vec<String>,
}

impl ParseResultBuilder {
    fn new() -> Self {
        Self {
            functions: HashMap::new(),
            variables: HashMap::new(),
            total_functions: 0,
            debug_info_functions: 0,
            symbol_table_functions: 0,
            line_entries: Vec::new(),
            compilation_units: HashMap::new(),
            files_by_index: HashMap::new(),
            total_files: 0,
            total_compilation_units: 0,
            scoped_file_manager: ScopedFileIndexManager::new(),
            compilation_unit_names: Vec::new(),
        }
    }

    /// Build final data structures from accumulated results
    fn build(self, module_path: String) -> DwarfParseResult {
        let lightweight_index =
            LightweightIndex::from_builder_data(self.functions.clone(), self.variables.clone());

        // Post-process line entries to fill in file paths using scoped file manager
        let processed_line_entries =
            Self::post_process_line_entries(&self.line_entries, &self.scoped_file_manager);

        let line_mapping = LineMappingTable::from_entries(processed_line_entries);

        let source_file_manager = SourceFileManager::from_builder_data(
            self.compilation_units.clone(),
            self.files_by_index.clone(),
            self.total_files,
            self.total_compilation_units,
        );

        let stats = DwarfParseStats {
            module_path,
            total_functions: self.functions.len(),
            debug_info_functions: self.debug_info_functions,
            symbol_table_functions: self.symbol_table_functions,
            total_variables: self.variables.len(),
            total_line_entries: self.line_entries.len(),
            total_files: self.total_files,
            total_compilation_units: self.total_compilation_units,
            compilation_unit_names: self.compilation_unit_names,
        };

        DwarfParseResult {
            lightweight_index,
            line_mapping,
            source_file_manager,
            scoped_file_manager: Some(self.scoped_file_manager), // Use built scoped manager
            stats,
        }
    }

    /// Post-process line entries to fill in file paths using intelligent file selection
    fn post_process_line_entries(
        line_entries: &[crate::core::LineEntry],
        scoped_manager: &ScopedFileIndexManager,
    ) -> Vec<crate::core::LineEntry> {
        line_entries
            .iter()
            .map(|entry| {
                // If file_path is already filled, keep it; otherwise resolve it
                let file_path = if entry.file_path.is_empty() {
                    DwarfParser::resolve_file_path_with_smart_selection(
                        scoped_manager,
                        &entry.compilation_unit,
                        entry.file_index,
                    )
                } else {
                    entry.file_path.clone()
                };

                // Create new entry with resolved file path
                crate::core::LineEntry {
                    address: entry.address,
                    file_path,
                    file_index: entry.file_index,
                    compilation_unit: entry.compilation_unit.clone(),
                    line: entry.line,
                    column: entry.column,
                    is_stmt: entry.is_stmt,
                    prologue_end: entry.prologue_end,
                    epilogue_begin: entry.epilogue_begin,
                    end_sequence: entry.end_sequence,
                }
            })
            .collect()
    }
}

impl<'a> DwarfParser<'a> {
    pub fn new(dwarf: &'a gimli::Dwarf<EndianSlice<'static, LittleEndian>>) -> Self {
        Self { dwarf }
    }


    /// Process single compilation unit - decoupled debug_line and debug_info processing
    /// (Architecture ready for parallelization, currently sequential for simplicity)
    fn process_compilation_unit(
        &self,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        // Phase 1: Process debug_line section (file info + line entries)
        if let Some(ref line_program) = unit.line_program {
            // Extract file information
            let compilation_unit =
                self.extract_file_info_from_line_program(&self.dwarf, unit, line_program)?;

            // Extract line entries (file_index only, file_path resolved later via ScopedFileIndexManager)
            self.extract_line_entries(line_program, &compilation_unit.name, builder)?;

            // Add to file manager structures
            self.add_compilation_unit_to_builder(compilation_unit, builder);
        }

        // Phase 2: Process debug_info section (functions + variables)
        self.parse_dies(unit, unit_offset, builder)?;

        Ok(())
    }

    /// Single DIE traversal - extract functions, variables, etc.
    fn parse_dies(
        &self,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        let mut entries = unit.entries();
        let mut die_count = 0;

        while let Some((_, entry)) = entries.next_dfs()? {
            die_count += 1;
            self.process_die_entry(&self.dwarf, unit, entry, unit_offset, builder)?;
        }

        debug!(
            "Processed {} DIEs for unit at offset {:?}",
            die_count, unit_offset
        );
        Ok(())
    }

    /// Process single DIE - extract all relevant information
    fn process_die_entry(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        match entry.tag() {
            gimli::constants::DW_TAG_subprogram => {
                if let Some(name) = self.extract_name(dwarf, unit, entry)? {
                    debug!("Found function: '{}' at offset {:?}", name, entry.offset());

                    // Add to cooked index (GDB-style)
                    let mut flags = crate::core::IndexFlags::default();
                    flags.is_static = self.is_static_symbol(entry).unwrap_or(false);
                    flags.is_main = self.is_main_function(entry, &name).unwrap_or(false);

                    // Extract address information - now supports multiple ranges
                    let mut address_ranges = self.extract_address_ranges(dwarf, unit, entry)?;

                    // If no ranges found, try to get single address and create minimal range
                    if address_ranges.is_empty() {
                        let function_address = self.extract_function_address(entry)?;
                        if let Some(addr) = function_address {
                            // Use a minimal range for functions without high_pc
                            // We'll use addr+1 as a placeholder (actual size unknown)
                            address_ranges.push((addr, addr + 1));
                            debug!("Function '{}' has low_pc 0x{:x} but no high_pc, using minimal range", name, addr);
                        }
                    }

                    let index_entry = IndexEntry {
                        name: name.clone(),
                        die_offset: entry.offset(),
                        unit_offset,
                        tag: entry.tag(),
                        flags,
                        language: self.extract_language(dwarf, unit, entry),
                        address_ranges: address_ranges.clone(),
                    };
                    builder
                        .functions
                        .entry(name.clone())
                        .or_default()
                        .push(index_entry);

                    // Update stats
                    if !address_ranges.is_empty() {
                        let address = address_ranges[0].0;
                        debug!("Function '{}' has address: 0x{:x}", name, address);
                        builder.total_functions += 1;
                        builder.debug_info_functions += 1;
                    } else {
                        debug!(
                            "Function '{}' has no address (might be declaration only)",
                            name
                        );
                    }
                }
            }
            gimli::constants::DW_TAG_inlined_subroutine => {
                if let Some(name) = self.extract_name(dwarf, unit, entry)? {
                    debug!(
                        "Found inlined function: '{}' at offset {:?}",
                        name,
                        entry.offset()
                    );

                    // Add to cooked index - inline functions need to be indexed too!
                    let mut flags = crate::core::IndexFlags::default();
                    flags.is_inline = true;

                    // Extract proper address ranges for inline instance
                    // Inline functions should have DW_AT_low_pc/high_pc or DW_AT_ranges
                    let address_ranges = self.extract_address_ranges(dwarf, unit, entry)?;

                    // Log if inline function has no ranges
                    if address_ranges.is_empty() {
                        tracing::debug!(
                            "Inline function '{}' has no address ranges - may be optimized out",
                            name
                        );
                    }

                    let index_entry = IndexEntry {
                        name: name.clone(),
                        die_offset: entry.offset(),
                        unit_offset,
                        tag: entry.tag(),
                        flags,
                        language: self.extract_language(dwarf, unit, entry),
                        address_ranges: address_ranges.clone(),
                    };

                    // Add to functions map (inline functions are also functions)
                    builder
                        .functions
                        .entry(name.clone())
                        .or_default()
                        .push(index_entry);

                    // Update stats for inline functions
                    if !address_ranges.is_empty() {
                        let address = address_ranges[0].0;
                        debug!("Inline function '{}' has address: 0x{:x}", name, address);
                        builder.total_functions += 1;
                        builder.debug_info_functions += 1;
                    }
                }
            }
            gimli::constants::DW_TAG_variable => {
                if let Some(name) = self.extract_name(dwarf, unit, entry)? {
                    let mut flags = crate::core::IndexFlags::default();
                    flags.is_static = self.is_static_symbol(entry).unwrap_or(false);

                    // Extract address for static variables
                    let address_ranges = if flags.is_static {
                        self.extract_variable_address(entry)
                            .ok()
                            .flatten()
                            .map(|addr| vec![(addr, addr)])
                            .unwrap_or_else(Vec::new)
                    } else {
                        Vec::new()
                    };

                    let index_entry = IndexEntry {
                        name: name.clone(),
                        die_offset: entry.offset(),
                        unit_offset,
                        tag: entry.tag(),
                        flags,
                        language: self.extract_language(dwarf, unit, entry),
                        address_ranges: address_ranges.clone(),
                    };
                    builder.variables.entry(name).or_default().push(index_entry);
                }
            }
            _ => {} // Skip other DIE types
        }

        Ok(())
    }

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

    /// Extract address range from DIE (for functions)
    /// Legacy function - returns single range for compatibility
    fn extract_address_range(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<(u64, u64)>> {
        // Use RangeExtractor for unified logic
        RangeExtractor::extract_single_range(entry)
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

    /// Extract function address from DIE (simple version for backward compatibility)
    fn extract_function_address(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<u64>> {
        // Just get the low_pc for backward compatibility
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_low_pc)? {
            if let gimli::AttributeValue::Addr(addr) = attr.value() {
                return Ok(Some(addr));
            }
        }

        Ok(None)
    }

    /// Extract file information from line program
    fn extract_file_info_from_line_program(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
    ) -> Result<CompilationUnit> {
        // Get compilation unit name
        let cu_name =
            Self::extract_cu_name(dwarf, unit).unwrap_or_else(|| "unknown".to_string());

        debug!("Extracting files from compilation unit: {}", cu_name);

        let header = line_program.header();

        let mut compilation_unit = CompilationUnit {
            name: cu_name.clone(),
            base_directory: Self::extract_comp_dir(dwarf, unit).unwrap_or_default(),
            include_directories: Vec::new(),
            files: Vec::new(),
            dwarf_version: header.version(),
        };

        // Extract include directories
        for (dir_index, dir_entry) in header.include_directories().into_iter().enumerate() {
            if let Ok(dir_path) = dwarf.attr_string(unit, *dir_entry) {
                let dir_str = dir_path.to_string_lossy().into_owned();
                debug!("Include directory [{}]: '{}'", dir_index + 1, dir_str);
                compilation_unit.include_directories.push(dir_str);
            }
        }

        // Extract files from line program
        for (file_index, file_entry) in header.file_names().into_iter().enumerate() {
            match Self::extract_source_file(
                dwarf,
                unit,
                file_index as u64,
                file_entry,
                &cu_name,
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

    /// Extract line entries from line program (file_index only, file_path resolved later)
    fn extract_line_entries(
        &self,
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
        compilation_unit_name: &str,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        let (line_program, sequences) = line_program.clone().sequences()?;

        for seq in sequences {
            let mut rows = line_program.resume_from(&seq);
            while let Some((_, line_row)) = rows.next_row()? {
                let column = match line_row.column() {
                    gimli::ColumnType::LeftEdge => 0,
                    gimli::ColumnType::Column(x) => x.get(),
                };

                // Resolve file path using scoped file manager with intelligent file selection
                let file_path = Self::resolve_file_path_with_smart_selection(
                    &builder.scoped_file_manager,
                    compilation_unit_name,
                    line_row.file_index(),
                );

                let line_entry = crate::core::LineEntry {
                    address: line_row.address(),
                    file_path,
                    file_index: line_row.file_index(),
                    compilation_unit: compilation_unit_name.to_string(),
                    line: line_row.line().map(|l| l.get()).unwrap_or(0),
                    column,
                    is_stmt: line_row.is_stmt(),
                    prologue_end: line_row.prologue_end(),
                    epilogue_begin: line_row.epilogue_begin(),
                    end_sequence: line_row.end_sequence(),
                };

                builder.line_entries.push(line_entry);
            }
        }

        Ok(())
    }

    /// Add compilation unit to builder
    fn add_compilation_unit_to_builder(
        &self,
        compilation_unit: CompilationUnit,
        builder: &mut ParseResultBuilder,
    ) {
        debug!(
            "Adding compilation unit: {} with {} files",
            compilation_unit.name,
            compilation_unit.files.len()
        );

        let cu_name = compilation_unit.name.clone(); // Clone once

        // Update file indices for fast lookup (with compilation unit scope)
        for file in &compilation_unit.files {
            builder
                .files_by_index
                .insert((cu_name.clone(), file.file_index), file.clone());
            builder.total_files += 1;
        }

        // Add to optimized ScopedFileIndexManager
        let mut file_index = LightweightFileIndex::new(
            Some(compilation_unit.base_directory.clone()),
            compilation_unit.dwarf_version,
        );

        // Add directories
        for directory in &compilation_unit.include_directories {
            file_index.add_directory(directory.clone());
        }

        // Add files
        for file in &compilation_unit.files {
            file_index.add_file_entry(file.file_index, file.directory_index, file.filename.clone());
        }

        builder
            .scoped_file_manager
            .add_compilation_unit(cu_name.clone(), file_index);

        builder.compilation_unit_names.push(cu_name.clone());
        builder.compilation_units.insert(cu_name, compilation_unit);
        builder.total_compilation_units += 1;
    }

    // Helper methods
    fn extract_cu_name(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        if let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_compile_unit {
                if let Some(name_attr) = entry.attr_value(gimli::DW_AT_name).ok().flatten() {
                    if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                        return Some(name.to_string_lossy().into_owned());
                    }
                }
            }
        }
        None
    }

    fn extract_comp_dir(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        if let Ok(Some((_, entry))) = entries.next_dfs() {
            if entry.tag() == gimli::DW_TAG_compile_unit {
                if let Some(comp_dir_attr) = entry.attr_value(gimli::DW_AT_comp_dir).ok().flatten()
                {
                    if let Ok(comp_dir) = dwarf.attr_string(unit, comp_dir_attr) {
                        return Some(comp_dir.to_string_lossy().into_owned());
                    }
                }
            }
        }
        None
    }

    fn extract_source_file(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianSlice<'static, LittleEndian>>,
        compilation_unit: &str,
        include_directories: &[String],
    ) -> anyhow::Result<SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        let directory_path = if dir_index == 0 {
            Self::extract_comp_dir(dwarf, unit).unwrap_or_else(|| ".".to_string())
        } else {
            let actual_index = (dir_index - 1) as usize;
            include_directories
                .get(actual_index)
                .cloned()
                .unwrap_or_else(|| ".".to_string())
        };

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        // Create full path - handle cases where filename may already contain relative path
        let full_path = if directory_path == "." || directory_path.is_empty() {
            // If filename already contains path separators, use it as-is
            // Otherwise it's just a basename and should stay as-is
            filename.clone()
        } else if filename.starts_with('/') {
            // Absolute path in filename, use as-is
            filename.clone()
        } else {
            // Relative path: combine directory + filename
            format!("{}/{}", directory_path, filename)
        };

        tracing::debug!(
            "extract_source_file: file_index={}, dir_index={}, directory_path='{}', filename='{}', full_path='{}'",
            file_index, dir_index, directory_path, filename, full_path
        );

        Ok(SourceFile {
            file_index,
            compilation_unit: compilation_unit.to_string(),
            directory_index: dir_index,
            directory_path,
            filename,
            full_path,
        })
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
                    match lang_attr.value() {
                        gimli::AttributeValue::Language(lang) => return Some(lang),
                        _ => {}
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
        let mut compilation_unit_names = Vec::new();
        let mut total_files = 0;
        let mut total_compilation_units = 0;

        // Parse all compilation units for line information only
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = self.dwarf.unit(header)?;

            if let Some(ref line_program) = unit.line_program {
                // Get compilation unit name
                let cu_name = Self::extract_cu_name(&self.dwarf, &unit)
                    .unwrap_or_else(|| "unknown".to_string());
                let comp_dir = Self::extract_comp_dir(&self.dwarf, &unit);

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
                for (file_idx, file_entry) in header.file_names().into_iter().enumerate() {
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

                let (files_count, _) = file_index.get_stats();
                total_files += files_count;
                total_compilation_units += 1;
                compilation_unit_names.push(cu_name.clone());

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
            total_compilation_units
        );

        Ok(LineParseResult {
            line_mapping,
            scoped_file_manager,
            line_entries_count: line_entries.len(),
            files_count: total_files,
            compilation_units_count: total_compilation_units,
            compilation_unit_names,
        })
    }

    /// Parse debug_info sections (for parallel processing)
    pub fn parse_debug_info(&self, module_path: &str) -> Result<DebugParseResult> {
        debug!("Starting debug_info-only parsing for: {}", module_path);

        let mut functions: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        let mut variables: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        let mut total_functions = 0;

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
                        if let Some(name) = self.extract_name(&self.dwarf, &unit, entry)? {
                            let mut flags = crate::core::IndexFlags::default();
                            flags.is_static = self.is_static_symbol(entry).unwrap_or(false);
                            flags.is_main = self.is_main_function(entry, &name).unwrap_or(false);

                            let address_ranges =
                                self.extract_address_ranges(&self.dwarf, &unit, entry)?;

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(&self.dwarf, &unit, entry),
                                address_ranges: address_ranges.clone(),
                            };

                            functions.entry(name).or_default().push(index_entry);

                            if !address_ranges.is_empty() {
                                total_functions += 1;
                            }
                        }
                    }
                    gimli::constants::DW_TAG_inlined_subroutine => {
                        if let Some(name) = self.extract_name(&self.dwarf, &unit, entry)? {
                            let mut flags = crate::core::IndexFlags::default();
                            flags.is_inline = true;

                            let address_ranges =
                                self.extract_address_ranges(&self.dwarf, &unit, entry)?;

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(&self.dwarf, &unit, entry),
                                address_ranges: address_ranges.clone(),
                            };

                            functions.entry(name).or_default().push(index_entry);

                            if !address_ranges.is_empty() {
                                total_functions += 1;
                            }
                        }
                    }
                    gimli::constants::DW_TAG_variable => {
                        if let Some(name) = self.extract_name(&self.dwarf, &unit, entry)? {
                            let mut flags = crate::core::IndexFlags::default();
                            flags.is_static = self.is_static_symbol(entry).unwrap_or(false);

                            let address_ranges = if flags.is_static {
                                self.extract_variable_address(entry)
                                    .ok()
                                    .flatten()
                                    .map(|addr| vec![(addr, addr)])
                                    .unwrap_or_else(Vec::new)
                            } else {
                                Vec::new()
                            };

                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(&self.dwarf, &unit, entry),
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

        // Create SourceFileManager from ScopedFileIndexManager data
        // We need to reconstruct the compilation units and files_by_index
        let mut compilation_units = HashMap::new();
        let mut files_by_index = HashMap::new();

        // Extract compilation unit info from ScopedFileIndexManager
        // Convert lightweight file manager to old format for compatibility
        for cu_name in &line_result.compilation_unit_names {
            // TODO: This is a temporary compatibility layer - eventually we'll use the lightweight index directly

            // Create minimal compilation unit (files managed by ScopedFileIndexManager)
            let compilation_unit = CompilationUnit {
                name: cu_name.clone(),
                base_directory: String::new(),
                include_directories: Vec::new(),
                files: Vec::new(), // Files managed by ScopedFileIndexManager now
                dwarf_version: 4,  // Default for parallel compatibility
            };

            compilation_units.insert(cu_name.clone(), compilation_unit);
        }

        let source_file_manager = SourceFileManager::from_builder_data(
            compilation_units,
            files_by_index,
            line_result.files_count,
            line_result.compilation_units_count,
        );

        let stats = DwarfParseStats {
            module_path,
            total_functions: info_result.functions_count,
            debug_info_functions: info_result.functions_count,
            symbol_table_functions: 0,
            total_variables: info_result.variables_count,
            total_line_entries: line_result.line_entries_count,
            total_files: line_result.files_count,
            total_compilation_units: line_result.compilation_units_count,
            compilation_unit_names: line_result.compilation_unit_names,
        };

        DwarfParseResult {
            lightweight_index: info_result.lightweight_index,
            line_mapping: line_result.line_mapping,
            source_file_manager,
            scoped_file_manager: Some(line_result.scoped_file_manager), // Use optimized scoped file manager
            stats,
        }
    }

    // ===== Static methods for parallel processing =====

    /// Static version of extract_file_info_from_line_program for parallel use
    fn extract_file_info_from_line_program_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
    ) -> Result<crate::data::CompilationUnit> {
        let cu_name = Self::extract_cu_name_from_dwarf(dwarf, unit)
            .unwrap_or_else(|| format!("unknown_cu_{:?}", unit.header.offset()));

        debug!("Extracting files from compilation unit: {}", cu_name);

        let header = line_program.header();
        let mut compilation_unit = crate::data::CompilationUnit {
            name: cu_name.clone(),
            base_directory: Self::extract_comp_dir_from_dwarf(dwarf, unit)
                .unwrap_or_else(|| ".".to_string()),
            include_directories: Vec::new(),
            files: Vec::new(),
            dwarf_version: header.version(),
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
                    .unwrap_or_else(|_| format!("unknown_dir_{}", i));
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

    /// Static version of extract_line_entries for parallel use
    fn extract_line_entries_static(
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
        compilation_unit_name: &str,
    ) -> Result<Vec<crate::core::LineEntry>> {
        let (line_program, sequences) = line_program.clone().sequences()?;
        let mut line_entries = Vec::new();

        for seq in sequences {
            let mut rows = line_program.resume_from(&seq);
            while let Some((_, line_row)) = rows.next_row()? {
                let column = match line_row.column() {
                    gimli::ColumnType::LeftEdge => 0,
                    gimli::ColumnType::Column(x) => x.get(),
                };

                // File path will be resolved later in post-processing
                // (Static method doesn't have access to scoped file manager)
                let file_path = String::new();

                let line_entry = crate::core::LineEntry {
                    address: line_row.address(),
                    file_path,
                    file_index: line_row.file_index(),
                    compilation_unit: compilation_unit_name.to_string(),
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

        Ok(line_entries)
    }

    /// Static version of parse_dies for parallel use
    fn parse_dies_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
    ) -> Result<Vec<crate::core::IndexEntry>> {
        let mut entries = unit.entries();
        let mut index_entries = Vec::new();

        while let Some((_, entry)) = entries.next_dfs()? {
            match entry.tag() {
                gimli::constants::DW_TAG_subprogram => {
                    if let Some(name) = Self::extract_name_static(dwarf, unit, entry)? {
                        debug!("Found function: '{}' at offset {:?}", name, entry.offset());

                        let address_ranges =
                            crate::parser::RangeExtractor::extract_all_ranges(entry, unit, dwarf)?;

                        let index_entry = crate::core::IndexEntry {
                            name: name.clone(),
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: gimli::constants::DW_TAG_subprogram,
                            flags: crate::core::IndexFlags::default(),
                            language: None,
                            address_ranges,
                        };
                        index_entries.push(index_entry);
                    }
                }
                gimli::constants::DW_TAG_variable => {
                    if let Some(name) = Self::extract_name_static(dwarf, unit, entry)? {
                        debug!("Found variable: '{}' at offset {:?}", name, entry.offset());

                        let index_entry = crate::core::IndexEntry {
                            name,
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: gimli::constants::DW_TAG_variable,
                            flags: crate::core::IndexFlags::default(),
                            language: None,
                            address_ranges: Vec::new(), // Variables may not have fixed addresses
                        };
                        index_entries.push(index_entry);
                    }
                }
                _ => {}
            }
        }

        Ok(index_entries)
    }

    /// Static helper methods

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

    fn extract_name_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        if let Ok(Some(name_attr)) = entry.attr_value(gimli::constants::DW_AT_name) {
            if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                return Ok(Some(name.to_string_lossy().into_owned()));
            }
        }

        Ok(None)
    }

    fn extract_source_file_static(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianSlice<'static, LittleEndian>>,
        compilation_unit: &str,
        include_directories: &[String],
    ) -> anyhow::Result<crate::data::SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        let directory_path = if dir_index == 0 {
            Self::extract_comp_dir_from_dwarf(dwarf, unit).unwrap_or_else(|| ".".to_string())
        } else {
            let actual_index = (dir_index - 1) as usize;
            include_directories
                .get(actual_index)
                .cloned()
                .unwrap_or_else(|| ".".to_string())
        };

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        // Create full path
        let full_path = if directory_path == "." || directory_path.is_empty() {
            filename.clone()
        } else if filename.starts_with('/') {
            filename.clone()
        } else {
            format!("{}/{}", directory_path, filename)
        };

        debug!(
            "extract_source_file: file_index={}, dir_index={}, directory_path='{}', filename='{}', full_path='{}'",
            file_index, dir_index, directory_path, filename, full_path
        );

        Ok(crate::data::SourceFile {
            file_index,
            compilation_unit: compilation_unit.to_string(),
            directory_index: dir_index,
            directory_path,
            filename,
            full_path,
        })
    }

    /// Resolve file path with intelligent file selection
    /// If the resolved path points to a header file, try to find the main source file
    fn resolve_file_path_with_smart_selection(
        scoped_manager: &ScopedFileIndexManager,
        compilation_unit: &str,
        file_index: u64,
    ) -> String {
        // First, try to resolve the file path normally
        let resolved_path = scoped_manager
            .lookup_by_scoped_index(compilation_unit, file_index)
            .map(|file_info| file_info.full_path)
            .unwrap_or_else(|| String::new());

        // If the path is empty or points to a header file, try to find a better alternative
        if resolved_path.is_empty() || Self::is_header_file(&resolved_path) {
            if let Some(alternative_path) =
                Self::find_main_source_file_in_cu(scoped_manager, compilation_unit)
            {
                tracing::debug!(
                    "FastParser: replaced header/empty '{}' with main source '{}' in CU '{}'",
                    resolved_path,
                    alternative_path,
                    compilation_unit
                );
                return alternative_path;
            }
        }

        resolved_path
    }

    /// Check if a file path is a header file
    fn is_header_file(file_path: &str) -> bool {
        file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/")
    }

    /// Find the main source file in the compilation unit
    fn find_main_source_file_in_cu(
        scoped_manager: &ScopedFileIndexManager,
        compilation_unit: &str,
    ) -> Option<String> {
        if let Some(cu_file_index) = scoped_manager.get_cu_file_index(compilation_unit) {
            tracing::debug!(
                "FastParser: searching for main source file in CU '{}'",
                compilation_unit
            );

            // First priority: look for files that match the compilation unit name
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !Self::is_header_file(&full_path) {
                        // Check if this file matches the compilation unit name
                        if let Some(cu_stem) = std::path::Path::new(compilation_unit).file_stem() {
                            if let Some(file_stem) = std::path::Path::new(&full_path).file_stem() {
                                if cu_stem == file_stem {
                                    tracing::debug!(
                                        "FastParser: found matching source file '{}'",
                                        full_path
                                    );
                                    return Some(full_path);
                                }
                            }
                        }
                    }
                }
            }

            // Second priority: any non-header file
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !Self::is_header_file(&full_path) {
                        tracing::debug!(
                            "FastParser: found alternative source file '{}'",
                            full_path
                        );
                        return Some(full_path);
                    }
                }
            }
        }

        None
    }
}

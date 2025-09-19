//! Unified DWARF parser - true single-pass parsing

use crate::{
    core::{IndexEntry, Result},
    data::{CompilationUnit, LightweightIndex, LineMappingTable, SourceFile, SourceFileManager},
    parser::RangeExtractor,
};
use gimli::{DebugInfoOffset, EndianSlice, LittleEndian};
use std::collections::HashMap;
use tracing::{debug, info};

/// Complete result of DWARF parsing
pub struct DwarfParseResult {
    pub lightweight_index: LightweightIndex,
    pub line_mapping: LineMappingTable,
    pub source_file_manager: SourceFileManager,
    pub stats: DwarfParseStats,
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
            compilation_unit_names: Vec::new(),
        }
    }

    /// Build final data structures from accumulated results
    fn build(self, module_path: String) -> DwarfParseResult {
        let lightweight_index =
            LightweightIndex::from_builder_data(self.functions.clone(), self.variables.clone());

        let line_mapping = LineMappingTable::from_entries(self.line_entries.clone());

        let source_file_manager = SourceFileManager::from_builder_data(
            self.compilation_units,
            self.files_by_index,
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
            stats,
        }
    }
}

impl<'a> DwarfParser<'a> {
    pub fn new(dwarf: &'a gimli::Dwarf<EndianSlice<'static, LittleEndian>>) -> Self {
        Self { dwarf }
    }

    /// Single-pass parse of all DWARF information
    pub fn parse_all(&self, module_path: &str) -> Result<DwarfParseResult> {
        debug!("Starting unified DWARF parsing for: {}", module_path);

        let mut builder = ParseResultBuilder::new();

        // Single pass through all compilation units
        let mut units = self.dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = self.dwarf.unit(header)?;

            let unit_offset = match header.offset() {
                gimli::UnitSectionOffset::DebugInfoOffset(offset) => offset,
                _ => continue,
            };

            // Process this compilation unit (all information in one pass)
            self.process_compilation_unit(&unit, unit_offset, &mut builder)?;
        }

        // Create result with stats
        let result = builder.build(module_path.to_string());

        // Log detailed statistics
        info!(
            "Completed unified DWARF parsing for {}: {} functions ({} from debug_info), \
            {} variables, {} line entries, {} files, {} compilation units",
            module_path,
            result.stats.total_functions,
            result.stats.debug_info_functions,
            result.stats.total_variables,
            result.stats.total_line_entries,
            result.stats.total_files,
            result.stats.total_compilation_units
        );

        // Log compilation unit names (first few)
        if !result.stats.compilation_unit_names.is_empty() {
            let sample_units: Vec<&str> = result
                .stats
                .compilation_unit_names
                .iter()
                .take(3)
                .map(|s| s.as_str())
                .collect();
            debug!(
                "Compilation units in {}: {} (showing first {})",
                module_path,
                sample_units.join(", "),
                sample_units.len()
            );

            if result.stats.compilation_unit_names.len() > 3 {
                debug!(
                    "... and {} more compilation units",
                    result.stats.compilation_unit_names.len() - 3
                );
            }
        }

        Ok(result)
    }

    /// Process single compilation unit - extract ALL information in one pass
    fn process_compilation_unit(
        &self,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        // Step 1: Parse line program first (provides file mapping)
        let file_index_map = self.parse_line_program(unit, builder)?;

        // Step 2: Single DIE traversal (uses file mapping from step 1)
        self.parse_dies(unit, unit_offset, &file_index_map, builder)?;

        Ok(())
    }

    /// Parse line program and extract line entries + file information
    fn parse_line_program(
        &self,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        builder: &mut ParseResultBuilder,
    ) -> Result<HashMap<u64, String>> {
        let mut file_index_map = HashMap::new();

        if let Some(line_program) = unit.line_program.clone() {
            // Extract file information
            let compilation_unit =
                self.extract_file_info_from_line_program(&self.dwarf, unit, &line_program)?;

            // Build file index map for DIE processing
            for file in &compilation_unit.files {
                file_index_map.insert(file.file_index, file.full_path.clone());
            }

            // Extract line entries with file path mapping (pass compilation unit name for scoped file_index)
            self.extract_line_entries(
                &line_program,
                &file_index_map,
                &compilation_unit.name,
                builder,
            )?;

            // Add to file manager structures
            self.add_compilation_unit_to_builder(compilation_unit, builder);
        }

        Ok(file_index_map)
    }

    /// Single DIE traversal - extract functions, variables, etc.
    fn parse_dies(
        &self,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        unit_offset: DebugInfoOffset,
        file_index_map: &HashMap<u64, String>,
        builder: &mut ParseResultBuilder,
    ) -> Result<()> {
        let mut entries = unit.entries();
        let mut die_count = 0;

        while let Some((_, entry)) = entries.next_dfs()? {
            die_count += 1;
            self.process_die_entry(
                &self.dwarf,
                unit,
                entry,
                unit_offset,
                file_index_map,
                builder,
            )?;
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
        _file_index_map: &HashMap<u64, String>,
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
            Self::get_compilation_unit_name(dwarf, unit).unwrap_or_else(|| "unknown".to_string());

        debug!("Extracting files from compilation unit: {}", cu_name);

        let mut compilation_unit = CompilationUnit {
            name: cu_name.clone(),
            base_directory: Self::get_comp_dir(dwarf, unit).unwrap_or_default(),
            include_directories: Vec::new(),
            files: Vec::new(),
        };

        let header = line_program.header();

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

    /// Extract line entries from line program
    fn extract_line_entries(
        &self,
        line_program: &gimli::IncompleteLineProgram<EndianSlice<'static, LittleEndian>>,
        file_index_map: &HashMap<u64, String>,
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

                // Get file path from the map, fallback to empty string if not found
                let file_path = file_index_map
                    .get(&line_row.file_index())
                    .cloned()
                    .unwrap_or_else(|| {
                        tracing::warn!("File index {} not found in map", line_row.file_index());
                        String::new()
                    });

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

        // Update file indices for fast lookup (with compilation unit scope)
        for file in &compilation_unit.files {
            builder.files_by_index.insert(
                (compilation_unit.name.clone(), file.file_index),
                file.clone(),
            );
            builder.total_files += 1;
        }

        builder
            .compilation_units
            .insert(compilation_unit.name.clone(), compilation_unit.clone());
        builder.compilation_unit_names.push(compilation_unit.name);
        builder.total_compilation_units += 1;
    }

    // Helper methods
    fn get_compilation_unit_name(
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

    fn get_comp_dir(
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
            Self::get_comp_dir(dwarf, unit).unwrap_or_else(|| ".".to_string())
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
}

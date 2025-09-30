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
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[derive(Clone, Default)]
struct FunctionMetadata {
    name: Option<String>,
    is_inline: bool,
    is_linkage_name: bool,
    is_external: Option<bool>,
}

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

    fn extract_attr_string(
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        attr_value: gimli::AttributeValue<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<String>> {
        if let Ok(string) = dwarf.attr_string(unit, attr_value) {
            return Ok(Some(string.to_string_lossy().into_owned()));
        }
        Ok(None)
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

    fn extract_linkage_name(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<(String, bool)>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_linkage_name)? {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_MIPS_linkage_name)? {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        Ok(None)
    }

    fn extract_inline_flag(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_inline)? {
            if let gimli::AttributeValue::Inline(inline_attr) = attr.value() {
                return Ok(inline_attr == gimli::DW_INL_inlined
                    || inline_attr == gimli::DW_INL_declared_inlined);
            }
        }
        Ok(false)
    }

    fn resolve_function_metadata(
        &self,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        cache: &mut HashMap<gimli::UnitOffset, FunctionMetadata>,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<FunctionMetadata> {
        let offset = entry.offset();
        if let Some(cached) = cache.get(&offset) {
            return Ok(cached.clone());
        }

        if !visited.insert(offset) {
            return Ok(FunctionMetadata::default());
        }

        let mut metadata = FunctionMetadata::default();
        if let Some(name) = self.extract_name(dwarf, unit, entry)? {
            metadata.name = Some(name);
        } else if let Some((name, is_linkage)) = self.extract_linkage_name(dwarf, unit, entry)? {
            metadata.name = Some(name);
            metadata.is_linkage_name = is_linkage;
        }

        metadata.is_inline = Self::extract_inline_flag(entry)?;

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_external)? {
            if let gimli::AttributeValue::Flag(flag) = attr.value() {
                metadata.is_external = Some(flag);
            }
        }

        let mut merge_from_origin = |origin_offset: gimli::UnitOffset| -> Result<()> {
            if visited.contains(&origin_offset) {
                return Ok(());
            }

            let origin_entry = unit.entry(origin_offset)?;
            let origin_metadata =
                self.resolve_function_metadata(dwarf, unit, &origin_entry, cache, visited)?;

            if metadata.name.is_none() {
                metadata.name = origin_metadata.name.clone();
            }
            metadata.is_inline |= origin_metadata.is_inline;
            if metadata.is_external.is_none() {
                metadata.is_external = origin_metadata.is_external;
            }
            metadata.is_linkage_name |= origin_metadata.is_linkage_name;
            Ok(())
        };

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_abstract_origin)? {
            match attr.value() {
                gimli::AttributeValue::UnitRef(unit_ref) => {
                    merge_from_origin(unit_ref)?;
                }
                gimli::AttributeValue::DebugInfoRef(debug_info_ref) => {
                    if let Some(unit_ref) = debug_info_ref.to_unit_offset(&unit.header) {
                        merge_from_origin(unit_ref)?;
                    }
                }
                _ => {}
            }
        }

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_specification)? {
            match attr.value() {
                gimli::AttributeValue::UnitRef(unit_ref) => {
                    merge_from_origin(unit_ref)?;
                }
                gimli::AttributeValue::DebugInfoRef(debug_info_ref) => {
                    if let Some(unit_ref) = debug_info_ref.to_unit_offset(&unit.header) {
                        merge_from_origin(unit_ref)?;
                    }
                }
                _ => {}
            }
        }

        visited.remove(&offset);
        cache.insert(offset, metadata.clone());
        Ok(metadata)
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

    fn extract_entry_pc(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
    ) -> Result<Option<u64>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_entry_pc)? {
            if let gimli::AttributeValue::Addr(addr) = attr.value() {
                return Ok(Some(addr));
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

        // Build line mapping with canonical paths using the scoped file index manager
        let line_mapping =
            LineMappingTable::from_entries_with_scoped_manager(line_entries.clone(), &scoped_file_manager);

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
        let mut types: HashMap<String, Vec<IndexEntry>> = HashMap::new();
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
            let mut metadata_cache: HashMap<gimli::UnitOffset, FunctionMetadata> = HashMap::new();
            while let Some((_, entry)) = entries.next_dfs()? {
                match entry.tag() {
                    gimli::constants::DW_TAG_subprogram => {
                        let mut visited = HashSet::new();
                        let metadata = self.resolve_function_metadata(
                            self.dwarf,
                            &unit,
                            entry,
                            &mut metadata_cache,
                            &mut visited,
                        )?;
                        if let Some(name) = metadata.name.clone() {
                            let is_main = self.is_main_function(entry, &name).unwrap_or(false);
                            let is_static = metadata
                                .is_external
                                .map(|external| !external)
                                .unwrap_or_else(|| self.is_static_symbol(entry).unwrap_or(false));
                            let flags = crate::core::IndexFlags {
                                is_static,
                                is_main,
                                is_inline: metadata.is_inline,
                                is_linkage: metadata.is_linkage_name,
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
                                entry_pc: self.extract_entry_pc(entry)?,
                            };

                            functions.entry(name).or_default().push(index_entry);
                        }
                    }
                    gimli::constants::DW_TAG_inlined_subroutine => {
                        let mut visited = HashSet::new();
                        let metadata = self.resolve_function_metadata(
                            self.dwarf,
                            &unit,
                            entry,
                            &mut metadata_cache,
                            &mut visited,
                        )?;
                        if let Some(name) = metadata.name.clone() {
                            let is_static = metadata
                                .is_external
                                .map(|external| !external)
                                .unwrap_or(false);
                            let flags = crate::core::IndexFlags {
                                is_static,
                                is_inline: true,
                                is_linkage: metadata.is_linkage_name,
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
                                entry_pc: self.extract_entry_pc(entry)?,
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
                                entry_pc: None,
                            };

                            variables.entry(name).or_default().push(index_entry);
                        }
                    }
                    gimli::constants::DW_TAG_structure_type
                    | gimli::constants::DW_TAG_class_type
                    | gimli::constants::DW_TAG_union_type
                    | gimli::constants::DW_TAG_enumeration_type
                    | gimli::constants::DW_TAG_typedef => {
                        if let Some(name) = self.extract_name(self.dwarf, &unit, entry)? {
                            // DW_AT_declaration indicates a declaration-only (no definition)
                            let is_decl = match entry.attr(gimli::constants::DW_AT_declaration)? {
                                Some(attr) => match attr.value() {
                                    gimli::AttributeValue::Flag(f) => f,
                                    _ => false,
                                },
                                None => false,
                            };
                            let flags = crate::core::IndexFlags {
                                is_type_declaration: is_decl,
                                ..Default::default()
                            };
                            let index_entry = IndexEntry {
                                name: name.clone(),
                                die_offset: entry.offset(),
                                unit_offset,
                                tag: entry.tag(),
                                flags,
                                language: self.extract_language(self.dwarf, &unit, entry),
                                address_ranges: Vec::new(),
                                entry_pc: None,
                            };
                            types.entry(name).or_default().push(index_entry);
                        }
                    }
                    _ => {} // Skip other DIE types
                }
            }
        }

        let functions_count = functions.len();
        let variables_count = variables.len();
        let lightweight_index = LightweightIndex::from_builder_data(functions, variables, types);

        debug!(
            "Completed debug_info parsing for {}: {} functions, {} variables",
            module_path, functions_count, variables_count
        );

        Ok(DebugParseResult {
            lightweight_index,
            functions_count,
            variables_count,
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

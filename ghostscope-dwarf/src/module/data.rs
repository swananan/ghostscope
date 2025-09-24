//! Single module DWARF data management (simplified and restructured)

/// Constants for intelligent file selection scoring
mod file_selection_scoring {
    /// Search range in bytes when looking for alternative source file entries
    pub const SEARCH_RANGE_BYTES: u64 = 100;

    /// Strong preference for non-header files (*.c, *.cpp, *.rs vs *.h, *.hpp)
    pub const NON_HEADER_BONUS: i32 = 1000;

    /// Moderate preference when compilation unit filename matches source filename
    pub const COMPILATION_UNIT_MATCH_BONUS: i32 = 500;

    /// Preference for non-system paths (not in /usr/, /lib/)
    pub const NON_SYSTEM_PATH_BONUS: i32 = 200;

    /// Preference for statement boundaries (is_stmt = true)
    pub const STATEMENT_BOUNDARY_BONUS: i32 = 100;

    /// Heavy penalty for entries without resolvable file paths
    pub const NO_PATH_PENALTY: i32 = -1000;
}

use crate::{
    core::{MappedFile, Result, SourceLocation},
    data::{
        CfiIndex, LightweightIndex, LineMappingTable, OnDemandResolver, ScopedFileIndexManager,
    },
    parser::{CompilationUnit, SourceFile},
    proc_mapping::ModuleMapping,
};
use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
};

/// Module loading state for error tracking and UI display
#[derive(Debug, Clone)]
pub enum ModuleLoadState {
    /// Module loaded successfully
    Success,
    /// Module loaded with some warnings (e.g., CFI failed but DWARF succeeded)
    PartialSuccess(Vec<String>),
    /// Module loading failed completely
    Failed(String),
}

/// Complete DWARF data for a single module
#[derive(Debug)]
pub(crate) struct ModuleData {
    /// Module mapping info (from proc mapping)
    module_mapping: ModuleMapping,
    /// Loading state for error tracking
    load_state: ModuleLoadState,
    /// Lightweight index (startup time)
    lightweight_index: LightweightIndex,
    /// Line mapping table (address→line lookup)
    line_mapping: LineMappingTable,
    /// Lightweight scoped file index manager (primary file management)
    scoped_file_manager: ScopedFileIndexManager,
    /// Compilation unit metadata (base dir, include dirs, file list)
    compilation_units: HashMap<String, CompilationUnit>,
    /// CFI index for CFA lookup
    cfi_index: Option<CfiIndex>,
    /// On-demand resolver (for detailed parsing)
    resolver: OnDemandResolver,
    /// Parsing statistics
    stats: crate::parser::DwarfParseStats,
    /// Memory mapped file (keep alive)
    _mapped_file: MappedFile,
}

impl ModuleData {
    /// Parallel loading: debug_info || debug_line || CFI simultaneously
    pub(crate) async fn load_parallel(module_mapping: ModuleMapping) -> Result<Self> {
        tracing::info!("Parallel loading for: {}", module_mapping.path.display());
        Self::load_internal_parallel(module_mapping).await
    }

    /// Parallel internal load implementation - true parallelism for debug_info || debug_line || CFI
    async fn load_internal_parallel(module_mapping: ModuleMapping) -> Result<Self> {
        tracing::debug!(
            "Loading module in parallel: {}",
            module_mapping.path.display()
        );

        // Memory map the file once
        let mapped_file = std::sync::Arc::new(Self::map_file(&module_mapping.path)?);

        // Parse object file
        let object = object::File::parse(&mapped_file.data[..])?;

        // Load DWARF sections
        let dwarf = std::sync::Arc::new(Self::load_dwarf_sections(&object)?);

        tracing::debug!(
            "Starting parallel DWARF parsing with true debug_line || debug_info parallelism..."
        );

        // Parse three components in parallel: debug_line || debug_info || CFI
        let (line_result, info_result, cfi_index_result) = tokio::try_join!(
            // Parse debug_line only
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<crate::parser::LineParseResult> {
                    let parser = crate::parser::DwarfParser::new(&dwarf);
                    parser.parse_line_info(&module_path)
                }
            }),
            // Parse debug_info only
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<crate::parser::DebugParseResult> {
                    let parser = crate::parser::DwarfParser::new(&dwarf);
                    parser.parse_debug_info(&module_path)
                }
            }),
            // Parse CFI independently (uses raw file data)
            tokio::task::spawn_blocking({
                let mapped_file = std::sync::Arc::clone(&mapped_file);
                let module_path = module_mapping.path.clone();
                move || -> Result<Option<crate::data::CfiIndex>> {
                    // SAFETY: We keep the mapped file alive for the lifetime of the module
                    // The Arc ensures the memory remains valid during CFI parsing
                    let static_data: &'static [u8] =
                        unsafe { std::mem::transmute(&mapped_file.data[..]) };
                    match crate::data::CfiIndex::from_static_data(static_data) {
                        Ok(cfi) => {
                            tracing::info!(
                                "CFI index initialized successfully for {}",
                                module_path.display()
                            );
                            Ok(Some(cfi))
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to initialize CFI index for {}: {}",
                                module_path.display(),
                                e
                            );
                            Ok(None)
                        }
                    }
                }
            })
        )?;

        // Unwrap the spawn_blocking results
        let line_result = line_result?;
        let info_result = info_result?;
        let cfi_index = cfi_index_result?;

        // Assemble parallel results into unified result
        let parse_result = crate::parser::DwarfParser::combine_parallel_results(
            line_result,
            info_result,
            module_mapping.path.to_string_lossy().to_string(),
        );

        // Create resolver with parsed data
        let resolver = crate::data::OnDemandResolver::new(
            std::sync::Arc::try_unwrap(dwarf)
                .map_err(|_| anyhow::anyhow!("Failed to unwrap DWARF Arc"))?,
            gimli::BaseAddresses::default(),
        );

        // Determine load state based on parallel loading results
        let mut warnings = Vec::new();
        if cfi_index.is_none() {
            warnings.push("CFI index failed to initialize".to_string());
        }

        let load_state = if warnings.is_empty() {
            ModuleLoadState::Success
        } else {
            ModuleLoadState::PartialSuccess(warnings)
        };

        tracing::info!(
            "True parallel loading completed for {}: {} functions, {} variables, {} line entries, {} files (state: {:?})",
            module_mapping.path.display(),
            parse_result.stats.total_functions,
            parse_result.stats.total_variables,
            parse_result.stats.total_line_entries,
            parse_result.stats.total_files,
            load_state
        );

        Ok(Self {
            module_mapping: module_mapping.clone(),
            load_state,
            lightweight_index: parse_result.lightweight_index,
            line_mapping: parse_result.line_mapping,
            scoped_file_manager: parse_result.scoped_file_manager,
            compilation_units: parse_result.compilation_units,
            cfi_index,
            resolver,
            stats: parse_result.stats,
            _mapped_file: std::sync::Arc::try_unwrap(mapped_file)
                .map_err(|_| anyhow::anyhow!("Failed to unwrap MappedFile Arc"))?,
        })
    }

    /// Memory map the file
    fn map_file(path: &PathBuf) -> Result<MappedFile> {
        use std::fs::File;
        let file = File::open(path)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

        Ok(MappedFile {
            data: mmap,
            path: path.clone(),
        })
    }

    /// Load DWARF sections using gimli
    fn load_dwarf_sections(
        object: &object::File,
    ) -> Result<gimli::Dwarf<EndianSlice<'static, LittleEndian>>> {
        // Load DWARF sections
        let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'static, LittleEndian>> {
            let data = object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or_else(|| std::borrow::Cow::Borrowed(&[]));

            // SAFETY: We keep the mapped file alive for the lifetime of the module
            let data: &'static [u8] = unsafe { std::mem::transmute(data.as_ref()) };
            Ok(EndianSlice::new(data, LittleEndian))
        };

        let dwarf = gimli::Dwarf::load(load_section)?;
        Ok(dwarf)
    }

    /// Lookup function addresses by name with prologue skipping for real functions
    pub(crate) fn lookup_function_addresses(&self, name: &str) -> Vec<u64> {
        tracing::debug!("ModuleData: looking up function '{}'", name);

        // Get function entries from lightweight index
        let entries = self.lightweight_index.find_dies_by_function_name(name);
        let mut addresses = Vec::new();

        for entry in entries {
            for (start_addr, _end_addr) in &entry.address_ranges {
                if entry.flags.is_inline {
                    // Inline function, use original address
                    tracing::debug!(
                        "ModuleData: function '{}' is inline at 0x{:x}, using original address",
                        name,
                        start_addr
                    );
                    addresses.push(*start_addr);
                } else {
                    // Real function, skip prologue
                    let executable_addr =
                        self.line_mapping.find_first_executable_address(*start_addr);
                    tracing::debug!(
                        "ModuleData: function '{}' is real function at 0x{:x}, first executable at 0x{:x} (offset +{})",
                        name, start_addr, executable_addr, executable_addr - start_addr
                    );
                    addresses.push(executable_addr);
                }
            }
        }

        tracing::debug!(
            "ModuleData: function '{}' resolved to {} addresses: {:?}",
            name,
            addresses.len(),
            addresses
        );
        addresses
    }

    /// Get all variables visible at the given address with EvaluationResult
    pub(crate) fn get_all_variables_at_address(
        &mut self,
        address: u64,
    ) -> Result<Vec<crate::data::VariableWithEvaluation>> {
        tracing::info!(
            "ModuleData::get_all_variables_at_address for module {}: address=0x{:x}",
            self.module_mapping.path.display(),
            address
        );

        // Find the DIE containing this address (could be function, inline, lexical block, etc.)
        if let Some(entry) = self.lightweight_index.find_die_at_address(address) {
            tracing::info!(
                "Found DIE '{}' (tag={:?}) at DIE offset {:?} containing address 0x{:x}",
                entry.name,
                entry.tag,
                entry.unit_offset,
                address
            );

            // Create CFA provider closure
            // Note: We need to handle the borrow checker by getting CFA beforehand if needed
            let cfa_result = if self.cfi_index.is_some() {
                tracing::debug!("CFI index exists, querying CFA for address 0x{:x}", address);
                match self.get_cfa_result(address) {
                    Ok(Some(cfa)) => {
                        tracing::debug!("CFA found for address 0x{:x}: {:?}", address, cfa);
                        Some(cfa)
                    }
                    Ok(None) => {
                        tracing::warn!(
                            "No CFA found for address 0x{:x} despite CFI index",
                            address
                        );
                        None
                    }
                    Err(e) => {
                        tracing::error!("Error querying CFA for address 0x{:x}: {}", address, e);
                        None
                    }
                }
            } else {
                tracing::warn!(
                    "No CFI index available for module {}",
                    self.module_mapping.path.display()
                );
                None
            };

            let get_cfa_closure = move |addr: u64| -> Result<Option<crate::core::CfaResult>> {
                // For now, return the pre-computed CFA if the address matches
                // In a more complete implementation, we'd need a different approach
                if addr == address {
                    Ok(cfa_result.clone())
                } else {
                    Ok(None)
                }
            };

            // Pass the DIE information to resolver for variable extraction
            self.resolver.get_all_variables_at_address(
                address,
                entry.unit_offset,
                Some(&get_cfa_closure),
            )
        } else {
            tracing::warn!(
                "No DIE found at address 0x{:x} in module {}",
                address,
                self.module_mapping.path.display()
            );
            Ok(Vec::new())
        }
    }

    /// Lookup source location at address (line mapping + file manager)
    pub(crate) fn lookup_source_location(&self, address: u64) -> Option<SourceLocation> {
        // Get all line entries at this exact address to handle overlapping instructions
        let all_line_entries = self.line_mapping.lookup_all_lines_at_address(address);

        if all_line_entries.is_empty() {
            // Fallback to closest address lookup
            if let Some(line_entry) = self.line_mapping.lookup_line(address) {
                return self.create_source_location_from_entry(line_entry);
            }
            return None;
        }

        // Check if we should use alternative file selection for header files
        let best_entry = if all_line_entries.len() == 1 {
            let entry = all_line_entries[0];
            self.find_alternative_source_file(entry).unwrap_or(entry)
        } else {
            // Multiple entries: use smart selection
            self.select_best_line_entry(&all_line_entries)
        };

        self.create_source_location_from_entry(best_entry)
    }

    /// Find alternative source file when current entry points to header file
    fn find_alternative_source_file<'a>(
        &'a self,
        entry: &'a crate::core::LineEntry,
    ) -> Option<&'a crate::core::LineEntry> {
        // Get the file path for this entry
        let current_file_path = self.get_file_path_for_entry(entry)?;

        // Check if current file is a header
        let is_header = current_file_path.ends_with(".h")
            || current_file_path.ends_with(".hpp")
            || current_file_path.ends_with(".hxx")
            || current_file_path.contains("/include/")
            || current_file_path.contains("/usr/include/");

        if !is_header {
            return None; // Current file is already a source file
        }

        tracing::debug!(
            "find_alternative_source_file: current entry points to header '{}', looking for main source alternative",
            current_file_path
        );

        // Look for entries at nearby addresses that point to main source files
        let search_range = file_selection_scoring::SEARCH_RANGE_BYTES;
        let start_addr = entry.address.saturating_sub(search_range);
        let end_addr = entry.address.saturating_add(search_range);

        // Search through all line entries in the range
        for (addr, candidate_entry) in self.line_mapping.get_entries_in_range(start_addr, end_addr)
        {
            {
                // Skip if same compilation unit (to avoid circular references)
                if candidate_entry.compilation_unit != entry.compilation_unit {
                    continue;
                }

                // Check if this candidate points to a main source file
                if let Some(candidate_file_path) = self.get_file_path_for_entry(candidate_entry) {
                    let is_candidate_header = candidate_file_path.ends_with(".h")
                        || candidate_file_path.ends_with(".hpp")
                        || candidate_file_path.ends_with(".hxx")
                        || candidate_file_path.contains("/include/")
                        || candidate_file_path.contains("/usr/include/");

                    if !is_candidate_header {
                        tracing::debug!(
                            "find_alternative_source_file: found alternative source file '{}' at address 0x{:x}",
                            candidate_file_path, addr
                        );

                        // Create a synthetic entry with the source file but original line number
                        // This is a bit hacky, but it works for our use case
                        return Some(candidate_entry);
                    }
                }
            }
        }

        // Fallback: try to find any main source file in the same compilation unit
        if let Some(cu_file_index) = self
            .scoped_file_manager
            .get_cu_file_index(&entry.compilation_unit)
        {
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    let is_source = full_path.ends_with(".c")
                        || full_path.ends_with(".cpp")
                        || full_path.ends_with(".cc")
                        || full_path.ends_with(".rs")
                        || (full_path.contains(&entry.compilation_unit)
                            && !full_path.ends_with(".h"));

                    if is_source {
                        tracing::debug!(
                            "find_alternative_source_file: using main source file '{}' from compilation unit",
                            full_path
                        );

                        // Return the original entry - we'll modify the file lookup in create_source_location_from_entry
                        return None; // We'll handle this in the create_source_location_from_entry method
                    }
                }
            }
        }

        None
    }

    /// Select the best line entry from multiple candidates
    fn select_best_line_entry<'a>(
        &self,
        entries: &[&'a crate::core::LineEntry],
    ) -> &'a crate::core::LineEntry {
        if entries.len() == 1 {
            return entries[0];
        }

        tracing::debug!(
            "select_best_line_entry: {} candidates at address 0x{:x}",
            entries.len(),
            entries[0].address
        );

        // Priority rules for file selection:
        // 1. Prefer .c/.cpp/.rs files over .h/.hpp files (main source over headers)
        // 2. Prefer files with compilation_unit name matching filename
        // 3. Prefer longer paths (more specific)
        // 4. Prefer entries with is_stmt=true (statement boundaries)

        let mut best = entries[0];
        let mut best_score = self.score_line_entry(best);

        for &entry in entries.iter().skip(1) {
            let score = self.score_line_entry(entry);
            tracing::debug!(
                "  candidate: {}:{} (stmt={}, score={})",
                self.get_file_path_for_entry(entry)
                    .unwrap_or("unknown".to_string()),
                entry.line,
                entry.is_stmt,
                score
            );

            if score > best_score {
                best = entry;
                best_score = score;
            }
        }

        tracing::debug!(
            "select_best_line_entry: selected {} (score={})",
            self.get_file_path_for_entry(best)
                .unwrap_or("unknown".to_string()),
            best_score
        );

        best
    }

    /// Score a line entry for smart selection (higher is better)
    fn score_line_entry(&self, entry: &crate::core::LineEntry) -> i32 {
        let mut score = 0;

        // Get file path for scoring
        let file_path = match self.get_file_path_for_entry(entry) {
            Some(path) => path,
            None => return file_selection_scoring::NO_PATH_PENALTY,
        };

        // Rule 1: Prefer main source files over headers
        let is_header = file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/");

        if !is_header {
            score += file_selection_scoring::NON_HEADER_BONUS;
        }

        // Rule 2: Prefer files where compilation unit matches filename
        if let Some(filename) = std::path::Path::new(&file_path).file_stem() {
            if let Some(cu_stem) = std::path::Path::new(&entry.compilation_unit).file_stem() {
                if filename == cu_stem {
                    score += file_selection_scoring::COMPILATION_UNIT_MATCH_BONUS;
                }
            }
        }

        // Rule 3: Prefer longer/more specific paths
        score += file_path.len() as i32;

        // Rule 4: Prefer statement boundaries
        if entry.is_stmt {
            score += file_selection_scoring::STATEMENT_BOUNDARY_BONUS;
        }

        // Rule 5: Prefer non-system paths
        if !file_path.starts_with("/usr/") && !file_path.starts_with("/lib/") {
            score += file_selection_scoring::NON_SYSTEM_PATH_BONUS;
        }

        score
    }

    /// Helper to get file path for a line entry
    fn get_file_path_for_entry(&self, entry: &crate::core::LineEntry) -> Option<String> {
        // First check if the entry already has a file path filled in (avoids redundant lookups)
        if !entry.file_path.is_empty() {
            return Some(entry.file_path.clone());
        }

        // Fallback to file index lookup if needed
        if let Some(file_info) = self
            .scoped_file_manager
            .lookup_by_scoped_index(&entry.compilation_unit, entry.file_index)
        {
            return Some(file_info.full_path);
        }

        Some(entry.compilation_unit.clone())
    }

    /// Create SourceLocation from line entry
    fn create_source_location_from_entry(
        &self,
        line_entry: &crate::core::LineEntry,
    ) -> Option<SourceLocation> {
        tracing::debug!(
            "create_source_location_from_entry: line_entry.file_path='{}', line_entry.file_index={}, compilation_unit='{}'",
            line_entry.file_path, line_entry.file_index, line_entry.compilation_unit
        );

        // Check if compilation_unit itself is a file path (contains path separators)
        // If so, try to resolve it to a full path by combining with base directory
        if line_entry.compilation_unit.contains('/')
            && (line_entry.compilation_unit.ends_with(".c")
                || line_entry.compilation_unit.ends_with(".cpp")
                || line_entry.compilation_unit.ends_with(".cc")
                || line_entry.compilation_unit.ends_with(".rs"))
        {
            // Try to get base directory from file index resolution
            let full_path = if let Some(file_info) = self
                .scoped_file_manager
                .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
            {
                // Extract base directory from the resolved absolute path
                let resolved_path = &file_info.full_path;
                if let Some(base_dir) =
                    self.extract_base_directory(resolved_path, &line_entry.compilation_unit)
                {
                    let full_path = format!("{}/{}", base_dir, line_entry.compilation_unit);
                    tracing::debug!(
                        "create_source_location_from_entry: constructed full path '{}' from base_dir='{}' + compilation_unit='{}'",
                        full_path, base_dir, line_entry.compilation_unit
                    );
                    full_path
                } else {
                    line_entry.compilation_unit.clone()
                }
            } else {
                line_entry.compilation_unit.clone()
            };

            return Some(SourceLocation {
                file_path: full_path,
                line_number: line_entry.line as u32,
                column: Some(line_entry.column as u32),
                address: line_entry.address,
            });
        }

        // Try to find a better file if current one is a header
        let preferred_file_path = if let Some(file_info) = self
            .scoped_file_manager
            .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
        {
            let current_path = &file_info.full_path;
            tracing::debug!(
                "create_source_location_from_entry: found file via ScopedFileIndexManager: '{}'",
                current_path
            );

            // If current file is a header, try to find the main source file
            if self.is_header_file(current_path) {
                if let Some(alternative_path) =
                    self.find_main_source_file_in_cu(&line_entry.compilation_unit)
                {
                    tracing::debug!(
                        "create_source_location_from_entry: replaced header '{}' with main source '{}'",
                        current_path, alternative_path
                    );
                    alternative_path
                } else {
                    current_path.clone()
                }
            } else {
                current_path.clone()
            }
        } else if !line_entry.file_path.is_empty() {
            tracing::debug!(
                "create_source_location_from_entry: using line entry file_path: '{}'",
                line_entry.file_path
            );
            line_entry.file_path.clone()
        } else {
            tracing::debug!(
                "create_source_location_from_entry: no file info found, using compilation unit name: '{}'",
                line_entry.compilation_unit
            );
            line_entry.compilation_unit.clone()
        };

        tracing::debug!(
            "create_source_location_from_entry: final file_path='{}'",
            preferred_file_path
        );

        Some(SourceLocation {
            file_path: preferred_file_path,
            line_number: line_entry.line as u32,
            column: Some(line_entry.column as u32),
            address: line_entry.address,
        })
    }

    /// Check if a file path is a header file
    fn is_header_file(&self, file_path: &str) -> bool {
        file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/")
    }

    /// Find the main source file in the compilation unit
    fn find_main_source_file_in_cu(&self, compilation_unit: &str) -> Option<String> {
        if let Some(cu_file_index) = self.scoped_file_manager.get_cu_file_index(compilation_unit) {
            tracing::debug!(
                "find_main_source_file_in_cu: searching for main source file in CU '{}'",
                compilation_unit
            );

            // First priority: look for files that match the compilation unit name
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !self.is_header_file(&full_path) {
                        // Check if this file matches the compilation unit name
                        if let Some(cu_stem) = std::path::Path::new(compilation_unit).file_stem() {
                            if let Some(file_stem) = std::path::Path::new(&full_path).file_stem() {
                                if cu_stem == file_stem {
                                    tracing::debug!(
                                        "find_main_source_file_in_cu: found matching source file '{}'",
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
                    if !self.is_header_file(&full_path) {
                        tracing::debug!(
                            "find_main_source_file_in_cu: found alternative source file '{}'",
                            full_path
                        );
                        return Some(full_path);
                    }
                }
            }
        }

        None
    }

    /// Extract base directory from an absolute path by removing the filename
    /// For example:
    /// - absolute_path: "/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx-1.27.1/nginx.c"
    /// - compilation_unit: "src/core/nginx.c"
    /// - returns: "/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx-1.27.1"
    /// - final result: "/mnt/500g/code/openresty/openresty-1.27.1.1/build/nginx-1.27.1/src/core/nginx.c"
    fn extract_base_directory(
        &self,
        absolute_path: &str,
        compilation_unit: &str,
    ) -> Option<String> {
        // Extract the directory part from the absolute path (remove filename)
        if let Some(parent) = std::path::Path::new(absolute_path).parent() {
            let base_dir = parent.to_string_lossy().to_string();
            tracing::debug!(
                "extract_base_directory: absolute_path='{}' -> base_dir='{}' (will append compilation_unit='{}')",
                absolute_path, base_dir, compilation_unit
            );
            return Some(base_dir);
        }

        tracing::debug!(
            "extract_base_directory: failed to extract parent directory from absolute_path='{}'",
            absolute_path
        );
        None
    }

    /// Get module path
    pub(crate) fn module_path(&self) -> &PathBuf {
        &self.module_mapping.path
    }

    /// Get module mapping info
    pub(crate) fn module_mapping(&self) -> &ModuleMapping {
        &self.module_mapping
    }

    /// Get function names for debugging
    pub(crate) fn get_function_names(&self) -> Vec<&String> {
        self.lightweight_index.get_function_names()
    }

    /// Get variable names for debugging
    pub(crate) fn get_variable_names(&self) -> Vec<&String> {
        self.lightweight_index.get_variable_names()
    }

    /// Get lightweight index for stats access
    pub(crate) fn get_lightweight_index(&self) -> &crate::data::LightweightIndex {
        &self.lightweight_index
    }

    /// Get line header count for debugging (legacy compatibility)
    pub(crate) fn get_line_header_count(&self) -> usize {
        self.scoped_file_manager.get_stats().1
    }

    /// Get cache statistics
    pub(crate) fn get_cache_stats(&self) -> (usize, usize) {
        self.resolver.get_cache_stats()
    }

    /// Get module mapping info
    pub(crate) fn get_mapping(&self) -> &ModuleMapping {
        &self.module_mapping
    }

    /// Get CFA result at given PC
    pub(crate) fn get_cfa_result(&self, pc: u64) -> Result<Option<crate::core::CfaResult>> {
        match &self.cfi_index {
            Some(cfi) => Ok(Some(cfi.get_cfa_result(pc)?)),
            None => Ok(None),
        }
    }

    /// Check if CFI fast lookup is available
    pub(crate) fn has_cfi_fast_lookup(&self) -> bool {
        self.cfi_index
            .as_ref()
            .map(|cfi| cfi.has_fast_lookup())
            .unwrap_or(false)
    }

    /// Get DWARF parsing statistics
    pub(crate) fn get_parse_stats(&self) -> &crate::parser::DwarfParseStats {
        &self.stats
    }

    /// Get debug_line parsing statistics
    pub(crate) fn get_debug_line_stats(&self) -> DebugLineStats {
        let (total_files, _) = self.scoped_file_manager.get_stats();

        let mut seen = HashSet::new();
        let mut sample_paths = Vec::new();

        for cu in self.compilation_units.values() {
            for file in &cu.files {
                if seen.insert(file.full_path.clone()) {
                    sample_paths.push(PathBuf::from(file.full_path.clone()));
                    if sample_paths.len() >= 10 {
                        break;
                    }
                }
            }
            if sample_paths.len() >= 10 {
                break;
            }
        }

        DebugLineStats {
            total_line_entries: self.line_mapping.total_entries(),
            file_count: total_files,
            address_range: self.line_mapping.address_range(),
            file_paths: sample_paths,
        }
    }

    /// Lookup addresses by source file path and line number
    /// Returns addresses that correspond to the given source line
    pub(crate) fn lookup_addresses_by_source_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<u64> {
        // Use the new path-based lookup method
        let addresses = self
            .line_mapping
            .lookup_addresses_by_path(file_path, line_number as u64);

        if !addresses.is_empty() {
            tracing::info!(
                "Found {} addresses for {}:{} in module {}",
                addresses.len(),
                file_path,
                line_number,
                self.module_path().display()
            );
        } else {
            tracing::debug!(
                "No addresses found for {}:{} in module {}",
                file_path,
                line_number,
                self.module_path().display()
            );
        }

        addresses
    }

    /// Find symbol name by address (compatibility method)
    pub(crate) fn find_symbol_by_address(&self, address: u64) -> Option<String> {
        // Find the DIE containing this address
        if let Some(entry) = self.lightweight_index.find_die_at_address(address) {
            Some(entry.name.clone())
        } else {
            None
        }
    }

    /// Get all source files from stored compilation unit metadata
    pub(crate) fn get_all_files(&self) -> Vec<SourceFile> {
        let mut source_files = Vec::new();
        let mut seen_paths = HashSet::new();

        for cu in self.compilation_units.values() {
            for file in &cu.files {
                if seen_paths.insert(file.full_path.clone()) {
                    source_files.push(file.clone());
                }
            }
        }

        source_files.sort_by(|a, b| a.full_path.cmp(&b.full_path));
        source_files
    }

    /// Get module loading state for error tracking and UI display
    pub(crate) fn get_load_state(&self) -> &ModuleLoadState {
        &self.load_state
    }

    /// Check if module loaded successfully (no warnings or errors)
    pub(crate) fn is_fully_loaded(&self) -> bool {
        matches!(self.load_state, ModuleLoadState::Success)
    }

    /// Check if module has any warnings
    pub(crate) fn has_warnings(&self) -> bool {
        matches!(self.load_state, ModuleLoadState::PartialSuccess(_))
    }

    /// Get warning messages if any
    pub(crate) fn get_warnings(&self) -> Vec<String> {
        match &self.load_state {
            ModuleLoadState::PartialSuccess(warnings) => warnings.clone(),
            _ => Vec::new(),
        }
    }
}

/// Debug line statistics for verification
#[derive(Debug, Clone)]
pub struct DebugLineStats {
    pub total_line_entries: usize,
    pub file_count: usize,
    pub address_range: Option<(u64, u64)>,
    pub file_paths: Vec<PathBuf>,
}

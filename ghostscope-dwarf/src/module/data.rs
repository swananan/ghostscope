//! Single module DWARF data management (simplified and restructured)

use crate::{
    core::{MappedFile, Result, SourceLocation, VariableInfo},
    data::{CfiIndex, LightweightIndex, LineMappingTable, OnDemandResolver, SourceFileManager},
    parser::DwarfParser,
    proc_mapping::ModuleMapping,
};
use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection};
use std::path::PathBuf;

/// Complete DWARF data for a single module
#[derive(Debug)]
pub(crate) struct ModuleData {
    /// Module mapping info (from proc mapping)
    module_mapping: ModuleMapping,
    /// Lightweight index (startup time)
    lightweight_index: LightweightIndex,
    /// Line mapping table (address→line lookup)
    line_mapping: LineMappingTable,
    /// File manager for source files
    file_manager: SourceFileManager,
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
    /// Sequential loading: debug_info -> debug_line -> CFI one by one
    pub(crate) fn load_sequential(module_mapping: ModuleMapping) -> Result<Self> {
        Self::load_internal_sequential(module_mapping)
    }

    /// Parallel loading: debug_info || debug_line || CFI simultaneously
    pub(crate) async fn load_parallel(module_mapping: ModuleMapping) -> Result<Self> {
        Self::load_internal_parallel(module_mapping).await
    }

    /// Sequential internal load implementation
    fn load_internal_sequential(module_mapping: ModuleMapping) -> Result<Self> {
        tracing::debug!("Loading module: {}", module_mapping.path.display());

        // Memory map the file
        let mapped_file = Self::map_file(&module_mapping.path)?;

        // Parse object file
        let object = object::File::parse(&mapped_file.data[..])?;

        // Load DWARF sections
        let dwarf = Self::load_dwarf_sections(&object)?;

        tracing::debug!("Starting unified DWARF parsing...");
        let parser = DwarfParser::new(&dwarf);
        let parse_result = parser.parse_all(&module_mapping.path.to_string_lossy())?;

        let lightweight_index = parse_result.lightweight_index;
        let line_mapping = parse_result.line_mapping;
        let file_manager = parse_result.source_file_manager;

        let cfi_index = {
            // SAFETY: We keep the mapped file alive for the lifetime of the module
            // The _mapped_file field ensures the memory remains valid
            let static_data: &'static [u8] = unsafe { std::mem::transmute(&mapped_file.data[..]) };

            match CfiIndex::from_static_data(static_data) {
                Ok(cfi) => {
                    tracing::info!(
                        "CFI index initialized successfully for {}",
                        module_mapping.path.display()
                    );
                    Some(cfi)
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize CFI index for {}: {}",
                        module_mapping.path.display(),
                        e
                    );
                    None
                }
            }
        };

        tracing::debug!("Preparing on-demand resolver...");
        let base_addresses = gimli::BaseAddresses::default();
        let resolver = OnDemandResolver::new(dwarf, base_addresses);

        tracing::debug!(
            "Loaded module {} - Summary: {} functions, {} variables, {} line entries, {} files, {} compilation units",
            module_mapping.path.display(),
            parse_result.stats.total_functions,
            parse_result.stats.total_variables,
            parse_result.stats.total_line_entries,
            parse_result.stats.total_files,
            parse_result.stats.total_compilation_units
        );

        Ok(Self {
            module_mapping,
            lightweight_index,
            line_mapping,
            file_manager,
            cfi_index,
            resolver,
            stats: parse_result.stats,
            _mapped_file: mapped_file,
        })
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

        tracing::debug!("Starting parallel DWARF parsing...");

        // Parse three components in parallel: debug_info || debug_line || CFI
        let (parse_result, cfi_index_result) = tokio::try_join!(
            // Parse debug_info and debug_line together (they share DWARF data)
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<crate::parser::DwarfParseResult> {
                    let parser = crate::parser::DwarfParser::new(&dwarf);
                    parser.parse_all(&module_path)
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
        let parse_result = parse_result?;
        let cfi_index = cfi_index_result?;

        // Create resolver with parsed data
        let resolver = crate::data::OnDemandResolver::new(
            std::sync::Arc::try_unwrap(dwarf)
                .map_err(|_| anyhow::anyhow!("Failed to unwrap DWARF Arc"))?,
            gimli::BaseAddresses::default(),
        );

        tracing::info!(
            "Parallel loading completed for {}: {} functions, {} variables, {} line entries, {} files",
            module_mapping.path.display(),
            parse_result.stats.total_functions,
            parse_result.stats.total_variables,
            parse_result.stats.total_line_entries,
            parse_result.stats.total_files
        );

        Ok(Self {
            module_mapping: module_mapping.clone(),
            lightweight_index: parse_result.lightweight_index,
            line_mapping: parse_result.line_mapping,
            file_manager: parse_result.source_file_manager,
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
        if let Some(line_entry) = self.line_mapping.lookup_line(address) {
            tracing::debug!(
                "lookup_source_location: line_entry.file_path='{}', line_entry.file_index={}, compilation_unit='{}'",
                line_entry.file_path, line_entry.file_index, line_entry.compilation_unit
            );

            // Prefer compilation unit name if it contains path separators and matches the file
            let preferred_file_path = if line_entry.compilation_unit.contains('/') {
                let cu_filename = line_entry.compilation_unit.split('/').last().unwrap_or("");
                let line_filename = line_entry.file_path.split('/').last().unwrap_or("");

                if cu_filename == line_filename {
                    // Get compilation unit to access base_directory
                    if let Some(compilation_unit) = self
                        .file_manager
                        .get_compilation_unit(&line_entry.compilation_unit)
                    {
                        let full_path = if compilation_unit.base_directory.is_empty()
                            || compilation_unit.base_directory == "."
                        {
                            line_entry.compilation_unit.clone()
                        } else {
                            format!(
                                "{}/{}",
                                compilation_unit.base_directory, line_entry.compilation_unit
                            )
                        };

                        tracing::debug!(
                            "lookup_source_location: using compilation unit name '{}' with base_directory '{}' -> full_path '{}'",
                            line_entry.compilation_unit,
                            compilation_unit.base_directory,
                            full_path
                        );

                        full_path
                    } else {
                        tracing::debug!(
                            "lookup_source_location: compilation unit '{}' not found, using as-is",
                            line_entry.compilation_unit
                        );
                        line_entry.compilation_unit.clone()
                    }
                } else {
                    // Fall back to file manager lookup
                    self.file_manager
                        .get_file_path_by_scoped_index(
                            &line_entry.compilation_unit,
                            line_entry.file_index,
                        )
                        .unwrap_or_else(|| line_entry.file_path.clone())
                }
            } else {
                // Use scoped file_index for efficient lookup and get full structured path info
                self.file_manager
                    .get_file_path_by_scoped_index(
                        &line_entry.compilation_unit,
                        line_entry.file_index,
                    )
                    .unwrap_or_else(|| line_entry.file_path.clone())
            };

            tracing::debug!(
                "lookup_source_location: final file_path='{}'",
                preferred_file_path
            );

            return Some(SourceLocation {
                file_path: preferred_file_path,
                line_number: line_entry.line as u32,
                column: Some(line_entry.column as u32),
                address: line_entry.address,
            });
        }
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

    /// Get line header count for debugging (legacy compatibility)
    pub(crate) fn get_line_header_count(&self) -> usize {
        self.file_manager.get_stats().1 // compilation unit count as proxy
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
        let (total_files, _total_compilation_units) = self.file_manager.get_stats();

        DebugLineStats {
            total_line_entries: self.line_mapping.total_entries(),
            file_count: total_files,
            address_range: self.line_mapping.address_range(),
            file_paths: self
                .file_manager
                .get_all_files()
                .iter()
                .take(10)
                .map(|f| PathBuf::from(&f.full_path))
                .collect(),
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

    /// Get all source files from file manager (compatibility method)
    pub(crate) fn get_all_files(&self) -> Vec<&crate::data::SourceFile> {
        self.file_manager.get_all_files()
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

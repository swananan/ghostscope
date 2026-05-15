//! Main DWARF analyzer - unified entry point for all DWARF operations

use crate::{
    core::{
        mapping::ModuleMapping, CallerFrameRecovery, ModuleAddress, Result, SectionType,
        SourceLocation,
    },
    objfile::LoadedObjfile,
    semantics::{CompactUnwindRow, CompactUnwindTable, PcContext, VisibleVariable},
};
use ghostscope_debuginfod::DebuginfodClient;
use object::{Object, ObjectSection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

mod plan_global;
mod plan_pc;
mod type_lookup;

#[cfg(test)]
use crate::{
    core::{AddressExpr, Availability, Provenance, VariableLocation},
    semantics::VariableReadPlan,
};

/// Events emitted during module loading process
#[derive(Debug, Clone)]
pub enum ModuleLoadingEvent {
    /// Module discovered during process scanning
    Discovered {
        module_path: String,
        current: usize,
        total: usize,
    },
    /// Module loading started
    LoadingStarted {
        module_path: String,
        current: usize,
        total: usize,
    },
    /// Module loading completed successfully
    LoadingCompleted {
        module_path: String,
        stats: ModuleLoadingStats,
        current: usize,
        total: usize,
    },
    /// Module loading failed
    LoadingFailed {
        module_path: String,
        error: String,
        current: usize,
        total: usize,
    },
}

/// Statistics for a loaded module
#[derive(Debug, Clone)]
pub struct ModuleLoadingStats {
    pub functions: usize,
    pub variables: usize,
    pub types: usize,
    pub load_time_ms: u64,
    pub parse_time_ms: u64,
    pub index_time_ms: u64,
    pub module_total_time_ms: u64,
}

/// Rich query result for a single address within a module.
#[derive(Debug, Clone)]
pub struct AddressQueryResult {
    pub module_path: PathBuf,
    pub address: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub source_column: Option<u32>,
    pub function_name: Option<String>,
    pub is_inline: Option<bool>,
    pub variables: Vec<VisibleVariable>,
    pub parameters: Vec<VisibleVariable>,
}

/// Rich query result for a function lookup across modules.
#[derive(Debug, Clone)]
pub struct FunctionQueryResult {
    pub function_name: String,
    pub addresses: Vec<AddressQueryResult>,
}

/// DWARF analyzer - unified entry point for all DWARF analysis
#[derive(Debug)]
pub struct DwarfAnalyzer {
    /// Process ID
    pid: u32,
    /// Module path -> module data mapping
    modules: HashMap<PathBuf, LoadedObjfile>,
}

impl DwarfAnalyzer {
    fn build_address_query_result(
        &self,
        module_address: &ModuleAddress,
    ) -> Result<AddressQueryResult> {
        self.build_address_query_result_with_source_hint(module_address, None)
    }

    fn build_address_query_result_with_source_hint(
        &self,
        module_address: &ModuleAddress,
        source_hint: Option<(&str, u32)>,
    ) -> Result<AddressQueryResult> {
        let mut variables = Vec::new();
        let mut parameters = Vec::new();

        for variable in self.visible_variables_at_address(module_address)? {
            if variable.is_parameter {
                parameters.push(variable);
            } else {
                variables.push(variable);
            }
        }

        let source_location = if let Some((file_path, line_number)) = source_hint {
            self.modules
                .get(&module_address.module_path)
                .and_then(|module_data| {
                    module_data.lookup_source_location_for_source_line(
                        module_address.address,
                        file_path,
                        line_number,
                    )
                })
        } else {
            self.lookup_source_location(module_address)
        };
        let function_name = self.find_function_name_by_module_address(module_address);
        let is_inline = self.is_inline_at(module_address);

        Ok(AddressQueryResult {
            module_path: module_address.module_path.clone(),
            address: module_address.address,
            source_file: source_location.as_ref().map(|sl| sl.file_path.clone()),
            source_line: source_location.as_ref().map(|sl| sl.line_number),
            source_column: source_location.as_ref().and_then(|sl| sl.column),
            function_name,
            is_inline,
            variables,
            parameters,
        })
    }

    fn query_module_addresses(
        &self,
        module_addresses: Vec<ModuleAddress>,
    ) -> Result<Vec<AddressQueryResult>> {
        module_addresses
            .iter()
            .map(|module_address| self.build_address_query_result(module_address))
            .collect()
    }

    fn query_module_addresses_for_source_line(
        &self,
        module_addresses: Vec<ModuleAddress>,
        file_path: &str,
        line_number: u32,
    ) -> Result<Vec<AddressQueryResult>> {
        module_addresses
            .iter()
            .map(|module_address| {
                self.build_address_query_result_with_source_hint(
                    module_address,
                    Some((file_path, line_number)),
                )
            })
            .collect()
    }

    fn query_module_addresses_best_effort(
        &self,
        module_addresses: Vec<ModuleAddress>,
        query_label: &str,
    ) -> Result<Vec<AddressQueryResult>> {
        let mut results = Vec::new();
        let mut first_error: Option<(ModuleAddress, String)> = None;

        for module_address in &module_addresses {
            match self.build_address_query_result(module_address) {
                Ok(result) => results.push(result),
                Err(error) => {
                    let error_string = error.to_string();
                    tracing::warn!(
                        "Skipping failed address query for {} at {}:0x{:x}: {}",
                        query_label,
                        module_address.module_display(),
                        module_address.address,
                        error_string
                    );

                    if first_error.is_none() {
                        first_error = Some((module_address.clone(), error_string));
                    }
                }
            }
        }

        if results.is_empty() {
            if let Some((module_address, error)) = first_error {
                return Err(anyhow::anyhow!(
                    "Failed to analyze any address for {} (first failure at {}:0x{:x}: {})",
                    query_label,
                    module_address.module_display(),
                    module_address.address,
                    error
                ));
            }
        }

        Ok(results)
    }

    fn query_module_addresses_for_source_line_best_effort(
        &self,
        module_addresses: Vec<ModuleAddress>,
        file_path: &str,
        line_number: u32,
        query_label: &str,
    ) -> Result<Vec<AddressQueryResult>> {
        let mut results = Vec::new();
        let mut first_error: Option<(ModuleAddress, String)> = None;

        for module_address in &module_addresses {
            match self.build_address_query_result_with_source_hint(
                module_address,
                Some((file_path, line_number)),
            ) {
                Ok(result) => results.push(result),
                Err(error) => {
                    let error_string = error.to_string();
                    tracing::warn!(
                        "Skipping failed address query for {} at {}:0x{:x}: {}",
                        query_label,
                        module_address.module_display(),
                        module_address.address,
                        error_string
                    );

                    if first_error.is_none() {
                        first_error = Some((module_address.clone(), error_string));
                    }
                }
            }
        }

        if results.is_empty() {
            if let Some((module_address, error)) = first_error {
                return Err(anyhow::anyhow!(
                    "Failed to analyze any address for {} (first failure at {}:0x{:x}: {})",
                    query_label,
                    module_address.module_display(),
                    module_address.address,
                    error
                ));
            }
        }

        Ok(results)
    }

    fn find_function_name_by_module_address(
        &self,
        module_address: &ModuleAddress,
    ) -> Option<String> {
        self.modules
            .get(&module_address.module_path)
            .and_then(|module_data| {
                module_data.find_function_name_by_address(module_address.address)
            })
    }

    fn sorted_module_paths(&self) -> Vec<&PathBuf> {
        let mut paths: Vec<&PathBuf> = self.modules.keys().collect();
        paths.sort();
        paths
    }

    /// Return the deterministic per-analyzer module id for a loaded module path.
    pub fn module_id_for_path<P: AsRef<Path>>(&self, module_path: P) -> Option<crate::ModuleId> {
        let module_path = module_path.as_ref();
        self.sorted_module_paths()
            .into_iter()
            .position(|path| path.as_path() == module_path)
            .map(|index| crate::ModuleId(index as u32))
    }

    /// Resolve a semantic module id back to its loaded module path.
    pub fn module_path_for_id(&self, module: crate::ModuleId) -> Option<&Path> {
        self.sorted_module_paths()
            .get(module.0 as usize)
            .map(|path| path.as_path())
    }

    /// Create DWARF analyzer from PID (now uses parallel loading)
    pub async fn from_pid(pid: u32) -> Result<Self> {
        Self::from_pid_parallel(pid).await
    }

    /// Classify whether an address is inside an inlined subroutine instance
    /// Returns Some(true) if inline, Some(false) if a normal (non-inline) context,
    /// or None if the module/address cannot be resolved.
    pub fn is_inline_at(&self, module_address: &ModuleAddress) -> Option<bool> {
        if let Some(module_data) = self.modules.get(&module_address.module_path) {
            module_data.is_inline_at(module_address.address)
        } else {
            None
        }
    }

    /// Create DWARF analyzer from PID using parallel loading
    pub async fn from_pid_parallel(pid: u32) -> Result<Self> {
        Self::from_pid_parallel_with_config(pid, &[], false, |_event| {}).await
    }

    /// Create DWARF analyzer from PID using parallel loading with progress callback
    pub async fn from_pid_parallel_with_progress<F>(pid: u32, progress_callback: F) -> Result<Self>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        Self::from_pid_parallel_with_config(pid, &[], false, progress_callback).await
    }

    /// Create DWARF analyzer from PID using parallel loading with debug search paths and progress callback
    pub async fn from_pid_parallel_with_config<F>(
        pid: u32,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        progress_callback: F,
    ) -> Result<Self>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        Self::from_pid_parallel_with_config_and_debuginfod(
            pid,
            debug_search_paths,
            allow_loose_debug_match,
            None,
            progress_callback,
        )
        .await
    }

    /// Create DWARF analyzer from PID with debug search paths, debuginfod, and progress callback.
    pub async fn from_pid_parallel_with_config_and_debuginfod<F>(
        pid: u32,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
        progress_callback: F,
    ) -> Result<Self>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        tracing::info!("Creating DWARF analyzer for PID {} (parallel)", pid);

        // Discover all modules for this process using coordinator
        let mut coord = ghostscope_process::ProcessManager::new();
        coord.ensure_prefill_pid(pid)?;
        let mut module_mappings: Vec<crate::core::mapping::ModuleMapping> = Vec::new();
        if let Some(entries) = coord.cached_offsets_with_paths_for_pid(pid) {
            use std::collections::HashSet;
            let mut seen = HashSet::new();
            for e in entries {
                if seen.insert(e.module_path.clone()) {
                    let mut mm = crate::core::mapping::ModuleMapping::from_path(
                        std::path::PathBuf::from(&e.module_path),
                    );
                    mm.loaded_address = Some(e.base);
                    mm.size = e.size;
                    module_mappings.push(mm);
                }
            }
        }

        tracing::info!(
            "Discovered {} modules for PID {}",
            module_mappings.len(),
            pid
        );

        // Notify discovery completion
        for (index, mapping) in module_mappings.iter().enumerate() {
            progress_callback(ModuleLoadingEvent::Discovered {
                module_path: mapping.path.to_string_lossy().to_string(),
                current: index + 1,
                total: module_mappings.len(),
            });
        }

        // Load all modules in parallel with progress tracking
        let mut loader = crate::loader::ModuleLoader::new(module_mappings).parallel();

        // Configure debug search paths if provided
        if !debug_search_paths.is_empty() {
            loader = loader.with_debug_search_paths(debug_search_paths.to_vec());
        }
        loader = loader.with_loose_debug_match(allow_loose_debug_match);
        loader = loader.with_debuginfod_client(debuginfod_client);

        let modules = loader
            .with_progress_callback(progress_callback)
            .load()
            .await?;

        tracing::info!(
            "Created DWARF analyzer for PID {} with {} modules (parallel)",
            pid,
            modules.len()
        );

        Ok(Self::from_modules(pid, modules))
    }

    /// Create DWARF analyzer from executable path (single module mode, now async parallel)
    pub async fn from_exec_path<P: AsRef<std::path::Path>>(exec_path: P) -> Result<Self> {
        Self::from_exec_path_with_config(exec_path, &[], false).await
    }

    /// Create DWARF analyzer from executable path with debug search paths
    pub async fn from_exec_path_with_config<P: AsRef<std::path::Path>>(
        exec_path: P,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
    ) -> Result<Self> {
        Self::from_exec_path_with_config_and_debuginfod(
            exec_path,
            debug_search_paths,
            allow_loose_debug_match,
            None,
        )
        .await
    }

    /// Create DWARF analyzer from executable path with debug search paths and debuginfod.
    pub async fn from_exec_path_with_config_and_debuginfod<P: AsRef<std::path::Path>>(
        exec_path: P,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
    ) -> Result<Self> {
        Self::from_exec_path_with_config_and_debuginfod_and_progress(
            exec_path,
            debug_search_paths,
            allow_loose_debug_match,
            debuginfod_client,
            |_event| {},
        )
        .await
    }

    /// Create DWARF analyzer from executable path with debug search paths and progress callback
    pub async fn from_exec_path_with_config_and_progress<P, F>(
        exec_path: P,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        progress_callback: F,
    ) -> Result<Self>
    where
        P: AsRef<std::path::Path>,
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        Self::from_exec_path_with_config_and_debuginfod_and_progress(
            exec_path,
            debug_search_paths,
            allow_loose_debug_match,
            None,
            progress_callback,
        )
        .await
    }

    /// Create DWARF analyzer from executable path with debug search paths, debuginfod, and progress callback.
    pub async fn from_exec_path_with_config_and_debuginfod_and_progress<P, F>(
        exec_path: P,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
        progress_callback: F,
    ) -> Result<Self>
    where
        P: AsRef<std::path::Path>,
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        let exec_path = exec_path.as_ref().to_path_buf();
        tracing::info!(
            "Creating DWARF analyzer for executable: {}",
            exec_path.display()
        );

        let mut analyzer = Self {
            pid: 0, // No specific PID in exec mode
            modules: HashMap::new(),
        };

        // Create a single module mapping for the executable
        // No loaded address since we're not analyzing a running process
        let module_mapping = ModuleMapping {
            path: exec_path.clone(),
            loaded_address: None, // No process mapping in exec path mode
            size: 0,              // Will be determined from file size if needed
        };
        let module_path = exec_path.to_string_lossy().to_string();

        progress_callback(ModuleLoadingEvent::Discovered {
            module_path: module_path.clone(),
            current: 1,
            total: 1,
        });
        progress_callback(ModuleLoadingEvent::LoadingStarted {
            module_path: module_path.clone(),
            current: 1,
            total: 1,
        });

        // Load the single module using parallel loading
        let start_time = std::time::Instant::now();
        match LoadedObjfile::load_parallel(
            module_mapping,
            debug_search_paths,
            allow_loose_debug_match,
            debuginfod_client,
        )
        .await
        {
            Ok(module_data) => {
                let (functions, variables, types) = module_data.get_lightweight_index().get_stats();
                let (parse_time_ms, index_time_ms, module_total_time_ms) =
                    module_data.get_load_timing_ms();
                progress_callback(ModuleLoadingEvent::LoadingCompleted {
                    module_path,
                    stats: ModuleLoadingStats {
                        functions,
                        variables,
                        types,
                        load_time_ms: start_time.elapsed().as_millis() as u64,
                        parse_time_ms,
                        index_time_ms,
                        module_total_time_ms,
                    },
                    current: 1,
                    total: 1,
                });
                analyzer.modules.insert(exec_path.clone(), module_data);
                tracing::info!(
                    "Created DWARF analyzer for executable {} with 1 module",
                    exec_path.display()
                );
            }
            Err(e) => {
                progress_callback(ModuleLoadingEvent::LoadingFailed {
                    module_path,
                    error: e.to_string(),
                    current: 1,
                    total: 1,
                });
                return Err(crate::DwarfError::ModuleLoadError(format!(
                    "Failed to load executable {}: {}",
                    exec_path.display(),
                    e
                ))
                .into());
            }
        }

        Ok(analyzer)
    }

    /// Create analyzer from pre-loaded modules (for Builder pattern)
    pub(crate) fn from_modules(pid: u32, modules: Vec<LoadedObjfile>) -> Self {
        let mut analyzer = Self {
            pid,
            modules: HashMap::new(),
        };

        for module in modules {
            let module_path = module.module_path().clone();
            analyzer.modules.insert(module_path, module);
        }

        tracing::info!(
            "Created DWARF analyzer for PID {} with {} pre-loaded modules",
            pid,
            analyzer.modules.len()
        );

        analyzer
    }

    /// Lookup function addresses across all modules
    /// Returns: Vec<ModuleAddress> - one for each address where the function is found
    pub fn lookup_function_addresses(&self, name: &str) -> Vec<ModuleAddress> {
        let mut results = Vec::new();

        for (module_path, module_data) in &self.modules {
            let addresses = module_data.lookup_function_addresses_any(name);

            // Create a ModuleAddress for each address found in this module
            for address in addresses {
                tracing::debug!(
                    "Function '{}' found in module {} at address: 0x{:x}",
                    name,
                    module_path.display(),
                    address
                );
                results.push(ModuleAddress::new(module_path.clone(), address));
            }
        }

        // Deterministic ordering: module path asc, then address asc
        results.sort_by(|a, b| {
            let pa = a.module_path.to_string_lossy();
            let pb = b.module_path.to_string_lossy();
            match pa.cmp(&pb) {
                std::cmp::Ordering::Equal => a.address.cmp(&b.address),
                other => other,
            }
        });
        results
    }

    /// Query function debug information across all modules.
    pub fn query_function(&self, name: &str) -> Result<FunctionQueryResult> {
        let module_addresses = self.lookup_function_addresses(name);
        let addresses = self.query_module_addresses(module_addresses)?;
        Ok(FunctionQueryResult {
            function_name: name.to_string(),
            addresses,
        })
    }

    /// Query function debug information across all modules, skipping addresses
    /// that fail to resolve so callers can still display partial results.
    pub fn query_function_best_effort(&self, name: &str) -> Result<FunctionQueryResult> {
        let module_addresses = self.lookup_function_addresses(name);
        let addresses = self
            .query_module_addresses_best_effort(module_addresses, &format!("function '{name}'"))?;
        Ok(FunctionQueryResult {
            function_name: name.to_string(),
            addresses,
        })
    }

    /// Convert a module-relative virtual address (DWARF PC) to an ELF file offset
    /// Returns None if the module is unknown or the address is not within a PT_LOAD segment
    pub fn vaddr_to_file_offset<P: AsRef<std::path::Path>>(
        &self,
        module_path: P,
        vaddr: u64,
    ) -> Option<u64> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get(&path_buf) {
            module_data.vaddr_to_file_offset(vaddr)
        } else {
            None
        }
    }

    /// Recover the direct caller frame at a module address as PlanExprOp[].
    pub fn recover_caller_frame(
        &self,
        module_address: &ModuleAddress,
        registers: &[u16],
    ) -> Result<Option<CallerFrameRecovery>> {
        if let Some(module_data) = self.modules.get(&module_address.module_path) {
            module_data.recover_caller_frame(module_address.address, registers)
        } else {
            Ok(None)
        }
    }

    /// Recover the direct caller frame at a previously resolved PC context.
    pub fn recover_caller_frame_for_context(
        &self,
        ctx: &PcContext,
        registers: &[u16],
    ) -> Result<Option<CallerFrameRecovery>> {
        let module_address = self.module_address_for_context(ctx)?;
        self.recover_caller_frame(&module_address, registers)
    }

    /// Build compact unwind rows for the module referenced by a PC context.
    pub fn compact_unwind_table_for_context(
        &self,
        ctx: &PcContext,
    ) -> Result<Option<CompactUnwindTable>> {
        let module_path = self
            .module_path_for_id(ctx.module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {:?} is not loaded", ctx.module))?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .compact_unwind_table(ctx.module)
    }

    /// Resolve the compact unwind row that covers a previously resolved PC context.
    pub fn compact_unwind_row_for_context(
        &self,
        ctx: &PcContext,
    ) -> Result<Option<CompactUnwindRow>> {
        let module_path = self
            .module_path_for_id(ctx.module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {:?} is not loaded", ctx.module))?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .compact_unwind_row(ctx.module, ctx.normalized_pc)
    }

    /// Build compact unwind rows for a loaded semantic module id.
    pub fn compact_unwind_table_for_module(
        &self,
        module: crate::ModuleId,
    ) -> Result<Option<CompactUnwindTable>> {
        let module_path = self
            .module_path_for_id(module)
            .ok_or_else(|| anyhow::anyhow!("Semantic module id {:?} is not loaded", module))?;
        self.modules
            .get(module_path)
            .ok_or_else(|| anyhow::anyhow!("Module {} not loaded", module_path.display()))?
            .compact_unwind_table(module)
    }

    /// Get all loaded module paths
    pub fn get_loaded_modules(&self) -> Vec<&PathBuf> {
        self.modules.keys().collect()
    }

    /// Classify the section type for a link-time virtual address in a specific module
    pub fn classify_section_for_address<P: AsRef<Path>>(
        &self,
        module_path: P,
        vaddr: u64,
    ) -> Option<SectionType> {
        let path = module_path.as_ref();
        if let Some(module_data) = self.modules.get(path) {
            module_data.classify_section_for_vaddr(vaddr)
        } else {
            None
        }
    }

    /// Lookup function address by name - returns first match
    /// Returns ModuleAddress for the first function found
    pub fn lookup_function_address_by_name(&self, function_name: &str) -> Option<ModuleAddress> {
        let module_addresses = self.lookup_function_addresses(function_name);

        if let Some(first_module_address) = module_addresses.first() {
            tracing::info!(
                "Found function '{}' in module '{}' at address 0x{:x}",
                function_name,
                first_module_address.module_display(),
                first_module_address.address
            );
            Some(first_module_address.clone())
        } else {
            tracing::warn!("Function '{}' not found in any module", function_name);
            None
        }
    }

    /// Lookup source location by module address
    /// Returns source location for the given module address
    pub fn lookup_source_location(&self, module_address: &ModuleAddress) -> Option<SourceLocation> {
        if let Some(module_data) = self.modules.get(&module_address.module_path) {
            module_data.lookup_source_location(module_address.address)
        } else {
            tracing::warn!("Module {} not found", module_address.module_display());
            None
        }
    }

    /// Lookup addresses by source line (cross-module)
    /// Returns: Vec<ModuleAddress> for all matches
    pub fn lookup_addresses_by_source_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<ModuleAddress> {
        let mut results = Vec::new();

        // Check each module for this source:line combination
        for (module_path, module_data) in &self.modules {
            let addresses = module_data.lookup_addresses_by_source_line(file_path, line_number);

            // Add all addresses from this module
            for address in addresses {
                results.push(ModuleAddress::new(module_path.clone(), address));
            }
        }

        if !results.is_empty() {
            tracing::info!(
                "Found {} addresses for {}:{} across {} modules",
                results.len(),
                file_path,
                line_number,
                self.modules.len()
            );
        }

        results.sort_by(|a, b| {
            let pa = a.module_path.to_string_lossy();
            let pb = b.module_path.to_string_lossy();
            match pa.cmp(&pb) {
                std::cmp::Ordering::Equal => a.address.cmp(&b.address),
                other => other,
            }
        });
        results
    }

    /// Query source-line debug information across all modules.
    pub fn query_source_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Result<Vec<AddressQueryResult>> {
        let module_addresses = self.lookup_addresses_by_source_line(file_path, line_number);
        self.query_module_addresses_for_source_line(module_addresses, file_path, line_number)
    }

    /// Query source-line debug information across all modules, skipping
    /// addresses that fail to resolve so callers can still display partial
    /// results.
    pub fn query_source_line_best_effort(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Result<Vec<AddressQueryResult>> {
        let module_addresses = self.lookup_addresses_by_source_line(file_path, line_number);
        self.query_module_addresses_for_source_line_best_effort(
            module_addresses,
            file_path,
            line_number,
            &format!("source line '{file_path}:{line_number}'"),
        )
    }

    /// Query a specific address within a module.
    pub fn query_address<P: AsRef<Path>>(
        &self,
        module_path: P,
        address: u64,
    ) -> Result<AddressQueryResult> {
        let module_address = ModuleAddress::new(module_path.as_ref().to_path_buf(), address);
        self.build_address_query_result(&module_address)
    }

    /// Get all function names (cross-module)
    pub fn get_all_function_names(&self) -> Vec<String> {
        let mut all_names = std::collections::HashSet::new();
        for module_data in self.modules.values() {
            for name in module_data.get_function_names() {
                all_names.insert(name.clone());
            }
        }
        all_names.into_iter().collect()
    }

    /// Get statistics for debugging
    pub fn get_stats(&self) -> AnalyzerStats {
        let mut total_functions = 0;
        let mut total_variables = 0;
        let mut total_line_headers = 0;

        for module_data in self.modules.values() {
            total_functions += module_data.get_function_names().len();
            total_variables += module_data.get_variable_names().len();
            total_line_headers += module_data.get_line_header_count();
        }

        AnalyzerStats {
            pid: self.pid,
            module_count: self.modules.len(),
            total_functions,
            total_variables,
            total_line_headers,
        }
    }

    /// Get module statistics (compatible with ghostscope-binary's ModuleStats)
    pub fn get_module_stats(&self) -> ModuleStats {
        let mut total_symbols = 0;
        let mut executable_modules = 0;
        let mut library_modules = 0;

        for (module_path, module_data) in &self.modules {
            let function_names = module_data.get_function_names();
            total_symbols += function_names.len();

            // Check if module is executable (main binary) or library
            if self.is_main_executable_module(module_path) {
                executable_modules += 1;
            } else {
                library_modules += 1;
            }
        }

        ModuleStats {
            total_modules: self.modules.len(),
            executable_modules,
            library_modules,
            total_symbols,
            modules_with_debug_info: self.modules.len(), // All DWARF modules have debug info
        }
    }

    /// Get main executable module information
    pub fn get_main_executable(&self) -> Option<MainExecutableInfo> {
        // Find the main executable module (usually the first non-library module)
        for module_path in self.modules.keys() {
            if self.is_main_executable_module(module_path) {
                return Some(MainExecutableInfo {
                    path: module_path.to_string_lossy().to_string(),
                });
            }
        }
        None
    }

    /// Check if a module is the main executable (not a shared library)
    fn is_main_executable_module(&self, module_path: &Path) -> bool {
        // Heuristic: main executable usually doesn't have .so extension and contains the process name
        let filename = module_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        // Not a shared library
        !filename.contains(".so") &&
        // Not a system library path
        !module_path.to_string_lossy().starts_with("/lib") &&
        !module_path.to_string_lossy().starts_with("/usr/lib")
    }

    /// Get list of all function names across all modules
    pub fn list_functions(&self) -> Vec<String> {
        let mut all_functions = Vec::new();

        for module_data in self.modules.values() {
            let function_names = module_data.get_function_names();
            for name in function_names {
                all_functions.push(name.clone());
            }
        }

        // Remove duplicates and sort
        all_functions.sort();
        all_functions.dedup();

        tracing::debug!(
            "Listed {} unique functions across {} modules",
            all_functions.len(),
            self.modules.len()
        );

        all_functions
    }

    /// Lookup functions by pattern (simplified - exact match only for now)
    pub fn lookup_functions_by_pattern(&self, pattern: &str) -> Vec<String> {
        let all_functions = self.list_functions();
        all_functions
            .into_iter()
            .filter(|name| name.contains(pattern))
            .collect()
    }

    /// Get all function names (alias for compatibility)
    pub fn lookup_all_function_names(&self) -> Vec<String> {
        self.list_functions()
    }

    /// Get PID (accessor for private field)
    pub fn get_pid(&self) -> u32 {
        self.pid
    }

    /// Get shared library information (compatibility method)
    pub fn get_shared_library_info(&self) -> Vec<SharedLibraryInfo> {
        self.modules
            .iter()
            .filter(|(path, _)| self.is_shared_library(path))
            .map(|(path, module_data)| {
                let mapping = module_data.module_mapping();
                let debug_file_path = module_data
                    .get_debug_file_path()
                    .map(|p| p.to_string_lossy().to_string());

                SharedLibraryInfo {
                    from_address: mapping.loaded_address.unwrap_or(0),
                    to_address: mapping.loaded_address.map_or(0, |addr| addr + mapping.size),
                    symbols_read: !module_data.get_function_names().is_empty(),
                    // Reflect actual DWARF availability (embedded or via .gnu_debuglink)
                    debug_info_available: module_data.has_dwarf_info(),
                    library_path: path.to_string_lossy().to_string(),
                    size: mapping.size,
                    debug_file_path,
                }
            })
            .collect()
    }

    /// Get executable file information (for "info file" command)
    pub fn get_executable_file_info(&self) -> Option<ExecutableFileInfo> {
        // Find the primary executable (not a shared library)
        let executable = self
            .modules
            .iter()
            .find(|(path, _)| !self.is_shared_library(path))?;

        let (exe_path, module_data) = executable;
        let file_path = exe_path.to_string_lossy().to_string();

        // Parse the ELF file to get detailed information
        let file_bytes = std::fs::read(exe_path).ok()?;
        let obj = object::File::parse(&file_bytes[..]).ok()?;

        // Get file type
        let file_type = match obj.format() {
            object::BinaryFormat::Elf => {
                if obj.is_64() {
                    "ELF 64-bit executable"
                } else {
                    "ELF 32-bit executable"
                }
            }
            _ => "Unknown format",
        }
        .to_string();

        // Check if has symbols
        let has_symbols = !module_data.get_function_names().is_empty()
            || obj.symbols().count() > 0
            || obj.dynamic_symbols().count() > 0;

        // Check if has debug info - check if DWARF was successfully loaded
        // This includes both embedded DWARF and debug link external files
        let has_debug_info = module_data.has_dwarf_info();

        // Get debug file path if using separate debug file (e.g., via .gnu_debuglink)
        let debug_file_path = module_data.get_debug_file_path();

        // Load bias for PID mode from module mapping (if available)
        let load_bias = if self.pid != 0 {
            module_data.module_mapping().loaded_address.unwrap_or(0)
        } else {
            0
        };

        // Get entry point (add load bias in PID mode)
        let entry_point = Some(obj.entry() + load_bias);

        // Get .text section info (add load bias in PID mode)
        let text_section = obj.section_by_name(".text").map(|section| {
            let addr = section.address() + load_bias;
            let size = section.size();
            SectionInfo {
                start_address: addr,
                end_address: addr + size,
                size,
            }
        });

        // Get .data section info (add load bias in PID mode)
        let data_section = obj.section_by_name(".data").map(|section| {
            let addr = section.address() + load_bias;
            let size = section.size();
            SectionInfo {
                start_address: addr,
                end_address: addr + size,
                size,
            }
        });

        // Determine mode description based on pid
        let mode_description = if self.pid != 0 {
            format!("Attached to process {} (PID mode)", self.pid)
        } else {
            "Static analysis mode (target file specified with -t)".to_string()
        };

        Some(ExecutableFileInfo {
            file_path,
            file_type,
            entry_point,
            has_symbols,
            has_debug_info,
            debug_file_path: debug_file_path.map(|p| p.to_string_lossy().to_string()),
            text_section,
            data_section,
            mode_description,
        })
    }

    // NOTE: Runtime section offsets are handled by ghostscope-coordinator.

    /// Check if a module is a shared library
    fn is_shared_library(&self, module_path: &Path) -> bool {
        let filename = module_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        // Shared libraries typically have .so extension or contain .so
        filename.contains(".so")
            || module_path.to_string_lossy().starts_with("/lib")
            || module_path.to_string_lossy().starts_with("/usr/lib")
    }

    /// Get grouped file info by module (compatibility method)
    pub fn get_grouped_file_info_by_module(&self) -> Result<Vec<(String, Vec<SimpleFileInfo>)>> {
        let mut grouped = Vec::new();

        for (module_path, module_data) in &self.modules {
            let files = module_data.get_all_files();
            if !files.is_empty() {
                let simple_files: Vec<SimpleFileInfo> = files
                    .into_iter()
                    .map(|source_file| SimpleFileInfo {
                        full_path: source_file.full_path,
                        basename: source_file.filename,
                        directory: source_file.directory_path,
                    })
                    .collect();

                grouped.push((module_path.to_string_lossy().to_string(), simple_files));
            }
        }

        Ok(grouped)
    }
}

///
/// Module statistics compatible with ghostscope-binary
#[derive(Debug, Clone)]
pub struct ModuleStats {
    pub total_modules: usize,
    pub executable_modules: usize,
    pub library_modules: usize,
    pub total_symbols: usize,
    pub modules_with_debug_info: usize,
}

/// Main executable information
#[derive(Debug, Clone)]
pub struct MainExecutableInfo {
    pub path: String,
}

/// Statistics for debugging and monitoring
#[derive(Debug, Clone)]
pub struct AnalyzerStats {
    pub pid: u32,
    pub module_count: usize,
    pub total_functions: usize,
    pub total_variables: usize,
    pub total_line_headers: usize,
}

/// Shared library information (compatible with ghostscope-ui)
#[derive(Debug, Clone)]
pub struct SharedLibraryInfo {
    pub from_address: u64,               // Starting address in memory
    pub to_address: u64,                 // Ending address in memory
    pub symbols_read: bool,              // Whether symbols were successfully read
    pub debug_info_available: bool,      // Whether debug information is available
    pub library_path: String,            // Full path to the library file
    pub size: u64,                       // Size of the library in memory
    pub debug_file_path: Option<String>, // Path to separate debug file (if via .gnu_debuglink)
}

/// Executable file information (for "info file" command)
#[derive(Debug, Clone)]
pub struct ExecutableFileInfo {
    pub file_path: String,
    pub file_type: String,
    pub entry_point: Option<u64>,
    pub has_symbols: bool,
    pub has_debug_info: bool,
    pub debug_file_path: Option<String>,
    pub text_section: Option<SectionInfo>,
    pub data_section: Option<SectionInfo>,
    pub mode_description: String,
}

/// Section information for executable files
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
}

/// Simple file information compatible with ghostscope-binary
#[derive(Debug, Clone)]
pub struct SimpleFileInfo {
    pub full_path: String,
    pub basename: String,
    pub directory: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn global_plan(name: &str, address: u64) -> VariableReadPlan {
        VariableReadPlan {
            name: name.to_string(),
            type_name: "int".to_string(),
            access_path: crate::VariableAccessPath::default(),
            module_path: None,
            dwarf_type: Some(crate::TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: gimli::constants::DW_ATE_signed.0 as u16,
            }),
            declaration: None,
            type_id: None,
            location: VariableLocation::Address(AddressExpr::constant(address)),
            availability: Availability::Available,
            scope_depth: 0,
            is_parameter: false,
            is_artificial: false,
            pc_range: None,
            inline_context: None,
            provenance: Provenance::Synthesized {
                detail: "test".to_string(),
            },
        }
    }

    fn visible_var(name: &str, scope_depth: usize) -> VisibleVariable {
        VisibleVariable {
            name: name.to_string(),
            type_name: "int".to_string(),
            dwarf_type: Some(crate::TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: gimli::constants::DW_ATE_signed.0 as u16,
            }),
            declaration: None,
            type_id: None,
            location: VariableLocation::RegisterValue { dwarf_reg: 0 },
            availability: Availability::Available,
            scope_depth,
            is_parameter: false,
            is_artificial: false,
        }
    }

    fn diagnostic(
        name: &str,
        scope_depth: usize,
        detail: &str,
    ) -> crate::semantics::VariableQueryDiagnostic {
        crate::semantics::VariableQueryDiagnostic {
            pc: 0x1234,
            name: Some(name.to_string()),
            scope_depth,
            availability: Availability::Unsupported(crate::UnsupportedReason::ExpressionShape {
                detail: detail.to_string(),
            }),
            detail: detail.to_string(),
        }
    }

    #[test]
    fn variable_selection_rejects_inner_diagnostic_over_outer_match() {
        let err = DwarfAnalyzer::select_visible_variable_by_name(
            0x1234,
            "state",
            vec![visible_var("state", 1)],
            &[diagnostic("state", 2, "DW_OP_bad is unsupported")],
        )
        .expect_err("inner unavailable variable should block outer fallback");

        assert!(err.to_string().contains("Unavailable variable 'state'"));
        assert!(err.to_string().contains("DW_OP_bad is unsupported"));
    }

    #[test]
    fn variable_selection_keeps_inner_match_over_outer_diagnostic() {
        let selected = DwarfAnalyzer::select_visible_variable_by_name(
            0x1234,
            "state",
            vec![visible_var("state", 2)],
            &[diagnostic("state", 1, "outer variable is unavailable")],
        )
        .expect("outer diagnostic should not block inner match")
        .expect("inner match should be returned");

        assert_eq!(selected.name, "state");
        assert_eq!(selected.scope_depth, 2);
    }

    #[test]
    fn global_plan_selection_rejects_ambiguous_matches() {
        let err = DwarfAnalyzer::select_unambiguous_global_plan(
            "state",
            vec![
                (PathBuf::from("/tmp/a"), global_plan("state", 0x1000)),
                (PathBuf::from("/tmp/b"), global_plan("state", 0x2000)),
            ],
        )
        .expect_err("multiple global candidates should be ambiguous");

        assert!(err.to_string().contains("Ambiguous global 'state'"));
        assert!(err.to_string().contains("2 matches"));
    }

    #[test]
    fn global_plan_selection_accepts_single_match() {
        let selected = DwarfAnalyzer::select_unambiguous_global_plan(
            "state",
            vec![(PathBuf::from("/tmp/a"), global_plan("state", 0x1000))],
        )
        .expect("single global candidate should be accepted")
        .expect("single global candidate should be returned");

        assert_eq!(selected.0, PathBuf::from("/tmp/a"));
        assert_eq!(selected.1.name, "state");
    }

    #[test]
    fn global_plan_selection_prefers_current_module_match() {
        let selected = DwarfAnalyzer::select_global_plan_with_preferred_module(
            "state",
            Path::new("/tmp/current"),
            vec![
                (PathBuf::from("/tmp/other"), global_plan("state", 0x2000)),
                (PathBuf::from("/tmp/current"), global_plan("state", 0x1000)),
            ],
        )
        .expect("current module candidate should be accepted")
        .expect("current module candidate should be returned");

        assert_eq!(selected.0, PathBuf::from("/tmp/current"));
        assert_eq!(
            selected.1.location,
            VariableLocation::Address(AddressExpr::constant(0x1000))
        );
    }

    #[test]
    fn global_plan_selection_rejects_ambiguous_current_module_matches() {
        let err = DwarfAnalyzer::select_global_plan_with_preferred_module(
            "state",
            Path::new("/tmp/current"),
            vec![
                (PathBuf::from("/tmp/current"), global_plan("state", 0x1000)),
                (PathBuf::from("/tmp/current"), global_plan("state", 0x1004)),
                (PathBuf::from("/tmp/other"), global_plan("state", 0x2000)),
            ],
        )
        .expect_err("duplicate current-module candidates should be ambiguous");

        assert!(err.to_string().contains("Ambiguous global 'state'"));
        assert!(err.to_string().contains("2 matches"));
        assert!(err.to_string().contains("/tmp/current"));
        assert!(!err.to_string().contains("/tmp/other"));
    }
}

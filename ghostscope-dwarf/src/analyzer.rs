//! Main DWARF analyzer - unified entry point for all DWARF operations

use crate::{
    core::{GlobalVariableInfo, ModuleAddress, Result, SectionOffsets, SourceLocation},
    module::ModuleData,
    proc_mapping::{ModuleMapping, ProcMappingParser},
};
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
}

/// DWARF analyzer - unified entry point for all DWARF analysis
#[derive(Debug)]
pub struct DwarfAnalyzer {
    /// Process ID
    pid: u32,
    /// Module path -> module data mapping
    modules: HashMap<PathBuf, ModuleData>,
}

impl DwarfAnalyzer {
    /// Create DWARF analyzer from PID (now uses parallel loading)
    pub async fn from_pid(pid: u32) -> Result<Self> {
        Self::from_pid_parallel(pid).await
    }

    /// Resolve struct/class by name (shallow) in a specific module using only indexes
    pub fn resolve_struct_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &mut self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get_mut(&path_buf) {
            return module_data.resolve_struct_type_shallow_by_name(name);
        }
        None
    }

    /// Resolve struct/class by name (shallow) across modules (first match)
    pub fn resolve_struct_type_shallow_by_name(&mut self, name: &str) -> Option<crate::TypeInfo> {
        for module_data in self.modules.values_mut() {
            if let Some(t) = module_data.resolve_struct_type_shallow_by_name(name) {
                return Some(t);
            }
        }
        None
    }

    /// Resolve union by name (shallow) in a specific module
    pub fn resolve_union_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &mut self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get_mut(&path_buf) {
            return module_data.resolve_union_type_shallow_by_name(name);
        }
        None
    }

    /// Resolve union by name (shallow) across modules (first match)
    pub fn resolve_union_type_shallow_by_name(&mut self, name: &str) -> Option<crate::TypeInfo> {
        for module_data in self.modules.values_mut() {
            if let Some(t) = module_data.resolve_union_type_shallow_by_name(name) {
                return Some(t);
            }
        }
        None
    }

    /// Resolve enum by name (shallow) in a specific module
    pub fn resolve_enum_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &mut self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get_mut(&path_buf) {
            return module_data.resolve_enum_type_shallow_by_name(name);
        }
        None
    }

    /// Resolve enum by name (shallow) across modules (first match)
    pub fn resolve_enum_type_shallow_by_name(&mut self, name: &str) -> Option<crate::TypeInfo> {
        for module_data in self.modules.values_mut() {
            if let Some(t) = module_data.resolve_enum_type_shallow_by_name(name) {
                return Some(t);
            }
        }
        None
    }

    /// Create DWARF analyzer from PID using parallel loading
    pub async fn from_pid_parallel(pid: u32) -> Result<Self> {
        Self::from_pid_parallel_with_config(pid, &[], |_event| {}).await
    }

    /// Create DWARF analyzer from PID using parallel loading with progress callback
    pub async fn from_pid_parallel_with_progress<F>(pid: u32, progress_callback: F) -> Result<Self>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        Self::from_pid_parallel_with_config(pid, &[], progress_callback).await
    }

    /// Create DWARF analyzer from PID using parallel loading with debug search paths and progress callback
    pub async fn from_pid_parallel_with_config<F>(
        pid: u32,
        debug_search_paths: &[String],
        progress_callback: F,
    ) -> Result<Self>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        tracing::info!("Creating DWARF analyzer for PID {} (parallel)", pid);

        // Discover all modules for this process using proc mapping parser
        let module_mappings = ProcMappingParser::discover_modules(pid)?;

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
        Self::from_exec_path_with_config(exec_path, &[]).await
    }

    /// Create DWARF analyzer from executable path with debug search paths
    pub async fn from_exec_path_with_config<P: AsRef<std::path::Path>>(
        exec_path: P,
        debug_search_paths: &[String],
    ) -> Result<Self> {
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

        // Load the single module using parallel loading
        match ModuleData::load_parallel(module_mapping, debug_search_paths).await {
            Ok(module_data) => {
                analyzer.modules.insert(exec_path.clone(), module_data);
                tracing::info!(
                    "Created DWARF analyzer for executable {} with 1 module",
                    exec_path.display()
                );
            }
            Err(e) => {
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
    pub(crate) fn from_modules(pid: u32, modules: Vec<ModuleData>) -> Self {
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
            let addresses = module_data.lookup_function_addresses(name);

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

        results
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

    /// Get all variables visible at the given module address with EvaluationResult
    ///
    /// # Arguments
    /// * `module_address` - Module address containing both module path and address offset
    pub fn get_all_variables_at_address(
        &mut self,
        module_address: &ModuleAddress,
    ) -> Result<Vec<crate::data::VariableWithEvaluation>> {
        tracing::info!(
            "Looking up variables at address 0x{:x} in module {}",
            module_address.address,
            module_address.module_display()
        );

        if let Some(module_data) = self.modules.get_mut(&module_address.module_path) {
            module_data.get_all_variables_at_address(module_address.address)
        } else {
            tracing::warn!(
                "Module {} not found in loaded modules",
                module_address.module_display()
            );
            Err(anyhow::anyhow!(
                "Module {} not loaded",
                module_address.module_display()
            ))
        }
    }

    /// Plan a chain access (e.g., r.headers_in) and synthesize a VariableWithEvaluation
    pub fn plan_chain_access(
        &mut self,
        module_address: &ModuleAddress,
        base_var: &str,
        chain: &[String],
    ) -> Result<Option<crate::data::VariableWithEvaluation>> {
        if let Some(module_data) = self.modules.get_mut(&module_address.module_path) {
            module_data.plan_chain_access(module_address.address, base_var, chain)
        } else {
            Ok(None)
        }
    }

    /// Get all loaded module paths
    pub fn get_loaded_modules(&self) -> Vec<&PathBuf> {
        self.modules.keys().collect()
    }

    /// Find global/static variables by name across all loaded modules
    pub fn find_global_variables_by_name(&self, name: &str) -> Vec<(PathBuf, GlobalVariableInfo)> {
        let mut results = Vec::new();
        for (module_path, module_data) in &self.modules {
            let vars = module_data.find_global_variables_by_name(name);
            for v in vars {
                results.push((module_path.clone(), v));
            }
        }
        results
    }

    /// Resolve a variable by CU/DIE offsets in a specific module at an arbitrary address context (for globals)
    pub fn resolve_variable_by_offsets_in_module<P: AsRef<Path>>(
        &mut self,
        module_path: P,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Result<crate::data::VariableWithEvaluation> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get_mut(&path_buf) {
            let items = vec![(cu_off, die_off)];
            let vars = module_data.resolve_variables_by_offsets_at_address(0, &items)?;
            let mut var = vars.into_iter().next().ok_or_else(|| {
                anyhow::anyhow!(
                    "Failed to resolve variable at offsets {:?}/{:?} in module {}",
                    cu_off,
                    die_off,
                    path_buf.display()
                )
            })?;
            if var.dwarf_type.is_none() {
                if let Some(ti) = module_data.shallow_type_for_variable_offsets(cu_off, die_off) {
                    var.type_name = ti.type_name();
                    var.dwarf_type = Some(ti);
                }
            }
            Ok(var)
        } else {
            Err(anyhow::anyhow!(
                "Module {} not loaded",
                module_path.as_ref().display()
            ))
        }
    }

    /// List all global/static variables with usable addresses across all loaded modules
    pub fn list_all_global_variables(&self) -> Vec<(PathBuf, GlobalVariableInfo)> {
        let mut results = Vec::new();
        for (module_path, module_data) in &self.modules {
            for v in module_data.list_all_global_variables() {
                results.push((module_path.clone(), v));
            }
        }
        results
    }

    /// Classify the section type for a link-time virtual address in a specific module
    pub fn classify_section_for_address<P: AsRef<Path>>(
        &self,
        module_path: P,
        vaddr: u64,
    ) -> Option<crate::core::SectionType> {
        let path = module_path.as_ref();
        if let Some(module_data) = self.modules.get(path) {
            module_data.classify_section_for_vaddr(vaddr)
        } else {
            None
        }
    }

    /// Compute static offset for a global variable member chain
    pub fn compute_global_member_static_offset<P: AsRef<Path>>(
        &mut self,
        module_path: P,
        link_address: u64,
        cu_off: gimli::DebugInfoOffset,
        var_die: gimli::UnitOffset,
        fields: &[String],
    ) -> Result<Option<(u64, crate::TypeInfo)>> {
        let path_buf = module_path.as_ref().to_path_buf();
        if let Some(module_data) = self.modules.get_mut(&path_buf) {
            module_data.compute_global_member_static_offset(cu_off, var_die, link_address, fields)
        } else {
            Err(anyhow::anyhow!(
                "Module {} not loaded",
                module_path.as_ref().display()
            ))
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
    pub fn lookup_source_location(
        &mut self,
        module_address: &ModuleAddress,
    ) -> Option<SourceLocation> {
        if let Some(module_data) = self.modules.get_mut(&module_address.module_path) {
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

        results
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
        let mut total_cache_entries = 0;

        for module_data in self.modules.values() {
            total_functions += module_data.get_function_names().len();
            total_variables += module_data.get_variable_names().len();
            total_line_headers += module_data.get_line_header_count();
            let (cache_entries, _) = module_data.get_cache_stats();
            total_cache_entries += cache_entries;
        }

        AnalyzerStats {
            pid: self.pid,
            module_count: self.modules.len(),
            total_functions,
            total_variables,
            total_line_headers,
            total_cache_entries,
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

    /// Find symbol by name in a specific module (compatibility method)
    pub fn find_symbol_by_name_in_module(
        &self,
        module_path: &std::path::Path,
        function_name: &str,
    ) -> Option<Vec<u64>> {
        if let Some(module_data) = self.modules.get(&module_path.to_path_buf()) {
            let addresses = module_data.lookup_function_addresses(function_name);
            if !addresses.is_empty() {
                Some(addresses)
            } else {
                None
            }
        } else {
            None
        }
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
                    debug_info_available: true, // DWARF modules always have debug info
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

        // Get load bias for PID mode (ASLR offset)
        // In PID mode, we need to add the runtime load address to ELF VMAs
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

    /// Compute per-module section offsets (runtime bias) using /proc/[pid]/maps
    /// Only available in -p mode; returns a vector of (module_path, offsets)
    pub fn compute_section_offsets(&self) -> Result<Vec<(PathBuf, u64, SectionOffsets)>> {
        if self.pid == 0 {
            return Err(anyhow::anyhow!(
                "proc_maps_unavailable: offsets computation requires -p mode"
            ));
        }

        let maps = ProcMappingParser::get_proc_maps(self.pid)?;
        let mut results = Vec::new();
        let page_mask: u64 = !0xfffu64; // 4K alignment

        for module_path in self.modules.keys() {
            // Collect mappings for this module (ignore " (deleted)" suffix)
            let module_str = module_path.to_string_lossy();
            let candidates: Vec<&crate::proc_mapping::MemoryMapping> = maps
                .iter()
                .filter(|m| match &m.pathname {
                    Some(p) => {
                        let ps = if let Some(idx) = p.find(" (deleted)") {
                            &p[..idx]
                        } else {
                            p.as_str()
                        };
                        ps == module_str
                    }
                    None => false,
                })
                .collect();

            // Parse object file and build bias per PT_LOAD
            // Re-open file from disk for object parsing; skip on failure
            let file_bytes = match std::fs::read(module_path) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(
                        "compute_section_offsets: skip module '{}' (read failed: {})",
                        module_path.display(),
                        e
                    );
                    continue;
                }
            };
            let obj = match object::File::parse(&file_bytes[..]) {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(
                        "compute_section_offsets: skip module '{}' (parse failed: {})",
                        module_path.display(),
                        e
                    );
                    continue;
                }
            };

            // Build map: (aligned file_off) -> bias
            let mut seg_bias: Vec<(u64, u64, u64)> = Vec::new(); // (file_off_aligned, vaddr, bias)
            for seg in obj.segments() {
                let (file_off, _sz) = seg.file_range();
                let vaddr = seg.address();
                let key = file_off & page_mask;
                // Find mapping with matching file offset page
                if let Some(m) = candidates
                    .iter()
                    .find(|mm| (mm.file_offset & page_mask) == key)
                {
                    let bias = m.start_addr.saturating_sub(vaddr);
                    seg_bias.push((key, vaddr, bias));
                }
            }

            // Helper to find bias for a section address by segment containment
            let find_bias_for = |addr: u64| -> Option<u64> {
                for seg in obj.segments() {
                    let vaddr = seg.address();
                    let vsize = seg.size();
                    if vsize == 0 {
                        continue;
                    }
                    if addr >= vaddr && addr < vaddr + vsize {
                        let (file_off, _sz) = seg.file_range();
                        let key = file_off & page_mask;
                        if let Some((_, _, b)) = seg_bias.iter().find(|(k, _, _)| *k == key) {
                            return Some(*b);
                        }
                    }
                }
                None
            };

            // Pick representative section addresses
            let mut text_addr: Option<u64> = None;
            let mut rodata_addr: Option<u64> = None;
            let mut data_addr: Option<u64> = None;
            let mut bss_addr: Option<u64> = None;

            for sect in obj.sections() {
                if let Ok(name) = sect.name() {
                    let addr = sect.address();
                    if text_addr.is_none() && (name == ".text" || name.starts_with(".text")) {
                        text_addr = Some(addr);
                    } else if rodata_addr.is_none()
                        && (name == ".rodata" || name.starts_with(".rodata"))
                    {
                        rodata_addr = Some(addr);
                    } else if data_addr.is_none() && (name == ".data" || name.starts_with(".data"))
                    {
                        data_addr = Some(addr);
                    } else if bss_addr.is_none() && (name == ".bss" || name.starts_with(".bss")) {
                        bss_addr = Some(addr);
                    }
                }
            }

            let mut offsets = SectionOffsets::default();
            if let Some(a0) = text_addr {
                if let Some(b0) = find_bias_for(a0) {
                    offsets.text = b0;
                }
            }
            if let Some(a1) = rodata_addr {
                if let Some(b1) = find_bias_for(a1) {
                    offsets.rodata = b1;
                }
            }
            if let Some(a2) = data_addr {
                if let Some(b2) = find_bias_for(a2) {
                    offsets.data = b2;
                }
            }
            if let Some(a3) = bss_addr {
                if let Some(b3) = find_bias_for(a3) {
                    offsets.bss = b3;
                }
            }

            // Compute module cookie from first candidate mapping (dev:ino)
            let cookie = if let Some(m) = candidates.first() {
                // device is like "08:01" (hex); split and parse
                let mut maj: u64 = 0;
                let mut min: u64 = 0;
                if let Some((mj, mn)) = m.device.split_once(':') {
                    maj = u64::from_str_radix(mj, 16).unwrap_or(0);
                    min = u64::from_str_radix(mn, 16).unwrap_or(0);
                }
                // Low-risk packing: major[16]@48, minor[16]@32, inode_low[32]@0
                ((maj & 0xffffu64) << 48) | ((min & 0xffffu64) << 32) | (m.inode & 0xffff_ffffu64)
            } else {
                0
            };

            results.push((module_path.clone(), cookie, offsets));
        }

        Ok(results)
    }

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

    /// Find symbol by module address
    pub fn find_symbol_by_module_address(&self, module_address: &ModuleAddress) -> Option<String> {
        if let Some(module_data) = self.modules.get(&module_address.module_path) {
            module_data.find_symbol_by_address(module_address.address)
        } else {
            None
        }
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
    pub total_cache_entries: usize,
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

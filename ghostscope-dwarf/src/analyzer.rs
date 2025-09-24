//! Main DWARF analyzer - unified entry point for all DWARF operations

use crate::{
    core::{ModuleAddress, Result, SourceLocation},
    module::ModuleData,
    proc_mapping::{ModuleMapping, ProcMappingParser},
};
use std::collections::HashMap;
use std::path::PathBuf;

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

    /// Create DWARF analyzer from PID using parallel loading
    pub async fn from_pid_parallel(pid: u32) -> Result<Self> {
        Self::from_pid_parallel_with_progress(pid, |_event| {}).await
    }

    /// Create DWARF analyzer from PID using parallel loading with progress callback
    pub async fn from_pid_parallel_with_progress<F>(pid: u32, progress_callback: F) -> Result<Self>
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
        let modules = crate::loader::ModuleLoader::new(module_mappings)
            .parallel()
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
            base_address: 0x0,    // Base address in file
            loaded_address: None, // No process mapping in exec path mode
            size: 0,              // Will be determined from file size if needed
            is_executable: true,  // This is the main executable
        };

        // Load the single module using parallel loading
        match ModuleData::load_parallel(module_mapping).await {
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

    /// Get module by path
    pub(crate) fn get_module(&self, module_path: &PathBuf) -> Option<&ModuleData> {
        self.modules.get(module_path)
    }

    /// Get mutable module by path
    pub(crate) fn get_module_mut(&mut self, module_path: &PathBuf) -> Option<&mut ModuleData> {
        self.modules.get_mut(module_path)
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

    /// Get all loaded module paths
    pub fn get_loaded_modules(&self) -> Vec<&PathBuf> {
        self.modules.keys().collect()
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

    /// Get all source files (cross-module)
    pub(crate) fn get_all_source_files(&self) -> Vec<(PathBuf, Vec<crate::parser::SourceFile>)> {
        let mut results = Vec::new();
        for (module_path, _module_data) in &self.modules {
            if let Some(module) = self.get_module(module_path) {
                let files = module.get_all_files();
                if !files.is_empty() {
                    results.push((module_path.clone(), files));
                }
            }
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
        for (module_path, _module_data) in &self.modules {
            if self.is_main_executable_module(module_path) {
                return Some(MainExecutableInfo {
                    path: module_path.to_string_lossy().to_string(),
                });
            }
        }
        None
    }

    /// Check if a module is the main executable (not a shared library)
    fn is_main_executable_module(&self, module_path: &PathBuf) -> bool {
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

        for (_module_path, module_data) in &self.modules {
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
                SharedLibraryInfo {
                    from_address: mapping.loaded_address.unwrap_or(0),
                    to_address: mapping.loaded_address.map_or(0, |addr| addr + mapping.size),
                    symbols_read: !module_data.get_function_names().is_empty(),
                    debug_info_available: true, // DWARF modules always have debug info
                    library_path: path.to_string_lossy().to_string(),
                    size: mapping.size,
                }
            })
            .collect()
    }

    /// Check if a module is a shared library
    fn is_shared_library(&self, module_path: &PathBuf) -> bool {
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
    pub from_address: u64,          // Starting address in memory
    pub to_address: u64,            // Ending address in memory
    pub symbols_read: bool,         // Whether symbols were successfully read
    pub debug_info_available: bool, // Whether debug information is available
    pub library_path: String,       // Full path to the library file
    pub size: u64,                  // Size of the library in memory
}

/// Simple file information compatible with ghostscope-binary
#[derive(Debug, Clone)]
pub struct SimpleFileInfo {
    pub full_path: String,
    pub basename: String,
    pub directory: String,
}

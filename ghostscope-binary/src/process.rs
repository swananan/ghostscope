// Process-level binary analysis with multi-module support
// Handles main executable + dynamic libraries through /proc/PID/maps

use crate::binary_analyzer::BinaryAnalyzer;
use crate::dwarf::{FunctionInfo, SourceLocation};
use crate::file::SourceFile;
use crate::scoped_variables::VariableResult;
use crate::{BinaryError, Result};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// Memory mapping information from /proc/PID/maps
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String, // r-xp, rw-p etc.
    pub offset: u64,         // File offset
    pub device: String,      // major:minor device
    pub inode: u64,
    pub pathname: Option<String>, // Binary file path
}

/// Information about a loaded module (executable or dynamic library)
#[derive(Debug)]
pub struct ModuleInfo {
    pub path: String,
    pub binary_analyzer: BinaryAnalyzer,
    pub base_address: u64,   // Base address in file
    pub loaded_address: u64, // Loaded address in process
    pub size: u64,
    pub is_executable: bool, // Main executable vs dynamic library
}

/// Information about a shared library (similar to GDB's "info share" output)
#[derive(Debug, Clone)]
pub struct SharedLibraryInfo {
    pub from_address: u64,          // Starting address in memory
    pub to_address: u64,            // Ending address in memory
    pub symbols_read: bool,         // Whether symbols were successfully read
    pub debug_info_available: bool, // Whether debug information is available
    pub library_path: String,       // Full path to the library file
    pub size: u64,                  // Size of the library in memory
}

// AddressSpaceManager removed - we only need proc mappings for module discovery

/// Process-level binary analyzer supporting multiple modules
#[derive(Debug)]
pub struct ProcessAnalyzer {
    pub pid: u32,
    pub modules: HashMap<String, ModuleInfo>, // path -> module info
    pub mappings: Vec<MemoryMapping>,         // proc mappings for module discovery only
}

impl ProcessAnalyzer {
    /// Create ProcessAnalyzer from PID by parsing /proc/PID/maps
    pub fn from_pid(pid: u32) -> Result<Self> {
        info!("Creating process analyzer for PID: {}", pid);

        let mappings = Self::parse_proc_maps(pid)?;
        info!("Found {} memory mappings", mappings.len());

        let mut modules = HashMap::new();

        // Process executable mappings to find modules
        for mapping in &mappings {
            if let Some(path) = &mapping.pathname {
                // Only process executable mappings and avoid duplicates
                if mapping.permissions.contains('x') && !modules.contains_key(path) {
                    match Self::try_create_module(path, mapping) {
                        Ok(module_info) => {
                            debug!("Added module: {} at 0x{:x}", path, mapping.start_addr);
                            modules.insert(path.clone(), module_info);
                        }
                        Err(e) => {
                            debug!("Skipping module {}: {}", path, e);
                        }
                    }
                }
            }
        }

        info!("Successfully loaded {} modules", modules.len());

        Ok(Self {
            pid,
            modules,
            mappings,
        })
    }

    /// Parse /proc/PID/maps file
    fn parse_proc_maps(pid: u32) -> Result<Vec<MemoryMapping>> {
        let maps_path = format!("/proc/{}/maps", pid);
        debug!("Reading memory mappings from: {}", maps_path);

        let content = fs::read_to_string(&maps_path).map_err(|e| {
            BinaryError::ProcessInfoError(format!("Cannot read {}: {}", maps_path, e))
        })?;

        let mut mappings = Vec::new();

        for line in content.lines() {
            if let Some(mapping) = Self::parse_maps_line(line) {
                mappings.push(mapping);
            }
        }

        Ok(mappings)
    }

    /// Parse single line from /proc/PID/maps
    /// Format: address perms offset dev inode pathname
    /// Example: 7f8b8c000000-7f8b8c028000 r--p 00000000 08:01 2097153 /lib64/ld-linux-x86-64.so.2
    fn parse_maps_line(line: &str) -> Option<MemoryMapping> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let start_addr = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(addr_parts[1], 16).ok()?;

        // Parse other fields
        let permissions = parts[1].to_string();
        let offset = u64::from_str_radix(parts[2], 16).ok()?;
        let device = parts[3].to_string();
        let inode = parts[4].parse().ok()?;

        // Pathname is optional (might be empty for anonymous mappings)
        let pathname = if parts.len() > 5 {
            let path_str = parts[5];
            // Filter out special entries like [stack], [vdso], etc.
            if path_str.starts_with('[') && path_str.ends_with(']') {
                None
            } else {
                Some(path_str.to_string())
            }
        } else {
            None
        };

        Some(MemoryMapping {
            start_addr,
            end_addr,
            permissions,
            offset,
            device,
            inode,
            pathname,
        })
    }

    /// Try to create a module from a memory mapping
    fn try_create_module(path: &str, mapping: &MemoryMapping) -> Result<ModuleInfo> {
        debug!("Trying to create module from: {}", path);

        // Check if file exists and is accessible
        let path_buf = PathBuf::from(path);
        if !path_buf.exists() {
            return Err(BinaryError::NotFound(path_buf));
        }

        // Create binary analyzer
        let binary_analyzer = BinaryAnalyzer::new(path, None)?;

        // Determine if this is the main executable or a dynamic library
        let is_executable = !path.contains(".so");

        let module_info = ModuleInfo {
            path: path.to_string(),
            binary_analyzer,
            base_address: mapping.offset,
            loaded_address: mapping.start_addr,
            size: mapping.end_addr - mapping.start_addr,
            is_executable,
        };

        debug!(
            "Successfully created module: {} (size: {} bytes)",
            path, module_info.size
        );
        Ok(module_info)
    }

    /// Resolve binary offset to uprobe target (binary_path, file_offset)
    /// Since we work with binary offsets directly, this is a simple lookup
    pub fn resolve_offset_to_uprobe(
        &self,
        module_path: &str,
        binary_offset: u64,
    ) -> Option<(String, u64)> {
        if let Some(_module) = self.modules.get(module_path) {
            debug!(
                "Resolved offset 0x{:x} in module {} for uprobe",
                binary_offset, module_path
            );
            return Some((module_path.to_string(), binary_offset));
        }

        warn!("Module '{}' not found", module_path);
        None
    }

    /// Get module by path
    pub fn get_module(&self, module_path: &str) -> Option<&ModuleInfo> {
        self.modules.get(module_path)
    }

    /// Get module by path (mutable)
    pub fn get_module_mut(&mut self, module_path: &str) -> Option<&mut ModuleInfo> {
        self.modules.get_mut(module_path)
    }

    /// Get all loaded modules
    pub fn get_all_modules(&self) -> &HashMap<String, ModuleInfo> {
        &self.modules
    }

    /// Get main executable module
    pub fn get_main_executable(&self) -> Option<&ModuleInfo> {
        self.modules.values().find(|m| m.is_executable)
    }

    /// Get main executable module (mutable)
    pub fn get_main_executable_mut(&mut self) -> Option<&mut ModuleInfo> {
        self.modules.values_mut().find(|m| m.is_executable)
    }

    // ===== Cross-Module Query Methods =====

    /// Lookup variable at binary address in specific module
    pub fn lookup_variable_by_address(
        &mut self,
        module_path: &str,
        address: u64,
        var_name: &str,
    ) -> Option<VariableResult> {
        if let Some(module) = self.get_module_mut(module_path) {
            debug!(
                "Looking up variable '{}' at binary address 0x{:x} in module '{}'",
                var_name, address, module_path
            );

            // Query variable from the module's binary analyzer
            if let Some(dwarf_ctx) = module.binary_analyzer.dwarf_context_mut() {
                return dwarf_ctx.find_variable_at_pc(address, var_name);
            }
        }

        debug!(
            "Variable '{}' not found at address 0x{:x} in module '{}'",
            var_name, address, module_path
        );
        None
    }

    /// Get variable size at binary offset in specific module
    pub fn get_variable_size_in_module(
        &mut self,
        module_path: &str,
        binary_offset: u64,
        var_name: &str,
    ) -> Option<u64> {
        if let Some(module) = self.get_module_mut(module_path) {
            return module
                .binary_analyzer
                .get_variable_size(binary_offset, var_name);
        }
        None
    }

    /// Lookup source location for binary address in specific module
    pub fn lookup_source_location_by_address(
        &mut self,
        module_path: &str,
        address: u64,
    ) -> Option<SourceLocation> {
        if let Some(module) = self.get_module_mut(module_path) {
            debug!(
                "Looking up source location for binary address 0x{:x} in module '{}'",
                address, module_path
            );

            return module.binary_analyzer.get_source_location(address);
        }

        debug!(
            "Source location not found for address 0x{:x} in module '{}'",
            address, module_path
        );
        None
    }

    /// Lookup function information at binary address in specific module
    pub fn lookup_function_info_by_address(
        &self,
        module_path: &str,
        address: u64,
    ) -> Option<FunctionInfo> {
        if let Some(module) = self.get_module(module_path) {
            return module.binary_analyzer.get_function_info(address);
        }
        None
    }

    /// Lookup function information (symbol + source location) by name across all modules
    /// Returns (module_path, symbol, source_location) if found
    pub fn lookup_function_info_by_name(
        &mut self,
        function_name: &str,
    ) -> Option<(String, crate::symbol::Symbol, Option<SourceLocation>)> {
        debug!(
            "Searching for function '{}' across all modules",
            function_name
        );

        for (path, module) in &mut self.modules {
            debug!("Checking module: {}", path);

            // First find the function symbol in this module
            if let Some(symbol) = module.binary_analyzer.find_symbol(function_name) {
                info!(
                    "Found function '{}' at offset 0x{:x} in module '{}'",
                    function_name, symbol.address, path
                );

                // Store symbol info before any more borrowing
                let symbol_address = symbol.address;
                let symbol_copy = crate::symbol::Symbol {
                    name: symbol.name.clone(),
                    address: symbol.address,
                    size: symbol.size,
                    kind: symbol.kind.clone(),
                    is_global: symbol.is_global,
                    section_name: symbol.section_name.clone(),
                    section_viraddr: symbol.section_viraddr,
                    section_file_offset: symbol.section_file_offset,
                };

                // Now try to get source location for this symbol's address
                let source_location = module.binary_analyzer.get_source_location(symbol_address);
                if let Some(ref src_loc) = source_location {
                    info!(
                        "Found source location for '{}': {}:{}",
                        function_name, src_loc.file_path, src_loc.line_number
                    );
                } else {
                    debug!(
                        "No source location found for function '{}' at offset 0x{:x}",
                        function_name, symbol_address
                    );
                }

                return Some((path.clone(), symbol_copy, source_location));
            }
        }

        debug!("Function '{}' not found in any module", function_name);
        None
    }

    /// Lookup all function addresses (binary offsets) by name across all modules
    pub fn lookup_addresses_by_function_name(&self, func_name: &str) -> Vec<(String, Vec<u64>)> {
        let mut results = Vec::new();

        for (path, module) in &self.modules {
            let addresses = module.binary_analyzer.get_all_function_addresses(func_name);
            if !addresses.is_empty() {
                // Return binary offsets directly (no virtual address conversion)
                debug!(
                    "Found {} addresses for function '{}' in module '{}'",
                    addresses.len(),
                    func_name,
                    path
                );
                results.push((path.clone(), addresses));
            }
        }

        results
    }

    /// Lookup all addresses (binary offsets) for a source line across all modules
    pub fn lookup_addresses_by_source_line(
        &mut self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<(String, Vec<u64>)> {
        let mut results = Vec::new();

        for (path, module) in &mut self.modules {
            let addresses = module
                .binary_analyzer
                .get_all_source_line_addresses(file_path, line_number);
            if !addresses.is_empty() {
                // Return binary offsets directly (no virtual address conversion)
                debug!(
                    "Found {} addresses for {}:{} in module '{}'",
                    addresses.len(),
                    file_path,
                    line_number,
                    path
                );
                results.push((path.clone(), addresses));
            }
        }

        results
    }

    /// Lookup all source files from all modules
    pub fn lookup_all_source_files(&self) -> Vec<(String, Vec<SourceFile>)> {
        let mut all_files = Vec::new();

        for (path, module) in &self.modules {
            if let Some(dwarf_ctx) = module.binary_analyzer.dwarf_context() {
                let files = dwarf_ctx.get_all_source_files();
                if !files.is_empty() {
                    all_files.push((path.clone(), files));
                }
            }
        }

        all_files
    }

    /// Lookup aggregated file list (no duplicates by path)
    pub fn lookup_unique_source_files(&self) -> Vec<SourceFile> {
        let mut unique_files = HashMap::new();

        for (_, module) in &self.modules {
            if let Some(dwarf_ctx) = module.binary_analyzer.dwarf_context() {
                let files = dwarf_ctx.get_all_source_files();
                for file in files {
                    // Use full_path as key to avoid duplicates
                    unique_files.insert(file.full_path.clone(), file);
                }
            }
        }

        unique_files.into_values().collect()
    }

    /// Get frame base offset at binary offset in specific module
    pub fn get_frame_base_offset_in_module(
        &self,
        module_path: &str,
        binary_offset: u64,
    ) -> Option<i64> {
        if let Some(module) = self.get_module(module_path) {
            return module.binary_analyzer.get_frame_base_offset(binary_offset);
        }
        None
    }

    // All virtual address compatibility methods removed - use module-based queries directly

    /// Get statistics about loaded modules
    pub fn get_module_stats(&self) -> ModuleStats {
        let mut stats = ModuleStats {
            total_modules: self.modules.len(),
            executable_modules: 0,
            library_modules: 0,
            total_symbols: 0,
            modules_with_debug_info: 0,
        };

        for module in self.modules.values() {
            if module.is_executable {
                stats.executable_modules += 1;
            } else {
                stats.library_modules += 1;
            }

            stats.total_symbols += module.binary_analyzer.symbol_table.len();

            if module.binary_analyzer.dwarf_context().is_some() {
                stats.modules_with_debug_info += 1;
            }
        }

        stats
    }

    /// Get shared library information (similar to GDB's "info share")
    /// Returns information about loaded dynamic libraries, excluding the main executable
    pub fn get_shared_library_info(&self) -> Vec<SharedLibraryInfo> {
        let mut libraries = Vec::new();

        for module in self.modules.values() {
            // Skip the main executable, only include dynamic libraries
            if !module.is_executable {
                let has_symbols = module.binary_analyzer.symbol_table.len() > 0;
                let has_debug_info = module
                    .binary_analyzer
                    .dwarf_context()
                    .map(|ctx| ctx.has_valid_debug_info())
                    .unwrap_or(false);

                libraries.push(SharedLibraryInfo {
                    from_address: module.loaded_address,
                    to_address: module.loaded_address + module.size - 1,
                    symbols_read: has_symbols,
                    debug_info_available: has_debug_info,
                    library_path: module.path.clone(),
                    size: module.size,
                });
            }
        }

        // Sort by load address for consistent display
        libraries.sort_by_key(|lib| lib.from_address);
        libraries
    }

    /// Get enhanced variable locations at a specific address in a module
    /// Lookup all variables at binary address in specific module (enhanced information)
    pub fn lookup_all_variables_by_address(
        &mut self,
        module_path: &str,
        address: u64,
    ) -> Vec<crate::dwarf::EnhancedVariableLocation> {
        if let Some(module) = self.get_module_mut(module_path) {
            if let Some(dwarf_context) = module.binary_analyzer.dwarf_context_mut() {
                return dwarf_context.get_enhanced_variable_locations(address);
            }
        }
        Vec::new()
    }

    /// Find symbol by address in a specific module
    /// Encapsulates access to binary_analyzer.find_symbol_by_address()
    pub fn find_symbol_by_address_in_module(
        &self,
        module_path: &str,
        address: u64,
    ) -> Option<crate::symbol::Symbol> {
        if let Some(module) = self.get_module(module_path) {
            return module
                .binary_analyzer
                .find_symbol_by_address(address)
                .map(|symbol| symbol.clone());
        }
        None
    }

    /// Find symbol by name in a specific module
    pub fn find_symbol_by_name_in_module(
        &self,
        module_path: &str,
        name: &str,
    ) -> Option<crate::symbol::Symbol> {
        if let Some(module) = self.get_module(module_path) {
            return module
                .binary_analyzer
                .find_symbol(name)
                .map(|symbol| symbol.clone());
        }
        None
    }

    /// Get all functions from all modules
    pub fn lookup_all_function_names(&self) -> Vec<String> {
        let mut all_functions = Vec::new();

        for (_, module) in self.modules.iter() {
            let functions: Vec<String> = module
                .binary_analyzer
                .symbol_table
                .get_functions()
                .iter()
                .map(|sym| {
                    format!(
                        "{}::{}",
                        module.path.split('/').last().unwrap_or("unknown"),
                        sym.name
                    )
                })
                .collect();
            all_functions.extend(functions);
        }

        all_functions
    }

    /// Find matching functions across all modules
    pub fn lookup_functions_by_pattern(&self, pattern: &str) -> Vec<String> {
        let mut matching_functions = Vec::new();

        for (_, module) in self.modules.iter() {
            let matches = module.binary_analyzer.symbol_table.find_matching(pattern);

            for sym in matches {
                matching_functions.push(sym.name.clone());
            }
        }

        matching_functions
    }

    /// Get all file info from all modules (for file listing)
    /// Encapsulates access to dwarf_context.get_all_file_info()
    pub fn lookup_all_file_info(&self) -> Result<Vec<crate::file::SimpleFileInfo>> {
        let mut all_file_info = Vec::new();

        for (_module_path, module) in &self.modules {
            if let Some(dwarf_context) = module.binary_analyzer.dwarf_context() {
                match dwarf_context.get_all_file_info() {
                    Ok(file_info_vec) => {
                        all_file_info.extend(file_info_vec);
                    }
                    Err(e) => {
                        warn!(
                            "Failed to get file info from module '{}': {}",
                            _module_path, e
                        );
                    }
                }
            }
        }

        Ok(all_file_info)
    }

    /// Get file info grouped by module for UI display
    /// Returns Vec of (module_path, Vec<SimpleFileInfo>)
    pub fn get_grouped_file_info_by_module(
        &self,
    ) -> Result<Vec<(String, Vec<crate::file::SimpleFileInfo>)>> {
        let mut grouped: Vec<(String, Vec<crate::file::SimpleFileInfo>)> = Vec::new();

        for (module_path, module) in &self.modules {
            if let Some(dwarf_context) = module.binary_analyzer.dwarf_context() {
                match dwarf_context.get_all_file_info() {
                    Ok(file_info_vec) => {
                        if !file_info_vec.is_empty() {
                            grouped.push((module_path.clone(), file_info_vec));
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Failed to get file info from module '{}': {}",
                            module_path, e
                        );
                    }
                }
            }
        }

        // Sort modules by path for stable UI
        grouped.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(grouped)
    }

    /// Execute evaluation context operations on enhanced variables in a specific module
    /// This encapsulates the pattern of getting enhanced variables and then evaluating them
    pub fn get_and_evaluate_enhanced_variables(
        &mut self,
        module_path: &str,
        address: u64,
        evaluation_context: &crate::expression::EvaluationContext,
    ) -> Vec<crate::dwarf::EnhancedVariableLocation> {
        if let Some(module) = self.get_module_mut(module_path) {
            if let Some(dwarf_context) = module.binary_analyzer.dwarf_context_mut() {
                let mut vars = dwarf_context.get_enhanced_variable_locations(address);

                // Evaluate variables that don't have evaluation results
                for var in vars.iter_mut() {
                    if var.evaluation_result.is_none() {
                        if let Some(expression_evaluator) = dwarf_context.get_expression_evaluator()
                        {
                            match expression_evaluator.evaluate_location_with_enhanced_types(
                                &var.location_at_address,
                                address,
                                evaluation_context,
                                None, // No frame context for static analysis
                            ) {
                                Ok(evaluation_result) => {
                                    var.evaluation_result = Some(evaluation_result);
                                }
                                Err(e) => {
                                    warn!(
                                        "Failed to evaluate variable '{}' at 0x{:x} in module '{}': {}",
                                        var.variable.name, address, module_path, e
                                    );
                                }
                            }
                        }
                    }
                }

                return vars;
            }
        }
        Vec::new()
    }
}

/// Statistics about loaded modules
#[derive(Debug, Clone)]
pub struct ModuleStats {
    pub total_modules: usize,
    pub executable_modules: usize,
    pub library_modules: usize,
    pub total_symbols: usize,
    pub modules_with_debug_info: usize,
}

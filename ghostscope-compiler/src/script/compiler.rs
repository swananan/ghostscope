use crate::script::ast::{Program, Statement, TracePattern};
use crate::CompileError;
// BinaryAnalyzer is now internal to ghostscope-binary, use DwarfAnalyzer instead
use inkwell::context::Context;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use tracing::{debug, error, info, warn};

/// Resolved target information from DWARF queries
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub function_name: Option<String>,
    pub function_address: Option<u64>,
    pub binary_path: String,
    pub uprobe_offset: Option<u64>,
    pub pattern: TracePattern,
}

/// Complete uprobe configuration ready for attachment
#[derive(Debug, Clone)]
pub struct UProbeConfig {
    /// The trace pattern this uprobe corresponds to
    pub trace_pattern: TracePattern,

    /// Target binary path
    pub binary_path: String,

    /// Function name (for FunctionName patterns)
    pub function_name: Option<String>,

    /// Resolved function address in the binary
    pub function_address: Option<u64>,

    /// Calculated uprobe offset (for aya uprobe attachment)
    pub uprobe_offset: Option<u64>,

    /// Process ID to attach to (None means attach to all instances)
    pub target_pid: Option<u32>,

    /// eBPF bytecode for this uprobe
    pub ebpf_bytecode: Vec<u8>,

    /// eBPF function name for this uprobe (e.g., "ghostscope_main_0", "ghostscope_printf_1")
    pub ebpf_function_name: String,

    /// Trace ID assigned by compiler (starts from starting_trace_id and increments)
    pub assigned_trace_id: u32,
}

/// Compilation result containing all uprobe configurations
#[derive(Debug)]
pub struct CompilationResult {
    pub uprobe_configs: Vec<UProbeConfig>,
    pub trace_count: usize,
    pub target_info: String,
    pub failed_targets: Vec<FailedTarget>, // New field for failed compilation info
    pub next_available_trace_id: u32,      // Next trace_id that can be used by trace_manager
}

/// Information about a target that failed to compile
#[derive(Debug, Clone)]
pub struct FailedTarget {
    pub target_name: String,
    pub pc_address: u64,
    pub error_message: String,
}

/// Unified AST compiler that performs DWARF queries and code generation in single pass
pub struct AstCompiler<'a> {
    process_analyzer: Option<&'a mut ghostscope_dwarf::DwarfAnalyzer>,
    uprobe_configs: Vec<UProbeConfig>,
    failed_targets: Vec<FailedTarget>, // Track failed compilation attempts
    binary_path_hint: Option<String>,
    starting_trace_id: u32, // Starting trace_id passed from trace_manager
    current_trace_id: u32,  // Current trace_id counter (increments for each uprobe)
    save_options: Option<crate::SaveOptions>, // Save options for file output
}

impl<'a> AstCompiler<'a> {
    pub fn new(
        process_analyzer: Option<&'a mut ghostscope_dwarf::DwarfAnalyzer>,
        binary_path_hint: Option<String>,
        starting_trace_id: u32,
        save_options: crate::SaveOptions,
    ) -> Self {
        Self {
            process_analyzer,
            uprobe_configs: Vec::new(),
            failed_targets: Vec::new(),
            binary_path_hint,
            starting_trace_id,
            current_trace_id: starting_trace_id,
            save_options: Some(save_options),
        }
    }

    /// Main entry point: compile AST with integrated DWARF queries and code generation
    pub fn compile_program(
        &mut self,
        program: &Program,
        pid: Option<u32>,
    ) -> Result<CompilationResult, CompileError> {
        info!(
            "Starting unified AST compilation with {} statements",
            program.statements.len()
        );

        // AST will be saved immediately when we know the target details in generate_ebpf_for_target

        // Single-pass traversal: process each statement immediately
        // Continue processing even if some trace points fail
        let mut successful_trace_points = 0;
        let mut failed_trace_points = 0;

        for (index, stmt) in program.statements.iter().enumerate() {
            match stmt {
                Statement::TracePoint { pattern, body } => {
                    debug!("Processing trace point {}: {:?}", index, pattern);
                    match self.process_trace_point(pattern, body, pid, index) {
                        Ok(_) => {
                            successful_trace_points += 1;
                            info!(
                                "✓ Successfully processed trace point {}: {:?}",
                                index, pattern
                            );
                        }
                        Err(e) => {
                            failed_trace_points += 1;
                            error!(
                                "❌ Failed to process trace point {}: {:?} - Error: {}",
                                index, pattern, e
                            );
                            // Continue processing other trace points
                        }
                    }
                }
                _ => {
                    warn!("Skipping non-trace statement: {:?}", stmt);
                    // TODO: Non-trace statements are ignored in current implementation
                }
            }
        }

        if successful_trace_points > 0 && failed_trace_points == 0 {
            info!(
                "All {} trace points processed successfully",
                successful_trace_points
            );
        } else if successful_trace_points > 0 && failed_trace_points > 0 {
            warn!(
                "Partial success: {} trace points successful, {} failed",
                successful_trace_points, failed_trace_points
            );
        } else {
            error!("All {} trace points failed to process", failed_trace_points);
            return Err(CompileError::Other(format!(
                "All {} trace points failed to process",
                failed_trace_points
            )));
        }

        // Generate target info summary
        let target_info = self.generate_target_info_summary();

        info!(
            "Compilation completed: {} uprobe configs generated",
            self.uprobe_configs.len()
        );

        Ok(CompilationResult {
            uprobe_configs: std::mem::take(&mut self.uprobe_configs),
            failed_targets: std::mem::take(&mut self.failed_targets),
            trace_count: self.uprobe_configs.len(),
            target_info,
            next_available_trace_id: self.current_trace_id,
        })
    }

    /// Process a trace point: resolve target + generate eBPF in one step
    fn process_trace_point(
        &mut self,
        pattern: &TracePattern,
        statements: &[Statement],
        pid: Option<u32>,
        index: usize,
    ) -> Result<(), CompileError> {
        match pattern {
            TracePattern::SourceLine {
                file_path,
                line_number,
            } => {
                // Obtain addresses first in a separate scope to avoid holding a mutable borrow of self
                let module_addresses = if let Some(analyzer) = &mut self.process_analyzer {
                    analyzer.lookup_addresses_by_source_line(file_path, *line_number)
                } else {
                    Vec::new()
                };

                if module_addresses.is_empty() {
                    warn!(
                        "No addresses resolved for source line {}:{}; skipping",
                        file_path, line_number
                    );
                    return Ok(());
                }

                debug!(
                    "Resolved {}:{} to {} address(es)",
                    file_path,
                    line_number,
                    module_addresses.len()
                );

                // Process each module and its addresses - continue even if some fail
                let mut successful_addresses = 0;
                let mut failed_addresses = 0;

                let mut pc_idx = 0;
                for module_address in &module_addresses {
                    let target_info = ResolvedTarget {
                        function_name: Some(format!("{}:{}", file_path, line_number)),
                        function_address: Some(module_address.address),
                        binary_path: module_address.module_path.to_string_lossy().to_string(),
                        uprobe_offset: Some(module_address.address), // For line addresses, offset equals address
                        pattern: pattern.clone(),
                    };

                    match self.generate_ebpf_for_target(&target_info, statements, pid) {
                        Ok(uprobe_config) => {
                            self.uprobe_configs.push(uprobe_config);
                            successful_addresses += 1;
                            info!(
                                "✓ Successfully generated eBPF for {}:{} at 0x{:x}",
                                file_path, line_number, module_address.address
                            );
                        }
                        Err(e) => {
                            failed_addresses += 1;
                            error!(
                                "❌ Failed to generate eBPF for {}:{} at 0x{:x}: {}",
                                file_path, line_number, module_address.address, e
                            );

                            // Record this failed target
                            self.failed_targets.push(FailedTarget {
                                target_name: format!("{}:{}", file_path, line_number),
                                pc_address: module_address.address,
                                error_message: e.to_string(),
                            });

                            // Continue processing other addresses
                        }
                    }
                    pc_idx += 1;
                }

                // Log summary for this trace point
                if successful_addresses > 0 && failed_addresses == 0 {
                    info!(
                        "All {} addresses for {}:{} processed successfully",
                        successful_addresses, file_path, line_number
                    );
                } else if successful_addresses > 0 && failed_addresses > 0 {
                    warn!(
                        "Partial success for {}:{}: {} successful, {} failed addresses",
                        file_path, line_number, successful_addresses, failed_addresses
                    );
                } else {
                    error!(
                        "All {} addresses for {}:{} failed to process",
                        failed_addresses, file_path, line_number
                    );
                    // Don't return error here - let the caller decide based on overall results
                }
                Ok(())
            }
            TracePattern::FunctionName(func_name) => {
                // Resolve all addresses for the function name and generate per-PC programs
                let module_addresses = if let Some(analyzer) = &mut self.process_analyzer {
                    analyzer.lookup_function_addresses(func_name)
                } else {
                    Vec::new()
                };

                if module_addresses.is_empty() {
                    warn!(
                        "No addresses resolved for function '{}'; skipping",
                        func_name
                    );
                    return Ok(());
                }

                let total_addresses: usize = module_addresses.len();
                debug!(
                    "Resolved function '{}' to {} address(es) across {} modules",
                    func_name,
                    total_addresses,
                    module_addresses.len()
                );

                // We may need analyzer again to compute precise uprobe offsets
                // Process each address - continue even if some fail
                let mut successful_addresses = 0;
                let mut failed_addresses = 0;

                let mut pc_idx = 0;
                for module_address in &module_addresses {
                    // For DwarfAnalyzer, the address is already the binary offset we need for uprobe
                    let uprobe_offset = module_address.address;

                    let target_info = ResolvedTarget {
                        function_name: Some(func_name.clone()),
                        function_address: Some(module_address.address),
                        binary_path: module_address.module_path.to_string_lossy().to_string(),
                        uprobe_offset: Some(uprobe_offset),
                        pattern: pattern.clone(),
                    };

                    match self.generate_ebpf_for_target(&target_info, statements, pid) {
                        Ok(uprobe_config) => {
                            self.uprobe_configs.push(uprobe_config);
                            successful_addresses += 1;
                            info!(
                                "✓ Successfully generated eBPF for function '{}' at 0x{:x}",
                                func_name, module_address.address
                            );
                        }
                        Err(e) => {
                            failed_addresses += 1;
                            error!(
                                "❌ Failed to generate eBPF for function '{}' at 0x{:x}: {}",
                                func_name, module_address.address, e
                            );

                            // Record this failed target
                            self.failed_targets.push(FailedTarget {
                                target_name: func_name.clone(),
                                pc_address: module_address.address,
                                error_message: e.to_string(),
                            });

                            // Continue processing other addresses
                        }
                    }
                    pc_idx += 1;
                }

                // Log summary for this trace point
                if successful_addresses > 0 && failed_addresses == 0 {
                    info!(
                        "All {} addresses for function '{}' processed successfully",
                        successful_addresses, func_name
                    );
                } else if successful_addresses > 0 && failed_addresses > 0 {
                    warn!(
                        "Partial success for function '{}': {} successful, {} failed addresses",
                        func_name, successful_addresses, failed_addresses
                    );
                } else {
                    error!(
                        "All {} addresses for function '{}' failed to process",
                        failed_addresses, func_name
                    );
                    // Don't return error here - let the caller decide based on overall results
                }
                Ok(())
            }
            _ => {
                unimplemented!();
            }
        }
    }

    /// Generate eBPF bytecode for resolved target
    fn generate_ebpf_for_target(
        &mut self,
        target: &ResolvedTarget,
        statements: &[Statement],
        pid: Option<u32>,
    ) -> Result<UProbeConfig, CompileError> {
        let context = Context::create();

        // Allocate trace_id for this uprobe
        let assigned_trace_id = self.current_trace_id;
        self.current_trace_id += 1;

        // Generate unified eBPF function name using the assigned trace_id
        let ebpf_function_name = self.generate_unified_function_name(target, assigned_trace_id);

        info!(
            "Generating eBPF code for '{}' (function: {})",
            target.function_name.as_deref().unwrap_or("unknown"),
            ebpf_function_name
        );

        // Save AST immediately when we know the target details (before generating LLVM IR)
        if let Some(save_options) = self.get_save_options() {
            if save_options.save_ast {
                let ast_filename = self.generate_filename(target, assigned_trace_id, "txt");
                // Create a Program from statements to save
                let program = Program {
                    statements: statements.to_vec(),
                };
                if let Err(e) = self.save_ast_to_file(&program, &ast_filename) {
                    warn!("Failed to save AST to {}: {}", ast_filename, e);
                } else {
                    info!("Saved AST to: {}", ast_filename);
                }
            }
        }

        // Use new codegen implementation with full AST compilation
        let mut codegen_new = crate::ebpf::context::NewCodeGen::new_with_process_analyzer(
            &context,
            &ebpf_function_name,
            self.process_analyzer.as_deref_mut(),
            Some(assigned_trace_id),
        )
        .map_err(|e| CompileError::LLVM(format!("Failed to create new codegen: {}", e)))?;

        // Set compile-time context for DWARF queries
        if let Some(function_address) = target.function_address {
            codegen_new.set_compile_time_context(function_address, target.binary_path.clone());
        }

        info!(
            "Compiling full AST program with {} statements",
            statements.len()
        );

        // Use full AST compilation
        let _main_function = codegen_new
            .compile_program(
                &crate::script::ast::Program { statements: vec![] }, // Empty program - statements passed separately
                &ebpf_function_name,
                statements,
                pid,
                target.function_address,
                Some(&target.binary_path),
            )
            .map_err(|e| CompileError::LLVM(format!("Failed to compile AST program: {}", e)))?;

        let module = codegen_new.get_module();

        // Generate eBPF bytecode from LLVM module
        let ebpf_bytecode =
            self.generate_ebpf_bytecode(module, &ebpf_function_name, target, assigned_trace_id)?;

        Ok(UProbeConfig {
            trace_pattern: target.pattern.clone(),
            binary_path: target.binary_path.clone(),
            function_name: target.function_name.clone(),
            function_address: target.function_address,
            uprobe_offset: target.uprobe_offset,
            target_pid: pid,
            ebpf_bytecode,
            ebpf_function_name,
            assigned_trace_id,
        })
    }

    /// Generate summary of all targets for reporting
    fn generate_target_info_summary(&self) -> String {
        if self.uprobe_configs.is_empty() {
            return "no_targets".to_string();
        }

        let first_target = &self.uprobe_configs[0];
        match &first_target.function_name {
            Some(name) => name.clone(),
            None => format!("addr_0x{:x}", first_target.function_address.unwrap_or(0)),
        }
    }

    /// Generate unified eBPF function name for all contexts
    ///
    /// This is the SINGLE source of truth for eBPF function naming.
    /// All other naming logic should use this method to ensure consistency.
    /// Calculate 8-digit hex hash for module path with logging
    fn calculate_module_hash(&self, module_path: &str) -> String {
        let mut hasher = DefaultHasher::new();
        module_path.hash(&mut hasher);
        let hash = hasher.finish();
        let hash_hex = format!("{:08x}", (hash & 0xFFFFFFFF) as u32);

        info!("Module hash calculated: {} -> {}", module_path, hash_hex);
        hash_hex
    }

    /// Generate unified function name with format: ghostscope_{module_hash}_{address_hex}_{trace_id}
    fn generate_unified_function_name(&self, target: &ResolvedTarget, trace_id: u32) -> String {
        let module_hash = self.calculate_module_hash(&target.binary_path);
        let address_hex = if let Some(addr) = target.function_address {
            format!("{:x}", addr)
        } else {
            "unknown".to_string()
        };

        let function_name = format!(
            "ghostscope_{}_{}_trace{}",
            module_hash, address_hex, trace_id
        );
        info!(
            "Generated eBPF function name: {} (module: {}, address: 0x{}, trace_id: {})",
            function_name, target.binary_path, address_hex, trace_id
        );

        function_name
    }

    /// Get save options (helper method)
    fn get_save_options(&self) -> Option<&crate::SaveOptions> {
        self.save_options.as_ref()
    }

    /// Generate filename for output files
    fn generate_filename(&self, target: &ResolvedTarget, trace_id: u32, extension: &str) -> String {
        let module_hash = self.calculate_module_hash(&target.binary_path);
        let address_hex = if let Some(addr) = target.function_address {
            format!("{:x}", addr)
        } else {
            "unknown".to_string()
        };

        format!(
            "gs_{}_{}_trace{}.{}",
            module_hash, address_hex, trace_id, extension
        )
    }

    /// Generate eBPF bytecode from LLVM module
    fn generate_ebpf_bytecode(
        &mut self,
        module: &inkwell::module::Module,
        function_name: &str,
        target: &ResolvedTarget,
        assigned_trace_id: u32,
    ) -> Result<Vec<u8>, CompileError> {
        use inkwell::targets::{FileType, Target, TargetTriple};
        use inkwell::OptimizationLevel;

        // Get LLVM IR string for logging and saving
        let llvm_ir = module.print_to_string().to_string();
        let llvm_ir = llvm_ir.trim_end().to_string();
        info!(
            "Successfully generated LLVM IR for {}, length: {}",
            function_name,
            llvm_ir.len()
        );

        // Save LLVM IR file if requested
        if let Some(save_options) = self.get_save_options() {
            if save_options.save_llvm_ir {
                let filename = self.generate_filename(target, assigned_trace_id, "ll");
                if let Err(e) = std::fs::write(&filename, &llvm_ir) {
                    warn!("Failed to save LLVM IR to {}: {}", filename, e);
                } else {
                    info!("Saved LLVM IR to: {}", filename);
                }
            }
        }

        // Get target triple
        let triple = TargetTriple::create("bpf-pc-linux");

        // Get BPF target
        let llvm_target = Target::from_triple(&triple).map_err(|e| {
            CompileError::LLVM(format!("Failed to get target for {}: {}", function_name, e))
        })?;

        // Create target machine
        let target_machine = llvm_target
            .create_target_machine(
                &triple,
                "generic", // CPU
                "+alu32",  // Enable BPF ALU32 instructions
                OptimizationLevel::Default,
                inkwell::targets::RelocMode::PIC,
                inkwell::targets::CodeModel::Small,
            )
            .ok_or_else(|| {
                CompileError::LLVM(format!(
                    "Failed to create target machine for {}",
                    function_name
                ))
            })?;

        // Generate eBPF object file
        info!("Generating eBPF object file for {}...", function_name);
        let object_code = target_machine
            .write_to_memory_buffer(module, FileType::Object)
            .map_err(|e| {
                CompileError::LLVM(format!(
                    "Failed to generate object code for {}: {}",
                    function_name, e
                ))
            })?;

        info!(
            "Successfully generated object code for {}! Size: {}",
            function_name,
            object_code.get_size()
        );

        // Convert to Vec<u8>
        let bytecode = object_code.as_slice().to_vec();

        // Save eBPF object file and AST if requested
        if let Some(save_options) = self.get_save_options() {
            if save_options.save_ebpf {
                let filename = self.generate_filename(target, assigned_trace_id, "o");
                if let Err(e) = std::fs::write(&filename, &bytecode) {
                    warn!("Failed to save eBPF object to {}: {}", filename, e);
                } else {
                    info!("Saved eBPF object to: {}", filename);
                }
            }

            // AST has already been saved earlier in generate_ebpf_for_target
        }

        Ok(bytecode)
    }

    /// Save AST to file
    fn save_ast_to_file(
        &mut self,
        program: &crate::script::ast::Program,
        filename: &str,
    ) -> Result<(), CompileError> {
        let mut ast_content = String::new();
        ast_content.push_str("=== AST Tree ===\n");
        ast_content.push_str("Program:\n");
        for (i, stmt) in program.statements.iter().enumerate() {
            ast_content.push_str(&format!("  Statement {}: {:?}\n", i, stmt));
        }
        ast_content.push_str("=== End AST Tree ===\n");

        std::fs::write(filename, ast_content).map_err(|e| {
            CompileError::Other(format!("Failed to save AST file '{}': {}", filename, e))
        })?;

        Ok(())
    }
}

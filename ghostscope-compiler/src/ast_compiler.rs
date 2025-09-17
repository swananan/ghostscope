use crate::ast::{Program, Statement, TracePattern};
use crate::codegen::CodeGen;
use crate::CompileError;
// BinaryAnalyzer is now internal to ghostscope-binary, use ProcessAnalyzer instead
use inkwell::context::Context;
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
}

/// Compilation result containing all uprobe configurations
#[derive(Debug)]
pub struct CompilationResult {
    pub uprobe_configs: Vec<UProbeConfig>,
    pub trace_count: usize,
    pub target_info: String,
    pub failed_targets: Vec<FailedTarget>, // New field for failed compilation info
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
    process_analyzer: Option<&'a mut ghostscope_binary::ProcessAnalyzer>,
    uprobe_configs: Vec<UProbeConfig>,
    failed_targets: Vec<FailedTarget>, // Track failed compilation attempts
    binary_path_hint: Option<String>,
    trace_id: Option<u32>,
}

impl<'a> AstCompiler<'a> {
    pub fn new(
        process_analyzer: Option<&'a mut ghostscope_binary::ProcessAnalyzer>,
        binary_path_hint: Option<String>,
        trace_id: Option<u32>,
    ) -> Self {
        Self {
            process_analyzer,
            uprobe_configs: Vec::new(),
            failed_targets: Vec::new(),
            binary_path_hint,
            trace_id,
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

                let total_addresses: usize =
                    module_addresses.iter().map(|(_, addrs)| addrs.len()).sum();
                debug!(
                    "Resolved {}:{} to {} address(es) across {} modules",
                    file_path,
                    line_number,
                    total_addresses,
                    module_addresses.len()
                );

                // Process each module and its addresses - continue even if some fail
                let mut successful_addresses = 0;
                let mut failed_addresses = 0;

                let mut pc_idx = 0;
                for (module_path, addresses) in &module_addresses {
                    for address in addresses {
                        let target_info = ResolvedTarget {
                            function_name: Some(format!("{}:{}", file_path, line_number)),
                            function_address: Some(*address),
                            binary_path: module_path.clone(),
                            uprobe_offset: Some(*address), // For line addresses, offset equals address
                            pattern: pattern.clone(),
                        };

                        match self.generate_ebpf_for_target(
                            &target_info,
                            statements,
                            pid,
                            index + pc_idx,
                        ) {
                            Ok(uprobe_config) => {
                                self.uprobe_configs.push(uprobe_config);
                                successful_addresses += 1;
                                info!(
                                    "✓ Successfully generated eBPF for {}:{} at 0x{:x}",
                                    file_path, line_number, address
                                );
                            }
                            Err(e) => {
                                failed_addresses += 1;
                                error!(
                                    "❌ Failed to generate eBPF for {}:{} at 0x{:x}: {}",
                                    file_path, line_number, address, e
                                );

                                // Record this failed target
                                self.failed_targets.push(FailedTarget {
                                    target_name: format!("{}:{}", file_path, line_number),
                                    pc_address: *address,
                                    error_message: e.to_string(),
                                });

                                // Continue processing other addresses
                            }
                        }
                        pc_idx += 1;
                    }
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
                    analyzer.lookup_addresses_by_function_name(func_name)
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

                let total_addresses: usize =
                    module_addresses.iter().map(|(_, addrs)| addrs.len()).sum();
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
                for (module_path, addresses) in &module_addresses {
                    for address in addresses {
                        // For ProcessAnalyzer, the address is already the binary offset we need for uprobe
                        let uprobe_offset = *address;

                        let target_info = ResolvedTarget {
                            function_name: Some(func_name.clone()),
                            function_address: Some(*address),
                            binary_path: module_path.clone(),
                            uprobe_offset: Some(uprobe_offset),
                            pattern: pattern.clone(),
                        };

                        match self.generate_ebpf_for_target(
                            &target_info,
                            statements,
                            pid,
                            index + pc_idx,
                        ) {
                            Ok(uprobe_config) => {
                                self.uprobe_configs.push(uprobe_config);
                                successful_addresses += 1;
                                info!(
                                    "✓ Successfully generated eBPF for function '{}' at 0x{:x}",
                                    func_name, address
                                );
                            }
                            Err(e) => {
                                failed_addresses += 1;
                                error!(
                                    "❌ Failed to generate eBPF for function '{}' at 0x{:x}: {}",
                                    func_name, address, e
                                );

                                // Record this failed target
                                self.failed_targets.push(FailedTarget {
                                    target_name: func_name.clone(),
                                    pc_address: *address,
                                    error_message: e.to_string(),
                                });

                                // Continue processing other addresses
                            }
                        }
                        pc_idx += 1;
                    }
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
        index: usize,
    ) -> Result<UProbeConfig, CompileError> {
        let context = Context::create();

        // Generate unified eBPF function name - this name will be used everywhere
        let ebpf_function_name = self.generate_unified_function_name(&target.pattern, index);

        info!(
            "Generating eBPF code for '{}' (function: {})",
            target.function_name.as_deref().unwrap_or("unknown"),
            ebpf_function_name
        );

        // Immediate LLVM IR and eBPF generation
        let mut codegen = CodeGen::new_with_process_analyzer(
            &context,
            &ebpf_function_name,
            self.process_analyzer.as_deref_mut(),
        );

        // Use the same function name for actual compilation
        let actual_function_name = ebpf_function_name.clone();

        let module = codegen.compile_with_function_name(
            // Create a minimal program for this trace point
            &crate::ast::Program {
                statements: statements.to_vec(),
            },
            &actual_function_name,
            statements,
            pid,
            self.trace_id,
            target.function_address,   // compile_time_pc
            Some(&target.binary_path), // module_path
            None,                      // save_ir_path
        )?;

        // Generate eBPF bytecode from LLVM module
        let ebpf_bytecode = self.generate_ebpf_bytecode(module, &ebpf_function_name)?;

        Ok(UProbeConfig {
            trace_pattern: target.pattern.clone(),
            binary_path: target.binary_path.clone(),
            function_name: target.function_name.clone(),
            function_address: target.function_address,
            uprobe_offset: target.uprobe_offset,
            target_pid: pid,
            ebpf_bytecode,
            ebpf_function_name,
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
    fn generate_unified_function_name(&self, pattern: &TracePattern, index: usize) -> String {
        match pattern {
            TracePattern::FunctionName(name) => {
                // Sanitize function name for eBPF compatibility
                let sanitized = name.replace(".", "_").replace(":", "_").replace("/", "_");
                format!("ghostscope_{}_{}", sanitized, index)
            }
            TracePattern::SourceLine {
                file_path,
                line_number,
            } => {
                // Create consistent name for source lines
                let sanitized_path = file_path.replace(".", "_").replace("/", "_");
                // Include index to disambiguate multiple PCs for the same line
                format!(
                    "ghostscope_line_{}_{}_{}",
                    line_number, sanitized_path, index
                )
            }
            TracePattern::Address(addr) => {
                format!("ghostscope_addr_0x{:x}_{}", addr, index)
            }
            TracePattern::Wildcard(pattern) => {
                let sanitized = pattern
                    .replace(".", "_")
                    .replace(":", "_")
                    .replace("/", "_");
                format!("ghostscope_wildcard_{}_{}", sanitized, index)
            }
        }
    }

    /// Generate eBPF bytecode from LLVM module
    fn generate_ebpf_bytecode(
        &self,
        module: &inkwell::module::Module,
        function_name: &str,
    ) -> Result<Vec<u8>, CompileError> {
        use inkwell::targets::{FileType, Target, TargetTriple};
        use inkwell::OptimizationLevel;

        // Get LLVM IR string for logging only
        let llvm_ir = module.print_to_string().to_string();
        let llvm_ir = llvm_ir.trim_end().to_string();
        info!(
            "Successfully generated LLVM IR for {}, length: {}",
            function_name,
            llvm_ir.len()
        );

        // Get target triple
        let triple = TargetTriple::create("bpf-pc-linux");

        // Get BPF target
        let target = Target::from_triple(&triple).map_err(|e| {
            CompileError::LLVM(format!("Failed to get target for {}: {}", function_name, e))
        })?;

        // Create target machine
        let target_machine = target
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
        Ok(bytecode)
    }
}

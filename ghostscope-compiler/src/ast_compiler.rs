use crate::ast::{Program, Statement, TracePattern};
use crate::codegen::CodeGen;
use crate::CompileError;
use ghostscope_binary::BinaryAnalyzer;
use inkwell::context::Context;
use tracing::{debug, info, warn};

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
}

/// Unified AST compiler that performs DWARF queries and code generation in single pass
pub struct AstCompiler<'a> {
    binary_analyzer: Option<&'a mut BinaryAnalyzer>,
    uprobe_configs: Vec<UProbeConfig>,
    binary_path_hint: Option<String>,
    trace_id: Option<u32>,
}

impl<'a> AstCompiler<'a> {
    pub fn new(
        binary_analyzer: Option<&'a mut BinaryAnalyzer>,
        binary_path_hint: Option<String>,
        trace_id: Option<u32>,
    ) -> Self {
        Self {
            binary_analyzer,
            uprobe_configs: Vec::new(),
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
        for (index, stmt) in program.statements.iter().enumerate() {
            match stmt {
                Statement::TracePoint { pattern, body } => {
                    debug!("Processing trace point {}: {:?}", index, pattern);
                    self.process_trace_point(pattern, body, pid, index)?;
                }
                _ => {
                    warn!("Skipping non-trace statement: {:?}", stmt);
                    // TODO: Non-trace statements are ignored in current implementation
                }
            }
        }

        // Generate target info summary
        let target_info = self.generate_target_info_summary();

        info!(
            "Compilation completed: {} uprobe configs generated",
            self.uprobe_configs.len()
        );

        Ok(CompilationResult {
            uprobe_configs: std::mem::take(&mut self.uprobe_configs),
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
        // Step 1: Immediately resolve target info using DWARF
        let target_info = self.resolve_target_info(pattern)?;
        debug!("Resolved target: {:?}", target_info);

        // Step 2: Immediately generate eBPF bytecode for this target
        let uprobe_config = self.generate_ebpf_for_target(&target_info, statements, pid, index)?;

        // Step 3: Store result
        self.uprobe_configs.push(uprobe_config);

        Ok(())
    }

    /// Resolve target information using DWARF queries
    fn resolve_target_info(
        &mut self,
        pattern: &TracePattern,
    ) -> Result<ResolvedTarget, CompileError> {
        match pattern {
            TracePattern::FunctionName(func_name) => {
                debug!("Resolving function target: {}", func_name);

                if let Some(analyzer) = &mut self.binary_analyzer {
                    // Immediate DWARF query
                    // Query function address and uprobe offset
                    if let (Some(address), Some(offset)) = (
                        analyzer.resolve_function_address(func_name),
                        analyzer.resolve_function_uprobe_offset(func_name),
                    ) {
                        info!("Function resolution successful for '{}': address=0x{:x}, offset=0x{:x}", 
                            func_name, address, offset);

                        Ok(ResolvedTarget {
                            function_name: Some(func_name.clone()),
                            function_address: Some(address),
                            binary_path: analyzer
                                .debug_info()
                                .binary_path
                                .to_string_lossy()
                                .to_string(),
                            uprobe_offset: Some(offset),
                            pattern: pattern.clone(),
                        })
                    } else {
                        warn!("Function resolution failed for '{}'", func_name);
                        // Create unresolved target for later resolution
                        Ok(ResolvedTarget {
                            function_name: Some(func_name.clone()),
                            function_address: None,
                            binary_path: analyzer
                                .debug_info()
                                .binary_path
                                .to_string_lossy()
                                .to_string(),
                            uprobe_offset: None,
                            pattern: pattern.clone(),
                        })
                    }
                } else {
                    debug!("No binary analyzer available, creating unresolved target");
                    Ok(ResolvedTarget {
                        function_name: Some(func_name.clone()),
                        function_address: None,
                        binary_path: self.binary_path_hint.clone().unwrap_or_default(),
                        uprobe_offset: None,
                        pattern: pattern.clone(),
                    })
                }
            }
            TracePattern::Address(addr) => {
                debug!("Resolving address target: 0x{:x}", addr);
                Ok(ResolvedTarget {
                    function_name: None,
                    function_address: Some(*addr),
                    binary_path: self.binary_path_hint.clone().unwrap_or_default(),
                    uprobe_offset: Some(*addr), // For address patterns, offset equals address
                    pattern: pattern.clone(),
                })
            }
            TracePattern::Wildcard(pattern_str) => {
                debug!("Resolving wildcard target: {}", pattern_str);
                // Wildcard resolution would require more complex DWARF queries
                // For now, create unresolved target
                Ok(ResolvedTarget {
                    function_name: Some(pattern_str.clone()),
                    function_address: None,
                    binary_path: self.binary_path_hint.clone().unwrap_or_default(),
                    uprobe_offset: None,
                    pattern: pattern.clone(),
                })
            }
            TracePattern::SourceLine {
                file_path,
                line_number,
            } => {
                debug!(
                    "Resolving source line target: {}:{}",
                    file_path, line_number
                );

                if let Some(analyzer) = &mut self.binary_analyzer {
                    // Try to resolve line number to address using DWARF info
                    let addresses = if let Some(address) =
                        analyzer.resolve_source_line_address(file_path, *line_number)
                    {
                        vec![address]
                    } else {
                        Vec::new()
                    };
                    if let Some(&first_address) = addresses.first() {
                        info!(
                            "Source line resolution successful for '{}:{}': address=0x{:x}",
                            file_path, line_number, first_address
                        );

                        Ok(ResolvedTarget {
                            function_name: Some(format!("{}:{}", file_path, line_number)),
                            function_address: Some(first_address),
                            binary_path: analyzer
                                .debug_info()
                                .binary_path
                                .to_string_lossy()
                                .to_string(),
                            uprobe_offset: Some(first_address), // For line addresses, offset equals address
                            pattern: pattern.clone(),
                        })
                    } else {
                        warn!(
                            "Source line resolution failed for '{}:{}' - no address found",
                            file_path, line_number
                        );

                        Ok(ResolvedTarget {
                            function_name: Some(format!("{}:{}", file_path, line_number)),
                            function_address: None,
                            binary_path: analyzer
                                .debug_info()
                                .binary_path
                                .to_string_lossy()
                                .to_string(),
                            uprobe_offset: None,
                            pattern: pattern.clone(),
                        })
                    }
                } else {
                    debug!("No binary analyzer available for source line resolution");
                    Ok(ResolvedTarget {
                        function_name: Some(format!("{}:{}", file_path, line_number)),
                        function_address: None,
                        binary_path: self.binary_path_hint.clone().unwrap_or_default(),
                        uprobe_offset: None,
                        pattern: pattern.clone(),
                    })
                }
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
        let mut codegen = CodeGen::new_with_binary_analyzer(
            &context,
            &ebpf_function_name,
            self.binary_analyzer.as_deref_mut(),
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
            target.function_address, // compile_time_pc
            None,                    // save_ir_path
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
                format!("ghostscope_line_{}_{}", line_number, sanitized_path)
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

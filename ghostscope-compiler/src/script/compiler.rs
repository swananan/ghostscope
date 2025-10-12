use crate::script::ast::{Program, Statement, TracePattern};
use crate::CompileError;
// BinaryAnalyzer is now internal to ghostscope-binary, use DwarfAnalyzer instead
use inkwell::context::Context;
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
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

    /// Trace context containing all strings, types, and variable names used in this uprobe
    pub trace_context: ghostscope_protocol::TraceContext,
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
    current_trace_id: u32, // Current trace_id counter (increments for each uprobe)
    compile_options: crate::CompileOptions, // Compilation options (save + eBPF map config)
}

impl<'a> AstCompiler<'a> {
    pub fn new(
        process_analyzer: Option<&'a mut ghostscope_dwarf::DwarfAnalyzer>,
        binary_path_hint: Option<String>,
        starting_trace_id: u32,
        compile_options: crate::CompileOptions,
    ) -> Self {
        Self {
            process_analyzer,
            uprobe_configs: Vec::new(),
            failed_targets: Vec::new(),
            binary_path_hint,
            current_trace_id: starting_trace_id,
            compile_options,
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
        let mut first_error: Option<String> = None;

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
                            let error_msg = e.to_string();
                            error!(
                                "❌ Failed to process trace point {}: {:?} - Error: {}",
                                index, pattern, error_msg
                            );

                            // Save first error for detailed error message
                            if first_error.is_none() {
                                first_error = Some(error_msg.clone());
                            }

                            // Check if failed_targets was already populated by process_trace_point
                            // (e.g., when all addresses failed for a function)
                            // If not, add a general failed target entry
                            let has_failed_for_this_pattern =
                                self.failed_targets.iter().any(|ft| match pattern {
                                    TracePattern::FunctionName(name) => ft.target_name == *name,
                                    TracePattern::SourceLine {
                                        file_path,
                                        line_number,
                                    } => ft.target_name == format!("{file_path}:{line_number}"),
                                    _ => false,
                                });

                            if !has_failed_for_this_pattern {
                                let target_name = match pattern {
                                    TracePattern::FunctionName(name) => name.clone(),
                                    TracePattern::SourceLine {
                                        file_path,
                                        line_number,
                                    } => format!("{file_path}:{line_number}"),
                                    _ => format!("trace_point_{index}"),
                                };

                                self.failed_targets.push(FailedTarget {
                                    target_name,
                                    pc_address: 0,
                                    error_message: error_msg,
                                });
                            }
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
        } else if failed_trace_points > 0 {
            // All trace points failed - return error with first failure reason
            error!("All {} trace points failed to process", failed_trace_points);
            return Err(CompileError::Other(
                first_error.unwrap_or_else(|| "All trace points failed".to_string()),
            ));
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

    /// Build a detailed error message for SourceLine resolution failures
    fn describe_source_line_failure(&mut self, file_path: &str, line_number: u32) -> String {
        let default_msg =
            format!("No addresses resolved for source line {file_path}:{line_number}");

        let analyzer = match &mut self.process_analyzer {
            Some(a) => a,
            None => return default_msg,
        };

        let grouped = match analyzer.get_grouped_file_info_by_module() {
            Ok(g) => g,
            Err(_) => return default_msg,
        };

        // Collect all full paths and those sharing the basename
        let mut all_full_paths: Vec<String> = Vec::new();
        let mut same_basename_paths: Vec<String> = Vec::new();
        let has_sep = file_path.contains('/') || file_path.contains('\\');
        let basename = Path::new(file_path)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(file_path);

        for (_module, files) in &grouped {
            for f in files {
                all_full_paths.push(f.full_path.clone());
                if f.basename == basename {
                    same_basename_paths.push(f.full_path.clone());
                }
            }
        }

        if all_full_paths.is_empty() {
            return default_msg;
        }

        let exact_match = all_full_paths.iter().any(|p| p == file_path);
        let suffix_matches: Vec<String> = all_full_paths
            .iter()
            .filter(|p| p.ends_with(file_path) || file_path.ends_with(p.as_str()))
            .cloned()
            .collect();

        if same_basename_paths.is_empty() {
            return format!(
                "Source file not found in DWARF: {file_path}.\n- Tips: use 'srcpath map <dwf_comp_dir> <local_dir>' or pass full DWARF path.\n- List files with: dwarf-tool source-files or 'info source-files'"
            );
        }

        if !exact_match && suffix_matches.is_empty() && has_sep && same_basename_paths.len() > 1 {
            let mut samples = same_basename_paths.clone();
            samples.sort();
            samples.dedup();
            if samples.len() > 3 {
                samples.truncate(3);
            }
            let sample_list = samples.join("\n  - ");
            return format!(
                "Multiple files named '{basename}' found; the given path '{file_path}' did not uniquely match by suffix.\nTry a more specific path or add a path mapping (srcpath map).\nExamples:\n  - {sample_list}"
            );
        }

        // Probe a few candidate paths to see if any has addresses on this line
        let mut hit_candidates: Vec<String> = Vec::new();
        let probe_list: Vec<String> = if !suffix_matches.is_empty() {
            suffix_matches
        } else {
            let mut v = same_basename_paths.clone();
            v.sort();
            v.dedup();
            v.truncate(20);
            v
        };

        for cand in &probe_list {
            let addrs = analyzer.lookup_addresses_by_source_line(cand, line_number);
            if !addrs.is_empty() {
                hit_candidates.push(cand.clone());
                if hit_candidates.len() >= 3 {
                    break;
                }
            }
        }

        if !hit_candidates.is_empty() {
            let list = hit_candidates.join("\n  - ");
            return format!(
                "Ambiguous path: '{file_path}' did not resolve, but found addresses for the same line in:\n  - {list}\nPlease use a more specific path (full DWARF path) or add a mapping (srcpath map)."
            );
        }

        format!(
            "No executable addresses for {file_path}:{line_number} (file exists in DWARF but this line has no statement).\nTry a nearby line, or rebuild with debug info and lower optimization (e.g., -g -O0)."
        )
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
                    let detailed = self.describe_source_line_failure(file_path, *line_number);
                    return Err(CompileError::Other(detailed));
                }

                debug!(
                    "Resolved {}:{} to {} address(es) for trace point {}",
                    file_path,
                    line_number,
                    module_addresses.len(),
                    index
                );

                // Process each module and its addresses - continue even if some fail
                let mut successful_addresses = 0;
                let mut failed_addresses = 0;

                for module_address in &module_addresses {
                    // Convert DWARF PC (vaddr) to ELF file offset for uprobe
                    let file_off = self.process_analyzer.as_ref().and_then(|an| {
                        an.vaddr_to_file_offset(&module_address.module_path, module_address.address)
                    });

                    let target_info = ResolvedTarget {
                        function_name: Some(format!("{file_path}:{line_number}")),
                        // Keep function_address as DWARF PC for compile-time DWARF queries
                        function_address: Some(module_address.address),
                        binary_path: module_address.module_path.to_string_lossy().to_string(),
                        // Attach with absolute file offset if conversion succeeded
                        uprobe_offset: file_off,
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
                                target_name: format!("{file_path}:{line_number}"),
                                pc_address: module_address.address,
                                error_message: e.to_string(),
                            });

                            // Continue processing other addresses
                        }
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
            TracePattern::Address(addr) => {
                // Resolve default module path
                // Prefer main executable; if unavailable (e.g., -t <lib>.so),
                // fall back to the single loaded shared library (target module).
                let module_path: Option<String> = if let Some(analyzer) = &self.process_analyzer {
                    if let Some(main) = analyzer.get_main_executable() {
                        Some(main.path)
                    } else {
                        let libs = analyzer.get_shared_library_info();
                        if libs.len() == 1 {
                            Some(libs[0].library_path.clone())
                        } else {
                            None
                        }
                    }
                } else {
                    None
                };

                let module_path = match module_path {
                    Some(p) => p,
                    None => {
                        return Err(CompileError::Other(
                            "No module available to resolve address. In PID mode, default module is the main executable. In target mode (-t <binary>), the specified binary is used (including .so).".to_string(),
                        ));
                    }
                };

                // Convert DWARF PC (vaddr) to ELF file offset for uprobe
                let file_off = self
                    .process_analyzer
                    .as_ref()
                    .and_then(|an| an.vaddr_to_file_offset(&module_path, *addr));

                if file_off.is_none() {
                    return Err(CompileError::Other(format!(
                        "Address 0x{addr:x} is not within a loadable segment of '{module_path}' (cannot compute file offset)"
                    )));
                }

                let target_info = ResolvedTarget {
                    function_name: None,
                    function_address: Some(*addr),
                    binary_path: module_path,
                    uprobe_offset: file_off,
                    pattern: pattern.clone(),
                };

                match self.generate_ebpf_for_target(&target_info, statements, pid) {
                    Ok(uprobe_config) => {
                        self.uprobe_configs.push(uprobe_config);
                        info!("✓ Successfully generated eBPF for address 0x{:x}", addr);
                        Ok(())
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        self.failed_targets.push(FailedTarget {
                            target_name: format!("0x{addr:x}"),
                            pc_address: *addr,
                            error_message: error_msg.clone(),
                        });
                        Err(CompileError::Other(error_msg))
                    }
                }
            }
            TracePattern::AddressInModule { module, address } => {
                // Resolve module path by exact or suffix match across loaded modules
                let module_path = if let Some(analyzer) = &self.process_analyzer {
                    let mut modules: Vec<String> = Vec::new();
                    if let Some(main) = analyzer.get_main_executable() {
                        modules.push(main.path);
                    }
                    for lib in analyzer.get_shared_library_info() {
                        modules.push(lib.library_path);
                    }

                    // exact match
                    if let Some(found) = modules.iter().find(|p| p.as_str() == module) {
                        found.clone()
                    } else {
                        // suffix match
                        let candidates: Vec<String> = modules
                            .into_iter()
                            .filter(|p| p.ends_with(module))
                            .collect();
                        match candidates.len() {
                            0 => {
                                return Err(CompileError::Other(format!(
                                    "Module '{module}' not found among loaded modules. Use full path or a unique suffix."
                                )));
                            }
                            1 => candidates[0].clone(),
                            _ => {
                                let mut sample = candidates.clone();
                                sample.truncate(5);
                                return Err(CompileError::Other(format!(
                                    "Ambiguous module suffix '{}'. Candidates:\n  - {}\nPlease use a more specific suffix or full path.",
                                    module,
                                    sample.join("\n  - ")
                                )));
                            }
                        }
                    }
                } else {
                    return Err(CompileError::Other(
                        "No process analyzer available to resolve module".to_string(),
                    ));
                };

                // Convert DWARF PC (vaddr) to ELF file offset for uprobe
                let file_off = self
                    .process_analyzer
                    .as_ref()
                    .and_then(|an| an.vaddr_to_file_offset(&module_path, *address));

                if file_off.is_none() {
                    return Err(CompileError::Other(format!(
                        "Address 0x{address:x} is not within a loadable segment of '{module_path}' (cannot compute file offset)"
                    )));
                }

                let target_info = ResolvedTarget {
                    function_name: None,
                    function_address: Some(*address),
                    binary_path: module_path,
                    uprobe_offset: file_off,
                    pattern: pattern.clone(),
                };

                match self.generate_ebpf_for_target(&target_info, statements, pid) {
                    Ok(uprobe_config) => {
                        self.uprobe_configs.push(uprobe_config);
                        info!(
                            "✓ Successfully generated eBPF for module-qualified address {}:0x{:x}",
                            module, address
                        );
                        Ok(())
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        self.failed_targets.push(FailedTarget {
                            target_name: format!("{module}:0x{address:x}"),
                            pc_address: *address,
                            error_message: error_msg.clone(),
                        });
                        Err(CompileError::Other(error_msg))
                    }
                }
            }
            TracePattern::FunctionName(func_name) => {
                // Resolve all addresses for the function name and generate per-PC programs
                let module_addresses = if let Some(analyzer) = &mut self.process_analyzer {
                    analyzer.lookup_function_addresses(func_name)
                } else {
                    Vec::new()
                };

                if module_addresses.is_empty() {
                    // Strict behavior: fail this trace point immediately instead of skipping silently
                    return Err(CompileError::Other(format!(
                        "No addresses resolved for function '{func_name}' - function not found in debug symbols"
                    )));
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

                for module_address in &module_addresses {
                    // Convert DWARF function address (vaddr) to ELF file offset for uprobe attach
                    let file_off = self.process_analyzer.as_ref().and_then(|an| {
                        an.vaddr_to_file_offset(&module_address.module_path, module_address.address)
                    });

                    let target_info = ResolvedTarget {
                        function_name: Some(func_name.clone()),
                        function_address: Some(module_address.address),
                        binary_path: module_address.module_path.to_string_lossy().to_string(),
                        uprobe_offset: file_off,
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
                }

                // Log summary for this trace point
                if successful_addresses > 0 && failed_addresses == 0 {
                    info!(
                        "All {} addresses for function '{}' processed successfully",
                        successful_addresses, func_name
                    );
                    Ok(())
                } else if successful_addresses > 0 && failed_addresses > 0 {
                    warn!(
                        "Partial success for function '{}': {} successful, {} failed addresses",
                        func_name, successful_addresses, failed_addresses
                    );
                    Ok(())
                } else {
                    // All addresses failed to process — record failures already captured above
                    // Defer final error shaping to the caller based on aggregated results
                    error!(
                        "All {} addresses for function '{}' failed to process",
                        failed_addresses, func_name
                    );
                    Ok(())
                }
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
        if let Some(compile_options) = self.get_compile_options() {
            if compile_options.save_ast {
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
            &self.compile_options,
        )
        .map_err(|e| CompileError::LLVM(format!("Failed to create new codegen: {e}")))?;

        // Set compile-time context for DWARF queries
        if let Some(function_address) = target.function_address {
            codegen_new.set_compile_time_context(function_address, target.binary_path.clone());
        }

        info!(
            "Compiling full AST program with {} statements",
            statements.len()
        );

        // Use full AST compilation
        let (_main_function, trace_context) = codegen_new
            .compile_program(
                &crate::script::ast::Program { statements: vec![] }, // Empty program - statements passed separately
                &ebpf_function_name,
                statements,
                pid,
                target.function_address,
                Some(&target.binary_path),
            )
            .map_err(|e| CompileError::LLVM(format!("Failed to compile AST program: {e}")))?;

        info!(
            "Generated TraceContext for '{}' with {} strings and {} variables",
            ebpf_function_name,
            trace_context.string_count(),
            trace_context.variable_name_count()
        );

        let module = codegen_new.get_module();

        // Generate eBPF bytecode from LLVM module
        let ebpf_bytecode =
            self.generate_ebpf_bytecode(module, &ebpf_function_name, target, assigned_trace_id)?;

        // Use the TraceContext returned from compile_program (no need to get it again)

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
            trace_context,
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
        let effective_path = self.effective_binary_path(module_path);
        let mut hasher = DefaultHasher::new();
        effective_path.hash(&mut hasher);
        let hash = hasher.finish();
        let truncated = (hash & 0xFFFF_FFFF) as u32;
        let hash_hex = format!("{truncated:08x}");

        info!("Module hash calculated: {} -> {}", effective_path, hash_hex);
        hash_hex
    }

    /// Generate unified function name with format: ghostscope_{module_hash}_{address_hex}_{trace_id}
    fn generate_unified_function_name(&self, target: &ResolvedTarget, trace_id: u32) -> String {
        let module_hash = self.calculate_module_hash(&target.binary_path);
        let effective_path = self.effective_binary_path(&target.binary_path);
        let address_hex = if let Some(addr) = target.function_address {
            format!("{addr:x}")
        } else {
            "unknown".to_string()
        };

        let function_name = format!("ghostscope_{module_hash}_{address_hex}_trace{trace_id}");
        info!(
            "Generated eBPF function name: {} (module: {}, address: 0x{}, trace_id: {})",
            function_name, effective_path, address_hex, trace_id
        );

        function_name
    }

    /// Get save options (helper method)
    fn get_compile_options(&self) -> Option<&crate::CompileOptions> {
        Some(&self.compile_options)
    }

    /// Pick a binary path, falling back to compiler hint when the resolved target is empty
    fn effective_binary_path<'b>(&'b self, target_path: &'b str) -> Cow<'b, str> {
        if target_path.is_empty() {
            if let Some(hint) = &self.binary_path_hint {
                Cow::Owned(hint.clone())
            } else {
                Cow::Borrowed("unknown")
            }
        } else {
            Cow::Borrowed(target_path)
        }
    }

    /// Generate filename for output files
    fn generate_filename(&self, target: &ResolvedTarget, trace_id: u32, extension: &str) -> String {
        let module_hash = self.calculate_module_hash(&target.binary_path);
        let address_hex = if let Some(addr) = target.function_address {
            format!("{addr:x}")
        } else {
            "unknown".to_string()
        };

        format!("gs_{module_hash}_{address_hex}_trace{trace_id}.{extension}")
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
        if let Some(compile_options) = self.get_compile_options() {
            if compile_options.save_llvm_ir {
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
        info!("Created target triple: bpf-pc-linux for {}", function_name);

        // Get BPF target
        let llvm_target = Target::from_triple(&triple).map_err(|e| {
            error!("Failed to get target for {}: {}", function_name, e);
            CompileError::LLVM(format!("Failed to get target for {function_name}: {e}"))
        })?;
        info!("Successfully got LLVM target for {}", function_name);

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
                error!("Failed to create target machine for {}", function_name);
                CompileError::LLVM(format!(
                    "Failed to create target machine for {function_name}"
                ))
            })?;
        info!("Successfully created target machine for {}", function_name);

        // Validate module before generating object code
        info!("Validating LLVM module for {}...", function_name);
        if let Err(llvm_errors) = module.verify() {
            error!(
                "LLVM module validation failed for {}: {}",
                function_name, llvm_errors
            );
            return Err(CompileError::LLVM(format!(
                "Module validation failed for {function_name}: {llvm_errors}"
            )));
        }
        info!("Module validation passed for {}", function_name);

        // Generate eBPF object file
        info!("Generating eBPF object file for {}...", function_name);
        info!("About to call LLVM write_to_memory_buffer...");

        let object_code = {
            // Print module for debugging before compilation
            let module_string = module.print_to_string();
            debug!(
                "Module IR before compilation:\n{}",
                module_string.to_string()
            );

            // Add a flush to ensure logs are written before potential crash
            use std::io::Write;
            let _ = std::io::stderr().flush();
            let _ = std::io::stdout().flush();

            info!("Calling target_machine.write_to_memory_buffer...");
            match target_machine.write_to_memory_buffer(module, FileType::Object) {
                Ok(code) => {
                    info!("Successfully generated object code for {}", function_name);
                    code
                }
                Err(e) => {
                    error!("LLVM compilation failed for {}: {}", function_name, e);
                    error!("This might be due to unsupported eBPF instructions or invalid LLVM IR");

                    return Err(CompileError::LLVM(format!(
                        "eBPF compilation failed for {function_name}: {e}. This often indicates unsupported instructions or invalid IR."
                    )));
                }
            }
        };

        info!(
            "Successfully generated object code for {}! Size: {}",
            function_name,
            object_code.get_size()
        );

        // Convert to Vec<u8>
        let bytecode = object_code.as_slice().to_vec();

        // Save eBPF object file and AST if requested
        if let Some(compile_options) = self.get_compile_options() {
            if compile_options.save_ebpf {
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
            ast_content.push_str(&format!("  Statement {i}: {stmt:?}\n"));
        }
        ast_content.push_str("=== End AST Tree ===\n");

        std::fs::write(filename, ast_content).map_err(|e| {
            CompileError::Other(format!("Failed to save AST file '{filename}': {e}"))
        })?;

        Ok(())
    }
}

pub mod ast;
pub mod codegen;
pub mod debug_logger;
pub mod map;
pub mod parser;

use crate::ast::{Program, TracePattern};
use codegen::CodeGenError;
use inkwell::context::Context;
use inkwell::memory_buffer::MemoryBuffer;
use inkwell::module::Module;
use inkwell::passes::PassManager;
use inkwell::targets::{
    CodeModel, FileType, InitializationConfig, RelocMode, Target, TargetTriple,
};
use inkwell::OptimizationLevel;
use parser::ParseError;
use tracing::{debug, error, info, warn};

pub fn hello() -> &'static str {
    "Hello from ghostscope-compiler!"
}

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Code generation error: {0}")]
    CodeGen(#[from] CodeGenError),

    #[error("LLVM error: {0}")]
    LLVM(String),

    #[error("Error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CompileError>;

pub fn print_ast(program: &Program) {
    info!("\n=== AST Tree ===");
    info!("Program:");
    for (i, stmt) in program.statements.iter().enumerate() {
        info!("  Statement {}: {:?}", i, stmt);
    }
    info!("=== End AST Tree ===\n");
}

/// Extract trace patterns from the parsed program
/// This function traverses the AST and collects all trace points with their patterns
#[derive(Debug, Clone)]
pub struct TracePoint {
    pub pattern: TracePattern,
    pub function_name: Option<String>, // Resolved function name for FunctionName pattern
    pub address: Option<u64>,          // Resolved address for Address pattern
    pub wildcard: Option<String>,      // Pattern string for Wildcard pattern
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

pub fn extract_trace_patterns(program: &Program) -> Vec<TracePoint> {
    let mut trace_points = Vec::new();

    for stmt in &program.statements {
        if let crate::ast::Statement::TracePoint { pattern, body: _ } = stmt {
            let trace_point = match pattern {
                TracePattern::FunctionName(func_name) => TracePoint {
                    pattern: pattern.clone(),
                    function_name: Some(func_name.clone()),
                    address: None,
                    wildcard: None,
                },
                TracePattern::Address(addr) => TracePoint {
                    pattern: pattern.clone(),
                    function_name: None,
                    address: Some(*addr),
                    wildcard: None,
                },
                TracePattern::SourceLine {
                    file_path,
                    line_number,
                } => {
                    TracePoint {
                        pattern: pattern.clone(),
                        function_name: None,
                        address: None, // Will be resolved from DWARF info
                        wildcard: Some(format!("{}:{}", file_path, line_number)),
                    }
                }
                TracePattern::Wildcard(pattern_str) => TracePoint {
                    pattern: pattern.clone(),
                    function_name: None,
                    address: None,
                    wildcard: Some(pattern_str.clone()),
                },
            };

            trace_points.push(trace_point);
        }
    }

    trace_points
}

/// Generate filename for IR and eBPF files based on trace pattern
/// Format: gs_{pid}_{target_exec}_{function_name}_index
/// Binary name and function name are NOT truncated for file naming
pub fn generate_file_name(
    pattern: &TracePattern,
    index: usize,
    pid: Option<u32>,
    binary_path: Option<&str>,
) -> String {
    let pid_str = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "0".to_string());

    let exec_name = if let Some(path) = binary_path {
        // Extract just the filename from the path
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");

        // Sanitize but don't truncate for file naming
        filename
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>()
    } else {
        "unknown".to_string()
    };

    match pattern {
        TracePattern::FunctionName(name) => {
            // Sanitize but don't truncate function name for file naming
            let func_name = name
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>();
            format!("gs_{}_{}_{}_{}", pid_str, exec_name, func_name, index)
        }
        TracePattern::Wildcard(pattern) => {
            // Sanitize but don't truncate wildcard pattern for file naming
            let pattern_name = pattern
                .chars()
                .map(|c| match c {
                    '*' => 's', // star -> s
                    '?' => 'q', // question -> q
                    c if c.is_alphanumeric() => c,
                    _ => '_',
                })
                .collect::<String>();
            format!("gs_{}_{}_{}_{}", pid_str, exec_name, pattern_name, index)
        }
        TracePattern::Address(addr) => {
            format!("gs_{}_{}_0x{:x}_{}", pid_str, exec_name, addr, index)
        }
        TracePattern::SourceLine {
            file_path,
            line_number,
        } => {
            // Extract filename from path for naming
            let filename = std::path::Path::new(file_path)
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            let sanitized_filename = filename
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>();
            format!(
                "gs_{}_{}_{}_L{}_{}",
                pid_str, exec_name, sanitized_filename, line_number, index
            )
        }
    }
}

/// Generate a unique eBPF function name based on trace pattern
/// Generate eBPF function name in format: gs_{pid}_{target_exec}_{function_name}_{trace_id}
/// Uses trace_id instead of index to avoid conflicts between different trace instances
/// Binary name and function name are NOT truncated for eBPF function naming
pub fn generate_ebpf_function_name(
    pattern: &TracePattern,
    trace_id: Option<u32>,
    pid: Option<u32>,
    binary_path: Option<&str>,
) -> String {
    let pid_str = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "0".to_string());

    let exec_name = if let Some(path) = binary_path {
        // Extract just the filename from the path
        let filename = std::path::Path::new(path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("unknown");

        // Sanitize but don't truncate for eBPF function naming
        filename
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect::<String>()
    } else {
        "unknown".to_string()
    };

    // Use trace_id for uniqueness, fallback to 0 if not provided
    let id_str = trace_id.unwrap_or(0).to_string();

    match pattern {
        TracePattern::FunctionName(name) => {
            // Sanitize but don't truncate function name for eBPF function naming
            let func_name = name
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>();
            format!("gs_{}_{}_{}_{}", pid_str, exec_name, func_name, id_str)
        }
        TracePattern::Wildcard(pattern) => {
            // Sanitize but don't truncate wildcard pattern for eBPF function naming
            let pattern_name = pattern
                .chars()
                .map(|c| match c {
                    '*' => 's', // star -> s
                    '?' => 'q', // question -> q
                    c if c.is_alphanumeric() => c,
                    _ => '_',
                })
                .collect::<String>();
            format!(
                "gs_{}_{}_ptn{}_{}",
                pid_str, exec_name, pattern_name, id_str
            )
        }
        TracePattern::Address(addr) => {
            format!("gs_{}_{}_{:x}_{}", pid_str, exec_name, addr, id_str)
        }
        TracePattern::SourceLine {
            file_path,
            line_number,
        } => {
            // Extract filename from path for eBPF function naming
            let filename = std::path::Path::new(file_path)
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("unknown");
            let sanitized_filename = filename
                .chars()
                .map(|c| if c.is_alphanumeric() { c } else { '_' })
                .collect::<String>();
            format!(
                "gs_{}_{}_{}_L{}_{}",
                pid_str, exec_name, sanitized_filename, line_number, id_str
            )
        }
    }
}

/// Unified script compilation interface - from script source to ready-to-use uprobe configs
/// This is the main interface that both command line and TUI should use
///
/// # Arguments
/// * `script_source` - The script source code to compile
/// * `binary_analyzer` - Binary analyzer for address resolution (immutable reference)
/// * `pid` - Optional target PID for filtering
/// * `save_options` - Options for saving intermediate files (IR, AST, etc.)
///
/// # Returns
/// * `CompilationResult` - Contains uprobe configs ready for attachment and metadata
#[derive(Debug)]
pub struct SaveOptions {
    pub save_llvm_ir: bool,
    pub save_ast: bool,
    pub save_ebpf: bool,
    pub binary_path_hint: Option<String>, // For file naming
}

#[derive(Debug)]
pub struct CompilationResult {
    pub uprobe_configs: Vec<UProbeConfig>,
    pub trace_count: usize,
    pub target_info: String, // Extracted target information
    pub compilation_metadata: CompilationMetadata,
}

#[derive(Debug)]
pub struct CompilationMetadata {
    pub parsed_successfully: bool,
    pub trace_patterns_found: usize,
    pub compilation_warnings: Vec<String>,
}

/// Main unified compilation interface
pub fn compile_script_to_uprobe_configs(
    script_source: &str,
    binary_analyzer: &ghostscope_binary::BinaryAnalyzer,
    pid: Option<u32>,
    trace_id: Option<u32>,
    save_options: &SaveOptions,
) -> Result<CompilationResult> {
    info!("Starting unified script compilation...");

    // Step 1: Parse and validate script
    let program = parser::parse(script_source)?;

    // Step 2: Extract target information and trace count
    let target_info = extract_target_from_script(script_source);
    let trace_count = program
        .statements
        .iter()
        .filter(|stmt| matches!(stmt, crate::ast::Statement::TracePoint { .. }))
        .count();

    info!(
        "Parsed script with {} trace points, target: {}",
        trace_count, target_info
    );

    // Step 3: Save AST if requested
    if save_options.save_ast {
        let ast_filename =
            generate_file_name_for_ast(pid, save_options.binary_path_hint.as_deref());
        save_ast_to_file(&program, &ast_filename)?;
        info!("AST saved to '{}'", ast_filename);
    }

    // Step 4: Compile AST to uprobe configs with address resolution
    let mut uprobe_configs = compile_ast_to_uprobe_configs(
        &program,
        pid,
        trace_id,
        save_options.binary_path_hint.as_deref(),
        save_options.save_llvm_ir,
        Some(binary_analyzer),
    )?;

    // Step 5: Resolve addresses for all configs using unified interfaces
    resolve_addresses_for_configs(&mut uprobe_configs, binary_analyzer)?;

    // Step 6: Save eBPF bytecode if requested
    if save_options.save_ebpf {
        save_ebpf_bytecode_files(&uprobe_configs, save_options.binary_path_hint.as_deref())?;
    }

    let result = CompilationResult {
        uprobe_configs,
        trace_count,
        target_info,
        compilation_metadata: CompilationMetadata {
            parsed_successfully: true,
            trace_patterns_found: trace_count,
            compilation_warnings: vec![], // TODO: collect warnings during compilation
        },
    };

    info!("Script compilation completed successfully");
    Ok(result)
}

/// Extract target from script source (e.g., "trace main { ... }" -> "main")
fn extract_target_from_script(script_source: &str) -> String {
    if let Some(trace_start) = script_source.find("trace ") {
        let after_trace = &script_source[trace_start + 6..]; // "trace ".len() = 6
        if let Some(first_space_or_brace) =
            after_trace.find(|c: char| c.is_whitespace() || c == '{')
        {
            return after_trace[..first_space_or_brace].trim().to_string();
        } else {
            return after_trace.trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Resolve addresses for all uprobe configs using unified DWARF interfaces
fn resolve_addresses_for_configs(
    configs: &mut [UProbeConfig],
    binary_analyzer: &ghostscope_binary::BinaryAnalyzer,
) -> Result<()> {
    info!(
        "Resolving addresses for {} uprobe configurations",
        configs.len()
    );

    for (i, config) in configs.iter_mut().enumerate() {
        match &config.trace_pattern {
            crate::ast::TracePattern::FunctionName(function_name) => {
                info!("  {}: Resolving function '{}'", i, function_name);

                match (
                    binary_analyzer.resolve_function_address(function_name),
                    binary_analyzer.resolve_function_uprobe_offset(function_name),
                ) {
                    (Some(address), Some(uprobe_offset)) => {
                        config.function_address = Some(address);
                        config.uprobe_offset = Some(uprobe_offset);
                        info!(
                            "    ✓ Resolved to address 0x{:x}, uprobe offset 0x{:x}",
                            address, uprobe_offset
                        );
                    }
                    (Some(address), None) => {
                        return Err(CompileError::Other(format!(
                            "Function '{}' found at address 0x{:x} but uprobe offset calculation failed",
                            function_name, address
                        )));
                    }
                    (None, _) => {
                        return Err(CompileError::Other(format!(
                            "Function '{}' not found in symbol table",
                            function_name
                        )));
                    }
                }
            }
            crate::ast::TracePattern::SourceLine {
                file_path,
                line_number,
            } => {
                info!(
                    "  {}: Resolving source line '{}:{}'",
                    i, file_path, line_number
                );

                match (
                    binary_analyzer.resolve_source_line_address(file_path, *line_number),
                    binary_analyzer.resolve_source_line_uprobe_offset(file_path, *line_number),
                ) {
                    (Some(address), Some(uprobe_offset)) => {
                        config.function_address = Some(address);
                        config.uprobe_offset = Some(uprobe_offset);
                        info!(
                            "    ✓ Resolved to address 0x{:x}, uprobe offset 0x{:x}",
                            address, uprobe_offset
                        );
                    }
                    (Some(address), None) => {
                        return Err(CompileError::Other(format!(
                            "Source line '{}:{}' found at address 0x{:x} but uprobe offset calculation failed",
                            file_path, line_number, address
                        )));
                    }
                    (None, _) => {
                        return Err(CompileError::Other(format!(
                            "No addresses found for source line '{}:{}'",
                            file_path, line_number
                        )));
                    }
                }
            }
            crate::ast::TracePattern::Address(addr) => {
                info!("  {}: Using direct address 0x{:x}", i, addr);
                config.function_address = Some(*addr);
                config.uprobe_offset = Some(*addr);
            }
            crate::ast::TracePattern::Wildcard(pattern) => {
                return Err(CompileError::Other(format!(
                    "Wildcard pattern '{}' not yet implemented",
                    pattern
                )));
            }
        }
    }

    info!("Address resolution completed for all configs");
    Ok(())
}

/// Save AST to file
fn save_ast_to_file(program: &Program, filename: &str) -> Result<()> {
    let ast_content = format!("{:#?}", program);
    std::fs::write(filename, ast_content)
        .map_err(|e| CompileError::Other(format!("Failed to save AST to '{}': {}", filename, e)))?;
    Ok(())
}

/// Save eBPF bytecode files for all configs
fn save_ebpf_bytecode_files(
    configs: &[UProbeConfig],
    binary_path_hint: Option<&str>,
) -> Result<()> {
    for (index, config) in configs.iter().enumerate() {
        let file_base_name = generate_file_name(
            &config.trace_pattern,
            index,
            config.target_pid,
            binary_path_hint,
        );
        let ebpf_filename = format!("{}.o", file_base_name);

        std::fs::write(&ebpf_filename, &config.ebpf_bytecode).map_err(|e| {
            CompileError::Other(format!(
                "Failed to save eBPF bytecode to '{}': {}",
                ebpf_filename, e
            ))
        })?;

        info!("eBPF bytecode saved to '{}'", ebpf_filename);
    }
    Ok(())
}

/// Compiles a string of source code in our small language to LLVM IR
/// Note: This will use BPF target functions (e.g., bpf_trace_printk) by default
pub fn compile_to_llvm_ir(source: &str) -> Result<String> {
    // Parse the source code
    let program = parser::parse(source)?;

    print_ast(&program);

    // Extract trace patterns
    let trace_points = extract_trace_patterns(&program);
    if !trace_points.is_empty() {
        info!("\n=== Extracted Trace Points ===");
        for (i, tp) in trace_points.iter().enumerate() {
            match &tp.pattern {
                TracePattern::FunctionName(name) => {
                    info!("  Trace Point {}: Function '{}'", i, name);
                }
                TracePattern::Wildcard(pattern) => {
                    info!("  Trace Point {}: Wildcard pattern '{}'", i, pattern);
                }
                TracePattern::Address(addr) => {
                    info!("  Trace Point {}: Address 0x{:x}", i, addr);
                }
                TracePattern::SourceLine {
                    file_path,
                    line_number,
                } => {
                    info!(
                        "  Trace Point {}: Source Line '{}:{}'",
                        i, file_path, line_number
                    );
                }
            }
        }
        info!("=== End Trace Points ===\n");
    } else {
        info!("No trace points found in script");
    }

    // Generate LLVM IR
    let context = Context::create();
    let mut codegen = codegen::CodeGen::new(&context, "output");

    match codegen.compile(&program) {
        Ok(module) => {
            // Return the LLVM IR as a string
            let llvm_ir = module.print_to_string().to_string();
            // Ensure IR format is correct, remove trailing empty lines
            let llvm_ir = llvm_ir.trim_end().to_string();
            info!("Successfully generated LLVM IR, length: {}", llvm_ir.len());
            Ok(llvm_ir)
        }
        Err(e) => {
            error!("CodeGen error: {:?}", e);
            Err(CompileError::CodeGen(e))
        }
    }
}

/// Compile pre-parsed AST to eBPF bytecode for multiple trace patterns
/// Returns UProbeConfig for each trace pattern with individual eBPF bytecode
pub fn compile_ast_to_uprobe_configs(
    program: &Program,
    pid: Option<u32>,
    trace_id: Option<u32>,
    binary_path: Option<&str>,
    save_ir: bool,
    binary_analyzer: Option<&ghostscope_binary::BinaryAnalyzer>,
) -> Result<Vec<UProbeConfig>> {
    info!("Starting eBPF compilation from pre-parsed AST for multiple trace patterns...");
    info!(
        "Using pre-validated AST with {} statements",
        program.statements.len()
    );

    // Extract trace patterns with their statements
    let mut trace_patterns_with_statements = Vec::new();
    for stmt in &program.statements {
        if let crate::ast::Statement::TracePoint { pattern, body } = stmt {
            trace_patterns_with_statements.push((pattern.clone(), body));
        }
    }

    if trace_patterns_with_statements.is_empty() {
        return Err(CompileError::LLVM(
            "No trace patterns found in source code".to_string(),
        ));
    }

    info!(
        "Found {} trace patterns to compile",
        trace_patterns_with_statements.len()
    );

    let mut uprobe_configs = Vec::new();

    // Initialize BPF target
    let config = inkwell::targets::InitializationConfig::default();
    inkwell::targets::Target::initialize_bpf(&config);
    info!("BPF target initialized");

    // Pre-calculate pattern count for trace_id generation
    let pattern_count = trace_patterns_with_statements.len();

    for (index, (pattern, statements)) in trace_patterns_with_statements.into_iter().enumerate() {
        info!("Compiling trace pattern {}: {:?}", index, pattern);

        // Generate unique function name for this trace pattern
        // Use trace_id directly for single pattern, or combine with index for multiple patterns
        let pattern_trace_id = match trace_id {
            Some(base_id) => {
                // For single pattern scripts, use trace_id directly
                // For multi-pattern scripts, combine trace_id with pattern index
                if pattern_count == 1 {
                    Some(base_id)
                } else {
                    Some(base_id * 1000 + index as u32)
                }
            }
            None => Some(index as u32), // Fallback for legacy usage
        };
        let ebpf_function_name =
            generate_ebpf_function_name(&pattern, pattern_trace_id, pid, binary_path);
        info!("Generated eBPF function name: {}", ebpf_function_name);

        // Create new context and codegen for each trace pattern
        let context = Context::create();
        let mut codegen = codegen::CodeGen::new_with_binary_analyzer(
            &context,
            &format!("bpf_output_{}", index),
            binary_analyzer,
        );

        // Create variable context for scope validation
        let mut var_context = ast::VariableContext::new();

        // For source line patterns, extract variable scope from DWARF if available
        if let ast::TracePattern::SourceLine {
            file_path,
            line_number,
        } = &pattern
        {
            info!(
                "Setting up variable context for source line {}:{}",
                file_path, line_number
            );

            if let Some(analyzer) = binary_analyzer {
                if let Some(dwarf_context) = analyzer.dwarf_context() {
                    // Get all addresses for this source line first
                    let line_mappings =
                        dwarf_context.get_addresses_for_line(file_path, *line_number);

                    if !line_mappings.is_empty() {
                        // Use the first address to find variables in scope
                        let target_addr = line_mappings[0].address;
                        let variables = dwarf_context.get_variables_at_address(target_addr);

                        info!(
                            "Found {} variables in scope at {}:{} (address 0x{:x})",
                            variables.len(),
                            file_path,
                            line_number,
                            target_addr
                        );

                        // Add all found variables to the context
                        for var in variables {
                            info!(
                                "  Adding variable '{}' of type '{}' to scope",
                                var.name, var.type_name
                            );
                            var_context.add_variable(var.name);
                        }
                    } else {
                        error!(
                            "No addresses found for source line '{}:{}'",
                            file_path, line_number
                        );
                        error!("This usually means:");
                        error!("  1. The line number doesn't exist in the source file");
                        error!("  2. The line contains no executable code (comments, empty lines, etc.)");
                        error!("  3. The binary was compiled without debug information (-g flag)");
                        error!("  4. The file name doesn't match the compiled source");
                        return Err(CompileError::Other(
                            format!("Source line '{}:{}' not found in debug information. Cannot attach probe to non-existent line.", 
                                   file_path, line_number)
                        ));
                    }
                } else {
                    warn!("No DWARF context available for variable analysis");
                    warn!("Source line variable validation requires debug information");
                }
            } else {
                error!("Binary analyzer required for source line variable validation");
                error!(
                    "Cannot validate variables in 'trace {}:{}' without binary analysis",
                    file_path, line_number
                );
                return Err(CompileError::Other(
                    "Source line tracing requires binary analyzer".to_string(),
                ));
            }
        }

        // For function patterns, we could also extract function parameter info
        if let ast::TracePattern::FunctionName(func_name) = &pattern {
            info!("Setting up variable context for function '{}'", func_name);
            // TODO: Extract function parameters from DWARF and add to context
        }

        // Set the variable context for validation during compilation
        codegen.set_variable_context(var_context);

        // For source line patterns, populate DWARF variables into code generation context
        if let ast::TracePattern::SourceLine {
            file_path,
            line_number,
        } = &pattern
        {
            if let Some(analyzer) = binary_analyzer {
                if let Some(dwarf_context) = analyzer.dwarf_context() {
                    // Get all addresses for this source line
                    let line_mappings =
                        dwarf_context.get_addresses_for_line(file_path, *line_number);

                    if !line_mappings.is_empty() {
                        // Use the first address to get enhanced variable location information
                        let target_addr = line_mappings[0].address;
                        let enhanced_variables =
                            dwarf_context.get_enhanced_variable_locations(target_addr);

                        if !enhanced_variables.is_empty() {
                            info!(
                                "Integrating {} DWARF variables into LLVM code generation",
                                enhanced_variables.len()
                            );

                            // We need to get the ctx parameter from the function being compiled
                            // For now, we'll do this during the compile process where we have access to the parameter
                            // Store the enhanced variables for later use
                            if let Err(e) = codegen.prepare_dwarf_variables(&enhanced_variables) {
                                error!(
                                    "Failed to prepare DWARF variables for code generation: {}",
                                    e
                                );
                                return Err(CompileError::CodeGen(e));
                            }
                        }
                    }
                }
            }
        }

        // Generate file base name using consistent naming
        let file_base_name = generate_file_name(&pattern, index, pid, binary_path);

        // Compile this specific trace pattern with PID filtering and optionally save IR
        let ir_file_path = if save_ir {
            Some(format!("{}.ll", file_base_name))
        } else {
            None
        };
        let module = match codegen.compile_with_function_name(
            &program,
            &ebpf_function_name,
            statements,
            pid,
            trace_id,
            ir_file_path.as_deref(),
        ) {
            Ok(module) => module,
            Err(e) => {
                error!("CodeGen error for pattern {:?}: {:?}", pattern, e);
                return Err(CompileError::CodeGen(e));
            }
        };

        // Get LLVM IR string for logging only
        let llvm_ir = module.print_to_string().to_string();
        let llvm_ir = llvm_ir.trim_end().to_string();
        info!(
            "Successfully generated LLVM IR for {}, length: {}",
            ebpf_function_name,
            llvm_ir.len()
        );

        // Get target triple
        let triple = inkwell::targets::TargetTriple::create("bpf-pc-linux");

        // Get BPF target
        let target = match inkwell::targets::Target::from_triple(&triple) {
            Ok(t) => t,
            Err(e) => {
                error!("Failed to get target for {}: {}", ebpf_function_name, e);
                return Err(CompileError::LLVM(format!("Failed to get target: {}", e)));
            }
        };

        // Create target machine
        let target_machine = match target.create_target_machine(
            &triple,
            "generic", // CPU
            "+alu32",  // Enable BPF ALU32 instructions
            inkwell::OptimizationLevel::Default,
            inkwell::targets::RelocMode::PIC,
            inkwell::targets::CodeModel::Small,
        ) {
            Some(tm) => tm,
            None => {
                error!("Failed to create target machine for {}", ebpf_function_name);
                return Err(CompileError::LLVM(
                    "Failed to create target machine".to_string(),
                ));
            }
        };

        // Generate eBPF object file
        info!("Generating eBPF object file for {}...", ebpf_function_name);
        let object_code = match target_machine
            .write_to_memory_buffer(&module, inkwell::targets::FileType::Object)
        {
            Ok(buf) => {
                info!(
                    "Successfully generated object code for {}! Size: {}",
                    ebpf_function_name,
                    buf.get_size()
                );
                buf
            }
            Err(e) => {
                error!(
                    "Failed to generate object code for {}: {}",
                    ebpf_function_name, e
                );
                return Err(CompileError::LLVM(format!(
                    "Failed to generate object code: {}",
                    e
                )));
            }
        };

        // Create UProbeConfig for this trace pattern
        let uprobe_config = UProbeConfig {
            trace_pattern: pattern.clone(),
            binary_path: String::new(), // Will be set later when attaching
            function_name: match &pattern {
                TracePattern::FunctionName(name) => Some(name.clone()),
                _ => None,
            },
            function_address: None, // Will be resolved later
            uprobe_offset: None,    // Will be calculated later
            target_pid: pid,        // Set from function parameter
            ebpf_bytecode: object_code.as_slice().to_vec(),
            ebpf_function_name,
        };

        uprobe_configs.push(uprobe_config);
        info!("Created UProbeConfig for pattern {:?}", pattern);
    }

    info!(
        "eBPF compilation completed! Generated {} UProbe configurations",
        uprobe_configs.len()
    );
    Ok(uprobe_configs)
}

/// Compile source code to eBPF bytecode for multiple trace patterns (legacy interface)
/// Returns UProbeConfig for each trace pattern with individual eBPF bytecode
/// This function parses the source and then calls compile_ast_to_uprobe_configs
pub fn compile_to_uprobe_configs(
    source: &str,
    pid: Option<u32>,
    binary_path: Option<&str>,
    save_ir: bool,
    binary_analyzer: Option<&ghostscope_binary::BinaryAnalyzer>,
) -> Result<Vec<UProbeConfig>> {
    info!("Starting eBPF compilation for multiple trace patterns (legacy interface)...");

    // Parse the source code
    let program = parser::parse(source)?;

    // Call the new function with pre-parsed AST
    compile_ast_to_uprobe_configs(&program, pid, None, binary_path, save_ir, binary_analyzer)
}

/// Compile source code to eBPF bytecode
/// Also returns extracted trace points for the caller to use
pub fn compile_to_ebpf_with_trace_points(source: &str) -> Result<(Vec<u8>, Vec<TracePoint>)> {
    // Use the new function and return first config's bytecode for backward compatibility
    // Use default values for pid and binary path since this is legacy function
    let uprobe_configs = compile_to_uprobe_configs(source, None, None, false, None)?;
    if uprobe_configs.is_empty() {
        return Err(CompileError::LLVM(
            "No uprobe configurations generated".to_string(),
        ));
    }

    // Extract trace points from uprobe configs
    let trace_points: Vec<TracePoint> = uprobe_configs
        .iter()
        .map(|config| TracePoint {
            pattern: config.trace_pattern.clone(),
            function_name: config.function_name.clone(),
            address: config.function_address,
            wildcard: match &config.trace_pattern {
                TracePattern::Wildcard(pattern) => Some(pattern.clone()),
                _ => None,
            },
        })
        .collect();

    // Return first config's bytecode for backward compatibility
    Ok((uprobe_configs[0].ebpf_bytecode.clone(), trace_points))
}

/// Compile source code to eBPF bytecode (legacy interface)
pub fn compile_to_ebpf(source: &str) -> Result<Vec<u8>> {
    compile_to_ebpf_with_trace_points(source).map(|(bytecode, _)| bytecode)
}

/// Format eBPF bytecode as hexadecimal string for inspection
pub fn format_ebpf_bytecode(bytecode: &[u8]) -> String {
    let mut result = String::new();

    // Display in 16-byte per line format
    for (i, chunk) in bytecode.chunks(16).enumerate() {
        // Add offset address
        result.push_str(&format!("{:08x}:  ", i * 16));

        // Add hexadecimal bytes
        for (j, &byte) in chunk.iter().enumerate() {
            result.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                // Add extra space in the middle
                result.push_str(" ");
            }
        }

        // Add spaces to align ASCII part
        if chunk.len() < 16 {
            let spaces = (16 - chunk.len()) * 3 + if chunk.len() <= 8 { 1 } else { 0 };
            result.push_str(&" ".repeat(spaces));
        }

        // Add ASCII representation
        result.push_str(" |");
        for &byte in chunk {
            if byte >= 32 && byte <= 126 {
                // Printable ASCII character
                result.push(byte as char);
            } else {
                // Non-printable character represented by dot
                result.push('.');
            }
        }
        result.push_str("|\n");
    }

    result
}

/// Generate file name for AST files
pub fn generate_file_name_for_ast(pid: Option<u32>, binary_path: Option<&str>) -> String {
    let pid_part = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let exec_part = binary_path
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");

    format!("gs_{}_{}_{}", pid_part, exec_part, "ast")
}

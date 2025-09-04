use crate::args::ParsedArgs;
use crate::session::GhostSession;
use anyhow::Result;
use tracing::{info, warn};

/// Run GhostScope in command line mode with direct script execution
pub async fn run_command_line_runtime(parsed_args: ParsedArgs) -> Result<()> {
    info!("Starting GhostScope in command line mode");

    // Step 1: Get script content
    let script_content = get_script_content(&parsed_args)?;

    // Step 2: Initialize debug session and DWARF information processing
    info!("Initializing debug session and DWARF information processing...");

    let mut session = GhostSession::new_with_binary(&parsed_args)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create debug session: {}", e))?;

    // Step 3: Display session information
    info!("Debug session created");
    info!("Save LLVM IR files: {}", parsed_args.should_save_llvm_ir);
    info!("Save eBPF bytecode files: {}", parsed_args.should_save_ebpf);
    info!("Save AST files: {}", parsed_args.should_save_ast);

    if let Some(ref binary) = session.target_binary {
        info!("Target binary: {}", binary);
        if !session.target_args.is_empty() {
            info!("Binary arguments: {:?}", session.target_args);
        }
    }
    if let Some(pid) = session.target_pid {
        info!("Target PID: {}", pid);
    }

    // Step 4: Validate binary analysis
    if parsed_args.pid.is_some() || parsed_args.binary_path.is_some() {
        match session.get_debug_info() {
            Some(debug_info) => {
                info!("✓ Binary analysis successful");
                info!("  Path: {}", debug_info.binary_path.display());
                info!("  Debug info: {:?}", debug_info.debug_path);
                info!("  Has symbols: {}", debug_info.has_symbols);
                info!("  Has debug info: {}", debug_info.has_debug_info);
                info!("  Entry point: {:?}", debug_info.entry_point);
                info!("  Base address: 0x{:x}", debug_info.base_address);

                // For source line tracing, we need debug info
                if !debug_info.has_debug_info {
                    warn!("Warning: No debug information available. Source line tracing (trace file.c:line) will not work.");
                    warn!("To enable source line tracing, compile your target with debug symbols (-g flag).");
                }
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Binary analysis failed! Cannot proceed without binary information for PID or binary path. \
                    Possible solutions: 1. Check that PID {} exists: ps -p {}, \
                    2. Check binary path permissions, 3. Run with sudo if needed for process access",
                    parsed_args.pid.unwrap_or(0),
                    parsed_args.pid.unwrap_or(0)
                ));
            }
        }
    } else {
        info!("No target binary or PID specified - running in standalone mode");
    }

    // Step 5: Show available functions for user reference
    if let Some(_debug_info) = session.get_debug_info() {
        let functions = session.list_functions();
        if !functions.is_empty() {
            info!("Available functions (showing first 10):");
            for func in functions.iter().take(10) {
                info!("  {}", func);
            }
            if functions.len() > 10 {
                info!("  ... and {} more", functions.len() - 10);
            }
        }
    }

    // Step 6: Compile script using unified interface
    info!("Starting unified script compilation with DWARF integration...");

    let binary_analyzer = session
        .binary_analyzer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Binary analyzer is required for script compilation"))?;

    let binary_path_string = binary_analyzer
        .debug_info()
        .binary_path
        .to_string_lossy()
        .to_string();

    let save_options = ghostscope_compiler::SaveOptions {
        save_llvm_ir: parsed_args.should_save_llvm_ir,
        save_ast: parsed_args.should_save_ast,
        save_ebpf: parsed_args.should_save_ebpf,
        binary_path_hint: Some(binary_path_string.clone()),
    };

    let compilation_result = ghostscope_compiler::compile_script_to_uprobe_configs(
        &script_content,
        binary_analyzer,
        session.target_pid,
        &save_options,
    )?;

    info!(
        "✓ Script compilation successful: {} trace points found, {} uprobe configs generated",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len()
    );
    info!("Target info: {}", compilation_result.target_info);

    if save_options.save_llvm_ir || save_options.save_ebpf || save_options.save_ast {
        info!("Files saved with consistent naming: gs_{{pid}}_{{exec}}_{{func}}_{{index}}");
    }

    // Step 7: Prepare and attach uprobe configurations
    let mut uprobe_configs = compilation_result.uprobe_configs;

    for config in uprobe_configs.iter_mut() {
        config.binary_path = binary_path_string.clone();
    }

    if !uprobe_configs.is_empty() {
        info!("Attaching {} uprobe configurations", uprobe_configs.len());
        for (i, config) in uprobe_configs.iter().enumerate() {
            info!(
                "  Config {}: {:?} -> 0x{:x}",
                i,
                config
                    .function_name
                    .as_ref()
                    .unwrap_or(&format!("0x{:x}", config.function_address.unwrap_or(0))),
                config.uprobe_offset.unwrap_or(0)
            );
        }

        session.attach_uprobes(&uprobe_configs).await.map_err(|e| {
            anyhow::anyhow!(
                "Failed to attach uprobes: {}. Possible reasons: \
                1. Need root permissions (run with sudo), \
                2. Target binary doesn't exist or lacks debug info, \
                3. Process not running or PID invalid, \
                4. Function addresses not accessible",
                e
            )
        })?;

        info!("All uprobes attached successfully! Starting event monitoring...");
    } else {
        return Err(anyhow::anyhow!(
            "No uprobe configurations created - nothing to attach"
        ));
    }

    // Step 8: Display usage information
    info!("\nUsage examples:");
    info!("  sudo ./ghostscope --script 'trace main {{ print \"Hello\"; }}'");
    info!("  sudo ./ghostscope --script-file my_trace.gs");
    info!("  sudo ./ghostscope -s 'trace printf* {{ print $arg0; }}'");
    info!("\nTrace script syntax:");
    info!("  trace <function_name> {{ statements... }}");
    info!("  trace <pattern*> {{ statements... }}");
    info!("  trace 0x<address> {{ statements... }}");
    info!("  trace file.c:123 {{ statements... }}");
    info!("  Special variables: $arg0, $arg1, $retval, $pc, $sp");

    // Step 9: Start event monitoring loop
    session
        .start_event_monitoring()
        .await
        .map_err(|e| anyhow::anyhow!("Event monitoring failed: {}", e))?;

    Ok(())
}

/// Validate command line arguments for consistency and completeness
pub fn validate_arguments(args: &ParsedArgs) -> Result<()> {
    // Must have either PID or binary path for meaningful operation
    if args.pid.is_none() && args.binary_path.is_none() {
        warn!("No target PID or binary path specified - running in standalone mode");
    }

    // Cannot specify both PID and binary simultaneously
    if args.pid.is_some() && args.binary_path.is_some() {
        // TODO: actually we can
        return Err(anyhow::anyhow!(
            "Cannot specify both PID (-p) and binary path simultaneously. Choose one target method."
        ));
    }

    if let Some(pid) = args.pid {
        if !is_pid_running(pid) {
            return Err(anyhow::anyhow!(
                "Process with PID {} is not running. Use 'ps -p {}' to verify the process exists",
                pid,
                pid
            ));
        }
        info!("✓ Target PID {} is running", pid);
    }

    // Script file must exist if specified
    if let Some(script_file) = &args.script_file {
        if !script_file.exists() {
            return Err(anyhow::anyhow!(
                "Script file does not exist: {}",
                script_file.display()
            ));
        }
        if !script_file.is_file() {
            return Err(anyhow::anyhow!(
                "Script path is not a file: {}",
                script_file.display()
            ));
        }
    }

    // Debug file must exist if specified
    if let Some(debug_file) = &args.debug_file {
        if !debug_file.exists() {
            return Err(anyhow::anyhow!(
                "Debug file does not exist: {}",
                debug_file.display()
            ));
        }
    }

    info!("✓ Command line arguments validated successfully");
    Ok(())
}

/// Check if a process with given PID is currently running
fn is_pid_running(pid: u32) -> bool {
    use std::path::Path;

    // On Linux, check if /proc/PID exists and is a directory
    let proc_path = format!("/proc/{}", pid);
    Path::new(&proc_path).is_dir()
}

/// Get script content from arguments or provide default
fn get_script_content(args: &ParsedArgs) -> Result<String> {
    match (&args.script, &args.script_file) {
        (Some(script), _) => {
            info!("Using inline script from command line");
            Ok(script.clone())
        }
        (None, Some(script_file)) => {
            info!("Loading script from file: {}", script_file.display());
            std::fs::read_to_string(script_file).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read script file '{}': {}",
                    script_file.display(),
                    e
                )
            })
        }
        (None, None) => {
            warn!("No script provided, using default trace example");
            Ok(r#"
                trace main {
                    print "Entering main function";
                    print $arg0;
                    print $arg1;
                }
            "#
            .to_string())
        }
    }
}

/// Parse and validate script syntax, return AST
pub fn parse_and_validate_script(
    script_content: &str,
) -> Result<ghostscope_compiler::ast::Program> {
    info!("Parsing script content:\n{}", script_content);

    // Use ghostscope_compiler directly to parse the script
    match ghostscope_compiler::parser::parse(script_content) {
        Ok(ast) => {
            // Additional validation
            if ast.statements.is_empty() {
                return Err(anyhow::anyhow!("Script contains no statements"));
            }

            // Count trace patterns
            let trace_count = ast
                .statements
                .iter()
                .filter(|stmt| {
                    matches!(stmt, ghostscope_compiler::ast::Statement::TracePoint { .. })
                })
                .count();

            if trace_count == 0 {
                return Err(anyhow::anyhow!("Script contains no trace patterns"));
            }

            // Validate each statement
            for (i, stmt) in ast.statements.iter().enumerate() {
                validate_statement(i, stmt)?;
            }

            Ok(ast)
        }
        Err(e) => Err(anyhow::anyhow!("Script parsing error: {}", e)),
    }
}

/// Validate individual statement for semantic correctness
pub fn validate_statement(index: usize, stmt: &ghostscope_compiler::ast::Statement) -> Result<()> {
    match stmt {
        ghostscope_compiler::ast::Statement::TracePoint { pattern, body } => {
            // Validate trace pattern
            match pattern {
                ghostscope_compiler::ast::TracePattern::FunctionName(name) => {
                    if name.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Statement {}: function name cannot be empty",
                            index
                        ));
                    }
                    if name.contains(' ') {
                        return Err(anyhow::anyhow!(
                            "Statement {}: function name '{}' contains spaces",
                            index,
                            name
                        ));
                    }
                }
                ghostscope_compiler::ast::TracePattern::Wildcard(pattern) => {
                    if pattern.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Statement {}: wildcard pattern cannot be empty",
                            index
                        ));
                    }
                }
                ghostscope_compiler::ast::TracePattern::Address(addr) => {
                    if *addr == 0 {
                        return Err(anyhow::anyhow!(
                            "Statement {}: address cannot be zero",
                            index
                        ));
                    }
                }
                ghostscope_compiler::ast::TracePattern::SourceLine {
                    file_path,
                    line_number,
                } => {
                    if file_path.is_empty() {
                        return Err(anyhow::anyhow!(
                            "Statement {}: source file path cannot be empty",
                            index
                        ));
                    }
                    if *line_number == 0 {
                        return Err(anyhow::anyhow!(
                            "Statement {}: line number cannot be zero",
                            index
                        ));
                    }
                }
            }

            // Validate statements
            if body.is_empty() {
                warn!("Statement {}: no statements defined in trace block", index);
            }
        }
        _ => {
            // Other statement types are generally valid
        }
    }

    Ok(())
}

/// Get binary path for file naming from session
pub fn binary_path_for_session(session: &GhostSession) -> Option<String> {
    if let Some(ref analyzer) = session.binary_analyzer {
        Some(
            analyzer
                .debug_info()
                .binary_path
                .to_string_lossy()
                .to_string(),
        )
    } else {
        session.target_binary.clone()
    }
}

/// Save AST to file with consistent naming
pub fn save_ast_to_file(
    ast: &ghostscope_compiler::ast::Program,
    pid: Option<u32>,
    binary_path: Option<&str>,
) -> Result<()> {
    let file_base_name = ghostscope_compiler::generate_file_name_for_ast(pid, binary_path);
    let ast_filename = format!("{}.ast", file_base_name);

    // Format AST as pretty-printed JSON or debug format
    let ast_content = format!("{:#?}", ast);

    std::fs::write(&ast_filename, ast_content)
        .map_err(|e| anyhow::anyhow!("Failed to save AST to '{}': {}", ast_filename, e))?;

    info!("AST saved to '{}'", ast_filename);
    Ok(())
}

/// Helper function to extract target from script command
pub fn extract_target_from_script(script: &str) -> Option<String> {
    // Parse "trace <target> <script_content>" format
    if let Some(trace_prefix) = script.strip_prefix("trace ") {
        if let Some(first_space) = trace_prefix.find(' ') {
            return Some(trace_prefix[..first_space].to_string());
        } else {
            // Only target, no script content
            return Some(trace_prefix.trim().to_string());
        }
    }
    None
}

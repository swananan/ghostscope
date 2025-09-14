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
        match session.get_module_stats() {
            Some(stats) => {
                info!("✓ Process analysis successful");
                info!("  Total modules: {}", stats.total_modules);
                info!("  Executable modules: {}", stats.executable_modules);
                info!("  Library modules: {}", stats.library_modules);
                info!("  Total symbols: {}", stats.total_symbols);
                info!(
                    "  Modules with debug info: {}",
                    stats.modules_with_debug_info
                );

                // For source line tracing, we need debug info
                if stats.modules_with_debug_info == 0 {
                    warn!("Warning: No debug information available in any module. Source line tracing (trace file.c:line) will not work.");
                    warn!("To enable source line tracing, compile your target with debug symbols (-g flag).");
                } else {
                    info!("✓ Debug information available for source line tracing");
                }
            }
            None => {
                return Err(anyhow::anyhow!(
                    "Process analysis failed! Cannot proceed without process information. \
                    Possible solutions: 1. Check that PID {} exists: ps -p {}, \
                    2. Check process permissions, 3. Run with sudo if needed for /proc access",
                    parsed_args.pid.unwrap_or(0),
                    parsed_args.pid.unwrap_or(0)
                ));
            }
        }
    } else {
        info!("No target binary or PID specified - running in standalone mode");
    }

    // Step 5: Show available functions for user reference
    if let Some(_stats) = session.get_module_stats() {
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

    // Step 6: Compile and load script using unified interface
    let save_options = ghostscope_compiler::SaveOptions {
        save_llvm_ir: parsed_args.should_save_llvm_ir,
        save_ast: parsed_args.should_save_ast,
        save_ebpf: parsed_args.should_save_ebpf,
        binary_path_hint: session
            .process_analyzer
            .as_ref()
            .and_then(|analyzer| analyzer.get_main_executable())
            .map(|main_module| {
                std::path::Path::new(&main_module.path)
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            }),
    };

    crate::script_compiler::compile_and_load_script_for_cli(
        &script_content,
        &mut session,
        &save_options,
    )
    .await?;

    // Step 7: Start event monitoring loop
    session
        .start_event_monitoring()
        .await
        .map_err(|e| anyhow::anyhow!("Event monitoring failed: {}", e))?;

    Ok(())
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
    if let Some(ref analyzer) = session.process_analyzer {
        analyzer
            .get_main_executable()
            .map(|main_module| main_module.path.clone())
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

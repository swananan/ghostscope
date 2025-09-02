mod args;
mod logging;
mod session;

use anyhow::Result;
use args::ParsedArgs;
use ghostscope_ui::{run_tui_mode, EventRegistry, LayoutMode};
use session::DebugSession;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

#[tokio::main]
async fn main() -> Result<()> {
    // Step 1: Parse and validate command line arguments
    let parsed_args = args::Args::parse_args();

    // Check if we should start in TUI mode
    if parsed_args.tui_mode {
        return run_tui_runtime(parsed_args).await;
    }

    // Initialize logging first so we can use it for validation
    let log_file_path = parsed_args.log_file.as_ref().and_then(|p| p.to_str());
    if let Err(e) = logging::initialize_logging(log_file_path, false) {
        eprintln!("Failed to initialize logging: {}", e);
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    // Step 1.1: Validate arguments immediately
    validate_arguments(&parsed_args)?;

    // Step 2: Validate PID existence if specified
    if let Some(pid) = parsed_args.pid {
        if !is_pid_running(pid) {
            return Err(anyhow::anyhow!(
                "Process with PID {} is not running. Use 'ps -p {}' to verify the process exists",
                pid,
                pid
            ));
        }
        info!("✓ Target PID {} is running", pid);
    }

    // Step 3: Parse and validate script syntax early
    let script_content = get_script_content(&parsed_args)?;
    let parsed_script = parse_and_validate_script(&script_content)?;

    let trace_count = parsed_script
        .statements
        .iter()
        .filter(|stmt| matches!(stmt, ghostscope_compiler::ast::Statement::TracePoint { .. }))
        .count();
    info!(
        "✓ Script parsing successful, found {} trace patterns",
        trace_count
    );

    // Step 4: Initialize and prepare DWARF information for efficient queries
    // This creates the debug session with optimized DWARF processing
    info!("Initializing debug session and DWARF information processing...");

    // Create debug session
    let mut session = DebugSession::new(&parsed_args)
        .map_err(|e| anyhow::anyhow!("Failed to create debug session: {}", e))?;

    // Save AST to file if requested (after session creation so we have target info)
    if parsed_args.should_save_ast {
        save_ast_to_file(
            &parsed_script,
            session.target_pid,
            binary_path_for_session(&session).as_deref(),
        )?;
    }

    // Display parsed arguments and session info
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

    // ====== CRITICAL: Validate binary analysis before proceeding ======
    // If we have a target PID or binary, we MUST have valid binary analysis
    // This prevents proceeding with incomplete information
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

    // Script has been validated and parsed successfully in Step 3

    // Show available functions if we have binary analysis and no target function specified
    if let Some(_debug_info) = session.get_debug_info() {
        if session.target_function.is_none() {
            let functions = session.list_functions();
            if functions.len() > 0 {
                info!("Available functions (showing first 10):");
                for func in functions.iter().take(10) {
                    info!("  {}", func);
                }
                if functions.len() > 10 {
                    info!("  ... and {} more", functions.len() - 10);
                }
            }
        }
    }

    // Script content and parsed AST are already available from Step 3
    info!("Starting GhostScope with validated script");

    // Note: LLVM IR generation is now unified with eBPF compilation
    // Each trace pattern will save its IR file during eBPF compilation

    // Compile to eBPF uprobe configurations (now includes LLVM IR generation)
    let binary_path_string = if let Some(ref analyzer) = session.binary_analyzer {
        Some(
            analyzer
                .debug_info()
                .binary_path
                .to_string_lossy()
                .to_string(),
        )
    } else {
        session.target_binary.clone()
    };
    let binary_path_for_naming = binary_path_string.as_deref();

    // Step 5: Generate LLVM IR using pre-parsed AST with optimized DWARF queries
    // Now we use the already validated parsed_script instead of re-parsing
    info!("Generating LLVM IR with optimized DWARF information access...");
    info!(
        "Using pre-validated AST with {} statements",
        parsed_script.statements.len()
    );

    match ghostscope_compiler::compile_ast_to_uprobe_configs(
        &parsed_script, // Use pre-parsed AST instead of re-parsing
        session.target_pid,
        binary_path_for_naming,
        parsed_args.should_save_llvm_ir,
        session.binary_analyzer.as_ref(), // Pass binary analyzer for variable validation
    ) {
        Ok(mut uprobe_configs) => {
            info!(
                "eBPF compilation successful, generated {} uprobe configurations",
                uprobe_configs.len()
            );
            if parsed_args.should_save_llvm_ir || parsed_args.should_save_ebpf {
                info!("Files saved with consistent naming: gs_{{pid}}_{{exec}}_{{func}}_{{index}}");
            }

            // Save each config's bytecode to individual files with consistent naming (if enabled)
            if parsed_args.should_save_ebpf {
                for (index, config) in uprobe_configs.iter().enumerate() {
                    let file_base_name = ghostscope_compiler::generate_file_name(
                        &config.trace_pattern,
                        index,
                        session.target_pid,
                        binary_path_for_naming,
                    );
                    let ebpf_filename = format!("{}.o", file_base_name);

                    if let Err(e) = std::fs::write(&ebpf_filename, &config.ebpf_bytecode) {
                        warn!("Failed to save eBPF bytecode to '{}': {}", ebpf_filename, e);
                    } else {
                        info!("eBPF bytecode saved to '{}'", ebpf_filename);
                    }
                }
            }

            // Resolve addresses for each uprobe configuration
            if !uprobe_configs.is_empty() {
                info!(
                    "Processing {} uprobe configurations from script:",
                    uprobe_configs.len()
                );
                let binary_path = if let Some(ref analyzer) = session.binary_analyzer {
                    analyzer
                        .debug_info()
                        .binary_path
                        .to_string_lossy()
                        .to_string()
                } else if let Some(ref binary_path) = session.target_binary {
                    binary_path.clone()
                } else {
                    return Err(anyhow::anyhow!(
                        "No target binary available for address resolution"
                    ));
                };

                for (i, config) in uprobe_configs.iter_mut().enumerate() {
                    // Update binary path and target PID for each config
                    config.binary_path = binary_path.clone();
                    config.target_pid = session.target_pid;

                    match &config.trace_pattern {
                        ghostscope_compiler::ast::TracePattern::FunctionName(function_name) => {
                            info!(
                                "  {}: Function '{}' - looking up in symbol table",
                                i, function_name
                            );

                            if let Some(ref analyzer) = session.binary_analyzer {
                                match analyzer.find_symbol(function_name) {
                                    Some(symbol) => {
                                        info!(
                                            "    Found function '{}' at address 0x{:x}",
                                            function_name, symbol.address
                                        );

                                        // Calculate uprobe offset
                                        if let Some(uprobe_offset) = symbol.uprobe_offset() {
                                            info!(
                                                "    Calculated uprobe offset: 0x{:x}",
                                                uprobe_offset
                                            );

                                            // Update config with resolved addresses
                                            config.function_name = Some(function_name.clone());
                                            config.function_address = Some(symbol.address);
                                            config.uprobe_offset = Some(uprobe_offset);

                                            info!(
                                                "    ✓ UProbe config updated for function '{}'",
                                                function_name
                                            );
                                        } else {
                                            warn!("    ✗ Unable to calculate uprobe offset for function '{}'", function_name);
                                        }
                                    }
                                    None => {
                                        warn!(
                                            "    ✗ Function '{}' not found in symbol table",
                                            function_name
                                        );

                                        // Show similar function names for debugging
                                        let similar =
                                            analyzer.symbol_table.find_matching(function_name);
                                        if !similar.is_empty() {
                                            info!("    Similar functions found:");
                                            for sym in similar.iter().take(5) {
                                                info!("      {}", sym.name);
                                            }
                                        }
                                    }
                                }
                            } else {
                                warn!("    ✗ No binary analyzer available for symbol lookup");
                            }
                        }
                        ghostscope_compiler::ast::TracePattern::Wildcard(pattern) => {
                            info!(
                                "  {}: Wildcard '{}' - pattern matching not yet implemented",
                                i, pattern
                            );
                        }
                        ghostscope_compiler::ast::TracePattern::Address(addr) => {
                            info!("  {}: Address 0x{:x} - direct attachment", i, addr);

                            // Update config with address information
                            config.function_name = None;
                            config.function_address = Some(*addr);
                            config.uprobe_offset = Some(*addr); // For direct address, offset equals address

                            info!("    ✓ UProbe config updated for address 0x{:x}", addr);
                        }
                        ghostscope_compiler::ast::TracePattern::SourceLine {
                            file_path,
                            line_number,
                        } => {
                            info!(
                                "  {}: Source line '{}:{}' - resolving from DWARF info",
                                i, file_path, line_number
                            );

                            if let Some(ref analyzer) = session.binary_analyzer {
                                info!(
                                    "    Resolving line {}:{} to machine code addresses...",
                                    file_path, line_number
                                );

                                // Use DWARF context to resolve line to addresses
                                if let Some(dwarf_context) = analyzer.dwarf_context() {
                                    let line_mappings = dwarf_context
                                        .get_addresses_for_line(file_path, *line_number);

                                    if !line_mappings.is_empty() {
                                        info!(
                                            "    Found {} addresses for line {}:{}",
                                            line_mappings.len(),
                                            file_path,
                                            line_number
                                        );

                                        // Use the first mapping for uprobe attachment
                                        // In a more sophisticated implementation, we might want to handle multiple addresses
                                        let first_mapping = &line_mappings[0];
                                        let resolved_address = first_mapping.address;

                                        info!("    ✓ Resolved {}:{} to address 0x{:x} (file: {}, line: {})", 
                                            file_path, line_number, resolved_address, first_mapping.file_path, first_mapping.line_number);

                                        // Calculate proper uprobe offset from the resolved address
                                        // We need to convert the virtual address to a file offset for uprobe attachment
                                        let uprobe_offset = analyzer
                                            .calculate_uprobe_offset_from_address(resolved_address);

                                        match uprobe_offset {
                                            Some(offset) => {
                                                info!("    ✓ Calculated uprobe offset: 0x{:x} (from virtual address: 0x{:x})", offset, resolved_address);

                                                // Update config with resolved address information
                                                config.function_name = None; // Source line tracing doesn't use function names
                                                config.function_address = Some(resolved_address);
                                                config.uprobe_offset = Some(offset);
                                            }
                                            None => {
                                                warn!("    ✗ Failed to calculate uprobe offset for address 0x{:x}", resolved_address);
                                                warn!("    This may happen if the address is not in a loadable section");
                                                continue; // Skip this configuration
                                            }
                                        }

                                        info!(
                                            "    ✓ UProbe config updated for source line '{}:{}'",
                                            file_path, line_number
                                        );

                                        // Show additional mappings if available
                                        if line_mappings.len() > 1 {
                                            info!("    Note: {} additional addresses available for this line:", line_mappings.len() - 1);
                                            for (idx, mapping) in
                                                line_mappings.iter().skip(1).take(3).enumerate()
                                            {
                                                info!(
                                                    "      [{}] 0x{:x}",
                                                    idx + 2,
                                                    mapping.address
                                                );
                                            }
                                            if line_mappings.len() > 4 {
                                                info!(
                                                    "      ... and {} more",
                                                    line_mappings.len() - 4
                                                );
                                            }
                                        }
                                    } else {
                                        warn!(
                                            "    ✗ No addresses found for source line '{}:{}'",
                                            file_path, line_number
                                        );
                                        warn!("    Possible reasons:");
                                        warn!("      - Source file path doesn't match debug info");
                                        warn!("      - Line number not found in debug info");
                                        warn!("      - Code may have been optimized away");
                                    }
                                } else {
                                    warn!("    ✗ No DWARF debug context available");
                                }
                            } else {
                                warn!("    ✗ No binary analyzer available for DWARF info");
                            }
                        }
                    }
                }

                info!("Updated {} uprobe configurations", uprobe_configs.len());

                // Attach each uprobe configuration
                if !uprobe_configs.is_empty() {
                    info!("Attaching uprobes using the configurations");
                    for (i, config) in uprobe_configs.iter().enumerate() {
                        info!(
                            "  Config {}: {:?} -> 0x{:x}",
                            i,
                            config.function_name.as_ref().unwrap_or(&format!(
                                "0x{:x}",
                                config.function_address.unwrap_or(0)
                            )),
                            config.uprobe_offset.unwrap_or(0)
                        );
                    }

                    match session.attach_uprobes(&uprobe_configs).await {
                        Ok(()) => {
                            info!(
                                "All uprobes attached successfully! Starting event monitoring..."
                            );
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Failed to attach uprobes: {}. Possible reasons: \
                                1. Need root permissions (run with sudo), \
                                2. Target binary doesn't exist or lacks debug info, \
                                3. Process not running or PID invalid, \
                                4. Function addresses not accessible",
                                e
                            ));
                        }
                    }
                } else {
                    return Err(anyhow::anyhow!(
                        "No uprobe configurations created - nothing to attach"
                    ));
                }
            } else {
                info!("No trace points found in script - using legacy behavior");
            }

            info!("\nNew usage with trace scripts:");
            info!("  sudo ./ghostscope --script 'trace main {{ print \"Hello\"; }}'");
            info!("  sudo ./ghostscope --script-file my_trace.gs");
            info!("  sudo ./ghostscope -s 'trace printf* {{ print $arg0; }}'");
            info!("\nTrace script syntax:");
            info!("  trace <function_name> {{ statements... }}");
            info!("  trace <pattern*> {{ statements... }}");
            info!("  trace 0x<address> {{ statements... }}");
            info!("  trace file.c:123 {{ statements... }}");
            info!("  Special variables: $arg0, $arg1, $retval, $pc, $sp");

            // For now, skip uprobe attachment since we need to implement
            // trace pattern extraction and multiple uprobe support

            // Start event monitoring loop
            session
                .start_monitoring()
                .await
                .map_err(|e| anyhow::anyhow!("Event monitoring failed: {}", e))?;

            Ok(())
        }
        Err(e) => Err(anyhow::anyhow!("eBPF compilation failed: {:?}", e)),
    }
}

/// Validate command line arguments for consistency and completeness
fn validate_arguments(args: &ParsedArgs) -> Result<()> {
    // Must have either PID or binary path for meaningful operation
    if args.pid.is_none() && args.binary_path.is_none() {
        warn!("No target PID or binary path specified - running in standalone mode");
    }

    // Cannot specify both PID and binary simultaneously
    if args.pid.is_some() && args.binary_path.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot specify both PID (-p) and binary path simultaneously. Choose one target method."
        ));
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
fn parse_and_validate_script(script_content: &str) -> Result<ghostscope_compiler::ast::Program> {
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
fn validate_statement(index: usize, stmt: &ghostscope_compiler::ast::Statement) -> Result<()> {
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
fn binary_path_for_session(session: &DebugSession) -> Option<String> {
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
fn save_ast_to_file(
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

/// Run GhostScope in TUI mode with tokio runtime coordination
async fn run_tui_runtime(parsed_args: ParsedArgs) -> Result<()> {
    // Initialize logging first
    let log_file_path = parsed_args.log_file.as_ref().and_then(|p| p.to_str());
    if let Err(e) = logging::initialize_logging(log_file_path, true) {
        eprintln!("Failed to initialize logging: {}", e);
        return Err(anyhow::anyhow!("Failed to initialize logging: {}", e));
    }

    info!("Starting GhostScope in TUI mode");

    // Validate basic arguments
    validate_tui_arguments(&parsed_args)?;

    // Create event communication channels
    let (event_registry, runtime_channels) = EventRegistry::new();

    // Initialize DWARF information processing in background
    let dwarf_task = {
        let parsed_args_clone = parsed_args.clone();
        let status_sender = runtime_channels.create_status_sender();
        tokio::spawn(
            async move { initialize_dwarf_processing(parsed_args_clone, status_sender).await },
        )
    };

    // Start the runtime coordination task with session from DWARF processing
    let runtime_task = tokio::spawn(async move {
        // Wait for DWARF processing to complete and get the session
        match dwarf_task.await {
            Ok(Ok(session)) => run_runtime_coordinator(runtime_channels, Some(session)).await,
            Ok(Err(e)) => {
                error!("DWARF processing failed: {}", e);
                run_runtime_coordinator(runtime_channels, None).await
            }
            Err(e) => {
                error!("DWARF task panicked: {}", e);
                run_runtime_coordinator(runtime_channels, None).await
            }
        }
    });

    // Convert layout mode to UI layout mode
    let ui_layout_mode = match parsed_args.layout_mode {
        args::LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
        args::LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
    };

    // Wait for tasks to complete or handle shutdown
    let result = tokio::select! {
        tui_result = run_tui_mode(event_registry, ui_layout_mode) => {
            info!("TUI exited");
            tui_result
        }
        runtime_result = runtime_task => {
            match runtime_result {
                Ok(result) => {
                    info!("Runtime coordinator completed");
                    result
                }
                Err(e) => {
                    error!("Runtime coordinator task failed: {}", e);
                    Err(anyhow::anyhow!("Runtime coordinator task failed: {}", e))
                }
            }
        }
    };

    result
}

/// Validate arguments specific to TUI mode
fn validate_tui_arguments(args: &ParsedArgs) -> Result<()> {
    // In TUI mode, we need at least a PID or binary path for DWARF processing
    if args.pid.is_none() && args.binary_path.is_none() {
        return Err(anyhow::anyhow!(
            "TUI mode requires either a PID (-p) or binary path. Example:\n  \
            ghostscope -p $(pidof test_program)\n  \
            ghostscope /path/to/binary"
        ));
    }

    // Cannot specify both PID and binary simultaneously
    if args.pid.is_some() && args.binary_path.is_some() {
        return Err(anyhow::anyhow!(
            "Cannot specify both PID (-p) and binary path simultaneously in TUI mode"
        ));
    }

    // Check PID exists if specified
    if let Some(pid) = args.pid {
        if !is_pid_running(pid) {
            return Err(anyhow::anyhow!(
                "Process with PID {} is not running. Use 'ps -p {}' to verify",
                pid,
                pid
            ));
        }
        info!("✓ Target PID {} is running", pid);
    }

    info!("✓ TUI mode arguments validated successfully");
    Ok(())
}

/// Initialize DWARF processing in background
async fn initialize_dwarf_processing(
    parsed_args: ParsedArgs,
    status_sender: tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) -> Result<DebugSession> {
    use ghostscope_ui::RuntimeStatus;

    // Send status update: starting DWARF loading
    let _ = status_sender.send(RuntimeStatus::DwarfLoadingStarted);

    // Create debug session for DWARF processing
    match DebugSession::new(&parsed_args) {
        Ok(session) => {
            // Validate that we have debug information
            match session.get_debug_info() {
                Some(debug_info) => {
                    info!("✓ Binary analysis successful in TUI mode");
                    info!("  Path: {}", debug_info.binary_path.display());
                    info!("  Debug info: {:?}", debug_info.debug_path);
                    info!("  Has symbols: {}", debug_info.has_symbols);
                    info!("  Has debug info: {}", debug_info.has_debug_info);
                    info!("  Base address: 0x{:x}", debug_info.base_address);

                    // Count available symbols for status update
                    let functions = session.list_functions();
                    let symbols_count = functions.len();

                    // Send success status
                    let _ =
                        status_sender.send(RuntimeStatus::DwarfLoadingCompleted { symbols_count });

                    if !debug_info.has_debug_info {
                        let _ = status_sender.send(
                            RuntimeStatus::Error(
                                "No debug information available. Compile with -g for full functionality".to_string()
                            )
                        );
                    }

                    // Return the session for use by runtime coordinator
                    Ok(session)
                }
                None => {
                    let error_msg = format!(
                        "Binary analysis failed! Cannot load DWARF information for PID {} or binary path {:?}",
                        parsed_args.pid.unwrap_or(0),
                        parsed_args.binary_path
                    );
                    let _ =
                        status_sender.send(RuntimeStatus::DwarfLoadingFailed(error_msg.clone()));
                    Err(anyhow::anyhow!(error_msg))
                }
            }
        }
        Err(e) => {
            let error_msg = format!("Failed to create debug session: {}", e);
            let _ = status_sender.send(RuntimeStatus::DwarfLoadingFailed(error_msg.clone()));
            Err(anyhow::anyhow!(error_msg))
        }
    }
}

/// Main runtime coordinator that handles commands and manages eBPF sessions
async fn run_runtime_coordinator(
    mut runtime_channels: ghostscope_ui::RuntimeChannels,
    mut session: Option<DebugSession>,
) -> Result<()> {
    use ghostscope_protocol::MessageType;
    use ghostscope_ui::events::TraceEvent;
    use ghostscope_ui::{RuntimeCommand, RuntimeStatus};

    info!("Runtime coordinator started");

    // Create trace sender for event polling task
    let trace_sender = runtime_channels.create_trace_sender();

    loop {
        tokio::select! {
            // Poll ringbuf events from all active loaders
            _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                if let Some(ref mut session) = session {
                    poll_ringbuf_events(session, &trace_sender);
                }
            }

            // Handle script compilation requests
            Some(script) = runtime_channels.script_receiver.recv() => {
                info!("Received script for compilation: {}", script);
                let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationStarted);

                // Use actual script compilation and loading
                if let Some(ref mut session) = session {
                    match compile_and_load_script(&script, session, &runtime_channels.status_sender) {
                        Ok(_) => {
                            info!("Script compilation and loading completed successfully");
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationCompleted);
                        }
                        Err(e) => {
                            error!("Script compilation failed: {}", e);
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed(e.to_string()));
                        }
                    }
                } else {
                    warn!("No debug session available for script compilation");
                    let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed("No debug session available".to_string()));
                }
            }

            // Handle runtime commands
            Some(command) = runtime_channels.command_receiver.recv() => {
                match command {
                    RuntimeCommand::ExecuteScript(script) => {
                        info!("Executing script: {}", script);
                        // Same as script_receiver handling
                        let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationStarted);
                        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
                        let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationCompleted);
                    }
                    RuntimeCommand::AttachToProcess(pid) => {
                        info!("Attaching to process: {}", pid);
                        // TODO: Implement process attachment
                        let _ = runtime_channels.status_sender.send(RuntimeStatus::ProcessAttached(pid));
                    }
                    RuntimeCommand::DetachFromProcess => {
                        info!("Detaching from process");
                        let _ = runtime_channels.status_sender.send(RuntimeStatus::ProcessDetached);
                    }
                    RuntimeCommand::ReloadBinary(path) => {
                        info!("Reloading binary: {}", path);
                        // TODO: Implement binary reloading
                    }
                    RuntimeCommand::RequestSourceCode => {
                        info!("Source code request received");
                        handle_source_code_request(&session, &runtime_channels.status_sender).await;
                    }
                    RuntimeCommand::Shutdown => {
                        info!("Shutdown command received");
                        break;
                    }
                }
            }
        }
    }

    info!("Runtime coordinator shutting down");
    Ok(())
}

/// Handle source code request from TUI
async fn handle_source_code_request(
    session: &Option<DebugSession>,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) {
    use ghostscope_ui::{events::SourceCodeInfo, RuntimeStatus};

    if let Some(session) = session {
        // Try to get source information from DWARF
        if let Some(binary_analyzer) = &session.binary_analyzer {
            if let Some(dwarf_context) = binary_analyzer.dwarf_context() {
                // For now, get main function address and find its source
                if let Some(main_symbol) = binary_analyzer.find_symbol("main") {
                    if let Some(source_location) =
                        dwarf_context.get_source_location(main_symbol.address)
                    {
                        info!(
                            "Found source location: file_path={}, line={}",
                            source_location.file_path, source_location.line_number
                        );

                        // Try multiple strategies to find the source file
                        let possible_paths = get_possible_source_paths(
                            &source_location.file_path,
                            &binary_analyzer.debug_info().binary_path,
                        );

                        for path in possible_paths {
                            info!("Trying to read source file: {}", path.display());
                            match std::fs::read_to_string(&path) {
                                Ok(content) => {
                                    let lines: Vec<String> =
                                        content.lines().map(|s| s.to_string()).collect();
                                    let source_info = SourceCodeInfo {
                                        file_path: path.to_string_lossy().to_string(),
                                        content: lines,
                                        current_line: Some(source_location.line_number as usize),
                                    };
                                    let _ = status_sender
                                        .send(RuntimeStatus::SourceCodeLoaded(source_info));
                                    return;
                                }
                                Err(e) => {
                                    info!("Failed to read source file {}: {}", path.display(), e);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // If we get here, source code loading failed - provide detailed error info
    if let Some(session) = session {
        if let Some(binary_analyzer) = &session.binary_analyzer {
            if let Some(dwarf_context) = binary_analyzer.dwarf_context() {
                if let Some(main_symbol) = binary_analyzer.find_symbol("main") {
                    if let Some(source_location) =
                        dwarf_context.get_source_location(main_symbol.address)
                    {
                        // We found DWARF info but couldn't find source files
                        let possible_paths = get_possible_source_paths(
                            &source_location.file_path,
                            &binary_analyzer.debug_info().binary_path,
                        );

                        let path_list: Vec<String> = possible_paths
                            .iter()
                            .map(|p| p.to_string_lossy().to_string())
                            .collect();

                        let error_msg = format!(
                            "Source file not found. DWARF reports: '{}' (line {}). Searched paths: {}",
                            source_location.file_path,
                            source_location.line_number,
                            path_list.join(", ")
                        );

                        let _ = status_sender.send(RuntimeStatus::SourceCodeLoadFailed(error_msg));
                        return;
                    }
                }
            }
        }
    }

    // Fallback error message
    let _ = status_sender.send(RuntimeStatus::SourceCodeLoadFailed(
        "No debug information available. Compile with -g for source code display.".to_string(),
    ));
}

/// Get possible source file paths based on DWARF info and binary location
fn get_possible_source_paths(dwarf_file_path: &str, binary_path: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Try the original path from DWARF
    paths.push(PathBuf::from(dwarf_file_path));

    // 2. If it's a relative path like "file_1", try common source file names in binary directory
    if dwarf_file_path.starts_with("file_") || !Path::new(dwarf_file_path).is_absolute() {
        if let Some(binary_dir) = binary_path.parent() {
            // Try test_program.c in the same directory as binary
            paths.push(binary_dir.join("test_program.c"));

            // Try other common source file extensions
            let binary_stem = binary_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("main");

            for ext in &["c", "cpp", "cc", "cxx"] {
                paths.push(binary_dir.join(format!("{}.{}", binary_stem, ext)));
            }
        }
    }

    // 3. If it's a filename without directory, try in binary directory
    if let Some(filename) = Path::new(dwarf_file_path).file_name() {
        if let Some(binary_dir) = binary_path.parent() {
            paths.push(binary_dir.join(filename));
        }
    }

    paths
}

/// Compile and load a script in TUI mode using existing logic from CLI mode
fn compile_and_load_script(
    script: &str,
    session: &mut DebugSession,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) -> Result<()> {
    use ghostscope_ui::RuntimeStatus;

    // Step 1: Parse and validate script
    let parsed_script = parse_and_validate_script(script)?;
    let trace_count = parsed_script
        .statements
        .iter()
        .filter(|stmt| matches!(stmt, ghostscope_compiler::ast::Statement::TracePoint { .. }))
        .count();

    info!("Parsed script with {} trace points", trace_count);

    if trace_count == 0 {
        return Err(anyhow::anyhow!("Script contains no valid trace points"));
    }

    // Step 2: Compile to eBPF using existing compiler
    let binary_path = if let Some(ref analyzer) = session.binary_analyzer {
        analyzer
            .debug_info()
            .binary_path
            .to_string_lossy()
            .to_string()
    } else if let Some(ref binary_path) = session.target_binary {
        binary_path.clone()
    } else {
        return Err(anyhow::anyhow!(
            "No target binary available for compilation"
        ));
    };

    let binary_path_for_naming = Path::new(&binary_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("unknown");

    let mut uprobe_configs = match ghostscope_compiler::compile_ast_to_uprobe_configs(
        &parsed_script,
        session.target_pid,
        Some(binary_path_for_naming),
        false, // don't save LLVM IR in TUI mode
        session.binary_analyzer.as_ref(),
    ) {
        Ok(configs) => configs,
        Err(e) => {
            return Err(anyhow::anyhow!("eBPF compilation failed: {}", e));
        }
    };

    info!(
        "eBPF compilation successful, generated {} uprobe configurations",
        uprobe_configs.len()
    );

    // Step 3: Resolve addresses and attach uprobes (simplified version)
    for (i, config) in uprobe_configs.iter_mut().enumerate() {
        config.binary_path = binary_path.clone();
        config.target_pid = session.target_pid;

        match &config.trace_pattern {
            ghostscope_compiler::ast::TracePattern::FunctionName(function_name) => {
                if let Some(ref analyzer) = session.binary_analyzer {
                    if let Some(symbol) = analyzer.find_symbol(function_name) {
                        config.function_address = Some(symbol.address);
                        if let Some(uprobe_offset) = symbol.uprobe_offset() {
                            config.uprobe_offset = Some(uprobe_offset);
                        } else {
                            config.uprobe_offset = Some(symbol.address);
                        }

                        info!(
                            "Resolved function '{}' to address 0x{:x}",
                            function_name, symbol.address
                        );

                        // Send uprobe attached status
                        let _ = status_sender.send(RuntimeStatus::UprobeAttached {
                            function: function_name.clone(),
                            address: symbol.address,
                        });
                    } else {
                        warn!("Function '{}' not found in binary", function_name);
                        continue;
                    }
                } else {
                    warn!("No binary analyzer available for address resolution");
                    continue;
                }
            }
            ghostscope_compiler::ast::TracePattern::SourceLine {
                file_path,
                line_number,
            } => {
                info!(
                    "Resolving source line '{}:{}' to addresses",
                    file_path, line_number
                );

                if let Some(ref analyzer) = session.binary_analyzer {
                    if let Some(dwarf_context) = analyzer.dwarf_context() {
                        let line_mappings =
                            dwarf_context.get_addresses_for_line(file_path, *line_number);

                        if !line_mappings.is_empty() {
                            info!(
                                "Found {} addresses for line {}:{}",
                                line_mappings.len(),
                                file_path,
                                line_number
                            );

                            // Use the first mapping for uprobe attachment
                            let first_mapping = &line_mappings[0];
                            let resolved_address = first_mapping.address;

                            info!(
                                "Resolved {}:{} to address 0x{:x}",
                                file_path, line_number, resolved_address
                            );

                            // Calculate proper uprobe offset from the resolved address
                            if let Some(uprobe_offset) =
                                analyzer.calculate_uprobe_offset_from_address(resolved_address)
                            {
                                info!(
                                    "Calculated uprobe offset: 0x{:x} for address 0x{:x}",
                                    uprobe_offset, resolved_address
                                );

                                // Update config with resolved address information
                                config.function_name = None; // Source line tracing doesn't use function names
                                config.function_address = Some(resolved_address);
                                config.uprobe_offset = Some(uprobe_offset);

                                // Send uprobe attached status for source line
                                let _ = status_sender.send(RuntimeStatus::UprobeAttached {
                                    function: format!("{}:{}", file_path, line_number),
                                    address: resolved_address,
                                });
                            } else {
                                warn!(
                                    "Failed to calculate uprobe offset for address 0x{:x}",
                                    resolved_address
                                );
                                continue;
                            }
                        } else {
                            warn!(
                                "No addresses found for source line {}:{}",
                                file_path, line_number
                            );
                            continue;
                        }
                    } else {
                        warn!("No DWARF context available for line number resolution");
                        continue;
                    }
                } else {
                    warn!("No binary analyzer available for source line resolution");
                    continue;
                }
            }
            _ => {
                // Handle other trace patterns if needed
                warn!(
                    "Trace pattern not yet supported in TUI mode: {:?}",
                    config.trace_pattern
                );
                continue;
            }
        }

        // Step 4: Actually load and attach the eBPF program
        info!(
            "Loading eBPF program for config {} ({} bytes)",
            i,
            config.ebpf_bytecode.len()
        );

        let mut loader = match ghostscope_loader::GhostScopeLoader::new(&config.ebpf_bytecode) {
            Ok(loader) => loader,
            Err(e) => {
                error!("Failed to create eBPF loader for config {}: {}", i, e);
                continue;
            }
        };

        // Attach uprobe based on resolved address
        if let Some(uprobe_offset) = config.uprobe_offset {
            // Handle both function name and source line based tracing
            let attachment_name = if let Some(ref function_name) = config.function_name {
                // Function-based tracing
                info!(
                    "Attaching uprobe to function '{}' at offset 0x{:x} in {}",
                    function_name, uprobe_offset, config.binary_path
                );
                function_name.clone()
            } else if let Some(function_address) = config.function_address {
                // Source line based tracing - use address as identifier
                let address_name = format!("0x{:x}", function_address);
                info!(
                    "Attaching uprobe to address {} (offset 0x{:x}) in {}",
                    address_name, uprobe_offset, config.binary_path
                );
                address_name
            } else {
                warn!("No function name or address available for uprobe attachment");
                continue;
            };

            match loader.attach_uprobe_with_program_name(
                &config.binary_path,
                &attachment_name,
                Some(uprobe_offset),
                session.target_pid.map(|p| p as i32),
                Some(&config.ebpf_function_name),
            ) {
                Ok(_) => {
                    info!("Successfully attached uprobe for '{}'", attachment_name);

                    // Store the loader in session for event polling
                    session.loaders.push(loader);
                }
                Err(e) => {
                    error!("Failed to attach uprobe for '{}': {}", attachment_name, e);
                    continue;
                }
            }
        } else {
            warn!("No uprobe offset available for config {}", i);
            continue;
        }
    }

    Ok(())
}

/// Poll ringbuf events from all active loaders and send formatted events to TUI
fn poll_ringbuf_events(
    session: &mut DebugSession,
    trace_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::events::TraceEvent>,
) {
    use ghostscope_protocol::MessageType;
    use ghostscope_ui::events::TraceEvent;
    use std::time::{SystemTime, UNIX_EPOCH};

    // Get current timestamp for events
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    // Poll events from all loaders
    for (loader_index, loader) in session.loaders.iter_mut().enumerate() {
        match loader.poll_events() {
            Ok(Some(events)) => {
                for event in events {
                    // Format the main message content
                    let variables_text = event
                        .variables
                        .iter()
                        .map(|var| format!("{}: {}", var.name, var.formatted_value))
                        .collect::<Vec<_>>()
                        .join(", ");

                    let message = if variables_text.is_empty() {
                        format!("[Loader {}] Function trace", loader_index)
                    } else {
                        format!("[Loader {}] Variables: [{}]", loader_index, variables_text)
                    };

                    let trace_event = TraceEvent {
                        timestamp: event.timestamp,
                        trace_id: event.trace_id,
                        pid: event.pid,
                        message,
                        trace_type: MessageType::VariableData,
                    };

                    // Send to TUI (ignore errors if channel is closed)
                    let _ = trace_sender.send(trace_event);
                }
            }
            Ok(None) => {
                // No events available, continue
            }
            Err(e) => {
                // Log error and send error event to TUI
                error!("Error polling events from loader {}: {}", loader_index, e);
                let error_event = TraceEvent {
                    timestamp: current_timestamp,
                    trace_id: 0, // No trace ID for error events
                    pid: 0,      // No specific PID for error events
                    message: format!("Error polling events from loader {}: {}", loader_index, e),
                    trace_type: MessageType::Error,
                };
                let _ = trace_sender.send(error_event);
            }
        }
    }
}

use crate::config::{MergedConfig, ParsedArgs};
use crate::core::GhostSession;
use anyhow::Result;
use tracing::{debug, error, info, warn};

/// Run GhostScope in command line mode with merged configuration
pub async fn run_command_line_runtime_with_config(config: MergedConfig) -> Result<()> {
    info!("Starting GhostScope in command line mode");

    // Step 1: Get script content
    let script_content = get_script_content_from_config(&config)?;

    // Step 2: Initialize debug session and DWARF information processing
    info!("Initializing debug session and DWARF information processing...");

    let session = GhostSession::new_with_binary_and_config(&config)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create debug session: {}", e))?;

    // Continue with the rest of the CLI runtime logic, using config instead of parsed_args
    run_cli_with_session(session, script_content, &config).await
}

/// Run GhostScope in command line mode with direct script execution
#[allow(dead_code)]
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

    // Step 6: Compile and load script with graceful error handling
    if let Err(e) =
        crate::script::compile_and_load_script_for_cli(&script_content, &mut session, &save_options)
            .await
    {
        error!("Failed to compile and load script: {}", e);
        info!("GhostScope encountered an error during script compilation. Exiting gracefully.");
        return Err(e);
    }

    // Step 7: Start event monitoring loop using trace_manager
    info!(
        "Starting event monitoring for {} active traces",
        session.trace_manager.active_trace_count()
    );

    let mut event_count = 0;
    loop {
        tokio::select! {
            events = session.trace_manager.wait_for_all_events_async() => {
                for event in events {
                    event_count += 1;

                    // Generate formatted output for better display
                    let formatted_output = event.to_formatted_output();
                    if !formatted_output.is_empty() {
                        println!("[Event #{}] Output:", event_count);
                        for line in formatted_output {
                            println!("  {}", line);
                        }
                    }

                    // Also show raw debug info if needed (can be removed later)
                    debug!("[Event #{}] Raw: {:?}", event_count, event);
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Run CLI session with existing GhostSession and configuration
async fn run_cli_with_session(
    mut session: GhostSession,
    script_content: String,
    config: &MergedConfig,
) -> Result<()> {
    // Step 3: Display session information
    info!("Debug session created");
    info!("Save LLVM IR files: {}", config.should_save_llvm_ir);
    info!("Save eBPF bytecode files: {}", config.should_save_ebpf);
    info!("Save AST files: {}", config.should_save_ast);

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
    if config.pid.is_some() || config.binary_path.is_some() {
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
                    config.pid.unwrap_or(0),
                    config.pid.unwrap_or(0)
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
        save_llvm_ir: config.should_save_llvm_ir,
        save_ast: config.should_save_ast,
        save_ebpf: config.should_save_ebpf,
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

    // Step 7: Compile and load script with graceful error handling
    if let Err(e) =
        crate::script::compile_and_load_script_for_cli(&script_content, &mut session, &save_options)
            .await
    {
        error!("Failed to compile and load script: {}", e);
        info!("GhostScope encountered an error during script compilation. Exiting gracefully.");
        return Err(e);
    }

    // Step 8: Start event monitoring loop using trace_manager
    info!(
        "Starting event monitoring for {} active traces",
        session.trace_manager.active_trace_count()
    );

    let mut event_count = 0;
    loop {
        tokio::select! {
            events = session.trace_manager.wait_for_all_events_async() => {
                for event in events {
                    event_count += 1;

                    // Generate formatted output for better display
                    let formatted_output = event.to_formatted_output();
                    if !formatted_output.is_empty() {
                        println!("[Event #{}] Output:", event_count);
                        for line in formatted_output {
                            println!("  {}", line);
                        }
                    }

                    // Also show raw debug info if needed (can be removed later)
                    debug!("[Event #{}] Raw: {:?}", event_count, event);
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, shutting down...");
                break;
            }
        }
    }

    Ok(())
}

/// Get script content from merged configuration or provide default
fn get_script_content_from_config(config: &MergedConfig) -> Result<String> {
    match (&config.script, &config.script_file) {
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

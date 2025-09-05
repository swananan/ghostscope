use crate::args::ParsedArgs;
use crate::session::GhostSession;
use anyhow::Result;
use futures::future;
use ghostscope_protocol::{EventData, MessageType};
use ghostscope_ui::{
    events::{TargetDebugInfo, TargetType, VariableDebugInfo},
    run_tui_mode, EventRegistry,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Run GhostScope in TUI mode with tokio task coordination
pub async fn run_tui_coordinator(parsed_args: ParsedArgs) -> Result<()> {
    info!("Starting GhostScope in TUI mode");

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
        crate::args::LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
        crate::args::LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
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

/// Initialize DWARF processing in background
async fn initialize_dwarf_processing(
    parsed_args: ParsedArgs,
    status_sender: tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) -> Result<GhostSession> {
    use ghostscope_ui::RuntimeStatus;

    // Send status update: starting DWARF loading
    let _ = status_sender.send(RuntimeStatus::DwarfLoadingStarted);

    // Create debug session for DWARF processing
    match GhostSession::new_with_binary(&parsed_args).await {
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
    mut session: Option<GhostSession>,
) -> Result<()> {
    use ghostscope_ui::{RuntimeCommand, RuntimeStatus};

    info!("Runtime coordinator started");

    // Create trace sender for event polling task
    let trace_sender = runtime_channels.create_trace_sender();

    loop {
        tokio::select! {
            // Wait for events asynchronously from trace manager (TUI mode should use trace manager, not command loaders)
            events = async {
                if let Some(ref mut session) = session {
                    // TUI mode uses trace manager which manages individual trace instances
                    session.trace_manager.wait_for_all_events_async().await
                } else {
                    // No session, return empty events and let the outer loop continue
                    Vec::new()
                }
            }, if session.is_some() => {
                if let Some(ref session) = session {
                    // events is Vec<EventData> from trace manager
                    for event_data in events {
                        // Send EventData directly to TUI (ignore errors if channel is closed)
                        let _ = trace_sender.send(event_data);
                    }
                }
            }

            // Handle runtime commands
            Some(command) = runtime_channels.command_receiver.recv() => {
                match command {
                    RuntimeCommand::ExecuteScript { command: script, trace_id } => {
                        info!("Executing script with trace_id {:?}: {}", trace_id, script);

                        if let Some(ref mut session) = session {
                            // Use the new TUI-specific compilation and loading with strict all-or-nothing success
                            match crate::script_compiler::compile_and_load_script_for_tui(
                                &script,
                                trace_id,
                                session,
                            ).await {
                                Ok(_) => {
                                    info!("Script with trace_id {} compiled and loaded successfully", trace_id);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationCompleted { trace_id });
                                }
                                Err(e) => {
                                    let _target = crate::script_compiler::extract_target_from_script(&script);
                                    error!("Script compilation failed for trace_id {}: {}", trace_id, e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                                        error: e.to_string(),
                                        trace_id,
                                    });
                                }
                            }
                        } else {
                            let _target = crate::script_compiler::extract_target_from_script(&script);
                            warn!("No debug session available for script compilation");
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                                error: "No debug session available".to_string(),
                                trace_id,
                            });
                        }
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
                        handle_source_code_request(&mut session, &runtime_channels.status_sender).await;
                    }
                    RuntimeCommand::DisableTrace(trace_id) => {
                        info!("Disabling trace: {}", trace_id);
                        if let Some(ref mut session) = session {
                            match session.trace_manager.disable_trace(trace_id).await {
                                Ok(_) => {
                                    info!("Trace {} disabled successfully", trace_id);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDisabled { trace_id });
                                }
                                Err(e) => {
                                    error!("Failed to disable trace {}: {}", trace_id, e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDisableFailed {
                                        trace_id,
                                        error: e.to_string()
                                    });
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDisableFailed {
                                trace_id,
                                error: "No debug session available".to_string()
                            });
                        }
                    }
                    RuntimeCommand::EnableTrace(trace_id) => {
                        info!("Enabling trace: {}", trace_id);
                        if let Some(ref mut session) = session {
                            match session.trace_manager.enable_trace(trace_id).await {
                                Ok(_) => {
                                    info!("Trace {} enabled successfully", trace_id);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceEnabled { trace_id });
                                }
                                Err(e) => {
                                    error!("Failed to enable trace {}: {}", trace_id, e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceEnableFailed {
                                        trace_id,
                                        error: e.to_string()
                                    });
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceEnableFailed {
                                trace_id,
                                error: "No debug session available".to_string()
                            });
                        }
                    }
                    RuntimeCommand::DisableAllTraces => {
                        info!("Disabling all traces");
                        if let Some(ref mut session) = session {
                            let trace_count = session.trace_manager.active_trace_count();
                            match session.trace_manager.disable_all_traces().await {
                                Ok(_) => {
                                    info!("All {} traces disabled successfully", trace_count);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::AllTracesDisabled { count: trace_count });
                                }
                                Err(e) => {
                                    error!("Failed to disable all traces: {}", e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(format!("Failed to disable all traces: {}", e)));
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::Error("No debug session available".to_string()));
                        }
                    }
                    RuntimeCommand::EnableAllTraces => {
                        info!("Enabling all traces");
                        if let Some(ref mut session) = session {
                            let trace_count = session.trace_manager.trace_count();
                            match session.trace_manager.enable_all_traces().await {
                                Ok(_) => {
                                    info!("All {} traces enabled successfully", trace_count);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::AllTracesEnabled { count: trace_count });
                                }
                                Err(e) => {
                                    error!("Failed to enable all traces: {}", e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(format!("Failed to enable all traces: {}", e)));
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::Error("No debug session available".to_string()));
                        }
                    }
                    RuntimeCommand::DeleteTrace(trace_id) => {
                        info!("Deleting trace: {}", trace_id);
                        if let Some(ref mut session) = session {
                            match session.trace_manager.delete_trace(trace_id).await {
                                Ok(_) => {
                                    info!("Trace {} deleted successfully", trace_id);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDeleted { trace_id });
                                }
                                Err(e) => {
                                    error!("Failed to delete trace {}: {}", trace_id, e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDeleteFailed {
                                        trace_id,
                                        error: e.to_string()
                                    });
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::TraceDeleteFailed {
                                trace_id,
                                error: "No debug session available".to_string()
                            });
                        }
                    }
                    RuntimeCommand::DeleteAllTraces => {
                        info!("Deleting all traces");
                        if let Some(ref mut session) = session {
                            match session.trace_manager.delete_all_traces().await {
                                Ok(count) => {
                                    info!("All {} traces deleted successfully", count);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::AllTracesDeleted { count });
                                }
                                Err(e) => {
                                    error!("Failed to delete all traces: {}", e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(format!("Failed to delete all traces: {}", e)));
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::Error("No debug session available".to_string()));
                        }
                    }
                    RuntimeCommand::InfoTarget { target } => {
                        info!("Info target request for: {}", target);
                        handle_info_target_request(&mut session, &target, &runtime_channels.status_sender).await;
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
    session: &mut Option<GhostSession>,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) {
    use ghostscope_ui::{events::SourceCodeInfo, RuntimeStatus};

    let result = try_load_source_code(session).await;

    match result {
        Ok(source_info) => {
            info!(
                "Successfully loaded source code from: {}",
                source_info.file_path
            );
            let _ = status_sender.send(RuntimeStatus::SourceCodeLoaded(source_info));
        }
        Err(error_msg) => {
            info!("Source code loading failed: {}", error_msg);
            let _ = status_sender.send(RuntimeStatus::SourceCodeLoadFailed(error_msg));
        }
    }
}

/// Try to load source code, returning detailed error information
async fn try_load_source_code(
    session: &mut Option<GhostSession>,
) -> Result<ghostscope_ui::events::SourceCodeInfo, String> {
    use ghostscope_ui::events::SourceCodeInfo;

    let session = session
        .as_mut()
        .ok_or_else(|| "No active session available".to_string())?;

    let binary_analyzer = session
        .binary_analyzer
        .as_mut()
        .ok_or_else(|| "Binary analyzer not available. Try reloading the binary.".to_string())?;

    let main_symbol = binary_analyzer.find_symbol("main").ok_or_else(|| {
        "Main function not found in binary. Ensure the binary has debug symbols.".to_string()
    })?;

    info!("Found main symbol at address: 0x{:x}", main_symbol.address);

    let source_location = binary_analyzer
        .get_source_location(main_symbol.address)
        .ok_or_else(|| {
            "No source location found for main function. Compile with -g flag.".to_string()
        })?;

    info!(
        "Found source location: {}:{}",
        source_location.file_path, source_location.line_number
    );

    // Return source location info, let UI handle file reading
    Ok(SourceCodeInfo {
        file_path: source_location.file_path,
        current_line: Some(source_location.line_number as usize),
    })
}

/// Handle info target request from TUI
async fn handle_info_target_request(
    session: &mut Option<GhostSession>,
    target: &str,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) {
    use ghostscope_ui::{
        events::{TargetDebugInfo, TargetType, VariableDebugInfo},
        RuntimeStatus,
    };

    let result = try_get_target_debug_info(session, target).await;

    match result {
        Ok(debug_info) => {
            info!("Successfully retrieved debug info for target: {}", target);
            let _ = status_sender.send(RuntimeStatus::InfoTargetResult {
                target: target.to_string(),
                info: debug_info,
            });
        }
        Err(error_msg) => {
            info!(
                "Failed to get debug info for target {}: {}",
                target, error_msg
            );
            let _ = status_sender.send(RuntimeStatus::InfoTargetFailed {
                target: target.to_string(),
                error: error_msg,
            });
        }
    }
}

/// Try to get debug info for a target (function name or file:line)
async fn try_get_target_debug_info(
    session: &mut Option<GhostSession>,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    let session = session
        .as_mut()
        .ok_or_else(|| "No active session available".to_string())?;

    let binary_analyzer = session
        .binary_analyzer
        .as_mut()
        .ok_or_else(|| "Binary analyzer not available. Try reloading the binary.".to_string())?;

    // Parse the target to determine if it's a function name or file:line
    if target.contains(':') {
        // Parse as file:line
        handle_source_location_target(binary_analyzer, target).await
    } else {
        // Parse as function name
        handle_function_target(binary_analyzer, target).await
    }
}

/// Handle function name target
async fn handle_function_target(
    binary_analyzer: &mut ghostscope_binary::BinaryAnalyzer,
    function_name: &str,
) -> Result<TargetDebugInfo, String> {
    use ghostscope_ui::events::*;

    let symbol = binary_analyzer
        .find_symbol(function_name)
        .ok_or_else(|| format!("Function '{}' not found in binary symbols", function_name))?;

    let symbol_address = symbol.address;
    info!(
        "Found function '{}' at address: 0x{:x}",
        function_name, symbol_address
    );

    // Get enhanced variables at the function entry point using NewScopedVariableSystem
    let enhanced_vars = if let Some(dwarf_context) = binary_analyzer.dwarf_context_mut() {
        info!("Using scoped variable system for function analysis");
        dwarf_context.get_enhanced_variable_locations(symbol_address)
    } else {
        Vec::new()
    };

    // Separate parameters and variables
    let mut parameters = Vec::new();
    let mut variables = Vec::new();

    for enhanced_var in enhanced_vars {
        let var_info = VariableDebugInfo {
            name: enhanced_var.variable.name.clone(),
            type_name: enhanced_var.variable.type_name.clone(),
            location_description: format!("{:?}", enhanced_var.variable.location_expr),
            size: enhanced_var.size,
            scope_start: enhanced_var.variable.scope_ranges.first().map(|r| r.start),
            scope_end: enhanced_var.variable.scope_ranges.first().map(|r| r.end),
        };

        // Use the is_parameter field from DWARF parsing (which is based on DW_TAG_formal_parameter)
        let is_parameter = enhanced_var.variable.is_parameter;

        info!(
            "Variable '{}' location: {:?}, is_parameter: {} (from DWARF)",
            enhanced_var.variable.name, enhanced_var.variable.location_expr, is_parameter
        );

        if is_parameter {
            parameters.push(var_info);
        } else {
            variables.push(var_info);
        }
    }

    // Try to get source location for the function
    let source_location = binary_analyzer.get_source_location(symbol_address);

    Ok(TargetDebugInfo {
        target: function_name.to_string(),
        target_type: TargetType::Function,
        file_path: source_location.as_ref().map(|sl| sl.file_path.clone()),
        line_number: source_location.as_ref().map(|sl| sl.line_number),
        function_name: Some(function_name.to_string()),
        variables,
        parameters,
        address: Some(symbol_address),
    })
}

/// Handle source location target (file:line)
async fn handle_source_location_target(
    binary_analyzer: &mut ghostscope_binary::BinaryAnalyzer,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    use ghostscope_ui::events::*;

    // Parse file:line format
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid target format '{}'. Expected format: file:line",
            target
        ));
    }

    let file_path = parts[0];
    let line_number = parts[1]
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{}' in target '{}'", parts[1], target))?;

    // Resolve source line to address
    let address = binary_analyzer
        .resolve_source_line_address(file_path, line_number)
        .ok_or_else(|| format!("Cannot resolve address for {}:{}", file_path, line_number))?;

    info!(
        "Resolved {}:{} to address: 0x{:x}",
        file_path, line_number, address
    );

    // Get enhanced variables at this location using NewScopedVariableSystem
    let enhanced_vars = if let Some(dwarf_context) = binary_analyzer.dwarf_context_mut() {
        info!("Using scoped variable system for source location analysis");
        dwarf_context.get_enhanced_variable_locations(address)
    } else {
        Vec::new()
    };

    // Separate parameters and variables
    let mut parameters = Vec::new();
    let mut variables = Vec::new();

    for enhanced_var in enhanced_vars {
        let var_info = VariableDebugInfo {
            name: enhanced_var.variable.name.clone(),
            type_name: enhanced_var.variable.type_name.clone(),
            location_description: format!("{:?}", enhanced_var.variable.location_expr),
            size: enhanced_var.size,
            scope_start: enhanced_var.variable.scope_ranges.first().map(|r| r.start),
            scope_end: enhanced_var.variable.scope_ranges.first().map(|r| r.end),
        };

        // Use the is_parameter field from DWARF parsing (which is based on DW_TAG_formal_parameter)
        let is_parameter = enhanced_var.variable.is_parameter;

        info!(
            "Variable '{}' location: {:?}, is_parameter: {} (from DWARF)",
            enhanced_var.variable.name, enhanced_var.variable.location_expr, is_parameter
        );

        if is_parameter {
            parameters.push(var_info);
        } else {
            variables.push(var_info);
        }
    }

    // Try to find containing function
    let function_symbol = binary_analyzer.symbol_table.find_containing_symbol(address);
    let function_name = function_symbol.map(|s| s.name.clone());

    // Get the actual source location from the address to get the complete file path
    let actual_source_location = binary_analyzer.get_source_location(address);
    let complete_file_path = actual_source_location
        .as_ref()
        .map(|sl| sl.file_path.clone())
        .unwrap_or_else(|| file_path.to_string()); // fallback to user input if no location found

    Ok(TargetDebugInfo {
        target: target.to_string(),
        target_type: TargetType::SourceLocation,
        file_path: Some(complete_file_path),
        line_number: Some(line_number),
        function_name,
        variables,
        parameters,
        address: Some(address),
    })
}

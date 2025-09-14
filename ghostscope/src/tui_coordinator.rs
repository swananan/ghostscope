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
                    RuntimeCommand::ExecuteScript { command: script } => {
                        info!("Executing script: {}", script);

                        if let Some(ref mut session) = session {
                            // Use the new TUI-specific compilation and loading with detailed results
                            match crate::script_compiler::compile_and_load_script_for_tui(
                                &script,
                                session,
                            ).await {
                                Ok(details) => {
                                    info!("Script compiled with detailed results: {:?} trace_ids generated, {:?} successful",
                                          details.trace_ids.len(), details.success_count);

                                    // Types are now unified, no conversion needed
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationCompleted {
                                        details,
                                    });
                                }
                                Err(e) => {
                                    let target = crate::script_compiler::extract_target_from_script(&script);
                                    error!("Script compilation failed for target {}: {}", target, e);
                                    let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                                        error: e.to_string(),
                                        target,
                                    });
                                }
                            }
                        } else {
                            let target = crate::script_compiler::extract_target_from_script(&script);
                            warn!("No debug session available for script compilation");
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                                error: "No debug session available".to_string(),
                                target,
                            });
                        }
                    }
                    RuntimeCommand::InfoTrace { trace_id } => {
                        if let Some(ref session) = session {
                            let ids: Vec<u32> = match trace_id {
                                Some(id) => vec![id],
                                None => session.trace_manager.get_all_trace_ids(),
                            };
                            for id in ids {
                                if let Some(snap) = session.trace_manager.get_trace_snapshot(id) {
                                    let status = if snap.is_enabled {
                                        ghostscope_ui::events::TraceStatus::Active
                                    } else {
                                        ghostscope_ui::events::TraceStatus::Disabled
                                    };
                                    // Build a cleaner script preview: prefer first non-empty line inside braces
                                    let script_preview = {
                                        let raw = snap.script_content.as_str();
                                        let inner = if let (Some(open), Some(close)) = (raw.find('{'), raw.rfind('}')) {
                                            if close > open { Some(&raw[open+1..close]) } else { None }
                                        } else { None };
                                        let candidate = inner.unwrap_or(raw);
                                        let first_line = candidate
                                            .lines()
                                            .map(|l| l.trim())
                                            .filter(|l| !l.is_empty())
                                            .find(|_| true)
                                            .or_else(|| raw.lines().skip(1).map(|l| l.trim()).find(|l| !l.is_empty()));
                                        first_line.map(|l| {
                                            let mut s = l.to_string();
                                            if s.len() > 120 { s.truncate(120); }
                                            s
                                        })
                                    };
                                    let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::TraceInfo {
                                        trace_id: snap.trace_id,
                                        target: snap.target_display,
                                        status,
                                        pid: snap.target_pid,
                                        binary: snap.binary_path,
                                        script_preview,
                                        pc: snap.pc,
                                    });
                                } else {
                                    warn!("InfoTrace requested for non-existent trace {}", id);
                                    // Send error status to UI for specific trace ID requests
                                    if let Some(specific_id) = trace_id {
                                        let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::TraceInfoFailed {
                                            trace_id: specific_id,
                                            error: format!("Trace {} not found", specific_id),
                                        });
                                    }
                                }
                            }
                        } else {
                            warn!("InfoTrace requested but no session available");
                            // Send error status to UI for specific trace ID requests
                            if let Some(specific_id) = trace_id {
                                let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::TraceInfoFailed {
                                    trace_id: specific_id,
                                    error: "No debug session available".to_string(),
                                });
                            }
                        }
                    }
                    RuntimeCommand::InfoTraceAll => {
                        if let Some(ref session) = session {
                            let summary_info = session.trace_manager.get_summary();
                            let trace_details = session.trace_manager.get_all_formatted_traces();

                            let summary = ghostscope_ui::events::TraceSummaryInfo {
                                total: summary_info.total,
                                active: summary_info.active,
                                disabled: summary_info.disabled,
                            };

                            let traces = trace_details
                                .into_iter()
                                .map(|t| ghostscope_ui::events::TraceDetailInfo {
                                    trace_id: t.trace_id,
                                    target_display: t.target_display,
                                    status: t.status,
                                    duration: t.duration,
                                })
                                .collect();

                            let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::TraceInfoAll {
                                summary,
                                traces,
                            });
                        } else {
                            let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::TraceInfoAll {
                                summary: ghostscope_ui::events::TraceSummaryInfo {
                                    total: 0,
                                    active: 0,
                                    disabled: 0,
                                },
                                traces: vec![],
                            });
                        }
                    }
                    RuntimeCommand::InfoSource => {
                        if let Some(ref session) = session {
                            // Get source files from DWARF context
                            match get_source_files_info(session) {
                                Ok(files) => {
                                    let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::FileInfo {
                                        files,
                                    });
                                }
                                Err(error) => {
                                    let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::FileInfoFailed {
                                        error: error.to_string(),
                                    });
                                }
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(ghostscope_ui::events::RuntimeStatus::FileInfoFailed {
                                error: "No debug session available".to_string(),
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
                            match session.trace_manager.disable_trace(trace_id) {
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
                            match session.trace_manager.enable_trace(trace_id) {
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
                            match session.trace_manager.disable_all_traces() {
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
                            match session.trace_manager.enable_all_traces() {
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
                            match session.trace_manager.delete_trace(trace_id) {
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
                            match session.trace_manager.delete_all_traces() {
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

    // Use DWARF information first, then fall back to symbol table
    let addresses = binary_analyzer.get_all_function_addresses(function_name);

    if addresses.is_empty() {
        return Err(format!(
            "Function '{}' not found in DWARF info or symbols",
            function_name
        ));
    }

    info!(
        "Found function '{}' at {} address(es): [{}]",
        function_name,
        addresses.len(),
        addresses
            .iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Analyze variables for each address separately
    let mut address_mappings = Vec::new();

    for address in &addresses {
        info!(
            "Analyzing variables at address 0x{:x} for function '{}'",
            address, function_name
        );

        // Get enhanced variables at this address using ScopedVariableSystem
        let mut enhanced_vars = if let Some(dwarf_context) = binary_analyzer.dwarf_context_mut() {
            info!(
                "Using scoped variable system for function analysis at 0x{:x}",
                address
            );
            let mut vars = dwarf_context.get_enhanced_variable_locations(*address);

            // Compute new evaluation results for variables that don't have them
            for var in vars.iter_mut() {
                if var.evaluation_result.is_none() {
                    let context = ghostscope_binary::expression::EvaluationContext {
                        pc_address: *address,
                        address_size: 8,
                    };

                    match dwarf_context
                        .get_expression_evaluator()
                        .ok_or_else(|| "Expression evaluator not available".to_string())?
                        .evaluate_location_with_enhanced_types(
                            &var.location_at_address,
                            *address,
                            &context,
                            None, // Pass None to avoid borrowing conflicts
                        ) {
                        Ok(new_result) => {
                            info!(
                                "Computed new evaluation result for '{}': {:?}",
                                var.variable.name, new_result
                            );
                            var.evaluation_result = Some(new_result);
                        }
                        Err(e) => {
                            info!(
                                "Failed to compute new evaluation result for '{}': {}",
                                var.variable.name, e
                            );
                        }
                    }
                }
            }
            vars
        } else {
            Vec::new()
        };

        // Separate parameters and variables for this address
        let mut parameters = Vec::new();
        let mut variables = Vec::new();

        for enhanced_var in enhanced_vars {
            // NEW: Use the enhanced type-safe evaluation result first, then fall back to legacy result
            let location_description =
                if let Some(evaluation_result) = &enhanced_var.evaluation_result {
                    format!("{:?}", evaluation_result)
                } else {
                    format!("{:?} (raw)", enhanced_var.variable.location_expr)
                };

            let var_info = VariableDebugInfo {
                name: enhanced_var.variable.name.clone(),
                type_name: enhanced_var.variable.type_name.clone(),
                location_description,
                size: enhanced_var.size,
                scope_start: enhanced_var.variable.scope_ranges.first().map(|r| r.start),
                scope_end: enhanced_var.variable.scope_ranges.first().map(|r| r.end),
            };

            // Use the is_parameter field from DWARF parsing (which is based on DW_TAG_formal_parameter)
            let is_parameter = enhanced_var.variable.is_parameter;

            // Log using enhanced evaluation result if available
            let log_location = if let Some(evaluation_result) = &enhanced_var.evaluation_result {
                format!("{:?}", evaluation_result)
            } else {
                format!("{:?} (raw)", enhanced_var.variable.location_expr)
            };

            info!(
                "Address 0x{:x}: Variable '{}' location: {}, is_parameter: {} (from DWARF)",
                *address, enhanced_var.variable.name, log_location, is_parameter
            );

            if is_parameter {
                parameters.push(var_info);
            } else {
                variables.push(var_info);
            }
        }

        address_mappings.push(AddressMapping {
            address: *address,
            function_name: Some(function_name.to_string()),
            variables,
            parameters,
        });
    }

    // Try to get source location for the main function address
    let first_address = addresses[0];
    let source_location = binary_analyzer.get_source_location(first_address);

    Ok(TargetDebugInfo {
        target: function_name.to_string(),
        target_type: TargetType::Function,
        file_path: source_location.as_ref().map(|sl| sl.file_path.clone()),
        line_number: source_location.as_ref().map(|sl| sl.line_number),
        function_name: Some(function_name.to_string()),
        address_mappings,
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

    // Resolve source line to all addresses
    let addresses = binary_analyzer.get_all_source_line_addresses(file_path, line_number);

    if addresses.is_empty() {
        return Err(format!(
            "Cannot resolve any address for {}:{}",
            file_path, line_number
        ));
    }

    info!(
        "Resolved {}:{} to {} address(es): [{}]",
        file_path,
        line_number,
        addresses.len(),
        addresses
            .iter()
            .map(|a| format!("0x{:x}", a))
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Analyze variables for each address separately
    let mut address_mappings = Vec::new();

    for address in &addresses {
        info!("Analyzing variables at address 0x{:x}", address);

        let mut enhanced_vars = if let Some(dwarf_context) = binary_analyzer.dwarf_context_mut() {
            let mut vars = dwarf_context.get_enhanced_variable_locations(*address);

            // Compute new evaluation results for variables that don't have them
            for var in vars.iter_mut() {
                if var.evaluation_result.is_none() {
                    let context = ghostscope_binary::expression::EvaluationContext {
                        pc_address: *address,
                        address_size: 8,
                    };

                    match dwarf_context
                        .get_expression_evaluator()
                        .ok_or_else(|| "Expression evaluator not available".to_string())?
                        .evaluate_location_with_enhanced_types(
                            &var.location_at_address,
                            *address,
                            &context,
                            None, // Pass None to avoid borrowing conflicts
                        ) {
                        Ok(new_result) => {
                            info!(
                                "Computed new evaluation result for '{}': {:?}",
                                var.variable.name, new_result
                            );
                            var.evaluation_result = Some(new_result);
                        }
                        Err(e) => {
                            info!(
                                "Failed to compute new evaluation result for '{}': {}",
                                var.variable.name, e
                            );
                        }
                    }
                }
            }
            vars
        } else {
            Vec::new()
        };

        // Separate parameters and variables for this address
        let mut parameters = Vec::new();
        let mut variables = Vec::new();

        for enhanced_var in enhanced_vars {
            // NEW: Use the enhanced type-safe evaluation result first, then fall back to legacy result
            let location_description =
                if let Some(evaluation_result) = &enhanced_var.evaluation_result {
                    format!("{:?}", evaluation_result)
                } else {
                    format!("{:?} (raw)", enhanced_var.variable.location_expr)
                };

            let var_info = VariableDebugInfo {
                name: enhanced_var.variable.name.clone(),
                type_name: enhanced_var.variable.type_name.clone(),
                location_description,
                size: enhanced_var.size,
                scope_start: enhanced_var.variable.scope_ranges.first().map(|r| r.start),
                scope_end: enhanced_var.variable.scope_ranges.first().map(|r| r.end),
            };

            let is_parameter = enhanced_var.variable.is_parameter;

            // Log using enhanced evaluation result if available
            let log_location = if let Some(evaluation_result) = &enhanced_var.evaluation_result {
                format!("{:?}", evaluation_result)
            } else {
                format!("{:?} (raw)", enhanced_var.variable.location_expr)
            };

            info!(
                "Address 0x{:x}: Variable '{}' location: {}, is_parameter: {} (from DWARF)",
                *address, enhanced_var.variable.name, log_location, is_parameter
            );

            if is_parameter {
                parameters.push(var_info);
            } else {
                variables.push(var_info);
            }
        }

        // Find containing function for this address
        let function_symbol = binary_analyzer
            .symbol_table
            .find_containing_symbol(*address);
        let function_name = function_symbol.map(|s| s.name.clone());

        address_mappings.push(AddressMapping {
            address: *address,
            function_name,
            variables,
            parameters,
        });
    }

    // Get the actual source location from the first address to get the complete file path
    let first_address = address_mappings[0].address;
    let actual_source_location = binary_analyzer.get_source_location(first_address);
    let complete_file_path = actual_source_location
        .as_ref()
        .map(|sl| sl.file_path.clone())
        .unwrap_or_else(|| file_path.to_string()); // fallback to user input if no location found

    // Try to get overall function name (from first mapping or fallback)
    let overall_function_name = address_mappings
        .first()
        .and_then(|m| m.function_name.clone());

    Ok(TargetDebugInfo {
        target: target.to_string(),
        target_type: TargetType::SourceLocation,
        file_path: Some(complete_file_path),
        line_number: Some(line_number),
        function_name: overall_function_name,
        address_mappings,
    })
}

/// Get source files information from DWARF context
fn get_source_files_info(
    session: &GhostSession,
) -> anyhow::Result<Vec<ghostscope_ui::events::SourceFileInfo>> {
    use std::collections::HashSet;

    let mut files = Vec::new();
    let mut seen_files = HashSet::new();

    // Get files from binary analyzer
    if let Some(ref binary_analyzer) = session.binary_analyzer {
        if let Some(dwarf_context) = binary_analyzer.dwarf_context() {
            // Get all file information from DWARF context
            let file_info_vec = dwarf_context.get_all_file_info()?;

            for file_info in file_info_vec {
                let key = format!("{}:{}", file_info.directory, file_info.basename);
                if seen_files.contains(&key) {
                    continue;
                }
                seen_files.insert(key);

                files.push(ghostscope_ui::events::SourceFileInfo {
                    path: file_info.basename,
                    directory: file_info.directory,
                });
            }
        }
    }

    // Sort files by path for consistent display
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(files)
}

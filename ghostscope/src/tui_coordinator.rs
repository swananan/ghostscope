use crate::args::ParsedArgs;
use crate::session::GhostSession;
use anyhow::Result;
use futures::future;
use ghostscope_protocol::{EventData, MessageType};
use ghostscope_ui::{run_tui_mode, EventRegistry};
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
    use ghostscope_protocol::MessageType;
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
                            // Use the new trace-aware compilation and loading
                            match crate::script_compiler::compile_and_load_script_with_trace_id(
                                &script,
                                trace_id,
                                session,
                                &runtime_channels.status_sender
                            ).await {
                                Ok(_) => {
                                    info!("Script with trace_id {} compiled and loaded successfully", trace_id);
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
                        handle_source_code_request(&session, &runtime_channels.status_sender).await;
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
    session: &Option<GhostSession>,
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

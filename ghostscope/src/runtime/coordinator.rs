use crate::config::{MergedConfig, ParsedArgs};
use crate::core::GhostSession;
use crate::runtime::{dwarf_loader, info_handlers, source_handlers, trace_handlers};
use anyhow::Result;
use ghostscope_ui::{EventRegistry, RuntimeChannels, RuntimeCommand, RuntimeStatus};
use tracing::{error, info};

/// Run GhostScope in TUI mode with merged configuration
pub async fn run_tui_coordinator_with_config(config: MergedConfig) -> Result<()> {
    info!("Starting GhostScope in TUI mode with merged configuration");

    // Pass the UI configuration to the TUI system
    let ui_config = config.get_ui_config();

    // Clone config for session creation before converting to ParsedArgs
    let config_for_session = config.clone();

    // Convert MergedConfig back to ParsedArgs for existing code compatibility
    // TODO: Refactor to use MergedConfig directly throughout the TUI system
    let parsed_args = ParsedArgs {
        binary_path: config.binary_path,
        target_path: config.target_path,
        binary_args: config.binary_args,
        log_file: Some(config.log_file),
        enable_logging: config.enable_logging,
        enable_console_logging: config.enable_console_logging,
        log_level: config.log_level,
        config: None, // Not needed for runtime conversion
        debug_file: config.debug_file,
        script: config.script,
        script_file: config.script_file,
        pid: config.pid,
        tui_mode: config.tui_mode,
        should_save_llvm_ir: config.should_save_llvm_ir,
        should_save_ebpf: config.should_save_ebpf,
        should_save_ast: config.should_save_ast,
        layout_mode: config.layout_mode,
        has_explicit_log_flag: false, // Not relevant for TUI conversion
        has_explicit_console_log_flag: false, // Not relevant for TUI conversion
        force_perf_event_array: config.ebpf_config.force_perf_event_array,
    };

    run_tui_coordinator_with_ui_config_and_merged_config(parsed_args, ui_config, config_for_session)
        .await
}

/// Run GhostScope in TUI mode with tokio task coordination (without merged config)
#[allow(dead_code)]
pub async fn run_tui_coordinator(parsed_args: ParsedArgs) -> Result<()> {
    // Use default UI configuration when no merged config is available
    let ui_config = ghostscope_ui::UiConfig {
        layout_mode: match parsed_args.layout_mode {
            crate::config::LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
            crate::config::LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
        },
        default_focus: ghostscope_ui::PanelType::InteractiveCommand, // Default
        panel_ratios: [4, 3, 3],                                     // Default
        history: ghostscope_ui::HistoryConfig::default(),
        ebpf_max_messages: 2000, // Default
    };

    // Create a default MergedConfig from ParsedArgs for compatibility
    let default_config = MergedConfig::new(
        parsed_args.clone(),
        crate::config::settings::Config::default(),
    );

    run_tui_coordinator_with_ui_config_and_merged_config(parsed_args, ui_config, default_config)
        .await
}

/// Internal function to run TUI coordinator with UI configuration
async fn run_tui_coordinator_with_ui_config_and_merged_config(
    parsed_args: ParsedArgs,
    ui_config: ghostscope_ui::UiConfig,
    merged_config: MergedConfig,
) -> Result<()> {
    info!("Starting GhostScope in TUI mode");

    // Create event communication channels
    let (event_registry, runtime_channels) = EventRegistry::new();

    // Initialize DWARF information processing in background
    let dwarf_task = {
        let status_sender = runtime_channels.create_status_sender();
        let config_clone = merged_config.clone();
        tokio::spawn(async move {
            // Pass MergedConfig directly to ensure search_paths are available during DWARF loading
            let session =
                dwarf_loader::initialize_dwarf_processing(&config_clone, status_sender).await?;
            Ok::<_, anyhow::Error>(session)
        })
    };

    // Create compile options from command line arguments
    let compile_options = ghostscope_compiler::CompileOptions {
        save_llvm_ir: parsed_args.should_save_llvm_ir,
        save_ast: parsed_args.should_save_ast,
        save_ebpf: parsed_args.should_save_ebpf,
        binary_path_hint: None, // Will be set later when we know the binary
        ringbuf_size: 262144,   // Default, will be overridden by config
        proc_module_offsets_max_entries: 4096, // Default, will be overridden by config
        perf_page_count: 64,    // Default, will be overridden by config
        event_map_type: ghostscope_compiler::EventMapType::RingBuf, // Will be overridden by config
        mem_dump_cap: 1024,
        max_trace_event_size: 32768,
    };

    // Start the runtime coordination task with session from DWARF processing
    let runtime_task = tokio::spawn(async move {
        // Wait for DWARF processing to complete and get the session
        match dwarf_task.await {
            Ok(Ok(session)) => {
                run_runtime_coordinator(runtime_channels, Some(session), compile_options).await
            }
            Ok(Err(e)) => {
                error!("DWARF processing failed: {}", e);
                run_runtime_coordinator(runtime_channels, None, compile_options).await
            }
            Err(e) => {
                error!("DWARF task panicked: {}", e);
                run_runtime_coordinator(runtime_channels, None, compile_options).await
            }
        }
    });

    // Run TUI mode and runtime coordination concurrently
    let tui_result = ghostscope_ui::run_tui_mode_with_config(event_registry, ui_config).await;
    let runtime_result = runtime_task.await.unwrap_or_else(|e| {
        error!("Runtime task failed: {}", e);
        Err(anyhow::anyhow!("Runtime task panicked"))
    });

    // Return the first error encountered, or Ok if both succeeded
    tui_result.and(runtime_result)
}

/// Main runtime coordinator that handles commands and manages eBPF sessions
async fn run_runtime_coordinator(
    mut runtime_channels: RuntimeChannels,
    mut session: Option<GhostSession>,
    compile_options: ghostscope_compiler::CompileOptions,
) -> Result<()> {
    info!("Runtime coordinator started");

    // Create trace sender for event polling task
    let trace_sender = runtime_channels.create_trace_sender();

    loop {
        tokio::select! {
            // Wait for events asynchronously from active traces' loaders
            result = async {
                if let Some(ref mut session) = session {
                    // Use trace_manager's built-in event polling method
                    session.trace_manager.wait_for_all_events_async().await
                } else {
                    // No session, return empty events and let the outer loop continue
                    Ok(Vec::new())
                }
            }, if session.is_some() => {
                match result {
                    Ok(events) => {
                        if let Some(ref _session) = session {
                            for event_data in events {
                                let _ = trace_sender.send(event_data);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Fatal error receiving trace events: {}", e);
                        break;
                    }
                }
            }

            // Handle runtime commands
            Some(command) = runtime_channels.command_receiver.recv() => {
                match command {
                    RuntimeCommand::ExecuteScript { command: script } => {
                        handle_execute_script(&mut session, &mut runtime_channels, script, &compile_options).await;
                    }
                    RuntimeCommand::InfoTrace { trace_id } => {
                        match trace_id {
                            Some(id) => {
                                info_handlers::handle_info_trace(&session, &mut runtime_channels, id).await;
                            }
                            None => {
                                info_handlers::handle_info_trace_all(&session, &mut runtime_channels).await;
                            }
                        }
                    }
                    RuntimeCommand::InfoTraceAll => {
                        info_handlers::handle_info_trace_all(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::InfoSource => {
                        info_handlers::handle_info_source(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::InfoShare => {
                        info_handlers::handle_info_share(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::InfoFile => {
                        info_handlers::handle_info_file(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::RequestSourceCode => {
                        source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::DisableTrace(trace_id) => {
                        trace_handlers::handle_disable_trace(&mut session, &mut runtime_channels, trace_id).await;
                    }
                    RuntimeCommand::EnableTrace(trace_id) => {
                        trace_handlers::handle_enable_trace(&mut session, &mut runtime_channels, trace_id).await;
                    }
                    RuntimeCommand::DisableAllTraces => {
                        trace_handlers::handle_disable_all_traces(&mut session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::EnableAllTraces => {
                        trace_handlers::handle_enable_all_traces(&mut session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::DeleteTrace(trace_id) => {
                        trace_handlers::handle_delete_trace(&mut session, &mut runtime_channels, trace_id).await;
                    }
                    RuntimeCommand::DeleteAllTraces => {
                        trace_handlers::handle_delete_all_traces(&mut session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::InfoFunction { target } => {
                        info_handlers::handle_info_function(&mut session, &mut runtime_channels, target).await;
                    }
                    RuntimeCommand::InfoLine { target } => {
                        info_handlers::handle_info_line(&mut session, &mut runtime_channels, target).await;
                    }
                    RuntimeCommand::InfoAddress { target } => {
                        info_handlers::handle_info_address(&mut session, &mut runtime_channels, target).await;
                    }
                    RuntimeCommand::SaveTraces { filename, filter } => {
                        if let Some(ref session) = session {
                            handle_save_traces(session, &mut runtime_channels, filename, filter).await;
                        } else {
                            let _ = runtime_channels
                                .status_sender
                                .send(RuntimeStatus::TracesSaveFailed {
                                    error: "No debug session available".to_string(),
                                });
                        }
                    }
                    RuntimeCommand::LoadTraces { filename, traces } => {
                        handle_load_traces(&mut session, &mut runtime_channels, filename, traces).await;
                    }
                    RuntimeCommand::SrcPathList => {
                        if let Some(ref session) = session {
                            let info = session.source_path_resolver.get_all_rules();
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathInfo { info });
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                        }
                    }
                    RuntimeCommand::SrcPathAddDir { dir } => {
                        if let Some(ref mut sess) = session {
                            sess.source_path_resolver.add_search_dir(dir.clone());
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathUpdated {
                                message: format!("Added search directory: {}", dir),
                            });
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                            continue;
                        }
                        // Auto-reload source code and file list (outside the if-let to avoid borrow issues)
                        info!("Reloading source code and file list after srcpath change");
                        source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                        source_handlers::handle_request_source_code(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::SrcPathAddMap { from, to } => {
                        if let Some(ref mut sess) = session {
                            sess.source_path_resolver.add_substitution(from.clone(), to.clone());
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathUpdated {
                                message: format!("Added path mapping: {} -> {}", from, to),
                            });
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                            continue;
                        }
                        // Auto-reload source code and file list (outside the if-let to avoid borrow issues)
                        info!("Reloading source code and file list after srcpath change");
                        source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                        source_handlers::handle_request_source_code(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::SrcPathRemove { pattern } => {
                        let should_reload = if let Some(ref mut sess) = session {
                            if sess.source_path_resolver.remove(&pattern) {
                                let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathUpdated {
                                    message: format!("Removed path rule: {}", pattern),
                                });
                                true
                            } else {
                                let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                    error: format!("No matching path rule found: {}", pattern),
                                });
                                false
                            }
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                            false
                        };
                        if should_reload {
                            // Auto-reload source code and file list (outside the if-let to avoid borrow issues)
                            info!("Reloading source code and file list after srcpath change");
                            source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                            source_handlers::handle_request_source_code(&session, &mut runtime_channels).await;
                        }
                    }
                    RuntimeCommand::SrcPathClear => {
                        if let Some(ref mut sess) = session {
                            sess.source_path_resolver.clear_runtime();
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathUpdated {
                                message: "Cleared all runtime path rules".to_string(),
                            });
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                            continue;
                        }
                        // Auto-reload source code and file list (outside the if-let to avoid borrow issues)
                        info!("Reloading source code and file list after srcpath clear");
                        source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                        source_handlers::handle_request_source_code(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::SrcPathReset => {
                        if let Some(ref mut sess) = session {
                            sess.source_path_resolver.reset();
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathUpdated {
                                message: "Reset to config file path rules".to_string(),
                            });
                        } else {
                            let _ = runtime_channels.status_sender.send(RuntimeStatus::SrcPathFailed {
                                error: "No debug session available".to_string(),
                            });
                            continue;
                        }
                        // Auto-reload source code and file list (outside the if-let to avoid borrow issues)
                        info!("Reloading source code and file list after srcpath reset");
                        source_handlers::handle_main_source_request(&mut session, &mut runtime_channels).await;
                        source_handlers::handle_request_source_code(&session, &mut runtime_channels).await;
                    }
                    RuntimeCommand::Shutdown => {
                        info!("Shutdown requested");
                        break;
                    }
                }
            }
        }
    }

    info!("Runtime coordinator shutting down");
    Ok(())
}

/// Handle script execution command
async fn handle_execute_script(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    script: String,
    compile_options: &ghostscope_compiler::CompileOptions,
) {
    info!("Executing script: {}", script);

    if let Some(ref mut session) = session {
        let details =
            match crate::script::compile_and_load_script_for_tui(&script, session, compile_options)
                .await
            {
                Ok(details) => {
                    info!(
                        "✓ Script compilation completed: {} total, {} success, {} failed",
                        details.total_count, details.success_count, details.failed_count
                    );
                    details
                }
                Err(e) => {
                    error!("❌ Script compilation failed: {}", e);
                    // Return details with all failures
                    ghostscope_ui::events::ScriptCompilationDetails {
                        trace_ids: vec![],
                        results: vec![ghostscope_ui::events::ScriptExecutionResult {
                            pc_address: 0,
                            target_name: script.clone(),
                            binary_path: String::new(),
                            status: ghostscope_ui::events::ExecutionStatus::Failed(e.to_string()),
                        }],
                        total_count: 1,
                        success_count: 0,
                        failed_count: 1,
                    }
                }
            };

        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::ScriptCompilationCompleted { details });
    } else {
        // No session available - return details with failure
        let details = ghostscope_ui::events::ScriptCompilationDetails {
            trace_ids: vec![],
            results: vec![ghostscope_ui::events::ScriptExecutionResult {
                pc_address: 0,
                target_name: script.clone(),
                binary_path: String::new(),
                status: ghostscope_ui::events::ExecutionStatus::Failed(
                    "No debug session available".to_string(),
                ),
            }],
            total_count: 1,
            success_count: 0,
            failed_count: 1,
        };

        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::ScriptCompilationCompleted { details });
    }
}

/// Handle save traces command
async fn handle_save_traces(
    session: &GhostSession,
    runtime_channels: &mut RuntimeChannels,
    filename: Option<String>,
    filter: ghostscope_ui::components::command_panel::trace_persistence::SaveFilter,
) {
    use ghostscope_ui::components::command_panel::trace_persistence::{
        TraceConfig, TracePersistence,
    };
    use ghostscope_ui::RuntimeStatus;

    // Create TracePersistence instance
    let mut persistence = TracePersistence::new();

    // Set binary path if available
    if let Some(ref binary_path) = session.binary_path() {
        persistence.set_binary_path(binary_path.clone());
    }

    // Set PID if available
    if let Some(pid) = session.pid() {
        persistence.set_pid(pid);
    }

    // Collect trace information from session
    let traces = session.get_traces();
    for trace in &traces {
        let config = TraceConfig {
            id: trace.trace_id,
            target: trace.target_display.clone(),
            script: trace.script.clone(),
            status: if trace.enabled {
                ghostscope_ui::events::TraceStatus::Active
            } else {
                ghostscope_ui::events::TraceStatus::Disabled
            },
            binary_path: trace.binary_path.clone().unwrap_or_default(),
        };
        persistence.add_trace(config);
    }

    // Save traces to file
    match persistence.save_traces(filename.as_deref(), filter) {
        Ok(result) => {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::TracesSaved {
                    filename: result.filename.to_string_lossy().to_string(),
                    saved_count: result.saved_count,
                    total_count: result.total_count,
                });
        }
        Err(e) => {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::TracesSaveFailed {
                    error: e.to_string(),
                });
        }
    }
}

/// Handle load traces command
async fn handle_load_traces(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    filename: String,
    traces: Vec<ghostscope_ui::events::TraceDefinition>,
) {
    use ghostscope_ui::RuntimeStatus;

    if session.is_none() {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TracesLoadFailed {
                filename,
                error: "No debug session available".to_string(),
            });
        return;
    }

    // Send all trace scripts for execution
    // The UI will track individual ScriptCompilationCompleted responses
    for trace in &traces {
        // Build the trace command
        let script_command = format!("trace {} {{\n{}\n}}", trace.target, trace.script);

        // Execute the script (this sends the command but doesn't wait for result)
        let default_compile_options = ghostscope_compiler::CompileOptions::default();
        handle_execute_script(
            session,
            runtime_channels,
            script_command,
            &default_compile_options,
        )
        .await;

        // TODO: Handle disabled traces from //@disabled markers
        // Currently ignoring disabled state - would need to track trace_id from
        // ScriptCompilationCompleted response and then send disable command
    }

    // Don't send TracesLoaded here - let the UI track individual completions
    // and send the final summary when all are done
}

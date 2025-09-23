use crate::args::ParsedArgs;
use crate::core::GhostSession;
use crate::runtime::{dwarf_loader, info_handlers, source_handlers, trace_handlers};
use anyhow::Result;
use ghostscope_ui::{run_tui_mode, EventRegistry, RuntimeChannels, RuntimeCommand, RuntimeStatus};
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
        tokio::spawn(async move {
            dwarf_loader::initialize_dwarf_processing(parsed_args_clone, status_sender).await
        })
    };

    // Create save options from command line arguments
    let save_options = ghostscope_compiler::SaveOptions {
        save_llvm_ir: parsed_args.should_save_llvm_ir,
        save_ast: parsed_args.should_save_ast,
        save_ebpf: parsed_args.should_save_ebpf,
        binary_path_hint: None, // Will be set later when we know the binary
    };

    // Start the runtime coordination task with session from DWARF processing
    let runtime_task = tokio::spawn(async move {
        // Wait for DWARF processing to complete and get the session
        match dwarf_task.await {
            Ok(Ok(session)) => {
                run_runtime_coordinator(runtime_channels, Some(session), save_options).await
            }
            Ok(Err(e)) => {
                error!("DWARF processing failed: {}", e);
                run_runtime_coordinator(runtime_channels, None, save_options).await
            }
            Err(e) => {
                error!("DWARF task panicked: {}", e);
                run_runtime_coordinator(runtime_channels, None, save_options).await
            }
        }
    });

    // Start TUI with layout mode configuration
    let layout_mode = match parsed_args.layout_mode {
        crate::args::LayoutMode::Horizontal => ghostscope_ui::LayoutMode::Horizontal,
        crate::args::LayoutMode::Vertical => ghostscope_ui::LayoutMode::Vertical,
    };

    // Run TUI mode and runtime coordination concurrently
    let tui_result = run_tui_mode(event_registry, layout_mode).await;
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
    save_options: ghostscope_compiler::SaveOptions,
) -> Result<()> {
    info!("Runtime coordinator started");

    // Create trace sender for event polling task
    let trace_sender = runtime_channels.create_trace_sender();

    loop {
        tokio::select! {
            // Wait for events asynchronously from active traces' loaders
            events = async {
                if let Some(ref mut session) = session {
                    // Use trace_manager's built-in event polling method
                    session.trace_manager.wait_for_all_events_async().await
                } else {
                    // No session, return empty events and let the outer loop continue
                    Vec::new()
                }
            }, if session.is_some() => {
                if let Some(ref session) = session {
                    for event_data in events {
                        let _ = trace_sender.send(event_data);
                    }
                }
            }

            // Handle runtime commands
            Some(command) = runtime_channels.command_receiver.recv() => {
                match command {
                    RuntimeCommand::ExecuteScript { command: script } => {
                        handle_execute_script(&mut session, &mut runtime_channels, script, &save_options).await;
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
    save_options: &ghostscope_compiler::SaveOptions,
) {
    info!("Executing script: {}", script);

    if let Some(ref mut session) = session {
        match crate::script::compile_and_load_script_for_tui(&script, session, save_options).await {
            Ok(details) => {
                info!(
                    "✓ Script compilation completed: {} total, {} success, {} failed",
                    details.total_count, details.success_count, details.failed_count
                );
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::ScriptCompilationCompleted { details });
            }
            Err(e) => {
                error!("❌ Script compilation failed: {}", e);
                let _ =
                    runtime_channels
                        .status_sender
                        .send(RuntimeStatus::ScriptCompilationFailed {
                            error: format!("Script compilation failed: {}", e),
                            target: script.clone(),
                        });
            }
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::ScriptCompilationFailed {
                error: "No debug session available".to_string(),
                target: script,
            });
    }
}

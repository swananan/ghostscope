use crate::config::ParsedArgs;
use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_dwarf::ModuleLoadingEvent;
use ghostscope_ui::{events::ModuleLoadingStats as UIModuleLoadingStats, RuntimeStatus};
use tracing::info;

/// Convert ModuleLoadingEvent to RuntimeStatus
fn convert_loading_event_to_runtime_status(event: ModuleLoadingEvent) -> RuntimeStatus {
    match event {
        ModuleLoadingEvent::Discovered {
            module_path,
            current: _,
            total,
        } => RuntimeStatus::DwarfModuleDiscovered {
            module_path,
            total_modules: total,
        },
        ModuleLoadingEvent::LoadingStarted {
            module_path,
            current,
            total,
        } => RuntimeStatus::DwarfModuleLoadingStarted {
            module_path,
            current,
            total,
        },
        ModuleLoadingEvent::LoadingCompleted {
            module_path,
            stats,
            current,
            total,
        } => {
            let ui_stats = UIModuleLoadingStats {
                functions: stats.functions,
                variables: stats.variables,
                types: stats.types,
                load_time_ms: stats.load_time_ms,
            };
            RuntimeStatus::DwarfModuleLoadingCompleted {
                module_path,
                stats: ui_stats,
                current,
                total,
            }
        }
        ModuleLoadingEvent::LoadingFailed {
            module_path,
            error,
            current,
            total,
        } => RuntimeStatus::DwarfModuleLoadingFailed {
            module_path,
            error,
            current,
            total,
        },
    }
}

/// Initialize DWARF processing in background
pub async fn initialize_dwarf_processing(
    parsed_args: ParsedArgs,
    status_sender: tokio::sync::mpsc::UnboundedSender<RuntimeStatus>,
) -> Result<GhostSession> {
    initialize_dwarf_processing_with_progress(parsed_args, status_sender).await
}

/// Initialize DWARF processing in background with detailed progress reporting
pub async fn initialize_dwarf_processing_with_progress(
    parsed_args: ParsedArgs,
    status_sender: tokio::sync::mpsc::UnboundedSender<RuntimeStatus>,
) -> Result<GhostSession> {
    // Send status update: starting DWARF loading
    let _ = status_sender.send(RuntimeStatus::DwarfLoadingStarted);

    // Create progress callback that converts ModuleLoadingEvent to RuntimeStatus
    let progress_callback = {
        let sender = status_sender.clone();
        move |event: ModuleLoadingEvent| {
            let runtime_status = convert_loading_event_to_runtime_status(event);
            let _ = sender.send(runtime_status);
        }
    };

    // Create debug session for DWARF processing with parallel loading and progress
    match GhostSession::new_with_binary_parallel_with_progress(&parsed_args, progress_callback)
        .await
    {
        Ok(session) => {
            // Validate that we have process analysis information
            match session.get_module_stats() {
                Some(stats) => {
                    info!("✓ Process analysis successful in TUI mode");
                    info!("  Total modules: {}", stats.total_modules);
                    info!("  Executable modules: {}", stats.executable_modules);
                    info!("  Library modules: {}", stats.library_modules);
                    info!("  Total symbols: {}", stats.total_symbols);
                    info!(
                        "  Modules with debug info: {}",
                        stats.modules_with_debug_info
                    );

                    // Count available symbols for status update
                    let functions = session.list_functions();
                    let symbols_count = functions.len();

                    // Send success status
                    // If no debug information was found, treat it as a loading failure
                    if stats.modules_with_debug_info == 0 {
                        let _ = status_sender.send(RuntimeStatus::DwarfLoadingFailed(
                            "No debug information available. Compile with -g for full functionality"
                                .to_string(),
                        ));
                    } else {
                        let _ = status_sender
                            .send(RuntimeStatus::DwarfLoadingCompleted { symbols_count });
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

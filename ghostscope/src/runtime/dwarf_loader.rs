use crate::args::ParsedArgs;
use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_ui::RuntimeStatus;
use tracing::info;

/// Initialize DWARF processing in background
pub async fn initialize_dwarf_processing(
    parsed_args: ParsedArgs,
    status_sender: tokio::sync::mpsc::UnboundedSender<RuntimeStatus>,
) -> Result<GhostSession> {
    // Send status update: starting DWARF loading
    let _ = status_sender.send(RuntimeStatus::DwarfLoadingStarted);

    // Create debug session for DWARF processing with parallel loading
    match GhostSession::new_with_binary_parallel(&parsed_args).await {
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
                    let _ =
                        status_sender.send(RuntimeStatus::DwarfLoadingCompleted { symbols_count });

                    if stats.modules_with_debug_info == 0 {
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

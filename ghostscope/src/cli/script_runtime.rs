//! CLI script-mode runtime orchestration.

use crate::config::MergedConfig;
use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_dwarf::ModuleLoadingEvent;
use std::io::{self, IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
async fn wait_for_shutdown_signal() -> io::Result<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => Ok("SIGINT"),
        _ = sigterm.recv() => Ok("SIGTERM"),
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown_signal() -> io::Result<&'static str> {
    tokio::signal::ctrl_c().await?;
    Ok("Ctrl+C")
}

/// Run GhostScope in command line mode with merged configuration
pub async fn run_command_line_runtime_with_config(config: MergedConfig) -> Result<()> {
    info!("Starting GhostScope in command line mode");

    // Step 1: Get script content
    let script_content = get_script_content_from_config(&config)?;

    // Step 2: Initialize debug session and DWARF information processing
    info!("Initializing debug session and DWARF information processing...");

    let console_stderr_logging_active =
        is_console_stderr_logging_active(config.enable_logging, config.enable_console_logging);
    let reporter = Arc::new(Mutex::new(
        crate::cli::loading_reporter::CliLoadingReporter::new(
            console_stderr_logging_active,
            config.script_color_mode,
        ),
    ));
    let reporter_task = spawn_loading_reporter(Arc::clone(&reporter));
    let progress_callback = {
        let reporter = Arc::clone(&reporter);
        move |event: ModuleLoadingEvent| {
            if let Ok(mut reporter) = reporter.lock() {
                reporter.handle_event(event);
            }
        }
    };

    let session_result =
        GhostSession::new_with_config_and_progress(&config, progress_callback).await;
    if let Some(task) = reporter_task {
        task.abort();
        let _ = task.await;
    }

    let session = match session_result {
        Ok(session) => {
            if let Ok(mut reporter) = reporter.lock() {
                reporter.finish_success();
            }
            session
        }
        Err(e) => {
            if let Ok(mut reporter) = reporter.lock() {
                reporter.finish_failure(&e.to_string());
            }
            return Err(anyhow::anyhow!("Failed to create debug session: {}", e));
        }
    };

    // Continue with the rest of the CLI runtime logic, using config instead of parsed_args
    run_cli_with_session(session, script_content, &config).await
}

fn spawn_loading_reporter(
    reporter: Arc<Mutex<crate::cli::loading_reporter::CliLoadingReporter>>,
) -> Option<tokio::task::JoinHandle<()>> {
    let enabled = reporter
        .lock()
        .map(|reporter| reporter.is_enabled())
        .unwrap_or(false);
    if !enabled {
        return None;
    }

    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_millis(120));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Ok(mut reporter) = reporter.lock() {
                reporter.render_tick();
            } else {
                break;
            }
        }
    }))
}

/// Run CLI session with existing GhostSession and configuration
async fn run_cli_with_session(
    mut session: GhostSession,
    script_content: String,
    config: &MergedConfig,
) -> Result<()> {
    let show_cli_status = should_print_cli_status(config);
    let stderr_colors = crate::cli::color::CliColors::for_stderr(config.script_color_mode);

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
    if let Some(pid_views) = session.pid_views() {
        info!("PID views: {}", pid_views.compact_display());
    } else if let Some(proc_pid) = session.proc_pid() {
        info!("Target PID: {}", proc_pid);
    }
    if let Some(env) = config.runtime_env.as_ref() {
        info!("Runtime environment: {}", env.compact_display());
    }
    if let Some(spec) = config.pid_filter_spec {
        info!("PID filter strategy: {:?}", spec);
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
                let host_hint = config
                    .host_pid
                    .map(|pid| format!(" (host PID for eBPF filter: {pid})"))
                    .unwrap_or_default();
                let requested_pid = config.input_pid.or(config.pid).unwrap_or(0);
                return Err(anyhow::anyhow!(
                    "Process analysis failed! Cannot proceed without process information. \
                    Possible solutions: 1. Check that PID {} exists: ps -p {}, \
                    2. Check process permissions, 3. Run with sudo if needed for /proc access{}",
                    requested_pid,
                    requested_pid,
                    host_hint
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

    // Step 6: Build compile options from merged config
    let binary_path_hint = crate::util::derive_binary_path_hint(&session);

    let compile_options = config.get_compile_options(
        config.should_save_llvm_ir,
        config.should_save_ebpf,
        config.should_save_ast,
        binary_path_hint,
    );

    // Step 7: Compile and load script with graceful error handling
    if show_cli_status {
        eprintln!(
            "{}",
            stderr_colors.yellow(stderr_colors.bold("Compiling script..."))
        );
    }
    if let Err(e) = crate::script::compile_and_load_script_for_cli(
        &script_content,
        &mut session,
        &compile_options,
    )
    .await
    {
        error!("Failed to compile and load script: {:#}", e);
        info!("GhostScope encountered an error during script compilation. Exiting gracefully.");
        return Err(e);
    }

    // Step 8: Start event monitoring loop using trace_manager
    info!(
        "Starting event monitoring for {} active traces",
        session.trace_manager.active_trace_count()
    );
    crate::util::emit_ready_marker(config.emit_ready_marker.as_deref())
        .map_err(|e| anyhow::anyhow!("failed to emit ready marker: {}", e))?;
    if show_cli_status {
        eprintln!(
            "{} {}",
            stderr_colors.green("Attached"),
            stderr_colors.bold(format!(
                "{} trace(s). Waiting for events...",
                session.trace_manager.active_trace_count()
            ))
        );
    }
    let mut output_renderer = crate::cli::script_output::ScriptOutputRenderer::new(
        crate::cli::script_output::ScriptOutputOptions {
            mode: config.script_output_mode,
            timestamp: config.script_timestamp_format,
            color_enabled: should_use_script_stdout_color(config),
        },
    );

    let shutdown_signal = wait_for_shutdown_signal();
    tokio::pin!(shutdown_signal);
    loop {
        tokio::select! {
            result = session.trace_manager.wait_for_all_events_async() => {
                match result {
                    Ok(events) => {
                        for event in events {
                            let rendered_lines = output_renderer.render_event_lines(&event);

                            if !rendered_lines.is_empty() {
                                for line in rendered_lines {
                                    println!("{line}");
                                }
                                // When stdout is piped (as in tests), Rust switches to block buffering.
                                // Flush explicitly so short event bursts appear before the process exits.
                                if let Err(e) = io::stdout().flush() {
                                    warn!("Failed to flush event output: {e}");
                                }
                            }

                            debug!("Raw trace event: {:?}", event);
                        }
                    }
                    Err(e) => {
                        error!("Fatal error receiving trace events: {}", e);
                        return Err(e);
                    }
                }
            }

            signal = &mut shutdown_signal => {
                match signal {
                    Ok(signal_name) => info!("Received {signal_name}, shutting down..."),
                    Err(err) => warn!("Failed to listen for shutdown signal: {err}"),
                }
                break;
            }
        }
    }

    Ok(())
}

fn should_print_cli_status(config: &MergedConfig) -> bool {
    !is_console_stderr_logging_active(config.enable_logging, config.enable_console_logging)
        && io::stderr().is_terminal()
}

fn is_console_stderr_logging_active(enable_logging: bool, enable_console_logging: bool) -> bool {
    enable_logging && enable_console_logging
}

fn should_use_script_stdout_color(config: &MergedConfig) -> bool {
    crate::cli::color::CliColors::for_stdout(config.script_color_mode).enabled()
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

#[cfg(test)]
mod tests {
    use super::is_console_stderr_logging_active;

    #[test]
    fn console_stderr_logging_requires_logging_to_be_enabled() {
        assert!(!is_console_stderr_logging_active(false, false));
        assert!(!is_console_stderr_logging_active(false, true));
        assert!(!is_console_stderr_logging_active(true, false));
        assert!(is_console_stderr_logging_active(true, true));
    }
}

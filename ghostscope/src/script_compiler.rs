use crate::session::GhostSession;
use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use std::path::Path;
use tracing::{error, info, warn};

/// Compile and load script specifically for TUI mode with strict all-or-nothing success
/// This function ensures that ALL uprobe configurations must succeed for the operation to be considered successful
pub async fn compile_and_load_script_for_tui(
    script: &str,
    trace_id: u32,
    session: &mut GhostSession,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) -> Result<()> {
    use ghostscope_ui::RuntimeStatus;

    // Step 1: Validate binary analyzer availability
    let binary_analyzer = match session.binary_analyzer.as_ref() {
        Some(analyzer) => analyzer,
        None => {
            let error = "Binary analyzer is required for script compilation".to_string();
            let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                error: error.clone(),
                trace_id,
            });
            return Err(anyhow::anyhow!(error));
        }
    };

    // Step 2: Configure save options (no file saving in TUI mode)
    let binary_path_hint = binary_analyzer
        .debug_info()
        .binary_path
        .file_stem()
        .and_then(|s| s.to_str())
        .map(|s| s.to_string());

    let save_options = ghostscope_compiler::SaveOptions {
        save_llvm_ir: false,
        save_ast: false,
        save_ebpf: false,
        binary_path_hint,
    };

    // Step 3: Use unified compilation interface
    let compilation_result = match ghostscope_compiler::compile_script_to_uprobe_configs(
        script,
        binary_analyzer,
        session.target_pid,
        Some(trace_id),
        &save_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            let error = format!("Script compilation failed: {}", e);
            let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                error: error.clone(),
                trace_id,
            });
            return Err(anyhow::anyhow!(error));
        }
    };

    info!(
        "Script compilation successful: {} trace points found, {} uprobe configs generated, target: {}",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len(),
        compilation_result.target_info
    );

    if compilation_result.uprobe_configs.is_empty() {
        let error = "No valid uprobe configurations generated from script".to_string();
        let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
            error: error.clone(),
            trace_id,
        });
        return Err(anyhow::anyhow!(error));
    }

    // Step 4: Get binary path for trace instances
    let binary_path = binary_analyzer
        .debug_info()
        .binary_path
        .to_string_lossy()
        .to_string();

    // Step 5: Process each uprobe configuration and create trace instances
    // TUI mode requires strict all-or-nothing success: ALL uprobe configs must succeed
    let mut successful_trace_ids = Vec::new();
    let expected_trace_count = compilation_result.uprobe_configs.len();

    for (i, mut config) in compilation_result.uprobe_configs.into_iter().enumerate() {
        config.binary_path = binary_path.clone();

        // Compiler should have already resolved addresses and offsets
        let uprobe_offset = match config.uprobe_offset {
            Some(offset) => offset,
            None => {
                let error = format!(
                    "Uprobe config {} missing uprobe_offset - compilation failed",
                    i
                );
                error!("{}", error);
                // Clean up any successful traces before failing
                for &trace_id in &successful_trace_ids {
                    let _ = session.trace_manager.remove_trace(trace_id).await;
                }
                let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                    error: error.clone(),
                    trace_id,
                });
                return Err(anyhow::anyhow!(error));
            }
        };

        // Generate target display name from the trace pattern
        let target_display = generate_target_display_name(&config.trace_pattern);

        info!(
            "Processing uprobe config {}: target='{}', offset=0x{:x}",
            i, target_display, uprobe_offset
        );

        // Step 6: Create GhostScopeLoader with compiled eBPF bytecode
        let loader = match GhostScopeLoader::new(&config.ebpf_bytecode) {
            Ok(loader) => loader,
            Err(e) => {
                let error = format!("Failed to create eBPF loader for config {}: {}", i, e);
                error!("{}", error);
                // Clean up any successful traces before failing
                for &trace_id in &successful_trace_ids {
                    let _ = session.trace_manager.remove_trace(trace_id).await;
                }
                let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                    error: error.clone(),
                    trace_id,
                });
                return Err(anyhow::anyhow!(error));
            }
        };

        // Step 7: Add trace instance to TraceManager
        let actual_trace_id = session.trace_manager.add_trace(
            compilation_result.target_info.clone(),
            script.to_string(),
            loader,
            binary_path.clone(),
            target_display.clone(),
            Some(uprobe_offset), // Always use offset for uprobe loading
            session.target_pid,
        );

        info!(
            "Created trace instance {} for target '{}' with uprobe config {}",
            actual_trace_id, target_display, i
        );

        // Step 8: Activate the trace instance (attach uprobe)
        if let Err(e) = session.trace_manager.activate_trace(actual_trace_id).await {
            let error = format!("Failed to activate trace {}: {}", actual_trace_id, e);
            error!("{}", error);
            // Clean up this failed trace and any successful ones
            let _ = session.trace_manager.remove_trace(actual_trace_id).await;
            for &trace_id in &successful_trace_ids {
                let _ = session.trace_manager.remove_trace(trace_id).await;
            }
            let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
                error: error.clone(),
                trace_id,
            });
            return Err(anyhow::anyhow!(error));
        }

        successful_trace_ids.push(actual_trace_id);

        // Send uprobe attached status for UI only after successful activation
        if let Some(address) = config.function_address {
            let _ = status_sender.send(RuntimeStatus::UprobeAttached {
                function: target_display.clone(),
                address,
            });
        }

        info!(
            "Successfully activated trace {} for target '{}'",
            actual_trace_id, target_display
        );
    }

    // Step 9: Verify ALL uprobe configurations were processed successfully
    if successful_trace_ids.len() == expected_trace_count {
        let _ = status_sender.send(RuntimeStatus::ScriptCompilationCompleted { trace_id });
        info!(
            "Script compilation and loading completed successfully: ALL {} uprobe configurations attached",
            expected_trace_count
        );
        Ok(())
    } else {
        let error = format!(
            "Script compilation failed: only {} out of {} uprobe configurations succeeded",
            successful_trace_ids.len(),
            expected_trace_count
        );
        // This should never happen due to early returns above, but defensive programming
        for &trace_id in &successful_trace_ids {
            let _ = session.trace_manager.remove_trace(trace_id).await;
        }
        let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
            error: error.clone(),
            trace_id,
        });
        Err(anyhow::anyhow!(error))
    }
}

/// Generate target display name from trace pattern
/// This is used for UI display and logging, not for uprobe attachment
fn generate_target_display_name(pattern: &ghostscope_compiler::ast::TracePattern) -> String {
    match pattern {
        ghostscope_compiler::ast::TracePattern::FunctionName(name) => name.clone(),
        ghostscope_compiler::ast::TracePattern::Wildcard(pattern) => pattern.clone(),
        ghostscope_compiler::ast::TracePattern::Address(addr) => format!("0x{:x}", addr),
        ghostscope_compiler::ast::TracePattern::SourceLine {
            file_path,
            line_number,
        } => format!("{}:{}", file_path, line_number),
    }
}

/// Extract target from script (e.g., "trace main { ... }" -> "main")
pub fn extract_target_from_script(script: &str) -> String {
    if let Some(trace_start) = script.find("trace ") {
        let after_trace = &script[trace_start + 6..]; // "trace ".len() = 6
        if let Some(first_space_or_brace) =
            after_trace.find(|c: char| c.is_whitespace() || c == '{')
        {
            return after_trace[..first_space_or_brace].trim().to_string();
        } else {
            return after_trace.trim().to_string();
        }
    }
    "unknown".to_string()
}

/// Parse and validate script (reuse existing logic)
fn parse_and_validate_script(script: &str) -> Result<ghostscope_compiler::ast::Program> {
    match ghostscope_compiler::parser::parse(script) {
        Ok(parsed) => {
            info!("Script parsing completed successfully");
            Ok(parsed)
        }
        Err(e) => {
            error!("Script parsing failed: {}", e);
            Err(anyhow::anyhow!("Script parsing failed: {}", e))
        }
    }
}

/// Compile and load script for command line mode using session.command_loaders
pub async fn compile_and_load_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    save_options: &ghostscope_compiler::SaveOptions,
) -> Result<()> {
    info!("Starting unified script compilation with DWARF integration...");

    // Step 1: Validate binary analyzer
    let binary_analyzer = session
        .binary_analyzer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Binary analyzer is required for script compilation"))?;

    let binary_path_string = binary_analyzer
        .debug_info()
        .binary_path
        .to_string_lossy()
        .to_string();

    // Step 2: Use unified compilation interface
    let compilation_result = ghostscope_compiler::compile_script_to_uprobe_configs(
        script,
        binary_analyzer,
        session.target_pid,
        None, // Command line mode doesn't have specific trace_id, use default
        save_options,
    )?;

    info!(
        "✓ Script compilation successful: {} trace points found, {} uprobe configs generated",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len()
    );
    info!("Target info: {}", compilation_result.target_info);

    if save_options.save_llvm_ir || save_options.save_ebpf || save_options.save_ast {
        info!("Files saved with consistent naming: gs_{{pid}}_{{exec}}_{{func}}_{{index}}");
    }

    // Step 3: Prepare and attach uprobe configurations
    let mut uprobe_configs = compilation_result.uprobe_configs;

    for config in uprobe_configs.iter_mut() {
        config.binary_path = binary_path_string.clone();
    }

    if uprobe_configs.is_empty() {
        return Err(anyhow::anyhow!(
            "No uprobe configurations created - nothing to attach"
        ));
    }

    info!("Attaching {} uprobe configurations", uprobe_configs.len());
    for (i, config) in uprobe_configs.iter().enumerate() {
        info!(
            "  Config {}: {:?} -> 0x{:x}",
            i,
            config
                .function_name
                .as_ref()
                .unwrap_or(&format!("0x{:x}", config.function_address.unwrap_or(0))),
            config.uprobe_offset.unwrap_or(0)
        );
    }

    // Step 4: Attach uprobes using session's attach_uprobes method
    session.attach_uprobes(&uprobe_configs).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to attach uprobes: {}. Possible reasons: \
            1. Need root permissions (run with sudo), \
            2. Target binary doesn't exist or lacks debug info, \
            3. Process not running or PID invalid, \
            4. Function addresses not accessible",
            e
        )
    })?;

    info!("All uprobes attached successfully!");
    Ok(())
}

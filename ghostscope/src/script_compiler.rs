use crate::session::GhostSession;
use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use std::path::Path;
use tracing::{error, info, warn};

/// Compile and load a script with trace_id support using the new TraceManager
pub async fn compile_and_load_script_with_trace_id(
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
    for (i, mut config) in compilation_result.uprobe_configs.into_iter().enumerate() {
        config.binary_path = binary_path.clone();

        let (function_name, uprobe_offset) =
            match resolve_uprobe_config(&mut config, session, status_sender).await {
                Ok((name, offset)) => (name, offset),
                Err(e) => {
                    warn!("Failed to resolve uprobe config {}: {}", i, e);
                    continue;
                }
            };

        // Step 6: Create GhostScopeLoader with compiled eBPF bytecode
        let loader = match GhostScopeLoader::new(&config.ebpf_bytecode) {
            Ok(loader) => loader,
            Err(e) => {
                error!("Failed to create eBPF loader for config {}: {}", i, e);
                continue;
            }
        };

        // Step 7: Add trace instance to TraceManager
        let actual_trace_id = session.trace_manager.add_trace(
            compilation_result.target_info.clone(),
            script.to_string(),
            loader,
            binary_path.clone(),
            function_name.clone(),
            uprobe_offset,
            session.target_pid,
        );

        info!(
            "Created trace instance {} for function '{}' with uprobe config {}",
            actual_trace_id, function_name, i
        );

        // Step 8: Activate the trace instance (attach uprobe)
        if let Err(e) = session.trace_manager.activate_trace(actual_trace_id).await {
            error!("Failed to activate trace {}: {}", actual_trace_id, e);
            // Remove failed trace
            let _ = session.trace_manager.remove_trace(actual_trace_id).await;
            continue;
        }

        info!(
            "Successfully activated trace {} for function '{}'",
            actual_trace_id, function_name
        );
    }

    // Step 9: Check if any traces were successfully created
    if session.trace_manager.active_trace_count() > 0 {
        let _ = status_sender.send(RuntimeStatus::ScriptCompilationCompleted { trace_id });
        info!(
            "Script compilation and loading completed successfully using unified interface with {} active traces",
            session.trace_manager.active_trace_count()
        );
        Ok(())
    } else {
        let error = "No traces could be activated".to_string();
        let _ = status_sender.send(RuntimeStatus::ScriptCompilationFailed {
            error: error.clone(),
            trace_id,
        });
        Err(anyhow::anyhow!(error))
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

/// Resolve uprobe configuration to function name and offset
/// Uses unified DWARF query interfaces for cleaner code
async fn resolve_uprobe_config(
    config: &mut ghostscope_compiler::UProbeConfig,
    session: &GhostSession,
    status_sender: &tokio::sync::mpsc::UnboundedSender<ghostscope_ui::RuntimeStatus>,
) -> Result<(String, Option<u64>)> {
    use ghostscope_ui::RuntimeStatus;

    let analyzer = session
        .binary_analyzer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No binary analyzer available for address resolution"))?;

    match &config.trace_pattern {
        ghostscope_compiler::ast::TracePattern::FunctionName(function_name) => {
            // Use unified function address resolution
            let address = analyzer
                .resolve_function_address(function_name)
                .ok_or_else(|| {
                    anyhow::anyhow!("Function '{}' not found in binary", function_name)
                })?;

            let uprobe_offset = analyzer
                .resolve_function_uprobe_offset(function_name)
                .unwrap_or(address); // Fallback to address if uprobe offset calculation fails

            // Update config
            config.function_address = Some(address);
            config.uprobe_offset = Some(uprobe_offset);

            info!(
                "Resolved function '{}' to address 0x{:x}",
                function_name, address
            );

            // Send uprobe attached status
            let _ = status_sender.send(RuntimeStatus::UprobeAttached {
                function: function_name.clone(),
                address,
            });

            Ok((function_name.clone(), Some(uprobe_offset)))
        }
        ghostscope_compiler::ast::TracePattern::SourceLine {
            file_path,
            line_number,
        } => {
            // Use unified source line address resolution
            let address = analyzer
                .resolve_source_line_address(file_path, *line_number)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No addresses found for source line {}:{}",
                        file_path,
                        line_number
                    )
                })?;

            let uprobe_offset = analyzer
                .resolve_source_line_uprobe_offset(file_path, *line_number)
                .unwrap_or(address); // Fallback to address if uprobe offset calculation fails

            // Update config
            config.function_name = None;
            config.function_address = Some(address);
            config.uprobe_offset = Some(uprobe_offset);

            let function_name = format!("{}:{}", file_path, line_number);

            info!(
                "Resolved source line '{}:{}' to address 0x{:x}",
                file_path, line_number, address
            );

            // Send uprobe attached status for source line
            let _ = status_sender.send(RuntimeStatus::UprobeAttached {
                function: function_name.clone(),
                address,
            });

            Ok((function_name, Some(uprobe_offset)))
        }
        _ => Err(anyhow::anyhow!(
            "Trace pattern not yet supported: {:?}",
            config.trace_pattern
        )),
    }
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

use crate::session::GhostSession;
use crate::trace_manager::TraceMountPoint;
use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use tracing::{error, info};

/// Compile and load script specifically for TUI mode with detailed execution results
/// This function collects detailed results for each PC/target and returns comprehensive status
pub async fn compile_and_load_script_for_tui(
    script: &str,
    trace_id: u32,
    session: &mut GhostSession,
) -> Result<ScriptCompilationDetails> {
    // Step 1: Validate binary analyzer availability
    let binary_analyzer = session
        .binary_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Binary analyzer is required for script compilation"))?;

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
    // Handle compilation errors gracefully - some trace points might still succeed
    let compilation_result = match ghostscope_compiler::compile_script(
        script,
        binary_analyzer,
        session.target_pid,
        Some(trace_id),
        &save_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Script compilation failed: {}", e);
            // Return a compilation result with no uprobe configs but with error details
            return Ok(ScriptCompilationDetails {
                trace_id,
                results: vec![ScriptExecutionResult {
                    pc_address: 0,
                    target_name: "script_compilation".to_string(),
                    status: ExecutionStatus::Failed(format!("Script compilation failed: {}", e)),
                }],
                total_count: 1,
                success_count: 0,
                failed_count: 1,
            });
        }
    };

    info!(
        "Script compilation successful: {} trace points found, {} uprobe configs generated, target: {}",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len(),
        compilation_result.target_info
    );

    if compilation_result.uprobe_configs.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid uprobe configurations generated from script"
        ));
    }

    // Step 4: Get binary path for trace instances
    let binary_path = binary_analyzer
        .debug_info()
        .binary_path
        .to_string_lossy()
        .to_string();

    // Step 5: Process compilation results at PC level for detailed error reporting
    let mut execution_results: Vec<ScriptExecutionResult> = Vec::new();
    let mut successful_mounts: Vec<TraceMountPoint> = Vec::new();
    let mut success_count = 0;
    let mut failed_count = 0;

    // Use the first uprobe config's pattern as the trace display name (if available)
    let target_display = if !compilation_result.uprobe_configs.is_empty() {
        generate_target_display_name(&compilation_result.uprobe_configs[0].trace_pattern)
    } else {
        "unknown_target".to_string()
    };

    // Create mapping from PC address to uprobe config for successful compilations
    let mut pc_to_config: std::collections::HashMap<u64, ghostscope_compiler::UProbeConfig> =
        std::collections::HashMap::new();
    for mut config in compilation_result.uprobe_configs {
        config.binary_path = binary_path.clone();
        if let Some(pc_address) = config.uprobe_offset {
            pc_to_config.insert(pc_address, config);
        }
    }

    // Handle empty PC results (edge case)
    if compilation_result.pc_results.is_empty() {
        info!("No PC compilation results available, checking if there are any uprobe configs");
        if pc_to_config.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid PC addresses found during compilation"
            ));
        }
    }

    // Check if we have multiple PCs to determine naming strategy
    let has_multiple_pcs = compilation_result.pc_results.len() > 1;

    // Process each PC compilation result
    for pc_result in compilation_result.pc_results {
        let pc_address = pc_result.pc_address;
        let target_name = if has_multiple_pcs {
            format!("{} (PC: 0x{:x})", pc_result.target_name, pc_address)
        } else {
            pc_result.target_name
        };

        if pc_result.success {
            // Compilation succeeded - try to create eBPF loader and mount
            if let Some(config) = pc_to_config.remove(&pc_address) {
                info!(
                    "Processing successful target: '{}', offset=0x{:x}, prog='{}'",
                    target_name, pc_address, config.ebpf_function_name
                );

                // Try to create eBPF loader
                match GhostScopeLoader::new(&config.ebpf_bytecode) {
                    Ok(loader) => {
                        execution_results.push(ScriptExecutionResult {
                            pc_address,
                            target_name: target_name.clone(),
                            status: ExecutionStatus::Success,
                        });

                        successful_mounts.push(TraceMountPoint {
                            loader,
                            uprobe_offset: config.uprobe_offset.unwrap_or(pc_address),
                            ebpf_function_name: config.ebpf_function_name,
                        });
                        success_count += 1;
                        info!(
                            "✓ Successfully prepared target '{}' at 0x{:x}",
                            target_name, pc_address
                        );
                    }
                    Err(e) => {
                        let error_msg =
                            format!("Failed to create eBPF loader for '{}': {}", target_name, e);
                        error!("{}", error_msg);
                        execution_results.push(ScriptExecutionResult {
                            pc_address,
                            target_name,
                            status: ExecutionStatus::Failed(error_msg),
                        });
                        failed_count += 1;
                    }
                }
            } else {
                let error_msg = format!(
                    "Internal error: No uprobe config found for successful PC 0x{:x}",
                    pc_address
                );
                error!("{}", error_msg);
                execution_results.push(ScriptExecutionResult {
                    pc_address,
                    target_name,
                    status: ExecutionStatus::Failed(error_msg),
                });
                failed_count += 1;
            }
        } else {
            // Compilation failed - use the error message from pc_result
            let error_msg = pc_result
                .error_message
                .unwrap_or_else(|| "Unknown compilation error".to_string());
            error!(
                "❌ Failed to compile target '{}' at 0x{:x}: {}",
                target_name, pc_address, error_msg
            );
            execution_results.push(ScriptExecutionResult {
                pc_address,
                target_name,
                status: ExecutionStatus::Failed(format!("Compilation failed: {}", error_msg)),
            });
            failed_count += 1;
        }
    }

    // Step 6: Create trace instance only if we have successful mounts
    let actual_trace_id = if !successful_mounts.is_empty() {
        let trace_id = session.trace_manager.add_trace(
            compilation_result.target_info.clone(),
            script.to_string(),
            successful_mounts,
            binary_path.clone(),
            target_display.clone(),
            session.target_pid,
        );

        info!(
            "Created trace instance {} for target '{}' with {} successful mounts",
            trace_id, target_display, success_count
        );

        // Step 7: Try to activate the trace instance (attach all uprobes)
        match session.trace_manager.activate_trace(trace_id).await {
            Ok(_) => {
                info!(
                    "Successfully activated trace {} for target '{}' with {} mounts",
                    trace_id, target_display, success_count
                );
                Some(trace_id)
            }
            Err(e) => {
                let error_msg = format!("Failed to activate trace {}: {}", trace_id, e);
                error!("{}", error_msg);
                let _ = session.trace_manager.remove_trace(trace_id).await;

                // If trace activation failed, all uprobes failed to load
                // Mark all previously successful targets as failed
                for result in &mut execution_results {
                    if matches!(result.status, ExecutionStatus::Success) {
                        result.status =
                            ExecutionStatus::Failed(format!("Uprobe attachment failed: {}", e));
                    }
                }

                // Update counts
                failed_count += success_count;
                success_count = 0;

                info!(
                    "Trace activation failed, marking all {} targets as failed",
                    failed_count
                );
                None
            }
        }
    } else {
        info!("No successful mounts to create trace instance");
        None
    };

    // Step 8: Return detailed compilation results
    // If all targets failed, return an error instead of success
    if success_count == 0 && failed_count > 0 {
        let error_msg = format!("All {} targets failed to compile", failed_count);
        error!("{}", error_msg);
        return Err(anyhow::anyhow!(error_msg));
    }

    let total_count = success_count + failed_count;

    let details = ScriptCompilationDetails {
        trace_id: actual_trace_id.unwrap_or(trace_id), // Use provided trace_id if no actual trace created
        results: execution_results,
        total_count,
        success_count,
        failed_count,
    };

    info!(
        "Script compilation completed: {}/{} PC targets successful, {}/{} failed",
        success_count, total_count, failed_count, total_count
    );

    Ok(details)
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
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Binary analyzer is required for script compilation"))?;

    let binary_path_string = binary_analyzer
        .debug_info()
        .binary_path
        .to_string_lossy()
        .to_string();

    // Step 2: Use unified compilation interface
    let compilation_result = ghostscope_compiler::compile_script(
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

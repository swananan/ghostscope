use crate::session::GhostSession;
use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use tracing::{error, info, warn};

/// Compile and load script specifically for TUI mode with detailed execution results
/// This function collects detailed results for each PC/target and returns comprehensive status
pub async fn compile_and_load_script_for_tui(
    script: &str,
    session: &mut GhostSession,
) -> Result<ScriptCompilationDetails> {
    // Step 1: Validate process analyzer availability
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;

    // Step 2: Configure save options (no file saving in TUI mode)
    let binary_path_hint = if let Some(main_module) = process_analyzer.get_main_executable() {
        std::path::Path::new(&main_module.path)
            .file_stem()
            .and_then(|s| s.to_str())
            .map(|s| s.to_string())
    } else {
        Some("ghostscope".to_string())
    };

    let save_options = ghostscope_compiler::SaveOptions {
        save_llvm_ir: false,
        save_ast: false,
        save_ebpf: false,
        binary_path_hint,
    };

    // Step 2.5: Get binary path early for error handling
    let binary_path = if let Some(main_module) = process_analyzer.get_main_executable() {
        main_module.path.clone()
    } else {
        return Err(anyhow::anyhow!("No main executable found in process"));
    };

    // Step 3: Do a single compilation to get all results
    let compilation_result = match ghostscope_compiler::compile_script(
        script,
        process_analyzer,
        session.target_pid,
        None, // We'll assign trace IDs after we know how many we need
        &save_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Script compilation failed: {}", e);
            return Ok(ScriptCompilationDetails {
                trace_ids: vec![],
                results: vec![ScriptExecutionResult {
                    pc_address: 0,
                    target_name: "script_compilation".to_string(),
                    binary_path: process_analyzer
                        .get_main_executable()
                        .map(|m| m.path.clone())
                        .unwrap_or_else(|| "unknown".to_string()),
                    status: ExecutionStatus::Failed(format!("Script compilation failed: {}", e)),
                }],
                total_count: 1,
                success_count: 0,
                failed_count: 1,
            });
        }
    };

    // Pre-allocate trace IDs based on successful PC count
    let mut pre_allocated_trace_ids = Vec::new();
    for _ in &compilation_result.uprobe_configs {
        let trace_id = session.trace_manager.reserve_next_trace_id();
        pre_allocated_trace_ids.push(trace_id);
    }

    info!(
        "Script compilation successful: {} trace points found, {} uprobe configs generated, target: {}",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len(),
        compilation_result.target_info
    );

    if compilation_result.uprobe_configs.is_empty() {
        warn!("No valid uprobe configurations generated from script");

        // Check if we have detailed failure information from the compiler
        if !compilation_result.failed_targets.is_empty() {
            info!(
                "Using detailed failure information from compiler: {} failed targets",
                compilation_result.failed_targets.len()
            );

            // Use the detailed failure information instead of generic error
            let mut execution_results = Vec::new();
            for failed_target in &compilation_result.failed_targets {
                execution_results.push(ScriptExecutionResult {
                    pc_address: failed_target.pc_address,
                    target_name: failed_target.target_name.clone(),
                    binary_path: binary_path.clone(),
                    status: ExecutionStatus::Failed(format!(
                        "Compilation failed: {}",
                        failed_target.error_message
                    )),
                });
            }

            let details = ScriptCompilationDetails {
                trace_ids: vec![],
                results: execution_results,
                total_count: compilation_result.failed_targets.len(),
                success_count: 0,
                failed_count: compilation_result.failed_targets.len(),
            };

            info!(
                "Returning detailed compilation failures for {} targets",
                compilation_result.failed_targets.len()
            );
            return Ok(details);
        } else {
            // Fallback to generic error if no detailed failure info available
            let target_name = extract_target_from_script(script);
            let execution_results = vec![ScriptExecutionResult {
                pc_address: 0,
                target_name: target_name.clone(),
                binary_path: binary_path.clone(),
                status: ExecutionStatus::Failed("No valid uprobe configurations generated from script - target not found or compilation failed".to_string()),
            }];

            let details = ScriptCompilationDetails {
                trace_ids: vec![],
                results: execution_results,
                total_count: 1,
                success_count: 0,
                failed_count: 1,
            };

            info!(
                "Returning compilation details with generic failed target: {}",
                target_name
            );
            return Ok(details);
        }
    }

    // Step 4: Process compilation results at PC level for detailed error reporting
    let mut execution_results: Vec<ScriptExecutionResult> = Vec::new();
    let mut successful_traces: Vec<(u64, GhostScopeLoader, String)> = Vec::new();
    let mut success_count: usize = 0;
    let mut failed_count: usize = 0;

    // First, add all failed targets from compilation
    for failed_target in &compilation_result.failed_targets {
        execution_results.push(ScriptExecutionResult {
            pc_address: failed_target.pc_address,
            target_name: failed_target.target_name.clone(),
            binary_path: binary_path.clone(),
            status: ExecutionStatus::Failed(format!(
                "Compilation failed: {}",
                failed_target.error_message
            )),
        });
        failed_count += 1;
    }

    // Use the first uprobe config's pattern as the trace display name (if available)
    let target_display = if !compilation_result.uprobe_configs.is_empty() {
        generate_target_display_name(&compilation_result.uprobe_configs[0].trace_pattern)
    } else {
        "unknown_target".to_string()
    };

    // Move uprobe_configs out of compilation_result to avoid borrow checker issues
    let mut uprobe_configs = compilation_result.uprobe_configs;

    // Create mapping from PC address to uprobe config for successful compilations
    let mut pc_to_config: std::collections::HashMap<u64, ghostscope_compiler::UProbeConfig> =
        std::collections::HashMap::new();

    // First collect all configs for later processing and create PC mapping
    for config in &mut uprobe_configs {
        config.binary_path = binary_path.clone();
        if let Some(pc_address) = config.uprobe_offset {
            pc_to_config.insert(pc_address, config.clone());
        }
    }

    // Handle empty PC results (edge case)
    if uprobe_configs.is_empty() {
        info!("No PC compilation results available, checking if there are any uprobe configs");
        if pc_to_config.is_empty() {
            return Err(anyhow::anyhow!(
                "No valid PC addresses found during compilation"
            ));
        }
    }

    // Check if we have multiple PCs to determine naming strategy
    let has_multiple_pcs = uprobe_configs.len() > 1;

    // Process each PC compilation result
    for pc_result in uprobe_configs {
        let pc_address = pc_result.function_address.unwrap_or(0);
        let target_name = if has_multiple_pcs {
            format!(
                "{} (PC: 0x{:x})",
                pc_result.function_name.as_deref().unwrap_or("unknown"),
                pc_address
            )
        } else {
            pc_result
                .function_name
                .as_deref()
                .unwrap_or("unknown")
                .to_string()
        };

        if !pc_result.ebpf_bytecode.is_empty() {
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
                            binary_path: binary_path.clone(),
                            status: ExecutionStatus::Success,
                        });

                        successful_traces.push((pc_address, loader, config.ebpf_function_name));
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
                            binary_path: binary_path.clone(),
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
                    binary_path: binary_path.clone(),
                    status: ExecutionStatus::Failed(error_msg),
                });
                failed_count += 1;
            }
        } else {
            // Compilation failed - eBPF bytecode is empty
            let error_msg = "eBPF bytecode generation failed".to_string();
            error!(
                "❌ Failed to compile target '{}' at 0x{:x}: {}",
                target_name, pc_address, error_msg
            );
            execution_results.push(ScriptExecutionResult {
                pc_address,
                target_name,
                binary_path: binary_path.clone(),
                status: ExecutionStatus::Failed(format!("Compilation failed: {}", error_msg)),
            });
            failed_count += 1;
        }
    }

    // Step 6: Create trace instances - one per successful target if multiple, or one combined if single target
    let mut trace_ids = Vec::new();

    if !successful_traces.is_empty() {
        // Create a separate trace for each successful PC using pre-allocated IDs
        for (index, (pc, loader, ebpf_function_name)) in successful_traces.into_iter().enumerate() {
            // Use the corresponding pre-allocated trace ID
            let trace_id = pre_allocated_trace_ids[index];

            let created_trace_id = session.trace_manager.add_trace_with_id(
                trace_id,
                compilation_result.target_info.clone(),
                script.to_string(),
                pc,
                binary_path.clone(),
                target_display.clone(),
                session.target_pid,
                Some(loader),
                ebpf_function_name,
            );

            // Verify that the IDs match (safety check)
            assert_eq!(
                trace_id, created_trace_id,
                "Trace ID mismatch during creation"
            );

            info!(
                "Created trace instance {} for target '{}' at PC 0x{:x}",
                trace_id, target_display, pc
            );

            // Step 7: Try to activate the trace instance
            match session.trace_manager.activate_trace(trace_id) {
                Ok(_) => {
                    info!(
                        "Successfully activated trace {} for target '{}' at PC 0x{:x}",
                        trace_id, target_display, pc
                    );
                    trace_ids.push(trace_id);
                }
                Err(e) => {
                    let error_msg = format!("Failed to activate trace {}: {}", trace_id, e);
                    error!("{}", error_msg);
                    let _ = session.trace_manager.remove_trace(trace_id);

                    // If trace activation failed, mark this PC as failed
                    for result in &mut execution_results {
                        if matches!(result.status, ExecutionStatus::Success)
                            && result.pc_address == pc
                        {
                            result.status =
                                ExecutionStatus::Failed(format!("Uprobe attachment failed: {}", e));
                            // Update the counts since we changed Success to Failed
                            success_count = success_count.saturating_sub(1);
                            failed_count += 1;
                        }
                    }
                }
            }
        }
    } else {
        info!("No successful PCs to create trace instances");
    }

    // Step 8: Recalculate final counts based on actual execution results
    // This ensures accuracy after any trace activation failures
    let final_success_count = execution_results
        .iter()
        .filter(|r| matches!(r.status, ExecutionStatus::Success))
        .count();
    let final_failed_count = execution_results
        .iter()
        .filter(|r| matches!(r.status, ExecutionStatus::Failed(_)))
        .count();
    let final_total_count = execution_results.len();

    // Step 9: Return detailed compilation results
    // Note: We no longer return an error when all targets fail
    // Instead, we return the detailed failure information for UI display
    if final_success_count == 0 && final_failed_count > 0 {
        warn!(
            "All {} targets failed to compile or attach, but returning detailed results",
            final_failed_count
        );
    }

    // Debug: Log all execution results before returning
    info!("Final execution results summary:");
    for (i, result) in execution_results.iter().enumerate() {
        info!(
            "  Result {}: {} at 0x{:x} in {} - {:?}",
            i,
            result.target_name,
            result.pc_address,
            std::path::Path::new(&result.binary_path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown"),
            result.status
        );
    }

    let details = ScriptCompilationDetails {
        trace_ids, // List of generated trace IDs
        results: execution_results,
        total_count: final_total_count,
        success_count: final_success_count,
        failed_count: final_failed_count,
    };

    info!(
        "Script compilation completed: {}/{} PC targets successful, {}/{} failed",
        final_success_count, final_total_count, final_failed_count, final_total_count
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

    // Step 1: Validate process analyzer
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;

    let binary_path_string = if let Some(main_module) = process_analyzer.get_main_executable() {
        main_module.path.clone()
    } else {
        return Err(anyhow::anyhow!("No main executable found in process"));
    };

    // Step 2: Use unified compilation interface with ProcessAnalyzer
    let compilation_result = ghostscope_compiler::compile_script(
        script,
        process_analyzer,
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

use crate::core::GhostSession;
use anyhow::{Context, Result};
use ghostscope_loader::{GhostScopeLoader, ProcModuleOffsetsValue};
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use tracing::{error, info, warn};

/// Create and attach a loader for a single uprobe configuration
async fn create_and_attach_loader(
    config: &ghostscope_compiler::UProbeConfig,
    target_pid: Option<u32>,
) -> Result<GhostScopeLoader> {
    // Create a new loader for this uprobe configuration
    info!(
        "Creating new eBPF loader with {} bytes of bytecode for trace_id {}",
        config.ebpf_bytecode.len(),
        config.assigned_trace_id
    );

    let mut loader = GhostScopeLoader::new(&config.ebpf_bytecode)
        .context("Failed to create eBPF loader for uprobe config")?;

    // Set the TraceContext for trace event parsing
    info!(
        "Setting TraceContext for loader: {} strings, {} variables",
        config.trace_context.string_count(),
        config.trace_context.variable_name_count()
    );
    loader.set_trace_context(config.trace_context.clone());

    if let Some(uprobe_offset) = config.uprobe_offset {
        if let Some(ref function_name) = config.function_name {
            // Function-based attachment with calculated offset
            info!(
                "Attaching to function '{}' at offset 0x{:x} in {} using eBPF function '{}'",
                function_name, uprobe_offset, config.binary_path, config.ebpf_function_name
            );

            loader.attach_uprobe_with_program_name(
                &config.binary_path,
                function_name,
                Some(uprobe_offset),
                target_pid.map(|p| p as i32),
                Some(&config.ebpf_function_name),
            )?;
        } else {
            // Direct address attachment
            info!(
                "Attaching to address 0x{:x} in {} using eBPF function '{}'",
                uprobe_offset, config.binary_path, config.ebpf_function_name
            );

            loader.attach_uprobe_with_program_name(
                &config.binary_path,
                &format!("0x{:x}", uprobe_offset), // Use address as function name
                Some(uprobe_offset),
                target_pid.map(|p| p as i32),
                Some(&config.ebpf_function_name),
            )?;
        }
    } else {
        return Err(anyhow::anyhow!("No uprobe offset available in config"));
    }

    Ok(loader)
}

/// Compile and load script specifically for TUI mode with detailed execution results
/// This function collects detailed results for each PC/target and returns comprehensive status
pub async fn compile_and_load_script_for_tui(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<ScriptCompilationDetails> {
    // Step 1: Validate process analyzer availability
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;

    // Step 2: Get binary path early for error handling
    let binary_path = if let Some(main_module) = process_analyzer.get_main_executable() {
        main_module.path.clone()
    } else {
        return Err(anyhow::anyhow!("No main executable found in process"));
    };

    // Step 3: Get starting trace ID from trace manager
    let starting_trace_id = session.trace_manager.get_next_trace_id();

    // Step 4: Use provided compile options directly
    // Compile script using DWARF analyzer with proper starting trace ID
    let compilation_result = match ghostscope_compiler::compile_script(
        script,
        process_analyzer,
        session.target_pid,
        Some(starting_trace_id), // Use trace_manager's next available ID
        compile_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Script compilation failed: {}", e);
            return Ok(ScriptCompilationDetails {
                trace_ids: vec![],
                results: vec![ScriptExecutionResult {
                    pc_address: 0,
                    target_name: "compilation_failed".to_string(),
                    binary_path,
                    status: ExecutionStatus::Failed(format!("Compilation error: {}", e)),
                }],
                total_count: 1,
                success_count: 0,
                failed_count: 1,
            });
        }
    };

    info!(
        "✓ Script compilation successful: {} uprobe configs generated",
        compilation_result.uprobe_configs.len()
    );

    // Step 4: Process compilation results and create execution details
    let mut results = Vec::new();
    let mut trace_ids = Vec::new();
    let mut success_count = 0;
    let mut failed_count = 0;

    // Process successful configurations
    for config in compilation_result.uprobe_configs.iter() {
        let trace_id = config.assigned_trace_id; // Use the trace_id assigned by compiler
        trace_ids.push(trace_id);

        results.push(ScriptExecutionResult {
            pc_address: config.function_address.unwrap_or(0),
            target_name: config
                .function_name
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", config.function_address.unwrap_or(0))),
            binary_path: config.binary_path.clone(),
            status: ExecutionStatus::Success,
        });
        success_count += 1;
    }

    // Process failed targets
    for failed in &compilation_result.failed_targets {
        results.push(ScriptExecutionResult {
            pc_address: failed.pc_address,
            target_name: failed.target_name.clone(),
            binary_path: binary_path.clone(),
            status: ExecutionStatus::Failed(failed.error_message.clone()),
        });
        failed_count += 1;
    }

    info!(
        "Compilation summary: {} successful, {} failed",
        success_count, failed_count
    );

    // Prepare ASLR offsets map items once (for -p mode)
    let mut offsets_items: Vec<(u64, ProcModuleOffsetsValue)> = Vec::new();
    if let Some(pid) = session.target_pid {
        match process_analyzer.compute_section_offsets() {
            Ok(items) => {
                // Log cookie ↔ module path mapping for clarity
                for (path, cookie, off) in &items {
                    let cookie_hi = (*cookie >> 32) as u32;
                    let cookie_lo = (*cookie & 0xffff_ffff) as u32;
                    info!(
                        "Offsets entry: pid={} module='{}' cookie=0x{:08x}{:08x} text=0x{:x} rodata=0x{:x} data=0x{:x} bss=0x{:x}",
                        pid,
                        path.display(),
                        cookie_hi,
                        cookie_lo,
                        off.text,
                        off.rodata,
                        off.data,
                        off.bss
                    );
                }
                offsets_items = items
                    .into_iter()
                    .map(|(_path, cookie, off)| {
                        (
                            cookie,
                            ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss),
                        )
                    })
                    .collect();
                info!(
                    "Computed {} module offset entries for PID {}",
                    offsets_items.len(),
                    pid
                );
            }
            Err(e) => {
                warn!(
                    "Failed to compute section offsets: {} (globals may show OffsetsUnavailable)",
                    e
                );
            }
        }
    }

    // Step 5: If we have successful configurations, attach uprobes and register traces
    if !compilation_result.uprobe_configs.is_empty() {
        // Prepare uprobe configurations with binary path
        let mut uprobe_configs = compilation_result.uprobe_configs;
        for config in uprobe_configs.iter_mut() {
            config.binary_path = binary_path.clone();
        }

        info!("Attaching {} uprobe configurations", uprobe_configs.len());
        for (i, config) in uprobe_configs.iter().enumerate() {
            info!(
                "  Config {}: {:?} -> 0x{:x} (trace_id: {})",
                i,
                config
                    .function_name
                    .as_ref()
                    .unwrap_or(&format!("0x{:x}", config.function_address.unwrap_or(0))),
                config.uprobe_offset.unwrap_or(0),
                config.assigned_trace_id
            );
        }

        // Step 6: Attach uprobes individually and create traces with their own loaders
        let mut attached_count = 0;
        for config in &uprobe_configs {
            let target_display = config
                .function_name
                .clone()
                .unwrap_or_else(|| format!("0x{:x}", config.function_address.unwrap_or(0)));

            // Create individual loader for this config
            match create_and_attach_loader(config, session.target_pid).await {
                Ok(mut loader) => {
                    // Populate proc_module_offsets for this loader (if available)
                    if let Some(pid) = session.target_pid {
                        if !offsets_items.is_empty() {
                            if let Err(e) = loader.populate_proc_module_offsets(pid, &offsets_items)
                            {
                                warn!("Failed to populate proc_module_offsets: {}", e);
                            } else {
                                info!(
                                    "✓ Populated proc_module_offsets ({} entries) for PID {}",
                                    offsets_items.len(),
                                    pid
                                );
                            }
                        }
                    }

                    info!(
                        "✓ Successfully attached uprobe for trace_id {}",
                        config.assigned_trace_id
                    );

                    // Register trace with its own loader
                    let _registered_trace_id = session.trace_manager.add_trace_with_id(
                        config.assigned_trace_id,
                        target_display.clone(),               // target
                        script.to_string(),                   // script_content
                        config.function_address.unwrap_or(0), // pc
                        config.binary_path.clone(),           // binary_path
                        target_display.clone(),               // target_display
                        session.target_pid,                   // target_pid
                        Some(loader),                         // Each trace gets its own loader
                        format!(
                            "gs_{}_{}_{}",
                            session.target_pid.unwrap_or(0),
                            target_display,
                            config.assigned_trace_id
                        ), // ebpf_function_name
                    );

                    // Enable the trace immediately since we just attached it
                    if let Err(e) = session.trace_manager.enable_trace(config.assigned_trace_id) {
                        warn!(
                            "Failed to enable trace_id {}: {}",
                            config.assigned_trace_id, e
                        );
                    } else {
                        info!(
                            "✓ Registered and enabled trace_id {} with trace manager",
                            config.assigned_trace_id
                        );
                        attached_count += 1;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to attach uprobe for trace_id {}: {}",
                        config.assigned_trace_id, e
                    );
                    // Update corresponding result to failed
                    for result in &mut results {
                        if result.pc_address == config.function_address.unwrap_or(0) {
                            result.status =
                                ExecutionStatus::Failed(format!("Failed to attach uprobe: {}", e));
                            success_count -= 1;
                            failed_count += 1;
                            break;
                        }
                    }
                }
            }
        }

        if attached_count > 0 {
            info!(
                "✓ Successfully attached {} of {} uprobes",
                attached_count,
                uprobe_configs.len()
            );
        } else {
            warn!("No uprobes were successfully attached");
        }
    }

    Ok(ScriptCompilationDetails {
        trace_ids,
        results,
        total_count: success_count + failed_count,
        success_count,
        failed_count,
    })
}

/// Compile and load script for command line mode using session.command_loaders
pub async fn compile_and_load_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
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

    // Step 2: Get starting trace ID from trace manager and use unified compilation interface with DwarfAnalyzer
    let starting_trace_id = session.trace_manager.get_next_trace_id();

    // Use provided compile options directly
    let compilation_result = match ghostscope_compiler::compile_script(
        script,
        process_analyzer,
        session.target_pid,
        Some(starting_trace_id), // Use trace_manager's next available ID
        compile_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            error!("Script compilation failed: {}", e);
            return Err(anyhow::anyhow!(
                "Script compilation failed: {}. Please check your script syntax and try again.",
                e
            ));
        }
    };

    info!(
        "✓ Script compilation successful: {} trace points found, {} uprobe configs generated",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len()
    );
    info!("Target info: {}", compilation_result.target_info);

    // Report failed targets if any
    if !compilation_result.failed_targets.is_empty() {
        warn!("Some targets failed to compile:");
        for failed in &compilation_result.failed_targets {
            warn!(
                "  {} at 0x{:x}: {}",
                failed.target_name, failed.pc_address, failed.error_message
            );
        }
    }

    // Pre-compute ASLR offsets once (for -p mode)
    let mut offsets_items: Vec<(u64, ProcModuleOffsetsValue)> = Vec::new();
    if let Some(pid) = session.target_pid {
        match process_analyzer.compute_section_offsets() {
            Ok(items) => {
                offsets_items = items
                    .into_iter()
                    .map(|(_path, cookie, off)| {
                        (
                            cookie,
                            ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss),
                        )
                    })
                    .collect();
                info!(
                    "Computed {} module offset entries for PID {}",
                    offsets_items.len(),
                    pid
                );
            }
            Err(e) => {
                warn!(
                    "Failed to compute section offsets: {} (globals may show OffsetsUnavailable)",
                    e
                );
            }
        }
    }

    // Step 3: Prepare and attach uprobe configurations
    let mut uprobe_configs = compilation_result.uprobe_configs;

    for config in uprobe_configs.iter_mut() {
        config.binary_path = binary_path_string.clone();
    }

    if uprobe_configs.is_empty() {
        // Check if we have debug info - this is checked during module loading
        let available_functions = session.list_functions();

        if available_functions.is_empty() {
            return Err(anyhow::anyhow!(
                "No debug information found in any module!\n\
                \n\
                The target binary and its libraries are stripped or compiled without debug symbols.\n\
                GhostScope requires debug information (DWARF) to:\n\
                - Locate functions by name\n\
                - Analyze variable types and locations\n\
                - Map source lines to addresses\n\
                \n\
                Solutions:\n\
                1. Recompile your target with -g flag: gcc -g your_program.c -o your_program\n\
                2. Install debug symbol packages (e.g., libc6-dbg on Debian/Ubuntu)\n\
                3. For stripped binaries, use objcopy to create separate debug files:\n\
                   objcopy --only-keep-debug binary binary.debug\n\
                   objcopy --add-gnu-debuglink=binary.debug binary"
            ));
        }

        return Err(anyhow::anyhow!(
            "No uprobe configurations created - the functions referenced in your script were not found.\n\
            \n\
            Possible reasons:\n\
            - Function names are misspelled (check available functions below)\n\
            - Functions don't exist in the target binary\n\
            - Functions are from libraries that aren't loaded yet\n\
            \n\
            Available functions (first 10):\n{}\n\
            \n\
            Tip: Run GhostScope in TUI mode to browse all available functions",
            available_functions.iter().take(10).map(|f| format!("  - {}", f)).collect::<Vec<_>>().join("\n")
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

    // Step 4: Attach uprobes individually and create traces with their own loaders
    let mut attached_count = 0;
    for config in &uprobe_configs {
        let target_display = config
            .function_name
            .clone()
            .unwrap_or_else(|| format!("0x{:x}", config.function_address.unwrap_or(0)));

        // Create individual loader for this config
        match create_and_attach_loader(config, session.target_pid).await {
            Ok(mut loader) => {
                // Populate proc_module_offsets for this loader (if available)
                if let Some(pid) = session.target_pid {
                    if !offsets_items.is_empty() {
                        if let Err(e) = loader.populate_proc_module_offsets(pid, &offsets_items) {
                            warn!("Failed to populate proc_module_offsets: {}", e);
                        } else {
                            info!(
                                "✓ Populated proc_module_offsets ({} entries) for PID {}",
                                offsets_items.len(),
                                pid
                            );
                        }
                    }
                }

                info!(
                    "✓ Successfully attached uprobe for trace_id {}",
                    config.assigned_trace_id
                );

                // Register trace with its own loader (CLI mode)
                let _registered_trace_id = session.trace_manager.add_trace_with_id(
                    config.assigned_trace_id,
                    target_display.clone(),               // target
                    script.to_string(),                   // script_content
                    config.function_address.unwrap_or(0), // pc
                    config.binary_path.clone(),           // binary_path
                    target_display.clone(),               // target_display
                    session.target_pid,                   // target_pid
                    Some(loader),                         // Each trace gets its own loader
                    format!(
                        "gs_{}_{}_{}",
                        session.target_pid.unwrap_or(0),
                        target_display,
                        config.assigned_trace_id
                    ), // ebpf_function_name
                );

                // Enable the trace immediately since we just attached it
                if let Err(e) = session.trace_manager.enable_trace(config.assigned_trace_id) {
                    warn!(
                        "Failed to enable trace_id {}: {}",
                        config.assigned_trace_id, e
                    );
                } else {
                    info!(
                        "✓ Registered and enabled trace_id {} with trace manager",
                        config.assigned_trace_id
                    );
                    attached_count += 1;
                }
            }
            Err(e) => {
                error!(
                    "Failed to attach uprobe for trace_id {}: {}",
                    config.assigned_trace_id, e
                );
                return Err(anyhow::anyhow!(
                    "Failed to attach uprobe: {}. Possible reasons: \
                    1. Need root permissions (run with sudo), \
                    2. Target binary doesn't exist or lacks debug info, \
                    3. Process not running or PID invalid, \
                    4. Function addresses not accessible",
                    e
                ));
            }
        }
    }

    if attached_count > 0 {
        info!(
            "✓ Successfully attached {} of {} uprobes",
            attached_count,
            uprobe_configs.len()
        );
    } else {
        return Err(anyhow::anyhow!("No uprobes were successfully attached"));
    }

    Ok(())
}

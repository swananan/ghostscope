use crate::core::GhostSession;
use anyhow::{Context, Result};
use ghostscope_loader::GhostScopeLoader;
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use tracing::{error, info, warn};

fn map_compile_error_message(e: &ghostscope_compiler::CompileError) -> String {
    e.user_message().into_owned()
}

fn pid_alias_runtime_pid(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Option<u32> {
    let resolved_target_ns = session
        .pid_views()
        .and_then(|pid_views| Some((pid_views.pid_ns_dev()?, pid_views.pid_ns_inode()?)));
    let proc_offsets_ns = compile_options
        .proc_offsets_pid_ns
        .and_then(|pid_ns| pid_ns.helper_dev_inode());

    // When proc offsets are configured against the resolved target namespace, the
    // eBPF-side runtime key is the namespace-local TGID rather than the host-visible
    // PID used for `/proc` prefill.
    if let (Some(pid_views), Some(target_ns)) = (session.pid_views(), resolved_target_ns) {
        if proc_offsets_ns == Some(target_ns) && pid_views.container_pid.is_some() {
            return pid_views.container_pid;
        }
    }

    match compile_options.pid_filter_spec {
        Some(ghostscope_compiler::PidFilterSpec::NamespaceTgid { filter_pid, .. }) => {
            Some(filter_pid)
        }
        Some(ghostscope_compiler::PidFilterSpec::HostTgid { filter_pid }) => Some(filter_pid),
        None => session.host_pid(),
    }
}

fn pid_alias_pair(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Option<(u32, u32)> {
    let proc_pid = session.proc_pid()?;
    let runtime_pid = pid_alias_runtime_pid(session, compile_options)?;
    (runtime_pid != proc_pid).then_some((runtime_pid, proc_pid))
}

fn apply_pid_alias_for_session(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) {
    if let Some((runtime_pid, proc_pid)) = pid_alias_pair(session, compile_options) {
        match ghostscope_process::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid) {
            Ok(()) => info!(
                "✓ Applied PID alias runtime_pid={} -> proc_pid={}",
                runtime_pid, proc_pid
            ),
            Err(e) => warn!(
                "Failed to write PID alias runtime_pid={} -> proc_pid={}: {}",
                runtime_pid, proc_pid, e
            ),
        }
    }
}

fn apply_cached_offsets_for_session_pid(
    session: &GhostSession,
    _compile_options: &ghostscope_compiler::CompileOptions,
) {
    if let Some(proc_pid) = session.proc_pid() {
        let items = {
            let coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            coordinator
                .cached_offsets_with_paths_for_pid(proc_pid)
                .map(|entries| entries.to_vec())
        };
        if let Some(items) = items {
            use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
            let adapted: Vec<(u64, ProcModuleOffsetsValue)> = items
                .iter()
                .map(|entry| {
                    (
                        entry.cookie,
                        ProcModuleOffsetsValue::new(
                            entry.offsets.text,
                            entry.offsets.rodata,
                            entry.offsets.data,
                            entry.offsets.bss,
                            entry.base,
                            entry.size,
                        ),
                    )
                })
                .collect();

            if let Err(e) =
                ghostscope_process::pinned_bpf_maps::insert_offsets_for_pid(proc_pid, &adapted)
            {
                warn!(
                    "Failed to write cached offsets to pinned map for PID {}: {}",
                    proc_pid, e
                );
            } else {
                info!(
                    "✓ Applied {} cached offsets to pinned map for PID {}",
                    adapted.len(),
                    proc_pid
                );
            }
        }
    }
}

/// Create and attach a loader for a single uprobe configuration
async fn create_and_attach_loader(
    config: &ghostscope_compiler::UProbeConfig,
    attach_pid: Option<u32>,
    session: &mut crate::core::GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<GhostScopeLoader> {
    // Create a new loader for this uprobe configuration
    info!(
        "Creating new eBPF loader with {} bytes of bytecode for trace_id {}",
        config.ebpf_bytecode.len(),
        config.assigned_trace_id
    );

    // Ensure the per-process pinned proc_module_offsets map exists before creating the loader
    let max_entries = session
        .config
        .as_ref()
        .map(|c| c.ebpf_config.proc_module_offsets_max_entries as u32)
        .unwrap_or(4096);
    let pin_path = ghostscope_process::pinned_bpf_maps::proc_offsets_pin_path()
        .context("Failed to resolve pinned proc_module_offsets map path")?;
    if let Err(e) =
        ghostscope_process::pinned_bpf_maps::ensure_pinned_proc_offsets_exists(max_entries)
    {
        error!(
            "Failed to ensure pinned proc_module_offsets map exists at {} ({} entries): {:#}",
            pin_path.display(),
            max_entries,
            e
        );
        return Err(e.context(format!(
            "Unable to prepare pinned proc_module_offsets map at {}",
            pin_path.display()
        )));
    }
    let alias_pin_path = ghostscope_process::pinned_bpf_maps::pid_aliases_pin_path()
        .context("Failed to resolve pinned pid_aliases map path")?;
    if let Err(e) =
        ghostscope_process::pinned_bpf_maps::ensure_pinned_pid_aliases_exists(max_entries)
    {
        error!(
            "Failed to ensure pinned pid_aliases map exists at {} ({} entries): {:#}",
            alias_pin_path.display(),
            max_entries,
            e
        );
        return Err(e.context(format!(
            "Unable to prepare pinned pid_aliases map at {}",
            alias_pin_path.display()
        )));
    }

    let mut loader = GhostScopeLoader::new(&config.ebpf_bytecode)
        .context("Failed to create eBPF loader for uprobe config")?;

    // Apply PerfEventArray page count from config (for kernels without RingBuf or forced Perf mode)
    if let Some(cfg) = &session.config {
        loader.set_perf_page_count(cfg.ebpf_config.perf_page_count);
        tracing::info!(
            "Configured PerfEventArray page count: {} pages per CPU",
            cfg.ebpf_config.perf_page_count
        );
    }

    // Set the TraceContext for trace event parsing
    info!(
        "Setting TraceContext for loader: {} strings, {} variables",
        config.trace_context.string_count(),
        config.trace_context.variable_name_count()
    );
    loader.set_trace_context(config.trace_context.clone());
    loader
        .populate_backtrace_unwind_rows(&config.backtrace_unwind_rows)
        .context("Failed to populate DWARF backtrace unwind rows")?;
    loader
        .register_backtrace_tail_call_program(
            config
                .backtrace_tail_call_program
                .as_ref()
                .map(|program| program.step_program_name.as_str()),
        )
        .context("Failed to register bt tail-call program")?;

    // In -t mode (no attach PID), perform module prefill once per session and apply to this loader
    if attach_pid.is_none() {
        let (prefilled, entries) = {
            let mut coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            let prefilled = coordinator
                .ensure_prefill_module(&config.binary_path)
                .unwrap_or(0);
            let entries = coordinator.cached_offsets_for_module(&config.binary_path);
            (prefilled, entries)
        };
        tracing::info!(
            "Coordinator cached offsets for {} pid(s) for module {}",
            prefilled,
            config.binary_path
        );
        // Apply cached offsets for this module to the loader's map
        if !entries.is_empty() {
            use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
            // Group by pid for efficient batch insert
            use std::collections::HashMap;
            let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> = HashMap::new();
            for (pid, cookie, off, base, size) in entries {
                by_pid.entry(pid).or_default().push((
                    cookie,
                    ProcModuleOffsetsValue::new(
                        off.text, off.rodata, off.data, off.bss, base, size,
                    ),
                ));
            }
            let mut total = 0usize;
            for (pid, items) in by_pid {
                if let Err(e) =
                    ghostscope_process::pinned_bpf_maps::insert_offsets_for_pid(pid, &items)
                {
                    tracing::warn!(
                        "Failed to write offsets to pinned map for PID {}: {}",
                        pid,
                        e
                    );
                } else {
                    total += items.len();
                }
                // Loader no longer manages offsets map; only pinned map is authoritative
            }
            tracing::info!(
                "Applied {} cached offset entries to pinned map for module {}",
                total,
                config.binary_path
            );
        }
    }

    apply_pid_alias_for_session(session, compile_options);
    // Populate PID-mode module offsets before attaching. Once the uprobe is
    // attached, a running target can hit it immediately.
    apply_cached_offsets_for_session_pid(session, compile_options);

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
                attach_pid.map(|p| p as i32),
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
                &format!("0x{uprobe_offset:x}"), // Use address as function name
                Some(uprobe_offset),
                attach_pid.map(|p| p as i32),
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
    let fallback_host_pid = session.host_pid();

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
        fallback_host_pid,
        Some(starting_trace_id), // Use trace_manager's next available ID
        compile_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            let friendly = map_compile_error_message(&e);
            error!("Script compilation failed: {}", friendly);
            return Ok(ScriptCompilationDetails {
                trace_ids: vec![],
                results: vec![ScriptExecutionResult {
                    pc_address: 0,
                    target_name: "compilation_failed".to_string(),
                    binary_path,
                    status: ExecutionStatus::Failed(format!("Compilation error: {friendly}")),
                    source_file: None,
                    source_line: None,
                    is_inline: None,
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

        // Compute source location and inline classification for this target
        let (source_file, source_line, is_inline) = {
            let addr = config.function_address.unwrap_or(0);
            let module_address = ghostscope_dwarf::ModuleAddress::new(
                std::path::PathBuf::from(&config.binary_path),
                addr,
            );
            let src = process_analyzer.lookup_source_location(&module_address);
            let inline = process_analyzer.is_inline_at(&module_address);
            (
                src.as_ref().map(|s| s.file_path.clone()),
                src.as_ref().map(|s| s.line_number),
                inline,
            )
        };

        results.push(ScriptExecutionResult {
            pc_address: config.function_address.unwrap_or(0),
            target_name: config
                .function_name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", config.function_address.unwrap_or(0))),
            binary_path: config.binary_path.clone(),
            status: ExecutionStatus::Success,
            source_file,
            source_line,
            is_inline,
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
            source_file: None,
            source_line: None,
            is_inline: None,
        });
        failed_count += 1;
    }

    info!(
        "Compilation summary: {} successful, {} failed",
        success_count, failed_count
    );

    // Ensure -p offsets are cached once per session
    if let Some(proc_pid) = session.proc_pid() {
        let result = {
            let mut coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            coordinator.ensure_prefill_pid(proc_pid)
        };
        match result {
            Ok(count) => info!(
                "Coordinator cached {} module offset entries for PID {}",
                count, proc_pid
            ),
            Err(e) => warn!(
                "Failed to compute section offsets via coordinator: {} (globals may show OffsetsUnavailable)",
                e
            ),
        }
    }

    // Step 5: If we have successful configurations, attach uprobes and register traces
    if !compilation_result.uprobe_configs.is_empty() {
        // Prepare uprobe configurations with binary path
        let uprobe_configs = compilation_result.uprobe_configs;

        info!("Attaching {} uprobe configurations", uprobe_configs.len());
        for (i, config) in uprobe_configs.iter().enumerate() {
            let fallback_name = format!("{:#x}", config.function_address.unwrap_or(0));
            info!(
                "  Config {}: {:?} -> 0x{:x} (trace_id: {})",
                i,
                config.function_name.as_ref().unwrap_or(&fallback_name),
                config.uprobe_offset.unwrap_or(0),
                config.assigned_trace_id
            );
        }

        // Step 6: Attach uprobes individually and create traces with their own loaders
        let mut attached_count = 0;
        for config in &uprobe_configs {
            let addr_disp = config.function_address.unwrap_or(0);
            let target_display = config
                .function_name
                .clone()
                .unwrap_or_else(|| format!("{addr_disp:#x}"));

            // Create individual loader for this config
            match create_and_attach_loader(config, session.attach_pid(), session, compile_options)
                .await
            {
                Ok(loader) => {
                    info!(
                        "✓ Successfully attached uprobe for trace_id {}",
                        config.assigned_trace_id
                    );

                    // Register trace with its own loader
                    let _registered_trace_id = session.trace_manager.add_trace_with_id(
                        crate::trace::manager::AddTraceParams {
                            trace_id: config.assigned_trace_id,
                            target: target_display.clone(),
                            script_content: script.to_string(),
                            pc: config.function_address.unwrap_or(0),
                            binary_path: config.binary_path.clone(),
                            target_display: target_display.clone(),
                            pid_context: crate::trace::instance::TracePidContext {
                                attach_pid: session.attach_pid(),
                                host_pid: session.host_pid(),
                                proc_pid: session.proc_pid(),
                            },
                            loader: Some(loader),
                            ebpf_function_name: format!(
                                "gs_{}_{}_{}",
                                session.host_pid().unwrap_or(0),
                                target_display,
                                config.assigned_trace_id
                            ),
                            address_global_index: config.resolved_address_index,
                        },
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
                        "Failed to attach uprobe for trace_id {}: {:#}",
                        config.assigned_trace_id, e
                    );
                    tracing::info!(
                        "Attachment hints: check privileges, target binary availability, PID validity, and function addresses if needed."
                    );
                    // Update corresponding result to failed
                    for result in &mut results {
                        if result.pc_address == config.function_address.unwrap_or(0) {
                            result.status =
                                ExecutionStatus::Failed(format!("Failed to attach uprobe: {e:#}"));
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

/// Compile a script for command line mode without attaching uprobes.
pub fn compile_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<ghostscope_compiler::CompilationResult> {
    let fallback_host_pid = session.host_pid();

    info!("Starting unified script compilation with DWARF integration...");

    // Step 1: Validate process analyzer
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;

    // Step 2: Get starting trace ID from trace manager and use unified compilation interface with DwarfAnalyzer
    let starting_trace_id = session.trace_manager.get_next_trace_id();

    // Use provided compile options directly
    let compilation_result = match ghostscope_compiler::compile_script(
        script,
        process_analyzer,
        fallback_host_pid,
        Some(starting_trace_id), // Use trace_manager's next available ID
        compile_options,
    ) {
        Ok(result) => result,
        Err(e) => {
            let friendly = map_compile_error_message(&e);
            error!("Script compilation failed: {}", friendly);
            return Err(anyhow::anyhow!(
                "Script compilation failed: {}. Please check your script syntax and try again.",
                friendly
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

    Ok(compilation_result)
}

/// Compile and load script for command line mode using session.command_loaders
pub async fn compile_and_load_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<()> {
    let compilation_result = compile_script_for_cli(script, session, compile_options)?;

    // Ensure -p offsets are cached once per session
    if let Some(proc_pid) = session.proc_pid() {
        let result = {
            let mut coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            coordinator.ensure_prefill_pid(proc_pid)
        };
        match result {
            Ok(count) => info!(
                "Coordinator cached {} module offset entries for PID {}",
                count, proc_pid
            ),
            Err(e) => warn!(
                "Failed to compute section offsets via coordinator: {} (globals may show OffsetsUnavailable)",
                e
            ),
        }
    }

    // Step 3: Prepare and attach uprobe configurations
    let ghostscope_compiler::CompilationResult {
        uprobe_configs,
        failed_targets,
        ..
    } = compilation_result;

    if uprobe_configs.is_empty() {
        // If we had resolved targets but all failed to compile, surface the real compile errors
        if !failed_targets.is_empty() {
            let mut details = String::new();
            for failed in &failed_targets {
                let _ = std::fmt::Write::write_fmt(
                    &mut details,
                    format_args!(
                        "  - {} at 0x{:x}: {}\n",
                        failed.target_name, failed.pc_address, failed.error_message
                    ),
                );
            }
            let full = format!(
                "No uprobe configurations created because all {} target(s) failed to compile.\n\nFailed targets:\n{}\n\nTip: fix the reported compile-time errors above (e.g., avoid struct/union/array arithmetic; select a scalar field or use '&expr + <non-negative literal>' in an alias/address context).",
                failed_targets.len(),
                details
            );
            // Log the full multi-line error to ensure it appears in stderr when logging is enabled
            error!("{}", full);
            return Err(anyhow::anyhow!(full));
        }

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
            available_functions.iter().take(10).map(|f| format!("  - {f}")).collect::<Vec<_>>().join("\n")
        ));
    }

    info!("Attaching {} uprobe configurations", uprobe_configs.len());
    for (i, config) in uprobe_configs.iter().enumerate() {
        let fallback_name = format!("{:#x}", config.function_address.unwrap_or(0));
        info!(
            "  Config {}: {:?} -> 0x{:x}",
            i,
            config.function_name.as_ref().unwrap_or(&fallback_name),
            config.uprobe_offset.unwrap_or(0)
        );
    }

    // Step 4: Attach uprobes individually and create traces with their own loaders
    let mut attached_count = 0;
    for config in &uprobe_configs {
        let addr_disp = config.function_address.unwrap_or(0);
        let target_display = config
            .function_name
            .clone()
            .unwrap_or_else(|| format!("{addr_disp:#x}"));

        // Create individual loader for this config
        match create_and_attach_loader(config, session.attach_pid(), session, compile_options).await
        {
            Ok(loader) => {
                info!(
                    "✓ Successfully attached uprobe for trace_id {}",
                    config.assigned_trace_id
                );

                // Register trace with its own loader (CLI mode)
                let _registered_trace_id = session.trace_manager.add_trace_with_id(
                    crate::trace::manager::AddTraceParams {
                        trace_id: config.assigned_trace_id,
                        target: target_display.clone(),
                        script_content: script.to_string(),
                        pc: config.function_address.unwrap_or(0),
                        binary_path: config.binary_path.clone(),
                        target_display: target_display.clone(),
                        pid_context: crate::trace::instance::TracePidContext {
                            attach_pid: session.attach_pid(),
                            host_pid: session.host_pid(),
                            proc_pid: session.proc_pid(),
                        },
                        loader: Some(loader),
                        ebpf_function_name: format!(
                            "gs_{}_{}_{}",
                            session.host_pid().unwrap_or(0),
                            target_display,
                            config.assigned_trace_id
                        ),
                        address_global_index: config.resolved_address_index,
                    },
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
                    "Failed to attach uprobe for trace_id {}: {:#}",
                    config.assigned_trace_id, e
                );
                tracing::info!(
                    "Attachment hints: check privileges, target binary availability, PID validity, and function addresses if needed."
                );
                return Err(e.context(format!(
                    "Failed to attach uprobe for trace_id {}",
                    config.assigned_trace_id
                )));
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

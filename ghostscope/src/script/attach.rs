use crate::core::GhostSession;
use anyhow::{Context, Result};
use ghostscope_loader::GhostScopeLoader;
use tracing::{error, info, warn};

use super::runtime_maps::{apply_cached_offsets_for_session_pid, apply_pid_alias_for_session};

pub(super) fn target_display(config: &ghostscope_compiler::UProbeConfig) -> String {
    let addr_disp = config.function_address.unwrap_or(0);
    config
        .function_name
        .clone()
        .unwrap_or_else(|| format!("{addr_disp:#x}"))
}

pub(super) fn log_uprobe_configs(
    uprobe_configs: &[ghostscope_compiler::UProbeConfig],
    include_trace_id: bool,
) {
    info!("Attaching {} uprobe configurations", uprobe_configs.len());
    for (i, config) in uprobe_configs.iter().enumerate() {
        let fallback_name = format!("{:#x}", config.function_address.unwrap_or(0));
        if include_trace_id {
            info!(
                "  Config {}: {:?} -> 0x{:x} (trace_id: {})",
                i,
                config.function_name.as_ref().unwrap_or(&fallback_name),
                config.uprobe_offset.unwrap_or(0),
                config.assigned_trace_id
            );
        } else {
            info!(
                "  Config {}: {:?} -> 0x{:x}",
                i,
                config.function_name.as_ref().unwrap_or(&fallback_name),
                config.uprobe_offset.unwrap_or(0)
            );
        }
    }
}

pub(super) fn log_attachment_hints() {
    tracing::info!(
        "Attachment hints: check privileges, target binary availability, PID validity, and function addresses if needed."
    );
}

/// Create and attach a loader for a single uprobe configuration.
pub(super) async fn create_and_attach_loader(
    config: &ghostscope_compiler::UProbeConfig,
    attach_pid: Option<u32>,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<GhostScopeLoader> {
    info!(
        "Creating new eBPF loader with {} bytes of bytecode for trace_id {}",
        config.ebpf_bytecode.len(),
        config.assigned_trace_id
    );

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

    let range_meta_pin_path =
        ghostscope_process::pinned_bpf_maps::proc_module_range_meta_pin_path()
            .context("Failed to resolve pinned proc_module_range_meta map path")?;
    if let Err(e) =
        ghostscope_process::pinned_bpf_maps::ensure_pinned_proc_module_ranges_exist(max_entries)
    {
        error!(
            "Failed to ensure pinned module range maps at {} ({} entries): {:#}",
            range_meta_pin_path.display(),
            max_entries,
            e
        );
        return Err(e.context(format!(
            "Unable to prepare pinned module range maps at {}",
            range_meta_pin_path.display()
        )));
    }

    let share_backtrace_cfi_maps = !config.backtrace_module_row_ranges.is_empty();
    if share_backtrace_cfi_maps {
        let unwind_row_entries = compile_options
            .backtrace_unwind_rows_max_entries
            .max(config.backtrace_unwind_rows.len() as u32)
            .max(1);
        let module_entries = u32::try_from(compile_options.proc_module_offsets_max_entries)
            .unwrap_or(u32::MAX)
            .max(1);
        let rows_pin_path = ghostscope_process::pinned_bpf_maps::bt_unwind_rows_pin_path()
            .context("Failed to resolve pinned bt_unwind_rows map path")?;
        if let Err(e) = ghostscope_process::pinned_bpf_maps::ensure_pinned_backtrace_cfi_maps_exist(
            unwind_row_entries,
            module_entries,
        ) {
            error!(
                "Failed to ensure pinned backtrace CFI maps at {} (rows={}, modules={}): {:#}",
                rows_pin_path.display(),
                unwind_row_entries,
                module_entries,
                e
            );
            return Err(e.context(format!(
                "Unable to prepare pinned backtrace CFI maps at {}",
                rows_pin_path.display()
            )));
        }
    }

    let mut loader = GhostScopeLoader::new_with_shared_backtrace_maps(
        &config.ebpf_bytecode,
        share_backtrace_cfi_maps,
    )
    .context("Failed to create eBPF loader for uprobe config")?;

    if let Some(cfg) = &session.config {
        loader.set_perf_page_count(cfg.ebpf_config.perf_page_count);
        tracing::info!(
            "Configured PerfEventArray page count: {} pages per CPU",
            cfg.ebpf_config.perf_page_count
        );
    }

    info!(
        "Setting TraceContext for loader: {} strings, {} variables",
        config.trace_context.string_count(),
        config.trace_context.variable_name_count()
    );
    loader.set_trace_context(config.trace_context.clone());
    loader
        .populate_backtrace_unwind_rows_and_module_row_ranges(
            &config.backtrace_unwind_rows,
            &config.backtrace_module_row_ranges,
        )
        .context("Failed to populate DWARF backtrace unwind rows")?;
    loader
        .register_backtrace_tail_call_program(
            config
                .backtrace_tail_call_program
                .as_ref()
                .map(|program| program.step_program_name.as_str()),
        )
        .context("Failed to register bt tail-call program")?;

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
        if !entries.is_empty() {
            use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
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
            }
            tracing::info!(
                "Applied {} cached offset entries to pinned map for module {}",
                total,
                config.binary_path
            );
        }
    }

    apply_pid_alias_for_session(session, compile_options);
    apply_cached_offsets_for_session_pid(session);

    let Some(uprobe_offset) = config.uprobe_offset else {
        return Err(anyhow::anyhow!("No uprobe offset available in config"));
    };

    if let Some(ref function_name) = config.function_name {
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
        info!(
            "Attaching to address 0x{:x} in {} using eBPF function '{}'",
            uprobe_offset, config.binary_path, config.ebpf_function_name
        );
        loader.attach_uprobe_with_program_name(
            &config.binary_path,
            &format!("0x{uprobe_offset:x}"),
            Some(uprobe_offset),
            attach_pid.map(|p| p as i32),
            Some(&config.ebpf_function_name),
        )?;
    }

    Ok(loader)
}

pub(super) fn register_attached_trace(
    session: &mut GhostSession,
    script: &str,
    config: &ghostscope_compiler::UProbeConfig,
    loader: GhostScopeLoader,
) -> bool {
    let target_display = target_display(config);
    let _registered_trace_id =
        session
            .trace_manager
            .add_trace_with_id(crate::trace::manager::AddTraceParams {
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
            });

    if let Err(e) = session.trace_manager.enable_trace(config.assigned_trace_id) {
        warn!(
            "Failed to enable trace_id {}: {}",
            config.assigned_trace_id, e
        );
        false
    } else {
        info!(
            "✓ Registered and enabled trace_id {} with trace manager",
            config.assigned_trace_id
        );
        true
    }
}

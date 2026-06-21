use crate::trace::TraceManager;
use anyhow::Result;
use ghostscope_debuginfod::DebuginfodClient;
use ghostscope_dwarf::{DwarfAnalyzer, LoadedModuleRuntimeInfo};
use ghostscope_loader::BacktraceUnwindRowsAppendStats;
use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
use ghostscope_process::{runtime_pid_candidates_for_proc, PidOffsetsEntry, ProcessManager};
use ghostscope_protocol::BacktraceUnwindRow;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, warn};

/// Coordinates runtime module refreshes with backtrace CFI publication.
#[derive(Debug, Default, Clone, Copy)]
pub struct BacktraceRuntimeRunner;

impl BacktraceRuntimeRunner {
    pub fn refresh_pid_modules(
        coordinator: &mut ProcessManager,
        proc_pid: u32,
    ) -> Result<Vec<LoadedModuleRuntimeInfo>> {
        coordinator.refresh_prefill_pid(proc_pid)?;

        let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(Vec::new());
        };
        let entries = entries.to_vec();

        Self::record_runtime_pid_alias(coordinator, proc_pid, &[]);
        Self::write_pinned_offsets_for_pid("PID-mode", proc_pid, &entries, &[]);
        Ok(DwarfAnalyzer::runtime_modules_from_pid_offsets(&entries))
    }

    pub fn collect_target_modules(
        coordinator: &mut ProcessManager,
        target_binary: &str,
        extra_runtime_pids: &[u32],
    ) -> Result<Vec<LoadedModuleRuntimeInfo>> {
        coordinator.refresh_prefill_module(target_binary)?;

        let target_pids = coordinator
            .cached_offsets_for_module(target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .filter(|pid| *pid != std::process::id())
            .collect::<BTreeSet<_>>();
        if target_pids.is_empty() {
            return Ok(Vec::new());
        }

        let target_pid_count = target_pids.len();
        let mut modules_by_cookie = BTreeMap::new();
        for pid in target_pids {
            if let Err(error) = coordinator.refresh_prefill_pid(pid) {
                warn!(
                    "Failed to refresh module offsets for target-mode PID {}: {}",
                    pid, error
                );
                continue;
            }

            let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(pid) else {
                continue;
            };
            let entries = entries.to_vec();

            let pid_runtime_pids =
                runtime_pids_for_target_pid(coordinator, pid, target_pid_count, extra_runtime_pids);
            Self::record_runtime_pid_alias(coordinator, pid, &pid_runtime_pids);
            Self::write_pinned_offsets_for_pid("target-mode", pid, &entries, &pid_runtime_pids);
            for entry in &entries {
                modules_by_cookie
                    .entry(entry.cookie)
                    .or_insert_with(|| LoadedModuleRuntimeInfo {
                        module_path: PathBuf::from(&entry.module_path),
                        loaded_address: Some(entry.base),
                        load_bias: Some(entry.offsets.text),
                        size: entry.size,
                    });
            }
        }

        Ok(modules_by_cookie.into_values().collect())
    }

    pub async fn refresh_analyzer_modules(
        analyzer: &mut DwarfAnalyzer,
        runtime_modules: Vec<LoadedModuleRuntimeInfo>,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
    ) -> Result<usize> {
        analyzer
            .refresh_pid_runtime_modules_with_config_and_debuginfod(
                runtime_modules,
                debug_search_paths,
                allow_loose_debug_match,
                debuginfod_client,
                |_| {},
            )
            .await
    }

    pub fn append_loaded_module_cfi(
        analyzer: &DwarfAnalyzer,
        trace_manager: &mut TraceManager,
    ) -> BacktraceUnwindRowsAppendStats {
        let modules = Self::collect_backtrace_unwind_rows(analyzer);
        let stats = trace_manager.append_backtrace_unwind_rows_for_modules(&modules);
        if stats.modules > 0 {
            info!(
                modules = stats.modules,
                rows = stats.rows,
                "Appended runtime DWARF bt unwind rows to active traces"
            );
        }
        stats
    }

    fn collect_backtrace_unwind_rows(
        analyzer: &DwarfAnalyzer,
    ) -> Vec<(u64, Vec<BacktraceUnwindRow>)> {
        let mut modules_by_cookie = BTreeMap::<u64, Vec<BacktraceUnwindRow>>::new();
        for module in analyzer.loaded_module_runtime_info() {
            let Some(module_id) = analyzer.module_id_for_path(&module.module_path) else {
                continue;
            };
            let Ok(Some(table)) = analyzer.compact_unwind_table_for_module(module_id) else {
                continue;
            };
            let mut rows = table
                .rows
                .iter()
                .filter_map(ghostscope_compiler::backtrace_unwind_row_from_compact)
                .collect::<Vec<_>>();
            if rows.is_empty() {
                continue;
            }
            rows.sort_by_key(|row| (row.pc_start, row.pc_end));
            let module_path = module.module_path.to_string_lossy();
            let cookie = ghostscope_compiler::module_cookie_for_path(&module_path);
            modules_by_cookie.entry(cookie).or_insert(rows);
        }

        modules_by_cookie.into_iter().collect()
    }

    fn record_runtime_pid_alias(
        coordinator: &mut ProcessManager,
        proc_pid: u32,
        extra_runtime_pids: &[u32],
    ) {
        let runtime_pids = runtime_pid_keys_for_proc(proc_pid, extra_runtime_pids);
        for runtime_pid in runtime_pids {
            coordinator.record_runtime_pid_alias(runtime_pid, proc_pid);
            if runtime_pid == proc_pid {
                continue;
            }
            if let Err(error) =
                ghostscope_process::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid)
            {
                warn!(
                    "Failed to write runtime PID alias {} -> {}: {}",
                    runtime_pid, proc_pid, error
                );
            } else {
                tracing::debug!(
                    "Backtrace runtime wrote PID alias runtime_pid={} -> proc_pid={}",
                    runtime_pid,
                    proc_pid
                );
            }
        }
    }

    fn write_pinned_offsets_for_pid(
        mode: &str,
        pid: u32,
        entries: &[PidOffsetsEntry],
        extra_runtime_pids: &[u32],
    ) {
        let pinned_offsets = entries
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
            .collect::<Vec<_>>();

        let runtime_pids = runtime_pid_keys_for_proc(pid, extra_runtime_pids);
        for runtime_pid in &runtime_pids {
            if let Err(error) = ghostscope_process::pinned_bpf_maps::insert_offsets_for_pid(
                *runtime_pid,
                &pinned_offsets,
            ) {
                warn!(
                    "Failed to write {} module offsets for PID {} (runtime PID {}): {}",
                    mode, pid, runtime_pid, error
                );
            }
            if let Err(error) = ghostscope_process::pinned_bpf_maps::replace_ranges_for_pid(
                *runtime_pid,
                &pinned_offsets,
            ) {
                warn!(
                    "Failed to write {} module ranges for PID {} (runtime PID {}): {}",
                    mode, pid, runtime_pid, error
                );
            }
        }
        tracing::debug!(
            "{} module offsets for PID {} written to runtime PID keys {:?}",
            mode,
            pid,
            runtime_pids
        );
    }
}

fn runtime_pid_keys_for_proc(proc_pid: u32, extra_runtime_pids: &[u32]) -> Vec<u32> {
    let mut pids = runtime_pid_candidates_for_proc(proc_pid)
        .into_iter()
        .chain(extra_runtime_pids.iter().copied().filter(|pid| *pid != 0))
        .collect::<BTreeSet<_>>();
    pids.insert(proc_pid);
    pids.into_iter().collect()
}

fn runtime_pids_for_target_pid(
    coordinator: &ProcessManager,
    proc_pid: u32,
    target_pid_count: usize,
    extra_runtime_pids: &[u32],
) -> Vec<u32> {
    let proc_pid_candidates = runtime_pid_candidates_for_proc(proc_pid)
        .into_iter()
        .collect::<BTreeSet<_>>();
    extra_runtime_pids
        .iter()
        .copied()
        .filter(|runtime_pid| *runtime_pid != 0)
        .filter(|runtime_pid| {
            *runtime_pid == proc_pid
                || proc_pid_candidates.contains(runtime_pid)
                || coordinator.resolve_runtime_proc_pid(*runtime_pid) == Some(proc_pid)
                || (target_pid_count == 1 && !proc_pid_visible(*runtime_pid))
        })
        .collect()
}

fn proc_pid_visible(pid: u32) -> bool {
    std::path::Path::new("/proc").join(pid.to_string()).exists()
}

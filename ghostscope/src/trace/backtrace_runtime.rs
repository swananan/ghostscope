use crate::trace::TraceManager;
use anyhow::Result;
use ghostscope_debuginfod::DebuginfodClient;
use ghostscope_dwarf::{DwarfAnalyzer, LoadedModuleRuntimeInfo};
use ghostscope_loader::BacktraceUnwindRowsAppendStats;
use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
use ghostscope_process::{PidOffsetsEntry, ProcessManager};
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

        Self::record_runtime_pid_alias(coordinator, proc_pid);
        Self::write_pinned_offsets_for_pid("PID-mode", proc_pid, &entries);
        Ok(DwarfAnalyzer::runtime_modules_from_pid_offsets(&entries))
    }

    pub fn collect_target_modules(
        coordinator: &mut ProcessManager,
        target_binary: &str,
    ) -> Result<Vec<LoadedModuleRuntimeInfo>> {
        coordinator.refresh_prefill_module(target_binary)?;

        let target_pids = coordinator
            .cached_offsets_for_module(target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .collect::<BTreeSet<_>>();
        if target_pids.is_empty() {
            return Ok(Vec::new());
        }

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

            Self::record_runtime_pid_alias(coordinator, pid);
            Self::write_pinned_offsets_for_pid("target-mode", pid, &entries);
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

    fn record_runtime_pid_alias(coordinator: &mut ProcessManager, proc_pid: u32) {
        let runtime_pid = ghostscope_process::resolve_event_pid_for_proc(proc_pid);
        coordinator.record_runtime_pid_alias(runtime_pid, proc_pid);
        if runtime_pid == proc_pid {
            return;
        }
        if let Err(error) =
            ghostscope_process::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid)
        {
            warn!(
                "Failed to write runtime PID alias {} -> {}: {}",
                runtime_pid, proc_pid, error
            );
        }
    }

    fn write_pinned_offsets_for_pid(mode: &str, pid: u32, entries: &[PidOffsetsEntry]) {
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

        if let Err(error) =
            ghostscope_process::pinned_bpf_maps::insert_offsets_for_pid(pid, &pinned_offsets)
        {
            warn!(
                "Failed to write {} module offsets for PID {}: {}",
                mode, pid, error
            );
        }
        if let Err(error) =
            ghostscope_process::pinned_bpf_maps::replace_ranges_for_pid(pid, &pinned_offsets)
        {
            warn!(
                "Failed to write {} module ranges for PID {}: {}",
                mode, pid, error
            );
        }
    }
}

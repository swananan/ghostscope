use ghostscope_dwarf::LoadedModuleRuntimeInfo;
use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
use ghostscope_process::{runtime_pid_candidates_for_proc, PidOffsetsEntry, ProcessManager};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use tracing::warn;

/// Coordinates runtime module refreshes with backtrace CFI publication.
#[derive(Debug, Default, Clone, Copy)]
pub struct BacktraceRuntimeRunner;

impl BacktraceRuntimeRunner {
    pub fn prepare_target_module_mappings(
        coordinator: &mut ProcessManager,
        target_binary: &str,
    ) -> anyhow::Result<usize> {
        coordinator.refresh_prefill_module(target_binary)?;
        let target_pids = coordinator
            .cached_offsets_for_module(target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .filter(|pid| *pid != std::process::id())
            .collect::<BTreeSet<_>>();

        let mut mapped_modules = BTreeSet::new();
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
            Self::record_runtime_pid_alias(coordinator, pid, &[]);
            Self::write_pinned_offsets_for_pid("target-mode", pid, &entries, &[]);
            mapped_modules.extend(entries.iter().map(|entry| entry.cookie));
        }
        Ok(mapped_modules.len())
    }

    pub fn refresh_pid_modules_for_requests(
        coordinator: &mut ProcessManager,
        proc_pid: u32,
        requested_cookies: &BTreeSet<u64>,
        requested_raw_ips: &BTreeSet<u64>,
        refresh: bool,
    ) -> Vec<LoadedModuleRuntimeInfo> {
        if refresh {
            if let Err(error) = coordinator.refresh_prefill_pid(proc_pid) {
                tracing::debug!(
                    "Failed to refresh module offsets for backtrace PID {}: {}",
                    proc_pid,
                    error
                );
            }
        }
        let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Vec::new();
        };
        let entries = entries.to_vec();
        let modules = runtime_modules_for_requests(&entries, requested_cookies, requested_raw_ips);
        if modules.is_empty() {
            return modules;
        }

        Self::record_runtime_pid_alias(coordinator, proc_pid, &[]);
        Self::write_pinned_offsets_for_pid("PID-mode", proc_pid, &entries, &[]);
        modules
    }

    pub fn refresh_target_modules_for_requests(
        coordinator: &mut ProcessManager,
        target_binary: &str,
        extra_runtime_pids: &[u32],
        requested_cookies: &BTreeSet<u64>,
        requested_raw_ips: &BTreeSet<u64>,
        refreshed_proc_pids: &mut BTreeSet<u32>,
    ) -> Vec<LoadedModuleRuntimeInfo> {
        let mut target_pids = coordinator
            .cached_offsets_for_module(target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .filter(|pid| *pid != std::process::id())
            .collect::<BTreeSet<_>>();
        for runtime_pid in extra_runtime_pids.iter().copied().filter(|pid| *pid != 0) {
            if let Some(proc_pid) = coordinator.resolve_runtime_proc_pid(runtime_pid) {
                if proc_pid != std::process::id() {
                    target_pids.insert(proc_pid);
                }
            }
            if proc_pid_visible(runtime_pid) && runtime_pid != std::process::id() {
                target_pids.insert(runtime_pid);
            }
        }
        let target_pid_count = target_pids.len();
        let mut modules_by_cookie = BTreeMap::new();

        for pid in target_pids {
            if refreshed_proc_pids.insert(pid) {
                if let Err(error) = coordinator.refresh_prefill_pid(pid) {
                    tracing::debug!(
                        "Failed to refresh module offsets for target-mode backtrace PID {}: {}",
                        pid,
                        error
                    );
                }
            }
            let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(pid) else {
                continue;
            };
            let entries = entries.to_vec();
            let pid_runtime_pids =
                runtime_pids_for_target_pid(coordinator, pid, target_pid_count, extra_runtime_pids);
            let empty_raw_ips = BTreeSet::new();
            let pid_requested_raw_ips = if pid_runtime_pids.is_empty() {
                &empty_raw_ips
            } else {
                requested_raw_ips
            };
            let modules =
                runtime_modules_for_requests(&entries, requested_cookies, pid_requested_raw_ips);
            if modules.is_empty() {
                continue;
            }
            Self::record_runtime_pid_alias(coordinator, pid, &pid_runtime_pids);
            Self::write_pinned_offsets_for_pid("target-mode", pid, &entries, &pid_runtime_pids);

            for module in modules {
                let cookie = ghostscope_compiler::module_cookie_for_path(
                    &module.module_path.to_string_lossy(),
                );
                modules_by_cookie.entry(cookie).or_insert(module);
            }
        }

        modules_by_cookie.into_values().take(1).collect()
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

fn runtime_modules_for_requests(
    entries: &[PidOffsetsEntry],
    requested_cookies: &BTreeSet<u64>,
    requested_raw_ips: &BTreeSet<u64>,
) -> Vec<LoadedModuleRuntimeInfo> {
    let mut seen = BTreeSet::new();
    entries
        .iter()
        .filter(|entry| {
            let requested_by_cookie = requested_cookies.contains(&entry.cookie);
            let requested_by_ip = requested_raw_ips.iter().any(|raw_ip| {
                *raw_ip >= entry.base && *raw_ip < entry.base.saturating_add(entry.size)
            });
            (requested_by_cookie || requested_by_ip) && seen.insert(entry.cookie)
        })
        .take(1)
        .map(|entry| LoadedModuleRuntimeInfo {
            module_path: PathBuf::from(&entry.module_path),
            loaded_address: Some(entry.base),
            load_bias: Some(entry.offsets.text),
            size: entry.size,
        })
        .collect()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ghostscope_process::SectionOffsets;

    fn entry(path: &str, cookie: u64, base: u64) -> PidOffsetsEntry {
        PidOffsetsEntry {
            module_path: path.to_string(),
            cookie,
            offsets: SectionOffsets {
                text: base + 0x100,
                ..Default::default()
            },
            base,
            size: 0x1_000,
        }
    }

    #[test]
    fn runtime_module_selection_is_demand_driven_and_single_module() {
        let entries = vec![
            entry("/tmp/one.so", 1, 0x10_000),
            entry("/tmp/two.so", 2, 0x20_000),
        ];
        let requested_cookies = BTreeSet::from([2]);
        let requested_raw_ips = BTreeSet::from([0x10_123]);

        let selected =
            runtime_modules_for_requests(&entries, &requested_cookies, &requested_raw_ips);

        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].module_path, PathBuf::from("/tmp/one.so"));
        assert_eq!(selected[0].loaded_address, Some(0x10_000));
    }
}

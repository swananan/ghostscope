use ghostscope_dwarf::LoadedModuleRuntimeInfo;
use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
use ghostscope_process::{runtime_pid_candidates_for_proc, PidOffsetsEntry, ProcessManager};
use std::collections::BTreeSet;
use std::path::PathBuf;
use tracing::warn;

/// One backtrace stopping-frame observation in its original address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BacktraceRuntimeModuleObservation {
    pub runtime_pid: u32,
    pub raw_ip: u64,
    pub cookie_hint: u64,
    pub cookie_is_authoritative: bool,
}

impl BacktraceRuntimeModuleObservation {
    pub fn is_empty(self) -> bool {
        self.runtime_pid == 0 || (self.raw_ip == 0 && self.cookie_hint == 0)
    }
}

/// A stopping-frame observation resolved against one exact process snapshot.
#[derive(Debug, Clone)]
pub struct ResolvedBacktraceRuntimeModule {
    pub observation: BacktraceRuntimeModuleObservation,
    pub proc_pid: u32,
    pub cookie: u64,
    pub module: LoadedModuleRuntimeInfo,
}

/// Result of matching an observation to a current process mapping.
#[derive(Debug, Clone)]
pub enum BacktraceRuntimeModuleResolution {
    Resolved(ResolvedBacktraceRuntimeModule),
    Unavailable,
    IdentityChanged,
}

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

    /// Resolve one observation in fixed-PID mode.
    pub fn resolve_pid_module_for_observation(
        coordinator: &mut ProcessManager,
        proc_pid: u32,
        observation: BacktraceRuntimeModuleObservation,
    ) -> BacktraceRuntimeModuleResolution {
        if observation.is_empty() || proc_pid == std::process::id() {
            return BacktraceRuntimeModuleResolution::Unavailable;
        }

        let refreshed_entry = if observation.raw_ip != 0 {
            match coordinator.refresh_module_for_runtime_ip(proc_pid, observation.raw_ip) {
                Ok(Some(entry)) => Some(entry),
                Ok(None) => {
                    let entries = coordinator
                        .cached_offsets_with_paths_for_pid(proc_pid)
                        .unwrap_or_default()
                        .to_vec();
                    Self::publish_observation_pid_snapshot(
                        coordinator,
                        proc_pid,
                        observation,
                        &entries,
                    );
                    return BacktraceRuntimeModuleResolution::Unavailable;
                }
                Err(error) => {
                    tracing::debug!(
                        "Failed to refresh the backtrace module for PID {} at 0x{:x}: {}",
                        proc_pid,
                        observation.raw_ip,
                        error
                    );
                    let entries = coordinator
                        .cached_offsets_with_paths_for_pid(proc_pid)
                        .unwrap_or_default()
                        .to_vec();
                    Self::publish_observation_pid_snapshot(
                        coordinator,
                        proc_pid,
                        observation,
                        &entries,
                    );
                    return BacktraceRuntimeModuleResolution::Unavailable;
                }
            }
        } else {
            if let Err(error) = coordinator.refresh_prefill_pid(proc_pid) {
                tracing::debug!(
                    "Failed to refresh module offsets for backtrace PID {}: {}",
                    proc_pid,
                    error
                );
                return BacktraceRuntimeModuleResolution::Unavailable;
            }
            None
        };

        let Some(entries) = coordinator.cached_offsets_with_paths_for_pid(proc_pid) else {
            return BacktraceRuntimeModuleResolution::Unavailable;
        };
        let entries = entries.to_vec();
        let entry = match refreshed_entry {
            Some(entry) => {
                runtime_entry_for_observation(std::slice::from_ref(&entry), observation).cloned()
            }
            None => runtime_entry_for_observation(&entries, observation).cloned(),
        };
        Self::publish_observation_pid_snapshot(coordinator, proc_pid, observation, &entries);
        let Some(entry) = entry else {
            return BacktraceRuntimeModuleResolution::Unavailable;
        };
        if !observation_matches_entry_identity(observation, &entry) {
            tracing::debug!(
                observed_cookie = format_args!("0x{:016x}", observation.cookie_hint),
                mapped_cookie = format_args!("0x{:016x}", entry.cookie),
                raw_ip = format_args!("0x{:x}", observation.raw_ip),
                "Backtrace observation no longer matches the current module mapping"
            );
            return BacktraceRuntimeModuleResolution::IdentityChanged;
        }

        BacktraceRuntimeModuleResolution::Resolved(ResolvedBacktraceRuntimeModule {
            observation,
            proc_pid,
            cookie: entry.cookie,
            module: runtime_module_from_entry(&entry),
        })
    }

    /// Resolve one target-mode observation without trying its raw IP in any
    /// unrelated process address space.
    pub fn resolve_target_module_for_observation(
        coordinator: &mut ProcessManager,
        target_binary: &str,
        observation: BacktraceRuntimeModuleObservation,
        refresh_target_pids: bool,
    ) -> BacktraceRuntimeModuleResolution {
        if refresh_target_pids {
            if let Err(error) = coordinator.refresh_prefill_module(target_binary) {
                tracing::debug!(
                    "Failed to refresh target PID discovery for backtrace module resolution: {}",
                    error
                );
            }
        }
        let target_pids = coordinator
            .cached_offsets_for_module(target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .filter(|pid| *pid != std::process::id())
            .collect::<BTreeSet<_>>();
        let Some(proc_pid) =
            resolve_target_proc_pid(coordinator, observation.runtime_pid, &target_pids)
        else {
            return BacktraceRuntimeModuleResolution::Unavailable;
        };
        Self::resolve_pid_module_for_observation(coordinator, proc_pid, observation)
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

    fn publish_observation_pid_snapshot(
        coordinator: &mut ProcessManager,
        proc_pid: u32,
        observation: BacktraceRuntimeModuleObservation,
        entries: &[PidOffsetsEntry],
    ) {
        let runtime_pid = std::slice::from_ref(&observation.runtime_pid);
        Self::record_runtime_pid_alias(coordinator, proc_pid, runtime_pid);
        Self::write_pinned_offsets_for_pid("backtrace-runtime", proc_pid, entries, runtime_pid);
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

fn runtime_entry_for_observation(
    entries: &[PidOffsetsEntry],
    observation: BacktraceRuntimeModuleObservation,
) -> Option<&PidOffsetsEntry> {
    if observation.raw_ip != 0 {
        return entries.iter().find(|entry| {
            observation.raw_ip >= entry.base
                && observation.raw_ip < entry.base.saturating_add(entry.size)
        });
    }

    (observation.cookie_hint != 0)
        .then(|| {
            entries
                .iter()
                .find(|entry| entry.cookie == observation.cookie_hint)
        })
        .flatten()
}

fn observation_matches_entry_identity(
    observation: BacktraceRuntimeModuleObservation,
    entry: &PidOffsetsEntry,
) -> bool {
    !observation.cookie_is_authoritative
        || observation.cookie_hint == 0
        || observation.cookie_hint == entry.cookie
}

fn runtime_module_from_entry(entry: &PidOffsetsEntry) -> LoadedModuleRuntimeInfo {
    LoadedModuleRuntimeInfo {
        module_path: PathBuf::from(&entry.module_path),
        loaded_address: Some(entry.base),
        load_bias: Some(entry.offsets.text),
        size: entry.size,
    }
}

fn resolve_target_proc_pid(
    coordinator: &ProcessManager,
    runtime_pid: u32,
    target_pids: &BTreeSet<u32>,
) -> Option<u32> {
    if runtime_pid == 0 {
        return None;
    }
    if let Some(proc_pid) = coordinator.resolve_runtime_proc_pid(runtime_pid) {
        return (proc_pid != std::process::id() && target_pids.contains(&proc_pid))
            .then_some(proc_pid);
    }

    let mut matches = target_pids.iter().copied().filter(|proc_pid| {
        *proc_pid == runtime_pid
            || runtime_pid_candidates_for_proc(*proc_pid).contains(&runtime_pid)
    });
    let matched = matches.next();
    if matched.is_some() && matches.next().is_none() {
        return matched;
    }

    if target_pids.len() == 1 && !proc_pid_visible(runtime_pid) {
        return target_pids.first().copied();
    }
    None
}

fn runtime_pid_keys_for_proc(proc_pid: u32, extra_runtime_pids: &[u32]) -> Vec<u32> {
    let mut pids = runtime_pid_candidates_for_proc(proc_pid)
        .into_iter()
        .chain(extra_runtime_pids.iter().copied().filter(|pid| *pid != 0))
        .collect::<BTreeSet<_>>();
    pids.insert(proc_pid);
    pids.into_iter().collect()
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
    fn raw_observation_is_resolved_only_in_the_supplied_pid_snapshot() {
        let first_pid_entries = vec![entry("/tmp/one.so", 1, 0x10_000)];
        let second_pid_entries = vec![entry("/tmp/two.so", 2, 0x10_000)];
        let observation = BacktraceRuntimeModuleObservation {
            runtime_pid: 42,
            raw_ip: 0x10_123,
            cookie_hint: 0,
            cookie_is_authoritative: false,
        };

        assert_eq!(
            runtime_entry_for_observation(&first_pid_entries, observation)
                .map(|entry| entry.cookie),
            Some(1)
        );
        assert_eq!(
            runtime_entry_for_observation(&second_pid_entries, observation)
                .map(|entry| entry.cookie),
            Some(2)
        );
    }

    #[test]
    fn non_authoritative_cookie_uses_the_current_mapping_for_a_reused_raw_range() {
        let entries = vec![entry("/tmp/replacement.so", 2, 0x10_000)];
        let observation = BacktraceRuntimeModuleObservation {
            runtime_pid: 42,
            raw_ip: 0x10_123,
            cookie_hint: 1,
            cookie_is_authoritative: false,
        };

        assert_eq!(
            runtime_entry_for_observation(&entries, observation).map(|entry| entry.cookie),
            Some(2)
        );
    }

    #[test]
    fn authoritative_cookie_detects_identity_change_for_a_reused_raw_range() {
        let mapped = entry("/tmp/replacement.so", 2, 0x10_000);
        let observation = BacktraceRuntimeModuleObservation {
            runtime_pid: 42,
            raw_ip: 0x10_123,
            cookie_hint: 1,
            cookie_is_authoritative: true,
        };

        assert!(!observation_matches_entry_identity(observation, &mapped));

        let non_authoritative = BacktraceRuntimeModuleObservation {
            cookie_is_authoritative: false,
            ..observation
        };
        assert!(observation_matches_entry_identity(
            non_authoritative,
            &mapped
        ));
    }

    #[test]
    fn target_pid_resolution_does_not_choose_between_ambiguous_processes() {
        let coordinator = ProcessManager::new();
        let target_pids = BTreeSet::from([42, 43]);

        assert_eq!(
            resolve_target_proc_pid(&coordinator, 4242, &target_pids),
            None
        );
    }

    #[test]
    fn target_pid_resolution_rejects_a_stale_runtime_alias() {
        let mut coordinator = ProcessManager::new();
        coordinator.record_runtime_pid_alias(7, 42);
        let target_pids = BTreeSet::from([43]);

        assert_eq!(resolve_target_proc_pid(&coordinator, 7, &target_pids), None);
    }
}

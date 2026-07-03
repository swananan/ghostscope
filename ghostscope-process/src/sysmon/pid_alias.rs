use super::events::sys_event_host_pid;
use super::*;

pub(super) fn write_pinned_runtime_pid_alias(runtime_pid: u32, proc_pid: u32) {
    if runtime_pid == proc_pid {
        return;
    }
    match crate::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid) {
        Ok(()) => tracing::trace!(
            "Sysmon: inserted PID alias runtime pid {} -> proc pid {}",
            runtime_pid,
            proc_pid
        ),
        Err(e) => {
            tracing::debug!(
                "Sysmon: failed to insert PID alias runtime pid {} -> proc pid {}: {}",
                runtime_pid,
                proc_pid,
                e
            );
        }
    }
}

pub(super) fn record_runtime_pid_alias_for_event(
    mgr: &Arc<Mutex<ProcessManager>>,
    runtime_pid: u32,
    proc_pid: u32,
) {
    write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
    if let Ok(mut guard) = mgr.lock() {
        guard.record_runtime_pid_alias(runtime_pid, proc_pid);
    }
}

pub(super) fn record_runtime_pid_aliases_for_proc_pid_locked(
    guard: &mut ProcessManager,
    proc_pid: u32,
) {
    for runtime_pid in runtime_pid_candidates_for_proc(proc_pid) {
        write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
        guard.record_runtime_pid_alias(runtime_pid, proc_pid);
    }
}

pub(super) fn record_runtime_pid_aliases_for_proc_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    proc_pid: u32,
) {
    if let Ok(mut guard) = mgr.lock() {
        record_runtime_pid_aliases_for_proc_pid_locked(&mut guard, proc_pid);
    } else {
        for runtime_pid in runtime_pid_candidates_for_proc(proc_pid) {
            write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
        }
    }
}

pub(super) fn runtime_pid_keys_for_proc_event(
    proc_pid: u32,
    event_pid: u32,
    extra_runtime_pids: impl IntoIterator<Item = u32>,
) -> Vec<u32> {
    let mut keys = BTreeSet::new();
    keys.insert(proc_pid);
    keys.insert(event_pid);
    for runtime_pid in runtime_pid_candidates_for_proc(proc_pid) {
        keys.insert(runtime_pid);
    }
    for runtime_pid in extra_runtime_pids {
        if runtime_pid != 0 {
            keys.insert(runtime_pid);
        }
    }
    keys.into_iter().collect()
}

pub(super) fn record_runtime_pid_aliases_for_keys(
    mgr: &Arc<Mutex<ProcessManager>>,
    proc_pid: u32,
    runtime_pids: &[u32],
) {
    for runtime_pid in runtime_pids {
        write_pinned_runtime_pid_alias(*runtime_pid, proc_pid);
    }
    if let Ok(mut guard) = mgr.lock() {
        for runtime_pid in runtime_pids {
            guard.record_runtime_pid_alias(*runtime_pid, proc_pid);
        }
    }
}

pub(super) fn insert_allowed_runtime_pid_keys(runtime_pids: &[u32]) {
    for runtime_pid in runtime_pids {
        let _ = crate::pinned_bpf_maps::insert_allowed_pid(*runtime_pid);
    }
}

pub(super) fn publish_offsets_for_runtime_pid_keys(
    proc_pid: u32,
    event_pid: u32,
    runtime_pids: &[u32],
    items: &[(u64, crate::pinned_bpf_maps::ProcModuleOffsetsValue)],
    log_context: &str,
) -> anyhow::Result<usize> {
    use crate::pinned_bpf_maps::{insert_offsets_for_pid, replace_ranges_for_pid};

    let mut total_inserted = 0usize;
    for runtime_pid in runtime_pids {
        match insert_offsets_for_pid(*runtime_pid, items) {
            Ok(inserted) => {
                if inserted == 0 {
                    tracing::warn!(
                        "Sysmon: no offsets inserted for {} runtime pid {} (event pid {}, proc pid {}) (entry count={})",
                        log_context,
                        runtime_pid,
                        event_pid,
                        proc_pid,
                        items.len()
                    );
                    continue;
                }
                total_inserted += inserted;
                if let Err(e) = replace_ranges_for_pid(*runtime_pid, items) {
                    tracing::warn!(
                        "Sysmon: failed to replace module ranges for {} runtime pid {} (event pid {}, proc pid {}): {}",
                        log_context,
                        runtime_pid,
                        event_pid,
                        proc_pid,
                        e
                    );
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Sysmon: failed to insert offsets for {} runtime pid {} (event pid {}, proc pid {}): {}",
                    log_context,
                    runtime_pid,
                    event_pid,
                    proc_pid,
                    e
                );
            }
        }
    }

    Ok(total_inserted)
}

pub(super) fn purge_offsets_for_runtime_pid_keys(runtime_pids: &[u32]) -> anyhow::Result<usize> {
    let mut purged = 0usize;
    for runtime_pid in runtime_pids {
        purged += crate::pinned_bpf_maps::purge_offsets_for_pid(*runtime_pid)?;
        let _ = crate::pinned_bpf_maps::purge_ranges_for_pid(*runtime_pid);
    }
    Ok(purged)
}

pub(super) fn purge_runtime_pid_artifacts(proc_pid: u32, event_pid: u32, host_pid: u32) -> usize {
    let runtime_pids = runtime_pid_keys_for_proc_event(proc_pid, event_pid, [host_pid]);
    let mut purged_offsets = 0usize;
    for runtime_pid in runtime_pids {
        if let Ok(purged) = crate::pinned_bpf_maps::purge_offsets_for_pid(runtime_pid) {
            purged_offsets += purged;
        }
        let _ = crate::pinned_bpf_maps::purge_ranges_for_pid(runtime_pid);
        let _ = crate::pinned_bpf_maps::remove_allowed_pid(runtime_pid);
        if runtime_pid != proc_pid {
            let _ = crate::pinned_bpf_maps::remove_pid_alias(runtime_pid);
        }
    }
    purged_offsets
}

pub(super) fn record_runtime_pid_aliases_for_sys_event(
    mgr: &Arc<Mutex<ProcessManager>>,
    ev: &SysEvent,
    proc_pid: u32,
) {
    record_runtime_pid_alias_for_event(mgr, ev.tgid, proc_pid);
    let host_pid = sys_event_host_pid(ev);
    if host_pid != ev.tgid {
        record_runtime_pid_alias_for_event(mgr, host_pid, proc_pid);
    }
    record_runtime_pid_aliases_for_proc_pid(mgr, proc_pid);
}

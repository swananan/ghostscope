use super::offset_refresh::*;
use super::pending::*;
use super::pid_alias::*;
use super::*;

pub(super) fn try_publish_sys_event(tx: &mpsc::SyncSender<SysEvent>, ev: SysEvent) -> bool {
    match tx.try_send(ev) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(ev)) => {
            tracing::trace!(
                "Sysmon event queue full; dropping lifecycle notification for pid {} kind {}",
                ev.tgid,
                ev.kind
            );
            false
        }
        Err(mpsc::TrySendError::Disconnected(ev)) => {
            tracing::trace!(
                "Sysmon event receiver disconnected; dropping lifecycle notification for pid {} kind {}",
                ev.tgid,
                ev.kind
            );
            false
        }
    }
}

pub(super) fn dispatch_sysmon_event(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: &Option<PathBuf>,
    pending: &Arc<Mutex<PendingOffsets>>,
    pending_map_refreshes: &Arc<Mutex<PendingMapRefreshes>>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
    ev: &SysEvent,
) -> bool {
    match SysEventKind::from_u32(ev.kind) {
        Some(SysEventKind::MapChange) => {
            if let Some(proc_pid) =
                proc_pid_for_map_change_event(mgr, target, proc_pid_for_event, ev)
            {
                let proc_pid = target
                    .as_deref()
                    .map(|target_path| {
                        canonicalize_cached_target_proc_pid(mgr, target_path, proc_pid)
                    })
                    .unwrap_or(proc_pid);
                record_runtime_pid_aliases_for_sys_event(mgr, ev, proc_pid);
                if let Ok(mut guard) = pending_map_refreshes.lock() {
                    guard.register(ev.tgid, sys_event_host_pid(ev), proc_pid);
                }
                true
            } else if let Some(target_path) = target.as_deref() {
                let candidates = pending
                    .lock()
                    .ok()
                    .map(|guard| {
                        pending_map_change_candidates(&guard, target_path, proc_pid_for_event, ev)
                    })
                    .unwrap_or_default();

                if candidates.is_empty() {
                    tracing::trace!(
                        "Sysmon: map-change event pid {} (host pid {}) did not resolve to a target /proc pid; skipping per-pid refresh",
                        ev.tgid,
                        sys_event_host_pid(ev)
                    );
                    false
                } else {
                    if let Ok(mut guard) = pending_map_refreshes.lock() {
                        for candidate in &candidates {
                            guard.register(
                                candidate.event_pid,
                                candidate.host_pid,
                                candidate.proc_pid,
                            );
                        }
                    }
                    tracing::trace!(
                        "Sysmon: queued map-change refresh for {} pending target candidate(s) from event pid {} (host pid {})",
                        candidates.len(),
                        ev.tgid,
                        sys_event_host_pid(ev)
                    );
                    false
                }
            } else {
                tracing::trace!(
                    "Sysmon: map-change event pid {} (host pid {}) did not resolve to a target /proc pid; skipping per-pid refresh",
                    ev.tgid,
                    sys_event_host_pid(ev)
                );
                false
            }
        }
        Some(_) => {
            match ProcessSysmon::handle_event_with_proc_pid_resolver(
                mgr,
                target,
                pending,
                ev,
                proc_pid_for_event,
            ) {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!(
                        "Sysmon: handle_event failed for pid {} kind {}: {}",
                        ev.tgid,
                        ev.kind,
                        e
                    );
                    false
                }
            }
        }
        None => {
            match ProcessSysmon::handle_event_with_proc_pid_resolver(
                mgr,
                target,
                pending,
                ev,
                proc_pid_for_event,
            ) {
                Ok(()) => true,
                Err(e) => {
                    tracing::debug!(
                        "Sysmon: handle_event rejected invalid event for pid {} kind {}: {}",
                        ev.tgid,
                        ev.kind,
                        e
                    );
                    false
                }
            }
        }
    }
}

pub(super) fn proc_pid_for_map_change_event(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: &Option<PathBuf>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
    ev: &SysEvent,
) -> Option<u32> {
    let host_pid = sys_event_host_pid(ev);
    let mut candidates = Vec::with_capacity(2);
    push_unique_pid(&mut candidates, proc_pid_for_event(ev.tgid));
    if host_pid != ev.tgid {
        push_unique_pid(&mut candidates, proc_pid_for_event(host_pid));
    }

    for proc_pid in candidates {
        if !pid_alive(proc_pid) {
            continue;
        }
        if target.is_some() && is_current_process_pid(proc_pid) {
            tracing::trace!(
                "Sysmon: ignoring self map-change candidate proc pid {}",
                proc_pid
            );
            continue;
        }

        let Some(target_path) = target.as_deref() else {
            return Some(proc_pid);
        };

        if pid_maps_target_module(proc_pid, target_path)
            || cached_offsets_exist_for_target_pid(mgr, target_path, proc_pid)
        {
            return Some(proc_pid);
        }
    }

    None
}

pub(super) fn pending_map_change_candidates(
    pending: &PendingOffsets,
    target_path: &Path,
    proc_pid_for_event: &impl Fn(u32) -> u32,
    ev: &SysEvent,
) -> Vec<PendingMapChangeCandidate> {
    let host_pid = sys_event_host_pid(ev);
    let mut candidates = Vec::with_capacity(2);
    push_pending_map_change_candidate(
        &mut candidates,
        pending,
        target_path,
        proc_pid_for_event,
        ev.tgid,
        host_pid,
    );
    if host_pid != ev.tgid {
        push_pending_map_change_candidate(
            &mut candidates,
            pending,
            target_path,
            proc_pid_for_event,
            host_pid,
            host_pid,
        );
    }
    candidates
}

pub(super) fn push_pending_map_change_candidate(
    candidates: &mut Vec<PendingMapChangeCandidate>,
    pending: &PendingOffsets,
    target_path: &Path,
    proc_pid_for_event: &impl Fn(u32) -> u32,
    event_pid: u32,
    host_pid: u32,
) {
    if !pending.contains_map_change_candidate(event_pid, target_path) {
        return;
    }

    let proc_pid = proc_pid_for_event(event_pid);
    if !pid_alive(proc_pid) || is_current_process_pid(proc_pid) {
        return;
    }

    if candidates
        .iter()
        .any(|candidate| candidate.proc_pid == proc_pid)
    {
        return;
    }

    candidates.push(PendingMapChangeCandidate {
        event_pid,
        host_pid,
        proc_pid,
    });
}

pub(super) fn is_current_process_pid(proc_pid: u32) -> bool {
    proc_pid == std::process::id()
}

pub(super) fn cached_single_target_proc_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    target_path: &Path,
) -> Option<u32> {
    let module_path = target_path.to_string_lossy();
    let mut target_pids = BTreeSet::new();
    let guard = mgr.lock().ok()?;
    for (pid, _, _, _, _) in guard.cached_offsets_for_module(module_path.as_ref()) {
        if !is_current_process_pid(pid)
            && pid_alive(pid)
            && pid_maps_target_module(pid, target_path)
        {
            target_pids.insert(pid);
        }
    }

    if target_pids.len() == 1 {
        target_pids.iter().next().copied()
    } else {
        None
    }
}

pub(super) fn canonicalize_cached_target_proc_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    target_path: &Path,
    fallback_proc_pid: u32,
) -> u32 {
    if pid_alive(fallback_proc_pid) && pid_maps_target_module(fallback_proc_pid, target_path) {
        return fallback_proc_pid;
    }

    let Some(proc_pid) = cached_single_target_proc_pid(mgr, target_path) else {
        return fallback_proc_pid;
    };

    if proc_pid != fallback_proc_pid {
        tracing::debug!(
            "Sysmon: canonicalized map-change proc pid {} -> {} for target {}",
            fallback_proc_pid,
            proc_pid,
            target_path.display()
        );
    }

    proc_pid
}

pub(super) fn push_unique_pid(pids: &mut Vec<u32>, pid: u32) {
    if !pids.contains(&pid) {
        pids.push(pid);
    }
}

pub(super) fn sysmon_proc_pid_resolver(
    watched_event_pid: Option<u32>,
    watched_proc_pid: Option<u32>,
) -> impl Fn(u32) -> u32 {
    move |event_pid| {
        if watched_event_pid == Some(event_pid) {
            if let Some(proc_pid) = watched_proc_pid {
                return proc_pid;
            }
        }

        resolve_proc_pid_for_event(event_pid)
    }
}

pub(super) fn sys_event_host_pid(ev: &SysEvent) -> u32 {
    if ev.host_tgid != 0 {
        ev.host_tgid
    } else {
        ev.tgid
    }
}

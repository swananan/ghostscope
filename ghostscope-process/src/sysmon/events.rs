use super::offset_refresh::*;
use super::pending::*;
use super::pid_alias::*;
use super::*;
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct MapChangeKey {
    event_pid: u32,
    host_pid: u32,
}

impl MapChangeKey {
    fn from_event(ev: SysEvent) -> Self {
        Self {
            event_pid: ev.tgid,
            host_pid: sys_event_host_pid(&ev),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct QueuedMapChange {
    event: SysEvent,
    ready_at: Instant,
}

/// Coalesces noisy map-change events by process before any `/proc` work is performed.
///
/// An entry remains queued during the debounce window, so a process repeatedly calling mmap does
/// not make sysmon rescan the same maps on every syscall. Queue overflow is safe because the
/// periodic target-module reconciliation remains the correctness fallback.
#[derive(Debug)]
pub(super) struct CoalescedMapChanges {
    entries: HashMap<MapChangeKey, QueuedMapChange>,
    order: VecDeque<MapChangeKey>,
    last_processed: HashMap<MapChangeKey, Instant>,
    capacity: usize,
    debounce_interval: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SysmonWorkEnqueueResult {
    Queued,
    LifecycleQueueFull,
    MapChangeQueueFull,
}

/// Bounded handoff between the eBPF event reader and the sysmon work thread.
///
/// Lifecycle events retain FIFO order in their own queue. Map changes use the
/// existing per-process coalescer, so mmap-heavy workloads cannot crowd exec,
/// fork, or exit work out of the handoff queue.
#[derive(Debug)]
pub(super) struct SysmonWorkQueue {
    lifecycle_events: VecDeque<SysEvent>,
    map_changes: CoalescedMapChanges,
    lifecycle_capacity: usize,
}

impl SysmonWorkQueue {
    pub(super) fn new(
        lifecycle_capacity: usize,
        map_change_capacity: usize,
        map_change_debounce_interval: Duration,
    ) -> Self {
        Self {
            lifecycle_events: VecDeque::new(),
            map_changes: CoalescedMapChanges::new(
                map_change_capacity,
                map_change_debounce_interval,
            ),
            lifecycle_capacity,
        }
    }

    pub(super) fn enqueue(&mut self, event: SysEvent, now: Instant) -> SysmonWorkEnqueueResult {
        if event.event_kind() == Some(SysEventKind::MapChange) {
            return if self.map_changes.enqueue(event, now) {
                SysmonWorkEnqueueResult::Queued
            } else {
                SysmonWorkEnqueueResult::MapChangeQueueFull
            };
        }

        if self.lifecycle_events.len() >= self.lifecycle_capacity {
            return SysmonWorkEnqueueResult::LifecycleQueueFull;
        }
        self.lifecycle_events.push_back(event);
        SysmonWorkEnqueueResult::Queued
    }

    pub(super) fn pop_lifecycle(&mut self) -> Option<SysEvent> {
        self.lifecycle_events.pop_front()
    }

    pub(super) fn pop_ready_map_change(&mut self, now: Instant) -> Option<SysEvent> {
        self.map_changes.pop_ready(now)
    }

    #[cfg(test)]
    fn lifecycle_len(&self) -> usize {
        self.lifecycle_events.len()
    }

    #[cfg(test)]
    fn map_change_len(&self) -> usize {
        self.map_changes.len()
    }
}

impl CoalescedMapChanges {
    pub(super) fn new(capacity: usize, debounce_interval: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
            last_processed: HashMap::new(),
            capacity,
            debounce_interval,
        }
    }

    pub(super) fn enqueue(&mut self, event: SysEvent, now: Instant) -> bool {
        let key = MapChangeKey::from_event(event);
        if let Some(queued) = self.entries.get_mut(&key) {
            queued.event = event;
            return true;
        }
        if self.entries.len() >= self.capacity {
            return false;
        }

        if self.last_processed.len() >= self.capacity {
            self.last_processed.retain(|_, processed_at| {
                now.saturating_duration_since(*processed_at) < self.debounce_interval
            });
        }
        let ready_at = self
            .last_processed
            .get(&key)
            .and_then(|processed_at| processed_at.checked_add(self.debounce_interval))
            .unwrap_or(now);
        self.entries
            .insert(key, QueuedMapChange { event, ready_at });
        self.order.push_back(key);
        true
    }

    pub(super) fn pop_ready(&mut self, now: Instant) -> Option<SysEvent> {
        let queued_len = self.order.len();
        for _ in 0..queued_len {
            let key = self.order.pop_front()?;
            let Some(queued) = self.entries.get(&key).copied() else {
                continue;
            };
            if queued.ready_at > now {
                self.order.push_back(key);
                continue;
            }

            self.entries.remove(&key);
            self.last_processed.insert(key, now);
            return Some(queued.event);
        }
        None
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

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

pub(super) fn cached_sysmon_proc_pid_resolver(
    watched_event_pid: Option<u32>,
    watched_proc_pid: Option<u32>,
) -> impl Fn(u32) -> u32 {
    let resolver = RefCell::new(EventProcPidResolver::new());
    move |event_pid| {
        if watched_event_pid == Some(event_pid) {
            if let Some(proc_pid) = watched_proc_pid {
                return proc_pid;
            }
        }

        resolver.borrow_mut().resolve(event_pid)
    }
}

pub(super) fn sys_event_host_pid(ev: &SysEvent) -> u32 {
    if ev.host_tgid != 0 {
        ev.host_tgid
    } else {
        ev.tgid
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_change(event_pid: u32, host_pid: u32) -> SysEvent {
        SysEvent {
            tgid: event_pid,
            host_tgid: host_pid,
            kind: SysEventKind::MapChange.as_u32(),
        }
    }

    #[test]
    fn coalesced_map_changes_keep_one_entry_per_pid() {
        let now = Instant::now();
        let mut changes = CoalescedMapChanges::new(4, Duration::from_millis(75));

        assert!(changes.enqueue(map_change(10, 20), now));
        assert!(changes.enqueue(map_change(10, 20), now));
        assert_eq!(changes.len(), 1);

        let event = changes.pop_ready(now).expect("coalesced event");
        assert_eq!(event.tgid, 10);
        assert_eq!(event.host_tgid, 20);
        assert!(changes.is_empty());
    }

    #[test]
    fn coalesced_map_changes_debounce_repeated_pid() {
        let now = Instant::now();
        let debounce = Duration::from_millis(75);
        let mut changes = CoalescedMapChanges::new(4, debounce);

        assert!(changes.enqueue(map_change(10, 10), now));
        assert!(changes.pop_ready(now).is_some());
        assert!(changes.enqueue(map_change(10, 10), now));
        assert!(changes.pop_ready(now + debounce / 2).is_none());
        assert!(changes.pop_ready(now + debounce).is_some());
    }

    #[test]
    fn coalesced_map_changes_bound_unique_pid_queue() {
        let now = Instant::now();
        let mut changes = CoalescedMapChanges::new(1, Duration::from_millis(75));

        assert!(changes.enqueue(map_change(10, 10), now));
        assert!(changes.enqueue(map_change(10, 10), now));
        assert!(!changes.enqueue(map_change(11, 11), now));
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn work_queue_keeps_lifecycle_events_separate_from_map_churn() {
        let now = Instant::now();
        let mut queue = SysmonWorkQueue::new(2, 1, Duration::from_millis(75));
        let exec = SysEvent {
            tgid: 30,
            host_tgid: 30,
            kind: SysEventKind::Exec.as_u32(),
        };

        assert_eq!(
            queue.enqueue(map_change(10, 10), now),
            SysmonWorkEnqueueResult::Queued
        );
        assert_eq!(
            queue.enqueue(map_change(11, 11), now),
            SysmonWorkEnqueueResult::MapChangeQueueFull
        );
        assert_eq!(queue.enqueue(exec, now), SysmonWorkEnqueueResult::Queued);

        assert_eq!(queue.lifecycle_len(), 1);
        assert_eq!(queue.map_change_len(), 1);
        assert_eq!(queue.pop_lifecycle().map(|event| event.tgid), Some(30));
        assert_eq!(
            queue.pop_ready_map_change(now).map(|event| event.tgid),
            Some(10)
        );
    }

    #[test]
    fn work_queue_bounds_lifecycle_events() {
        let now = Instant::now();
        let mut queue = SysmonWorkQueue::new(1, 1, Duration::from_millis(75));
        let lifecycle = |pid, kind| SysEvent {
            tgid: pid,
            host_tgid: pid,
            kind: SysEventKind::from_u32(kind)
                .expect("valid lifecycle kind")
                .as_u32(),
        };

        assert_eq!(
            queue.enqueue(lifecycle(10, 1), now),
            SysmonWorkEnqueueResult::Queued
        );
        assert_eq!(
            queue.enqueue(lifecycle(11, 2), now),
            SysmonWorkEnqueueResult::LifecycleQueueFull
        );
        assert_eq!(queue.lifecycle_len(), 1);
        assert_eq!(queue.pop_lifecycle().map(|event| event.tgid), Some(10));
    }
}

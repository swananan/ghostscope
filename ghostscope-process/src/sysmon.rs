use crate::{
    module_probe::cookie_for_path,
    offsets::{PidOffsetsEntry, ProcessManager},
    pid::{
        resolve_event_pid_for_proc, resolve_proc_pid_for_event, runtime_pid_candidates_for_proc,
        PidNamespaceId,
    },
    pinned_bpf_maps,
    proc_maps::{
        normalize_mapped_module_path, read_proc_maps, should_skip_mapped_module_path,
        visit_proc_maps, ModuleIdentity,
    },
};
use std::collections::{BTreeSet, HashMap};
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

/// Kind of process lifecycle event
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysEventKind {
    Exec,
    Fork,
    Exit,
    MapChange,
}

impl SysEventKind {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(SysEventKind::Exec),
            2 => Some(SysEventKind::Fork),
            3 => Some(SysEventKind::Exit),
            4 => Some(SysEventKind::MapChange),
            _ => None,
        }
    }

    fn as_u32(self) -> u32 {
        match self {
            SysEventKind::Exec => 1,
            SysEventKind::Fork => 2,
            SysEventKind::Exit => 3,
            SysEventKind::MapChange => 4,
        }
    }
}

/// Internal sysmon event selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysmonEventMask {
    pub exec: bool,
    pub fork: bool,
    pub exit: bool,
    pub map_change: bool,
}

impl SysmonEventMask {
    pub fn target_mode() -> Self {
        Self {
            exec: true,
            fork: true,
            exit: true,
            map_change: false,
        }
    }

    pub fn target_mode_with_map_changes() -> Self {
        Self {
            exec: true,
            fork: true,
            exit: true,
            map_change: true,
        }
    }

    pub fn pid_module_changes() -> Self {
        Self {
            exec: false,
            fork: false,
            exit: false,
            map_change: true,
        }
    }

    fn without_map_change(self) -> Self {
        Self {
            map_change: false,
            ..self
        }
    }

    fn has_lifecycle_events(self) -> bool {
        self.exec || self.fork || self.exit
    }

    #[cfg(feature = "sysmon-ebpf")]
    fn bits(self) -> u32 {
        let mut bits = 0u32;
        if self.exec {
            bits |= SYSMON_EVENT_MASK_EXEC;
        }
        if self.fork {
            bits |= SYSMON_EVENT_MASK_FORK;
        }
        if self.exit {
            bits |= SYSMON_EVENT_MASK_EXIT;
        }
        if self.map_change {
            bits |= SYSMON_EVENT_MASK_MAP_CHANGE;
        }
        bits
    }
}

impl Default for SysmonEventMask {
    fn default() -> Self {
        Self::target_mode()
    }
}

/// Raw SysEvent ABI — must match eBPF side exactly
/// ABI note: This layout is mirrored in eBPF at
/// `ghostscope-process/ebpf/sysmon-bpf/src/lib.rs`. We intentionally keep
/// two copies for now to avoid entangling the BPF build with the workspace.
/// Keep repr(C), field order and sizes identical on both sides. Current
/// layout (12 bytes): { tgid: u32, host_tgid: u32, kind: u32 }.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysEvent {
    /// Runtime TGID in the configured sysmon event namespace when available.
    pub tgid: u32,
    /// Host/initial-namespace TGID from bpf_get_current_pid_tgid().
    pub host_tgid: u32,
    pub kind: u32, // 1=exec,2=fork,3=exit,4=map-change
}

impl SysEvent {
    pub fn event_kind(self) -> Option<SysEventKind> {
        SysEventKind::from_u32(self.kind)
    }
}

const PENDING_POLL_INTERVAL: Duration = Duration::from_millis(150);
const PENDING_MAX_ATTEMPTS: u32 = 20;
const MAP_CHANGE_DEBOUNCE_INTERVAL: Duration = Duration::from_millis(75);
const MODULE_REFRESH_INTERVAL: Duration = Duration::from_millis(250);
const SYSMON_EVENT_QUEUE_CAPACITY: usize = 1024;

#[cfg(feature = "sysmon-ebpf")]
const SYSMON_EVENT_MASK_EXEC: u32 = 1 << 0;
#[cfg(feature = "sysmon-ebpf")]
const SYSMON_EVENT_MASK_FORK: u32 = 1 << 1;
#[cfg(feature = "sysmon-ebpf")]
const SYSMON_EVENT_MASK_EXIT: u32 = 1 << 2;
#[cfg(feature = "sysmon-ebpf")]
const SYSMON_EVENT_MASK_MAP_CHANGE: u32 = 1 << 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingOffsetsKind {
    Retry,
    MapChangeCandidate,
}

impl PendingOffsetsKind {
    fn keep_for_map_changes_after_retry_exhaustion(self) -> bool {
        matches!(self, Self::MapChangeCandidate)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingOffsetsEntry {
    target_path: PathBuf,
    attempts: u32,
    kind: PendingOffsetsKind,
    retry_exhausted: bool,
    last_poll: Instant,
}

#[derive(Debug, Clone)]
struct PendingOffsetsDue {
    event_pid: u32,
    target_path: PathBuf,
    attempts: u32,
    kind: PendingOffsetsKind,
}

#[derive(Debug, Default)]
pub(crate) struct PendingOffsets {
    entries: HashMap<u32, PendingOffsetsEntry>,
}

impl PendingOffsets {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn register(&mut self, pid: u32, target: &Path) {
        self.register_with_kind(pid, target, PendingOffsetsKind::Retry);
    }

    fn register_map_change_candidate(&mut self, pid: u32, target: &Path) {
        self.register_with_kind(pid, target, PendingOffsetsKind::MapChangeCandidate);
    }

    fn register_with_kind(&mut self, pid: u32, target: &Path, kind: PendingOffsetsKind) {
        let now = Instant::now();
        let last_poll = now.checked_sub(PENDING_POLL_INTERVAL).unwrap_or(now);
        self.entries
            .entry(pid)
            .and_modify(|entry| {
                entry.target_path = target.to_path_buf();
                entry.attempts = 0;
                entry.kind = kind;
                entry.retry_exhausted = false;
                entry.last_poll = last_poll;
            })
            .or_insert(PendingOffsetsEntry {
                target_path: target.to_path_buf(),
                attempts: 0,
                kind,
                retry_exhausted: false,
                last_poll,
            });
    }

    fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    fn contains_map_change_candidate(&self, pid: u32, target: &Path) -> bool {
        self.entries
            .get(&pid)
            .map(|entry| {
                entry.kind == PendingOffsetsKind::MapChangeCandidate && entry.target_path == target
            })
            .unwrap_or(false)
    }

    fn mark_retry_exhausted(&mut self, pid: u32) {
        if let Some(entry) = self.entries.get_mut(&pid) {
            entry.retry_exhausted = true;
        }
    }

    fn take_due(&mut self) -> Vec<PendingOffsetsDue> {
        let mut due = Vec::new();
        let now = Instant::now();
        for (&pid, entry) in self.entries.iter_mut() {
            if entry.retry_exhausted {
                continue;
            }
            if now.duration_since(entry.last_poll) >= PENDING_POLL_INTERVAL {
                entry.last_poll = now;
                entry.attempts = entry.attempts.saturating_add(1);
                due.push(PendingOffsetsDue {
                    event_pid: pid,
                    target_path: entry.target_path.clone(),
                    attempts: entry.attempts,
                    kind: entry.kind,
                });
            }
        }
        due
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PendingMapRefreshEntry {
    last_seen: Instant,
    event_pid: u32,
    host_pid: u32,
}

#[derive(Debug, Clone, Copy)]
struct PendingMapRefreshDue {
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingMapChangeCandidate {
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
}

#[derive(Debug, Default)]
pub(crate) struct PendingMapRefreshes {
    entries: HashMap<u32, PendingMapRefreshEntry>,
}

impl PendingMapRefreshes {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn register(&mut self, event_pid: u32, host_pid: u32, proc_pid: u32) {
        self.entries.insert(
            proc_pid,
            PendingMapRefreshEntry {
                last_seen: Instant::now(),
                event_pid,
                host_pid,
            },
        );
    }

    fn take_due(&mut self) -> Vec<PendingMapRefreshDue> {
        let now = Instant::now();
        let due: Vec<PendingMapRefreshDue> = self
            .entries
            .iter()
            .filter_map(|(&proc_pid, entry)| {
                (now.duration_since(entry.last_seen) >= MAP_CHANGE_DEBOUNCE_INTERVAL).then_some(
                    PendingMapRefreshDue {
                        event_pid: entry.event_pid,
                        host_pid: entry.host_pid,
                        proc_pid,
                    },
                )
            })
            .collect();
        for entry in &due {
            self.entries.remove(&entry.proc_pid);
        }
        due
    }
}

/// Configuration for sysmon
#[derive(Debug, Clone)]
pub struct SysmonConfig {
    /// If set, only attempt offsets prefill for events whose binary/module path matches this target.
    pub target_module: Option<PathBuf>,
    /// Maximum number of entries for the pinned proc offsets map (used when ensuring existence).
    pub proc_offsets_max_entries: u32,
    /// PerfEventArray per-CPU buffer pages (used when ringbuf is unavailable).
    pub perf_page_count: Option<usize>,
    /// Internal event selector for the sysmon eBPF side.
    pub event_mask: SysmonEventMask,
    /// Whether map-change events should be emitted before the PID allowlist is populated.
    pub map_change_unfiltered: bool,
    /// Optional event PID to watch. `None` means system-wide.
    pub watched_pid: Option<u32>,
    /// Optional PID namespace for interpreting `watched_pid`.
    pub watched_pid_ns: Option<PidNamespaceId>,
    /// Optional PID namespace for reporting target-mode event TGIDs.
    pub event_pid_ns: Option<PidNamespaceId>,
    /// Optional `/proc` PID corresponding to `watched_pid`.
    pub watched_proc_pid: Option<u32>,
}

impl SysmonConfig {
    pub fn new() -> Self {
        Self {
            target_module: None,
            proc_offsets_max_entries: 4096,
            perf_page_count: None,
            event_mask: SysmonEventMask::target_mode(),
            map_change_unfiltered: false,
            watched_pid: None,
            watched_pid_ns: None,
            event_pid_ns: None,
            watched_proc_pid: None,
        }
    }
}

impl Default for SysmonConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Process sysmon — userspace controller that listens for process lifecycle events and
/// performs incremental prefill/cleanup of offsets.
///
/// Note: The low-level event source (tracepoints via eBPF or kernel proc connector) is pluggable.
/// This initial implementation provides the public API and a background loop stub; the event source
/// integration will be wired subsequently.
pub struct ProcessSysmon {
    cfg: SysmonConfig,
    mgr: Arc<Mutex<ProcessManager>>, // shared manager to compute/prefill offsets
    tx: mpsc::SyncSender<SysEvent>,
    rx: mpsc::Receiver<SysEvent>,
    pending_offsets: Arc<Mutex<PendingOffsets>>,
    pending_map_refreshes: Arc<Mutex<PendingMapRefreshes>>,
    handle: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for ProcessSysmon {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ProcessSysmon{..}")
    }
}

impl ProcessSysmon {
    /// Create a new sysmon instance with shared ProcessManager and config.
    pub fn new(mgr: Arc<Mutex<ProcessManager>>, cfg: SysmonConfig) -> Self {
        let (tx, rx) = mpsc::sync_channel(SYSMON_EVENT_QUEUE_CAPACITY);
        Self {
            cfg,
            mgr,
            tx,
            rx,
            pending_offsets: Arc::new(Mutex::new(PendingOffsets::new())),
            pending_map_refreshes: Arc::new(Mutex::new(PendingMapRefreshes::new())),
            handle: None,
        }
    }

    /// Start background monitoring thread and return immediately.
    ///
    /// In the next iteration we will attach eBPF tracepoints (sched_process_exec/exit/fork)
    /// and stream events into this channel. For now, we ensure the pinned offsets map exists
    /// and keep a placeholder loop that can be extended to consume a real source.
    pub fn start(&mut self) {
        let _ =
            pinned_bpf_maps::ensure_pinned_proc_offsets_exists(self.cfg.proc_offsets_max_entries);
        let _ =
            pinned_bpf_maps::ensure_pinned_pid_aliases_exists(self.cfg.proc_offsets_max_entries);
        let _ = pinned_bpf_maps::ensure_pinned_proc_module_ranges_exist(
            self.cfg.proc_offsets_max_entries,
        );
        let _ = pinned_bpf_maps::ensure_pinned_allowed_pids_exists(16_384);

        let tx = self.tx.clone();
        let mgr = Arc::clone(&self.mgr);
        let pending = Arc::clone(&self.pending_offsets);
        let pending_map_refreshes = Arc::clone(&self.pending_map_refreshes);
        let cfg = self.cfg.clone();

        let handle = thread::Builder::new()
            .name("gs-sysmon".to_string())
            .spawn(move || {
                info!("ProcessSysmon thread started");
                #[cfg(feature = "sysmon-ebpf")]
                {
                    if let Err(e) = run_sysmon_loop(mgr, cfg, pending, pending_map_refreshes, tx) {
                        error!("Sysmon loop error: {}", e);
                    }
                }
                #[cfg(not(feature = "sysmon-ebpf"))]
                {
                    let _ = pending;
                    let _ = pending_map_refreshes;
                    let _ = cfg;
                    warn!("sysmon-ebpf feature is disabled; sysmon is in stub mode");
                    loop {
                        std::thread::sleep(std::time::Duration::from_millis(5000));
                    }
                }
                info!("ProcessSysmon thread exiting");
            });
        match handle {
            Ok(h) => self.handle = Some(h),
            Err(e) => {
                error!("Failed to spawn ProcessSysmon thread: {}", e);
                self.handle = None;
            }
        }
    }

    /// Blocking poll (with timeout) for the next system event.
    pub fn recv_timeout(&self, timeout: std::time::Duration) -> Option<SysEvent> {
        match self.rx.recv_timeout(timeout) {
            Ok(ev) => Some(ev),
            Err(mpsc::RecvTimeoutError::Timeout) => None,
            Err(mpsc::RecvTimeoutError::Disconnected) => None,
        }
    }

    /// Handle one system event: prefill on Exec/Fork, cleanup on Exit.
    fn handle_event_with_proc_pid_resolver(
        mgr: &Arc<Mutex<ProcessManager>>,
        target: &Option<PathBuf>,
        pending: &Arc<Mutex<PendingOffsets>>,
        ev: &SysEvent,
        proc_pid_for_event: impl Fn(u32) -> u32,
    ) -> anyhow::Result<()> {
        let kind = match SysEventKind::from_u32(ev.kind) {
            Some(k) => k,
            None => {
                tracing::warn!(
                    "Sysmon: invalid event kind {} for pid {}; ignoring",
                    ev.kind,
                    ev.tgid
                );
                return Ok(());
            }
        };
        tracing::trace!("Sysmon event: kind={:?} event_pid={}", kind, ev.tgid);
        match kind {
            SysEventKind::Exec | SysEventKind::Fork => {
                let proc_pid = proc_pid_for_event(ev.tgid);
                record_runtime_pid_aliases_for_sys_event(mgr, ev, proc_pid);
                if let Some(tpath) = target {
                    let path = tpath.as_path();
                    if crate::util::is_shared_object(path) {
                        if kind == SysEventKind::Exec && !pid_maps_target_module(proc_pid, path) {
                            if pid_alive(proc_pid) {
                                tracing::debug!(
                                    "Sysmon: event pid {} (proc pid {}) does not map target module yet; scheduling retry",
                                    ev.tgid,
                                    proc_pid
                                );
                                if let Ok(mut guard) = pending.lock() {
                                    guard.register_map_change_candidate(ev.tgid, path);
                                }
                            } else {
                                let host_pid = sys_event_host_pid(ev);
                                if host_pid != ev.tgid && pid_alive(host_pid) {
                                    tracing::debug!(
                                        "Sysmon: event pid {} is not visible in current /proc namespace; scheduling host pid {} retry",
                                        ev.tgid,
                                        host_pid
                                    );
                                    if let Ok(mut guard) = pending.lock() {
                                        guard.register_map_change_candidate(host_pid, path);
                                    }
                                } else {
                                    tracing::debug!(
                                        "Sysmon: event pid {} (host pid {}) is not visible in current /proc namespace; skip exec-based target retry",
                                        ev.tgid,
                                        host_pid
                                    );
                                }
                            }
                            return Ok(());
                        } else if let Ok(mut guard) = pending.lock() {
                            guard.remove(ev.tgid);
                        }
                    } else if kind == SysEventKind::Exec {
                        if let Some(actual) = get_comm_from_proc(proc_pid) {
                            let expected = truncate_basename_to_comm(path);
                            if actual.as_bytes() != expected.as_slice() {
                                tracing::warn!(
                                    "Sysmon: comm mismatch for event pid {} (proc pid {}) (actual='{}', expected='{}'); skip prefill/insert",
                                    ev.tgid,
                                    proc_pid,
                                    actual,
                                    core::str::from_utf8(&expected).unwrap_or("")
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                let inserted =
                    prefill_offsets_for_pid(mgr, ev.tgid, target.as_deref(), &proc_pid_for_event)?;
                if inserted {
                    let host_pid = sys_event_host_pid(ev);
                    if host_pid != ev.tgid {
                        let _ = crate::pinned_bpf_maps::insert_allowed_pid(host_pid);
                    }
                }
                if kind == SysEventKind::Exec {
                    if let Some(tpath) = target {
                        if inserted {
                            if let Ok(mut guard) = pending.lock() {
                                guard.remove(ev.tgid);
                            }
                        } else if let Ok(mut guard) = pending.lock() {
                            tracing::debug!(
                                "Sysmon: event pid {} (proc pid {}) prefill inserted no matching offsets; scheduling retry",
                                ev.tgid,
                                proc_pid
                            );
                            guard.register(ev.tgid, tpath.as_path());
                        }
                    }
                }
            }
            SysEventKind::Exit => {
                let proc_pid = proc_pid_for_event(ev.tgid);
                let host_pid = sys_event_host_pid(ev);
                if let Ok(mut guard) = pending.lock() {
                    guard.remove(ev.tgid);
                    if host_pid != ev.tgid {
                        guard.remove(host_pid);
                    }
                }
                if let Ok(mut guard) = mgr.lock() {
                    guard.forget_pid(proc_pid);
                    if proc_pid != ev.tgid {
                        guard.forget_pid(ev.tgid);
                    }
                    if host_pid != ev.tgid && host_pid != proc_pid {
                        guard.forget_pid(host_pid);
                    }
                }
                let purged = purge_runtime_pid_artifacts(proc_pid, ev.tgid, host_pid);
                info!(
                    "Sysmon: observed exit for event pid {} (host pid {}, proc pid {}) (purged {} entries)",
                    ev.tgid,
                    host_pid,
                    proc_pid,
                    purged
                );
            }
            SysEventKind::MapChange => {
                tracing::trace!(
                    "Sysmon: map-change event for pid {} is handled by the debounce queue",
                    ev.tgid
                );
            }
        }
        Ok(())
    }
}

fn try_publish_sys_event(tx: &mpsc::SyncSender<SysEvent>, ev: SysEvent) -> bool {
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

fn dispatch_sysmon_event(
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

fn proc_pid_for_map_change_event(
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

fn pending_map_change_candidates(
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

fn push_pending_map_change_candidate(
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

fn is_current_process_pid(proc_pid: u32) -> bool {
    proc_pid == std::process::id()
}

fn cached_single_target_proc_pid(
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

fn canonicalize_cached_target_proc_pid(
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

fn push_unique_pid(pids: &mut Vec<u32>, pid: u32) {
    if !pids.contains(&pid) {
        pids.push(pid);
    }
}

fn sysmon_proc_pid_resolver(
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

fn write_pinned_runtime_pid_alias(runtime_pid: u32, proc_pid: u32) {
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

fn record_runtime_pid_alias_for_event(
    mgr: &Arc<Mutex<ProcessManager>>,
    runtime_pid: u32,
    proc_pid: u32,
) {
    write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
    if let Ok(mut guard) = mgr.lock() {
        guard.record_runtime_pid_alias(runtime_pid, proc_pid);
    }
}

fn record_runtime_pid_aliases_for_proc_pid_locked(guard: &mut ProcessManager, proc_pid: u32) {
    for runtime_pid in runtime_pid_candidates_for_proc(proc_pid) {
        write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
        guard.record_runtime_pid_alias(runtime_pid, proc_pid);
    }
}

fn record_runtime_pid_aliases_for_proc_pid(mgr: &Arc<Mutex<ProcessManager>>, proc_pid: u32) {
    if let Ok(mut guard) = mgr.lock() {
        record_runtime_pid_aliases_for_proc_pid_locked(&mut guard, proc_pid);
    } else {
        for runtime_pid in runtime_pid_candidates_for_proc(proc_pid) {
            write_pinned_runtime_pid_alias(runtime_pid, proc_pid);
        }
    }
}

fn runtime_pid_keys_for_proc_event(
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

fn record_runtime_pid_aliases_for_keys(
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

fn insert_allowed_runtime_pid_keys(runtime_pids: &[u32]) {
    for runtime_pid in runtime_pids {
        let _ = crate::pinned_bpf_maps::insert_allowed_pid(*runtime_pid);
    }
}

fn publish_offsets_for_runtime_pid_keys(
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

fn purge_offsets_for_runtime_pid_keys(runtime_pids: &[u32]) -> anyhow::Result<usize> {
    let mut purged = 0usize;
    for runtime_pid in runtime_pids {
        purged += crate::pinned_bpf_maps::purge_offsets_for_pid(*runtime_pid)?;
        let _ = crate::pinned_bpf_maps::purge_ranges_for_pid(*runtime_pid);
    }
    Ok(purged)
}

fn purge_runtime_pid_artifacts(proc_pid: u32, event_pid: u32, host_pid: u32) -> usize {
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

fn sys_event_host_pid(ev: &SysEvent) -> u32 {
    if ev.host_tgid != 0 {
        ev.host_tgid
    } else {
        ev.tgid
    }
}

fn record_runtime_pid_aliases_for_sys_event(
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

#[cfg(feature = "sysmon-ebpf")]
#[derive(Debug, Clone, Copy)]
enum SysmonAttachBackend {
    Raw,
    Btf,
    Classic,
}

#[cfg(feature = "sysmon-ebpf")]
impl SysmonAttachBackend {
    fn label(self) -> &'static str {
        match self {
            SysmonAttachBackend::Raw => "raw tracepoint",
            SysmonAttachBackend::Btf => "BTF tracepoint",
            SysmonAttachBackend::Classic => "classic tracepoint",
        }
    }
}

#[cfg(feature = "sysmon-ebpf")]
struct SysmonTracepoint {
    event: &'static str,
    category: &'static str,
    classic_program: &'static str,
    raw_program: &'static str,
    btf_program: &'static str,
}

#[cfg(feature = "sysmon-ebpf")]
const SYSMON_TRACEPOINTS: &[SysmonTracepoint] = &[
    SysmonTracepoint {
        event: "sched_process_exec",
        category: "sched",
        classic_program: "sched_process_exec",
        raw_program: "raw_sched_process_exec",
        btf_program: "btf_sched_process_exec",
    },
    SysmonTracepoint {
        event: "sched_process_exit",
        category: "sched",
        classic_program: "sched_process_exit",
        raw_program: "raw_sched_process_exit",
        btf_program: "btf_sched_process_exit",
    },
    SysmonTracepoint {
        event: "sched_process_fork",
        category: "sched",
        classic_program: "sched_process_fork",
        raw_program: "raw_sched_process_fork",
        btf_program: "btf_sched_process_fork",
    },
];

#[cfg(feature = "sysmon-ebpf")]
struct SysmonMapChangeTracepoint {
    event: &'static str,
    category: &'static str,
    program: &'static str,
}

#[cfg(feature = "sysmon-ebpf")]
const SYSMON_MAP_CHANGE_TRACEPOINTS: &[SysmonMapChangeTracepoint] = &[
    SysmonMapChangeTracepoint {
        event: "sys_exit_mmap",
        category: "syscalls",
        program: "sys_exit_mmap",
    },
    SysmonMapChangeTracepoint {
        event: "sys_exit_mprotect",
        category: "syscalls",
        program: "sys_exit_mprotect",
    },
    SysmonMapChangeTracepoint {
        event: "sys_exit_munmap",
        category: "syscalls",
        program: "sys_exit_munmap",
    },
    SysmonMapChangeTracepoint {
        event: "sys_exit_mremap",
        category: "syscalls",
        program: "sys_exit_mremap",
    },
];

#[cfg(feature = "sysmon-ebpf")]
fn load_sysmon_bpf(obj: &[u8], use_verbose: bool) -> anyhow::Result<aya::Ebpf> {
    use aya::{EbpfLoader, VerifierLogLevel};

    let mut loader = EbpfLoader::new();
    if use_verbose {
        loader.verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS);
        tracing::info!("Sysmon verifier logs: VERBOSE (debug build/log)");
    } else {
        loader.verifier_log_level(VerifierLogLevel::DEBUG | VerifierLogLevel::STATS);
        tracing::info!("Sysmon verifier logs: DEBUG (release/info)");
    }

    let pin_dir = crate::pinned_bpf_maps::proc_offsets_pin_dir()?;
    loader.map_pin_path(
        crate::pinned_bpf_maps::ALLOWED_PIDS_MAP_NAME,
        pin_dir.join(crate::pinned_bpf_maps::ALLOWED_PIDS_MAP_NAME),
    );
    loader.map_pin_path(
        crate::pinned_bpf_maps::TARGET_EXEC_COMM_MAP_NAME,
        pin_dir.join(crate::pinned_bpf_maps::TARGET_EXEC_COMM_MAP_NAME),
    );
    loader.map_pin_path(
        crate::pinned_bpf_maps::SYSMON_MAP_CHANGE_UNFILTERED_MAP_NAME,
        pin_dir.join(crate::pinned_bpf_maps::SYSMON_MAP_CHANGE_UNFILTERED_MAP_NAME),
    );

    Ok(loader.load(obj)?)
}

#[cfg(feature = "sysmon-ebpf")]
fn configure_sysmon_exec_comm_filter(
    bpf: &mut aya::Ebpf,
    target: Option<&Path>,
) -> anyhow::Result<()> {
    use aya::maps::Array;

    let mut filter_bytes = [0u8; 16];
    let mut filter_len = 0usize;
    if let Some(tpath) = target {
        if !crate::util::is_shared_object(tpath) {
            if let Some(name) = tpath.file_name().and_then(|s| s.to_str()) {
                let bytes = name.as_bytes();
                // task->comm stores at most TASK_COMM_LEN - 1 visible bytes plus NUL.
                // Keep the filter null-terminated so long executable basenames compare
                // against the same truncation that bpf_get_current_comm() returns.
                let len = bytes.len().min(filter_bytes.len() - 1);
                filter_bytes[..len].copy_from_slice(&bytes[..len]);
                filter_len = len;
            } else {
                tracing::warn!(
                    "Sysmon: target basename contains non-UTF8 bytes; exec comm filter disabled"
                );
            }
        }
    }

    if let Some(map) = bpf.map_mut("target_exec_comm") {
        let mut array: Array<_, [u8; 16]> = map.try_into()?;
        array.set(0, filter_bytes, 0)?;
        if filter_len > 0 {
            match std::str::from_utf8(&filter_bytes[..filter_len]) {
                Ok(name_str) => {
                    tracing::info!("Sysmon: exec comm filter configured for '{}'", name_str)
                }
                Err(_) => tracing::info!(
                    "Sysmon: exec comm filter configured (non-UTF8 basename, len={})",
                    filter_len
                ),
            }
        } else {
            tracing::info!("Sysmon: exec comm filter disabled");
        }
    } else if filter_len > 0 {
        tracing::warn!("Sysmon: target_exec_comm map missing; exec filtering unavailable");
    }

    Ok(())
}

#[cfg(feature = "sysmon-ebpf")]
fn configure_sysmon_event_filter(
    bpf: &mut aya::Ebpf,
    event_mask: SysmonEventMask,
    map_change_unfiltered: bool,
    watched_pid: Option<u32>,
    watched_pid_ns: Option<PidNamespaceId>,
    event_pid_ns: Option<PidNamespaceId>,
) -> anyhow::Result<()> {
    use aya::maps::Array;

    if let Some(map) = bpf.map_mut("sysmon_event_mask") {
        let mut array: Array<_, u32> = map.try_into()?;
        array.set(0, event_mask.bits(), 0)?;
        tracing::info!(
            "Sysmon: event mask configured (exec={}, fork={}, exit={}, map_change={})",
            event_mask.exec,
            event_mask.fork,
            event_mask.exit,
            event_mask.map_change
        );
    } else {
        tracing::warn!("Sysmon: sysmon_event_mask map missing; event filtering unavailable");
    }

    if let Some(map) = bpf.map_mut("sysmon_map_change_unfiltered") {
        let mut array: Array<_, u32> = map.try_into()?;
        array.set(0, u32::from(map_change_unfiltered), 0)?;
        tracing::info!(
            "Sysmon: map-change pre-allowlist emission {}",
            if map_change_unfiltered {
                "enabled"
            } else {
                "disabled"
            }
        );
    } else if map_change_unfiltered {
        tracing::warn!(
            "Sysmon: sysmon_map_change_unfiltered map missing; pre-allowlist map-change events unavailable"
        );
    }

    if let Some(map) = bpf.map_mut("sysmon_watched_pid") {
        let mut array: Array<_, u32> = map.try_into()?;
        array.set(0, watched_pid.unwrap_or(0), 0)?;
        if let Some(pid) = watched_pid {
            tracing::info!("Sysmon: watched event pid configured: {}", pid);
        } else {
            tracing::info!("Sysmon: watched event pid disabled");
        }
    } else if watched_pid.is_some() {
        tracing::warn!("Sysmon: sysmon_watched_pid map missing; PID filtering unavailable");
    }

    let watched_pid_ns = watched_pid.and(watched_pid_ns);
    let ns_spec = watched_pid_ns.and_then(|pid_ns| pid_ns.helper_dev_inode());
    let (ns_dev, ns_ino) = ns_spec.unwrap_or((0, 0));

    if let Some(map) = bpf.map_mut("sysmon_watched_pid_ns_dev") {
        let mut array: Array<_, u64> = map.try_into()?;
        array.set(0, ns_dev, 0)?;
    } else if ns_spec.is_some() {
        tracing::warn!(
            "Sysmon: sysmon_watched_pid_ns_dev map missing; namespace PID filtering unavailable"
        );
    }

    if let Some(map) = bpf.map_mut("sysmon_watched_pid_ns_ino") {
        let mut array: Array<_, u64> = map.try_into()?;
        array.set(0, ns_ino, 0)?;
    } else if ns_spec.is_some() {
        tracing::warn!(
            "Sysmon: sysmon_watched_pid_ns_ino map missing; namespace PID filtering unavailable"
        );
    }

    if let (Some(pid), Some((dev, ino))) = (watched_pid, ns_spec) {
        tracing::info!(
            "Sysmon: watched PID namespace configured: pid={} ns_dev={} ns_inode={}",
            pid,
            dev,
            ino
        );
    }

    let event_ns_spec = event_pid_ns.and_then(|pid_ns| pid_ns.helper_dev_inode());
    let (event_ns_dev, event_ns_ino) = event_ns_spec.unwrap_or((0, 0));

    if let Some(map) = bpf.map_mut("sysmon_event_pid_ns_dev") {
        let mut array: Array<_, u64> = map.try_into()?;
        array.set(0, event_ns_dev, 0)?;
    } else if event_ns_spec.is_some() {
        tracing::warn!(
            "Sysmon: sysmon_event_pid_ns_dev map missing; event namespace reporting unavailable"
        );
    }

    if let Some(map) = bpf.map_mut("sysmon_event_pid_ns_ino") {
        let mut array: Array<_, u64> = map.try_into()?;
        array.set(0, event_ns_ino, 0)?;
    } else if event_ns_spec.is_some() {
        tracing::warn!(
            "Sysmon: sysmon_event_pid_ns_ino map missing; event namespace reporting unavailable"
        );
    }

    if let Some((dev, ino)) = event_ns_spec {
        tracing::info!(
            "Sysmon: event PID namespace configured: ns_dev={} ns_inode={}",
            dev,
            ino
        );
    }

    Ok(())
}

#[cfg(feature = "sysmon-ebpf")]
fn attach_sysmon_backend(bpf: &mut aya::Ebpf, backend: SysmonAttachBackend) -> anyhow::Result<()> {
    match backend {
        SysmonAttachBackend::Raw => attach_raw_sysmon_tracepoints(bpf),
        SysmonAttachBackend::Btf => attach_btf_sysmon_tracepoints(bpf),
        SysmonAttachBackend::Classic => attach_classic_sysmon_tracepoints(bpf),
    }
}

#[cfg(feature = "sysmon-ebpf")]
fn attach_raw_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use aya::programs::RawTracePoint;

    for spec in SYSMON_TRACEPOINTS {
        let prog = bpf.program_mut(spec.raw_program).ok_or_else(|| {
            anyhow::anyhow!("missing program '{}' in sysmon-bpf", spec.raw_program)
        })?;
        let tp: &mut RawTracePoint = prog.try_into()?;
        tp.load()?;
        tp.attach(spec.event)?;
        info!("Attached raw tracepoint: {}", spec.event);
    }
    Ok(())
}

#[cfg(feature = "sysmon-ebpf")]
fn attach_btf_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use aya::{programs::BtfTracePoint, Btf};

    let btf = Btf::from_sys_fs().context("kernel BTF is unavailable")?;
    for spec in SYSMON_TRACEPOINTS {
        let prog = bpf.program_mut(spec.btf_program).ok_or_else(|| {
            anyhow::anyhow!("missing program '{}' in sysmon-bpf", spec.btf_program)
        })?;
        let tp: &mut BtfTracePoint = prog.try_into()?;
        tp.load(spec.event, &btf)?;
        tp.attach()?;
        info!("Attached BTF tracepoint: {}", spec.event);
    }
    Ok(())
}

#[cfg(feature = "sysmon-ebpf")]
fn attach_classic_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    use aya::programs::TracePoint;

    for spec in SYSMON_TRACEPOINTS {
        let prog = bpf.program_mut(spec.classic_program).ok_or_else(|| {
            anyhow::anyhow!("missing program '{}' in sysmon-bpf", spec.classic_program)
        })?;
        let tp: &mut TracePoint = prog.try_into()?;
        tp.load()?;
        tp.attach(spec.category, spec.event)?;
        info!(
            "Attached classic tracepoint: {}:{}",
            spec.category, spec.event
        );
    }
    Ok(())
}

#[cfg(feature = "sysmon-ebpf")]
fn attach_classic_map_change_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<usize> {
    use aya::programs::TracePoint;

    let mut attached = 0usize;
    for spec in SYSMON_MAP_CHANGE_TRACEPOINTS {
        let Some(prog) = bpf.program_mut(spec.program) else {
            tracing::warn!(
                "Sysmon: missing map-change program '{}' in sysmon-bpf",
                spec.program
            );
            continue;
        };
        let attach_result = (|| {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach(spec.category, spec.event)?;
            Ok::<_, anyhow::Error>(())
        })();
        match attach_result {
            Ok(()) => {
                attached += 1;
                info!(
                    "Attached map-change tracepoint: {}:{}",
                    spec.category, spec.event
                );
            }
            Err(err) => {
                tracing::warn!(
                    "Sysmon: map-change tracepoint {}:{} unavailable: {:#}",
                    spec.category,
                    spec.event,
                    err
                );
            }
        }
    }

    Ok(attached)
}

#[cfg(feature = "sysmon-ebpf")]
fn load_and_attach_sysmon_bpf(
    obj: &[u8],
    cfg: &SysmonConfig,
    use_verbose: bool,
) -> anyhow::Result<aya::Ebpf> {
    let mut failures = Vec::new();
    for backend in [
        SysmonAttachBackend::Raw,
        SysmonAttachBackend::Btf,
        SysmonAttachBackend::Classic,
    ] {
        tracing::info!("Sysmon: trying {} backend", backend.label());
        let result = (|| {
            let mut bpf = load_sysmon_bpf(obj, use_verbose)?;
            configure_sysmon_exec_comm_filter(&mut bpf, cfg.target_module.as_deref())?;
            configure_sysmon_event_filter(
                &mut bpf,
                cfg.event_mask,
                cfg.map_change_unfiltered,
                cfg.watched_pid,
                cfg.watched_pid_ns,
                cfg.event_pid_ns,
            )?;
            attach_sysmon_backend(&mut bpf, backend)?;
            if cfg.event_mask.map_change {
                let map_attached = attach_classic_map_change_tracepoints(&mut bpf)?;
                if map_attached == 0 {
                    if !cfg.event_mask.has_lifecycle_events() {
                        return Err(anyhow::anyhow!(
                            "map-change events requested but no syscall tracepoints attached"
                        ));
                    }

                    let fallback_mask = cfg.event_mask.without_map_change();
                    configure_sysmon_event_filter(
                        &mut bpf,
                        fallback_mask,
                        cfg.map_change_unfiltered,
                        cfg.watched_pid,
                        cfg.watched_pid_ns,
                        cfg.event_pid_ns,
                    )?;
                    tracing::warn!(
                        "Sysmon: map-change events requested but no syscall tracepoints attached; \
                         continuing with exec/fork/exit lifecycle events only"
                    );
                }
            }
            Ok::<_, anyhow::Error>(bpf)
        })();

        match result {
            Ok(bpf) => {
                tracing::info!("Sysmon: using {} backend", backend.label());
                return Ok(bpf);
            }
            Err(err) => {
                tracing::warn!("Sysmon: {} backend unavailable: {:#}", backend.label(), err);
                failures.push(format!("{}: {err:#}", backend.label()));
            }
        }
    }

    Err(anyhow::anyhow!(
        "no sysmon tracepoint backend available ({})",
        failures.join("; ")
    ))
}

#[cfg(feature = "sysmon-ebpf")]
fn run_sysmon_loop(
    mgr: Arc<Mutex<ProcessManager>>,
    cfg: SysmonConfig,
    pending: Arc<Mutex<PendingOffsets>>,
    pending_map_refreshes: Arc<Mutex<PendingMapRefreshes>>,
    tx: mpsc::SyncSender<SysEvent>,
) -> anyhow::Result<()> {
    use aya::include_bytes_aligned;
    use aya::maps::{
        perf::{PerfEvent, PerfEventArray},
        ring_buf::RingBuf,
        MapData,
    };
    use log::{log_enabled, Level as LogLevel};
    // Load eBPF object (copied to OUT_DIR at build time)
    #[allow(unused_variables)]
    let obj_le: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sysmon-bpf.bpfel.o"));
    #[allow(unused_variables)]
    let obj_be: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/sysmon-bpf.bpfeb.o"));
    let obj: &[u8] = if cfg!(target_endian = "little") {
        obj_le
    } else {
        obj_be
    };
    if obj.is_empty() {
        warn!("sysmon-bpf object missing; running in stub mode (no realtime process events)");
        return Ok(());
    }
    let target = cfg.target_module.clone();
    let use_verbose =
        cfg!(debug_assertions) || log_enabled!(LogLevel::Trace) || log_enabled!(LogLevel::Debug);
    let mut bpf = load_and_attach_sysmon_bpf(obj, &cfg, use_verbose)?;
    let proc_pid_for_event = sysmon_proc_pid_resolver(cfg.watched_pid, cfg.watched_proc_pid);

    // Using allowlist-based gating in kernel; userspace decides allow on exec.

    // Initial prefill for late-start cases: compute and insert offsets for already-running PIDs.
    if let Some(tpath) = &target {
        let mut initial_target_pids: BTreeSet<u32> = BTreeSet::new();
        if let Ok(mut guard) = mgr.lock() {
            if let Ok(prefilled) = guard.ensure_prefill_module(tpath.to_string_lossy().as_ref()) {
                tracing::info!(
                    "Sysmon: initial prefill cached {} pid(s) for module {}",
                    prefilled,
                    tpath.display()
                );
                let entries = guard.cached_offsets_for_module(tpath.to_string_lossy().as_ref());
                if !entries.is_empty() {
                    use crate::pinned_bpf_maps::ProcModuleOffsetsValue;
                    let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> =
                        HashMap::new();
                    for (pid, cookie, off, base, size) in entries {
                        if is_current_process_pid(pid) {
                            continue;
                        }
                        by_pid.entry(pid).or_default().push((
                            cookie,
                            ProcModuleOffsetsValue::new(
                                off.text, off.rodata, off.data, off.bss, base, size,
                            ),
                        ));
                    }
                    let mut total = 0usize;
                    for (pid, items) in by_pid {
                        initial_target_pids.insert(pid);
                        // Add event PID (kernel namespace) to allowlist so subsequent
                        // fork/exit events are filtered in-kernel.
                        let event_pid = resolve_event_pid_for_proc(pid);
                        let runtime_pids = runtime_pid_keys_for_proc_event(pid, event_pid, []);
                        for runtime_pid in &runtime_pids {
                            write_pinned_runtime_pid_alias(*runtime_pid, pid);
                            guard.record_runtime_pid_alias(*runtime_pid, pid);
                        }
                        if let Ok(n) = publish_offsets_for_runtime_pid_keys(
                            pid,
                            event_pid,
                            &runtime_pids,
                            &items,
                            "initial prefill",
                        ) {
                            total += n;
                        }
                        insert_allowed_runtime_pid_keys(&runtime_pids);
                    }
                    tracing::info!(
                        "Sysmon: initial inserted {} offset entries for module {}",
                        total,
                        tpath.display()
                    );
                }
            }
        }
        for pid in initial_target_pids {
            let event_pid = resolve_event_pid_for_proc(pid);
            if let Err(e) =
                prefill_full_offsets_for_pid_if_new(&mgr, event_pid, &proc_pid_for_event)
            {
                tracing::debug!(
                    "Sysmon: initial full offset prefill failed for proc pid {} (event pid {}): {}",
                    pid,
                    event_pid,
                    e
                );
            }
        }
    }
    tracing::info!("Sysmon: setup complete");
    // Initial prefill already ran above. Do not make the first periodic module
    // refresh immediately due: for `-t executable`, the exec event is the fast
    // path that inserts proc_module_offsets and allowed_pids. A fallback /proc
    // scan here can delay a short-lived target past its only probe.
    let mut last_module_refresh = Instant::now();
    let mut target_pid_map_signatures = HashMap::<u32, PidMapsSignature>::new();

    // Event loop: prefer ringbuf; fallback to perf
    if let Some(map) = bpf.take_map("sysmon_events") {
        let mut rb: RingBuf<MapData> = map.try_into()?;
        loop {
            let mut had_event = false;
            // Drain queued lifecycle events before periodic refresh. In the
            // short-lived `-t executable` path, sched_process_exec must be
            // handled promptly so offsets are ready before the first uprobe.
            while let Some(item) = rb.next() {
                had_event = true;
                if item.len() == core::mem::size_of::<SysEvent>() {
                    // SAFETY: The ring buffer sample length was checked to match SysEvent;
                    // read_unaligned handles any alignment from the byte slice.
                    let ev = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const SysEvent) };
                    let matched = dispatch_sysmon_event(
                        &mgr,
                        &target,
                        &pending,
                        &pending_map_refreshes,
                        &proc_pid_for_event,
                        &ev,
                    );
                    if matched {
                        try_publish_sys_event(&tx, ev);
                    }
                }
            }
            poll_pending_offsets(&mgr, &pending, &proc_pid_for_event);
            poll_pending_map_refreshes(
                &mgr,
                target.as_deref(),
                &pending_map_refreshes,
                &pending,
                &tx,
            );
            refresh_target_module_offsets(
                &mgr,
                target.as_deref(),
                &mut last_module_refresh,
                &mut target_pid_map_signatures,
                &tx,
            );
            if !had_event {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    } else if let Some(map) = bpf.take_map("sysmon_events_perf") {
        let mut perf: PerfEventArray<_> = map.try_into()?;
        let online = aya::util::online_cpus().map_err(|(_, e)| anyhow::anyhow!(e))?;
        let mut bufs = Vec::new();
        for cpu in online {
            match perf.open(cpu, cfg.perf_page_count) {
                Ok(buf) => bufs.push(buf),
                Err(e) => warn!("Perf open failed for CPU {}: {}", cpu, e),
            }
        }
        if bufs.is_empty() {
            return Err(anyhow::anyhow!("No perf buffers opened"));
        }
        loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            for buf in bufs.iter_mut() {
                if !buf.readable() {
                    continue;
                }
                buf.for_each(|event| match event {
                    PerfEvent::Sample { head, tail } => {
                        let mut raw = [0u8; core::mem::size_of::<SysEvent>()];
                        let mut copied = 0;
                        for chunk in [head, tail] {
                            let remaining = raw.len().saturating_sub(copied);
                            if remaining == 0 {
                                break;
                            }
                            let take = chunk.len().min(remaining);
                            raw[copied..copied + take].copy_from_slice(&chunk[..take]);
                            copied += take;
                        }
                        if copied == raw.len() {
                            // SAFETY: raw is exactly the size of SysEvent and read_unaligned
                            // handles the byte array's alignment.
                            let ev = unsafe {
                                core::ptr::read_unaligned(raw.as_ptr() as *const SysEvent)
                            };
                            let matched = dispatch_sysmon_event(
                                &mgr,
                                &target,
                                &pending,
                                &pending_map_refreshes,
                                &proc_pid_for_event,
                                &ev,
                            );
                            if matched {
                                try_publish_sys_event(&tx, ev);
                            }
                        }
                    }
                    PerfEvent::Lost { count } => {
                        warn!("Perf event buffer lost {} sysmon events", count);
                    }
                });
            }
            poll_pending_offsets(&mgr, &pending, &proc_pid_for_event);
            poll_pending_map_refreshes(
                &mgr,
                target.as_deref(),
                &pending_map_refreshes,
                &pending,
                &tx,
            );
            refresh_target_module_offsets(
                &mgr,
                target.as_deref(),
                &mut last_module_refresh,
                &mut target_pid_map_signatures,
                &tx,
            );
        }
    } else {
        return Err(anyhow::anyhow!("No sysmon events map found (ringbuf/perf)"));
    }
}

/* moved to ghostscope_process::util::is_shared_object
fn looks_like_shared_object(path: &Path) -> bool {
    // Determine shared object by ELF metadata:
    // - ET_EXEC => executable (not shared)
    // - ET_DYN + PT_INTERP present => PIE executable (not shared)
    // - ET_DYN without PT_INTERP => shared library
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    const EI_CLASS: usize = 4; // 1=32-bit, 2=64-bit
    const EI_DATA: usize = 5; // 1=little, 2=big
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const PT_INTERP: u32 = 3;

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false, // conservative: treat as executable (enable filtering)
    };
    let mut ehdr = [0u8; 64];
    if f.read(&mut ehdr).ok().filter(|&n| n >= 52).is_none() {
        return false;
    }
    // ELF magic
    if &ehdr[0..4] != b"\x7FELF" {
        return false;
    }
    let class = ehdr[EI_CLASS];
    let data = ehdr[EI_DATA];
    let is_le = data == 1;
    // read u16/u32/u64 helpers
    let rd16 = |b: &[u8]| -> u16 {
        if is_le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let rd32 = |b: &[u8]| -> u32 {
        if is_le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let rd64 = |b: &[u8]| -> u64 {
        if is_le {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
    };

    // e_type at 0x10
    let e_type = rd16(&ehdr[16..18]);
    if e_type == ET_EXEC {
        return false; // executable
    }

    // program header table offsets
    let (e_phoff, e_phentsize, e_phnum) = match class {
        1 => {
            // ELF32: e_phoff @0x1C (4), e_phentsize @0x2A (2), e_phnum @0x2C (2)
            let phoff = rd32(&ehdr[28..32]) as u64;
            let entsz = rd16(&ehdr[42..44]) as u64;
            let phnum = rd16(&ehdr[44..46]) as u64;
            (phoff, entsz, phnum)
        }
        2 => {
            // ELF64: e_phoff @0x20 (8), e_phentsize @0x36 (2), e_phnum @0x38 (2)
            let phoff = rd64(&ehdr[32..40]);
            let entsz = rd16(&ehdr[54..56]) as u64;
            let phnum = rd16(&ehdr[56..58]) as u64;
            (phoff, entsz, phnum)
        }
        _ => return false,
    };

    if e_type == ET_DYN {
        // Scan program headers for PT_INTERP
        if e_phoff == 0 || e_phentsize < 4 || e_phnum == 0 {
            // malformed
            // If cannot inspect, be conservative and treat as shared library (disable filtering)
            return true;
        }
        // Seek and read each p_type
        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if f.seek(SeekFrom::Start(off)).is_err() {
                return true;
            }
            let mut p = [0u8; 8];
            if f.read(&mut p[..4]).ok().filter(|&n| n == 4).is_none() {
                return true;
            }
            let p_type = rd32(&p[..4]);
            if p_type == PT_INTERP {
                return false; // PIE executable
            }
        }
        return true; // ET_DYN w/o PT_INTERP => shared library
    }

    // Unknown types: default to 'not shared' (enable filtering)
    false
}
*/

fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn filter_entries_for_target<'a>(
    entries: &'a [PidOffsetsEntry],
    target: Option<&Path>,
) -> Vec<&'a PidOffsetsEntry> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    if let Some(tpath) = target {
        match fs::metadata(tpath) {
            Ok(meta) => {
                let t_dev = meta.dev();
                let t_ino = meta.ino();
                entries
                    .iter()
                    .filter(|e| {
                        fs::metadata(&e.module_path)
                            .map(|m| m.dev() == t_dev && m.ino() == t_ino)
                            .unwrap_or(false)
                    })
                    .collect()
            }
            Err(_) => {
                let tc = cookie_for_path(&tpath.to_string_lossy());
                let by_cookie: Vec<_> = entries.iter().filter(|e| e.cookie == tc).collect();
                if !by_cookie.is_empty() {
                    by_cookie
                } else {
                    let tnorm = tpath.to_string_lossy().replace("/./", "/");
                    entries.iter().filter(|e| e.module_path == tnorm).collect()
                }
            }
        }
    } else {
        entries.iter().collect()
    }
}

fn prefill_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    target: Option<&Path>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    write_offsets_for_pid(mgr, event_pid, target, false, &[], proc_pid_for_event)
}

fn refresh_offsets_for_known_proc_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
) -> anyhow::Result<bool> {
    let proc_pid_for_event = |_: u32| proc_pid;
    write_offsets_for_pid(mgr, event_pid, None, true, &[host_pid], &proc_pid_for_event)
}

fn write_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    target: Option<&Path>,
    force_refresh: bool,
    extra_runtime_pids: &[u32],
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    let proc_pid = proc_pid_for_event(event_pid);
    let runtime_pids =
        runtime_pid_keys_for_proc_event(proc_pid, event_pid, extra_runtime_pids.iter().copied());
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);
    let mut inserted_any = false;
    if let Ok(mut guard) = mgr.lock() {
        if target.is_some() && is_current_process_pid(proc_pid) {
            tracing::debug!(
                "Sysmon: skipping self proc pid {} for target-module offset prefill",
                proc_pid
            );
            return Ok(false);
        }
        let prefilled = match if force_refresh {
            guard.refresh_prefill_pid(proc_pid)
        } else {
            guard.ensure_prefill_pid(proc_pid)
        } {
            Ok(v) => v,
            Err(e) => {
                // In private PID namespaces, sysmon event PID may be in the initial namespace
                // and not resolvable via /proc/<event_pid>. Fall back to module-wide refresh.
                if let Some(target_path) = target {
                    let module_path = target_path.to_string_lossy().to_string();
                    tracing::debug!(
                        "Sysmon: pid prefill failed for event pid {} (proc pid {}): {}; falling back to module refresh for {}",
                        event_pid,
                        proc_pid,
                        e,
                        module_path
                    );
                    let refreshed = guard.refresh_prefill_module(&module_path)?;
                    if refreshed > 0 {
                        tracing::info!(
                            "Sysmon: module refresh cached {} pid(s) for {}",
                            refreshed,
                            module_path
                        );
                    }
                    let mut target_pids = BTreeSet::new();
                    for (pid, _, _, _, _) in guard.cached_offsets_for_module(&module_path) {
                        target_pids.insert(pid);
                    }
                    drop(guard);

                    for pid in target_pids {
                        let runtime_pid = resolve_event_pid_for_proc(pid);
                        match refresh_full_offsets_for_pid(mgr, pid, runtime_pid) {
                            Ok(true) => inserted_any = true,
                            Ok(false) => {}
                            Err(err) => tracing::warn!(
                                "Sysmon: module refresh failed to publish full snapshot for proc pid {}: {}",
                                pid,
                                err
                            ),
                        }
                    }
                    return Ok(inserted_any);
                }
                return Err(e);
            }
        };
        if prefilled > 0 {
            info!(
                "Sysmon: {} {} entries for event pid {} (proc pid {})",
                if force_refresh {
                    "refreshed"
                } else {
                    "prefilled"
                },
                prefilled,
                event_pid,
                proc_pid
            );
        }
        let mut entries = guard
            .cached_offsets_with_paths_for_pid(proc_pid)
            .map(|entries| entries.to_vec())
            .unwrap_or_default();
        let mut target_match_count = filter_entries_for_target(&entries, target).len();

        if target_match_count == 0 && target.is_some() {
            let refreshed = guard.refresh_prefill_pid(proc_pid)?;
            if refreshed > 0 {
                tracing::debug!(
                    "Sysmon: refreshed {} cached entries for event pid {} (proc pid {})",
                    refreshed,
                    event_pid,
                    proc_pid
                );
            }
            entries = guard
                .cached_offsets_with_paths_for_pid(proc_pid)
                .map(|entries| entries.to_vec())
                .unwrap_or_default();
            target_match_count = filter_entries_for_target(&entries, target).len();
        }

        if force_refresh && target.is_none() {
            let purged = purge_offsets_for_runtime_pid_keys(&runtime_pids)?;
            if purged > 0 {
                tracing::debug!(
                    "Sysmon: purged {} stale offset entries before map-change refresh for event pid {} (proc pid {}, runtime keys={:?})",
                    purged,
                    event_pid,
                    proc_pid,
                    runtime_pids
                );
            }
        }

        if !entries.is_empty() && (target.is_none() || target_match_count > 0) {
            let items = offset_items_from_entries(entries.iter());
            match publish_offsets_for_runtime_pid_keys(
                proc_pid,
                event_pid,
                &runtime_pids,
                &items,
                "prefill",
            ) {
                Ok(inserted) => {
                    if inserted == 0 {
                        tracing::warn!(
                            "Sysmon: no offsets inserted for event pid {} (proc pid {}, runtime keys={:?}) (entry count={})",
                            event_pid,
                            proc_pid,
                            runtime_pids,
                            items.len()
                        );
                    } else {
                        tracing::info!(
                            "Sysmon: inserted {} offset entries for event pid {} (proc pid {}, runtime keys={:?})",
                            inserted,
                            event_pid,
                            proc_pid,
                            runtime_pids
                        );
                        insert_allowed_runtime_pid_keys(&runtime_pids);
                        inserted_any = true;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Sysmon: failed to insert offsets for event pid {} (proc pid {}): {}",
                        event_pid,
                        proc_pid,
                        e
                    );
                }
            }
        } else if target.is_some() {
            tracing::debug!(
                "Sysmon: event pid {} (proc pid {}) does not map target module; skip",
                event_pid,
                proc_pid
            );
        }
    }
    Ok(inserted_any)
}

fn prefill_full_offsets_for_pid_if_new(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    let proc_pid = proc_pid_for_event(event_pid);
    let runtime_pids = runtime_pid_keys_for_proc_event(proc_pid, event_pid, []);
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);

    let items = {
        let Ok(mut guard) = mgr.lock() else {
            return Ok(false);
        };
        let prefilled = guard.ensure_prefill_pid(proc_pid)?;
        if prefilled == 0 {
            return Ok(false);
        }
        let Some(entries) = guard.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(false);
        };
        offset_items_from_entries(entries.iter())
    };

    if items.is_empty() {
        return Ok(false);
    }

    match publish_offsets_for_runtime_pid_keys(
        proc_pid,
        event_pid,
        &runtime_pids,
        &items,
        "full prefill",
    ) {
        Ok(inserted) if inserted > 0 => {
            tracing::info!(
                "Sysmon: inserted {} full offset entries for event pid {} (proc pid {}, runtime keys={:?})",
                inserted,
                event_pid,
                proc_pid,
                runtime_pids
            );
            insert_allowed_runtime_pid_keys(&runtime_pids);
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) => {
            tracing::warn!(
                "Sysmon: failed to insert full offsets for event pid {} (proc pid {}): {}",
                event_pid,
                proc_pid,
                e
            );
            Ok(false)
        }
    }
}

type PidMapsSignature = Vec<(String, u64, u64, u64, u64, u64, bool)>;

fn pid_maps_signature(pid: u32) -> anyhow::Result<PidMapsSignature> {
    let mut signature = read_proc_maps(pid)?
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path()?;
            if should_skip_mapped_module_path(path) {
                return None;
            }
            Some((
                normalize_mapped_module_path(path).to_string(),
                entry.start,
                entry.end,
                entry.offset,
                entry.inode,
                (entry.dev_major << 32) | entry.dev_minor,
                entry.executable(),
            ))
        })
        .collect::<Vec<_>>();
    signature.sort_unstable();
    Ok(signature)
}

fn refresh_full_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    proc_pid: u32,
    event_pid: u32,
) -> anyhow::Result<bool> {
    let runtime_pids = runtime_pid_keys_for_proc_event(proc_pid, event_pid, []);
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);

    let items = {
        let Ok(mut guard) = mgr.lock() else {
            return Ok(false);
        };
        guard.refresh_prefill_pid(proc_pid)?;
        let Some(entries) = guard.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(false);
        };
        offset_items_from_entries(entries.iter())
    };

    if items.is_empty() {
        return Ok(false);
    }

    let purged = purge_offsets_for_runtime_pid_keys(&runtime_pids)?;
    if purged > 0 {
        tracing::debug!(
            "Sysmon: purged {} stale offset entries before periodic full refresh for proc pid {} (runtime keys={:?})",
            purged,
            proc_pid,
            runtime_pids
        );
    }
    let inserted = publish_offsets_for_runtime_pid_keys(
        proc_pid,
        event_pid,
        &runtime_pids,
        &items,
        "periodic full refresh",
    )?;
    insert_allowed_runtime_pid_keys(&runtime_pids);
    tracing::debug!(
        "Sysmon: periodic full refresh wrote {} offset entries for proc pid {} (event pid {}, runtime keys={:?})",
        inserted,
        proc_pid,
        event_pid,
        runtime_pids
    );
    Ok(inserted > 0)
}

fn offset_items_from_entries<'a>(
    entries: impl IntoIterator<Item = &'a PidOffsetsEntry>,
) -> Vec<(u64, crate::pinned_bpf_maps::ProcModuleOffsetsValue)> {
    entries
        .into_iter()
        .map(|e| {
            (
                e.cookie,
                crate::pinned_bpf_maps::ProcModuleOffsetsValue::new(
                    e.offsets.text,
                    e.offsets.rodata,
                    e.offsets.data,
                    e.offsets.bss,
                    e.base,
                    e.size,
                ),
            )
        })
        .collect()
}

fn refresh_target_module_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    last_refresh: &mut Instant,
    target_pid_map_signatures: &mut HashMap<u32, PidMapsSignature>,
    tx: &mpsc::SyncSender<SysEvent>,
) {
    use crate::pinned_bpf_maps::{allowed_pid_exists, ProcModuleOffsetsValue};

    let Some(target_path) = target else {
        return;
    };
    let now = Instant::now();
    if now.duration_since(*last_refresh) < MODULE_REFRESH_INTERVAL {
        return;
    }
    *last_refresh = now;

    let module_path = target_path.to_string_lossy().to_string();
    let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> = HashMap::new();
    let mut target_pids: BTreeSet<u32> = BTreeSet::new();
    if let Ok(mut guard) = mgr.lock() {
        if let Err(e) = guard.refresh_prefill_module(&module_path) {
            tracing::debug!(
                "Sysmon: periodic module refresh failed for {}: {}",
                module_path,
                e
            );
            return;
        }
        for (pid, cookie, off, base, size) in guard.cached_offsets_for_module(&module_path) {
            if is_current_process_pid(pid) {
                continue;
            }
            target_pids.insert(pid);
            by_pid.entry(pid).or_default().push((
                cookie,
                ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss, base, size),
            ));
        }
    }
    if by_pid.is_empty() {
        return;
    }

    let mut total = 0usize;
    let mut newly_allowed_event_pids = BTreeSet::new();
    for (pid, items) in by_pid {
        let event_pid = resolve_event_pid_for_proc(pid);
        let runtime_pids = runtime_pid_keys_for_proc_event(pid, event_pid, []);
        record_runtime_pid_aliases_for_keys(mgr, pid, &runtime_pids);
        let was_allowed = match allowed_pid_exists(event_pid) {
            Ok(value) => value,
            Err(e) => {
                tracing::debug!(
                    "Sysmon: allowed_pids lookup failed for event pid {} (proc pid {}): {}",
                    event_pid,
                    pid,
                    e
                );
                false
            }
        };
        match publish_offsets_for_runtime_pid_keys(
            pid,
            event_pid,
            &runtime_pids,
            &items,
            "periodic module refresh",
        ) {
            Ok(inserted) => {
                if inserted > 0 {
                    total += inserted;
                    insert_allowed_runtime_pid_keys(&runtime_pids);
                    if !was_allowed {
                        tracing::debug!(
                            "Sysmon: event pid {} became allowed during periodic module refresh",
                            event_pid
                        );
                        newly_allowed_event_pids.insert(event_pid);
                    }
                }
            }
            Err(e) => tracing::debug!(
                "Sysmon: periodic module refresh insert failed for pid {} ({}): {}",
                pid,
                module_path,
                e
            ),
        }
    }
    for pid in &target_pids {
        let event_pid = resolve_event_pid_for_proc(*pid);
        let maps_signature = match pid_maps_signature(*pid) {
            Ok(signature) => signature,
            Err(e) => {
                tracing::debug!(
                    "Sysmon: periodic maps signature failed for proc pid {} (event pid {}): {}",
                    *pid,
                    event_pid,
                    e
                );
                continue;
            }
        };
        if target_pid_map_signatures.get(pid) == Some(&maps_signature) {
            continue;
        }
        target_pid_map_signatures.insert(*pid, maps_signature);

        match refresh_full_offsets_for_pid(mgr, *pid, event_pid) {
            Ok(true) => {
                newly_allowed_event_pids.insert(event_pid);
            }
            Ok(false) => {}
            Err(e) => {
                tracing::debug!(
                    "Sysmon: periodic full offset refresh failed for proc pid {} (event pid {}): {}",
                    *pid,
                    event_pid,
                    e
                );
            }
        }
    }
    target_pid_map_signatures.retain(|pid, _| target_pids.contains(pid));
    for event_pid in newly_allowed_event_pids {
        let ev = SysEvent {
            tgid: event_pid,
            host_tgid: event_pid,
            kind: SysEventKind::MapChange.as_u32(),
        };
        if try_publish_sys_event(tx, ev) {
            tracing::debug!(
                "Sysmon: published synthetic map-change for newly discovered target pid {}",
                event_pid
            );
        }
    }
    if total > 0 {
        tracing::debug!(
            "Sysmon: periodic module refresh inserted {} offset entries for {}",
            total,
            module_path
        );
    }
}

fn poll_pending_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    pending: &Arc<Mutex<PendingOffsets>>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) {
    let due = if let Ok(mut guard) = pending.lock() {
        guard.take_due()
    } else {
        Vec::new()
    };

    if due.is_empty() {
        return;
    }

    let mut to_remove: Vec<u32> = Vec::new();
    let mut to_exhaust: Vec<u32> = Vec::new();

    for due in due {
        let event_pid = due.event_pid;
        let target_path = due.target_path;
        let attempts = due.attempts;
        let proc_pid = proc_pid_for_event(event_pid);
        if !pid_alive(proc_pid) {
            tracing::debug!(
                "Sysmon: event pid {} (proc pid {}) exited while waiting for offsets; removing from retry queue",
                event_pid,
                proc_pid
            );
            to_remove.push(event_pid);
            continue;
        }

        if !pid_maps_target_module(proc_pid, &target_path) {
            if attempts >= PENDING_MAX_ATTEMPTS {
                if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                    tracing::debug!(
                        "Sysmon: event pid {} (proc pid {}) still missing module {} after {} retries; waiting for map-change trigger",
                        event_pid,
                        proc_pid,
                        target_path.display(),
                        attempts
                    );
                    to_exhaust.push(event_pid);
                } else {
                    tracing::warn!(
                        "Sysmon: event pid {} (proc pid {}) still missing module {} after {} retries; giving up",
                        event_pid,
                        proc_pid,
                        target_path.display(),
                        attempts
                    );
                    to_remove.push(event_pid);
                }
            }
            continue;
        }

        match prefill_offsets_for_pid(
            mgr,
            event_pid,
            Some(target_path.as_path()),
            proc_pid_for_event,
        ) {
            Ok(true) => {
                tracing::info!(
                    "Sysmon: deferred prefill succeeded for event pid {} (proc pid {}) (module {})",
                    event_pid,
                    proc_pid,
                    target_path.display()
                );
                to_remove.push(event_pid);
            }
            Ok(false) => {
                if attempts >= PENDING_MAX_ATTEMPTS {
                    if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                        tracing::debug!(
                            "Sysmon: deferred prefill produced no entries for event pid {} (proc pid {}) after {} retries; waiting for map-change trigger",
                            event_pid,
                            proc_pid,
                            attempts
                        );
                        to_exhaust.push(event_pid);
                    } else {
                        tracing::warn!(
                            "Sysmon: deferred prefill produced no entries for event pid {} (proc pid {}) after {} retries; giving up",
                            event_pid,
                            proc_pid,
                            attempts
                        );
                        to_remove.push(event_pid);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Sysmon: deferred prefill failed for event pid {} (proc pid {}) (attempt {}): {}",
                    event_pid,
                    proc_pid,
                    attempts,
                    e
                );
                if attempts >= PENDING_MAX_ATTEMPTS {
                    if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                        to_exhaust.push(event_pid);
                    } else {
                        to_remove.push(event_pid);
                    }
                }
            }
        }
    }

    if !to_remove.is_empty() || !to_exhaust.is_empty() {
        if let Ok(mut guard) = pending.lock() {
            for pid in to_remove {
                guard.remove(pid);
            }
            for pid in to_exhaust {
                guard.mark_retry_exhausted(pid);
            }
        }
    }
}

fn cached_offsets_exist_for_target_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    target_path: &Path,
    proc_pid: u32,
) -> bool {
    let module_path = target_path.to_string_lossy().to_string();
    mgr.lock()
        .ok()
        .map(|guard| {
            guard.cached_offsets_with_paths_for_pid(proc_pid).is_some()
                || guard
                    .cached_offsets_for_module(&module_path)
                    .iter()
                    .any(|(pid, _, _, _, _)| *pid == proc_pid)
        })
        .unwrap_or(false)
}

fn forget_pid_offsets_after_target_unmap(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
) {
    if let Ok(mut guard) = mgr.lock() {
        guard.forget_pid(proc_pid);
        if proc_pid != event_pid {
            guard.forget_pid(event_pid);
        }
        if host_pid != event_pid && host_pid != proc_pid {
            guard.forget_pid(host_pid);
        }
    }

    let purged = purge_runtime_pid_artifacts(proc_pid, event_pid, host_pid);
    if purged > 0 {
        tracing::info!(
            "Sysmon: target unmapped for event pid {} (host pid {}, proc pid {}); purged {} offset entries",
            event_pid,
            host_pid,
            proc_pid,
            purged
        );
    }
}

fn poll_pending_map_refreshes(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    pending_map_refreshes: &Arc<Mutex<PendingMapRefreshes>>,
    pending: &Arc<Mutex<PendingOffsets>>,
    tx: &mpsc::SyncSender<SysEvent>,
) {
    let due = if let Ok(mut guard) = pending_map_refreshes.lock() {
        guard.take_due()
    } else {
        Vec::new()
    };

    if due.is_empty() {
        return;
    }

    for event in due {
        let event_pid = event.event_pid;
        let host_pid = event.host_pid;
        let proc_pid = target
            .map(|target_path| {
                canonicalize_cached_target_proc_pid(mgr, target_path, event.proc_pid)
            })
            .unwrap_or(event.proc_pid);
        if !pid_alive(proc_pid) {
            tracing::trace!(
                "Sysmon: event pid {} (proc pid {}) exited before map refresh",
                event_pid,
                proc_pid
            );
            continue;
        }

        if let Some(target_path) = target {
            if !pid_maps_target_module(proc_pid, target_path) {
                if cached_offsets_exist_for_target_pid(mgr, target_path, proc_pid) {
                    forget_pid_offsets_after_target_unmap(mgr, event_pid, host_pid, proc_pid);
                    let ev = SysEvent {
                        tgid: event_pid,
                        host_tgid: host_pid,
                        kind: SysEventKind::MapChange.as_u32(),
                    };
                    try_publish_sys_event(tx, ev);
                }
                tracing::trace!(
                    "Sysmon: event pid {} (proc pid {}) map-change does not include target {}; skip",
                    event_pid,
                    proc_pid,
                    target_path.display()
                );
                continue;
            }
        }

        match refresh_offsets_for_known_proc_pid(mgr, event_pid, host_pid, proc_pid) {
            Ok(true) => {
                tracing::debug!(
                    "Sysmon: refreshed offsets after map-change for event pid {} (host pid {}, proc pid {})",
                    event_pid,
                    host_pid,
                    proc_pid
                );
                if let Ok(mut guard) = pending.lock() {
                    guard.remove(event_pid);
                    if host_pid != event_pid {
                        guard.remove(host_pid);
                    }
                }
                let ev = SysEvent {
                    tgid: event_pid,
                    host_tgid: host_pid,
                    kind: SysEventKind::MapChange.as_u32(),
                };
                try_publish_sys_event(tx, ev);
            }
            Ok(false) => tracing::trace!(
                "Sysmon: map-change refresh inserted no offsets for event pid {} (proc pid {})",
                event_pid,
                proc_pid
            ),
            Err(e) => tracing::debug!(
                "Sysmon: map-change refresh failed for event pid {} (proc pid {}): {}",
                event_pid,
                proc_pid,
                e
            ),
        }
    }
}

fn get_comm_from_proc(pid: u32) -> Option<String> {
    use std::io::Read;
    let path = format!("/proc/{pid}/comm");
    let mut f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    // Kernel task->comm is at most 15 bytes; /proc returns without NUL. We compare as-is.
    Some(s)
}

fn truncate_basename_to_comm(path: &Path) -> Vec<u8> {
    use std::ffi::OsStr;
    let mut buf = Vec::with_capacity(16);
    if let Some(name) = path.file_name().and_then(OsStr::to_str) {
        let bytes = name.as_bytes();
        let n = core::cmp::min(bytes.len(), 15);
        buf.extend_from_slice(&bytes[..n]);
    }
    buf
}

fn pid_maps_target_module(pid: u32, target: &Path) -> bool {
    let target = ModuleIdentity::from_path(target);
    let mut matched = false;

    if visit_proc_maps(pid, |entry| {
        if target.matches(&entry) {
            matched = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })
    .is_err()
    {
        return false;
    }

    matched
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysmon_target_mode_does_not_enable_map_change_events() {
        let mask = SysmonEventMask::target_mode();
        assert!(mask.exec);
        assert!(mask.fork);
        assert!(mask.exit);
        assert!(!mask.map_change);
    }

    #[test]
    fn sysmon_pid_module_changes_only_enable_map_change_events() {
        let mask = SysmonEventMask::pid_module_changes();
        assert!(!mask.exec);
        assert!(!mask.fork);
        assert!(!mask.exit);
        assert!(mask.map_change);
    }

    #[test]
    fn sysmon_event_publish_drops_when_queue_is_full() {
        let (tx, rx) = mpsc::sync_channel(1);

        assert!(try_publish_sys_event(
            &tx,
            SysEvent {
                tgid: 1,
                host_tgid: 1,
                kind: 1
            }
        ));
        assert!(!try_publish_sys_event(
            &tx,
            SysEvent {
                tgid: 2,
                host_tgid: 2,
                kind: 2
            }
        ));

        let queued = rx.try_recv().expect("first event should be queued");
        assert_eq!(queued.tgid, 1);
        assert_eq!(queued.kind, 1);
        assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
    }

    #[test]
    fn invisible_shared_object_exec_does_not_queue_unresolved_alias() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target_path = dir.path().join("libtarget.so");
        let mut elf = [0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        std::fs::write(&target_path, elf)?;

        let mgr = Arc::new(Mutex::new(ProcessManager::new()));
        let pending = Arc::new(Mutex::new(PendingOffsets::new()));
        let ev = SysEvent {
            tgid: u32::MAX - 1,
            host_tgid: u32::MAX - 2,
            kind: SysEventKind::Exec.as_u32(),
        };

        ProcessSysmon::handle_event_with_proc_pid_resolver(
            &mgr,
            &Some(target_path),
            &pending,
            &ev,
            |pid| pid,
        )?;

        assert!(
            pending
                .lock()
                .expect("pending offsets lock")
                .entries
                .is_empty(),
            "unresolved exec events must not be deferred without target-map proof"
        );
        Ok(())
    }

    #[test]
    fn visible_shared_object_exec_queues_map_change_candidate() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target_path = dir.path().join("libtarget.so");
        let mut elf = [0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        std::fs::write(&target_path, elf)?;

        let event_pid = std::process::id();
        let mgr = Arc::new(Mutex::new(ProcessManager::new()));
        let pending = Arc::new(Mutex::new(PendingOffsets::new()));
        let ev = SysEvent {
            tgid: event_pid,
            host_tgid: event_pid,
            kind: SysEventKind::Exec.as_u32(),
        };

        ProcessSysmon::handle_event_with_proc_pid_resolver(
            &mgr,
            &Some(target_path.clone()),
            &pending,
            &ev,
            |pid| pid,
        )?;

        let guard = pending.lock().expect("pending offsets lock");
        let entry = guard
            .entries
            .get(&event_pid)
            .expect("visible shared-object exec should be queued for retry");
        assert_eq!(entry.target_path, target_path);
        assert_eq!(entry.kind, PendingOffsetsKind::MapChangeCandidate);
        Ok(())
    }

    #[test]
    fn invisible_shared_object_exec_queues_visible_host_pid_retry() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target_path = dir.path().join("libtarget.so");
        let mut elf = [0u8; 64];
        elf[0..4].copy_from_slice(b"\x7FELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[16..18].copy_from_slice(&3u16.to_le_bytes());
        std::fs::write(&target_path, elf)?;

        let host_pid = std::process::id();
        let mgr = Arc::new(Mutex::new(ProcessManager::new()));
        let pending = Arc::new(Mutex::new(PendingOffsets::new()));
        let ev = SysEvent {
            tgid: u32::MAX - 1,
            host_tgid: host_pid,
            kind: SysEventKind::Exec.as_u32(),
        };

        ProcessSysmon::handle_event_with_proc_pid_resolver(
            &mgr,
            &Some(target_path.clone()),
            &pending,
            &ev,
            |pid| pid,
        )?;

        let guard = pending.lock().expect("pending offsets lock");
        let entry = guard
            .entries
            .get(&host_pid)
            .expect("visible host PID should be queued for maps-based retry");
        assert_eq!(entry.target_path, target_path);
        assert_eq!(entry.kind, PendingOffsetsKind::MapChangeCandidate);
        Ok(())
    }

    #[test]
    fn shared_object_candidate_survives_retry_exhaustion() -> anyhow::Result<()> {
        let dir = tempfile::tempdir()?;
        let target_path = dir.path().join("libtarget.so");
        std::fs::write(&target_path, b"not actually mapped")?;

        let event_pid = std::process::id();
        let pending = Arc::new(Mutex::new(PendingOffsets::new()));
        {
            let mut guard = pending.lock().expect("pending offsets lock");
            guard.register_map_change_candidate(event_pid, &target_path);
            let entry = guard
                .entries
                .get_mut(&event_pid)
                .expect("pending candidate");
            entry.attempts = PENDING_MAX_ATTEMPTS - 1;
            entry.last_poll = Instant::now() - PENDING_POLL_INTERVAL;
        }

        let mgr = Arc::new(Mutex::new(ProcessManager::new()));
        poll_pending_offsets(&mgr, &pending, &|pid| pid);

        let guard = pending.lock().expect("pending offsets lock");
        let entry = guard
            .entries
            .get(&event_pid)
            .expect("map-change candidate should remain after retry exhaustion");
        assert!(entry.retry_exhausted);
        assert!(guard.contains_map_change_candidate(event_pid, &target_path));
        Ok(())
    }
}

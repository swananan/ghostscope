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

#[cfg(feature = "sysmon-ebpf")]
mod attach;
mod events;
mod offset_refresh;
mod pending;
mod pid_alias;
#[cfg(feature = "sysmon-ebpf")]
mod runtime_loop;

use events::sys_event_host_pid;
use offset_refresh::{
    get_comm_from_proc, pid_alive, pid_maps_target_module, prefill_offsets_for_pid,
    truncate_basename_to_comm,
};
use pending::{PendingMapRefreshes, PendingOffsets};
use pid_alias::{purge_runtime_pid_artifacts, record_runtime_pid_aliases_for_sys_event};
#[cfg(feature = "sysmon-ebpf")]
use runtime_loop::run_sysmon_loop;

#[cfg(test)]
use events::try_publish_sys_event;
#[cfg(test)]
use offset_refresh::poll_pending_offsets;
#[cfg(test)]
use pending::PendingOffsetsKind;

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

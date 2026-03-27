use crate::{
    maps,
    offsets::{PidOffsetsEntry, ProcessManager},
    proc_maps::{parse_maps_line, ModuleIdentity},
};
use std::collections::HashMap;
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
}

impl SysEventKind {
    fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(SysEventKind::Exec),
            2 => Some(SysEventKind::Fork),
            3 => Some(SysEventKind::Exit),
            _ => None,
        }
    }
}

/// Raw SysEvent ABI — must match eBPF side exactly
/// ABI note: This layout is mirrored in eBPF at
/// `ghostscope-process/ebpf/sysmon-bpf/src/lib.rs`. We intentionally keep
/// two copies for now to avoid entangling the BPF build with the workspace.
/// Keep repr(C), field order and sizes identical on both sides. Current
/// layout (8 bytes): { tgid: u32, kind: u32 }.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SysEvent {
    pub tgid: u32,
    pub kind: u32, // 1=exec,2=fork,3=exit
}

const PENDING_POLL_INTERVAL: Duration = Duration::from_millis(150);
const PENDING_MAX_ATTEMPTS: u32 = 20;
const MODULE_REFRESH_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone)]
pub(crate) struct PendingOffsetsEntry {
    target_path: PathBuf,
    attempts: u32,
    last_poll: Instant,
    first_seen: Instant,
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
        let now = Instant::now();
        let last_poll = now.checked_sub(PENDING_POLL_INTERVAL).unwrap_or(now);
        self.entries
            .entry(pid)
            .and_modify(|entry| {
                entry.target_path = target.to_path_buf();
                entry.attempts = 0;
                entry.last_poll = last_poll;
                entry.first_seen = now;
            })
            .or_insert(PendingOffsetsEntry {
                target_path: target.to_path_buf(),
                attempts: 0,
                last_poll,
                first_seen: now,
            });
    }

    fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    fn take_due(&mut self) -> Vec<(u32, PathBuf, u32)> {
        let mut due = Vec::new();
        let now = Instant::now();
        for (&pid, entry) in self.entries.iter_mut() {
            if now.duration_since(entry.last_poll) >= PENDING_POLL_INTERVAL {
                entry.last_poll = now;
                entry.attempts = entry.attempts.saturating_add(1);
                due.push((pid, entry.target_path.clone(), entry.attempts));
            }
        }
        due
    }
}

/// Configuration for sysmon
#[derive(Debug, Clone, Default)]
pub struct SysmonConfig {
    /// If set, only attempt offsets prefill for events whose binary/module path matches this target.
    pub target_module: Option<PathBuf>,
    /// Maximum number of entries for the pinned proc offsets map (used when ensuring existence).
    pub proc_offsets_max_entries: u32,
    /// PerfEventArray per-CPU buffer pages (used when ringbuf is unavailable).
    pub perf_page_count: Option<usize>,
}

impl SysmonConfig {
    pub fn new() -> Self {
        Self {
            target_module: None,
            proc_offsets_max_entries: 4096,
            perf_page_count: None,
        }
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
    tx: mpsc::Sender<SysEvent>,
    rx: mpsc::Receiver<SysEvent>,
    pending_offsets: Arc<Mutex<PendingOffsets>>,
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
        let (tx, rx) = mpsc::channel();
        Self {
            cfg,
            mgr,
            tx,
            rx,
            pending_offsets: Arc::new(Mutex::new(PendingOffsets::new())),
            handle: None,
        }
    }

    /// Start background monitoring thread and return immediately.
    ///
    /// In the next iteration we will attach eBPF tracepoints (sched_process_exec/exit/fork)
    /// and stream events into this channel. For now, we ensure the pinned offsets map exists
    /// and keep a placeholder loop that can be extended to consume a real source.
    pub fn start(&mut self) {
        let _ = maps::ensure_pinned_proc_offsets_exists(self.cfg.proc_offsets_max_entries);
        let _ = maps::ensure_pinned_allowed_pids_exists(16_384);

        let tx = self.tx.clone();
        let mgr = Arc::clone(&self.mgr);
        let pending = Arc::clone(&self.pending_offsets);
        let target = self.cfg.target_module.clone();
        let perf_pages = self.cfg.perf_page_count;

        let handle = thread::Builder::new()
            .name("gs-sysmon".to_string())
            .spawn(move || {
                info!("ProcessSysmon thread started");
                #[cfg(feature = "sysmon-ebpf")]
                {
                    if let Err(e) = run_sysmon_loop(mgr, target, pending, perf_pages, tx) {
                        error!("Sysmon loop error: {}", e);
                    }
                }
                #[cfg(not(feature = "sysmon-ebpf"))]
                {
                    let _ = pending;
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
    pub(crate) fn handle_event(
        mgr: &Arc<Mutex<ProcessManager>>,
        target: &Option<PathBuf>,
        pending: &Arc<Mutex<PendingOffsets>>,
        ev: &SysEvent,
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
                let proc_pid = resolve_procfs_pid(ev.tgid);
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
                                    guard.register(ev.tgid, path);
                                }
                            } else {
                                tracing::trace!(
                                    "Sysmon: event pid {} is not visible in current /proc namespace; rely on module refresh fallback",
                                    ev.tgid
                                );
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
                let inserted = prefill_offsets_for_pid(mgr, ev.tgid, target.as_deref())?;
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
                let proc_pid = resolve_procfs_pid(ev.tgid);
                if let Ok(mut guard) = pending.lock() {
                    guard.remove(ev.tgid);
                }
                if let Ok(mut guard) = mgr.lock() {
                    guard.forget_pid(proc_pid);
                    if proc_pid != ev.tgid {
                        guard.forget_pid(ev.tgid);
                    }
                }
                // Cleanup: purge keys for this PID in pinned map and remove from allowlist
                match crate::maps::purge_offsets_for_pid(proc_pid) {
                    Ok(n) => info!(
                        "Sysmon: observed exit for event pid {} (proc pid {}) (purged {} entries)",
                        ev.tgid, proc_pid, n
                    ),
                    Err(e) => tracing::warn!(
                        "Sysmon: purge failed for event pid {} (proc pid {}): {}",
                        ev.tgid,
                        proc_pid,
                        e
                    ),
                }
                if proc_pid != ev.tgid {
                    let _ = crate::maps::purge_offsets_for_pid(ev.tgid);
                }
                let _ = crate::maps::remove_allowed_pid(ev.tgid);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "sysmon-ebpf")]
fn run_sysmon_loop(
    mgr: Arc<Mutex<ProcessManager>>,
    target: Option<PathBuf>,
    pending: Arc<Mutex<PendingOffsets>>,
    perf_pages: Option<usize>,
    tx: mpsc::Sender<SysEvent>,
) -> anyhow::Result<()> {
    use aya::maps::{perf::PerfEventArray, ring_buf::RingBuf, Array, MapData};
    use aya::programs::TracePoint;
    use aya::{include_bytes_aligned, EbpfLoader, VerifierLogLevel};
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
    let mut loader = EbpfLoader::new();
    let use_verbose =
        cfg!(debug_assertions) || log_enabled!(LogLevel::Trace) || log_enabled!(LogLevel::Debug);
    if use_verbose {
        loader.verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS);
        tracing::info!("Sysmon verifier logs: VERBOSE (debug build/log)");
    } else {
        loader.verifier_log_level(VerifierLogLevel::DEBUG | VerifierLogLevel::STATS);
        tracing::info!("Sysmon verifier logs: DEBUG (release/info)");
    }
    // Reuse pinned maps by name under our per-process dir
    loader.map_pin_path(crate::maps::proc_offsets_pin_dir());
    let mut bpf = loader.load(obj)?;

    // Configure optional exec comm filter when targeting executables (-t binary).
    {
        let mut filter_bytes = [0u8; 16];
        let mut filter_len = 0usize;
        if let Some(tpath) = target.as_ref() {
            if !crate::util::is_shared_object(tpath) {
                if let Some(name) = tpath.file_name().and_then(|s| s.to_str()) {
                    let bytes = name.as_bytes();
                    let len = bytes.len().min(filter_bytes.len());
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
    }

    // Using allowlist-based gating in kernel; userspace decides allow on exec.

    // Attach tracepoints
    for (name, cat, evt) in [
        ("sched_process_exec", "sched", "sched_process_exec"),
        ("sched_process_exit", "sched", "sched_process_exit"),
        ("sched_process_fork", "sched", "sched_process_fork"),
    ] {
        if let Some(prog) = bpf.program_mut(name) {
            let tp: &mut TracePoint = prog.try_into()?;
            tp.load()?;
            tp.attach(cat, evt)?;
            info!("Attached tracepoint: {}:{}", cat, evt);
        } else {
            warn!("Missing program '{}' in sysmon-bpf", name);
        }
    }
    tracing::info!("Sysmon: attached all tracepoints");

    // Initial prefill for late-start cases: compute and insert offsets for already-running PIDs.
    if let Some(tpath) = &target {
        if let Ok(mut guard) = mgr.lock() {
            if let Ok(prefilled) = guard.ensure_prefill_module(tpath.to_string_lossy().as_ref()) {
                tracing::info!(
                    "Sysmon: initial prefill cached {} pid(s) for module {}",
                    prefilled,
                    tpath.display()
                );
                let entries = guard.cached_offsets_for_module(tpath.to_string_lossy().as_ref());
                if !entries.is_empty() {
                    use crate::maps::{insert_offsets_for_pid, ProcModuleOffsetsValue};
                    use std::collections::HashMap;
                    let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> =
                        HashMap::new();
                    for (pid, cookie, off) in entries {
                        by_pid.entry(pid).or_default().push((
                            cookie,
                            ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss),
                        ));
                    }
                    let mut total = 0usize;
                    for (pid, items) in by_pid {
                        if let Ok(n) = insert_offsets_for_pid(pid, &items) {
                            total += n;
                        }
                        // Add event PID (kernel namespace) to allowlist so subsequent
                        // fork/exit events are filtered in-kernel.
                        let event_pid = resolve_event_pid(pid);
                        let _ = crate::maps::insert_allowed_pid(event_pid);
                    }
                    tracing::info!(
                        "Sysmon: initial inserted {} offset entries for module {}",
                        total,
                        tpath.display()
                    );
                }
            }
        }
    }
    tracing::info!("Sysmon: setup complete");
    let mut last_module_refresh = Instant::now()
        .checked_sub(MODULE_REFRESH_INTERVAL)
        .unwrap_or_else(Instant::now);

    // Event loop: prefer ringbuf; fallback to perf
    if let Some(map) = bpf.take_map("sysmon_events") {
        let mut rb: RingBuf<MapData> = map.try_into()?;
        loop {
            let mut had_event = false;
            if let Some(item) = rb.next() {
                if item.len() == core::mem::size_of::<SysEvent>() {
                    let ev = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const SysEvent) };
                    if let Err(e) = ProcessSysmon::handle_event(&mgr, &target, &pending, &ev) {
                        tracing::debug!(
                            "Sysmon: handle_event failed (ringbuf) for pid {} kind {}: {}",
                            ev.tgid,
                            ev.kind,
                            e
                        );
                    }
                    let _ = tx.send(ev);
                    had_event = true;
                }
            }
            poll_pending_offsets(&mgr, &pending);
            refresh_target_module_offsets(&mgr, target.as_deref(), &mut last_module_refresh);
            if !had_event {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    } else if let Some(map) = bpf.take_map("sysmon_events_perf") {
        let mut perf: PerfEventArray<_> = map.try_into()?;
        let online = aya::util::online_cpus().map_err(|(_, e)| anyhow::anyhow!(e))?;
        let mut bufs = Vec::new();
        for cpu in online {
            match perf.open(cpu, perf_pages) {
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
                let mut read_bufs = vec![bytes::BytesMut::with_capacity(256)];
                match buf.read_events(&mut read_bufs) {
                    Ok(res) => {
                        for data in read_bufs.iter().take(res.read.min(read_bufs.len())) {
                            if data.len() == core::mem::size_of::<SysEvent>() {
                                let ev = unsafe {
                                    core::ptr::read_unaligned(data.as_ptr() as *const SysEvent)
                                };
                                if let Err(e) =
                                    ProcessSysmon::handle_event(&mgr, &target, &pending, &ev)
                                {
                                    tracing::debug!(
                                        "Sysmon: handle_event failed (perf) for pid {} kind {}: {}",
                                        ev.tgid,
                                        ev.kind,
                                        e
                                    );
                                }
                                let _ = tx.send(ev);
                            }
                        }
                    }
                    Err(e) => warn!("Perf read_events failed: {}", e),
                }
            }
            poll_pending_offsets(&mgr, &pending);
            refresh_target_module_offsets(&mgr, target.as_deref(), &mut last_module_refresh);
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
                let tc = crate::cookie::from_path(&tpath.to_string_lossy());
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
) -> anyhow::Result<bool> {
    use crate::maps::{insert_offsets_for_pid, ProcModuleOffsetsValue};

    let proc_pid = resolve_procfs_pid(event_pid);
    let mut inserted_any = false;
    if let Ok(mut guard) = mgr.lock() {
        let prefilled = match guard.ensure_prefill_pid(proc_pid) {
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
                    let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> =
                        HashMap::new();
                    for (pid, cookie, off) in guard.cached_offsets_for_module(&module_path) {
                        by_pid.entry(pid).or_default().push((
                            cookie,
                            ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss),
                        ));
                    }
                    for (pid, items) in by_pid {
                        match insert_offsets_for_pid(pid, &items) {
                            Ok(inserted) if inserted > 0 => {
                                tracing::info!(
                                    "Sysmon: module refresh inserted {} offset entries for proc pid {} (event pid {})",
                                    inserted, pid, event_pid
                                );
                                let _ = crate::maps::insert_allowed_pid(resolve_event_pid(pid));
                                inserted_any = true;
                            }
                            Ok(_) => {}
                            Err(err) => tracing::warn!(
                                "Sysmon: module refresh failed to insert offsets for proc pid {}: {}",
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
                "Sysmon: prefilled {} entries for event pid {} (proc pid {})",
                prefilled, event_pid, proc_pid
            );
        }
        let mut filtered = guard
            .cached_offsets_with_paths_for_pid(proc_pid)
            .map(|entries| filter_entries_for_target(entries, target))
            .unwrap_or_default();

        if filtered.is_empty() && target.is_some() {
            let refreshed = guard.refresh_prefill_pid(proc_pid)?;
            if refreshed > 0 {
                tracing::debug!(
                    "Sysmon: refreshed {} cached entries for event pid {} (proc pid {})",
                    refreshed,
                    event_pid,
                    proc_pid
                );
            }
            filtered = guard
                .cached_offsets_with_paths_for_pid(proc_pid)
                .map(|entries| filter_entries_for_target(entries, target))
                .unwrap_or_default();
        }

        if !filtered.is_empty() {
            let items: Vec<(u64, ProcModuleOffsetsValue)> = filtered
                .iter()
                .map(|e| {
                    (
                        e.cookie,
                        ProcModuleOffsetsValue::new(
                            e.offsets.text,
                            e.offsets.rodata,
                            e.offsets.data,
                            e.offsets.bss,
                        ),
                    )
                })
                .collect();
            match insert_offsets_for_pid(proc_pid, &items) {
                Ok(inserted) => {
                    if inserted == 0 {
                        tracing::warn!(
                            "Sysmon: no offsets inserted for event pid {} (proc pid {}) (filtered count={})",
                            event_pid,
                            proc_pid,
                            items.len()
                        );
                    } else {
                        tracing::info!(
                            "Sysmon: inserted {} offset entries for event pid {} (proc pid {})",
                            inserted,
                            event_pid,
                            proc_pid
                        );
                        let _ = crate::maps::insert_allowed_pid(event_pid);
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

fn refresh_target_module_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    last_refresh: &mut Instant,
) {
    use crate::maps::{insert_offsets_for_pid, ProcModuleOffsetsValue};

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
    if let Ok(mut guard) = mgr.lock() {
        if let Err(e) = guard.refresh_prefill_module(&module_path) {
            tracing::debug!(
                "Sysmon: periodic module refresh failed for {}: {}",
                module_path,
                e
            );
            return;
        }
        for (pid, cookie, off) in guard.cached_offsets_for_module(&module_path) {
            by_pid.entry(pid).or_default().push((
                cookie,
                ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss),
            ));
        }
    }
    if by_pid.is_empty() {
        return;
    }

    let mut total = 0usize;
    for (pid, items) in by_pid {
        match insert_offsets_for_pid(pid, &items) {
            Ok(inserted) => {
                if inserted > 0 {
                    total += inserted;
                    let _ = crate::maps::insert_allowed_pid(resolve_event_pid(pid));
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
    if total > 0 {
        tracing::debug!(
            "Sysmon: periodic module refresh inserted {} offset entries for {}",
            total,
            module_path
        );
    }
}

fn poll_pending_offsets(mgr: &Arc<Mutex<ProcessManager>>, pending: &Arc<Mutex<PendingOffsets>>) {
    let due = if let Ok(mut guard) = pending.lock() {
        guard.take_due()
    } else {
        Vec::new()
    };

    if due.is_empty() {
        return;
    }

    let mut to_remove: Vec<u32> = Vec::new();

    for (event_pid, target_path, attempts) in due {
        let proc_pid = resolve_procfs_pid(event_pid);
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
                tracing::warn!(
                    "Sysmon: event pid {} (proc pid {}) still missing module {} after {} retries; giving up",
                    event_pid,
                    proc_pid,
                    target_path.display(),
                    attempts
                );
                to_remove.push(event_pid);
            }
            continue;
        }

        match prefill_offsets_for_pid(mgr, event_pid, Some(target_path.as_path())) {
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
                    tracing::warn!(
                        "Sysmon: deferred prefill produced no entries for event pid {} (proc pid {}) after {} retries; giving up",
                        event_pid,
                        proc_pid,
                        attempts
                    );
                    to_remove.push(event_pid);
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
                    to_remove.push(event_pid);
                }
            }
        }
    }

    if !to_remove.is_empty() {
        if let Ok(mut guard) = pending.lock() {
            for pid in to_remove {
                guard.remove(pid);
            }
        }
    }
}

fn parse_status_chain(status: &str, key: &str) -> Option<Vec<u32>> {
    status.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.trim();
        let values: Vec<u32> = rest
            .split_whitespace()
            .filter_map(|v| v.parse::<u32>().ok())
            .collect();
        if values.is_empty() {
            None
        } else {
            Some(values)
        }
    })
}

fn read_nspid_chain(pid: u32) -> Option<Vec<u32>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    parse_status_chain(&status, "NSpid:")
}

/// Resolve a kernel event PID (initial PID namespace) to the /proc-visible PID in
/// the current namespace when possible.
fn resolve_procfs_pid(event_pid: u32) -> u32 {
    if std::path::Path::new(&format!("/proc/{event_pid}")).exists() {
        return event_pid;
    }

    if let Ok(dir) = std::fs::read_dir("/proc") {
        for ent in dir.flatten() {
            let fname = ent.file_name();
            let Ok(visible_pid) = fname.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(chain) = read_nspid_chain(visible_pid) else {
                continue;
            };
            if chain.first().copied() == Some(event_pid) {
                return visible_pid;
            }
        }
    }

    event_pid
}

/// Resolve a /proc-visible PID back to the kernel event PID when possible.
fn resolve_event_pid(proc_pid: u32) -> u32 {
    read_nspid_chain(proc_pid)
        .and_then(|chain| chain.first().copied())
        .unwrap_or(proc_pid)
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
    use std::fs;

    let maps_path = format!("/proc/{pid}/maps");
    let Ok(content) = fs::read_to_string(&maps_path) else {
        return false;
    };

    let target = ModuleIdentity::from_path(target);

    for line in content.lines() {
        let Some(entry) = parse_maps_line(line) else {
            continue;
        };
        if target.matches(&entry) {
            return true;
        }
    }

    false
}

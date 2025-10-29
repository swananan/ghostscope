use crate::{maps, offsets::ProcessManager};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
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
        let target = self.cfg.target_module.clone();
        let perf_pages = self.cfg.perf_page_count;

        let handle = thread::Builder::new()
            .name("gs-sysmon".to_string())
            .spawn(move || {
                info!("ProcessSysmon thread started");
                #[cfg(feature = "sysmon-ebpf")]
                {
                    if let Err(e) = run_sysmon_loop(mgr, target, perf_pages, tx) {
                        error!("Sysmon loop error: {}", e);
                    }
                }
                #[cfg(not(feature = "sysmon-ebpf"))]
                {
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
    pub fn handle_event(
        mgr: &Arc<Mutex<ProcessManager>>,
        target: &Option<PathBuf>,
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
        match kind {
            SysEventKind::Exec | SysEventKind::Fork => {
                if let SysEventKind::Exec = kind {
                    if let Some(tpath) = target {
                        let path = tpath.as_path();
                        if crate::util::is_shared_object(path) {
                            if !pid_maps_target_module(ev.tgid, path) {
                                tracing::debug!(
                                    "Sysmon: pid {} does not map target module yet; skip",
                                    ev.tgid
                                );
                                // TODO: Support delayed shared-library mapping by retrying when
                                // the module finally appears in /proc/<pid>/maps.
                                return Ok(());
                            }
                        } else if let Some(actual) = get_comm_from_proc(ev.tgid) {
                            let expected = truncate_basename_to_comm(path);
                            if actual.as_bytes() != expected.as_slice() {
                                tracing::warn!(
                                    "Sysmon: comm mismatch for pid {} (actual='{}', expected='{}'); skip prefill/insert",
                                    ev.tgid,
                                    actual,
                                    core::str::from_utf8(&expected).unwrap_or("")
                                );
                                return Ok(());
                            }
                        }
                    }
                }
                // Prefill all modules for this PID, then insert matched entries into the pinned map
                if let Ok(mut guard) = mgr.lock() {
                    let prefilled = guard.ensure_prefill_pid(ev.tgid)?;
                    if prefilled > 0 {
                        info!(
                            "Sysmon: prefilled {} entries for pid {} (exec/fork)",
                            prefilled, ev.tgid
                        );
                    }
                    // Collect entries to write into pinned map
                    if let Some(entries) = guard.cached_offsets_with_paths_for_pid(ev.tgid) {
                        use crate::maps::{insert_offsets_for_pid, ProcModuleOffsetsValue};
                        use std::fs;
                        use std::os::unix::fs::MetadataExt;
                        // Prefer robust dev:inode matching; fall back to cookie, then to path string only as last resort.
                        let filtered = if let Some(tpath) = target {
                            match fs::metadata(tpath) {
                                Ok(tmeta) => {
                                    let t_dev = tmeta.dev();
                                    let t_ino = tmeta.ino();
                                    entries
                                        .iter()
                                        .filter(|e| {
                                            fs::metadata(&e.module_path)
                                                .map(|m| m.dev() == t_dev && m.ino() == t_ino)
                                                .unwrap_or(false)
                                        })
                                        .collect::<Vec<_>>()
                                }
                                Err(_) => {
                                    // Target metadata missing (e.g., deleted file) — compare by cookie first
                                    let tc = crate::cookie::from_path(&tpath.to_string_lossy());
                                    let by_cookie: Vec<_> =
                                        entries.iter().filter(|e| e.cookie == tc).collect();
                                    if !by_cookie.is_empty() {
                                        by_cookie
                                    } else {
                                        // Last resort: compare normalized path strings
                                        let tnorm = tpath.to_string_lossy().replace("/./", "/");
                                        entries
                                            .iter()
                                            .filter(|e| e.module_path == tnorm)
                                            .collect::<Vec<_>>()
                                    }
                                }
                            }
                        } else {
                            entries.iter().collect::<Vec<_>>()
                        };
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
                            let inserted = insert_offsets_for_pid(ev.tgid, &items).unwrap_or(0);
                            if inserted == 0 {
                                tracing::warn!(
                                    "Sysmon: no offsets inserted for pid {} (filtered count={})",
                                    ev.tgid,
                                    items.len()
                                );
                            } else {
                                tracing::info!(
                                    "Sysmon: inserted {} offset entries for pid {}",
                                    inserted,
                                    ev.tgid
                                );
                                // Allowlist this PID so subsequent fork/exit events are delivered
                                let _ = crate::maps::insert_allowed_pid(ev.tgid);
                            }
                        } else if target.is_some() {
                            tracing::debug!(
                                "Sysmon: pid {} does not map target module; skip",
                                ev.tgid
                            );
                        }
                    }
                }
            }
            SysEventKind::Exit => {
                // Cleanup: purge keys for this PID in pinned map and remove from allowlist
                match crate::maps::purge_offsets_for_pid(ev.tgid) {
                    Ok(n) => info!(
                        "Sysmon: observed exit for pid {} (purged {} entries)",
                        ev.tgid, n
                    ),
                    Err(e) => tracing::warn!("Sysmon: purge failed for pid {}: {}", ev.tgid, e),
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
                        // Add pid to allowed set so subsequent fork/exit are filtered in-kernel
                        let _ = crate::maps::insert_allowed_pid(pid);
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

    // Event loop: prefer ringbuf; fallback to perf
    if let Some(map) = bpf.take_map("sysmon_events") {
        let mut rb: RingBuf<MapData> = map.try_into()?;
        loop {
            if let Some(item) = rb.next() {
                if item.len() == core::mem::size_of::<SysEvent>() {
                    let ev = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const SysEvent) };
                    let _ = ProcessSysmon::handle_event(&mgr, &target, &ev);
                    let _ = tx.send(ev);
                }
            } else {
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
                                let _ = ProcessSysmon::handle_event(&mgr, &target, &ev);
                                let _ = tx.send(ev);
                            }
                        }
                    }
                    Err(e) => warn!("Perf read_events failed: {}", e),
                }
            }
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
    use std::os::unix::fs::MetadataExt;

    let maps_path = format!("/proc/{pid}/maps");
    let Ok(content) = fs::read_to_string(&maps_path) else {
        return false;
    };

    let (t_dev, t_ino) = fs::metadata(target)
        .map(|m| (Some(m.dev()), Some(m.ino())))
        .unwrap_or((None, None));
    let t_norm = target.to_string_lossy().replace("/./", "/");

    for line in content.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }
        let path = parts[5];
        if path.starts_with('[') {
            continue;
        }
        let path_trim = if let Some(idx) = path.find(" (deleted)") {
            &path[..idx]
        } else {
            path
        };

        let matched = if let (Some(dev), Some(ino)) = (t_dev, t_ino) {
            if let Some((maj_s, min_s)) = parts[3].split_once(':') {
                if let (Ok(maj), Ok(min), Ok(inode)) = (
                    u64::from_str_radix(maj_s, 16),
                    u64::from_str_radix(min_s, 16),
                    parts[4].parse::<u64>(),
                ) {
                    let d = dev as libc::dev_t;
                    let t_maj = libc::major(d) as u64;
                    let t_min = libc::minor(d) as u64;
                    maj == t_maj && min == t_min && inode == ino
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            path_trim == t_norm
        };

        if matched {
            return true;
        }
    }

    false
}

use super::attach::*;
use super::events::*;
use super::offset_refresh::*;
use super::pid_alias::*;
use super::*;

#[cfg(feature = "sysmon-ebpf")]
struct SysmonLoopContext<'a, F, M> {
    mgr: &'a Arc<Mutex<ProcessManager>>,
    target: &'a Option<PathBuf>,
    pending: &'a Arc<Mutex<PendingOffsets>>,
    pending_map_refreshes: &'a Arc<Mutex<PendingMapRefreshes>>,
    proc_pid_for_event: &'a F,
    proc_pid_for_map_change: &'a M,
    tx: &'a mpsc::SyncSender<SysEvent>,
}

#[cfg(feature = "sysmon-ebpf")]
fn enqueue_or_dispatch_sysmon_event<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    map_changes: &mut CoalescedMapChanges,
    map_change_queue_overflow_reported: &mut bool,
    ev: SysEvent,
) {
    if ev.event_kind() == Some(SysEventKind::MapChange) {
        if !map_changes.enqueue(ev, Instant::now()) && !*map_change_queue_overflow_reported {
            warn!(
                "Sysmon: coalesced map-change queue reached capacity {}; relying on periodic reconciliation",
                SYSMON_MAP_CHANGE_QUEUE_CAPACITY
            );
            *map_change_queue_overflow_reported = true;
        }
        return;
    }

    let matched = dispatch_sysmon_event(
        context.mgr,
        context.target,
        context.pending,
        context.pending_map_refreshes,
        context.proc_pid_for_event,
        &ev,
    );
    if matched {
        try_publish_sys_event(context.tx, ev);
    }
}

#[cfg(feature = "sysmon-ebpf")]
fn process_coalesced_map_changes<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    map_changes: &mut CoalescedMapChanges,
) -> usize {
    let started_at = Instant::now();
    let mut processed = 0;
    while processed < SYSMON_MAP_CHANGE_PROCESS_LIMIT {
        let Some(ev) = map_changes.pop_ready(Instant::now()) else {
            break;
        };
        let matched = dispatch_sysmon_event(
            context.mgr,
            context.target,
            context.pending,
            context.pending_map_refreshes,
            context.proc_pid_for_map_change,
            &ev,
        );
        if matched {
            try_publish_sys_event(context.tx, ev);
        }
        processed += 1;
        if started_at.elapsed() >= SYSMON_MAP_CHANGE_PROCESS_TIME_BUDGET {
            break;
        }
    }
    processed
}

#[cfg(feature = "sysmon-ebpf")]
fn service_sysmon_maintenance<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    map_changes: &mut CoalescedMapChanges,
    last_module_refresh: &mut Instant,
    target_pid_map_signatures: &mut HashMap<u32, PidMapsSignature>,
) -> usize {
    // Reconciliation is the correctness fallback when lifecycle or map-change events are delayed
    // or dropped. Service it before lower-priority per-PID map work so event pressure cannot defer
    // the refresh past its deadline.
    refresh_target_module_offsets(
        context.mgr,
        context.target.as_deref(),
        last_module_refresh,
        target_pid_map_signatures,
        context.tx,
    );
    poll_pending_offsets(context.mgr, context.pending, context.proc_pid_for_event);
    let processed = process_coalesced_map_changes(context, map_changes);
    poll_pending_map_refreshes(
        context.mgr,
        context.target.as_deref(),
        context.pending_map_refreshes,
        context.pending,
        context.tx,
    );
    processed
}

#[cfg(feature = "sysmon-ebpf")]
pub(super) fn run_sysmon_loop(
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
    // Only noisy map-change handling uses a short-lived `/proc` index snapshot. Lifecycle events
    // keep fresh resolution semantics so a newly visible short-lived process cannot hit a cached
    // miss from an earlier unrelated event.
    let proc_pid_for_map_change =
        cached_sysmon_proc_pid_resolver(cfg.watched_pid, cfg.watched_proc_pid);

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
    let context = SysmonLoopContext {
        mgr: &mgr,
        target: &target,
        pending: &pending,
        pending_map_refreshes: &pending_map_refreshes,
        proc_pid_for_event: &proc_pid_for_event,
        proc_pid_for_map_change: &proc_pid_for_map_change,
        tx: &tx,
    };

    // Event loop: prefer ringbuf; fallback to perf
    if let Some(map) = bpf.take_map("sysmon_events") {
        let mut rb: RingBuf<MapData> = map.try_into()?;
        let mut map_changes = CoalescedMapChanges::new(
            SYSMON_MAP_CHANGE_QUEUE_CAPACITY,
            MAP_CHANGE_DEBOUNCE_INTERVAL,
        );
        let mut map_change_queue_overflow_reported = false;
        loop {
            let mut had_event = false;
            let drain_started_at = Instant::now();
            let mut drained = 0;
            // Keep lifecycle handling prompt without requiring the ring buffer to become empty.
            // Map-change processing is deferred and coalesced so draining it remains O(1).
            while drained < SYSMON_RING_DRAIN_EVENT_LIMIT {
                let Some(item) = rb.next() else {
                    break;
                };
                had_event = true;
                drained += 1;
                if item.len() == core::mem::size_of::<SysEvent>() {
                    // SAFETY: The ring buffer sample length was checked to match SysEvent;
                    // read_unaligned handles any alignment from the byte slice.
                    let ev = unsafe { core::ptr::read_unaligned(item.as_ptr() as *const SysEvent) };
                    enqueue_or_dispatch_sysmon_event(
                        &context,
                        &mut map_changes,
                        &mut map_change_queue_overflow_reported,
                        ev,
                    );
                }
                if drain_started_at.elapsed() >= SYSMON_RING_DRAIN_TIME_BUDGET {
                    break;
                }
            }
            let processed_map_changes = service_sysmon_maintenance(
                &context,
                &mut map_changes,
                &mut last_module_refresh,
                &mut target_pid_map_signatures,
            );
            if !had_event && processed_map_changes == 0 {
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
        let mut map_changes = CoalescedMapChanges::new(
            SYSMON_MAP_CHANGE_QUEUE_CAPACITY,
            MAP_CHANGE_DEBOUNCE_INTERVAL,
        );
        let mut map_change_queue_overflow_reported = false;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            let mut had_event = false;
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
                            had_event = true;
                            // SAFETY: raw is exactly the size of SysEvent and read_unaligned
                            // handles the byte array's alignment.
                            let ev = unsafe {
                                core::ptr::read_unaligned(raw.as_ptr() as *const SysEvent)
                            };
                            enqueue_or_dispatch_sysmon_event(
                                &context,
                                &mut map_changes,
                                &mut map_change_queue_overflow_reported,
                                ev,
                            );
                        }
                    }
                    PerfEvent::Lost { count } => {
                        warn!("Perf event buffer lost {} sysmon events", count);
                    }
                });
            }
            let processed_map_changes = service_sysmon_maintenance(
                &context,
                &mut map_changes,
                &mut last_module_refresh,
                &mut target_pid_map_signatures,
            );
            if !had_event && processed_map_changes == 0 && !map_changes.is_empty() {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        }
    } else {
        Err(anyhow::anyhow!("No sysmon events map found (ringbuf/perf)"))
    }
}

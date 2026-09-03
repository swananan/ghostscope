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
type SharedSysmonWorkQueue = Arc<Mutex<SysmonWorkQueue>>;

#[cfg(feature = "sysmon-ebpf")]
struct SysmonWorker {
    queue: SharedSysmonWorkQueue,
    wake_tx: Option<mpsc::SyncSender<()>>,
    handle: Option<JoinHandle<()>>,
    lifecycle_queue_overflow_reported: bool,
    map_change_queue_overflow_reported: bool,
}

#[cfg(feature = "sysmon-ebpf")]
impl SysmonWorker {
    fn spawn(
        mgr: Arc<Mutex<ProcessManager>>,
        cfg: SysmonConfig,
        pending: Arc<Mutex<PendingOffsets>>,
        pending_map_refreshes: Arc<Mutex<PendingMapRefreshes>>,
        tx: mpsc::SyncSender<SysEvent>,
    ) -> anyhow::Result<Self> {
        let queue = Arc::new(Mutex::new(SysmonWorkQueue::new(
            SYSMON_WORK_LIFECYCLE_QUEUE_CAPACITY,
            SYSMON_MAP_CHANGE_QUEUE_CAPACITY,
            MAP_CHANGE_DEBOUNCE_INTERVAL,
        )));
        let worker_queue = Arc::clone(&queue);
        let (wake_tx, wake_rx) = mpsc::sync_channel(1);
        let handle = thread::Builder::new()
            .name("gs-sysmon-work".to_string())
            .spawn(move || {
                info!("Sysmon work thread started");
                if let Err(error) = run_sysmon_worker(
                    mgr,
                    cfg,
                    pending,
                    pending_map_refreshes,
                    tx,
                    worker_queue,
                    wake_rx,
                ) {
                    error!("Sysmon work thread failed: {error:#}");
                }
                info!("Sysmon work thread exiting");
            })
            .map_err(|error| anyhow::anyhow!("failed to spawn sysmon work thread: {error}"))?;

        Ok(Self {
            queue,
            wake_tx: Some(wake_tx),
            handle: Some(handle),
            lifecycle_queue_overflow_reported: false,
            map_change_queue_overflow_reported: false,
        })
    }

    fn enqueue(&mut self, event: SysEvent) -> anyhow::Result<()> {
        let result = self
            .queue
            .lock()
            .map_err(|_| anyhow::anyhow!("sysmon work queue lock poisoned"))?
            .enqueue(event, Instant::now());

        match result {
            SysmonWorkEnqueueResult::Queued => {}
            SysmonWorkEnqueueResult::LifecycleQueueFull => {
                if !self.lifecycle_queue_overflow_reported {
                    warn!(
                        "Sysmon lifecycle work queue reached capacity {}; dropping events while periodic reconciliation remains active",
                        SYSMON_WORK_LIFECYCLE_QUEUE_CAPACITY
                    );
                    self.lifecycle_queue_overflow_reported = true;
                }
            }
            SysmonWorkEnqueueResult::MapChangeQueueFull => {
                if !self.map_change_queue_overflow_reported {
                    warn!(
                        "Sysmon coalesced map-change queue reached capacity {}; relying on periodic reconciliation",
                        SYSMON_MAP_CHANGE_QUEUE_CAPACITY
                    );
                    self.map_change_queue_overflow_reported = true;
                }
            }
        }

        let wake_tx = self
            .wake_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("sysmon work thread is stopped"))?;
        match wake_tx.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => {
                Err(anyhow::anyhow!("sysmon work thread stopped unexpectedly"))
            }
        }
    }

    fn ensure_running(&self) -> anyhow::Result<()> {
        if self.handle.as_ref().is_some_and(JoinHandle::is_finished) {
            Err(anyhow::anyhow!("sysmon work thread stopped unexpectedly"))
        } else {
            Ok(())
        }
    }
}

#[cfg(feature = "sysmon-ebpf")]
impl Drop for SysmonWorker {
    fn drop(&mut self) {
        self.wake_tx.take();
        if let Some(handle) = self.handle.take() {
            if handle.join().is_err() {
                warn!("Sysmon work thread panicked");
            }
        }
    }
}

#[cfg(feature = "sysmon-ebpf")]
fn pop_lifecycle_work(queue: &SharedSysmonWorkQueue) -> anyhow::Result<Option<SysEvent>> {
    queue
        .lock()
        .map_err(|_| anyhow::anyhow!("sysmon work queue lock poisoned"))
        .map(|mut queue| queue.pop_lifecycle())
}

#[cfg(feature = "sysmon-ebpf")]
fn pop_ready_map_change_work(
    queue: &SharedSysmonWorkQueue,
    now: Instant,
) -> anyhow::Result<Option<SysEvent>> {
    queue
        .lock()
        .map_err(|_| anyhow::anyhow!("sysmon work queue lock poisoned"))
        .map(|mut queue| queue.pop_ready_map_change(now))
}

#[cfg(feature = "sysmon-ebpf")]
fn process_lifecycle_events<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    queue: &SharedSysmonWorkQueue,
) -> anyhow::Result<usize> {
    let started_at = Instant::now();
    let mut processed = 0;
    while processed < SYSMON_WORK_LIFECYCLE_PROCESS_LIMIT {
        let Some(event) = pop_lifecycle_work(queue)? else {
            break;
        };
        let matched = dispatch_sysmon_event(
            context.mgr,
            context.target,
            context.pending,
            context.pending_map_refreshes,
            context.proc_pid_for_event,
            &event,
        );
        if matched {
            try_publish_sys_event(context.tx, event);
        }
        processed += 1;
        if started_at.elapsed() >= SYSMON_WORK_LIFECYCLE_TIME_BUDGET {
            break;
        }
    }
    Ok(processed)
}

#[cfg(feature = "sysmon-ebpf")]
fn process_coalesced_map_changes<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    queue: &SharedSysmonWorkQueue,
) -> anyhow::Result<usize> {
    let started_at = Instant::now();
    let mut processed = 0;
    while processed < SYSMON_MAP_CHANGE_PROCESS_LIMIT {
        let Some(ev) = pop_ready_map_change_work(queue, Instant::now())? else {
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
    Ok(processed)
}

#[cfg(feature = "sysmon-ebpf")]
fn service_sysmon_maintenance<F: Fn(u32) -> u32, M: Fn(u32) -> u32>(
    context: &SysmonLoopContext<'_, F, M>,
    queue: &SharedSysmonWorkQueue,
    last_module_refresh: &mut Instant,
    target_pid_map_signatures: &mut HashMap<u32, PidMapsSignature>,
) -> anyhow::Result<usize> {
    // Lifecycle work is the latency-sensitive path. It is always selected before
    // scans, retries, and map-change refreshes, regardless of mmap event volume.
    let processed_lifecycle = process_lifecycle_events(context, queue)?;
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
    let processed_map_changes = process_coalesced_map_changes(context, queue)?;
    poll_pending_map_refreshes(
        context.mgr,
        context.target.as_deref(),
        context.pending_map_refreshes,
        context.pending,
        context.tx,
    );
    Ok(processed_lifecycle + processed_map_changes)
}

#[cfg(feature = "sysmon-ebpf")]
fn initialize_target_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) {
    let Some(target_path) = target else {
        return;
    };

    let mut initial_target_pids = BTreeSet::new();
    if let Ok(mut guard) = mgr.lock() {
        if let Ok(prefilled) = guard.ensure_prefill_module(target_path.to_string_lossy().as_ref()) {
            tracing::info!(
                "Sysmon: initial prefill cached {} pid(s) for module {}",
                prefilled,
                target_path.display()
            );
            let entries = guard.cached_offsets_for_module(target_path.to_string_lossy().as_ref());
            if !entries.is_empty() {
                use crate::pinned_bpf_maps::ProcModuleOffsetsValue;
                let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> = HashMap::new();
                for (pid, cookie, offsets, base, size) in entries {
                    if is_current_process_pid(pid) {
                        continue;
                    }
                    by_pid.entry(pid).or_default().push((
                        cookie,
                        ProcModuleOffsetsValue::new(
                            offsets.text,
                            offsets.rodata,
                            offsets.data,
                            offsets.bss,
                            base,
                            size,
                        ),
                    ));
                }
                let mut total = 0;
                for (pid, items) in by_pid {
                    initial_target_pids.insert(pid);
                    let event_pid = resolve_event_pid_for_proc(pid);
                    let runtime_pids = runtime_pid_keys_for_proc_event(pid, event_pid, []);
                    for runtime_pid in &runtime_pids {
                        write_pinned_runtime_pid_alias(*runtime_pid, pid);
                        guard.record_runtime_pid_alias(*runtime_pid, pid);
                    }
                    if let Ok(inserted) = publish_offsets_for_runtime_pid_keys(
                        pid,
                        event_pid,
                        &runtime_pids,
                        &items,
                        "initial prefill",
                    ) {
                        total += inserted;
                    }
                    insert_allowed_runtime_pid_keys(&runtime_pids);
                }
                tracing::info!(
                    "Sysmon: initial inserted {} offset entries for module {}",
                    total,
                    target_path.display()
                );
            }
        }
    }

    for pid in initial_target_pids {
        let event_pid = resolve_event_pid_for_proc(pid);
        if let Err(error) = prefill_full_offsets_for_pid_if_new(mgr, event_pid, proc_pid_for_event)
        {
            tracing::debug!(
                "Sysmon: initial full offset prefill failed for proc pid {} (event pid {}): {}",
                pid,
                event_pid,
                error
            );
        }
    }
}

#[cfg(feature = "sysmon-ebpf")]
fn run_sysmon_worker(
    mgr: Arc<Mutex<ProcessManager>>,
    cfg: SysmonConfig,
    pending: Arc<Mutex<PendingOffsets>>,
    pending_map_refreshes: Arc<Mutex<PendingMapRefreshes>>,
    tx: mpsc::SyncSender<SysEvent>,
    queue: SharedSysmonWorkQueue,
    wake_rx: mpsc::Receiver<()>,
) -> anyhow::Result<()> {
    let target = cfg.target_module;
    let proc_pid_for_event = sysmon_proc_pid_resolver(cfg.watched_pid, cfg.watched_proc_pid);
    // Only noisy map-change handling uses a short-lived `/proc` index snapshot. Lifecycle events
    // keep fresh resolution semantics so a newly visible short-lived process cannot hit a cached
    // miss from an earlier unrelated event.
    let proc_pid_for_map_change =
        cached_sysmon_proc_pid_resolver(cfg.watched_pid, cfg.watched_proc_pid);

    initialize_target_offsets(&mgr, target.as_deref(), &proc_pid_for_event);
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

    loop {
        let processed = service_sysmon_maintenance(
            &context,
            &queue,
            &mut last_module_refresh,
            &mut target_pid_map_signatures,
        )?;
        if processed == 0 {
            match wake_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(()) | Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        }
    }
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
    let use_verbose =
        cfg!(debug_assertions) || log_enabled!(LogLevel::Trace) || log_enabled!(LogLevel::Debug);
    let mut bpf = load_and_attach_sysmon_bpf(obj, &cfg, use_verbose)?;

    // Event loop: prefer ringbuf; fallback to perf
    if let Some(map) = bpf.take_map("sysmon_events") {
        let mut rb: RingBuf<MapData> = map.try_into()?;
        let mut worker = SysmonWorker::spawn(mgr, cfg, pending, pending_map_refreshes, tx)?;
        loop {
            worker.ensure_running()?;
            let mut had_event = false;
            let drain_started_at = Instant::now();
            let mut drained = 0;
            // Keep the collector bounded so the work thread gets CPU even when
            // the ring never becomes empty. All `/proc` and map work happens
            // after this handoff.
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
                    worker.enqueue(ev)?;
                }
                if drain_started_at.elapsed() >= SYSMON_RING_DRAIN_TIME_BUDGET {
                    break;
                }
            }
            if !had_event {
                std::thread::sleep(std::time::Duration::from_millis(5));
            } else if drained >= SYSMON_RING_DRAIN_EVENT_LIMIT
                || drain_started_at.elapsed() >= SYSMON_RING_DRAIN_TIME_BUDGET
            {
                std::thread::yield_now();
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
        let mut worker = SysmonWorker::spawn(mgr, cfg, pending, pending_map_refreshes, tx)?;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(10));
            worker.ensure_running()?;
            let mut enqueue_error = None;
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
                            if enqueue_error.is_none() {
                                enqueue_error = worker.enqueue(ev).err();
                            }
                        }
                    }
                    PerfEvent::Lost { count } => {
                        warn!("Perf event buffer lost {} sysmon events", count);
                    }
                });
            }
            if let Some(error) = enqueue_error {
                return Err(error);
            }
        }
    } else {
        Err(anyhow::anyhow!("No sysmon events map found (ringbuf/perf)"))
    }
}

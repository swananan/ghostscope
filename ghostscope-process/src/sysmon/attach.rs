use super::*;

#[cfg(feature = "sysmon-ebpf")]
#[derive(Debug, Clone, Copy)]
pub(super) enum SysmonAttachBackend {
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
pub(super) struct SysmonTracepoint {
    event: &'static str,
    category: &'static str,
    classic_program: &'static str,
    raw_program: &'static str,
    btf_program: &'static str,
}

#[cfg(feature = "sysmon-ebpf")]
pub(super) const SYSMON_TRACEPOINTS: &[SysmonTracepoint] = &[
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
pub(super) struct SysmonMapChangeTracepoint {
    event: &'static str,
    category: &'static str,
    program: &'static str,
}

#[cfg(feature = "sysmon-ebpf")]
pub(super) const SYSMON_MAP_CHANGE_TRACEPOINTS: &[SysmonMapChangeTracepoint] = &[
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
pub(super) fn load_sysmon_bpf(obj: &[u8], use_verbose: bool) -> anyhow::Result<aya::Ebpf> {
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
pub(super) fn configure_sysmon_exec_comm_filter(
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
pub(super) fn configure_sysmon_event_filter(
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
pub(super) fn attach_sysmon_backend(
    bpf: &mut aya::Ebpf,
    backend: SysmonAttachBackend,
) -> anyhow::Result<()> {
    match backend {
        SysmonAttachBackend::Raw => attach_raw_sysmon_tracepoints(bpf),
        SysmonAttachBackend::Btf => attach_btf_sysmon_tracepoints(bpf),
        SysmonAttachBackend::Classic => attach_classic_sysmon_tracepoints(bpf),
    }
}

#[cfg(feature = "sysmon-ebpf")]
pub(super) fn attach_raw_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
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
pub(super) fn attach_btf_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
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
pub(super) fn attach_classic_sysmon_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
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
pub(super) fn attach_classic_map_change_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<usize> {
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
pub(super) fn load_and_attach_sysmon_bpf(
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

use crate::core::GhostSession;
use tracing::{info, warn};

fn pid_alias_runtime_pid(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Option<u32> {
    let resolved_target_ns = session
        .pid_views()
        .and_then(|pid_views| Some((pid_views.pid_ns_dev()?, pid_views.pid_ns_inode()?)));
    let proc_offsets_ns = compile_options
        .proc_offsets_pid_ns
        .and_then(|pid_ns| pid_ns.helper_dev_inode());

    // When proc offsets are configured against the resolved target namespace, the
    // eBPF-side runtime key is the namespace-local TGID rather than the host-visible
    // PID used for `/proc` prefill.
    if let (Some(pid_views), Some(target_ns)) = (session.pid_views(), resolved_target_ns) {
        if proc_offsets_ns == Some(target_ns) && pid_views.container_pid.is_some() {
            return pid_views.container_pid;
        }
    }

    match compile_options.pid_filter_spec {
        Some(ghostscope_compiler::PidFilterSpec::NamespaceTgid { filter_pid, .. }) => {
            Some(filter_pid)
        }
        Some(ghostscope_compiler::PidFilterSpec::HostTgid { filter_pid }) => Some(filter_pid),
        None => session.host_pid(),
    }
}

fn pid_alias_pair(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Option<(u32, u32)> {
    let proc_pid = session.proc_pid()?;
    let runtime_pid = pid_alias_runtime_pid(session, compile_options)?;
    (runtime_pid != proc_pid).then_some((runtime_pid, proc_pid))
}

pub(super) fn apply_pid_alias_for_session(
    session: &GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) {
    if let Some((runtime_pid, proc_pid)) = pid_alias_pair(session, compile_options) {
        match ghostscope_process::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid) {
            Ok(()) => info!(
                "✓ Applied PID alias runtime_pid={} -> proc_pid={}",
                runtime_pid, proc_pid
            ),
            Err(e) => warn!(
                "Failed to write PID alias runtime_pid={} -> proc_pid={}: {}",
                runtime_pid, proc_pid, e
            ),
        }
    }
}

pub(super) fn ensure_prefill_for_session_pid(session: &GhostSession) {
    if let Some(proc_pid) = session.proc_pid() {
        let result = {
            let mut coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            coordinator.ensure_prefill_pid(proc_pid)
        };
        match result {
            Ok(count) => info!(
                "Coordinator cached {} module offset entries for PID {}",
                count, proc_pid
            ),
            Err(e) => warn!(
                "Failed to compute section offsets via coordinator: {} (globals may show OffsetsUnavailable)",
                e
            ),
        }
    }
}

pub(super) fn apply_cached_offsets_for_session_pid(session: &GhostSession) {
    if let Some(proc_pid) = session.proc_pid() {
        let items = {
            let coordinator = session
                .coordinator
                .lock()
                .expect("coordinator mutex poisoned");
            coordinator
                .cached_offsets_with_paths_for_pid(proc_pid)
                .map(|entries| entries.to_vec())
        };
        if let Some(items) = items {
            use ghostscope_process::pinned_bpf_maps::ProcModuleOffsetsValue;
            let adapted: Vec<(u64, ProcModuleOffsetsValue)> = items
                .iter()
                .map(|entry| {
                    (
                        entry.cookie,
                        ProcModuleOffsetsValue::new(
                            entry.offsets.text,
                            entry.offsets.rodata,
                            entry.offsets.data,
                            entry.offsets.bss,
                            entry.base,
                            entry.size,
                        ),
                    )
                })
                .collect();

            if let Err(e) =
                ghostscope_process::pinned_bpf_maps::insert_offsets_for_pid(proc_pid, &adapted)
            {
                warn!(
                    "Failed to write cached offsets to pinned map for PID {}: {}",
                    proc_pid, e
                );
            } else {
                info!(
                    "✓ Applied {} cached offsets to pinned map for PID {}",
                    adapted.len(),
                    proc_pid
                );
            }
            if let Err(e) =
                ghostscope_process::pinned_bpf_maps::replace_ranges_for_pid(proc_pid, &adapted)
            {
                warn!(
                    "Failed to write cached module ranges to pinned map for PID {}: {}",
                    proc_pid, e
                );
            }
        }
    }
}

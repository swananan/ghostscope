use super::procfs::{
    process_exists, read_nspid_chain, read_nspid_chain_from_status, read_pid_ns_id, read_status,
};
use super::types::{PidResolveSource, PidViews};

fn push_unique_pid(pids: &mut Vec<u32>, pid: u32) {
    if !pids.contains(&pid) {
        pids.push(pid);
    }
}

fn runtime_pid_candidates_from_chain(proc_pid: u32, nspid_chain: Option<&[u32]>) -> Vec<u32> {
    let mut pids = Vec::new();
    push_unique_pid(&mut pids, proc_pid);
    if let Some(chain) = nspid_chain {
        for pid in chain {
            push_unique_pid(&mut pids, *pid);
        }
    }
    pids
}

pub fn resolve_input_pid(input_pid: u32) -> anyhow::Result<PidViews> {
    if !process_exists(input_pid) {
        return Err(anyhow::anyhow!(
            "Process with PID {} is not running. Use 'ps -p {}' to verify the process exists.\n\
             Additional check: -p expects a PID visible in the current PID namespace.",
            input_pid,
            input_pid
        ));
    }

    resolve_proc_pid(input_pid)
}

pub fn resolve_proc_pid(proc_pid: u32) -> anyhow::Result<PidViews> {
    let status = read_status(proc_pid)?;
    let nspid_chain = read_nspid_chain_from_status(&status);
    let host_pid = nspid_chain
        .as_ref()
        .and_then(|chain| chain.first().copied())
        .unwrap_or(proc_pid);
    let container_pid = nspid_chain.as_ref().and_then(|chain| chain.last().copied());

    Ok(PidViews {
        proc_pid,
        host_pid,
        container_pid,
        pid_ns: read_pid_ns_id(proc_pid),
        nspid_chain,
        source: PidResolveSource::DirectProcStatus,
    })
}

pub fn host_pid_for_proc_pid(proc_pid: u32) -> u32 {
    read_nspid_chain(proc_pid)
        .and_then(|chain| chain.first().copied())
        .unwrap_or(proc_pid)
}

/// Resolve a kernel event PID (initial PID namespace) to the `/proc` PID in the
/// current userspace namespace when possible.
pub fn resolve_proc_pid_for_event(event_pid: u32) -> u32 {
    if std::path::Path::new(&format!("/proc/{event_pid}")).exists() {
        return event_pid;
    }

    if let Ok(dir) = std::fs::read_dir("/proc") {
        for ent in dir.flatten() {
            let file_name = ent.file_name();
            let Ok(proc_pid) = file_name.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(chain) = read_nspid_chain(proc_pid) else {
                continue;
            };
            if chain.first().copied() == Some(event_pid) {
                return proc_pid;
            }
        }
    }

    event_pid
}

/// Resolve a `/proc` PID back to the host-view event PID when possible.
pub fn resolve_event_pid_for_proc(proc_pid: u32) -> u32 {
    read_nspid_chain(proc_pid)
        .and_then(|chain| chain.first().copied())
        .unwrap_or(proc_pid)
}

/// Return PID values that eBPF-side runtime lookups may observe for a process.
///
/// Userspace stores proc-module offsets under the PID visible in its `/proc`
/// view, but eBPF helpers and sysmon events may report any PID in the visible
/// namespace chain for nested containers.
pub fn runtime_pid_candidates_for_proc(proc_pid: u32) -> Vec<u32> {
    let chain = read_nspid_chain(proc_pid);
    runtime_pid_candidates_from_chain(proc_pid, chain.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_pid_candidates_include_proc_and_full_nspid_chain() {
        assert_eq!(
            runtime_pid_candidates_from_chain(445, Some(&[1000, 531, 17])),
            vec![445, 1000, 531, 17]
        );
    }

    #[test]
    fn runtime_pid_candidates_deduplicate_proc_pid() {
        assert_eq!(
            runtime_pid_candidates_from_chain(531, Some(&[1000, 531, 17])),
            vec![531, 1000, 17]
        );
    }
}

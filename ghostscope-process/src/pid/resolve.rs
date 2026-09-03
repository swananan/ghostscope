use super::procfs::{
    process_exists, read_nspid_chain, read_nspid_chain_from_status, read_pid_ns_id, read_status,
};
use super::types::{PidResolveSource, PidViews};
use std::collections::HashMap;
use std::time::{Duration, Instant};

const EVENT_PID_INDEX_REFRESH_INTERVAL: Duration = Duration::from_millis(50);

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
            "Process with PID {input_pid} is not running. Use 'ps -p {input_pid}' to verify the process exists.\n\
             Additional check: -p expects a PID visible in the current PID namespace."
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
    if process_exists(event_pid) {
        return event_pid;
    }

    event_pid_index()
        .get(&event_pid)
        .copied()
        .unwrap_or(event_pid)
}

/// Cached resolver for bursts of sysmon events.
///
/// Short-lived processes often disappear before userspace drains their map-change events. A
/// direct lookup then fails, but rebuilding the complete namespace PID index for every stale event
/// turns an event burst into repeated full `/proc` scans. Keep one short-lived snapshot so a burst
/// pays that cost at most once per refresh interval.
#[derive(Debug)]
pub(crate) struct EventProcPidResolver {
    event_pid_to_proc_pid: HashMap<u32, u32>,
    refreshed_at: Option<Instant>,
    refresh_interval: Duration,
    #[cfg(test)]
    refresh_count: usize,
}

impl EventProcPidResolver {
    pub(crate) fn new() -> Self {
        Self::with_refresh_interval(EVENT_PID_INDEX_REFRESH_INTERVAL)
    }

    fn with_refresh_interval(refresh_interval: Duration) -> Self {
        Self {
            event_pid_to_proc_pid: HashMap::new(),
            refreshed_at: None,
            refresh_interval,
            #[cfg(test)]
            refresh_count: 0,
        }
    }

    pub(crate) fn resolve(&mut self, event_pid: u32) -> u32 {
        if process_exists(event_pid) {
            return event_pid;
        }

        let now = Instant::now();
        let index_is_stale = self
            .refreshed_at
            .map(|refreshed_at| now.duration_since(refreshed_at) >= self.refresh_interval)
            .unwrap_or(true);
        if index_is_stale {
            self.event_pid_to_proc_pid = event_pid_index();
            self.refreshed_at = Some(now);
            #[cfg(test)]
            {
                self.refresh_count += 1;
            }
        }

        self.event_pid_to_proc_pid
            .get(&event_pid)
            .copied()
            .unwrap_or(event_pid)
    }
}

fn event_pid_index() -> HashMap<u32, u32> {
    let mut event_pid_to_proc_pid = HashMap::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return event_pid_to_proc_pid;
    };

    for ent in dir.flatten() {
        let file_name = ent.file_name();
        let Ok(proc_pid) = file_name.to_string_lossy().parse::<u32>() else {
            continue;
        };
        let Some(chain) = read_nspid_chain(proc_pid) else {
            continue;
        };
        let Some(event_pid) = chain.first().copied() else {
            continue;
        };
        event_pid_to_proc_pid.insert(event_pid, proc_pid);
    }

    event_pid_to_proc_pid
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

    #[test]
    fn event_pid_resolver_reuses_one_proc_snapshot_for_missing_pids() {
        let mut resolver = EventProcPidResolver::with_refresh_interval(Duration::from_secs(1));

        assert_eq!(resolver.resolve(u32::MAX), u32::MAX);
        assert_eq!(resolver.resolve(u32::MAX - 1), u32::MAX - 1);
        assert_eq!(resolver.refresh_count, 1);
    }
}

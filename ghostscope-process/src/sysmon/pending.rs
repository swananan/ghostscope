use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PendingOffsetsKind {
    Retry,
    MapChangeCandidate,
}

impl PendingOffsetsKind {
    pub(super) fn keep_for_map_changes_after_retry_exhaustion(self) -> bool {
        matches!(self, Self::MapChangeCandidate)
    }
}

#[derive(Debug, Clone)]
pub(super) struct PendingOffsetsEntry {
    pub(super) target_path: PathBuf,
    pub(super) attempts: u32,
    pub(super) kind: PendingOffsetsKind,
    pub(super) retry_exhausted: bool,
    pub(super) last_poll: Instant,
}

#[derive(Debug, Clone)]
pub(super) struct PendingOffsetsDue {
    pub(super) event_pid: u32,
    pub(super) target_path: PathBuf,
    pub(super) attempts: u32,
    pub(super) kind: PendingOffsetsKind,
}

#[derive(Debug, Default)]
pub(super) struct PendingOffsets {
    pub(super) entries: HashMap<u32, PendingOffsetsEntry>,
}

impl PendingOffsets {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub(super) fn register(&mut self, pid: u32, target: &Path) {
        self.register_with_kind(pid, target, PendingOffsetsKind::Retry);
    }

    pub(super) fn register_map_change_candidate(&mut self, pid: u32, target: &Path) {
        self.register_with_kind(pid, target, PendingOffsetsKind::MapChangeCandidate);
    }

    pub(super) fn register_with_kind(&mut self, pid: u32, target: &Path, kind: PendingOffsetsKind) {
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

    pub(super) fn remove(&mut self, pid: u32) {
        self.entries.remove(&pid);
    }

    pub(super) fn contains_map_change_candidate(&self, pid: u32, target: &Path) -> bool {
        self.entries
            .get(&pid)
            .map(|entry| {
                entry.kind == PendingOffsetsKind::MapChangeCandidate && entry.target_path == target
            })
            .unwrap_or(false)
    }

    pub(super) fn mark_retry_exhausted(&mut self, pid: u32) {
        if let Some(entry) = self.entries.get_mut(&pid) {
            entry.retry_exhausted = true;
        }
    }

    pub(super) fn take_due(&mut self) -> Vec<PendingOffsetsDue> {
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
pub(super) struct PendingMapRefreshEntry {
    pub(super) last_seen: Instant,
    pub(super) event_pid: u32,
    pub(super) host_pid: u32,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct PendingMapRefreshDue {
    pub(super) event_pid: u32,
    pub(super) host_pid: u32,
    pub(super) proc_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PendingMapChangeCandidate {
    pub(super) event_pid: u32,
    pub(super) host_pid: u32,
    pub(super) proc_pid: u32,
}

#[derive(Debug, Default)]
pub(super) struct PendingMapRefreshes {
    pub(super) entries: HashMap<u32, PendingMapRefreshEntry>,
}

impl PendingMapRefreshes {
    pub(super) fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub(super) fn register(&mut self, event_pid: u32, host_pid: u32, proc_pid: u32) {
        self.entries.insert(
            proc_pid,
            PendingMapRefreshEntry {
                last_seen: Instant::now(),
                event_pid,
                host_pid,
            },
        );
    }

    pub(super) fn take_due(&mut self) -> Vec<PendingMapRefreshDue> {
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

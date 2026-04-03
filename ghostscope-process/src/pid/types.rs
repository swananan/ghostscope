use super::procfs::INITIAL_PID_NAMESPACE_INO;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidAttachRequest {
    /// Original user input from `ghostscope -p <PID>`.
    ///
    /// This is kept for CLI diagnostics and `$input_pid`, not as part of the
    /// runtime PID view model.
    pub input_pid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidResolveSource {
    /// `/proc/<proc_pid>/status` already provided a usable NSpid chain.
    DirectProcStatus,
}

impl fmt::Display for PidResolveSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PidResolveSource::DirectProcStatus => write!(f, "direct-proc-status"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PidNamespaceId {
    /// Device id is only present when GhostScope resolved a helper-usable namespace handle.
    ///
    /// Some procfs-derived paths only expose the inode, so `dev` remains `None` until
    /// we collect the extra information needed by `bpf_get_ns_current_pid_tgid`.
    pub dev: Option<u64>,
    pub inode: u64,
}

impl PidNamespaceId {
    pub fn helper_dev_inode(self) -> Option<(u64, u64)> {
        self.dev.map(|dev| (dev, self.inode))
    }
}

#[derive(Debug, Clone)]
pub struct PidViews {
    /// PID used for `/proc/<pid>/...` access in GhostScope's current userspace view.
    ///
    /// We intentionally do not store `input_pid` here. In GhostScope's supported
    /// `-p` contract, users enter the PID visible in the current environment, so
    /// `input_pid` and `proc_pid` are normally the same value. Keeping only
    /// `proc_pid` avoids duplicating the same concept inside the runtime PID model.
    pub proc_pid: u32,
    /// PID used by host-view runtime events and host-TGID filtering.
    pub host_pid: u32,
    /// Innermost PID namespace view when it differs from `proc_pid`.
    pub container_pid: Option<u32>,
    /// PID namespace identifier for `proc_pid` when it can be resolved.
    pub pid_ns: Option<PidNamespaceId>,
    /// Raw NSpid chain as reported by `/proc/<proc_pid>/status`.
    pub nspid_chain: Option<Vec<u32>>,
    /// Resolution source for diagnostics.
    pub source: PidResolveSource,
}

impl PidViews {
    pub fn compact_display(&self) -> String {
        let container = self
            .container_pid
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let ns_inode = self
            .pid_ns_inode()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let ns_dev = self
            .pid_ns_dev()
            .map(|value| value.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let chain = self
            .nspid_chain
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.to_string())
                    .collect::<Vec<_>>()
                    .join("->")
            })
            .unwrap_or_else(|| "n/a".to_string());

        format!(
            "proc_pid={} host_pid={} container_pid={} ns_dev={} ns_inode={} nspid_chain={} source={}",
            self.proc_pid, self.host_pid, container, ns_dev, ns_inode, chain, self.source
        )
    }

    pub fn has_explicit_host_mapping(&self) -> bool {
        self.nspid_chain
            .as_ref()
            .map(|chain| chain.len() >= 2)
            .unwrap_or(false)
    }

    pub fn is_initial_pid_namespace(&self) -> bool {
        self.pid_ns_inode() == Some(INITIAL_PID_NAMESPACE_INO)
    }

    pub fn pid_ns_dev(&self) -> Option<u64> {
        self.pid_ns.and_then(|pid_ns| pid_ns.dev)
    }

    pub fn pid_ns_inode(&self) -> Option<u64> {
        self.pid_ns.map(|pid_ns| pid_ns.inode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_pid_namespace_detection_works() {
        let mut pid_views = PidViews {
            proc_pid: 123,
            host_pid: 123,
            container_pid: None,
            pid_ns: Some(PidNamespaceId {
                dev: Some(1),
                inode: INITIAL_PID_NAMESPACE_INO,
            }),
            nspid_chain: None,
            source: PidResolveSource::DirectProcStatus,
        };
        assert!(pid_views.is_initial_pid_namespace());

        pid_views.pid_ns = Some(PidNamespaceId {
            dev: Some(1),
            inode: INITIAL_PID_NAMESPACE_INO + 1,
        });
        assert!(!pid_views.is_initial_pid_namespace());
    }
}

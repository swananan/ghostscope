use anyhow::Result;
use std::fmt;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Linux initial PID namespace inode (PROC_PID_INIT_INO).
pub const INITIAL_PID_NAMESPACE_INO: u64 = 4026531836;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidResolveSource {
    /// /proc/<input_pid>/status already provided a usable NSpid chain.
    DirectProcStatus,
}

impl fmt::Display for PidResolveSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PidResolveSource::DirectProcStatus => write!(f, "direct-proc-status"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedPidInfo {
    /// User-supplied PID from CLI -p.
    pub input_pid: u32,
    /// PID used for /proc reads in current userspace context.
    pub process_pid: u32,
    /// Host PID used by eBPF PID filtering and map keys.
    pub host_pid: u32,
    /// Container/namespace-local PID when available from NSpid tail.
    pub container_pid: Option<u32>,
    /// PID namespace device id (for bpf_get_ns_current_pid_tgid).
    pub pid_ns_dev: Option<u64>,
    /// PID namespace inode for process_pid when available.
    pub pid_ns_inode: Option<u64>,
    /// Raw NSpid chain as reported by /proc/<process_pid>/status.
    pub nspid_chain: Option<Vec<u32>>,
    /// Resolution source for diagnostics.
    pub source: PidResolveSource,
}

impl ResolvedPidInfo {
    pub fn compact_display(&self) -> String {
        let container = self
            .container_pid
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let ns_inode = self
            .pid_ns_inode
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let ns_dev = self
            .pid_ns_dev
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".to_string());
        let chain = self
            .nspid_chain
            .as_ref()
            .map(|v| {
                v.iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join("->")
            })
            .unwrap_or_else(|| "n/a".to_string());

        format!(
            "input_pid={} proc_pid={} host_pid={} container_pid={} ns_dev={} ns_inode={} nspid_chain={} source={}",
            self.input_pid,
            self.process_pid,
            self.host_pid,
            container,
            ns_dev,
            ns_inode,
            chain,
            self.source
        )
    }

    pub fn has_explicit_host_mapping(&self) -> bool {
        self.nspid_chain
            .as_ref()
            .map(|chain| chain.len() >= 2)
            .unwrap_or(false)
    }

    pub fn is_initial_pid_namespace(&self) -> bool {
        self.pid_ns_inode == Some(INITIAL_PID_NAMESPACE_INO)
    }
}

pub fn resolve_pid_info(input_pid: u32) -> Result<ResolvedPidInfo> {
    if !process_exists(input_pid) {
        return Err(anyhow::anyhow!(
            "Process with PID {} is not running. Use 'ps -p {}' to verify the process exists.\n\
             Additional check: -p expects a PID visible in the current PID namespace.",
            input_pid,
            input_pid
        ));
    }

    resolve_from_visible_pid(input_pid)
}

fn resolve_from_visible_pid(input_pid: u32) -> Result<ResolvedPidInfo> {
    let status = read_status(input_pid)?;
    let nspid_chain = parse_status_chain(&status, "NSpid:");
    let host_pid = nspid_chain
        .as_ref()
        .and_then(|v| v.first().copied())
        .unwrap_or(input_pid);
    let container_pid = nspid_chain.as_ref().and_then(|v| v.last().copied());
    let (pid_ns_dev, pid_ns_inode) = read_pid_ns_info(input_pid)
        .unwrap_or_else(|| (None, read_pid_ns_inode_from_link(input_pid)));

    Ok(ResolvedPidInfo {
        input_pid,
        process_pid: input_pid,
        host_pid,
        container_pid,
        pid_ns_dev,
        pid_ns_inode,
        nspid_chain,
        source: PidResolveSource::DirectProcStatus,
    })
}

fn process_exists(pid: u32) -> bool {
    let proc_path = format!("/proc/{pid}");
    Path::new(&proc_path).is_dir()
}

fn read_status(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/status");
    fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read {} while resolving PID mapping: {}", path, e))
}

fn parse_status_chain(status: &str, key: &str) -> Option<Vec<u32>> {
    let line = status.lines().find(|line| line.starts_with(key))?;
    let payload = line.strip_prefix(key)?.trim();
    if payload.is_empty() {
        return None;
    }
    let chain: Vec<u32> = payload
        .split_whitespace()
        .filter_map(|token| token.parse::<u32>().ok())
        .collect();
    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
}

fn read_pid_ns_info(pid: u32) -> Option<(Option<u64>, Option<u64>)> {
    let md = fs::metadata(format!("/proc/{pid}/ns/pid")).ok()?;
    Some((Some(md.dev()), Some(md.ino())))
}

fn read_pid_ns_inode_from_link(pid: u32) -> Option<u64> {
    let link = fs::read_link(format!("/proc/{pid}/ns/pid")).ok()?;
    parse_ns_inode(&link.to_string_lossy())
}

fn parse_ns_inode(link_target: &str) -> Option<u64> {
    // expected format: "pid:[4026531836]"
    let lb = link_target.find('[')?;
    let rb = link_target[lb + 1..].find(']')? + lb + 1;
    link_target[lb + 1..rb].parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ns_inode_works() {
        assert_eq!(
            parse_ns_inode("pid:[4026531836]"),
            Some(INITIAL_PID_NAMESPACE_INO)
        );
        assert_eq!(parse_ns_inode("pid:[abc]"), None);
        assert_eq!(parse_ns_inode("unknown"), None);
    }

    #[test]
    fn parse_status_chain_works() {
        let status = "Name:\tcat\nNSpid:\t1234 1\n";
        assert_eq!(parse_status_chain(status, "NSpid:"), Some(vec![1234, 1]));
    }

    #[test]
    fn initial_pid_namespace_detection_works() {
        let mut info = ResolvedPidInfo {
            input_pid: 123,
            process_pid: 123,
            host_pid: 123,
            container_pid: None,
            pid_ns_dev: None,
            pid_ns_inode: Some(INITIAL_PID_NAMESPACE_INO),
            nspid_chain: None,
            source: PidResolveSource::DirectProcStatus,
        };
        assert!(info.is_initial_pid_namespace());

        info.pid_ns_inode = Some(INITIAL_PID_NAMESPACE_INO + 1);
        assert!(!info.is_initial_pid_namespace());
    }
}

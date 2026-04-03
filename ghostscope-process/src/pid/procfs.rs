use super::types::PidNamespaceId;
use anyhow::Result;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Linux initial PID namespace inode (PROC_PID_INIT_INO).
pub const INITIAL_PID_NAMESPACE_INO: u64 = 4026531836;

pub fn process_exists(pid: u32) -> bool {
    let proc_path = format!("/proc/{pid}");
    Path::new(&proc_path).is_dir()
}

pub fn read_status(pid: u32) -> Result<String> {
    let path = format!("/proc/{pid}/status");
    fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("Failed to read {} while resolving PID mapping: {}", path, e))
}

pub fn read_nspid_chain(pid: u32) -> Option<Vec<u32>> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    read_nspid_chain_from_status(&status)
}

pub fn read_pid_ns_id(pid: u32) -> Option<PidNamespaceId> {
    if let Ok(metadata) = fs::metadata(format!("/proc/{pid}/ns/pid")) {
        return Some(PidNamespaceId {
            dev: Some(metadata.dev()),
            inode: metadata.ino(),
        });
    }

    read_pid_ns_inode_from_link(pid).map(|inode| PidNamespaceId { dev: None, inode })
}

pub fn read_pid_ns_inode(pid: u32) -> Option<u64> {
    read_pid_ns_id(pid).map(|pid_ns| pid_ns.inode)
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

pub(crate) fn read_nspid_chain_from_status(status: &str) -> Option<Vec<u32>> {
    parse_status_chain(status, "NSpid:")
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
}

use crate::pid::{
    host_pid_for_proc_pid, read_nspid_chain, read_pid_ns_inode, INITIAL_PID_NAMESPACE_INO,
};
use aya::maps::MapData;
use aya_obj::maps::bpf_map_def;
use aya_obj::{
    generated::bpf_map_type::BPF_MAP_TYPE_HASH, maps::LegacyMap, EbpfSectionKind, Map as ObjMap,
};
use libc as c;
use std::io;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

const BPFFS_MOUNT_POINT: &str = "/sys/fs/bpf";
const BPFFS_ROOT: &str = "/sys/fs/bpf/ghostscope";
const PROC_STAT_STARTTIME_INDEX: usize = 19;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentProcessIdentity {
    host_pid: u32,
    host_pid_reliable: bool,
    starttime: u64,
    initial_pid_namespace: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpffsPruneMode {
    Stale,
    Instance(String),
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpffsPruneOptions {
    pub mode: BpffsPruneMode,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpffsPruneStatus {
    RemoveDir,
    CleanKnownPins,
    SkipLive,
    Ignore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpffsPruneEntry {
    pub directory: String,
    pub status: BpffsPruneStatus,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BpffsPruneReport {
    pub root: PathBuf,
    pub dry_run: bool,
    pub entries: Vec<BpffsPruneEntry>,
}

fn process_starttime(pid: u32) -> io::Result<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let (_, rest) = stat
        .rsplit_once(") ")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed /proc stat"))?;
    let raw = rest
        .split_whitespace()
        .nth(PROC_STAT_STARTTIME_INDEX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing starttime field"))?;
    raw.parse::<u64>()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn host_pid_mapping_from_chain(
    chain: Option<&[u32]>,
    allow_single_value_nspid: bool,
) -> Option<u32> {
    match chain {
        Some([]) => None,
        Some([only]) if allow_single_value_nspid => Some(*only),
        Some([_only]) => None,
        Some(values) => values.first().copied(),
        None if allow_single_value_nspid => None,
        None => None,
    }
}

fn resolve_proc_pid_for_host_pid(host_pid: u32, allow_single_value_nspid: bool) -> Option<u32> {
    let direct = Path::new("/proc").join(host_pid.to_string());
    if direct.exists() {
        let chain = read_nspid_chain(host_pid);
        if host_pid_mapping_from_chain(chain.as_deref(), allow_single_value_nspid) == Some(host_pid)
        {
            return Some(host_pid);
        }
    }

    let entries = std::fs::read_dir("/proc").ok()?;
    for entry in entries.flatten() {
        let Ok(proc_pid) = entry.file_name().to_string_lossy().parse::<u32>() else {
            continue;
        };
        let chain = read_nspid_chain(proc_pid);
        if host_pid_mapping_from_chain(chain.as_deref(), allow_single_value_nspid) == Some(host_pid)
        {
            return Some(proc_pid);
        }
    }

    None
}

fn current_process_identity() -> anyhow::Result<CurrentProcessIdentity> {
    let proc_pid = std::process::id();
    let initial_pid_namespace = read_pid_ns_inode(proc_pid) == Some(INITIAL_PID_NAMESPACE_INO);
    let nspid_chain = read_nspid_chain(proc_pid);
    let host_pid_reliable =
        initial_pid_namespace || nspid_chain.as_ref().is_some_and(|chain| chain.len() > 1);
    Ok(CurrentProcessIdentity {
        host_pid: host_pid_for_proc_pid(proc_pid),
        host_pid_reliable,
        starttime: process_starttime(proc_pid)?,
        initial_pid_namespace,
    })
}

fn current_process_dir_name() -> anyhow::Result<String> {
    let identity = current_process_identity()?;
    Ok(format!("{}-{}", identity.host_pid, identity.starttime))
}

fn parse_pin_dir_name(name: &str) -> Option<(u32, u64)> {
    let (pid, starttime) = name.split_once('-')?;
    let pid = pid.parse::<u32>().ok()?;
    let starttime = starttime.parse::<u64>().ok()?;
    Some((pid, starttime))
}

/// Compute the bpffs pin path for the proc_module_offsets map for current process
/// Using per-process directory avoids conflicts across multiple GhostScope instances
pub fn proc_offsets_pin_path() -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{BPFFS_ROOT}/{}/proc_module_offsets",
        current_process_dir_name()?
    )))
}

/// Pin directory containing the per-process offsets map
pub fn proc_offsets_pin_dir() -> anyhow::Result<PathBuf> {
    proc_offsets_pin_path()?
        .parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("bpffs root has no parent for proc offsets pin path"))
}

/// Map name as embedded in BPF object
pub const PROC_OFFSETS_MAP_NAME: &str = "proc_module_offsets";
pub const ALLOWED_PIDS_MAP_NAME: &str = "allowed_pids";
pub const PID_ALIASES_MAP_NAME: &str = "pid_aliases";

fn bpffs_is_mounted() -> bool {
    let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    mountinfo.lines().any(|line| {
        let Some((left, right)) = line.split_once(" - ") else {
            return false;
        };
        let mount_point = left.split_whitespace().nth(4);
        let fs_type = right.split_whitespace().next();
        mount_point == Some(BPFFS_MOUNT_POINT) && fs_type == Some("bpf")
    })
}

fn bpffs_mount_hint_for_state(
    pin_path: &Path,
    bpffs_mount_point_exists: bool,
    bpffs_mounted: bool,
) -> Option<String> {
    if !pin_path.starts_with(BPFFS_ROOT) {
        return None;
    }

    if bpffs_mounted {
        return None;
    }

    if !bpffs_mount_point_exists {
        return Some(format!(
            "GhostScope requires bpffs mounted at {BPFFS_MOUNT_POINT} to pin BPF maps under {BPFFS_ROOT}. That mount point does not exist. Try: `sudo mkdir -p {BPFFS_MOUNT_POINT} && sudo mount -t bpf bpf {BPFFS_MOUNT_POINT}`."
        ));
    }

    Some(format!(
        "GhostScope requires bpffs mounted at {BPFFS_MOUNT_POINT} to pin BPF maps under {BPFFS_ROOT}. Some systems, including WSL2 and minimal/container environments, do not mount it by default. Try: `sudo mount -t bpf bpf {BPFFS_MOUNT_POINT}` and verify with `mount | grep bpf`."
    ))
}

pub fn bpffs_mount_hint_for_pin_path(pin_path: &Path) -> Option<String> {
    bpffs_mount_hint_for_state(
        pin_path,
        Path::new(BPFFS_MOUNT_POINT).exists(),
        bpffs_is_mounted(),
    )
}

/// Key for proc_module_offsets map: { pid:u32, pad:u32, cookie_lo:u32, cookie_hi:u32 }
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcModuleKey {
    pub pid: u32,
    pub pad: u32,
    pub cookie_lo: u32,
    pub cookie_hi: u32,
}

/// Value for proc_module_offsets map - section offsets for a module
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProcModuleOffsetsValue {
    pub text: u64,
    pub rodata: u64,
    pub data: u64,
    pub bss: u64,
}

unsafe impl aya::Pod for ProcModuleKey {}
unsafe impl aya::Pod for ProcModuleOffsetsValue {}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PidAliasValue {
    pub proc_pid: u32,
}

unsafe impl aya::Pod for PidAliasValue {}

impl ProcModuleOffsetsValue {
    pub fn new(text: u64, rodata: u64, data: u64, bss: u64) -> Self {
        Self {
            text,
            rodata,
            data,
            bss,
        }
    }
}

fn ensure_pin_dir(path: &Path) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
    } else {
        Ok(())
    }
}

/// Ensure the pinned global proc_module_offsets map exists at the standard path.
/// If not present, create and pin it with the specified capacity.
pub fn ensure_pinned_proc_offsets_exists(max_entries: u32) -> anyhow::Result<()> {
    let pin_path = proc_offsets_pin_path()?;
    // Ensure parent dir exists
    ensure_pin_dir(&pin_path).map_err(|e| {
        let hint = bpffs_mount_hint_for_pin_path(&pin_path)
            .map(|hint| format!(" {hint}"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "Failed to create pin directory for {} at {}: {}.{}",
            PROC_OFFSETS_MAP_NAME,
            pin_path.display(),
            e,
            hint
        )
    })?;

    // If pinned file already exists, try to reuse it directly (idempotent)
    if pin_path.exists() {
        if MapData::from_pin(&pin_path).is_ok() {
            info!(
                "Reusing existing pinned map at {} (no recreate)",
                pin_path.display()
            );
            return Ok(());
        } else {
            // Stale/corrupted pin path, remove and recreate
            let _ = std::fs::remove_file(&pin_path);
        }
    }

    // Define the map as a legacy map (compatible with Aya expectations)
    let obj_map = ObjMap::Legacy(LegacyMap {
        section_index: 0,
        section_kind: EbpfSectionKind::Maps,
        symbol_index: None,
        def: bpf_map_def {
            map_type: BPF_MAP_TYPE_HASH as u32,
            key_size: 16,   // pid:u32, pad:u32, cookie:u64
            value_size: 32, // text, rodata, data, bss
            max_entries,
            map_flags: 0,
            id: 0,
            pinning: aya_obj::maps::PinningType::None,
        },
        data: Vec::new(),
    });

    // Create the map in kernel
    let map = MapData::create(obj_map, PROC_OFFSETS_MAP_NAME, None)?;
    info!(
        "Created {} map with capacity {} entries",
        PROC_OFFSETS_MAP_NAME, max_entries
    );

    // Pin to bpffs for global reuse; handle races safely
    match map.pin(&pin_path) {
        Ok(()) => {
            info!("Pinned {} at {}", PROC_OFFSETS_MAP_NAME, pin_path.display());
            Ok(())
        }
        Err(e) => {
            // If another thread/process pinned concurrently, reuse the existing pin
            match MapData::from_pin(&pin_path) {
                Ok(_) => {
                    info!(
                        "Pin path {} already exists; reusing existing map ({}).",
                        pin_path.display(),
                        e
                    );
                    Ok(())
                }
                Err(_) => {
                    // Best-effort cleanup and propagate error
                    let _ = std::fs::remove_file(&pin_path);
                    let hint = bpffs_mount_hint_for_pin_path(&pin_path)
                        .map(|hint| format!(" {hint}"))
                        .unwrap_or_default();
                    Err(anyhow::anyhow!(
                        "Failed to pin {} at {}: {}",
                        PROC_OFFSETS_MAP_NAME,
                        pin_path.display(),
                        e
                    )
                    .context(format!(
                        "Unable to persist {PROC_OFFSETS_MAP_NAME} in bpffs.{hint}"
                    )))
                }
            }
        }
    }
}

// Low-level bpf syscall wrapper for map update (avoids tight coupling to aya map wrappers)
#[repr(C)]
struct BpfMapUpdateAttr {
    map_fd: u32,
    _pad: u32, // align to 64-bit for following fields
    key: u64,
    value: u64,
    flags: u64,
}

const BPF_MAP_UPDATE_ELEM: c::c_long = 2; // from linux/bpf.h
const BPF_MAP_DELETE_ELEM: c::c_long = 1; // from linux/bpf.h
const BPF_MAP_GET_NEXT_KEY: c::c_long = 4; // from linux/bpf.h

fn bpf_map_update_elem(
    fd: i32,
    key: *const c::c_void,
    value: *const c::c_void,
    flags: u64,
) -> io::Result<()> {
    let attr = BpfMapUpdateAttr {
        map_fd: fd as u32,
        _pad: 0,
        key: key as usize as u64,
        value: value as usize as u64,
        flags,
    };
    let ret = unsafe {
        c::syscall(
            c::SYS_bpf,
            BPF_MAP_UPDATE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapUpdateAttr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct BpfMapKeyAttr {
    map_fd: u32,
    _pad: u32, // align to 64-bit for following fields
    key: u64,
    next_key: u64,
}

fn bpf_map_get_next_key(
    fd: i32,
    key: *const c::c_void,
    next_key: *mut c::c_void,
) -> io::Result<()> {
    let attr = BpfMapKeyAttr {
        map_fd: fd as u32,
        _pad: 0,
        key: key as usize as u64,
        next_key: next_key as usize as u64,
    };
    let ret = unsafe {
        c::syscall(
            c::SYS_bpf,
            BPF_MAP_GET_NEXT_KEY,
            &attr,
            std::mem::size_of::<BpfMapKeyAttr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Compute the bpffs pin path for the allowed_pids map for current process
pub fn allowed_pids_pin_path() -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{BPFFS_ROOT}/{}/allowed_pids",
        current_process_dir_name()?
    )))
}

/// Compute the bpffs pin path for the pid_aliases map for current process.
pub fn pid_aliases_pin_path() -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(format!(
        "{BPFFS_ROOT}/{}/pid_aliases",
        current_process_dir_name()?
    )))
}

/// Ensure the pinned allowed_pids map exists under the per-process directory.
pub fn ensure_pinned_allowed_pids_exists(max_entries: u32) -> anyhow::Result<()> {
    let pin_path = allowed_pids_pin_path()?;
    ensure_pin_dir(&pin_path).map_err(|e| {
        let hint = bpffs_mount_hint_for_pin_path(&pin_path)
            .map(|hint| format!(" {hint}"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "Failed to create pin directory for {} at {}: {}.{}",
            ALLOWED_PIDS_MAP_NAME,
            pin_path.display(),
            e,
            hint
        )
    })?;

    if pin_path.exists() {
        if MapData::from_pin(&pin_path).is_ok() {
            info!("Reusing existing pinned map at {}", pin_path.display());
            return Ok(());
        } else {
            let _ = std::fs::remove_file(&pin_path);
        }
    }

    let obj_map = ObjMap::Legacy(LegacyMap {
        section_index: 0,
        section_kind: EbpfSectionKind::Maps,
        symbol_index: None,
        def: bpf_map_def {
            map_type: BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: 1,
            max_entries,
            map_flags: 0,
            id: 0,
            pinning: aya_obj::maps::PinningType::None,
        },
        data: Vec::new(),
    });

    let map = MapData::create(obj_map, ALLOWED_PIDS_MAP_NAME, None)?;
    info!(
        "Created {} map with capacity {} entries",
        ALLOWED_PIDS_MAP_NAME, max_entries
    );

    match map.pin(&pin_path) {
        Ok(()) => {
            info!("Pinned {} at {}", ALLOWED_PIDS_MAP_NAME, pin_path.display());
            Ok(())
        }
        Err(e) => match MapData::from_pin(&pin_path) {
            Ok(_) => {
                info!(
                    "Pin path {} already exists; reusing existing map ({}).",
                    pin_path.display(),
                    e
                );
                Ok(())
            }
            Err(_) => {
                let _ = std::fs::remove_file(&pin_path);
                let hint = bpffs_mount_hint_for_pin_path(&pin_path)
                    .map(|hint| format!(" {hint}"))
                    .unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to pin {} at {}: {}",
                    ALLOWED_PIDS_MAP_NAME,
                    pin_path.display(),
                    e
                )
                .context(format!(
                    "Unable to persist {ALLOWED_PIDS_MAP_NAME} in bpffs.{hint}"
                )))
            }
        },
    }
}

/// Ensure the pinned pid_aliases map exists under the per-process directory.
pub fn ensure_pinned_pid_aliases_exists(max_entries: u32) -> anyhow::Result<()> {
    let pin_path = pid_aliases_pin_path()?;
    ensure_pin_dir(&pin_path).map_err(|e| {
        let hint = bpffs_mount_hint_for_pin_path(&pin_path)
            .map(|hint| format!(" {hint}"))
            .unwrap_or_default();
        anyhow::anyhow!(
            "Failed to create pin directory for {} at {}: {}.{}",
            PID_ALIASES_MAP_NAME,
            pin_path.display(),
            e,
            hint
        )
    })?;

    if pin_path.exists() {
        if MapData::from_pin(&pin_path).is_ok() {
            info!("Reusing existing pinned map at {}", pin_path.display());
            return Ok(());
        } else {
            let _ = std::fs::remove_file(&pin_path);
        }
    }

    let obj_map = ObjMap::Legacy(LegacyMap {
        section_index: 0,
        section_kind: EbpfSectionKind::Maps,
        symbol_index: None,
        def: bpf_map_def {
            map_type: BPF_MAP_TYPE_HASH as u32,
            key_size: 4,
            value_size: 4,
            max_entries,
            map_flags: 0,
            id: 0,
            pinning: aya_obj::maps::PinningType::None,
        },
        data: Vec::new(),
    });

    let map = MapData::create(obj_map, PID_ALIASES_MAP_NAME, None)?;
    info!(
        "Created {} map with capacity {} entries",
        PID_ALIASES_MAP_NAME, max_entries
    );

    match map.pin(&pin_path) {
        Ok(()) => {
            info!("Pinned {} at {}", PID_ALIASES_MAP_NAME, pin_path.display());
            Ok(())
        }
        Err(e) => match MapData::from_pin(&pin_path) {
            Ok(_) => {
                info!(
                    "Pin path {} already exists; reusing existing map ({}).",
                    pin_path.display(),
                    e
                );
                Ok(())
            }
            Err(_) => {
                let _ = std::fs::remove_file(&pin_path);
                let hint = bpffs_mount_hint_for_pin_path(&pin_path)
                    .map(|hint| format!(" {hint}"))
                    .unwrap_or_default();
                Err(anyhow::anyhow!(
                    "Failed to pin {} at {}: {}",
                    PID_ALIASES_MAP_NAME,
                    pin_path.display(),
                    e
                )
                .context(format!(
                    "Unable to persist {PID_ALIASES_MAP_NAME} in bpffs.{hint}"
                )))
            }
        },
    }
}

/// Insert a PID into the allowed_pids pinned map.
pub fn insert_allowed_pid(pid: u32) -> anyhow::Result<()> {
    let map_data = MapData::from_pin(allowed_pids_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    let key = pid;
    let val: u8 = 1;
    bpf_map_update_elem(
        fd,
        &key as *const _ as *const _,
        &val as *const _ as *const _,
        0,
    )
    .map_err(|e| anyhow::anyhow!("allowed_pids update failed for {}: {}", pid, e))
}

/// Remove a PID from the allowed_pids pinned map.
pub fn remove_allowed_pid(pid: u32) -> anyhow::Result<()> {
    let map_data = MapData::from_pin(allowed_pids_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    bpf_map_delete_elem(fd, &pid as *const _ as *const _)
        .map_err(|e| anyhow::anyhow!("allowed_pids delete failed for {}: {}", pid, e))
}

/// Insert a runtime-pid -> proc-pid alias into the pinned pid_aliases map.
pub fn insert_pid_alias(runtime_pid: u32, proc_pid: u32) -> anyhow::Result<()> {
    let map_data = MapData::from_pin(pid_aliases_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    let key = runtime_pid;
    let val = PidAliasValue { proc_pid };
    bpf_map_update_elem(
        fd,
        &key as *const _ as *const _,
        &val as *const _ as *const _,
        0,
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "pid_aliases update failed for runtime_pid={} proc_pid={}: {}",
            runtime_pid,
            proc_pid,
            e
        )
    })
}

/// Remove a runtime-pid alias from the pinned pid_aliases map.
pub fn remove_pid_alias(runtime_pid: u32) -> anyhow::Result<()> {
    let map_data = MapData::from_pin(pid_aliases_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    bpf_map_delete_elem(fd, &runtime_pid as *const _ as *const _).map_err(|e| {
        anyhow::anyhow!(
            "pid_aliases delete failed for runtime_pid={}: {}",
            runtime_pid,
            e
        )
    })
}

fn bpf_map_delete_elem(fd: i32, key: *const c::c_void) -> io::Result<()> {
    let attr = BpfMapUpdateAttr {
        map_fd: fd as u32,
        _pad: 0,
        key: key as usize as u64,
        value: 0,
        flags: 0,
    };
    let ret = unsafe {
        c::syscall(
            c::SYS_bpf,
            BPF_MAP_DELETE_ELEM,
            &attr,
            std::mem::size_of::<BpfMapUpdateAttr>(),
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Purge all entries for a given pid in the pinned proc_module_offsets map.
pub fn purge_offsets_for_pid(pid: u32) -> anyhow::Result<usize> {
    let map_data = MapData::from_pin(proc_offsets_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    let mut deleted = 0usize;

    // Iterate keys with GET_NEXT_KEY
    let mut prev: Option<ProcModuleKey> = None;
    loop {
        let mut next: ProcModuleKey = ProcModuleKey {
            pid: 0,
            pad: 0,
            cookie_lo: 0,
            cookie_hi: 0,
        };
        let key_ptr = prev
            .as_ref()
            .map(|k| k as *const _ as *const c::c_void)
            .unwrap_or(std::ptr::null());
        let res = bpf_map_get_next_key(fd, key_ptr, &mut next as *mut _ as *mut _);
        match res {
            Ok(()) => {
                // Check pid match
                if next.pid == pid {
                    // Delete and continue iteration from the same prev (do not advance prev)
                    let _ = bpf_map_delete_elem(fd, &next as *const _ as *const _);
                    deleted += 1;
                    // Do not set prev = Some(next) to avoid skipping following keys
                    continue;
                } else {
                    prev = Some(next);
                }
            }
            Err(e) => {
                // ENOENT means end of iteration
                if e.raw_os_error() == Some(libc::ENOENT) {
                    break;
                } else {
                    return Err(anyhow::anyhow!("bpf_map_get_next_key failed: {}", e));
                }
            }
        }
    }
    Ok(deleted)
}

/// Open the pinned global proc_module_offsets map and insert entries via raw bpf syscall.
pub fn insert_offsets_for_pid(
    pid: u32,
    items: &[(u64, ProcModuleOffsetsValue)],
) -> anyhow::Result<usize> {
    let map_data = MapData::from_pin(proc_offsets_pin_path()?)?;
    let fd = map_data.fd().as_fd().as_raw_fd();
    let mut inserted = 0usize;
    for (cookie, off) in items {
        let key = ProcModuleKey {
            pid,
            pad: 0,
            cookie_lo: (*cookie & 0xffff_ffff) as u32,
            cookie_hi: (*cookie >> 32) as u32,
        };
        match bpf_map_update_elem(
            fd,
            &key as *const _ as *const _,
            off as *const _ as *const _,
            0,
        ) {
            Ok(()) => {
                tracing::debug!(
                    "proc_module_offsets insert ok: pid={} cookie=0x{:08x}{:08x} text=0x{:x} rodata=0x{:x} data=0x{:x} bss=0x{:x}",
                    pid, key.cookie_hi, key.cookie_lo, off.text, off.rodata, off.data, off.bss
                );
                inserted += 1
            }
            Err(e) => warn!(
                "bpf_map_update_elem failed for pid={} cookie=0x{:08x}{:08x}: {}",
                pid, key.cookie_hi, key.cookie_lo, e
            ),
        }
    }
    Ok(inserted)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirCleanupOutcome {
    RemovedDir,
}

fn cleanup_outcome_without_mutation(dir: &Path) -> anyhow::Result<DirCleanupOutcome> {
    if let Err(err) = std::fs::metadata(dir) {
        if err.kind() != io::ErrorKind::NotFound {
            return Err(err.into());
        }
    }
    Ok(DirCleanupOutcome::RemovedDir)
}

fn cleanup_pinned_maps_in_dir(dir: &Path) -> anyhow::Result<DirCleanupOutcome> {
    match std::fs::remove_dir_all(dir) {
        Ok(()) => Ok(DirCleanupOutcome::RemovedDir),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(DirCleanupOutcome::RemovedDir),
        Err(err) => Err(err.into()),
    }
}

fn stale_reason_for_dir<R, S>(
    host_pid: u32,
    dir_starttime: u64,
    current: CurrentProcessIdentity,
    resolve_proc_pid: &R,
    read_starttime: &S,
) -> Option<&'static str>
where
    R: Fn(u32) -> Option<u32>,
    S: Fn(u32) -> io::Result<u64>,
{
    if current.host_pid_reliable && host_pid == current.host_pid {
        return (dir_starttime != current.starttime).then_some("starttime_mismatch");
    }

    let Some(proc_pid) = resolve_proc_pid(host_pid) else {
        return current.initial_pid_namespace.then_some("pid_not_running");
    };

    match read_starttime(proc_pid) {
        Ok(live_starttime) if live_starttime != dir_starttime => Some("starttime_mismatch"),
        Ok(_) => None,
        Err(_) => current.initial_pid_namespace.then_some("pid_not_running"),
    }
}

fn prune_entry_for_cleanup(
    directory: String,
    reason: &str,
    outcome: DirCleanupOutcome,
) -> BpffsPruneEntry {
    BpffsPruneEntry {
        directory,
        status: match outcome {
            DirCleanupOutcome::RemovedDir => BpffsPruneStatus::RemoveDir,
        },
        reason: reason.to_string(),
    }
}

fn prune_pinned_maps_under<R, S>(
    root: &Path,
    current: CurrentProcessIdentity,
    options: &BpffsPruneOptions,
    resolve_proc_pid: R,
    read_starttime: S,
) -> anyhow::Result<BpffsPruneReport>
where
    R: Fn(u32) -> Option<u32>,
    S: Fn(u32) -> io::Result<u64>,
{
    if let BpffsPruneMode::Instance(instance) = &options.mode {
        let path = root.join(instance);
        if !path.exists() {
            return Err(anyhow::anyhow!(
                "bpffs pin directory not found: {}",
                path.display()
            ));
        }
        if !path.is_dir() {
            return Err(anyhow::anyhow!(
                "bpffs pin path is not a directory: {}",
                path.display()
            ));
        }

        let outcome = if options.dry_run {
            cleanup_outcome_without_mutation(&path)?
        } else {
            cleanup_pinned_maps_in_dir(&path)?
        };

        return Ok(BpffsPruneReport {
            root: root.to_path_buf(),
            dry_run: options.dry_run,
            entries: vec![prune_entry_for_cleanup(
                instance.clone(),
                "explicit_instance",
                outcome,
            )],
        });
    }

    let mut entries_out = Vec::new();

    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(BpffsPruneReport {
                root: root.to_path_buf(),
                dry_run: options.dry_run,
                entries: entries_out,
            });
        }
        Err(err) => return Err(err.into()),
    };

    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }

        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some((host_pid, dir_starttime)) = parse_pin_dir_name(&name) else {
            entries_out.push(BpffsPruneEntry {
                directory: name,
                status: BpffsPruneStatus::Ignore,
                reason: "non_matching_name".to_string(),
            });
            continue;
        };

        let removal_reason = match &options.mode {
            BpffsPruneMode::Stale => stale_reason_for_dir(
                host_pid,
                dir_starttime,
                current,
                &resolve_proc_pid,
                &read_starttime,
            ),
            BpffsPruneMode::All => Some("force_all"),
            BpffsPruneMode::Instance(_) => unreachable!(),
        };

        let Some(reason) = removal_reason else {
            entries_out.push(BpffsPruneEntry {
                directory: name,
                status: BpffsPruneStatus::SkipLive,
                reason: "live_instance".to_string(),
            });
            continue;
        };

        let outcome = if options.dry_run {
            cleanup_outcome_without_mutation(&entry.path())?
        } else {
            cleanup_pinned_maps_in_dir(&entry.path())?
        };
        entries_out.push(prune_entry_for_cleanup(name, reason, outcome));
    }

    entries_out.sort_by(|left, right| left.directory.cmp(&right.directory));

    Ok(BpffsPruneReport {
        root: root.to_path_buf(),
        dry_run: options.dry_run,
        entries: entries_out,
    })
}

fn cleanup_stale_pinned_maps_under<R, S>(
    root: &Path,
    current: CurrentProcessIdentity,
    resolve_proc_pid: R,
    read_starttime: S,
) -> anyhow::Result<usize>
where
    R: Fn(u32) -> Option<u32>,
    S: Fn(u32) -> io::Result<u64>,
{
    let report = prune_pinned_maps_under(
        root,
        current,
        &BpffsPruneOptions {
            mode: BpffsPruneMode::Stale,
            dry_run: false,
        },
        resolve_proc_pid,
        read_starttime,
    )?;

    Ok(report
        .entries
        .iter()
        .filter(|entry| entry.status == BpffsPruneStatus::RemoveDir)
        .count())
}

/// Remove the current process's pinned maps and its per-process directory (best effort).
/// Safe to call multiple times; missing paths are ignored.
pub fn cleanup_current_pinned_maps() -> anyhow::Result<()> {
    let _ = cleanup_pinned_maps_in_dir(&proc_offsets_pin_dir()?);
    Ok(())
}

/// Remove stale per-process pinned map directories whose PID no longer exists.
pub fn cleanup_stale_pinned_maps_root() -> anyhow::Result<usize> {
    let current = current_process_identity()?;
    cleanup_stale_pinned_maps_under(
        Path::new(BPFFS_ROOT),
        current,
        |host_pid| resolve_proc_pid_for_host_pid(host_pid, current.initial_pid_namespace),
        process_starttime,
    )
}

pub fn prune_pinned_maps_root(options: &BpffsPruneOptions) -> anyhow::Result<BpffsPruneReport> {
    let current = current_process_identity()?;
    prune_pinned_maps_under(
        Path::new(BPFFS_ROOT),
        current,
        options,
        |host_pid| resolve_proc_pid_for_host_pid(host_pid, current.initial_pid_namespace),
        process_starttime,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_pinned_maps_in_dir, cleanup_stale_pinned_maps_under, parse_pin_dir_name,
        process_starttime, prune_pinned_maps_under, BpffsPruneMode, BpffsPruneOptions,
        BpffsPruneStatus, CurrentProcessIdentity, ALLOWED_PIDS_MAP_NAME, PROC_OFFSETS_MAP_NAME,
    };
    use std::{fs, io};
    use tempfile::tempdir;

    fn host_test_identity(host_pid: u32, starttime: u64) -> CurrentProcessIdentity {
        CurrentProcessIdentity {
            host_pid,
            host_pid_reliable: true,
            starttime,
            initial_pid_namespace: true,
        }
    }

    fn private_ns_test_identity(host_pid: u32, starttime: u64) -> CurrentProcessIdentity {
        CurrentProcessIdentity {
            host_pid,
            host_pid_reliable: false,
            starttime,
            initial_pid_namespace: false,
        }
    }

    fn simulated_starttime(pid: u32) -> io::Result<u64> {
        match pid {
            222 => Ok(20),
            333 => Ok(30),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "missing pid")),
        }
    }

    #[test]
    fn cleanup_removes_known_pinned_maps_and_empty_dir() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("1234");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();

        cleanup_pinned_maps_in_dir(&dir).unwrap();

        assert!(!dir.exists());
    }

    #[test]
    fn cleanup_removes_dir_even_when_unknown_files_remain() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("1234");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        let extra = dir.join("keep-me");
        fs::write(&extra, b"extra").unwrap();

        cleanup_pinned_maps_in_dir(&dir).unwrap();

        assert!(!dir.exists());
        assert!(!extra.exists());
    }

    #[test]
    fn stale_cleanup_removes_only_dead_pid_dirs() {
        let temp = tempdir().unwrap();
        let stale_dir = temp.path().join("111-10");
        let live_dir = temp.path().join("222-20");
        let current_dir = temp.path().join("333-30");
        let non_pid_dir = temp.path().join("not-a-pid");

        for dir in [&stale_dir, &live_dir, &current_dir, &non_pid_dir] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
            fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        }

        let removed = cleanup_stale_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            |host_pid| matches!(host_pid, 222 | 333).then_some(host_pid),
            simulated_starttime,
        )
        .unwrap();

        assert_eq!(removed, 1);
        assert!(!stale_dir.exists());
        assert!(live_dir.exists());
        assert!(current_dir.exists());
        assert!(non_pid_dir.exists());
    }

    #[test]
    fn stale_cleanup_removes_mismatched_starttime_for_reused_pid() {
        let temp = tempdir().unwrap();
        let stale_current_pid_dir = temp.path().join("333-10");
        let current_pid_dir = temp.path().join("333-30");

        for dir in [&stale_current_pid_dir, &current_pid_dir] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
            fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        }

        let removed = cleanup_stale_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            |host_pid| (host_pid == 333).then_some(host_pid),
            simulated_starttime,
        )
        .unwrap();

        assert_eq!(removed, 1);
        assert!(!stale_current_pid_dir.exists());
        assert!(current_pid_dir.exists());
    }

    #[test]
    fn parse_pin_dir_name_requires_pid_starttime_format() {
        assert_eq!(parse_pin_dir_name("1234"), None);
        assert_eq!(parse_pin_dir_name("1234-5678"), Some((1234, 5678)));
        assert_eq!(parse_pin_dir_name("bad"), None);
        assert_eq!(parse_pin_dir_name("1234-bad"), None);
    }

    #[test]
    fn stale_cleanup_ignores_legacy_numeric_dirs() {
        let temp = tempdir().unwrap();
        let legacy_dir = temp.path().join("444");
        let current_dir = temp.path().join("333-30");

        for dir in [&legacy_dir, &current_dir] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
            fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        }

        let removed = cleanup_stale_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            |host_pid| matches!(host_pid, 333 | 444).then_some(host_pid),
            simulated_starttime,
        )
        .unwrap();

        assert_eq!(removed, 0);
        assert!(legacy_dir.exists());
        assert!(current_dir.exists());
    }

    #[test]
    fn dry_run_prune_reports_stale_and_keeps_dirs_intact() {
        let temp = tempdir().unwrap();
        let stale_dir = temp.path().join("111-10");
        let live_dir = temp.path().join("222-20");
        let legacy_dir = temp.path().join("legacy");

        for dir in [&stale_dir, &live_dir, &legacy_dir] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
            fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        }

        let report = prune_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::Stale,
                dry_run: true,
            },
            |host_pid| (host_pid == 222).then_some(host_pid),
            simulated_starttime,
        )
        .unwrap();

        assert!(stale_dir.exists());
        assert!(live_dir.exists());
        assert!(legacy_dir.exists());
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "111-10"
                && entry.status == BpffsPruneStatus::RemoveDir
                && entry.reason == "pid_not_running"
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "222-20"
                && entry.status == BpffsPruneStatus::SkipLive
                && entry.reason == "live_instance"
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "legacy"
                && entry.status == BpffsPruneStatus::Ignore
                && entry.reason == "non_matching_name"
        }));
    }

    #[test]
    fn instance_prune_removes_selected_dir_even_when_live() {
        let temp = tempdir().unwrap();
        let live_dir = temp.path().join("222-20");
        fs::create_dir_all(&live_dir).unwrap();
        fs::write(live_dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(live_dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();

        let report = prune_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::Instance("222-20".to_string()),
                dry_run: false,
            },
            |_host_pid| Some(222),
            simulated_starttime,
        )
        .unwrap();

        assert!(!live_dir.exists());
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].directory, "222-20");
        assert_eq!(report.entries[0].status, BpffsPruneStatus::RemoveDir);
        assert_eq!(report.entries[0].reason, "explicit_instance");
    }

    #[test]
    fn force_all_prune_skips_legacy_dirs_but_removes_pid_starttime_dirs() {
        let temp = tempdir().unwrap();
        let live_dir = temp.path().join("222-20");
        let legacy_dir = temp.path().join("222");

        for dir in [&live_dir, &legacy_dir] {
            fs::create_dir_all(dir).unwrap();
            fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
            fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        }

        let report = prune_pinned_maps_under(
            temp.path(),
            host_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::All,
                dry_run: false,
            },
            |_host_pid| Some(222),
            simulated_starttime,
        )
        .unwrap();

        assert!(!live_dir.exists());
        assert!(legacy_dir.exists());
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "222-20"
                && entry.status == BpffsPruneStatus::RemoveDir
                && entry.reason == "force_all"
        }));
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "222"
                && entry.status == BpffsPruneStatus::Ignore
                && entry.reason == "non_matching_name"
        }));
    }

    #[test]
    fn stale_prune_skips_unresolvable_host_pid_in_private_namespace() {
        let temp = tempdir().unwrap();
        let foreign_live_dir = temp.path().join("999-10");
        fs::create_dir_all(&foreign_live_dir).unwrap();
        fs::write(foreign_live_dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(foreign_live_dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();

        let report = prune_pinned_maps_under(
            temp.path(),
            private_ns_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::Stale,
                dry_run: false,
            },
            |_host_pid| None,
            simulated_starttime,
        )
        .unwrap();

        assert!(foreign_live_dir.exists());
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "999-10"
                && entry.status == BpffsPruneStatus::SkipLive
                && entry.reason == "live_instance"
        }));
    }

    #[test]
    fn stale_prune_skips_same_numeric_pid_when_current_host_pid_is_not_reliable() {
        let temp = tempdir().unwrap();
        let foreign_live_dir = temp.path().join("333-10");
        fs::create_dir_all(&foreign_live_dir).unwrap();
        fs::write(foreign_live_dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(foreign_live_dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();

        let report = prune_pinned_maps_under(
            temp.path(),
            private_ns_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::Stale,
                dry_run: false,
            },
            |_host_pid| None,
            simulated_starttime,
        )
        .unwrap();

        assert!(foreign_live_dir.exists());
        assert!(report.entries.iter().any(|entry| {
            entry.directory == "333-10"
                && entry.status == BpffsPruneStatus::SkipLive
                && entry.reason == "live_instance"
        }));
    }

    #[test]
    fn stale_prune_keeps_live_dir_when_host_pid_maps_to_proc_pid() {
        let temp = tempdir().unwrap();
        let proc_pid = std::process::id();
        let proc_starttime = process_starttime(proc_pid).unwrap();
        let live_dir = temp.path().join(format!("999-{proc_starttime}"));
        fs::create_dir_all(&live_dir).unwrap();
        fs::write(live_dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(live_dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();

        let report = prune_pinned_maps_under(
            temp.path(),
            private_ns_test_identity(333, 30),
            &BpffsPruneOptions {
                mode: BpffsPruneMode::Stale,
                dry_run: false,
            },
            |host_pid| (host_pid == 999).then_some(proc_pid),
            process_starttime,
        )
        .unwrap();

        assert!(live_dir.exists());
        assert!(report.entries.iter().any(|entry| {
            entry.directory == format!("999-{proc_starttime}")
                && entry.status == BpffsPruneStatus::SkipLive
                && entry.reason == "live_instance"
        }));
    }
}
// Note: map open/write helpers will be added once we standardize on aya APIs across crates.

#[cfg(test)]
mod bpffs_hint_tests {
    use super::bpffs_mount_hint_for_state;
    use std::path::Path;

    #[test]
    fn bpffs_hint_mentions_mount_for_unmounted_sys_fs_bpf() {
        let hint =
            bpffs_mount_hint_for_state(Path::new("/sys/fs/bpf/ghostscope/1/test"), true, false)
                .expect("expected mount hint");
        assert!(hint.contains("mount -t bpf bpf /sys/fs/bpf"));
        assert!(hint.contains("WSL2"));
    }

    #[test]
    fn bpffs_hint_omits_message_when_bpffs_is_mounted() {
        let hint =
            bpffs_mount_hint_for_state(Path::new("/sys/fs/bpf/ghostscope/1/test"), true, true);
        assert!(hint.is_none());
    }

    #[test]
    fn bpffs_hint_ignores_non_bpffs_paths() {
        let hint = bpffs_mount_hint_for_state(Path::new("/tmp/ghostscope/test"), true, false);
        assert!(hint.is_none());
    }
}

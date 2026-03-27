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

const BPFFS_ROOT: &str = "/sys/fs/bpf/ghostscope";
const PROC_STAT_STARTTIME_INDEX: usize = 19;

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

fn current_process_dir_name() -> anyhow::Result<String> {
    let pid = std::process::id();
    let starttime = process_starttime(pid)?;
    Ok(format!("{pid}-{starttime}"))
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
    ensure_pin_dir(&pin_path)?;

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
                    Err(anyhow::anyhow!(
                        "Failed to pin {} at {}: {}",
                        PROC_OFFSETS_MAP_NAME,
                        pin_path.display(),
                        e
                    ))
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

/// Ensure the pinned allowed_pids map exists under the per-process directory.
pub fn ensure_pinned_allowed_pids_exists(max_entries: u32) -> anyhow::Result<()> {
    let pin_path = allowed_pids_pin_path()?;
    ensure_pin_dir(&pin_path)?;

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
                Err(anyhow::anyhow!(
                    "Failed to pin {} at {}: {}",
                    ALLOWED_PIDS_MAP_NAME,
                    pin_path.display(),
                    e
                ))
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

fn cleanup_pinned_maps_in_dir(dir: &Path) -> anyhow::Result<()> {
    for file_name in [PROC_OFFSETS_MAP_NAME, ALLOWED_PIDS_MAP_NAME] {
        let path = dir.join(file_name);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }

    if let Ok(mut rd) = std::fs::read_dir(dir) {
        if rd.next().is_none() {
            let _ = std::fs::remove_dir(dir);
        }
    }

    Ok(())
}

fn cleanup_stale_pinned_maps_under<F>(
    root: &Path,
    current_pid: u32,
    current_starttime: u64,
    is_pid_live: F,
) -> anyhow::Result<usize>
where
    F: Fn(u32) -> bool,
{
    let mut removed_dirs = 0usize;

    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(0),
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
        let Some((pid, dir_starttime)) = parse_pin_dir_name(&name) else {
            continue;
        };

        let live = if pid == current_pid {
            dir_starttime == current_starttime
        } else if !is_pid_live(pid) {
            false
        } else {
            match process_starttime(pid) {
                Ok(live_starttime) => live_starttime == dir_starttime,
                Err(_) => true,
            }
        };

        if live {
            continue;
        }

        cleanup_pinned_maps_in_dir(&entry.path())?;
        removed_dirs += 1;
    }

    Ok(removed_dirs)
}

fn is_pid_live(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

/// Remove the current process's pinned maps and its per-process directory (best effort).
/// Safe to call multiple times; missing paths are ignored.
pub fn cleanup_current_pinned_maps() -> anyhow::Result<()> {
    cleanup_pinned_maps_in_dir(&proc_offsets_pin_dir()?)
}

/// Remove stale per-process pinned map directories whose PID no longer exists.
pub fn cleanup_stale_pinned_maps_root() -> anyhow::Result<usize> {
    let current_pid = std::process::id();
    let current_starttime = process_starttime(current_pid)?;
    cleanup_stale_pinned_maps_under(
        Path::new(BPFFS_ROOT),
        current_pid,
        current_starttime,
        is_pid_live,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        cleanup_pinned_maps_in_dir, cleanup_stale_pinned_maps_under, parse_pin_dir_name,
        ALLOWED_PIDS_MAP_NAME, PROC_OFFSETS_MAP_NAME,
    };
    use std::fs;
    use tempfile::tempdir;

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
    fn cleanup_preserves_dir_when_unknown_files_remain() {
        let temp = tempdir().unwrap();
        let dir = temp.path().join("1234");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(PROC_OFFSETS_MAP_NAME), b"offsets").unwrap();
        fs::write(dir.join(ALLOWED_PIDS_MAP_NAME), b"allow").unwrap();
        let extra = dir.join("keep-me");
        fs::write(&extra, b"extra").unwrap();

        cleanup_pinned_maps_in_dir(&dir).unwrap();

        assert!(dir.exists());
        assert!(extra.exists());
        assert!(!dir.join(PROC_OFFSETS_MAP_NAME).exists());
        assert!(!dir.join(ALLOWED_PIDS_MAP_NAME).exists());
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

        let removed =
            cleanup_stale_pinned_maps_under(temp.path(), 333, 30, |pid| matches!(pid, 222 | 333))
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

        let removed =
            cleanup_stale_pinned_maps_under(temp.path(), 333, 30, |pid| pid == 333).unwrap();

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

        let removed =
            cleanup_stale_pinned_maps_under(temp.path(), 333, 30, |pid| matches!(pid, 333 | 444))
                .unwrap();

        assert_eq!(removed, 0);
        assert!(legacy_dir.exists());
        assert!(current_dir.exists());
    }
}
// Note: map open/write helpers will be added once we standardize on aya APIs across crates.

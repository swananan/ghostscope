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

/// Compute the bpffs pin path for the proc_module_offsets map for current process
/// Using per-process directory avoids conflicts across multiple GhostScope instances
pub fn proc_offsets_pin_path() -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/sys/fs/bpf/ghostscope/{pid}/proc_module_offsets"))
}

/// Pin directory containing the per-process offsets map
pub fn proc_offsets_pin_dir() -> PathBuf {
    proc_offsets_pin_path()
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/sys/fs/bpf/ghostscope"))
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
    let pin_path = proc_offsets_pin_path();
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
pub fn allowed_pids_pin_path() -> PathBuf {
    let pid = std::process::id();
    PathBuf::from(format!("/sys/fs/bpf/ghostscope/{pid}/allowed_pids"))
}

/// Ensure the pinned allowed_pids map exists under the per-process directory.
pub fn ensure_pinned_allowed_pids_exists(max_entries: u32) -> anyhow::Result<()> {
    let pin_path = allowed_pids_pin_path();
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
    let map_data = MapData::from_pin(allowed_pids_pin_path())?;
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
    let map_data = MapData::from_pin(allowed_pids_pin_path())?;
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
    let map_data = MapData::from_pin(proc_offsets_pin_path())?;
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
    let map_data = MapData::from_pin(proc_offsets_pin_path())?;
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

/// Remove the pinned proc_module_offsets map and its per-process directory (best effort).
/// Safe to call multiple times; missing paths are ignored.
pub fn cleanup_pinned_proc_offsets() -> anyhow::Result<()> {
    let path = proc_offsets_pin_path();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
    if let Some(dir) = path.parent() {
        if let Ok(mut rd) = std::fs::read_dir(dir) {
            if rd.next().is_none() {
                let _ = std::fs::remove_dir(dir);
            }
        }
    }
    Ok(())
}
// Note: map open/write helpers will be added once we standardize on aya APIs across crates.

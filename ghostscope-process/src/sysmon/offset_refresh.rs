use super::events::*;
use super::pending::*;
use super::pid_alias::*;
use super::*;

/* moved to ghostscope_process::util::is_shared_object
pub(super) fn looks_like_shared_object(path: &Path) -> bool {
    // Determine shared object by ELF metadata:
    // - ET_EXEC => executable (not shared)
    // - ET_DYN + PT_INTERP present => PIE executable (not shared)
    // - ET_DYN without PT_INTERP => shared library
    use std::fs::File;
    use std::io::{Read, Seek, SeekFrom};

    const EI_CLASS: usize = 4; // 1=32-bit, 2=64-bit
    const EI_DATA: usize = 5; // 1=little, 2=big
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const PT_INTERP: u32 = 3;

    let mut f = match File::open(path) {
        Ok(f) => f,
        Err(_) => return false, // conservative: treat as executable (enable filtering)
    };
    let mut ehdr = [0u8; 64];
    if f.read(&mut ehdr).ok().filter(|&n| n >= 52).is_none() {
        return false;
    }
    // ELF magic
    if &ehdr[0..4] != b"\x7FELF" {
        return false;
    }
    let class = ehdr[EI_CLASS];
    let data = ehdr[EI_DATA];
    let is_le = data == 1;
    // read u16/u32/u64 helpers
    let rd16 = |b: &[u8]| -> u16 {
        if is_le {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let rd32 = |b: &[u8]| -> u32 {
        if is_le {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    let rd64 = |b: &[u8]| -> u64 {
        if is_le {
            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        } else {
            u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
        }
    };

    // e_type at 0x10
    let e_type = rd16(&ehdr[16..18]);
    if e_type == ET_EXEC {
        return false; // executable
    }

    // program header table offsets
    let (e_phoff, e_phentsize, e_phnum) = match class {
        1 => {
            // ELF32: e_phoff @0x1C (4), e_phentsize @0x2A (2), e_phnum @0x2C (2)
            let phoff = rd32(&ehdr[28..32]) as u64;
            let entsz = rd16(&ehdr[42..44]) as u64;
            let phnum = rd16(&ehdr[44..46]) as u64;
            (phoff, entsz, phnum)
        }
        2 => {
            // ELF64: e_phoff @0x20 (8), e_phentsize @0x36 (2), e_phnum @0x38 (2)
            let phoff = rd64(&ehdr[32..40]);
            let entsz = rd16(&ehdr[54..56]) as u64;
            let phnum = rd16(&ehdr[56..58]) as u64;
            (phoff, entsz, phnum)
        }
        _ => return false,
    };

    if e_type == ET_DYN {
        // Scan program headers for PT_INTERP
        if e_phoff == 0 || e_phentsize < 4 || e_phnum == 0 {
            // malformed
            // If cannot inspect, be conservative and treat as shared library (disable filtering)
            return true;
        }
        // Seek and read each p_type
        for i in 0..e_phnum {
            let off = e_phoff + i * e_phentsize;
            if f.seek(SeekFrom::Start(off)).is_err() {
                return true;
            }
            let mut p = [0u8; 8];
            if f.read(&mut p[..4]).ok().filter(|&n| n == 4).is_none() {
                return true;
            }
            let p_type = rd32(&p[..4]);
            if p_type == PT_INTERP {
                return false; // PIE executable
            }
        }
        return true; // ET_DYN w/o PT_INTERP => shared library
    }

    // Unknown types: default to 'not shared' (enable filtering)
    false
}
*/

pub(super) fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

pub(super) fn filter_entries_for_target<'a>(
    entries: &'a [PidOffsetsEntry],
    target: Option<&Path>,
) -> Vec<&'a PidOffsetsEntry> {
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    if let Some(tpath) = target {
        match fs::metadata(tpath) {
            Ok(meta) => {
                let t_dev = meta.dev();
                let t_ino = meta.ino();
                entries
                    .iter()
                    .filter(|e| {
                        fs::metadata(&e.module_path)
                            .map(|m| m.dev() == t_dev && m.ino() == t_ino)
                            .unwrap_or(false)
                    })
                    .collect()
            }
            Err(_) => {
                let tc = cookie_for_path(&tpath.to_string_lossy());
                let by_cookie: Vec<_> = entries.iter().filter(|e| e.cookie == tc).collect();
                if !by_cookie.is_empty() {
                    by_cookie
                } else {
                    let tnorm = tpath.to_string_lossy().replace("/./", "/");
                    entries.iter().filter(|e| e.module_path == tnorm).collect()
                }
            }
        }
    } else {
        entries.iter().collect()
    }
}

pub(super) fn prefill_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    target: Option<&Path>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    write_offsets_for_pid(mgr, event_pid, target, false, &[], proc_pid_for_event)
}

pub(super) fn refresh_offsets_for_known_proc_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
) -> anyhow::Result<bool> {
    let proc_pid_for_event = |_: u32| proc_pid;
    write_offsets_for_pid(mgr, event_pid, None, true, &[host_pid], &proc_pid_for_event)
}

pub(super) fn write_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    target: Option<&Path>,
    force_refresh: bool,
    extra_runtime_pids: &[u32],
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    let proc_pid = proc_pid_for_event(event_pid);
    let runtime_pids =
        runtime_pid_keys_for_proc_event(proc_pid, event_pid, extra_runtime_pids.iter().copied());
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);
    let mut inserted_any = false;
    if let Ok(mut guard) = mgr.lock() {
        if target.is_some() && is_current_process_pid(proc_pid) {
            tracing::debug!(
                "Sysmon: skipping self proc pid {} for target-module offset prefill",
                proc_pid
            );
            return Ok(false);
        }
        let prefilled = match if force_refresh {
            guard.refresh_prefill_pid(proc_pid)
        } else {
            guard.ensure_prefill_pid(proc_pid)
        } {
            Ok(v) => v,
            Err(e) => {
                // In private PID namespaces, sysmon event PID may be in the initial namespace
                // and not resolvable via /proc/<event_pid>. Fall back to module-wide refresh.
                if let Some(target_path) = target {
                    let module_path = target_path.to_string_lossy().to_string();
                    tracing::debug!(
                        "Sysmon: pid prefill failed for event pid {} (proc pid {}): {}; falling back to module refresh for {}",
                        event_pid,
                        proc_pid,
                        e,
                        module_path
                    );
                    let refreshed = guard.refresh_prefill_module(&module_path)?;
                    if refreshed > 0 {
                        tracing::info!(
                            "Sysmon: module refresh cached {} pid(s) for {}",
                            refreshed,
                            module_path
                        );
                    }
                    let mut target_pids = BTreeSet::new();
                    for (pid, _, _, _, _) in guard.cached_offsets_for_module(&module_path) {
                        target_pids.insert(pid);
                    }
                    drop(guard);

                    for pid in target_pids {
                        let runtime_pid = resolve_event_pid_for_proc(pid);
                        match refresh_full_offsets_for_pid(mgr, pid, runtime_pid) {
                            Ok(true) => inserted_any = true,
                            Ok(false) => {}
                            Err(err) => tracing::warn!(
                                "Sysmon: module refresh failed to publish full snapshot for proc pid {}: {}",
                                pid,
                                err
                            ),
                        }
                    }
                    return Ok(inserted_any);
                }
                return Err(e);
            }
        };
        if prefilled > 0 {
            info!(
                "Sysmon: {} {} entries for event pid {} (proc pid {})",
                if force_refresh {
                    "refreshed"
                } else {
                    "prefilled"
                },
                prefilled,
                event_pid,
                proc_pid
            );
        }
        let mut entries = guard
            .cached_offsets_with_paths_for_pid(proc_pid)
            .map(|entries| entries.to_vec())
            .unwrap_or_default();
        let mut target_match_count = filter_entries_for_target(&entries, target).len();

        if target_match_count == 0 && target.is_some() {
            let refreshed = guard.refresh_prefill_pid(proc_pid)?;
            if refreshed > 0 {
                tracing::debug!(
                    "Sysmon: refreshed {} cached entries for event pid {} (proc pid {})",
                    refreshed,
                    event_pid,
                    proc_pid
                );
            }
            entries = guard
                .cached_offsets_with_paths_for_pid(proc_pid)
                .map(|entries| entries.to_vec())
                .unwrap_or_default();
            target_match_count = filter_entries_for_target(&entries, target).len();
        }

        if force_refresh && target.is_none() {
            let purged = purge_offsets_for_runtime_pid_keys(&runtime_pids)?;
            if purged > 0 {
                tracing::debug!(
                    "Sysmon: purged {} stale offset entries before map-change refresh for event pid {} (proc pid {}, runtime keys={:?})",
                    purged,
                    event_pid,
                    proc_pid,
                    runtime_pids
                );
            }
        }

        if !entries.is_empty() && (target.is_none() || target_match_count > 0) {
            let items = offset_items_from_entries(entries.iter());
            match publish_offsets_for_runtime_pid_keys(
                proc_pid,
                event_pid,
                &runtime_pids,
                &items,
                "prefill",
            ) {
                Ok(inserted) => {
                    if inserted == 0 {
                        tracing::warn!(
                            "Sysmon: no offsets inserted for event pid {} (proc pid {}, runtime keys={:?}) (entry count={})",
                            event_pid,
                            proc_pid,
                            runtime_pids,
                            items.len()
                        );
                    } else {
                        tracing::info!(
                            "Sysmon: inserted {} offset entries for event pid {} (proc pid {}, runtime keys={:?})",
                            inserted,
                            event_pid,
                            proc_pid,
                            runtime_pids
                        );
                        insert_allowed_runtime_pid_keys(&runtime_pids);
                        inserted_any = true;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Sysmon: failed to insert offsets for event pid {} (proc pid {}): {}",
                        event_pid,
                        proc_pid,
                        e
                    );
                }
            }
        } else if target.is_some() {
            tracing::debug!(
                "Sysmon: event pid {} (proc pid {}) does not map target module; skip",
                event_pid,
                proc_pid
            );
        }
    }
    Ok(inserted_any)
}

pub(super) fn prefill_full_offsets_for_pid_if_new(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) -> anyhow::Result<bool> {
    let proc_pid = proc_pid_for_event(event_pid);
    let runtime_pids = runtime_pid_keys_for_proc_event(proc_pid, event_pid, []);
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);

    let items = {
        let Ok(mut guard) = mgr.lock() else {
            return Ok(false);
        };
        let prefilled = guard.ensure_prefill_pid(proc_pid)?;
        if prefilled == 0 {
            return Ok(false);
        }
        let Some(entries) = guard.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(false);
        };
        offset_items_from_entries(entries.iter())
    };

    if items.is_empty() {
        return Ok(false);
    }

    match publish_offsets_for_runtime_pid_keys(
        proc_pid,
        event_pid,
        &runtime_pids,
        &items,
        "full prefill",
    ) {
        Ok(inserted) if inserted > 0 => {
            tracing::info!(
                "Sysmon: inserted {} full offset entries for event pid {} (proc pid {}, runtime keys={:?})",
                inserted,
                event_pid,
                proc_pid,
                runtime_pids
            );
            insert_allowed_runtime_pid_keys(&runtime_pids);
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) => {
            tracing::warn!(
                "Sysmon: failed to insert full offsets for event pid {} (proc pid {}): {}",
                event_pid,
                proc_pid,
                e
            );
            Ok(false)
        }
    }
}

pub(super) type PidMapsSignature = Vec<(String, u64, u64, u64, u64, u64, bool)>;

pub(super) fn pid_maps_signature(pid: u32) -> anyhow::Result<PidMapsSignature> {
    let mut signature = read_proc_maps(pid)?
        .into_iter()
        .filter_map(|entry| {
            let path = entry.path()?;
            if should_skip_mapped_module_path(path) {
                return None;
            }
            Some((
                normalize_mapped_module_path(path).to_string(),
                entry.start,
                entry.end,
                entry.offset,
                entry.inode,
                (entry.dev_major << 32) | entry.dev_minor,
                entry.executable(),
            ))
        })
        .collect::<Vec<_>>();
    signature.sort_unstable();
    Ok(signature)
}

pub(super) fn refresh_full_offsets_for_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    proc_pid: u32,
    event_pid: u32,
) -> anyhow::Result<bool> {
    let runtime_pids = runtime_pid_keys_for_proc_event(proc_pid, event_pid, []);
    record_runtime_pid_aliases_for_keys(mgr, proc_pid, &runtime_pids);

    let items = {
        let Ok(mut guard) = mgr.lock() else {
            return Ok(false);
        };
        guard.refresh_prefill_pid(proc_pid)?;
        let Some(entries) = guard.cached_offsets_with_paths_for_pid(proc_pid) else {
            return Ok(false);
        };
        offset_items_from_entries(entries.iter())
    };

    if items.is_empty() {
        return Ok(false);
    }

    let purged = purge_offsets_for_runtime_pid_keys(&runtime_pids)?;
    if purged > 0 {
        tracing::debug!(
            "Sysmon: purged {} stale offset entries before periodic full refresh for proc pid {} (runtime keys={:?})",
            purged,
            proc_pid,
            runtime_pids
        );
    }
    let inserted = publish_offsets_for_runtime_pid_keys(
        proc_pid,
        event_pid,
        &runtime_pids,
        &items,
        "periodic full refresh",
    )?;
    insert_allowed_runtime_pid_keys(&runtime_pids);
    tracing::debug!(
        "Sysmon: periodic full refresh wrote {} offset entries for proc pid {} (event pid {}, runtime keys={:?})",
        inserted,
        proc_pid,
        event_pid,
        runtime_pids
    );
    Ok(inserted > 0)
}

pub(super) fn offset_items_from_entries<'a>(
    entries: impl IntoIterator<Item = &'a PidOffsetsEntry>,
) -> Vec<(u64, crate::pinned_bpf_maps::ProcModuleOffsetsValue)> {
    entries
        .into_iter()
        .map(|e| {
            (
                e.cookie,
                crate::pinned_bpf_maps::ProcModuleOffsetsValue::new(
                    e.offsets.text,
                    e.offsets.rodata,
                    e.offsets.data,
                    e.offsets.bss,
                    e.base,
                    e.size,
                ),
            )
        })
        .collect()
}

pub(super) fn refresh_target_module_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    last_refresh: &mut Instant,
    target_pid_map_signatures: &mut HashMap<u32, PidMapsSignature>,
    tx: &mpsc::SyncSender<SysEvent>,
) {
    use crate::pinned_bpf_maps::{allowed_pid_exists, ProcModuleOffsetsValue};

    let Some(target_path) = target else {
        return;
    };
    let now = Instant::now();
    if now.duration_since(*last_refresh) < MODULE_REFRESH_INTERVAL {
        return;
    }
    *last_refresh = now;

    let module_path = target_path.to_string_lossy().to_string();
    let mut by_pid: HashMap<u32, Vec<(u64, ProcModuleOffsetsValue)>> = HashMap::new();
    let mut target_pids: BTreeSet<u32> = BTreeSet::new();
    if let Ok(mut guard) = mgr.lock() {
        if let Err(e) = guard.refresh_prefill_module(&module_path) {
            tracing::debug!(
                "Sysmon: periodic module refresh failed for {}: {}",
                module_path,
                e
            );
            return;
        }
        for (pid, cookie, off, base, size) in guard.cached_offsets_for_module(&module_path) {
            if is_current_process_pid(pid) {
                continue;
            }
            target_pids.insert(pid);
            by_pid.entry(pid).or_default().push((
                cookie,
                ProcModuleOffsetsValue::new(off.text, off.rodata, off.data, off.bss, base, size),
            ));
        }
    }
    if by_pid.is_empty() {
        return;
    }

    let mut total = 0usize;
    let mut newly_allowed_event_pids = BTreeSet::new();
    for (pid, items) in by_pid {
        let event_pid = resolve_event_pid_for_proc(pid);
        let runtime_pids = runtime_pid_keys_for_proc_event(pid, event_pid, []);
        record_runtime_pid_aliases_for_keys(mgr, pid, &runtime_pids);
        let was_allowed = match allowed_pid_exists(event_pid) {
            Ok(value) => value,
            Err(e) => {
                tracing::debug!(
                    "Sysmon: allowed_pids lookup failed for event pid {} (proc pid {}): {}",
                    event_pid,
                    pid,
                    e
                );
                false
            }
        };
        match publish_offsets_for_runtime_pid_keys(
            pid,
            event_pid,
            &runtime_pids,
            &items,
            "periodic module refresh",
        ) {
            Ok(inserted) => {
                if inserted > 0 {
                    total += inserted;
                    insert_allowed_runtime_pid_keys(&runtime_pids);
                    if !was_allowed {
                        tracing::debug!(
                            "Sysmon: event pid {} became allowed during periodic module refresh",
                            event_pid
                        );
                        newly_allowed_event_pids.insert(event_pid);
                    }
                }
            }
            Err(e) => tracing::debug!(
                "Sysmon: periodic module refresh insert failed for pid {} ({}): {}",
                pid,
                module_path,
                e
            ),
        }
    }
    for pid in &target_pids {
        let event_pid = resolve_event_pid_for_proc(*pid);
        let maps_signature = match pid_maps_signature(*pid) {
            Ok(signature) => signature,
            Err(e) => {
                tracing::debug!(
                    "Sysmon: periodic maps signature failed for proc pid {} (event pid {}): {}",
                    *pid,
                    event_pid,
                    e
                );
                continue;
            }
        };
        if target_pid_map_signatures.get(pid) == Some(&maps_signature) {
            continue;
        }
        target_pid_map_signatures.insert(*pid, maps_signature);

        match refresh_full_offsets_for_pid(mgr, *pid, event_pid) {
            Ok(true) => {
                newly_allowed_event_pids.insert(event_pid);
            }
            Ok(false) => {}
            Err(e) => {
                tracing::debug!(
                    "Sysmon: periodic full offset refresh failed for proc pid {} (event pid {}): {}",
                    *pid,
                    event_pid,
                    e
                );
            }
        }
    }
    target_pid_map_signatures.retain(|pid, _| target_pids.contains(pid));
    for event_pid in newly_allowed_event_pids {
        let ev = SysEvent {
            tgid: event_pid,
            host_tgid: event_pid,
            kind: SysEventKind::MapChange.as_u32(),
        };
        if try_publish_sys_event(tx, ev) {
            tracing::debug!(
                "Sysmon: published synthetic map-change for newly discovered target pid {}",
                event_pid
            );
        }
    }
    if total > 0 {
        tracing::debug!(
            "Sysmon: periodic module refresh inserted {} offset entries for {}",
            total,
            module_path
        );
    }
}

pub(super) fn poll_pending_offsets(
    mgr: &Arc<Mutex<ProcessManager>>,
    pending: &Arc<Mutex<PendingOffsets>>,
    proc_pid_for_event: &impl Fn(u32) -> u32,
) {
    let due = if let Ok(mut guard) = pending.lock() {
        guard.take_due()
    } else {
        Vec::new()
    };

    if due.is_empty() {
        return;
    }

    let mut to_remove: Vec<u32> = Vec::new();
    let mut to_exhaust: Vec<u32> = Vec::new();

    for due in due {
        let event_pid = due.event_pid;
        let target_path = due.target_path;
        let attempts = due.attempts;
        let proc_pid = proc_pid_for_event(event_pid);
        if !pid_alive(proc_pid) {
            tracing::debug!(
                "Sysmon: event pid {} (proc pid {}) exited while waiting for offsets; removing from retry queue",
                event_pid,
                proc_pid
            );
            to_remove.push(event_pid);
            continue;
        }

        if !pid_maps_target_module(proc_pid, &target_path) {
            if attempts >= PENDING_MAX_ATTEMPTS {
                if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                    tracing::debug!(
                        "Sysmon: event pid {} (proc pid {}) still missing module {} after {} retries; waiting for map-change trigger",
                        event_pid,
                        proc_pid,
                        target_path.display(),
                        attempts
                    );
                    to_exhaust.push(event_pid);
                } else {
                    tracing::warn!(
                        "Sysmon: event pid {} (proc pid {}) still missing module {} after {} retries; giving up",
                        event_pid,
                        proc_pid,
                        target_path.display(),
                        attempts
                    );
                    to_remove.push(event_pid);
                }
            }
            continue;
        }

        match prefill_offsets_for_pid(
            mgr,
            event_pid,
            Some(target_path.as_path()),
            proc_pid_for_event,
        ) {
            Ok(true) => {
                tracing::info!(
                    "Sysmon: deferred prefill succeeded for event pid {} (proc pid {}) (module {})",
                    event_pid,
                    proc_pid,
                    target_path.display()
                );
                to_remove.push(event_pid);
            }
            Ok(false) => {
                if attempts >= PENDING_MAX_ATTEMPTS {
                    if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                        tracing::debug!(
                            "Sysmon: deferred prefill produced no entries for event pid {} (proc pid {}) after {} retries; waiting for map-change trigger",
                            event_pid,
                            proc_pid,
                            attempts
                        );
                        to_exhaust.push(event_pid);
                    } else {
                        tracing::warn!(
                            "Sysmon: deferred prefill produced no entries for event pid {} (proc pid {}) after {} retries; giving up",
                            event_pid,
                            proc_pid,
                            attempts
                        );
                        to_remove.push(event_pid);
                    }
                }
            }
            Err(e) => {
                tracing::warn!(
                    "Sysmon: deferred prefill failed for event pid {} (proc pid {}) (attempt {}): {}",
                    event_pid,
                    proc_pid,
                    attempts,
                    e
                );
                if attempts >= PENDING_MAX_ATTEMPTS {
                    if due.kind.keep_for_map_changes_after_retry_exhaustion() {
                        to_exhaust.push(event_pid);
                    } else {
                        to_remove.push(event_pid);
                    }
                }
            }
        }
    }

    if !to_remove.is_empty() || !to_exhaust.is_empty() {
        if let Ok(mut guard) = pending.lock() {
            for pid in to_remove {
                guard.remove(pid);
            }
            for pid in to_exhaust {
                guard.mark_retry_exhausted(pid);
            }
        }
    }
}

pub(super) fn cached_offsets_exist_for_target_pid(
    mgr: &Arc<Mutex<ProcessManager>>,
    target_path: &Path,
    proc_pid: u32,
) -> bool {
    let module_path = target_path.to_string_lossy().to_string();
    mgr.lock()
        .ok()
        .map(|guard| {
            guard.cached_offsets_with_paths_for_pid(proc_pid).is_some()
                || guard
                    .cached_offsets_for_module(&module_path)
                    .iter()
                    .any(|(pid, _, _, _, _)| *pid == proc_pid)
        })
        .unwrap_or(false)
}

pub(super) fn forget_pid_offsets_after_target_unmap(
    mgr: &Arc<Mutex<ProcessManager>>,
    event_pid: u32,
    host_pid: u32,
    proc_pid: u32,
) {
    if let Ok(mut guard) = mgr.lock() {
        guard.forget_pid(proc_pid);
        if proc_pid != event_pid {
            guard.forget_pid(event_pid);
        }
        if host_pid != event_pid && host_pid != proc_pid {
            guard.forget_pid(host_pid);
        }
    }

    let purged = purge_runtime_pid_artifacts(proc_pid, event_pid, host_pid);
    if purged > 0 {
        tracing::info!(
            "Sysmon: target unmapped for event pid {} (host pid {}, proc pid {}); purged {} offset entries",
            event_pid,
            host_pid,
            proc_pid,
            purged
        );
    }
}

pub(super) fn poll_pending_map_refreshes(
    mgr: &Arc<Mutex<ProcessManager>>,
    target: Option<&Path>,
    pending_map_refreshes: &Arc<Mutex<PendingMapRefreshes>>,
    pending: &Arc<Mutex<PendingOffsets>>,
    tx: &mpsc::SyncSender<SysEvent>,
) {
    let due = if let Ok(mut guard) = pending_map_refreshes.lock() {
        guard.take_due()
    } else {
        Vec::new()
    };

    if due.is_empty() {
        return;
    }

    for event in due {
        let event_pid = event.event_pid;
        let host_pid = event.host_pid;
        let proc_pid = target
            .map(|target_path| {
                canonicalize_cached_target_proc_pid(mgr, target_path, event.proc_pid)
            })
            .unwrap_or(event.proc_pid);
        if !pid_alive(proc_pid) {
            tracing::trace!(
                "Sysmon: event pid {} (proc pid {}) exited before map refresh",
                event_pid,
                proc_pid
            );
            continue;
        }

        if let Some(target_path) = target {
            if !pid_maps_target_module(proc_pid, target_path) {
                if cached_offsets_exist_for_target_pid(mgr, target_path, proc_pid) {
                    forget_pid_offsets_after_target_unmap(mgr, event_pid, host_pid, proc_pid);
                    let ev = SysEvent {
                        tgid: event_pid,
                        host_tgid: host_pid,
                        kind: SysEventKind::MapChange.as_u32(),
                    };
                    try_publish_sys_event(tx, ev);
                }
                tracing::trace!(
                    "Sysmon: event pid {} (proc pid {}) map-change does not include target {}; skip",
                    event_pid,
                    proc_pid,
                    target_path.display()
                );
                continue;
            }
        }

        match refresh_offsets_for_known_proc_pid(mgr, event_pid, host_pid, proc_pid) {
            Ok(true) => {
                tracing::debug!(
                    "Sysmon: refreshed offsets after map-change for event pid {} (host pid {}, proc pid {})",
                    event_pid,
                    host_pid,
                    proc_pid
                );
                if let Ok(mut guard) = pending.lock() {
                    guard.remove(event_pid);
                    if host_pid != event_pid {
                        guard.remove(host_pid);
                    }
                }
                let ev = SysEvent {
                    tgid: event_pid,
                    host_tgid: host_pid,
                    kind: SysEventKind::MapChange.as_u32(),
                };
                try_publish_sys_event(tx, ev);
            }
            Ok(false) => tracing::trace!(
                "Sysmon: map-change refresh inserted no offsets for event pid {} (proc pid {})",
                event_pid,
                proc_pid
            ),
            Err(e) => tracing::debug!(
                "Sysmon: map-change refresh failed for event pid {} (proc pid {}): {}",
                event_pid,
                proc_pid,
                e
            ),
        }
    }
}

pub(super) fn get_comm_from_proc(pid: u32) -> Option<String> {
    use std::io::Read;
    let path = format!("/proc/{pid}/comm");
    let mut f = std::fs::File::open(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    if s.ends_with('\n') {
        s.pop();
        if s.ends_with('\r') {
            s.pop();
        }
    }
    // Kernel task->comm is at most 15 bytes; /proc returns without NUL. We compare as-is.
    Some(s)
}

pub(super) fn truncate_basename_to_comm(path: &Path) -> Vec<u8> {
    use std::ffi::OsStr;
    let mut buf = Vec::with_capacity(16);
    if let Some(name) = path.file_name().and_then(OsStr::to_str) {
        let bytes = name.as_bytes();
        let n = core::cmp::min(bytes.len(), 15);
        buf.extend_from_slice(&bytes[..n]);
    }
    buf
}

pub(super) fn pid_maps_target_module(pid: u32, target: &Path) -> bool {
    let target = ModuleIdentity::from_path(target);
    let mut matched = false;

    if visit_proc_maps(pid, |entry| {
        if target.matches(&entry) {
            matched = true;
            return ControlFlow::Break(());
        }
        ControlFlow::Continue(())
    })
    .is_err()
    {
        return false;
    }

    matched
}

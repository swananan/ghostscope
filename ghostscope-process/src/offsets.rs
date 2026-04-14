use crate::module_probe::ModuleProbe;
use crate::proc_maps::{
    normalize_mapped_module_path, read_proc_maps, should_skip_mapped_module_path, visit_proc_maps,
    ModuleIdentity, OwnedProcMapEntry,
};
use anyhow::Result;
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::ops::ControlFlow;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
// no extra imports

/// Per-module section offsets (runtime bias) computed from /proc/PID/maps
#[derive(Debug, Clone, Copy, Default)]
pub struct SectionOffsets {
    pub text: u64,
    pub rodata: u64,
    pub data: u64,
    pub bss: u64,
}

#[derive(Debug, Clone)]
pub struct PidOffsetsEntry {
    pub module_path: String,
    pub cookie: u64,
    pub offsets: SectionOffsets,
    pub base: u64,
    pub size: u64,
}

/// ProcessManager for precomputing and caching ASLR section offsets.
#[derive(Debug)]
pub struct ProcessManager {
    module_cache: HashMap<String, Vec<CachedEntry>>,
    prefilled_modules: HashSet<String>,
    pid_cache: HashMap<u32, Vec<PidOffsetsEntry>>,
    prefilled_pids: HashSet<u32>,
}

impl Default for ProcessManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
struct CachedEntry {
    pid: u32,
    cookie: u64,
    offsets: SectionOffsets,
}

#[derive(Debug, Clone, Default)]
struct ModuleMapSummary {
    candidates: Vec<(u64, u64)>,
    min_start: Option<u64>,
    max_end: Option<u64>,
}

impl ModuleMapSummary {
    fn observe(&mut self, entry: &OwnedProcMapEntry) {
        self.min_start = Some(self.min_start.map_or(entry.start, |v| v.min(entry.start)));
        self.max_end = Some(self.max_end.map_or(entry.end, |v| v.max(entry.end)));
        self.candidates.push((entry.offset, entry.start));
    }

    fn base(&self) -> u64 {
        self.min_start.unwrap_or(0)
    }

    fn size(&self) -> u64 {
        let base = self.base();
        self.max_end.unwrap_or(base).saturating_sub(base)
    }

    fn merge(&mut self, other: &Self) {
        self.candidates.extend(other.candidates.iter().copied());
        if let Some(start) = other.min_start {
            self.min_start = Some(self.min_start.map_or(start, |v| v.min(start)));
        }
        if let Some(end) = other.max_end {
            self.max_end = Some(self.max_end.map_or(end, |v| v.max(end)));
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ModuleMapIdentityKey {
    dev_major: u64,
    dev_minor: u64,
    inode: u64,
}

impl ModuleMapIdentityKey {
    fn from_entry(entry: &OwnedProcMapEntry) -> Self {
        Self {
            dev_major: entry.dev_major,
            dev_minor: entry.dev_minor,
            inode: entry.inode,
        }
    }

    fn from_metadata(meta: &fs::Metadata) -> Self {
        let dev = meta.dev() as libc::dev_t;
        Self {
            dev_major: libc::major(dev) as u64,
            dev_minor: libc::minor(dev) as u64,
            inode: meta.ino(),
        }
    }
}

#[derive(Debug, Clone, Default)]
struct ModulePathSummaries {
    by_identity: BTreeMap<ModuleMapIdentityKey, ModuleMapSummary>,
}

impl ModulePathSummaries {
    fn observe(&mut self, entry: &OwnedProcMapEntry) {
        self.by_identity
            .entry(ModuleMapIdentityKey::from_entry(entry))
            .or_default()
            .observe(entry);
    }

    fn summary_for_inode(&self, inode: u64) -> Option<ModuleMapSummary> {
        let mut matches = self
            .by_identity
            .iter()
            .filter(|(key, _)| key.inode == inode)
            .map(|(_, summary)| summary);
        let mut merged = matches.next()?.clone();
        for summary in matches {
            merged.merge(summary);
        }
        Some(merged)
    }

    fn summary_for_path(&self, module_path: &str) -> Option<ModuleMapSummary> {
        match fs::metadata(module_path) {
            Ok(meta) => self
                .by_identity
                .get(&ModuleMapIdentityKey::from_metadata(&meta))
                .cloned()
                // overlayfs compatibility: within the same normalized path bucket, the mapped
                // file can keep the same inode while reporting a different device number.
                .or_else(|| self.summary_for_inode(meta.ino())),
            Err(_) => {
                let mut merged = ModuleMapSummary::default();
                for summary in self.by_identity.values() {
                    merged.merge(summary);
                }
                (!merged.candidates.is_empty()).then_some(merged)
            }
        }
    }
}

impl ProcessManager {
    pub fn new() -> Self {
        Self {
            module_cache: HashMap::new(),
            prefilled_modules: HashSet::new(),
            pid_cache: HashMap::new(),
            prefilled_pids: HashSet::new(),
        }
    }

    pub fn ensure_prefill_module(&mut self, module_path: &str) -> Result<usize> {
        if self.prefilled_modules.contains(module_path) {
            return Ok(0);
        }
        let mut pids: BTreeSet<u32> = BTreeSet::new();

        // 1) Fast path for executable targets: compare /proc/*/exe dev+ino
        let (t_dev, t_ino) = if let Ok(meta) = fs::metadata(module_path) {
            (Some(meta.dev()), Some(meta.ino()))
        } else {
            (None, None)
        };
        if let (Some(dev), Some(ino)) = (t_dev, t_ino) {
            if let Ok(dir) = fs::read_dir("/proc") {
                for ent in dir.flatten() {
                    let fname = ent.file_name();
                    if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                        let exe_path = format!("/proc/{pid}/exe");
                        if is_same_executable_as_current(pid) {
                            continue; // never treat ghostscope itself as a target process
                        }
                        if let Ok(st) = fs::metadata(&exe_path) {
                            if st.dev() == dev && st.ino() == ino {
                                pids.insert(pid);
                            }
                        }
                    }
                }
            }
        }

        // 2) Shared libraries/modules: scan /proc/<pid>/maps for executable matches.
        let target = ModuleIdentity::from_path(Path::new(module_path));
        if let Ok(dir) = fs::read_dir("/proc") {
            for ent in dir.flatten() {
                let fname = ent.file_name();
                if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                    if is_same_executable_as_current(pid) {
                        continue; // skip our own processes even if they mmap the target for reading
                    }
                    let mut hit = false;
                    if visit_proc_maps(pid, |entry| {
                        if !entry.executable() {
                            return ControlFlow::Continue(());
                        }
                        if target.matches(&entry) {
                            hit = true;
                            return ControlFlow::Break(());
                        }
                        ControlFlow::Continue(())
                    })
                    .is_ok()
                        && hit
                    {
                        pids.insert(pid);
                    }
                }
            }
        }
        let mut cached: Vec<CachedEntry> = Vec::new();
        let mut new_count = 0usize;
        // Intentionally keep PID list silent to avoid noisy logs in normal runs
        for pid in pids {
            match self.compute_section_offsets_for_process_with_retry(
                pid,
                module_path,
                3,
                std::time::Duration::from_millis(75),
            ) {
                Ok((cookie, offsets, _base, _size)) => {
                    cached.push(CachedEntry {
                        pid,
                        cookie,
                        offsets,
                    });
                    new_count += 1;
                }
                Err(e) => tracing::debug!(
                    "ProcessManager: skip pid {} for module {} (offsets failed: {})",
                    pid,
                    module_path,
                    e
                ),
            }
        }
        self.module_cache.insert(module_path.to_string(), cached);
        self.prefilled_modules.insert(module_path.to_string());
        Ok(new_count)
    }

    pub fn cached_offsets_for_module(&self, module_path: &str) -> Vec<(u32, u64, SectionOffsets)> {
        self.module_cache
            .get(module_path)
            .map(|v| v.iter().map(|e| (e.pid, e.cookie, e.offsets)).collect())
            .unwrap_or_default()
    }

    /// Force-refresh per-module cache (used when late-start targets appear after initial prefill).
    pub fn refresh_prefill_module(&mut self, module_path: &str) -> Result<usize> {
        self.prefilled_modules.remove(module_path);
        self.ensure_prefill_module(module_path)
    }

    pub fn ensure_prefill_pid(&mut self, pid: u32) -> Result<usize> {
        if self.prefilled_pids.contains(&pid) {
            return Ok(0);
        }
        let maps = read_proc_maps(pid)?;
        let mut module_summaries: BTreeMap<String, ModulePathSummaries> = BTreeMap::new();
        for entry in &maps {
            let Some(path) = entry.path() else {
                continue;
            };
            if should_skip_mapped_module_path(path) {
                continue;
            }
            let path_trim = normalize_mapped_module_path(path);
            module_summaries
                .entry(path_trim.to_string())
                .or_default()
                .observe(entry);
        }
        let mut list: Vec<PidOffsetsEntry> = Vec::new();
        for (module_path, summaries) in module_summaries {
            let Some(summary) = summaries.summary_for_path(&module_path) else {
                tracing::debug!(
                    "ProcessManager: skip module {} for pid {}: no maps matched current file identity",
                    module_path,
                    pid
                );
                continue;
            };
            match self.compute_section_offsets_from_candidates(
                pid,
                &module_path,
                &summary.candidates,
                summary.base(),
                summary.size(),
            ) {
                Ok((cookie, off, base, size)) => list.push(PidOffsetsEntry {
                    module_path,
                    cookie,
                    offsets: off,
                    base,
                    size,
                }),
                Err(e) => {
                    tracing::debug!(
                        "ProcessManager: skip module {} for pid {}: {}",
                        module_path,
                        pid,
                        e
                    )
                }
            }
        }
        self.pid_cache.insert(pid, list);
        self.prefilled_pids.insert(pid);
        Ok(self.pid_cache.get(&pid).map(|v| v.len()).unwrap_or(0))
    }

    /// Force-refresh per-PID cache (used when exec-time prefill raced with module mapping).
    pub fn refresh_prefill_pid(&mut self, pid: u32) -> Result<usize> {
        self.prefilled_pids.remove(&pid);
        self.pid_cache.remove(&pid);
        self.ensure_prefill_pid(pid)
    }

    fn compute_section_offsets_for_process(
        &self,
        pid: u32,
        module_path: &str,
    ) -> Result<(u64, SectionOffsets, u64, u64)> {
        let module_path = normalize_mapped_module_path(module_path);
        let mut candidates: Vec<(u64, u64)> = Vec::new();
        let mut min_start: Option<u64> = None;
        let mut max_end: Option<u64> = None;
        let target = ModuleIdentity::from_path(Path::new(module_path));
        visit_proc_maps(pid, |entry| {
            if !target.matches(&entry) {
                return ControlFlow::Continue(());
            }
            min_start = Some(min_start.map_or(entry.start, |v| v.min(entry.start)));
            max_end = Some(max_end.map_or(entry.end, |v| v.max(entry.end)));
            candidates.push((entry.offset, entry.start));
            ControlFlow::Continue(())
        })?;
        let base = min_start.unwrap_or(0);
        let size = max_end.unwrap_or(base).saturating_sub(base);
        self.compute_section_offsets_from_candidates(pid, module_path, &candidates, base, size)
    }

    fn compute_section_offsets_from_candidates(
        &self,
        pid: u32,
        module_path: &str,
        candidates: &[(u64, u64)],
        base: u64,
        size: u64,
    ) -> Result<(u64, SectionOffsets, u64, u64)> {
        let probe = ModuleProbe::open(module_path)?;
        let obj = probe.object()?;
        let page_mask: u64 = !0xfffu64;
        let mut seg_bias: Vec<(u64, u64, u64)> = Vec::new();
        for seg in obj.segments() {
            let (file_off, _sz) = seg.file_range();
            let vaddr = seg.address();
            let key = file_off & page_mask;
            if let Some((_, start)) = candidates
                .iter()
                .find(|(fo, _)| (*fo & page_mask) == key)
                .copied()
            {
                let bias = start.saturating_sub(vaddr);
                seg_bias.push((key, vaddr, bias));
            }
        }
        let find_bias_for = |addr: u64| -> Option<u64> {
            for seg in obj.segments() {
                let vaddr = seg.address();
                let vsize = seg.size();
                if vsize == 0 {
                    continue;
                }
                if addr >= vaddr && addr < vaddr + vsize {
                    let (file_off, _sz) = seg.file_range();
                    let key = file_off & page_mask;
                    if let Some((_, _, b)) = seg_bias.iter().find(|(k, _, _)| *k == key) {
                        return Some(*b);
                    }
                }
            }
            None
        };
        let mut text_addr: Option<u64> = None;
        let mut rodata_addr: Option<u64> = None;
        let mut data_addr: Option<u64> = None;
        let mut bss_addr: Option<u64> = None;
        for sect in obj.sections() {
            if let Ok(name) = sect.name() {
                let addr = sect.address();
                if text_addr.is_none() && (name == ".text" || name.starts_with(".text")) {
                    text_addr = Some(addr);
                } else if rodata_addr.is_none()
                    && (name == ".rodata" || name.starts_with(".rodata"))
                {
                    rodata_addr = Some(addr);
                } else if data_addr.is_none() && (name == ".data" || name.starts_with(".data")) {
                    data_addr = Some(addr);
                } else if bss_addr.is_none() && (name == ".bss" || name.starts_with(".bss")) {
                    bss_addr = Some(addr);
                }
            }
        }
        let mut offsets = SectionOffsets::default();
        // Each DW_OP_addr we encounter is an absolute link-time virtual address (e.g. 0x5798c for
        // G_COUNTER). To rebase it we only need the ASLR bias `module_base`, not per-section
        // runtime starts. Derive that bias from whichever segment we could match, then store it for
        // all four slots so the eBPF helper can simply do `link_addr + bias`.
        let module_base = text_addr
            .and_then(find_bias_for)
            .or_else(|| rodata_addr.and_then(find_bias_for))
            .or_else(|| data_addr.and_then(find_bias_for))
            .or_else(|| bss_addr.and_then(find_bias_for))
            .unwrap_or(0);

        offsets.text = module_base;
        offsets.rodata = module_base;
        offsets.data = module_base;
        offsets.bss = module_base;
        let cookie = probe.cookie_for_object(&obj);
        if offsets.text == 0 && offsets.rodata == 0 && offsets.data == 0 && offsets.bss == 0 {
            if seg_bias.is_empty() {
                // No segment matches at all: genuine failure to map offsets
                tracing::error!(
                    "Offsets all zero for pid={} module='{}' (cookie=0x{:016x}); no segment matches, maps matching failed (dev:inode/path)",
                    pid, module_path, cookie
                );
                return Err(anyhow::anyhow!(
                    "computed zero offsets (no segment matches)"
                ));
            } else {
                // Segments matched but all biases are zero — likely ET_EXEC (Non-PIE) loaded at linked addresses.
                // This is valid: no ASLR rebase is needed.
                tracing::debug!(
                    "Offsets zero with valid segment matches (treat as Non-PIE): pid={} module='{}' cookie=0x{:016x}",
                    pid, module_path, cookie
                );
            }
        }
        let runtime_text = text_addr
            .map(|t| module_base.saturating_add(t))
            .unwrap_or(0);
        let runtime_ro = rodata_addr
            .map(|r| module_base.saturating_add(r))
            .unwrap_or(0);
        let runtime_data = data_addr
            .map(|d| module_base.saturating_add(d))
            .unwrap_or(0);
        let runtime_bss = bss_addr.map(|b| module_base.saturating_add(b)).unwrap_or(0);

        tracing::debug!(
            "computed offsets: pid={} module='{}' cookie=0x{:016x} base=0x{:x} size=0x{:x} module_bias=0x{:x} text=0x{:x} rodata=0x{:x} data=0x{:x} bss=0x{:x}",
            pid,
            module_path,
            cookie,
            base,
            size,
            offsets.text,
            runtime_text,
            runtime_ro,
            runtime_data,
            runtime_bss
        );
        Ok((cookie, offsets, base, size))
    }

    fn compute_section_offsets_for_process_with_retry(
        &self,
        pid: u32,
        module_path: &str,
        attempts: usize,
        backoff: std::time::Duration,
    ) -> Result<(u64, SectionOffsets, u64, u64)> {
        let mut last_err: Option<anyhow::Error> = None;
        for i in 0..attempts {
            match self.compute_section_offsets_for_process(pid, module_path) {
                Ok(v) => return Ok(v),
                Err(e) => {
                    last_err = Some(e);
                    if i + 1 < attempts {
                        std::thread::sleep(backoff);
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("offsets compute failed")))
    }

    pub fn cached_offsets_pairs_for_pid(&self, pid: u32) -> Option<Vec<(u64, SectionOffsets)>> {
        self.pid_cache
            .get(&pid)
            .map(|v| v.iter().map(|e| (e.cookie, e.offsets)).collect())
    }

    pub fn cached_offsets_with_paths_for_pid(&self, pid: u32) -> Option<&[PidOffsetsEntry]> {
        self.pid_cache.get(&pid).map(|v| v.as_slice())
    }

    /// Drop per-PID caches when a process exits so PID reuse can prefill again.
    pub fn forget_pid(&mut self, pid: u32) {
        self.prefilled_pids.remove(&pid);
        self.pid_cache.remove(&pid);
        for entries in self.module_cache.values_mut() {
            entries.retain(|entry| entry.pid != pid);
        }
    }
}

fn is_same_executable_as_current(pid: u32) -> bool {
    // Strongest signal: dev+ino equality on /proc/*/exe
    let self_meta = fs::metadata("/proc/self/exe");
    let pid_meta = fs::metadata(format!("/proc/{pid}/exe"));
    if let (Ok(sm), Ok(pm)) = (self_meta, pid_meta) {
        if sm.dev() == pm.dev() && sm.ino() == pm.ino() {
            return true;
        }
    }

    // Fallback: compare canonicalized exe symlink targets
    let self_path = fs::read_link("/proc/self/exe")
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());
    let pid_path = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|p| fs::canonicalize(p).ok());
    if let (Some(sp), Some(pp)) = (self_path, pid_path) {
        if sp == pp {
            return true;
        }
    }

    // Last resort: process name check via /proc/<pid>/comm (best-effort)
    if let Ok(name) = fs::read_to_string(format!("/proc/{pid}/comm")) {
        let n = name.trim();
        if n.eq("ghostscope") {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proc_maps::parse_maps_line;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn dev_pair_differs_from(meta: &std::fs::Metadata, salt: u64) -> (u64, u64) {
        let dev = meta.dev() as libc::dev_t;
        let actual_major = libc::major(dev) as u64;
        let actual_minor = libc::minor(dev) as u64;
        let major = actual_major ^ (0x40 + salt);
        let minor = actual_minor ^ (0x80 + salt);
        if major == actual_major && minor == actual_minor {
            (actual_major + 1, actual_minor)
        } else {
            (major, minor)
        }
    }

    #[test]
    fn forget_pid_clears_pid_caches_and_module_entries() {
        let mut mgr = ProcessManager::new();
        mgr.prefilled_pids.insert(42);
        mgr.pid_cache.insert(
            42,
            vec![PidOffsetsEntry {
                module_path: "/tmp/a.so".to_string(),
                cookie: 1,
                offsets: SectionOffsets::default(),
                base: 0,
                size: 0,
            }],
        );
        mgr.module_cache.insert(
            "/tmp/a.so".to_string(),
            vec![
                CachedEntry {
                    pid: 42,
                    cookie: 1,
                    offsets: SectionOffsets::default(),
                },
                CachedEntry {
                    pid: 7,
                    cookie: 2,
                    offsets: SectionOffsets::default(),
                },
            ],
        );

        mgr.forget_pid(42);

        assert!(!mgr.prefilled_pids.contains(&42));
        assert!(!mgr.pid_cache.contains_key(&42));
        let module_entries = mgr.module_cache.get("/tmp/a.so").unwrap();
        assert_eq!(module_entries.len(), 1);
        assert_eq!(module_entries[0].pid, 7);
    }

    #[test]
    fn path_summaries_prefer_current_file_identity_when_metadata_exists() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghostscope-offsets-{suffix}.so"));
        std::fs::write(&path, b"current").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let dev = meta.dev() as libc::dev_t;
        let dev_major = libc::major(dev) as u64;
        let dev_minor = libc::minor(dev) as u64;
        let inode = meta.ino();
        let path_str = path.to_string_lossy().to_string();

        let current_entry: OwnedProcMapEntry = parse_maps_line(&format!(
            "2000-3000 r-xp 00001000 {dev_major:02x}:{dev_minor:02x} {inode} {path_str}"
        ))
        .unwrap()
        .into();
        let stale_entry: OwnedProcMapEntry = parse_maps_line(&format!(
            "1000-2000 r-xp 00000000 {dev_major:02x}:{dev_minor:02x} {} {path_str}",
            inode + 1
        ))
        .unwrap()
        .into();

        let mut summaries = ModulePathSummaries::default();
        summaries.observe(&stale_entry);
        summaries.observe(&current_entry);

        let summary = summaries.summary_for_path(&path_str).unwrap();
        assert_eq!(summary.candidates, vec![(0x1000, 0x2000)]);
        assert_eq!(summary.base(), 0x2000);
        assert_eq!(summary.size(), 0x1000);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn path_summaries_merge_groups_when_metadata_is_unavailable() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!("/tmp/ghostscope-missing-{suffix}.so");

        let first: OwnedProcMapEntry =
            parse_maps_line(&format!("1000-2000 r-xp 00000000 08:01 10 {path}"))
                .unwrap()
                .into();
        let second: OwnedProcMapEntry =
            parse_maps_line(&format!("3000-5000 r-xp 00002000 08:01 11 {path}"))
                .unwrap()
                .into();

        let mut summaries = ModulePathSummaries::default();
        summaries.observe(&first);
        summaries.observe(&second);

        let summary = summaries.summary_for_path(&path).unwrap();
        assert_eq!(summary.candidates, vec![(0, 0x1000), (0x2000, 0x3000)]);
        assert_eq!(summary.base(), 0x1000);
        assert_eq!(summary.size(), 0x4000);
    }

    #[test]
    fn path_summaries_fallback_to_inode_when_device_differs() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghostscope-offsets-overlayfs-{suffix}.so"));
        std::fs::write(&path, b"current").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let inode = meta.ino();
        let path_str = path.to_string_lossy().to_string();
        let (dev_major, dev_minor) = dev_pair_differs_from(&meta, 1);

        let overlay_entry: OwnedProcMapEntry = parse_maps_line(&format!(
            "2000-3000 r-xp 00001000 {dev_major:02x}:{dev_minor:02x} {inode} {path_str}"
        ))
        .unwrap()
        .into();

        let mut summaries = ModulePathSummaries::default();
        summaries.observe(&overlay_entry);

        let summary = summaries.summary_for_path(&path_str).unwrap();
        assert_eq!(summary.candidates, vec![(0x1000, 0x2000)]);
        assert_eq!(summary.base(), 0x2000);
        assert_eq!(summary.size(), 0x1000);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn path_summaries_merge_same_inode_groups_within_path_bucket() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghostscope-offsets-overlayfs-{suffix}.so"));
        std::fs::write(&path, b"current").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let inode = meta.ino();
        let path_str = path.to_string_lossy().to_string();
        let (lower_dev_major, lower_dev_minor) = dev_pair_differs_from(&meta, 2);
        let (upper_dev_major, upper_dev_minor) = dev_pair_differs_from(&meta, 3);

        let lower_entry: OwnedProcMapEntry = parse_maps_line(&format!(
            "1000-2000 r-xp 00000000 {lower_dev_major:02x}:{lower_dev_minor:02x} {inode} {path_str}"
        ))
        .unwrap()
        .into();
        let upper_entry: OwnedProcMapEntry = parse_maps_line(&format!(
            "3000-5000 r-xp 00002000 {upper_dev_major:02x}:{upper_dev_minor:02x} {inode} {path_str}"
        ))
        .unwrap()
        .into();

        let mut summaries = ModulePathSummaries::default();
        summaries.observe(&lower_entry);
        summaries.observe(&upper_entry);

        let summary = summaries.summary_for_path(&path_str).unwrap();
        assert_eq!(summary.candidates, vec![(0, 0x1000), (0x2000, 0x3000)]);
        assert_eq!(summary.base(), 0x1000);
        assert_eq!(summary.size(), 0x4000);

        let _ = std::fs::remove_file(path);
    }
}

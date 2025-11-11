use anyhow::Result;
use object::{Object, ObjectSection, ObjectSegment};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
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

        // 2) Shared libraries/modules: scan /proc/<pid>/maps and match dev:inode when metadata available
        // Convert target st_dev to major/minor for comparing with maps 'dev' field
        let (t_maj, t_min) = if let Some(dev) = t_dev {
            let d = dev as libc::dev_t;
            let maj = libc::major(d) as u64;
            let min = libc::minor(d) as u64;
            (Some(maj), Some(min))
        } else {
            (None, None)
        };
        if let (Some(tmaj), Some(tmin), Some(tino)) = (t_maj, t_min, t_ino) {
            if let Ok(dir) = fs::read_dir("/proc") {
                for ent in dir.flatten() {
                    let fname = ent.file_name();
                    if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                        if is_same_executable_as_current(pid) {
                            continue; // skip our own processes even if they mmap the target for reading
                        }
                        let maps_path = format!("/proc/{pid}/maps");
                        if let Ok(content) = fs::read_to_string(&maps_path) {
                            let mut hit = false;
                            for line in content.lines() {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() < 6 {
                                    continue;
                                }
                                // Require execute permission on the mapping to avoid read-only mmaps
                                // perms format example: r-xp, r--p, rw-p
                                let perms = parts[1];
                                if !perms.contains('x') {
                                    continue;
                                }
                                // parts[3] = dev (maj:min), hex; parts[4] = inode (dec)
                                let dev_str = parts[3];
                                let inode_str = parts[4];
                                if let Some((maj_s, min_s)) = dev_str.split_once(':') {
                                    if let (Ok(maj), Ok(min), Ok(ino)) = (
                                        u64::from_str_radix(maj_s, 16),
                                        u64::from_str_radix(min_s, 16),
                                        inode_str.parse::<u64>(),
                                    ) {
                                        if maj == tmaj && min == tmin && ino == tino {
                                            hit = true;
                                            break; // early stop per PID
                                        }
                                    }
                                }
                            }
                            if hit {
                                pids.insert(pid);
                            }
                        }
                    }
                }
            }
        } else {
            // 3) Fallback: when metadata is unavailable (file removed/replaced),
            // scan /proc/<pid>/maps and match pathname string (trim " (deleted)")
            if let Ok(dir) = fs::read_dir("/proc") {
                for ent in dir.flatten() {
                    let fname = ent.file_name();
                    if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                        if is_same_executable_as_current(pid) {
                            continue;
                        }
                        let maps_path = format!("/proc/{pid}/maps");
                        if let Ok(content) = fs::read_to_string(&maps_path) {
                            let mut hit = false;
                            for line in content.lines() {
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                if parts.len() < 6 {
                                    continue;
                                }
                                let perms = parts[1];
                                if !perms.contains('x') {
                                    continue;
                                }
                                let path = parts[5];
                                if path.starts_with('[') {
                                    continue;
                                }
                                let path_trim = if let Some(idx) = path.find(" (deleted)") {
                                    &path[..idx]
                                } else {
                                    path
                                };
                                if path_trim == module_path {
                                    hit = true;
                                    break; // early stop per PID
                                }
                            }
                            if hit {
                                pids.insert(pid);
                            }
                        }
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

    pub fn ensure_prefill_pid(&mut self, pid: u32) -> Result<usize> {
        if self.prefilled_pids.contains(&pid) {
            return Ok(0);
        }
        let maps_path = format!("/proc/{pid}/maps");
        let content = fs::read_to_string(&maps_path)?;
        let mut modules: BTreeSet<String> = BTreeSet::new();
        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            let path = parts[5];
            if path.starts_with('[') {
                continue;
            }
            let path_trim = if let Some(idx) = path.find(" (deleted)") {
                &path[..idx]
            } else {
                path
            };
            modules.insert(path_trim.to_string());
        }
        let mut list: Vec<PidOffsetsEntry> = Vec::new();
        for m in modules {
            match self.compute_section_offsets_for_process(pid, &m) {
                Ok((cookie, off, base, size)) => list.push(PidOffsetsEntry {
                    module_path: m,
                    cookie,
                    offsets: off,
                    base,
                    size,
                }),
                Err(e) => {
                    tracing::debug!("ProcessManager: skip module {} for pid {}: {}", m, pid, e)
                }
            }
        }
        self.pid_cache.insert(pid, list);
        self.prefilled_pids.insert(pid);
        Ok(self.pid_cache.get(&pid).map(|v| v.len()).unwrap_or(0))
    }

    fn compute_section_offsets_for_process(
        &self,
        pid: u32,
        module_path: &str,
    ) -> Result<(u64, SectionOffsets, u64, u64)> {
        let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
        let mut candidates: Vec<(u64, u64)> = Vec::new();
        let mut min_start: Option<u64> = None;
        let mut max_end: Option<u64> = None;

        // Prefer dev:inode matching; fallback to normalized path compare
        let (t_dev, t_ino) = fs::metadata(module_path)
            .map(|m| (Some(m.dev()), Some(m.ino())))
            .unwrap_or((None, None));
        let (tmaj, tmin) = if let Some(dev) = t_dev {
            let d = dev as libc::dev_t;
            (Some(libc::major(d) as u64), Some(libc::minor(d) as u64))
        } else {
            (None, None)
        };
        let norm_target = module_path.replace("/./", "/");

        for line in maps.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 6 {
                continue;
            }
            if parts[5].starts_with('[') {
                continue;
            }
            let mut matched = false;
            if let (Some(maj), Some(min), Some(ino)) = (tmaj, tmin, t_ino) {
                if let Some((maj_s, min_s)) = parts[3].split_once(':') {
                    if let (Ok(dm), Ok(dn), Ok(inode)) = (
                        u64::from_str_radix(maj_s, 16),
                        u64::from_str_radix(min_s, 16),
                        parts[4].parse::<u64>(),
                    ) {
                        matched = dm == maj && dn == min && inode == ino;
                    }
                }
            } else {
                let p = parts[5];
                let path_trim = if let Some(idx) = p.find(" (deleted)") {
                    &p[..idx]
                } else {
                    p
                };
                matched = path_trim == norm_target;
            }
            if !matched {
                continue;
            }
            let addrs: Vec<&str> = parts[0].split('-').collect();
            if addrs.len() != 2 {
                continue;
            }
            let start = u64::from_str_radix(addrs[0], 16).unwrap_or(0);
            let end = u64::from_str_radix(addrs[1], 16).unwrap_or(start);
            min_start = Some(min_start.map_or(start, |v| v.min(start)));
            max_end = Some(max_end.map_or(end, |v| v.max(end)));
            let file_off = u64::from_str_radix(parts[2], 16).unwrap_or(0);
            candidates.push((file_off, start));
        }
        let data = fs::read(module_path)?;
        let obj = object::File::parse(&data[..])?;
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
        let cookie = crate::cookie::from_path(module_path);
        let base = min_start.unwrap_or(0);
        let size = max_end.unwrap_or(base).saturating_sub(base);
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

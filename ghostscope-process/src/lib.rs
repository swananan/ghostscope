pub mod offsets {
    use anyhow::Result;
    use object::{Object, ObjectSection, ObjectSegment};
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::fs;
    use std::os::unix::fs::MetadataExt;

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
            if let Ok(meta) = fs::metadata(module_path) {
                let dev = meta.dev();
                let ino = meta.ino();
                if let Ok(dir) = fs::read_dir("/proc") {
                    for ent in dir.flatten() {
                        let fname = ent.file_name();
                        if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                            let exe_path = format!("/proc/{pid}/exe");
                            if let Ok(st) = fs::metadata(&exe_path) {
                                if st.dev() == dev && st.ino() == ino {
                                    pids.insert(pid);
                                }
                            }
                        }
                    }
                }
            }
            if let Ok(dir) = fs::read_dir("/proc") {
                for ent in dir.flatten() {
                    let fname = ent.file_name();
                    if let Ok(pid) = fname.to_string_lossy().parse::<u32>() {
                        let maps_path = format!("/proc/{pid}/maps");
                        if let Ok(content) = fs::read_to_string(&maps_path) {
                            let mut hit = false;
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
                                if path_trim == module_path {
                                    hit = true;
                                    break;
                                }
                            }
                            if hit {
                                pids.insert(pid);
                            }
                        }
                    }
                }
            }
            let mut cached: Vec<CachedEntry> = Vec::new();
            let mut new_count = 0usize;
            for pid in pids {
                match self.compute_cookie_and_offsets_for_pid_module(pid, module_path) {
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

        pub fn cached_offsets_for_module(
            &self,
            module_path: &str,
        ) -> Vec<(u32, u64, SectionOffsets)> {
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
                match self.compute_cookie_and_offsets_for_pid_module(pid, &m) {
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

        fn compute_cookie_and_offsets_for_pid_module(
            &self,
            pid: u32,
            module_path: &str,
        ) -> Result<(u64, SectionOffsets, u64, u64)> {
            let maps = fs::read_to_string(format!("/proc/{pid}/maps"))?;
            let mut candidates: Vec<(u64, u64)> = Vec::new();
            let mut min_start: Option<u64> = None;
            let mut max_end: Option<u64> = None;
            for line in maps.lines() {
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
                if path_trim != module_path {
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
                    } else if data_addr.is_none() && (name == ".data" || name.starts_with(".data"))
                    {
                        data_addr = Some(addr);
                    } else if bss_addr.is_none() && (name == ".bss" || name.starts_with(".bss")) {
                        bss_addr = Some(addr);
                    }
                }
            }
            let mut offsets = SectionOffsets::default();
            if let Some(a0) = text_addr.and_then(find_bias_for) {
                offsets.text = a0;
            }
            if let Some(a1) = rodata_addr.and_then(find_bias_for) {
                offsets.rodata = a1;
            }
            if let Some(a2) = data_addr.and_then(find_bias_for) {
                offsets.data = a2;
            }
            if let Some(a3) = bss_addr.and_then(find_bias_for) {
                offsets.bss = a3;
            }
            let cookie = crate::cookie::from_path(module_path);
            let base = min_start.unwrap_or(0);
            let size = max_end.unwrap_or(base).saturating_sub(base);
            Ok((cookie, offsets, base, size))
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
}
pub mod cookie;
pub use offsets::{PidOffsetsEntry, ProcessManager, SectionOffsets};

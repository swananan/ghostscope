use anyhow::Result;
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::ops::ControlFlow;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcMapEntry<'a> {
    pub start: u64,
    pub end: u64,
    pub perms: &'a str,
    pub offset: u64,
    pub dev_major: u64,
    pub dev_minor: u64,
    pub inode: u64,
    path: Option<&'a str>,
}

impl<'a> ProcMapEntry<'a> {
    pub fn path(&self) -> Option<&'a str> {
        self.path
    }

    pub fn normalized_path(&self) -> Option<&'a str> {
        self.path.map(normalize_mapped_module_path)
    }

    pub fn executable(&self) -> bool {
        self.perms.contains('x')
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedProcMapEntry {
    pub start: u64,
    pub end: u64,
    pub perms: String,
    pub offset: u64,
    pub dev_major: u64,
    pub dev_minor: u64,
    pub inode: u64,
    path: Option<String>,
}

impl OwnedProcMapEntry {
    pub fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }

    pub fn normalized_path(&self) -> Option<&str> {
        self.path().map(normalize_mapped_module_path)
    }

    pub fn executable(&self) -> bool {
        self.perms.contains('x')
    }
}

impl From<ProcMapEntry<'_>> for OwnedProcMapEntry {
    fn from(entry: ProcMapEntry<'_>) -> Self {
        Self {
            start: entry.start,
            end: entry.end,
            perms: entry.perms.to_owned(),
            offset: entry.offset,
            dev_major: entry.dev_major,
            dev_minor: entry.dev_minor,
            inode: entry.inode,
            path: entry.path().map(str::to_owned),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ModuleIdentity {
    dev_major: Option<u64>,
    dev_minor: Option<u64>,
    inode: Option<u64>,
    normalized_path: String,
}

impl ModuleIdentity {
    pub fn from_path(path: &Path) -> Self {
        let path_str = path.to_string_lossy();
        // Fallback path matching against /proc/<pid>/maps must normalize "/./";
        // otherwise equivalent paths can miss the same mapped module when
        // metadata is unavailable.
        let normalized_path = normalize_mapped_module_path(&path_str).replace("/./", "/");
        let (dev_major, dev_minor, inode) = fs::metadata(path)
            .map(|meta| {
                let dev = meta.dev() as libc::dev_t;
                (
                    Some(libc::major(dev) as u64),
                    Some(libc::minor(dev) as u64),
                    Some(meta.ino()),
                )
            })
            .unwrap_or((None, None, None));

        Self {
            dev_major,
            dev_minor,
            inode,
            normalized_path,
        }
    }

    pub fn normalized_path(&self) -> &str {
        &self.normalized_path
    }

    pub fn matches(&self, entry: &ProcMapEntry<'_>) -> bool {
        if let (Some(maj), Some(min), Some(ino)) = (self.dev_major, self.dev_minor, self.inode) {
            if entry.dev_major == maj && entry.dev_minor == min && entry.inode == ino {
                return true;
            }

            // overlayfs compatibility: the same mapped file can keep the same inode while
            // surfacing under a different device number across mount namespaces, so relax
            // the match to inode+path before giving up.
            return entry.inode == ino && entry.normalized_path() == Some(self.normalized_path());
        }

        entry.normalized_path() == Some(self.normalized_path())
    }
}

pub fn parse_maps_line(line: &str) -> Option<ProcMapEntry<'_>> {
    let (range, rest) = take_field(line)?;
    let (perms, rest) = take_field(rest)?;
    let (offset, rest) = take_field(rest)?;
    let (dev, rest) = take_field(rest)?;
    let (inode, rest) = take_field(rest)?;

    let (start_s, end_s) = range.split_once('-')?;
    let (dev_major_s, dev_minor_s) = dev.split_once(':')?;
    let path = rest.trim_start();

    Some(ProcMapEntry {
        start: u64::from_str_radix(start_s, 16).ok()?,
        end: u64::from_str_radix(end_s, 16).ok()?,
        perms,
        offset: u64::from_str_radix(offset, 16).ok()?,
        dev_major: u64::from_str_radix(dev_major_s, 16).ok()?,
        dev_minor: u64::from_str_radix(dev_minor_s, 16).ok()?,
        inode: inode.parse::<u64>().ok()?,
        path: (!path.is_empty()).then_some(path),
    })
}

pub fn visit_proc_maps<F>(pid: u32, visitor: F) -> Result<()>
where
    F: FnMut(ProcMapEntry<'_>) -> ControlFlow<()>,
{
    let maps_path = format!("/proc/{pid}/maps");
    let file = File::open(&maps_path)?;
    visit_maps_reader(BufReader::new(file), visitor)
}

pub fn read_proc_maps(pid: u32) -> Result<Vec<OwnedProcMapEntry>> {
    let maps_path = format!("/proc/{pid}/maps");
    let file = File::open(&maps_path)?;
    read_maps_reader(BufReader::new(file))
}

fn visit_maps_reader<R, F>(mut reader: R, mut visitor: F) -> Result<()>
where
    R: BufRead,
    F: FnMut(ProcMapEntry<'_>) -> ControlFlow<()>,
{
    let mut line = String::new();

    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            break;
        }

        let line = line.trim_end_matches(['\n', '\r']);
        if let Some(entry) = parse_maps_line(line) {
            if matches!(visitor(entry), ControlFlow::Break(())) {
                break;
            }
        }
    }

    Ok(())
}

fn read_maps_reader<R>(reader: R) -> Result<Vec<OwnedProcMapEntry>>
where
    R: BufRead,
{
    let mut entries = Vec::new();
    visit_maps_reader(reader, |entry| {
        entries.push(entry.into());
        ControlFlow::Continue(())
    })?;
    Ok(entries)
}

pub fn normalize_mapped_module_path(path: &str) -> &str {
    if let Some(idx) = path.find(" (deleted)") {
        &path[..idx]
    } else {
        path
    }
}

pub fn is_filtered_module_prefix(path: &str) -> bool {
    matches!(path, "/proc" | "/sys") || path.starts_with("/proc/") || path.starts_with("/sys/")
}

pub fn should_skip_mapped_module_path(path: &str) -> bool {
    let path = normalize_mapped_module_path(path);
    path.starts_with('[')
        || is_filtered_module_prefix(path)
        || matches!(fs::metadata(path), Ok(meta) if !meta.file_type().is_file())
}

fn take_field(input: &str) -> Option<(&str, &str)> {
    let input = input.trim_start();
    if input.is_empty() {
        return None;
    }

    let split_at = input.find(char::is_whitespace).unwrap_or(input.len());
    Some((&input[..split_at], &input[split_at..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
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
    fn parse_maps_line_handles_deleted_paths_and_spaces() {
        let line = "7f1234500000-7f1234510000 r-xp 00000000 08:02 12345 /tmp/lib demo.so (deleted)";
        let entry = parse_maps_line(line).unwrap();

        assert_eq!(entry.start, 0x7f1234500000);
        assert_eq!(entry.end, 0x7f1234510000);
        assert_eq!(entry.offset, 0);
        assert_eq!(entry.dev_major, 0x08);
        assert_eq!(entry.dev_minor, 0x02);
        assert_eq!(entry.inode, 12345);
        assert_eq!(entry.normalized_path(), Some("/tmp/lib demo.so"));
    }

    #[test]
    fn skips_virtual_and_pseudo_filesystem_mappings() {
        assert!(should_skip_mapped_module_path("[heap]"));
        assert!(should_skip_mapped_module_path("/dev/null"));
        assert!(should_skip_mapped_module_path("/sys/kernel/tracing"));
        assert!(should_skip_mapped_module_path("/proc/123/maps"));
        assert!(!is_filtered_module_prefix("/dev/shm/ghostscope-module.so"));
        assert!(!should_skip_mapped_module_path(
            "/dev/shm/ghostscope-module.so"
        ));
        assert!(!should_skip_mapped_module_path("/usr/lib/libc.so.6"));
    }

    #[test]
    fn module_identity_matches_by_path_when_metadata_is_missing() {
        let missing = PathBuf::from("/tmp/./ghostscope-missing-lib.so");
        let identity = ModuleIdentity::from_path(&missing);
        let entry = parse_maps_line(
            "7f1234500000-7f1234510000 r-xp 00000000 00:00 0 /tmp/ghostscope-missing-lib.so (deleted)",
        )
        .unwrap();

        assert!(identity.matches(&entry));
    }

    #[test]
    fn module_identity_falls_back_to_inode_and_path_when_dev_differs() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghostscope-overlayfs-{suffix}.so"));
        std::fs::write(&path, b"current").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let inode = meta.ino();
        let path_str = path.to_string_lossy().to_string();
        let identity = ModuleIdentity::from_path(&path);
        let (dev_major, dev_minor) = dev_pair_differs_from(&meta, 1);
        let line = format!(
            "7f1234500000-7f1234510000 r-xp 00000000 {dev_major:02x}:{dev_minor:02x} {inode} {path_str}"
        );
        let entry = parse_maps_line(&line).unwrap();

        assert!(identity.matches(&entry));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn module_identity_does_not_fallback_without_path_match() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ghostscope-overlayfs-{suffix}.so"));
        std::fs::write(&path, b"current").unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        let inode = meta.ino();
        let identity = ModuleIdentity::from_path(&path);
        let (dev_major, dev_minor) = dev_pair_differs_from(&meta, 2);
        let line = format!(
            "7f1234500000-7f1234510000 r-xp 00000000 {dev_major:02x}:{dev_minor:02x} {inode} /tmp/other-{suffix}.so"
        );
        let entry = parse_maps_line(&line).unwrap();

        assert!(!identity.matches(&entry));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn visit_proc_maps_stops_when_visitor_breaks() {
        use std::cell::Cell;

        let lines =
            b"7f1-7f2 r-xp 00000000 08:02 1 /tmp/a.so\n7f2-7f3 r-xp 00000000 08:02 2 /tmp/b.so\n";
        let mut reader = BufReader::new(&lines[..]);
        let seen = Cell::new(0usize);

        visit_maps_reader(&mut reader, |entry| {
            seen.set(seen.get() + 1);
            if entry.inode == 1 {
                return ControlFlow::Break(());
            }
            ControlFlow::Continue(())
        })
        .unwrap();

        assert_eq!(seen.get(), 1);
    }

    #[test]
    fn read_maps_reader_collects_owned_entries() {
        let lines =
            b"7f1-7f2 r-xp 00000000 08:02 1 /tmp/a.so\n7f2-7f3 rw-p 00001000 08:02 1 /tmp/a.so\n";
        let reader = BufReader::new(&lines[..]);

        let entries = read_maps_reader(reader).unwrap();

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path(), Some("/tmp/a.so"));
        assert!(entries[0].executable());
        assert_eq!(entries[1].offset, 0x1000);
    }
}

use anyhow::Result;
use std::fs;
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
        let normalized_path = normalize_mapped_module_path(&path_str).to_string();
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
            return entry.dev_major == maj && entry.dev_minor == min && entry.inode == ino;
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

pub fn normalize_mapped_module_path(path: &str) -> &str {
    if let Some(idx) = path.find(" (deleted)") {
        &path[..idx]
    } else {
        path
    }
}

pub fn is_filtered_module_prefix(path: &str) -> bool {
    matches!(path, "/dev" | "/proc" | "/sys")
        || path.starts_with("/dev/")
        || path.starts_with("/proc/")
        || path.starts_with("/sys/")
}

pub fn should_skip_mapped_module_path(path: &str) -> bool {
    let path = normalize_mapped_module_path(path);
    path.starts_with('[') || is_filtered_module_prefix(path)
}

pub fn ensure_readable_module_path(path: &str) -> Result<()> {
    if is_filtered_module_prefix(path) {
        anyhow::bail!("refusing to read pseudo-filesystem path {path}");
    }

    let meta = fs::metadata(path)?;
    if !meta.file_type().is_file() {
        anyhow::bail!("refusing to read non-regular file {path}");
    }

    Ok(())
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
        assert!(should_skip_mapped_module_path("/dev/dri/renderD128"));
        assert!(should_skip_mapped_module_path("/sys/kernel/tracing"));
        assert!(should_skip_mapped_module_path("/proc/123/maps"));
        assert!(should_skip_mapped_module_path(
            "/dev/dri/renderD128 (deleted)"
        ));
        assert!(!should_skip_mapped_module_path("/usr/lib/libc.so.6"));
    }

    #[test]
    fn rejects_non_regular_module_paths_before_read() {
        let err = ensure_readable_module_path("/dev/null").unwrap_err();
        assert!(err
            .to_string()
            .contains("refusing to read pseudo-filesystem path /dev/null"));
    }

    #[test]
    fn module_identity_matches_by_path_when_metadata_is_missing() {
        let missing = PathBuf::from("/tmp/ghostscope-missing-lib.so");
        let identity = ModuleIdentity::from_path(&missing);
        let entry = parse_maps_line(
            "7f1234500000-7f1234510000 r-xp 00000000 00:00 0 /tmp/ghostscope-missing-lib.so (deleted)",
        )
        .unwrap();

        assert!(identity.matches(&entry));
    }
}

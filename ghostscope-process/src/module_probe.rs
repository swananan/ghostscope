use crate::proc_maps::{is_filtered_module_prefix, normalize_mapped_module_path};
use anyhow::Result;
use memmap2::{Mmap, MmapOptions};
use object::Object;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;

#[derive(Debug)]
pub struct ModuleProbe {
    metadata_cookie: u64,
    metadata: fs::Metadata,
    mmap: Mmap,
}

impl ModuleProbe {
    pub fn open(module_path: &str) -> Result<Self> {
        let normalized_path = normalize_cookie_path(module_path);
        let validated = validate_module_path(&normalized_path)?;
        Self::from_validated_file(validated)
    }

    fn from_validated_file(validated: fs::File) -> Result<Self> {
        // Reopen the retained O_PATH descriptor, not a canonicalized pathname:
        // resolving /proc/<pid>/root in userspace can select a host-side file
        // instead of the target's file in another mount namespace. The retained
        // descriptor also prevents replacement or symlink swaps after validation.
        let validated_metadata = validated.metadata()?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", validated.as_raw_fd()))?;
        let meta = file.metadata()?;
        anyhow::ensure!(
            meta.file_type().is_file()
                && meta.dev() == validated_metadata.dev()
                && meta.ino() == validated_metadata.ino(),
            "module identity changed while reopening validated descriptor"
        );

        let dev = meta.dev();
        let ino = meta.ino();
        let metadata_cookie = ((dev & 0xffff_ffff) << 32) | (ino & 0xffff_ffff);

        // SAFETY: The descriptor is a validated read-only regular file. This code
        // only exposes the mapping immutably for object parsing; callers must not
        // concurrently modify the mapped file while the mapping is alive.
        let mmap = unsafe { MmapOptions::new().map(&file)? };

        Ok(Self {
            metadata_cookie,
            metadata: meta,
            mmap,
        })
    }

    /// Identity of the descriptor backing this mapping, not a later path lookup.
    pub fn metadata(&self) -> &fs::Metadata {
        &self.metadata
    }

    pub fn into_mmap(self) -> Mmap {
        self.mmap
    }

    pub fn object(&self) -> Result<object::File<'_>> {
        Ok(object::File::parse(&self.mmap[..])?)
    }

    pub fn cookie_for_object(&self, obj: &object::File<'_>) -> u64 {
        if let Ok(Some(build_id)) = obj.build_id() {
            return stable_hash(&build_id);
        }

        self.fallback_cookie()
    }

    pub fn cookie(&self) -> u64 {
        self.object()
            .map(|obj| self.cookie_for_object(&obj))
            .unwrap_or_else(|_| self.fallback_cookie())
    }

    fn fallback_cookie(&self) -> u64 {
        self.metadata_cookie
    }
}

pub fn cookie_for_path(module_path: &str) -> u64 {
    ModuleProbe::open(module_path)
        .map(|probe| probe.cookie())
        .unwrap_or_else(|_| stable_hash(&normalize_cookie_path(module_path)))
}

fn validate_module_path(path: &str) -> Result<fs::File> {
    // `/proc/<pid>/maps` is not a trustworthy module list. Reject procfs/sysfs
    // paths up front. O_PATH follows launcher symlinks without opening devices
    // or blocking on FIFOs; inspect the retained object before reading any data.
    let input_is_proc_root = is_safe_proc_root_path(path);
    if is_filtered_module_prefix(path) && !input_is_proc_root {
        anyhow::bail!("refusing to read pseudo-filesystem path {path}");
    }

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        anyhow::bail!("refusing to read non-regular file {path}");
    }

    // Check the actual filesystem too: symlinks and proc-root paths can conceal
    // a procfs/sysfs file behind an otherwise ordinary pathname.
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: file owns a live descriptor and filesystem points to writable
    // storage of the exact type and size expected by fstatfs.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful fstatfs initialized the entire output structure.
    let filesystem = unsafe { filesystem.assume_init() };
    if matches!(
        filesystem.f_type,
        libc::PROC_SUPER_MAGIC | libc::SYSFS_MAGIC
    ) {
        anyhow::bail!("refusing to read pseudo-filesystem path {path}");
    }

    Ok(file)
}

fn is_safe_proc_root_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("/proc/") else {
        return false;
    };
    let Some((pid, path)) = rest.split_once('/') else {
        return false;
    };
    let Some(inner_path) = path.strip_prefix("root/") else {
        return false;
    };
    !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && !matches!(inner_path, "proc" | "sys")
        && !inner_path.starts_with("proc/")
        && !inner_path.starts_with("sys/")
}

fn normalize_cookie_path(module_path: &str) -> String {
    normalize_mapped_module_path(module_path).replace("/./", "/")
}

fn stable_hash<T: Hash + ?Sized>(value: &T) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn cookie_path_fallback_normalizes_equivalent_paths() {
        let a = cookie_for_path("/tmp/./ghostscope-missing-lib.so");
        let b = cookie_for_path("/tmp/ghostscope-missing-lib.so");
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_pseudo_filesystem_paths() {
        let err = match ModuleProbe::open("/dev/null") {
            Ok(_) => panic!("expected /dev/null probe to be rejected"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("refusing to read non-regular file /dev/null"));

        let err = match ModuleProbe::open("/proc/self/maps") {
            Ok(_) => panic!("expected /proc/self/maps probe to be rejected"),
            Err(err) => err,
        };
        assert!(err
            .to_string()
            .contains("refusing to read pseudo-filesystem path /proc/self/maps"));

        let err = match ModuleProbe::open("/proc/self/root/proc/self/maps") {
            Ok(_) => panic!("expected /proc/self/root/proc/self/maps probe to be rejected"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("pseudo-filesystem path"));
    }

    #[test]
    fn allows_proc_root_regular_files() {
        let base = std::env::temp_dir().join(format!(
            "ghostscope-module-probe-proc-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&base, b"not an elf but still a regular file").unwrap();
        let pid = std::process::id();
        let proc_root_path = format!("/proc/{pid}/root{}", base.display());

        ModuleProbe::open(&proc_root_path).unwrap();

        let _ = std::fs::remove_file(&base);
    }

    #[test]
    fn allows_symlinked_regular_files() {
        let base = std::env::temp_dir().join(format!(
            "ghostscope-module-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let target = base.with_extension("so");
        let link = base.with_extension("link");
        std::fs::write(&target, b"not an elf but still a regular file").unwrap();
        symlink(&target, &link).unwrap();

        let target_cookie = cookie_for_path(target.to_str().unwrap());
        let link_cookie = cookie_for_path(link.to_str().unwrap());
        assert_eq!(link_cookie, target_cookie);
        ModuleProbe::open(link.to_str().unwrap()).unwrap();

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }

    #[test]
    fn retains_validated_file_after_path_replacement() {
        let base = std::env::temp_dir().join(format!(
            "ghostscope-module-probe-replacement-{}",
            std::process::id()
        ));
        let replaced = base.with_extension("replaced");
        std::fs::write(&base, b"original module").unwrap();
        let validated = validate_module_path(base.to_str().unwrap()).unwrap();
        std::fs::rename(&base, &replaced).unwrap();
        std::fs::write(&base, b"replacement module").unwrap();

        let probe = ModuleProbe::from_validated_file(validated).unwrap();
        assert_eq!(&probe.mmap[..], b"original module");
        assert_ne!(
            probe.metadata().ino(),
            std::fs::metadata(&base).unwrap().ino()
        );

        std::fs::remove_file(&base).unwrap();
        std::fs::remove_file(&replaced).unwrap();
    }

    #[test]
    fn rejects_symlinks_to_pseudo_filesystems() {
        let link = std::env::temp_dir().join(format!(
            "ghostscope-module-probe-proc-link-{}",
            std::process::id()
        ));
        symlink("/proc/self/maps", &link).unwrap();
        let err = ModuleProbe::open(link.to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("pseudo-filesystem path"));
        std::fs::remove_file(&link).unwrap();
    }
}

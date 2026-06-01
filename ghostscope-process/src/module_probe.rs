use crate::proc_maps::{is_filtered_module_prefix, normalize_mapped_module_path};
use anyhow::Result;
use memmap2::{Mmap, MmapOptions};
use object::Object;
use std::fs::{self, OpenOptions};
use std::hash::{Hash, Hasher};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

pub struct ModuleProbe {
    metadata_cookie: u64,
    mmap: Mmap,
}

struct ValidatedModulePath {
    resolved_path: PathBuf,
    metadata: fs::Metadata,
}

impl ModuleProbe {
    pub fn open(module_path: &str) -> Result<Self> {
        let normalized_path = normalize_cookie_path(module_path);
        let validated = validate_module_path(&normalized_path)?;

        // Open the resolved regular file so common launcher symlinks like
        // `/bin/sh` and `/usr/bin/python3` continue to probe correctly.
        // `O_NOFOLLOW` still protects the final open against a symlink swap
        // after resolution.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&validated.resolved_path)?;
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            anyhow::bail!(
                "refusing to read non-regular file {}",
                validated.resolved_path.display()
            );
        }
        if meta.dev() != validated.metadata.dev() || meta.ino() != validated.metadata.ino() {
            anyhow::bail!(
                "module path changed while opening {}",
                validated.resolved_path.display()
            );
        }

        let dev = meta.dev();
        let ino = meta.ino();
        let metadata_cookie = ((dev & 0xffff_ffff) << 32) | (ino & 0xffff_ffff);

        // SAFETY: The descriptor is a validated read-only regular file. This code
        // only exposes the mapping immutably for object parsing; callers must not
        // concurrently modify the mapped file while the mapping is alive.
        let mmap = unsafe { MmapOptions::new().map(&file)? };

        Ok(Self {
            metadata_cookie,
            mmap,
        })
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

fn validate_module_path(path: &str) -> Result<ValidatedModulePath> {
    // `/proc/<pid>/maps` is not a trustworthy module list. Reject procfs/sysfs
    // paths up front, then resolve symlinks to the final target and insist that
    // the resolved object is a regular file before it reaches the ELF path.
    let input_is_proc_root = is_safe_proc_root_path(path);
    if is_filtered_module_prefix(path) && !input_is_proc_root {
        anyhow::bail!("refusing to read pseudo-filesystem path {}", path);
    }

    let resolved_path = fs::canonicalize(path)?;
    let resolved_str = resolved_path.to_string_lossy();
    let resolved_is_safe_proc_root = input_is_proc_root && is_safe_proc_root_path(&resolved_str);
    if is_filtered_module_prefix(&resolved_str) && !resolved_is_safe_proc_root {
        anyhow::bail!("refusing to read pseudo-filesystem path {}", resolved_str);
    }
    let meta = fs::metadata(&resolved_path)?;
    if !meta.file_type().is_file() {
        anyhow::bail!("refusing to read non-regular file {}", resolved_str);
    }

    Ok(ValidatedModulePath {
        resolved_path,
        metadata: meta,
    })
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
}

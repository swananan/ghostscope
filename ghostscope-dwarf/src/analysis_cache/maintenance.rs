use super::{create_private_directory, CACHE_SCHEMA_VERSION};
use anyhow::{Context, Result};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const TOUCH_INTERVAL: Duration = Duration::from_secs(60);
const LEGACY_TEMP_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Recency is advisory: read-only mounts and shared caches must remain usable.
/// Touch the opened inode, not a path that a writer may already have replaced.
pub(super) fn record_hit(file: &File, metadata: &Metadata) {
    let now = SystemTime::now();
    if metadata.modified().is_ok_and(|modified| {
        now.duration_since(modified)
            .is_ok_and(|elapsed| elapsed < TOUCH_INTERVAL)
    }) {
        return;
    }
    if let Err(error) = file.set_modified(now) {
        tracing::debug!("Could not update analysis cache recency: {error}");
    }
}

/// All prepare operations share one root lock, including different targets.
/// Readers retain owned snapshots and never acquire this lock.
pub(super) struct Maintenance {
    directory: PathBuf,
    _lock: File,
}

struct Entry {
    path: PathBuf,
    size: u64,
    used: SystemTime,
    obsolete: bool,
}

impl Maintenance {
    pub(super) fn acquire(directory: &Path) -> Result<Self> {
        create_private_directory(directory)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(directory.join(".lock"))
            .context("Failed to open analysis cache maintenance lock")?;
        anyhow::ensure!(
            lock.metadata()?.is_file(),
            "Cache lock is not a regular file"
        );
        lock.lock()
            .context("Failed to lock analysis cache directory")?;
        Ok(Self {
            directory: directory.to_owned(),
            _lock: lock,
        })
    }

    /// Reserve incoming bytes before opening the temporary output. Holding the
    /// lock until rename also bounds temporary space for cooperating writers.
    pub(super) fn prune(
        &self,
        max_size: u64,
        incoming: u64,
        protected: Option<&Path>,
    ) -> Result<()> {
        let budget = max_size
            .checked_sub(incoming)
            .context("Prepared analysis cache entry exceeds the configured cache size limit")?;
        let now = SystemTime::now();
        let mut entries = Vec::new();
        let mut total = 0_u64;
        for version in fs::read_dir(&self.directory)? {
            let version = version?;
            // Never traverse a symlink or an unknown/future format directory.
            if !version.file_type()?.is_dir() {
                continue;
            }
            let name = version.file_name();
            let Some(schema) = name
                .to_str()
                .and_then(|name| name.strip_prefix('v'))
                .and_then(|version| version.parse::<u32>().ok())
                .filter(|&schema| schema > 0 && schema <= CACHE_SCHEMA_VERSION)
            else {
                continue;
            };
            if name != format!("v{schema}").as_str() {
                continue;
            }
            for entry in fs::read_dir(version.path())? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let temporary = is_temporary_name(name);
                if !temporary && !is_entry_name(name) {
                    continue;
                }
                let metadata = entry.metadata()?;
                let modified = metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                if temporary {
                    // Current writers hold this lock for the entire temporary
                    // file lifetime. Older formats may not implement locking;
                    // leave their recent temporary files alone.
                    if schema == CACHE_SCHEMA_VERSION
                        || now
                            .duration_since(modified)
                            .is_ok_and(|age| age >= LEGACY_TEMP_MAX_AGE)
                    {
                        fs::remove_file(entry.path())
                            .context("Failed to remove abandoned cache output")?;
                    } else {
                        total = total
                            .checked_add(metadata.len())
                            .context("Cache size overflow")?;
                    }
                    continue;
                }
                if protected == Some(entry.path().as_path()) {
                    anyhow::ensure!(
                        metadata.len() <= budget,
                        "Prepared analysis cache entry exceeds the configured cache size limit"
                    );
                }
                total = total
                    .checked_add(metadata.len())
                    .context("Cache size overflow")?;
                entries.push(Entry {
                    path: entry.path(),
                    size: metadata.len(),
                    used: modified.min(now),
                    obsolete: schema < CACHE_SCHEMA_VERSION,
                });
            }
        }
        entries.sort_unstable_by(|a, b| {
            (!a.obsolete, a.used, &a.path).cmp(&(!b.obsolete, b.used, &b.path))
        });
        let mut removed = 0;
        for entry in entries {
            if total <= budget {
                break;
            }
            if protected == Some(entry.path.as_path()) {
                continue;
            }
            fs::remove_file(&entry.path)
                .with_context(|| format!("Failed to evict cache {}", entry.path.display()))?;
            total -= entry.size;
            removed += 1;
        }
        anyhow::ensure!(total <= budget,
            "Analysis cache cannot fit within the configured limit; recent legacy temporary files still occupy space");
        if removed > 0 {
            tracing::info!("Evicted {removed} analysis cache entries; {total} bytes retained, {incoming} bytes reserved");
        }
        Ok(())
    }
}

fn is_entry_name(name: &str) -> bool {
    name.strip_suffix(".bin").is_some_and(|hash| {
        hash.len() == 16
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn is_temporary_name(name: &str) -> bool {
    let Some(name) = name.strip_prefix('.') else {
        return false;
    };
    let Some(name) = name.strip_suffix(".tmp") else {
        return false;
    };
    let mut fields = name.rsplitn(3, '.');
    let sequence = fields.next().unwrap_or("");
    let pid = fields.next().unwrap_or("");
    let entry = fields.next().unwrap_or("");
    is_entry_name(entry)
        && !pid.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(root: &Path, version: u32, id: u64, size: u64, seconds: u64) -> PathBuf {
        let directory = root.join(format!("v{version}"));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{id:016x}.bin"));
        let file = File::create(&path).unwrap();
        file.set_len(size).unwrap();
        file.set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(seconds))
            .unwrap();
        path
    }

    #[test]
    fn hits_refresh_lru_without_rewriting_payload_or_touching_every_read() {
        let root = tempfile::tempdir().unwrap();
        let hot = entry(root.path(), CACHE_SCHEMA_VERSION, 1, 10, 1);
        let cold = entry(root.path(), CACHE_SCHEMA_VERSION, 2, 10, 2);
        let file = File::open(&hot).unwrap();
        record_hit(&file, &file.metadata().unwrap());
        let touched = file.metadata().unwrap();
        record_hit(&file, &touched);
        assert_eq!(
            file.metadata().unwrap().modified().unwrap(),
            touched.modified().unwrap()
        );
        assert_eq!(fs::read(&hot).unwrap(), vec![0; 10]);
        Maintenance::acquire(root.path())
            .unwrap()
            .prune(20, 10, None)
            .unwrap();
        assert!(hot.exists());
        assert!(!cold.exists());
    }

    #[test]
    fn lowered_budget_preserves_the_reused_entry_and_rejects_oversized_entries() {
        let root = tempfile::tempdir().unwrap();
        let reused = entry(root.path(), CACHE_SCHEMA_VERSION, 1, 10, 1);
        let other = entry(root.path(), CACHE_SCHEMA_VERSION, 2, 10, 2);
        let maintenance = Maintenance::acquire(root.path()).unwrap();
        assert!(maintenance.prune(9, 0, Some(&reused)).is_err());
        assert!(reused.exists() && other.exists());
        assert!(maintenance.prune(9, 10, None).is_err());
        assert!(reused.exists() && other.exists());
        maintenance.prune(10, 0, Some(&reused)).unwrap();
        assert!(reused.exists());
        assert!(!other.exists());
    }

    #[test]
    fn maintenance_only_removes_managed_files_and_prefers_obsolete_formats() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let external = entry(outside.path(), CACHE_SCHEMA_VERSION, 1, 20, 1);
        let current = entry(root.path(), CACHE_SCHEMA_VERSION, 1, 10, 1);
        let obsolete = entry(root.path(), CACHE_SCHEMA_VERSION - 1, 1, 10, 100);
        let future = entry(root.path(), CACHE_SCHEMA_VERSION + 1, 1, 20, 1);
        let version = current.parent().unwrap();
        let orphan = version.join(".0000000000000001.bin.123.0.tmp");
        fs::write(&orphan, b"abandoned").unwrap();
        let unknown = version.join("notes.tmp");
        fs::write(&unknown, b"not ours").unwrap();
        let link = version.join("0000000000000002.bin");
        std::os::unix::fs::symlink(&external, &link).unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("v1")).unwrap();
        Maintenance::acquire(root.path())
            .unwrap()
            .prune(10, 0, None)
            .unwrap();
        assert!(current.exists());
        assert!(!obsolete.exists() && !orphan.exists());
        assert!(future.exists() && unknown.exists() && link.is_symlink() && external.exists());
    }

    #[test]
    fn legacy_temporary_files_are_counted_until_old_enough_to_remove() {
        let root = tempfile::tempdir().unwrap();
        let path = entry(root.path(), CACHE_SCHEMA_VERSION - 1, 1, 10, 1);
        let temporary = path.with_file_name(".0000000000000001.bin.123.0.tmp");
        fs::rename(path, &temporary).unwrap();
        File::open(&temporary)
            .unwrap()
            .set_modified(SystemTime::now())
            .unwrap();
        let maintenance = Maintenance::acquire(root.path()).unwrap();
        assert!(maintenance.prune(9, 0, None).is_err());
        assert!(temporary.exists());
        File::open(&temporary)
            .unwrap()
            .set_modified(SystemTime::UNIX_EPOCH)
            .unwrap();
        maintenance.prune(9, 0, None).unwrap();
        assert!(!temporary.exists());
    }

    #[test]
    fn writer_lock_is_exclusive_and_released_on_drop() {
        let root = tempfile::tempdir().unwrap();
        let maintenance = Maintenance::acquire(root.path()).unwrap();
        let other = OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join(".lock"))
            .unwrap();
        assert!(matches!(
            other.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
        drop(maintenance);
        other.try_lock().unwrap();
    }
}

use std::path::{Component, Path, PathBuf};

/// Resolve directory string from DWARF directory index.
pub(crate) fn directory_from_index<T: AsRef<str>>(
    dwarf_version: u16,
    comp_dir: &str,
    directories: &[T],
    directory_index: u64,
) -> String {
    let resolve_relative = |entry: &str| {
        if entry.is_empty() {
            comp_dir.trim().to_string()
        } else if Path::new(entry).is_absolute() {
            entry.to_string()
        } else if comp_dir.trim().is_empty() {
            entry.to_string()
        } else {
            join_paths(comp_dir.trim(), entry)
        }
    };

    if dwarf_version >= 5 {
        let idx = directory_index as usize;
        match directories.get(idx) {
            Some(value) => resolve_relative(value.as_ref()),
            None => {
                tracing::debug!(
                    "directory_from_index fallback (DWARF v5): dir_index={}, comp_dir='{}'",
                    directory_index,
                    comp_dir
                );
                comp_dir.to_string()
            }
        }
    } else if directory_index == 0 {
        comp_dir.to_string()
    } else {
        let idx = (directory_index - 1) as usize;
        match directories.get(idx) {
            Some(value) => resolve_relative(value.as_ref()),
            None => {
                tracing::debug!(
                    "directory_from_index fallback (DWARF v{}): dir_index={}, comp_dir='{}'",
                    dwarf_version,
                    directory_index,
                    comp_dir
                );
                comp_dir.to_string()
            }
        }
    }
}

/// Join directory and filename into a normalized path (no filesystem checks).
pub(crate) fn join_paths(left: &str, right: &str) -> String {
    let mut buf = if left.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(left)
    };

    for comp in Path::new(right).components() {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                buf.pop();
            }
            other => buf.push(other.as_os_str()),
        }
    }

    buf.to_string_lossy().into_owned()
}

/// Resolve a full file path using DWARF directory information.
pub(crate) fn resolve_file_path<T: AsRef<str>>(
    dwarf_version: u16,
    comp_dir: &str,
    directories: &[T],
    directory_index: u64,
    filename: &str,
) -> String {
    if filename.is_empty() {
        return String::new();
    }

    if Path::new(filename).is_absolute() {
        return filename.to_string();
    }

    let directory = directory_from_index(dwarf_version, comp_dir, directories, directory_index);

    if directory.is_empty() {
        filename.to_string()
    } else {
        join_paths(&directory, filename)
    }
}

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
        } else if Path::new(entry).is_absolute() || comp_dir.trim().is_empty() {
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

/// Join left and right paths but avoid duplicating overlapping directory components.
/// Example: left="/a/b/src/core", right="src/core/file.c" => "/a/b/src/core/file.c".
fn join_paths_dedup(left: &str, right: &str) -> String {
    if right.is_empty() {
        return left.to_string();
    }

    // Start with the original left path
    let mut out = if left.is_empty() {
        PathBuf::new()
    } else {
        PathBuf::from(left)
    };

    // If right contains any parent directory traversals, fall back to normal join
    // to preserve exact semantics of ".." handling.
    let right_has_parent = Path::new(right)
        .components()
        .any(|c| matches!(c, Component::ParentDir));
    if right_has_parent {
        return join_paths(left, right);
    }

    // Collect only normal components for overlap comparison (no ".." in right at this point)
    fn normals_of(p: &Path) -> Vec<String> {
        p.components()
            .filter_map(|c| match c {
                Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                _ => None,
            })
            .collect()
    }

    let left_normals = normals_of(Path::new(left));
    let right_normals = normals_of(Path::new(right));

    // Determine overlap length (suffix of left equals prefix of right)
    let max_k = std::cmp::min(left_normals.len(), right_normals.len());
    let mut overlap = 0usize;
    for i in (1..=max_k).rev() {
        if left_normals[left_normals.len() - i..] == right_normals[..i] {
            overlap = i;
            break;
        }
    }

    // Append right with overlap trimmed (safe because right has no parent dirs)
    let mut comps = Path::new(right).components();
    // Skip the first `overlap` normal components
    let mut skipped = 0usize;
    while skipped < overlap {
        if let Some(c) = comps.next() {
            match c {
                Component::Normal(_) => skipped += 1,
                // Should not happen (we ensured no ParentDir), but break defensively
                _ => break,
            }
        } else {
            break;
        }
    }

    for comp in comps {
        match comp {
            Component::CurDir => continue,
            Component::ParentDir => {
                // Not expected here (guarded above), but handle safely
                out.pop();
            }
            other => out.push(other.as_os_str()),
        }
    }

    out.to_string_lossy().into_owned()
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
        // Deduplicate overlapping segments between directory and filename
        join_paths_dedup(&directory, filename)
    }
}

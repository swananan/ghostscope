//! Locate local separate debug information by Build-ID or `.gnu_debuglink`.
//!
//! This module follows GDB's standard directory layouts while retaining
//! GhostScope's existing flat search-directory behavior.

use crate::{binary::MappedFile, core::Result};
use anyhow::Context;
use object::Object;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebugFileValidation {
    BuildId,
    DebugLink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DebugFileCandidate {
    path: PathBuf,
    validation: DebugFileValidation,
}

/// Find separate debug information using a build ID or `.gnu_debuglink`.
///
/// Search order (following GDB conventions):
/// 1. Absolute path (if `.gnu_debuglink` contains one; a GhostScope extension)
/// 2. Build-ID paths below user-configured global debug directories
/// 3. User-configured flat search paths (a GhostScope extension)
/// 4. Same directory as the binary and its `.debug` subdirectory
/// 5. The binary's absolute directory mirrored below each global debug directory
///
/// Note: If .gnu_debuglink contains an absolute path (e.g., /usr/lib/debug/foo.debug),
/// the function will:
/// - First try the absolute path directly
/// - Then extract basename (foo.debug) and search in all configured paths
///
/// This ensures maximum flexibility:
/// - Absolute paths are honored if they exist
/// - But custom search_paths can still provide alternatives via basename
///
/// System-wide debug directories are searched when the caller includes them in
/// `user_search_paths`; the default GhostScope config includes common system
/// paths.
///
/// Returns the path to the debug file if a strict CRC/Build-ID match is found,
/// or if loose mode falls back to the first mismatched candidate.
pub fn find_debug_file<P: AsRef<Path>>(
    binary_path: P,
    user_search_paths: &[String],
    allow_loose_debug_match: bool,
) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();

    // Read the binary and discover its local separate-debug metadata.
    let binary_data = MappedFile::open(binary_path)?;
    let binary_obj = binary_data.parse_object()?;

    // Extract the build ID both for discovery and later verification.
    let binary_build_id = binary_obj.build_id().ok().flatten();

    // A build ID is an independent discovery mechanism, so a missing or
    // malformed .gnu_debuglink must not prevent build-ID lookup.
    let debug_link = match binary_obj.gnu_debuglink() {
        Ok(Some((filename, crc))) => {
            use std::os::unix::ffi::OsStrExt;
            let filename = PathBuf::from(std::ffi::OsStr::from_bytes(filename));
            Some((filename, crc))
        }
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(
                "Failed to read .gnu_debuglink from {}: {}",
                binary_path.display(),
                e
            );
            None
        }
    };

    if debug_link.is_none() && binary_build_id.is_none() {
        tracing::debug!(
            "No build ID or .gnu_debuglink section in {}",
            binary_path.display()
        );
        return Ok(None);
    }

    if let Some((debug_filename, _)) = &debug_link {
        tracing::info!(
            "Looking for debug file '{}' for binary '{}'",
            debug_filename.display(),
            binary_path.display()
        );
    } else {
        tracing::info!(
            "Looking for separate debug information by build ID for '{}'",
            binary_path.display()
        );
    }

    // Build search paths following GDB's strategy
    let search_candidates = build_search_candidates(
        binary_path,
        debug_link.as_ref().map(|(filename, _)| filename.as_path()),
        binary_build_id,
        user_search_paths,
    );

    // Try each path and verify CRC + build ID. Strict matches always win, even
    // in loose mode; only fall back to the first mismatched candidate after the
    // full search list has been checked.
    let mut first_loose_candidate = None;
    for candidate in search_candidates {
        let candidate_path = &candidate.path;
        tracing::debug!("Checking debug file path: {}", candidate_path.display());

        if candidate_path.exists() {
            let verified = match candidate.validation {
                DebugFileValidation::BuildId => {
                    let Some(build_id) = binary_build_id else {
                        continue;
                    };
                    verify_build_id_debug_file(candidate_path, build_id)
                }
                DebugFileValidation::DebugLink => {
                    let Some((_, expected_crc)) = &debug_link else {
                        continue;
                    };
                    verify_debug_file(candidate_path, *expected_crc, binary_build_id)
                }
            };
            match verified {
                Ok(true) => {
                    tracing::info!(
                        "Found matching debug file: {} ({:?})",
                        candidate_path.display(),
                        candidate.validation
                    );
                    return Ok(Some(candidate.path));
                }
                Ok(false) => {
                    if allow_loose_debug_match {
                        tracing::warn!(
                            "Debug file {} exists but verification failed; loose match enabled -> retaining as fallback",
                            candidate_path.display()
                        );
                        if first_loose_candidate.is_none() {
                            first_loose_candidate = Some(candidate.path);
                        }
                    } else {
                        tracing::error!(
                            "Debug file {} exists but verification failed (CRC or Build-ID mismatch)",
                            candidate_path.display()
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        "Failed to verify debug file {}: {}",
                        candidate_path.display(),
                        e
                    );
                }
            }
        }
    }

    if let Some(candidate_path) = first_loose_candidate {
        tracing::warn!(
            "No strict matching debug file found; loose match enabled -> using {}",
            candidate_path.display()
        );
        return Ok(Some(candidate_path));
    }

    if let Some((debug_filename, _)) = &debug_link {
        tracing::warn!(
            "Debug file '{}' was not found in any standard location for '{}'",
            debug_filename.display(),
            binary_path.display()
        );
    } else {
        tracing::debug!(
            "No local separate debug information found by build ID for '{}'",
            binary_path.display()
        );
    }
    Ok(None)
}

/// Expand home directory in path (e.g., ~/.local/debug -> /home/user/.local/debug)
fn expand_home_dir(path: &str) -> PathBuf {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            let expanded = home.join(stripped);
            tracing::debug!(
                "Expanded home directory: {} -> {}",
                path,
                expanded.display()
            );
            return expanded;
        } else {
            tracing::warn!(
                "Failed to expand home directory for path '{}', using as-is",
                path
            );
        }
    }
    PathBuf::from(path)
}

/// Build search candidates for separate debug information.
///
/// Search order (highest priority first):
/// 1. Absolute `.gnu_debuglink` path, when present
/// 2. `<global-dir>/.build-id/xx/yyyy.debug`
/// 3. GhostScope's existing flat user-configured paths
/// 4. The binary directory and its `.debug` subdirectory
/// 5. `<global-dir>/<absolute-binary-dir>/<debuglink-basename>`
///
/// Note:
/// - If debug_filename is an absolute path, it will be tried first, then basename extracted
/// - Paths are deduplicated to avoid redundant filesystem checks
/// - Each configured search path acts as both a global debug directory and a
///   flat GhostScope search directory for backwards compatibility
fn build_search_candidates(
    binary_path: &Path,
    debug_filename: Option<&Path>,
    binary_build_id: Option<&[u8]>,
    user_search_paths: &[String],
) -> Vec<DebugFileCandidate> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();
    let proc_root = split_proc_root_path(binary_path);

    let mut add_candidate = |path: PathBuf, validation: DebugFileValidation| {
        if seen.insert(path.clone()) {
            candidates.push(DebugFileCandidate { path, validation });
        }
    };

    if let Some(debug_filename) = debug_filename.filter(|path| path.is_absolute()) {
        add_candidate(debug_filename.to_path_buf(), DebugFileValidation::DebugLink);
        if let Some((proc_root, _)) = &proc_root {
            add_candidate(
                path_below_proc_root(proc_root, debug_filename),
                DebugFileValidation::DebugLink,
            );
        }
    }

    let expanded_search_paths = user_search_paths
        .iter()
        .map(|path| expand_home_dir(path))
        .collect::<Vec<_>>();
    let mut search_paths = Vec::with_capacity(expanded_search_paths.len() * 2);
    for search_path in &expanded_search_paths {
        search_paths.push(search_path.clone());
        if let Some((proc_root, _)) = &proc_root {
            let target_search_path = path_below_proc_root(proc_root, search_path);
            if target_search_path != *search_path {
                search_paths.push(target_search_path);
            }
        }
    }

    if let Some(build_id) = binary_build_id {
        for search_path in &search_paths {
            if let Some(path) = build_id_debug_path(search_path, build_id) {
                add_candidate(path, DebugFileValidation::BuildId);
            }
        }
    }

    let Some(debug_filename) = debug_filename else {
        return candidates;
    };
    let basename = debug_filename
        .file_name()
        .map(Path::new)
        .unwrap_or(debug_filename);

    // Preserve GhostScope's existing flat search-directory behavior.
    for search_path in &search_paths {
        add_candidate(search_path.join(basename), DebugFileValidation::DebugLink);
        add_candidate(
            search_path.join(".debug").join(basename),
            DebugFileValidation::DebugLink,
        );
    }

    if let Some(binary_dir) = binary_path.parent() {
        add_candidate(binary_dir.join(basename), DebugFileValidation::DebugLink);
        add_candidate(
            binary_dir.join(".debug").join(basename),
            DebugFileValidation::DebugLink,
        );
    }

    // Canonicalizing a /proc/<pid>/root path resolves it in GhostScope's mount
    // namespace and loses the target root needed for target-local debug files.
    let absolute_binary = proc_root
        .as_ref()
        .map(|(_, target_path)| target_path.clone())
        .unwrap_or_else(|| {
            binary_path
                .canonicalize()
                .or_else(|_| std::path::absolute(binary_path))
                .unwrap_or_else(|_| binary_path.to_path_buf())
        });
    if let Some(binary_dir) = absolute_binary.parent() {
        let relative_binary_dir = binary_dir
            .strip_prefix(Path::new("/"))
            .unwrap_or(binary_dir);
        for search_path in &search_paths {
            add_candidate(
                search_path.join(relative_binary_dir).join(basename),
                DebugFileValidation::DebugLink,
            );
        }
    }

    candidates
}

/// Split `/proc/<pid>/root/<target-path>` into the proc-root prefix and the
/// absolute path as seen by the target.
fn split_proc_root_path(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("proc")
    ) {
        return None;
    }
    let pid = match components.next() {
        Some(Component::Normal(pid)) if pid.to_string_lossy().parse::<u32>().is_ok() => pid,
        _ => return None,
    };
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("root")
    ) {
        return None;
    }

    let proc_root = Path::new("/proc").join(pid).join("root");
    let mut target_path = PathBuf::from("/");
    let remaining = components.as_path();
    if !remaining.as_os_str().is_empty() {
        target_path.push(remaining);
    }
    Some((proc_root, target_path))
}

fn path_below_proc_root(proc_root: &Path, path: &Path) -> PathBuf {
    if !path.is_absolute() || path.starts_with(proc_root) {
        return path.to_path_buf();
    }

    proc_root.join(path.strip_prefix(Path::new("/")).unwrap_or(path))
}

fn build_id_debug_path(global_debug_dir: &Path, build_id: &[u8]) -> Option<PathBuf> {
    let (first, remainder) = build_id.split_first()?;

    Some(
        global_debug_dir
            .join(".build-id")
            .join(format!("{first:02x}"))
            .join(format!("{}.debug", format_build_id(remainder))),
    )
}

fn verify_build_id_debug_file(debug_file_path: &Path, expected_build_id: &[u8]) -> Result<bool> {
    let file_data = MappedFile::open(debug_file_path)?;
    let debug_obj = file_data.parse_object()?;
    let debug_build_id = debug_obj.build_id().ok().flatten();

    match debug_build_id {
        Some(debug_id) if debug_id == expected_build_id => {
            tracing::info!(
                "Build ID verification passed for {}: {}",
                debug_file_path.display(),
                format_build_id(debug_id)
            );
            Ok(true)
        }
        Some(debug_id) => {
            tracing::error!(
                "Build ID mismatch for {}: expected={}, actual={}",
                debug_file_path.display(),
                format_build_id(expected_build_id),
                format_build_id(debug_id)
            );
            Ok(false)
        }
        None => {
            tracing::error!(
                "Build-ID debug file {} has no build ID",
                debug_file_path.display()
            );
            Ok(false)
        }
    }
}

/// Verify debug file matches binary (CRC + build ID)
///
/// Checks:
/// 1. CRC-32 matches (required by .gnu_debuglink)
/// 2. Build ID matches if present in both files (warning if mismatch)
fn verify_debug_file(
    debug_file_path: &Path,
    expected_crc: u32,
    binary_build_id: Option<&[u8]>,
) -> Result<bool> {
    let file_data = MappedFile::open(debug_file_path)?;

    // 1. Verify CRC-32
    let actual_crc = calculate_gnu_debuglink_crc(file_data.as_bytes());

    if actual_crc != expected_crc {
        tracing::error!(
            "CRC mismatch for {}: expected=0x{:08x}, actual=0x{:08x}",
            debug_file_path.display(),
            expected_crc,
            actual_crc
        );
        return Ok(false);
    }
    tracing::info!(
        "CRC verification passed for {}: 0x{:08x}",
        debug_file_path.display(),
        actual_crc
    );

    // 2. Verify build ID if present
    let debug_obj = file_data.parse_object()?;
    let debug_build_id = debug_obj.build_id().ok().flatten();

    match (binary_build_id, debug_build_id) {
        (Some(binary_id), Some(debug_id)) => {
            if binary_id != debug_id {
                tracing::error!(
                    "Build ID mismatch for {}: binary={:02x?}, debug={:02x?}",
                    debug_file_path.display(),
                    binary_id,
                    debug_id
                );
                return Ok(false);
            } else {
                tracing::info!(
                    "Build ID verification passed for {}: binary={:02x?}, debug={:02x?}",
                    debug_file_path.display(),
                    binary_id,
                    debug_id
                );
            }
        }
        (Some(binary_id), None) => {
            tracing::info!(
                "Binary has Build ID {:02x?} but debug file has none (CRC matched)",
                binary_id
            );
        }
        (None, Some(debug_id)) => {
            tracing::info!(
                "Debug file has Build ID {:02x?} but binary has none (CRC matched)",
                debug_id
            );
        }
        (None, None) => {
            tracing::info!("Neither binary nor debug file has Build ID (CRC matched)");
        }
    }

    Ok(true)
}

/// Calculate CRC-32 using GNU debuglink algorithm
///
/// This uses the IEEE 802.3 polynomial (same as standard CRC-32)
/// Note: GNU debuglink uses specific CRC-32 variant
fn calculate_gnu_debuglink_crc(data: &[u8]) -> u32 {
    // Use crc32fast crate for standard CRC-32 (IEEE polynomial)
    crc32fast::hash(data)
}

/// Try to load debug file if available, otherwise return None
///
/// This is the main entry point for loading debug info
pub fn try_load_debug_file<P: AsRef<Path>>(
    binary_path: P,
    user_search_paths: &[String],
    allow_loose_debug_match: bool,
) -> Result<Option<MappedFile>> {
    let binary_path = binary_path.as_ref();

    match find_debug_file(binary_path, user_search_paths, allow_loose_debug_match)? {
        Some(debug_path) => {
            tracing::info!(
                "Loading debug info from separate file: {}",
                debug_path.display()
            );
            Ok(Some(MappedFile::open(&debug_path)?))
        }
        None => Ok(None),
    }
}

/// Load a user-provided debug file after verifying it belongs to `binary_path`.
///
/// Unlike `.gnu_debuglink` auto-discovery, an explicit debug file may be used
/// even when the target binary has no debuglink section. When a debuglink CRC or
/// Build ID comparison is available, strict mode rejects mismatches.
pub fn load_explicit_debug_file<P: AsRef<Path>, Q: AsRef<Path>>(
    binary_path: P,
    debug_file_path: Q,
    allow_loose_debug_match: bool,
) -> Result<MappedFile> {
    let binary_path = binary_path.as_ref();
    let debug_file_path = debug_file_path.as_ref();

    let binary_data = MappedFile::open(binary_path)
        .with_context(|| format!("failed to open target binary {}", binary_path.display()))?;
    let binary_obj = binary_data
        .parse_object()
        .with_context(|| format!("failed to parse target binary {}", binary_path.display()))?;
    let binary_build_id = binary_obj.build_id().ok().flatten();
    let expected_crc = match binary_obj.gnu_debuglink() {
        Ok(Some((_filename, crc))) => Some(crc),
        Ok(None) => None,
        Err(err) => {
            tracing::warn!(
                "Failed to read .gnu_debuglink from {} while validating explicit debug file {}: {}",
                binary_path.display(),
                debug_file_path.display(),
                err
            );
            None
        }
    };

    let debug_data = MappedFile::open(debug_file_path)
        .with_context(|| format!("failed to open debug file {}", debug_file_path.display()))?;
    verify_explicit_debug_file(
        binary_path,
        debug_file_path,
        &debug_data,
        expected_crc,
        binary_build_id,
        allow_loose_debug_match,
    )?;

    Ok(debug_data)
}

fn verify_explicit_debug_file(
    binary_path: &Path,
    debug_file_path: &Path,
    debug_data: &MappedFile,
    expected_crc: Option<u32>,
    binary_build_id: Option<&[u8]>,
    allow_loose_debug_match: bool,
) -> Result<()> {
    if let Some(expected_crc) = expected_crc {
        let actual_crc = calculate_gnu_debuglink_crc(debug_data.as_bytes());
        if actual_crc != expected_crc {
            let message = format!(
                "Explicit debug file {} failed CRC verification for {}: expected=0x{:08x}, actual=0x{:08x}",
                debug_file_path.display(),
                binary_path.display(),
                expected_crc,
                actual_crc
            );
            if allow_loose_debug_match {
                tracing::warn!("{}; loose match enabled -> using it", message);
            } else {
                return Err(anyhow::anyhow!(message));
            }
        } else {
            tracing::info!(
                "Explicit debug file CRC verification passed for {}: 0x{:08x}",
                debug_file_path.display(),
                actual_crc
            );
        }
    } else {
        tracing::info!(
            "No .gnu_debuglink CRC available in {}; validating explicit debug file {} by Build ID when possible",
            binary_path.display(),
            debug_file_path.display()
        );
    }

    let debug_obj = debug_data
        .parse_object()
        .with_context(|| format!("failed to parse debug file {}", debug_file_path.display()))?;
    let debug_build_id = debug_obj.build_id().ok().flatten();

    match (binary_build_id, debug_build_id) {
        (Some(binary_id), Some(debug_id)) if binary_id != debug_id => {
            let message = format!(
                "Explicit debug file {} Build ID mismatch for {}: binary={}, debug={}",
                debug_file_path.display(),
                binary_path.display(),
                format_build_id(binary_id),
                format_build_id(debug_id)
            );
            if allow_loose_debug_match {
                tracing::warn!("{}; loose match enabled -> using it", message);
            } else {
                return Err(anyhow::anyhow!(message));
            }
        }
        (Some(binary_id), Some(debug_id)) => {
            tracing::info!(
                "Explicit debug file Build ID verification passed for {}: binary={}, debug={}",
                debug_file_path.display(),
                format_build_id(binary_id),
                format_build_id(debug_id)
            );
        }
        (Some(binary_id), None) => {
            tracing::warn!(
                "Target binary {} has Build ID {} but explicit debug file {} has none",
                binary_path.display(),
                format_build_id(binary_id),
                debug_file_path.display()
            );
        }
        (None, Some(debug_id)) => {
            tracing::warn!(
                "Explicit debug file {} has Build ID {} but target binary {} has none",
                debug_file_path.display(),
                format_build_id(debug_id),
                binary_path.display()
            );
        }
        (None, None) => {
            tracing::warn!(
                "Neither target binary {} nor explicit debug file {} has Build ID",
                binary_path.display(),
                debug_file_path.display()
            );
        }
    }

    Ok(())
}

fn format_build_id(build_id: &[u8]) -> String {
    let mut hex = String::with_capacity(build_id.len() * 2);
    for byte in build_id {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_id_note(build_id: &[u8]) -> Vec<u8> {
        let mut note = Vec::new();
        note.extend_from_slice(&4_u32.to_le_bytes());
        note.extend_from_slice(&u32::try_from(build_id.len()).unwrap().to_le_bytes());
        note.extend_from_slice(&object::elf::NT_GNU_BUILD_ID.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(build_id);
        while !note.len().is_multiple_of(4) {
            note.push(0);
        }
        note
    }

    fn debuglink_section(filename: &str, crc: u32) -> Vec<u8> {
        let mut data = filename.as_bytes().to_vec();
        data.push(0);
        while !data.len().is_multiple_of(4) {
            data.push(0);
        }
        data.extend_from_slice(&crc.to_le_bytes());
        data
    }

    fn elf_bytes(build_id: &[u8], debug_link: Option<(&str, u32)>) -> Vec<u8> {
        let mut object = object::write::Object::new(
            object::BinaryFormat::Elf,
            object::Architecture::X86_64,
            object::Endianness::Little,
        );
        let note = object.add_section(
            Vec::new(),
            b".note.gnu.build-id".to_vec(),
            object::SectionKind::Note,
        );
        object
            .section_mut(note)
            .set_data(build_id_note(build_id), 4);
        if let Some((filename, crc)) = debug_link {
            let section = object.add_section(
                Vec::new(),
                b".gnu_debuglink".to_vec(),
                object::SectionKind::ReadOnlyData,
            );
            object
                .section_mut(section)
                .set_data(debuglink_section(filename, crc), 4);
        }
        object.write().unwrap()
    }

    fn build_search_paths(
        binary_path: &Path,
        debug_filename: &Path,
        user_search_paths: &[String],
    ) -> Vec<PathBuf> {
        build_search_candidates(binary_path, Some(debug_filename), None, user_search_paths)
            .into_iter()
            .map(|candidate| candidate.path)
            .collect()
    }

    #[test]
    fn discovers_debuglink_in_mirrored_global_directory() {
        let temp = tempfile::tempdir().unwrap();
        let binary_dir = temp.path().join("opt/example/bin");
        let global_debug_dir = temp.path().join("debug-root");
        std::fs::create_dir_all(&binary_dir).unwrap();

        let build_id = [0x10, 0x20, 0x30, 0x40];
        let debug_bytes = elf_bytes(&build_id, None);
        let crc = calculate_gnu_debuglink_crc(&debug_bytes);
        let binary_path = binary_dir.join("example");
        std::fs::write(
            &binary_path,
            elf_bytes(&build_id, Some(("example.debug", crc))),
        )
        .unwrap();

        let relative_binary_dir = binary_path
            .canonicalize()
            .unwrap()
            .parent()
            .unwrap()
            .strip_prefix(Path::new("/"))
            .unwrap()
            .to_path_buf();
        let debug_path = global_debug_dir
            .join(relative_binary_dir)
            .join("example.debug");
        std::fs::create_dir_all(debug_path.parent().unwrap()).unwrap();
        std::fs::write(&debug_path, debug_bytes).unwrap();

        let found = find_debug_file(
            &binary_path,
            &[global_debug_dir.to_string_lossy().into_owned()],
            false,
        )
        .unwrap();
        assert_eq!(found.as_deref(), Some(debug_path.as_path()));
    }

    #[test]
    fn discovers_build_id_file_without_debuglink() {
        let temp = tempfile::tempdir().unwrap();
        let global_debug_dir = temp.path().join("debug-root");
        let binary_path = temp.path().join("example");
        let build_id = [0xab, 0xcd, 0xef, 0x12, 0x34];
        let bytes = elf_bytes(&build_id, None);
        std::fs::write(&binary_path, &bytes).unwrap();

        let debug_path = build_id_debug_path(&global_debug_dir, &build_id).unwrap();
        std::fs::create_dir_all(debug_path.parent().unwrap()).unwrap();
        std::fs::write(&debug_path, bytes).unwrap();

        let found = find_debug_file(
            &binary_path,
            &[global_debug_dir.to_string_lossy().into_owned()],
            false,
        )
        .unwrap();
        assert_eq!(found.as_deref(), Some(debug_path.as_path()));
    }

    #[test]
    fn discovers_one_byte_build_id_file_without_debuglink() {
        let temp = tempfile::tempdir().unwrap();
        let global_debug_dir = temp.path().join("debug-root");
        let binary_path = temp.path().join("example");
        let build_id = [0xab];
        let bytes = elf_bytes(&build_id, None);
        std::fs::write(&binary_path, &bytes).unwrap();

        let debug_path = build_id_debug_path(&global_debug_dir, &build_id).unwrap();
        assert_eq!(debug_path, global_debug_dir.join(".build-id/ab/.debug"));
        std::fs::create_dir_all(debug_path.parent().unwrap()).unwrap();
        std::fs::write(&debug_path, bytes).unwrap();

        let found = find_debug_file(
            &binary_path,
            &[global_debug_dir.to_string_lossy().into_owned()],
            false,
        )
        .unwrap();
        assert_eq!(found.as_deref(), Some(debug_path.as_path()));
    }

    #[test]
    fn test_build_search_paths_no_user_paths() {
        let binary_path = Path::new("/usr/bin/my_program");
        let debug_filename = Path::new("my_program.debug");

        let paths = build_search_paths(binary_path, debug_filename, &[]);

        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[1], Path::new("/usr/bin/.debug/my_program.debug"));
    }

    #[test]
    fn test_build_search_paths_with_user_paths() {
        let binary_path = Path::new("/usr/bin/my_program");
        let debug_filename = Path::new("my_program.debug");
        let user_paths = vec!["/opt/debug".to_string(), "/home/user/.debug".to_string()];

        let paths = build_search_paths(binary_path, debug_filename, &user_paths);

        // Two flat candidates and one mirrored candidate per configured path,
        // plus the two locations next to the binary.
        assert_eq!(paths.len(), 8);

        // User paths come first (highest priority)
        assert_eq!(paths[0], Path::new("/opt/debug/my_program.debug"));
        assert_eq!(paths[1], Path::new("/opt/debug/.debug/my_program.debug"));
        assert_eq!(paths[2], Path::new("/home/user/.debug/my_program.debug"));
        assert_eq!(
            paths[3],
            Path::new("/home/user/.debug/.debug/my_program.debug")
        );

        // Then locations next to the binary.
        assert_eq!(paths[4], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[5], Path::new("/usr/bin/.debug/my_program.debug"));

        // Finally, GDB-compatible mirrored global debug directories.
        assert_eq!(paths[6], Path::new("/opt/debug/usr/bin/my_program.debug"));
        assert_eq!(
            paths[7],
            Path::new("/home/user/.debug/usr/bin/my_program.debug")
        );
    }

    #[test]
    fn test_expand_home_dir() {
        let expanded = expand_home_dir("~/test/path");

        // Should replace ~ with home directory
        if let Some(home) = dirs::home_dir() {
            assert_eq!(expanded, home.join("test/path"));
        }

        // Non-home paths should be unchanged
        let regular_path = expand_home_dir("/usr/local/debug");
        assert_eq!(regular_path, Path::new("/usr/local/debug"));
    }

    #[test]
    fn test_path_deduplication() {
        // Test that duplicate paths are removed
        let binary_path = Path::new("/usr/bin/my_program");
        let debug_filename = Path::new("my_program.debug");
        // Configure /usr/bin which is the same as binary directory
        let user_paths = vec!["/usr/bin".to_string()];

        let paths = build_search_paths(binary_path, debug_filename, &user_paths);

        // Should deduplicate:
        // User path: /usr/bin/my_program.debug (same as standard path #1)
        // User path: /usr/bin/.debug/my_program.debug (same as standard path #2)
        // Standard: /usr/bin/my_program.debug (duplicate, skipped)
        // Standard: /usr/bin/.debug/my_program.debug (duplicate, skipped)
        // Mirrored: /usr/bin/usr/bin/my_program.debug
        assert_eq!(paths.len(), 3);

        // Verify user paths come first (priority)
        assert_eq!(paths[0], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[1], Path::new("/usr/bin/.debug/my_program.debug"));
        assert_eq!(paths[2], Path::new("/usr/bin/usr/bin/my_program.debug"));
    }

    #[test]
    fn test_absolute_path_debug_filename() {
        // Test handling of absolute path in debug_filename
        let binary_path = Path::new("/usr/bin/my_program");
        let debug_filename = Path::new("/usr/lib/debug/my_program.debug");
        let user_paths = vec!["/opt/debug".to_string()];

        let paths = build_search_paths(binary_path, debug_filename, &user_paths);

        // Should try:
        // 1. Absolute path first: /usr/lib/debug/my_program.debug
        // 2. Extract basename (my_program.debug) and search in user paths
        // 3. Extract basename and search in standard locations

        // First path should be the absolute path
        assert_eq!(paths[0], Path::new("/usr/lib/debug/my_program.debug"));

        // Then user-configured paths with basename
        assert_eq!(paths[1], Path::new("/opt/debug/my_program.debug"));
        assert_eq!(paths[2], Path::new("/opt/debug/.debug/my_program.debug"));

        // Then standard paths with basename
        assert_eq!(paths[3], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[4], Path::new("/usr/bin/.debug/my_program.debug"));
        assert_eq!(paths[5], Path::new("/opt/debug/usr/bin/my_program.debug"));

        // Verify basename was correctly extracted
        assert!(paths
            .iter()
            .all(|p| p.file_name().unwrap() == "my_program.debug"));
    }

    #[test]
    fn test_gdb_global_debug_directory_layout() {
        let binary_path = Path::new("/usr/bin/ls");
        let debug_filename = Path::new("ls.debug");
        let user_paths = vec!["/usr/lib/debug".to_string()];
        let build_id = [0xab, 0xcd, 0xef, 0x12, 0x34];

        let candidates = build_search_candidates(
            binary_path,
            Some(debug_filename),
            Some(&build_id),
            &user_paths,
        );

        assert_eq!(
            candidates[0],
            DebugFileCandidate {
                path: PathBuf::from("/usr/lib/debug/.build-id/ab/cdef1234.debug"),
                validation: DebugFileValidation::BuildId,
            }
        );
        assert!(candidates.iter().any(|candidate| {
            candidate.path == Path::new("/usr/lib/debug/usr/bin/ls.debug")
                && candidate.validation == DebugFileValidation::DebugLink
        }));
    }

    #[test]
    fn test_proc_root_searches_host_and_target_debug_directories() {
        let binary_path = Path::new("/proc/1234/root/usr/bin/ls");
        let debug_filename = Path::new("ls.debug");
        let user_paths = vec!["/usr/lib/debug".to_string()];
        let build_id = [0xab, 0xcd, 0xef];

        let candidates = build_search_candidates(
            binary_path,
            Some(debug_filename),
            Some(&build_id),
            &user_paths,
        );

        for (path, validation) in [
            (
                "/usr/lib/debug/.build-id/ab/cdef.debug",
                DebugFileValidation::BuildId,
            ),
            (
                "/proc/1234/root/usr/lib/debug/.build-id/ab/cdef.debug",
                DebugFileValidation::BuildId,
            ),
            (
                "/usr/lib/debug/usr/bin/ls.debug",
                DebugFileValidation::DebugLink,
            ),
            (
                "/proc/1234/root/usr/lib/debug/usr/bin/ls.debug",
                DebugFileValidation::DebugLink,
            ),
        ] {
            assert!(
                candidates.iter().any(|candidate| {
                    candidate.path == Path::new(path) && candidate.validation == validation
                }),
                "missing {validation:?} candidate {path} from {candidates:#?}"
            );
        }
    }

    #[test]
    fn test_build_id_lookup_does_not_require_debuglink() {
        let user_paths = vec!["/opt/debug".to_string()];
        let build_id = [0x12, 0x34, 0x56, 0x78];

        let candidates = build_search_candidates(
            Path::new("/usr/bin/example"),
            None,
            Some(&build_id),
            &user_paths,
        );

        assert_eq!(
            candidates,
            vec![DebugFileCandidate {
                path: PathBuf::from("/opt/debug/.build-id/12/345678.debug"),
                validation: DebugFileValidation::BuildId,
            }]
        );
    }

    #[test]
    fn test_crc_calculation() {
        // Test with known data
        let data = b"hello world";
        let crc = calculate_gnu_debuglink_crc(data);

        // CRC-32 (IEEE) for "hello world" is 0x0d4a1185
        assert_eq!(crc, 0x0d4a1185);
    }
}

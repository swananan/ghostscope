//! Support for .gnu_debuglink section - find separate debug info files
//!
//! This module implements the standard GNU debuglink mechanism for locating
//! debug information in separate files, following GDB's search strategy.

use crate::core::Result;
use object::Object;
use std::collections::HashSet;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Find separate debug file using .gnu_debuglink section
///
/// Search order (following GDB conventions):
/// 1. Absolute path (if .gnu_debuglink contains an absolute path)
/// 2. User-configured search paths + basename (from config file, highest priority)
/// 3. Same directory as binary + basename
/// 4. .debug subdirectory + basename
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
/// For system-wide debug directories (like /usr/lib/debug), configure them in search_paths.
///
/// Returns the path to the debug file if found and CRC matches
/// Also verifies build ID if present in both files
pub fn find_debug_file<P: AsRef<Path>>(
    binary_path: P,
    user_search_paths: &[String],
    allow_loose_debug_match: bool,
) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();

    // Read binary and check for .gnu_debuglink section
    let binary_data = std::fs::read(binary_path)?;
    let binary_obj = object::File::parse(&*binary_data)?;

    // Extract build ID from binary for later verification
    let binary_build_id = binary_obj.build_id().ok().flatten();

    // Check if .gnu_debuglink section exists
    let (debug_filename, expected_crc) = match binary_obj.gnu_debuglink() {
        Ok(Some((filename, crc))) => (filename, crc),
        Ok(None) => {
            // No .gnu_debuglink section - binary contains debug info
            tracing::debug!("No .gnu_debuglink section in {}", binary_path.display());
            return Ok(None);
        }
        Err(e) => {
            tracing::warn!(
                "Failed to read .gnu_debuglink from {}: {}",
                binary_path.display(),
                e
            );
            return Ok(None);
        }
    };

    // Convert filename bytes to PathBuf (Linux-only, as GhostScope is an eBPF project)
    use std::os::unix::ffi::OsStrExt;
    let os_str = std::ffi::OsStr::from_bytes(debug_filename);
    let debug_filename = Path::new(os_str);

    tracing::info!(
        "Looking for debug file '{}' for binary '{}'",
        debug_filename.display(),
        binary_path.display()
    );

    // Build search paths following GDB's strategy
    let search_paths = build_search_paths(binary_path, debug_filename, user_search_paths);

    // Try each path and verify CRC + build ID
    for candidate_path in search_paths {
        tracing::debug!("Checking debug file path: {}", candidate_path.display());

        if candidate_path.exists() {
            match verify_debug_file(&candidate_path, expected_crc, binary_build_id) {
                Ok(true) => {
                    tracing::info!(
                        "Found matching debug file: {} (CRC: 0x{:08x})",
                        candidate_path.display(),
                        expected_crc
                    );
                    return Ok(Some(candidate_path));
                }
                Ok(false) => {
                    if allow_loose_debug_match {
                        tracing::warn!(
                            "Debug file {} exists but verification failed; loose match enabled -> using it",
                            candidate_path.display()
                        );
                        return Ok(Some(candidate_path));
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

    tracing::warn!(
        "Debug file '{}' not found in any standard location",
        debug_filename.display()
    );
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

/// Build search paths for debug file following GDB conventions
///
/// Search order (highest priority first):
/// 1. Absolute path (if debug_filename is absolute)
/// 2. User-configured search paths (from config file)
/// 3. Same directory as binary
/// 4. .debug subdirectory
///
/// Note:
/// - If debug_filename is an absolute path, it will be tried first, then basename extracted
/// - Paths are deduplicated to avoid redundant filesystem checks
/// - Global debug directories (like /usr/lib/debug) should be configured via search_paths
fn build_search_paths(
    binary_path: &Path,
    debug_filename: &Path,
    user_search_paths: &[String],
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = HashSet::new();

    // Helper to add path only if not already seen
    let mut add_path = |path: PathBuf| {
        if seen.insert(path.clone()) {
            paths.push(path);
        }
    };

    // 1. If debug_filename is an absolute path, try it first
    if debug_filename.is_absolute() {
        add_path(debug_filename.to_path_buf());
    }

    // Extract basename for searching in configured paths
    // This handles both absolute paths (e.g., /usr/lib/debug/foo.debug -> foo.debug)
    // and relative paths (e.g., foo.debug -> foo.debug)
    let basename = debug_filename
        .file_name()
        .map(Path::new)
        .unwrap_or(debug_filename);

    // 2. User-configured search paths (highest priority)
    // For each user path, try both:
    //   - user_path/basename
    //   - user_path/.debug/basename
    for user_path in user_search_paths {
        let expanded = expand_home_dir(user_path);
        add_path(expanded.join(basename));
        add_path(expanded.join(".debug").join(basename));
    }

    // Get binary directory
    let binary_dir = binary_path.parent();

    // 3. Same directory as binary
    if let Some(dir) = binary_dir {
        add_path(dir.join(basename));
    }

    // 4. .debug subdirectory
    if let Some(dir) = binary_dir {
        add_path(dir.join(".debug").join(basename));
    }

    // Note: Global debug directories (like /usr/lib/debug) should be configured
    // in user_search_paths if needed. This avoids generating nonsensical paths
    // like /usr/lib/debug/mnt/500g/... for non-system binaries.

    paths
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
    let file_data = std::fs::read(debug_file_path)?;

    // 1. Verify CRC-32
    let actual_crc = calculate_gnu_debuglink_crc(&file_data);

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
    let debug_obj = object::File::parse(&*file_data)?;
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
) -> Result<Option<(PathBuf, memmap2::Mmap)>> {
    let binary_path = binary_path.as_ref();

    match find_debug_file(binary_path, user_search_paths, allow_loose_debug_match)? {
        Some(debug_path) => {
            tracing::info!(
                "Loading debug info from separate file: {}",
                debug_path.display()
            );

            let file = File::open(&debug_path)?;
            let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

            Ok(Some((debug_path, mmap)))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        // Should have: 2 user paths * 2 (direct + .debug) + 2 standard paths = 6 total
        assert_eq!(paths.len(), 6);

        // User paths come first (highest priority)
        assert_eq!(paths[0], Path::new("/opt/debug/my_program.debug"));
        assert_eq!(paths[1], Path::new("/opt/debug/.debug/my_program.debug"));
        assert_eq!(paths[2], Path::new("/home/user/.debug/my_program.debug"));
        assert_eq!(
            paths[3],
            Path::new("/home/user/.debug/.debug/my_program.debug")
        );

        // Then standard paths
        assert_eq!(paths[4], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[5], Path::new("/usr/bin/.debug/my_program.debug"));
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
        assert_eq!(paths.len(), 2); // Only 2 unique paths

        // Verify user paths come first (priority)
        assert_eq!(paths[0], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[1], Path::new("/usr/bin/.debug/my_program.debug"));
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

        // Verify basename was correctly extracted
        assert!(paths
            .iter()
            .all(|p| p.file_name().unwrap() == "my_program.debug"));
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

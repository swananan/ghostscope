//! Support for .gnu_debuglink section - find separate debug info files
//!
//! This module implements the standard GNU debuglink mechanism for locating
//! debug information in separate files, following GDB's search strategy.

use crate::core::Result;
use object::Object;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Find separate debug file using .gnu_debuglink section
///
/// Search order (following GDB conventions):
/// 1. Same directory as binary: /path/to/binary.debug
/// 2. .debug subdirectory: /path/to/.debug/binary.debug
/// 3. Global debug directory: /usr/lib/debug/path/to/binary.debug
///
/// Returns the path to the debug file if found and CRC matches
/// Also verifies build ID if present in both files
pub fn find_debug_file<P: AsRef<Path>>(binary_path: P) -> Result<Option<PathBuf>> {
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
    let search_paths = build_search_paths(binary_path, debug_filename);

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
                    tracing::warn!(
                        "Debug file {} exists but verification failed (CRC or build ID mismatch)",
                        candidate_path.display()
                    );
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

/// Build search paths for debug file following GDB conventions
fn build_search_paths(binary_path: &Path, debug_filename: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // Get binary directory
    let binary_dir = binary_path.parent();

    // 1. Same directory as binary
    if let Some(dir) = binary_dir {
        paths.push(dir.join(debug_filename));
    }

    // 2. .debug subdirectory
    if let Some(dir) = binary_dir {
        paths.push(dir.join(".debug").join(debug_filename));
    }

    // 3. Global debug directory with full path structure
    // For /usr/bin/foo -> /usr/lib/debug/usr/bin/foo.debug
    if binary_path.is_absolute() {
        let global_debug_path = PathBuf::from("/usr/lib/debug")
            .join(binary_path.strip_prefix("/").unwrap_or(binary_path))
            .with_file_name(debug_filename);
        paths.push(global_debug_path);
    }

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

    tracing::debug!(
        "CRC check for {}: expected=0x{:08x}, actual=0x{:08x}",
        debug_file_path.display(),
        expected_crc,
        actual_crc
    );

    if actual_crc != expected_crc {
        tracing::warn!(
            "CRC mismatch for {}: expected=0x{:08x}, actual=0x{:08x}",
            debug_file_path.display(),
            expected_crc,
            actual_crc
        );
        return Ok(false);
    }

    // 2. Verify build ID if present
    let debug_obj = object::File::parse(&*file_data)?;
    let debug_build_id = debug_obj.build_id().ok().flatten();

    match (binary_build_id, debug_build_id) {
        (Some(binary_id), Some(debug_id)) => {
            if binary_id != debug_id {
                tracing::warn!(
                    "Build ID mismatch for {}: binary={:02x?}, debug={:02x?}",
                    debug_file_path.display(),
                    binary_id,
                    debug_id
                );
                // According to GDB behavior: CRC takes priority, build ID mismatch is just a warning
                // We still return true if CRC matches
                tracing::warn!(
                    "CRC matches but build IDs differ - using debug file anyway (following GDB behavior)"
                );
            } else {
                tracing::debug!(
                    "Build ID verification passed for {}: {:02x?}",
                    debug_file_path.display(),
                    binary_id
                );
            }
        }
        (Some(binary_id), None) => {
            tracing::debug!(
                "Binary has build ID {:02x?} but debug file has none",
                binary_id
            );
        }
        (None, Some(debug_id)) => {
            tracing::debug!(
                "Debug file has build ID {:02x?} but binary has none",
                debug_id
            );
        }
        (None, None) => {
            tracing::debug!("Neither binary nor debug file has build ID");
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
) -> Result<Option<(PathBuf, memmap2::Mmap)>> {
    let binary_path = binary_path.as_ref();

    match find_debug_file(binary_path)? {
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
    fn test_build_search_paths() {
        let binary_path = Path::new("/usr/bin/my_program");
        let debug_filename = Path::new("my_program.debug");

        let paths = build_search_paths(binary_path, debug_filename);

        assert_eq!(paths.len(), 3);
        assert_eq!(paths[0], Path::new("/usr/bin/my_program.debug"));
        assert_eq!(paths[1], Path::new("/usr/bin/.debug/my_program.debug"));
        assert_eq!(
            paths[2],
            Path::new("/usr/lib/debug/usr/bin/my_program.debug")
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

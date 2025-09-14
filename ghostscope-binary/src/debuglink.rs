use crate::{BinaryError, Result};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// Find debug information file using various methods
pub(crate) fn find_debug_info<P: AsRef<Path>>(binary_path: P) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();
    info!("Searching for debug info for: {}", binary_path.display());

    // First, check if the binary itself has debug information
    if has_debug_sections(binary_path)? {
        debug!("Binary contains debug sections");
        return Ok(Some(binary_path.to_path_buf()));
    }

    // Try to find separate debug file via .gnu_debuglink
    if let Some(debug_path) = find_via_debuglink(binary_path)? {
        return Ok(Some(debug_path));
    }

    // Try to find compressed debug data via .gnu_debugdata (Android/compressed)
    if let Some(debug_path) = find_via_debugdata(binary_path)? {
        return Ok(Some(debug_path));
    }

    // Try common debug file locations
    if let Some(debug_path) = find_via_common_paths(binary_path)? {
        return Ok(Some(debug_path));
    }

    warn!("No debug information found for {}", binary_path.display());
    Ok(None)
}

/// Check if binary has debug sections
fn has_debug_sections<P: AsRef<Path>>(path: P) -> Result<bool> {
    crate::elf::has_section(path, ".debug_info")
}

/// Find debug file via .gnu_debuglink section
fn find_via_debuglink<P: AsRef<Path>>(binary_path: P) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();

    // Read .gnu_debuglink section
    let debuglink_data = match crate::elf::get_section_data(binary_path, ".gnu_debuglink")? {
        Some(data) => data,
        None => {
            debug!("No .gnu_debuglink section found");
            return Ok(None);
        }
    };

    // Parse debuglink data
    let (debug_filename, _crc) = parse_debuglink(&debuglink_data)?;
    info!("Found debug link to: {}", debug_filename);

    // Search for debug file in standard locations
    let search_paths = get_debug_search_paths(binary_path);

    for search_path in search_paths {
        let candidate = search_path.join(&debug_filename);
        debug!("Checking debug file candidate: {}", candidate.display());

        if candidate.exists() && candidate.is_file() {
            // TODO: Verify CRC32 checksum
            info!("Found debug file: {}", candidate.display());
            return Ok(Some(candidate));
        }
    }

    warn!(
        "Debug file '{}' not found in standard locations",
        debug_filename
    );
    Ok(None)
}

/// Parse .gnu_debuglink section data
fn parse_debuglink(data: &[u8]) -> Result<(String, u32)> {
    if data.len() < 8 {
        return Err(BinaryError::InvalidDebugLink(
            "Section too short".to_string(),
        ));
    }

    // Find null terminator for filename
    let null_pos = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| BinaryError::InvalidDebugLink("No null terminator found".to_string()))?;

    // Extract filename
    let filename = String::from_utf8(data[..null_pos].to_vec())
        .map_err(|_| BinaryError::InvalidDebugLink("Invalid UTF-8 in filename".to_string()))?;

    // CRC32 is stored after null terminator, aligned to 4 bytes
    let crc_offset = ((null_pos + 1) + 3) & !3; // Align to 4-byte boundary

    if crc_offset + 4 > data.len() {
        return Err(BinaryError::InvalidDebugLink("CRC32 not found".to_string()));
    }

    // Read CRC32 (little-endian)
    let crc = u32::from_le_bytes([
        data[crc_offset],
        data[crc_offset + 1],
        data[crc_offset + 2],
        data[crc_offset + 3],
    ]);

    debug!("Parsed debuglink: filename='{}', crc={:08x}", filename, crc);
    Ok((filename, crc))
}

/// Find debug info via .gnu_debugdata section (compressed debug data, common on Android)
fn find_via_debugdata<P: AsRef<Path>>(binary_path: P) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();

    // Check if .gnu_debugdata section exists
    let debugdata_data = match crate::elf::get_section_data(binary_path, ".gnu_debugdata")? {
        Some(data) => data,
        None => {
            debug!("No .gnu_debugdata section found");
            return Ok(None);
        }
    };

    info!(
        "Found .gnu_debugdata section with {} bytes of compressed data",
        debugdata_data.len()
    );

    // TODO: Implement LZMA decompression and temporary file extraction
    // For now, we'll just indicate that compressed debug data was found but not yet supported
    warn!(".gnu_debugdata section found but decompression not yet implemented");
    warn!("This is commonly used on Android systems with compressed debug info");
    warn!("Consider using --debug-file to specify a pre-extracted debug file");

    Ok(None)
}

/// Get standard search paths for debug files
fn get_debug_search_paths<P: AsRef<Path>>(binary_path: P) -> Vec<PathBuf> {
    let binary_path = binary_path.as_ref();
    let mut paths = Vec::new();

    // Same directory as binary
    if let Some(parent) = binary_path.parent() {
        paths.push(parent.to_path_buf());
    }

    // .debug subdirectory
    if let Some(parent) = binary_path.parent() {
        paths.push(parent.join(".debug"));
    }

    // Global debug directories
    paths.push(PathBuf::from("/usr/lib/debug"));
    paths.push(PathBuf::from("/usr/local/lib/debug"));

    // Build-id based paths (common on newer systems)
    // Format: /usr/lib/debug/.build-id/ab/cdefg.debug (where abcdefg is build-id)
    // TODO: Implement build-id based lookup
    if let Some(build_id_path) = try_build_id_path(binary_path) {
        paths.push(build_id_path);
    }

    debug!("Debug search paths: {:?}", paths);
    paths
}

/// Find debug file via common naming patterns
fn find_via_common_paths<P: AsRef<Path>>(binary_path: P) -> Result<Option<PathBuf>> {
    let binary_path = binary_path.as_ref();

    // Try common debug file patterns
    let patterns = [
        format!("{}.debug", binary_path.display()),
        format!("{}.dbg", binary_path.display()),
    ];

    for pattern in &patterns {
        let debug_path = PathBuf::from(pattern);
        if debug_path.exists() && debug_path.is_file() {
            debug!(
                "Found debug file via common pattern: {}",
                debug_path.display()
            );
            return Ok(Some(debug_path));
        }
    }

    // Try in .debug subdirectory
    if let Some(parent) = binary_path.parent() {
        if let Some(filename) = binary_path.file_name() {
            let debug_dir = parent.join(".debug");
            let debug_file = debug_dir.join(filename);

            if debug_file.exists() && debug_file.is_file() {
                debug!(
                    "Found debug file in .debug subdirectory: {}",
                    debug_file.display()
                );
                return Ok(Some(debug_file));
            }
        }
    }

    Ok(None)
}

/// Try to construct build-id based debug path
/// Build-ID is typically stored in .note.gnu.build-id section
fn try_build_id_path<P: AsRef<Path>>(_binary_path: P) -> Option<PathBuf> {
    // TODO: Extract build-id from .note.gnu.build-id section
    // Format: /usr/lib/debug/.build-id/ab/cdefg.debug
    // where ab is first 2 chars of build-id, cdefg is rest
    None
}

/// Verify CRC32 checksum of debug file (placeholder)
/// TODO: Implement actual CRC32 verification
pub(crate) fn _verify_debug_crc(debug_path: &Path, expected_crc: u32) -> Result<bool> {
    debug!(
        "TODO: Verify CRC32 {:08x} for {}",
        expected_crc,
        debug_path.display()
    );
    // For now, assume it's correct
    Ok(true)
}

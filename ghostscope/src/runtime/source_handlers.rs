use crate::core::GhostSession;
use ghostscope_ui::{events::*, RuntimeChannels, RuntimeStatus};
use std::collections::HashSet;
use tracing::info;

/// Handle main source request - initialize and display source code files for UI
pub async fn handle_main_source_request(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    let result = try_get_main_source_info(session);

    match result {
        Ok(source_info) => {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::SourceCodeLoaded(source_info));
        }
        Err(error_msg) => {
            info!("Source code loading failed: {}", error_msg);
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::SourceCodeLoadFailed(error_msg));
        }
    }
}

/// Try to get main function source information
fn try_get_main_source_info(session: &mut Option<GhostSession>) -> Result<SourceCodeInfo, String> {
    let session = session.as_mut().ok_or("No active session available")?;
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or("Process analyzer not available. Try reloading the process.")?;

    // Try to find main function first
    let module_address_opt = process_analyzer.lookup_function_address_by_name("main");

    if let Some(addr) = module_address_opt {
        info!(
            "Found main function at address 0x{:x} in module: {}",
            addr.address,
            addr.module_display()
        );

        if let Some(source_location) = process_analyzer.lookup_source_location(&addr) {
            info!(
                "Main function source location (DWARF): {}:{}",
                source_location.file_path, source_location.line_number
            );

            // Apply source path resolution
            let resolved_path = session
                .source_path_resolver
                .resolve(&source_location.file_path)
                .unwrap_or_else(|| std::path::PathBuf::from(&source_location.file_path));

            info!(
                "Resolved source path: {} -> {}",
                source_location.file_path,
                resolved_path.display()
            );

            return Ok(SourceCodeInfo {
                file_path: resolved_path.to_string_lossy().to_string(),
                current_line: Some(source_location.line_number as usize),
            });
        }
    }

    // Main not found or has no source, try fallback
    info!("Main function not found or has no source info, trying fallback");

    // Try to find any function with source location
    if let Some(module_address) = try_find_any_function_with_source(process_analyzer) {
        if let Some(source_location) = process_analyzer.lookup_source_location(&module_address) {
            info!(
                "Fallback function source location (DWARF): {}:{}",
                source_location.file_path, source_location.line_number
            );

            let resolved_path = session
                .source_path_resolver
                .resolve(&source_location.file_path)
                .unwrap_or_else(|| std::path::PathBuf::from(&source_location.file_path));

            return Ok(SourceCodeInfo {
                file_path: resolved_path.to_string_lossy().to_string(),
                current_line: Some(source_location.line_number as usize),
            });
        }
    }

    // Last resort: if we have any file info at all, just show the first file
    if let Ok(grouped) = process_analyzer.get_grouped_file_info_by_module() {
        for (_module_path, files) in grouped {
            if let Some(file) = files.first() {
                let full_path = format!("{}/{}", file.directory, file.basename);
                info!(
                    "Last resort fallback: using first available file: {}",
                    full_path
                );

                let resolved_path = session
                    .source_path_resolver
                    .resolve(&full_path)
                    .unwrap_or_else(|| std::path::PathBuf::from(&full_path));

                return Ok(SourceCodeInfo {
                    file_path: resolved_path.to_string_lossy().to_string(),
                    current_line: Some(1),
                });
            }
        }
    }

    // Absolutely no source information available
    Err(
        "No source code information available. This may be due to:\n\
         1. Binary was compiled without debug symbols (-g flag)\n\
         2. Using stripped binary without separate debug file\n\
         3. Analyzing a library without entry point\n\
         \n\
         💡 Try: Recompile with debug symbols or load a binary with DWARF information"
            .to_string(),
    )
}

/// Try to find any function that has source location information
/// Used as fallback when main function is not available
fn try_find_any_function_with_source(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
) -> Option<ghostscope_dwarf::ModuleAddress> {
    // Try common entry point function names first
    let common_entry_points = [
        "_start", // C/C++ actual entry point
        "__libc_start_main",
        "start",    // Some languages
        "_main",    // Alternative naming
        "WinMain",  // Windows entry
        "wWinMain", // Windows Unicode entry
    ];

    for name in &common_entry_points {
        if let Some(addr) = process_analyzer.lookup_function_address_by_name(name) {
            if process_analyzer.lookup_source_location(&addr).is_some() {
                info!("Fallback: found {} with source info", name);
                return Some(addr);
            }
        }
    }

    // If no common entry point found, try to get any function with source info
    // Get all available functions from the file info
    if let Ok(grouped) = process_analyzer.get_grouped_file_info_by_module() {
        for (_module_path, files) in grouped {
            if let Some(file) = files.first() {
                // Try to find a function at the first line of the first file
                let full_path = format!("{}/{}", file.directory, file.basename);

                // Try to look up addresses for the first few lines (expanded range for libraries)
                for line in 1..100 {
                    let addrs = process_analyzer.lookup_addresses_by_source_line(&full_path, line);
                    if let Some(addr) = addrs.first() {
                        info!(
                            "Fallback: using first available source location at {}:{}",
                            full_path, line
                        );
                        return Some(addr.clone());
                    }
                }
            }
        }
    }

    info!("Fallback: no address mapping with source information found");
    None
}

/// Handle request source code - for compatibility with InfoSource command
pub async fn handle_request_source_code(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref session) = session {
        info!("Source code request received");

        match get_grouped_source_files_info(session) {
            Ok(groups) => {
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::FileInfo { groups });
            }
            Err(error) => {
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::FileInfoFailed {
                        error: error.to_string(),
                    });
            }
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::FileInfoFailed {
                error: "No debug session available for source code request".to_string(),
            });
    }
}

/// Get grouped source files information by module for UI
fn get_grouped_source_files_info(session: &GhostSession) -> anyhow::Result<Vec<SourceFileGroup>> {
    use crate::runtime::source_path_resolver::apply_substitutions_to_directory;

    let mut groups = Vec::new();

    if let Some(ref process_analyzer) = session.process_analyzer {
        let grouped = process_analyzer.get_grouped_file_info_by_module()?;

        for (module_path, files) in grouped {
            // Deduplicate by directory+basename per module
            let mut seen = HashSet::new();
            let mut ui_files = Vec::new();
            for file in files {
                // Construct full DWARF path and resolve it using all strategies:
                // 1. Exact path match
                // 2. Path substitution rules (srcpath map)
                // 3. Search directories by basename (srcpath add)
                let dwarf_full_path = format!("{}/{}", file.directory, file.basename);

                let (resolved_dir, resolved_basename) = if let Some(resolved_path) =
                    session.source_path_resolver.resolve(&dwarf_full_path)
                {
                    // Successfully resolved - extract directory and basename from resolved path
                    let resolved_str = resolved_path.to_string_lossy().to_string();
                    if let Some(last_slash) = resolved_str.rfind('/') {
                        let dir = resolved_str[..last_slash].to_string();
                        let basename = resolved_str[last_slash + 1..].to_string();
                        (dir, basename)
                    } else {
                        // No directory separator - use current dir
                        (".".to_string(), resolved_str)
                    }
                } else {
                    // Resolution failed - use substitution-only fallback for directory
                    // This maintains backward compatibility with pure substitution approach
                    let resolved_dir = apply_substitutions_to_directory(
                        &session.source_path_resolver,
                        &file.directory,
                    );
                    (resolved_dir, file.basename.clone())
                };

                let key = format!("{resolved_dir}:{resolved_basename}");
                if seen.insert(key) {
                    ui_files.push(SourceFileInfo {
                        path: resolved_basename,
                        directory: resolved_dir,
                    });
                }
            }

            // Sort files within module by path
            ui_files.sort_by(|a, b| a.path.cmp(&b.path));

            groups.push(SourceFileGroup {
                module_path,
                files: ui_files,
            });
        }
    }

    // Sort modules by path for consistent display
    groups.sort_by(|a, b| a.module_path.cmp(&b.module_path));
    Ok(groups)
}

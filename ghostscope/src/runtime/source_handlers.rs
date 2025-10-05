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

    let module_address = process_analyzer
        .lookup_function_address_by_name("main")
        .ok_or(
            "Main function not found in any loaded module. Ensure the binary has debug symbols.",
        )?;

    info!(
        "Found main function at address 0x{:x} in module: {}",
        module_address.address,
        module_address.module_display()
    );

    match process_analyzer.lookup_source_location(&module_address) {
        Some(source_location) => {
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

            Ok(SourceCodeInfo {
                file_path: resolved_path.to_string_lossy().to_string(),
                current_line: Some(source_location.line_number as usize),
            })
        }
        None => {
            info!("No source location available for main function, using module info");
            Ok(SourceCodeInfo {
                file_path: format!("main function found in {}", module_address.module_display()),
                current_line: Some(1),
            })
        }
    }
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

                let key = format!("{}:{}", resolved_dir, resolved_basename);
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

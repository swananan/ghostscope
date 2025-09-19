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
                "Main function source location: {}:{}",
                source_location.file_path, source_location.line_number
            );

            Ok(SourceCodeInfo {
                file_path: source_location.file_path,
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
    let mut groups = Vec::new();

    if let Some(ref process_analyzer) = session.process_analyzer {
        let grouped = process_analyzer.get_grouped_file_info_by_module()?;

        for (module_path, files) in grouped {
            // Deduplicate by directory+basename per module
            let mut seen = HashSet::new();
            let mut ui_files = Vec::new();
            for file in files {
                let key = format!("{}:{}", file.directory, file.basename);
                if seen.insert(key) {
                    ui_files.push(SourceFileInfo {
                        path: file.basename,
                        directory: file.directory,
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

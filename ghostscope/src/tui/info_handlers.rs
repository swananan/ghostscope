use crate::core::GhostSession;
use ghostscope_dwarf::{AddressQueryResult, FunctionQueryResult, ModuleDefaultPolicy};
use ghostscope_ui::{events::*, RuntimeChannels, RuntimeStatus};
use tracing::info;

/// Handle InfoTrace command
pub async fn handle_info_trace(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    trace_id: u32,
) {
    if let Some(ref session) = session {
        if let Some(snapshot) = session.trace_manager.get_trace_snapshot(trace_id) {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::TraceInfo {
                    trace_id,
                    target: snapshot.target,
                    status: if snapshot.is_enabled {
                        TraceStatus::Active
                    } else {
                        TraceStatus::Disabled
                    },
                    pid: snapshot.pid_context.display_pid(),
                    host_pid: snapshot.pid_context.host_pid,
                    binary: snapshot.binary_path,
                    script_preview: Some(snapshot.script_content),
                    pc: snapshot.pc,
                });
        } else {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::TraceInfoFailed {
                    trace_id,
                    error: "Trace not found".to_string(),
                });
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceInfoFailed {
                trace_id,
                error: "No debug session available".to_string(),
            });
    }
}

/// Handle InfoTraceAll command
pub async fn handle_info_trace_all(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref session) = session {
        let summary = session.trace_manager.get_summary();
        let traces: Vec<TraceDetailInfo> = session
            .trace_manager
            .get_all_trace_ids()
            .into_iter()
            .filter_map(|id| {
                session
                    .trace_manager
                    .get_trace_snapshot(id)
                    .map(|snapshot| TraceDetailInfo {
                        trace_id: id,
                        target_display: snapshot.target_display,
                        binary_path: snapshot.binary_path,
                        pc: snapshot.pc,
                        status: if snapshot.is_enabled {
                            TraceStatus::Active
                        } else {
                            TraceStatus::Disabled
                        },
                        duration: "0s".to_string(),
                    })
            })
            .collect();

        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceInfoAll {
                summary: TraceSummaryInfo {
                    total: summary.total,
                    active: summary.active,
                    disabled: summary.disabled,
                },
                traces,
            });
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceInfoAll {
                summary: TraceSummaryInfo {
                    total: 0,
                    active: 0,
                    disabled: 0,
                },
                traces: vec![],
            });
    }
}

/// Handle InfoSource command
pub async fn handle_info_source(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    crate::tui::source_handlers::handle_request_source_code(session, runtime_channels).await;
}

/// Handle InfoFile command
pub async fn handle_info_file(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref session) = session {
        // Get executable file information from the DWARF analyzer
        if let Some(ref analyzer) = session.process_analyzer {
            // Get primary executable file information
            let file_info = analyzer.get_executable_file_info();

            if let Some(info) = file_info {
                // Convert SectionInfo from ghostscope-dwarf to ghostscope-ui
                let text_section =
                    info.text_section
                        .map(|section| ghostscope_ui::events::SectionInfo {
                            start_address: section.start_address,
                            end_address: section.end_address,
                            size: section.size,
                        });

                let data_section =
                    info.data_section
                        .map(|section| ghostscope_ui::events::SectionInfo {
                            start_address: section.start_address,
                            end_address: section.end_address,
                            size: section.size,
                        });

                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::ExecutableFileInfo {
                        file_path: info.file_path,
                        file_type: info.file_type,
                        entry_point: info.entry_point,
                        has_symbols: info.has_symbols,
                        has_debug_info: info.has_debug_info,
                        debug_file_path: info.debug_file_path,
                        text_section,
                        data_section,
                        mode_description: info.mode_description,
                    });
            } else {
                let _ =
                    runtime_channels
                        .status_sender
                        .send(RuntimeStatus::ExecutableFileInfoFailed {
                            error: "No executable file information available".to_string(),
                        });
            }
        } else {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::ExecutableFileInfoFailed {
                    error: "No process analyzer available".to_string(),
                });
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::ExecutableFileInfoFailed {
                error: "No active debugging session. Target process may not be attached or initialization failed."
                    .to_string(),
            });
    }
}

/// Handle InfoShare command
pub async fn handle_info_share(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref session) = session {
        // Get shared library information from the DWARF analyzer
        if let Some(ref analyzer) = session.process_analyzer {
            let libraries = analyzer.get_shared_library_info();

            // Check if we have any shared libraries
            if libraries.is_empty() && session.is_target_mode() {
                // Target file mode - explain why no shared libraries
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::ShareInfoFailed {
                        error: "No shared libraries found. Launched with target file - only analyzing the specified file. Use PID-based startup to see all loaded libraries in a running process.".to_string(),
                    });
                return;
            }

            let ui_libraries = libraries
                .into_iter()
                .map(|lib| SharedLibraryInfo {
                    from_address: lib.from_address,
                    to_address: lib.to_address,
                    symbols_read: lib.symbols_read,
                    debug_info_available: lib.debug_info_available,
                    library_path: lib.library_path,
                    size: lib.size,
                    debug_file_path: lib.debug_file_path,
                })
                .collect();

            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::ShareInfo {
                    libraries: ui_libraries,
                });
        } else {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::ShareInfoFailed {
                    error: "No process analyzer available".to_string(),
                });
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::ShareInfoFailed {
                error: "No active debugging session. Target process may not be attached or initialization failed."
                    .to_string(),
            });
    }
}

/// Handle InfoFunction command
pub async fn handle_info_function(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    target: String,
    verbose: bool,
) {
    info!(
        "Info function request for: {} (verbose: {})",
        target, verbose
    );

    let result = try_get_function_debug_info(session, &target);

    match result {
        Ok(debug_info) => {
            info!("Successfully retrieved debug info for function: {}", target);
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoFunctionResult {
                    target: target.clone(),
                    info: debug_info,
                    verbose,
                });
        }
        Err(error_msg) => {
            info!(
                "Failed to get debug info for function {}: {}",
                target, error_msg
            );
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoFunctionFailed {
                    target: target.clone(),
                    error: error_msg,
                });
        }
    }
}

/// Handle InfoLine command
pub async fn handle_info_line(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    target: String,
    verbose: bool,
) {
    info!("Info line request for: {} (verbose: {})", target, verbose);

    let result = try_get_line_debug_info(session, &target);

    match result {
        Ok(debug_info) => {
            info!("Successfully retrieved debug info for line: {}", target);
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoLineResult {
                    target: target.clone(),
                    info: debug_info,
                    verbose,
                });
        }
        Err(error_msg) => {
            info!(
                "Failed to get debug info for line {}: {}",
                target, error_msg
            );
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoLineFailed {
                    target: target.clone(),
                    error: error_msg,
                });
        }
    }
}

/// Handle InfoAddress command
pub async fn handle_info_address(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    target: String,
    verbose: bool,
) {
    info!(
        "Info address request for: {} (verbose: {})",
        target, verbose
    );

    // Helper: parse address (hex 0x.. or decimal)
    fn parse_addr(s: &str) -> Result<u64, String> {
        let t = s.trim();
        if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)
                .map_err(|_| format!("Invalid hex address '{s}': must be 0x.."))
        } else {
            t.parse::<u64>()
                .map_err(|_| format!("Invalid address '{s}': use 0x.. or decimal"))
        }
    }

    let result = (|| -> Result<TargetDebugInfo, String> {
        let sess = session.as_mut().ok_or_else(|| {
            "No active debugging session. Target process may not be attached or DWARF symbols are unavailable.".to_string()
        })?;
        let analyzer = sess
            .process_analyzer
            .as_ref()
            .ok_or_else(|| "No process analyzer available".to_string())?;

        // Parse target: either "module:0xADDR" or "0xADDR"
        let (module_spec, addr_str) = if let Some(idx) = target.rfind(':') {
            let (lhs, rhs) = target.split_at(idx);
            (Some(lhs), rhs.trim_start_matches(':'))
        } else {
            (None, target.as_str())
        };

        let vaddr = parse_addr(addr_str)?;
        let module_path = analyzer
            .resolve_address_module(
                module_spec,
                sess.target_binary.as_deref(),
                ModuleDefaultPolicy::MainExecutableOnly,
            )
            .map_err(|e| e.to_string())?;
        let module_display = module_path.to_string_lossy().to_string();

        let address_info = analyzer.query_address(&module_path, vaddr).map_err(|e| {
            format!("Failed to analyze address 0x{vaddr:x} in module '{module_display}': {e}")
        })?;

        Ok(TargetDebugInfo {
            target: if let Some(ms) = module_spec {
                format!("{}:{}", ms.trim(), addr_str.trim())
            } else {
                addr_str.trim().to_string()
            },
            target_type: TargetType::Address,
            file_path: address_info.source_file.clone(),
            line_number: address_info.source_line,
            function_name: address_info.function_name.clone(),
            modules: group_module_debug_info(vec![address_info]),
        })
    })();

    match result {
        Ok(info) => {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoAddressResult {
                    target: target.clone(),
                    info,
                    verbose,
                });
        }
        Err(error_msg) => {
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoAddressFailed {
                    target,
                    error: error_msg,
                });
        }
    }
}

/// Try to get debug info for a function
fn try_get_function_debug_info(
    session: &mut Option<GhostSession>,
    function_name: &str,
) -> Result<TargetDebugInfo, String> {
    let session = session.as_mut().ok_or_else(|| {
        "No active debugging session. Target process may not be attached or DWARF symbols are unavailable."
            .to_string()
    })?;

    let target_path = session.target_binary.clone();
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| "Debug information not available. DWARF symbols may not be loaded or initialization failed.".to_string())?;

    handle_function_target(process_analyzer, function_name, target_path.as_deref())
}

/// Try to get debug info for a source line (file:line)
fn try_get_line_debug_info(
    session: &mut Option<GhostSession>,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    let session = session.as_mut().ok_or_else(|| {
        "No active debugging session. Target process may not be attached or DWARF symbols are unavailable."
            .to_string()
    })?;

    let target_path = session.target_binary.clone();
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| "Debug information not available. DWARF symbols may not be loaded or initialization failed.".to_string())?;

    // Parse original input once
    let (orig_file, line_part) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("Invalid target format '{target}'. Expected format: file:line"))?;
    let line_number = line_part
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{line_part}' in target '{target}'"))?;

    let source_line = process_analyzer
        .resolve_source_line_query_best_effort(
            session
                .source_path_resolver
                .source_line_candidates(orig_file, process_analyzer),
            line_number,
            target_path.as_deref(),
        )
        .map_err(|e| format!("Failed to analyze {orig_file}:{line_number}: {e}"))?;

    if !source_line.addresses.is_empty() {
        let file_path = source_line
            .file_path
            .clone()
            .unwrap_or_else(|| orig_file.to_string());
        let cand_target = format!("{file_path}:{line_number}");
        return Ok(build_source_location_target_debug_info(
            cand_target,
            file_path,
            line_number,
            source_line.addresses,
        ));
    }

    if source_line.raw_address_count > 0 {
        let target_path = target_path.as_deref().unwrap_or("<unknown>");
        return Err(format!(
            "Cannot resolve any address for {orig_file}:{line_number} in -t target '{target_path}'"
        ));
    }

    Err(process_analyzer.describe_source_line_failure(orig_file, line_number))
}

fn unique_module_count(addresses: &[AddressQueryResult]) -> usize {
    use std::collections::HashSet;

    addresses
        .iter()
        .map(|address| address.module_path.as_path())
        .collect::<HashSet<_>>()
        .len()
}

fn variable_debug_info_from_query(
    variable: ghostscope_dwarf::VisibleVariable,
) -> VariableDebugInfo {
    let type_pretty = variable.dwarf_type.as_ref().map(|t| t.to_string());
    let size = variable.dwarf_type.as_ref().map(|t| t.size());

    VariableDebugInfo {
        name: variable.name,
        type_name: variable.type_name,
        type_pretty,
        location_description: format!("{}", variable.location),
        size,
        scope_start: None,
        scope_end: None,
    }
}

fn group_module_debug_info(addresses: Vec<AddressQueryResult>) -> Vec<ModuleDebugInfo> {
    let mut modules = Vec::new();
    let mut current_binary_path: Option<String> = None;
    let mut current_mappings = Vec::new();

    for (index, address) in addresses.into_iter().enumerate() {
        let binary_path = address.module_path.to_string_lossy().to_string();
        if current_binary_path.as_deref() != Some(binary_path.as_str()) {
            if let Some(path) = current_binary_path.take() {
                modules.push(ModuleDebugInfo {
                    binary_path: path,
                    address_mappings: current_mappings,
                });
                current_mappings = Vec::new();
            }
            current_binary_path = Some(binary_path.clone());
        }

        current_mappings.push(AddressMapping {
            address: address.address,
            binary_path,
            function_name: address.function_name,
            variables: address
                .variables
                .into_iter()
                .map(variable_debug_info_from_query)
                .collect(),
            parameters: address
                .parameters
                .into_iter()
                .map(variable_debug_info_from_query)
                .collect(),
            source_file: address.source_file,
            source_line: address.source_line,
            is_inline: address.is_inline,
            index: Some(index + 1),
        });
    }

    if let Some(path) = current_binary_path {
        modules.push(ModuleDebugInfo {
            binary_path: path,
            address_mappings: current_mappings,
        });
    }

    modules
}

fn build_target_debug_info_from_query_results(
    target: String,
    target_type: TargetType,
    addresses: Vec<AddressQueryResult>,
    fallback_file_path: Option<String>,
    fallback_line_number: Option<u32>,
    function_name: Option<String>,
) -> TargetDebugInfo {
    let file_path = addresses
        .first()
        .and_then(|address| address.source_file.clone())
        .or(fallback_file_path);
    let line_number = addresses
        .first()
        .and_then(|address| address.source_line)
        .or(fallback_line_number);
    let resolved_function_name = function_name.or_else(|| {
        addresses
            .first()
            .and_then(|address| address.function_name.clone())
    });

    TargetDebugInfo {
        target,
        target_type,
        file_path,
        line_number,
        function_name: resolved_function_name,
        modules: group_module_debug_info(addresses),
    }
}

fn handle_function_query_result(
    process_analyzer: &ghostscope_dwarf::DwarfAnalyzer,
    query_result: FunctionQueryResult,
    target_path: Option<&str>,
) -> Result<TargetDebugInfo, String> {
    let raw_address_count = query_result.addresses.len();
    let addresses = process_analyzer
        .filter_address_results_to_target(query_result.addresses, target_path)
        .map_err(|e| e.to_string())?;
    if raw_address_count == 0 {
        return Err(format!(
            "Function '{}' not found in any loaded module",
            query_result.function_name
        ));
    }
    if raw_address_count > 0 && addresses.is_empty() {
        let target = target_path.unwrap_or("<unknown>");
        return Err(format!(
            "Function '{}' was found, but not in -t target '{}'",
            query_result.function_name, target
        ));
    }

    info!(
        "Found function '{}' at {} address(es) across {} modules",
        query_result.function_name,
        addresses.len(),
        unique_module_count(&addresses)
    );

    let function_name = query_result.function_name.clone();
    Ok(build_target_debug_info_from_query_results(
        function_name.clone(),
        TargetType::Function,
        addresses,
        None,
        None,
        Some(function_name),
    ))
}

fn build_source_location_target_debug_info(
    target: String,
    fallback_file_path: String,
    line_number: u32,
    query_results: Vec<AddressQueryResult>,
) -> TargetDebugInfo {
    info!(
        "Found source line '{}:{}' at {} address(es) across {} modules",
        fallback_file_path,
        line_number,
        query_results.len(),
        unique_module_count(&query_results)
    );

    build_target_debug_info_from_query_results(
        target,
        TargetType::SourceLocation,
        query_results,
        Some(fallback_file_path),
        Some(line_number),
        None,
    )
}

/// Handle function name target
fn handle_function_target(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    function_name: &str,
    target_path: Option<&str>,
) -> Result<TargetDebugInfo, String> {
    let query_result = process_analyzer
        .query_function_best_effort(function_name)
        .map_err(|e| format!("Failed to analyze function '{function_name}': {e}"))?;
    handle_function_query_result(process_analyzer, query_result, target_path)
}

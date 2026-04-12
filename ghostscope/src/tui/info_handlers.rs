use crate::core::GhostSession;
use ghostscope_dwarf::{AddressQueryResult, FunctionQueryResult};
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

    // Helper: resolve module path by exact or suffix match
    fn resolve_module_path(
        analyzer: &ghostscope_dwarf::DwarfAnalyzer,
        sess: &GhostSession,
        module_spec: Option<&str>,
    ) -> Result<String, String> {
        // Build module list: main + shared libraries
        let mut modules: Vec<String> = Vec::new();
        if let Some(main) = analyzer.get_main_executable() {
            modules.push(main.path);
        }
        for lib in analyzer.get_shared_library_info() {
            modules.push(lib.library_path);
        }

        if let Some(spec) = module_spec {
            let spec = spec.trim();
            // Exact match first
            if let Some(found) = modules.iter().find(|p| p.as_str() == spec) {
                return Ok(found.clone());
            }
            // Suffix match
            let candidates: Vec<String> =
                modules.into_iter().filter(|p| p.ends_with(spec)).collect();
            match candidates.len() {
                0 => Err(format!(
                    "Module '{spec}' not found among loaded modules. Use full path or a unique suffix."
                )),
                1 => Ok(candidates[0].clone()),
                _ => {
                    let mut sample = candidates.clone();
                    sample.truncate(5);
                    Err(format!(
                        "Ambiguous module suffix '{}'. Candidates:\n  - {}\nPlease use a more specific suffix or full path.",
                        spec,
                        sample.join("\n  - ")
                    ))
                }
            }
        } else {
            // No module specified: choose default based on mode
            if sess.is_target_mode() {
                // -t mode: default to the target binary
                if let Some(bin) = &sess.target_binary {
                    return Ok(bin.clone());
                }
            }
            // Otherwise use main executable
            analyzer
                .get_main_executable()
                .map(|m| m.path)
                .ok_or_else(|| {
                    "No default module available. Start with -p <pid> or -t <binary>.".to_string()
                })
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
        let module_path = resolve_module_path(analyzer, sess, module_spec)?;

        let address_info = sess
            .process_analyzer
            .as_mut()
            .unwrap()
            .query_address(&module_path, vaddr)
            .map_err(|e| {
                format!("Failed to analyze address 0x{vaddr:x} in module '{module_path}': {e}")
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

    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| "Debug information not available. DWARF symbols may not be loaded or initialization failed.".to_string())?;

    handle_function_target(process_analyzer, function_name)
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

    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| "Debug information not available. DWARF symbols may not be loaded or initialization failed.".to_string())?;

    use std::collections::HashSet;
    use std::path::PathBuf;

    // Parse original input once
    let (orig_file, line_part) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("Invalid target format '{target}'. Expected format: file:line"))?;
    let line_number = line_part
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{line_part}' in target '{target}'"))?;

    // Build candidate DWARF file paths in priority order
    let mut candidates: Vec<String> = Vec::new();

    // 1) Reverse-map absolute local paths to DWARF paths (if applicable)
    if let Some(dwarf_path) = session.source_path_resolver.reverse_map_to_dwarf(orig_file) {
        candidates.push(dwarf_path);
    }

    // 2) If user provided a relative path, combine with each substitution's 'from' (DWARF comp_dir)
    if !orig_file.starts_with('/') {
        let rules = session.source_path_resolver.get_all_rules();
        for sub in rules.substitutions {
            let joined = PathBuf::from(&sub.from).join(orig_file);
            candidates.push(joined.to_string_lossy().to_string());
        }

        // 2b) Also combine with all DWARF-reported directories (comp_dir) from analyzer's file index
        if let Ok(grouped) = process_analyzer.get_grouped_file_info_by_module() {
            for (_module_path, files) in grouped {
                for f in files {
                    let joined = PathBuf::from(&f.directory).join(orig_file);
                    candidates.push(joined.to_string_lossy().to_string());
                }
            }
        }
    }

    // 3) Always try original input (might already be full DWARF path)
    candidates.push(orig_file.to_string());

    // Deduplicate while preserving order
    let mut seen = HashSet::new();
    candidates.retain(|c| seen.insert(c.clone()));

    // Probe candidates until we find addresses
    for cand in &candidates {
        let query_results = process_analyzer
            .query_source_line_best_effort(cand, line_number)
            .map_err(|e| format!("Failed to analyze {cand}:{line_number}: {e}"))?;
        if !query_results.is_empty() {
            let cand_target = format!("{cand}:{line_number}");
            return Ok(build_source_location_target_debug_info(
                cand_target,
                cand.to_string(),
                line_number,
                query_results,
            ));
        }
    }

    // Fallback to previous behavior (with reverse-map if available)
    let final_target =
        if let Some(dwarf_path) = session.source_path_resolver.reverse_map_to_dwarf(orig_file) {
            format!("{dwarf_path}:{line_number}")
        } else {
            target.to_string()
        };
    handle_source_location_target(process_analyzer, &final_target)
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
    variable: ghostscope_dwarf::VariableWithEvaluation,
) -> VariableDebugInfo {
    let type_pretty = variable.dwarf_type.as_ref().map(|t| t.to_string());
    let size = variable.dwarf_type.as_ref().map(|t| t.size());

    VariableDebugInfo {
        name: variable.name,
        type_name: variable.type_name,
        type_pretty,
        location_description: format!("{}", variable.evaluation_result),
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
    query_result: FunctionQueryResult,
) -> Result<TargetDebugInfo, String> {
    if query_result.addresses.is_empty() {
        return Err(format!(
            "Function '{}' not found in any loaded module",
            query_result.function_name
        ));
    }

    info!(
        "Found function '{}' at {} address(es) across {} modules",
        query_result.function_name,
        query_result.addresses.len(),
        unique_module_count(&query_result.addresses)
    );

    let function_name = query_result.function_name.clone();
    Ok(build_target_debug_info_from_query_results(
        function_name.clone(),
        TargetType::Function,
        query_result.addresses,
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
) -> Result<TargetDebugInfo, String> {
    let query_result = process_analyzer
        .query_function_best_effort(function_name)
        .map_err(|e| format!("Failed to analyze function '{function_name}': {e}"))?;
    handle_function_query_result(query_result)
}

/// Handle source location target (file:line)
fn handle_source_location_target(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    let (file_path, line_part) = target
        .rsplit_once(':')
        .ok_or_else(|| format!("Invalid target format '{target}'. Expected format: file:line"))?;
    let line_number = line_part
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{line_part}' in target '{target}'"))?;

    let query_results = process_analyzer
        .query_source_line_best_effort(file_path, line_number)
        .map_err(|e| format!("Failed to analyze {file_path}:{line_number}: {e}"))?;

    if query_results.is_empty() {
        return Err(format!(
            "Cannot resolve any address for {file_path}:{line_number}"
        ));
    }

    Ok(build_source_location_target_debug_info(
        target.to_string(),
        file_path.to_string(),
        line_number,
        query_results,
    ))
}

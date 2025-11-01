use crate::core::GhostSession;
use ghostscope_dwarf::ModuleAddress;
use ghostscope_ui::{events::*, RuntimeChannels, RuntimeStatus};
use tracing::{info, warn};

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
                    pid: snapshot.target_pid,
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
    crate::runtime::source_handlers::handle_request_source_code(session, runtime_channels).await;
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

        // Aggregate per-module info via existing helper
        let ma = ModuleAddress::new(std::path::PathBuf::from(&module_path), vaddr);
        let (modules, _first) = process_module_addresses_for_variables(
            sess.process_analyzer.as_mut().unwrap(),
            &[ma.clone()],
            &format!("address 0x{vaddr:x}"),
        );

        // Derive source location if available
        let source_location = sess
            .process_analyzer
            .as_mut()
            .unwrap()
            .lookup_source_location(&ma);

        Ok(TargetDebugInfo {
            target: if let Some(ms) = module_spec {
                format!("{}:{}", ms.trim(), addr_str.trim())
            } else {
                addr_str.trim().to_string()
            },
            target_type: TargetType::Address,
            file_path: source_location.as_ref().map(|sl| sl.file_path.clone()),
            line_number: source_location.as_ref().map(|sl| sl.line_number),
            function_name: None,
            modules,
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
        let addrs = process_analyzer.lookup_addresses_by_source_line(cand, line_number);
        if !addrs.is_empty() {
            let cand_target = format!("{cand}:{line_number}");
            return handle_source_location_target(process_analyzer, &cand_target);
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

/// Process module addresses and extract variable information
fn process_module_addresses_for_variables(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    module_addresses: &[ModuleAddress],
    target_description: &str, // e.g., "function 'main'" or "source line 'file.c:42'"
) -> (Vec<ModuleDebugInfo>, Option<ModuleAddress>) {
    use std::collections::HashMap;

    let mut modules = Vec::new();
    let mut first_module_address: Option<ModuleAddress> = None;

    // Build ordered modules and per-module address lists preserving input order
    let mut module_order: Vec<std::path::PathBuf> = Vec::new();
    let mut grouped_by_module: HashMap<std::path::PathBuf, Vec<&ModuleAddress>> = HashMap::new();
    for ma in module_addresses {
        if !grouped_by_module.contains_key(&ma.module_path) {
            module_order.push(ma.module_path.clone());
        }
        grouped_by_module
            .entry(ma.module_path.clone())
            .or_default()
            .push(ma);

        if first_module_address.is_none() {
            first_module_address = Some(ma.clone());
        }
    }

    let mut global_index: usize = 1;
    for module_path in module_order {
        let module_addresses_in_module = grouped_by_module.get(&module_path).unwrap();
        info!(
            "Processing {} in module '{}' at {} addresses",
            target_description,
            module_path.display(),
            module_addresses_in_module.len()
        );

        let mut address_mappings = Vec::new();

        for module_address in module_addresses_in_module {
            info!(
                "Analyzing variables at address 0x{:x} for {} in module '{}'",
                module_address.address,
                target_description,
                module_address.module_display()
            );

            // Get enhanced variables at this address using the DWARF analyzer helper
            info!(
                "Using module '{}' for analysis at binary offset 0x{:x}",
                module_address.module_display(),
                module_address.address
            );

            // DWARF analyzer doesn't need EvaluationContext - just pass the module address directly
            let enhanced_vars = match process_analyzer.get_all_variables_at_address(module_address)
            {
                Ok(vars) => vars,
                Err(e) => {
                    warn!(
                        "Failed to get variables at address 0x{:x}: {}",
                        module_address.address, e
                    );
                    Vec::new()
                }
            };

            // Separate parameters and variables for this address
            let mut parameters = Vec::new();
            let mut variables = Vec::new();

            for enhanced_var in enhanced_vars {
                let location_description = format!("{}", enhanced_var.evaluation_result);

                let var_info = VariableDebugInfo {
                    name: enhanced_var.name.clone(),
                    type_name: enhanced_var.type_name.clone(),
                    type_pretty: enhanced_var.dwarf_type.as_ref().map(|t| t.to_string()),
                    location_description,
                    size: enhanced_var.dwarf_type.as_ref().map(|t| t.size()),
                    scope_start: None, // VariableWithEvaluation doesn't have scope_ranges
                    scope_end: None,   // VariableWithEvaluation doesn't have scope_ranges
                };

                // Use the is_parameter field from DWARF parsing (which is based on DW_TAG_formal_parameter)
                let is_parameter = enhanced_var.is_parameter;

                // Log using enhanced evaluation result
                let log_location = format!("{:?}", enhanced_var.evaluation_result);

                info!(
                    "Address 0x{:x}: Variable '{}' location: {}, is_parameter: {} (from DWARF)",
                    module_address.address, enhanced_var.name, log_location, is_parameter
                );

                if is_parameter {
                    parameters.push(var_info);
                } else {
                    variables.push(var_info);
                }
            }

            // Get function name by finding symbol at this address in the specific module
            let function_name: Option<String> =
                process_analyzer.find_symbol_by_module_address(module_address);

            // Source location for this address (per mapping)
            let src_loc = process_analyzer.lookup_source_location(module_address);
            // Inline classification
            let is_inline = process_analyzer.is_inline_at(module_address);

            address_mappings.push(AddressMapping {
                address: module_address.address,
                binary_path: module_address.module_path.to_string_lossy().to_string(),
                function_name,
                variables,
                parameters,
                source_file: src_loc.as_ref().map(|sl| sl.file_path.clone()),
                source_line: src_loc.as_ref().map(|sl| sl.line_number),
                is_inline,
                index: Some(global_index),
            });
            global_index += 1;
        }

        // Create ModuleDebugInfo for this module
        modules.push(ModuleDebugInfo {
            binary_path: module_path.to_string_lossy().to_string(),
            address_mappings,
        });
    }

    (modules, first_module_address)
}

/// Handle function name target
fn handle_function_target(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    function_name: &str,
) -> Result<TargetDebugInfo, String> {
    // Use DWARF information across all modules
    let module_addresses = process_analyzer.lookup_function_addresses(function_name);

    if module_addresses.is_empty() {
        return Err(format!(
            "Function '{function_name}' not found in any loaded module"
        ));
    }

    let total_addresses: usize = module_addresses.len();
    let unique_modules: std::collections::HashSet<_> =
        module_addresses.iter().map(|ma| &ma.module_path).collect();
    info!(
        "Found function '{}' at {} address(es) across {} modules",
        function_name,
        total_addresses,
        unique_modules.len()
    );

    // Process modules and extract variable information
    let target_description = format!("function '{function_name}'");
    let (mut modules, first_module_address) = process_module_addresses_for_variables(
        process_analyzer,
        &module_addresses,
        &target_description,
    );

    // Update function_name in all address mappings since we know it's a function target
    for module in &mut modules {
        for mapping in &mut module.address_mappings {
            if mapping.function_name.is_none() {
                mapping.function_name = Some(function_name.to_string());
            }
        }
    }

    // Try to get source location for the first function address
    let source_location = if let Some(module_address) = &first_module_address {
        process_analyzer.lookup_source_location(module_address)
    } else {
        None
    };

    Ok(TargetDebugInfo {
        target: function_name.to_string(),
        target_type: TargetType::Function,
        file_path: source_location.as_ref().map(|sl| sl.file_path.clone()),
        line_number: source_location.as_ref().map(|sl| sl.line_number),
        function_name: Some(function_name.to_string()),
        modules,
    })
}

/// Handle source location target (file:line)
fn handle_source_location_target(
    process_analyzer: &mut ghostscope_dwarf::DwarfAnalyzer,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    // Parse file:line format
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid target format '{target}'. Expected format: file:line"
        ));
    }

    let file_path = parts[0];
    let line_number = parts[1]
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{}' in target '{target}'", parts[1]))?;

    // Resolve source line to all addresses across all modules
    let module_addresses = process_analyzer.lookup_addresses_by_source_line(file_path, line_number);

    if module_addresses.is_empty() {
        return Err(format!(
            "Cannot resolve any address for {file_path}:{line_number}"
        ));
    }

    let total_addresses: usize = module_addresses.len();
    let unique_modules: std::collections::HashSet<_> =
        module_addresses.iter().map(|ma| &ma.module_path).collect();
    info!(
        "Found source line '{}:{}' at {} address(es) across {} modules",
        file_path,
        line_number,
        total_addresses,
        unique_modules.len()
    );

    // Process modules and extract variable information
    let target_description = format!("source line '{file_path}:{line_number}'");
    let (modules, first_module_address) = process_module_addresses_for_variables(
        process_analyzer,
        &module_addresses,
        &target_description,
    );

    // Get actual source location from first module that has addresses
    let actual_source_location = if let Some(ref first_module_address) = first_module_address {
        process_analyzer.lookup_source_location(first_module_address)
    } else {
        None
    };
    let complete_file_path = actual_source_location
        .as_ref()
        .map(|sl| sl.file_path.clone())
        .unwrap_or_else(|| file_path.to_string()); // fallback to user input if no location found

    // Try to get overall function name (from first module's first mapping or fallback)
    let overall_function_name = modules
        .first()
        .and_then(|module| module.address_mappings.first())
        .and_then(|mapping| mapping.function_name.clone());

    Ok(TargetDebugInfo {
        target: target.to_string(),
        target_type: TargetType::SourceLocation,
        file_path: Some(complete_file_path),
        line_number: Some(line_number),
        function_name: overall_function_name,
        modules,
    })
}

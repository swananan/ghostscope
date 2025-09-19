use crate::core::GhostSession;
use ghostscope_dwarf::ModuleAddress;
use ghostscope_ui::{events::*, RuntimeChannels, RuntimeStatus};
use tracing::{error, info, warn};

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

/// Handle InfoShare command
pub async fn handle_info_share(
    session: &Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref session) = session {
        // Get shared library information from ProcessAnalyzer
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
                error: "No debug session available. Session initialization may have failed."
                    .to_string(),
            });
    }
}

/// Handle InfoTarget command
pub async fn handle_info_target(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    target: String,
) {
    info!("Info target request for: {}", target);

    let result = try_get_target_debug_info(session, &target);

    match result {
        Ok(debug_info) => {
            info!("Successfully retrieved debug info for target: {}", target);
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoTargetResult {
                    target: target.clone(),
                    info: debug_info,
                });
        }
        Err(error_msg) => {
            info!(
                "Failed to get debug info for target {}: {}",
                target, error_msg
            );
            let _ = runtime_channels
                .status_sender
                .send(RuntimeStatus::InfoTargetFailed {
                    target: target.clone(),
                    error: error_msg,
                });
        }
    }
}

/// Try to get debug info for a target (function name or file:line)
fn try_get_target_debug_info(
    session: &mut Option<GhostSession>,
    target: &str,
) -> Result<TargetDebugInfo, String> {
    let session = session
        .as_mut()
        .ok_or_else(|| "No active session available. Session initialization may have failed. Check that the target file exists and has debug symbols.".to_string())?;

    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| "Process analyzer not available. Try reloading the process.".to_string())?;

    // Parse the target to determine if it's a function name or file:line
    if target.contains(':') {
        // Parse as file:line
        handle_source_location_target(process_analyzer, target)
    } else {
        // Parse as function name
        handle_function_target(process_analyzer, target)
    }
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

    // Group module addresses by module path for UI display structure
    let mut grouped_by_module: HashMap<std::path::PathBuf, Vec<&ModuleAddress>> = HashMap::new();
    for module_address in module_addresses {
        grouped_by_module
            .entry(module_address.module_path.clone())
            .or_insert_with(Vec::new)
            .push(module_address);

        // Remember the first module address for source location lookup
        if first_module_address.is_none() {
            first_module_address = Some(module_address.clone());
        }
    }

    for (module_path, module_addresses_in_module) in &grouped_by_module {
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

            // Get enhanced variables at this address using ProcessAnalyzer encapsulated method
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
                    type_pretty: enhanced_var
                        .dwarf_type
                        .as_ref()
                        .map(|t| t.to_human_readable_with_size()),
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

            address_mappings.push(AddressMapping {
                address: module_address.address,
                binary_path: module_address.module_path.to_string_lossy().to_string(),
                function_name,
                variables,
                parameters,
            });
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
            "Function '{}' not found in any loaded module",
            function_name
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
    let target_description = format!("function '{}'", function_name);
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
            "Invalid target format '{}'. Expected format: file:line",
            target
        ));
    }

    let file_path = parts[0];
    let line_number = parts[1]
        .parse::<u32>()
        .map_err(|_| format!("Invalid line number '{}' in target '{}'", parts[1], target))?;

    // Resolve source line to all addresses across all modules
    let module_addresses = process_analyzer.lookup_addresses_by_source_line(file_path, line_number);

    if module_addresses.is_empty() {
        return Err(format!(
            "Cannot resolve any address for {}:{}",
            file_path, line_number
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
    let target_description = format!("source line '{}:{}'", file_path, line_number);
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

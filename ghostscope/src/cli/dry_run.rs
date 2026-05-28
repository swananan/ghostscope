use ghostscope_compiler::{CompilationResult, UProbeConfig};
use ghostscope_dwarf::{
    Availability, DwarfAnalyzer, ModuleAddress, Provenance, RuntimeCapabilities,
    VariableLoweringKind, VariableQueryDiagnostic, VariableReadPlan, VisibleVariable,
};

const VARIABLE_DISPLAY_LIMIT: usize = 40;

#[derive(Debug, Clone, Copy)]
pub struct DryRunReportOptions {
    pub details: bool,
}

pub fn print_dry_run_report(
    result: &CompilationResult,
    analyzer: Option<&DwarfAnalyzer>,
    runtime_capabilities: &RuntimeCapabilities,
    options: DryRunReportOptions,
) {
    let attachable_configs: Vec<_> = result
        .uprobe_configs
        .iter()
        .filter(|config| is_attachable_config(config))
        .collect();
    let unattachable_configs: Vec<_> = result
        .uprobe_configs
        .iter()
        .filter(|config| !is_attachable_config(config))
        .collect();

    println!("GhostScope dry run: no uprobes were attached.");
    println!(
        "Summary: {} attachable target(s), {} unattachable resolved target(s), {} failed target(s), next trace id {}",
        attachable_configs.len(),
        unattachable_configs.len(),
        result.failed_targets.len(),
        result.next_available_trace_id
    );
    if !result.target_info.is_empty() {
        println!("Primary target: {}", result.target_info);
    }

    if attachable_configs.is_empty() {
        println!("\nAttachable targets: none");
    } else {
        println!("\nAttachable targets:");
        for (index, config) in attachable_configs.iter().enumerate() {
            print_target(
                index + 1,
                config,
                analyzer,
                runtime_capabilities,
                options.details,
            );
        }
    }

    if !unattachable_configs.is_empty() {
        println!("\nResolved but not attachable targets:");
        for (index, config) in unattachable_configs.iter().enumerate() {
            print_target(
                index + 1,
                config,
                analyzer,
                runtime_capabilities,
                options.details,
            );
        }
    }

    if !result.failed_targets.is_empty() {
        println!("\nFailed targets:");
        for failed in &result.failed_targets {
            println!(
                "  - {} at 0x{:x}: {}",
                failed.target_name, failed.pc_address, failed.error_message
            );
        }
    }
}

fn is_attachable_config(config: &UProbeConfig) -> bool {
    config.uprobe_offset.is_some()
}

fn print_target(
    index: usize,
    config: &UProbeConfig,
    analyzer: Option<&DwarfAnalyzer>,
    runtime_capabilities: &RuntimeCapabilities,
    details: bool,
) {
    let pc = config.function_address.unwrap_or(0);
    let target = target_label(config);
    let offset = config
        .uprobe_offset
        .map(|offset| format!("0x{offset:x}"))
        .unwrap_or_else(|| "<unresolved>".to_string());

    println!(
        "  [{index}] {} -> pc=0x{pc:x}, uprobe_offset={}, module={}",
        target, offset, config.binary_path
    );

    if !details {
        return;
    }

    println!("      trace_id: {}", config.assigned_trace_id);
    println!("      eBPF program: {}", config.ebpf_function_name);
    println!("      pattern: {}", trace_pattern_label(config));
    println!("      attachable: {}", attachable_label(config));
    if let Some(address_index) = config.resolved_address_index {
        println!("      resolved address index: {address_index}");
    }
    if let Some(source) = source_label(config, analyzer) {
        println!("      source: {source}");
    }
    if let Some(inline) = inline_label(config, analyzer) {
        println!("      inline context: {inline}");
    }
    print_used_variables(config);
    print_visible_variables(config, analyzer, runtime_capabilities);
}

fn target_label(config: &UProbeConfig) -> String {
    config
        .function_name
        .clone()
        .unwrap_or_else(|| format!("0x{:x}", config.function_address.unwrap_or(0)))
}

fn trace_pattern_label(config: &UProbeConfig) -> String {
    use ghostscope_compiler::script::TracePattern;

    match &config.trace_pattern {
        TracePattern::FunctionName(name) => format!("function {name}"),
        TracePattern::Wildcard(pattern) => format!("wildcard {pattern}"),
        TracePattern::Address(address) => format!("address 0x{address:x}"),
        TracePattern::AddressInModule { module, address } => {
            format!("address {module}:0x{address:x}")
        }
        TracePattern::SourceLine {
            file_path,
            line_number,
        } => format!("source {file_path}:{line_number}"),
    }
}

fn attachable_label(config: &UProbeConfig) -> &'static str {
    if config.uprobe_offset.is_some() && !config.ebpf_bytecode.is_empty() {
        "yes (file offset resolved; eBPF bytecode generated)"
    } else if config.uprobe_offset.is_some() {
        "partial (file offset resolved; empty eBPF bytecode)"
    } else {
        "no (file offset unresolved)"
    }
}

fn module_address(config: &UProbeConfig) -> Option<ModuleAddress> {
    config.function_address.map(|address| {
        ModuleAddress::new(
            std::path::PathBuf::from(config.binary_path.clone()),
            address,
        )
    })
}

fn source_label(config: &UProbeConfig, analyzer: Option<&DwarfAnalyzer>) -> Option<String> {
    let analyzer = analyzer?;
    let module_address = module_address(config)?;
    let source = analyzer.lookup_source_location(&module_address)?;
    let column = source
        .column
        .map(|column| format!(":{column}"))
        .unwrap_or_default();
    Some(format!(
        "{}:{}{}",
        source.file_path, source.line_number, column
    ))
}

fn inline_label(config: &UProbeConfig, analyzer: Option<&DwarfAnalyzer>) -> Option<&'static str> {
    let analyzer = analyzer?;
    let module_address = module_address(config)?;
    analyzer
        .is_inline_at(&module_address)
        .map(|is_inline| if is_inline { "yes" } else { "no" })
}

fn print_used_variables(config: &UProbeConfig) {
    if config.trace_context.variable_names.is_empty() {
        println!("      variables used by script: none");
        return;
    }

    println!(
        "      variables used by script: {}",
        config.trace_context.variable_names.join(", ")
    );
}

fn print_visible_variables(
    config: &UProbeConfig,
    analyzer: Option<&DwarfAnalyzer>,
    runtime_capabilities: &RuntimeCapabilities,
) {
    let Some(analyzer) = analyzer else {
        println!("      visible variables: unavailable (no DWARF analyzer)");
        return;
    };
    let Some(module_address) = module_address(config) else {
        println!("      visible variables: unavailable (no PC)");
        return;
    };

    let visible = analyzer
        .resolve_pc(&module_address)
        .and_then(|ctx| analyzer.visible_variables_with_diagnostics(&ctx));

    match visible {
        Ok(result) => {
            print_visible_variable_list(&result.variables, runtime_capabilities);
            print_variable_diagnostics(&result.diagnostics);
        }
        Err(error) => {
            println!("      visible variables: unavailable ({error})");
        }
    }
}

fn print_visible_variable_list(
    variables: &[VisibleVariable],
    runtime_capabilities: &RuntimeCapabilities,
) {
    if variables.is_empty() {
        println!("      visible variables: none");
        return;
    }

    println!(
        "      visible variables: {} shown{}",
        variables.len().min(VARIABLE_DISPLAY_LIMIT),
        if variables.len() > VARIABLE_DISPLAY_LIMIT {
            format!(" of {}", variables.len())
        } else {
            String::new()
        }
    );

    for variable in variables.iter().take(VARIABLE_DISPLAY_LIMIT) {
        let plan = VariableReadPlan::from_visible_variable(variable.clone(), Provenance::DirectDie);
        let materialization = plan.materialization_plan(runtime_capabilities);
        println!(
            "        - {}{}: {} [{}; {}; {}]",
            if variable.is_parameter { "param " } else { "" },
            variable.name,
            variable.type_name,
            availability_label(&materialization.availability),
            lowering_label(&materialization.lowering.kind),
            variable.location
        );
    }

    if variables.len() > VARIABLE_DISPLAY_LIMIT {
        println!(
            "        ... {} more variable(s) omitted",
            variables.len() - VARIABLE_DISPLAY_LIMIT
        );
    }
}

fn print_variable_diagnostics(diagnostics: &[VariableQueryDiagnostic]) {
    if diagnostics.is_empty() {
        return;
    }

    println!("      variable diagnostics:");
    for diagnostic in diagnostics.iter().take(VARIABLE_DISPLAY_LIMIT) {
        let name = diagnostic.name.as_deref().unwrap_or("<unnamed>");
        println!(
            "        - {}: {} [{}]",
            name,
            diagnostic.detail,
            availability_label(&diagnostic.availability)
        );
    }

    if diagnostics.len() > VARIABLE_DISPLAY_LIMIT {
        println!(
            "        ... {} more diagnostic(s) omitted",
            diagnostics.len() - VARIABLE_DISPLAY_LIMIT
        );
    }
}

fn availability_label(availability: &Availability) -> String {
    match availability {
        Availability::Available => "available".to_string(),
        Availability::PartiallyAvailable => "partially available".to_string(),
        Availability::OptimizedOut => "optimized out".to_string(),
        Availability::NotInScope => "not in scope".to_string(),
        Availability::Unsupported(reason) => format!("unsupported: {reason:?}"),
        Availability::Requires(requirement) => format!("requires: {requirement:?}"),
        Availability::Ambiguous(reason) => format!("ambiguous: {reason:?}"),
    }
}

fn lowering_label(kind: &VariableLoweringKind) -> &'static str {
    match kind {
        VariableLoweringKind::DirectValue => "direct value",
        VariableLoweringKind::UserMemoryRead => "user memory read",
        VariableLoweringKind::Composite => "composite",
        VariableLoweringKind::Unavailable => "unavailable",
    }
}

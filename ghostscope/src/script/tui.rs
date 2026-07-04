use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use tracing::{error, info, warn};

use super::attach::{
    create_and_attach_loader, log_attachment_hints, log_uprobe_configs, register_attached_trace,
};
use super::compile::{compile_script_with_session, main_executable_path, SessionCompileError};
use super::runtime_maps::ensure_prefill_for_session_pid;
use super::runtime_prep::refresh_runtime_modules_before_compile;

/// Compile and load script specifically for TUI mode with detailed execution results.
pub async fn compile_and_load_script_for_tui(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<ScriptCompilationDetails> {
    let mut compile_options = compile_options.clone();
    refresh_runtime_modules_before_compile(script, session, &mut compile_options).await?;

    let binary_path = main_executable_path(session)?;
    let compilation_result = match compile_script_with_session(script, session, &compile_options) {
        Ok(result) => result,
        Err(SessionCompileError::Compile(e)) => {
            let friendly = e.user_message().into_owned();
            error!("Script compilation failed: {}", friendly);
            return Ok(compilation_failed_details(binary_path, friendly));
        }
        Err(SessionCompileError::Setup(e)) => return Err(e),
    };

    info!(
        "✓ Script compilation successful: {} uprobe configs generated",
        compilation_result.uprobe_configs.len()
    );

    let process_analyzer = session
        .process_analyzer
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;
    let (mut results, trace_ids, mut success_count, mut failed_count) =
        build_tui_results(&compilation_result, &binary_path, process_analyzer);

    info!(
        "Compilation summary: {} successful, {} failed",
        success_count, failed_count
    );

    ensure_prefill_for_session_pid(session);

    if !compilation_result.uprobe_configs.is_empty() {
        let uprobe_configs = compilation_result.uprobe_configs;
        log_uprobe_configs(&uprobe_configs, true);

        let mut attached_count = 0;
        for config in &uprobe_configs {
            match create_and_attach_loader(config, session.attach_pid(), session, &compile_options)
                .await
            {
                Ok(loader) => {
                    info!(
                        "✓ Successfully attached uprobe for trace_id {}",
                        config.assigned_trace_id
                    );
                    if register_attached_trace(session, script, config, loader) {
                        attached_count += 1;
                    }
                }
                Err(e) => {
                    error!(
                        "Failed to attach uprobe for trace_id {}: {:#}",
                        config.assigned_trace_id, e
                    );
                    log_attachment_hints();
                    for result in &mut results {
                        if result.pc_address == config.function_address.unwrap_or(0) {
                            result.status =
                                ExecutionStatus::Failed(format!("Failed to attach uprobe: {e:#}"));
                            success_count -= 1;
                            failed_count += 1;
                            break;
                        }
                    }
                }
            }
        }

        if attached_count > 0 {
            info!(
                "✓ Successfully attached {} of {} uprobes",
                attached_count,
                uprobe_configs.len()
            );
        } else {
            warn!("No uprobes were successfully attached");
        }
    }

    Ok(ScriptCompilationDetails {
        trace_ids,
        results,
        total_count: success_count + failed_count,
        success_count,
        failed_count,
    })
}

fn compilation_failed_details(binary_path: String, friendly: String) -> ScriptCompilationDetails {
    ScriptCompilationDetails {
        trace_ids: vec![],
        results: vec![ScriptExecutionResult {
            pc_address: 0,
            target_name: "compilation_failed".to_string(),
            binary_path,
            status: ExecutionStatus::Failed(format!("Compilation error: {friendly}")),
            source_file: None,
            source_line: None,
            is_inline: None,
        }],
        total_count: 1,
        success_count: 0,
        failed_count: 1,
    }
}

fn build_tui_results(
    compilation_result: &ghostscope_compiler::CompilationResult,
    binary_path: &str,
    process_analyzer: &ghostscope_dwarf::DwarfAnalyzer,
) -> (Vec<ScriptExecutionResult>, Vec<u32>, usize, usize) {
    let mut results = Vec::new();
    let mut trace_ids = Vec::new();
    let mut success_count = 0;
    let mut failed_count = 0;

    for config in compilation_result.uprobe_configs.iter() {
        let trace_id = config.assigned_trace_id;
        trace_ids.push(trace_id);

        let (source_file, source_line, is_inline) = {
            let addr = config.function_address.unwrap_or(0);
            let module_address = ghostscope_dwarf::ModuleAddress::new(
                std::path::PathBuf::from(&config.binary_path),
                addr,
            );
            let src = process_analyzer.lookup_source_location(&module_address);
            let inline = process_analyzer.is_inline_at(&module_address);
            (
                src.as_ref().map(|s| s.file_path.clone()),
                src.as_ref().map(|s| s.line_number),
                inline,
            )
        };

        results.push(ScriptExecutionResult {
            pc_address: config.function_address.unwrap_or(0),
            target_name: config
                .function_name
                .clone()
                .unwrap_or_else(|| format!("{:#x}", config.function_address.unwrap_or(0))),
            binary_path: config.binary_path.clone(),
            status: ExecutionStatus::Success,
            source_file,
            source_line,
            is_inline,
        });
        success_count += 1;
    }

    for failed in &compilation_result.failed_targets {
        results.push(ScriptExecutionResult {
            pc_address: failed.pc_address,
            target_name: failed.target_name.clone(),
            binary_path: binary_path.to_string(),
            status: ExecutionStatus::Failed(failed.error_message.clone()),
            source_file: None,
            source_line: None,
            is_inline: None,
        });
        failed_count += 1;
    }

    (results, trace_ids, success_count, failed_count)
}

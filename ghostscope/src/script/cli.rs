use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_compiler::script::FailedTarget;
use tracing::{error, info, warn};

use super::attach::{
    create_and_attach_loader, log_attachment_hints, log_uprobe_configs, register_attached_trace,
};
use super::compile::{compile_script_with_session, SessionCompileError};
use super::runtime_maps::ensure_prefill_for_session_pid;
use super::runtime_prep::refresh_runtime_modules_before_compile;

/// Compile a script for command line mode without attaching uprobes.
pub fn compile_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<ghostscope_compiler::CompilationResult> {
    info!("Starting unified script compilation with DWARF integration...");

    let compilation_result = match compile_script_with_session(script, session, compile_options) {
        Ok(result) => result,
        Err(SessionCompileError::Compile(e)) => {
            let friendly = e.user_message().into_owned();
            error!("Script compilation failed: {}", friendly);
            return Err(anyhow::anyhow!(
                "Script compilation failed: {friendly}. Please check your script syntax and try again."
            ));
        }
        Err(SessionCompileError::Setup(e)) => return Err(e),
    };

    info!(
        "✓ Script compilation successful: {} trace points found, {} uprobe configs generated",
        compilation_result.trace_count,
        compilation_result.uprobe_configs.len()
    );
    info!("Target info: {}", compilation_result.target_info);

    if !compilation_result.failed_targets.is_empty() {
        warn!("Some targets failed to compile:");
        for failed in &compilation_result.failed_targets {
            warn!(
                "  {} at 0x{:x}: {}",
                failed.target_name, failed.pc_address, failed.error_message
            );
        }
    }

    Ok(compilation_result)
}

/// Compile and load script for command line mode using session.command_loaders.
pub async fn compile_and_load_script_for_cli(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> Result<()> {
    let mut compile_options = compile_options.clone();
    refresh_runtime_modules_before_compile(script, session, &mut compile_options).await?;

    let compilation_result = compile_script_for_cli(script, session, &compile_options)?;
    ensure_prefill_for_session_pid(session);

    let ghostscope_compiler::CompilationResult {
        uprobe_configs,
        failed_targets,
        ..
    } = compilation_result;

    if uprobe_configs.is_empty() {
        return handle_empty_cli_configs(session, &failed_targets);
    }

    log_uprobe_configs(&uprobe_configs, false);

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
                return Err(e.context(format!(
                    "Failed to attach uprobe for trace_id {}",
                    config.assigned_trace_id
                )));
            }
        }
    }

    if attached_count > 0 {
        info!(
            "✓ Successfully attached {} of {} uprobes",
            attached_count,
            uprobe_configs.len()
        );
        Ok(())
    } else {
        Err(anyhow::anyhow!("No uprobes were successfully attached"))
    }
}

fn handle_empty_cli_configs(session: &GhostSession, failed_targets: &[FailedTarget]) -> Result<()> {
    if !failed_targets.is_empty() {
        let mut details = String::new();
        for failed in failed_targets {
            let _ = std::fmt::Write::write_fmt(
                &mut details,
                format_args!(
                    "  - {} at 0x{:x}: {}\n",
                    failed.target_name, failed.pc_address, failed.error_message
                ),
            );
        }
        let full = format!(
            "No uprobe configurations created because all {} target(s) failed to compile.\n\nFailed targets:\n{}\n\nTip: fix the reported compile-time errors above (e.g., avoid struct/union/array arithmetic; select a scalar field or use '&expr + <non-negative literal>' in an alias/address context).",
            failed_targets.len(),
            details
        );
        error!("{}", full);
        return Err(anyhow::anyhow!(full));
    }

    let available_functions = session.list_functions();
    if available_functions.is_empty() {
        return Err(anyhow::anyhow!(
            "No debug information found in any module!\n\
            \n\
            The target binary and its libraries are stripped or compiled without debug symbols.\n\
            GhostScope requires debug information (DWARF) to:\n\
            - Locate functions by name\n\
            - Analyze variable types and locations\n\
            - Map source lines to addresses\n\
            \n\
            Solutions:\n\
            1. Recompile your target with -g flag: gcc -g your_program.c -o your_program\n\
            2. Install debug symbol packages (e.g., libc6-dbg on Debian/Ubuntu)\n\
            3. For stripped binaries, use objcopy to create separate debug files:\n\
               objcopy --only-keep-debug binary binary.debug\n\
               objcopy --add-gnu-debuglink=binary.debug binary"
        ));
    }

    Err(anyhow::anyhow!(
        "No uprobe configurations created - the functions referenced in your script were not found.\n\
        \n\
        Possible reasons:\n\
        - Function names are misspelled (check available functions below)\n\
        - Functions don't exist in the target binary\n\
        - Functions are from libraries that aren't loaded yet\n\
        \n\
        Available functions (first 10):\n{}\n\
        \n\
        Tip: Run GhostScope in TUI mode to browse all available functions",
        available_functions
            .iter()
            .take(10)
            .map(|f| format!("  - {f}"))
            .collect::<Vec<_>>()
            .join("\n")
    ))
}

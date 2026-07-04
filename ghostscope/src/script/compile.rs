use crate::core::GhostSession;
use anyhow::Result;

pub(super) enum SessionCompileError {
    Setup(anyhow::Error),
    Compile(ghostscope_compiler::CompileError),
}

pub(super) fn main_executable_path(session: &mut GhostSession) -> Result<String> {
    let process_analyzer = session
        .process_analyzer
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("Process analyzer is required for script compilation"))?;

    process_analyzer
        .get_main_executable()
        .map(|module| module.path.clone())
        .ok_or_else(|| anyhow::anyhow!("No main executable found in process"))
}

pub(super) fn compile_script_with_session(
    script: &str,
    session: &mut GhostSession,
    compile_options: &ghostscope_compiler::CompileOptions,
) -> std::result::Result<ghostscope_compiler::CompilationResult, SessionCompileError> {
    let fallback_host_pid = session.host_pid();
    let starting_trace_id = session.trace_manager.get_next_trace_id();
    let process_analyzer = session.process_analyzer.as_mut().ok_or_else(|| {
        SessionCompileError::Setup(anyhow::anyhow!(
            "Process analyzer is required for script compilation"
        ))
    })?;

    ghostscope_compiler::compile_script(
        script,
        process_analyzer,
        fallback_host_pid,
        Some(starting_trace_id),
        compile_options,
    )
    .map_err(SessionCompileError::Compile)
}

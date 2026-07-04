use crate::core::GhostSession;
use anyhow::Result;
use ghostscope_compiler::script::Statement;
use tracing::{info, warn};

fn statement_contains_backtrace(statement: &Statement) -> bool {
    match statement {
        Statement::Backtrace(_) => true,
        Statement::TracePoint { body, .. } | Statement::Block(body) => {
            statements_contain_backtrace(body)
        }
        Statement::If {
            then_body,
            else_body,
            ..
        } => {
            statements_contain_backtrace(then_body)
                || else_body
                    .as_deref()
                    .is_some_and(statement_contains_backtrace)
        }
        _ => false,
    }
}

fn statements_contain_backtrace(statements: &[Statement]) -> bool {
    statements.iter().any(statement_contains_backtrace)
}

fn script_contains_backtrace(script: &str) -> bool {
    ghostscope_compiler::script::parser::parse(script)
        .map(|program| statements_contain_backtrace(&program.statements))
        .unwrap_or(false)
}

pub(super) async fn refresh_runtime_modules_before_compile(
    script: &str,
    session: &mut GhostSession,
    compile_options: &mut ghostscope_compiler::CompileOptions,
) -> Result<()> {
    if let Err(e) = session.refresh_pid_runtime_modules_if_needed().await {
        warn!(
            "Failed to refresh PID runtime modules after sysmon map-change event: {:#}",
            e
        );
    }

    if session.is_target_mode() && script_contains_backtrace(script) {
        session.enable_target_backtrace_runtime_modules();
        if let Err(e) = session.refresh_target_runtime_modules().await {
            warn!(
                "Failed to refresh target-mode runtime modules before backtrace compilation: {:#}",
                e
            );
        }
        configure_target_mode_backtrace_pid_namespace(session, compile_options);
    }

    Ok(())
}

fn configure_target_mode_backtrace_pid_namespace(
    session: &GhostSession,
    compile_options: &mut ghostscope_compiler::CompileOptions,
) {
    if !session.is_target_mode() {
        return;
    }
    let Some(target_binary) = session.binary_path() else {
        return;
    };

    let target_pids = {
        let coordinator = session
            .coordinator
            .lock()
            .expect("coordinator mutex poisoned");
        let mut pids = coordinator
            .cached_offsets_for_module(&target_binary)
            .into_iter()
            .map(|(pid, _, _, _, _)| pid)
            .collect::<Vec<_>>();
        pids.sort_unstable();
        pids.dedup();
        pids
    };

    let [proc_pid] = target_pids.as_slice() else {
        if !target_pids.is_empty() {
            tracing::debug!(
                "target-mode backtrace PID namespace remains unchanged: matched {} target PIDs for {}",
                target_pids.len(),
                target_binary
            );
        }
        return;
    };

    let pid_views = match ghostscope_process::resolve_proc_pid(*proc_pid) {
        Ok(pid_views) => pid_views,
        Err(error) => {
            warn!(
                "Failed to resolve target-mode PID views for proc pid {}: {}",
                proc_pid, error
            );
            return;
        }
    };

    let Some(pid_ns) = pid_views
        .pid_ns
        .filter(|pid_ns| pid_ns.helper_dev_inode().is_some())
    else {
        tracing::debug!(
            "target-mode backtrace PID namespace remains unchanged: no helper-usable namespace for proc pid {}",
            proc_pid
        );
        return;
    };

    compile_options.proc_offsets_pid_ns = Some(pid_ns);
    record_target_mode_pid_aliases(session, *proc_pid, &pid_views);

    let (pid_ns_dev, pid_ns_inode) = pid_ns
        .helper_dev_inode()
        .expect("filtered to helper-usable pid namespace");
    info!(
        "target-mode proc_module_offsets PID namespace configured from target PID {}: ns_dev={} ns_inode={}",
        proc_pid, pid_ns_dev, pid_ns_inode
    );
}

fn record_target_mode_pid_aliases(
    session: &GhostSession,
    proc_pid: u32,
    pid_views: &ghostscope_process::PidViews,
) {
    let mut runtime_pids = Vec::new();
    runtime_pids.push(pid_views.host_pid);
    if let Some(container_pid) = pid_views.container_pid {
        runtime_pids.push(container_pid);
    }
    if let Some(chain) = pid_views.nspid_chain.as_ref() {
        runtime_pids.extend(chain.iter().copied());
    }
    runtime_pids.sort_unstable();
    runtime_pids.dedup();

    let mut coordinator = session
        .coordinator
        .lock()
        .expect("coordinator mutex poisoned");
    for runtime_pid in runtime_pids {
        if runtime_pid == proc_pid {
            continue;
        }
        coordinator.record_runtime_pid_alias(runtime_pid, proc_pid);
        match ghostscope_process::pinned_bpf_maps::insert_pid_alias(runtime_pid, proc_pid) {
            Ok(()) => info!(
                "target-mode PID alias applied runtime_pid={} -> proc_pid={}",
                runtime_pid, proc_pid
            ),
            Err(error) => warn!(
                "Failed to write target-mode PID alias runtime_pid={} -> proc_pid={}: {}",
                runtime_pid, proc_pid, error
            ),
        }
    }
}

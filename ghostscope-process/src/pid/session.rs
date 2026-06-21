use std::fmt;

use tracing::warn;

use super::{
    build_runtime_pid_plan, detect_runtime_environment, resolve_input_pid, PidModeFailFast,
    PidViews, RuntimeEnvironmentInfo, RuntimePidPlan, RuntimePidPlanInput,
};

#[derive(Debug)]
pub enum ResolvePidSessionError {
    Resolve(anyhow::Error),
    FailFast(PidModeFailFast),
}

impl fmt::Display for ResolvePidSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvePidSessionError::Resolve(err) => write!(f, "{err}"),
            ResolvePidSessionError::FailFast(PidModeFailFast { proc_pid }) => {
                write!(f, "PID mode is not reliable for proc pid {proc_pid}")
            }
        }
    }
}

impl std::error::Error for ResolvePidSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolvePidSessionError::Resolve(err) => Some(err.as_ref()),
            ResolvePidSessionError::FailFast(_) => None,
        }
    }
}

impl From<anyhow::Error> for ResolvePidSessionError {
    fn from(value: anyhow::Error) -> Self {
        ResolvePidSessionError::Resolve(value)
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedPidSession {
    pub runtime_env: RuntimeEnvironmentInfo,
    pub target_pid_views: Option<PidViews>,
    pub self_pid_views: Option<PidViews>,
    pub runtime_pid_plan: RuntimePidPlan,
}

pub fn resolve_pid_session(
    input_pid: Option<u32>,
    helper_supported: bool,
) -> Result<ResolvedPidSession, ResolvePidSessionError> {
    let runtime_env = detect_runtime_environment();
    let in_container = runtime_env.is_container_likely();

    let target_pid_views = input_pid.map(resolve_input_pid).transpose()?;
    let self_pid_views = if helper_supported {
        let self_pid = std::process::id();
        match resolve_input_pid(self_pid) {
            Ok(pid_views) => Some(pid_views),
            Err(err) => {
                warn!(
                    "Failed to resolve self PID namespace context (self pid={}): {}",
                    self_pid, err
                );
                None
            }
        }
    } else {
        None
    };

    let runtime_pid_plan = build_runtime_pid_plan(RuntimePidPlanInput {
        target_pid_views: target_pid_views.as_ref(),
        self_pid_views: self_pid_views.as_ref(),
        in_container,
        helper_supported,
    })
    .map_err(ResolvePidSessionError::FailFast)?;

    Ok(ResolvedPidSession {
        runtime_env,
        target_pid_views,
        self_pid_views,
        runtime_pid_plan,
    })
}

#![allow(dead_code)]

//! Shared asynchronous runner for invoking the `ghostscope` CLI from tests.
//!
//! Features:
//! - Attach by PID or by target path (exactly one required)
//! - Optional sandbox backend for GhostScope itself (host by default)
//! - Configurable timeout (overall cap) and optional PerfEventArray backend
//! - Consistent flags: disable artifact saving by default; logging opt-in
//! - Robust output collection: incremental read during run, drain after exit
//! - Pragmatic success rule: if process was terminated on timeout but produced
//!   any output, treat exit code -1 as success (0) to keep tests stable

use super::sandbox::SandboxHandle;
use super::targets::ensure_target_binary_ready_for_default_sandbox;
use super::targets::TargetHandle;
use super::termination::{terminate_tokio_child_gracefully, GRACEFUL_TERMINATION_TIMEOUT};
use anyhow::{Context, Result};
use ghostscope_process::is_shared_object;
use std::env;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

const ENV_GHOSTSCOPE_LOG_LEVEL: &str = "E2E_GHOSTSCOPE_LOG_LEVEL";
const ENV_GHOSTSCOPE_ENABLE_LOGGING: &str = "E2E_GHOSTSCOPE_ENABLE_LOGGING";
const ENV_GHOSTSCOPE_LOG_CONSOLE: &str = "E2E_GHOSTSCOPE_LOG_CONSOLE";
const ENV_E2E_TARGET_MODE: &str = "E2E_TARGET_MODE";
const GHOSTSCOPE_PID_BOOTSTRAP_PREFIX: &str = "__GHOSTSCOPE_PID__ ";
#[allow(dead_code)]
const GHOSTSCOPE_READY_MARKER: &str = "__GHOSTSCOPE_READY__";
const CHILD_CONTAINER_TIMEOUT_SLACK_SECS: u64 = 3;

pub struct GhostscopeRunner {
    script_content: String,
    pid: Option<u32>,
    attach_target: Option<TargetHandle>,
    target: Option<PathBuf>,
    timeout_secs: u64,
    force_perf_event_array: bool,
    log_level: Option<String>,
    enable_sysmon_shared_lib: bool,
    enable_file_logging: bool,
    enable_console_logging: bool,
    sandbox: Option<SandboxHandle>,
}

impl Default for GhostscopeRunner {
    fn default() -> Self {
        Self {
            script_content: String::new(),
            pid: None,
            attach_target: None,
            target: None,
            timeout_secs: 3,
            force_perf_event_array: false,
            log_level: None,
            enable_sysmon_shared_lib: false,
            enable_file_logging: false,
            enable_console_logging: false,
            sandbox: None,
        }
    }
}

impl GhostscopeRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_script(mut self, content: &str) -> Self {
        self.script_content = content.to_string();
        self
    }

    #[allow(dead_code)]
    pub fn with_pid(mut self, pid: u32) -> Self {
        self.pid = Some(pid);
        self
    }

    #[allow(dead_code)]
    pub fn attach_to(mut self, target: &TargetHandle) -> Self {
        self.attach_target = Some(target.clone());
        self
    }

    pub fn with_target<P: AsRef<Path>>(mut self, target: P) -> Self {
        self.target = Some(target.as_ref().to_path_buf());
        self
    }

    #[allow(dead_code)]
    pub fn in_sandbox(mut self, sandbox: &SandboxHandle) -> Self {
        self.sandbox = Some(sandbox.clone());
        self
    }

    pub fn timeout_secs(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn force_perf_event_array(mut self, yes: bool) -> Self {
        self.force_perf_event_array = yes;
        self
    }

    pub fn enable_sysmon_shared_lib(mut self, yes: bool) -> Self {
        self.enable_sysmon_shared_lib = yes;
        self
    }

    #[allow(dead_code)]
    pub fn enable_file_logging(mut self, yes: bool) -> Self {
        self.enable_file_logging = yes;
        self
    }

    #[allow(dead_code)]
    pub fn enable_console_logging(mut self, yes: bool) -> Self {
        self.enable_console_logging = yes;
        self
    }

    #[allow(dead_code)]
    pub fn with_log_level<S: Into<String>>(mut self, level: S) -> Self {
        self.log_level = Some(level.into());
        self
    }

    pub async fn run(self) -> Result<(i32, String, String)> {
        let (exit_code, stdout, stderr, ()) = self
            .run_internal(
                Some(GHOSTSCOPE_READY_MARKER.to_string()),
                None::<fn() -> std::future::Ready<Result<()>>>,
                false,
                Some(()),
            )
            .await?;
        Ok((exit_code, stdout, stderr))
    }

    #[allow(dead_code)]
    pub async fn run_after_ready<OnReady, Fut, T>(
        self,
        on_ready: OnReady,
    ) -> Result<(i32, String, String, T)>
    where
        OnReady: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        self.run_internal(
            Some(GHOSTSCOPE_READY_MARKER.to_string()),
            Some(on_ready),
            true,
            None,
        )
        .await
    }

    async fn run_internal<OnReady, Fut, T>(
        self,
        ready_marker: Option<String>,
        on_ready: Option<OnReady>,
        require_ready_marker: bool,
        default_ready_result: Option<T>,
    ) -> Result<(i32, String, String, T)>
    where
        OnReady: FnOnce() -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let logging = self.resolve_logging_config();
        let monitor_timeout_secs = self.effective_timeout_secs();
        let setup_timeout_secs = self.setup_timeout_secs();
        let sandbox = match self.sandbox {
            Some(sandbox) => sandbox,
            None => SandboxHandle::default_ghostscope()?,
        };

        let by_pid = self.pid.is_some();
        let by_attached_target = self.attach_target.is_some();
        let by_target = self.target.is_some();
        anyhow::ensure!(
            (by_pid as usize) + (by_attached_target as usize) + (by_target as usize) == 1,
            "Must set exactly one of pid, attached target, or target path"
        );

        let _target_sandbox_guard = if let Some(ref target) = self.target {
            if !is_shared_object(target) {
                Some(ensure_target_binary_ready_for_default_sandbox(target)?)
            } else {
                None
            }
        } else {
            None
        };

        let mut script_file = create_script_file()?;
        use std::io::Write as _;
        script_file.write_all(self.script_content.as_bytes())?;
        let script_path = sandbox.path_in_sandbox(script_file.path())?;

        let mut args: Vec<OsString> = Vec::new();
        if let Some(pid) = self.pid {
            args.push(OsString::from("-p"));
            args.push(OsString::from(pid.to_string()));
        } else if let Some(target) = &self.attach_target {
            let pid = target.visible_pid_from(&sandbox)?;
            args.push(OsString::from("-p"));
            args.push(OsString::from(pid.to_string()));
        } else if let Some(ref target) = self.target {
            args.push(OsString::from("-t"));
            args.push(sandbox.path_in_sandbox(target)?.into_os_string());
        }

        args.push(OsString::from("--script-file"));
        args.push(script_path.into_os_string());

        if let Some(level) = &logging.level {
            args.push(OsString::from("--log-level"));
            args.push(OsString::from(level.clone()));
        }
        if self.force_perf_event_array {
            args.push(OsString::from("--force-perf-event-array"));
        }
        if let Some(marker) = ready_marker.as_ref() {
            args.push(OsString::from("--emit-ready-marker"));
            args.push(OsString::from(marker));
        }
        if self.enable_sysmon_shared_lib {
            args.push(OsString::from("--enable-sysmon-shared-lib"));
        }
        if logging.enable_logging {
            args.push(OsString::from("--log"));
        }
        if logging.enable_console_logging {
            args.push(OsString::from("--log-console"));
        }

        let launch = sandbox.ghostscope_runner_command(&args)?;
        let mut cmd = Command::new(&launch.program);
        cmd.args(&launch.args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdout_handle = child.stdout.take().unwrap();
        let stderr_handle = child.stderr.take().unwrap();
        let mut stdout_reader = BufReader::new(stdout_handle);
        let mut stderr_reader = BufReader::new(stderr_handle);

        let mut stdout_content = String::new();
        let mut stderr_content = String::new();
        let mut managed_ghostscope_pid = None;
        let mut ready_callback = on_ready;
        let mut ready_result = default_ready_result;
        let mut ready_fired = ready_marker.is_none();

        if ready_fired && ready_result.is_none() {
            if let Some(callback) = ready_callback.take() {
                ready_result = Some(callback().await?);
            }
        }

        if launch.bootstrap_pid_from_stdout {
            let mut bootstrap_line = String::new();
            let read = timeout(
                Duration::from_secs(2),
                stdout_reader.read_line(&mut bootstrap_line),
            )
            .await
            .context("timed out waiting for container GhostScope pid bootstrap")??;
            anyhow::ensure!(
                read > 0,
                "container GhostScope exited before emitting pid bootstrap line"
            );
            let pid_text = bootstrap_line
                .trim_end()
                .strip_prefix(GHOSTSCOPE_PID_BOOTSTRAP_PREFIX)
                .with_context(|| {
                    format!(
                        "invalid GhostScope pid bootstrap line from {}: {}",
                        sandbox.label(),
                        bootstrap_line.trim_end()
                    )
                })?;
            managed_ghostscope_pid = Some(pid_text.parse::<u32>().with_context(|| {
                format!(
                    "invalid GhostScope pid bootstrap value from {}: {}",
                    sandbox.label(),
                    pid_text
                )
            })?);
        }

        if !ready_fired {
            let pre_ready_task = async {
                let mut stdout_line = String::new();
                let mut stderr_line = String::new();
                loop {
                    stdout_line.clear();
                    if let Ok(Ok(n)) = timeout(
                        Duration::from_millis(50),
                        stdout_reader.read_line(&mut stdout_line),
                    )
                    .await
                    {
                        if n > 0 {
                            stdout_content.push_str(&stdout_line);
                            if ready_marker
                                .as_deref()
                                .is_some_and(|marker| stdout_line.trim_end() == marker)
                            {
                                if let Some(callback) = ready_callback.take() {
                                    ready_result = Some(callback().await?);
                                }
                                ready_fired = true;
                                break;
                            }
                        }
                    }

                    stderr_line.clear();
                    if let Ok(Ok(n)) = timeout(
                        Duration::from_millis(50),
                        stderr_reader.read_line(&mut stderr_line),
                    )
                    .await
                    {
                        if n > 0 {
                            stderr_content.push_str(&stderr_line);
                            if ready_marker
                                .as_deref()
                                .is_some_and(|marker| stderr_line.trim_end() == marker)
                            {
                                if let Some(callback) = ready_callback.take() {
                                    ready_result = Some(callback().await?);
                                }
                                ready_fired = true;
                                break;
                            }
                        }
                    }

                    if let Ok(Some(_status)) = child.try_wait() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok::<(), anyhow::Error>(())
            };

            match timeout(Duration::from_secs(setup_timeout_secs), pre_ready_task).await {
                Ok(result) => result?,
                Err(_) => {
                    if let Some(pid) = managed_ghostscope_pid {
                        sandbox.terminate_pid(pid).with_context(|| {
                            format!(
                                "failed to terminate startup-stalled GhostScope pid {} in {}",
                                pid,
                                sandbox.label()
                            )
                        })?;
                    } else {
                        let _ = terminate_tokio_child_gracefully(
                            &mut child,
                            "ghostscope runner child",
                            GRACEFUL_TERMINATION_TIMEOUT,
                        )
                        .await?;
                    }
                }
            }
        }

        let timed_out = if ready_fired {
            let read_task = async {
                let mut stdout_line = String::new();
                let mut stderr_line = String::new();
                loop {
                    stdout_line.clear();
                    if let Ok(Ok(n)) = timeout(
                        Duration::from_millis(50),
                        stdout_reader.read_line(&mut stdout_line),
                    )
                    .await
                    {
                        if n > 0 {
                            stdout_content.push_str(&stdout_line);
                        }
                    }

                    stderr_line.clear();
                    if let Ok(Ok(n)) = timeout(
                        Duration::from_millis(50),
                        stderr_reader.read_line(&mut stderr_line),
                    )
                    .await
                    {
                        if n > 0 {
                            stderr_content.push_str(&stderr_line);
                        }
                    }

                    if let Ok(Some(_status)) = child.try_wait() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok::<(), anyhow::Error>(())
            };

            match timeout(Duration::from_secs(monitor_timeout_secs), read_task).await {
                Ok(result) => {
                    result?;
                    false
                }
                Err(_) => true,
            }
        } else {
            false
        };

        let mut exit_code = match child.try_wait() {
            Ok(Some(status)) => status.code().unwrap_or(-1),
            _ => {
                if timed_out {
                    if let Some(pid) = managed_ghostscope_pid {
                        sandbox.terminate_pid(pid).with_context(|| {
                            format!(
                                "failed to terminate timed-out GhostScope pid {} in {}",
                                pid,
                                sandbox.label()
                            )
                        })?;
                        match timeout(GRACEFUL_TERMINATION_TIMEOUT, child.wait()).await {
                            Ok(Ok(status)) => status.code().unwrap_or(-1),
                            _ => -1,
                        }
                    } else {
                        match terminate_tokio_child_gracefully(
                            &mut child,
                            "ghostscope runner child",
                            GRACEFUL_TERMINATION_TIMEOUT,
                        )
                        .await?
                        {
                            Some(status) => status.code().unwrap_or(-1),
                            None => -1,
                        }
                    }
                } else {
                    match timeout(Duration::from_secs(2), child.wait()).await {
                        Ok(Ok(status)) => status.code().unwrap_or(-1),
                        _ => -1,
                    }
                }
            }
        };

        {
            let mut line = String::new();
            loop {
                line.clear();
                match stdout_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => stdout_content.push_str(&line),
                    Err(_) => break,
                }
            }
        }
        {
            let mut line = String::new();
            loop {
                line.clear();
                match stderr_reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => stderr_content.push_str(&line),
                    Err(_) => break,
                }
            }
        }

        if exit_code == -1 && (!stdout_content.is_empty() || !stderr_content.is_empty()) {
            exit_code = 0;
        }

        if !ready_fired && require_ready_marker {
            anyhow::bail!(
                "GhostScope exited before reaching ready state '{}'. stderr={} stdout={}",
                ready_marker.as_deref().unwrap_or("<none>"),
                stderr_content,
                stdout_content
            );
        }

        Ok((
            exit_code,
            stdout_content,
            stderr_content,
            ready_result.expect("ready result missing after runner completion"),
        ))
    }

    fn resolve_logging_config(&self) -> EffectiveLoggingConfig {
        let env_log_level = env::var(ENV_GHOSTSCOPE_LOG_LEVEL)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        let env_enable_logging = env_bool(ENV_GHOSTSCOPE_ENABLE_LOGGING);
        let env_console_logging = env_bool(ENV_GHOSTSCOPE_LOG_CONSOLE);

        let level = self.log_level.clone().or(env_log_level);
        let mut enable_logging = self.enable_file_logging || env_enable_logging.unwrap_or(false);
        let mut enable_console_logging =
            self.enable_console_logging || env_console_logging.unwrap_or(false);

        // A requested log level is only useful if GhostScope logging is enabled.
        // Default to dual file+console logging so `cargo test` and runner jobs
        // surface the requested logs without additional flags.
        if level.is_some() && !enable_logging && !enable_console_logging {
            enable_logging = true;
            enable_console_logging = true;
        } else if enable_console_logging {
            enable_logging = true;
        }

        EffectiveLoggingConfig {
            level,
            enable_logging,
            enable_console_logging,
        }
    }

    fn effective_timeout_secs(&self) -> u64 {
        self.timeout_secs
    }

    fn setup_timeout_secs(&self) -> u64 {
        let mut timeout_secs = self.timeout_secs.max(15);
        if env::var(ENV_E2E_TARGET_MODE)
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("child-container"))
        {
            timeout_secs = timeout_secs.saturating_add(CHILD_CONTAINER_TIMEOUT_SLACK_SECS);
        }
        timeout_secs
    }
}

struct EffectiveLoggingConfig {
    level: Option<String>,
    enable_logging: bool,
    enable_console_logging: bool,
}

fn create_script_file() -> Result<NamedTempFile> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve repo root for temp script file"))?
        .to_path_buf();
    Builder::new()
        .prefix(".ghostscope-test-script-")
        .suffix(".gs")
        .tempfile_in(repo_root)
        .map_err(Into::into)
}

fn env_bool(name: &str) -> Option<bool> {
    let raw = env::var(name).ok()?;
    let value = raw.trim();
    if value.is_empty() {
        return None;
    }

    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

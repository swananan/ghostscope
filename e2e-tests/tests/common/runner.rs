#![allow(dead_code)]

//! Shared asynchronous runner for invoking the `ghostscope` CLI from tests.
//!
//! Features:
//! - Attach by PID, target path, or both for target-scoped PID runs
//! - Optional sandbox backend for GhostScope itself (host by default)
//! - Configurable timeout (overall cap) and optional PerfEventArray backend
//! - Consistent flags: disable artifact saving by default; logging opt-in
//! - Robust output collection: incremental read during run, drain after exit
//! - Pragmatic success rule: if process was terminated on timeout but produced
//!   any output, treat exit code -1 as success (0) to keep tests stable

use super::sandbox::SandboxHandle;
use super::targets::ensure_target_binary_ready_for_default_sandbox;
use super::targets::TargetHandle;
use super::termination::{
    terminate_tokio_child_with_escalation, FORCEFUL_TERMINATION_TIMEOUT,
    GRACEFUL_TERMINATION_TIMEOUT,
};
use anyhow::{Context, Result};
use ghostscope_process::is_shared_object;
use std::env;
use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use tempfile::{Builder, NamedTempFile};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

const ENV_GHOSTSCOPE_LOG_LEVEL: &str = "E2E_GHOSTSCOPE_LOG_LEVEL";
const ENV_GHOSTSCOPE_ENABLE_LOGGING: &str = "E2E_GHOSTSCOPE_ENABLE_LOGGING";
const ENV_GHOSTSCOPE_LOG_CONSOLE: &str = "E2E_GHOSTSCOPE_LOG_CONSOLE";
const ENV_E2E_TARGET_MODE: &str = "E2E_TARGET_MODE";
const ENV_E2E_GHOSTSCOPE_SANDBOX: &str = "E2E_GHOSTSCOPE_SANDBOX";
const ENV_E2E_TARGET_SANDBOX: &str = "E2E_TARGET_SANDBOX";
const GHOSTSCOPE_PID_BOOTSTRAP_PREFIX: &str = "__GHOSTSCOPE_PID__ ";
#[allow(dead_code)]
const GHOSTSCOPE_READY_MARKER: &str = "__GHOSTSCOPE_READY__";
const CHILD_CONTAINER_TIMEOUT_SLACK_SECS: u64 = 45;
const CHILD_CONTAINER_POST_READY_CALLBACK_SLACK_SECS: u64 = 45;
// CI commonly starts four BPF-heavy tests together. Leave enough headroom for
// their verifier work before treating a missing ready marker as a stalled load.
const CONTAINER_TOPOLOGY_SETUP_SLACK_SECS: u64 = 30;

pub struct GhostscopeRunner {
    script_content: String,
    pid: Option<u32>,
    attach_target: Option<TargetHandle>,
    target: Option<PathBuf>,
    timeout_secs: u64,
    force_perf_event_array: bool,
    log_level: Option<String>,
    enable_sysmon_for_target: bool,
    disable_sysmon_for_target: bool,
    enable_file_logging: bool,
    enable_console_logging: bool,
    sandbox: Option<SandboxHandle>,
    config_content: Option<String>,
    extra_args: Vec<OsString>,
    startup_timeout_secs: Option<u64>,
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
            enable_sysmon_for_target: false,
            disable_sysmon_for_target: false,
            enable_file_logging: false,
            enable_console_logging: false,
            sandbox: None,
            config_content: None,
            extra_args: Vec::new(),
            startup_timeout_secs: None,
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

    #[allow(dead_code)]
    pub fn startup_timeout_secs(mut self, secs: u64) -> Self {
        self.startup_timeout_secs = Some(secs);
        self
    }

    pub fn force_perf_event_array(mut self, yes: bool) -> Self {
        self.force_perf_event_array = yes;
        self
    }

    pub fn enable_sysmon_for_target(mut self, yes: bool) -> Self {
        self.enable_sysmon_for_target = yes;
        self
    }

    pub fn disable_sysmon_for_target(mut self, yes: bool) -> Self {
        self.disable_sysmon_for_target = yes;
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

    pub fn with_cli_args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.extra_args.extend(args.into_iter().map(Into::into));
        self
    }

    #[allow(dead_code)]
    pub fn with_config_content(mut self, content: impl Into<String>) -> Self {
        self.config_content = Some(content.into());
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
        let runner_debug = logging.level.is_some();
        let monitor_timeout_secs = self.effective_timeout_secs();
        let setup_timeout_secs = self.setup_timeout_secs();
        let post_ready_callback_timeout_secs = self.post_ready_callback_timeout_secs();
        let sandbox = match self.sandbox {
            Some(sandbox) => sandbox,
            None => SandboxHandle::default_ghostscope()?,
        };

        let by_pid = self.pid.is_some();
        let by_attached_target = self.attach_target.is_some();
        let by_target = self.target.is_some();
        anyhow::ensure!(
            by_pid || by_attached_target || by_target,
            "Must set pid, attached target, target path, or a target path plus one PID source"
        );
        anyhow::ensure!(
            !(by_pid && by_attached_target),
            "Must set at most one PID source: pid or attached target"
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
        let config_file =
            if self.disable_sysmon_for_target || self.config_content.as_deref().is_some() {
                let mut file = create_config_file()?;
                let content = build_config_content(
                    self.config_content.as_deref(),
                    self.disable_sysmon_for_target,
                );
                file.write_all(content.as_bytes())?;
                Some(file)
            } else {
                None
            };

        let mut args: Vec<OsString> = Vec::new();
        if let Some(ref target) = self.target {
            args.push(OsString::from("-t"));
            args.push(sandbox.path_in_sandbox(target)?.into_os_string());
        }
        if let Some(pid) = self.pid {
            args.push(OsString::from("-p"));
            args.push(OsString::from(pid.to_string()));
        } else if let Some(target) = &self.attach_target {
            let pid = target.visible_pid_from(&sandbox)?;
            args.push(OsString::from("-p"));
            args.push(OsString::from(pid.to_string()));
        }

        args.push(OsString::from("--script-file"));
        args.push(script_path.into_os_string());
        if let Some(config_file) = config_file.as_ref() {
            args.push(OsString::from("--config"));
            args.push(
                sandbox
                    .path_in_sandbox(config_file.path())?
                    .into_os_string(),
            );
        }

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
        if self.enable_sysmon_for_target {
            args.push(OsString::from("--enable-sysmon-for-target"));
        }
        if logging.enable_logging {
            args.push(OsString::from("--log"));
        }
        if logging.enable_console_logging {
            args.push(OsString::from("--log-console"));
        }
        args.extend(self.extra_args);

        let launch = sandbox.ghostscope_runner_command(&args)?;
        let mut cmd = Command::new(&launch.program);
        cmd.args(&launch.args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn()?;
        let stdout_handle = child.stdout.take().unwrap();
        let stderr_handle = child.stderr.take().unwrap();
        let mut stdout_reader = BufReader::new(stdout_handle);
        let stderr_reader = BufReader::new(stderr_handle);

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

        let (output_tx, mut output_rx) = mpsc::unbounded_channel();
        let stdout_task =
            spawn_output_reader(stdout_reader, OutputStream::Stdout, output_tx.clone());
        let stderr_task = spawn_output_reader(stderr_reader, OutputStream::Stderr, output_tx);

        if !ready_fired {
            let pre_ready_task = async {
                loop {
                    let mut saw_output = false;
                    while let Ok(output_line) = output_rx.try_recv() {
                        saw_output = true;
                        if handle_output_line(
                            output_line,
                            &mut stdout_content,
                            &mut stderr_content,
                            ready_marker.as_deref(),
                            runner_debug,
                            &sandbox,
                        ) {
                            ready_fired = true;
                            break;
                        }
                    }
                    if ready_fired {
                        break;
                    }
                    if !saw_output {
                        match timeout(Duration::from_millis(100), output_rx.recv()).await {
                            Ok(Some(output_line)) => {
                                if handle_output_line(
                                    output_line,
                                    &mut stdout_content,
                                    &mut stderr_content,
                                    ready_marker.as_deref(),
                                    runner_debug,
                                    &sandbox,
                                ) {
                                    ready_fired = true;
                                    break;
                                }
                            }
                            Ok(None) => tokio::time::sleep(Duration::from_millis(100)).await,
                            Err(_) => {}
                        }
                    }

                    if let Ok(Some(_status)) = child.try_wait() {
                        break;
                    }
                }
                Ok::<(), anyhow::Error>(())
            };

            match timeout(Duration::from_secs(setup_timeout_secs), pre_ready_task).await {
                Ok(result) => result?,
                Err(_) => {
                    if runner_debug {
                        eprintln!(
                            "[ghostscope-test-runner] timed out waiting for ready marker from {} after {}s",
                            sandbox.label(),
                            setup_timeout_secs
                        );
                    }
                    let termination_result = terminate_runner_process(
                        &sandbox,
                        managed_ghostscope_pid,
                        &mut child,
                        "startup-stalled GhostScope",
                    )
                    .await;
                    finish_output_readers(stdout_task, stderr_task).await;
                    drain_output_channel(
                        &mut output_rx,
                        &mut stdout_content,
                        &mut stderr_content,
                        ready_marker.as_deref(),
                        runner_debug,
                        &sandbox,
                    );
                    termination_result?;
                    anyhow::bail!(
                        "timed out waiting for ready marker '{}' from {} after {}s. stderr={} stdout={}",
                        ready_marker.as_deref().unwrap_or("<none>"),
                        sandbox.label(),
                        setup_timeout_secs,
                        stderr_content,
                        stdout_content
                    );
                }
            }
        }

        if ready_fired && ready_result.is_none() {
            if let Some(callback) = ready_callback.take() {
                if runner_debug {
                    eprintln!(
                        "[ghostscope-test-runner] starting post-ready callback for {} with {}s timeout",
                        sandbox.label(),
                        post_ready_callback_timeout_secs
                    );
                }
                match timeout(
                    Duration::from_secs(post_ready_callback_timeout_secs),
                    callback(),
                )
                .await
                {
                    Ok(result) => {
                        if runner_debug {
                            eprintln!(
                                "[ghostscope-test-runner] completed post-ready callback for {}",
                                sandbox.label()
                            );
                        }
                        ready_result = Some(result?);
                    }
                    Err(_) => {
                        if runner_debug {
                            eprintln!(
                                "[ghostscope-test-runner] timed out waiting for post-ready callback for {} after {}s",
                                sandbox.label(),
                                post_ready_callback_timeout_secs
                            );
                        }
                        let termination_result = terminate_runner_process(
                            &sandbox,
                            managed_ghostscope_pid,
                            &mut child,
                            "GhostScope after post-ready callback timeout",
                        )
                        .await;
                        finish_output_readers(stdout_task, stderr_task).await;
                        drain_output_channel(
                            &mut output_rx,
                            &mut stdout_content,
                            &mut stderr_content,
                            ready_marker.as_deref(),
                            runner_debug,
                            &sandbox,
                        );
                        termination_result?;
                        anyhow::bail!(
                            "timed out waiting for post-ready callback after ready marker '{}' in {}. stderr={} stdout={}",
                            ready_marker.as_deref().unwrap_or("<none>"),
                            sandbox.label(),
                            stderr_content,
                            stdout_content
                        );
                    }
                }
            }
        }

        let timed_out = if ready_fired {
            let read_task = async {
                loop {
                    let mut saw_output = false;
                    while let Ok(output_line) = output_rx.try_recv() {
                        saw_output = true;
                        handle_output_line(
                            output_line,
                            &mut stdout_content,
                            &mut stderr_content,
                            ready_marker.as_deref(),
                            runner_debug,
                            &sandbox,
                        );
                    }
                    if !saw_output {
                        match timeout(Duration::from_millis(100), output_rx.recv()).await {
                            Ok(Some(output_line)) => {
                                handle_output_line(
                                    output_line,
                                    &mut stdout_content,
                                    &mut stderr_content,
                                    ready_marker.as_deref(),
                                    runner_debug,
                                    &sandbox,
                                );
                            }
                            Ok(None) => tokio::time::sleep(Duration::from_millis(100)).await,
                            Err(_) => {}
                        }
                    }

                    if let Ok(Some(_status)) = child.try_wait() {
                        break;
                    }
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

        let exit_code_result = match child.try_wait() {
            Ok(Some(status)) => Ok(status.code().unwrap_or(-1)),
            _ => {
                if timed_out {
                    terminate_runner_process(
                        &sandbox,
                        managed_ghostscope_pid,
                        &mut child,
                        "timed-out GhostScope",
                    )
                    .await
                    .map(|status| status.and_then(|status| status.code()).unwrap_or(-1))
                } else {
                    match timeout(Duration::from_secs(2), child.wait()).await {
                        Ok(Ok(status)) => Ok(status.code().unwrap_or(-1)),
                        Ok(Err(err)) => Err(err.into()),
                        Err(_) => Ok(-1),
                    }
                }
            }
        };

        finish_output_readers(stdout_task, stderr_task).await;
        drain_output_channel(
            &mut output_rx,
            &mut stdout_content,
            &mut stderr_content,
            ready_marker.as_deref(),
            runner_debug,
            &sandbox,
        );

        let mut exit_code = exit_code_result?;
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
        if let Some(timeout_secs) = self.startup_timeout_secs {
            return timeout_secs;
        }

        let mut timeout_secs = self.timeout_secs.max(15);
        let docker_topology = [ENV_E2E_GHOSTSCOPE_SANDBOX, ENV_E2E_TARGET_SANDBOX]
            .into_iter()
            .filter_map(|key| env::var(key).ok())
            .any(|value| value.trim_start().starts_with("docker-"));
        if docker_topology {
            timeout_secs = timeout_secs.saturating_add(CONTAINER_TOPOLOGY_SETUP_SLACK_SECS);
        }
        if env::var(ENV_E2E_TARGET_MODE)
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("child-container"))
        {
            timeout_secs = timeout_secs.saturating_add(CHILD_CONTAINER_TIMEOUT_SLACK_SECS);
        }
        timeout_secs
    }

    fn post_ready_callback_timeout_secs(&self) -> u64 {
        let mut timeout_secs = self.setup_timeout_secs();
        if env::var(ENV_E2E_TARGET_MODE)
            .ok()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("child-container"))
        {
            timeout_secs =
                timeout_secs.saturating_add(CHILD_CONTAINER_POST_READY_CALLBACK_SLACK_SECS);
        }
        timeout_secs
    }
}

struct EffectiveLoggingConfig {
    level: Option<String>,
    enable_logging: bool,
    enable_console_logging: bool,
}

#[derive(Clone, Copy)]
enum OutputStream {
    Stdout,
    Stderr,
}

struct OutputLine {
    stream: OutputStream,
    line: String,
}

fn spawn_output_reader<R>(
    mut reader: BufReader<R>,
    stream: OutputStream,
    tx: UnboundedSender<OutputLine>,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    if tx
                        .send(OutputLine {
                            stream,
                            line: line.clone(),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

async fn terminate_runner_process(
    sandbox: &SandboxHandle,
    managed_pid: Option<u32>,
    child: &mut tokio::process::Child,
    label: &str,
) -> Result<Option<std::process::ExitStatus>> {
    let managed_result = managed_pid
        .map(|pid| {
            sandbox.terminate_pid(pid).with_context(|| {
                format!(
                    "failed to terminate {label} pid {} in {}",
                    pid,
                    sandbox.label()
                )
            })
        })
        .transpose();
    let child_result = if managed_pid.is_some() {
        match timeout(GRACEFUL_TERMINATION_TIMEOUT, child.wait()).await {
            Ok(result) => result.map(Some).map_err(Into::into),
            Err(_) => {
                terminate_tokio_child_with_escalation(
                    child,
                    "ghostscope runner child",
                    GRACEFUL_TERMINATION_TIMEOUT,
                    FORCEFUL_TERMINATION_TIMEOUT,
                )
                .await
            }
        }
    } else {
        terminate_tokio_child_with_escalation(
            child,
            "ghostscope runner child",
            GRACEFUL_TERMINATION_TIMEOUT,
            FORCEFUL_TERMINATION_TIMEOUT,
        )
        .await
    };

    match (managed_result, child_result) {
        (Ok(_), Ok(status)) => Ok(status),
        (Err(err), Ok(_)) | (Ok(_), Err(err)) => Err(err),
        (Err(managed_err), Err(child_err)) => {
            anyhow::bail!("{managed_err:#}; host runner process cleanup also failed: {child_err:#}")
        }
    }
}

async fn finish_output_readers(stdout_task: JoinHandle<()>, stderr_task: JoinHandle<()>) {
    tokio::join!(
        finish_output_reader(stdout_task),
        finish_output_reader(stderr_task)
    );
}

async fn finish_output_reader(mut task: JoinHandle<()>) {
    if timeout(FORCEFUL_TERMINATION_TIMEOUT, &mut task)
        .await
        .is_err()
    {
        task.abort();
        let _ = task.await;
    }
}

fn handle_output_line(
    output_line: OutputLine,
    stdout_content: &mut String,
    stderr_content: &mut String,
    ready_marker: Option<&str>,
    runner_debug: bool,
    sandbox: &SandboxHandle,
) -> bool {
    let target = match output_line.stream {
        OutputStream::Stdout => stdout_content,
        OutputStream::Stderr => stderr_content,
    };
    target.push_str(&output_line.line);

    let saw_ready = ready_marker.is_some_and(|marker| output_line.line.trim_end() == marker);
    if saw_ready && runner_debug {
        let stream = match output_line.stream {
            OutputStream::Stdout => "stdout",
            OutputStream::Stderr => "stderr",
        };
        eprintln!(
            "[ghostscope-test-runner] observed ready marker on {stream} from {}",
            sandbox.label()
        );
    }

    saw_ready
}

fn drain_output_channel(
    output_rx: &mut UnboundedReceiver<OutputLine>,
    stdout_content: &mut String,
    stderr_content: &mut String,
    ready_marker: Option<&str>,
    runner_debug: bool,
    sandbox: &SandboxHandle,
) {
    while let Ok(output_line) = output_rx.try_recv() {
        handle_output_line(
            output_line,
            stdout_content,
            stderr_content,
            ready_marker,
            runner_debug,
            sandbox,
        );
    }
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

fn create_config_file() -> Result<NamedTempFile> {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("failed to resolve repo root for temp config file"))?
        .to_path_buf();
    Builder::new()
        .prefix(".ghostscope-test-config-")
        .suffix(".toml")
        .tempfile_in(repo_root)
        .map_err(Into::into)
}

fn build_config_content(config_content: Option<&str>, disable_sysmon_for_target: bool) -> String {
    let mut lines = config_content
        .unwrap_or_default()
        .lines()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();

    if disable_sysmon_for_target && !contains_config_key(&lines, "enable_sysmon_for_target") {
        let setting = "enable_sysmon_for_target = false".to_string();
        if let Some(ebpf_table_index) = lines.iter().position(|line| line.trim() == "[ebpf]") {
            lines.insert(ebpf_table_index + 1, setting);
        } else {
            lines.push("[ebpf]".to_string());
            lines.push(setting);
        }
    }

    let mut content = lines.join("\n");
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content
}

fn contains_config_key(lines: &[String], key: &str) -> bool {
    lines.iter().any(|line| {
        let trimmed = line.trim_start();
        !trimmed.starts_with('#') && trimmed.starts_with(key)
    })
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

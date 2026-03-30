#![allow(dead_code)]

use super::sandbox::{BackgroundProcess, SandboxHandle};
use super::termination::{terminate_std_child_gracefully, GRACEFUL_TERMINATION_TIMEOUT};
use super::{ensure_test_program_compiled_with_opt, OptimizationLevel};
use anyhow::{Context, Result};
use std::env;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

const ENV_E2E_TARGET_MODE: &str = "E2E_TARGET_MODE";

#[derive(Debug, Clone)]
pub struct TargetHandle {
    inner: Arc<TargetHandleInner>,
}

struct TargetHandleInner {
    sandbox: SandboxHandle,
    sandbox_pid: u32,
    host_pid: u32,
    container_pid: Option<u32>,
    nspid_chain: Vec<u32>,
    process_handle: TargetProcessHandle,
}

enum TargetProcessHandle {
    Host(Mutex<Option<std::process::Child>>),
    Detached,
    ChildContainer { container_name: String },
}

impl fmt::Debug for TargetHandleInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetHandleInner")
            .field("sandbox", &self.sandbox)
            .field("sandbox_pid", &self.sandbox_pid)
            .field("host_pid", &self.host_pid)
            .field("container_pid", &self.container_pid)
            .field("nspid_chain", &self.nspid_chain)
            .field("process_handle", &self.process_handle)
            .finish()
    }
}

impl fmt::Debug for TargetProcessHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(_) => f.write_str("Host"),
            Self::Detached => f.write_str("Detached"),
            Self::ChildContainer { container_name } => f
                .debug_struct("ChildContainer")
                .field("container_name", container_name)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetLauncher {
    sandbox: Option<SandboxHandle>,
    program: TargetProgram,
    working_dir: Option<PathBuf>,
    launch_mode: Option<TargetLaunchMode>,
}

#[derive(Debug, Clone)]
enum TargetProgram {
    SampleProgram(OptimizationLevel),
    Binary(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetLaunchMode {
    Direct,
    ChildContainer,
}

impl TargetLaunchMode {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "direct" | "same" | "same-sandbox" => Ok(Self::Direct),
            "child-container" | "child" | "nested" | "descendant" => Ok(Self::ChildContainer),
            _ => anyhow::bail!("expected one of: direct, child-container"),
        }
    }
}

impl TargetLauncher {
    pub fn sample_program() -> Self {
        Self::sample_program_with_opt(OptimizationLevel::Debug)
    }

    pub fn sample_program_with_opt(opt_level: OptimizationLevel) -> Self {
        Self {
            sandbox: None,
            program: TargetProgram::SampleProgram(opt_level),
            working_dir: None,
            launch_mode: None,
        }
    }

    pub fn binary<P: AsRef<Path>>(path: P) -> Self {
        Self {
            sandbox: None,
            program: TargetProgram::Binary(path.as_ref().to_path_buf()),
            working_dir: None,
            launch_mode: None,
        }
    }

    pub fn in_sandbox(mut self, sandbox: &SandboxHandle) -> Self {
        self.sandbox = Some(sandbox.clone());
        self
    }

    pub fn in_child_container_of(mut self, sandbox: &SandboxHandle) -> Self {
        self.sandbox = Some(sandbox.clone());
        self.launch_mode = Some(TargetLaunchMode::ChildContainer);
        self
    }

    pub fn current_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.working_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub async fn spawn(self) -> Result<TargetHandle> {
        let use_default_sandbox = self.sandbox.is_none();
        let sandbox = match self.sandbox {
            Some(sandbox) => sandbox,
            None => SandboxHandle::default_target()?,
        };
        let launch_mode = match self.launch_mode {
            Some(mode) => mode,
            None if use_default_sandbox => default_target_launch_mode()?,
            None => TargetLaunchMode::Direct,
        };
        match self.program {
            TargetProgram::SampleProgram(opt_level) => {
                spawn_sample_program(
                    &sandbox,
                    opt_level,
                    self.working_dir.as_deref(),
                    launch_mode,
                )
                .await
            }
            TargetProgram::Binary(path) => {
                let binary_path = ensure_binary_ready(&sandbox, &path)?;
                spawn_binary_target(
                    &sandbox,
                    &binary_path,
                    self.working_dir.as_deref(),
                    launch_mode,
                )
                .await
            }
        }
    }
}

pub(crate) fn ensure_target_binary_ready_for_default_sandbox(
    binary_path: &Path,
) -> Result<SandboxHandle> {
    let sandbox = SandboxHandle::default_target()?;
    let _ = ensure_binary_ready(&sandbox, binary_path)?;
    if matches!(
        default_target_launch_mode()?,
        TargetLaunchMode::ChildContainer
    ) {
        sandbox.ensure_child_container_runtime_ready()?;
    }
    Ok(sandbox)
}

impl TargetHandle {
    pub fn sandbox(&self) -> &SandboxHandle {
        &self.inner.sandbox
    }

    pub fn sandbox_pid(&self) -> u32 {
        self.inner.sandbox_pid
    }

    pub fn host_pid(&self) -> u32 {
        self.inner.host_pid
    }

    pub fn container_pid(&self) -> Option<u32> {
        self.inner.container_pid
    }

    #[allow(dead_code)]
    pub fn nspid_chain(&self) -> &[u32] {
        &self.inner.nspid_chain
    }

    pub fn visible_pid_from(&self, observer: &SandboxHandle) -> Result<u32> {
        if observer.same_sandbox(self.sandbox()) {
            return Ok(self.sandbox_pid());
        }
        if observer.is_host_pid_view() {
            return Ok(self.host_pid());
        }
        observer
            .resolve_visible_pid_for_host_pid(self.host_pid())?
            .with_context(|| {
                format!(
                    "target host pid {} is not visible from observer sandbox {}",
                    self.host_pid(),
                    observer.label()
                )
            })
    }

    pub async fn terminate(&self) -> Result<()> {
        match &self.inner.process_handle {
            TargetProcessHandle::Host(child) => {
                if let Some(mut child) = child.lock().await.take() {
                    let pid = child.id();
                    tokio::task::spawn_blocking(move || -> Result<()> {
                        match terminate_std_child_gracefully(
                            &mut child,
                            "host target",
                            GRACEFUL_TERMINATION_TIMEOUT,
                        )? {
                            Some(_) => Ok(()),
                            None => anyhow::bail!(
                                "timed out waiting for host target pid {} to exit after SIGTERM",
                                pid
                            ),
                        }
                    })
                    .await
                    .context("host target reaping task panicked")??;
                }
            }
            TargetProcessHandle::Detached => {
                self.sandbox()
                    .terminate_pid(self.sandbox_pid())
                    .with_context(|| {
                        format!(
                            "failed to terminate target pid {} in sandbox {}",
                            self.sandbox_pid(),
                            self.sandbox().label()
                        )
                    })?;
            }
            TargetProcessHandle::ChildContainer { container_name } => {
                self.sandbox()
                    .remove_child_container(container_name)
                    .with_context(|| {
                        format!(
                            "failed to remove child container {} in sandbox {}",
                            container_name,
                            self.sandbox().label()
                        )
                    })?;
            }
        }
        Ok(())
    }
}

async fn spawn_sample_program(
    sandbox: &SandboxHandle,
    opt_level: OptimizationLevel,
    working_dir: Option<&Path>,
    launch_mode: TargetLaunchMode,
) -> Result<TargetHandle> {
    let binary_path = ensure_sample_program_ready(sandbox, opt_level)?;
    spawn_binary_target(sandbox, &binary_path, working_dir, launch_mode).await
}

async fn spawn_binary_target(
    sandbox: &SandboxHandle,
    binary_path: &Path,
    working_dir: Option<&Path>,
    launch_mode: TargetLaunchMode,
) -> Result<TargetHandle> {
    let binary_path = sandbox.path_in_sandbox(binary_path)?;
    let working_dir = working_dir
        .map(|path| sandbox.path_in_sandbox(path))
        .transpose()?;
    let process = match launch_mode {
        TargetLaunchMode::Direct => sandbox
            .spawn_background_binary(&binary_path, working_dir.as_deref())
            .with_context(|| {
                format!(
                    "failed to start target binary {} in {}",
                    binary_path.display(),
                    sandbox.label()
                )
            })?,
        TargetLaunchMode::ChildContainer => sandbox
            .spawn_background_binary_in_child_container(&binary_path, working_dir.as_deref())
            .with_context(|| {
                format!(
                    "failed to start child-container target binary {} in {}",
                    binary_path.display(),
                    sandbox.label()
                )
            })?,
    };
    let sandbox_pid = process.pid();
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let status = sandbox
        .read_status(sandbox_pid)
        .with_context(|| format!("failed to read target status for pid {sandbox_pid}"))?;
    let nspid_chain = parse_nspid_chain(&status).context("target status did not contain NSpid")?;
    let host_pid = if sandbox.is_host_pid_view() {
        nspid_chain
            .first()
            .copied()
            .with_context(|| "target status did not expose a host-visible PID".to_string())?
    } else {
        sandbox
            .resolve_host_pid_for_sandbox_pid(sandbox_pid)
            .context("failed to resolve host PID for target process")?
    };
    let container_pid = nspid_chain.last().copied();

    Ok(TargetHandle {
        inner: Arc::new(TargetHandleInner {
            sandbox: sandbox.clone(),
            sandbox_pid,
            host_pid,
            container_pid,
            nspid_chain,
            process_handle: match process {
                BackgroundProcess::Host { child, .. } => {
                    TargetProcessHandle::Host(Mutex::new(Some(child)))
                }
                BackgroundProcess::Detached { .. } => TargetProcessHandle::Detached,
                BackgroundProcess::ChildContainer { container_name, .. } => {
                    TargetProcessHandle::ChildContainer { container_name }
                }
            },
        }),
    })
}

fn default_target_launch_mode() -> Result<TargetLaunchMode> {
    match env::var(ENV_E2E_TARGET_MODE) {
        Ok(value) => TargetLaunchMode::parse(&value)
            .with_context(|| format!("invalid value for {ENV_E2E_TARGET_MODE}: {value}")),
        Err(env::VarError::NotPresent) => Ok(TargetLaunchMode::Direct),
        Err(err) => Err(anyhow::Error::new(err))
            .with_context(|| format!("failed to read environment variable {ENV_E2E_TARGET_MODE}")),
    }
}

fn ensure_sample_program_ready(
    sandbox: &SandboxHandle,
    opt_level: OptimizationLevel,
) -> Result<PathBuf> {
    ensure_test_program_compiled_with_opt(opt_level)?;

    sandbox.repo_path_for_fixture_binary(Path::new(&format!(
        "ghostscope/tests/fixtures/sample_program/{}",
        opt_level.as_binary_name()
    )))
}

fn ensure_binary_ready(_sandbox: &SandboxHandle, binary_path: &Path) -> Result<PathBuf> {
    anyhow::ensure!(
        binary_path.exists(),
        "target binary {} does not exist on host; build the fixture before launching a container-backed target",
        binary_path.display()
    );
    Ok(binary_path.to_path_buf())
}

fn parse_nspid_chain(status: &str) -> Option<Vec<u32>> {
    let line = status.lines().find(|line| line.starts_with("NSpid:"))?;
    let chain: Vec<u32> = line
        .strip_prefix("NSpid:")?
        .split_whitespace()
        .filter_map(|token| token.parse::<u32>().ok())
        .collect();
    if chain.is_empty() {
        None
    } else {
        Some(chain)
    }
}

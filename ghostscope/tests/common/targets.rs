#![allow(dead_code)]

use super::sandbox::{BackgroundProcess, SandboxHandle};
use super::{ensure_test_program_compiled_with_opt, OptimizationLevel};
use anyhow::{Context, Result};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const SAMPLE_PROGRAM_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/sample_program";
const COMPLEX_TYPES_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/complex_types_program";
const GLOBALS_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/globals_program";
const RUST_GLOBAL_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/rust_global_program";
const CPP_COMPLEX_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/cpp_complex_program";

#[derive(Debug, Clone)]
pub struct TargetHandle {
    inner: Arc<TargetHandleInner>,
}

struct TargetHandleInner {
    sandbox: SandboxHandle,
    sandbox_pid: u32,
    host_pid: u32,
    nspid_chain: Vec<u32>,
    process_handle: TargetProcessHandle,
}

enum TargetProcessHandle {
    Host(Mutex<Option<std::process::Child>>),
    Detached,
}

impl fmt::Debug for TargetHandleInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TargetHandleInner")
            .field("sandbox", &self.sandbox)
            .field("sandbox_pid", &self.sandbox_pid)
            .field("host_pid", &self.host_pid)
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
        }
    }
}

#[derive(Debug, Clone)]
pub struct TargetLauncher {
    sandbox: Option<SandboxHandle>,
    program: TargetProgram,
    working_dir: Option<PathBuf>,
}

#[derive(Debug, Clone)]
enum TargetProgram {
    SampleProgram(OptimizationLevel),
    Binary(PathBuf),
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
        }
    }

    pub fn binary<P: AsRef<Path>>(path: P) -> Self {
        Self {
            sandbox: None,
            program: TargetProgram::Binary(path.as_ref().to_path_buf()),
            working_dir: None,
        }
    }

    pub fn in_sandbox(mut self, sandbox: &SandboxHandle) -> Self {
        self.sandbox = Some(sandbox.clone());
        self
    }

    pub fn current_dir<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.working_dir = Some(path.as_ref().to_path_buf());
        self
    }

    pub async fn spawn(self) -> Result<TargetHandle> {
        let sandbox = match self.sandbox {
            Some(sandbox) => sandbox,
            None => SandboxHandle::default_target()?,
        };
        match self.program {
            TargetProgram::SampleProgram(opt_level) => {
                spawn_sample_program(&sandbox, opt_level, self.working_dir.as_deref()).await
            }
            TargetProgram::Binary(path) => {
                let binary_path = ensure_binary_ready(&sandbox, &path)?;
                spawn_binary_target(&sandbox, &binary_path, self.working_dir.as_deref()).await
            }
        }
    }
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
                    tokio::task::spawn_blocking(move || {
                        let _ = child.kill();
                        let _ = child.wait();
                    })
                    .await
                    .context("host target reaping task panicked")?;
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
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }
        Ok(())
    }
}

async fn spawn_sample_program(
    sandbox: &SandboxHandle,
    opt_level: OptimizationLevel,
    working_dir: Option<&Path>,
) -> Result<TargetHandle> {
    let binary_path = ensure_sample_program_ready(sandbox, opt_level)?;
    spawn_binary_target(sandbox, &binary_path, working_dir).await
}

async fn spawn_binary_target(
    sandbox: &SandboxHandle,
    binary_path: &Path,
    working_dir: Option<&Path>,
) -> Result<TargetHandle> {
    let binary_path = sandbox.path_in_sandbox(binary_path)?;
    let working_dir = working_dir
        .map(|path| sandbox.path_in_sandbox(path))
        .transpose()?;
    let process = sandbox
        .spawn_background_binary(&binary_path, working_dir.as_deref())
        .with_context(|| {
            format!(
                "failed to start target binary {} in {}",
                binary_path.display(),
                sandbox.label()
            )
        })?;
    let sandbox_pid = process.pid();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let status = sandbox
        .read_status(sandbox_pid)
        .with_context(|| format!("failed to read target status for pid {sandbox_pid}"))?;
    let nspid_chain = parse_nspid_chain(&status).context("target status did not contain NSpid")?;
    let host_pid = sandbox
        .resolve_host_pid_for_sandbox_pid(sandbox_pid)
        .context("failed to resolve host PID for target process")?;

    Ok(TargetHandle {
        inner: Arc::new(TargetHandleInner {
            sandbox: sandbox.clone(),
            sandbox_pid,
            host_pid,
            nspid_chain,
            process_handle: match process {
                BackgroundProcess::Host { child, .. } => {
                    TargetProcessHandle::Host(Mutex::new(Some(child)))
                }
                BackgroundProcess::Detached { .. } => TargetProcessHandle::Detached,
            },
        }),
    })
}

fn ensure_sample_program_ready(
    sandbox: &SandboxHandle,
    opt_level: OptimizationLevel,
) -> Result<PathBuf> {
    if sandbox.is_host_backend() {
        ensure_test_program_compiled_with_opt(opt_level)?;
    } else {
        let build_key = format!("sample_program:{}", opt_level.as_make_target());
        let build_script = format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B {}",
            opt_level.as_make_target()
        );
        sandbox.ensure_fixture_command_built_once(&build_key, &build_script)?;
    }

    sandbox.repo_path_for_fixture_binary(Path::new(&format!(
        "ghostscope/tests/fixtures/sample_program/{}",
        opt_level.as_binary_name()
    )))
}

fn ensure_binary_ready(sandbox: &SandboxHandle, binary_path: &Path) -> Result<PathBuf> {
    if sandbox.is_host_backend() {
        return Ok(binary_path.to_path_buf());
    }

    maybe_prepare_container_fixture_binary(sandbox, binary_path)?;
    Ok(binary_path.to_path_buf())
}

fn maybe_prepare_container_fixture_binary(
    sandbox: &SandboxHandle,
    binary_path: &Path,
) -> Result<()> {
    let repo_root = repo_root()?;
    let Ok(relative) = binary_path.strip_prefix(&repo_root) else {
        return Ok(());
    };

    let command = match relative.to_string_lossy().as_ref() {
        "ghostscope/tests/fixtures/sample_program/sample_program" => Some(format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B sample_program"
        )),
        "ghostscope/tests/fixtures/sample_program/sample_program_o1" => Some(format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B sample_program_o1"
        )),
        "ghostscope/tests/fixtures/sample_program/sample_program_o2" => Some(format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B sample_program_o2"
        )),
        "ghostscope/tests/fixtures/sample_program/sample_program_o3" => Some(format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B sample_program_o3"
        )),
        "ghostscope/tests/fixtures/sample_program/sample_program_stripped" => Some(format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make -B sample_program_stripped"
        )),
        "ghostscope/tests/fixtures/complex_types_program/complex_types_program" => Some(format!(
            "cd {COMPLEX_TYPES_BUILD_DIR} && make -B complex_types_program"
        )),
        "ghostscope/tests/fixtures/complex_types_program/complex_types_program_o1" => Some(
            format!("cd {COMPLEX_TYPES_BUILD_DIR} && make -B complex_types_program_o1"),
        ),
        "ghostscope/tests/fixtures/complex_types_program/complex_types_program_o2" => Some(
            format!("cd {COMPLEX_TYPES_BUILD_DIR} && make -B complex_types_program_o2"),
        ),
        "ghostscope/tests/fixtures/complex_types_program/complex_types_program_o3" => Some(
            format!("cd {COMPLEX_TYPES_BUILD_DIR} && make -B complex_types_program_o3"),
        ),
        "ghostscope/tests/fixtures/complex_types_program/complex_types_program_nopie" => Some(
            format!("cd {COMPLEX_TYPES_BUILD_DIR} && make -B complex_types_program_nopie"),
        ),
        "ghostscope/tests/fixtures/globals_program/globals_program"
        | "ghostscope/tests/fixtures/globals_program/libgvars.so" => {
            Some(format!("cd {GLOBALS_BUILD_DIR} && make -B all"))
        }
        "ghostscope/tests/fixtures/rust_global_program/target/debug/rust_global_program" => {
            Some(format!("cd {RUST_GLOBAL_BUILD_DIR} && cargo build"))
        }
        "ghostscope/tests/fixtures/cpp_complex_program/cpp_complex_program" => {
            Some(format!("cd {CPP_COMPLEX_BUILD_DIR} && make -B"))
        }
        _ => None,
    };

    let Some(command) = command else {
        return Ok(());
    };

    let build_key = format!("fixture-cmd:{command}");
    sandbox.ensure_fixture_command_built_once(&build_key, &command)?;
    Ok(())
}

fn repo_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to resolve workspace root from CARGO_MANIFEST_DIR")
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

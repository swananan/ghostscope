#![allow(dead_code)]

use super::sandbox::SandboxHandle;
use super::{ensure_test_program_compiled_with_opt, OptimizationLevel};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const SAMPLE_PROGRAM_RELATIVE_BIN: &str = "ghostscope/tests/fixtures/sample_program/sample_program";
const SAMPLE_PROGRAM_BUILD_DIR: &str = "/workspace/ghostscope/tests/fixtures/sample_program";

#[derive(Debug, Clone)]
pub struct TargetHandle {
    inner: Arc<TargetHandleInner>,
}

#[derive(Debug)]
struct TargetHandleInner {
    sandbox: SandboxHandle,
    sandbox_pid: u32,
    host_pid: u32,
    nspid_chain: Vec<u32>,
}

#[derive(Debug, Clone)]
pub struct TargetLauncher {
    sandbox: SandboxHandle,
    program: TargetProgram,
}

#[derive(Debug, Clone, Copy)]
enum TargetProgram {
    SampleProgram,
}

impl TargetLauncher {
    pub fn sample_program() -> Self {
        Self {
            sandbox: SandboxHandle::host(),
            program: TargetProgram::SampleProgram,
        }
    }

    pub fn in_sandbox(mut self, sandbox: &SandboxHandle) -> Self {
        self.sandbox = sandbox.clone();
        self
    }

    pub async fn spawn(self) -> Result<TargetHandle> {
        match self.program {
            TargetProgram::SampleProgram => spawn_sample_program(&self.sandbox).await,
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
        Ok(())
    }
}

async fn spawn_sample_program(sandbox: &SandboxHandle) -> Result<TargetHandle> {
    let binary_path = ensure_sample_program_ready(sandbox)?;
    let sandbox_pid = sandbox
        .spawn_background_binary(&binary_path)
        .with_context(|| format!("failed to start sample_program in {}", sandbox.label()))?;
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
        }),
    })
}

fn ensure_sample_program_ready(sandbox: &SandboxHandle) -> Result<PathBuf> {
    if sandbox.is_host_backend() {
        ensure_test_program_compiled_with_opt(OptimizationLevel::Debug)?;
    } else {
        let output = sandbox.run_shell(&format!(
            "cd {SAMPLE_PROGRAM_BUILD_DIR} && make clean && make sample_program"
        ))?;
        anyhow::ensure!(
            output.status.success(),
            "failed to compile sample_program inside {}: {}",
            sandbox.label(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    sandbox.repo_path_for_fixture_binary(Path::new(SAMPLE_PROGRAM_RELATIVE_BIN))
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

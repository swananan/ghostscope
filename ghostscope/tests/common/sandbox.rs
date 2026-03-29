#![allow(dead_code)]

use super::termination::{terminate_pid_gracefully, GRACEFUL_TERMINATION_TIMEOUT};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_REMOTE_IMAGE: &str = "ghcr.io/swananan/ghostscope-build:ubuntu20.04-llvm18.1.8";
const CONTAINER_REPO_ROOT: &str = "/workspace";
const CONTAINER_TARGET_DIR: &str = "/tmp/ghostscope-target";
const CONTAINER_GHOSTSCOPE_BIN: &str = "/tmp/ghostscope-target/debug/ghostscope";

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(1);
static DEFAULT_SANDBOX_STATE: OnceLock<Result<DefaultSandboxState, String>> = OnceLock::new();
static STALE_DOCKER_SANDBOX_SWEEP: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Debug)]
struct DefaultSandboxState {
    ghostscope: DefaultSandboxSelection,
    target: DefaultSandboxSelection,
    handles: Mutex<CachedDefaultSandboxes>,
}

#[derive(Debug, Default)]
struct CachedDefaultSandboxes {
    host: Option<Weak<SandboxInner>>,
    docker_private: Option<Weak<SandboxInner>>,
    docker_host: Option<Weak<SandboxInner>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DefaultSandboxSelection {
    Host,
    DockerPrivate,
    DockerHost,
}

impl DefaultSandboxSelection {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "docker-private" | "private" | "container-private" => Ok(Self::DockerPrivate),
            "docker-host" | "host-pid" | "docker-host-pid" | "container-host" => {
                Ok(Self::DockerHost)
            }
            _ => anyhow::bail!("expected one of: host, docker-private, docker-host"),
        }
    }

    fn from_env(name: &str, default: Self) -> Result<Self> {
        match std::env::var(name) {
            Ok(value) => {
                Self::parse(&value).with_context(|| format!("invalid value for {name}: {value}"))
            }
            Err(std::env::VarError::NotPresent) => Ok(default),
            Err(err) => Err(anyhow::Error::new(err))
                .with_context(|| format!("failed to read environment variable {name}")),
        }
    }

    fn instantiate(self) -> Result<SandboxHandle> {
        match self {
            Self::Host => Ok(SandboxHandle::host()),
            Self::DockerPrivate => SandboxHandle::docker(DockerSpec::private()),
            Self::DockerHost => SandboxHandle::docker(DockerSpec::host_pid()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DockerPidMode {
    Private,
    Host,
}

impl DockerPidMode {
    fn as_docker_arg(self) -> Option<&'static str> {
        match self {
            DockerPidMode::Private => None,
            DockerPidMode::Host => Some("host"),
        }
    }

    fn is_host_pid_view(self) -> bool {
        matches!(self, DockerPidMode::Host)
    }
}

#[derive(Debug, Clone)]
pub struct DockerSpec {
    image: String,
    pid_mode: DockerPidMode,
}

impl DockerSpec {
    pub fn private() -> Self {
        Self {
            image: resolve_default_image(),
            pid_mode: DockerPidMode::Private,
        }
    }

    pub fn host_pid() -> Self {
        Self {
            image: resolve_default_image(),
            pid_mode: DockerPidMode::Host,
        }
    }

    #[allow(dead_code)]
    pub fn with_image<S: Into<String>>(mut self, image: S) -> Self {
        self.image = image.into();
        self
    }
}

#[derive(Debug, Clone)]
pub struct SandboxHandle {
    inner: Arc<SandboxInner>,
}

pub enum BackgroundProcess {
    Host { pid: u32, child: Child },
    Detached { pid: u32 },
}

pub struct GhostscopeRunnerCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub bootstrap_pid_from_stdout: bool,
}

impl BackgroundProcess {
    pub fn pid(&self) -> u32 {
        match self {
            Self::Host { pid, .. } | Self::Detached { pid } => *pid,
        }
    }
}

#[derive(Debug)]
enum SandboxInner {
    Host,
    Docker(DockerSandboxInner),
}

#[derive(Debug)]
struct DockerSandboxInner {
    id: u64,
    container_name: String,
    image: String,
    pid_mode: DockerPidMode,
    init_host_pid: u32,
    pid_ns_inode: Option<u64>,
    repo_root: PathBuf,
    build_ready: Mutex<bool>,
    prepared_fixture_commands: Mutex<HashSet<String>>,
}

impl Drop for DockerSandboxInner {
    fn drop(&mut self) {
        let _ = remove_docker_sandbox(&self.container_name);
    }
}

impl SandboxHandle {
    pub fn host() -> Self {
        Self {
            inner: Arc::new(SandboxInner::Host),
        }
    }

    pub fn default_ghostscope() -> Result<Self> {
        default_sandbox_state()?.ghostscope_handle()
    }

    pub fn default_target() -> Result<Self> {
        default_sandbox_state()?.target_handle()
    }

    pub fn docker_available() -> bool {
        Command::new("docker")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    pub fn docker(spec: DockerSpec) -> Result<Self> {
        anyhow::ensure!(
            Self::docker_available(),
            "docker is not available for container-backed e2e tests"
        );
        ensure_stale_docker_sandboxes_swept()?;

        let repo_root = workspace_root()?;
        let id = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
        let container_name = format!(
            "ghostscope-test-{id}-{}-{}",
            std::process::id(),
            unix_timestamp_nanos()
        );

        let mut args: Vec<OsString> = vec![
            "run".into(),
            "-d".into(),
            "--rm".into(),
            "--init".into(),
            "--privileged".into(),
            "--name".into(),
            container_name.clone().into(),
            "--label".into(),
            "ghostscope.test-sandbox=1".into(),
            "--label".into(),
            format!("ghostscope.owner-pid={}", std::process::id()).into(),
            "--label".into(),
            format!(
                "ghostscope.owner-starttime={}",
                current_process_starttime()
                    .context("failed to determine current process starttime for sandbox labels")?
            )
            .into(),
            "-v".into(),
            format!("{}:{CONTAINER_REPO_ROOT}", repo_root.display()).into(),
            "-v".into(),
            format!("{}:{}", repo_root.display(), repo_root.display()).into(),
            "-w".into(),
            CONTAINER_REPO_ROOT.into(),
            "-e".into(),
            "LLVM_SYS_181_PREFIX=/opt/llvm-18".into(),
            "-e".into(),
            "LLVM_CONFIG_PATH=/opt/llvm-18/bin/llvm-config".into(),
            "-e".into(),
            "RUSTFLAGS=-C link-arg=-Wl,--as-needed".into(),
        ];

        if let Some(pid_mode) = spec.pid_mode.as_docker_arg() {
            args.push("--pid".into());
            args.push(pid_mode.into());
        }

        if Path::new("/sys/fs/bpf").is_dir() {
            args.push("-v".into());
            args.push("/sys/fs/bpf:/sys/fs/bpf".into());
        }
        if Path::new("/sys/kernel/debug").is_dir() {
            args.push("-v".into());
            args.push("/sys/kernel/debug:/sys/kernel/debug".into());
        }

        // Reuse the same cache layout as the container e2e script.
        args.push("-v".into());
        args.push("ghostscope-e2e-rustup:/root/.rustup".into());
        args.push("-v".into());
        args.push("ghostscope-e2e-cargo-registry:/root/.cargo/registry".into());
        args.push("-v".into());
        args.push("ghostscope-e2e-cargo-git:/root/.cargo/git".into());
        args.push("-v".into());
        args.push(format!("ghostscope-e2e-target:{CONTAINER_TARGET_DIR}").into());

        args.push(spec.image.clone().into());
        args.push("bash".into());
        args.push("-lc".into());
        args.push("sleep infinity".into());

        let output = Command::new("docker")
            .args(&args)
            .output()
            .context("failed to start docker sandbox")?;
        anyhow::ensure!(
            output.status.success(),
            "failed to start docker sandbox: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let init_host_pid = resolve_container_init_host_pid(&container_name)?;
        let pid_ns_inode = match spec.pid_mode {
            DockerPidMode::Private => Some(read_pid_ns_inode(init_host_pid)?),
            DockerPidMode::Host => None,
        };

        let sandbox = Self {
            inner: Arc::new(SandboxInner::Docker(DockerSandboxInner {
                id,
                container_name,
                image: spec.image,
                pid_mode: spec.pid_mode,
                init_host_pid,
                pid_ns_inode,
                repo_root,
                build_ready: Mutex::new(false),
                prepared_fixture_commands: Mutex::new(HashSet::new()),
            })),
        };

        sandbox.run_shell("mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true")?;
        sandbox.run_shell("mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true")?;
        Ok(sandbox)
    }

    pub fn label(&self) -> String {
        match &*self.inner {
            SandboxInner::Host => "host".to_string(),
            SandboxInner::Docker(inner) => {
                format!(
                    "docker(pid_mode={:?}, image={})",
                    inner.pid_mode, inner.image
                )
            }
        }
    }

    pub fn is_host_pid_view(&self) -> bool {
        match &*self.inner {
            SandboxInner::Host => true,
            SandboxInner::Docker(inner) => inner.pid_mode.is_host_pid_view(),
        }
    }

    pub fn is_host_backend(&self) -> bool {
        matches!(&*self.inner, SandboxInner::Host)
    }

    pub fn same_sandbox(&self, other: &Self) -> bool {
        match (&*self.inner, &*other.inner) {
            (SandboxInner::Host, SandboxInner::Host) => true,
            (SandboxInner::Docker(a), SandboxInner::Docker(b)) => a.id == b.id,
            _ => false,
        }
    }

    pub fn path_in_sandbox(&self, host_path: &Path) -> Result<PathBuf> {
        match &*self.inner {
            SandboxInner::Host => Ok(host_path.to_path_buf()),
            SandboxInner::Docker(inner) => {
                host_path.strip_prefix(&inner.repo_root).with_context(|| {
                    format!(
                        "path {} is not under repo root {}",
                        host_path.display(),
                        inner.repo_root.display()
                    )
                })?;
                Ok(host_path.to_path_buf())
            }
        }
    }

    pub fn read_status(&self, pid: u32) -> Result<String> {
        match &*self.inner {
            SandboxInner::Host => fs::read_to_string(format!("/proc/{pid}/status"))
                .with_context(|| format!("failed to read /proc/{pid}/status")),
            SandboxInner::Docker(inner) => {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &inner.container_name,
                        "cat",
                        &format!("/proc/{pid}/status"),
                    ])
                    .output()
                    .with_context(|| {
                        format!(
                            "failed to read /proc/{pid}/status in docker sandbox {}",
                            inner.container_name
                        )
                    })?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to read /proc/{pid}/status in docker sandbox {}: {}",
                    inner.container_name,
                    String::from_utf8_lossy(&output.stderr)
                );
                String::from_utf8(output.stdout)
                    .context("docker /proc status output was not valid UTF-8")
            }
        }
    }

    pub fn resolve_visible_pid_for_host_pid(&self, host_pid: u32) -> Result<Option<u32>> {
        if self.is_host_pid_view() {
            return Ok(Some(host_pid));
        }

        match &*self.inner {
            SandboxInner::Host => Ok(Some(host_pid)),
            SandboxInner::Docker(inner) => {
                let Ok(target_ns_inode) = read_pid_ns_inode(host_pid) else {
                    return Ok(None);
                };
                let Some(pid_ns_inode) = inner.pid_ns_inode else {
                    return Ok(None);
                };
                if target_ns_inode != pid_ns_inode {
                    return Ok(None);
                }
                let Ok(status) = fs::read_to_string(format!("/proc/{host_pid}/status")) else {
                    return Ok(None);
                };
                let Some(chain) = parse_nspid_chain(&status) else {
                    return Ok(None);
                };
                Ok(chain.last().copied())
            }
        }
    }

    pub fn resolve_host_pid_for_sandbox_pid(&self, sandbox_pid: u32) -> Result<u32> {
        match &*self.inner {
            SandboxInner::Host => Ok(sandbox_pid),
            SandboxInner::Docker(inner) => {
                if inner.pid_mode.is_host_pid_view() {
                    return Ok(sandbox_pid);
                }
                let pid_ns_inode = inner.pid_ns_inode.with_context(|| {
                    format!(
                        "docker sandbox {} is missing a private PID namespace inode",
                        inner.container_name
                    )
                })?;

                let proc_dir = fs::read_dir("/proc")
                    .context("failed to read host /proc while resolving container host PID")?;
                for entry in proc_dir.flatten() {
                    let name = entry.file_name();
                    let Ok(host_pid) = name.to_string_lossy().parse::<u32>() else {
                        continue;
                    };
                    let Ok(ns_inode) = read_pid_ns_inode(host_pid) else {
                        continue;
                    };
                    if ns_inode != pid_ns_inode {
                        continue;
                    }
                    let Ok(status) = fs::read_to_string(format!("/proc/{host_pid}/status")) else {
                        continue;
                    };
                    let Some(chain) = parse_nspid_chain(&status) else {
                        continue;
                    };
                    if chain.last() == Some(&sandbox_pid) {
                        return Ok(host_pid);
                    }
                }

                anyhow::bail!(
                    "failed to resolve host PID for sandbox pid {} in {} (init_host_pid={}, pid_ns_inode={})",
                    sandbox_pid,
                    inner.container_name,
                    inner.init_host_pid,
                    pid_ns_inode
                )
            }
        }
    }

    pub fn ensure_ghostscope_built(&self) -> Result<()> {
        match &*self.inner {
            SandboxInner::Host => Ok(()),
            SandboxInner::Docker(inner) => {
                let mut ready = inner.build_ready.lock().unwrap();
                if *ready {
                    return Ok(());
                }
                let script = format!(
                    "cd {CONTAINER_REPO_ROOT} && cargo build --all-features --target-dir {CONTAINER_TARGET_DIR} -p ghostscope && cargo build --all-features --target-dir {CONTAINER_TARGET_DIR} -p dwarf-tool"
                );
                let output = self.run_shell(&script).with_context(|| {
                    format!(
                        "failed to build ghostscope inside docker sandbox {}",
                        inner.container_name
                    )
                })?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to build ghostscope inside docker sandbox {}: {}",
                    inner.container_name,
                    String::from_utf8_lossy(&output.stderr)
                );
                *ready = true;
                Ok(())
            }
        }
    }

    pub fn ensure_fixture_command_built_once(&self, key: &str, script: &str) -> Result<()> {
        match &*self.inner {
            SandboxInner::Host => Ok(()),
            SandboxInner::Docker(inner) => {
                let mut prepared = inner.prepared_fixture_commands.lock().unwrap();
                if prepared.contains(key) {
                    return Ok(());
                }

                let output = self.run_shell(script).with_context(|| {
                    format!(
                        "failed to prepare fixture inside docker sandbox {}",
                        inner.container_name
                    )
                })?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to prepare fixture inside docker sandbox {}: {}",
                    inner.container_name,
                    String::from_utf8_lossy(&output.stderr)
                );

                prepared.insert(key.to_string());
                Ok(())
            }
        }
    }

    pub fn run_shell(&self, script: &str) -> Result<Output> {
        match &*self.inner {
            SandboxInner::Host => Command::new("bash")
                .args(["-lc", script])
                .output()
                .with_context(|| format!("failed to run host shell command: {script}")),
            SandboxInner::Docker(inner) => Command::new("docker")
                .args(["exec", &inner.container_name, "bash", "-lc", script])
                .output()
                .with_context(|| {
                    format!(
                        "failed to run docker shell command in {}: {}",
                        inner.container_name, script
                    )
                }),
        }
    }

    pub fn spawn_background_binary(
        &self,
        binary_path: &Path,
        working_dir: Option<&Path>,
    ) -> Result<BackgroundProcess> {
        match &*self.inner {
            SandboxInner::Host => {
                let mut cmd = Command::new(binary_path);
                if let Some(path) = working_dir {
                    cmd.current_dir(path);
                }
                let child = cmd
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .with_context(|| format!("failed to spawn {}", binary_path.display()))?;
                Ok(BackgroundProcess::Host {
                    pid: child.id(),
                    child,
                })
            }
            SandboxInner::Docker(inner) => {
                let pid_file = format!("/tmp/ghostscope-target-{}.pid", unix_timestamp_nanos());
                let err_file = format!("/tmp/ghostscope-target-{}.err", unix_timestamp_nanos());
                let working_dir = working_dir
                    .map(Path::to_path_buf)
                    .or_else(|| binary_path.parent().map(Path::to_path_buf))
                    .unwrap_or_else(|| PathBuf::from(CONTAINER_REPO_ROOT));
                let script = format!(
                    "rm -f {pid_file} {err_file}; cd {}; {} >/dev/null 2>{err_file} & child=$!; echo $child > {pid_file}; wait $child",
                    working_dir.display(),
                    binary_path.display()
                );
                let output = Command::new("docker")
                    .args(["exec", "-d", &inner.container_name, "bash", "-lc", &script])
                    .output()
                    .with_context(|| {
                        format!(
                            "failed to spawn {} in docker sandbox {}",
                            binary_path.display(),
                            inner.container_name
                        )
                    })?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to spawn {} in docker sandbox {}: {}",
                    binary_path.display(),
                    inner.container_name,
                    String::from_utf8_lossy(&output.stderr)
                );

                for _ in 0..30 {
                    let pid_output = Command::new("docker")
                        .args(["exec", &inner.container_name, "cat", &pid_file])
                        .output()
                        .with_context(|| {
                            format!(
                                "failed to read pid file {} in docker sandbox {}",
                                pid_file, inner.container_name
                            )
                        })?;
                    if pid_output.status.success() {
                        let pid_text = String::from_utf8(pid_output.stdout)
                            .context("docker spawned pid output was not valid UTF-8")?;
                        let pid = pid_text.trim().parse::<u32>().with_context(|| {
                            format!(
                                "invalid PID returned when spawning in docker sandbox: {pid_text}"
                            )
                        })?;

                        let status_output = Command::new("docker")
                            .args([
                                "exec",
                                &inner.container_name,
                                "test",
                                "-r",
                                &format!("/proc/{pid}/status"),
                            ])
                            .output()
                            .with_context(|| {
                                format!(
                                    "failed to validate pid {} in docker sandbox {}",
                                    pid, inner.container_name
                                )
                            })?;
                        if status_output.status.success() {
                            let _ = Command::new("docker")
                                .args(["exec", &inner.container_name, "rm", "-f", &pid_file])
                                .status();
                            return Ok(BackgroundProcess::Detached { pid });
                        }

                        let err_output = Command::new("docker")
                            .args(["exec", &inner.container_name, "cat", &err_file])
                            .output()
                            .with_context(|| {
                                format!(
                                    "failed to read stderr file {} in docker sandbox {}",
                                    err_file, inner.container_name
                                )
                            })?;
                        let err_text = String::from_utf8_lossy(&err_output.stdout)
                            .trim()
                            .to_owned();
                        if !err_text.is_empty() {
                            anyhow::bail!(
                                "spawned process {} in docker sandbox {} exited before it could be observed: {}",
                                binary_path.display(),
                                inner.container_name,
                                err_text
                            );
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }

                anyhow::bail!(
                    "timed out waiting for live pid from {} in docker sandbox {} (pid_file={}, err_file={})",
                    binary_path.display(),
                    inner.container_name,
                    pid_file,
                    err_file
                )
            }
        }
    }

    pub fn terminate_pid(&self, pid: u32) -> Result<()> {
        let label = self.label().to_owned();
        terminate_pid_gracefully(
            pid,
            &label,
            GRACEFUL_TERMINATION_TIMEOUT,
            |pid| match &*self.inner {
                SandboxInner::Host => {
                    terminate_pid_with_shell("host", pid, &format!("kill -TERM {pid}"))
                }
                SandboxInner::Docker(inner) => terminate_pid_with_shell(
                    &inner.container_name,
                    pid,
                    &format!("docker exec {} kill -TERM {}", inner.container_name, pid),
                ),
            },
            |pid| self.pid_is_running(pid),
        )
    }

    fn pid_is_running(&self, pid: u32) -> Result<bool> {
        match &*self.inner {
            SandboxInner::Host => Ok(PathBuf::from(format!("/proc/{pid}")).is_dir()),
            SandboxInner::Docker(inner) => {
                let output = Command::new("docker")
                    .args([
                        "exec",
                        &inner.container_name,
                        "test",
                        "-r",
                        &format!("/proc/{pid}/status"),
                    ])
                    .output()
                    .with_context(|| {
                        format!(
                            "failed to probe pid {} in docker sandbox {}",
                            pid, inner.container_name
                        )
                    })?;
                Ok(output.status.success())
            }
        }
    }

    pub fn repo_path_for_fixture_binary(&self, relative_binary: &Path) -> Result<PathBuf> {
        let host_path = workspace_root()?.join(relative_binary);
        self.path_in_sandbox(&host_path)
    }

    pub fn ghostscope_command(&self) -> Result<(OsString, Vec<OsString>)> {
        match &*self.inner {
            SandboxInner::Host => Ok((resolve_host_ghostscope_bin().into_os_string(), Vec::new())),
            SandboxInner::Docker(inner) => {
                self.ensure_ghostscope_built()?;
                Ok((
                    OsString::from("docker"),
                    vec![
                        OsString::from("exec"),
                        OsString::from(&inner.container_name),
                        OsString::from(CONTAINER_GHOSTSCOPE_BIN),
                    ],
                ))
            }
        }
    }

    pub fn ghostscope_runner_command(
        &self,
        extra_args: &[OsString],
    ) -> Result<GhostscopeRunnerCommand> {
        match &*self.inner {
            SandboxInner::Host => {
                let (program, args) = self.ghostscope_command()?;
                let mut full_args = args;
                full_args.extend(extra_args.iter().cloned());
                Ok(GhostscopeRunnerCommand {
                    program,
                    args: full_args,
                    bootstrap_pid_from_stdout: false,
                })
            }
            SandboxInner::Docker(inner) => {
                self.ensure_ghostscope_built()?;
                let bin = shell_quote(CONTAINER_GHOSTSCOPE_BIN);
                let quoted_args = extra_args
                    .iter()
                    .map(|arg| shell_quote(&arg.to_string_lossy()))
                    .collect::<Vec<_>>()
                    .join(" ");
                let exec_line = if quoted_args.is_empty() {
                    format!("printf '__GHOSTSCOPE_PID__ %s\\n' \"$$\"; exec {bin}")
                } else {
                    format!("printf '__GHOSTSCOPE_PID__ %s\\n' \"$$\"; exec {bin} {quoted_args}")
                };

                Ok(GhostscopeRunnerCommand {
                    program: OsString::from("docker"),
                    args: vec![
                        OsString::from("exec"),
                        OsString::from(&inner.container_name),
                        OsString::from("bash"),
                        OsString::from("-lc"),
                        OsString::from(exec_line),
                    ],
                    bootstrap_pid_from_stdout: true,
                })
            }
        }
    }
}

impl DefaultSandboxState {
    fn ghostscope_handle(&self) -> Result<SandboxHandle> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| anyhow::anyhow!("default sandbox cache mutex was poisoned"))?;
        get_or_create_cached_sandbox(handles.slot_for_selection(self.ghostscope), self.ghostscope)
    }

    fn target_handle(&self) -> Result<SandboxHandle> {
        let mut handles = self
            .handles
            .lock()
            .map_err(|_| anyhow::anyhow!("default sandbox cache mutex was poisoned"))?;
        get_or_create_cached_sandbox(handles.slot_for_selection(self.target), self.target)
    }
}

impl CachedDefaultSandboxes {
    fn slot_for_selection(
        &mut self,
        selection: DefaultSandboxSelection,
    ) -> &mut Option<Weak<SandboxInner>> {
        match selection {
            DefaultSandboxSelection::Host => &mut self.host,
            DefaultSandboxSelection::DockerPrivate => &mut self.docker_private,
            DefaultSandboxSelection::DockerHost => &mut self.docker_host,
        }
    }
}

fn get_or_create_cached_sandbox(
    slot: &mut Option<Weak<SandboxInner>>,
    selection: DefaultSandboxSelection,
) -> Result<SandboxHandle> {
    if let Some(inner) = slot.as_ref().and_then(Weak::upgrade) {
        return Ok(SandboxHandle { inner });
    }

    let handle = selection.instantiate()?;
    *slot = Some(Arc::downgrade(&handle.inner));
    Ok(handle)
}

fn default_sandbox_state() -> Result<&'static DefaultSandboxState> {
    let state = DEFAULT_SANDBOX_STATE
        .get_or_init(|| resolve_default_sandbox_state().map_err(|err| format!("{err:#}")));

    match state {
        Ok(state) => Ok(state),
        Err(message) => anyhow::bail!("{message}"),
    }
}

fn resolve_default_sandbox_state() -> Result<DefaultSandboxState> {
    let ghostscope =
        DefaultSandboxSelection::from_env("E2E_GHOSTSCOPE_SANDBOX", DefaultSandboxSelection::Host)?;
    let target =
        DefaultSandboxSelection::from_env("E2E_TARGET_SANDBOX", DefaultSandboxSelection::Host)?;

    Ok(DefaultSandboxState {
        ghostscope,
        target,
        handles: Mutex::new(CachedDefaultSandboxes::default()),
    })
}

fn resolve_default_image() -> String {
    if let Ok(image) = std::env::var("E2E_CONTAINER_IMAGE") {
        if !image.trim().is_empty() {
            return image;
        }
    }
    // Default to the same published image used in CI so local e2e, runner,
    // and GitHub Actions exercise the same container userspace by default.
    DEFAULT_REMOTE_IMAGE.to_string()
}

fn remove_docker_sandbox(container_name: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("docker")
        .args(["rm", "-f", container_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn ensure_stale_docker_sandboxes_swept() -> Result<()> {
    let result = STALE_DOCKER_SANDBOX_SWEEP
        .get_or_init(|| sweep_stale_docker_sandboxes().map_err(|err| format!("{err:#}")));
    match result {
        Ok(()) => Ok(()),
        Err(message) => anyhow::bail!("{message}"),
    }
}

fn sweep_stale_docker_sandboxes() -> Result<()> {
    // Default sandboxes are cached in a OnceLock for process-wide reuse, so
    // they cannot rely on process-exit Drop for final cleanup. Instead, each
    // new test process garbage-collects stale docker sandboxes left behind by
    // dead owners before creating fresh ones.
    for container_id in list_test_sandbox_container_ids()? {
        let Some(metadata) = inspect_test_sandbox_if_present(&container_id)? else {
            continue;
        };
        if metadata.belongs_to_live_owner() {
            continue;
        }
        let _ = remove_docker_sandbox(&metadata.name);
    }
    Ok(())
}

fn list_test_sandbox_container_ids() -> Result<Vec<String>> {
    let labeled = docker_ps_ids(&["--filter", "label=ghostscope.test-sandbox=1"])?;
    let named = docker_ps_ids(&["--filter", "name=^ghostscope-test-"])?;

    let mut ids = labeled;
    for id in named {
        if !ids.iter().any(|existing| existing == &id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn docker_ps_ids(extra_args: &[&str]) -> Result<Vec<String>> {
    let output = Command::new("docker")
        .arg("ps")
        .arg("-aq")
        .args(extra_args)
        .output()
        .context("failed to enumerate docker sandboxes")?;
    anyhow::ensure!(
        output.status.success(),
        "failed to enumerate docker sandboxes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

#[derive(Debug)]
struct TestSandboxMetadata {
    name: String,
    owner_pid: Option<u32>,
    owner_starttime: Option<u64>,
}

impl TestSandboxMetadata {
    fn belongs_to_live_owner(&self) -> bool {
        match (self.owner_pid, self.owner_starttime) {
            (Some(pid), Some(starttime)) => process_starttime(pid) == Some(starttime),
            (Some(pid), None) => process_starttime(pid).is_some(),
            (None, _) => parse_owner_pid_from_name(&self.name)
                .and_then(process_starttime)
                .is_some(),
        }
    }
}

fn inspect_test_sandbox_if_present(container_id: &str) -> Result<Option<TestSandboxMetadata>> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{.Name}}|{{ index .Config.Labels \"ghostscope.owner-pid\" }}|{{ index .Config.Labels \"ghostscope.owner-starttime\" }}",
            container_id,
        ])
        .output()
        .with_context(|| format!("failed to inspect docker sandbox {container_id}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_missing_docker_container_error(&stderr) {
            // Another docker-backed test may delete a stale sandbox between our
            // `docker ps -aq` listing and this inspect call. Treat that race as a
            // successful cleanup outcome instead of poisoning the process-wide
            // stale-sandbox sweep cache.
            return Ok(None);
        }
        anyhow::bail!(
            "failed to inspect docker sandbox {}: {}",
            container_id,
            stderr
        );
    }

    let line = String::from_utf8(output.stdout)
        .context("docker inspect output was not valid UTF-8")?
        .trim()
        .to_string();
    let mut parts = line.split('|');
    let name = parts
        .next()
        .unwrap_or_default()
        .trim_start_matches('/')
        .to_string();
    let owner_pid = parts.next().and_then(parse_optional_u32);
    let owner_starttime = parts.next().and_then(parse_optional_u64);

    Ok(Some(TestSandboxMetadata {
        name,
        owner_pid,
        owner_starttime,
    }))
}

fn is_missing_docker_container_error(stderr: &str) -> bool {
    let normalized = stderr.trim().to_ascii_lowercase();
    normalized.contains("no such object") || normalized.contains("no such container")
}

fn parse_optional_u32(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "<no value>" {
        None
    } else {
        trimmed.parse().ok()
    }
}

fn parse_optional_u64(value: &str) -> Option<u64> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed == "<no value>" {
        None
    } else {
        trimmed.parse().ok()
    }
}

fn parse_owner_pid_from_name(name: &str) -> Option<u32> {
    let mut parts = name.rsplitn(3, '-');
    let _timestamp = parts.next()?;
    let pid = parts.next()?;
    let _id = parts.next()?;
    pid.parse().ok()
}

fn current_process_starttime() -> Result<u64> {
    process_starttime(std::process::id())
        .with_context(|| "failed to read /proc/self/stat starttime".to_string())
}

fn process_starttime(pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let rest = stat.split_once(") ")?.1;
    rest.split_whitespace().nth(19)?.parse().ok()
}

fn resolve_container_init_host_pid(container_name: &str) -> Result<u32> {
    let output = Command::new("docker")
        .args(["inspect", "-f", "{{.State.Pid}}", container_name])
        .output()
        .with_context(|| format!("failed to inspect docker sandbox {container_name}"))?;
    anyhow::ensure!(
        output.status.success(),
        "failed to inspect docker sandbox {}: {}",
        container_name,
        String::from_utf8_lossy(&output.stderr)
    );
    let pid_text = String::from_utf8(output.stdout)
        .context("docker inspect PID output was not valid UTF-8")?;
    pid_text.trim().parse::<u32>().with_context(|| {
        format!("invalid container init PID returned for {container_name}: {pid_text}")
    })
}

fn read_pid_ns_inode(pid: u32) -> Result<u64> {
    fs::metadata(format!("/proc/{pid}/ns/pid"))
        .map(|metadata| metadata.ino())
        .with_context(|| format!("failed to read PID namespace inode for pid {pid}"))
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

fn resolve_host_ghostscope_bin() -> PathBuf {
    if let Ok(path) = std::env::var("GHOSTSCOPE_TEST_BIN") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_ghostscope") {
        let path = PathBuf::from(path);
        if path.exists() {
            return path;
        }
    }
    if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
        let candidate = PathBuf::from(target_dir).join("debug/ghostscope");
        if candidate.exists() {
            return candidate;
        }
    }
    if let Ok(current_exe) = std::env::current_exe() {
        let mut candidates = Vec::new();
        if let Some(parent) = current_exe.parent() {
            candidates.push(parent.join("ghostscope"));
            if let Some(grandparent) = parent.parent() {
                candidates.push(grandparent.join("ghostscope"));
            }
        }
        for candidate in candidates {
            if candidate.exists() {
                return candidate;
            }
        }
    }
    if let Ok(root) = workspace_root() {
        let candidate = root.join("target/debug/ghostscope");
        if candidate.exists() {
            return candidate;
        }
    }
    PathBuf::from("../target/debug/ghostscope")
}

fn terminate_pid_with_shell(label: &str, pid: u32, command: &str) -> Result<()> {
    let _ = Command::new("bash")
        .args(["-lc", command])
        .status()
        .with_context(|| format!("failed to terminate pid {pid} in {label}"))?;
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .context("failed to resolve workspace root from CARGO_MANIFEST_DIR")
}

fn unix_timestamp_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

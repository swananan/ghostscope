#![allow(dead_code)]

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_REMOTE_IMAGE: &str = "ghcr.io/swananan/ghostscope-build:ubuntu20.04-llvm18.1.8";
const CONTAINER_REPO_ROOT: &str = "/workspace";
const CONTAINER_TARGET_DIR: &str = "/tmp/ghostscope-target";
const CONTAINER_GHOSTSCOPE_BIN: &str = "/tmp/ghostscope-target/debug/ghostscope";

static NEXT_SANDBOX_ID: AtomicU64 = AtomicU64::new(1);
static DEFAULT_SANDBOX_PAIR: OnceLock<Result<DefaultSandboxPair, String>> = OnceLock::new();
static REGISTERED_DOCKER_SANDBOXES: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
static DOCKER_SANDBOX_CLEANUP_HOOK: OnceLock<()> = OnceLock::new();

#[derive(Debug, Clone)]
struct DefaultSandboxPair {
    ghostscope: SandboxHandle,
    target: SandboxHandle,
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
        unregister_docker_sandbox(&self.container_name);
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
        Ok(default_sandbox_pair()?.ghostscope.clone())
    }

    pub fn default_target() -> Result<Self> {
        Ok(default_sandbox_pair()?.target.clone())
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
        register_docker_sandbox_for_exit(&container_name);
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
        match &*self.inner {
            SandboxInner::Host => {
                terminate_pid_with_shell("host", pid, &format!("kill -TERM {pid}"))?
            }
            SandboxInner::Docker(inner) => {
                terminate_pid_with_shell(
                    &inner.container_name,
                    pid,
                    &format!("docker exec {} kill -TERM {}", inner.container_name, pid),
                )?;
            }
        }
        Ok(())
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
}

fn default_sandbox_pair() -> Result<&'static DefaultSandboxPair> {
    let pair = DEFAULT_SANDBOX_PAIR
        .get_or_init(|| resolve_default_sandbox_pair().map_err(|err| format!("{err:#}")));

    match pair {
        Ok(pair) => Ok(pair),
        Err(message) => anyhow::bail!("{message}"),
    }
}

fn resolve_default_sandbox_pair() -> Result<DefaultSandboxPair> {
    let ghostscope =
        DefaultSandboxSelection::from_env("E2E_GHOSTSCOPE_SANDBOX", DefaultSandboxSelection::Host)?;
    let target =
        DefaultSandboxSelection::from_env("E2E_TARGET_SANDBOX", DefaultSandboxSelection::Host)?;
    let share = bool_env("E2E_SHARE_SANDBOX")?.unwrap_or(false);

    if share {
        anyhow::ensure!(
            ghostscope == target,
            "E2E_SHARE_SANDBOX=1 requires GhostScope and target to use the same sandbox kind"
        );
        let shared = ghostscope.instantiate()?;
        return Ok(DefaultSandboxPair {
            ghostscope: shared.clone(),
            target: shared,
        });
    }

    Ok(DefaultSandboxPair {
        ghostscope: ghostscope.instantiate()?,
        target: target.instantiate()?,
    })
}

fn bool_env(name: &str) -> Result<Option<bool>> {
    match std::env::var(name) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Ok(Some(true)),
            "0" | "false" | "no" | "off" => Ok(Some(false)),
            _ => anyhow::bail!("invalid boolean value for {name}: {value}"),
        },
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow::Error::new(err))
            .with_context(|| format!("failed to read environment variable {name}")),
    }
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

fn registered_docker_sandboxes() -> &'static Mutex<HashSet<String>> {
    REGISTERED_DOCKER_SANDBOXES.get_or_init(|| Mutex::new(HashSet::new()))
}

extern "C" fn cleanup_registered_docker_sandboxes() {
    let names: Vec<String> = registered_docker_sandboxes()
        .lock()
        .map(|mut names| names.drain().collect())
        .unwrap_or_default();

    for container_name in names {
        let _ = remove_docker_sandbox(&container_name);
    }
}

fn register_docker_sandbox_for_exit(container_name: &str) {
    // Tests cache default sandboxes in a OnceLock so they can be reused across
    // the whole process. That cache means DockerSandboxInner::drop is not a
    // reliable end-of-process cleanup path, so register an explicit atexit
    // cleanup hook for any containers we create here.
    DOCKER_SANDBOX_CLEANUP_HOOK.get_or_init(|| unsafe {
        libc::atexit(cleanup_registered_docker_sandboxes);
    });

    if let Ok(mut names) = registered_docker_sandboxes().lock() {
        names.insert(container_name.to_string());
    }
}

fn unregister_docker_sandbox(container_name: &str) {
    if let Ok(mut names) = registered_docker_sandboxes().lock() {
        names.remove(container_name);
    }
}

fn remove_docker_sandbox(container_name: &str) -> std::io::Result<std::process::ExitStatus> {
    Command::new("docker")
        .args(["rm", "-f", container_name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
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

fn unix_timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

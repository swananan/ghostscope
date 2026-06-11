#![allow(dead_code)]

use super::termination::{
    terminate_pid_with_escalation, FORCEFUL_TERMINATION_TIMEOUT, GRACEFUL_TERMINATION_TIMEOUT,
};
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{SystemTime, UNIX_EPOCH};

const DEFAULT_REMOTE_IMAGE: &str = "ghcr.io/swananan/ghostscope-e2e-runtime@sha256:d5df1b977c38f7a51bbf28b878f2246705a05b83ac6df7cb6be8f8a4de4105f4";
const CONTAINER_REPO_ROOT: &str = "/workspace";
const CONTAINER_TARGET_DIR: &str = "/tmp/ghostscope-target";
const STAGED_TOOL_DIR: &str = ".ghostscope-test-bin";
const ENV_E2E_SANDBOX_SESSION: &str = "E2E_SANDBOX_SESSION";
const INNER_DOCKER_HOST: &str = "unix:///tmp/ghostscope-dind.sock";
const INNER_DOCKER_SOCK: &str = "/tmp/ghostscope-dind.sock";
const INNER_DOCKER_PIDFILE: &str = "/tmp/ghostscope-dind.pid";
const INNER_DOCKER_LOG: &str = "/tmp/ghostscope-dind.log";
const INNER_DOCKER_DATA_ROOT: &str = "/var/lib/ghostscope-dind";
const INNER_DOCKER_EXEC_ROOT: &str = "/var/run/ghostscope-dind";

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
    ChildContainer { pid: u32 },
}

pub struct GhostscopeRunnerCommand {
    pub program: OsString,
    pub args: Vec<OsString>,
    pub bootstrap_pid_from_stdout: bool,
}

impl BackgroundProcess {
    pub fn pid(&self) -> u32 {
        match self {
            Self::Host { pid, .. } | Self::Detached { pid } | Self::ChildContainer { pid } => *pid,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum SandboxInner {
    Host,
    Docker(DockerSandboxInner),
}

#[derive(Debug)]
struct DockerSandboxInner {
    id: u64,
    container_name: String,
    session: Option<String>,
    image: String,
    pid_mode: DockerPidMode,
    init_host_pid: u32,
    pid_ns_inode: Option<u64>,
    repo_root: PathBuf,
    prepared_fixture_commands: Mutex<HashSet<String>>,
    dind_ready: Mutex<bool>,
    loaded_child_images: Mutex<HashSet<String>>,
    child_runtime: Mutex<Option<ChildRuntimeState>>,
}

#[derive(Debug, Clone)]
struct ChildRuntimeState {
    container_name: String,
    image: String,
    init_host_pid: u32,
    pid_ns_inode: u64,
}

#[derive(Debug)]
struct InnerDockerContainerState {
    running: bool,
    pid: u32,
    image: String,
}

impl Drop for DockerSandboxInner {
    fn drop(&mut self) {
        if self.session.is_none() {
            let _ = remove_docker_sandbox(&self.container_name);
        }
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
        if let Some(session) = current_sandbox_session() {
            return Self::docker_with_session(spec, repo_root, session);
        }

        let id = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
        let container_name = format!(
            "ghostscope-test-{id}-{}-{}",
            std::process::id(),
            unix_timestamp_nanos()
        );
        Self::create_docker_sandbox(spec, repo_root, container_name, None)
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
            (SandboxInner::Docker(a), SandboxInner::Docker(b)) => {
                a.container_name == b.container_name
            }
            _ => false,
        }
    }

    fn docker_with_session(spec: DockerSpec, repo_root: PathBuf, session: String) -> Result<Self> {
        let container_name = session_scoped_container_name(&session, &spec, &repo_root);
        if let Some(handle) = Self::attach_existing_docker_sandbox(
            &spec,
            repo_root.clone(),
            &container_name,
            &session,
        )? {
            return Ok(handle);
        }

        match Self::create_docker_sandbox(
            spec.clone(),
            repo_root.clone(),
            container_name.clone(),
            Some(session.clone()),
        ) {
            Ok(handle) => Ok(handle),
            Err(create_err) => {
                if let Some(handle) = Self::attach_existing_docker_sandbox(
                    &spec,
                    repo_root,
                    &container_name,
                    &session,
                )? {
                    return Ok(handle);
                }
                Err(create_err)
            }
        }
    }

    fn attach_existing_docker_sandbox(
        spec: &DockerSpec,
        repo_root: PathBuf,
        container_name: &str,
        session: &str,
    ) -> Result<Option<Self>> {
        let Some(state) = inspect_docker_container_state(container_name)? else {
            return Ok(None);
        };
        if !state.running || state.image != spec.image {
            let _ = remove_docker_sandbox(container_name);
            return Ok(None);
        }

        let health = Command::new("docker")
            .args(["exec", container_name, "bash", "-lc", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("failed to probe docker sandbox {container_name}"))?;
        if !health.success() {
            let _ = remove_docker_sandbox(container_name);
            return Ok(None);
        }

        Ok(Some(Self::build_docker_sandbox_handle(
            spec.clone(),
            repo_root,
            container_name.to_string(),
            Some(session.to_string()),
        )?))
    }

    fn create_docker_sandbox(
        spec: DockerSpec,
        repo_root: PathBuf,
        container_name: String,
        session: Option<String>,
    ) -> Result<Self> {
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
        ];

        if let Some(session) = session.as_ref() {
            args.push("--label".into());
            args.push(format!("ghostscope.session={session}").into());
        }

        args.push("-v".into());
        args.push(format!("{}:{CONTAINER_REPO_ROOT}", repo_root.display()).into());
        args.push("-v".into());
        args.push(format!("{}:{}", repo_root.display(), repo_root.display()).into());
        args.push("-w".into());
        args.push(CONTAINER_REPO_ROOT.into());

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

        Self::build_docker_sandbox_handle(spec, repo_root, container_name, session)
    }

    fn build_docker_sandbox_handle(
        spec: DockerSpec,
        repo_root: PathBuf,
        container_name: String,
        session: Option<String>,
    ) -> Result<Self> {
        let id = NEXT_SANDBOX_ID.fetch_add(1, Ordering::Relaxed);
        let init_host_pid = resolve_container_init_host_pid(&container_name)?;
        let pid_ns_inode = match spec.pid_mode {
            DockerPidMode::Private => Some(read_pid_ns_inode(init_host_pid)?),
            DockerPidMode::Host => None,
        };

        let sandbox = Self {
            inner: Arc::new(SandboxInner::Docker(DockerSandboxInner {
                id,
                container_name,
                session,
                image: spec.image,
                pid_mode: spec.pid_mode,
                init_host_pid,
                pid_ns_inode,
                repo_root,
                prepared_fixture_commands: Mutex::new(HashSet::new()),
                dind_ready: Mutex::new(false),
                loaded_child_images: Mutex::new(HashSet::new()),
                child_runtime: Mutex::new(None),
            })),
        };

        sandbox.run_shell("mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true")?;
        sandbox.run_shell("mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true")?;
        Ok(sandbox)
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
                    let Ok(status) = fs::read_to_string(format!("/proc/{host_pid}/status")) else {
                        continue;
                    };
                    let Some(chain) = parse_nspid_chain(&status) else {
                        continue;
                    };
                    let same_namespace_pid = read_pid_ns_inode(host_pid)
                        .ok()
                        .filter(|ns_inode| *ns_inode == pid_ns_inode)
                        .is_some()
                        && chain.last() == Some(&sandbox_pid);
                    if same_namespace_pid {
                        return Ok(host_pid);
                    }
                    if process_descends_from(host_pid, inner.init_host_pid)
                        && chain.iter().skip(1).any(|pid| *pid == sandbox_pid)
                    {
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

    fn resolve_ghostscope_bin_for_sandbox(&self) -> Result<PathBuf> {
        let host_bin = resolve_host_ghostscope_bin();
        anyhow::ensure!(
            host_bin.exists(),
            "ghostscope test binary does not exist on host: {}",
            host_bin.display()
        );
        match self.path_in_sandbox(&host_bin) {
            Ok(path) => Ok(path),
            Err(_) => {
                let staged = stage_host_binary_under_repo(&host_bin, "ghostscope")?;
                self.path_in_sandbox(&staged)
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

    pub fn ensure_dind_ready(&self) -> Result<()> {
        match &*self.inner {
            SandboxInner::Host => {
                anyhow::bail!("child-container targets require a docker sandbox, not the host")
            }
            SandboxInner::Docker(inner) => {
                anyhow::ensure!(
                    matches!(inner.pid_mode, DockerPidMode::Private),
                    "child-container targets require a private docker sandbox"
                );

                let mut ready = inner.dind_ready.lock().unwrap();
                if *ready {
                    let output = self.run_shell(&format!(
                        "docker -H {} info >/dev/null 2>&1",
                        shell_quote(INNER_DOCKER_HOST)
                    ))?;
                    if output.status.success() {
                        return Ok(());
                    }
                    *ready = false;
                }

                let script = format!(
                    "set -eu\n\
                     if ! command -v docker >/dev/null 2>&1; then\n\
                       echo 'docker CLI is missing from sandbox image {image}' >&2\n\
                       exit 1\n\
                     fi\n\
                     if ! command -v dockerd >/dev/null 2>&1; then\n\
                       echo 'dockerd is missing from sandbox image {image}' >&2\n\
                       exit 1\n\
                     fi\n\
                     if docker -H {host} info >/dev/null 2>&1; then\n\
                       exit 0\n\
                     fi\n\
                     rm -f {sock} {pidfile}\n\
                     mkdir -p {data_root} {exec_root}\n\
                     nohup dockerd \\\n\
                       --host={host} \\\n\
                       --pidfile={pidfile} \\\n\
                       --data-root={data_root} \\\n\
                       --exec-root={exec_root} \\\n\
                       --storage-driver=vfs \\\n\
                       --iptables=false \\\n\
                       >{log} 2>&1 &\n\
                     for _ in $(seq 1 60); do\n\
                       if docker -H {host} info >/dev/null 2>&1; then\n\
                         exit 0\n\
                       fi\n\
                       sleep 1\n\
                     done\n\
                     echo 'failed to start nested dockerd' >&2\n\
                     tail -n 80 {log} >&2 || true\n\
                     exit 1",
                    host = shell_quote(INNER_DOCKER_HOST),
                    image = shell_quote(&inner.image),
                    sock = shell_quote(INNER_DOCKER_SOCK),
                    pidfile = shell_quote(INNER_DOCKER_PIDFILE),
                    data_root = shell_quote(INNER_DOCKER_DATA_ROOT),
                    exec_root = shell_quote(INNER_DOCKER_EXEC_ROOT),
                    log = shell_quote(INNER_DOCKER_LOG),
                );
                let output = self.run_shell(&script).with_context(|| {
                    format!(
                        "failed to prepare nested docker daemon inside sandbox {}",
                        inner.container_name
                    )
                })?;
                anyhow::ensure!(
                    output.status.success(),
                    "failed to prepare nested docker daemon inside sandbox {}: stdout={} stderr={}",
                    inner.container_name,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                *ready = true;
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

    fn ensure_child_image_ready(
        &self,
        inner: &DockerSandboxInner,
        child_image: &str,
        inner_child_image: &str,
    ) -> Result<()> {
        let inspect_script = format!(
            "docker -H {host} image inspect {image} >/dev/null 2>&1",
            host = shell_quote(INNER_DOCKER_HOST),
            image = shell_quote(inner_child_image),
        );

        let mut loaded_images = inner.loaded_child_images.lock().unwrap();
        if loaded_images.contains(inner_child_image) {
            let output = self.run_shell(&inspect_script)?;
            if output.status.success() {
                return Ok(());
            }
            loaded_images.remove(inner_child_image);
        }

        let output = self.run_shell(&inspect_script)?;
        if output.status.success() {
            loaded_images.insert(inner_child_image.to_string());
            return Ok(());
        }

        let host_has_image = Command::new("docker")
            .args(["image", "inspect", child_image])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .with_context(|| format!("failed to inspect host image {child_image}"))?
            .success();

        if host_has_image {
            let load_script = if child_image == inner_child_image {
                format!(
                    "set -euo pipefail\n\
                     docker image save {image} | docker exec -i {container} docker -H {host} load",
                    image = shell_quote(child_image),
                    container = shell_quote(&inner.container_name),
                    host = shell_quote(INNER_DOCKER_HOST),
                )
            } else {
                format!(
                    "set -euo pipefail\n\
                     host_id=$(docker image inspect --format '{{{{.Id}}}}' {source})\n\
                     cleanup() {{ docker image rm -f {alias} >/dev/null 2>&1 || true; }}\n\
                     trap cleanup EXIT\n\
                     docker image tag \"$host_id\" {alias}\n\
                     docker image save {alias} | docker exec -i {container} docker -H {host} load",
                    source = shell_quote(child_image),
                    alias = shell_quote(inner_child_image),
                    container = shell_quote(&inner.container_name),
                    host = shell_quote(INNER_DOCKER_HOST),
                )
            };
            let output = Command::new("bash")
                .args(["-lc", &load_script])
                .output()
                .with_context(|| {
                    format!(
                        "failed to load child image {} into nested docker daemon for sandbox {}",
                        child_image, inner.container_name
                    )
                })?;
            anyhow::ensure!(
                output.status.success(),
                "failed to load child image {} into nested docker daemon for sandbox {}: stdout={} stderr={}",
                child_image,
                inner.container_name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        } else {
            let pull_script = format!(
                "set -eu\n\
                 for _ in $(seq 1 5); do\n\
                   if docker -H {host} pull {image}; then\n\
                     exit 0\n\
                   fi\n\
                   sleep 2\n\
                 done\n\
                 exit 1",
                host = shell_quote(INNER_DOCKER_HOST),
                image = shell_quote(child_image),
            );
            let output = self.run_shell(&pull_script).with_context(|| {
                format!(
                    "failed to pull child image {} inside sandbox {}",
                    child_image, inner.container_name
                )
            })?;
            anyhow::ensure!(
                output.status.success(),
                "failed to pull child image {} inside sandbox {}: stdout={} stderr={}",
                child_image,
                inner.container_name,
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            if child_image != inner_child_image {
                let tag_script = format!(
                    "set -eu\n\
                     image_id=$(docker -H {host} image inspect --format '{{{{.Id}}}}' {source})\n\
                     docker -H {host} image tag \"$image_id\" {alias}",
                    host = shell_quote(INNER_DOCKER_HOST),
                    source = shell_quote(child_image),
                    alias = shell_quote(inner_child_image),
                );
                let tag_output = self.run_shell(&tag_script)?;
                anyhow::ensure!(
                    tag_output.status.success(),
                    "failed to tag child image {} as {} inside nested docker daemon for sandbox {}: stdout={} stderr={}",
                    child_image,
                    inner_child_image,
                    inner.container_name,
                    String::from_utf8_lossy(&tag_output.stdout),
                    String::from_utf8_lossy(&tag_output.stderr)
                );
            }
        }

        let verify = self.run_shell(&inspect_script)?;
        anyhow::ensure!(
            verify.status.success(),
            "child image {} (inner alias {}) is still unavailable inside nested docker daemon for sandbox {}",
            child_image,
            inner_child_image,
            inner.container_name
        );
        loaded_images.insert(inner_child_image.to_string());
        Ok(())
    }

    fn inspect_inner_docker_container(
        &self,
        container_name: &str,
    ) -> Result<Option<InnerDockerContainerState>> {
        let inspect_script = format!(
            "docker -H {host} inspect -f '{{{{.State.Running}}}}|{{{{.State.Pid}}}}|{{{{.Config.Image}}}}' {name}",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(container_name),
        );
        let output = self.run_shell(&inspect_script)?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if is_missing_docker_container_error(&stderr) {
                return Ok(None);
            }
            anyhow::bail!(
                "failed to inspect nested docker container {} in sandbox {}: {}",
                container_name,
                self.label(),
                stderr
            );
        }

        let inspect_text = String::from_utf8(output.stdout)
            .context("nested docker inspect output was not valid UTF-8")?;
        let mut parts = inspect_text.trim().split('|');
        let running = parts
            .next()
            .unwrap_or_default()
            .trim()
            .eq_ignore_ascii_case("true");
        let pid = parts
            .next()
            .unwrap_or_default()
            .trim()
            .parse::<u32>()
            .unwrap_or(0);
        let image = parts.next().unwrap_or_default().trim().to_string();
        Ok(Some(InnerDockerContainerState {
            running,
            pid,
            image,
        }))
    }

    fn remove_inner_docker_container(&self, container_name: &str) -> Result<()> {
        let output = self.run_shell(&format!(
            "docker -H {host} rm -f {name}",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(container_name),
        ))?;
        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_missing_docker_container_error(&stderr) {
            return Ok(());
        }

        anyhow::bail!(
            "failed to remove nested docker container {} in sandbox {}: {}",
            container_name,
            self.label(),
            stderr
        )
    }

    fn attach_existing_child_runtime(
        &self,
        container_name: &str,
        image: &str,
    ) -> Result<Option<ChildRuntimeState>> {
        let Some(state) = self.inspect_inner_docker_container(container_name)? else {
            return Ok(None);
        };
        if !state.running || state.pid == 0 || state.image != image {
            let _ = self.remove_inner_docker_container(container_name);
            return Ok(None);
        }

        let health_output = self.run_shell(&format!(
            "docker -H {host} exec {name} bash -lc true",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(container_name),
        ))?;
        if !health_output.status.success() {
            let _ = self.remove_inner_docker_container(container_name);
            return Ok(None);
        }

        let Ok(init_host_pid) = self.resolve_host_pid_for_sandbox_pid(state.pid) else {
            let _ = self.remove_inner_docker_container(container_name);
            return Ok(None);
        };
        let Ok(pid_ns_inode) = read_pid_ns_inode(init_host_pid) else {
            let _ = self.remove_inner_docker_container(container_name);
            return Ok(None);
        };

        Ok(Some(ChildRuntimeState {
            container_name: container_name.to_string(),
            image: image.to_string(),
            init_host_pid,
            pid_ns_inode,
        }))
    }

    fn ensure_child_runtime_state(&self) -> Result<ChildRuntimeState> {
        self.ensure_dind_ready()?;

        let SandboxInner::Docker(inner) = &*self.inner else {
            anyhow::bail!("child-container targets require a docker sandbox");
        };

        let child_image = resolve_default_child_image();
        let inner_child_image = resolve_inner_child_image_ref(&child_image);
        self.ensure_child_image_ready(inner, &child_image, &inner_child_image)?;
        let runtime_name = child_runtime_container_name(&inner.container_name, &inner_child_image);

        let mut runtime = inner.child_runtime.lock().unwrap();
        if let Some(state) = runtime.as_ref() {
            if state.image == inner_child_image {
                if let Some(attached) =
                    self.attach_existing_child_runtime(&state.container_name, &state.image)?
                {
                    *runtime = Some(attached.clone());
                    return Ok(attached);
                }
            } else {
                let _ = self.remove_inner_docker_container(&state.container_name);
            }
            *runtime = None;
        }

        if let Some(attached) =
            self.attach_existing_child_runtime(&runtime_name, &inner_child_image)?
        {
            *runtime = Some(attached.clone());
            return Ok(attached);
        }

        let create_script = format!(
            "docker -H {host} run -d --name {name} \
               --label {label} \
               -v {workspace_mount} \
               -v {repo_mount} \
               -v {target_mount} \
               -w {workdir} \
               {image} \
               bash -lc {entrypoint}",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(&runtime_name),
            label = shell_quote("ghostscope.test-child-runtime=1"),
            workspace_mount = shell_quote(&format!("{CONTAINER_REPO_ROOT}:{CONTAINER_REPO_ROOT}")),
            repo_mount = shell_quote(&format!(
                "{}:{}",
                inner.repo_root.display(),
                inner.repo_root.display()
            )),
            target_mount = shell_quote(&format!("{CONTAINER_TARGET_DIR}:{CONTAINER_TARGET_DIR}")),
            workdir = shell_quote(CONTAINER_REPO_ROOT),
            image = shell_quote(&inner_child_image),
            entrypoint = shell_quote("trap : TERM INT; sleep infinity & wait"),
        );
        let output = self.run_shell(&create_script).with_context(|| {
            format!(
                "failed to create child runtime container {} in sandbox {}",
                runtime_name, inner.container_name
            )
        })?;
        if !output.status.success() {
            if let Some(attached) =
                self.attach_existing_child_runtime(&runtime_name, &inner_child_image)?
            {
                *runtime = Some(attached.clone());
                return Ok(attached);
            }
            anyhow::bail!(
                "failed to create child runtime container {} in sandbox {}: {}",
                runtime_name,
                inner.container_name,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let attached = self
            .attach_existing_child_runtime(&runtime_name, &inner_child_image)?
            .with_context(|| {
                format!(
                    "child runtime container {} did not become ready in sandbox {}",
                    runtime_name, inner.container_name
                )
            })?;
        *runtime = Some(attached.clone());
        Ok(attached)
    }

    fn resolve_descendant_process_pids(
        &self,
        runtime: &ChildRuntimeState,
        child_local_pid: u32,
    ) -> Result<(u32, u32)> {
        let SandboxInner::Docker(inner) = &*self.inner else {
            anyhow::bail!("child-container targets require a docker sandbox");
        };

        let proc_dir = fs::read_dir("/proc")
            .context("failed to read host /proc while resolving child-container target pid")?;
        for entry in proc_dir.flatten() {
            let name = entry.file_name();
            let Ok(host_pid) = name.to_string_lossy().parse::<u32>() else {
                continue;
            };
            if host_pid == runtime.init_host_pid {
                continue;
            }
            let Ok(status) = fs::read_to_string(format!("/proc/{host_pid}/status")) else {
                continue;
            };
            let Some(chain) = parse_nspid_chain(&status) else {
                continue;
            };
            let Ok(pid_ns_inode) = read_pid_ns_inode(host_pid) else {
                continue;
            };
            if pid_ns_inode != runtime.pid_ns_inode {
                continue;
            }
            if chain.last() != Some(&child_local_pid) || chain.len() < 2 {
                continue;
            }
            return Ok((chain[chain.len() - 2], host_pid));
        }

        anyhow::bail!(
            "failed to resolve child-container target pid {} in sandbox {} via runtime host pid {}",
            child_local_pid,
            inner.container_name,
            runtime.init_host_pid
        )
    }

    pub fn ensure_child_container_runtime_ready(&self) -> Result<()> {
        let _ = self.ensure_child_runtime_state()?;
        Ok(())
    }

    pub fn list_inner_docker_container_names_by_label(&self, label: &str) -> Result<Vec<String>> {
        self.ensure_dind_ready()?;

        let SandboxInner::Docker(inner) = &*self.inner else {
            anyhow::bail!("nested docker container listing requires a docker sandbox");
        };

        let output = self.run_shell(&format!(
            "docker -H {host} ps -a --filter label={label} --format '{{{{.Names}}}}'",
            host = shell_quote(INNER_DOCKER_HOST),
            label = shell_quote(label),
        ))?;
        anyhow::ensure!(
            output.status.success(),
            "failed to list nested docker containers in sandbox {}: {}",
            inner.container_name,
            String::from_utf8_lossy(&output.stderr)
        );

        let mut names: Vec<String> = String::from_utf8(output.stdout)
            .context("nested docker ps output was not valid UTF-8")?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        names.sort();
        Ok(names)
    }

    pub fn spawn_background_binary_in_child_container(
        &self,
        binary_path: &Path,
        working_dir: Option<&Path>,
    ) -> Result<BackgroundProcess> {
        let runtime = self.ensure_child_runtime_state()?;

        let SandboxInner::Docker(inner) = &*self.inner else {
            anyhow::bail!("child-container targets require a docker sandbox");
        };

        let pid_file = format!(
            "/tmp/ghostscope-child-target-{}.pid",
            unix_timestamp_nanos()
        );
        let err_file = format!(
            "/tmp/ghostscope-child-target-{}.err",
            unix_timestamp_nanos()
        );
        let working_dir = working_dir
            .map(Path::to_path_buf)
            .or_else(|| binary_path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from(CONTAINER_REPO_ROOT));
        let entrypoint = format!(
            "rm -f {pid_file} {err_file}; cd {workdir}; {binary} >/dev/null 2>{err_file} & child=$!; echo $child > {pid_file}; wait $child",
            pid_file = shell_quote(&pid_file),
            err_file = shell_quote(&err_file),
            workdir = shell_quote(&working_dir.display().to_string()),
            binary = shell_quote(&binary_path.display().to_string()),
        );
        let script = format!(
            "docker -H {host} exec -d {name} bash -lc {entrypoint}",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(&runtime.container_name),
            entrypoint = shell_quote(&entrypoint),
        );
        let output = self.run_shell(&script).with_context(|| {
            format!(
                "failed to start child-container target {} in sandbox {}",
                binary_path.display(),
                inner.container_name
            )
        })?;
        anyhow::ensure!(
            output.status.success(),
            "failed to start child-container target {} in sandbox {}: {}",
            binary_path.display(),
            inner.container_name,
            String::from_utf8_lossy(&output.stderr)
        );

        let read_pid_script = format!(
            "docker -H {host} exec {name} cat {pid_file}",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(&runtime.container_name),
            pid_file = shell_quote(&pid_file),
        );
        let read_err_script = format!(
            "docker -H {host} exec {name} cat {err_file} 2>/dev/null || true",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(&runtime.container_name),
            err_file = shell_quote(&err_file),
        );
        let cleanup_script = format!(
            "docker -H {host} exec {name} rm -f {pid_file} {err_file} >/dev/null 2>&1 || true",
            host = shell_quote(INNER_DOCKER_HOST),
            name = shell_quote(&runtime.container_name),
            pid_file = shell_quote(&pid_file),
            err_file = shell_quote(&err_file),
        );

        for _ in 0..30 {
            let pid_output = self.run_shell(&read_pid_script).with_context(|| {
                format!(
                    "failed to inspect child-container target runtime {} in sandbox {}",
                    runtime.container_name, inner.container_name
                )
            })?;
            if pid_output.status.success() {
                let pid_text = String::from_utf8(pid_output.stdout)
                    .context("child-container pid output was not valid UTF-8")?;
                let child_local_pid = pid_text
                    .trim()
                    .parse::<u32>()
                    .with_context(|| format!("invalid child-container pid output: {pid_text}"))?;
                if let Ok((sandbox_pid, _host_pid)) =
                    self.resolve_descendant_process_pids(&runtime, child_local_pid)
                {
                    let _ = self.run_shell(&cleanup_script);
                    return Ok(BackgroundProcess::ChildContainer { pid: sandbox_pid });
                }

                let process_alive = self
                    .run_shell(&format!(
                        "docker -H {host} exec {name} test -r /proc/{pid}/status",
                        host = shell_quote(INNER_DOCKER_HOST),
                        name = shell_quote(&runtime.container_name),
                        pid = child_local_pid,
                    ))?
                    .status
                    .success();
                if !process_alive {
                    let logs = self
                        .run_shell(&read_err_script)
                        .ok()
                        .and_then(|output| String::from_utf8(output.stdout).ok())
                        .unwrap_or_default();
                    let _ = self.run_shell(&cleanup_script);
                    let trimmed_logs = logs.trim();
                    anyhow::bail!(
                        "child-container target {} exited before it could be observed: {}",
                        binary_path.display(),
                        if trimmed_logs.is_empty() {
                            "<no logs available>"
                        } else {
                            trimmed_logs
                        }
                    );
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }

        let _ = self.run_shell(&cleanup_script);
        anyhow::bail!(
            "timed out waiting for child-container target {} to become visible (runtime={})",
            binary_path.display(),
            runtime.container_name
        )
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

    pub fn remove_child_container(&self, container_name: &str) -> Result<()> {
        match &*self.inner {
            SandboxInner::Host => {
                anyhow::bail!("cannot remove a child container from the host sandbox")
            }
            SandboxInner::Docker(inner) => {
                anyhow::ensure!(
                    matches!(inner.pid_mode, DockerPidMode::Private),
                    "child-container cleanup requires a private docker sandbox"
                );
                self.ensure_dind_ready()?;
                let output = self.run_shell(&format!(
                    "docker -H {host} rm -f {name}",
                    host = shell_quote(INNER_DOCKER_HOST),
                    name = shell_quote(container_name),
                ))?;
                if output.status.success() {
                    return Ok(());
                }

                let stderr = String::from_utf8_lossy(&output.stderr);
                if is_missing_docker_container_error(&stderr) {
                    return Ok(());
                }

                anyhow::bail!(
                    "failed to remove child container {} from sandbox {}: {}",
                    container_name,
                    inner.container_name,
                    stderr
                )
            }
        }
    }

    pub fn terminate_pid(&self, pid: u32) -> Result<()> {
        let label = self.label().to_owned();
        terminate_pid_with_escalation(
            pid,
            &label,
            GRACEFUL_TERMINATION_TIMEOUT,
            FORCEFUL_TERMINATION_TIMEOUT,
            |pid| self.send_signal_to_pid(pid, "TERM"),
            |pid| self.send_signal_to_pid(pid, "KILL"),
            |pid| self.pid_is_running(pid),
        )
    }

    fn send_signal_to_pid(&self, pid: u32, signal: &str) -> Result<()> {
        match &*self.inner {
            SandboxInner::Host => {
                send_pid_signal_with_shell("host", pid, &format!("kill -{signal} {pid}"))
            }
            SandboxInner::Docker(inner) => send_pid_signal_with_shell(
                &inner.container_name,
                pid,
                &format!(
                    "docker exec {} kill -{} {}",
                    inner.container_name, signal, pid
                ),
            ),
        }
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
                let bin = self.resolve_ghostscope_bin_for_sandbox()?;
                let output = self.run_shell(&format!(
                    "test -x {}",
                    shell_quote(&bin.display().to_string())
                ))?;
                anyhow::ensure!(
                    output.status.success(),
                    "ghostscope host binary {} is not executable inside docker sandbox {}",
                    bin.display(),
                    inner.container_name
                );
                Ok((
                    OsString::from("docker"),
                    vec![
                        OsString::from("exec"),
                        OsString::from(&inner.container_name),
                        bin.into_os_string(),
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
                let bin_path = self.resolve_ghostscope_bin_for_sandbox()?;
                let output = self.run_shell(&format!(
                    "test -x {}",
                    shell_quote(&bin_path.display().to_string())
                ))?;
                anyhow::ensure!(
                    output.status.success(),
                    "ghostscope host binary {} is not executable inside docker sandbox {}",
                    bin_path.display(),
                    inner.container_name
                );
                let bin = shell_quote(&bin_path.display().to_string());
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

fn resolve_default_child_image() -> String {
    if let Ok(image) = std::env::var("E2E_CHILD_CONTAINER_IMAGE") {
        if !image.trim().is_empty() {
            return image;
        }
    }
    // Nested child containers default to the same runtime image as the outer
    // sandbox so local runs and CI do not fall back to a fresh ubuntu pull.
    resolve_default_image()
}

fn resolve_inner_child_image_ref(child_image: &str) -> String {
    if let Some((_, digest)) = child_image.split_once("@sha256:") {
        let short = &digest[..digest.len().min(16)];
        return format!("ghostscope-e2e-child:{short}");
    }
    child_image.to_string()
}

fn current_sandbox_session() -> Option<String> {
    std::env::var(ENV_E2E_SANDBOX_SESSION)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn session_scoped_container_name(session: &str, spec: &DockerSpec, repo_root: &Path) -> String {
    let mode = match spec.pid_mode {
        DockerPidMode::Private => "private",
        DockerPidMode::Host => "host",
    };
    let session_part = sanitize_docker_name_component(session, 24);
    let key = format!("{session}|{mode}|{}|{}", spec.image, repo_root.display());
    let hash = stable_name_hash(&key);
    format!("ghostscope-session-{session_part}-{mode}-{hash:016x}")
}

fn child_runtime_container_name(outer_container_name: &str, inner_child_image: &str) -> String {
    let outer_part = sanitize_docker_name_component(outer_container_name, 24);
    let hash = stable_name_hash(&format!("{outer_container_name}|{inner_child_image}"));
    format!("ghostscope-child-runtime-{outer_part}-{hash:016x}")
}

fn sanitize_docker_name_component(value: &str, max_len: usize) -> String {
    let mut out = String::with_capacity(max_len);
    for ch in value.chars() {
        let mapped = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            '-'
        };
        if mapped == '-' && out.ends_with('-') {
            continue;
        }
        out.push(mapped);
        if out.len() >= max_len {
            break;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "default".to_string()
    } else {
        trimmed.to_string()
    }
}

fn stable_name_hash(input: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
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
    let current_session = current_sandbox_session();
    for container_id in list_test_sandbox_container_ids()? {
        let Some(metadata) = inspect_test_sandbox_if_present(&container_id)? else {
            continue;
        };
        if metadata.session == current_session {
            continue;
        }
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
    session: Option<String>,
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

    fn is_session_scoped(&self) -> bool {
        self.session
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty())
    }
}

fn inspect_test_sandbox_if_present(container_id: &str) -> Result<Option<TestSandboxMetadata>> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{.Name}}|{{ index .Config.Labels \"ghostscope.owner-pid\" }}|{{ index .Config.Labels \"ghostscope.owner-starttime\" }}|{{ index .Config.Labels \"ghostscope.session\" }}",
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
    let session = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "<no value>")
        .map(ToOwned::to_owned);

    Ok(Some(TestSandboxMetadata {
        name,
        owner_pid,
        owner_starttime,
        session,
    }))
}

#[derive(Debug)]
struct DockerContainerState {
    running: bool,
    image: String,
}

fn inspect_docker_container_state(container_name: &str) -> Result<Option<DockerContainerState>> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{.State.Running}}|{{.Config.Image}}",
            container_name,
        ])
        .output()
        .with_context(|| format!("failed to inspect docker sandbox {container_name}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_missing_docker_container_error(&stderr) {
            return Ok(None);
        }
        anyhow::bail!(
            "failed to inspect docker sandbox {}: {}",
            container_name,
            stderr
        );
    }

    let line =
        String::from_utf8(output.stdout).context("docker inspect output was not valid UTF-8")?;
    let mut parts = line.trim().split('|');
    let running = parts
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("true"));
    let image = parts.next().unwrap_or_default().trim().to_string();

    Ok(Some(DockerContainerState { running, image }))
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

fn parse_ppid(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("PPid:"))?;
    line.strip_prefix("PPid:")?.trim().parse::<u32>().ok()
}

fn process_descends_from(mut pid: u32, ancestor_pid: u32) -> bool {
    if pid == ancestor_pid {
        return true;
    }

    let mut visited = HashSet::new();
    while pid > 1 && visited.insert(pid) {
        let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) else {
            return false;
        };
        let Some(ppid) = parse_ppid(&status) else {
            return false;
        };
        if ppid == ancestor_pid {
            return true;
        }
        if ppid == 0 || ppid == pid {
            return false;
        }
        pid = ppid;
    }

    false
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

fn stage_host_binary_under_repo(host_bin: &Path, name: &str) -> Result<PathBuf> {
    let repo_root = workspace_root()?;
    let staged_dir = repo_root.join(STAGED_TOOL_DIR);
    fs::create_dir_all(&staged_dir).with_context(|| {
        format!(
            "failed to create staged tool directory {}",
            staged_dir.display()
        )
    })?;

    let staged = staged_dir.join(name);
    if host_bin == staged {
        return Ok(staged);
    }

    let needs_copy = match (fs::metadata(host_bin), fs::metadata(&staged)) {
        (Ok(src), Ok(dst)) => {
            let src_mtime = src.modified().ok();
            let dst_mtime = dst.modified().ok();
            src.len() != dst.len() || src_mtime != dst_mtime
        }
        (Ok(_), Err(_)) => true,
        (Err(err), _) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("failed to stat host binary {}", host_bin.display()));
        }
    };

    if needs_copy {
        fs::copy(host_bin, &staged).with_context(|| {
            format!(
                "failed to stage host binary {} under repo root at {}",
                host_bin.display(),
                staged.display()
            )
        })?;
        let mut perms = fs::metadata(&staged)
            .with_context(|| format!("failed to stat staged binary {}", staged.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&staged, perms)
            .with_context(|| format!("failed to chmod staged binary {}", staged.display()))?;
    }

    Ok(staged)
}

fn send_pid_signal_with_shell(label: &str, pid: u32, command: &str) -> Result<()> {
    let _ = Command::new("bash")
        .args(["-lc", command])
        .status()
        .with_context(|| format!("failed to signal pid {pid} in {label}"))?;
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

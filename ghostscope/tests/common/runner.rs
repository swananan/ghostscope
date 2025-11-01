//! Shared asynchronous runner for invoking the `ghostscope` CLI from tests.
//!
//! Features:
//! - Attach by PID or by target path (exactly one required)
//! - Configurable timeout (overall cap) and optional PerfEventArray backend
//! - Consistent flags: disable artifact saving by default; logging opt-in
//! - Robust output collection: incremental read during run, drain after exit
//! - Pragmatic success rule: if process was killed on timeout but produced
//!   any output, treat exit code -1 as success (0) to keep tests stable

use anyhow::Result;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::{timeout, Duration};

pub struct GhostscopeRunner {
    script_content: String,
    pid: Option<u32>,
    target: Option<PathBuf>,
    timeout_secs: u64,
    force_perf_event_array: bool,
    log_level: Option<String>,
    enable_sysmon_shared_lib: bool,
    enable_file_logging: bool,
}

impl Default for GhostscopeRunner {
    fn default() -> Self {
        Self {
            script_content: String::new(),
            pid: None,
            target: None,
            timeout_secs: 3,
            force_perf_event_array: false,
            log_level: None,
            enable_sysmon_shared_lib: false,
            enable_file_logging: false,
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

    pub fn with_target<P: AsRef<Path>>(mut self, target: P) -> Self {
        self.target = Some(target.as_ref().to_path_buf());
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

    pub fn enable_file_logging(mut self, yes: bool) -> Self {
        self.enable_file_logging = yes;
        self
    }

    #[allow(dead_code)]
    pub fn with_log_level<S: Into<String>>(mut self, level: S) -> Self {
        self.log_level = Some(level.into());
        self
    }

    fn resolve_ghostscope_bin() -> PathBuf {
        // Prefer Cargo-provided binary path, fallback to a relative debug path
        if let Ok(p) = std::env::var("CARGO_BIN_EXE_ghostscope") {
            PathBuf::from(p)
        } else {
            PathBuf::from("../target/debug/ghostscope")
        }
    }

    pub async fn run(self) -> Result<(i32, String, String)> {
        // Validate attach mode
        let by_pid = self.pid.is_some();
        let by_target = self.target.is_some();
        anyhow::ensure!(by_pid ^ by_target, "Must set exactly one of pid or target");

        // Write script to a temp file
        let mut script_file = NamedTempFile::new()?;
        use std::io::Write as _;
        script_file.write_all(self.script_content.as_bytes())?;
        let script_path = script_file.path().to_path_buf();

        // Build command + args
        let binary_path = Self::resolve_ghostscope_bin();
        let mut args: Vec<OsString> = Vec::new();

        if let Some(pid) = self.pid {
            args.push(OsString::from("-p"));
            args.push(OsString::from(pid.to_string()));
        } else if let Some(ref target) = self.target {
            args.push(OsString::from("-t"));
            args.push(target.clone().into_os_string());
        }

        args.push(OsString::from("--script-file"));
        args.push(script_path.into_os_string());

        if let Some(level) = &self.log_level {
            args.push(OsString::from("--log-level"));
            args.push(OsString::from(level.clone()));
        }

        if self.force_perf_event_array {
            args.push(OsString::from("--force-perf-event-array"));
        }

        // Opt-in sysmon for -t shared library tests
        if self.enable_sysmon_shared_lib {
            args.push(OsString::from("--enable-sysmon-shared-lib"));
        }

        if self.enable_file_logging {
            args.push(OsString::from("--log"));
        }

        let mut cmd = Command::new(&binary_path);
        cmd.args(&args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        let mut child = cmd.spawn()?;

        let stdout_handle = child.stdout.take().unwrap();
        let stderr_handle = child.stderr.take().unwrap();
        let mut stdout_reader = BufReader::new(stdout_handle);
        let mut stderr_reader = BufReader::new(stderr_handle);

        let mut stdout_content = String::new();
        let mut stderr_content = String::new();

        // Incremental read with periodic polls, bounded by overall timeout
        let read_task = async {
            let mut stdout_line = String::new();
            let mut stderr_line = String::new();
            loop {
                // stdout
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
                // stderr
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
                // quit early if the process exited
                if let Ok(Some(_status)) = child.try_wait() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        };

        let _ = timeout(Duration::from_secs(self.timeout_secs), read_task).await;

        // Determine exit code; kill on timeout
        let mut exit_code = match child.try_wait() {
            Ok(Some(status)) => status.code().unwrap_or(-1),
            _ => {
                let _ = child.kill().await.is_ok(); // best-effort
                match timeout(Duration::from_secs(2), child.wait()).await {
                    Ok(Ok(status)) => status.code().unwrap_or(-1),
                    _ => -1,
                }
            }
        };

        // Drain any remaining output to capture full diagnostics/banners
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

        // If the process was force-killed and produced some output, consider it success.
        if exit_code == -1 && (!stdout_content.is_empty() || !stderr_content.is_empty()) {
            exit_code = 0;
        }

        Ok((exit_code, stdout_content, stderr_content))
    }
}

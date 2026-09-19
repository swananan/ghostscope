mod common;

use anyhow::{ensure, Context, Result};
use common::sandbox::SandboxHandle;
use std::ffi::OsString;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, BufReader};

enum PipeShutdown {
    Signal { signal: i32, merge_stderr: bool },
    CloseReader { fill_pipe: bool },
}

async fn exercise_pipe_shutdown(shutdown: PipeShutdown) -> Result<()> {
    common::init();
    let sandbox = SandboxHandle::default_ghostscope()?;
    if !sandbox.is_host_backend() {
        eprintln!("Host pipe lifecycle test is covered by Standard E2E and host-to-private E2E");
        return Ok(());
    }
    let binary = common::FIXTURES.get_test_binary("scalar_types_program")?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .spawn()
        .await?;
    let stderr = tempfile::NamedTempFile::new()?;
    let result = async {
        let script = format!("trace scalar_anchor {{ print \"{}\"; }}", "x".repeat(1024));
        let args: Vec<OsString> = [
            "--no-log",
            "--no-status",
            "--debuginfod",
            "off",
            "--no-save-llvm-ir",
            "--no-save-ebpf",
            "--no-save-ast",
            "--script-output",
            "plain",
            "--script-output-events-per-sec",
            "0",
            "--emit-ready-marker",
            "PIPE_READY",
            "-p",
            &target.visible_pid_from(&sandbox)?.to_string(),
            "-s",
            &script,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        let launch = sandbox.ghostscope_runner_command(&args)?;
        let mut command = tokio::process::Command::new(&launch.program);
        command
            .args(&launch.args)
            .stdout(Stdio::piped())
            .stderr(stderr.reopen()?)
            .kill_on_drop(true);
        if matches!(
            shutdown,
            PipeShutdown::Signal {
                merge_stderr: true,
                ..
            }
        ) {
            // SAFETY: the child only calls async-signal-safe dup2 before exec;
            // descriptors 1 and 2 are configured by Command above.
            unsafe {
                command.pre_exec(|| {
                    if libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn()?;
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut line = String::new();
                ensure!(
                    reader.read_line(&mut line).await? != 0,
                    "exited before ready marker"
                );
                if line.contains("PIPE_READY") {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await
        .context("waiting for tracing to become ready")??;

        if !matches!(shutdown, PipeShutdown::CloseReader { fill_pipe: false }) {
            // Poll the pipe's write readiness: fragmented pipe buffers can block
            // writes before FIONREAD reaches the nominal byte capacity.
            let pid = child
                .id()
                .context("GhostScope exited before pipe inspection")?;
            let pipe = std::fs::OpenOptions::new()
                .write(true)
                .open(format!("/proc/{pid}/fd/1"))?;
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    ensure!(
                        child.try_wait()?.is_none(),
                        "exited while filling stdout pipe"
                    );
                    let mut descriptor = libc::pollfd {
                        fd: pipe.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    // SAFETY: descriptor is one initialized pollfd for the live pipe.
                    let status = unsafe { libc::poll(&mut descriptor, 1, 0) };
                    ensure!(status >= 0, "failed to inspect stdout pipe");
                    if descriptor.revents & libc::POLLOUT == 0 {
                        return Ok::<_, anyhow::Error>(());
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .context("stdout pipe never filled")??;
            // Leave enough events for the bounded userspace queue to fill too.
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        let status = match shutdown {
            PipeShutdown::Signal {
                signal,
                merge_stderr,
            } => {
                let pid = child
                    .id()
                    .context("GhostScope exited before shutdown signal")?;
                ensure!(
                    // SAFETY: pid belongs to the live child retained above; kill takes scalar arguments.
                    unsafe { libc::kill(pid as libc::pid_t, signal) } == 0,
                    "failed to send signal {signal}"
                );
                // Keep the read end open without draining it until the child has exited.
                let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
                    .await
                    .context("shutdown signal was blocked by full stdout")??;
                if !merge_stderr {
                    ensure!(
                        std::fs::read_to_string(stderr.path())?
                            .contains("discarding pending script output"),
                        "shutdown must disclose output abandoned after the drain deadline"
                    );
                }
                drop(reader);
                status
            }
            PipeShutdown::CloseReader { .. } => {
                drop(reader);
                tokio::time::timeout(Duration::from_secs(2), child.wait())
                    .await
                    .context("tracing continued after the stdout reader closed")??
            }
        };
        ensure!(status.success(), "unexpected shutdown status: {status}");
        Ok(())
    }
    .await;
    target.terminate().await?;
    result.with_context(|| std::fs::read_to_string(stderr.path()).unwrap_or_default())
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_a_full_stdout_pipe() -> Result<()> {
    exercise_pipe_shutdown(PipeShutdown::Signal {
        signal: libc::SIGTERM,
        merge_stderr: false,
    })
    .await
}

#[tokio::test]
async fn test_sigint_stops_tracing_with_a_full_stdout_pipe() -> Result<()> {
    exercise_pipe_shutdown(PipeShutdown::Signal {
        signal: libc::SIGINT,
        merge_stderr: false,
    })
    .await
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_a_full_combined_stdout_stderr_pipe() -> Result<()> {
    exercise_pipe_shutdown(PipeShutdown::Signal {
        signal: libc::SIGTERM,
        merge_stderr: true,
    })
    .await
}

#[tokio::test]
async fn test_closed_stdout_reader_stops_tracing() -> Result<()> {
    exercise_pipe_shutdown(PipeShutdown::CloseReader { fill_pipe: false }).await
}

#[tokio::test]
async fn test_closed_stdout_reader_stops_tracing_with_a_full_queue() -> Result<()> {
    exercise_pipe_shutdown(PipeShutdown::CloseReader { fill_pipe: true }).await
}

enum StderrWarning {
    RateLimit,
    KernelLoss,
}

async fn exercise_stderr_warning_shutdown(
    warning: StderrWarning,
    merge_stderr: bool,
    console_logging: bool,
) -> Result<()> {
    common::init();
    let sandbox = SandboxHandle::default_ghostscope()?;
    if !sandbox.is_host_backend() {
        eprintln!("Host pipe lifecycle test is covered by Standard E2E and host-to-private E2E");
        return Ok(());
    }
    if matches!(warning, StderrWarning::KernelLoss)
        && !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_ringbuf
    {
        eprintln!("Deterministic output-helper loss requires RingBuf support");
        return Ok(());
    }
    let binary = common::FIXTURES.get_test_binary("scalar_types_program")?;
    let target = common::targets::TargetLauncher::binary(&binary)
        .spawn()
        .await?;
    let log = tempfile::NamedTempFile::new()?;
    let mut config = tempfile::NamedTempFile::new()?;
    let (script, warning_text) = match warning {
        StderrWarning::RateLimit => (
            "trace scalar_anchor { print \"EVENT\"; }",
            "script output saturated",
        ),
        StderrWarning::KernelLoss => {
            // Dynamic capture fills the 4096-byte event budget, leaving no room
            // for the RingBuf record header. Every hit exercises the real
            // output-helper failure counter and report.
            writeln!(config, "[ebpf]\nringbuf_size = 4096\nmem_dump_cap = 4096")?;
            (
                "trace scalar_anchor { print \"{:x.*}\", 4096, cast($sp, \"unsigned char *\"); }",
                "eBPF output helper failed",
            )
        }
    };
    let result = async {
        let mut args: Vec<OsString> = [
            "--no-status",
            "--debuginfod",
            "off",
            "--no-save-llvm-ir",
            "--no-save-ebpf",
            "--no-save-ast",
            "--script-output",
            "plain",
            "--script-output-events-per-sec",
            "1",
            "--emit-ready-marker",
            "PIPE_READY",
            "-p",
            &target.visible_pid_from(&sandbox)?.to_string(),
            "-s",
            script,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.push("--config".into());
        args.push(config.path().as_os_str().to_owned());
        if console_logging {
            args.extend(
                [
                    "--log",
                    "--log-console",
                    "--log-level",
                    "warn",
                    "--log-file",
                ]
                .map(OsString::from),
            );
            args.push(log.path().as_os_str().to_owned());
        } else {
            args.push("--no-log".into());
        }
        let launch = sandbox.ghostscope_runner_command(&args)?;
        let mut command = tokio::process::Command::new(&launch.program);
        command
            .args(&launch.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if merge_stderr {
            // SAFETY: only async-signal-safe dup2 runs in the child before exec.
            unsafe {
                command.pre_exec(|| {
                    if libc::dup2(libc::STDOUT_FILENO, libc::STDERR_FILENO) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = command.spawn()?;
        let mut stdout = Some(BufReader::new(child.stdout.take().unwrap()));
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut line = String::new();
                if stdout.as_mut().unwrap().read_line(&mut line).await? == 0 {
                    let mut error = String::new();
                    if let Some(stderr) = child.stderr.as_mut() {
                        stderr.read_to_string(&mut error).await?;
                    }
                    anyhow::bail!("exited before ready marker: {error}");
                }
                if line.contains("PIPE_READY") {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await
        .context("waiting for tracing to become ready")??;
        let mut diagnostics: Box<dyn AsyncBufRead + Unpin> = if merge_stderr {
            Box::new(stdout.take().unwrap())
        } else {
            Box::new(BufReader::new(child.stderr.take().unwrap()))
        };
        // First prove the real warning is reporting before stopping consumption.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let mut line = String::new();
                ensure!(
                    diagnostics.read_line(&mut line).await? != 0,
                    "exited before runtime warning"
                );
                if line.contains(warning_text) {
                    return Ok::<_, anyhow::Error>(());
                }
            }
        })
        .await
        .context("waiting for the first runtime warning")??;

        let pid = child
            .id()
            .context("GhostScope exited before pipe inspection")?;
        // Opening /proc creates a separate file description, so O_NONBLOCK does
        // not change GhostScope's stderr flags. Keep its read end open and idle.
        let mut pipe = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(format!("/proc/{pid}/fd/2"))?;
        loop {
            match pipe.write(&[b'x'; 4096]) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => return Err(error.into()),
            }
        }
        // Keep producing warnings long enough to fill both the OS pipe and the
        // bounded userspace diagnostic queue, so signal handling must also
        // interrupt a pending asynchronous enqueue.
        tokio::time::sleep(Duration::from_millis(11_500)).await;
        ensure!(
            child.try_wait()?.is_none(),
            "GhostScope exited before SIGTERM"
        );
        ensure!(
            // SAFETY: pid belongs to this live child; kill takes scalar arguments.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == 0,
            "failed to send SIGTERM"
        );
        let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .context("SIGTERM was blocked by a runtime stderr warning")??;
        ensure!(status.success(), "unexpected shutdown status: {status}");
        Ok(())
    }
    .await;
    target.terminate().await?;
    result.with_context(|| std::fs::read_to_string(log.path()).unwrap_or_default())
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_full_stderr_warning_pipe() -> Result<()> {
    exercise_stderr_warning_shutdown(StderrWarning::RateLimit, false, false).await
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_full_combined_stderr_warning_pipe() -> Result<()> {
    exercise_stderr_warning_shutdown(StderrWarning::RateLimit, true, false).await
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_full_console_stderr_warning_pipe() -> Result<()> {
    exercise_stderr_warning_shutdown(StderrWarning::RateLimit, false, true).await
}

#[tokio::test]
async fn test_sigterm_stops_tracing_with_full_kernel_loss_stderr_warning_pipe() -> Result<()> {
    exercise_stderr_warning_shutdown(StderrWarning::KernelLoss, false, false).await
}

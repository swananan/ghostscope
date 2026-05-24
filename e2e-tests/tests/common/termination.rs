use anyhow::Context;
use std::time::{Duration, Instant};

pub(crate) const GRACEFUL_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(50);

#[cfg(unix)]
pub(crate) fn send_sigterm(pid: u32, label: &str) -> anyhow::Result<()> {
    // SAFETY: libc::kill has no pointer arguments; pid and signal are plain values.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc == 0 {
        return Ok(());
    }

    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }

    Err(err).with_context(|| format!("failed to send SIGTERM to {label} pid {pid}"))
}

#[cfg(not(unix))]
pub(crate) fn send_sigterm(pid: u32, label: &str) -> anyhow::Result<()> {
    let _ = (pid, label);
    anyhow::bail!("SIGTERM helpers are only supported on Unix test platforms");
}

pub(crate) fn terminate_pid_gracefully<Send, Running>(
    pid: u32,
    label: &str,
    wait_timeout: Duration,
    mut send_term: Send,
    mut is_running: Running,
) -> anyhow::Result<()>
where
    Send: FnMut(u32) -> anyhow::Result<()>,
    Running: FnMut(u32) -> anyhow::Result<bool>,
{
    if !is_running(pid)? {
        return Ok(());
    }

    send_term(pid)?;

    let deadline = Instant::now() + wait_timeout;
    while Instant::now() < deadline {
        if !is_running(pid)? {
            return Ok(());
        }
        std::thread::sleep(TERMINATION_POLL_INTERVAL);
    }

    anyhow::bail!("timed out waiting for {label} pid {pid} to exit after SIGTERM");
}

pub(crate) fn terminate_std_child_gracefully(
    child: &mut std::process::Child,
    label: &str,
    wait_timeout: Duration,
) -> anyhow::Result<Option<std::process::ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }

    let pid = child.id();
    send_sigterm(pid, label)?;

    let deadline = Instant::now() + wait_timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(TERMINATION_POLL_INTERVAL);
    }
}

pub(crate) async fn terminate_tokio_child_gracefully(
    child: &mut tokio::process::Child,
    label: &str,
    wait_timeout: Duration,
) -> anyhow::Result<Option<std::process::ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }

    let pid = child
        .id()
        .context("child process does not have an OS pid for SIGTERM")?;
    send_sigterm(pid, label)?;

    match tokio::time::timeout(wait_timeout, child.wait()).await {
        Ok(result) => result.map(Some).map_err(Into::into),
        Err(_) => Ok(None),
    }
}

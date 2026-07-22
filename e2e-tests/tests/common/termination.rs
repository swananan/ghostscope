use anyhow::Context;
use std::time::{Duration, Instant};

pub(crate) const GRACEFUL_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const FORCEFUL_TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
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

pub(crate) fn terminate_pid_with_escalation<SendTerm, SendKill, Running>(
    pid: u32,
    label: &str,
    graceful_timeout: Duration,
    forceful_timeout: Duration,
    mut send_term: SendTerm,
    mut send_kill: SendKill,
    mut is_running: Running,
) -> anyhow::Result<()>
where
    SendTerm: FnMut(u32) -> anyhow::Result<()>,
    SendKill: FnMut(u32) -> anyhow::Result<()>,
    Running: FnMut(u32) -> anyhow::Result<bool>,
{
    if !is_running(pid)? {
        return Ok(());
    }

    send_term(pid)?;
    if wait_for_pid_exit(pid, graceful_timeout, &mut is_running)? {
        return Ok(());
    }

    send_kill(pid)?;
    if wait_for_pid_exit(pid, forceful_timeout, &mut is_running)? {
        return Ok(());
    }

    anyhow::bail!("timed out waiting for {label} pid {pid} to exit after SIGTERM and SIGKILL");
}

fn wait_for_pid_exit<Running>(
    pid: u32,
    wait_timeout: Duration,
    is_running: &mut Running,
) -> anyhow::Result<bool>
where
    Running: FnMut(u32) -> anyhow::Result<bool>,
{
    let deadline = Instant::now() + wait_timeout;
    while Instant::now() < deadline {
        if !is_running(pid)? {
            return Ok(true);
        }
        std::thread::sleep(TERMINATION_POLL_INTERVAL);
    }
    Ok(false)
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

pub(crate) async fn terminate_tokio_child_with_escalation(
    child: &mut tokio::process::Child,
    label: &str,
    graceful_timeout: Duration,
    forceful_timeout: Duration,
) -> anyhow::Result<Option<std::process::ExitStatus>> {
    if let Some(status) = child.try_wait()? {
        return Ok(Some(status));
    }

    let pid = child
        .id()
        .context("child process does not have an OS pid for SIGTERM")?;
    send_sigterm(pid, label)?;

    match tokio::time::timeout(graceful_timeout, child.wait()).await {
        Ok(result) => return result.map(Some).map_err(Into::into),
        Err(_) => {}
    }

    child
        .start_kill()
        .with_context(|| format!("failed to send SIGKILL to {label} pid {pid}"))?;
    match tokio::time::timeout(forceful_timeout, child.wait()).await {
        Ok(result) => result.map(Some).map_err(Into::into),
        Err(_) => Ok(None),
    }
}

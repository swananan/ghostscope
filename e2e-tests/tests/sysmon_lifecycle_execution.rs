//! Exercise lifecycle events themselves so periodic discovery cannot hide lost forks.
use anyhow::{ensure, Context, Result};
use ghostscope_process::{
    offsets::ProcessManager,
    pid::read_pid_ns_id,
    pinned_bpf_maps,
    sysmon::{ProcessSysmon, SysEventKind, SysmonConfig, SysmonEventMask},
};
use std::{
    io::Write,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[test]
fn test_sysmon_process_lifecycle() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let source = dir.path().join("lifecycle.c");
    let binary = dir.path().join("lifecycle");
    std::fs::write(
        &source,
        r#"
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <signal.h>
void *worker(void *p) { return p; }
void *last_thread(void *p) { getchar(); return p; }
int main(void) {
    int command; pid_t child = 0;
    while ((command = getchar()) != EOF) {
        pthread_t thread;
        if (command == 'w') { pthread_create(&thread, 0, worker, 0); pthread_join(thread, 0); }
        if (command == 'f') { child = fork(); if (!child) { for (;;) pause(); } }
        if (command == 'c') { kill(child, SIGTERM); waitpid(child, 0, 0); }
        if (command == 'l') { pthread_create(&thread, 0, last_thread, 0); pthread_exit(0); }
    }
    return 0;
}
"#,
    )?;
    ensure!(
        Command::new("cc")
            .args(["-g", "-O0", "-pthread"])
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()?
            .success(),
        "compile lifecycle fixture"
    );
    let child = Command::new(&binary)
        .process_group(0)
        .stdin(Stdio::piped())
        .spawn()?;
    let mut target = scopeguard::guard(child, |mut child| {
        // SAFETY: the fixture owns this new process group; killpg sends a signal
        // without accessing Rust memory, and also reaps any forked fixture on failure.
        unsafe {
            libc::killpg(child.id() as i32, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    });
    let parent = target.id();
    let mut config = SysmonConfig::new();
    config.target_module = Some(binary);
    config.event_pid_ns = read_pid_ns_id(std::process::id());
    config.event_mask = SysmonEventMask {
        exec: false,
        fork: true,
        exit: true,
        map_change: false,
    };
    let mut sysmon = ProcessSysmon::new(Arc::new(Mutex::new(ProcessManager::new())), config);
    sysmon.start();
    ensure!(
        pinned_bpf_maps::allowed_pid_exists(parent)?,
        "sysmon start returned before initial parent prefill"
    );
    let send = |target: &mut std::process::Child, command: &[u8]| -> Result<()> {
        target
            .stdin
            .as_mut()
            .context("fixture stdin")?
            .write_all(command)?;
        Ok(())
    };
    send(&mut target, b"w")?;
    ensure!(
        recv_lifecycle(&sysmon, Duration::from_secs(1)).is_none(),
        "thread creation/exit emitted a process lifecycle event"
    );
    ensure!(
        pinned_bpf_maps::allowed_pid_exists(parent)?,
        "worker exit removed the parent allowlist entry"
    );
    send(&mut target, b"f")?;
    let fork =
        recv_lifecycle(&sysmon, Duration::from_secs(5)).context("missing child fork event")?;
    ensure!(
        fork.event_kind() == Some(SysEventKind::Fork) && fork.tgid != parent,
        "fork reported the parent: {fork:?}"
    );
    ensure!(
        pinned_bpf_maps::allowed_pid_exists(fork.tgid)?,
        "child was not prefilled"
    );
    send(&mut target, b"c")?;
    let exit =
        recv_lifecycle(&sysmon, Duration::from_secs(5)).context("missing child exit event")?;
    ensure!(
        exit.event_kind() == Some(SysEventKind::Exit) && exit.tgid == fork.tgid,
        "wrong child exit: {exit:?}"
    );
    ensure!(
        !pinned_bpf_maps::allowed_pid_exists(fork.tgid)?,
        "child exit retained process state"
    );
    send(&mut target, b"l")?;
    ensure!(
        recv_lifecycle(&sysmon, Duration::from_secs(1)).is_none(),
        "leader exit cleaned up a live thread group"
    );
    ensure!(
        pinned_bpf_maps::allowed_pid_exists(parent)?,
        "leader exit removed process state"
    );
    send(&mut target, b"x")?;
    let exit = recv_lifecycle(&sysmon, Duration::from_secs(5))
        .context("missing last-thread exit event")?;
    ensure!(
        exit.event_kind() == Some(SysEventKind::Exit) && exit.tgid == parent,
        "wrong final exit: {exit:?}"
    );
    ensure!(
        !pinned_bpf_maps::allowed_pid_exists(parent)?,
        "final exit retained process state"
    );
    Ok(())
}

fn recv_lifecycle(
    sysmon: &ProcessSysmon,
    timeout: Duration,
) -> Option<ghostscope_process::sysmon::SysEvent> {
    let deadline = Instant::now() + timeout;
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let event = sysmon.recv_timeout(remaining)?;
        if event.event_kind() != Some(SysEventKind::MapChange) {
            return Some(event);
        }
    }
    None
}

#[test]
fn test_sysmon_lifecycle_private_namespace() -> Result<()> {
    // Run the same behavioral assertions with a private /proc and event namespace.
    // The BPF child task still carries host IDs, so confusing the two PID views
    // makes the fork assertion fail even if periodic discovery finds the child.
    let output = Command::new("unshare")
        .args(["--mount", "--pid", "--fork", "--mount-proc", "--kill-child"])
        .arg(std::env::current_exe()?)
        .args(["--exact", "test_sysmon_process_lifecycle", "--nocapture"])
        .output()?;
    ensure!(
        output.status.success(),
        "private namespace lifecycle test failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

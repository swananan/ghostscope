use super::*;
use std::io::Write;
use std::process::{Child, Command, Stdio};

struct Target(Child);

impl Target {
    fn spawn(path: &Path, args: &[&str]) -> anyhow::Result<Self> {
        let target = Self(
            Command::new(path)
                .args(args)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .spawn()?,
        );
        target.wait_for_module(path)?;
        Ok(target)
    }

    fn wait_for_module(&self, path: &Path) -> anyhow::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !pid_maps_target_module(self.0.id(), path) {
            anyhow::ensure!(
                Instant::now() < deadline,
                "target did not map {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn copy_program(source: &str, destination: &Path) -> anyhow::Result<()> {
    // Keep writable executable descriptors out of this multithreaded test process.
    anyhow::ensure!(
        Command::new("cp")
            .arg(source)
            .arg(destination)
            .status()?
            .success(),
        "copy fixture executable"
    );
    Ok(())
}

fn replay_map_change(mgr: &Arc<Mutex<ProcessManager>>, paths: &[PathBuf], pid: u32) {
    let resolver = |pid| pid;
    let (tx, _rx) = mpsc::sync_channel(16);
    let mut context = SysmonLoopContext {
        mgr,
        targets: paths
            .iter()
            .map(|path| SysmonTargetState {
                target: Some(path.clone()),
                pending: Arc::new(Mutex::new(PendingOffsets::new())),
                pending_map_refreshes: Arc::new(Mutex::new(PendingMapRefreshes::new())),
                last_module_refresh: Instant::now(),
                map_signatures: HashMap::new(),
            })
            .collect(),
        proc_pid_for_event: &resolver,
        proc_pid_for_map_change: &resolver,
        tx: &tx,
    };
    context.dispatch(
        &SysEvent {
            tgid: pid,
            host_tgid: pid,
            kind: SysEventKind::MapChange.as_u32(),
        },
        &resolver,
    );
    // Expire the debounce without sleeping, and keep periodic reconciliation
    // out of this assertion so it cannot repair an incorrect map-change purge.
    for state in &mut context.targets {
        state.last_module_refresh = Instant::now();
        for (&queued_pid, entry) in &mut state.pending_map_refreshes.lock().unwrap().entries {
            assert_eq!(
                queued_pid, pid,
                "redirected an event to an unrelated process"
            );
            entry.ready_at = Instant::now();
        }
    }
    let queue = Arc::new(Mutex::new(SysmonWorkQueue::new(
        16,
        16,
        MAP_CHANGE_DEBOUNCE_INTERVAL,
    )));
    service_sysmon_maintenance(&mut context, &queue).unwrap();
}

#[test]
fn map_changes_preserve_any_selected_module() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    // Coreutils applets may share one executable. Copy them to distinct files
    // so the selected modules have distinct identities, preserving each applet
    // name for implementations that dispatch on argv[0].
    let sleep = dir.path().join("sleep");
    let absent = dir.path().join("true");
    let other = dir.path().join("false");
    copy_program("/bin/sleep", &sleep)?;
    copy_program("/bin/true", &absent)?;
    copy_program("/bin/false", &other)?;
    let target = Target::spawn(&sleep, &["60"])?;
    let pid = target.0.id();
    let mgr = Arc::new(Mutex::new(ProcessManager::new()));
    for paths in [
        vec![sleep.clone(), absent.clone()],
        vec![absent.clone(), sleep.clone()],
    ] {
        mgr.lock().unwrap().ensure_prefill_pid(pid)?;
        replay_map_change(&mgr, &paths, pid);
        assert!(
            mgr.lock()
                .unwrap()
                .cached_offsets_with_paths_for_pid(pid)
                .is_some(),
            "an absent module erased a still-selected process"
        );
    }

    // A stale cache with no remaining selected module must still be removed.
    replay_map_change(&mgr, &[absent, other], pid);
    assert!(mgr
        .lock()
        .unwrap()
        .cached_offsets_with_paths_for_pid(pid)
        .is_none());
    Ok(())
}

#[test]
fn map_changes_refresh_remaining_module_after_exec() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let sleep = dir.path().join("sleep");
    copy_program("/bin/sleep", &sleep)?;
    let shell = std::fs::canonicalize("/bin/sh")?;
    let mut target = Target::spawn(
        &shell,
        &[
            "-c",
            "read -r line; exec \"$1\" 60",
            "fixture",
            sleep.to_str().unwrap(),
        ],
    )?;
    let pid = target.0.id();
    let mgr = Arc::new(Mutex::new(ProcessManager::new()));
    mgr.lock().unwrap().ensure_prefill_pid(pid)?;
    assert!(mgr
        .lock()
        .unwrap()
        .cached_offsets_with_paths_for_pid(pid)
        .unwrap()
        .iter()
        .any(|entry| Path::new(&entry.module_path) == shell));

    target.0.stdin.as_mut().unwrap().write_all(b"go\n")?;
    target.wait_for_module(&sleep)?;
    replay_map_change(&mgr, &[sleep.clone(), shell.clone()], pid);
    let guard = mgr.lock().unwrap();
    let entries = guard
        .cached_offsets_with_paths_for_pid(pid)
        .expect("remaining module lost");
    assert!(entries
        .iter()
        .any(|entry| Path::new(&entry.module_path) == sleep));
    assert!(
        !entries
            .iter()
            .any(|entry| Path::new(&entry.module_path) == shell),
        "stale module retained after exec"
    );
    Ok(())
}

#[test]
fn map_changes_do_not_redirect_between_selected_processes() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let sleep = dir.path().join("sleep");
    let cat = dir.path().join("cat");
    copy_program("/bin/sleep", &sleep)?;
    copy_program("/bin/cat", &cat)?;
    let primary = Target::spawn(&sleep, &["60"])?;
    let secondary = Target::spawn(&cat, &[])?;
    let mgr = Arc::new(Mutex::new(ProcessManager::new()));
    {
        let mut guard = mgr.lock().unwrap();
        guard.ensure_prefill_pid(primary.0.id())?;
        guard.ensure_prefill_pid(secondary.0.id())?;
        guard.ensure_prefill_module(cat.to_str().unwrap())?;
    }
    replay_map_change(&mgr, &[sleep, cat], primary.0.id());
    let guard = mgr.lock().unwrap();
    assert_eq!(
        guard.resolve_runtime_proc_pid(primary.0.id()),
        None,
        "host PID must not be aliased to another selected process"
    );
    assert!(guard
        .cached_offsets_with_paths_for_pid(primary.0.id())
        .is_some());
    assert!(guard
        .cached_offsets_with_paths_for_pid(secondary.0.id())
        .is_some());
    Ok(())
}

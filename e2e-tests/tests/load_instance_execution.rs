mod common;

use anyhow::{ensure, Context, Result};
use common::runner::GhostscopeRunner;
use common::targets::{TargetHandle, TargetLauncher};
use std::path::Path;
use std::time::Duration;

const SCRIPT: &str =
    r#"trace instance_tick { print "INSTANCE {}:{}", expected, instance_marker; }"#;

async fn wait_for_instances(directory: &Path, count: u32) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            if std::fs::read_to_string(directory.join("instance.ready"))
                .is_ok_and(|value| value.trim() == count.to_string())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("target did not finish loading its instances")?;
    Ok(())
}

async fn spawn_instances(
    initial_count: u32,
    copy_image: bool,
    read_only_copy: bool,
) -> Result<(tempfile::TempDir, TargetHandle)> {
    let fixture = common::FIXTURES.get_test_binary("backtrace_dlopen_program")?;
    let base = fixture.parent().context("fixture has no parent")?;
    // Keep each test's ELF inode and trigger files independent, inside the shared
    // workspace mount so this also exercises host-to-private-container tracing.
    let directory = tempfile::Builder::new()
        .prefix(".load-instances-")
        .tempdir_in(base)?;
    std::fs::copy(
        base.join("libload_instance.so"),
        directory.path().join("libload_instance.so"),
    )?;
    if copy_image {
        std::fs::copy(
            directory.path().join("libload_instance.so"),
            directory.path().join("libload_instance_copy.so"),
        )?;
        std::fs::write(directory.path().join("instance.copy"), "")?;
    }
    if initial_count == 2 {
        std::fs::write(directory.path().join("instance.trigger"), "")?;
    }
    if read_only_copy {
        std::fs::write(directory.path().join("instance.readonly"), "")?;
    }
    let target = TargetLauncher::binary(base.join("load_instance_program"))
        .current_dir(directory.path())
        .spawn()
        .await?;
    if let Err(error) = wait_for_instances(directory.path(), initial_count).await {
        target.terminate().await?;
        return Err(error);
    }
    Ok((directory, target))
}

async fn rejects_initial_instances(target_mode: bool, copy_image: bool) -> Result<()> {
    common::init();
    let (directory, target) = spawn_instances(2, copy_image, false).await?;
    let runner = GhostscopeRunner::new().with_script(SCRIPT);
    let runner = if target_mode {
        runner.with_target(directory.path().join("libload_instance.so"))
    } else {
        runner.attach_to(&target)
    };
    let result = runner.run().await;
    target.terminate().await?;
    let (code, stdout, stderr) = result?;
    ensure!(
        code != 0,
        "ambiguous instances were accepted: {stdout}\n{stderr}"
    );
    ensure!(
        stderr.contains("multiple load instances are not supported"),
        "{stderr}"
    );
    ensure!(
        !stdout.contains("INSTANCE "),
        "printed a value from an ambiguous instance: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_pid_rejects_multiple_load_instances() -> Result<()> {
    rejects_initial_instances(false, false).await
}

#[tokio::test]
async fn test_target_rejects_multiple_load_instances() -> Result<()> {
    rejects_initial_instances(true, false).await
}

#[tokio::test]
async fn test_pid_rejects_different_files_with_the_same_module_cookie() -> Result<()> {
    rejects_initial_instances(false, true).await
}

#[tokio::test]
async fn test_target_rejects_different_files_with_the_same_module_cookie() -> Result<()> {
    rejects_initial_instances(true, true).await
}

#[derive(Clone, Copy)]
enum LateInstanceMode {
    Pid,
    Target,
    FrozenTarget,
}

async fn exercise_late_instance(mode: LateInstanceMode, read_only_copy: bool) -> Result<()> {
    if !matches!(mode, LateInstanceMode::Pid) && common::skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }
    common::init();
    let (directory, target) = spawn_instances(1, false, read_only_copy).await?;
    let trigger_directory = directory.path().to_path_buf();
    let proc_pid = target.host_pid();
    let mut manager = ghostscope_process::ProcessManager::new();
    manager.ensure_prefill_pid(proc_pid)?;
    ensure!(manager
        .cached_offsets_with_paths_for_pid(proc_pid)
        .is_some());
    let cached_range = manager
        .cached_offsets_with_paths_for_pid(proc_pid)
        .unwrap()
        .iter()
        .find(|entry| entry.module_path.ends_with("/libload_instance.so"))
        .map(|entry| (entry.base, entry.size))
        .context("missing initial library offsets")?;
    let runner = GhostscopeRunner::new().with_script(SCRIPT).timeout_secs(3);
    let runner = match mode {
        LateInstanceMode::Pid => runner.attach_to(&target),
        LateInstanceMode::Target => {
            runner.with_target(directory.path().join("libload_instance.so"))
        }
        // Leave initial offsets cached to exercise the eBPF guard independently
        // of userspace observing the second load.
        LateInstanceMode::FrozenTarget => runner
            .with_target(directory.path().join("libload_instance.so"))
            .disable_sysmon_for_target(true),
    };
    let result = runner
        .run_after_ready(move || async move {
            tokio::time::sleep(Duration::from_millis(250)).await;
            std::fs::write(trigger_directory.join("instance.trigger"), "")?;
            wait_for_instances(&trigger_directory, 2).await?;
            if read_only_copy {
                let second_pc: u64 =
                    std::fs::read_to_string(trigger_directory.join("instance.second_pc"))?
                        .trim()
                        .parse()?;
                ensure!(
                    second_pc >= cached_range.0 && second_pc - cached_range.0 < cached_range.1,
                    "fixture must place the second probe inside the old broad mapping range"
                );
            }
            let error = manager.refresh_prefill_pid(proc_pid).unwrap_err();
            ensure!(
                error.is::<ghostscope_process::MultipleLoadInstances>(),
                "{error}"
            );
            ensure!(
                manager
                    .cached_offsets_with_paths_for_pid(proc_pid)
                    .is_none(),
                "refresh retained offsets for the previous single instance"
            );
            Ok(())
        })
        .await;
    target.terminate().await?;
    let (code, stdout, stderr, ()) = result?;
    ensure!(code == 0, "{stdout}\n{stderr}");
    ensure!(
        stdout.contains("INSTANCE 11:11"),
        "missing initial instance: {stdout}\n{stderr}"
    );
    ensure!(
        stdout.contains("INSTANCE 22:<proc offsets unavailable>"),
        "new instance used cached offsets: {stdout}\n{stderr}"
    );
    ensure!(
        !stdout.contains("INSTANCE 22:11") && !stdout.contains("INSTANCE 11:22"),
        "read another instance's global: {stdout}\n{stderr}"
    );
    if matches!(mode, LateInstanceMode::Target) {
        ensure!(
            stdout.contains("INSTANCE 11:<proc offsets unavailable>"),
            "periodic target refresh retained the old published offsets: {stdout}\n{stderr}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_late_load_instance_never_reads_the_other_instance() -> Result<()> {
    exercise_late_instance(LateInstanceMode::Pid, false).await
}

#[tokio::test]
async fn test_late_load_instance_rejects_stale_offsets_without_sysmon() -> Result<()> {
    exercise_late_instance(LateInstanceMode::FrozenTarget, false).await
}

#[tokio::test]
async fn test_late_load_instance_rejects_offsets_with_read_only_elf_mapping() -> Result<()> {
    exercise_late_instance(LateInstanceMode::FrozenTarget, true).await
}

#[tokio::test]
async fn test_late_load_instance_invalidates_offsets_during_target_refresh() -> Result<()> {
    exercise_late_instance(LateInstanceMode::Target, false).await
}

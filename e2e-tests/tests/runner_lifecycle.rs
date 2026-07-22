mod common;

use anyhow::Context;
use common::runner::GhostscopeRunner;
use common::sandbox::SandboxHandle;
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use tempfile::tempdir;
use tokio::time::{timeout, Instant};

#[tokio::test]
async fn startup_timeout_does_not_wait_for_inherited_output_pipes() -> anyhow::Result<()> {
    let temp_dir = tempdir()?;
    let fake_ghostscope = temp_dir.path().join("fake-ghostscope");
    fs::write(
        &fake_ghostscope,
        "#!/bin/bash\ntrap '' TERM\nsleep 10 &\nwait\n",
    )?;
    let mut permissions = fs::metadata(&fake_ghostscope)?.permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&fake_ghostscope, permissions)?;

    let previous_bin = env::var_os("GHOSTSCOPE_TEST_BIN");
    env::set_var("GHOSTSCOPE_TEST_BIN", &fake_ghostscope);
    let _restore_bin = scopeguard::guard(previous_bin, |previous_bin| {
        if let Some(previous_bin) = previous_bin {
            env::set_var("GHOSTSCOPE_TEST_BIN", previous_bin);
        } else {
            env::remove_var("GHOSTSCOPE_TEST_BIN");
        }
    });

    let sandbox = SandboxHandle::host();
    let started = Instant::now();
    let result = timeout(
        Duration::from_secs(8),
        GhostscopeRunner::new()
            .with_script("trace unused {}")
            .with_pid(std::process::id())
            .in_sandbox(&sandbox)
            .startup_timeout_secs(1)
            .run(),
    )
    .await
    .context("runner hung while cleaning up a startup timeout")?;

    let error = result.expect_err("fake GhostScope should time out before its ready marker");
    assert!(
        error
            .to_string()
            .contains("timed out waiting for ready marker"),
        "unexpected startup timeout error: {error:#}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "startup timeout cleanup exceeded its bounded deadline"
    );

    Ok(())
}

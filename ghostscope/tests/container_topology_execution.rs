mod common;

use common::init;
use common::runner::GhostscopeRunner;
use common::sandbox::{DockerSpec, SandboxHandle};
use common::targets::{TargetHandle, TargetLauncher};
use serial_test::serial;

fn pid_filter_script() -> &'static str {
    r#"
trace calculate_something {
    print "FILTERED: a={} b={}", a, b;
}
"#
}

fn skip_if_docker_unavailable() -> bool {
    if SandboxHandle::docker_available() {
        false
    } else {
        eprintln!("skipping docker-backed pid namespace test: docker is unavailable");
        true
    }
}

fn docker_sandbox_or_skip(spec: DockerSpec) -> anyhow::Result<Option<SandboxHandle>> {
    match SandboxHandle::docker(spec) {
        Ok(sandbox) => Ok(Some(sandbox)),
        Err(err) => {
            eprintln!("skipping docker-backed pid namespace test: {err:#}");
            Ok(None)
        }
    }
}

fn target_diagnostics(target: &TargetHandle) -> String {
    let host_exe = std::fs::read_link(format!("/proc/{}/exe", target.host_pid()))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|err| format!("<failed to read host exe: {err}>"));
    let host_maps = std::fs::read_to_string(format!("/proc/{}/maps", target.host_pid()))
        .map(|maps| {
            maps.lines()
                .filter(|line| line.contains("sample_program"))
                .take(5)
                .collect::<Vec<_>>()
                .join(" | ")
        })
        .unwrap_or_else(|err| format!("<failed to read host maps: {err}>"));
    let sandbox_exe = target
        .sandbox()
        .run_shell(&format!("readlink -f /proc/{}/exe", target.sandbox_pid()))
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|err| format!("<failed to read sandbox exe: {err}>"));

    format!(
        "sandbox={} sandbox_pid={} host_pid={} container_pid={:?} nspid_chain={:?} host_exe={} sandbox_exe={} host_maps={}",
        target.sandbox().label(),
        target.sandbox_pid(),
        target.host_pid(),
        target.container_pid(),
        target.nspid_chain(),
        host_exe,
        sandbox_exe,
        host_maps
    )
}

#[tokio::test]
#[serial]
async fn test_attach_from_host_to_private_container_target() -> anyhow::Result<()> {
    init();
    if skip_if_docker_unavailable() {
        return Ok(());
    }

    let host = SandboxHandle::host();
    let Some(private_box) = docker_sandbox_or_skip(DockerSpec::private())? else {
        return Ok(());
    };
    let target = TargetLauncher::sample_program()
        .in_sandbox(&private_box)
        .spawn()
        .await?;

    let result = GhostscopeRunner::new()
        .in_sandbox(&host)
        .with_script(pid_filter_script())
        .attach_to(&target)
        .timeout_secs(5)
        .run()
        .await;
    let diagnostics = target_diagnostics(&target);
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    assert_eq!(
        exit_code, 0,
        "stderr={stderr} stdout={stdout} diagnostics={diagnostics}"
    );
    assert!(
        stdout.contains("FILTERED:"),
        "expected trace output for host -> private container attach. stdout={stdout} stderr={stderr} diagnostics={diagnostics}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_attach_from_host_pid_container_to_host_target() -> anyhow::Result<()> {
    init();
    if skip_if_docker_unavailable() {
        return Ok(());
    }

    let host = SandboxHandle::host();
    let target = TargetLauncher::sample_program()
        .in_sandbox(&host)
        .spawn()
        .await?;
    let Some(host_pid_box) = docker_sandbox_or_skip(DockerSpec::host_pid())? else {
        return Ok(());
    };

    let result = GhostscopeRunner::new()
        .in_sandbox(&host_pid_box)
        .with_script(pid_filter_script())
        .attach_to(&target)
        .timeout_secs(5)
        .run()
        .await;
    let diagnostics = target_diagnostics(&target);
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    assert_eq!(
        exit_code, 0,
        "stderr={stderr} stdout={stdout} diagnostics={diagnostics}"
    );
    assert!(
        stdout.contains("FILTERED:"),
        "expected trace output for host-pid container -> host attach. stdout={stdout} stderr={stderr} diagnostics={diagnostics}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_attach_from_private_container_to_host_target_fails_when_pid_invisible(
) -> anyhow::Result<()> {
    init();
    if skip_if_docker_unavailable() {
        return Ok(());
    }

    let host = SandboxHandle::host();
    let target = TargetLauncher::sample_program()
        .in_sandbox(&host)
        .spawn()
        .await?;
    let Some(private_box) = docker_sandbox_or_skip(DockerSpec::private())? else {
        return Ok(());
    };

    let result = GhostscopeRunner::new()
        .in_sandbox(&private_box)
        .with_script(pid_filter_script())
        .attach_to(&target)
        .timeout_secs(5)
        .run()
        .await;
    target.terminate().await?;

    let err = result.expect_err("private container observer should not resolve a host target PID");
    let message = format!("{err:#}");
    assert!(
        message.contains("not visible"),
        "expected not-visible error when private container tries to observe host target: {message}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_attach_from_private_container_to_child_container_target() -> anyhow::Result<()> {
    init();
    if skip_if_docker_unavailable() {
        return Ok(());
    }

    let Some(private_box) = docker_sandbox_or_skip(DockerSpec::private())? else {
        return Ok(());
    };
    let target = TargetLauncher::sample_program()
        .in_child_container_of(&private_box)
        .spawn()
        .await?;

    assert_ne!(
        target.container_pid(),
        Some(target.sandbox_pid()),
        "child-container target should expose a distinct innermost pid"
    );

    let result = GhostscopeRunner::new()
        .in_sandbox(&private_box)
        .with_script(pid_filter_script())
        .attach_to(&target)
        .timeout_secs(5)
        .run()
        .await;
    let diagnostics = target_diagnostics(&target);
    target.terminate().await?;

    let (exit_code, stdout, stderr) = result?;
    assert_eq!(
        exit_code, 0,
        "stderr={stderr} stdout={stdout} diagnostics={diagnostics}"
    );
    assert!(
        stdout.contains("FILTERED:"),
        "expected trace output for private container -> child container attach. stdout={stdout} stderr={stderr} diagnostics={diagnostics}"
    );
    Ok(())
}

mod common;

use anyhow::Context;
use common::init;
use common::runner::GhostscopeRunner;
use common::sandbox::{DockerSpec, SandboxHandle};
use common::targets::{TargetHandle, TargetLauncher};
use serial_test::serial;
use std::{fs, path::Path};

const ENV_RUN_CONTAINER_TOPOLOGY: &str = "E2E_RUN_CONTAINER_TOPOLOGY";
const ENV_GHOSTSCOPE_SANDBOX: &str = "E2E_GHOSTSCOPE_SANDBOX";
const ENV_TARGET_SANDBOX: &str = "E2E_TARGET_SANDBOX";
const ENV_TARGET_MODE: &str = "E2E_TARGET_MODE";

fn pid_filter_script() -> &'static str {
    r#"
trace calculate_something {
    print "FILTERED: a={} b={}", a, b;
}
"#
}

fn env_flag_enabled(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn env_value_is_container_sandbox(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "docker-private"
                | "private"
                | "container-private"
                | "docker-host"
                | "host-pid"
                | "docker-host-pid"
                | "container-host"
        )
    })
}

fn explicit_container_topology_requested() -> bool {
    env_flag_enabled(ENV_RUN_CONTAINER_TOPOLOGY)
        || env_value_is_container_sandbox(ENV_GHOSTSCOPE_SANDBOX)
        || env_value_is_container_sandbox(ENV_TARGET_SANDBOX)
        || std::env::var(ENV_TARGET_MODE).ok().is_some_and(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "child-container" | "child" | "nested" | "descendant"
            )
        })
}

fn skip_if_container_topology_not_requested() -> bool {
    if explicit_container_topology_requested() {
        false
    } else {
        eprintln!(
            "skipping explicit container-topology test: set {ENV_RUN_CONTAINER_TOPOLOGY}=1 \
             or run with docker-backed E2E_GHOSTSCOPE_SANDBOX/E2E_TARGET_SANDBOX"
        );
        true
    }
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
    if skip_if_container_topology_not_requested() {
        return Ok(());
    }
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
    if skip_if_container_topology_not_requested() {
        return Ok(());
    }
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
    if skip_if_container_topology_not_requested() {
        return Ok(());
    }
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
async fn test_child_container_runtime_reuses_single_nested_container() -> anyhow::Result<()> {
    init();
    if skip_if_container_topology_not_requested() {
        return Ok(());
    }
    if skip_if_docker_unavailable() {
        return Ok(());
    }

    let Some(private_box) = docker_sandbox_or_skip(DockerSpec::private())? else {
        return Ok(());
    };

    let target_one = TargetLauncher::sample_program()
        .in_child_container_of(&private_box)
        .spawn()
        .await?;
    let runtime_names_after_first = private_box
        .list_inner_docker_container_names_by_label("ghostscope.test-child-runtime=1")?;
    let child_target_names_after_first = private_box
        .list_inner_docker_container_names_by_label("ghostscope.test-child-container=1")?;
    assert_eq!(
        runtime_names_after_first.len(),
        1,
        "expected exactly one reusable child runtime container after first launch"
    );
    assert!(
        child_target_names_after_first.is_empty(),
        "expected child-container launch to avoid per-target docker run containers, found {child_target_names_after_first:?}"
    );
    let runtime_name = runtime_names_after_first[0].clone();
    target_one.terminate().await?;

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let target_two = TargetLauncher::sample_program()
        .in_child_container_of(&private_box)
        .spawn()
        .await?;
    let runtime_names_after_second = private_box
        .list_inner_docker_container_names_by_label("ghostscope.test-child-runtime=1")?;
    let child_target_names_after_second = private_box
        .list_inner_docker_container_names_by_label("ghostscope.test-child-container=1")?;
    assert_eq!(
        runtime_names_after_second,
        vec![runtime_name],
        "expected nested target launches to reuse the same child runtime container"
    );
    assert!(
        child_target_names_after_second.is_empty(),
        "expected nested target launches to avoid extra child docker containers, found {child_target_names_after_second:?}"
    );
    target_two.terminate().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn test_attach_from_private_container_to_child_container_target() -> anyhow::Result<()> {
    init();
    if skip_if_container_topology_not_requested() {
        return Ok(());
    }
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

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn nspid_chain(pid: u32) -> anyhow::Result<Vec<u32>> {
    fs::read_to_string(format!("/proc/{pid}/status"))?
        .lines()
        .find_map(|line| line.strip_prefix("NSpid:"))
        .context("missing NSpid")?
        .split_whitespace()
        .map(|value| value.parse().map_err(anyhow::Error::from))
        .collect()
}

#[tokio::test]
#[serial]
async fn test_host_pid_resolution_ignores_nested_namespace_pid_collisions() -> anyhow::Result<()> {
    common::init();
    let sandbox = SandboxHandle::default_target()?;
    if sandbox.is_host_pid_view() {
        eprintln!("skipping PID collision test: requires a private target PID namespace");
        return Ok(());
    }
    common::ensure_test_program_compiled_with_opt(common::OptimizationLevel::Debug)?;
    let fixture = common::TestFixtures::new().get_test_binary("sample_program")?;
    let dir = tempfile::Builder::new()
        .prefix("pid-collision-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?;
    let binary = dir.path().join("target");
    let collider = dir.path().join("collider");
    let ready = dir.path().join("ready");
    let error_log = dir.path().join("unshare.err");
    fs::copy(&fixture, &binary)?;
    fs::copy(&fixture, &collider)?;

    // Start the inner process first so its host PID sorts before the real
    // target in /proc. Give both processes the same PID in different namespaces.
    // All ns_last_pid writes are confined to these test-owned namespaces.
    let inner = format!(
        r#"set -e
        echo "$(( $1 - 1 ))" > /proc/sys/kernel/ns_last_pid
        {collider} >/dev/null 2>&1 & child=$!
        for i in {{1..100}}; do
            test /proc/$child/exe -ef {collider} && break
            sleep 0.02
        done
        test /proc/$child/exe -ef {collider}
        echo $child > {ready}
        wait $child"#,
        collider = quote(&collider.display().to_string()),
        ready = quote(&ready.display().to_string()),
    );
    let script = format!(
        r#"set -e
        wanted=30000
        while test -e /proc/$wanted; do wanted=$((wanted + 1)); done
        unshare --mount --pid --fork --mount-proc --kill-child=SIGKILL \
            bash -c {inner} -- "$wanted" >/dev/null 2>{error_log} & launcher=$!
        for i in {{1..100}}; do
            test -s {ready} && break
            sleep 0.02
        done
        test -s {ready} || {{ cat {error_log} >&2; exit 1; }}
        echo "$((wanted - 1))" > /proc/sys/kernel/ns_last_pid
        {binary} >/dev/null 2>&1 & target=$!
        for i in {{1..100}}; do
            test /proc/$target/exe -ef {binary} && break
            sleep 0.02
        done
        test /proc/$target/exe -ef {binary}
        echo $target $launcher $wanted"#,
        inner = quote(&inner),
        error_log = quote(&error_log.display().to_string()),
        ready = quote(&ready.display().to_string()),
        binary = quote(&binary.display().to_string()),
    );
    let launched = sandbox.run_shell(&script)?;
    anyhow::ensure!(
        launched.status.success(),
        "PID collision setup failed: {}",
        String::from_utf8_lossy(&launched.stderr)
    );
    let pids = String::from_utf8(launched.stdout)?;
    let mut pids = pids.split_whitespace();
    let target_pid: u32 = pids.next().context("missing target PID")?.parse()?;
    let launcher_pid: u32 = pids.next().context("missing launcher PID")?.parse()?;
    let wanted: u32 = pids.next().context("missing collision PID")?.parse()?;

    let result = async {
        anyhow::ensure!(target_pid == wanted, "failed to arrange collision: {target_pid} != {wanted}");
        let host_pid = sandbox.resolve_host_pid_for_sandbox_pid(target_pid)?;
        let chain = nspid_chain(host_pid)?;
        let exe = fs::read_link(format!("/proc/{host_pid}/exe"))?;
        let (code, stdout, stderr) = GhostscopeRunner::new()
            .in_sandbox(&SandboxHandle::host())
            .with_target(&binary)
            .with_pid(host_pid)
            .with_script("trace calculate_something { print \"COLLISION:a={}\", a; }")
            .timeout_secs(2)
            .run()
            .await?;
        assert_eq!(
            code, 0,
            "sandbox_pid={target_pid} host_pid={host_pid} exe={} NSpid={chain:?}\n{stderr}\n{stdout}",
            exe.display()
        );
        assert_eq!(exe, binary, "resolved a process from the wrong namespace");
        assert!(stdout.contains("COLLISION:a="), "{stderr}\n{stdout}");

        // Descendant lookup must still work when given the inner process's
        // actual PID as observed from the outer sandbox.
        let nested_host_pid = fs::read_dir("/proc")?
            .flatten()
            .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
            .find(|pid| {
                fs::read_link(format!("/proc/{pid}/exe")).ok().as_deref() == Some(collider.as_path())
            })
            .context("nested process was not found in host /proc")?;
        let nested_chain = nspid_chain(nested_host_pid)?;
        assert_eq!(nested_chain.last(), Some(&wanted), "{nested_chain:?}");
        assert!(nested_chain.len() > chain.len(), "{nested_chain:?}");
        let nested_sandbox_pid = nested_chain[chain.len() - 1];
        assert_ne!(nested_sandbox_pid, target_pid);
        assert_eq!(
            sandbox.resolve_host_pid_for_sandbox_pid(nested_sandbox_pid)?,
            nested_host_pid,
            "legitimate descendant PID mapping stopped working"
        );
        Ok::<_, anyhow::Error>(())
    }.await;
    let target_cleanup = sandbox.terminate_pid(target_pid);
    let launcher_cleanup = sandbox.terminate_pid(launcher_pid);
    target_cleanup?;
    launcher_cleanup?;
    result
}

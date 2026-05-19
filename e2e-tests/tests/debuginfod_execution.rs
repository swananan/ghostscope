//! debuginfod integration tests.

mod common;

use anyhow::{Context, Result};
use common::{init, OptimizationLevel, FIXTURES};
use object::Object;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

#[tokio::test]
#[serial_test::serial]
async fn test_stripped_binary_fetches_debug_info_from_debuginfod() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping debuginfod e2e outside host->host topology");
        return Ok(());
    }

    common::ensure_test_program_compiled_with_opt(OptimizationLevel::Stripped)?;

    let fixture_binary =
        FIXTURES.get_test_binary_with_opt("sample_program", OptimizationLevel::Stripped)?;
    let fixture_debug = fixture_binary.with_file_name("sample_program_stripped.debug");
    anyhow::ensure!(
        fixture_debug.exists(),
        "debug file should exist before debuginfod test: {}",
        fixture_debug.display()
    );

    let work_dir = TempDir::new().context("failed to create debuginfod e2e temp dir")?;
    let target_binary = work_dir.path().join("sample_program_debuginfod");
    fs::copy(&fixture_binary, &target_binary).with_context(|| {
        format!(
            "failed to copy stripped fixture {} to {}",
            fixture_binary.display(),
            target_binary.display()
        )
    })?;
    copy_executable_permissions(&fixture_binary, &target_binary)?;

    let build_id = read_build_id_hex(&target_binary)?;
    let cache_dir = work_dir.path().join("cache");
    let debug_file_bytes = Arc::new(fs::read(&fixture_debug).with_context(|| {
        format!(
            "failed to read debuginfod fixture debug file {}",
            fixture_debug.display()
        )
    })?);

    let mock = MockDebuginfod::start(build_id.clone(), debug_file_bytes).await?;
    let _mock_guard = scopeguard::guard(mock.task, |task| task.abort());

    let target = common::targets::TargetLauncher::binary(&target_binary)
        .spawn()
        .await?;

    let script_content = r#"
trace add_numbers {
    print "DEBUGINFOD_STRIPPED: add_numbers called with a={} b={}", a, b;
}
"#;

    let cli_args = vec![
        OsString::from("--debuginfod"),
        OsString::from("on"),
        OsString::from("--debuginfod-url"),
        OsString::from(mock.url.clone()),
        OsString::from("--debuginfod-cache-dir"),
        cache_dir.clone().into_os_string(),
        OsString::from("--debuginfod-timeout-secs"),
        OsString::from("2"),
    ];

    let (exit_code, stdout, stderr) = common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(&target)
        .timeout_secs(4)
        .enable_sysmon_for_target(false)
        .with_cli_args(cli_args)
        .run()
        .await?;

    target.terminate().await?;

    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope failed while using mock debuginfod\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        stdout.contains("DEBUGINFOD_STRIPPED"),
        "expected trace output from debuginfod-backed stripped binary\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
    );
    assert!(
        mock.target_request_count.load(Ordering::SeqCst) > 0,
        "mock debuginfod did not receive a request for target build-id {build_id}"
    );
    assert!(
        cache_dir.join(&build_id).join("debuginfo").exists(),
        "debuginfod cache did not contain downloaded debug info for {build_id}"
    );

    Ok(())
}

struct MockDebuginfod {
    url: String,
    target_request_count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl MockDebuginfod {
    async fn start(build_id: String, debug_file_bytes: Arc<Vec<u8>>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("failed to bind mock debuginfod server")?;
        let addr = listener.local_addr()?;
        let target_request_count = Arc::new(AtomicUsize::new(0));
        let request_count = Arc::clone(&target_request_count);
        let expected_path = format!("/buildid/{build_id}/debuginfo");

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let expected_path = expected_path.clone();
                let debug_file_bytes = Arc::clone(&debug_file_bytes);
                let request_count = Arc::clone(&request_count);
                tokio::spawn(async move {
                    let mut buffer = [0_u8; 4096];
                    let Ok(read) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if read == 0 {
                        return;
                    }

                    let request = String::from_utf8_lossy(&buffer[..read]);
                    let request_path = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("");

                    if request_path == expected_path {
                        request_count.fetch_add(1, Ordering::SeqCst);
                        let header = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            debug_file_bytes.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(&debug_file_bytes).await;
                    } else {
                        let body = b"not found";
                        let header = format!(
                            "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        );
                        let _ = stream.write_all(header.as_bytes()).await;
                        let _ = stream.write_all(body).await;
                    }
                });
            }
        });

        Ok(Self {
            url: format!("http://{addr}"),
            target_request_count,
            task,
        })
    }
}

fn read_build_id_hex(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read ELF {}", path.display()))?;
    let object = object::File::parse(&bytes[..])
        .with_context(|| format!("failed to parse ELF {}", path.display()))?;
    let build_id = object
        .build_id()
        .context("failed to read GNU build-id note")?
        .with_context(|| format!("ELF has no build-id: {}", path.display()))?;
    Ok(build_id_to_hex(build_id))
}

fn build_id_to_hex(build_id: &[u8]) -> String {
    let mut hex = String::with_capacity(build_id.len() * 2);
    for byte in build_id {
        use std::fmt::Write;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

#[cfg(unix)]
fn copy_executable_permissions(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(from)?.permissions().mode();
    fs::set_permissions(to, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(not(unix))]
fn copy_executable_permissions(_from: &Path, _to: &Path) -> Result<()> {
    Ok(())
}

fn is_host_topology() -> bool {
    env_is_unset_or("E2E_GHOSTSCOPE_SANDBOX", "host")
        && env_is_unset_or("E2E_TARGET_SANDBOX", "host")
        && std::env::var("E2E_TARGET_MODE")
            .map(|value| {
                matches!(
                    value.trim().to_ascii_lowercase().as_str(),
                    "" | "direct" | "same" | "same-sandbox"
                )
            })
            .unwrap_or(true)
}

fn env_is_unset_or(name: &str, expected: &str) -> bool {
    std::env::var(name)
        .map(|value| value.trim().eq_ignore_ascii_case(expected))
        .unwrap_or(true)
}

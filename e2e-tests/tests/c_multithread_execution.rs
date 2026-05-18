//! C multithreaded fixture execution tests

mod common;

use common::{init, FIXTURES};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

const TLS_WORKER_STRIDE: i64 = 100000;

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_shared_lib(false)
        .run()
        .await
}

async fn spawn_c_multithread_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("c_multithread_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[derive(Debug)]
struct MultithreadEvent {
    worker_id: i64,
    pid: i64,
    tid: i64,
    tls_snapshot: i64,
    tls_direct: i64,
}

fn parse_multithread_event(line: &str) -> Option<MultithreadEvent> {
    let payload = line.trim().strip_prefix("MT_EVENT:")?;
    let mut fields = payload.split(':');
    let event = MultithreadEvent {
        worker_id: fields.next()?.parse().ok()?,
        pid: fields.next()?.parse().ok()?,
        tid: fields.next()?.parse().ok()?,
        tls_snapshot: fields.next()?.parse().ok()?,
        tls_direct: fields.next()?.parse().ok()?,
    };

    fields.next().is_none().then_some(event)
}

#[tokio::test]
async fn test_c_multithread_tls_probe_reports_worker_threads() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("c_multithread_program")?;
    let target = spawn_c_multithread_program(&binary_path).await?;

    let script = r#"
trace c_multithread_program.c:23 {
    print "MT_EVENT:{}:{}:{}:{}:{}", worker_id, $pid, $tid, tls_snapshot, worker_tls_counter;
    if $tid != $pid { print "MT_WORKER_THREAD:{}:{}", worker_id, $tid; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 5, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let mut tids = HashSet::new();
    let mut pids = HashSet::new();
    let mut tls_values_by_worker: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut event_count = 0usize;

    for event in stdout.lines().filter_map(parse_multithread_event) {
        event_count += 1;
        tids.insert(event.tid);
        pids.insert(event.pid);
        tls_values_by_worker
            .entry(event.worker_id)
            .or_default()
            .push(event.tls_snapshot);

        assert_ne!(
            event.tid, event.pid,
            "worker trace should run on a pthread TID. STDOUT: {stdout}"
        );
        assert_eq!(
            event.tls_snapshot / TLS_WORKER_STRIDE,
            event.worker_id,
            "TLS snapshot should stay in the worker's thread-local range. STDOUT: {stdout}"
        );
        assert_eq!(
            event.tls_direct, event.tls_snapshot,
            "Direct TLS variable read should match the C-side snapshot. STDOUT: {stdout}"
        );
    }

    assert!(
        event_count >= 2,
        "Expected multiple multithread probe events. STDOUT: {stdout}"
    );
    assert!(
        tls_values_by_worker.len() >= 2,
        "Expected traces from at least two C worker threads. STDOUT: {stdout}"
    );
    assert!(
        tids.len() >= 2,
        "Expected at least two distinct worker TIDs. STDOUT: {stdout}"
    );
    assert_eq!(
        pids.len(),
        1,
        "All worker threads should report one process PID. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("MT_WORKER_THREAD"),
        "Expected worker-thread markers. STDOUT: {stdout}"
    );

    Ok(())
}

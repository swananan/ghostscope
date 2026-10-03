//! JSONL must remain parseable on real CLI stdout, including readiness/status.

mod common;

use anyhow::{ensure, Result};
use common::{runner::GhostscopeRunner, targets::TargetLauncher, FIXTURES};
use serde_json::Value;

#[tokio::test]
async fn test_jsonl_events_preserve_metadata_values_and_backtrace() -> Result<()> {
    common::init();
    let binary = FIXTURES.get_test_binary("backtrace_hot_program")?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(
            r#"trace hot_bt_probe {
            print "JSONL 中文";
            print value;
            bt;
        }"#,
        )
        .with_config_content("[script]\ncolor = 'always'\n")
        .with_cli_args([
            "--script-output",
            "jsonl",
            "--backtrace-depth",
            "1",
            "--debuginfod",
            "off",
        ])
        .timeout_secs(3)
        .run_after_ready(|| async { Ok(()) })
        .await;
    target.terminate().await?;
    let (code, stdout, stderr, ()) = result?;
    ensure!(code == 0, "stdout={stdout}\nstderr={stderr}");
    ensure!(!stdout.is_empty(), "no JSONL events: {stderr}");
    ensure!(
        stderr.contains("__GHOSTSCOPE_READY__"),
        "ready marker must use stderr"
    );
    ensure!(!stdout.contains('\u{1b}'), "ANSI color leaked into JSONL");
    for line in stdout.lines() {
        let event: Value = serde_json::from_str(line)?;
        ensure!(
            event["schema_version"] == 1 && event["event"] == "trace",
            "{event}"
        );
        ensure!(event["pid"].as_u64().is_some_and(|pid| pid > 0), "{event}");
        ensure!(event["tid"].as_u64().is_some_and(|tid| tid > 0), "{event}");
        ensure!(
            event["timestamp_ns"].as_u64().is_some_and(|ts| ts > 0),
            "{event}"
        );
        ensure!(event["trace_id"].is_u64(), "{event}");
        ensure!(
            event["trace"]["target"]
                .as_str()
                .is_some_and(|s| s.contains("hot_bt_probe")),
            "{event}"
        );
        ensure!(event["trace"]["binary_path"].is_string(), "{event}");
        ensure!(event["value_diagnostics"].is_array(), "{event}");
        let items = event["items"].as_array().unwrap();
        ensure!(
            items.iter().any(|item| item["content"] == "JSONL 中文"),
            "{event}"
        );
        ensure!(
            items
                .iter()
                .any(|item| item["kind"] == "complex_variable" && item["name"] == "value"),
            "{event}"
        );
        let backtrace = items
            .iter()
            .find(|item| item["kind"] == "backtrace")
            .unwrap();
        ensure!(backtrace["requested_depth"] == 1, "{event}");
        ensure!(
            backtrace["status"] == "truncated" && backtrace["status_code"] == 1,
            "{event}"
        );
        ensure!(
            backtrace["error_code"] == 0 && backtrace["error_reason"].is_null(),
            "{event}"
        );
        ensure!(backtrace["physical_frame_count"] == 1, "{event}");
        ensure!(
            backtrace["frames"]
                .as_array()
                .is_some_and(|frames| !frames.is_empty()),
            "{event}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_jsonl_runtime_expression_errors_are_structured() -> Result<()> {
    common::init();
    let binary = FIXTURES.get_test_binary("globals_program")?;
    let target = TargetLauncher::binary(&binary)
        .current_dir(binary.parent().unwrap())
        .spawn()
        .await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(
            r#"trace tick_once {
            if memcmp(G_STATE.lib, hex("00"), 1) { print "THEN"; } else { print "ELSE"; }
            print "AFTER";
        }"#,
        )
        .with_cli_args([
            "--script-output",
            "jsonl",
            "--no-status",
            "--debuginfod",
            "off",
        ])
        .force_perf_event_array(true)
        .timeout_secs(3)
        .run()
        .await;
    target.terminate().await?;
    let (code, stdout, stderr) = result?;
    ensure!(code == 0, "stdout={stdout}\nstderr={stderr}");
    let mut saw_error = false;
    for line in stdout.lines() {
        let event: Value = serde_json::from_str(line)?;
        let items = event["items"].as_array().unwrap();
        for error in items.iter().filter(|item| item["kind"] == "expr_error") {
            saw_error = true;
            ensure!(
                error["expr"]
                    .as_str()
                    .is_some_and(|expr| expr.contains("memcmp(")),
                "{event}"
            );
            ensure!(
                error["error_code"].as_u64().is_some_and(|code| code > 0),
                "{event}"
            );
            ensure!(
                error["flags"].is_u64() && error["failing_addr"].is_u64(),
                "{event}"
            );
            ensure!(
                items.iter().any(|item| item["content"] == "AFTER"),
                "{event}"
            );
            ensure!(
                !items
                    .iter()
                    .any(|item| item["content"] == "THEN" || item["content"] == "ELSE"),
                "{event}"
            );
        }
    }
    ensure!(
        saw_error,
        "no runtime expression errors: stdout={stdout}\nstderr={stderr}"
    );
    Ok(())
}

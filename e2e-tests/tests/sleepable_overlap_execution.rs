//! Stress sleepable event/tail state on one CPU with fresh page faults and tasks.
mod common;

use anyhow::{ensure, Result};
use common::{runner::GhostscopeRunner, targets::TargetLauncher};
use serde_json::Value;
use std::{collections::HashSet, path::PathBuf, time::Duration};

#[tokio::test]
async fn test_sleepable_invocations_isolate_events_and_tail_state() -> Result<()> {
    run_comparison_scratch_test(true).await
}

#[tokio::test]
async fn test_comparison_scratch_handles_large_and_combined_buffers() -> Result<()> {
    run_comparison_scratch_test(false).await
}

async fn run_comparison_scratch_test(sleepable: bool) -> Result<()> {
    common::init();
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sleepable_overlap_program");
    if std::env::var_os("GHOSTSCOPE_PRESERVE_PRECOMPILED_FIXTURES").is_none() {
        let output = std::process::Command::new("make")
            .arg("all")
            .current_dir(&directory)
            .output()?;
        ensure!(
            output.status.success(),
            "fixture build: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let target = TargetLauncher::binary(directory.join("sleepable_overlap_program"))
        .spawn()
        .await?;
    let status_path = format!("/tmp/ghostscope-overlap-{}.status", target.sandbox_pid());
    let read_status = || -> Result<String> {
        let output = target
            .sandbox()
            .run_shell(&format!("cat {status_path} 2>/dev/null"))?;
        Ok(String::from_utf8(output.stdout)?.trim().to_owned())
    };
    let result = async {
        let mut status = String::new();
        for _ in 0..100 {
            status = read_status()?;
            if !status.is_empty() { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        ensure!(status == "READY", "fixture not ready: {status}");
        let script = r#"
trace overlap_probe {
    if memcmp(a, b, 512) { } else { print "BAD_MEMCMP"; }
    if a == "LONG_LITERAL" { } else { print "BAD_STRING"; }
    if strncmp(a, "xxxx", 4) { } else { print "BAD_STRNCMP"; }
    print "OWNER:{}:{}", owner, iteration;
    bt;
    print "VALUE:{}", page.value;
    print "END:{}:{}", owner, iteration;
}
"#.replace("LONG_LITERAL", &"x".repeat(600));
        let mut args = vec!["--backtrace-depth", "12", "--script-output", "jsonl", "--script-output-events-per-sec", "0", "--debuginfod", "off"];
        if sleepable { args.push("--sleepable-uprobe"); }
        let (code, stdout, stderr, ()) = GhostscopeRunner::new()
            .attach_to(&target)
            .enable_sysmon_for_target(false)
            .with_script(&script)
            .with_config_content("[ebpf]\nringbuf_size = 4194304\ncompare_cap = 512\n")
            .with_cli_args(args)
            .startup_timeout_secs(60)
            .timeout_secs(12)
            .run_after_ready(|| async {
                let output = target.sandbox().run_shell(&format!("kill -USR1 {}", target.sandbox_pid()))?;
                ensure!(output.status.success(), "could not start fixture");
                Ok(())
            }).await?;
        ensure!(code == 0, "stdout={stdout}\nstderr={stderr}");
        ensure!(read_status()? == "DONE 140", "fixture did not complete: {}\n{stderr}", read_status()?);
        let mut seen = HashSet::new();
        let mut tids = HashSet::new();
        for line in stdout.lines() {
            let event: Value = serde_json::from_str(line)?;
            let items = event["items"].as_array().ok_or_else(|| anyhow::anyhow!("missing items: {event}"))?;
            let texts: Vec<_> = items.iter().filter_map(|i| i["content"].as_str()).collect();
            ensure!(texts.len() == 3, "mixed or missing event content: {event}");
            let fields: Vec<_> = texts[0].split(':').collect();
            ensure!(fields.len() == 3 && fields[0] == "OWNER", "{event}");
            let owner: u32 = fields[1].parse()?;
            let iteration: u32 = fields[2].parse()?;
            ensure!(matches!(owner, 101 | 202) && iteration < 140, "{event}");
            ensure!((texts[1] == format!("VALUE:{}", if owner == 101 { 0 } else { 202 }) || (!sleepable && owner == 101 && texts[1].contains("unreadable"))) && texts[2] == format!("END:{owner}:{iteration}"), "cross-invocation event corruption: {event}");
            ensure!(seen.insert((owner, iteration)), "duplicate event: {event}");
            ensure!(tids.insert(event["tid"].as_u64().ok_or_else(|| anyhow::anyhow!("missing tid"))?), "header reused from another invocation: {event}");
            let backtraces: Vec<_> = items.iter().filter(|i| i["kind"] == "backtrace").collect();
            ensure!(backtraces.len() == 1, "missing backtrace: {event}");
            for bt in backtraces {
                ensure!(bt["error_code"] == 0, "backtrace failed: {event}");
                // Kernels without sleepable tail calls intentionally use five
                // inline frames. On supported kernels, check the owner beyond
                // the inline prefix in the deferred backtrace state.
                if bt["requested_depth"].as_u64().unwrap_or(0) > 5 {
                    let expected = if owner == 101 { "overlap_owner_a" } else { "overlap_owner_b" };
                    let frames = bt["frames"].as_array().unwrap();
                    ensure!(frames.iter().any(|f| f["function"].as_str().is_some_and(|s| s.contains(expected))), "tail state belongs to another invocation: {event}");
                }
            }
        }
        ensure!(seen.len() == 280, "missing events / leaked invocation entries: got {} of 280\nstdout={stdout}\nstderr={stderr}", seen.len());
        Ok(())
    }.await;
    target.terminate().await?;
    let _ = target.sandbox().run_shell(&format!("rm -f {status_path}"));
    result
}

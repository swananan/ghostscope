use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_NAME: &str = "manual_runtime_performance_baseline";

#[test]
fn manual_runtime_performance_baseline() {
    // Standard e2e discovers this test too. Performance measurement needs an
    // explicit filter and an otherwise idle host, rather than concurrent e2e.
    if !std::env::args().any(|arg| arg == TEST_NAME) {
        eprintln!("skipping {TEST_NAME}; explicitly select this test to measure performance");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("e2e crate should live under repo root")
        .to_path_buf();
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis();
    let mut cmd = Command::new("python3");
    cmd.arg(repo_root.join("scripts/runtime-perf/runtime_perf.py"));

    for (env_name, arg_name, extension) in [
        (
            "GHOSTSCOPE_RUNTIME_BENCH_OUTPUT_JSON",
            "--output-json",
            "json",
        ),
        (
            "GHOSTSCOPE_RUNTIME_BENCH_OUTPUT_MARKDOWN",
            "--output-markdown",
            "md",
        ),
    ] {
        let path = std::env::var_os(env_name).map_or_else(
            || {
                PathBuf::from(format!(
                    "/tmp/ghostscope_runtime_perf_{stamp}_{}.{extension}",
                    std::process::id()
                ))
            },
            PathBuf::from,
        );
        cmd.arg(arg_name).arg(path);
    }

    for (env_name, arg_name) in [
        ("GHOSTSCOPE_RUNTIME_BENCH_BIN", "--ghostscope-bin"),
        ("GHOSTSCOPE_RUNTIME_BENCH_BASE_BIN", "--base-bin"),
        ("GHOSTSCOPE_RUNTIME_BENCH_PROFILE", "--build-profile"),
        ("GHOSTSCOPE_RUNTIME_BENCH_ITERATIONS", "--iterations"),
        ("GHOSTSCOPE_RUNTIME_BENCH_INNER_WORK", "--inner-work"),
        ("GHOSTSCOPE_RUNTIME_BENCH_REPETITIONS", "--repetitions"),
        ("GHOSTSCOPE_RUNTIME_BENCH_WARMUPS", "--warmups"),
        ("GHOSTSCOPE_RUNTIME_BENCH_TARGET_CPU", "--target-cpu"),
        ("GHOSTSCOPE_RUNTIME_BENCH_OBSERVER_CPU", "--observer-cpu"),
        (
            "GHOSTSCOPE_RUNTIME_BENCH_MAX_SLOWDOWN_PCT",
            "--max-slowdown-regression-pct",
        ),
        (
            "GHOSTSCOPE_RUNTIME_BENCH_MAX_RSS_PCT",
            "--max-rss-regression-pct",
        ),
        (
            "GHOSTSCOPE_RUNTIME_BENCH_MAX_LOSS_PP",
            "--max-loss-increase-pp",
        ),
    ] {
        if let Some(value) = std::env::var_os(env_name) {
            cmd.arg(arg_name).arg(value);
        }
    }
    if std::env::var("GHOSTSCOPE_RUNTIME_BENCH_FAIL_ON_REGRESSION").as_deref() == Ok("1") {
        cmd.arg("--fail-on-regression");
    }

    let status = cmd.status().expect("failed to start runtime benchmark");
    assert!(status.success(), "runtime benchmark failed with {status}");
}

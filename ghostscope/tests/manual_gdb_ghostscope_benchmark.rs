use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const TEST_NAME: &str = "manual_benchmark_gdb_vs_ghostscope_hot_function";

fn benchmark_requested() -> bool {
    // Routine e2e uses `cargo test --tests`, so this test can still be discovered.
    // Keep the expensive benchmark inert unless the caller explicitly targets this
    // exact test name as the cargo-test filter.
    std::env::args().any(|arg| arg.contains(TEST_NAME))
}

#[test]
fn manual_benchmark_gdb_vs_ghostscope_hot_function() {
    if !benchmark_requested() {
        eprintln!("skipping {TEST_NAME}; run cargo test {TEST_NAME} to execute the benchmark");
        return;
    }

    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("ghostscope crate should live under repo root")
        .to_path_buf();
    let script = repo_root
        .join("scripts")
        .join("compare")
        .join("compare_hot_function_bench.py");
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_millis();
    let output_json = std::env::var("GHOSTSCOPE_BENCH_OUTPUT_JSON")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(format!(
                "/tmp/ghostscope_gdb_benchmark_result_{stamp}_{}.json",
                std::process::id()
            ))
        });
    let output_markdown = std::env::var("GHOSTSCOPE_BENCH_OUTPUT_MARKDOWN")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(format!(
                "/tmp/ghostscope_gdb_benchmark_result_{stamp}_{}.md",
                std::process::id()
            ))
        });

    let mut cmd = Command::new("python3");
    cmd.arg(&script)
        .arg("--output-json")
        .arg(&output_json)
        .arg("--output-markdown")
        .arg(&output_markdown);

    if let Ok(modes) = std::env::var("GHOSTSCOPE_BENCH_MODES") {
        cmd.arg("--modes");
        for mode in modes.split_whitespace() {
            cmd.arg(mode);
        }
    }

    for (env_name, arg_name) in [
        ("GHOSTSCOPE_BENCH_ITERATIONS", "--iterations"),
        ("GHOSTSCOPE_BENCH_INNER_WORK", "--inner-work"),
        ("GHOSTSCOPE_BENCH_REPETITIONS", "--repetitions"),
    ] {
        if let Ok(value) = std::env::var(env_name) {
            cmd.arg(arg_name).arg(value);
        }
    }

    if std::env::var_os("GHOSTSCOPE_BENCH_GHOSTSCOPE_BIN").is_none() {
        if let Some(ghostscope_bin) = option_env!("CARGO_BIN_EXE_ghostscope") {
            cmd.env("GHOSTSCOPE_BENCH_GHOSTSCOPE_BIN", ghostscope_bin);
        }
    }

    let status = cmd.status().expect("failed to start benchmark harness");
    assert!(
        status.success(),
        "benchmark harness failed with status {status}. expected results at {} and {}",
        output_json.display(),
        output_markdown.display()
    );
}

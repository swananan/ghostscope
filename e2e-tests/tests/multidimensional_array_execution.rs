//! Exercise both multiple-subrange C arrays and nested array projections.
#[allow(dead_code)]
mod common;

use anyhow::{Context, Result};
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};

const SOURCE: &str = r#"
#include <unistd.h>
typedef int Row[3];
struct Cell { int value; int *pointer; };
int matrix[2][3] = {{11,12,13},{21,22,23}};
int cube[2][2][3] = {{{1,2,3},{4,5,6}},{{7,8,9},{10,11,12}}};
int pointed = 91;
struct Holder { struct Cell cells[2][3]; } holder = {
    .cells = {{{1, &pointed},{2, &pointed},{3, &pointed}},
              {{4, &pointed},{5, &pointed},{6, &pointed}}}
};
__attribute__((noinline)) void array_probe(Row *rows, Row *local) {
    __asm__ volatile("" : : "r"(rows), "r"(local) : "memory");
}
int main(void) {
    int local[2][3] = {{31,32,33},{41,42,43}};
    for (;;) { array_probe(matrix, local); usleep(10000); }
}
"#;

async fn capture(compiler: &str, optimization: &str) -> Result<()> {
    init();
    let directory = tempfile::Builder::new()
        .prefix(".multidim-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let source = directory.path().join("arrays.c");
    let binary = directory.path().join("arrays");
    std::fs::write(&source, SOURCE)?;
    let output = std::process::Command::new(compiler)
        .args(["-g", optimization, "-fno-omit-frame-pointer"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "fixture compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let script = r#"
trace array_probe {
    let i = $pid - $pid + 1;
    let j = $tid - $tid + 2;
    let row = matrix[i];
    print "STATIC {} {} {}", matrix[1][2], cube[1][0][2], holder.cells[1][2].value;
    print "DYNAMIC {} {} {} {}", matrix[i][j], matrix[i][2], matrix[1][j], cube[i][0][j];
    print "MEMBERS {} {}", holder.cells[i][j].value, *holder.cells[i][j].pointer;
    print "POINTERS {} {} {} {}", rows[i][j], local[i][2], row[j], rows[1][2];
    print "ROW {}", matrix[i];
    if &matrix[i][j] == &matrix[1][2] { print "ADDRESS_OK"; }
    if matrix[i][j] + local[i][j] == 66 { print "ARITHMETIC_OK"; }
    if memcmp(&matrix[i][0], &matrix[1][0], 12) { print "MEMORY_OK"; }
}
"#;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(script)
        .timeout_secs(2)
        .startup_timeout_secs(60)
        .run()
        .await;
    let invalid_results = if compiler == "gcc" && optimization == "-O0" {
        let mut results = Vec::new();
        for expression in ["matrix[1][2][0]", "matrix[i] * 2"] {
            let script =
                format!("trace array_probe {{ let i = $pid - $pid; print {expression}; }}");
            results.push(
                GhostscopeRunner::new()
                    .attach_to(&target)
                    .with_script(&script)
                    .timeout_secs(1)
                    .startup_timeout_secs(60)
                    .run()
                    .await,
            );
        }
        results
    } else {
        Vec::new()
    };
    target.terminate().await?;
    for invalid in invalid_results {
        let (exit, stdout, stderr) = invalid?;
        anyhow::ensure!(
            exit != 0 && stderr.contains("failed to compile"),
            "invalid array expression accepted: {stdout} {stderr}"
        );
    }
    let (exit, stdout, stderr) = result?;
    anyhow::ensure!(
        exit == 0,
        "{compiler} {optimization}: stdout={stdout}\nstderr={stderr}"
    );
    for expected in [
        "STATIC 23 9 6",
        "DYNAMIC 23 23 23 9",
        "MEMBERS 6 91",
        "POINTERS 23 43 23 23",
        "ADDRESS_OK",
        "ARITHMETIC_OK",
        "MEMORY_OK",
    ] {
        anyhow::ensure!(
            stdout.contains(expected),
            "missing {expected}: stdout={stdout}\nstderr={stderr}"
        );
    }
    let row = stdout
        .lines()
        .find(|line| line.contains("ROW "))
        .context("missing row output")?;
    anyhow::ensure!(
        ["21", "22", "23"].iter().all(|value| row.contains(value)),
        "incorrect row: {row}"
    );
    Ok(())
}

#[tokio::test]
async fn test_multidimensional_arrays_gcc_o0() -> Result<()> {
    capture("gcc", "-O0").await
}
#[tokio::test]
async fn test_multidimensional_arrays_gcc_o2() -> Result<()> {
    capture("gcc", "-O2").await
}
#[tokio::test]
async fn test_multidimensional_arrays_clang_o0() -> Result<()> {
    capture("clang", "-O0").await
}
#[tokio::test]
async fn test_multidimensional_arrays_clang_o2() -> Result<()> {
    capture("clang", "-O2").await
}

#[tokio::test]
async fn test_multidimensional_arrays_rust_nested_types() -> Result<()> {
    init();
    let directory = tempfile::Builder::new()
        .prefix(".multidim-rust-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))?;
    let source = directory.path().join("arrays.rs");
    let binary = directory.path().join("arrays");
    std::fs::write(
        &source,
        r#"
static MATRIX: [[i32; 3]; 2] = [[11, 12, 13], [21, 22, 23]];
static PAIRS: [[(i32, i32); 2]; 2] = [[(1, 2), (3, 4)], [(5, 6), (7, 8)]];
#[no_mangle]
#[inline(never)]
pub fn nested_probe() { std::hint::black_box((&MATRIX, &PAIRS)); }
fn main() { loop { nested_probe(); std::thread::sleep(std::time::Duration::from_millis(10)); } }
"#,
    )?;
    let output = std::process::Command::new("rustc")
        .args(["--edition=2021", "-g", "-C", "opt-level=0"])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()?;
    anyhow::ensure!(
        output.status.success(),
        "rustc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(
            r#"
trace nested_probe {
    let i = $pid - $pid + 1;
    print "RUST {} {} {} {}", MATRIX[1][2], MATRIX[i][2], PAIRS[i][1].0, PAIRS[1][i].1;
    if &MATRIX[i][2] == &MATRIX[1][2] { print "RUST_ADDRESS_OK"; }
}
"#,
        )
        .timeout_secs(2)
        .startup_timeout_secs(60)
        .run()
        .await;
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    anyhow::ensure!(
        exit == 0 && stdout.contains("RUST 23 23 7 8") && stdout.contains("RUST_ADDRESS_OK"),
        "stdout={stdout}\nstderr={stderr}"
    );
    Ok(())
}

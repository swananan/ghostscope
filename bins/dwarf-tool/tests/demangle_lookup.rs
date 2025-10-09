use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn tool_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dwarf-tool"))
}

fn ws_root() -> PathBuf {
    // bins/dwarf-tool -> bins -> workspace
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn fixtures_dir() -> PathBuf {
    ws_root().join("ghostscope/tests/fixtures")
}

// Ensure any spawned fixture process is terminated even if the test returns early
struct KillOnDrop(tokio::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

fn build_cpp_fixture(name: &str) {
    let dir = fixtures_dir().join(name);
    let _ = Command::new("make").arg("clean").current_dir(&dir).output();
    let out = Command::new("make")
        .arg("all")
        .current_dir(&dir)
        .output()
        .expect("make failed");
    assert!(
        out.status.success(),
        "make failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn build_rust_fixture(name: &str) -> PathBuf {
    let dir = fixtures_dir().join(name);
    let out = Command::new("cargo")
        .arg("build")
        .current_dir(&dir)
        .output()
        .expect("cargo build failed");
    assert!(
        out.status.success(),
        "cargo build failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    dir.join("target/debug").join(name)
}

async fn run_dwarf_tool_text(
    binary_path: &std::path::Path,
    subcommand: &str,
    args: &[&str],
) -> anyhow::Result<String> {
    let mut cmd_args = vec![
        "-t".to_string(),
        binary_path.to_string_lossy().to_string(),
        subcommand.to_string(),
    ];
    cmd_args.extend(args.iter().map(|s| s.to_string()));

    let out = tokio::process::Command::new(tool_path())
        .args(&cmd_args)
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "dwarf-tool failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

async fn run_dwarftool_text_pid(pid: u32, subcmd: &str, extra: &[&str]) -> anyhow::Result<String> {
    let mut args: Vec<String> = vec!["-p".into(), pid.to_string(), subcmd.into()];
    for a in extra {
        args.push((*a).into());
    }
    let out = tokio::process::Command::new(tool_path())
        .args(&args)
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "dwarf-tool failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

#[tokio::test]
async fn test_cpp_lookup_functions_and_globals() -> anyhow::Result<()> {
    build_cpp_fixture("cpp_complex_program");
    let bin = fixtures_dir().join("cpp_complex_program/cpp_complex_program");

    // Functions: 仅验证叶子名（不依赖带形参的去混淆名）
    let leaf = run_dwarf_tool_text(&bin, "function", &["add"]).await?;
    assert!(leaf.contains("=== Function:"), "STDOUT: {leaf}");

    // Globals via PID
    let child = tokio::process::Command::new(&bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut guard = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let g = run_dwarftool_text_pid(pid, "globals", &["g_counter"]).await?;
    assert!(
        g.contains("=== Globals: 'g_counter' ===") || g.contains("Module:"),
        "STDOUT: {g}"
    );

    let s = run_dwarftool_text_pid(pid, "globals", &["s_internal"]).await?;
    assert!(
        s.contains("=== Globals: 's_internal' ===") || s.contains("Module:"),
        "STDOUT: {s}"
    );

    let sv = run_dwarftool_text_pid(pid, "globals", &["s_val"]).await?;
    assert!(
        sv.contains("=== Globals: 's_val' ===") || sv.contains("Module:"),
        "STDOUT: {sv}"
    );

    // Variables ending with ::h / ::h264 should be discoverable by leaf name
    let vh = run_dwarftool_text_pid(pid, "globals", &["h"]).await?;
    assert!(
        vh.contains("=== Globals: 'h' ===") || vh.contains("Module:"),
        "STDOUT: {vh}"
    );
    let vh264 = run_dwarftool_text_pid(pid, "globals", &["h264"]).await?;
    assert!(
        vh264.contains("=== Globals: 'h264' ===") || vh264.contains("Module:"),
        "STDOUT: {vh264}"
    );

    let _ = guard.0.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_rust_lookup_functions_and_globals() -> anyhow::Result<()> {
    let bin = build_rust_fixture("rust_global_program");

    // Rust function by leaf name (text mode)
    let f = run_dwarf_tool_text(&bin, "function", &["do_stuff"]).await?;
    assert!(f.contains("=== Function:"), "STDOUT: {f}");

    // Globals via PID
    let child = tokio::process::Command::new(&bin)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let pid = child.id().ok_or_else(|| anyhow::anyhow!("no pid"))?;
    let mut guard = KillOnDrop(child);
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let gc = run_dwarftool_text_pid(pid, "globals", &["G_COUNTER"]).await?;
    assert!(
        gc.contains("=== Globals: 'G_COUNTER' ===") || gc.contains("Module:"),
        "STDOUT: {gc}"
    );

    let cfg = run_dwarftool_text_pid(pid, "globals", &["CONFIG"]).await?;
    assert!(
        cfg.contains("=== Globals: 'CONFIG' ===") || cfg.contains("Module:"),
        "STDOUT: {cfg}"
    );

    let _ = guard.0.kill().await;
    Ok(())
}

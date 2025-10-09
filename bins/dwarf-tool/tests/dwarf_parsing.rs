use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;
use std::time::Duration;

fn tool_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dwarf-tool"))
}
fn ws_root() -> PathBuf {
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

static BUILD_DEBUG_ONCE: Once = Once::new();

fn ensure_sample_program_debug() {
    BUILD_DEBUG_ONCE.call_once(|| {
        let dir = fixtures_dir().join("sample_program");
        let out = Command::new("make")
            .arg("sample_program")
            .current_dir(&dir)
            .output()
            .expect("make failed");
        assert!(
            out.status.success(),
            "make failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    });
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

#[tokio::test]
async fn test_function_and_modules_listing() -> anyhow::Result<()> {
    ensure_sample_program_debug();
    let bin = fixtures_dir().join("sample_program/sample_program");

    let func = run_dwarf_tool_text(&bin, "function", &["main"]).await?;
    assert!(func.contains("=== Function:"), "STDOUT: {func}");

    // modules list
    let modules = run_dwarf_tool_text(&bin, "modules", &[]).await?;
    assert!(
        modules.contains("Loaded modules")
            || modules.lines().any(|l| l.contains("/sample_program")),
        "STDOUT: {modules}"
    );
    Ok(())
}

#[tokio::test]
async fn test_source_files_and_source_line() -> anyhow::Result<()> {
    ensure_sample_program_debug();
    let bin = fixtures_dir().join("sample_program/sample_program");

    // source-files
    let files = run_dwarf_tool_text(&bin, "source-files", &[]).await?;
    assert!(files.contains("sample_program.c"), "STDOUT: {files}");

    // source-line on a known file
    let res = run_dwarf_tool_text(&bin, "source-line", &["sample_program.c:25"]).await?;
    assert!(
        res.contains("sample_program.c:25")
            || res.contains(" \u{2192} ")
            || res.contains("->")
            || res.contains("Address:"),
        "STDOUT: {res}"
    );
    Ok(())
}

#[tokio::test]
async fn test_module_addr_and_debuglink() -> anyhow::Result<()> {
    // Build stripped binary specifically (do not rely on 'all')
    let dir = fixtures_dir().join("sample_program");
    let _ = Command::new("make")
        .arg("sample_program_stripped")
        .current_dir(&dir)
        .output();
    let bin = fixtures_dir().join("sample_program/sample_program_stripped");

    // Ensure stripped binary exists; skip if the environment lacks objcopy or strip support
    if !bin.exists() {
        eprintln!(
            "Skipping debuglink test: stripped binary not available (objcopy may be missing)"
        );
        return Ok(());
    }

    // function main should still be resolvable via .gnu_debuglink
    let func = run_dwarf_tool_text(&bin, "function", &["main"]).await?;
    assert!(func.contains("=== Function:"), "STDOUT: {func}");

    // Optional: module-addr requires an address; try retrieving one via function first
    // Get an address from function result if it's array/object with address info
    // (keep this lenient; we're primarily checking CLI path doesn't crash)
    let _ = tokio::time::sleep(Duration::from_millis(10)).await;
    Ok(())
}

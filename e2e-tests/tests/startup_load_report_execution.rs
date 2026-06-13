//! CLI startup load report integration tests.

mod common;

use anyhow::{bail, Context, Result};
use common::init;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::sync::OnceLock;
use tempfile::TempDir;

static FIXTURE_BUILD: OnceLock<Result<(), String>> = OnceLock::new();

const FIXTURE_BINARY: &str = "debug_source_report";
const FIXTURE_DEBUG_FILE: &str = "debug_source_report.debug";
const EMBEDDED_BINARY: &str = "debug_source_report_embedded";
const NO_DEBUGLINK_BINARY: &str = "debug_source_report_no_debuglink";
const NO_DWARF_DEBUGLINK_BINARY: &str = "debug_source_report_no_dwarf_debuglink";
const NO_DWARF_DEBUG_FILE: &str = "debug_source_report_no_dwarf.debug";
const MISSING_BINARY: &str = "debug_source_report_missing";
const BAD_DEBUG_FILE: &str = "bad.debug";
const TEST_CONFIG: &str = r#"
[general]
enable_logging = false
enable_console_logging = false

[script]
status = true
color = "auto"

[dwarf.debuginfod]
enabled = "off"
"#;

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_shows_embedded_source() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run = run_startup_report_command_for_binary(&fixture, &fixture.embedded_binary, &[])?;

    assert!(
        run.status.success(),
        "embedded startup report run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "\x1b[32mDWARF ready:\x1b[0m");
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "\x1b[32membedded:1\x1b[0m");
    assert_output_contains(&run.output, "module details:");
    assert_output_contains(&run.output, "\x1b[32membedded\x1b[0m");
    assert_output_contains(&run.output, EMBEDDED_BINARY);
    assert_output_contains(&run.output, "Dry run complete; no uprobes attached.");

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_shows_debuglink_source() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run = run_startup_report_command(&fixture, &[])?;

    assert!(
        run.status.success(),
        "debuglink startup report run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "\x1b[32mDWARF ready:\x1b[0m");
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "target: target=");
    assert_output_contains(&run.output, "\x1b[34mdebuglink:1\x1b[0m");
    assert_output_contains(&run.output, "module details:");
    assert_output_contains(&run.output, "\x1b[34mdebuglink\x1b[0m");
    assert_output_contains(&run.output, FIXTURE_DEBUG_FILE);
    assert!(
        !run.output.contains("...."),
        "debug source path should not be rendered with a leading four-dot truncation\n{}",
        run.output
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_loose_debuglink_search_prefers_later_strict_match() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let bad_search_dir = TempDir::new().context("failed to create bad debug search dir")?;
    fs::copy(
        &fixture.no_dwarf_debug_file,
        bad_search_dir.path().join(FIXTURE_DEBUG_FILE),
    )
    .context("failed to seed bad debug search path")?;
    let config = startup_report_config(&[bad_search_dir.path()]);
    let run = run_startup_report_command_for_binary_with_config(
        &fixture,
        &fixture.binary,
        &[OsString::from("--allow-loose-debug-match")],
        &config,
    )?;

    assert!(
        run.status.success(),
        "loose debuglink search-order run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "\x1b[34mdebuglink:1\x1b[0m");
    assert_output_contains(&run.output, "module details:");
    assert_output_contains(&run.output, "\x1b[34mdebuglink\x1b[0m");
    assert_output_contains(&run.output, FIXTURE_DEBUG_FILE);
    assert!(
        !run.output.contains("\x1b[33mmissing:1\x1b[0m"),
        "loose mode should prefer a later strict match over an earlier bad candidate\n{}",
        run.output
    );
    assert!(
        !run.output.contains("\x1b[33mmissing DWARF:\x1b[0m"),
        "strict debuglink fallback should avoid missing-DWARF output\n{}",
        run.output
    );

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_shows_missing_source_without_module_details() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run = run_startup_report_command_for_binary(&fixture, &fixture.missing_binary, &[])?;

    assert!(
        run.status.success(),
        "missing-DWARF startup report run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "\x1b[32mDWARF ready:\x1b[0m");
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "\x1b[33mmissing:1\x1b[0m");
    assert_output_contains(&run.output, "modules loaded: 1 completed, 0 failed");
    assert_output_contains(&run.output, "\x1b[33mmissing DWARF:\x1b[0m");
    assert_output_contains(&run.output, MISSING_BINARY);
    assert!(
        !run.output.contains("module details:"),
        "missing-DWARF modules should stay out of module details\n{}",
        run.output
    );
    assert_output_contains(&run.output, "Dry run complete; no uprobes attached.");

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_treats_debuglink_without_dwarf_as_missing() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run =
        run_startup_report_command_for_binary(&fixture, &fixture.no_dwarf_debuglink_binary, &[])?;

    assert!(
        run.status.success(),
        "no-DWARF debuglink startup report run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "\x1b[32mDWARF ready:\x1b[0m");
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "\x1b[33mmissing:1\x1b[0m");
    assert_output_contains(&run.output, "modules loaded: 1 completed, 0 failed");
    assert_output_contains(&run.output, "\x1b[33mmissing DWARF:\x1b[0m");
    assert_output_contains(&run.output, NO_DWARF_DEBUGLINK_BINARY);
    assert!(
        !run.output.contains("\x1b[34mdebuglink:1\x1b[0m"),
        "debuglink file without .debug_info should not be reported as debuglink\n{}",
        run.output
    );
    assert!(
        !run.output.contains("module details:"),
        "missing-DWARF modules should stay out of module details\n{}",
        run.output
    );
    assert_output_contains(&run.output, "Dry run complete; no uprobes attached.");

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_shows_explicit_debug_file_source() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run = run_startup_report_command(
        &fixture,
        &[
            OsString::from("--debug-file"),
            fixture.debug_file.as_os_str().to_os_string(),
        ],
    )?;

    assert!(
        run.status.success(),
        "explicit debug-file startup report run failed with status {}\n{}",
        run.status,
        run.output
    );
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "debug_file=");
    assert_output_contains(&run.output, FIXTURE_DEBUG_FILE);
    assert_output_contains(&run.output, "\x1b[36mexplicit:1\x1b[0m");
    assert_output_contains(&run.output, "module details:");
    assert_output_contains(&run.output, "\x1b[36mexplicit\x1b[0m");
    assert_output_contains(&run.output, "Dry run complete; no uprobes attached.");

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_startup_report_shows_explicit_debug_file_failure() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping startup load report e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let run = run_startup_report_command_for_binary(
        &fixture,
        &fixture.no_debuglink_binary,
        &[
            OsString::from("--debug-file"),
            fixture.bad_debug_file.as_os_str().to_os_string(),
        ],
    )?;

    assert!(
        !run.status.success(),
        "bad explicit debug-file should fail\n{}",
        run.output
    );
    assert_output_contains(&run.output, "\x1b[31mDWARF loading failed after\x1b[0m");
    assert_output_contains(&run.output, "Startup load report:");
    assert_output_contains(&run.output, "debug_file=");
    assert_output_contains(&run.output, NO_DEBUGLINK_BINARY);
    assert_output_contains(&run.output, BAD_DEBUG_FILE);
    assert_output_contains(&run.output, "modules loaded: 0 completed, 1 failed");
    assert_output_contains(&run.output, "module failures:");
    assert_output_contains(&run.output, "\x1b[31mfailed\x1b[0m");
    assert_output_contains(&run.output, "failed to parse debug file");
    assert_output_contains(&run.output, "Error: Failed to create debug session");

    Ok(())
}

#[derive(Debug, Clone)]
struct StartupReportFixture {
    binary: PathBuf,
    embedded_binary: PathBuf,
    no_debuglink_binary: PathBuf,
    no_dwarf_debuglink_binary: PathBuf,
    no_dwarf_debug_file: PathBuf,
    missing_binary: PathBuf,
    debug_file: PathBuf,
    bad_debug_file: PathBuf,
    script_file: PathBuf,
}

#[derive(Debug)]
struct StartupReportRun {
    status: ExitStatus,
    output: String,
}

fn ensure_startup_report_fixture() -> Result<StartupReportFixture> {
    match FIXTURE_BUILD.get_or_init(build_startup_report_fixture) {
        Ok(()) => {
            let dir = startup_report_fixture_dir();
            Ok(StartupReportFixture {
                binary: dir.join(FIXTURE_BINARY),
                embedded_binary: dir.join(EMBEDDED_BINARY),
                no_debuglink_binary: dir.join(NO_DEBUGLINK_BINARY),
                no_dwarf_debuglink_binary: dir.join(NO_DWARF_DEBUGLINK_BINARY),
                no_dwarf_debug_file: dir.join(NO_DWARF_DEBUG_FILE),
                missing_binary: dir.join(MISSING_BINARY),
                debug_file: dir.join(FIXTURE_DEBUG_FILE),
                bad_debug_file: dir.join(BAD_DEBUG_FILE),
                script_file: dir.join("trace.gs"),
            })
        }
        Err(error) => bail!("failed to build startup load report fixture: {error}"),
    }
}

fn build_startup_report_fixture() -> Result<(), String> {
    let dir = startup_report_fixture_dir();
    let output = Command::new("make")
        .args(["clean", "all"])
        .current_dir(&dir)
        .output()
        .map_err(|error| format!("failed to run make in {}: {error}", dir.display()))?;

    if !output.status.success() {
        return Err(format!(
            "make failed with status {}\nSTDOUT:\n{}\nSTDERR:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(())
}

fn run_startup_report_command(
    fixture: &StartupReportFixture,
    extra_args: &[OsString],
) -> Result<StartupReportRun> {
    run_startup_report_command_for_binary(fixture, &fixture.binary, extra_args)
}

fn run_startup_report_command_for_binary(
    fixture: &StartupReportFixture,
    binary: &Path,
    extra_args: &[OsString],
) -> Result<StartupReportRun> {
    run_startup_report_command_for_binary_with_config(fixture, binary, extra_args, TEST_CONFIG)
}

fn run_startup_report_command_for_binary_with_config(
    fixture: &StartupReportFixture,
    binary: &Path,
    extra_args: &[OsString],
    config: &str,
) -> Result<StartupReportRun> {
    let sandbox = common::sandbox::SandboxHandle::default_ghostscope()?;
    let (program, sandbox_args) = sandbox.ghostscope_command()?;
    if !sandbox_args.is_empty() {
        bail!("startup load report PTY e2e expects a host ghostscope command");
    }

    let temp_dir = TempDir::new().context("failed to create startup report temp dir")?;
    let config_path = temp_dir.path().join("ghostscope.toml");
    fs::write(&config_path, config).with_context(|| {
        format!(
            "failed to write startup report config {}",
            config_path.display()
        )
    })?;

    let mut args = Vec::new();
    args.extend([
        OsString::from("--config"),
        config_path.into_os_string(),
        OsString::from("--target"),
        binary.as_os_str().to_os_string(),
        OsString::from("--script-file"),
        fixture.script_file.as_os_str().to_os_string(),
        OsString::from("--dry-run"),
        OsString::from("--status"),
        OsString::from("--no-log-console"),
    ]);
    args.extend(extra_args.iter().cloned());

    let command_line = shell_command_line(&program, &args);
    let output = Command::new("script")
        .env("TERM", "xterm-256color")
        .env("COLUMNS", "160")
        .args(["-q", "-e", "-c", &command_line, "/dev/null"])
        .output()
        .context("failed to run script(1) for startup report PTY capture")?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));

    Ok(StartupReportRun {
        status: output.status,
        output: combined,
    })
}

fn startup_report_config(debug_search_paths: &[&Path]) -> String {
    let mut config = String::from(
        r#"
[general]
enable_logging = false
enable_console_logging = false

[script]
status = true
color = "auto"
"#,
    );

    if !debug_search_paths.is_empty() {
        let paths = debug_search_paths
            .iter()
            .map(|path| format!("\"{}\"", toml_string(path)))
            .collect::<Vec<_>>()
            .join(", ");
        config.push_str(&format!("\n[dwarf]\nsearch_paths = [{paths}]\n"));
    }

    config.push_str(
        r#"
[dwarf.debuginfod]
enabled = "off"
"#,
    );
    config
}

fn toml_string(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

fn startup_report_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("startup_load_report")
}

fn shell_command_line(program: &OsStr, args: &[OsString]) -> String {
    std::iter::once(shell_quote(program))
        .chain(args.iter().map(|arg| shell_quote(arg.as_os_str())))
        .collect::<Vec<_>>()
        .join(" ")
}

fn shell_quote(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if value.is_empty() {
        "''".to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn assert_output_contains(output: &str, needle: &str) {
    assert!(
        output.contains(needle),
        "expected output to contain {needle:?}\n{output}"
    );
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

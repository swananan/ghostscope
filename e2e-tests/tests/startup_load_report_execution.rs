//! CLI startup load report integration tests.

mod common;

use anyhow::{bail, Context, Result};
use common::init;
use regex::Regex;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::fs::{chown, MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
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
async fn test_prepare_analysis_cache_runs_without_root_and_reuses_entry() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping analysis cache prepare e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("e2e-tests must have a workspace parent")?;
    let unprivileged_identity = workspace_owner_identity(workspace_root)?;
    let temp_dir = TempDir::new_in(workspace_root)
        .context("failed to create analysis cache temp dir in workspace")?;
    fs::set_permissions(temp_dir.path(), fs::Permissions::from_mode(0o755))?;
    let sandbox = common::sandbox::SandboxHandle::default_ghostscope()?;
    let (ghostscope_program, sandbox_args) = sandbox.ghostscope_command()?;
    if !sandbox_args.is_empty() {
        bail!("analysis cache prepare e2e expects a host ghostscope command");
    }
    let public_ghostscope = temp_dir.path().join("ghostscope");
    let public_binary = temp_dir.path().join(EMBEDDED_BINARY);
    fs::copy(PathBuf::from(ghostscope_program), &public_ghostscope)?;
    fs::copy(&fixture.embedded_binary, &public_binary)?;
    fs::set_permissions(&public_ghostscope, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&public_binary, fs::Permissions::from_mode(0o755))?;
    let cache_dir = temp_dir.path().join("analysis-cache");
    fs::create_dir(&cache_dir)?;
    fs::set_permissions(&cache_dir, fs::Permissions::from_mode(0o700))?;
    if let Some((uid, gid)) = unprivileged_identity {
        chown(&cache_dir, Some(uid), Some(gid))?;
    }

    let first = run_prepare_analysis_cache_command(
        &public_ghostscope,
        &public_binary,
        &cache_dir,
        unprivileged_identity,
    )?;
    assert!(
        first.status.success(),
        "rootless analysis prepare failed with status {}\n{}",
        first.status,
        first.output
    );
    assert_output_contains(&first.output, "Prepared analysis cache for");
    assert!(
        cache_dir.join("v2").is_dir(),
        "prepare did not create a versioned cache under {}",
        cache_dir.display()
    );

    let second = run_prepare_analysis_cache_command(
        &public_ghostscope,
        &public_binary,
        &cache_dir,
        unprivileged_identity,
    )?;
    assert!(
        second.status.success(),
        "analysis cache reuse failed with status {}\n{}",
        second.status,
        second.output
    );
    assert_output_contains(&second.output, "Reused analysis cache for");

    let runtime = run_startup_report_command_for_binary(
        &fixture,
        &public_binary,
        &[
            OsString::from("--analysis-cache-dir"),
            cache_dir.as_os_str().to_os_string(),
        ],
    )?;
    assert!(
        runtime.status.success(),
        "runtime cache consumption failed with status {}\n{}",
        runtime.status,
        runtime.output
    );
    assert_plain_output_contains(&runtime.output, "analysis cache: 1 hit");

    corrupt_analysis_cache_payload_length(&cache_dir)?;
    let fallback = run_startup_report_command_for_binary(
        &fixture,
        &public_binary,
        &[
            OsString::from("--analysis-cache-dir"),
            cache_dir.as_os_str().to_os_string(),
        ],
    )?;
    assert!(
        fallback.status.success(),
        "runtime should ignore a malformed cache and reparse with status {}\n{}",
        fallback.status,
        fallback.output
    );
    let plain_fallback = output_without_ansi(&fallback.output);
    assert!(
        !plain_fallback.contains("analysis cache: 1 hit"),
        "malformed cache must not be reported as a hit\n{}",
        fallback.output
    );
    assert_plain_output_contains(&fallback.output, "analysis cache: 1 rejected");
    assert_plain_output_contains(&fallback.output, "cache fallback:");
    assert_plain_output_contains(&fallback.output, "Failed to decode analysis cache metadata");
    assert_plain_output_contains(&fallback.output, "Dry run complete; no uprobes attached.");

    Ok(())
}

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

#[tokio::test]
#[serial_test::serial]
async fn test_startup_rejects_aarch64_target() -> Result<()> {
    init();

    if !is_host_topology() {
        println!("skipping target architecture e2e outside host->host topology");
        return Ok(());
    }

    let fixture = ensure_startup_report_fixture()?;
    let temp_dir = TempDir::new().context("failed to create unsupported target temp dir")?;
    let target = temp_dir.path().join("aarch64-target");
    let mut target_bytes = fs::read(&fixture.embedded_binary).with_context(|| {
        format!(
            "failed to read fixture binary {}",
            fixture.embedded_binary.display()
        )
    })?;
    target_bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    fs::write(&target, target_bytes)
        .with_context(|| format!("failed to write unsupported target {}", target.display()))?;

    let run = run_startup_report_command_for_binary(&fixture, &target, &[])?;

    assert!(
        !run.status.success(),
        "AArch64 target should fail before DWARF loading\n{}",
        run.output
    );
    assert_output_contains(&run.output, "unsupported target object");
    assert_output_contains(&run.output, "expected 64-bit little-endian x86_64 ELF");
    assert_output_contains(&run.output, "architecture=Aarch64");
    assert!(
        !run.output.contains("DWARF ready:"),
        "unsupported target must not reach DWARF-ready state\n{}",
        run.output
    );

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

fn run_prepare_analysis_cache_command(
    ghostscope: &Path,
    binary: &Path,
    cache_dir: &Path,
    unprivileged_identity: Option<(u32, u32)>,
) -> Result<StartupReportRun> {
    let mut command = Command::new(ghostscope);
    command.args([
        OsStr::new("--prepare"),
        OsStr::new("--target"),
        binary.as_os_str(),
        OsStr::new("--analysis-cache-dir"),
        cache_dir.as_os_str(),
        OsStr::new("--no-log"),
    ]);
    command.current_dir("/tmp");
    if let Some(home) = cache_dir.parent() {
        command.env("HOME", home);
    }
    if let Some((uid, gid)) = unprivileged_identity {
        command.gid(gid).uid(uid);
    }
    let output = command
        .output()
        .context("failed to run rootless analysis cache prepare")?;

    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(StartupReportRun {
        status: output.status,
        output: combined,
    })
}

fn workspace_owner_identity(workspace_root: &Path) -> Result<Option<(u32, u32)>> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }

    let metadata = fs::metadata(workspace_root).with_context(|| {
        format!(
            "failed to inspect workspace owner for {}",
            workspace_root.display()
        )
    })?;
    if metadata.uid() == 0 {
        bail!(
            "rootless prepare e2e requires a workspace owned by a non-root user: {}",
            workspace_root.display()
        );
    }
    Ok(Some((metadata.uid(), metadata.gid())))
}

fn corrupt_analysis_cache_payload_length(cache_dir: &Path) -> Result<()> {
    let entries = fs::read_dir(cache_dir.join("v2"))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    if entries.len() != 1 {
        bail!(
            "expected one analysis cache entry under {}, found {}",
            cache_dir.display(),
            entries.len()
        );
    }

    let entry = &entries[0];
    let mut encoded = fs::read(entry)?;
    if encoded.len() < 24 {
        bail!("analysis cache entry {} is too short", entry.display());
    }
    let header_len = u32::from_le_bytes(encoded[12..16].try_into()?) as usize;
    let string_length_offset = 24_usize
        .checked_add(header_len)
        .and_then(|offset| offset.checked_add(8))
        .context("analysis cache payload offset overflow")?;
    let string_length_end = string_length_offset
        .checked_add(8)
        .context("analysis cache string length offset overflow")?;
    if string_length_end > encoded.len() {
        bail!(
            "analysis cache entry {} has an invalid payload offset",
            entry.display()
        );
    }
    encoded[string_length_offset..string_length_end].copy_from_slice(&u64::MAX.to_le_bytes());
    fs::write(entry, encoded)?;
    Ok(())
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

fn assert_plain_output_contains(output: &str, needle: &str) {
    let plain_output = output_without_ansi(output);
    assert!(
        plain_output.contains(needle),
        "expected plain output to contain {needle:?}\n{output}"
    );
}

fn output_without_ansi(output: &str) -> String {
    static ANSI_ESCAPE: OnceLock<Regex> = OnceLock::new();
    ANSI_ESCAPE
        .get_or_init(|| Regex::new(r"\x1B\[[0-?]*[ -/]*[@-~]").expect("valid ANSI regex"))
        .replace_all(output, "")
        .into_owned()
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

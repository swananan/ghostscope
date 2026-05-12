mod common;

use anyhow::Context;
use common::{
    fixture_compiler_available, init,
    runner::GhostscopeRunner,
    targets::{TargetHandle, TargetLauncher},
    FixtureCompiler, FIXTURES,
};
use ghostscope_dwarf::{CfaRulePlan, MemoryAccessSize, PlanExprOp, RegisterRecoveryPlan};
use gimli::constants;
use gimli::write::{
    Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
    Expression as WriteExpression, LineProgram, Sections, Unit,
};
use gimli::{Format, Register, SectionId};
use object::{Object, ObjectSymbol};
use regex::Regex;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const FIXTURE_NAME: &str = "entry_value_recovery_program";
const FIXTURE_SOURCE: &str = "entry_value_recovery_program.c";
const TOUCH_TRACE_LINE: u32 = 16;
const POST_CALL_TRACE_LINE: u32 = 21;
const BREG_FIXTURE_NAME: &str = "entry_value_breg_program";
const BREG_FIXTURE_SOURCE: &str = "entry_value_breg_program.c";
const BREG_FUNCTION_NAME: &str = "stack_entry_target";
const BREG_ANCHOR_NAME: &str = "entry_value_breg_anchor";

static BREG_CLANG_FIXTURE: OnceLock<Result<PathBuf, String>> = OnceLock::new();

struct LoggedTarget {
    target: TargetHandle,
    temp_dir: PathBuf,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

impl LoggedTarget {
    async fn terminate_and_collect(self) -> anyhow::Result<(String, String)> {
        self.target.terminate().await?;
        let stdout = read_log_file(&self.stdout_log)?;
        let stderr = read_log_file(&self.stderr_log)?;
        let _ = fs::remove_dir_all(&self.temp_dir);
        Ok((stdout, stderr))
    }
}

fn should_skip_for_ebpf_env(exit_code: i32, stderr: &str) -> bool {
    exit_code != 0
        && (stderr.contains("BPF_PROG_LOAD")
            || stderr.contains("needs elevated privileges")
            || stderr.contains("cap_bpf"))
}

fn command_available(name: &str) -> bool {
    StdCommand::new(name)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn preferred_clang_binary() -> Option<&'static str> {
    if command_available("clang-18") {
        Some("clang-18")
    } else if command_available("clang") {
        Some("clang")
    } else {
        None
    }
}

fn compile_entry_value_breg_program_clang() -> anyhow::Result<PathBuf> {
    let result = BREG_CLANG_FIXTURE.get_or_init(|| {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(BREG_FIXTURE_NAME);
        let source = base.join(BREG_FIXTURE_SOURCE);
        let binary = base.join("entry_value_breg_program_clang_debuglink");
        let debug_file = base.join("entry_value_breg_program_clang_debuglink.debug");

        if !command_available("objcopy") {
            return Err("objcopy is unavailable".to_string());
        }
        let clang = preferred_clang_binary().ok_or_else(|| "clang is unavailable".to_string())?;

        let _ = fs::remove_file(&binary);
        let _ = fs::remove_file(&debug_file);

        let output = StdCommand::new(clang)
            .arg("-Wall")
            .arg("-Wextra")
            .arg("-gdwarf-4")
            .arg("-O2")
            .arg("-fomit-frame-pointer")
            .arg("-no-pie")
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .current_dir(&base)
            .output();

        match output {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Err(format!(
                    "failed to compile {BREG_FIXTURE_NAME} clang fixture: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Err(error) => {
                return Err(format!(
                    "failed to invoke clang for {BREG_FIXTURE_NAME}: {error}"
                ));
            }
        }

        if let Err(error) = build_entry_value_breg_debuglink_fixture(&binary, &debug_file) {
            return Err(format!(
                "failed to synthesize debuglink fixture for {BREG_FIXTURE_NAME}: {error}"
            ));
        }

        Ok(binary)
    });

    result.clone().map_err(|e| anyhow::anyhow!(e))
}

fn build_entry_value_breg_debuglink_fixture(
    binary: &Path,
    debug_file: &Path,
) -> anyhow::Result<()> {
    run_command(
        StdCommand::new("objcopy")
            .arg("--only-keep-debug")
            .arg(binary)
            .arg(debug_file),
        "objcopy --only-keep-debug",
    )?;
    run_command(
        StdCommand::new("objcopy").arg("--strip-debug").arg(binary),
        "objcopy --strip-debug",
    )?;

    let (function_addr, function_size) = lookup_symbol(binary, BREG_FUNCTION_NAME)?;
    let (anchor_addr, _) = lookup_symbol(binary, BREG_ANCHOR_NAME)?;
    let function_size = function_size.max(anchor_addr.saturating_sub(function_addr) + 16);

    let debug_sections_dir = create_runtime_log_dir(
        debug_file
            .parent()
            .ok_or_else(|| anyhow::anyhow!("debug file path has no parent"))?,
    )?;
    write_synthetic_entry_value_breg_sections(&debug_sections_dir, function_addr, function_size)?;

    update_debug_section(debug_file, ".debug_abbrev", &debug_sections_dir)?;
    update_debug_section(debug_file, ".debug_info", &debug_sections_dir)?;
    update_debug_section(debug_file, ".debug_str", &debug_sections_dir)?;
    let _ = StdCommand::new("objcopy")
        .arg("--remove-section")
        .arg(".debug_aranges")
        .arg(debug_file)
        .output();

    run_command(
        StdCommand::new("objcopy")
            .arg("--add-gnu-debuglink")
            .arg(debug_file)
            .arg(binary),
        "objcopy --add-gnu-debuglink",
    )?;

    if command_available("dwarfdump") {
        ensure_debug_dump_contains_breg_entry_value(debug_file)?;
    }
    let _ = fs::remove_dir_all(debug_sections_dir);
    Ok(())
}

fn run_command(command: &mut StdCommand, label: &str) -> anyhow::Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{label} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn lookup_symbol(binary: &Path, name: &str) -> anyhow::Result<(u64, u64)> {
    let data = fs::read(binary)?;
    let file = object::File::parse(&*data)?;
    for symbol in file.symbols() {
        if let Ok(symbol_name) = symbol.name() {
            if symbol_name == name {
                return Ok((symbol.address(), symbol.size()));
            }
        }
    }
    anyhow::bail!("missing symbol {name} in {}", binary.display())
}

fn write_synthetic_entry_value_breg_sections(
    out_dir: &Path,
    function_addr: u64,
    function_size: u64,
) -> anyhow::Result<()> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();
    let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    unit.get_mut(root).set(
        constants::DW_AT_name,
        WriteAttributeValue::String(BREG_FIXTURE_SOURCE.as_bytes().to_vec()),
    );

    let int_id = unit.add(root, constants::DW_TAG_base_type);
    let int_entry = unit.get_mut(int_id);
    int_entry.set(
        constants::DW_AT_name,
        WriteAttributeValue::String(b"int".to_vec()),
    );
    int_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(4));
    int_entry.set(
        constants::DW_AT_encoding,
        WriteAttributeValue::Encoding(constants::DW_ATE_signed),
    );

    let function_id = unit.add(root, constants::DW_TAG_subprogram);
    let function = unit.get_mut(function_id);
    function.set(
        constants::DW_AT_name,
        WriteAttributeValue::String(BREG_FUNCTION_NAME.as_bytes().to_vec()),
    );
    function.set(
        constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(function_addr)),
    );
    function.set(
        constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(function_size),
    );
    let payload_id = unit.add(function_id, constants::DW_TAG_formal_parameter);
    let payload = unit.get_mut(payload_id);
    payload.set(
        constants::DW_AT_name,
        WriteAttributeValue::String(b"payload".to_vec()),
    );
    payload.set(constants::DW_AT_type, WriteAttributeValue::UnitRef(int_id));
    let mut inner = WriteExpression::new();
    inner.op_breg(Register(7), 8);
    let mut location = WriteExpression::new();
    location.op_entry_value(inner);
    payload.set(
        constants::DW_AT_location,
        WriteAttributeValue::Exprloc(location),
    );

    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;
    write_section_file(&sections, SectionId::DebugAbbrev, out_dir)?;
    write_section_file(&sections, SectionId::DebugInfo, out_dir)?;
    write_section_file(&sections, SectionId::DebugStr, out_dir)?;
    Ok(())
}

fn write_section_file(
    sections: &Sections<EndianVec<gimli::LittleEndian>>,
    id: SectionId,
    out_dir: &Path,
) -> anyhow::Result<()> {
    let data = sections
        .get(id)
        .map(|section| section.slice().to_vec())
        .unwrap_or_default();
    fs::write(out_dir.join(section_output_name(id)), data)?;
    Ok(())
}

fn section_output_name(id: SectionId) -> &'static str {
    match id {
        SectionId::DebugAbbrev => "debug_abbrev.bin",
        SectionId::DebugInfo => "debug_info.bin",
        SectionId::DebugStr => "debug_str.bin",
        _ => unreachable!("unexpected section id for synthetic DWARF"),
    }
}

fn update_debug_section(debug_file: &Path, section: &str, dir: &Path) -> anyhow::Result<()> {
    let section_file = dir.join(match section {
        ".debug_abbrev" => "debug_abbrev.bin",
        ".debug_info" => "debug_info.bin",
        ".debug_str" => "debug_str.bin",
        _ => unreachable!("unexpected section name"),
    });
    run_command(
        StdCommand::new("objcopy")
            .arg("--update-section")
            .arg(format!("{section}={}", section_file.display()))
            .arg(debug_file),
        &format!("objcopy --update-section {section}"),
    )
}

fn ensure_debug_dump_contains_breg_entry_value(debug_file: &Path) -> anyhow::Result<()> {
    let output = StdCommand::new("dwarfdump")
        .arg("-i")
        .arg(debug_file)
        .output()
        .with_context(|| format!("failed to run dwarfdump on {}", debug_file.display()))?;
    anyhow::ensure!(
        output.status.success(),
        "dwarfdump failed for {}: {}",
        debug_file.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    anyhow::ensure!(
        (stdout.contains("DW_OP_entry_value") || stdout.contains("DW_OP_GNU_entry_value"))
            && stdout.contains("payload")
            && (stdout.contains("contents 0x7708")
                || stdout.contains("DW_OP_breg7")
                || stdout.contains("DW_OP_breg7 8")),
        "synthetic debug file did not contain the expected entry_value(breg7) expression:\n{}",
        stdout
    );
    Ok(())
}

async fn spawn_logged_target(binary_path: &Path) -> anyhow::Result<LoggedTarget> {
    let base = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("fixture binary has no parent dir"))?;
    let temp_dir = create_runtime_log_dir(base)?;
    let stdout_log = temp_dir.join("target.stdout");
    let stderr_log = temp_dir.join("target.stderr");
    let wrapper_path = temp_dir.join("launch_target.sh");
    let wrapper = format!(
        "#!/usr/bin/env bash
set -euo pipefail
cd {base}
exec {binary} >>{stdout} 2>>{stderr}
",
        base = shell_quote(base),
        binary = shell_quote(binary_path),
        stdout = shell_quote(&stdout_log),
        stderr = shell_quote(&stderr_log),
    );
    write_wrapper_script(&wrapper_path, &wrapper)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&wrapper_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&wrapper_path, perms)?;
    }
    let target = spawn_wrapper_target(&wrapper_path, base).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(LoggedTarget {
        target,
        temp_dir,
        stdout_log,
        stderr_log,
    })
}

fn create_runtime_log_dir(base: &Path) -> anyhow::Result<PathBuf> {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let path = base.join(format!(".ghostscope-entry-value-runtime-{unique}"));
    fs::create_dir(&path)?;
    Ok(path)
}

fn write_wrapper_script(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut file = fs::File::create(path)?;
    file.write_all(contents.as_bytes())?;
    file.sync_all()?;
    Ok(())
}

async fn spawn_wrapper_target(wrapper_path: &Path, base: &Path) -> anyhow::Result<TargetHandle> {
    let mut delay = Duration::from_millis(50);
    for attempt in 0..3 {
        match TargetLauncher::binary(wrapper_path)
            .current_dir(base)
            .spawn()
            .await
        {
            Ok(target) => return Ok(target),
            Err(err) if attempt < 2 && is_text_file_busy(&err) => {
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("spawn retry loop should return on success or the final error")
}

fn is_text_file_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            == Some(libc::ETXTBSY)
    })
}

fn read_log_file(path: &Path) -> anyhow::Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(err.into()),
    }
}

fn shell_quote(path: &Path) -> String {
    let raw = path.display().to_string();
    format!("'{}'", raw.replace('\'', "'\"'\"'"))
}

#[tokio::test]
async fn test_non_inline_entry_value_recovers_touch_parameters_at_runtime() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping non-inline entry_value runtime test because clang is unavailable");
        return Ok(());
    }

    let binary_path =
        FIXTURES.get_test_binary_with_compiler(FIXTURE_NAME, FixtureCompiler::ClangDwarf5)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, TOUCH_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{TOUCH_TRACE_LINE}"
    );

    let target = spawn_logged_target(&binary_path).await?;
    let script = format!(
        "trace {FIXTURE_SOURCE}:{TOUCH_TRACE_LINE} {{
    print \"TOUCH:{{}}:{{}}:{{}}\", x, state.total_bytes, state.stream_id;
    print \"TOUCH_CALC:{{}}:{{}}\", x * 0x3, state.total_bytes + (x * 0b11);
    print \"TOUCH_DIV:{{}}:{{}}:{{}}\", x / 0x2, state.total_bytes / 0x5, (state.stream_id + -0x10) / 0x2;
    if state.stream_id + -0x7 > 0 {{ print \"TOUCH_STREAM_OK\"; }}
}}
"
    );
    let (exit_code, ghostscope_stdout, ghostscope_stderr) = GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target.target)
        .timeout_secs(4)
        .enable_sysmon_shared_lib(false)
        .run()
        .await?;
    let (target_stdout, target_stderr) = target.terminate_and_collect().await?;

    if should_skip_for_ebpf_env(exit_code, &ghostscope_stderr) {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope stderr={ghostscope_stderr} ghostscope stdout={ghostscope_stdout} target stderr={target_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("ExprError"),
        "Expected exact non-inline entry_value recovery inside touch(). STDOUT: {ghostscope_stdout}\nSTDERR: {ghostscope_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("<optimized out>"),
        "touch() parameters should not be optimized out. STDOUT: {ghostscope_stdout}\nSTDERR: {ghostscope_stderr}"
    );

    let actual_re = Regex::new(r"ACTUAL:([0-9-]+):([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let mut actual_by_seed = HashMap::new();
    for caps in actual_re.captures_iter(&target_stdout) {
        actual_by_seed.insert(
            caps[1].parse::<i64>()?,
            (
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
                caps[4].parse::<i64>()?,
            ),
        );
    }
    anyhow::ensure!(
        !actual_by_seed.is_empty(),
        "fixture stdout did not contain ACTUAL lines: {target_stdout}"
    );

    let trace_re = Regex::new(r"TOUCH:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let calc_re = Regex::new(r"TOUCH_CALC:([0-9-]+):([0-9-]+)")?;
    let div_re = Regex::new(r"TOUCH_DIV:([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let calc_samples: Vec<(i64, i64)> = calc_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_samples: Vec<(i64, i64, i64)> = div_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| {
            Ok((
                caps[1].parse::<i64>()?,
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
            ))
        })
        .collect::<anyhow::Result<_>>()?;
    let mut seen = 0;
    for ((caps, (seed_times_3, total_plus_seed_times_3)), (seed_div, total_div, stream_neg_div)) in
        trace_re
            .captures_iter(&ghostscope_stdout)
            .zip(calc_samples.iter().copied())
            .zip(div_samples.iter().copied())
    {
        let seed = caps[1].parse::<i64>()?;
        let total_bytes = caps[2].parse::<i64>()?;
        let stream_id = caps[3].parse::<i64>()?;
        let actual = actual_by_seed.get(&seed).ok_or_else(|| {
            anyhow::anyhow!("missing ACTUAL record for seed={seed}; target stdout={target_stdout}")
        })?;
        let mut expected_result = total_bytes + (seed * 3);
        if (expected_result & 1) != 0 {
            expected_result += stream_id;
        }
        assert_eq!(
            (total_bytes, stream_id),
            (actual.0, actual.1),
            "touch() recovered the wrong state for seed={seed}; ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            actual.2, expected_result,
            "touch() recovered an inconsistent seed/result for seed={seed}; ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            seed_times_3,
            seed * 3,
            "ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            total_plus_seed_times_3,
            total_bytes + (seed * 3),
            "ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(seed_div, seed / 2, "ghostscope stdout={ghostscope_stdout}");
        assert_eq!(
            total_div,
            total_bytes / 5,
            "ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            stream_neg_div,
            (stream_id - 16) / 2,
            "ghostscope stdout={ghostscope_stdout}"
        );
        seen += 1;
    }

    assert!(
        seen >= 2,
        "Expected multiple touch() trace events. GhostScope STDOUT: {ghostscope_stdout}\nTarget STDOUT: {target_stdout}"
    );
    assert_eq!(
        calc_samples.len(),
        seen,
        "Expected matching TOUCH and TOUCH_CALC samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert_eq!(
        div_samples.len(),
        seen,
        "Expected matching TOUCH and TOUCH_DIV samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert!(
        ghostscope_stdout.contains("TOUCH_STREAM_OK"),
        "Expected stream-id arithmetic comparison marker. GhostScope STDOUT: {ghostscope_stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_post_call_entry_value_recovers_state_members_at_runtime() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping entry_value runtime test because clang is unavailable");
        return Ok(());
    }

    let binary_path =
        FIXTURES.get_test_binary_with_compiler(FIXTURE_NAME, FixtureCompiler::ClangDwarf5)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, POST_CALL_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE}"
    );

    let target = spawn_logged_target(&binary_path).await?;
    let script = format!(
        "trace {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE} {{
    let total = state.total_bytes + state.stream_id;
    print \"POSTCALL:{{}}:{{}}\", state.total_bytes, state.stream_id;
    print \"POSTCALL_CALC:{{}}:{{}}\", total, state.total_bytes - 0xa;
    print \"POSTCALL_DIV:{{}}:{{}}\", state.total_bytes / 0x5, (state.stream_id + -0x10) / 0x2;
    if state.stream_id == 0x8 || state.stream_id == 0x9 {{ print \"POSTCALL_STREAM_OK\"; }}
}}
"
    );
    let (exit_code, ghostscope_stdout, ghostscope_stderr) = GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target.target)
        .timeout_secs(4)
        .enable_sysmon_shared_lib(false)
        .run()
        .await?;
    let (target_stdout, target_stderr) = target.terminate_and_collect().await?;

    if should_skip_for_ebpf_env(exit_code, &ghostscope_stderr) {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope stderr={ghostscope_stderr} ghostscope stdout={ghostscope_stdout} target stderr={target_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("ExprError"),
        "Expected exact post-call entry_value recovery. STDOUT: {ghostscope_stdout}
STDERR: {ghostscope_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("<optimized out>"),
        "Post-call entry_value should not be optimized out. STDOUT: {ghostscope_stdout}
STDERR: {ghostscope_stderr}"
    );

    let actual_re = Regex::new(r"ACTUAL:([0-9-]+):([0-9-]+):([0-9-]+):([0-9-]+)")?;
    let mut actual_by_seed = HashMap::new();
    for caps in actual_re.captures_iter(&target_stdout) {
        actual_by_seed.insert(
            caps[1].parse::<i64>()?,
            (
                caps[2].parse::<i64>()?,
                caps[3].parse::<i64>()?,
                caps[4].parse::<i64>()?,
            ),
        );
    }
    anyhow::ensure!(
        !actual_by_seed.is_empty(),
        "fixture stdout did not contain ACTUAL lines: {target_stdout}"
    );

    let trace_re = Regex::new(r"POSTCALL:([0-9-]+):([0-9-]+)")?;
    let calc_re = Regex::new(r"POSTCALL_CALC:([0-9-]+):([0-9-]+)")?;
    let div_re = Regex::new(r"POSTCALL_DIV:([0-9-]+):([0-9-]+)")?;
    let calc_samples: Vec<(i64, i64)> = calc_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_samples: Vec<(i64, i64)> = div_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let mut seen = 0;
    for ((caps, (total, delta_from_first_state)), (total_div, stream_neg_div)) in trace_re
        .captures_iter(&ghostscope_stdout)
        .zip(calc_samples.iter().copied())
        .zip(div_samples.iter().copied())
    {
        let total_bytes = caps[1].parse::<i64>()?;
        let stream_id = caps[2].parse::<i64>()?;
        assert!(
            actual_by_seed
                .values()
                .any(|actual| actual.0 == total_bytes && actual.1 == stream_id),
            "missing ACTUAL record for total_bytes={total_bytes}, stream_id={stream_id}; target stdout={target_stdout}"
        );
        assert_eq!(
            total,
            total_bytes + stream_id,
            "STDOUT: {ghostscope_stdout}"
        );
        assert_eq!(
            delta_from_first_state,
            total_bytes - 10,
            "STDOUT: {ghostscope_stdout}"
        );
        assert_eq!(total_div, total_bytes / 5, "STDOUT: {ghostscope_stdout}");
        assert_eq!(
            stream_neg_div,
            (stream_id - 16) / 2,
            "STDOUT: {ghostscope_stdout}"
        );
        seen += 1;
    }

    assert!(
        seen >= 2,
        "Expected multiple post-call trace events. GhostScope STDOUT: {ghostscope_stdout}
Target STDOUT: {target_stdout}"
    );
    assert_eq!(
        calc_samples.len(),
        seen,
        "Expected matching POSTCALL and POSTCALL_CALC samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert_eq!(
        div_samples.len(),
        seen,
        "Expected matching POSTCALL and POSTCALL_DIV samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert!(
        ghostscope_stdout.contains("POSTCALL_STREAM_OK"),
        "Expected post-call stream-id comparison marker. GhostScope STDOUT: {ghostscope_stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_post_call_entry_value_state_pointer_memory_formats() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping entry_value memory-format test because clang is unavailable");
        return Ok(());
    }

    let binary_path =
        FIXTURES.get_test_binary_with_compiler(FIXTURE_NAME, FixtureCompiler::ClangDwarf5)?;
    let target = spawn_logged_target(&binary_path).await?;
    let script = format!(
        "trace {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE} {{
    print \"POST_STATE_PTR={{:p}}\", state + 0;
    print \"POST_STATE_HEX={{:x.0x8}}\", state + 0;
    if memcmp(state + 0, hex(\"1400000009000000\"), 0x8) {{ print \"POST_STATE_20_9\"; }}
    if memcmp(state + 0, hex(\"0a00000008000000\"), 0b1000) {{ print \"POST_STATE_10_8\"; }}
}}
"
    );
    let (exit_code, ghostscope_stdout, ghostscope_stderr) = GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target.target)
        .timeout_secs(4)
        .enable_sysmon_shared_lib(false)
        .run()
        .await?;
    let (_target_stdout, target_stderr) = target.terminate_and_collect().await?;

    if should_skip_for_ebpf_env(exit_code, &ghostscope_stderr) {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope stderr={ghostscope_stderr} ghostscope stdout={ghostscope_stdout} target stderr={target_stderr}"
    );
    assert!(
        ghostscope_stdout.contains("POST_STATE_PTR=0x"),
        "Expected entry_value state pointer formatting. STDOUT: {ghostscope_stdout}"
    );
    assert!(
        ghostscope_stdout.contains("POST_STATE_HEX=14 00 00 00 09 00 00 00")
            || ghostscope_stdout.contains("POST_STATE_HEX=0a 00 00 00 08 00 00 00"),
        "Expected entry_value state raw memory bytes. STDOUT: {ghostscope_stdout}"
    );
    assert!(
        ghostscope_stdout.contains("POST_STATE_20_9")
            && ghostscope_stdout.contains("POST_STATE_10_8"),
        "Expected both entry_value state memcmp markers. STDOUT: {ghostscope_stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_entry_value_breg_stack_parameter_recovers_at_runtime() -> anyhow::Result<()> {
    init();
    if preferred_clang_binary().is_none() {
        eprintln!("Skipping entry_value(breg) runtime test because clang is unavailable");
        return Ok(());
    }
    if !command_available("objcopy") {
        eprintln!("Skipping entry_value(breg) runtime test because objcopy is unavailable");
        return Ok(());
    }

    let binary_path = compile_entry_value_breg_program_clang()?;
    let (anchor_pc, _) = lookup_symbol(&binary_path, BREG_ANCHOR_NAME)?;

    let target = spawn_logged_target(&binary_path).await?;
    let script = format!(
        "trace 0x{anchor_pc:x} {{
    print \"STACKPAYLOAD:{{}}\", payload;
    print \"STACKPAYLOAD_CALC:{{}}:{{}}\", payload + 0x1, payload * 0b10;
    print \"STACKPAYLOAD_DIV:{{}}\", payload / 0x2;
    if payload > 0 {{ print \"STACKPAYLOAD_POS\"; }}
}}
"
    );
    let (exit_code, ghostscope_stdout, ghostscope_stderr) = GhostscopeRunner::new()
        .with_script(&script)
        .attach_to(&target.target)
        .timeout_secs(4)
        .enable_sysmon_shared_lib(false)
        .run()
        .await?;
    let (target_stdout, target_stderr) = target.terminate_and_collect().await?;

    if should_skip_for_ebpf_env(exit_code, &ghostscope_stderr) {
        return Ok(());
    }

    assert_eq!(
        exit_code, 0,
        "ghostscope stderr={ghostscope_stderr} ghostscope stdout={ghostscope_stdout} target stderr={target_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("ExprError"),
        "Expected entry_value(breg7 + 8) stack recovery. STDOUT: {ghostscope_stdout}\nSTDERR: {ghostscope_stderr}"
    );
    assert!(
        !ghostscope_stdout.contains("<optimized out>"),
        "entry_value(breg7 + 8) stack parameter should not be optimized out. STDOUT: {ghostscope_stdout}\nSTDERR: {ghostscope_stderr}"
    );

    let actual_re = Regex::new(r"ACTUAL:([0-9-]+):([0-9-]+)")?;
    let actual_seeds: Vec<i64> = actual_re
        .captures_iter(&target_stdout)
        .map(|caps| caps[1].parse::<i64>())
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(
        !actual_seeds.is_empty(),
        "fixture stdout did not contain ACTUAL lines: {target_stdout}"
    );

    let trace_re = Regex::new(r"STACKPAYLOAD:([0-9-]+)")?;
    let calc_re = Regex::new(r"STACKPAYLOAD_CALC:([0-9-]+):([0-9-]+)")?;
    let div_re = Regex::new(r"STACKPAYLOAD_DIV:([0-9-]+)")?;
    let calc_samples: Vec<(i64, i64)> = calc_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| Ok((caps[1].parse::<i64>()?, caps[2].parse::<i64>()?)))
        .collect::<anyhow::Result<_>>()?;
    let div_samples: Vec<i64> = div_re
        .captures_iter(&ghostscope_stdout)
        .map(|caps| caps[1].parse::<i64>())
        .collect::<Result<_, _>>()?;
    let mut next_actual_index = 0usize;
    let mut seen = 0;
    for ((caps, (payload_plus_1, payload_times_2)), payload_div) in trace_re
        .captures_iter(&ghostscope_stdout)
        .zip(calc_samples.iter().copied())
        .zip(div_samples.iter().copied())
    {
        let payload = caps[1].parse::<i64>()?;
        let relative_index = actual_seeds[next_actual_index..]
            .iter()
            .position(|seed| *seed == payload)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing ordered ACTUAL seed for payload={payload}; ghostscope stdout={ghostscope_stdout} target stdout={target_stdout}"
                )
        })?;
        next_actual_index += relative_index + 1;
        assert_eq!(
            payload_plus_1,
            payload + 1,
            "ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            payload_times_2,
            payload * 2,
            "ghostscope stdout={ghostscope_stdout}"
        );
        assert_eq!(
            payload_div,
            payload / 2,
            "ghostscope stdout={ghostscope_stdout}"
        );
        seen += 1;
    }

    assert!(
        seen >= 2,
        "Expected multiple stack-parameter trace events. GhostScope STDOUT: {ghostscope_stdout}\nTarget STDOUT: {target_stdout}"
    );
    assert_eq!(
        calc_samples.len(),
        seen,
        "Expected matching STACKPAYLOAD and STACKPAYLOAD_CALC samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert_eq!(
        div_samples.len(),
        seen,
        "Expected matching STACKPAYLOAD and STACKPAYLOAD_DIV samples. GhostScope STDOUT: {ghostscope_stdout}"
    );
    assert!(
        ghostscope_stdout.contains("STACKPAYLOAD_POS"),
        "Expected stack payload comparison marker. GhostScope STDOUT: {ghostscope_stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_recover_caller_frame_exposes_pc_and_callee_saved_steps() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping caller-frame recovery test because clang is unavailable");
        return Ok(());
    }

    let binary_path =
        FIXTURES.get_test_binary_with_compiler(FIXTURE_NAME, FixtureCompiler::ClangDwarf5)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, POST_CALL_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE}"
    );

    let recovery_by_address = analyzer
        .recover_caller_frame(&addrs[0], &[3, 16])?
        .ok_or_else(|| anyhow::anyhow!("no caller-frame recovery returned"))?;
    let ctx = analyzer.resolve_pc(&addrs[0])?;
    let recovery = analyzer
        .recover_caller_frame_for_context(&ctx, &[3, 16])?
        .ok_or_else(|| anyhow::anyhow!("no caller-frame recovery returned from PC context"))?;

    assert_eq!(recovery, recovery_by_address);

    assert_eq!(recovery.return_address_register, 16);
    assert!(
        recovery.caller_pc_steps.iter().any(|step| matches!(
            step,
            PlanExprOp::Dereference {
                size: MemoryAccessSize::U64
            }
        )),
        "caller_pc_steps should load the caller PC from memory: {:?}",
        recovery.caller_pc_steps
    );
    assert!(
        recovery
            .caller_pc_steps
            .iter()
            .any(|step| matches!(step, PlanExprOp::PushConstant(_))),
        "caller_pc_steps should include a CFA-relative offset: {:?}",
        recovery.caller_pc_steps
    );
    let rbx_steps = recovery
        .register_recovery_steps
        .get(&3)
        .ok_or_else(|| anyhow::anyhow!("missing rbx recovery steps"))?;
    assert!(
        rbx_steps.iter().any(|step| matches!(
            step,
            PlanExprOp::Dereference {
                size: MemoryAccessSize::U64
            }
        )),
        "rbx should recover from the caller stack slot at the post-call PC: {rbx_steps:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_compact_unwind_table_exposes_pc_row() -> anyhow::Result<()> {
    init();
    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping compact unwind table test because clang is unavailable");
        return Ok(());
    }

    let binary_path =
        FIXTURES.get_test_binary_with_compiler(FIXTURE_NAME, FixtureCompiler::ClangDwarf5)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_addresses_by_source_line(FIXTURE_SOURCE, POST_CALL_TRACE_LINE);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for {FIXTURE_SOURCE}:{POST_CALL_TRACE_LINE}"
    );

    let ctx = analyzer.resolve_pc(&addrs[0])?;
    let table_by_context = analyzer
        .compact_unwind_table_for_context(&ctx)?
        .ok_or_else(|| anyhow::anyhow!("no compact unwind table returned from PC context"))?;
    let table_by_module = analyzer
        .compact_unwind_table_for_module(ctx.module)?
        .ok_or_else(|| anyhow::anyhow!("no compact unwind table returned for module"))?;

    assert_eq!(table_by_context, table_by_module);

    let stats = table_by_context.stats();
    assert!(stats.row_count > 0, "compact unwind table is empty");
    assert!(
        stats.bpf_supported_rows > 0,
        "expected at least one BPF-fast-path unwind row: {stats:?}"
    );
    assert!(
        table_by_context
            .rows
            .windows(2)
            .all(|pair| (pair[0].pc_start, pair[0].pc_end) <= (pair[1].pc_start, pair[1].pc_end)),
        "compact unwind rows should be sorted by PC"
    );

    let row = table_by_context
        .row_for_pc(ctx.normalized_pc)
        .ok_or_else(|| anyhow::anyhow!("no compact unwind row for PC context"))?;
    let row_by_context = analyzer
        .compact_unwind_row_for_context(&ctx)?
        .ok_or_else(|| anyhow::anyhow!("no direct compact unwind row for PC context"))?;
    assert_eq!(&row_by_context, row);
    assert_eq!(row.module, ctx.module);
    assert_eq!(row.return_address_register, 16);
    assert!(matches!(
        row.cfa,
        CfaRulePlan::RegPlusOffset { .. } | CfaRulePlan::Expression { .. }
    ));
    assert!(
        !matches!(
            row.return_address,
            RegisterRecoveryPlan::Undefined | RegisterRecoveryPlan::Unsupported { .. }
        ),
        "return address recovery should be materialized: {:?}",
        row.return_address
    );

    Ok(())
}

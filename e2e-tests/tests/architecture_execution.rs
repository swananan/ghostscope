//! Native architecture contract shared by x86-64 and experimental ARM64 CI.
//! Missing BPF privileges or missing events are failures, never implicit skips.
mod common;

use anyhow::{Context, Result};
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};
use regex::Regex;
use std::path::PathBuf;
use std::sync::OnceLock;

fn fixture(variant: &str) -> Result<PathBuf> {
    static BUILD: OnceLock<Result<(), String>> = OnceLock::new();
    let directory =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/architecture_program");
    let built = BUILD.get_or_init(|| {
        if std::env::var_os("GHOSTSCOPE_PRESERVE_PRECOMPILED_FIXTURES").is_some() {
            return Ok(());
        }
        let output = std::process::Command::new("make")
            .arg("all")
            .current_dir(&directory)
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        Ok(())
    });
    built
        .as_ref()
        .map_err(|e| anyhow::anyhow!("fixture build: {e}"))?;
    let path = directory.join(format!("architecture_program_{variant}"));
    anyhow::ensure!(path.is_file(), "missing fixture: {}", path.display());
    Ok(path)
}

async fn capture(variant: &str, perf: bool, target_mode: bool) -> Result<()> {
    init();
    let binary = fixture(variant)?;
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let script = r#"
trace architecture_probe {
    print "ARGS {} {} {} {} {} {} {} {} GLOBAL {} PC {:p} SP {:p}",
        a, b, c, d, e, f, g, h, architecture_global,
        cast($pc, "unsigned char *"), cast($sp, "unsigned char *");
}
"#;
    let runner = GhostscopeRunner::new()
        .with_script(script)
        .timeout_secs(3)
        .startup_timeout_secs(60)
        .force_perf_event_array(perf)
        .enable_sysmon_for_target(false);
    let runner = if target_mode {
        runner.with_target(&binary)
    } else {
        runner.attach_to(&target)
    };
    let result = runner.run().await;
    // Read mappings in the target's namespace so the same checks work in
    // host -> private-container tests as well as native host tests.
    let maps = target
        .sandbox()
        .run_shell(&format!("cat /proc/{}/maps", target.sandbox_pid()));
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    assert_eq!(exit, 0, "stdout={stdout}\nstderr={stderr}");
    let samples = Regex::new(
        r"ARGS 11 22 33 44 55 66 77 88 GLOBAL 73 PC (0x[0-9a-fA-F]+) SP (0x[0-9a-fA-F]+)",
    )?;
    let captures = samples
        .captures(&stdout)
        .with_context(|| format!("missing DWARF values\nstdout={stdout}\nstderr={stderr}"))?;
    let pc = u64::from_str_radix(&captures[1][2..], 16)?;
    let sp = u64::from_str_radix(&captures[2][2..], 16)?;
    let maps = maps?;
    anyhow::ensure!(maps.status.success(), "could not read target mappings");
    let maps = String::from_utf8(maps.stdout)?;
    let mut valid_pc = false;
    let mut valid_sp = false;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let (start, end) = fields[0].split_once('-').context("invalid mapping")?;
        let range = u64::from_str_radix(start, 16)?..u64::from_str_radix(end, 16)?;
        valid_pc |= range.contains(&pc)
            && fields[1].contains('x')
            && fields
                .last()
                .is_some_and(|name| name.ends_with(&format!("architecture_program_{variant}")));
        valid_sp |= range.contains(&sp) && fields.last() == Some(&"[stack]");
    }
    assert!(valid_pc && valid_sp, "PC={pc:#x}, SP={sp:#x}\n{maps}");
    Ok(())
}

#[tokio::test]
async fn test_architecture_o0_parameters_globals_and_registers() -> Result<()> {
    capture("o0", false, false).await
}

#[tokio::test]
async fn test_architecture_o2_parameters_globals_and_registers() -> Result<()> {
    capture("o2", false, false).await
}

#[tokio::test]
#[serial_test::serial(architecture_target)]
async fn test_architecture_nopie_parameters_globals_and_registers() -> Result<()> {
    capture("nopie", false, false).await
}

#[tokio::test]
async fn test_architecture_perf_event_array() -> Result<()> {
    capture("o0", true, false).await
}

#[tokio::test]
#[serial_test::serial(architecture_target)]
async fn test_architecture_target_path() -> Result<()> {
    // Match the existing globals suite: nested child-container -t runs do
    // not yet maintain the runtime-PID alias needed for global offsets.
    if common::skip_if_nested_t_mode_unsupported() {
        return Ok(());
    }
    // Use a distinct executable from concurrent PID-scoped tests. -t traces
    // every instance, whereas the mapping assertion belongs to this process.
    capture("nopie", false, true).await
}

#[cfg(target_arch = "aarch64")]
async fn capture_arm64(binary: PathBuf, statement: &str) -> Result<String> {
    capture_arm64_with_depth(binary, statement, "8").await
}

#[cfg(target_arch = "aarch64")]
async fn capture_arm64_with_depth(binary: PathBuf, statement: &str, depth: &str) -> Result<String> {
    common::init();
    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .attach_to(&target)
        .with_script(&format!("trace architecture_probe {{ {statement} }}"))
        .with_cli_args(vec!["--backtrace-depth", depth])
        .timeout_secs(3)
        .startup_timeout_secs(60)
        .enable_sysmon_for_target(false)
        .run()
        .await;
    target.terminate().await?;
    let (exit, stdout, stderr) = result?;
    anyhow::ensure!(exit == 0, "{stdout}\n{stderr}");
    Ok(stdout)
}

#[cfg(target_arch = "aarch64")]
#[tokio::test]
async fn test_architecture_backtrace_recovers_link_register() -> Result<()> {
    let stdout = capture_arm64(fixture("o0")?, "bt full;").await?;
    anyhow::ensure!(
        stdout.contains("#0 architecture_probe") && stdout.contains("#1 main"),
        "{stdout}"
    );
    Ok(())
}

// ARM GCC/Clang may omit DW_AT_location for TLS entirely. Supply a valid
// DW_OP_form_tls_address expression to test DWARF TLS lowering independently
// of the ELF-symbol fallback for missing locations.
#[cfg(target_arch = "aarch64")]
fn tls_fixture() -> Result<(tempfile::TempDir, PathBuf)> {
    use gimli::write::{
        Address, AttributeValue as Attr, Dwarf, EndianVec, Expression, LineProgram, Sections, Unit,
    };
    use object::{Object, ObjectSymbol};
    let source = fixture("o0")?;
    let bytes = std::fs::read(&source)?;
    let elf = object::File::parse(bytes.as_slice())?;
    let symbol = elf
        .symbols()
        .find(|s| s.name().ok() == Some("architecture_probe"))
        .context("missing architecture_probe symbol")?;
    let mut dwarf = Dwarf::new();
    let id = dwarf.units.add(Unit::new(
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        },
        LineProgram::none(),
    ));
    let unit = dwarf.units.get_mut(id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::DW_AT_name,
        Attr::String(b"architecture_tls.c".to_vec()),
    );
    let ty = unit.add(root, gimli::DW_TAG_base_type);
    unit.get_mut(ty)
        .set(gimli::DW_AT_name, Attr::String(b"long".to_vec()));
    unit.get_mut(ty).set(gimli::DW_AT_byte_size, Attr::Data1(8));
    unit.get_mut(ty)
        .set(gimli::DW_AT_encoding, Attr::Encoding(gimli::DW_ATE_signed));
    let function = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(function).set(
        gimli::DW_AT_name,
        Attr::String(b"architecture_probe".to_vec()),
    );
    unit.get_mut(function).set(
        gimli::DW_AT_low_pc,
        Attr::Address(Address::Constant(symbol.address())),
    );
    unit.get_mut(function)
        .set(gimli::DW_AT_high_pc, Attr::Udata(symbol.size()));
    let variable = unit.add(root, gimli::DW_TAG_variable);
    unit.get_mut(variable).set(
        gimli::DW_AT_name,
        Attr::String(b"architecture_tls".to_vec()),
    );
    unit.get_mut(variable)
        .set(gimli::DW_AT_type, Attr::UnitRef(ty));
    let mut location = Expression::new();
    location.op_constu(0);
    location.op(gimli::DW_OP_form_tls_address);
    unit.get_mut(variable)
        .set(gimli::DW_AT_location, Attr::Exprloc(location));
    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;
    // Keep the temporary executable inside the checkout for container mounts.
    let directory = tempfile::Builder::new()
        .prefix(".tls-")
        .tempdir_in(source.parent().unwrap())?;
    let binary = directory.path().join("tls_program");
    std::fs::copy(source, &binary)?;
    let mut command = std::process::Command::new("objcopy");
    command.arg("--strip-debug");
    for id in [
        gimli::SectionId::DebugInfo,
        gimli::SectionId::DebugAbbrev,
        gimli::SectionId::DebugStr,
    ] {
        let path = directory.path().join(id.name());
        std::fs::write(
            &path,
            sections.get(id).context("missing DWARF section")?.slice(),
        )?;
        command
            .arg("--add-section")
            .arg(format!("{}={}", id.name(), path.display()));
    }
    let output = command.arg(&binary).output()?;
    anyhow::ensure!(
        output.status.success(),
        "objcopy: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok((directory, binary))
}

#[cfg(target_arch = "aarch64")]
#[tokio::test]
async fn test_architecture_tls_reads_thread_storage() -> Result<()> {
    for synthetic in [false, true] {
        let (_directory, binary) = if synthetic {
            let (directory, binary) = tls_fixture()?;
            (Some(directory), binary)
        } else {
            (None, fixture("o0")?)
        };
        let stdout = capture_arm64(binary, "print \"TLS {}\", architecture_tls;").await?;
        anyhow::ensure!(
            stdout.lines().any(|line| line
                .split("TLS ")
                .nth(1)
                .and_then(|value| value.trim().parse::<i64>().ok())
                .is_some_and(|value| value >= 91)),
            "{stdout}"
        );
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
async fn capture_pac(variant: &str) -> Result<()> {
    // Exercise both inline and tail-call unwinding. The leaf keeps a signed LR
    // in x30; main spills its signed LR to the stack.
    for depth in ["5", "128"] {
        let stdout = capture_arm64_with_depth(
            fixture(variant)?,
            r#"
            print "PAC ARGS {} {} {} {} {} {} {} {}", a, b, c, d, e, f, g, h;
            bt full;
        "#,
            depth,
        )
        .await?;
        anyhow::ensure!(
            stdout.contains("PAC ARGS 11 22 33 44 55 66 77 88"),
            "{stdout}"
        );
        let expected_stack = if depth == "5" {
            "backtrace: truncated, 5 frames (max 5)"
        } else {
            "backtrace: complete, 5 frames (max 128)"
        };
        anyhow::ensure!(
            stdout.contains("#0 architecture_probe")
                && stdout.contains("#1 main")
                && stdout.contains("#4 ")
                && stdout.contains(expected_stack),
            "{stdout}"
        );
    }
    Ok(())
}

#[cfg(target_arch = "aarch64")]
#[tokio::test]
async fn test_architecture_pac_a_parameters_and_backtrace() -> Result<()> {
    capture_pac("pac_a").await
}

#[cfg(target_arch = "aarch64")]
#[tokio::test]
async fn test_architecture_pac_b_parameters_and_backtrace() -> Result<()> {
    capture_pac("pac_b").await
}

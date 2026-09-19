#[allow(dead_code)]
mod common;

use anyhow::Context;
use common::{init, runner::GhostscopeRunner, targets::TargetLauncher};
use ghostscope_dwarf::{
    DwarfAnalyzer, LoadedModuleRuntimeInfo, ModuleAddress, VariableAccessSegment, VariableId,
};
use gimli::write::{
    Address, AttributeValue, Dwarf, EndianVec, Expression, LineProgram, Location, LocationList,
    Sections, Unit,
};
use object::{Object, ObjectSymbol};
use std::{fs, path::Path, process::Command};

fn run_command(command: &mut Command) -> anyhow::Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {command:?}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn fixture_dir() -> anyhow::Result<tempfile::TempDir> {
    // Keep runtime fixtures under the checkout so sandbox runners can map them.
    Ok(tempfile::Builder::new()
        .prefix("dwarf-semantics-")
        .tempdir_in(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"))?)
}

fn add_location_list_dwarf(binary: &Path, version: u16) -> anyhow::Result<(u64, u64)> {
    let bytes = fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let symbol = |name| {
        object
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .with_context(|| format!("missing fixture symbol {name}"))
    };
    let function = symbol("location_probe")?;
    let start = function.address();
    let end = start + function.size();
    let active = symbol("location_probe_active")?.address();
    anyhow::ensure!(start < active && active < end, "invalid probe ranges");

    let mut dwarf = Dwarf::new();
    let unit_id = dwarf.units.add(Unit::new(
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version,
            address_size: 8,
        },
        LineProgram::none(),
    ));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(start)),
    );
    unit.get_mut(root)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(end - start));
    let integer = unit.add(root, gimli::DW_TAG_base_type);
    unit.get_mut(integer)
        .set(gimli::DW_AT_name, AttributeValue::String(b"int".to_vec()));
    unit.get_mut(integer)
        .set(gimli::DW_AT_byte_size, AttributeValue::Udata(4));
    unit.get_mut(integer).set(
        gimli::DW_AT_encoding,
        AttributeValue::Encoding(gimli::DW_ATE_signed),
    );
    let function = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(function).set(
        gimli::DW_AT_name,
        AttributeValue::String(b"location_probe".to_vec()),
    );
    unit.get_mut(function).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(start)),
    );
    unit.get_mut(function)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(end - start));

    // This earlier range needs unsupported entry-value recovery. At the next
    // instruction the parameter is simply in RDI, regardless of that limitation.
    let mut entry_expression = Expression::new();
    entry_expression.op_breg(gimli::Register(5), 0);
    entry_expression.op_deref();
    let mut inactive_location = Expression::new();
    inactive_location.op_entry_value(entry_expression);
    inactive_location.op(gimli::DW_OP_stack_value);
    let mut active_location = Expression::new();
    active_location.op_reg(gimli::Register(5));
    let locations = unit.locations.add(LocationList(vec![
        Location::BaseAddress {
            address: Address::Constant(start),
        },
        Location::OffsetPair {
            begin: 0,
            end: active - start,
            data: inactive_location,
        },
        Location::OffsetPair {
            begin: active - start,
            end: end - start,
            data: active_location,
        },
    ]));
    let value = unit.add(function, gimli::DW_TAG_formal_parameter);
    unit.get_mut(value)
        .set(gimli::DW_AT_name, AttributeValue::String(b"value".to_vec()));
    unit.get_mut(value)
        .set(gimli::DW_AT_type, AttributeValue::UnitRef(integer));
    unit.get_mut(value).set(
        gimli::DW_AT_location,
        AttributeValue::LocationListRef(locations),
    );

    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;
    let mut objcopy = Command::new("objcopy");
    sections.for_each(|id, data| -> anyhow::Result<()> {
        if !data.slice().is_empty() {
            let section = binary.with_extension(id.name());
            fs::write(&section, data.slice())?;
            objcopy
                .arg("--add-section")
                .arg(format!("{}={}", id.name(), section.display()));
        }
        Ok(())
    })?;
    run_command(objcopy.arg(binary))?;
    Ok((start, active))
}

async fn check_location_list_at_probe_pc(version: u16) -> anyhow::Result<()> {
    init();
    let dir = fixture_dir()?;
    let source = dir.path().join("probe.c");
    let assembly = dir.path().join("probe.S");
    let binary = dir.path().join("probe");
    fs::write(
        &source,
        "#include <unistd.h>\n\
         extern void location_probe(int value);\n\
         int main(void) { for (;;) { location_probe(42); usleep(10000); } }\n",
    )?;
    fs::write(
        &assembly,
        ".text\n\
         .globl location_probe\n\
         .type location_probe, @function\n\
         location_probe:\n\
         nop\n\
         .globl location_probe_active\n\
         location_probe_active:\n\
         nop\n\
         ret\n\
         .size location_probe, .-location_probe\n\
         .section .note.GNU-stack,\"\",@progbits\n",
    )?;
    run_command(
        Command::new("cc")
            .args(["-g0", "-no-pie", "-o"])
            .arg(&binary)
            .arg(&source)
            .arg(&assembly),
    )?;
    let (unsupported_pc, active_pc) = add_location_list_dwarf(&binary, version)?;

    // Ignoring unrelated expressions must not suppress errors in an active one.
    let analyzer = DwarfAnalyzer::from_exec_path(&binary).await?;
    let context = analyzer.resolve_pc(&ModuleAddress::new(binary.clone(), unsupported_pc))?;
    let error = analyzer
        .plan_variable_by_name(&context, "value")
        .expect_err("active unsupported entry-value expression should fail");
    anyhow::ensure!(error.to_string().contains("unsupported DW_OP_entry_value"));

    let target = TargetLauncher::binary(&binary).spawn().await?;
    let result = GhostscopeRunner::new()
        .with_target(&binary)
        .attach_to(&target)
        .with_script(&format!(
            "trace 0x{active_pc:x} {{ print \"LOCATION_VALUE:{{}}\", value; }}"
        ))
        .timeout_secs(2)
        .run()
        .await;
    target.terminate().await?;
    let (exit_code, stdout, stderr) = result?;
    assert_eq!(exit_code, 0, "DWARF {version}: {stderr}\n{stdout}");
    assert!(
        stdout.contains("LOCATION_VALUE:42"),
        "DWARF {version}: active register value was not captured: {stderr}\n{stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_dwarf_semantics_location_list_dwarf4() -> anyhow::Result<()> {
    check_location_list_at_probe_pc(4).await
}

#[tokio::test]
async fn test_dwarf_semantics_location_list_dwarf5() -> anyhow::Result<()> {
    check_location_list_at_probe_pc(5).await
}

fn runtime_module(path: &Path) -> LoadedModuleRuntimeInfo {
    LoadedModuleRuntimeInfo {
        module_path: path.to_path_buf(),
        loaded_address: None,
        load_bias: None,
        size: 0,
    }
}

#[tokio::test]
async fn test_dwarf_semantics_module_identity_after_refresh() -> anyhow::Result<()> {
    init();
    let dir = fixture_dir()?;
    let source = dir.path().join("original.c");
    let original = dir.path().join("z-original");
    fs::write(
        &source,
        "struct Record { int value; };\n\
         struct Record record = {42};\n\
         int identity_probe(struct Record *arg) { return arg->value; }\n\
         int main(void) { return identity_probe(&record); }\n",
    )?;
    run_command(
        Command::new("cc")
            .args(["-g", "-O0", "-o"])
            .arg(&original)
            .arg(&source),
    )?;

    let mut analyzer = DwarfAnalyzer::from_exec_path(&original).await?;
    let address = analyzer
        .lookup_function_addresses("identity_probe")
        .into_iter()
        .next()
        .context("missing identity_probe")?;
    let context = analyzer.resolve_pc(&address)?;
    let plan = analyzer
        .plan_variable_by_name(&context, "arg")?
        .context("missing parameter")?;
    let variable = VariableId {
        declaration: plan.declaration.context("missing parameter identity")?,
    };
    let resolved = analyzer
        .resolved_type_for_plan(&plan)?
        .context("missing parameter type")?;
    let pointee = analyzer.project_resolved_type(
        &resolved,
        &VariableAccessSegment::Dereference,
        Some(&original),
    )?;
    let module_id = context.module;

    let added = dir.path().join("a-added.so");
    let retry = dir.path().join("b-retry.so");
    let alias = dir.path().join("0-original-alias");
    std::os::unix::fs::symlink(&original, &alias)?;
    let source = dir.path().join("added.c");
    fs::write(
        &source,
        "struct Other { double other; }; struct Other other;\n",
    )?;
    run_command(
        Command::new("cc")
            .args(["-g", "-O0", "-shared", "-fPIC", "-o"])
            .arg(&added)
            .arg(&source),
    )?;
    fs::write(&retry, b"invalid ELF")?;

    for repaired in [false, true] {
        if repaired {
            fs::copy(&added, &retry)?;
        }
        assert_eq!(
            analyzer
                .refresh_pid_runtime_modules_with_config_and_debuginfod(
                    vec![
                        runtime_module(&alias),
                        runtime_module(&added),
                        runtime_module(&retry)
                    ],
                    &[],
                    false,
                    None,
                    |_| {},
                )
                .await?,
            1
        );
        assert_eq!(
            analyzer.module_path_for_id(module_id),
            Some(original.as_path()),
            "refresh redirected the saved module identity"
        );
        assert_eq!(analyzer.module_id_for_path(&alias), Some(module_id));
        assert_eq!(analyzer.module_paths().len(), if repaired { 3 } else { 2 });
        assert_eq!(
            analyzer.module_load_failures().len(),
            usize::from(!repaired)
        );
        let refreshed_plan = analyzer
            .plan_variable(&context, variable)?
            .context("saved variable identity stopped resolving after refresh")?;
        assert_eq!(refreshed_plan.type_id, plan.type_id);
        assert_eq!(
            analyzer.project_resolved_type(
                &resolved,
                &VariableAccessSegment::Dereference,
                Some(&original),
            )?,
            pointee,
            "saved type identity changed after refresh"
        );
        assert_eq!(analyzer.resolve_pc(&address)?.module, module_id);
    }
    Ok(())
}

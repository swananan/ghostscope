#[path = "support/supplementary.rs"]
mod fixture;
use ghostscope_dwarf::{DwarfAnalyzer, DwarfObjectId, VariableAccessPath, VariableAccessSegment};

#[tokio::test]
async fn supplementary_rust_types_inherit_importer_metadata() -> anyhow::Result<()> {
    for standard in [false, true] {
        for dwarf64 in [false, true] {
            let dir = tempfile::tempdir()?;
            let fixture = fixture::build_rust(dir.path(), standard, dwarf64)?;
            let analyzer = DwarfAnalyzer::from_exec_path(&fixture.binary).await?;
            let path = VariableAccessPath::new(vec![VariableAccessSegment::TupleIndex(0)]);
            let (_, plan) = analyzer
                .plan_global_access_read_plan(&fixture.binary, "payload", &path)?
                .expect("Rust tuple element plan");
            let id = plan.type_id.expect("tuple element identity");
            assert_eq!(id.cu.1, DwarfObjectId::Supplementary);
            let origin = analyzer.type_origin(id)?.expect("inherited origin");
            assert_eq!(origin.language, ghostscope_dwarf::SourceLanguage::Rust);
            assert_eq!(origin.rustc_version().unwrap().minor, 88);
            assert_eq!(origin.cu, id.cu);
            assert_eq!(origin.dwarf_version, if standard { 5 } else { 4 });
            let physical = analyzer
                .compilation_unit_metadata(id.module, id.cu)?
                .unwrap();
            assert_eq!(physical.language, ghostscope_dwarf::SourceLanguage::Unknown);
            assert!(physical.producer.is_none());
            let imported = analyzer.resolve_c_style_semantic_type_spec("SharedAlias");
            // Direct named lookups must carry the import context as well.
            let (_, message) = analyzer
                .plan_global_access_read_plan(
                    &fixture.binary,
                    "message",
                    &VariableAccessPath::default(),
                )?
                .expect("Rust string plan");
            let id = message.type_id.unwrap();
            let resolved = ghostscope_dwarf::ResolvedType::new(
                message.dwarf_type.unwrap(),
                ghostscope_dwarf::TypeIdentity::Dwarf(id),
                analyzer.type_origin(id)?,
            );
            let report = analyzer.explain_value_read_plan(&resolved, Some(&fixture.binary))?;
            assert_eq!(report.adapter.as_deref(), Some("&str"));
            assert!(matches!(
                report.outcome,
                ghostscope_dwarf::ValueAdapterOutcome::Applied { .. }
            ));
            let imported = imported.expect("imported Rust type");
            assert_eq!(
                imported.origin.unwrap().language,
                ghostscope_dwarf::SourceLanguage::Rust
            );
            let (_, foreign) = analyzer
                .plan_global_access_read_plan(
                    &fixture.binary,
                    "foreign_payload",
                    &VariableAccessPath::default(),
                )?
                .unwrap();
            let foreign_id = foreign.type_id.unwrap();
            let origin = analyzer.type_origin(foreign_id)?.unwrap();
            assert_eq!(origin.language, ghostscope_dwarf::SourceLanguage::C);
            assert_eq!(origin.producer.unwrap().raw, "fixture C compiler");
            assert!(analyzer
                .plan_global_access_read_plan(&fixture.binary, "foreign_payload", &path)
                .is_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn supplementary_types_support_member_projection_and_imported_name_lookup(
) -> anyhow::Result<()> {
    for standard in [false, true] {
        for dwarf64 in [false, true] {
            let dir = tempfile::tempdir()?;
            let fixture = fixture::build(dir.path(), standard, dwarf64)?;
            let analyzer = DwarfAnalyzer::from_exec_path(&fixture.binary).await?;
            assert!(!analyzer.lookup_function_addresses("tick").is_empty());
            let path = VariableAccessPath::new(vec![VariableAccessSegment::Field("second".into())]);
            let (_, plan) = analyzer
                .plan_global_access_read_plan(&fixture.binary, "payload", &path)?
                .expect("member plan");
            assert_eq!(
                plan.type_id.expect("member type identity").cu.1,
                DwarfObjectId::Supplementary
            );
            assert_eq!(
                analyzer
                    .type_origin(plan.type_id.unwrap())?
                    .unwrap()
                    .dwarf_version,
                if standard { 5 } else { 4 }
            );
            let ty = analyzer
                .resolve_struct_type_shallow_by_name_in_module(&fixture.binary, "Shared")
                .expect("imported type");
            assert_eq!(ty.size(), 8);
        }
    }
    Ok(())
}

#[tokio::test]
async fn inline_origins_and_abstract_parameters_retain_supplementary_identity() -> anyhow::Result<()>
{
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let fixture = fixture::build(dir.path(), standard, false)?;
        let analyzer = DwarfAnalyzer::from_exec_path(&fixture.binary).await?;
        let mut pc = analyzer.lookup_function_addresses("tick").remove(0);
        pc.address += 1;
        let context = analyzer.resolve_pc(&pc)?;
        let origin = context
            .inline_chain
            .last()
            .expect("inline frame")
            .abstract_origin
            .expect("abstract origin");
        assert_eq!(origin.cu.1, DwarfObjectId::Supplementary);
        let variables = analyzer.visible_variables(&context)?;
        let parameter = variables
            .iter()
            .find(|variable| variable.name == "parameter")
            .expect("abstract parameter");
        assert_eq!(
            parameter.declaration.expect("parameter identity").cu.1,
            DwarfObjectId::Supplementary
        );
        assert_eq!(
            parameter.type_id.expect("parameter type").cu.1,
            DwarfObjectId::Supplementary
        );
        assert_eq!(
            analyzer
                .type_origin(parameter.type_id.unwrap())?
                .unwrap()
                .language,
            ghostscope_dwarf::SourceLanguage::C,
        );
        assert_eq!(parameter.type_name, "int");
    }
    Ok(())
}

#[tokio::test]
async fn missing_supplement_is_reported_as_a_loading_error() -> anyhow::Result<()> {
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let fixture = fixture::build(dir.path(), standard, false)?;
        std::fs::remove_file(fixture.supplementary)?;
        let error = DwarfAnalyzer::from_exec_path(&fixture.binary)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("required supplementary DWARF"),
            "{error:#}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn separate_primary_debug_file_resolves_its_own_relative_supplement() -> anyhow::Result<()> {
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let fixture = fixture::build(dir.path(), standard, false)?;
        let debug_dir = dir.path().join(".debug");
        std::fs::create_dir(&debug_dir)?;
        let debug = debug_dir.join("program.debug");
        let run = |command: &mut std::process::Command| -> anyhow::Result<()> {
            let output = command.output()?;
            anyhow::ensure!(output.status.success(), "{command:?}: {output:?}");
            Ok(())
        };
        run(std::process::Command::new("objcopy")
            .arg("--only-keep-debug")
            .arg(&fixture.binary)
            .arg(&debug))?;
        std::fs::rename(&fixture.supplementary, debug_dir.join("shared.debug"))?;
        run(std::process::Command::new("objcopy")
            .arg("--strip-debug")
            .arg(&fixture.binary))?;
        run(std::process::Command::new("objcopy")
            .arg(format!("--add-gnu-debuglink={}", debug.display()))
            .arg(&fixture.binary))?;
        let analyzer = DwarfAnalyzer::from_exec_path(&fixture.binary).await?;
        let path = VariableAccessPath::new(vec![VariableAccessSegment::Field("second".into())]);
        assert!(analyzer
            .plan_global_access_read_plan(&fixture.binary, "payload", &path)?
            .is_some());
    }
    Ok(())
}

#[tokio::test]
async fn supplementary_identity_mismatch_is_rejected_even_in_loose_mode() -> anyhow::Result<()> {
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let fixture = fixture::build(dir.path(), standard, false)?;
        let mut bytes = std::fs::read(&fixture.supplementary)?;
        let index = bytes
            .windows(4)
            .position(|window| window == [0x12, 0x34, 0x56, 0x78])
            .unwrap();
        bytes[index] ^= 0xff;
        std::fs::write(&fixture.supplementary, bytes)?;
        let error = DwarfAnalyzer::from_exec_path_with_config(&fixture.binary, &[], true)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("mismatch"), "{error:#}");
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires dwz; set GHOSTSCOPE_DWZ to its executable path"]
async fn real_dwz_multifile_supports_global_member_queries() -> anyhow::Result<()> {
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let fixture = fixture::build(dir.path(), false, false)?;
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        for binary in [&first, &second] {
            let output = std::process::Command::new("cc")
                .args(["-g", "-gdwarf-4", "-O0", "-o"])
                .arg(binary)
                .arg(dir.path().join("program.c"))
                .output()?;
            anyhow::ensure!(output.status.success(), "{output:?}");
        }
        std::fs::remove_file(fixture.supplementary)?;
        let dwz = std::env::var_os("GHOSTSCOPE_DWZ").unwrap_or_else(|| "dwz".into());
        let mut command = std::process::Command::new(dwz);
        if standard {
            command.arg("-5");
        }
        let output = command
            .arg("-r")
            .arg("-m")
            .arg(dir.path().join("shared.debug"))
            .arg(&first)
            .arg(&second)
            .output()?;
        anyhow::ensure!(output.status.success(), "dwz failed: {output:?}");
        let analyzer = DwarfAnalyzer::from_exec_path(&first).await?;
        let path = VariableAccessPath::new(vec![VariableAccessSegment::Field("second".into())]);
        assert!(analyzer
            .plan_global_access_read_plan(&first, "payload", &path)?
            .is_some());
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires dwz; set GHOSTSCOPE_DWZ to its executable path"]
async fn real_dwz_rust_types_keep_tuple_access_and_value_adapters() -> anyhow::Result<()> {
    for standard in [false, true] {
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("payload.rs");
        std::fs::write(
            &source,
            r##"#![no_std]
#[no_mangle] pub static PAYLOAD: (i32, i32) = (1234, 5678);
#[no_mangle] pub static MESSAGE: &str = "supplement";
#[no_mangle] pub extern "C" fn tick() -> i32 {
    core::hint::black_box(PAYLOAD).0
}
"##,
        )?;
        let object = dir.path().join("payload.o");
        let output = std::process::Command::new("rustc")
            .args([
                "--crate-type=lib",
                "--emit=obj",
                "-g",
                "-C",
                "dwarf-version=4",
                "-C",
                "panic=abort",
                "-o",
            ])
            .arg(&object)
            .arg(&source)
            .output()?;
        anyhow::ensure!(output.status.success(), "rustc: {output:?}");
        let main = dir.path().join("main.c");
        std::fs::write(
            &main,
            "extern int tick(void); int main(void) { return tick(); }\n",
        )?;
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        let output = std::process::Command::new("cc")
            .args(["-g0", "-no-pie", "-o"])
            .arg(&first)
            .arg(&main)
            .arg(&object)
            .output()?;
        anyhow::ensure!(output.status.success(), "cc: {output:?}");
        std::fs::copy(&first, &second)?;
        let check = async |supplemented| -> anyhow::Result<()> {
            let analyzer = DwarfAnalyzer::from_exec_path(&first).await?;
            let path = VariableAccessPath::new(vec![VariableAccessSegment::TupleIndex(0)]);
            let (_, tuple) = analyzer
                .plan_global_access_read_plan(&first, "PAYLOAD", &path)?
                .unwrap();
            let id = tuple.type_id.unwrap();
            assert_eq!(id.cu.1 == DwarfObjectId::Supplementary, supplemented);
            let origin = analyzer.type_origin(id)?.unwrap();
            assert_eq!(origin.language, ghostscope_dwarf::SourceLanguage::Rust);
            assert!(origin.rustc_version().is_some());
            if supplemented {
                let physical = analyzer
                    .compilation_unit_metadata(id.module, id.cu)?
                    .unwrap();
                assert_eq!(physical.language, ghostscope_dwarf::SourceLanguage::Unknown);
                assert!(physical.producer.is_none());
            }
            let (_, message) = analyzer
                .plan_global_access_read_plan(&first, "MESSAGE", &VariableAccessPath::default())?
                .unwrap();
            let id = message.type_id.unwrap();
            assert_eq!(id.cu.1 == DwarfObjectId::Supplementary, supplemented);
            let resolved = ghostscope_dwarf::ResolvedType::new(
                message.dwarf_type.unwrap(),
                ghostscope_dwarf::TypeIdentity::Dwarf(id),
                analyzer.type_origin(id)?,
            );
            let report = analyzer.explain_value_read_plan(&resolved, Some(&first))?;
            assert_eq!(report.adapter.as_deref(), Some("&str"));
            assert!(matches!(
                report.outcome,
                ghostscope_dwarf::ValueAdapterOutcome::Applied { .. }
            ));
            Ok(())
        };
        check(false).await?;
        let dwz = std::env::var_os("GHOSTSCOPE_DWZ").unwrap_or_else(|| "dwz".into());
        let mut command = std::process::Command::new(dwz);
        if standard {
            command.arg("-5");
        }
        let output = command
            .arg("-r")
            .arg("-m")
            .arg(dir.path().join("shared.debug"))
            .arg(&first)
            .arg(&second)
            .output()?;
        anyhow::ensure!(output.status.success(), "dwz: {output:?}");
        check(true).await?;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires dwz and gdb-add-index; set GHOSTSCOPE_DWZ to its executable path"]
async fn real_dwz_indexed_pointer_resolves_cross_cu_definition() -> anyhow::Result<()> {
    use std::process::Command;
    let dir = tempfile::tempdir()?;
    let source = |name: &str, text: &str| -> anyhow::Result<std::path::PathBuf> {
        let path = dir.path().join(name);
        std::fs::write(&path, text)?;
        Ok(path)
    };
    let main = source("main.c", "struct Cross; extern struct Cross instance; struct Cross *pointer = &instance; int shared_value(void); int main(void) { return shared_value() + (pointer != 0); }\n")?;
    let definition = source(
        "definition.c",
        "struct Cross { int first; long second; }; struct Cross instance = {17, 23};\n",
    )?;
    let peer_definition = source("peer.c", "long instance[2] = {17, 23};\n")?;
    let common = source("common.c", "struct Shared { int first; int second; }; struct Shared shared = {1, 2}; int shared_value(void) { return shared.first; }\n")?;
    let first = dir.path().join("first");
    let second = dir.path().join("second");
    for (binary, definition) in [(&first, &definition), (&second, &peer_definition)] {
        let output = Command::new("cc")
            .args(["-g", "-gdwarf-4", "-O0", "-no-pie", "-o"])
            .arg(binary)
            .arg(&main)
            .arg(definition)
            .arg(&common)
            .output()?;
        anyhow::ensure!(output.status.success(), "cc: {output:?}");
    }
    let dwz = std::env::var_os("GHOSTSCOPE_DWZ").unwrap_or_else(|| "dwz".into());
    let output = Command::new(dwz)
        .arg("-r")
        .arg("-m")
        .arg(dir.path().join("shared.debug"))
        .arg(&first)
        .arg(&second)
        .output()?;
    anyhow::ensure!(output.status.success(), "dwz: {output:?}");
    let binary_bytes = std::fs::read(&first)?;
    let shared = dir.path().join("shared.debug");
    let shared_bytes = std::fs::read(&shared)?;
    for kind in ["full-scan", "gdb-index", "debug-names"] {
        std::fs::write(&first, &binary_bytes)?;
        std::fs::write(&shared, &shared_bytes)?;
        if kind != "full-scan" {
            let mut command = Command::new("gdb-add-index");
            if kind == "debug-names" {
                command.arg("-dwarf-5");
            }
            let output = command.arg(&first).current_dir(dir.path()).output()?;
            anyhow::ensure!(output.status.success(), "gdb-add-index: {output:?}");
        }
        let selected = std::sync::Arc::new(std::sync::Mutex::new(None));
        let observed = std::sync::Arc::clone(&selected);
        let analyzer = DwarfAnalyzer::from_exec_path_with_config_and_progress(
            &first,
            &[],
            false,
            move |event| {
                if let ghostscope_dwarf::ModuleLoadingEvent::LoadingCompleted { stats, .. } = event
                {
                    assert!(stats.supplementary_debug_file.is_some());
                    *observed.lock().unwrap() = Some(stats.dwarf_index_status);
                }
            },
        )
        .await?;
        let selected = selected.lock().unwrap().clone().unwrap();
        assert!(
            match &selected {
                ghostscope_dwarf::DwarfIndexStatus::FullScan => kind == "full-scan",
                ghostscope_dwarf::DwarfIndexStatus::GdbIndex { .. } => kind == "gdb-index",
                ghostscope_dwarf::DwarfIndexStatus::DebugNames => kind == "debug-names",
                _ => false,
            },
            "{kind}: {selected:?}"
        );
        let (_, plan) = analyzer
            .plan_global_access_read_plan(&first, "pointer", &VariableAccessPath::default())?
            .unwrap();
        let pointer = analyzer.resolved_type_for_plan(&plan)?.unwrap();
        let projected = analyzer.project_resolved_type(
            &pointer,
            &VariableAccessSegment::Dereference,
            Some(&first),
        )?;
        assert_eq!(projected.resolved_type.summary.size(), 16, "{kind}");
        let member = analyzer.project_resolved_type(
            &projected.resolved_type,
            &VariableAccessSegment::Field("second".into()),
            Some(&first),
        )?;
        assert_eq!(member.resolved_type.summary.size(), 8, "{kind}");
    }
    Ok(())
}

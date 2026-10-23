#[path = "../../tests/support/supplementary.rs"]
mod fixture;
#[path = "../../tests/support/supplementary_indexes.rs"]
mod indexes;

use super::LoadedObjfile;
use crate::{core::mapping::ModuleMapping, DwarfIndexStatus, DwarfObjectId};
use indexes::Index;

#[tokio::test]
async fn supplementary_accelerators_keep_cu_parsing_and_type_imports_lazy() -> anyhow::Result<()> {
    for index in [
        Index::GnuPubNames,
        Index::Gdb,
        Index::DebugNames,
        Index::GdbDebugNames,
    ] {
        for standard in [false, true] {
            for dwarf64 in [false, true] {
                let dir = tempfile::tempdir()?;
                let fixture = fixture::build_rust(dir.path(), standard, dwarf64)?;
                assert!(fixture.supplementary.exists());
                indexes::add_index(&fixture.binary, index)?;
                let module = LoadedObjfile::load_parallel(
                    ModuleMapping::from_path(fixture.binary),
                    &[],
                    false,
                    None,
                    None,
                )
                .await?;
                assert!(
                    match index {
                        Index::GnuPubNames =>
                            matches!(module.dwarf_index_status, DwarfIndexStatus::GnuPubNames),
                        Index::Gdb =>
                            matches!(module.dwarf_index_status, DwarfIndexStatus::GdbIndex { .. }),
                        Index::DebugNames | Index::GdbDebugNames =>
                            matches!(module.dwarf_index_status, DwarfIndexStatus::DebugNames),
                    },
                    "{index:?}: {:?}",
                    module.dwarf_index_status
                );
                assert!(module.indexed_debug_info_cus.lock().unwrap().is_empty());
                assert!(!module.type_name_index.read().unwrap().imports_indexed());
                assert!(
                    !module.lookup_function_addresses("tick").is_empty(),
                    "{index:?}"
                );
                assert_eq!(module.indexed_debug_info_cus.lock().unwrap().len(), 1);
                assert!(!module.type_name_index.read().unwrap().imports_indexed());

                let before = module
                    .type_name_index()?
                    .find_typedef("SharedAlias")
                    .unwrap();
                assert_eq!(before.object, DwarfObjectId::Supplementary);
                assert!(before.importing_cu.is_some());

                // Loading the other CU must retain the already indexed imports.
                assert!(!module
                    .find_global_variables_by_name("foreign_payload")
                    .is_empty());
                assert_eq!(module.indexed_debug_info_cus.lock().unwrap().len(), 2);
                let after = module
                    .type_name_index()?
                    .find_typedef("SharedAlias")
                    .unwrap();
                assert_eq!(after.object, before.object);
                assert_eq!(after.importing_cu, before.importing_cu);
                assert_eq!(after.cu_offset, before.cu_offset);
                assert_eq!(after.die_offset, before.die_offset);
                let (ty, _) = module
                    .resolve_type_shallow_by_name_with_tags_and_loc(
                        "SharedAlias",
                        &[gimli::DW_TAG_structure_type],
                    )
                    .expect("imported alias after lazy CU materialization");
                assert_eq!(ty.size(), 8);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn supplementary_full_scan_defers_type_imports_until_a_type_query() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let fixture = fixture::build(dir.path(), false, false)?;
    let module = LoadedObjfile::load_parallel(
        ModuleMapping::from_path(fixture.binary),
        &[],
        false,
        None,
        None,
    )
    .await?;
    assert!(matches!(
        module.dwarf_index_status,
        DwarfIndexStatus::FullScan
    ));
    assert!(!module.type_name_index.read().unwrap().imports_indexed());
    let (ty, _) = module
        .resolve_type_shallow_by_name_with_tags_and_loc("Shared", &[gimli::DW_TAG_structure_type])
        .expect("imported aggregate without an accelerator");
    assert_eq!(ty.size(), 8);
    assert!(module.type_name_index.read().unwrap().imports_indexed());
    Ok(())
}

#[tokio::test]
async fn supplementary_rejected_accelerator_falls_back_to_working_dwarf() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let fixture = fixture::build(dir.path(), true, false)?;
    let index = dir.path().join("bad-index");
    std::fs::write(&index, b"truncated")?;
    let output = std::process::Command::new("objcopy")
        .arg("--add-section")
        .arg(format!(".gdb_index={}", index.display()))
        .arg(&fixture.binary)
        .output()?;
    anyhow::ensure!(output.status.success(), "{output:?}");
    let module = LoadedObjfile::load_parallel(
        ModuleMapping::from_path(fixture.binary),
        &[],
        false,
        None,
        None,
    )
    .await?;
    assert!(matches!(
        module.dwarf_index_status,
        DwarfIndexStatus::Rejected { .. }
    ));
    assert!(!module.lookup_function_addresses("tick").is_empty());
    let (ty, _) = module
        .resolve_type_shallow_by_name_with_tags_and_loc(
            "SharedAlias",
            &[gimli::DW_TAG_structure_type],
        )
        .expect("imported alias after rejecting an accelerator");
    assert_eq!(ty.size(), 8);
    Ok(())
}

#[tokio::test]
async fn cross_cu_declarations_load_definitions_only_when_projected() -> anyhow::Result<()> {
    use crate::{semantics::resolve_type_ref_with_origins, ModuleId, VariableAccessSegment};
    for index in [
        Index::GnuPubNames,
        Index::Gdb,
        Index::DebugNames,
        Index::GdbDebugNames,
    ] {
        for standard in [false, true] {
            let dir = tempfile::tempdir()?;
            let fixture = build_cross_cu_fixture(dir.path(), standard)?;
            indexes::add_index(&fixture.binary, index)?;
            for segment in [
                VariableAccessSegment::Dereference,
                VariableAccessSegment::Field("second".into()),
            ] {
                let module = LoadedObjfile::load_parallel(
                    ModuleMapping::from_path(fixture.binary.clone()),
                    &[],
                    false,
                    None,
                    None,
                )
                .await?;
                assert!(
                    module.lazy_debug_info,
                    "{index:?}: {:?}",
                    module.dwarf_index_status
                );
                assert!(module.indexed_debug_info_cus.lock().unwrap().is_empty());
                let pointer = module.find_global_variables_by_name("pointer").remove(0);
                assert_eq!(module.indexed_debug_info_cus.lock().unwrap().len(), 1);
                let unit = module.unit(pointer.unit_offset)?;
                let entry = unit.entry(pointer.die_offset)?;
                let pointer_type = resolve_type_ref_with_origins(module.dwarf(), &entry, &unit)?
                    .unwrap()
                    .type_id(ModuleId(0));
                let projected = module.projected_type_id(pointer_type, &segment)?.unwrap();
                let summary = module.type_summary(projected)?.unwrap();
                assert_eq!(
                    summary.size(),
                    if segment == VariableAccessSegment::Dereference {
                        16
                    } else {
                        8
                    },
                    "{index:?}, {segment:?}"
                );
                assert_eq!(
                    module.indexed_debug_info_cus.lock().unwrap().len(),
                    2,
                    "unrelated CU must remain lazy: {index:?}"
                );
                if segment == VariableAccessSegment::Dereference {
                    assert_eq!(module.type_alignment(projected)?, Some(16));
                }
                let opaque = module.find_global_variables_by_name("opaque").remove(0);
                let entry = unit.entry(opaque.die_offset)?;
                let opaque_type = resolve_type_ref_with_origins(module.dwarf(), &entry, &unit)?
                    .unwrap()
                    .type_id(ModuleId(0));
                let opaque = module
                    .projected_type_id(opaque_type, &VariableAccessSegment::Dereference)?
                    .unwrap();
                assert_eq!(module.type_summary(opaque)?.unwrap().size(), 0);
            }
        }
    }
    Ok(())
}

fn build_cross_cu_fixture(
    dir: &std::path::Path,
    standard: bool,
) -> anyhow::Result<fixture::Fixture> {
    use object::{Object, ObjectSection};
    use std::process::Command;
    let run = |command: &mut Command| -> anyhow::Result<()> {
        let output = command.output()?;
        anyhow::ensure!(output.status.success(), "{command:?}: {output:?}");
        Ok(())
    };
    let fixture = fixture::build(dir, standard, false)?;
    let data = std::fs::read(&fixture.binary)?;
    let object = object::File::parse(data.as_slice())?;
    let section_name = if standard {
        ".debug_sup"
    } else {
        ".gnu_debugaltlink"
    };
    let link = dir.join("cross-cu-link");
    std::fs::write(&link, object.section_by_name(section_name).unwrap().data()?)?;
    let main = dir.join("cross-main.c");
    let definition = dir.join("cross-definition.c");
    let unrelated = dir.join("cross-unrelated.c");
    std::fs::write(&main, "struct Cross; typedef const struct Cross CrossAlias; extern struct Cross instance; CrossAlias *pointer = &instance; struct Opaque *opaque; int main(void) { return pointer != 0; }\n")?;
    std::fs::write(&definition, "struct __attribute__((aligned(16))) Cross { int first; long second; }; struct Cross instance = {17, 23};\n")?;
    std::fs::write(
        &unrelated,
        "struct Unrelated { long value; }; struct Unrelated unrelated;\n",
    )?;
    run(Command::new("cc")
        .args(["-g", "-gdwarf-4", "-O0", "-no-pie", "-o"])
        .arg(&fixture.binary)
        .arg(main)
        .arg(definition)
        .arg(unrelated))?;
    run(Command::new("objcopy")
        .arg(format!("--add-section={section_name}={}", link.display()))
        .arg(&fixture.binary))?;
    Ok(fixture)
}

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

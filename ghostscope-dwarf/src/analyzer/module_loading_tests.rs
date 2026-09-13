use super::{DwarfAnalyzer, LoadedModuleRuntimeInfo, ModuleDefaultPolicy, ModuleLoadingEvent};
use crate::{
    core::mapping::ModuleMapping,
    loader::{ExplicitDebugFile, ModuleLoader},
    ModuleAddress, VariableAccessPath,
};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

fn write_module(path: &Path) {
    use gimli::write::{Address, AttributeValue, Dwarf, EndianVec, LineProgram, Sections, Unit};

    let mut object = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    let text = object.section_id(object::write::StandardSection::Text);
    object.append_section_data(text, &[0x90; 16], 1);
    object.add_symbol(object::write::Symbol {
        name: b"working_function".to_vec(),
        value: 1,
        size: 1,
        kind: object::SymbolKind::Text,
        scope: object::SymbolScope::Linkage,
        weak: false,
        section: object::write::SymbolSection::Section(text),
        flags: object::SymbolFlags::None,
    });
    let mut dwarf = Dwarf::new();
    let unit_id = dwarf.units.add(Unit::new(
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        },
        LineProgram::none(),
    ));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(1)),
    );
    unit.get_mut(root)
        .set(gimli::DW_AT_high_pc, AttributeValue::Udata(1));
    let function = unit.add(root, gimli::DW_TAG_subprogram);
    let entry = unit.get_mut(function);
    entry.set(
        gimli::DW_AT_name,
        AttributeValue::String(b"working_function".to_vec()),
    );
    entry.set(
        gimli::DW_AT_low_pc,
        AttributeValue::Address(Address::Constant(1)),
    );
    entry.set(gimli::DW_AT_high_pc, AttributeValue::Udata(1));
    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections).unwrap();
    sections
        .for_each(|id, data| {
            if !data.slice().is_empty() {
                let section = object.add_section(
                    Vec::new(),
                    id.name().as_bytes().to_vec(),
                    object::SectionKind::Debug,
                );
                object.append_section_data(section, data.slice(), 1);
            }
            Ok::<_, std::convert::Infallible>(())
        })
        .unwrap();
    std::fs::write(path, object.write().unwrap()).unwrap();
}

fn runtime_module(path: &Path) -> LoadedModuleRuntimeInfo {
    LoadedModuleRuntimeInfo {
        module_path: path.to_path_buf(),
        loaded_address: Some(0x1000),
        load_bias: Some(0x1000),
        size: 0x100,
    }
}

async fn load(paths: &[&Path]) -> DwarfAnalyzer {
    DwarfAnalyzer::from_pid_runtime_modules_with_config_and_debuginfod(
        0,
        paths.iter().map(|path| runtime_module(path)).collect(),
        &[],
        false,
        None,
        |_| {},
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn optional_failure_preserves_working_queries_and_reports_failed_queries() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.so");
    let bad = dir.path().join("bad.so");
    write_module(&good);
    std::fs::write(&bad, b"invalid ELF").unwrap();
    let analyzer = load(&[&bad, &good]).await;

    assert_eq!(analyzer.module_paths(), vec![good.clone()]);
    let failures = analyzer.module_load_failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].module_path, bad);
    assert!(failures[0].error.contains("Failed to parse target object"));
    let query = analyzer.query_function("working_function").unwrap();
    assert_eq!(query.addresses.len(), 1);
    assert_eq!(query.addresses[0].module_path, good);
    assert!(analyzer.query_address(&good, 1).is_ok());
    assert_eq!(
        analyzer.resolve_loaded_module_by_spec("good.so").unwrap(),
        good
    );

    let errors = [
        analyzer.query_address(&bad, 1).unwrap_err(),
        analyzer
            .resolve_pc(&ModuleAddress::new(bad.clone(), 1))
            .unwrap_err(),
        analyzer
            .recover_caller_frame(&ModuleAddress::new(bad.clone(), 1), &[])
            .unwrap_err(),
        analyzer
            .resolve_loaded_module_by_spec("bad.so")
            .unwrap_err(),
        analyzer
            .resolve_target_module_path(bad.to_str().unwrap())
            .unwrap_err(),
        analyzer
            .plan_global_access_read_plan(&bad, "global", &VariableAccessPath::default())
            .unwrap_err(),
        analyzer
            .plan_global_access_read_plan_at_address(
                &ModuleAddress::new(bad.clone(), 1),
                "global",
                &VariableAccessPath::default(),
            )
            .unwrap_err(),
        analyzer
            .try_resolve_type_spec_in_module(&bad, "int")
            .unwrap_err(),
        analyzer
            .resolve_source_line_addresses_best_effort(
                ["missing.c"],
                1,
                Some(bad.to_str().unwrap()),
            )
            .unwrap_err(),
        analyzer
            .filter_module_addresses_to_target(Vec::new(), Some(bad.to_str().unwrap()))
            .unwrap_err(),
        analyzer
            .filter_address_results_to_target(Vec::new(), Some(bad.to_str().unwrap()))
            .unwrap_err(),
    ];
    for error in errors {
        let failure = error.downcast_ref::<super::ModuleLoadFailure>().unwrap();
        assert_eq!(failure.module_path, bad);
        assert!(failure.error.contains("Failed to parse target object"));
    }
    assert!(analyzer.resolve_type_spec_in_module(&bad, "int").is_none());
}

#[tokio::test]
async fn malformed_optional_dwarf_preserves_healthy_module_queries() {
    use object::{Object, ObjectSection};

    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.so");
    let bad = dir.path().join("bad.so");
    write_module(&good);
    write_module(&bad);
    let mut bytes = std::fs::read(&bad).unwrap();
    let object = object::File::parse(bytes.as_slice()).unwrap();
    let (offset, _) = object
        .section_by_name(".debug_info")
        .unwrap()
        .file_range()
        .unwrap();
    // A reserved DWARF unit length keeps the ELF valid but makes parsing fail.
    bytes[offset as usize..offset as usize + 4].copy_from_slice(&0xfffffff0u32.to_le_bytes());
    std::fs::write(&bad, bytes).unwrap();
    let analyzer = load(&[&bad, &good]).await;
    assert_eq!(analyzer.module_load_failures().len(), 1);
    assert_eq!(analyzer.module_load_failures()[0].module_path, bad);
    let query = analyzer.query_function("working_function").unwrap();
    assert_eq!(query.addresses.len(), 1);
    assert_eq!(query.addresses[0].module_path, good);
    assert!(analyzer
        .query_address(&bad, 1)
        .unwrap_err()
        .downcast_ref::<super::ModuleLoadFailure>()
        .is_some());
}

#[tokio::test]
async fn failed_module_does_not_make_a_suffix_or_default_unambiguous() {
    let dir = tempfile::tempdir().unwrap();
    let good_dir = dir.path().join("good");
    let bad_dir = dir.path().join("bad");
    std::fs::create_dir(&good_dir).unwrap();
    std::fs::create_dir(&bad_dir).unwrap();
    let good = good_dir.join("libsame.so");
    let bad = bad_dir.join("libsame.so");
    write_module(&good);
    let analyzer = load(&[&good, &bad]).await;

    let error = analyzer
        .resolve_loaded_module_by_spec("libsame.so")
        .unwrap_err()
        .to_string();
    assert!(error.contains("Ambiguous module suffix"));
    assert!(error.contains(good.to_str().unwrap()));
    assert!(error.contains(bad.to_str().unwrap()));
    assert!(analyzer
        .resolve_address_module(
            None,
            None,
            ModuleDefaultPolicy::MainExecutableOrSingleSharedLibrary
        )
        .is_err());
    assert!(analyzer
        .resolve_loaded_module_by_spec(bad.to_str().unwrap())
        .unwrap_err()
        .to_string()
        .contains("failed to load"));
    assert_eq!(
        analyzer
            .resolve_loaded_module_by_spec(good.to_str().unwrap())
            .unwrap(),
        good
    );
}

#[tokio::test]
async fn refresh_retains_successes_and_clears_failure_after_retry() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original.so");
    let good = dir.path().join("good.so");
    let bad = dir.path().join("bad.so");
    write_module(&original);
    write_module(&good);
    let mut analyzer = load(&[&original]).await;
    let refresh = vec![runtime_module(&good), runtime_module(&bad)];
    assert_eq!(
        analyzer
            .refresh_pid_runtime_modules_with_config_and_debuginfod(
                refresh.clone(),
                &[],
                false,
                None,
                |_| {}
            )
            .await
            .unwrap(),
        1
    );
    assert_eq!(analyzer.module_paths().len(), 2);
    assert_eq!(analyzer.module_load_failures().len(), 1);
    assert!(analyzer.query_address(&original, 1).is_ok());
    assert!(analyzer.query_address(&bad, 1).is_err());

    write_module(&bad);
    assert_eq!(
        analyzer
            .refresh_pid_runtime_modules_with_config_and_debuginfod(
                refresh,
                &[],
                false,
                None,
                |_| {}
            )
            .await
            .unwrap(),
        1
    );
    assert!(analyzer.module_load_failures().is_empty());
    assert_eq!(analyzer.module_paths().len(), 3);
    assert!(analyzer.query_address(&bad, 1).is_ok());
}

#[tokio::test]
async fn refresh_clears_failures_for_repaired_aliases_of_cached_modules() {
    for hard_link in [false, true] {
        for refresh_alias in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let good = dir.path().join("good.so");
            let repaired = dir.path().join("repaired.so");
            let still_bad = dir.path().join("still-bad.so");
            write_module(&good);
            std::fs::write(&repaired, b"invalid ELF").unwrap();
            let mut analyzer = load(&[&good, &repaired, &still_bad]).await;
            assert_eq!(analyzer.module_load_failures().len(), 2);
            assert!(analyzer.query_address(&repaired, 1).is_err());

            std::fs::remove_file(&repaired).unwrap();
            if hard_link {
                std::fs::hard_link(&good, &repaired).unwrap();
            } else {
                std::os::unix::fs::symlink(&good, &repaired).unwrap();
            }

            // Reuse the cached module with unchanged mapping metadata. Either
            // path in the snapshot must clear the now-equivalent failed alias.
            let refresh_path = if refresh_alias { &repaired } else { &good };
            assert_eq!(
                analyzer
                    .refresh_pid_runtime_modules_with_config_and_debuginfod(
                        vec![runtime_module(refresh_path)],
                        &[],
                        false,
                        None,
                        |_| panic!("a cached module should not be loaded again"),
                    )
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(analyzer.module_paths(), vec![good.clone()]);
            assert_eq!(analyzer.module_load_failures().len(), 1);
            assert_eq!(analyzer.module_load_failures()[0].module_path, still_bad);
            assert!(analyzer.query_address(&repaired, 1).is_ok());
            assert!(analyzer.query_address(&still_bad, 1).is_err());
            for target in [&good, &repaired] {
                assert_eq!(
                    analyzer
                        .resolve_target_module_path(target.to_str().unwrap())
                        .unwrap(),
                    good
                );
            }
        }
    }
}

#[tokio::test]
async fn required_module_failure_is_fatal_and_all_progress_finishes() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.so");
    let main = dir.path().join("main");
    write_module(&good);
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorded = events.clone();
    let error = ModuleLoader::new(vec![
        ModuleMapping::from_path(main.clone()),
        ModuleMapping::from_path(good),
    ])
    .with_required_module(Some(main.clone()))
    .load_with_progress(move |event| recorded.lock().unwrap().push(event))
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<super::ModuleLoadFailure>()
            .unwrap()
            .module_path,
        main
    );
    {
        let events = events.lock().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ModuleLoadingEvent::LoadingCompleted { .. }))
                .count(),
            1
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, ModuleLoadingEvent::LoadingFailed { .. }))
                .count(),
            1
        );
    }
    assert!(DwarfAnalyzer::from_exec_path(&main).await.is_err());
}

#[tokio::test]
async fn explicit_debug_file_failure_on_optional_module_is_fatal() {
    let dir = tempfile::tempdir().unwrap();
    let good = dir.path().join("good.so");
    let explicit_target = dir.path().join("explicit.so");
    let debug_file = dir.path().join("bad.debug");
    write_module(&good);
    write_module(&explicit_target);
    std::fs::write(&debug_file, b"invalid debug ELF").unwrap();
    let error =
        DwarfAnalyzer::from_pid_runtime_modules_with_config_debuginfod_and_explicit_debug_file(
            0,
            vec![runtime_module(&good), runtime_module(&explicit_target)],
            &[],
            false,
            None,
            Some(ExplicitDebugFile::new(explicit_target.clone(), debug_file)),
            |_| {},
        )
        .await
        .unwrap_err();
    let failure = error.downcast_ref::<super::ModuleLoadFailure>().unwrap();
    assert_eq!(failure.module_path, explicit_target);
    assert!(failure.error.contains("failed to parse debug file"));
}

#[test]
fn pid_main_module_uses_executable_identity_and_leaves_missing_main_unresolved() {
    let pid = std::process::id();
    let dir = tempfile::tempdir().unwrap();
    let alias = dir.path().join("main.so");
    std::os::unix::fs::symlink(format!("/proc/{pid}/exe"), &alias).unwrap();
    let mapping = ModuleMapping::from_path(alias.clone());
    assert_eq!(
        DwarfAnalyzer::pid_main_module_path(pid, &[mapping]).unwrap(),
        Some(alias.clone())
    );
    let mut analyzer = DwarfAnalyzer::from_modules(pid, Vec::new());
    analyzer.main_module = Some(alias.clone());
    assert!(analyzer.is_main_executable_module(&alias));
    assert!(!analyzer.is_main_executable_module(Path::new("/tmp/other-app")));
    let missing = DwarfAnalyzer::pid_main_module_path(
        pid,
        &[ModuleMapping::from_path(PathBuf::from("/tmp/other-app"))],
    )
    .unwrap();
    assert!(missing.is_none());
}

#[tokio::test]
async fn pid_main_failure_is_fatal_during_initial_load_and_refresh() {
    for refresh in [false, true] {
        let pid = std::process::id();
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main.so");
        let good = dir.path().join("good.so");
        std::os::unix::fs::symlink(format!("/proc/{pid}/exe"), &main).unwrap();
        write_module(&good);
        let modules = vec![runtime_module(&main), runtime_module(&good)];
        let callback_main = main.clone();
        let callback = move |event| {
            if let ModuleLoadingEvent::Discovered { module_path, .. } = event {
                if Path::new(&module_path) == callback_main {
                    // Replace only the alias after discovery identifies the executable.
                    std::fs::remove_file(&callback_main).unwrap();
                    std::fs::write(&callback_main, b"invalid ELF").unwrap();
                }
            }
        };
        let error = if refresh {
            let mut analyzer = DwarfAnalyzer::from_modules(pid, Vec::new());
            analyzer
                .refresh_pid_runtime_modules_with_config_and_debuginfod(
                    modules,
                    &[],
                    false,
                    None,
                    callback,
                )
                .await
                .unwrap_err()
        } else {
            DwarfAnalyzer::from_pid_runtime_modules_with_config_and_debuginfod(
                pid,
                modules,
                &[],
                false,
                None,
                callback,
            )
            .await
            .unwrap_err()
        };
        let failure = error.downcast_ref::<super::ModuleLoadFailure>().unwrap();
        assert_eq!(failure.module_path, main);
    }
}

//! Shared CFI allocation across initial loaders and background runtime appends.

mod common;

use aya::maps::{Array, HashMap, Map, MapData};
use ghostscope_loader::GhostScopeLoader;
use ghostscope_process::pinned_bpf_maps::*;
use ghostscope_protocol::{BacktraceModuleRowRange, BacktraceUnwindRow};
use std::sync::{Arc, Barrier};

#[tokio::test]
async fn test_shared_cfi_initialization_and_runtime_append_do_not_overlap() -> anyhow::Result<()> {
    common::init();
    if std::env::var_os("E2E_RUN_CONTAINER_TOPOLOGY").is_some() {
        return Ok(());
    }
    cleanup_current_pinned_maps()?;
    let _cleanup = scopeguard::guard((), |_| {
        let _ = cleanup_current_pinned_maps();
    });
    ensure_pinned_proc_offsets_exists(4096)?;
    ensure_pinned_pid_aliases_exists(4096)?;
    ensure_pinned_proc_module_ranges_exist(4096)?;
    ensure_pinned_backtrace_cfi_maps_exist(4096, 4096)?;

    let binary = common::FIXTURES.get_test_binary("backtrace_hot_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let options = ghostscope_compiler::CompileOptions {
        binary_path_hint: Some(binary.to_string_lossy().into_owned()),
        backtrace_unwind_rows_max_entries: 4096,
        ..Default::default()
    };
    let compiled = ghostscope_compiler::compile_script(
        "trace hot_bt_probe { bt; }",
        &analyzer,
        None,
        Some(1),
        &options,
    )?;
    anyhow::ensure!(
        compiled.uprobe_configs.len() == 1,
        "expected one backtrace config"
    );
    let bytecode = &compiled.uprobe_configs[0].ebpf_bytecode;
    let initial = GhostScopeLoader::new_with_shared_backtrace_maps(bytecode, true)?;
    let runtime = GhostScopeLoader::new_with_shared_backtrace_maps(bytecode, true)?;
    let start = Arc::new(Barrier::new(2));
    let row = |cookie, index| BacktraceUnwindRow {
        pc_start: cookie * 0x1000 + index,
        pc_end: cookie * 0x1000 + index + 1,
        ..Default::default()
    };
    std::thread::scope(|scope| -> anyhow::Result<()> {
        let mut publishers = Vec::new();
        for (publisher, mut loader) in [(0, initial), (1, runtime)] {
            let start = Arc::clone(&start);
            publishers.push(scope.spawn(move || -> anyhow::Result<()> {
                start.wait();
                for round in 0..16 {
                    let cookie = 1 + round * 2 + publisher;
                    let rows: Vec<_> = (0..32).map(|index| row(cookie, index)).collect();
                    if publisher == 0 {
                        loader.populate_backtrace_unwind_rows_and_module_row_ranges(
                            &rows,
                            &[(
                                cookie,
                                BacktraceModuleRowRange {
                                    row_start: 0,
                                    row_end: 32,
                                },
                            )],
                        )?;
                    } else {
                        loader.append_backtrace_unwind_rows_for_modules(&[(cookie, rows)])?;
                    }
                }
                Ok(())
            }));
        }
        for publisher in publishers {
            publisher.join().unwrap()?;
        }
        Ok(())
    })?;

    let ranges = HashMap::<_, u64, BacktraceModuleRowRange>::try_from(Map::from_map_data(
        MapData::from_pin(bt_module_row_ranges_pin_path()?)?,
    )?)?;
    let rows = Array::<_, BacktraceUnwindRow>::try_from(Map::from_map_data(MapData::from_pin(
        bt_unwind_rows_pin_path()?,
    )?)?)?;
    let mut allocated = std::collections::BTreeSet::new();
    for cookie in 1..=32 {
        let range = ranges.get(&cookie, 0)?;
        assert_eq!(range.row_end - range.row_start, 32);
        for index in range.row_start..range.row_end {
            assert!(
                allocated.insert(index),
                "overlapping CFI row allocation at {index}"
            );
            assert_eq!(
                rows.get(&index, 0)?,
                row(cookie, u64::from(index - range.row_start))
            );
        }
    }
    // A trace attached after all original loaders are gone sees completed modules.
    let mut replacement = GhostScopeLoader::new_with_shared_backtrace_maps(bytecode, true)?;
    let stats = replacement.append_backtrace_unwind_rows_for_modules(&[(1, vec![row(1, 0)])])?;
    assert_eq!(stats.modules, 0);
    assert_eq!(stats.rows, 0);
    Ok(())
}

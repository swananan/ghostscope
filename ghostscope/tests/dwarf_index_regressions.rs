mod common;

use common::{init, FIXTURES};
use std::collections::HashSet;

#[tokio::test]
async fn test_late_globals_are_indexed_as_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("late_globals_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for late_globals_program: {}", e))?;

    // Scenario this test is meant to cover:
    //
    //   dwarfdump late_globals_program | rg 'DW_TAG_(subprogram|formal_parameter|variable)' -A4 -B2
    //
    // This fixture keeps a small local_fn subtree in the same compilation unit
    // as a couple of real globals. Correct behavior is:
    //   1. late_global / late_static appear in the global index
    //   2. x / tmp do not appear in the global index
    //
    // The compact subtree we rely on is:
    //
    //   DW_TAG_subprogram       local_fn
    //     DW_TAG_formal_parameter x
    //     DW_TAG_variable         tmp
    let late_global = analyzer.find_global_variables_by_name("late_global");
    assert!(
        late_global
            .iter()
            .any(|(module_path, info)| module_path == &binary_path && info.name == "late_global"),
        "Expected late_global to be indexed as a global. Results: {late_global:?}"
    );

    let late_static = analyzer.find_global_variables_by_name("late_static");
    assert!(
        late_static
            .iter()
            .any(|(module_path, info)| module_path == &binary_path && info.name == "late_static"),
        "Expected late_static to be indexed as a global. Results: {late_static:?}"
    );

    let all_names: HashSet<String> = analyzer
        .list_all_global_variables()
        .into_iter()
        .filter(|(module_path, _)| module_path == &binary_path)
        .map(|(_, info)| info.name)
        .collect();

    assert!(
        all_names.contains("late_global"),
        "late_global missing from list_all_global_variables: {all_names:?}"
    );
    assert!(
        all_names.contains("late_static"),
        "late_static missing from list_all_global_variables: {all_names:?}"
    );

    let tmp = analyzer.find_global_variables_by_name("tmp");
    assert!(
        tmp.is_empty(),
        "Function local tmp should not be indexed as global: {tmp:?}"
    );

    let x = analyzer.find_global_variables_by_name("x");
    assert!(
        x.is_empty(),
        "Function parameter x should not be indexed as global: {x:?}"
    );

    Ok(())
}

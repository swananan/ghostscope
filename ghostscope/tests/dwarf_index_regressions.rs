mod common;

use common::{fixture_compiler_available, init, FixtureCompiler, FIXTURES};
use std::collections::HashSet;
use std::path::PathBuf;

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

async fn assert_static_scope_fixture_indexes_expected_symbols(
    binary_path: PathBuf,
    scenario: &str,
) -> anyhow::Result<()> {
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for {scenario}: {}", e))?;

    let file_scope_static = analyzer.find_global_variables_by_name("file_scope_static_counter");
    assert!(
        file_scope_static.iter().any(|(module_path, info)| {
            module_path == &binary_path && info.name == "file_scope_static_counter"
        }),
        "Expected file_scope_static_counter to be indexed as a global for {scenario}. Results: {file_scope_static:?}"
    );

    let function_scope_static =
        analyzer.find_global_variables_by_name("function_scope_static_counter");
    assert!(
        function_scope_static.iter().any(|(module_path, info)| {
            module_path == &binary_path && info.name == "function_scope_static_counter"
        }),
        "Expected function_scope_static_counter to be indexed as a global for {scenario}. Results: {function_scope_static:?}"
    );

    let regular_local = analyzer.find_global_variables_by_name("regular_local");
    assert!(
        regular_local.is_empty(),
        "Function local regular_local should not be indexed as global for {scenario}: {regular_local:?}"
    );

    let all_names: HashSet<String> = analyzer
        .list_all_global_variables()
        .into_iter()
        .filter(|(module_path, _)| module_path == &binary_path)
        .map(|(_, info)| info.name)
        .collect();

    assert!(
        all_names.contains("file_scope_static_counter"),
        "file_scope_static_counter missing from list_all_global_variables for {scenario}: {all_names:?}"
    );
    assert!(
        all_names.contains("function_scope_static_counter"),
        "function_scope_static_counter missing from list_all_global_variables for {scenario}: {all_names:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_static_scope_fixture_indexes_statics_with_default_compiler() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("static_scope_program")?;
    assert_static_scope_fixture_indexes_expected_symbols(
        binary_path,
        "default static_scope_program",
    )
    .await
}

#[tokio::test]
async fn test_static_scope_fixture_indexes_statics_with_clang_dwarf5() -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping clang DWARF5 static-scope regression: clang is unavailable");
        return Ok(());
    }

    let binary_path = FIXTURES
        .get_test_binary_with_compiler("static_scope_program", FixtureCompiler::ClangDwarf5)?;
    assert_static_scope_fixture_indexes_expected_symbols(
        binary_path,
        "clang -gdwarf-5 static_scope_program",
    )
    .await
}

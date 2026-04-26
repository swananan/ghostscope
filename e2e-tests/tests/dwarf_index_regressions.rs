mod common;

use common::{fixture_compiler_available, init, FixtureCompiler, FIXTURES};
use gimli::Reader;
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::HashSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempPath;

// Keep these on the executable inline-body lines in inline_callsite_program.c.
const INLINE_TRACE_LINE: u32 = 43;

type TestReader = gimli::EndianArcSlice<gimli::RunTimeEndian>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangesAttrEncoding {
    Offset,
    Index,
}

fn find_symbol_address(binary_path: &std::path::Path, symbol_name: &str) -> anyhow::Result<u64> {
    let bytes = std::fs::read(binary_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", binary_path.display(), e))?;
    let file = object::File::parse(&*bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", binary_path.display(), e))?;

    file.symbols()
        .find_map(|symbol| match symbol.name() {
            Ok(name) if name == symbol_name => Some(symbol.address()),
            _ => None,
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Symbol '{}' not found in {}",
                symbol_name,
                binary_path.display()
            )
        })
}

async fn spawn_inline_callsite_program(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let bin_dir = binary_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("inline_callsite_program has no parent directory"))?;
    let target = common::targets::TargetLauncher::binary(binary_path)
        .current_dir(bin_dir)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

fn read_uleb128(input: &[u8], offset: &mut usize) -> anyhow::Result<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    loop {
        let byte = *input
            .get(*offset)
            .ok_or_else(|| anyhow::anyhow!("Unexpected EOF while reading ULEB128"))?;
        *offset += 1;
        let low_bits = u64::from(byte & 0x7f);
        anyhow::ensure!(
            shift < 64 && !(shift == 63 && low_bits > 1),
            "ULEB128 value exceeds u64"
        );
        value |= low_bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

#[test]
fn test_read_uleb128_rejects_values_that_overflow_u64() {
    let overflow = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
    let mut offset = 0;
    let err = read_uleb128(&overflow, &mut offset).expect_err("overflow should be rejected");
    assert!(
        err.to_string().contains("exceeds u64"),
        "unexpected overflow error: {err}"
    );
}

fn patch_inlined_subroutine_low_pc_to_entry_pc(abbrev: &mut [u8]) -> anyhow::Result<usize> {
    let mut offset = 0;
    let mut patched = 0;

    while offset < abbrev.len() {
        let code = read_uleb128(abbrev, &mut offset)?;
        if code == 0 {
            continue;
        }

        let tag = read_uleb128(abbrev, &mut offset)?;
        let _has_children = *abbrev
            .get(offset)
            .ok_or_else(|| anyhow::anyhow!("Missing abbrev children byte"))?;
        offset += 1;

        loop {
            let name_offset = offset;
            let name = read_uleb128(abbrev, &mut offset)?;
            let form = read_uleb128(abbrev, &mut offset)?;
            if name == 0 && form == 0 {
                break;
            }

            let is_addrx_form = form == u64::from(ghostscope_dwarf::constants::DW_FORM_addrx.0)
                || form == u64::from(ghostscope_dwarf::constants::DW_FORM_addrx1.0)
                || form == u64::from(ghostscope_dwarf::constants::DW_FORM_addrx2.0)
                || form == u64::from(ghostscope_dwarf::constants::DW_FORM_addrx3.0)
                || form == u64::from(ghostscope_dwarf::constants::DW_FORM_addrx4.0);
            if tag == u64::from(ghostscope_dwarf::constants::DW_TAG_inlined_subroutine.0)
                && name == u64::from(ghostscope_dwarf::constants::DW_AT_low_pc.0)
                && is_addrx_form
            {
                *abbrev
                    .get_mut(name_offset)
                    .ok_or_else(|| anyhow::anyhow!("Invalid abbrev attribute offset"))? =
                    ghostscope_dwarf::constants::DW_AT_entry_pc.0 as u8;
                patched += 1;
            }
        }
    }

    Ok(patched)
}

fn rewrite_inline_fixture_entry_pc_attr(input_path: &Path) -> anyhow::Result<TempPath> {
    let mut bytes = std::fs::read(input_path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", input_path.display(), e))?;
    let (abbrev_offset, abbrev_size) = {
        let object = object::File::parse(&*bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", input_path.display(), e))?;
        let section = object
            .section_by_name(".debug_abbrev")
            .ok_or_else(|| anyhow::anyhow!("{} is missing .debug_abbrev", input_path.display()))?;
        section.file_range().ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no file range for .debug_abbrev",
                input_path.display()
            )
        })?
    };

    let patched = patch_inlined_subroutine_low_pc_to_entry_pc(
        &mut bytes[abbrev_offset as usize..(abbrev_offset + abbrev_size) as usize],
    )?;
    anyhow::ensure!(
        patched > 0,
        "Expected to patch at least one inline low_pc abbrev in {}",
        input_path.display()
    );

    let fixture_dir = input_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", input_path.display()))?;
    let output = tempfile::Builder::new()
        .prefix(".ghostscope-inline-entry-pc-regression-")
        .tempfile_in(fixture_dir)?
        .into_temp_path();
    std::fs::write(&output, &bytes)?;
    let perms = std::fs::metadata(input_path)?.permissions().mode();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(perms))?;
    Ok(output)
}

fn load_dwarf_from_binary(path: &Path) -> anyhow::Result<gimli::Dwarf<TestReader>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {e}", path.display()))?;
    let object = object::File::parse(&*bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {e}", path.display()))?;
    let endian = match object.endianness() {
        object::Endianness::Little => gimli::RunTimeEndian::Little,
        object::Endianness::Big => gimli::RunTimeEndian::Big,
    };

    let dwarf = gimli::Dwarf::load(|id| {
        let section_data = object
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .map(|data| data.into_owned())
            .unwrap_or_default();
        Ok::<_, gimli::Error>(gimli::EndianArcSlice::new(
            Arc::<[u8]>::from(section_data),
            endian,
        ))
    })?;

    Ok(dwarf)
}

fn partitioned_target_ranges_attr_encoding(
    binary_path: &Path,
) -> anyhow::Result<RangesAttrEncoding> {
    let dwarf = load_dwarf_from_binary(binary_path)?;
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();

        while let Some(entry) = entries.next_dfs()? {
            if entry.tag() != gimli::constants::DW_TAG_subprogram {
                continue;
            }

            let Some(name_attr) = entry.attr(gimli::constants::DW_AT_name) else {
                continue;
            };
            let Ok(name) = dwarf.attr_string(&unit, name_attr.value()) else {
                continue;
            };
            let Ok(name) = name.to_string_lossy() else {
                continue;
            };
            if name.as_ref() != "partitioned_target" {
                continue;
            }

            let Some(ranges_attr) = entry.attr(gimli::constants::DW_AT_ranges) else {
                continue;
            };
            return match ranges_attr.value() {
                gimli::AttributeValue::DebugRngListsIndex(_) => Ok(RangesAttrEncoding::Index),
                gimli::AttributeValue::RangeListsRef(_) | gimli::AttributeValue::SecOffset(_) => {
                    Ok(RangesAttrEncoding::Offset)
                }
                other => anyhow::bail!(
                    "Unexpected DW_AT_ranges encoding for partitioned_target in {}: {:?}",
                    binary_path.display(),
                    other
                ),
            };
        }
    }

    anyhow::bail!(
        "Failed to find partitioned_target with DW_AT_ranges in {}",
        binary_path.display()
    )
}

async fn assert_partitioned_ranges_lookup_resolves_primary_entry(
    binary_path: PathBuf,
    scenario: &str,
) -> anyhow::Result<()> {
    let hot_addr = find_symbol_address(&binary_path, "partitioned_target")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_function_addresses("partitioned_target");

    assert_eq!(
        addrs.len(),
        1,
        "Expected a single resolved address for partitioned_target in {scenario}. Results: {addrs:?}"
    );
    assert_eq!(
        addrs[0].module_path, binary_path,
        "Resolved module should point at the partitioned fixture for {scenario}"
    );
    assert_eq!(
        addrs[0].address, hot_addr,
        "lookup_function_addresses should resolve to the primary entry address for {scenario}"
    );

    Ok(())
}

async fn assert_partitioned_ranges_source_line_query_recovers_function_scope(
    binary_path: PathBuf,
    scenario: &str,
) -> anyhow::Result<()> {
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let query_results = analyzer
        .query_source_line_best_effort("partitioned_ranges_program.c", 18)
        .map_err(|e| anyhow::anyhow!("Failed source-line query for {scenario}: {e}"))?;

    anyhow::ensure!(
        !query_results.is_empty(),
        "No source-line query results for {scenario}"
    );
    assert!(
        query_results.iter().any(|result| {
            result.module_path == binary_path
                && result.function_name.as_deref() == Some("partitioned_target")
                && result.parameters.iter().any(|param| param.name == "x")
        }),
        "Expected partitioned_target scope recovery with parameter x for {scenario}. Results: {query_results:?}"
    );

    Ok(())
}

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

#[tokio::test]
async fn test_partitioned_ranges_fixture_exposes_cold_symbol_before_hot_entry() -> anyhow::Result<()>
{
    init();

    let binary_path = FIXTURES.get_test_binary("partitioned_ranges_program")?;
    let hot_addr = find_symbol_address(&binary_path, "partitioned_target")?;
    let cold_addr = find_symbol_address(&binary_path, "partitioned_target.cold")?;

    assert_ne!(
        hot_addr, cold_addr,
        "partitioned_ranges_program should expose distinct hot/cold symbols"
    );
    assert!(
        cold_addr < hot_addr,
        "Expected cold partition to sort before the real entry. hot=0x{hot_addr:x} cold=0x{cold_addr:x}"
    );

    Ok(())
}

#[tokio::test]
async fn test_partitioned_ranges_lookup_prefers_hot_entry_over_cold_partition() -> anyhow::Result<()>
{
    init();

    let binary_path = FIXTURES.get_test_binary("partitioned_ranges_program")?;
    let hot_addr = find_symbol_address(&binary_path, "partitioned_target")?;
    let cold_addr = find_symbol_address(&binary_path, "partitioned_target.cold")?;

    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer.lookup_function_addresses("partitioned_target");

    assert_eq!(
        addrs.len(),
        1,
        "Expected a single resolved address for partitioned_target. Results: {addrs:?}"
    );
    assert_eq!(
        addrs[0].module_path, binary_path,
        "Resolved module should point at the partitioned fixture"
    );
    assert_eq!(
        addrs[0].address, hot_addr,
        "lookup_function_addresses should resolve to the entry/hot range"
    );
    assert_ne!(
        addrs[0].address, cold_addr,
        "lookup_function_addresses must not resolve to the .cold partition"
    );

    Ok(())
}

#[tokio::test]
async fn test_partitioned_ranges_gcc_dwarf5_function_sections_preserve_offset_ranges(
) -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::GccDwarf5FunctionSections) {
        eprintln!("Skipping gcc DWARF5 partitioned-ranges regression: gcc is unavailable");
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary_with_compiler(
        "partitioned_ranges_program",
        FixtureCompiler::GccDwarf5FunctionSections,
    )?;
    assert_eq!(
        partitioned_target_ranges_attr_encoding(&binary_path)?,
        RangesAttrEncoding::Offset,
        "gcc DWARF5 partitioned_ranges_program should keep offset-backed DW_AT_ranges"
    );
    assert_partitioned_ranges_lookup_resolves_primary_entry(
        binary_path.clone(),
        "gcc -gdwarf-5 -ffunction-sections partitioned_ranges_program",
    )
    .await?;
    assert_partitioned_ranges_source_line_query_recovers_function_scope(
        binary_path,
        "gcc -gdwarf-5 -ffunction-sections partitioned_ranges_program",
    )
    .await
}

#[tokio::test]
async fn test_partitioned_ranges_clang_dwarf5_rnglistx_lookup_resolves_primary_entry(
) -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5Rnglistx) {
        eprintln!("Skipping clang rnglistx partitioned-ranges regression: clang is unavailable");
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary_with_compiler(
        "partitioned_ranges_program",
        FixtureCompiler::ClangDwarf5Rnglistx,
    )?;
    assert_eq!(
        partitioned_target_ranges_attr_encoding(&binary_path)?,
        RangesAttrEncoding::Index,
        "clang rnglistx partitioned_ranges_program should expose indexed DW_AT_ranges"
    );
    assert_partitioned_ranges_lookup_resolves_primary_entry(
        binary_path,
        "clang -gdwarf-5 -ffunction-sections -fbasic-block-sections=all partitioned_ranges_program",
    )
    .await
}

#[tokio::test]
async fn test_partitioned_ranges_clang_dwarf5_rnglistx_source_line_query_recovers_scope(
) -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5Rnglistx) {
        eprintln!("Skipping clang rnglistx partitioned-ranges regression: clang is unavailable");
        return Ok(());
    }

    let binary_path = FIXTURES.get_test_binary_with_compiler(
        "partitioned_ranges_program",
        FixtureCompiler::ClangDwarf5Rnglistx,
    )?;
    assert_eq!(
        partitioned_target_ranges_attr_encoding(&binary_path)?,
        RangesAttrEncoding::Index,
        "clang rnglistx partitioned_ranges_program should expose indexed DW_AT_ranges"
    );
    assert_partitioned_ranges_source_line_query_recovers_function_scope(
        binary_path,
        "clang -gdwarf-5 -ffunction-sections -fbasic-block-sections=all partitioned_ranges_program",
    )
    .await
}

#[tokio::test]
async fn test_inline_callsite_clang_dwarf5_resolves_debug_addr_entry_pc() -> anyhow::Result<()> {
    init();

    if !fixture_compiler_available(FixtureCompiler::ClangDwarf5) {
        eprintln!("Skipping clang DWARF5 inline-callsite regression: clang is unavailable");
        return Ok(());
    }

    let compiled_binary_path = FIXTURES
        .get_test_binary_with_compiler("inline_callsite_program", FixtureCompiler::ClangDwarf5)?;
    let binary = rewrite_inline_fixture_entry_pc_attr(&compiled_binary_path)?;
    let binary_path: &Path = binary.as_ref();

    // Clang/DWARF5 can encode inline DW_AT_entry_pc via .debug_addr (DW_FORM_addrx).
    // We need both exec-path lookup and PID-backed scope recovery to keep working.
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(binary_path)
        .await
        .map_err(|e| {
            anyhow::anyhow!("Failed to load DWARF for clang dwarf5 inline fixture: {e}")
        })?;

    let inline_addrs =
        analyzer.lookup_addresses_by_source_line("inline_callsite_program.c", INLINE_TRACE_LINE);
    anyhow::ensure!(
        !inline_addrs.is_empty(),
        "No DWARF addresses found for inline_callsite_program.c:{INLINE_TRACE_LINE}"
    );
    let target = spawn_inline_callsite_program(binary_path).await?;
    let query_result: anyhow::Result<()> = async {
        let pid_analyzer = ghostscope_dwarf::DwarfAnalyzer::from_pid(target.host_pid()).await?;
        let query_results =
            pid_analyzer.query_source_line_best_effort("inline_callsite_program.c", INLINE_TRACE_LINE)?;
        anyhow::ensure!(
            !query_results.is_empty(),
            "No PID-backed query results for inline_callsite_program.c:{INLINE_TRACE_LINE}"
        );
        let inline_results: Vec<_> = query_results
            .iter()
            .filter(|result| {
                result.module_path.as_path() == binary_path && result.is_inline == Some(true)
            })
            .collect();
        anyhow::ensure!(
            !inline_results.is_empty(),
            "Expected at least one inline PID-backed result for clang dwarf5 inline fixture: {query_results:?}"
        );

        let recovered_params: HashSet<&str> = inline_results
            .iter()
            .flat_map(|result| result.parameters.iter().map(|param| param.name.as_str()))
            .collect();
        assert!(
            recovered_params.contains("a"),
            "Missing inline parameter 'a'. Results: {query_results:?}"
        );
        assert!(
            recovered_params.contains("b"),
            "Missing inline parameter 'b'. Results: {query_results:?}"
        );

        Ok(())
    }
    .await;
    target.terminate().await?;
    query_result
}

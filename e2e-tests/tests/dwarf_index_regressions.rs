mod common;

use anyhow::Context;
use common::{fixture_compiler_available, init, FixtureCompiler, OptimizationLevel, FIXTURES};
use gimli::write::{
    Address, AttributeValue as WriteAttributeValue, DebugInfoRef as WriteDebugInfoRef,
    Dwarf as WriteDwarf, EndianVec, LineProgram, Sections, Unit,
};
use gimli::Reader;
use gimli::{Format, SectionId};
use object::{Object, ObjectSection, ObjectSymbol};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command as StdCommand;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempPath;

// Keep these on the executable inline-body lines in inline_callsite_program.c.
const INLINE_TRACE_LINE: u32 = 43;
const COMPLEX_DUPLICATE_PC_LINE: u32 = 20;

type TestReader = gimli::EndianArcSlice<gimli::RunTimeEndian>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangesAttrEncoding {
    Offset,
    Index,
}

fn command_available(name: &str) -> bool {
    StdCommand::new(name)
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn preferred_c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|candidate| command_available(candidate))
}

fn run_command(command: &mut StdCommand, label: &str) -> anyhow::Result<()> {
    let output = command
        .output()
        .with_context(|| format!("failed to run {label}"))?;
    anyhow::ensure!(
        output.status.success(),
        "{label} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
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

fn duplicate_line_row_address_for_source_line(
    binary_path: &Path,
    source_basename: &str,
    target_line: u64,
) -> anyhow::Result<u64> {
    let dwarf = load_dwarf_from_binary(binary_path)?;
    let mut rows_by_address: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(ref line_program) = unit.line_program else {
            continue;
        };
        let line_header = line_program.header();
        let (line_program, sequences) = line_program.clone().sequences()?;

        for sequence in sequences {
            let mut rows = line_program.resume_from(&sequence);
            while let Some((_, row)) = rows.next_row()? {
                if row.end_sequence() {
                    continue;
                }
                let Some(line) = row.line().map(|line| line.get()) else {
                    continue;
                };
                let Some(file) = row.file(line_header) else {
                    continue;
                };
                let Ok(path) = dwarf.attr_string(&unit, file.path_name()) else {
                    continue;
                };
                let Ok(path) = path.to_string_lossy() else {
                    continue;
                };
                let basename_matches = Path::new(path.as_ref())
                    .file_name()
                    .and_then(|name| name.to_str())
                    == Some(source_basename);
                if basename_matches || path.as_ref().ends_with(source_basename) {
                    rows_by_address.entry(row.address()).or_default().push(line);
                }
            }
        }
    }

    rows_by_address
        .into_iter()
        .filter(|(_, lines)| {
            lines.contains(&target_line) && lines.iter().any(|line| *line != target_line)
        })
        .map(|(address, _)| address)
        .min()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no same-PC line rows for {}:{}",
                binary_path.display(),
                source_basename,
                target_line
            )
        })
}

fn line_sequence_end_and_gap_without_line_rows(binary_path: &Path) -> anyhow::Result<(u64, u64)> {
    let dwarf = load_dwarf_from_binary(binary_path)?;
    let mut non_end_addresses = HashSet::new();
    let mut sequence_ranges = Vec::new();
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let Some(ref line_program) = unit.line_program else {
            continue;
        };
        let (line_program, sequences) = line_program.clone().sequences()?;

        for sequence in sequences {
            let mut rows = line_program.resume_from(&sequence);
            let mut sequence_start = None;
            let mut sequence_end = None;

            while let Some((_, row)) = rows.next_row()? {
                if row.end_sequence() {
                    sequence_end = Some(row.address());
                    continue;
                }

                sequence_start.get_or_insert(row.address());
                non_end_addresses.insert(row.address());
            }

            if let (Some(start), Some(end)) = (sequence_start, sequence_end) {
                if start < end {
                    sequence_ranges.push((start, end));
                }
            }
        }
    }

    sequence_ranges.sort_unstable_by_key(|(start, _)| *start);
    let Some((_, first_end)) = sequence_ranges.first().copied() else {
        anyhow::bail!("{} has no line sequences", binary_path.display());
    };
    let mut covered_end = first_end;

    for (next_start, next_end) in sequence_ranges.into_iter().skip(1) {
        if covered_end.saturating_add(1) < next_start {
            let end_address = covered_end;
            let gap_address = covered_end + 1;
            if !non_end_addresses.contains(&end_address)
                && !non_end_addresses.contains(&gap_address)
            {
                return Ok((end_address, gap_address));
            }
        }
        covered_end = covered_end.max(next_end);
    }

    anyhow::bail!(
        "{} has no line-sequence gap without regular line rows",
        binary_path.display()
    );
}

fn write_cross_cu_ref_addr_dwarf_sections(
    out_dir: &Path,
) -> anyhow::Result<Vec<(String, PathBuf)>> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();

    let decl_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let decl_unit = dwarf.units.get_mut(decl_unit_id);
    let decl_root = decl_unit.root();
    decl_unit.get_mut(decl_root).set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"cross_cu_declarations.c".to_vec()),
    );

    let origin_fn_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_subprogram);
    decl_unit.get_mut(origin_fn_id).set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"cross_cu_origin_fn".to_vec()),
    );

    let spec_fn_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_subprogram);
    let spec_fn = decl_unit.get_mut(spec_fn_id);
    spec_fn.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"cross_cu_spec_fn".to_vec()),
    );
    spec_fn.set(
        gimli::constants::DW_AT_declaration,
        WriteAttributeValue::Flag(true),
    );

    let origin_type_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_structure_type);
    let origin_type = decl_unit.get_mut(origin_type_id);
    origin_type.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"CrossCuOriginType".to_vec()),
    );
    origin_type.set(
        gimli::constants::DW_AT_declaration,
        WriteAttributeValue::Flag(true),
    );

    let spec_type_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_structure_type);
    let spec_type = decl_unit.get_mut(spec_type_id);
    spec_type.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"CrossCuSpecType".to_vec()),
    );
    spec_type.set(
        gimli::constants::DW_AT_declaration,
        WriteAttributeValue::Flag(true),
    );

    let concrete_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let concrete_unit = dwarf.units.get_mut(concrete_unit_id);
    let concrete_root = concrete_unit.root();
    concrete_unit.get_mut(concrete_root).set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"cross_cu_concrete.c".to_vec()),
    );

    let concrete_origin_fn_id =
        concrete_unit.add(concrete_root, gimli::constants::DW_TAG_subprogram);
    let concrete_origin_fn = concrete_unit.get_mut(concrete_origin_fn_id);
    concrete_origin_fn.set(
        gimli::constants::DW_AT_abstract_origin,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, origin_fn_id)),
    );
    concrete_origin_fn.set(
        gimli::constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(0x501000)),
    );
    concrete_origin_fn.set(
        gimli::constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(0x20),
    );

    let concrete_spec_fn_id = concrete_unit.add(concrete_root, gimli::constants::DW_TAG_subprogram);
    let concrete_spec_fn = concrete_unit.get_mut(concrete_spec_fn_id);
    concrete_spec_fn.set(
        gimli::constants::DW_AT_specification,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, spec_fn_id)),
    );
    concrete_spec_fn.set(
        gimli::constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(0x502000)),
    );
    concrete_spec_fn.set(
        gimli::constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(0x30),
    );

    let concrete_origin_type_id =
        concrete_unit.add(concrete_root, gimli::constants::DW_TAG_structure_type);
    let concrete_origin_type = concrete_unit.get_mut(concrete_origin_type_id);
    concrete_origin_type.set(
        gimli::constants::DW_AT_abstract_origin,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, origin_type_id)),
    );
    concrete_origin_type.set(
        gimli::constants::DW_AT_byte_size,
        WriteAttributeValue::Udata(24),
    );

    let concrete_spec_type_id =
        concrete_unit.add(concrete_root, gimli::constants::DW_TAG_structure_type);
    let concrete_spec_type = concrete_unit.get_mut(concrete_spec_type_id);
    concrete_spec_type.set(
        gimli::constants::DW_AT_specification,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, spec_type_id)),
    );
    concrete_spec_type.set(
        gimli::constants::DW_AT_byte_size,
        WriteAttributeValue::Udata(16),
    );

    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;

    let mut written = Vec::new();
    for id in [
        SectionId::DebugAbbrev,
        SectionId::DebugInfo,
        SectionId::DebugStr,
    ] {
        let data = sections
            .get(id)
            .map(|section| section.slice().to_vec())
            .unwrap_or_default();
        if data.is_empty() {
            continue;
        }
        let path = out_dir.join(format!("{}.bin", id.name().trim_start_matches('.')));
        fs::write(&path, data)?;
        written.push((id.name().to_string(), path));
    }

    Ok(written)
}

fn build_cross_cu_ref_addr_binary(out_dir: &Path) -> anyhow::Result<Option<PathBuf>> {
    let Some(cc) = preferred_c_compiler() else {
        eprintln!("Skipping cross-CU ref_addr e2e: no C compiler is available");
        return Ok(None);
    };
    if !command_available("objcopy") {
        eprintln!("Skipping cross-CU ref_addr e2e: objcopy is unavailable");
        return Ok(None);
    }

    let source = out_dir.join("cross_cu_ref_addr_stub.c");
    let binary = out_dir.join("cross_cu_ref_addr_stub");
    fs::write(&source, "int main(void) { return 0; }\n")?;
    run_command(
        StdCommand::new(cc).arg("-o").arg(&binary).arg(&source),
        "compile cross-CU ref_addr stub",
    )?;

    let sections = write_cross_cu_ref_addr_dwarf_sections(out_dir)?;
    let mut objcopy = StdCommand::new("objcopy");
    for (section_name, section_path) in &sections {
        objcopy
            .arg("--add-section")
            .arg(format!("{section_name}={}", section_path.display()));
    }
    objcopy.arg(&binary);
    run_command(
        &mut objcopy,
        "objcopy --add-section synthetic cross-CU DWARF",
    )?;

    Ok(Some(binary))
}

fn cross_cu_ref_addr_attrs(binary_path: &Path) -> anyhow::Result<HashSet<gimli::DwAt>> {
    let dwarf = load_dwarf_from_binary(binary_path)?;
    let mut found = HashSet::new();
    let mut units = dwarf.units();

    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            for attr_name in [
                gimli::constants::DW_AT_abstract_origin,
                gimli::constants::DW_AT_specification,
            ] {
                let Some(attr) = entry.attr(attr_name) else {
                    continue;
                };
                if let gimli::AttributeValue::DebugInfoRef(offset) = attr.value() {
                    if offset.to_unit_offset(&unit.header).is_none() {
                        found.insert(attr_name);
                    }
                }
            }
        }
    }

    Ok(found)
}

fn assert_struct_type_size(
    ty: Option<ghostscope_dwarf::TypeInfo>,
    expected_name: &str,
    expected_size: u64,
) {
    match ty {
        Some(ghostscope_dwarf::TypeInfo::StructType { size, .. }) => {
            assert_eq!(size, expected_size, "unexpected size for {expected_name}");
        }
        other => panic!("expected struct type for {expected_name}, got {other:?}"),
    }
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
async fn test_source_lookup_ignores_line_sequence_end_and_gap() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::O3)?;
    let (end_address, gap_address) = line_sequence_end_and_gap_without_line_rows(&binary_path)?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;

    for address in [end_address, gap_address] {
        let module_address = ghostscope_dwarf::ModuleAddress::new(binary_path.clone(), address);
        let source_location = analyzer.lookup_source_location(&module_address);
        assert!(
            source_location.is_none(),
            "Expected no source location for line-sequence boundary/gap address 0x{address:x}. Got {source_location:?}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_source_line_query_preserves_same_pc_line_candidate() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::O3)?;
    let duplicate_pc = duplicate_line_row_address_for_source_line(
        &binary_path,
        "complex_types_program.c",
        u64::from(COMPLEX_DUPLICATE_PC_LINE),
    )?;

    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let addrs = analyzer
        .lookup_addresses_by_source_line("complex_types_program.c", COMPLEX_DUPLICATE_PC_LINE);
    assert!(
        addrs
            .iter()
            .any(|addr| addr.module_path == binary_path && addr.address == duplicate_pc),
        "Expected source-line lookup to include duplicate-PC row 0x{duplicate_pc:x}. Results: {addrs:?}"
    );

    let query_results = analyzer
        .query_source_line_best_effort("complex_types_program.c", COMPLEX_DUPLICATE_PC_LINE)?;
    assert!(
        query_results.iter().any(|result| {
            result.module_path == binary_path
                && result.address == duplicate_pc
                && result.source_line == Some(COMPLEX_DUPLICATE_PC_LINE)
        }),
        "Expected source-line query to keep requested line {COMPLEX_DUPLICATE_PC_LINE} at duplicate PC 0x{duplicate_pc:x}. Results: {query_results:?}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cross_cu_ref_addr_origin_and_spec_names_are_indexed() -> anyhow::Result<()> {
    init();

    let temp_dir = tempfile::tempdir()?;
    let Some(binary_path) = build_cross_cu_ref_addr_binary(temp_dir.path())? else {
        return Ok(());
    };

    let ref_attrs = cross_cu_ref_addr_attrs(&binary_path)?;
    assert!(
        ref_attrs.contains(&gimli::constants::DW_AT_abstract_origin),
        "fixture should contain cross-CU DW_AT_abstract_origin ref_addr"
    );
    assert!(
        ref_attrs.contains(&gimli::constants::DW_AT_specification),
        "fixture should contain cross-CU DW_AT_specification ref_addr"
    );

    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to load synthetic cross-CU DWARF from {}: {e}",
                binary_path.display()
            )
        })?;

    for (name, expected_address) in [
        ("cross_cu_origin_fn", 0x501000),
        ("cross_cu_spec_fn", 0x502000),
    ] {
        let addrs = analyzer.lookup_function_addresses(name);
        assert!(
            addrs.iter().any(|addr| {
                addr.module_path == binary_path && addr.address == expected_address
            }),
            "Expected {name} to be indexed through a cross-CU origin/spec ref. Results: {addrs:?}"
        );
    }

    assert_struct_type_size(
        analyzer.resolve_struct_type_shallow_by_name_in_module(&binary_path, "CrossCuOriginType"),
        "CrossCuOriginType",
        24,
    );
    assert_struct_type_size(
        analyzer.resolve_struct_type_shallow_by_name_in_module(&binary_path, "CrossCuSpecType"),
        "CrossCuSpecType",
        16,
    );

    Ok(())
}

#[tokio::test]
async fn test_late_globals_are_indexed_as_globals() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("late_globals_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for late_globals_program: {e}"))?;

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
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for {scenario}: {e}"))?;

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
    let ctx = analyzer.resolve_pc(&inline_addrs[0])?;
    assert_eq!(
        ctx.is_inline,
        Some(true),
        "expected inline PC context for {INLINE_TRACE_LINE}: {ctx:?}"
    );
    assert!(
        !ctx.inline_chain.is_empty(),
        "expected inline chain for {INLINE_TRACE_LINE}: {ctx:?}"
    );
    assert!(
        ctx.inline_chain
            .iter()
            .any(|frame| frame.context.is_some() && frame.function_name.as_deref() == Some("add3")),
        "expected add3 inline frame with context id: {ctx:?}"
    );
    assert!(
        ctx.inline_chain.iter().any(|frame| {
            frame.function_name.as_deref() == Some("add3")
                && frame
                    .call_site
                    .as_ref()
                    .is_some_and(|call_site| call_site.line_number > 0)
        }),
        "expected add3 inline frame with call-site line info: {ctx:?}"
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

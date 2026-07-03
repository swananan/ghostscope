use super::*;
use crate::binary::dwarf_reader_from_arc;
use gimli::write::{
    Address, AttributeValue as WriteAttributeValue, DebugInfoRef as WriteDebugInfoRef,
    Dwarf as WriteDwarf, EndianVec, Expression as WriteExpression, LineProgram, Sections, Unit,
};
use gimli::{Format, LittleEndian};
use object::{Object, ObjectSection};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use tempfile::TempPath;

fn test_line_entry(address: u64) -> LineEntry {
    LineEntry {
        address,
        end_address: None,
        file_path: "/src/main.c".to_string(),
        file_index: 1,
        compilation_unit: Arc::from("main.c"),
        line: 10,
        column: 0,
        is_stmt: true,
        prologue_end: false,
    }
}

fn write_dwarf_to_read(mut dwarf: WriteDwarf) -> gimli::Dwarf<DwarfReader> {
    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();

    let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            sections
                .get(id)
                .map(|section| section.slice().to_vec())
                .unwrap_or_default(),
        )
    })
    .unwrap();

    dwarf_sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
}

fn dwarf_with_debug_info_bytes(debug_info: Vec<u8>) -> gimli::Dwarf<DwarfReader> {
    gimli::Dwarf::load(|id| {
        let data = if id.name() == ".debug_info" {
            debug_info.clone()
        } else {
            Vec::new()
        };
        Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::<[u8]>::from(data)))
    })
    .unwrap()
}

#[test]
fn flush_pending_line_entries_keeps_equal_end_bounded() {
    let mut out = Vec::new();
    let mut pending = vec![test_line_entry(0x1000)];

    DwarfParser::flush_pending_line_entries(&mut out, &mut pending, Some(0x1000));

    assert!(pending.is_empty());
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].end_address, Some(0x1000));
    assert!(!out[0].contains_address(0x1000));
    assert!(!out[0].contains_address(0x1001));
}

#[test]
fn parse_line_info_propagates_unit_header_errors() {
    let dwarf = dwarf_with_debug_info_bytes(vec![0x0b, 0x00, 0x00, 0x00, 0x04]);
    let parser = DwarfParser { dwarf: &dwarf };

    let err = match parser.parse_line_info("malformed") {
        Ok(_) => panic!("malformed unit header must not be treated as end-of-units"),
        Err(err) => err,
    };

    assert!(
        err.downcast_ref::<gimli::Error>().is_some(),
        "expected gimli parse error, got: {err}"
    );
}

#[test]
fn parse_debug_info_propagates_unit_header_errors() {
    let dwarf = dwarf_with_debug_info_bytes(vec![0x0b, 0x00, 0x00, 0x00, 0x04]);
    let parser = DwarfParser { dwarf: &dwarf };

    let err = match parser.parse_debug_info("malformed") {
        Ok(_) => panic!("malformed unit header must not be treated as end-of-units"),
        Err(err) => err,
    };

    assert!(
        err.downcast_ref::<gimli::Error>().is_some(),
        "expected gimli parse error, got: {err}"
    );
}

fn build_variable_index_fixture() -> gimli::Dwarf<DwarfReader> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();
    let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();

    let global_id = unit.add(root, gimli::constants::DW_TAG_variable);
    let global = unit.get_mut(global_id);
    global.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"real_global".to_vec()),
    );
    global.set(
        gimli::constants::DW_AT_external,
        WriteAttributeValue::Flag(true),
    );
    let mut global_loc = WriteExpression::new();
    global_loc.op_addr(Address::Constant(0x401000));
    global.set(
        gimli::constants::DW_AT_location,
        WriteAttributeValue::Exprloc(global_loc),
    );

    let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
    unit.get_mut(subprogram_id).set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"touch".to_vec()),
    );

    let local_static_id = unit.add(subprogram_id, gimli::constants::DW_TAG_variable);
    let local_static = unit.get_mut(local_static_id);
    local_static.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"local_static".to_vec()),
    );
    let mut local_static_loc = WriteExpression::new();
    local_static_loc.op_addr(Address::Constant(0x402000));
    local_static.set(
        gimli::constants::DW_AT_location,
        WriteAttributeValue::Exprloc(local_static_loc),
    );

    let local_ptr_id = unit.add(subprogram_id, gimli::constants::DW_TAG_variable);
    let local_ptr = unit.get_mut(local_ptr_id);
    local_ptr.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"p".to_vec()),
    );
    let mut local_ptr_loc = WriteExpression::new();
    local_ptr_loc.op_addr(Address::Constant(0x403000));
    local_ptr_loc.op(gimli::constants::DW_OP_stack_value);
    local_ptr.set(
        gimli::constants::DW_AT_location,
        WriteAttributeValue::Exprloc(local_ptr_loc),
    );

    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();

    let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            sections
                .get(id)
                .map(|section| section.slice().to_vec())
                .unwrap_or_default(),
        )
    })
    .unwrap();

    dwarf_sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
}

fn build_inline_origin_fixture() -> gimli::Dwarf<DwarfReader> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();
    let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();

    let abstract_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
    let abstract_fn = unit.get_mut(abstract_id);
    abstract_fn.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"CGPsend".to_vec()),
    );
    abstract_fn.set(
        gimli::constants::DW_AT_inline,
        WriteAttributeValue::Inline(gimli::DW_INL_inlined),
    );
    abstract_fn.set(
        gimli::constants::DW_AT_external,
        WriteAttributeValue::Flag(true),
    );

    let concrete_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
    let concrete_fn = unit.get_mut(concrete_id);
    concrete_fn.set(
        gimli::constants::DW_AT_abstract_origin,
        WriteAttributeValue::UnitRef(abstract_id),
    );
    concrete_fn.set(
        gimli::constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(0x8e97c0)),
    );
    concrete_fn.set(
        gimli::constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(0x420),
    );

    let inlined_id = unit.add(root, gimli::constants::DW_TAG_inlined_subroutine);
    unit.get_mut(inlined_id).set(
        gimli::constants::DW_AT_abstract_origin,
        WriteAttributeValue::UnitRef(abstract_id),
    );

    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();

    let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            sections
                .get(id)
                .map(|section| section.slice().to_vec())
                .unwrap_or_default(),
        )
    })
    .unwrap();

    dwarf_sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
}

fn build_cross_cu_origin_fixture() -> gimli::Dwarf<DwarfReader> {
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
        WriteAttributeValue::String(b"decl_unit.c".to_vec()),
    );

    let abstract_fn_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_subprogram);
    let abstract_fn = decl_unit.get_mut(abstract_fn_id);
    abstract_fn.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"cross_cu_origin_fn".to_vec()),
    );
    abstract_fn.set(
        gimli::constants::DW_AT_external,
        WriteAttributeValue::Flag(true),
    );

    let spec_type_id = decl_unit.add(decl_root, gimli::constants::DW_TAG_structure_type);
    let spec_type = decl_unit.get_mut(spec_type_id);
    spec_type.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"CrossCuOriginType".to_vec()),
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
        WriteAttributeValue::String(b"concrete_unit.c".to_vec()),
    );

    let concrete_fn_id = concrete_unit.add(concrete_root, gimli::constants::DW_TAG_subprogram);
    let concrete_fn = concrete_unit.get_mut(concrete_fn_id);
    concrete_fn.set(
        gimli::constants::DW_AT_abstract_origin,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, abstract_fn_id)),
    );
    concrete_fn.set(
        gimli::constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(0x501000)),
    );
    concrete_fn.set(
        gimli::constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(0x40),
    );

    let concrete_type_id =
        concrete_unit.add(concrete_root, gimli::constants::DW_TAG_structure_type);
    concrete_unit.get_mut(concrete_type_id).set(
        gimli::constants::DW_AT_specification,
        WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(decl_unit_id, spec_type_id)),
    );

    write_dwarf_to_read(dwarf)
}

fn build_multi_cu_shared_function_fixture() -> gimli::Dwarf<DwarfReader> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();

    for (cu_name, low_pc) in [("unit_one.rs", 0x401000_u64), ("unit_two.rs", 0x402000_u64)] {
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();
        unit.get_mut(root).set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(cu_name.as_bytes().to_vec()),
        );

        let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
        let subprogram = unit.get_mut(subprogram_id);
        subprogram.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"shared".to_vec()),
        );
        subprogram.set(
            gimli::constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(low_pc)),
        );
        subprogram.set(
            gimli::constants::DW_AT_high_pc,
            WriteAttributeValue::Udata(0x20),
        );
    }

    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();

    let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            sections
                .get(id)
                .map(|section| section.slice().to_vec())
                .unwrap_or_default(),
        )
    })
    .unwrap();

    dwarf_sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
}

fn build_cu_body_lookup_fixture() -> gimli::Dwarf<DwarfReader> {
    let encoding = gimli::Encoding {
        format: Format::Dwarf32,
        version: 4,
        address_size: 8,
    };

    let mut dwarf = WriteDwarf::new();
    let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
    let unit = dwarf.units.get_mut(unit_id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"body_lookup_unit".to_vec()),
    );

    let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
    let subprogram = unit.get_mut(subprogram_id);
    subprogram.set(
        gimli::constants::DW_AT_name,
        WriteAttributeValue::String(b"body_lookup".to_vec()),
    );
    subprogram.set(
        gimli::constants::DW_AT_low_pc,
        WriteAttributeValue::Address(Address::Constant(0x401000)),
    );
    subprogram.set(
        gimli::constants::DW_AT_high_pc,
        WriteAttributeValue::Udata(0x40),
    );

    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    dwarf.write(&mut sections).unwrap();

    let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
        Ok::<_, gimli::Error>(
            sections
                .get(id)
                .map(|section| section.slice().to_vec())
                .unwrap_or_default(),
        )
    })
    .unwrap();

    dwarf_sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
}

fn clang_available() -> bool {
    Command::new("clang")
        .arg("--version")
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn compile_inline_callsite_fixture_with_clang_dwarf5() -> anyhow::Result<TempPath> {
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| anyhow::anyhow!("ghostscope-dwarf has no workspace parent"))?
        .to_path_buf();
    let source = workspace_root
        .join("e2e-tests/tests/fixtures/inline_callsite_program/inline_callsite_program.c");
    let binary = tempfile::Builder::new()
        .prefix("ghostscope-fast-parser-")
        .tempfile()?
        .into_temp_path();
    let binary_path = binary.to_path_buf();

    let compile_output = Command::new("clang")
        .args(["-Wall", "-Wextra", "-gdwarf-5", "-O3"])
        .arg("-o")
        .arg(&binary_path)
        .arg(&source)
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to run clang for {}: {}", source.display(), e))?;

    if compile_output.status.success() {
        Ok(binary)
    } else {
        let stderr = String::from_utf8_lossy(&compile_output.stderr);
        Err(anyhow::anyhow!(
            "Failed to compile {} with clang -gdwarf-5 -O3: {}",
            source.display(),
            stderr
        ))
    }
}

fn load_dwarf_from_binary(path: &Path) -> anyhow::Result<gimli::Dwarf<DwarfReader>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;
    let object = object::File::parse(&*bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
    let dwarf = gimli::Dwarf::load(|id| {
        let section_data = object
            .section_by_name(id.name())
            .and_then(|section| section.uncompressed_data().ok())
            .map(|data| data.into_owned())
            .unwrap_or_default();
        Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::<[u8]>::from(section_data)))
    })?;
    Ok(dwarf)
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
fn read_uleb128_rejects_values_that_overflow_u64() {
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

            let is_addrx_form = form == u64::from(gimli::constants::DW_FORM_addrx.0)
                || form == u64::from(gimli::constants::DW_FORM_addrx1.0)
                || form == u64::from(gimli::constants::DW_FORM_addrx2.0)
                || form == u64::from(gimli::constants::DW_FORM_addrx3.0)
                || form == u64::from(gimli::constants::DW_FORM_addrx4.0);
            if tag == u64::from(gimli::constants::DW_TAG_inlined_subroutine.0)
                && name == u64::from(gimli::constants::DW_AT_low_pc.0)
                && is_addrx_form
            {
                *abbrev
                    .get_mut(name_offset)
                    .ok_or_else(|| anyhow::anyhow!("Invalid abbrev attribute offset"))? =
                    gimli::constants::DW_AT_entry_pc.0 as u8;
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

    let output = tempfile::Builder::new()
        .prefix(".ghostscope-fast-parser-patched-")
        .tempfile()?
        .into_temp_path();
    std::fs::write(&output, &bytes)?;
    let perms = std::fs::metadata(input_path)?.permissions().mode();
    std::fs::set_permissions(&output, std::fs::Permissions::from_mode(perms))?;
    Ok(output)
}

fn has_inline_entry_pc_debug_addr_index(dwarf: &gimli::Dwarf<DwarfReader>) -> bool {
    let mut units = dwarf.units();
    while let Ok(Some(header)) = units.next() {
        let Ok(unit) = dwarf.unit(header) else {
            continue;
        };
        let mut entries = unit.entries();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() != gimli::constants::DW_TAG_inlined_subroutine {
                continue;
            }
            if let Some(attr) = entry.attr(gimli::constants::DW_AT_entry_pc) {
                if matches!(attr.value(), gimli::AttributeValue::DebugAddrIndex(_)) {
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn parse_debug_info_skips_stack_value_address_locals_from_global_index() {
    let dwarf = build_variable_index_fixture();
    let parser = DwarfParser { dwarf: &dwarf };

    let result = parser.parse_debug_info("synthetic").unwrap();
    let real_global = result
        .lightweight_index
        .find_variables_by_name("real_global");
    let local_static = result
        .lightweight_index
        .find_variables_by_name("local_static");
    let optimized_local = result.lightweight_index.find_variables_by_name("p");

    assert_eq!(
        real_global.len(),
        1,
        "real global should remain indexed: {real_global:?}"
    );
    assert_eq!(
        local_static.len(),
        1,
        "function-scoped static with real storage should remain indexed: {local_static:?}"
    );
    assert!(
        optimized_local.is_empty(),
        "address-valued optimized local must not be indexed as a global: {optimized_local:?}"
    );
}

#[test]
fn parse_debug_info_keeps_concrete_abstract_origin_subprogram_non_inline() {
    // Regression scenario:
    // GCC/Clang can emit all three DIE shapes for one logical function:
    // 1. an abstract DW_TAG_subprogram marked DW_AT_inline,
    // 2. a concrete out-of-line DW_TAG_subprogram with DW_AT_abstract_origin,
    // 3. one or more DW_TAG_inlined_subroutine instances.
    //
    // The bug was that merge_from_origin copied the abstract function's
    // inline attribute from (1) onto (2) and downstream code treated that
    // as if the concrete body were an inline instance.
    // Once that happened, the concrete body was routed through the inline
    // address-selection path and could pick the wrong cold-partition PC.
    //
    // This test keeps the synthetic DIE graph minimal and asserts the parser
    // preserves the intended split:
    // - abstract definition stays inline
    // - concrete out-of-line body stays non-inline
    // - inlined_subroutine instance stays inline
    let dwarf = build_inline_origin_fixture();
    let parser = DwarfParser { dwarf: &dwarf };

    let result = parser.parse_debug_info("synthetic").unwrap();
    let entries = result
        .lightweight_index
        .find_dies_by_function_name("CGPsend");

    let concrete_entries: Vec<_> = entries
        .iter()
        .copied()
        .filter(|entry| entry.function_kind() == crate::core::FunctionDieKind::ConcreteSubprogram)
        .collect();
    let abstract_entries: Vec<_> = entries
        .iter()
        .copied()
        .filter(|entry| entry.function_kind() == crate::core::FunctionDieKind::AbstractSubprogram)
        .collect();
    let inlined_entries: Vec<_> = entries
        .iter()
        .copied()
        .filter(|entry| entry.function_kind() == crate::core::FunctionDieKind::InlineInstance)
        .collect();

    assert_eq!(
        concrete_entries.len(),
        1,
        "concrete out-of-line subprogram should stay non-inline: {entries:?}"
    );
    assert_eq!(
        abstract_entries.len(),
        1,
        "only the abstract inline definition should carry the inline flag: {entries:?}"
    );
    assert_eq!(
        inlined_entries.len(),
        1,
        "expected one inlined subroutine instance: {entries:?}"
    );
    assert!(
        inlined_entries[0].is_inline_instance(),
        "DW_TAG_inlined_subroutine must remain an inline instance: {entries:?}"
    );
    assert!(
        !concrete_entries[0].flags.has_inline_attribute,
        "concrete out-of-line body should not inherit the abstract inline attribute: {entries:?}"
    );
    assert!(
        abstract_entries[0].flags.has_inline_attribute,
        "abstract definition should retain its original DW_AT_inline attribute: {entries:?}"
    );
}

#[test]
fn parse_debug_info_resolves_cross_cu_origin_names_for_index_entries() {
    let dwarf = build_cross_cu_origin_fixture();
    let parser = DwarfParser { dwarf: &dwarf };

    let result = parser.parse_debug_info("synthetic").unwrap();
    let function_entries = result
        .lightweight_index
        .find_dies_by_function_name("cross_cu_origin_fn");
    assert!(
        function_entries.iter().any(|entry| {
            entry.function_kind() == crate::core::FunctionDieKind::ConcreteSubprogram
                && entry.representative_addr == Some(0x501000)
        }),
        "concrete function should inherit its name through a cross-CU origin: {function_entries:?}"
    );

    let mut has_concrete_type = false;
    result
        .lightweight_index
        .for_each_type_map_entry(|name, entry_base, indices| {
            if name != "CrossCuOriginType" {
                return;
            }
            has_concrete_type |= indices.iter().any(|local_idx| {
                result
                    .lightweight_index
                    .entry(entry_base + *local_idx)
                    .is_some_and(|entry| !entry.flags.is_type_declaration)
            });
        });

    assert!(
        has_concrete_type,
        "concrete type should inherit its name through a cross-CU specification"
    );
}

#[test]
fn parse_debug_info_keeps_sharded_name_lookup_without_duplicate_keys() {
    let dwarf = build_multi_cu_shared_function_fixture();
    let parser = DwarfParser { dwarf: &dwarf };

    let result = parser.parse_debug_info("synthetic").unwrap();
    let entries = result
        .lightweight_index
        .find_dies_by_function_name("shared");
    let names = result.lightweight_index.get_function_names();

    assert_eq!(
        result.functions_count, 1,
        "unique function-name count should stay deduplicated across shards"
    );
    assert_eq!(
        entries.len(),
        2,
        "function lookup should fan out across CU shards: {entries:?}"
    );
    assert_eq!(
        names
            .iter()
            .filter(|name| name.as_str() == "shared")
            .count(),
        1,
        "function name listing should not duplicate shard-local keys: {names:?}"
    );
}

#[test]
fn parse_debug_info_builds_fallback_cu_map_for_function_body_addresses() {
    let dwarf = build_cu_body_lookup_fixture();
    let parser = DwarfParser { dwarf: &dwarf };

    let result = parser.parse_debug_info("synthetic").unwrap();
    let entry = result
        .lightweight_index
        .find_function_by_address(0x401020, |entry| {
            let header = dwarf.unit_header(entry.unit_offset).ok()?;
            let unit = dwarf.unit(header).ok()?;
            let die = unit.entry(entry.die_offset).ok()?;
            crate::parser::RangeExtractor::extract_all_ranges(&die, &unit, &dwarf).ok()
        })
        .expect("function body address should resolve through fallback CU map");

    assert_eq!(entry.name.as_ref(), "body_lookup");
    assert_eq!(
        result.lightweight_index.find_cu_by_address(0x401020),
        Some(entry.unit_offset),
        "fallback CU map should cover addresses inside the function body, not just the representative address"
    );
}

#[test]
fn parse_debug_info_resolves_debug_addr_index_entry_pc_for_inline_instances() {
    if !clang_available() {
        eprintln!("Skipping fast_parser DWARF5 entry_pc regression: clang is unavailable");
        return;
    }

    let patched_binary = {
        let binary = compile_inline_callsite_fixture_with_clang_dwarf5()
            .expect("clang dwarf5 inline fixture should compile");
        rewrite_inline_fixture_entry_pc_attr(binary.as_ref())
            .expect("inline fixture abbrev should rewrite low_pc addrx into entry_pc addrx")
    };
    let dwarf = load_dwarf_from_binary(patched_binary.as_ref())
        .expect("compiled inline fixture should load as DWARF");
    assert!(
        has_inline_entry_pc_debug_addr_index(&dwarf),
        "patched inline fixture should expose an inlined_subroutine DW_AT_entry_pc via DW_FORM_addrx/.debug_addr"
    );

    let parser = DwarfParser { dwarf: &dwarf };
    let result = parser
        .parse_debug_info(patched_binary.to_string_lossy().as_ref())
        .expect("fast parser should index patched clang dwarf5 inline fixture");

    let inline_entries: Vec<_> = ["add3", "consume_state"]
        .into_iter()
        .flat_map(|name| {
            result
                .lightweight_index
                .find_dies_by_function_name(name)
                .iter()
                .copied()
                .filter(|entry| {
                    entry.function_kind() == crate::core::FunctionDieKind::InlineInstance
                })
                .collect::<Vec<_>>()
        })
        .collect();

    assert!(
        !inline_entries.is_empty(),
        "expected inline entries for clang dwarf5 inline fixture"
    );
    assert!(
        inline_entries.iter().any(|entry| entry.entry_pc.is_some()),
        "fast parser should resolve DW_FORM_addrx-backed DW_AT_entry_pc values for inline instances: {inline_entries:?}"
    );
}

//! Small, complete primary-file accelerators for the supplementary DWARF fixture.
use anyhow::{ensure, Result};
use gimli::{Reader, Section};
use object::{Object, ObjectSection};
use std::{path::Path, process::Command};

#[derive(Clone, Copy, Debug)]
pub enum Index {
    GnuPubNames,
    Gdb,
    DebugNames,
    GdbDebugNames,
}

struct Symbol {
    name: String,
    cu: u32,
    die: usize,
    tag: gimli::DwTag,
}

fn word(out: &mut Vec<u8>, value: usize, width: usize) {
    out.extend_from_slice(&(value as u64).to_le_bytes()[..width]);
}

fn contribution(body: Vec<u8>, width: usize) -> Vec<u8> {
    let mut out = Vec::new();
    if width == 8 {
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    word(&mut out, body.len(), width);
    out.extend(body);
    out
}

fn read_dwarf(binary: &Path) -> Result<gimli::Dwarf<gimli::EndianRcSlice<gimli::LittleEndian>>> {
    let bytes = std::fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    gimli::Dwarf::load(|id| {
        let bytes = object
            .section_by_name(id.name())
            .map(|section| section.uncompressed_data())
            .transpose()?
            .unwrap_or_default()
            .into_owned();
        Ok::<_, anyhow::Error>(gimli::EndianRcSlice::new(bytes.into(), gimli::LittleEndian))
    })
}

pub fn add_index(binary: &Path, index: Index) -> Result<()> {
    let bytes = std::fs::read(binary)?;
    let object = object::File::parse(bytes.as_slice())?;
    let dwarf = read_dwarf(binary)?;
    let mut units = Vec::new();
    let mut symbols = Vec::new();
    let mut headers = dwarf.units();
    while let Some(header) = headers.next()? {
        let cu = units.len() as u32;
        let unit = dwarf.unit(header.clone())?;
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs()? {
            let name = match entry.tag() {
                gimli::DW_TAG_subprogram => "tick".to_owned(),
                gimli::DW_TAG_inlined_subroutine => "inlined_stub".to_owned(),
                gimli::DW_TAG_variable => dwarf
                    .attr_string(&unit, entry.attr_value(gimli::DW_AT_name).unwrap())?
                    .to_string()?
                    .into_owned(),
                _ => continue,
            };
            symbols.push(Symbol {
                name,
                cu,
                die: entry.offset().0,
                tag: entry.tag(),
            });
        }
        units.push(header);
    }
    let width = usize::from(units[0].format().word_size());
    let mut sections = Vec::new();
    match index {
        Index::GnuPubNames => {
            for (name, include_symbols) in [
                (".debug_gnu_pubnames", true),
                (".debug_gnu_pubtypes", false),
            ] {
                let mut data = Vec::new();
                for (cu, unit) in units.iter().enumerate() {
                    let mut body = 2u16.to_le_bytes().to_vec();
                    word(&mut body, unit.debug_info_offset().unwrap().0, width);
                    word(&mut body, unit.length_including_self(), width);
                    if include_symbols {
                        for symbol in symbols.iter().filter(|symbol| symbol.cu as usize == cu) {
                            word(&mut body, symbol.die, width);
                            body.push(if symbol.tag == gimli::DW_TAG_variable {
                                0x20
                            } else {
                                0x30
                            });
                            body.extend_from_slice(symbol.name.as_bytes());
                            body.push(0);
                        }
                    }
                    word(&mut body, 0, width);
                    data.extend(contribution(body, width));
                }
                sections.push((name, data));
            }
        }
        Index::DebugNames | Index::GdbDebugNames => {
            let gdb2 = matches!(index, Index::GdbDebugNames);
            if gdb2 {
                for symbol in &mut symbols {
                    symbol.die += units[symbol.cu as usize].debug_info_offset().unwrap().0;
                }
                // A real supplementary DIE attributed to the outer primary CU.
                // GDB2 does not make this DIE offset relative to that importer.
                let shared = read_dwarf(&binary.with_file_name("shared.debug"))?;
                let mut headers = shared.units();
                while let Some(header) = headers.next()? {
                    let unit = shared.unit(header)?;
                    let mut entries = unit.entries();
                    while let Some(entry) = entries.next_dfs()? {
                        if entry.tag() == gimli::DW_TAG_typedef {
                            symbols.push(Symbol {
                                name: "SharedAlias".to_owned(),
                                cu: 1,
                                die: entry.offset().to_debug_info_offset(&unit.header).unwrap().0,
                                tag: entry.tag(),
                            });
                            break;
                        }
                    }
                }
            }
            let mut strings = dwarf.debug_str.reader().to_slice()?.to_vec();
            let mut string_offsets = Vec::new();
            let mut entry_offsets = Vec::new();
            let mut pool = Vec::new();
            for symbol in &symbols {
                string_offsets.push(strings.len());
                strings.extend_from_slice(symbol.name.as_bytes());
                strings.push(0);
                entry_offsets.push(pool.len());
                pool.push(match symbol.tag {
                    gimli::DW_TAG_variable => 2,
                    gimli::DW_TAG_inlined_subroutine => 3,
                    gimli::DW_TAG_typedef => 4,
                    _ => 1,
                });
                word(&mut pool, symbol.cu as usize, 4);
                word(&mut pool, symbol.die, width);
                pool.push(0);
            }
            let mut abbrev = Vec::new();
            for (code, tag) in [
                (1, gimli::DW_TAG_subprogram),
                (2, gimli::DW_TAG_variable),
                (3, gimli::DW_TAG_inlined_subroutine),
                (4, gimli::DW_TAG_typedef),
            ] {
                abbrev.extend_from_slice(&[
                    code,
                    tag.0 as u8,
                    gimli::DW_IDX_compile_unit.0 as u8,
                    gimli::DW_FORM_data4.0 as u8,
                    gimli::DW_IDX_die_offset.0 as u8,
                    if gdb2 {
                        gimli::DW_FORM_ref_addr.0 as u8
                    } else if width == 8 {
                        gimli::DW_FORM_ref8.0 as u8
                    } else {
                        gimli::DW_FORM_ref4.0 as u8
                    },
                    0,
                    0,
                ]);
            }
            abbrev.push(0);
            let mut body = 5u16.to_le_bytes().to_vec();
            body.extend_from_slice(&0u16.to_le_bytes());
            for value in [
                units.len(),
                0,
                0,
                0,
                symbols.len(),
                abbrev.len(),
                if gdb2 { 8 } else { 0 },
            ] {
                word(&mut body, value, 4);
            }
            if gdb2 {
                body.extend_from_slice(b"GDB2\0\0\0\0");
            }
            for unit in &units {
                word(&mut body, unit.debug_info_offset().unwrap().0, width);
            }
            for offset in string_offsets.into_iter().chain(entry_offsets) {
                word(&mut body, offset, width);
            }
            body.extend(abbrev);
            body.extend(pool);
            sections.push((".debug_str", strings));
            sections.push((".debug_names", contribution(body, width)));
        }
        Index::Gdb => {
            let mut data = vec![0; 24];
            let cu_list = data.len();
            for unit in &units {
                word(&mut data, unit.debug_info_offset().unwrap().0, 8);
                word(&mut data, unit.length_including_self(), 8);
            }
            let types = data.len();
            let address_area = data.len();
            let unit = dwarf.unit(units[0].clone())?;
            let root = unit.entry(unit.header.root_offset())?;
            let low = match root.attr_value(gimli::DW_AT_low_pc).unwrap() {
                gimli::AttributeValue::Addr(value) => value,
                _ => unreachable!(),
            };
            let size = root
                .attr_value(gimli::DW_AT_high_pc)
                .unwrap()
                .udata_value()
                .unwrap();
            word(&mut data, low as usize, 8);
            word(&mut data, (low + size) as usize, 8);
            word(&mut data, 0, 4);
            let symbol_table = data.len();
            let slots = (symbols.len() * 2).next_power_of_two();
            data.resize(data.len() + slots * 8, 0);
            let pool = data.len();
            let mut used = std::collections::HashSet::new();
            for symbol in &symbols {
                let vector_offset = data.len() - pool;
                word(&mut data, 1, 4);
                let kind = if symbol.tag == gimli::DW_TAG_variable {
                    2
                } else {
                    3
                };
                word(&mut data, symbol.cu as usize | kind << 28, 4);
                let name_offset = data.len() - pool;
                data.extend_from_slice(symbol.name.as_bytes());
                data.push(0);
                while !data.len().is_multiple_of(4) {
                    data.push(0);
                }
                let hash = symbol.name.bytes().fold(0u32, |hash, byte| {
                    hash.wrapping_mul(67)
                        .wrapping_add(u32::from(byte.to_ascii_lowercase()))
                        .wrapping_sub(113)
                });
                let mut slot = hash as usize & (slots - 1);
                let step = (hash.wrapping_mul(17) as usize & (slots - 1)) | 1;
                while !used.insert(slot) {
                    slot = (slot + step) & (slots - 1);
                }
                data[symbol_table + slot * 8..symbol_table + slot * 8 + 4]
                    .copy_from_slice(&(name_offset as u32).to_le_bytes());
                data[symbol_table + slot * 8 + 4..symbol_table + slot * 8 + 8]
                    .copy_from_slice(&(vector_offset as u32).to_le_bytes());
            }
            for (position, value) in [7, cu_list, types, address_area, symbol_table, pool]
                .into_iter()
                .enumerate()
            {
                data[position * 4..position * 4 + 4].copy_from_slice(&(value as u32).to_le_bytes());
            }
            sections.push((".gdb_index", data));
        }
    }
    let mut command = Command::new("objcopy");
    let dir = tempfile::tempdir()?;
    for (name, bytes) in sections {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes)?;
        command
            .arg(if object.section_by_name(name).is_some() {
                "--update-section"
            } else {
                "--add-section"
            })
            .arg(format!("{name}={}", path.display()));
    }
    let output = command.arg(binary).output()?;
    ensure!(output.status.success(), "objcopy: {output:?}");
    Ok(())
}

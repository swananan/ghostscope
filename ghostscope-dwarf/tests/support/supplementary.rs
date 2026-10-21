//! Shared real-ELF fixture for parser and CLI regression tests.
use anyhow::{ensure, Context, Result};
use gimli::write::{
    Address, AttributeValue as A, Dwarf, EndianVec, Expression, LineProgram, Sections, Unit,
};
use gimli::{Reader, SectionId};
use object::{Object, ObjectSymbol};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process::Command,
};

pub struct Fixture {
    pub binary: PathBuf,
    pub supplementary: PathBuf,
}

fn run(command: &mut Command) -> Result<()> {
    let output = command.output()?;
    ensure!(
        output.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn sections(dwarf: &mut Dwarf) -> Result<Sections<EndianVec<gimli::LittleEndian>>> {
    let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
    dwarf.write(&mut sections)?;
    Ok(sections)
}

fn uleb(
    reader: &mut gimli::EndianSlice<'_, gimli::LittleEndian>,
    out: &mut Vec<u8>,
    replacement: Option<u64>,
) -> Result<u64> {
    let value = reader.read_uleb128()?;
    let mut encoded = replacement.unwrap_or(value);
    loop {
        let byte = (encoded & 127) as u8;
        encoded >>= 7;
        out.push(byte | if encoded == 0 { 0 } else { 128 });
        if encoded == 0 {
            break;
        }
    }
    Ok(value)
}

// gimli writes standard supplementary forms. Encode their GNU equivalents for
// the DWARF4 fixture, and use a partial-unit root as real dwz output does.
fn abbreviations(data: &[u8], gnu: bool, partial: bool) -> Result<Vec<u8>> {
    let mut reader = gimli::EndianSlice::new(data, gimli::LittleEndian);
    let mut out = Vec::new();
    while !reader.is_empty() {
        if uleb(&mut reader, &mut out, None)? == 0 {
            continue;
        }
        let mut peek = reader;
        let tag = peek.read_uleb128()?;
        uleb(
            &mut reader,
            &mut out,
            if partial && tag == u64::from(gimli::DW_TAG_compile_unit.0) {
                Some(u64::from(gimli::DW_TAG_partial_unit.0))
            } else {
                None
            },
        )?;
        out.push(reader.read_u8()?);
        loop {
            let attr = uleb(&mut reader, &mut out, None)?;
            let mut peek = reader;
            let form = peek.read_uleb128()?;
            let replacement = if gnu {
                match form as u16 {
                    x if x == gimli::DW_FORM_ref_sup4.0 || x == gimli::DW_FORM_ref_sup8.0 => {
                        Some(u64::from(gimli::DW_FORM_GNU_ref_alt.0))
                    }
                    x if x == gimli::DW_FORM_strp_sup.0 => {
                        Some(u64::from(gimli::DW_FORM_GNU_strp_alt.0))
                    }
                    _ => None,
                }
            } else {
                None
            };
            uleb(&mut reader, &mut out, replacement)?;
            if attr == 0 && form == 0 {
                break;
            }
        }
    }
    Ok(out)
}

fn sup_section(filename: &str, supplementary: bool) -> Vec<u8> {
    let mut bytes = vec![5, 0, u8::from(supplementary)];
    bytes.extend_from_slice(filename.as_bytes());
    bytes.push(0);
    bytes.push(4);
    bytes.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    bytes
}

pub fn build(dir: &Path, standard: bool, dwarf64: bool) -> Result<Fixture> {
    build_with_language(dir, standard, dwarf64, false)
}

pub fn build_rust(dir: &Path, standard: bool, dwarf64: bool) -> Result<Fixture> {
    build_with_language(dir, standard, dwarf64, true)
}

fn build_with_language(dir: &Path, standard: bool, dwarf64: bool, rust: bool) -> Result<Fixture> {
    std::fs::create_dir_all(dir)?;
    let binary = dir.join("supplementary-program");
    let source = dir.join("program.c");
    std::fs::write(&source, "#include <unistd.h>\nstruct Shared { int first; int second; };\nstruct Shared payload = {1234, 5678};\nconst char text[] = \"supplement\";\nstruct { const char *data; unsigned long length; } message = {text, 10};\n__attribute__((noinline)) int tick(void) { return payload.first + payload.second + *(const volatile char *)message.data; }\nint main(void) { for (;;) { tick(); usleep(10000); } }\n")?;
    run(Command::new("cc")
        .args(["-g0", "-O0", "-fno-pie", "-no-pie", "-o"])
        .arg(&binary)
        .arg(&source))?;
    let data = std::fs::read(&binary)?;
    let object = object::File::parse(data.as_slice())?;
    let symbol = |name| {
        object
            .symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .context("fixture symbol is absent")
    };
    let tick = symbol("tick")?;
    let tick_address = tick.address();
    let tick_size = tick.size();
    let payload_address = symbol("payload")?.address();
    let message_address = symbol("message")?.address();
    let encoding = gimli::Encoding {
        format: if dwarf64 {
            gimli::Format::Dwarf64
        } else {
            gimli::Format::Dwarf32
        },
        version: if standard { 5 } else { 4 },
        address_size: 8,
    };
    let mut supplement = Dwarf::new();
    let source_name = supplement.strings.add(b"program.c".to_vec());
    let id = supplement
        .units
        .add(Unit::new(encoding, LineProgram::none()));
    let unit = supplement.units.get_mut(id);
    let root = unit.root();
    unit.get_mut(root)
        .set(gimli::DW_AT_name, A::StringRef(source_name));
    // Real dwz partial units omit both language and producer. Their importers
    // retain those attributes, even when the shared DIEs are Rust types.
    let integer = unit.add(root, gimli::DW_TAG_base_type);
    unit.get_mut(integer)
        .set(gimli::DW_AT_name, A::String(b"int".to_vec()));
    unit.get_mut(integer)
        .set(gimli::DW_AT_byte_size, A::Udata(4));
    unit.get_mut(integer)
        .set(gimli::DW_AT_encoding, A::Encoding(gimli::DW_ATE_signed));
    let aggregate = unit.add(root, gimli::DW_TAG_structure_type);
    unit.get_mut(aggregate).set(
        gimli::DW_AT_name,
        A::String(if rust {
            b"(i32, i32)".to_vec()
        } else {
            b"Shared".to_vec()
        }),
    );
    unit.get_mut(aggregate)
        .set(gimli::DW_AT_byte_size, A::Udata(8));
    let fields = if rust {
        [(b"__0".to_vec(), 0), (b"__1".to_vec(), 4)]
    } else {
        [(b"first".to_vec(), 0), (b"second".to_vec(), 4)]
    };
    for (name, offset) in fields {
        let member = unit.add(aggregate, gimli::DW_TAG_member);
        unit.get_mut(member).set(gimli::DW_AT_name, A::String(name));
        unit.get_mut(member)
            .set(gimli::DW_AT_type, A::UnitRef(integer));
        unit.get_mut(member)
            .set(gimli::DW_AT_data_member_location, A::Udata(offset));
    }
    let alias = unit.add(root, gimli::DW_TAG_typedef);
    unit.get_mut(alias)
        .set(gimli::DW_AT_name, A::String(b"SharedAlias".to_vec()));
    unit.get_mut(alias)
        .set(gimli::DW_AT_type, A::UnitRef(aggregate));
    if rust {
        let byte = unit.add(root, gimli::DW_TAG_base_type);
        unit.get_mut(byte)
            .set(gimli::DW_AT_name, A::String(b"u8".to_vec()));
        unit.get_mut(byte).set(gimli::DW_AT_byte_size, A::Udata(1));
        unit.get_mut(byte)
            .set(gimli::DW_AT_encoding, A::Encoding(gimli::DW_ATE_unsigned));
        let length = unit.add(root, gimli::DW_TAG_base_type);
        unit.get_mut(length)
            .set(gimli::DW_AT_name, A::String(b"usize".to_vec()));
        unit.get_mut(length)
            .set(gimli::DW_AT_byte_size, A::Udata(8));
        unit.get_mut(length)
            .set(gimli::DW_AT_encoding, A::Encoding(gimli::DW_ATE_unsigned));
        let pointer = unit.add(root, gimli::DW_TAG_pointer_type);
        unit.get_mut(pointer)
            .set(gimli::DW_AT_type, A::UnitRef(byte));
        unit.get_mut(pointer)
            .set(gimli::DW_AT_byte_size, A::Udata(8));
        let string = unit.add(root, gimli::DW_TAG_structure_type);
        unit.get_mut(string)
            .set(gimli::DW_AT_name, A::String(b"&str".to_vec()));
        unit.get_mut(string)
            .set(gimli::DW_AT_byte_size, A::Udata(16));
        for (name, ty, offset) in [
            (b"data_ptr".to_vec(), pointer, 0),
            (b"length".to_vec(), length, 8),
        ] {
            let member = unit.add(string, gimli::DW_TAG_member);
            unit.get_mut(member).set(gimli::DW_AT_name, A::String(name));
            unit.get_mut(member).set(gimli::DW_AT_type, A::UnitRef(ty));
            unit.get_mut(member)
                .set(gimli::DW_AT_data_member_location, A::Udata(offset));
        }
    }
    let declaration = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(declaration)
        .set(gimli::DW_AT_name, A::String(b"tick".to_vec()));
    unit.get_mut(declaration)
        .set(gimli::DW_AT_declaration, A::Flag(true));
    let inline = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(inline)
        .set(gimli::DW_AT_name, A::String(b"inlined_stub".to_vec()));
    let parameter = unit.add(inline, gimli::DW_TAG_formal_parameter);
    unit.get_mut(parameter)
        .set(gimli::DW_AT_name, A::String(b"parameter".to_vec()));
    unit.get_mut(parameter)
        .set(gimli::DW_AT_type, A::UnitRef(integer));
    unit.get_mut(parameter)
        .set(gimli::DW_AT_const_value, A::Udata(7));
    let mut sup_sections = sections(&mut supplement)?;
    let read = gimli::Dwarf::load(|id| {
        Ok::<_, gimli::Error>(gimli::EndianSlice::new(
            sup_sections
                .get(id)
                .map_or(&[][..], |section| section.slice()),
            gimli::LittleEndian,
        ))
    })?;
    let header = read.units().next()?.unwrap();
    let unit = read.unit(header)?;
    let root_offset = unit
        .header
        .root_offset()
        .to_debug_info_offset(&unit.header)
        .unwrap();
    let mut offsets = HashMap::new();
    let mut entries = unit.entries();
    while let Some(entry) = entries.next_dfs()? {
        if let Some(name) = entry.attr_value(gimli::DW_AT_name) {
            offsets.insert(
                read.attr_string(&unit, name)?
                    .to_string_lossy()
                    .into_owned(),
                entry.offset().to_debug_info_offset(&unit.header).unwrap(),
            );
        }
    }
    let name_offset = sup_sections
        .debug_str
        .slice()
        .windows(b"program.c\0".len())
        .position(|window| window == b"program.c\0")
        .unwrap();
    let abbrev = abbreviations(sup_sections.debug_abbrev.slice(), false, true)?;
    sup_sections.debug_abbrev.0 = EndianVec::new(gimli::LittleEndian);
    use gimli::write::Writer;
    sup_sections.debug_abbrev.write(&abbrev)?;
    let mut supplement_object = object::write::Object::new(
        object::BinaryFormat::Elf,
        object::Architecture::X86_64,
        object::Endianness::Little,
    );
    sup_sections.for_each(|id, section| {
        let mut bytes = section.slice().to_vec();
        if id == SectionId::DebugInfo && standard {
            bytes[if dwarf64 { 14 } else { 6 }] = gimli::DW_UT_partial.0;
        }
        if !bytes.is_empty() {
            let id = supplement_object.add_section(
                Vec::new(),
                id.name().as_bytes().to_vec(),
                object::SectionKind::Debug,
            );
            supplement_object.append_section_data(id, &bytes, 1);
        }
        Ok::<_, anyhow::Error>(())
    })?;
    let link_section = if standard {
        sup_section("", true)
    } else {
        let mut note = vec![4, 0, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0];
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        note
    };
    let name = if standard {
        b".debug_sup".to_vec()
    } else {
        b".note.gnu.build-id".to_vec()
    };
    let id = supplement_object.add_section(
        Vec::new(),
        name,
        if standard {
            object::SectionKind::Debug
        } else {
            object::SectionKind::Note
        },
    );
    supplement_object.append_section_data(id, &link_section, 4);
    let supplementary = dir.join("shared.debug");
    std::fs::write(&supplementary, supplement_object.write()?)?;
    let mut primary = Dwarf::new();
    let id = primary.units.add(Unit::new(encoding, LineProgram::none()));
    let unit = primary.units.get_mut(id);
    let root = unit.root();
    unit.get_mut(root).set(
        gimli::DW_AT_name,
        A::DebugStrRefSup(gimli::DebugStrOffset(name_offset)),
    );
    unit.get_mut(root).set(
        gimli::DW_AT_language,
        A::Language(if rust {
            gimli::DW_LANG_Rust
        } else {
            gimli::DW_LANG_C11
        }),
    );
    unit.get_mut(root).set(
        gimli::DW_AT_producer,
        A::String(if rust {
            b"clang LLVM (rustc version 1.88.0)".to_vec()
        } else {
            b"fixture C compiler".to_vec()
        }),
    );
    unit.get_mut(root).set(
        gimli::DW_AT_low_pc,
        A::Address(Address::Constant(tick_address)),
    );
    unit.get_mut(root)
        .set(gimli::DW_AT_high_pc, A::Udata(tick_size));
    let import = unit.add(root, gimli::DW_TAG_imported_unit);
    unit.get_mut(import)
        .set(gimli::DW_AT_import, A::DebugInfoRefSup(root_offset));
    let function = unit.add(root, gimli::DW_TAG_subprogram);
    unit.get_mut(function).set(
        gimli::DW_AT_specification,
        A::DebugInfoRefSup(offsets["tick"]),
    );
    unit.get_mut(function).set(
        gimli::DW_AT_low_pc,
        A::Address(Address::Constant(tick_address)),
    );
    unit.get_mut(function)
        .set(gimli::DW_AT_high_pc, A::Udata(tick_size));
    let inline = unit.add(function, gimli::DW_TAG_inlined_subroutine);
    unit.get_mut(inline).set(
        gimli::DW_AT_abstract_origin,
        A::DebugInfoRefSup(offsets["inlined_stub"]),
    );
    unit.get_mut(inline).set(
        gimli::DW_AT_low_pc,
        A::Address(Address::Constant(tick_address + 1)),
    );
    unit.get_mut(inline).set(gimli::DW_AT_high_pc, A::Udata(1));
    let variable = unit.add(root, gimli::DW_TAG_variable);
    unit.get_mut(variable)
        .set(gimli::DW_AT_name, A::String(b"payload".to_vec()));
    unit.get_mut(variable).set(
        gimli::DW_AT_type,
        A::DebugInfoRefSup(offsets["SharedAlias"]),
    );
    let mut location = Expression::new();
    location.op_addr(Address::Constant(payload_address));
    unit.get_mut(variable)
        .set(gimli::DW_AT_location, A::Exprloc(location));
    if rust {
        let variable = unit.add(root, gimli::DW_TAG_variable);
        unit.get_mut(variable)
            .set(gimli::DW_AT_name, A::String(b"message".to_vec()));
        unit.get_mut(variable)
            .set(gimli::DW_AT_type, A::DebugInfoRefSup(offsets["&str"]));
        let mut location = Expression::new();
        location.op_addr(Address::Constant(message_address));
        unit.get_mut(variable)
            .set(gimli::DW_AT_location, A::Exprloc(location));
    }
    if rust {
        // A second importer with different semantic metadata must not inherit
        // the first importer's Rust context for the same physical type DIE.
        let id = primary.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = primary.units.get_mut(id);
        let root = unit.root();
        unit.get_mut(root)
            .set(gimli::DW_AT_name, A::String(b"foreign.c".to_vec()));
        unit.get_mut(root)
            .set(gimli::DW_AT_language, A::Language(gimli::DW_LANG_C11));
        unit.get_mut(root).set(
            gimli::DW_AT_producer,
            A::String(b"fixture C compiler".to_vec()),
        );
        let import = unit.add(root, gimli::DW_TAG_imported_unit);
        unit.get_mut(import)
            .set(gimli::DW_AT_import, A::DebugInfoRefSup(root_offset));
        let variable = unit.add(root, gimli::DW_TAG_variable);
        unit.get_mut(variable)
            .set(gimli::DW_AT_name, A::String(b"foreign_payload".to_vec()));
        unit.get_mut(variable).set(
            gimli::DW_AT_type,
            A::DebugInfoRefSup(offsets["SharedAlias"]),
        );
        let mut location = Expression::new();
        location.op_addr(Address::Constant(payload_address));
        unit.get_mut(variable)
            .set(gimli::DW_AT_location, A::Exprloc(location));
    }
    let primary_sections = sections(&mut primary)?;
    // GNU forms have longer ULEB encodings. Relocate every CU's abbreviation
    // table offset after converting, including the second semantic importer.
    let primary_read = gimli::Dwarf::load(|id| {
        Ok::<_, gimli::Error>(gimli::EndianSlice::new(
            primary_sections
                .get(id)
                .map_or(&[][..], |section| section.slice()),
            gimli::LittleEndian,
        ))
    })?;
    let mut info = primary_sections.debug_info.slice().to_vec();
    if !standard {
        let mut headers = primary_read.units();
        while let Some(header) = headers.next()? {
            let offset = header.debug_abbrev_offset().0;
            let relocated = abbreviations(
                &primary_sections.debug_abbrev.slice()[..offset],
                true,
                false,
            )?
            .len() as u64;
            let position = header.debug_info_offset().unwrap().0 + if dwarf64 { 14 } else { 6 };
            let size = if dwarf64 { 8 } else { 4 };
            info[position..position + size].copy_from_slice(&relocated.to_le_bytes()[..size]);
        }
    }
    let mut objcopy = Command::new("objcopy");
    primary_sections.for_each(|id, section| {
        let bytes = if id == SectionId::DebugAbbrev {
            abbreviations(section.slice(), !standard, false)?
        } else if id == SectionId::DebugInfo {
            info.clone()
        } else {
            section.slice().to_vec()
        };
        if !bytes.is_empty() {
            let path = dir.join(format!("{}.bin", id.name()));
            std::fs::write(&path, &bytes)?;
            objcopy
                .arg("--add-section")
                .arg(format!("{}={}", id.name(), path.display()));
        }
        Ok::<_, anyhow::Error>(())
    })?;
    let (name, link) = if standard {
        (".debug_sup", sup_section("shared.debug", false))
    } else {
        let mut link = b"shared.debug\0".to_vec();
        link.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        (".gnu_debugaltlink", link)
    };
    let path = dir.join("link.bin");
    std::fs::write(&path, link)?;
    objcopy
        .arg("--add-section")
        .arg(format!("{name}={}", path.display()))
        .arg(&binary);
    run(&mut objcopy)?;
    Ok(Fixture {
        binary,
        supplementary,
    })
}

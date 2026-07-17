//! DWARF-backed type identity and compilation-unit metadata queries.

use super::{variables::complete_aggregate_declaration_entry, LoadedObjfile};
use crate::{
    core::Result,
    semantics::{
        resolve_name_with_origins, resolve_type_ref_with_origins, CompilationUnitMetadata,
        ProducerInfo, SourceLanguage, TypeLoc, VariableAccessSegment,
    },
    CuId, ModuleId, TypeId,
};
use gimli::Reader;
use std::collections::HashSet;

const MAX_TYPE_REFERENCE_DEPTH: usize = 64;

fn debug_info_offset(cu: CuId) -> gimli::DebugInfoOffset {
    gimli::DebugInfoOffset(cu.0 as usize)
}

fn type_loc(type_id: TypeId) -> Result<TypeLoc> {
    if type_id.cu != type_id.die.cu || type_id.module != type_id.die.module {
        return Err(anyhow::anyhow!("inconsistent TypeId identity: {type_id:?}"));
    }

    Ok(TypeLoc {
        cu_off: debug_info_offset(type_id.cu),
        die_off: gimli::UnitOffset(
            usize::try_from(type_id.die.offset).map_err(|_| {
                anyhow::anyhow!("type DIE offset does not fit this host: {type_id:?}")
            })?,
        ),
    })
}

fn type_id_from_loc(module: ModuleId, loc: TypeLoc) -> TypeId {
    let cu = CuId(loc.cu_off.0 as u32);
    let die = crate::DieRef {
        module,
        cu,
        offset: loc.die_off.0 as u64,
    };
    TypeId { module, cu, die }
}

fn qualified_type_name_from_dwarf(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    loc: TypeLoc,
) -> Result<Option<String>> {
    let header = dwarf.unit_header(loc.cu_off)?;
    let unit = dwarf.unit(header)?;
    let mut namespaces = Vec::<(isize, String)>::new();
    let mut entries = unit.entries();

    while let Some(entry) = entries.next_dfs()? {
        while namespaces
            .last()
            .is_some_and(|(depth, _)| *depth >= entry.depth())
        {
            namespaces.pop();
        }

        if entry.offset() == loc.die_off {
            let Some(name) = resolve_name_with_origins(dwarf, &unit, entry)? else {
                return Ok(None);
            };
            let mut components = namespaces
                .iter()
                .map(|(_, namespace)| namespace.as_str())
                .collect::<Vec<_>>();
            components.push(&name);
            return Ok(Some(components.join("::")));
        }

        if entry.tag() == gimli::DW_TAG_namespace {
            if let Some(name) = resolve_name_with_origins(dwarf, &unit, entry)? {
                namespaces.push((entry.depth(), name));
            }
        }
    }

    Ok(None)
}

fn compilation_unit_metadata_from_dwarf(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    module: ModuleId,
    cu: CuId,
) -> Result<Option<CompilationUnitMetadata>> {
    let header = dwarf.unit_header(debug_info_offset(cu))?;
    let dwarf_version = header.version();
    let unit = dwarf.unit(header)?;
    let mut entries = unit.entries();
    let Some(root) = entries.next_dfs()? else {
        return Ok(None);
    };

    let dwarf_language = match root.attr_value(gimli::DW_AT_language) {
        Some(gimli::AttributeValue::Language(language)) => Some(language),
        _ => None,
    };
    let producer = match root.attr(gimli::DW_AT_producer) {
        Some(attribute) => {
            let value = dwarf.attr_string(&unit, attribute.value())?;
            Some(ProducerInfo::new(value.to_string_lossy()?.into_owned()))
        }
        None => None,
    };

    Ok(Some(CompilationUnitMetadata {
        module,
        cu,
        language: SourceLanguage::from_dwarf(dwarf_language),
        producer,
        dwarf_version,
    }))
}

fn normalize_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    mut loc: TypeLoc,
) -> Result<Option<TypeLoc>> {
    let mut visited = HashSet::new();
    for _ in 0..MAX_TYPE_REFERENCE_DEPTH {
        if !visited.insert((loc.cu_off.0, loc.die_off.0)) {
            return Err(anyhow::anyhow!(
                "cycle while resolving type DIE at {:?}:{:?}",
                loc.cu_off,
                loc.die_off
            ));
        }

        let header = dwarf.unit_header(loc.cu_off)?;
        let unit = dwarf.unit(header)?;
        let entry = unit.entry(loc.die_off)?;
        match entry.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {
                let Some(next) = resolve_type_ref_with_origins(dwarf, &entry, &unit)? else {
                    return Ok(None);
                };
                loc = next;
            }
            gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type => {
                if let Some((cu_off, die_off)) =
                    complete_aggregate_declaration_entry(dwarf, type_name_index, &unit, &entry)
                {
                    loc = TypeLoc { cu_off, die_off };
                } else {
                    return Ok(Some(loc));
                }
            }
            _ => return Ok(Some(loc)),
        }
    }

    Err(anyhow::anyhow!(
        "type reference depth exceeds {MAX_TYPE_REFERENCE_DEPTH}"
    ))
}

fn pointer_like(tag: gimli::DwTag) -> bool {
    matches!(
        tag,
        gimli::DW_TAG_pointer_type
            | gimli::DW_TAG_reference_type
            | gimli::DW_TAG_rvalue_reference_type
    )
}

fn projected_member_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    loc: TypeLoc,
    field: &str,
) -> Result<Option<TypeLoc>> {
    let mut aggregate_loc = match normalize_type_loc(dwarf, type_name_index, loc)? {
        Some(loc) => loc,
        None => return Ok(None),
    };

    let header = dwarf.unit_header(aggregate_loc.cu_off)?;
    let unit = dwarf.unit(header)?;
    let entry = unit.entry(aggregate_loc.die_off)?;
    if pointer_like(entry.tag()) {
        let Some(target) = resolve_type_ref_with_origins(dwarf, &entry, &unit)? else {
            return Ok(None);
        };
        aggregate_loc = match normalize_type_loc(dwarf, type_name_index, target)? {
            Some(loc) => loc,
            None => return Ok(None),
        };
    }

    let header = dwarf.unit_header(aggregate_loc.cu_off)?;
    let unit = dwarf.unit(header)?;
    let entry = unit.entry(aggregate_loc.die_off)?;
    if !matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
    ) {
        return Ok(None);
    }

    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();
    while let Some(child) = children.next()? {
        let member = child.entry();
        if member.tag() != gimli::DW_TAG_member {
            continue;
        }
        let Some(name_attribute) = member.attr(gimli::DW_AT_name) else {
            continue;
        };
        let name_reader = dwarf.attr_string(&unit, name_attribute.value())?;
        let name = name_reader.to_string_lossy()?;
        if name.as_ref() != field {
            continue;
        }
        return resolve_type_ref_with_origins(dwarf, member, &unit);
    }

    Ok(None)
}

fn projected_element_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    loc: TypeLoc,
    dereference_only: bool,
) -> Result<Option<TypeLoc>> {
    let Some(base) = normalize_type_loc(dwarf, type_name_index, loc)? else {
        return Ok(None);
    };
    let header = dwarf.unit_header(base.cu_off)?;
    let unit = dwarf.unit(header)?;
    let entry = unit.entry(base.die_off)?;
    let supported = if dereference_only {
        pointer_like(entry.tag())
    } else {
        pointer_like(entry.tag()) || entry.tag() == gimli::DW_TAG_array_type
    };
    if !supported {
        return Ok(None);
    }
    resolve_type_ref_with_origins(dwarf, &entry, &unit)
}

fn template_type_parameter_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    loc: TypeLoc,
    index: usize,
) -> Result<Option<TypeLoc>> {
    let Some(aggregate_loc) = normalize_type_loc(dwarf, type_name_index, loc)? else {
        return Ok(None);
    };
    let header = dwarf.unit_header(aggregate_loc.cu_off)?;
    let unit = dwarf.unit(header)?;
    let entry = unit.entry(aggregate_loc.die_off)?;
    if !matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
    ) {
        return Ok(None);
    }

    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut children = root.children();
    let mut type_parameter_index = 0usize;
    while let Some(child) = children.next()? {
        let parameter = child.entry();
        if parameter.tag() != gimli::DW_TAG_template_type_parameter {
            continue;
        }
        if type_parameter_index == index {
            let Some(parameter_loc) = resolve_type_ref_with_origins(dwarf, parameter, &unit)?
            else {
                return Ok(None);
            };
            return normalize_type_loc(dwarf, type_name_index, parameter_loc);
        }
        type_parameter_index += 1;
    }

    Ok(None)
}

fn projected_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    loc: TypeLoc,
    segment: &VariableAccessSegment,
) -> Result<Option<TypeLoc>> {
    match segment {
        VariableAccessSegment::Field(field) => {
            projected_member_type_loc(dwarf, type_name_index, loc, field)
        }
        VariableAccessSegment::TupleIndex(index) => Err(anyhow::anyhow!(
            "tuple index '.{index}' was not resolved to a DWARF member"
        )),
        VariableAccessSegment::ArrayIndex(_) => {
            projected_element_type_loc(dwarf, type_name_index, loc, false)
        }
        VariableAccessSegment::Dereference => {
            projected_element_type_loc(dwarf, type_name_index, loc, true)
        }
    }
}

impl LoadedObjfile {
    pub(crate) fn compilation_unit_metadata(
        &self,
        module: ModuleId,
        cu: CuId,
    ) -> Result<Option<CompilationUnitMetadata>> {
        compilation_unit_metadata_from_dwarf(self.dwarf(), module, cu)
    }

    pub(crate) fn projected_type_id(
        &self,
        current: TypeId,
        segment: &VariableAccessSegment,
    ) -> Result<Option<TypeId>> {
        let type_name_index = self
            .type_name_index
            .read()
            .expect("type name index lock poisoned");
        projected_type_loc(self.dwarf(), &type_name_index, type_loc(current)?, segment)
            .map(|loc| loc.map(|loc| type_id_from_loc(current.module, loc)))
    }

    pub(crate) fn type_summary(&self, current: TypeId) -> Result<Option<crate::TypeInfo>> {
        let normalized = {
            let type_name_index = self
                .type_name_index
                .read()
                .expect("type name index lock poisoned");
            normalize_type_loc(self.dwarf(), &type_name_index, type_loc(current)?)?
        };
        Ok(normalized.and_then(|loc| self.detailed_shallow_type(loc.cu_off, loc.die_off)))
    }

    pub(crate) fn qualified_type_name(&self, current: TypeId) -> Result<Option<String>> {
        qualified_type_name_from_dwarf(self.dwarf(), type_loc(current)?)
    }

    pub(crate) fn template_type_parameter(
        &self,
        current: TypeId,
        index: usize,
    ) -> Result<Option<(TypeId, crate::TypeInfo)>> {
        let parameter_loc = {
            let type_name_index = self
                .type_name_index
                .read()
                .expect("type name index lock poisoned");
            template_type_parameter_loc(self.dwarf(), &type_name_index, type_loc(current)?, index)?
        };
        let Some(parameter_loc) = parameter_loc else {
            return Ok(None);
        };
        let Some(summary) = self.detailed_shallow_type(parameter_loc.cu_off, parameter_loc.die_off)
        else {
            return Ok(None);
        };

        Ok(Some((
            type_id_from_loc(current.module, parameter_loc),
            summary,
        )))
    }

    pub(crate) fn aggregate_type_id_by_name(&self, module: ModuleId, name: &str) -> Option<TypeId> {
        if let Err(error) = self.ensure_debug_info_for_type_name(name) {
            tracing::warn!(
                "Failed to load indexed DWARF for type '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        let type_name_index = self
            .type_name_index
            .read()
            .expect("type name index lock poisoned");
        [gimli::DW_TAG_structure_type, gimli::DW_TAG_class_type]
            .into_iter()
            .find_map(|tag| type_name_index.find_aggregate_definition(name, tag))
            .map(|loc| {
                type_id_from_loc(
                    module,
                    TypeLoc {
                        cu_off: loc.cu_offset,
                        die_off: loc.die_offset,
                    },
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::index::TypeNameIndex;
    use gimli::write::{
        AttributeValue as WriteAttributeValue, DebugInfoRef as WriteDebugInfoRef,
        Dwarf as WriteDwarf, EndianVec, LineProgram, Sections, Unit,
    };
    use gimli::{Format, LittleEndian};
    use std::sync::Arc;

    struct Fixture {
        dwarf: gimli::Dwarf<DwarfReader>,
        cu: CuId,
        pair: TypeLoc,
        generic: TypeLoc,
        int: TypeLoc,
        pair_pointer: TypeLoc,
        int_array: TypeLoc,
    }

    fn build_fixture() -> Fixture {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };
        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        {
            let unit = dwarf.units.get_mut(unit_id);
            let root = unit.root();
            unit.get_mut(root).set(
                gimli::DW_AT_language,
                WriteAttributeValue::Language(gimli::DW_LANG_Rust),
            );
            unit.get_mut(root).set(
                gimli::DW_AT_producer,
                WriteAttributeValue::String(b"rustc version 1.88.0".to_vec()),
            );

            let int = unit.add(root, gimli::DW_TAG_base_type);
            unit.get_mut(int).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"i32".to_vec()),
            );
            unit.get_mut(int)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            unit.get_mut(int).set(
                gimli::DW_AT_encoding,
                WriteAttributeValue::Encoding(gimli::DW_ATE_signed),
            );

            let pair = unit.add(root, gimli::DW_TAG_structure_type);
            unit.get_mut(pair).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"Pair".to_vec()),
            );
            unit.get_mut(pair)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            let member = unit.add(pair, gimli::DW_TAG_member);
            unit.get_mut(member).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"value".to_vec()),
            );
            unit.get_mut(member)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));

            let generic = unit.add(root, gimli::DW_TAG_structure_type);
            unit.get_mut(generic).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"Generic".to_vec()),
            );
            let parameter = unit.add(generic, gimli::DW_TAG_template_type_parameter);
            unit.get_mut(parameter).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"T".to_vec()),
            );
            unit.get_mut(parameter)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));

            let pair_pointer = unit.add(root, gimli::DW_TAG_pointer_type);
            unit.get_mut(pair_pointer)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(pair));
            unit.get_mut(pair_pointer)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(8));

            let int_array = unit.add(root, gimli::DW_TAG_array_type);
            unit.get_mut(int_array)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();
        let sections = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();
        let dwarf =
            sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));

        let header = dwarf.units().next().unwrap().unwrap();
        let cu_off = header.debug_info_offset().unwrap();
        let unit = dwarf.unit(header).unwrap();
        let mut structures = Vec::new();
        let mut int = None;
        let mut pair_pointer = None;
        let mut int_array = None;
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            let loc = TypeLoc {
                cu_off,
                die_off: entry.offset(),
            };
            match entry.tag() {
                gimli::DW_TAG_base_type => int = Some(loc),
                gimli::DW_TAG_structure_type => structures.push(loc),
                gimli::DW_TAG_pointer_type => pair_pointer = Some(loc),
                gimli::DW_TAG_array_type => int_array = Some(loc),
                _ => {}
            }
        }

        assert_eq!(structures.len(), 2);
        Fixture {
            dwarf,
            cu: CuId(cu_off.0 as u32),
            pair: structures[0],
            generic: structures[1],
            int: int.unwrap(),
            pair_pointer: pair_pointer.unwrap(),
            int_array: int_array.unwrap(),
        }
    }

    fn build_cross_cu_fixture() -> (gimli::Dwarf<DwarfReader>, TypeLoc, TypeLoc) {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };
        let mut dwarf = WriteDwarf::new();
        let rust_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let c_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));

        let c_int = {
            let c_unit = dwarf.units.get_mut(c_unit_id);
            let root = c_unit.root();
            c_unit.get_mut(root).set(
                gimli::DW_AT_language,
                WriteAttributeValue::Language(gimli::DW_LANG_C11),
            );
            c_unit.get_mut(root).set(
                gimli::DW_AT_producer,
                WriteAttributeValue::String(b"clang version 18".to_vec()),
            );
            let int = c_unit.add(root, gimli::DW_TAG_base_type);
            c_unit.get_mut(int).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"int".to_vec()),
            );
            c_unit
                .get_mut(int)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            int
        };

        {
            let rust_unit = dwarf.units.get_mut(rust_unit_id);
            let root = rust_unit.root();
            rust_unit.get_mut(root).set(
                gimli::DW_AT_language,
                WriteAttributeValue::Language(gimli::DW_LANG_Rust),
            );
            let wrapper = rust_unit.add(root, gimli::DW_TAG_structure_type);
            rust_unit.get_mut(wrapper).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"ForeignValue".to_vec()),
            );
            let member = rust_unit.add(wrapper, gimli::DW_TAG_member);
            rust_unit.get_mut(member).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"value".to_vec()),
            );
            rust_unit.get_mut(member).set(
                gimli::DW_AT_type,
                WriteAttributeValue::DebugInfoRef(WriteDebugInfoRef::Entry(c_unit_id, c_int)),
            );
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();
        let sections = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();
        let dwarf =
            sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));

        let mut units = dwarf.units();
        let rust_header = units.next().unwrap().unwrap();
        let c_header = units.next().unwrap().unwrap();
        let rust_cu = rust_header.debug_info_offset().unwrap();
        let c_cu = c_header.debug_info_offset().unwrap();
        let rust_unit = dwarf.unit(rust_header).unwrap();
        let c_unit = dwarf.unit(c_header).unwrap();
        let find_tag = |unit: &gimli::Unit<DwarfReader>, tag| {
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs().unwrap() {
                if entry.tag() == tag {
                    return entry.offset();
                }
            }
            panic!("missing expected type tag {tag:?}");
        };
        let wrapper = find_tag(&rust_unit, gimli::DW_TAG_structure_type);
        let int = find_tag(&c_unit, gimli::DW_TAG_base_type);

        (
            dwarf,
            TypeLoc {
                cu_off: rust_cu,
                die_off: wrapper,
            },
            TypeLoc {
                cu_off: c_cu,
                die_off: int,
            },
        )
    }

    fn build_qualified_name_fixture() -> (gimli::Dwarf<DwarfReader>, TypeLoc, TypeLoc) {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };
        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        {
            let unit = dwarf.units.get_mut(unit_id);
            let root = unit.root();

            let alloc = unit.add(root, gimli::DW_TAG_namespace);
            unit.get_mut(alloc).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"alloc".to_vec()),
            );
            let string = unit.add(alloc, gimli::DW_TAG_namespace);
            unit.get_mut(string).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"string".to_vec()),
            );
            let std_string = unit.add(string, gimli::DW_TAG_structure_type);
            unit.get_mut(std_string).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"String".to_vec()),
            );

            let app = unit.add(root, gimli::DW_TAG_namespace);
            unit.get_mut(app).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"app".to_vec()),
            );
            let app_string = unit.add(app, gimli::DW_TAG_structure_type);
            unit.get_mut(app_string).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"String".to_vec()),
            );
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();
        let sections = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();
        let dwarf =
            sections.borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));

        let header = dwarf.units().next().unwrap().unwrap();
        let cu_off = header.debug_info_offset().unwrap();
        let unit = dwarf.unit(header).unwrap();
        let mut strings = Vec::new();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            if entry.tag() == gimli::DW_TAG_structure_type {
                strings.push(TypeLoc {
                    cu_off,
                    die_off: entry.offset(),
                });
            }
        }
        assert_eq!(strings.len(), 2);

        (dwarf, strings[0], strings[1])
    }

    #[test]
    fn reads_language_and_producer_from_compilation_unit() {
        let fixture = build_fixture();
        let metadata =
            compilation_unit_metadata_from_dwarf(&fixture.dwarf, ModuleId(7), fixture.cu)
                .unwrap()
                .unwrap();

        assert_eq!(metadata.module, ModuleId(7));
        assert_eq!(metadata.language, SourceLanguage::Rust);
        assert_eq!(metadata.dwarf_version, 5);
        assert_eq!(
            metadata
                .producer
                .as_ref()
                .map(|producer| producer.raw.as_str()),
            Some("rustc version 1.88.0")
        );
    }

    #[test]
    fn follows_member_pointer_and_array_type_references() {
        let fixture = build_fixture();
        let types = TypeNameIndex::default();

        let member = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.pair,
            &VariableAccessSegment::Field("value".to_string()),
        )
        .unwrap();
        let pointer_member = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.pair_pointer,
            &VariableAccessSegment::Field("value".to_string()),
        )
        .unwrap();
        let dereferenced = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.pair_pointer,
            &VariableAccessSegment::Dereference,
        )
        .unwrap();
        let element = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.int_array,
            &VariableAccessSegment::ArrayIndex(3),
        )
        .unwrap();

        assert_eq!(member, Some(fixture.int));
        assert_eq!(pointer_member, Some(fixture.int));
        assert_eq!(dereferenced, Some(fixture.pair));
        assert_eq!(element, Some(fixture.int));
    }

    #[test]
    fn resolves_template_type_parameter_by_dwarf_order() {
        let fixture = build_fixture();
        let types = TypeNameIndex::default();

        assert_eq!(
            template_type_parameter_loc(&fixture.dwarf, &types, fixture.generic, 0).unwrap(),
            Some(fixture.int)
        );
        assert_eq!(
            template_type_parameter_loc(&fixture.dwarf, &types, fixture.generic, 1).unwrap(),
            None
        );
    }

    #[test]
    fn follows_cross_cu_member_type_and_changes_language_origin() {
        let (dwarf, wrapper, c_int) = build_cross_cu_fixture();
        let projected = projected_type_loc(
            &dwarf,
            &TypeNameIndex::default(),
            wrapper,
            &VariableAccessSegment::Field("value".to_string()),
        )
        .unwrap()
        .unwrap();
        let metadata = compilation_unit_metadata_from_dwarf(
            &dwarf,
            ModuleId(3),
            CuId(projected.cu_off.0 as u32),
        )
        .unwrap()
        .unwrap();

        assert_eq!(projected, c_int);
        assert_eq!(metadata.language, SourceLanguage::C);
        assert_eq!(
            metadata
                .producer
                .as_ref()
                .map(|producer| producer.raw.as_str()),
            Some("clang version 18")
        );
    }

    #[test]
    fn reconstructs_type_names_from_exact_namespace_ancestors() {
        let (dwarf, std_string, app_string) = build_qualified_name_fixture();

        assert_eq!(
            qualified_type_name_from_dwarf(&dwarf, std_string).unwrap(),
            Some("alloc::string::String".to_string())
        );
        assert_eq!(
            qualified_type_name_from_dwarf(&dwarf, app_string).unwrap(),
            Some("app::String".to_string())
        );
    }
}

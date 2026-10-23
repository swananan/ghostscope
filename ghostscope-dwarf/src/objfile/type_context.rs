//! DWARF-backed type identity and compilation-unit metadata queries.

use super::{variables::complete_aggregate_declaration_entry, LoadedObjfile};
use crate::{
    core::Result,
    semantics::{
        resolve_attr_with_unit_origins, resolve_name_with_origins, resolve_type_definition_loc,
        resolve_type_definition_ref_with_origins, resolve_type_ref_with_origins,
        CompilationUnitMetadata, ProducerInfo, SourceLanguage, TypeLoc, VariableAccessSegment,
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
        object: type_id.cu.1,
        cu_off: debug_info_offset(type_id.cu),
        die_off: gimli::UnitOffset(
            usize::try_from(type_id.die.offset).map_err(|_| {
                anyhow::anyhow!("type DIE offset does not fit this host: {type_id:?}")
            })?,
        ),
        importing_cu: type_id.importing_cu,
    })
}

fn type_id_from_loc(module: ModuleId, loc: TypeLoc) -> TypeId {
    loc.type_id(module)
}

fn qualified_type_name_from_dwarf(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    loc: TypeLoc,
) -> Result<Option<String>> {
    let unit = loc.unit(dwarf)?;
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
    let dwarf = cu.1.dwarf(dwarf)?;
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

fn type_metadata_from_dwarf(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    current: TypeId,
) -> Result<Option<CompilationUnitMetadata>> {
    let Some(mut metadata) =
        compilation_unit_metadata_from_dwarf(dwarf, current.module, current.cu)?
    else {
        return Ok(None);
    };
    if let Some(importing_cu) = current.importing_cu {
        if metadata.language == SourceLanguage::Unknown || metadata.producer.is_none() {
            if let Some(importer) =
                compilation_unit_metadata_from_dwarf(dwarf, current.module, importing_cu)?
            {
                if metadata.language == SourceLanguage::Unknown {
                    metadata.language = importer.language;
                }
                metadata.producer = metadata.producer.or(importer.producer);
            }
        }
    }
    Ok(Some(metadata))
}

// A module can materialize the defining CU on demand. Pure DWARF fixtures use
// an already populated index through the same normalization path.
trait AggregateDefinitionResolver {
    fn complete_declaration(
        &self,
        dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
    ) -> Result<Option<TypeLoc>>;
}

impl AggregateDefinitionResolver for crate::index::TypeNameIndex {
    fn complete_declaration(
        &self,
        dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
    ) -> Result<Option<TypeLoc>> {
        Ok(complete_aggregate_declaration_entry(
            dwarf, self, unit, entry,
        ))
    }
}

impl AggregateDefinitionResolver for LoadedObjfile {
    fn complete_declaration(
        &self,
        _dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
    ) -> Result<Option<TypeLoc>> {
        self.complete_aggregate_declaration(unit, entry)
    }
}

fn normalize_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    mut loc: TypeLoc,
) -> Result<Option<TypeLoc>> {
    let mut visited = HashSet::new();
    for _ in 0..MAX_TYPE_REFERENCE_DEPTH {
        let semantic_cu = loc.semantic_cu();
        let Some(definition_loc) = resolve_type_definition_loc(dwarf, loc)? else {
            return Ok(None);
        };
        loc = definition_loc.in_context(semantic_cu);
        if !visited.insert((loc.object, loc.cu_off.0, loc.die_off.0)) {
            return Err(anyhow::anyhow!(
                "cycle while resolving type DIE at {:?}:{:?}",
                loc.cu_off,
                loc.die_off
            ));
        }

        let unit = loc.unit(dwarf)?;
        let entry = unit.entry(loc.die_off)?;
        match entry.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {
                let Some(next) = resolve_type_ref_with_origins(dwarf, &entry, &unit)? else {
                    return Ok(None);
                };
                loc = next.in_context(semantic_cu);
            }
            gimli::DW_TAG_structure_type
            | gimli::DW_TAG_class_type
            | gimli::DW_TAG_union_type
            | gimli::DW_TAG_enumeration_type => {
                if let Some(definition) =
                    type_resolver.complete_declaration(dwarf, &unit, &entry)?
                {
                    loc = definition.in_context(semantic_cu);
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
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    field: &str,
) -> Result<Option<TypeLoc>> {
    let mut aggregate_loc = match normalize_type_loc(dwarf, type_resolver, loc)? {
        Some(loc) => loc,
        None => return Ok(None),
    };

    let unit = aggregate_loc.unit(dwarf)?;
    let entry = unit.entry(aggregate_loc.die_off)?;
    if pointer_like(entry.tag()) {
        let Some(target) = resolve_type_ref_with_origins(dwarf, &entry, &unit)? else {
            return Ok(None);
        };
        aggregate_loc = match normalize_type_loc(dwarf, type_resolver, target)? {
            Some(loc) => loc,
            None => return Ok(None),
        };
    }

    projected_aggregate_member_type_loc(
        dwarf,
        type_resolver,
        aggregate_loc,
        field,
        &HashSet::new(),
        0,
    )
}

fn projected_aggregate_member_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    field: &str,
    visited: &HashSet<(crate::DwarfObjectId, usize, usize)>,
    inheritance_depth: usize,
) -> Result<Option<TypeLoc>> {
    if inheritance_depth >= MAX_TYPE_REFERENCE_DEPTH {
        return Ok(None);
    }
    let Some(aggregate_loc) = normalize_type_loc(dwarf, type_resolver, loc)? else {
        return Ok(None);
    };
    let mut current_path = visited.clone();
    if !current_path.insert((
        aggregate_loc.object,
        aggregate_loc.cu_off.0,
        aggregate_loc.die_off.0,
    )) {
        return Ok(None);
    }

    let unit = aggregate_loc.unit(dwarf)?;
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
    let mut base_classes = Vec::new();
    while let Some(child) = children.next()? {
        let member = child.entry();
        if member.tag() == gimli::DW_TAG_member {
            if resolve_name_with_origins(dwarf, &unit, member)?.as_deref() == Some(field) {
                return resolve_type_ref_with_origins(dwarf, member, &unit);
            }
        } else if member.tag() == gimli::DW_TAG_inheritance {
            if let Some(base_class) =
                resolve_type_definition_ref_with_origins(dwarf, member, &unit)?
            {
                base_classes.push(base_class);
            }
        }
    }

    let mut inherited_member = None;
    for base_class in base_classes {
        if let Some(member) = projected_aggregate_member_type_loc(
            dwarf,
            type_resolver,
            base_class,
            field,
            &current_path,
            inheritance_depth + 1,
        )? {
            if inherited_member.is_some() {
                let kind = match entry.tag() {
                    gimli::DW_TAG_class_type => "class",
                    gimli::DW_TAG_union_type => "union",
                    _ => "struct",
                };
                let type_name = resolve_name_with_origins(dwarf, &unit, &entry)?
                    .unwrap_or_else(|| "<anonymous>".to_string());
                return Err(crate::TypeLayoutError::AmbiguousMember {
                    kind,
                    type_name,
                    field: field.to_string(),
                }
                .into());
            }
            inherited_member = Some(member);
        }
    }
    Ok(inherited_member)
}

fn variant_member_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    part_index: usize,
    variant_index: usize,
    member_index: usize,
) -> Result<Option<TypeLoc>> {
    let Some(aggregate_loc) = normalize_type_loc(dwarf, type_resolver, loc)? else {
        return Ok(None);
    };
    let unit = aggregate_loc.unit(dwarf)?;
    let entry = unit.entry(aggregate_loc.die_off)?;
    if !matches!(
        entry.tag(),
        gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
    ) {
        return Ok(None);
    }

    let mut tree = unit.entries_tree(Some(entry.offset()))?;
    let root = tree.root()?;
    let mut parts = root.children();
    let mut current_part = 0usize;
    while let Some(part) = parts.next()? {
        if part.entry().tag() != gimli::DW_TAG_variant_part {
            continue;
        }
        if current_part != part_index {
            current_part += 1;
            continue;
        }

        let mut variants = part.children();
        let mut current_variant = 0usize;
        while let Some(variant) = variants.next()? {
            if variant.entry().tag() != gimli::DW_TAG_variant {
                continue;
            }
            if current_variant != variant_index {
                current_variant += 1;
                continue;
            }

            let mut members = variant.children();
            let mut current_member = 0usize;
            while let Some(member) = members.next()? {
                if member.entry().tag() != gimli::DW_TAG_member {
                    continue;
                }
                if current_member == member_index {
                    return resolve_type_ref_with_origins(dwarf, member.entry(), &unit);
                }
                current_member += 1;
            }
            return Ok(None);
        }
        return Ok(None);
    }

    Ok(None)
}

fn projected_element_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    dereference_only: bool,
) -> Result<Option<TypeLoc>> {
    let Some(base) = normalize_type_loc(dwarf, type_resolver, loc)? else {
        return Ok(None);
    };
    let unit = base.unit(dwarf)?;
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
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    index: usize,
) -> Result<Option<TypeLoc>> {
    let Some(aggregate_loc) = normalize_type_loc(dwarf, type_resolver, loc)? else {
        return Ok(None);
    };
    let unit = aggregate_loc.unit(dwarf)?;
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
            return normalize_type_loc(dwarf, type_resolver, parameter_loc);
        }
        type_parameter_index += 1;
    }

    Ok(None)
}

fn type_alignment_from_dwarf(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
) -> Result<Option<u64>> {
    let Some(loc) = normalize_type_loc(dwarf, type_resolver, loc)? else {
        return Ok(None);
    };
    let unit = loc.unit(dwarf)?;
    let entry = unit.entry(loc.die_off)?;
    Ok(
        resolve_attr_with_unit_origins(dwarf, &entry, &unit, gimli::DW_AT_alignment)?
            .and_then(crate::core::attr_u64),
    )
}

fn projected_type_loc(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_resolver: &impl AggregateDefinitionResolver,
    loc: TypeLoc,
    segment: &VariableAccessSegment,
) -> Result<Option<TypeLoc>> {
    match segment {
        VariableAccessSegment::Field(field) => {
            projected_member_type_loc(dwarf, type_resolver, loc, field)
        }
        VariableAccessSegment::TupleIndex(index) => Err(anyhow::anyhow!(
            "tuple index '.{index}' was not resolved to a DWARF member"
        )),
        VariableAccessSegment::ArrayIndex(_) => {
            projected_element_type_loc(dwarf, type_resolver, loc, false)
        }
        VariableAccessSegment::Dereference => {
            projected_element_type_loc(dwarf, type_resolver, loc, true)
        }
    }
}

impl LoadedObjfile {
    pub(super) fn type_language(
        &self,
        loc: TypeLoc,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
    ) -> SourceLanguage {
        let language = self.compilation_unit_language(loc.cu_off, unit);
        if language == SourceLanguage::Unknown {
            if let Some(importing_cu) = loc.importing_cu {
                let offset = debug_info_offset(importing_cu);
                if let Ok(unit) = self.unit_in(importing_cu.1, offset) {
                    return self.compilation_unit_language(offset, &unit);
                }
            }
        }
        language
    }

    pub(super) fn compilation_unit_language(
        &self,
        cu_off: gimli::DebugInfoOffset,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
    ) -> SourceLanguage {
        let key = (
            crate::binary::references::unit_object(self.dwarf(), unit),
            cu_off,
        );
        if let Some(language) = self
            .compilation_unit_languages
            .read()
            .expect("compilation unit language cache lock poisoned")
            .get(&key)
            .copied()
        {
            return language;
        }

        let mut entries = unit.entries();
        let dwarf_language = entries.next_dfs().ok().flatten().and_then(|root| {
            match root.attr_value(gimli::DW_AT_language) {
                Some(gimli::AttributeValue::Language(language)) => Some(language),
                _ => None,
            }
        });
        let language = SourceLanguage::from_dwarf(dwarf_language);
        *self
            .compilation_unit_languages
            .write()
            .expect("compilation unit language cache lock poisoned")
            .entry(key)
            .or_insert(language)
    }

    pub(crate) fn compilation_unit_metadata(
        &self,
        module: ModuleId,
        cu: CuId,
    ) -> Result<Option<CompilationUnitMetadata>> {
        compilation_unit_metadata_from_dwarf(self.dwarf(), module, cu)
    }

    pub(crate) fn type_metadata(&self, current: TypeId) -> Result<Option<CompilationUnitMetadata>> {
        type_metadata_from_dwarf(self.dwarf(), current)
    }

    pub(crate) fn projected_type_id(
        &self,
        current: TypeId,
        segment: &VariableAccessSegment,
    ) -> Result<Option<TypeId>> {
        let current_loc = type_loc(current)?;
        projected_type_loc(self.dwarf(), self, current_loc, segment).map(|loc| {
            loc.map(|loc| {
                type_id_from_loc(current.module, loc.in_context(current_loc.semantic_cu()))
            })
        })
    }

    pub(crate) fn variant_member_type_id(
        &self,
        current: TypeId,
        part_index: usize,
        variant_index: usize,
        member_index: usize,
    ) -> Result<Option<TypeId>> {
        let current_loc = type_loc(current)?;
        variant_member_type_loc(
            self.dwarf(),
            self,
            current_loc,
            part_index,
            variant_index,
            member_index,
        )
        .map(|loc| {
            loc.map(|loc| {
                type_id_from_loc(current.module, loc.in_context(current_loc.semantic_cu()))
            })
        })
    }

    pub(crate) fn type_summary(&self, current: TypeId) -> Result<Option<crate::TypeInfo>> {
        let normalized = normalize_type_loc(self.dwarf(), self, type_loc(current)?)?;
        Ok(normalized.and_then(|loc| self.detailed_shallow_type_loc(loc)))
    }

    pub(crate) fn qualified_type_name(&self, current: TypeId) -> Result<Option<String>> {
        qualified_type_name_from_dwarf(self.dwarf(), type_loc(current)?)
    }

    pub(crate) fn template_type_parameter(
        &self,
        current: TypeId,
        index: usize,
    ) -> Result<Option<(TypeId, crate::TypeInfo)>> {
        let parameter_loc =
            template_type_parameter_loc(self.dwarf(), self, type_loc(current)?, index)?;
        let Some(parameter_loc) = parameter_loc else {
            return Ok(None);
        };
        let parameter_loc = parameter_loc.in_context(type_loc(current)?.semantic_cu());
        let Some(summary) = self.detailed_shallow_type_loc(parameter_loc) else {
            return Ok(None);
        };

        Ok(Some((
            type_id_from_loc(current.module, parameter_loc),
            summary,
        )))
    }

    pub(crate) fn type_alignment(&self, current: TypeId) -> Result<Option<u64>> {
        type_alignment_from_dwarf(self.dwarf(), self, type_loc(current)?)
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
        let type_name_index = self.type_name_index().ok()?;
        [gimli::DW_TAG_structure_type, gimli::DW_TAG_class_type]
            .into_iter()
            .find_map(|tag| type_name_index.find_aggregate_definition(name, tag))
            .map(|loc| {
                type_id_from_loc(
                    module,
                    TypeLoc {
                        object: loc.object,
                        cu_off: loc.cu_offset,
                        die_off: loc.die_offset,
                        importing_cu: loc.importing_cu,
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
        derived: TypeLoc,
        ambiguous_derived: TypeLoc,
    }

    #[test]
    fn supplementary_metadata_inherits_only_missing_attributes() {
        for language in [None, Some(gimli::DW_LANG_C11)] {
            for producer in [None, Some("supplementary producer")] {
                let mut primary = build_fixture();
                let mut written = WriteDwarf::new();
                let id = written.units.add(Unit::new(
                    gimli::Encoding {
                        format: Format::Dwarf32,
                        version: 4,
                        address_size: 8,
                    },
                    LineProgram::none(),
                ));
                let unit = written.units.get_mut(id);
                let root = unit.root();
                if let Some(language) = language {
                    unit.get_mut(root).set(
                        gimli::DW_AT_language,
                        WriteAttributeValue::Language(language),
                    );
                }
                if let Some(producer) = producer {
                    unit.get_mut(root).set(
                        gimli::DW_AT_producer,
                        WriteAttributeValue::String(producer.as_bytes().to_vec()),
                    );
                }
                let mut sections = Sections::new(EndianVec::new(LittleEndian));
                written.write(&mut sections).unwrap();
                let supplementary = gimli::Dwarf::load(|id| {
                    Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::from(
                        sections.get(id).map_or(&[][..], |section| section.slice()),
                    )))
                })
                .unwrap();
                let header = supplementary.units().next().unwrap().unwrap();
                let loc = TypeLoc {
                    object: crate::DwarfObjectId::Supplementary,
                    cu_off: header.debug_info_offset().unwrap(),
                    die_off: header.root_offset(),
                    importing_cu: Some(primary.cu),
                };
                primary.dwarf.set_sup(supplementary);
                let metadata = type_metadata_from_dwarf(&primary.dwarf, loc.type_id(ModuleId(7)))
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    metadata.language,
                    if language.is_some() {
                        SourceLanguage::C
                    } else {
                        SourceLanguage::Rust
                    }
                );
                assert_eq!(
                    metadata.producer.unwrap().raw,
                    producer.unwrap_or("rustc version 1.88.0")
                );
                assert_eq!(metadata.dwarf_version, 4);
                assert_eq!(metadata.cu.1, crate::DwarfObjectId::Supplementary);
            }
        }
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

            let base = unit.add(root, gimli::DW_TAG_structure_type);
            unit.get_mut(base).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"Base".to_vec()),
            );
            unit.get_mut(base)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(8));
            let inherited = unit.add(base, gimli::DW_TAG_member);
            unit.get_mut(inherited).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"inherited".to_vec()),
            );
            unit.get_mut(inherited)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));
            unit.get_mut(inherited).set(
                gimli::DW_AT_data_member_location,
                WriteAttributeValue::Udata(4),
            );

            let derived = unit.add(root, gimli::DW_TAG_class_type);
            unit.get_mut(derived).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"Derived".to_vec()),
            );
            unit.get_mut(derived)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(20));
            let inheritance = unit.add(derived, gimli::DW_TAG_inheritance);
            unit.get_mut(inheritance)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(base));
            unit.get_mut(inheritance).set(
                gimli::DW_AT_data_member_location,
                WriteAttributeValue::Udata(8),
            );
            let own = unit.add(derived, gimli::DW_TAG_member);
            unit.get_mut(own).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"own".to_vec()),
            );
            unit.get_mut(own)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));
            unit.get_mut(own).set(
                gimli::DW_AT_data_member_location,
                WriteAttributeValue::Udata(16),
            );

            let other_base = unit.add(root, gimli::DW_TAG_structure_type);
            unit.get_mut(other_base).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"OtherBase".to_vec()),
            );
            unit.get_mut(other_base)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            let other_inherited = unit.add(other_base, gimli::DW_TAG_member);
            unit.get_mut(other_inherited).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"inherited".to_vec()),
            );
            unit.get_mut(other_inherited)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(int));

            let ambiguous_derived = unit.add(root, gimli::DW_TAG_class_type);
            unit.get_mut(ambiguous_derived).set(
                gimli::DW_AT_name,
                WriteAttributeValue::String(b"AmbiguousDerived".to_vec()),
            );
            unit.get_mut(ambiguous_derived)
                .set(gimli::DW_AT_byte_size, WriteAttributeValue::Data1(12));
            let first_inheritance = unit.add(ambiguous_derived, gimli::DW_TAG_inheritance);
            unit.get_mut(first_inheritance)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(base));
            let second_inheritance = unit.add(ambiguous_derived, gimli::DW_TAG_inheritance);
            unit.get_mut(second_inheritance)
                .set(gimli::DW_AT_type, WriteAttributeValue::UnitRef(other_base));
            unit.get_mut(second_inheritance).set(
                gimli::DW_AT_data_member_location,
                WriteAttributeValue::Udata(8),
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
        let mut structures = Vec::new();
        let mut int = None;
        let mut pair_pointer = None;
        let mut int_array = None;
        let mut classes = Vec::new();
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            let loc = TypeLoc {
                importing_cu: None,
                object: crate::DwarfObjectId::Primary,
                cu_off,
                die_off: entry.offset(),
            };
            match entry.tag() {
                gimli::DW_TAG_base_type => int = Some(loc),
                gimli::DW_TAG_structure_type => structures.push(loc),
                gimli::DW_TAG_pointer_type => pair_pointer = Some(loc),
                gimli::DW_TAG_array_type => int_array = Some(loc),
                gimli::DW_TAG_class_type => classes.push(loc),
                _ => {}
            }
        }

        assert_eq!(structures.len(), 4);
        assert_eq!(classes.len(), 2);
        Fixture {
            dwarf,
            cu: CuId::primary(cu_off.0 as u64),
            pair: structures[0],
            generic: structures[1],
            int: int.unwrap(),
            pair_pointer: pair_pointer.unwrap(),
            int_array: int_array.unwrap(),
            derived: classes[0],
            ambiguous_derived: classes[1],
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
                importing_cu: None,
                object: crate::DwarfObjectId::Primary,
                cu_off: rust_cu,
                die_off: wrapper,
            },
            TypeLoc {
                importing_cu: None,
                object: crate::DwarfObjectId::Primary,
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
                    importing_cu: None,
                    object: crate::DwarfObjectId::Primary,
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
            metadata.rustc_version(),
            Some(crate::RustcVersion::new(1, 88, 0))
        );
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
    fn follows_inheritance_for_member_type_and_layout() {
        let fixture = build_fixture();
        let types = TypeNameIndex::default();

        let inherited = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.derived,
            &VariableAccessSegment::Field("inherited".to_string()),
        )
        .unwrap();
        assert_eq!(inherited, Some(fixture.int));

        let header = fixture.dwarf.unit_header(fixture.derived.cu_off).unwrap();
        let unit = fixture.dwarf.unit(header).unwrap();
        let summary = crate::parser::DetailedParser::resolve_type_shallow_at_offset(
            &fixture.dwarf,
            &unit,
            fixture.derived.die_off,
            SourceLanguage::Cpp,
        )
        .unwrap();
        let crate::TypeInfo::StructType { members, .. } = summary else {
            panic!("expected derived class summary");
        };

        assert_eq!(
            members
                .iter()
                .find(|member| member.name == "inherited")
                .map(|member| member.offset),
            Some(12)
        );
        assert_eq!(
            members
                .iter()
                .find(|member| member.name == "own")
                .map(|member| member.offset),
            Some(16)
        );
    }

    #[test]
    fn rejects_ambiguous_inherited_member_paths() {
        let fixture = build_fixture();
        let types = TypeNameIndex::default();

        let projected_error = projected_type_loc(
            &fixture.dwarf,
            &types,
            fixture.ambiguous_derived,
            &VariableAccessSegment::Field("inherited".to_string()),
        )
        .expect_err("two inherited paths should be ambiguous");
        assert!(matches!(
            projected_error.downcast_ref::<crate::TypeLayoutError>(),
            Some(crate::TypeLayoutError::AmbiguousMember { field, .. })
                if field == "inherited"
        ));

        let header = fixture
            .dwarf
            .unit_header(fixture.ambiguous_derived.cu_off)
            .unwrap();
        let unit = fixture.dwarf.unit(header).unwrap();
        let summary = crate::parser::DetailedParser::resolve_type_shallow_at_offset(
            &fixture.dwarf,
            &unit,
            fixture.ambiguous_derived.die_off,
            SourceLanguage::Cpp,
        )
        .unwrap();
        assert!(matches!(
            crate::member_layout(&summary, "inherited"),
            Err(crate::TypeLayoutError::AmbiguousMember { field, .. })
                if field == "inherited"
        ));
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
            CuId::primary(projected.cu_off.0 as u64),
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

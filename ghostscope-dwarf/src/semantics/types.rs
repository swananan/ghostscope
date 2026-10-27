use super::origins::resolve_origin_entry;
use crate::binary::{
    references::{unit_dwarf, unit_object},
    DwarfReader,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypeLoc {
    pub object: crate::DwarfObjectId,
    pub cu_off: gimli::DebugInfoOffset,
    pub die_off: gimli::UnitOffset,
    pub importing_cu: Option<crate::CuId>,
}

impl TypeLoc {
    pub(crate) fn semantic_cu(self) -> crate::CuId {
        self.importing_cu
            .unwrap_or(crate::CuId(self.cu_off.0 as u64, self.object))
    }

    pub(crate) fn in_context(mut self, cu: crate::CuId) -> Self {
        if self.object == crate::DwarfObjectId::Supplementary
            && cu.1 == crate::DwarfObjectId::Primary
        {
            self.importing_cu = Some(cu);
        }
        self
    }

    pub(crate) fn unit(
        self,
        dwarf: &gimli::Dwarf<DwarfReader>,
    ) -> gimli::Result<gimli::Unit<DwarfReader>> {
        let source = self.object.dwarf(dwarf)?;
        source.unit(source.unit_header(self.cu_off)?)
    }

    pub(crate) fn type_id(self, module: crate::ModuleId) -> crate::TypeId {
        let cu = crate::CuId(self.cu_off.0 as u64, self.object);
        crate::TypeId {
            module,
            cu,
            importing_cu: self.importing_cu,
            die: crate::DieRef {
                module,
                cu,
                offset: self.die_off.0 as u64,
            },
        }
    }
}

fn type_unit_loc_by_signature(
    dwarf: &gimli::Dwarf<DwarfReader>,
    signature: gimli::DebugTypeSignature,
) -> crate::core::Result<Option<TypeLoc>> {
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let type_offset = match header.type_() {
            gimli::UnitType::Type {
                type_signature,
                type_offset,
            }
            | gimli::UnitType::SplitType {
                type_signature,
                type_offset,
            } if type_signature == signature => type_offset,
            _ => continue,
        };
        let cu_off = header
            .debug_info_offset()
            .ok_or_else(|| anyhow::anyhow!("type unit missing debug_info offset"))?;
        return Ok(Some(TypeLoc {
            object: crate::DwarfObjectId::Primary,
            cu_off,
            die_off: type_offset,
            importing_cu: None,
        }));
    }
    Ok(None)
}

fn type_loc_from_attr_value(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    value: gimli::AttributeValue<DwarfReader>,
) -> crate::core::Result<Option<TypeLoc>> {
    // Preserve the cheap same-unit path for ordinary (non-supplementary) DWARF.
    let local_offset = match &value {
        gimli::AttributeValue::UnitRef(offset) => Some(*offset),
        gimli::AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    };
    if let Some(die_off) = local_offset {
        return Ok(Some(TypeLoc {
            object: unit_object(dwarf, unit),
            cu_off: unit
                .header
                .debug_info_offset()
                .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?,
            die_off,
            importing_cu: None,
        }));
    }
    if let gimli::AttributeValue::DebugTypesRef(signature) = value {
        let mut location = type_unit_loc_by_signature(unit_dwarf(dwarf, unit)?, signature)?;
        if let Some(loc) = location.as_mut() {
            loc.object = unit_object(dwarf, unit);
        }
        return Ok(location);
    }
    let Some((_, target_unit, target_entry)) = resolve_origin_entry(dwarf, unit, value)? else {
        return Ok(None);
    };
    Ok(Some(TypeLoc {
        object: unit_object(dwarf, &target_unit),
        cu_off: target_unit
            .header
            .debug_info_offset()
            .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?,
        die_off: target_entry.offset(),
        importing_cu: None,
    }))
}

/// Follow a declaration DIE's `DW_AT_signature` to its DWARF5 type-unit definition.
///
/// A producer may use a unit-relative reference to a signature-bearing declaration
/// instead of referencing the type-unit signature directly with `DW_FORM_ref_sig8`.
pub(crate) fn resolve_type_definition_loc(
    dwarf: &gimli::Dwarf<DwarfReader>,
    loc: TypeLoc,
) -> crate::core::Result<Option<TypeLoc>> {
    let unit = loc.unit(dwarf)?;
    Ok(resolve_type_definition_loc_with_unit(dwarf, loc, unit)?.map(|(loc, _)| loc))
}

/// Retain the parsed unit so callers walking type chains can reuse it.
pub(crate) fn resolve_type_definition_loc_with_unit(
    dwarf: &gimli::Dwarf<DwarfReader>,
    mut loc: TypeLoc,
    mut unit: gimli::Unit<DwarfReader>,
) -> crate::core::Result<Option<(TypeLoc, gimli::Unit<DwarfReader>)>> {
    const MAX_SIGNATURE_DEPTH: usize = 64;
    let mut visited = std::collections::HashSet::new();

    for _ in 0..MAX_SIGNATURE_DEPTH {
        if !visited.insert((loc.object, loc.cu_off.0, loc.die_off.0)) {
            return Ok(None);
        }

        if loc.object != unit_object(dwarf, &unit)
            || unit.header.debug_info_offset() != Some(loc.cu_off)
        {
            unit = loc.unit(dwarf)?;
        }
        let entry = unit.entry(loc.die_off)?;
        let Some(value) = entry.attr_value(gimli::constants::DW_AT_signature) else {
            return Ok(Some((loc, unit)));
        };
        let gimli::AttributeValue::DebugTypesRef(signature) = value else {
            return Ok(Some((loc, unit)));
        };
        let source = loc.object.dwarf(dwarf)?;
        let Some(definition) = type_unit_loc_by_signature(source, signature)? else {
            return Ok(None);
        };
        loc = TypeLoc {
            object: loc.object,
            importing_cu: loc.importing_cu,
            ..definition
        };
    }

    Ok(None)
}

pub(crate) fn resolve_type_definition_ref_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
) -> crate::core::Result<Option<TypeLoc>> {
    let Some(loc) = resolve_type_ref_with_origins(dwarf, entry, unit)? else {
        return Ok(None);
    };
    if loc.object == unit_object(dwarf, unit)
        && unit.header.debug_info_offset() == Some(loc.cu_off)
        && unit
            .entry(loc.die_off)?
            .attr_value(gimli::DW_AT_signature)
            .is_none()
    {
        return Ok(Some(loc));
    }
    resolve_type_definition_loc(dwarf, loc)
}

pub(crate) fn resolve_type_ref_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
) -> crate::core::Result<Option<TypeLoc>> {
    fn inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        visited: &mut std::collections::HashSet<(crate::DwarfObjectId, gimli::DebugInfoOffset)>,
    ) -> crate::core::Result<Option<TypeLoc>> {
        if let Some(value) = entry.attr_value(gimli::constants::DW_AT_type) {
            return type_loc_from_attr_value(dwarf, unit, value);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((origin_abs, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)?
                {
                    if visited.len() < 64
                        && visited.insert((unit_object(dwarf, &origin_unit), origin_abs))
                    {
                        if let Some(v) = inner(dwarf, &origin_entry, &origin_unit, visited)? {
                            return Ok(Some(v));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    let location = if let Some(value) = entry.attr_value(gimli::constants::DW_AT_type) {
        type_loc_from_attr_value(dwarf, unit, value)?
    } else {
        let has_origin = entry.attr_value(gimli::DW_AT_abstract_origin).is_some()
            || entry.attr_value(gimli::DW_AT_specification).is_some();
        if !has_origin {
            return Ok(None);
        }
        let mut visited = std::collections::HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert((unit_object(dwarf, unit), entry_abs));
        }
        inner(dwarf, entry, unit, &mut visited)?
    };
    Ok(location.map(|loc| match unit.header.debug_info_offset() {
        Some(offset) => loc.in_context(crate::CuId(offset.0 as u64, unit_object(dwarf, unit))),
        None => loc,
    }))
}

pub(crate) fn resolve_type_ref_in_same_unit_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
) -> crate::core::Result<Option<gimli::UnitOffset>> {
    let unit_cu_off = unit
        .header
        .debug_info_offset()
        .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?;
    Ok(resolve_type_ref_with_origins(dwarf, entry, unit)?
        .filter(|loc| loc.cu_off == unit_cu_off && loc.object == unit_object(dwarf, unit))
        .map(|loc| loc.die_off))
}

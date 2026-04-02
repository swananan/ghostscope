use super::origins::resolve_origin_entry;
use gimli::{EndianArcSlice, LittleEndian};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TypeLoc {
    pub cu_off: gimli::DebugInfoOffset,
    pub die_off: gimli::UnitOffset,
}

fn resolve_debug_info_ref(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    debug_info_off: gimli::DebugInfoOffset,
) -> crate::core::Result<Option<(gimli::Unit<EndianArcSlice<LittleEndian>>, TypeLoc)>> {
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        if let Some(die_off) = debug_info_off.to_unit_offset(&header) {
            let target_unit = dwarf.unit(header)?;
            let cu_off = target_unit
                .header
                .debug_info_offset()
                .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?;
            return Ok(Some((target_unit, TypeLoc { cu_off, die_off })));
        }
    }
    Ok(None)
}

fn type_loc_from_attr_value(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    value: gimli::AttributeValue<EndianArcSlice<LittleEndian>>,
) -> crate::core::Result<Option<TypeLoc>> {
    let cu_off = unit
        .header
        .debug_info_offset()
        .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?;
    match value {
        gimli::AttributeValue::UnitRef(die_off) => Ok(Some(TypeLoc { cu_off, die_off })),
        gimli::AttributeValue::DebugInfoRef(debug_info_off) => {
            if let Some(die_off) = debug_info_off.to_unit_offset(&unit.header) {
                return Ok(Some(TypeLoc { cu_off, die_off }));
            }
            Ok(resolve_debug_info_ref(dwarf, debug_info_off)?.map(|(_, loc)| loc))
        }
        _ => Ok(None),
    }
}

pub(crate) fn resolve_type_ref_with_origins(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
) -> crate::core::Result<Option<TypeLoc>> {
    fn inner(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        visited: &mut std::collections::HashSet<gimli::DebugInfoOffset>,
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
                    if visited.insert(origin_abs) {
                        if let Some(v) = inner(dwarf, &origin_entry, &origin_unit, visited)? {
                            return Ok(Some(v));
                        }
                    }
                }
            }
        }
        Ok(None)
    }

    if let Some(value) = entry.attr_value(gimli::constants::DW_AT_type) {
        return type_loc_from_attr_value(dwarf, unit, value);
    }

    let has_origin = entry
        .attr_value(gimli::constants::DW_AT_abstract_origin)
        .is_some()
        || entry
            .attr_value(gimli::constants::DW_AT_specification)
            .is_some();
    if !has_origin {
        return Ok(None);
    }

    let mut visited = std::collections::HashSet::with_capacity(4);
    if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
        visited.insert(entry_abs);
    }
    inner(dwarf, entry, unit, &mut visited)
}

pub(crate) fn resolve_type_ref_in_same_unit_with_origins(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
) -> crate::core::Result<Option<gimli::UnitOffset>> {
    let unit_cu_off = unit
        .header
        .debug_info_offset()
        .ok_or_else(|| anyhow::anyhow!("unit missing debug_info offset"))?;
    Ok(resolve_type_ref_with_origins(dwarf, entry, unit)?
        .filter(|loc| loc.cu_off == unit_cu_off)
        .map(|loc| loc.die_off))
}

pub(crate) fn strip_typedef_qualified(
    dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    mut type_loc: TypeLoc,
) -> crate::core::Result<TypeLoc> {
    loop {
        let header = dwarf.unit_header(type_loc.cu_off)?;
        let unit = dwarf.unit(header)?;
        let die = unit.entry(type_loc.die_off)?;
        match die.tag() {
            gimli::DW_TAG_typedef
            | gimli::DW_TAG_const_type
            | gimli::DW_TAG_volatile_type
            | gimli::DW_TAG_restrict_type => {
                if let Some(next) = resolve_type_ref_with_origins(dwarf, &die, &unit)? {
                    type_loc = next;
                    continue;
                }
            }
            _ => {}
        }
        return Ok(type_loc);
    }
}

use gimli::{EndianArcSlice, LittleEndian, Reader};
use std::collections::HashSet;

type DwarfReader = EndianArcSlice<LittleEndian>;
type DwarfUnit = gimli::Unit<DwarfReader>;
type DwarfEntry = gimli::DebuggingInformationEntry<DwarfReader>;

pub(crate) type ResolvedOriginEntry = (gimli::DebugInfoOffset, DwarfUnit, DwarfEntry);
pub(crate) type ResolvedUnitEntry = (DwarfUnit, DwarfEntry);

pub(crate) fn resolve_attr_with_unit_origins(
    entry: &DwarfEntry,
    unit: &DwarfUnit,
    attr: gimli::DwAt,
) -> gimli::read::Result<Option<gimli::AttributeValue<DwarfReader>>> {
    if let Some(value) = entry.attr_value(attr) {
        return Ok(Some(value));
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

    let mut visited = HashSet::with_capacity(4);
    visited.insert(entry.offset());
    resolve_attr_with_unit_origins_inner(entry, unit, attr, &mut visited)
}

pub(crate) fn resolve_attr_with_unit_origins_inner(
    entry: &DwarfEntry,
    unit: &DwarfUnit,
    attr: gimli::DwAt,
    visited: &mut HashSet<gimli::UnitOffset>,
) -> gimli::read::Result<Option<gimli::AttributeValue<DwarfReader>>> {
    if let Some(value) = entry.attr_value(attr) {
        return Ok(Some(value));
    }

    for origin_attr in [
        gimli::constants::DW_AT_abstract_origin,
        gimli::constants::DW_AT_specification,
    ] {
        if let Some(gimli::AttributeValue::UnitRef(offset)) = entry.attr_value(origin_attr) {
            if visited.insert(offset) {
                let origin_entry = unit.entry(offset)?;
                if let Some(value) =
                    resolve_attr_with_unit_origins_inner(&origin_entry, unit, attr, visited)?
                {
                    return Ok(Some(value));
                }
            }
        }
    }

    Ok(None)
}

fn resolve_debug_info_ref(
    dwarf: &gimli::Dwarf<DwarfReader>,
    debug_info_off: gimli::DebugInfoOffset,
) -> gimli::read::Result<Option<ResolvedUnitEntry>> {
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        if let Some(unit_off) = debug_info_off.to_unit_offset(&header) {
            let target_unit = dwarf.unit(header)?;
            let target_entry = target_unit.entry(unit_off)?;
            return Ok(Some((target_unit, target_entry)));
        }
    }
    Ok(None)
}

fn reload_current_unit(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
) -> gimli::read::Result<DwarfUnit> {
    dwarf.unit(unit.header.clone())
}

pub(crate) fn resolve_origin_entry(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    value: gimli::AttributeValue<DwarfReader>,
) -> gimli::read::Result<Option<ResolvedOriginEntry>> {
    match value {
        gimli::AttributeValue::UnitRef(offset) => {
            let Some(debug_info_off) = offset.to_debug_info_offset(&unit.header) else {
                return Ok(None);
            };
            let origin_unit = reload_current_unit(dwarf, unit)?;
            let origin_entry = origin_unit.entry(offset)?;
            Ok(Some((debug_info_off, origin_unit, origin_entry)))
        }
        gimli::AttributeValue::DebugInfoRef(debug_info_off) => {
            if let Some(unit_off) = debug_info_off.to_unit_offset(&unit.header) {
                let origin_unit = reload_current_unit(dwarf, unit)?;
                let origin_entry = origin_unit.entry(unit_off)?;
                return Ok(Some((debug_info_off, origin_unit, origin_entry)));
            }

            let Some((origin_unit, origin_entry)) = resolve_debug_info_ref(dwarf, debug_info_off)?
            else {
                return Ok(None);
            };
            Ok(Some((debug_info_off, origin_unit, origin_entry)))
        }
        _ => Ok(None),
    }
}

fn read_name_attr(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
) -> gimli::read::Result<Option<String>> {
    if let Some(attr) = entry.attr(gimli::DW_AT_name) {
        if let Ok(name) = dwarf.attr_string(unit, attr.value()) {
            if let Ok(name) = name.to_string_lossy() {
                return Ok(Some(name.into_owned()));
            }
        }
    }
    Ok(None)
}

pub(crate) fn resolve_name_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
) -> gimli::read::Result<Option<String>> {
    fn inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &DwarfUnit,
        entry: &DwarfEntry,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> gimli::read::Result<Option<String>> {
        if let Some(name) = read_name_attr(dwarf, unit, entry)? {
            return Ok(Some(name));
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
                        if let Some(name) = inner(dwarf, &origin_unit, &origin_entry, visited)? {
                            return Ok(Some(name));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    if let Some(name) = read_name_attr(dwarf, unit, entry)? {
        return Ok(Some(name));
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

    let mut visited = HashSet::with_capacity(4);
    if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
        visited.insert(entry_abs);
    }
    inner(dwarf, unit, entry, &mut visited)
}

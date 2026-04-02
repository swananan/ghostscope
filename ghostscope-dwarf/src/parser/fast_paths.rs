use gimli::{EndianArcSlice, LittleEndian, Reader};
use std::collections::HashSet;

type DwarfReader = EndianArcSlice<LittleEndian>;
type DwarfUnit = gimli::Unit<DwarfReader>;
type DwarfEntry = gimli::DebuggingInformationEntry<DwarfReader>;

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

fn same_unit_ref(
    unit: &DwarfUnit,
    value: gimli::AttributeValue<DwarfReader>,
) -> Option<gimli::UnitOffset> {
    match value {
        gimli::AttributeValue::UnitRef(offset) => Some(offset),
        gimli::AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
        _ => None,
    }
}

pub(crate) fn resolve_name_in_unit_fast(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
) -> gimli::read::Result<Option<String>> {
    fn inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &DwarfUnit,
        entry: &DwarfEntry,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> gimli::read::Result<Option<String>> {
        if let Some(name) = read_name_attr(dwarf, unit, entry)? {
            return Ok(Some(name));
        }

        // Fast parser only follows same-CU refs to keep index construction cheap.
        for origin_attr in [
            gimli::constants::DW_AT_specification,
            gimli::constants::DW_AT_abstract_origin,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some(offset) = same_unit_ref(unit, value) {
                    if visited.insert(offset) {
                        let origin_entry = unit.entry(offset)?;
                        if let Some(name) = inner(dwarf, unit, &origin_entry, visited)? {
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

    let has_same_unit_origin = [
        gimli::constants::DW_AT_specification,
        gimli::constants::DW_AT_abstract_origin,
    ]
    .into_iter()
    .any(|attr| {
        entry
            .attr_value(attr)
            .and_then(|value| same_unit_ref(unit, value))
            .is_some()
    });
    if !has_same_unit_origin {
        return Ok(None);
    }

    let mut visited = HashSet::with_capacity(4);
    visited.insert(entry.offset());
    inner(dwarf, unit, entry, &mut visited)
}

use crate::binary::{
    references::{unit_dwarf, unit_object},
    DwarfReader,
};
use gimli::Reader;
use std::collections::HashSet;

type DwarfUnit = gimli::Unit<DwarfReader>;
type DwarfEntry = gimli::DebuggingInformationEntry<DwarfReader>;

/// Local references borrow the caller's unit; cross-unit references own their parsed unit.
pub(crate) enum ResolvedUnit<'a> {
    Borrowed(&'a DwarfUnit),
    Owned(Box<DwarfUnit>),
}

impl std::ops::Deref for ResolvedUnit<'_> {
    type Target = DwarfUnit;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(unit) => unit,
            Self::Owned(unit) => unit,
        }
    }
}

pub(crate) type ResolvedOriginEntry<'a> = (gimli::DebugInfoOffset, ResolvedUnit<'a>, DwarfEntry);
pub(crate) type ResolvedUnitEntry = (DwarfUnit, DwarfEntry);

pub(crate) fn resolve_attr_with_unit_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    entry: &DwarfEntry,
    unit: &DwarfUnit,
    attr: gimli::DwAt,
) -> gimli::read::Result<Option<gimli::AttributeValue<DwarfReader>>> {
    fn inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        entry: &DwarfEntry,
        unit: &DwarfUnit,
        attr: gimli::DwAt,
        visited: &mut HashSet<(crate::DwarfObjectId, gimli::DebugInfoOffset)>,
    ) -> gimli::read::Result<Option<gimli::AttributeValue<DwarfReader>>> {
        if let Some(value) = entry.attr_value(attr) {
            return Ok(Some(value));
        }
        let Some(absolute) = entry.offset().to_debug_info_offset(&unit.header) else {
            return Ok(None);
        };
        if visited.len() >= 64 || !visited.insert((unit_object(dwarf, unit), absolute)) {
            return Ok(None);
        }
        for origin_attr in [gimli::DW_AT_abstract_origin, gimli::DW_AT_specification] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((_, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)?
                {
                    if matches!(attr, gimli::DW_AT_location | gimli::DW_AT_frame_base)
                        && (unit_object(dwarf, unit) != unit_object(dwarf, &origin_unit)
                            || unit.header.offset() != origin_unit.header.offset())
                    {
                        // Callers evaluate location lists using the concrete unit.
                        // Address-bearing locations cannot be moved into supplements.
                        continue;
                    }
                    if let Some(value) = inner(dwarf, &origin_entry, &origin_unit, attr, visited)? {
                        return Ok(Some(value));
                    }
                }
            }
        }
        Ok(None)
    }
    inner(dwarf, entry, unit, attr, &mut HashSet::new())
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

pub(crate) fn resolve_origin_entry<'a>(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &'a DwarfUnit,
    value: gimli::AttributeValue<DwarfReader>,
) -> gimli::read::Result<Option<ResolvedOriginEntry<'a>>> {
    match value {
        gimli::AttributeValue::UnitRef(offset) => {
            let Some(debug_info_off) = offset.to_debug_info_offset(&unit.header) else {
                return Ok(None);
            };
            let origin_entry = unit.entry(offset)?;
            Ok(Some((
                debug_info_off,
                ResolvedUnit::Borrowed(unit),
                origin_entry,
            )))
        }
        gimli::AttributeValue::DebugInfoRef(debug_info_off) => {
            if let Some(unit_off) = debug_info_off.to_unit_offset(&unit.header) {
                let origin_entry = unit.entry(unit_off)?;
                return Ok(Some((
                    debug_info_off,
                    ResolvedUnit::Borrowed(unit),
                    origin_entry,
                )));
            }

            let Some((origin_unit, origin_entry)) =
                resolve_debug_info_ref(unit_dwarf(dwarf, unit)?, debug_info_off)?
            else {
                return Ok(None);
            };
            Ok(Some((
                debug_info_off,
                ResolvedUnit::Owned(Box::new(origin_unit)),
                origin_entry,
            )))
        }
        gimli::AttributeValue::DebugInfoRefSup(debug_info_off) => {
            let supplementary = crate::DwarfObjectId::Supplementary.dwarf(dwarf)?;
            Ok(resolve_debug_info_ref(supplementary, debug_info_off)?
                .map(|(unit, entry)| (debug_info_off, ResolvedUnit::Owned(Box::new(unit)), entry)))
        }
        _ => Ok(None),
    }
}

fn read_string_attr(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
    attrs: &[gimli::DwAt],
) -> gimli::read::Result<Option<String>> {
    for attr_name in attrs {
        if let Some(attr) = entry.attr(*attr_name) {
            if let Ok(value) = unit_dwarf(dwarf, unit)?.attr_string(unit, attr.value()) {
                if let Ok(value) = value.to_string().inspect_err(|error| {
                    tracing::debug!(
                        ?error,
                        ?attr_name,
                        "Ignoring DWARF name that is not valid UTF-8"
                    );
                }) {
                    return Ok(Some(value.into_owned()));
                }
            }
        }
    }
    Ok(None)
}

fn resolve_string_attr_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
    attrs: &[gimli::DwAt],
) -> gimli::read::Result<Option<String>> {
    fn inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &DwarfUnit,
        entry: &DwarfEntry,
        attrs: &[gimli::DwAt],
        visited: &mut HashSet<(crate::DwarfObjectId, gimli::DebugInfoOffset)>,
    ) -> gimli::read::Result<Option<String>> {
        if let Some(value) = read_string_attr(dwarf, unit, entry, attrs)? {
            return Ok(Some(value));
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
                        if let Some(value) =
                            inner(dwarf, &origin_unit, &origin_entry, attrs, visited)?
                        {
                            return Ok(Some(value));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    if let Some(value) = read_string_attr(dwarf, unit, entry, attrs)? {
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
    if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
        visited.insert((unit_object(dwarf, unit), entry_abs));
    }
    inner(dwarf, unit, entry, attrs, &mut visited)
}

pub(crate) fn resolve_name_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
) -> gimli::read::Result<Option<String>> {
    resolve_string_attr_with_origins(dwarf, unit, entry, &[gimli::DW_AT_name])
}

pub(crate) fn resolve_linkage_name_with_origins(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &DwarfUnit,
    entry: &DwarfEntry,
) -> gimli::read::Result<Option<String>> {
    resolve_string_attr_with_origins(
        dwarf,
        unit,
        entry,
        &[gimli::DW_AT_linkage_name, gimli::DW_AT_MIPS_linkage_name],
    )
}

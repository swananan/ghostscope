use super::LoadedObjfile;
use crate::{
    binary::DwarfReader,
    core::{demangled_name, normalize_demangled_signature, symbol_name_matches_query, Result},
    index::LightweightIndex,
    parser::RangeExtractor,
    semantics::{range_contains_pc, resolve_attr_with_unit_origins, resolve_origin_entry},
};
use std::collections::HashSet;

impl LoadedObjfile {
    pub(crate) fn lookup_function_addresses(&self, name: &str) -> Vec<u64> {
        tracing::debug!("LoadedObjfile: looking up function '{}'", name);

        let entries = self.lightweight_index.find_dies_by_function_name(name);
        let mut addresses = Vec::new();

        for entry in entries {
            addresses.extend(self.compute_addresses_for_entry(entry));
        }

        tracing::debug!(
            "LoadedObjfile: function '{}' resolved to {} addresses: {:?}",
            name,
            addresses.len(),
            addresses
        );
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    fn candidate_matches_name(
        name: &str,
        normalized_query: Option<&str>,
        entry: &crate::core::IndexEntry,
    ) -> bool {
        if symbol_name_matches_query(name, normalized_query, entry.name.as_ref(), None) {
            return true;
        }

        let should_attempt_demangle = entry.flags.is_linkage
            || crate::core::is_likely_mangled(entry.language, entry.name.as_ref());
        if !should_attempt_demangle {
            return false;
        }

        let demangled = demangled_name(entry.language, entry.name.as_ref());
        symbol_name_matches_query(
            name,
            normalized_query,
            entry.name.as_ref(),
            demangled.as_ref(),
        )
    }

    fn matching_fragment_candidate_indices(
        &self,
        name: &str,
        candidate_indices: Vec<usize>,
        tag_filter: impl Fn(gimli::DwTag) -> bool,
    ) -> Vec<usize> {
        let normalized_query = normalize_demangled_signature(name);
        candidate_indices
            .into_iter()
            .filter(|&idx| {
                let Some(entry) = self.lightweight_index.entry(idx) else {
                    return false;
                };
                tag_filter(entry.tag)
                    && Self::candidate_matches_name(name, normalized_query.as_deref(), entry)
            })
            .collect()
    }

    fn scan_matching_candidate_indices(
        lightweight_index: &LightweightIndex,
        name: &str,
        tag_filter: impl Fn(gimli::DwTag) -> bool,
    ) -> Vec<usize> {
        let normalized_query = normalize_demangled_signature(name);
        let mut matches = Vec::new();

        for idx in 0..lightweight_index.entry_count() {
            let Some(entry) = lightweight_index.entry(idx) else {
                continue;
            };
            if tag_filter(entry.tag)
                && Self::candidate_matches_name(name, normalized_query.as_deref(), entry)
            {
                matches.push(idx);
            }
        }

        matches
    }

    fn matching_function_candidate_indices(&self, name: &str) -> Vec<usize> {
        let fragment_matches = self.matching_fragment_candidate_indices(
            name,
            self.lightweight_index
                .function_candidate_indices_by_fragment(name),
            |tag| {
                matches!(
                    tag,
                    gimli::constants::DW_TAG_subprogram
                        | gimli::constants::DW_TAG_inlined_subroutine
                )
            },
        );

        if !fragment_matches.is_empty() {
            return fragment_matches;
        }

        Self::scan_matching_candidate_indices(&self.lightweight_index, name, |tag| {
            matches!(
                tag,
                gimli::constants::DW_TAG_subprogram | gimli::constants::DW_TAG_inlined_subroutine
            )
        })
    }

    pub(super) fn matching_variable_candidate_indices(&self, name: &str) -> Vec<usize> {
        let fragment_matches = self.matching_fragment_candidate_indices(
            name,
            self.lightweight_index
                .variable_candidate_indices_by_fragment(name),
            |tag| tag == gimli::constants::DW_TAG_variable,
        );

        if !fragment_matches.is_empty() {
            return fragment_matches;
        }

        Self::scan_matching_candidate_indices(&self.lightweight_index, name, |tag| {
            tag == gimli::constants::DW_TAG_variable
        })
    }

    fn resolve_function_ranges(&self, entry: &crate::core::IndexEntry) -> Result<Vec<(u64, u64)>> {
        if !matches!(
            entry.tag,
            gimli::constants::DW_TAG_subprogram | gimli::constants::DW_TAG_inlined_subroutine
        ) {
            return Ok(Vec::new());
        }

        let dwarf = self.dwarf();
        let header = dwarf
            .unit_header(entry.unit_offset)
            .map_err(|e| anyhow::anyhow!("unit header error: {}", e))?;
        let unit = dwarf
            .unit(header)
            .map_err(|e| anyhow::anyhow!("unit load error: {}", e))?;
        let die = unit
            .entry(entry.die_offset)
            .map_err(|e| anyhow::anyhow!("entry load error: {}", e))?;

        RangeExtractor::extract_all_ranges(&die, &unit, dwarf)
            .map_err(|e| anyhow::anyhow!("range extraction error: {}", e))
    }

    pub(super) fn find_function_index_entry_by_address(
        &self,
        address: u64,
    ) -> Option<&crate::core::IndexEntry> {
        self.lightweight_index
            .find_function_by_address(address, |entry| self.resolve_function_ranges(entry).ok())
    }

    fn compute_addresses_for_entry(&self, entry: &crate::core::IndexEntry) -> Vec<u64> {
        let mut out = Vec::new();
        let ranges = match self.resolve_function_ranges(entry) {
            Ok(ranges) => ranges,
            Err(err) => {
                tracing::warn!(
                    "Failed to resolve ranges for '{}' ({:?}/{:?}): {}",
                    entry.name,
                    entry.unit_offset,
                    entry.die_offset,
                    err
                );
                Vec::new()
            }
        };

        match entry.function_kind() {
            crate::core::FunctionDieKind::InlineInstance => {
                let mut debug_ranges = ranges.clone();
                debug_ranges.sort_unstable_by_key(|(s, _)| *s);
                if !debug_ranges.is_empty() {
                    let parts: Vec<String> = debug_ranges
                        .iter()
                        .map(|(s, e)| format!("(0x{s:x},0x{e:x})"))
                        .collect();
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    let rlen = debug_ranges.len();
                    let rlist = parts.join(", ");
                    tracing::debug!(
                        "Inline '{}' entry_pc={epc_dbg} ranges({rlen}): [{rlist}]",
                        entry.name
                    );
                } else {
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    tracing::debug!("Inline '{}' has no ranges; entry_pc={epc_dbg}", entry.name);
                }

                if let Some(addr) = Self::selected_inline_address(entry, &ranges) {
                    tracing::debug!("Inline '{}' selected=0x{addr:x}", entry.name);
                    out.push(addr);
                } else {
                    tracing::warn!(
                        "Inline entry has no usable address (no ranges/entry_pc): unit_off={:?}, die_off={:?}",
                        entry.unit_offset,
                        entry.die_offset
                    );
                }
            }
            crate::core::FunctionDieKind::ConcreteSubprogram => {
                let nranges = Self::selected_non_inline_ranges(entry, &ranges);
                for (start, end) in &nranges {
                    let candidate = {
                        let first_exec = self.line_mapping.find_first_executable_address(*start);
                        Self::selected_non_inline_probe_address(*start, *end, first_exec)
                    };
                    let prefer_entry = self
                        .function_uses_entry_value_at(entry, candidate)
                        .unwrap_or(false);
                    let addr = if prefer_entry { *start } else { candidate };
                    if prefer_entry {
                        tracing::debug!(
                            "Non-inline '{}' entry_value active at 0x{candidate:x}, using entry start=0x{start:x}",
                            entry.name,
                        );
                    } else {
                        let off = addr.saturating_sub(*start);
                        tracing::debug!(
                            "Non-inline '{}' start=0x{start:x} first_exec=0x{addr:x} (+0x{off:x})",
                            entry.name
                        );
                        if addr == *start {
                            tracing::debug!(
                                "Non-inline '{}' kept entry start because prologue-skip candidate escaped range [0x{start:x}, 0x{end:x})",
                                entry.name
                            );
                        }
                    }
                    out.push(addr);
                }
            }
            crate::core::FunctionDieKind::AbstractSubprogram => {
                tracing::debug!(
                    "Skipping abstract subprogram '{}' with no concrete code ranges",
                    entry.name
                );
            }
            crate::core::FunctionDieKind::NotFunction => {}
        }
        out
    }

    fn selected_inline_address(
        entry: &crate::core::IndexEntry,
        ranges: &[(u64, u64)],
    ) -> Option<u64> {
        let first_start = ranges.first().map(|(start, _)| *start);
        let low_pc = ranges.iter().map(|(start, _)| *start).min();

        entry
            .validated_entry_pc(ranges)
            .or(first_start)
            .or(low_pc)
            .or(entry.representative_addr)
    }

    fn selected_non_inline_ranges(
        entry: &crate::core::IndexEntry,
        ranges: &[(u64, u64)],
    ) -> Vec<(u64, u64)> {
        let ranges = ranges.to_vec();
        if ranges.len() <= 1 {
            return ranges;
        }

        if let Some(entry_pc) = entry.entry_pc {
            if let Some(range) = ranges
                .iter()
                .copied()
                .find(|(start, end)| *start <= entry_pc && entry_pc < *end)
            {
                return vec![range];
            }
        }

        vec![ranges[0]]
    }

    fn selected_non_inline_probe_address(start: u64, end: u64, candidate: u64) -> u64 {
        if start <= candidate && candidate < end {
            candidate
        } else {
            start
        }
    }

    fn function_uses_entry_value_at(
        &self,
        idx_entry: &crate::core::IndexEntry,
        pc: u64,
    ) -> Result<bool> {
        let dwarf = self.dwarf();
        let header = dwarf
            .unit_header(idx_entry.unit_offset)
            .map_err(|e| anyhow::anyhow!("unit header error: {}", e))?;
        let unit = dwarf
            .unit(header)
            .map_err(|e| anyhow::anyhow!("unit load error: {}", e))?;
        let entry = unit
            .entry(idx_entry.die_offset)
            .map_err(|e| anyhow::anyhow!("entry load error: {}", e))?;
        Self::subprogram_uses_entry_value_at(dwarf, &unit, &entry, pc)
    }

    #[cfg(test)]
    fn subprogram_uses_entry_value(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_with_pc(dwarf, unit, entry, None, &mut visited)
    }

    fn subprogram_uses_entry_value_at(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: u64,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_with_pc(dwarf, unit, entry, Some(pc), &mut visited)
    }

    fn subprogram_uses_entry_value_with_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: Option<u64>,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<bool> {
        if entry.tag() != gimli::constants::DW_TAG_subprogram {
            return Ok(false);
        }

        if let Some(uses_entry_value) =
            Self::direct_formal_parameters_entry_value_state_with_pc(dwarf, unit, entry, pc)?
        {
            return Ok(uses_entry_value);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((origin_abs, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)
                        .map_err(|e| anyhow::anyhow!("origin resolution error: {}", e))?
                {
                    if visited.insert(origin_abs)
                        && Self::subprogram_uses_entry_value_with_pc(
                            dwarf,
                            &origin_unit,
                            &origin_entry,
                            pc,
                            visited,
                        )?
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    #[cfg(test)]
    fn direct_formal_parameters_entry_value_state(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<bool>> {
        Self::direct_formal_parameters_entry_value_state_with_pc(dwarf, unit, entry, None)
    }

    fn direct_formal_parameters_entry_value_state_with_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: Option<u64>,
    ) -> Result<Option<bool>> {
        let mut saw_parameter = false;

        if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
            if let Ok(root) = tree.root() {
                let mut children = root.children();
                while let Ok(Some(child)) = children.next() {
                    let e = child.entry();
                    if e.tag() != gimli::constants::DW_TAG_formal_parameter {
                        continue;
                    }
                    saw_parameter = true;

                    if let Ok(Some(value)) =
                        resolve_attr_with_unit_origins(e, unit, gimli::constants::DW_AT_location)
                    {
                        if Self::attribute_uses_entry_value(dwarf, unit, value, pc)? {
                            return Ok(Some(true));
                        }
                    }
                }
            }
        }

        if saw_parameter {
            Ok(Some(false))
        } else {
            Ok(None)
        }
    }

    fn attribute_uses_entry_value(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
        pc: Option<u64>,
    ) -> Result<bool> {
        match value {
            gimli::AttributeValue::Exprloc(expr) => Ok(Self::expression_uses_entry_value(
                unit,
                gimli::Expression(expr.0),
            )),
            gimli::AttributeValue::LocationListsRef(offset) => match pc {
                Some(pc) => Self::location_list_uses_entry_value_at_pc(
                    dwarf,
                    unit,
                    gimli::LocationListsOffset(offset.0),
                    pc,
                ),
                None => Ok(false),
            },
            gimli::AttributeValue::SecOffset(offset) => match pc {
                Some(pc) => Self::location_list_uses_entry_value_at_pc(
                    dwarf,
                    unit,
                    gimli::LocationListsOffset(offset),
                    pc,
                ),
                None => Ok(false),
            },
            _ => Ok(false),
        }
    }

    fn location_list_uses_entry_value_at_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        pc: u64,
    ) -> Result<bool> {
        let mut raw_locations = match dwarf.raw_locations(unit, offset) {
            Ok(iter) => iter,
            Err(_) => return Ok(false),
        };

        let mut base_address = unit.low_pc;
        let mut default_location_uses_entry_value = None;
        while let Some(raw_entry) = raw_locations
            .next()
            .map_err(|e| anyhow::anyhow!("raw location list iteration error: {:?}", e))?
        {
            match raw_entry {
                gimli::RawLocListEntry::BaseAddress { addr } => {
                    base_address = addr;
                }
                gimli::RawLocListEntry::BaseAddressx { addr } => {
                    if let Ok(resolved) = dwarf.address(unit, addr) {
                        base_address = resolved;
                    }
                }
                gimli::RawLocListEntry::StartLength {
                    begin,
                    length,
                    data,
                } => {
                    if range_contains_pc(begin, begin.wrapping_add(length), pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartEnd { begin, end, data } => {
                    if range_contains_pc(begin, end, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::OffsetPair { begin, end, data }
                | gimli::RawLocListEntry::AddressOrOffsetPair { begin, end, data } => {
                    let start = base_address.wrapping_add(begin);
                    let end_addr = base_address.wrapping_add(end);
                    if range_contains_pc(start, end_addr, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartxLength {
                    begin,
                    length,
                    data,
                } => {
                    if let Ok(start) = dwarf.address(unit, begin) {
                        if range_contains_pc(start, start.wrapping_add(length), pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::StartxEndx { begin, end, data } => {
                    if let (Ok(start), Ok(end_addr)) =
                        (dwarf.address(unit, begin), dwarf.address(unit, end))
                    {
                        if range_contains_pc(start, end_addr, pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::DefaultLocation { data } => {
                    default_location_uses_entry_value =
                        Some(Self::expression_uses_entry_value(unit, data));
                }
            }
        }

        Ok(default_location_uses_entry_value.unwrap_or(false))
    }

    fn expression_uses_entry_value(
        unit: &gimli::Unit<DwarfReader>,
        mut expression: gimli::Expression<DwarfReader>,
    ) -> bool {
        while let Ok(op) = gimli::Operation::parse(&mut expression.0, unit.encoding()) {
            if matches!(op, gimli::Operation::EntryValue { .. }) {
                return true;
            }
        }

        false
    }

    pub(crate) fn lookup_function_addresses_any(&self, name: &str) -> Vec<u64> {
        let addrs = self.lookup_function_addresses(name);
        if !addrs.is_empty() {
            return addrs;
        }

        let mut out = Vec::new();
        for idx in self.matching_function_candidate_indices(name) {
            if let Some(entry) = self.lightweight_index.entry(idx) {
                out.extend(self.compute_addresses_for_entry(entry));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    pub(crate) fn find_function_name_by_address(&self, address: u64) -> Option<String> {
        self.find_function_index_entry_by_address(address)
            .map(|entry| entry.name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::super::LoadedObjfile;
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{FunctionDieKind, IndexEntry, IndexFlags};
    use crate::index::LightweightIndex;
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Location, LocationList, Sections, Unit,
    };
    use gimli::{Format, Register};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn subprogram_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        IndexEntry {
            name: Arc::from("CGPsend"),
            die_offset: gimli::UnitOffset(0),
            unit_offset: gimli::DebugInfoOffset(0),
            tag: constants::DW_TAG_subprogram,
            flags: IndexFlags::default(),
            language: None,
            representative_addr: ranges.first().map(|(start, _)| *start).or(entry_pc),
            entry_pc,
            function_kind: FunctionDieKind::ConcreteSubprogram,
        }
    }

    fn inline_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        let mut entry = subprogram_entry(ranges, entry_pc);
        entry.tag = constants::DW_TAG_inlined_subroutine;
        entry.function_kind = FunctionDieKind::InlineInstance;
        entry
    }

    fn build_origin_backed_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_entry_value_override_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_override_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let concrete_param_id = unit.add(concrete_id, constants::DW_TAG_formal_parameter);
        let concrete_param = unit.get_mut(concrete_param_id);
        concrete_param.set(
            constants::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(origin_param_id),
        );
        let mut concrete_param_loc = WriteExpression::new();
        concrete_param_loc.op_reg(Register(6));
        concrete_param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(concrete_param_loc),
        );

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_entry_value_range_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_range_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut entry_value_loc = WriteExpression::new();
        entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x1477),
                data: direct_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1477),
                end: Address::Constant(0x147b),
                data: entry_value_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_origin_backed_default_location_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_default_location_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut default_entry_value_loc = WriteExpression::new();
        default_entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::DefaultLocation {
                data: default_entry_value_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x147b),
                data: direct_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn first_unit(dwarf: &gimli::Dwarf<DwarfReader>) -> gimli::Unit<DwarfReader> {
        let mut units = dwarf.units();
        let header = units.next().unwrap().unwrap();
        dwarf.unit(header).unwrap()
    }

    fn find_subprogram_with_origin_attr(
        unit: &gimli::Unit<DwarfReader>,
        origin_attr: gimli::DwAt,
    ) -> gimli::UnitOffset {
        let mut tree = unit.entries_tree(None).unwrap();
        let root = tree.root().unwrap();
        let mut children = root.children();

        while let Some(child) = children.next().unwrap() {
            let entry = child.entry();
            if entry.tag() == constants::DW_TAG_subprogram
                && entry.attr_value(origin_attr).is_some()
            {
                return entry.offset();
            }
        }

        panic!("failed to find subprogram with origin attr {origin_attr:?}");
    }

    #[test]
    fn selected_non_inline_ranges_keeps_hot_partition_first_when_cold_has_lower_address() {
        let ranges = [(0x8e97c0, 0x8e9be0), (0x76e78e, 0x76e798)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges),
            vec![(0x8e97c0, 0x8e9be0)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_keeps_single_contiguous_range() {
        let ranges = [(0x8ea060, 0x8eb07b)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges),
            vec![(0x8ea060, 0x8eb07b)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_prefers_range_containing_entry_pc() {
        let ranges = [(0x100, 0x180), (0x200, 0x220)];
        let entry = subprogram_entry(&ranges, Some(0x208));

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges),
            vec![(0x200, 0x220)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_without_entry_pc_keeps_first_range_even_if_later_range_is_larger()
    {
        let ranges = [(0x100, 0x110), (0x200, 0x260)];
        let entry = subprogram_entry(&ranges, None);

        assert_eq!(
            LoadedObjfile::selected_non_inline_ranges(&entry, &ranges),
            vec![(0x100, 0x110)],
        );
    }

    #[test]
    fn selected_non_inline_probe_address_clamps_prologue_skip_to_function_range() {
        assert_eq!(
            LoadedObjfile::selected_non_inline_probe_address(0x1470, 0x147b, 0x14f2),
            0x1470
        );
        assert_eq!(
            LoadedObjfile::selected_non_inline_probe_address(0x1470, 0x147b, 0x1474),
            0x1474
        );
    }

    #[test]
    fn selected_inline_address_prefers_entry_pc_over_cold_min_range() {
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x8eb16a, 0x8eb1b0),
                (0x76e798, 0x76e7a2),
            ],
            Some(0x8eb16a),
        );

        assert_eq!(
            LoadedObjfile::selected_inline_address(
                &entry,
                &[
                    (0x8eb12b, 0x8eb139),
                    (0x8eb150, 0x8eb157),
                    (0x8eb16a, 0x8eb1b0),
                    (0x76e798, 0x76e7a2),
                ],
            ),
            Some(0x8eb16a)
        );
    }

    #[test]
    fn selected_inline_address_without_entry_pc_keeps_first_emitted_hot_range() {
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x76e798, 0x76e7a2),
            ],
            None,
        );

        assert_eq!(
            LoadedObjfile::selected_inline_address(
                &entry,
                &[
                    (0x8eb12b, 0x8eb139),
                    (0x8eb150, 0x8eb157),
                    (0x76e798, 0x76e7a2),
                ],
            ),
            Some(0x8eb12b)
        );
    }

    #[test]
    fn selected_inline_address_ignores_entry_pc_outside_inline_ranges() {
        let entry = inline_entry(&[(0x1289, 0x1293)], Some(0x1215));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[(0x1289, 0x1293)]),
            Some(0x1289)
        );
    }

    #[test]
    fn selected_inline_address_keeps_entry_pc_only_point_scopes() {
        let entry = inline_entry(&[], Some(0x1289));

        assert_eq!(
            LoadedObjfile::selected_inline_address(&entry, &[]),
            Some(0x1289)
        );
    }

    #[test]
    fn subprogram_uses_entry_value_via_abstract_origin_parameters() {
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_abstract_origin"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_via_specification_parameters() {
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_specification);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_specification);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_specification"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_does_not_override_concrete_parameter_locations() {
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            LoadedObjfile::direct_formal_parameters_entry_value_state(&dwarf, &unit, &concrete)
                .unwrap(),
            Some(false),
            "concrete DIE should treat its own parameter children as authoritative"
        );
        assert!(
            !LoadedObjfile::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "origin-level entry_value must not override concrete parameter locations"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_only_when_active_location_uses_it() {
        let dwarf = build_origin_backed_entry_value_range_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474).unwrap(),
            "entry_value should not force the true entry while the active location is still a direct register"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478)
                .unwrap(),
            "entry_value should still be detected once the active location range switches to it"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_respects_concrete_parameter_overrides() {
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478)
                .unwrap(),
            "concrete parameter locations must remain authoritative at the selected probe PC"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_prefers_specific_loclist_ranges_over_default_location() {
        let dwarf = build_origin_backed_default_location_entry_value_fixture(
            constants::DW_AT_abstract_origin,
        );
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474)
                .unwrap(),
            "the specific direct-register range should override the default-location entry_value"
        );
        assert!(
            LoadedObjfile::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1500)
                .unwrap(),
            "outside the specific range, the default-location entry_value should still apply"
        );
    }

    #[test]
    fn fragment_candidates_match_demangled_function_queries() {
        let mangled = "_ZN2ns6Widget3runEv".to_string();
        let demangled =
            crate::core::demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), &mangled).unwrap();
        let leaf = crate::core::demangled_leaf(&demangled);

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_C_plus_plus_17),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());
        let entry = ix.entry(0).unwrap();

        assert_eq!(
            ix.function_candidate_indices_by_fragment(&demangled),
            vec![0]
        );
        assert!(LoadedObjfile::candidate_matches_name(
            &demangled, None, entry
        ));
        assert!(LoadedObjfile::candidate_matches_name(&leaf, None, entry));
    }

    #[test]
    fn fragment_candidates_match_rust_v0_demangled_function_queries() {
        let mangled = "_RNvCs73fAdSrgOJL_4test4main".to_string();
        let demangled = crate::core::demangle_by_lang(Some(gimli::DW_LANG_Rust), &mangled).unwrap();

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_Rust),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());

        assert_eq!(
            ix.function_candidate_indices_by_fragment(&demangled),
            vec![0]
        );
    }

    #[test]
    fn scan_fallback_matches_substitution_heavy_cpp_queries() {
        let mangled = "_ZNSt6vectorIiSaIiEE3endEv".to_string();
        let demangled =
            crate::core::demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), &mangled).unwrap();

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_C_plus_plus_17),
                representative_addr: Some(0x1000),
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());

        assert!(ix
            .function_candidate_indices_by_fragment(&demangled)
            .is_empty());
        assert_eq!(
            LoadedObjfile::scan_matching_candidate_indices(&ix, &demangled, |tag| matches!(
                tag,
                constants::DW_TAG_subprogram | constants::DW_TAG_inlined_subroutine
            )),
            vec![0]
        );
    }
}

//! DWARF access planner: plan chain access using DIE-level traversal without
//! requiring full TypeInfo expansion.

use crate::core::{EvaluationResult, Result};
pub(crate) use crate::semantics::TypeLoc;
use crate::semantics::{
    eval_member_offset_expr, resolve_type_ref_with_origins, strip_typedef_qualified,
};
use gimli::Reader;
use gimli::{EndianArcSlice, LittleEndian};

/// Utilities for DIE-level chain access planning
pub struct AccessPlanner<'dwarf> {
    dwarf: &'dwarf gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    type_index: Option<std::sync::Arc<crate::index::TypeNameIndex>>,
    strict_index: bool,
}

/// Parent struct/class context for the final matched member.
#[derive(Debug, Clone)]
pub struct MemberParentCtx {
    pub parent_cu_off: gimli::DebugInfoOffset,
    pub parent_die_off: gimli::UnitOffset,
    pub member_name: String,
}

impl<'dwarf> AccessPlanner<'dwarf> {
    pub fn new(dwarf: &'dwarf gimli::Dwarf<EndianArcSlice<LittleEndian>>) -> Self {
        Self {
            dwarf,
            type_index: None,
            strict_index: false,
        }
    }

    pub fn new_with_index(
        dwarf: &'dwarf gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        type_index: std::sync::Arc<crate::index::TypeNameIndex>,
        strict_index: bool,
    ) -> Self {
        Self {
            dwarf,
            type_index: Some(type_index),
            strict_index,
        }
    }

    /// Public wrapper for resolving DW_AT_type via origins/specification chain
    pub fn resolve_type_ref_with_origins_public(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> crate::core::Result<Option<TypeLoc>> {
        resolve_type_ref_with_origins(self.dwarf, entry, unit)
    }

    /// If DIE is an explicit declaration, try to find a full definition across units.
    ///
    /// This must stay narrower than "childless aggregate". `die.has_children()`
    /// only answers whether this DIE has inline member DIEs; it does not say
    /// whether the DIE is a forward declaration. Empty definitions are valid
    /// aggregates and legitimately have no children, so rebinding every
    /// childless `struct Foo` by name can silently hop to an unrelated `Foo`
    /// from another CU or namespace.
    ///
    /// The child flag still matters for member scanning after we have the final
    /// DIE, but it must not be used as the trigger for declaration completion.
    fn maybe_complete_aggregate(
        &self,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        die: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> crate::core::Result<(Option<gimli::DebugInfoOffset>, gimli::UnitOffset)> {
        let mut is_decl = false;
        if let Some(attr) = die.attr(gimli::DW_AT_declaration) {
            is_decl = matches!(attr.value(), gimli::AttributeValue::Flag(true));
        }

        if !is_decl {
            return Ok((None, die.offset()));
        }

        let name_opt = if let Some(attr) = die.attr(gimli::DW_AT_name) {
            self.dwarf
                .attr_string(unit, attr.value())
                .ok()
                .and_then(|s| s.to_string_lossy().ok().map(|cow| cow.into_owned()))
        } else {
            None
        };

        if name_opt.is_some() {
            let name = name_opt.unwrap();
            let tag = die.tag();
            if let Some(tix) = &self.type_index {
                if let Some(loc) = tix.find_aggregate_definition(&name, tag) {
                    return Ok((Some(loc.cu_offset), loc.die_offset));
                }
                if self.strict_index {
                    return Err(anyhow::anyhow!(
                        "StrictIndex: missing definition for {} {:?}",
                        name,
                        tag
                    ));
                }
            }
            // Non-strict: do not scan here anymore to reduce load; return original
            return Ok((None, die.offset()));
        }
        Ok((None, die.offset()))
    }

    /// Start planning from a known variable (skip variable search)
    pub fn plan_chain_from_known(
        &self,
        mut current_cu_off: gimli::DebugInfoOffset,
        type_die_off: gimli::UnitOffset,
        mut current_eval: EvaluationResult,
        chain: &[String],
    ) -> Result<(EvaluationResult, TypeLoc, Option<MemberParentCtx>)> {
        let mut current_type = TypeLoc {
            cu_off: current_cu_off,
            die_off: type_die_off,
        };
        let mut idx = 0usize;
        let mut last_parent_ctx: Option<MemberParentCtx> = None;
        while idx < chain.len() {
            let field = &chain[idx];
            current_type = strip_typedef_qualified(self.dwarf, current_type)?;
            current_cu_off = current_type.cu_off;

            // Reacquire current unit on each step
            let header_now = self.dwarf.unit_header(current_type.cu_off)?;
            let unit_now = self.dwarf.unit(header_now)?;
            let type_die = unit_now.entry(current_type.die_off)?;

            match type_die.tag() {
                gimli::DW_TAG_pointer_type => {
                    // Dereference then continue without consuming field
                    current_eval = Self::compute_pointer_deref(current_eval);
                    if let Some(next) =
                        resolve_type_ref_with_origins(self.dwarf, &type_die, &unit_now)?
                    {
                        current_type = next;
                    } else {
                        return Ok((current_eval, current_type, last_parent_ctx));
                    }
                    continue;
                }
                gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type => {
                    // Ensure definition DIE; possibly switch unit
                    let (def_cu_opt, def_off) =
                        self.maybe_complete_aggregate(&unit_now, &type_die)?;
                    if let Some(cu_off) = def_cu_opt {
                        current_cu_off = cu_off;
                    }
                    // Reacquire possibly switched unit and read the definition DIE
                    let header_now2 = self.dwarf.unit_header(current_cu_off)?;
                    let unit_now2 = self.dwarf.unit(header_now2)?;
                    let def_die = unit_now2.entry(def_off)?;
                    // Scan members for the field
                    let mut entries = unit_now2.entries_at_offset(def_die.offset())?;
                    let _ = entries.next_entry()?; // self
                    let mut found_member = false;
                    while let Some(e) = entries.next_dfs()? {
                        if e.tag() == gimli::DW_TAG_member {
                            if let Some(attr) = e.attr(gimli::DW_AT_name) {
                                if let Ok(s) = self.dwarf.attr_string(&unit_now2, attr.value()) {
                                    if let Ok(s_str) = s.to_string_lossy() {
                                        if s_str == field.as_str() {
                                            // offset
                                            let mut off: Option<u64> = None;
                                            if let Some(a) =
                                                e.attr(gimli::DW_AT_data_member_location)
                                            {
                                                match a.value() {
                                                    gimli::AttributeValue::Udata(v) => {
                                                        off = Some(v)
                                                    }
                                                    gimli::AttributeValue::Exprloc(expr) => {
                                                        off = eval_member_offset_expr(&expr)
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if off.is_none() {
                                                if let Some(a) =
                                                    e.attr(gimli::DW_AT_data_bit_offset)
                                                {
                                                    if let gimli::AttributeValue::Udata(v) =
                                                        a.value()
                                                    {
                                                        off = Some(v / 8);
                                                    }
                                                }
                                            }
                                            // Apply offset immediately if available
                                            if let Some(off) = off {
                                                use crate::core::{
                                                    ComputeStep, EvaluationResult, LocationResult,
                                                };
                                                current_eval = match current_eval {
                                                    EvaluationResult::MemoryLocation(
                                                        LocationResult::RegisterAddress {
                                                            register,
                                                            offset,
                                                            size,
                                                        },
                                                    ) => {
                                                        let new_off = offset
                                                            .unwrap_or(0)
                                                            .saturating_add(off as i64);
                                                        EvaluationResult::MemoryLocation(
                                                            LocationResult::RegisterAddress {
                                                                register,
                                                                offset: Some(new_off),
                                                                size,
                                                            },
                                                        )
                                                    }
                                                    EvaluationResult::MemoryLocation(
                                                        LocationResult::Address(addr),
                                                    ) => EvaluationResult::MemoryLocation(
                                                        LocationResult::Address(
                                                            addr.saturating_add(off),
                                                        ),
                                                    ),
                                                    EvaluationResult::MemoryLocation(
                                                        LocationResult::ComputedLocation {
                                                            mut steps,
                                                        },
                                                    ) => {
                                                        steps.push(ComputeStep::PushConstant(
                                                            off as i64,
                                                        ));
                                                        steps.push(ComputeStep::Add);
                                                        EvaluationResult::MemoryLocation(
                                                            LocationResult::ComputedLocation {
                                                                steps,
                                                            },
                                                        )
                                                    }
                                                    other => other,
                                                };
                                            }
                                            // type
                                            let next_type = resolve_type_ref_with_origins(
                                                self.dwarf, e, &unit_now2,
                                            )?;
                                            let parent_cu_off = current_cu_off;
                                            current_type = next_type.unwrap_or(TypeLoc {
                                                cu_off: current_cu_off,
                                                die_off: current_type.die_off,
                                            });
                                            last_parent_ctx = Some(MemberParentCtx {
                                                parent_cu_off,
                                                parent_die_off: def_off,
                                                member_name: field.clone(),
                                            });
                                            found_member = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if found_member {
                        // consumed one field
                        idx += 1;
                    } else {
                        // Field not found on this aggregate — report an error instead of
                        // silently returning the base aggregate.
                        // Try to get a friendly type name for diagnostics
                        let type_name = if let Some(attr) = def_die.attr(gimli::DW_AT_name) {
                            if let Ok(s) = self.dwarf.attr_string(&unit_now2, attr.value()) {
                                s.to_string_lossy().ok().unwrap_or_default().into_owned()
                            } else {
                                String::new()
                            }
                        } else {
                            String::new()
                        };
                        let msg = if type_name.is_empty() {
                            format!("member '{field}' not found")
                        } else {
                            format!("member '{field}' not found on type '{type_name}'")
                        };
                        return Err(anyhow::anyhow!(msg));
                    }
                }
                _ => {
                    // Can't descend further
                    return Ok((current_eval, current_type, last_parent_ctx));
                }
            }
        }

        Ok((current_eval, current_type, last_parent_ctx))
    }

    fn compute_pointer_deref(base: EvaluationResult) -> EvaluationResult {
        use crate::core::{ComputeStep, DirectValueResult, LocationResult};
        match base {
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                ..
            }) => {
                let mut steps = Vec::new();
                steps.push(ComputeStep::LoadRegister(register));
                if let Some(off) = offset {
                    steps.push(ComputeStep::PushConstant(off));
                    steps.push(ComputeStep::Add);
                }
                steps.push(ComputeStep::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps })
            }
            EvaluationResult::MemoryLocation(LocationResult::Address(addr)) => {
                let steps = vec![
                    ComputeStep::PushConstant(addr as i64),
                    ComputeStep::Dereference {
                        size: crate::core::MemoryAccessSize::U64,
                    },
                ];
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps })
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { mut steps }) => {
                steps.push(ComputeStep::Dereference {
                    size: crate::core::MemoryAccessSize::U64,
                });
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps })
            }
            EvaluationResult::DirectValue(DirectValueResult::RegisterValue(register)) => {
                EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                    register,
                    offset: None,
                    size: None,
                })
            }
            EvaluationResult::DirectValue(DirectValueResult::Constant(value)) => {
                EvaluationResult::MemoryLocation(LocationResult::Address(value as u64))
            }
            EvaluationResult::DirectValue(DirectValueResult::ImplicitValue(bytes)) => {
                let mut value = 0u64;
                for (idx, byte) in bytes.iter().take(8).enumerate() {
                    value |= (*byte as u64) << (idx * 8);
                }
                EvaluationResult::MemoryLocation(LocationResult::Address(value))
            }
            EvaluationResult::DirectValue(DirectValueResult::ComputedValue { steps, .. }) => {
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps })
            }
            other => other,
        }
    }

    // compute_add_offset removed (unused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{IndexEntry, IndexFlags};
    use crate::index::{LightweightIndex, TypeNameIndex};
    use gimli::constants;
    use gimli::write::{
        AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec, LineProgram,
        Sections, Unit,
    };
    use gimli::{DebugInfoOffset, EndianArcSlice, Format};
    use std::collections::HashMap;
    use std::sync::Arc;

    type PlannerRegressionFixture = (
        gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        gimli::Unit<EndianArcSlice<LittleEndian>>,
        gimli::UnitOffset,
        DebugInfoOffset,
        gimli::UnitOffset,
        Arc<TypeNameIndex>,
    );

    fn build_declaration_completion_fixture() -> PlannerRegressionFixture {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let decl_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let def_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));

        {
            let unit = dwarf.units.get_mut(decl_unit_id);
            let root = unit.root();

            let struct_id = unit.add(root, constants::DW_TAG_structure_type);
            let struct_entry = unit.get_mut(struct_id);
            struct_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"Foo".to_vec()),
            );
            struct_entry.set(
                constants::DW_AT_declaration,
                WriteAttributeValue::Flag(true),
            );

            let sibling_id = unit.add(root, constants::DW_TAG_subprogram);
            let sibling = unit.get_mut(sibling_id);
            sibling.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"later_sibling".to_vec()),
            );
        }

        {
            let unit = dwarf.units.get_mut(def_unit_id);
            let root = unit.root();

            let int_id = unit.add(root, constants::DW_TAG_base_type);
            let int_entry = unit.get_mut(int_id);
            int_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"int".to_vec()),
            );
            int_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            int_entry.set(
                constants::DW_AT_encoding,
                WriteAttributeValue::Encoding(constants::DW_ATE_signed),
            );

            let struct_id = unit.add(root, constants::DW_TAG_structure_type);
            let struct_entry = unit.get_mut(struct_id);
            struct_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"Foo".to_vec()),
            );
            struct_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(4));

            let member_id = unit.add(struct_id, constants::DW_TAG_member);
            let member = unit.get_mut(member_id);
            member.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"x".to_vec()),
            );
            member.set(constants::DW_AT_type, WriteAttributeValue::UnitRef(int_id));
            member.set(
                constants::DW_AT_data_member_location,
                WriteAttributeValue::Data1(0),
            );
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
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
        let read_dwarf = dwarf_sections.borrow(|section| {
            EndianArcSlice::new(Arc::<[u8]>::from(section.as_slice()), LittleEndian)
        });

        let mut units = read_dwarf.units();
        let decl_header = units.next().unwrap().unwrap();
        let def_header = units.next().unwrap().unwrap();
        let def_cu_off = def_header.debug_info_offset().unwrap();

        let decl_unit = read_dwarf.unit(decl_header).unwrap();
        let def_unit = read_dwarf.unit(def_header).unwrap();
        let decl_struct_off = find_struct_offset(&read_dwarf, &decl_unit, "Foo", true, false);
        let def_struct_off = find_struct_offset(&read_dwarf, &def_unit, "Foo", false, true);

        let mut types = HashMap::new();
        types.insert(
            "Foo".to_string(),
            vec![IndexEntry {
                name: Arc::from("Foo"),
                die_offset: def_struct_off,
                unit_offset: def_cu_off,
                tag: constants::DW_TAG_structure_type,
                flags: IndexFlags::default(),
                language: None,
                address_ranges: Vec::new(),
                entry_pc: None,
            }],
        );
        let type_index = Arc::new(TypeNameIndex::build_from_lightweight(
            &LightweightIndex::from_builder_data(HashMap::new(), HashMap::new(), types),
        ));

        (
            read_dwarf,
            decl_unit,
            decl_struct_off,
            def_cu_off,
            def_struct_off,
            type_index,
        )
    }

    fn build_empty_definition_fixture() -> PlannerRegressionFixture {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let empty_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let full_unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));

        {
            let unit = dwarf.units.get_mut(empty_unit_id);
            let root = unit.root();

            let struct_id = unit.add(root, constants::DW_TAG_structure_type);
            let struct_entry = unit.get_mut(struct_id);
            struct_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"Foo".to_vec()),
            );
            // This is a real empty definition, not a forward declaration.
            struct_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(1));
        }

        {
            let unit = dwarf.units.get_mut(full_unit_id);
            let root = unit.root();

            let int_id = unit.add(root, constants::DW_TAG_base_type);
            let int_entry = unit.get_mut(int_id);
            int_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"int".to_vec()),
            );
            int_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(4));
            int_entry.set(
                constants::DW_AT_encoding,
                WriteAttributeValue::Encoding(constants::DW_ATE_signed),
            );

            let struct_id = unit.add(root, constants::DW_TAG_structure_type);
            let struct_entry = unit.get_mut(struct_id);
            struct_entry.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"Foo".to_vec()),
            );
            struct_entry.set(constants::DW_AT_byte_size, WriteAttributeValue::Data1(4));

            let member_id = unit.add(struct_id, constants::DW_TAG_member);
            let member = unit.get_mut(member_id);
            member.set(
                constants::DW_AT_name,
                WriteAttributeValue::String(b"x".to_vec()),
            );
            member.set(constants::DW_AT_type, WriteAttributeValue::UnitRef(int_id));
            member.set(
                constants::DW_AT_data_member_location,
                WriteAttributeValue::Data1(0),
            );
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
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
        let read_dwarf = dwarf_sections.borrow(|section| {
            EndianArcSlice::new(Arc::<[u8]>::from(section.as_slice()), LittleEndian)
        });

        let mut units = read_dwarf.units();
        let empty_header = units.next().unwrap().unwrap();
        let full_header = units.next().unwrap().unwrap();
        let full_cu_off = full_header.debug_info_offset().unwrap();

        let empty_unit = read_dwarf.unit(empty_header).unwrap();
        let full_unit = read_dwarf.unit(full_header).unwrap();
        let empty_struct_off = find_struct_offset(&read_dwarf, &empty_unit, "Foo", false, false);
        let full_struct_off = find_struct_offset(&read_dwarf, &full_unit, "Foo", false, true);

        let mut types = HashMap::new();
        types.insert(
            "Foo".to_string(),
            vec![IndexEntry {
                name: Arc::from("Foo"),
                die_offset: full_struct_off,
                unit_offset: full_cu_off,
                tag: constants::DW_TAG_structure_type,
                flags: IndexFlags::default(),
                language: None,
                address_ranges: Vec::new(),
                entry_pc: None,
            }],
        );
        let type_index = Arc::new(TypeNameIndex::build_from_lightweight(
            &LightweightIndex::from_builder_data(HashMap::new(), HashMap::new(), types),
        ));

        (
            read_dwarf,
            empty_unit,
            empty_struct_off,
            full_cu_off,
            full_struct_off,
            type_index,
        )
    }

    fn find_struct_offset(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        expected_name: &str,
        expected_is_declaration: bool,
        expected_has_children: bool,
    ) -> gimli::UnitOffset {
        let mut entries = unit.entries();
        while let Some(entry) = entries.next_dfs().unwrap() {
            if entry.tag() != constants::DW_TAG_structure_type {
                continue;
            }
            let Some(attr) = entry.attr(constants::DW_AT_name) else {
                continue;
            };
            let Ok(name) = dwarf.attr_string(unit, attr.value()) else {
                continue;
            };
            let Ok(name) = name.to_string_lossy() else {
                continue;
            };
            let is_declaration = matches!(
                entry.attr(constants::DW_AT_declaration),
                Some(attr) if matches!(attr.value(), gimli::AttributeValue::Flag(true))
            );
            if name == expected_name
                && is_declaration == expected_is_declaration
                && entry.has_children() == expected_has_children
            {
                return entry.offset();
            }
        }
        panic!(
            "missing struct {expected_name} with declaration={expected_is_declaration} \
             and has_children={expected_has_children}"
        );
    }

    fn legacy_has_children_via_next_dfs(
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        die: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> bool {
        let mut entries = unit.entries_at_offset(die.offset()).unwrap();
        let _ = entries.next_entry().unwrap();
        entries.next_dfs().unwrap().is_some()
    }

    #[test]
    fn maybe_complete_aggregate_uses_declaration_flag_despite_later_siblings() {
        let (dwarf, decl_unit, decl_struct_off, def_cu_off, def_struct_off, type_index) =
            build_declaration_completion_fixture();
        let decl_struct_die = decl_unit.entry(decl_struct_off).unwrap();
        let mut legacy_cursor = decl_unit.entries_at_offset(decl_struct_off).unwrap();
        assert!(legacy_cursor.next_entry().unwrap());
        let next_after_decl = legacy_cursor.next_dfs().unwrap().unwrap();

        assert!(!decl_struct_die.has_children());
        assert_eq!(next_after_decl.depth(), 0);
        assert_eq!(next_after_decl.tag(), constants::DW_TAG_subprogram);
        assert!(legacy_has_children_via_next_dfs(
            &decl_unit,
            &decl_struct_die
        ));

        let planner = AccessPlanner::new_with_index(&dwarf, type_index, false);
        let (resolved_cu, resolved_die) = planner
            .maybe_complete_aggregate(&decl_unit, &decl_struct_die)
            .unwrap();

        assert_eq!(resolved_cu, Some(def_cu_off));
        assert_eq!(resolved_die, def_struct_off);
    }

    #[test]
    fn maybe_complete_aggregate_does_not_rebind_empty_definitions() {
        let (dwarf, empty_unit, empty_struct_off, full_cu_off, full_struct_off, type_index) =
            build_empty_definition_fixture();
        let empty_struct_die = empty_unit.entry(empty_struct_off).unwrap();

        assert!(!empty_struct_die.has_children());
        assert!(empty_struct_die
            .attr(constants::DW_AT_declaration)
            .is_none());

        let planner = AccessPlanner::new_with_index(&dwarf, type_index, false);
        let (resolved_cu, resolved_die) = planner
            .maybe_complete_aggregate(&empty_unit, &empty_struct_die)
            .unwrap();

        assert_eq!(resolved_cu, None);
        assert_eq!(resolved_die, empty_struct_off);
        assert_ne!(resolved_die, full_struct_off);
        assert_ne!(resolved_cu, Some(full_cu_off));
    }

    #[test]
    fn pointer_deref_handles_direct_register_values() {
        let eval = EvaluationResult::DirectValue(crate::core::DirectValueResult::RegisterValue(12));
        assert_eq!(
            AccessPlanner::compute_pointer_deref(eval),
            EvaluationResult::MemoryLocation(crate::core::LocationResult::RegisterAddress {
                register: 12,
                offset: None,
                size: None,
            })
        );
    }
}

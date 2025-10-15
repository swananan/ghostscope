//! DWARF access planner: plan chain access using DIE-level traversal without
//! requiring full TypeInfo expansion.

use crate::core::{EvaluationResult, Result};
use gimli::Reader;
use gimli::{EndianArcSlice, LittleEndian};

// PlanAction removed (unused)

/// Utilities for DIE-level chain access planning
pub struct AccessPlanner<'dwarf> {
    dwarf: &'dwarf gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    type_index: Option<std::sync::Arc<crate::data::TypeNameIndex>>,
    strict_index: bool,
}

/// Location of a type within the DWARF (CU + DIE offset)
#[derive(Debug, Clone, Copy)]
pub struct TypeLoc {
    pub cu_off: gimli::UnitSectionOffset,
    pub die_off: gimli::UnitOffset,
}

/// Parent struct/class context for the final matched member.
#[derive(Debug, Clone)]
pub struct MemberParentCtx {
    pub parent_cu_off: gimli::UnitSectionOffset,
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
        type_index: std::sync::Arc<crate::data::TypeNameIndex>,
        strict_index: bool,
    ) -> Self {
        Self {
            dwarf,
            type_index: Some(type_index),
            strict_index,
        }
    }

    /// Resolve DW_AT_type reference with origins/specification following
    fn resolve_type_ref_with_origins(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> crate::core::Result<Option<gimli::UnitOffset>> {
        // Local recursive helper mimicking DetailedParser::resolve_attr_with_origins
        fn resolve_attr_with_origins(
            entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
            unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
            attr: gimli::DwAt,
            visited: &mut std::collections::HashSet<gimli::UnitOffset>,
        ) -> crate::core::Result<Option<gimli::AttributeValue<EndianArcSlice<LittleEndian>>>>
        {
            if let Some(value) = entry.attr_value(attr)? {
                return Ok(Some(value));
            }
            for origin_attr in [
                gimli::constants::DW_AT_abstract_origin,
                gimli::constants::DW_AT_specification,
            ] {
                if let Some(gimli::AttributeValue::UnitRef(off)) = entry.attr_value(origin_attr)? {
                    if visited.insert(off) {
                        let origin = unit.entry(off)?;
                        if let Some(v) = resolve_attr_with_origins(&origin, unit, attr, visited)? {
                            return Ok(Some(v));
                        }
                    }
                }
            }
            Ok(None)
        }

        let mut visited = std::collections::HashSet::new();
        Ok(
            resolve_attr_with_origins(entry, unit, gimli::constants::DW_AT_type, &mut visited)?
                .and_then(|v| match v {
                    gimli::AttributeValue::UnitRef(u) => Some(u),
                    _ => None,
                }),
        )
    }

    /// Public wrapper for resolving DW_AT_type via origins/specification chain
    pub fn resolve_type_ref_with_origins_public(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> crate::core::Result<Option<gimli::UnitOffset>> {
        self.resolve_type_ref_with_origins(entry, unit)
    }

    /// Follow typedef/qualified chain to the underlying type DIE
    fn strip_typedef_qualified(
        &self,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        mut die_off: gimli::UnitOffset,
    ) -> crate::core::Result<gimli::UnitOffset> {
        loop {
            let die = unit.entry(die_off)?;
            match die.tag() {
                gimli::DW_TAG_typedef
                | gimli::DW_TAG_const_type
                | gimli::DW_TAG_volatile_type
                | gimli::DW_TAG_restrict_type => {
                    if let Some(u) = self.resolve_type_ref_with_origins(&die, unit)? {
                        die_off = u;
                        continue;
                    }
                }
                _ => {}
            }
            return Ok(die_off);
        }
    }

    /// If DIE is a declaration, try to find a full definition across units by name+tag
    fn maybe_complete_aggregate(
        &self,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        die: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> crate::core::Result<(Option<gimli::UnitSectionOffset>, gimli::UnitOffset)> {
        // Check declaration flag or childless struct
        let mut is_decl = false;
        if let Some(attr) = die.attr(gimli::DW_AT_declaration)? {
            if let gimli::AttributeValue::Flag(f) = attr.value() {
                is_decl = f;
            }
        }
        let has_children = {
            let mut entries = unit.entries_at_offset(die.offset())?;
            let _ = entries.next_entry()?; // self
            (entries.next_dfs()?).is_some()
        };

        let name_opt = if let Some(attr) = die.attr(gimli::DW_AT_name)? {
            self.dwarf
                .attr_string(unit, attr.value())
                .ok()
                .and_then(|s| s.to_string_lossy().ok().map(|cow| cow.into_owned()))
        } else {
            None
        };

        if (is_decl || !has_children) && name_opt.is_some() {
            let name = name_opt.unwrap();
            let tag = die.tag();
            if let Some(tix) = &self.type_index {
                if let Some(loc) = tix.find_aggregate_definition(&name, tag) {
                    return Ok((Some(loc.cu_offset.into()), loc.die_offset));
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

    /// Evaluate DW_AT_data_member_location expression to constant offset if possible
    fn eval_member_offset_expr(
        &self,
        expr: &gimli::Expression<EndianArcSlice<LittleEndian>>,
    ) -> Option<u64> {
        use gimli::Reader;
        let bytes_cow = expr.0.to_slice().ok()?;
        let bytes: &[u8] = &bytes_cow;
        if bytes.is_empty() {
            return None;
        }
        let mut rdr = gimli::EndianSlice::new(bytes, LittleEndian);
        if let Ok(op) = rdr.read_u8() {
            match op {
                0x10 => rdr.read_uleb128().ok(),                   // DW_OP_constu
                0x11 => rdr.read_sleb128().ok().map(|v| v as u64), // DW_OP_consts
                0x23 => rdr.read_uleb128().ok(),                   // DW_OP_plus_uconst
                _ => None,
            }
        } else {
            None
        }
    }

    /// Helper: get UnitHeader from a UnitSectionOffset
    fn header_from_cu_off(
        &self,
        cu_off: gimli::UnitSectionOffset,
    ) -> crate::core::Result<gimli::UnitHeader<EndianArcSlice<LittleEndian>>> {
        Ok(match cu_off {
            gimli::UnitSectionOffset::DebugInfoOffset(off) => {
                self.dwarf.debug_info.header_from_offset(off)?
            }
            gimli::UnitSectionOffset::DebugTypesOffset(_off) => {
                // Currently we do not support .debug_types units in planner
                return Err(anyhow::anyhow!("planner: .debug_types units not supported"));
            }
        })
    }

    /// Start planning from a known variable (skip variable search)
    pub fn plan_chain_from_known(
        &self,
        mut current_cu_off: gimli::UnitSectionOffset,
        mut type_die_off: gimli::UnitOffset,
        mut current_eval: EvaluationResult,
        chain: &[String],
    ) -> Result<(EvaluationResult, TypeLoc, Option<MemberParentCtx>)> {
        let mut idx = 0usize;
        let mut last_parent_ctx: Option<MemberParentCtx> = None;
        while idx < chain.len() {
            let field = &chain[idx];
            // Reacquire current unit on each step
            let header_now = self.header_from_cu_off(current_cu_off)?;
            let unit_now = self.dwarf.unit(header_now)?;

            // Strip typedef/qualified
            type_die_off = self.strip_typedef_qualified(&unit_now, type_die_off)?;
            let type_die = unit_now.entry(type_die_off)?;

            match type_die.tag() {
                gimli::DW_TAG_pointer_type => {
                    // Dereference then continue without consuming field
                    current_eval = Self::compute_pointer_deref(current_eval);
                    if let Some(u) = self.resolve_type_ref_with_origins(&type_die, &unit_now)? {
                        type_die_off = u;
                    } else {
                        return Ok((
                            current_eval,
                            TypeLoc {
                                cu_off: current_cu_off,
                                die_off: type_die_off,
                            },
                            last_parent_ctx,
                        ));
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
                    let header_now2 = self.header_from_cu_off(current_cu_off)?;
                    let unit_now2 = self.dwarf.unit(header_now2)?;
                    let def_die = unit_now2.entry(def_off)?;
                    // Scan members for the field
                    let mut entries = unit_now2.entries_at_offset(def_die.offset())?;
                    let _ = entries.next_entry()?; // self
                    let mut next_type: Option<gimli::UnitOffset> = None;
                    let mut found_member = false;
                    while let Some((_, e)) = entries.next_dfs()? {
                        if e.tag() == gimli::DW_TAG_member {
                            if let Some(attr) = e.attr(gimli::DW_AT_name)? {
                                if let Ok(s) = self.dwarf.attr_string(&unit_now2, attr.value()) {
                                    if let Ok(s_str) = s.to_string_lossy() {
                                        if s_str == field.as_str() {
                                            // offset
                                            let mut off: Option<u64> = None;
                                            if let Some(a) =
                                                e.attr(gimli::DW_AT_data_member_location)?
                                            {
                                                match a.value() {
                                                    gimli::AttributeValue::Udata(v) => {
                                                        off = Some(v)
                                                    }
                                                    gimli::AttributeValue::Exprloc(expr) => {
                                                        off = self.eval_member_offset_expr(&expr)
                                                    }
                                                    _ => {}
                                                }
                                            }
                                            if off.is_none() {
                                                if let Some(a) =
                                                    e.attr(gimli::DW_AT_data_bit_offset)?
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
                                            if let Some(a) = e.attr(gimli::DW_AT_type)? {
                                                if let gimli::AttributeValue::UnitRef(u) = a.value()
                                                {
                                                    next_type = Some(u);
                                                }
                                            }
                                            type_die_off = next_type.unwrap_or(type_die_off);
                                            last_parent_ctx = Some(MemberParentCtx {
                                                parent_cu_off: current_cu_off,
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
                        let type_name = if let Some(attr) = def_die.attr(gimli::DW_AT_name)? {
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
                    return Ok((
                        current_eval,
                        TypeLoc {
                            cu_off: current_cu_off,
                            die_off: type_die_off,
                        },
                        last_parent_ctx,
                    ));
                }
            }
        }

        Ok((
            current_eval,
            TypeLoc {
                cu_off: current_cu_off,
                die_off: type_die_off,
            },
            last_parent_ctx,
        ))
    }

    fn compute_pointer_deref(base: EvaluationResult) -> EvaluationResult {
        use crate::core::ComputeStep;
        use crate::core::LocationResult;
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
            other => other,
        }
    }

    // compute_add_offset removed (unused)
}

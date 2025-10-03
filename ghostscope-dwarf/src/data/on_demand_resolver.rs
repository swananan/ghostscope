//! Real on-demand DWARF resolver implementation
//! This version actually parses DWARF DIEs instead of returning hardcoded data

use crate::{
    core::Result, data::TypeNameIndex, parser::DetailedParser, parser::VariableWithEvaluation,
};
use gimli::{EndianArcSlice, LittleEndian};
// Use upper-case aliases to satisfy non_upper_case_globals lint on pattern constants
// No direct constant tag imports needed here
// tracing::warn no longer used after removing legacy traversal

/// Chain specifier for complex variable access
pub struct ChainSpec<'a> {
    pub base: &'a str,
    pub fields: &'a [String],
}

/// Real on-demand DWARF resolver
#[derive(Debug)]
pub struct OnDemandResolver {
    dwarf: gimli::Dwarf<EndianArcSlice<LittleEndian>>,
    detailed_parser: DetailedParser,
    /// Optional cross-CU type name index (built from lightweight index)
    type_name_index: Option<std::sync::Arc<TypeNameIndex>>,
    /// Strict index mode: if index miss, return error (no fallback)
    strict_index: bool,
}

impl OnDemandResolver {
    /// Create resolver with a type name index for faster cross-CU completion
    pub fn new_with_type_index(
        dwarf: gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        type_index: std::sync::Arc<TypeNameIndex>,
    ) -> Self {
        let mut detailed_parser = DetailedParser::new();
        detailed_parser.set_type_name_index(type_index.clone());
        Self {
            dwarf,
            detailed_parser,
            type_name_index: Some(type_index),
            strict_index: true,
        }
    }

    /// Borrow DWARF reference for building auxiliary indexes lazily
    pub fn dwarf_ref(&self) -> &gimli::Dwarf<EndianArcSlice<LittleEndian>> {
        &self.dwarf
    }

    /// Plan chain access starting from a known variable DIE (fast path)
    pub fn plan_chain_access_from_var(
        &mut self,
        address: u64,
        cu_offset: gimli::DebugInfoOffset,
        subprogram_die: gimli::UnitOffset,
        var_die: gimli::UnitOffset,
        chain: ChainSpec,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Option<crate::parser::VariableWithEvaluation>> {
        let t0 = std::time::Instant::now();
        tracing::info!(
            "DWARF:plan_from_var addr=0x{:x} cu_off={:?} subprogram={:?} var_die={:?} base='{}' chain_len={}",
            address,
            cu_offset,
            subprogram_die,
            var_die,
            chain.base,
            chain.fields.len()
        );
        let header = self.dwarf.debug_info.header_from_offset(cu_offset)?;
        let unit = self.dwarf.unit(header)?;
        let var_entry = unit.entry(var_die)?;

        // Evaluate base variable (without heavy type resolution)
        let eval_t = std::time::Instant::now();
        let base_var = self.detailed_parser.parse_variable_entry_with_mode(
            &var_entry,
            &unit,
            &self.dwarf,
            address,
            get_cfa,
            0,
        )?;
        tracing::info!(
            "DWARF:plan_from_var eval_loc_ms={}",
            eval_t.elapsed().as_millis()
        );
        let Some(base_var) = base_var else {
            return Ok(None);
        };
        let current_eval = base_var.evaluation_result.clone();

        // Resolve starting type DIE
        let planner = match &self.type_name_index {
            Some(idx) => crate::planner::AccessPlanner::new_with_index(
                &self.dwarf,
                idx.clone(),
                self.strict_index,
            ),
            None => crate::planner::AccessPlanner::new(&self.dwarf),
        };
        let mut final_eval = current_eval.clone();
        let mut final_type_loc: Option<crate::planner::TypeLoc> = None;
        let mut parent_ctx: Option<crate::planner::MemberParentCtx> = None;

        if !chain.fields.is_empty() {
            let t1 = std::time::Instant::now();
            let type_die_off = planner
                .resolve_type_ref_with_origins_public(&var_entry, &unit)?
                .ok_or_else(|| anyhow::anyhow!("variable has no DW_AT_type"))?;
            tracing::info!(
                "DWARF:plan_from_var resolve_type_ref_ms={}",
                t1.elapsed().as_millis()
            );

            let t2 = std::time::Instant::now();
            let (fe, ftl, pctx) = planner.plan_chain_from_known(
                cu_offset.into(),
                type_die_off,
                current_eval,
                chain.fields,
            )?;
            final_eval = fe;
            final_type_loc = Some(ftl);
            parent_ctx = pctx;
            tracing::info!(
                "DWARF:plan_from_var planner_ms={}",
                t2.elapsed().as_millis()
            );
        }

        // Resolve final type for display (shallow) and minimally enrich using parent member context
        let mut final_type = None;
        if let Some(ftl) = final_type_loc {
            let t3 = std::time::Instant::now();
            // Base: shallow resolve the resulting DIE's type
            let mut shallow_final = match ftl.cu_off {
                gimli::UnitSectionOffset::DebugInfoOffset(off) => {
                    let h = self.dwarf.debug_info.header_from_offset(off)?;
                    let u = self.dwarf.unit(h)?;
                    crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                        &self.dwarf,
                        &u,
                        ftl.die_off,
                    )
                }
                gimli::UnitSectionOffset::DebugTypesOffset(_off) => None,
            };
            tracing::info!(
                "DWARF:plan_from_var final_type_ms={}",
                t3.elapsed().as_millis()
            );

            // Minimal parent enrichment: if planner provided parent member context,
            // use parent's shallow members to capture bitfield wrapper and accurate member type.
            if let Some(ctx) = parent_ctx {
                if let gimli::UnitSectionOffset::DebugInfoOffset(pcu) = ctx.parent_cu_off {
                    let h = self.dwarf.debug_info.header_from_offset(pcu)?;
                    let u = self.dwarf.unit(h)?;
                    if let Some(
                        crate::TypeInfo::StructType { members, .. }
                        | crate::TypeInfo::UnionType { members, .. },
                    ) = crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                        &self.dwarf,
                        &u,
                        ctx.parent_die_off,
                    ) {
                        if let Some(m) = members.iter().find(|m| m.name == ctx.member_name) {
                            tracing::info!(
                                "DWARF:parent_enrich member='{}' uses BitfieldType={}",
                                ctx.member_name,
                                matches!(m.member_type, crate::TypeInfo::BitfieldType { .. })
                            );
                            shallow_final = Some(m.member_type.clone());
                        }
                    }
                }
            }

            final_type = shallow_final;
        }

        let (type_name, dwarf_type) = if let Some(t) = final_type.clone() {
            (t.type_name(), Some(t))
        } else {
            // Use already computed base variable type name if chain is empty
            (base_var.type_name.clone(), None)
        };

        let name = if chain.fields.is_empty() {
            chain.base.to_string()
        } else {
            format!("{0}.", chain.base) + &chain.fields.join(".")
        };
        let var = crate::parser::VariableWithEvaluation {
            name,
            type_name,
            dwarf_type,
            evaluation_result: final_eval,
            scope_depth: 0,
            is_parameter: base_var.is_parameter,
            is_artificial: base_var.is_artificial,
        };
        tracing::info!("DWARF:plan_from_var total_ms={}", t0.elapsed().as_millis());
        Ok(Some(var))
    }

    /// Resolve variables by DIE offsets at a specific address using DetailedParser
    pub fn resolve_variables_by_offsets_at_address(
        &mut self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Vec<VariableWithEvaluation>> {
        let mut vars = Vec::with_capacity(items.len());
        for (cu_off, die_off) in items.iter().cloned() {
            let header = self.dwarf.debug_info.header_from_offset(cu_off)?;
            let unit = self.dwarf.unit(header)?;
            let entry = unit.entry(die_off)?;
            if let Some(v) = self.detailed_parser.parse_variable_entry_with_mode(
                &entry,
                &unit,
                &self.dwarf,
                address,
                get_cfa,
                0,
            )? {
                vars.push(v);
            }
        }
        Ok(vars)
    }

    /// Get cache statistics
    pub fn get_cache_stats(&self) -> (usize, usize) {
        (0, self.detailed_parser.get_cache_stats())
    }

    // entry_pc_matches removed (no longer used after switching to direct DIE traversal)

    /// Compute static byte offset for a global variable's member chain.
    /// Returns (total_offset_from_base, final_shallow_type) on success.
    pub fn compute_member_offset_for_global(
        &mut self,
        address: u64,
        cu_off: gimli::DebugInfoOffset,
        var_die: gimli::UnitOffset,
        link_address: u64,
        fields: &[String],
    ) -> crate::core::Result<Option<(u64, crate::TypeInfo)>> {
        // Plan using existing machinery starting from the known variable DIE.
        // We pass var_die also as the subprogram placeholder (not used for globals).
        let spec = ChainSpec {
            base: "__global__",
            fields,
        };
        let planned =
            self.plan_chain_access_from_var(address, cu_off, var_die, var_die, spec, None)?;
        let Some(var) = planned else { return Ok(None) };

        // Fold the final evaluation result into an absolute address if possible
        use crate::core::{ComputeStep, EvaluationResult, LocationResult};
        let abs_addr_opt = match &var.evaluation_result {
            EvaluationResult::MemoryLocation(LocationResult::Address(a)) => Some(*a),
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                // Simple constant-folder: only PushConstant/Add allowed
                let mut st: Vec<i64> = Vec::new();
                let mut foldable = true;
                for s in steps {
                    match s {
                        ComputeStep::PushConstant(v) => st.push(*v),
                        ComputeStep::Add => {
                            if st.len() >= 2 {
                                let b = st.pop().unwrap();
                                let a = st.pop().unwrap();
                                st.push(a.saturating_add(b));
                            } else {
                                foldable = false;
                                break;
                            }
                        }
                        _ => {
                            foldable = false;
                            break;
                        }
                    }
                }
                if foldable && st.len() == 1 {
                    Some(st[0] as u64)
                } else {
                    None
                }
            }
            _ => None,
        };

        if let Some(abs) = abs_addr_opt {
            let off = abs.saturating_sub(link_address);
            let final_ty = var
                .dwarf_type
                .unwrap_or(crate::TypeInfo::UnknownType { name: "".into() });
            return Ok(Some((off, final_ty)));
        }

        Ok(None)
    }
}

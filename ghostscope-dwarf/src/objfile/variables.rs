use super::{access_planner::AccessPlanner, LoadedObjfile};
use crate::{
    core::Result,
    index::{BlockIndexBuilder, FunctionBlocks, VarRef},
    parser::{DetailedParser, ExpressionEvaluator},
    semantics::{resolve_attr_with_unit_origins, resolve_name_with_origins},
};
use gimli::Reader;
use std::{sync::Arc, time::Instant};

pub(super) struct ChainSpec<'a> {
    pub base: &'a str,
    pub fields: &'a [String],
}

impl LoadedObjfile {
    fn find_innermost_inline_node(func: &FunctionBlocks, pc: u64) -> Option<usize> {
        let path = func.block_path_for_pc(pc);
        path.iter()
            .rev()
            .find(|&&idx| func.nodes[idx].entry_pc.is_some())
            .copied()
    }

    pub(crate) fn is_inline_at(&mut self, address: u64) -> Option<bool> {
        if self.block_index.find_function_by_pc(address).is_none() {
            let builder = BlockIndexBuilder::new(self.dwarf());
            if let Some(func_entry) = self.find_function_index_entry_by_address(address) {
                if let Some(fb) =
                    builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
                {
                    self.block_index.add_functions(vec![fb]);
                }
            } else if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    self.block_index.add_functions(funcs);
                }
            }
        }

        let func = self.block_index.find_function_by_pc(address)?;

        if let Some(inline_idx) = Self::find_innermost_inline_node(func, address) {
            let dwarf = self.dwarf();
            if let Ok(header) = dwarf.unit_header(func.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Some(off) = func.nodes[inline_idx].die_offset {
                        if let Ok(entry) = unit.entry(off) {
                            return Some(
                                entry.tag() == gimli::constants::DW_TAG_inlined_subroutine,
                            );
                        }
                    }
                }
            }
        }

        Some(false)
    }

    fn try_apply_call_site_mapping(
        &self,
        func: &FunctionBlocks,
        inline_idx: usize,
        address: u64,
        vars: &mut [crate::VariableWithEvaluation],
        _var_refs: &[VarRef],
        get_cfa: &dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>,
    ) {
        let dwarf = self.dwarf();
        let header = match dwarf.unit_header(func.cu_offset) {
            Ok(h) => h,
            Err(_) => return,
        };
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => return,
        };
        let node = &func.nodes[inline_idx];
        let inline_die = match node.die_offset.and_then(|off| unit.entry(off).ok()) {
            Some(e) => e,
            None => return,
        };
        if inline_die.tag() != gimli::constants::DW_TAG_inlined_subroutine {
            return;
        }

        let origin_off = match inline_die.attr_value(gimli::constants::DW_AT_abstract_origin) {
            Some(gimli::AttributeValue::UnitRef(o)) => o,
            _ => return,
        };

        let mut origin_param_names: Vec<String> = Vec::new();
        if let Ok(mut it) = unit.entries_at_offset(origin_off) {
            let _ = it.next_entry();
            while let Ok(Some(e)) = it.next_dfs() {
                if e.depth() <= 0 {
                    break;
                }
                if e.depth() > 1 {
                    continue;
                }
                if e.tag() == gimli::constants::DW_TAG_formal_parameter {
                    if let Some(a) = e.attr(gimli::constants::DW_AT_name) {
                        if let Ok(s) = dwarf.attr_string(&unit, a.value()) {
                            if let Ok(ss) = s.to_string_lossy() {
                                origin_param_names.push(ss.into_owned());
                            }
                        }
                    }
                }
            }
        }
        if origin_param_names.is_empty() {
            return;
        }

        let mut param_values: Vec<Option<crate::core::EvaluationResult>> =
            vec![None; origin_param_names.len()];
        if let Ok(mut it) = unit.entries_at_offset(node.die_offset.unwrap()) {
            let _ = it.next_entry();
            while let Ok(Some(e)) = it.next_dfs() {
                if e.depth() <= 0 {
                    break;
                }
                if e.depth() > 1 {
                    continue;
                }
                if e.tag() == gimli::constants::DW_TAG_call_site
                    || e.tag() == gimli::constants::DW_TAG_GNU_call_site
                {
                    if let Ok(mut pit) = unit.entries_at_offset(e.offset()) {
                        let _ = pit.next_entry();
                        while let Ok(Some(pe)) = pit.next_dfs() {
                            if pe.depth() <= 0 {
                                break;
                            }
                            if pe.depth() > 1 {
                                continue;
                            }
                            if pe.tag() == gimli::constants::DW_TAG_call_site_parameter
                                || pe.tag() == gimli::constants::DW_TAG_GNU_call_site_parameter
                            {
                                let loc_attr = pe.attr_value(gimli::constants::DW_AT_location);
                                if let Some(gimli::AttributeValue::Exprloc(expr)) = loc_attr {
                                    if let Ok(ev) = ExpressionEvaluator::parse_expression_in_unit(
                                        expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                        &unit,
                                        dwarf,
                                        address,
                                        Some(get_cfa),
                                    ) {
                                        if let Some(slot) =
                                            param_values.iter_mut().find(|v| v.is_none())
                                        {
                                            *slot = Some(ev);
                                        }
                                    }
                                } else if let Some(cv) =
                                    pe.attr_value(gimli::constants::DW_AT_const_value)
                                {
                                    use crate::core::DirectValueResult as DV;
                                    use crate::core::EvaluationResult as ER;
                                    let ev = match cv {
                                        gimli::AttributeValue::Udata(u) => {
                                            ER::DirectValue(DV::Constant(u as i64))
                                        }
                                        gimli::AttributeValue::Sdata(s) => {
                                            ER::DirectValue(DV::Constant(s))
                                        }
                                        gimli::AttributeValue::Data1(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data2(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data4(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data8(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Block(b) => match b.to_slice() {
                                            Ok(bytes) => {
                                                ER::DirectValue(DV::ImplicitValue(bytes.to_vec()))
                                            }
                                            Err(_) => ER::Optimized,
                                        },
                                        _ => ER::Optimized,
                                    };
                                    if let Some(slot) =
                                        param_values.iter_mut().find(|v| v.is_none())
                                    {
                                        *slot = Some(ev);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if param_values.iter().all(|v| v.is_none()) {
            return;
        }

        for v in vars.iter_mut() {
            if !v.is_parameter {
                continue;
            }
            if !matches!(
                v.evaluation_result,
                crate::core::EvaluationResult::Optimized
            ) {
                continue;
            }
            let name = v.name.as_str();
            if let Some(pos) = origin_param_names.iter().position(|n| n == name) {
                if let Some(Some(ev)) = param_values.get(pos) {
                    v.evaluation_result = ev.clone();
                }
            }
        }
    }

    pub(super) fn plan_chain_access_from_var(
        &mut self,
        address: u64,
        cu_offset: gimli::DebugInfoOffset,
        subprogram_die: gimli::UnitOffset,
        var_die: gimli::UnitOffset,
        chain: ChainSpec<'_>,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Option<crate::parser::VariableWithEvaluation>> {
        tracing::info!(
            "DWARF:plan_from_var addr=0x{:x} cu_off={:?} subprogram={:?} var_die={:?} base='{}' chain_len={}",
            address,
            cu_offset,
            subprogram_die,
            var_die,
            chain.base,
            chain.fields.len()
        );
        let header = self.dwarf.unit_header(cu_offset)?;
        let unit = self.dwarf.unit(header)?;
        let var_entry = unit.entry(var_die)?;

        let base_var = self.detailed_parser.parse_variable_entry_with_mode(
            &var_entry,
            &unit,
            &self.dwarf,
            address,
            get_cfa,
            0,
        )?;
        tracing::debug!("DWARF:plan_from_var done");
        let Some(base_var) = base_var else {
            return Ok(None);
        };
        let current_eval = base_var.evaluation_result.clone();

        let planner =
            AccessPlanner::new_with_index(self.dwarf(), Arc::clone(&self.type_name_index), true);
        let mut final_eval = current_eval.clone();
        let mut final_type_loc = None;
        let mut parent_ctx = None;

        if !chain.fields.is_empty() {
            let t1 = std::time::Instant::now();
            let type_loc = planner
                .resolve_type_ref_with_origins_public(&var_entry, &unit)?
                .ok_or_else(|| anyhow::anyhow!("variable has no DW_AT_type"))?;
            tracing::info!(
                "DWARF:plan_from_var resolve_type_ref_ms={}",
                t1.elapsed().as_millis()
            );

            let t2 = std::time::Instant::now();
            let (fe, ftl, pctx) = planner.plan_chain_from_known(
                type_loc.cu_off,
                type_loc.die_off,
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

        let mut final_type = None;
        if let Some(ftl) = final_type_loc {
            let t3 = std::time::Instant::now();
            let h = self.dwarf.unit_header(ftl.cu_off)?;
            let u = self.dwarf.unit(h)?;
            let mut shallow_final =
                DetailedParser::resolve_type_shallow_at_offset(&self.dwarf, &u, ftl.die_off);
            tracing::info!(
                "DWARF:plan_from_var final_type_ms={}",
                t3.elapsed().as_millis()
            );

            if let Some(ctx) = parent_ctx {
                let h = self.dwarf.unit_header(ctx.parent_cu_off)?;
                let u = self.dwarf.unit(h)?;
                if let Some(
                    crate::TypeInfo::StructType { members, .. }
                    | crate::TypeInfo::UnionType { members, .. },
                ) = DetailedParser::resolve_type_shallow_at_offset(
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

            final_type = shallow_final;
        }

        let (type_name, dwarf_type) = if let Some(t) = final_type.clone() {
            (t.type_name(), Some(t))
        } else {
            (base_var.type_name.clone(), None)
        };

        let name = if chain.fields.is_empty() {
            chain.base.to_string()
        } else {
            format!("{base}.", base = chain.base) + &chain.fields.join(".")
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
        tracing::debug!("DWARF:plan_from_var done");
        Ok(Some(var))
    }

    fn resolve_variables_by_offsets_at_address_with_cfa(
        &mut self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<Vec<crate::VariableWithEvaluation>> {
        let mut vars = Vec::with_capacity(items.len());
        for (cu_off, die_off) in items.iter().cloned() {
            let header = self.dwarf.unit_header(cu_off)?;
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

    pub(crate) fn resolve_struct_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_structure_type)
            .or_else(|| {
                self.type_name_index
                    .find_aggregate_definition(name, gimli::constants::DW_TAG_class_type)
            })
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.dwarf();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    pub(crate) fn resolve_union_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_union_type)
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.dwarf();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    pub(crate) fn resolve_enum_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_enumeration_type)
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.dwarf();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    pub(crate) fn get_all_variables_at_address(
        &mut self,
        address: u64,
    ) -> Result<Vec<crate::VariableWithEvaluation>> {
        let t0 = Instant::now();
        let mut built_funcs: usize = 0;
        let mut build_ms: u128 = 0;
        tracing::info!(
            "DWARF:get_vars module='{}' addr=0x{:x}",
            self.module_mapping.path.display(),
            address
        );

        if self.block_index.find_function_by_pc(address).is_none() {
            let b0 = Instant::now();
            if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                let builder = BlockIndexBuilder::new(self.dwarf());
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    tracing::info!(
                        "BlockIndex: built {} functions for CU {:?}",
                        funcs.len(),
                        cu_off
                    );
                    built_funcs += funcs.len();
                    self.block_index.add_functions(funcs);
                }
            }
            build_ms = b0.elapsed().as_millis();
        }

        if let Some(func) = self.block_index.find_function_by_pc(address).cloned() {
            let vars_in_func = func.nodes.iter().map(|n| n.variables.len()).sum::<usize>();
            tracing::info!(
                "DWARF:get_vars fast_path_hit addr=0x{:x} vars_in_func={} built_funcs={} build_ms={} total_ms={}",
                address,
                vars_in_func,
                built_funcs,
                build_ms,
                t0.elapsed().as_millis()
            );
            let fb_result = self.compute_frame_base_for_pc(&func, address);
            let cfa_result = if fb_result.is_none() {
                if self.cfi_index.is_some() {
                    match self.get_cfa_result(address) {
                        Ok(Some(cfa)) => Some(cfa),
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let get_cfa_closure = move |addr: u64| -> Result<Option<crate::core::CfaResult>> {
                if addr == address {
                    if let Some(fb) = fb_result.clone() {
                        return Ok(Some(fb));
                    }
                    return Ok(cfa_result.clone());
                }
                Ok(None)
            };
            let var_refs = func.variables_at_pc(address);
            if !var_refs.is_empty() {
                let items: Vec<(gimli::DebugInfoOffset, gimli::UnitOffset)> = var_refs
                    .iter()
                    .map(|v| (v.cu_offset, v.die_offset))
                    .collect();
                let mut vars = self.resolve_variables_by_offsets_at_address_with_cfa(
                    address,
                    &items,
                    Some(&get_cfa_closure),
                )?;

                let dwarf_ref = self.dwarf();
                for (idx, var_out) in vars.iter_mut().enumerate() {
                    if var_out.dwarf_type.is_none() {
                        let vr = &var_refs[idx];
                        if let Ok(header) = dwarf_ref.unit_header(vr.cu_offset) {
                            if let Ok(unit) = dwarf_ref.unit(header) {
                                if let Ok(entry) = unit.entry(vr.die_offset) {
                                    let planner = AccessPlanner::new(dwarf_ref);
                                    if let Ok(Some(type_loc)) =
                                        planner.resolve_type_ref_with_origins_public(&entry, &unit)
                                    {
                                        if let Some(ty) = self.detailed_shallow_type(
                                            type_loc.cu_off,
                                            type_loc.die_off,
                                        ) {
                                            var_out.type_name = ty.type_name();
                                            var_out.dwarf_type = Some(ty);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                if let Some(inline_idx) = Self::find_innermost_inline_node(&func, address) {
                    self.try_apply_call_site_mapping(
                        &func,
                        inline_idx,
                        address,
                        &mut vars,
                        &var_refs,
                        &get_cfa_closure,
                    );
                }

                let mut seen_param_names: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut filtered: Vec<crate::VariableWithEvaluation> =
                    Vec::with_capacity(vars.len());
                for v in vars.into_iter() {
                    if v.is_parameter {
                        if seen_param_names.insert(v.name.clone()) {
                            filtered.push(v);
                        }
                    } else {
                        filtered.push(v);
                    }
                }

                tracing::info!(
                    "DWARF:get_vars resolved {} vars total_ms={}",
                    filtered.len(),
                    t0.elapsed().as_millis()
                );
                return Ok(filtered);
            }
        }

        Err(anyhow::anyhow!(
            "StrictIndex: no function found for address 0x{:x} in block index",
            address
        ))
    }

    pub(crate) fn plan_chain_access(
        &mut self,
        address: u64,
        base_var: &str,
        chain: &[String],
    ) -> Result<Option<crate::VariableWithEvaluation>> {
        let t0 = Instant::now();
        let mut built_funcs: usize = 0;
        let mut build_ms: u128 = 0;
        tracing::info!(
            "DWARF:plan_chain module='{}' addr=0x{:x} base='{}' chain_len={}",
            self.module_mapping.path.display(),
            address,
            base_var,
            chain.len()
        );

        if self.block_index.find_function_by_pc(address).is_none() {
            let b0 = Instant::now();
            let builder = BlockIndexBuilder::new(self.dwarf());
            if let Some(func_entry) = self.find_function_index_entry_by_address(address) {
                if let Some(fb) =
                    builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
                {
                    self.block_index.add_functions(vec![fb]);
                    built_funcs += 1;
                }
            } else if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    built_funcs += funcs.len();
                    self.block_index.add_functions(funcs);
                }
            }
            build_ms = b0.elapsed().as_millis();
        }

        if let Some(func) = self.block_index.find_function_by_pc(address).cloned() {
            let cfa_result = if self.cfi_index.is_some() {
                match self.get_cfa_result(address) {
                    Ok(Some(cfa)) => Some(cfa),
                    _ => None,
                }
            } else {
                None
            };
            let get_cfa_closure = move |addr: u64| -> Result<Option<crate::core::CfaResult>> {
                if addr == address {
                    Ok(cfa_result.clone())
                } else {
                    Ok(None)
                }
            };

            let dwarf = self.dwarf();
            let header = dwarf.unit_header(func.cu_offset)?;
            let unit = dwarf.unit(header)?;
            let candidates = func.variables_at_pc(address);
            tracing::info!(
                "DWARF:plan_chain fast_path_hit addr=0x{:x} candidates={} built_funcs={} build_ms={}",
                address,
                candidates.len(),
                built_funcs,
                build_ms
            );
            let mut cand_names: Vec<String> = Vec::new();
            for v in &candidates {
                let e = unit.entry(v.die_offset)?;
                if let Some(name) = resolve_name_with_origins(dwarf, &unit, &e)? {
                    cand_names.push(name);
                }
            }
            tracing::info!("DWARF:plan_chain candidates_names={:?}", cand_names);

            for v in candidates {
                let e = unit.entry(v.die_offset)?;
                if let Some(n) = resolve_name_with_origins(dwarf, &unit, &e)? {
                    if n == base_var || n.starts_with(&format!("{base_var}@")) {
                        if chain.is_empty() {
                            let one = vec![(func.cu_offset, v.die_offset)];
                            let t1 = Instant::now();
                            let vars = self.resolve_variables_by_offsets_at_address_with_cfa(
                                address,
                                &one,
                                Some(&get_cfa_closure),
                            )?;
                            let mut var_opt = vars.into_iter().next();
                            let mut type_ms = 0u128;
                            if let Some(ref mut var0) = var_opt {
                                if var0.dwarf_type.is_none() {
                                    let dwarf = self.dwarf();
                                    let header = dwarf.unit_header(func.cu_offset)?;
                                    let unit = dwarf.unit(header)?;
                                    let e = unit.entry(v.die_offset)?;
                                    let planner = AccessPlanner::new(dwarf);
                                    if let Some(type_loc) =
                                        planner.resolve_type_ref_with_origins_public(&e, &unit)?
                                    {
                                        let tstart = Instant::now();
                                        if let Some(ty) = self.detailed_shallow_type(
                                            type_loc.cu_off,
                                            type_loc.die_off,
                                        ) {
                                            type_ms = tstart.elapsed().as_millis();
                                            var0.type_name = ty.type_name();
                                            var0.dwarf_type = Some(ty);
                                        }
                                    }
                                }
                            }
                            tracing::info!(
                                "DWARF:plan_chain var_match='{}' resolve_base_ms={} type_ms={} total_ms={}",
                                n,
                                t1.elapsed().as_millis(),
                                type_ms,
                                t0.elapsed().as_millis()
                            );
                            return Ok(var_opt);
                        }

                        let t1 = Instant::now();
                        let res = self.plan_chain_access_from_var(
                            address,
                            func.cu_offset,
                            func.die_offset,
                            v.die_offset,
                            ChainSpec {
                                base: base_var,
                                fields: chain,
                            },
                            Some(&get_cfa_closure),
                        )?;
                        tracing::info!(
                            "DWARF:plan_chain var_match='{}' plan_ms={} total_ms={}",
                            n,
                            t1.elapsed().as_millis(),
                            t0.elapsed().as_millis()
                        );
                        return Ok(res);
                    }
                }
            }
        }

        let globals = self.find_global_variables_by_name(base_var);
        if !globals.is_empty() {
            for info in globals {
                match self.plan_chain_access_from_var(
                    address,
                    info.unit_offset,
                    info.die_offset,
                    info.die_offset,
                    ChainSpec {
                        base: base_var,
                        fields: chain,
                    },
                    None,
                ) {
                    Ok(Some(v)) => {
                        tracing::info!(
                            "DWARF:plan_chain(global) success base='{}' total_ms={}",
                            base_var,
                            t0.elapsed().as_millis()
                        );
                        return Ok(Some(v));
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::debug!(
                            "DWARF:plan_chain(global) candidate failed for base='{}': {}",
                            base_var,
                            e
                        );
                        continue;
                    }
                }
            }
        }

        let err = anyhow::anyhow!(
            "StrictIndex: no function found for address 0x{:x} or no matching base var '{}' (plan_chain)",
            address,
            base_var
        );
        tracing::info!(
            "DWARF:plan_chain miss addr=0x{:x} built_funcs={} build_ms={} total_ms={} err={}",
            address,
            built_funcs,
            build_ms,
            t0.elapsed().as_millis(),
            err
        );
        Err(err)
    }

    fn compute_frame_base_for_pc(
        &self,
        func: &FunctionBlocks,
        pc: u64,
    ) -> Option<crate::core::CfaResult> {
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(func.cu_offset).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let path = func.block_path_for_pc(pc);
        let mut candidates: Vec<gimli::UnitOffset> = Vec::new();
        for &idx in path.iter().rev() {
            if idx == 0 {
                candidates.push(func.die_offset);
            } else if let Some(off) = func.nodes.get(idx).and_then(|n| n.die_offset) {
                candidates.push(off);
            }
        }

        for off in candidates {
            if let Ok(entry) = unit.entry(off) {
                if let Ok(Some(val)) = resolve_attr_with_unit_origins(
                    &entry,
                    &unit,
                    gimli::constants::DW_AT_frame_base,
                ) {
                    let eval_res = match val {
                        gimli::AttributeValue::Exprloc(expr) => {
                            ExpressionEvaluator::parse_expression_in_unit(
                                expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                &unit,
                                dwarf,
                                pc,
                                None,
                            )
                            .ok()
                        }
                        gimli::AttributeValue::LocationListsRef(offset) => {
                            ExpressionEvaluator::parse_location_lists(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset.0),
                                pc,
                                None,
                            )
                            .ok()
                        }
                        gimli::AttributeValue::SecOffset(offset) => {
                            ExpressionEvaluator::parse_location_lists(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset),
                                pc,
                                None,
                            )
                            .ok()
                        }
                        _ => None,
                    };

                    if let Some(er) = eval_res {
                        use crate::core::{
                            CfaResult, ComputeStep, EvaluationResult, LocationResult,
                        };
                        let cfa = match er {
                            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                                register,
                                offset,
                                ..
                            }) => CfaResult::RegisterPlusOffset {
                                register,
                                offset: offset.unwrap_or(0),
                            },
                            EvaluationResult::MemoryLocation(
                                LocationResult::ComputedLocation { steps },
                            ) => CfaResult::Expression { steps },
                            EvaluationResult::MemoryLocation(LocationResult::Address(addr)) => {
                                CfaResult::Expression {
                                    steps: vec![ComputeStep::PushConstant(addr as i64)],
                                }
                            }
                            EvaluationResult::DirectValue(
                                crate::core::DirectValueResult::Constant(c),
                            ) => CfaResult::Expression {
                                steps: vec![ComputeStep::PushConstant(c)],
                            },
                            EvaluationResult::DirectValue(
                                crate::core::DirectValueResult::ImplicitValue(bytes),
                            ) => {
                                if bytes.len() == 8 {
                                    let mut arr = [0u8; 8];
                                    arr.copy_from_slice(&bytes);
                                    let v = u64::from_le_bytes(arr) as i64;
                                    CfaResult::Expression {
                                        steps: vec![ComputeStep::PushConstant(v)],
                                    }
                                } else {
                                    continue;
                                }
                            }
                            _ => continue,
                        };
                        return Some(cfa);
                    }
                }
            }
        }

        None
    }

    fn detailed_shallow_type(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        crate::parser::DetailedParser::resolve_type_shallow_at_offset(dwarf, &unit, die_off)
    }

    pub(crate) fn shallow_type_for_variable_offsets(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let entry = unit.entry(die_off).ok()?;
        let planner = AccessPlanner::new(dwarf);
        match planner.resolve_type_ref_with_origins_public(&entry, &unit) {
            Ok(Some(type_loc)) => self.detailed_shallow_type(type_loc.cu_off, type_loc.die_off),
            _ => None,
        }
    }

    pub(crate) fn resolve_variables_by_offsets_at_address(
        &mut self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
    ) -> Result<Vec<crate::VariableWithEvaluation>> {
        self.resolve_variables_by_offsets_at_address_with_cfa(address, items, None)
    }
}

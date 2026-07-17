use super::LoadedObjfile;
use crate::{
    core::{
        attr_u64, Availability, FunctionId, InlineContextId, Result, ScopeId, UnsupportedReason,
    },
    index::{BlockIndexBuilder, FunctionBlocks, VarRef},
    parser::ExpressionEvaluator,
    semantics::{
        resolve_attr_with_unit_origins, resolve_name_with_origins, resolve_origin_entry,
        resolve_type_ref_with_origins, FunctionParameter, InlineFrame, PcLineInfo, TypeLoc,
        VariableQueryDiagnostic,
    },
};
use gimli::Reader;

type PcScopes = (
    Option<crate::CuId>,
    Option<FunctionId>,
    Vec<ScopeId>,
    Vec<InlineFrame>,
);

fn cu_id(cu_offset: gimli::DebugInfoOffset) -> crate::CuId {
    crate::CuId(cu_offset.0 as u32)
}

fn die_ref(
    module: crate::ModuleId,
    cu_offset: gimli::DebugInfoOffset,
    die_offset: gimli::UnitOffset,
) -> crate::DieRef {
    crate::DieRef {
        module,
        cu: cu_id(cu_offset),
        offset: die_offset.0 as u64,
    }
}

fn type_id(
    module: crate::ModuleId,
    cu_offset: gimli::DebugInfoOffset,
    die_offset: gimli::UnitOffset,
) -> crate::TypeId {
    let cu = cu_id(cu_offset);
    crate::TypeId {
        module,
        cu,
        die: crate::DieRef {
            module,
            cu,
            offset: die_offset.0 as u64,
        },
    }
}

pub(super) fn complete_aggregate_declaration_entry(
    dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
    type_name_index: &crate::index::TypeNameIndex,
    unit: &gimli::Unit<crate::binary::DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
) -> Option<(gimli::DebugInfoOffset, gimli::UnitOffset)> {
    match entry.tag() {
        gimli::constants::DW_TAG_structure_type
        | gimli::constants::DW_TAG_class_type
        | gimli::constants::DW_TAG_union_type
        | gimli::constants::DW_TAG_enumeration_type => {}
        _ => return None,
    }

    let is_declaration = entry
        .attr(gimli::constants::DW_AT_declaration)
        .is_some_and(|attr| matches!(attr.value(), gimli::AttributeValue::Flag(true)));
    if !is_declaration {
        return None;
    }

    let name = entry
        .attr(gimli::constants::DW_AT_name)
        .and_then(|attr| dwarf.attr_string(unit, attr.value()).ok())
        .and_then(|name| name.to_string_lossy().ok().map(|name| name.into_owned()))?;
    let definition = type_name_index.find_aggregate_definition(&name, entry.tag())?;
    Some((definition.cu_offset, definition.die_offset))
}

impl LoadedObjfile {
    pub(crate) fn attach_variable_identity(
        &self,
        module: crate::ModuleId,
        cu_offset: gimli::DebugInfoOffset,
        die_offset: gimli::UnitOffset,
        variable: &mut crate::parser::ParsedVariable,
    ) {
        variable.declaration = Some(die_ref(module, cu_offset, die_offset));

        let dwarf = self.dwarf();
        let Ok(header) = dwarf.unit_header(cu_offset) else {
            return;
        };
        let Ok(unit) = dwarf.unit(header) else {
            return;
        };
        let Ok(entry) = unit.entry(die_offset) else {
            return;
        };
        let Ok(Some(type_loc)) = resolve_type_ref_with_origins(dwarf, &entry, &unit) else {
            return;
        };

        variable.type_id = Some(type_id(module, type_loc.cu_off, type_loc.die_off));
        if variable.dwarf_type.is_none() {
            if let Some(ty) = self.detailed_shallow_type(type_loc.cu_off, type_loc.die_off) {
                variable.type_name = ty.type_name();
                variable.dwarf_type = Some(ty);
            }
        }
    }

    fn find_innermost_inline_node(func: &FunctionBlocks, pc: u64) -> Option<usize> {
        let path = func.block_path_for_pc(pc);
        path.iter()
            .rev()
            .find(|&&idx| func.nodes[idx].entry_pc.is_some())
            .copied()
    }

    fn ensure_block_index_for_address(&self, address: u64) {
        if self
            .block_index
            .read()
            .expect("block index lock poisoned")
            .find_function_by_pc(address)
            .is_some()
        {
            return;
        }

        let builder = BlockIndexBuilder::new(self.dwarf());
        if let Some(func_entry) = self.find_function_index_entry_by_address(address) {
            if let Some(fb) =
                builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
            {
                self.add_block_index_functions_if_missing(address, vec![fb]);
            }
        } else if let Some(cu_off) = self
            .lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .find_cu_by_address(address)
        {
            if let Some(funcs) = builder.build_for_unit(cu_off) {
                self.add_block_index_functions_if_missing(address, funcs);
            }
        }
    }

    fn add_block_index_functions_if_missing(
        &self,
        address: u64,
        funcs: Vec<FunctionBlocks>,
    ) -> bool {
        let mut block_index = self.block_index.write().expect("block index lock poisoned");
        if block_index.find_function_by_pc(address).is_some() {
            return false;
        }
        block_index.add_functions(funcs);
        true
    }

    fn cu_name_from_unit(&self, unit: &gimli::Unit<crate::binary::DwarfReader>) -> Option<String> {
        let mut entries = unit.entries();
        let entry = entries.next_dfs().ok()??;
        let name = entry.attr_value(gimli::constants::DW_AT_name)?;
        self.dwarf()
            .attr_string(unit, name)
            .ok()?
            .to_string_lossy()
            .ok()
            .map(|name| name.into_owned())
    }

    fn attr_file_index(value: gimli::AttributeValue<crate::binary::DwarfReader>) -> Option<u64> {
        match value {
            gimli::AttributeValue::FileIndex(index) => Some(index),
            other => attr_u64(other),
        }
    }

    fn inline_call_site_info(
        &self,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
        address: u64,
    ) -> Option<PcLineInfo> {
        let line_number = entry
            .attr_value(gimli::constants::DW_AT_call_line)
            .and_then(attr_u64)
            .and_then(|line| u32::try_from(line).ok())?;
        let column = entry
            .attr_value(gimli::constants::DW_AT_call_column)
            .and_then(attr_u64)
            .and_then(|column| u32::try_from(column).ok())
            .filter(|column| *column > 0);
        let cu_name = self.cu_name_from_unit(unit);
        let file_path = entry
            .attr_value(gimli::constants::DW_AT_call_file)
            .and_then(Self::attr_file_index)
            .and_then(|file_index| {
                cu_name.as_deref().and_then(|cu_name| {
                    self.scoped_file_manager
                        .read()
                        .expect("scoped file index lock poisoned")
                        .lookup_by_scoped_index(cu_name, file_index)
                })
            })
            .or_else(|| cu_name.clone())
            .unwrap_or_default();

        Some(PcLineInfo {
            file_path,
            line_number,
            column,
            address,
        })
    }

    pub(crate) fn is_inline_at(&self, address: u64) -> Option<bool> {
        self.ensure_block_index_for_address(address);

        let func = self
            .block_index
            .read()
            .expect("block index lock poisoned")
            .find_function_by_pc(address)
            .cloned()?;

        if let Some(inline_idx) = Self::find_innermost_inline_node(&func, address) {
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

    pub(crate) fn resolve_pc_scopes(
        &self,
        module: crate::ModuleId,
        address: u64,
    ) -> Result<PcScopes> {
        self.ensure_block_index_for_address(address);

        let func = match self
            .block_index
            .read()
            .expect("block index lock poisoned")
            .find_function_by_pc(address)
            .cloned()
        {
            Some(func) => func,
            None => return Ok((None, None, Vec::new(), Vec::new())),
        };

        let header = self.dwarf().unit_header(func.cu_offset)?;
        let unit = self.dwarf().unit(header)?;
        let cu = cu_id(func.cu_offset);
        let function_die = die_ref(module, func.cu_offset, func.die_offset);
        let function = Some(FunctionId {
            declaration: function_die,
        });
        let mut lexical_scopes = Vec::new();
        let mut inline_chain = Vec::new();

        for node_index in func.block_path_for_pc(address) {
            let Some(die_offset) = func.nodes[node_index].die_offset else {
                continue;
            };
            let entry = unit.entry(die_offset)?;
            let die = die_ref(module, func.cu_offset, die_offset);
            match entry.tag() {
                gimli::constants::DW_TAG_lexical_block => {
                    lexical_scopes.push(ScopeId { die });
                }
                gimli::constants::DW_TAG_inlined_subroutine => {
                    let abstract_origin = entry
                        .attr_value(gimli::constants::DW_AT_abstract_origin)
                        .and_then(|value| {
                            resolve_origin_entry(self.dwarf(), &unit, value)
                                .ok()
                                .flatten()
                                .and_then(|(_, origin_unit, origin_entry)| {
                                    origin_unit.header.debug_info_offset().map(|origin_cu| {
                                        die_ref(module, origin_cu, origin_entry.offset())
                                    })
                                })
                        });
                    let function_name = resolve_name_with_origins(self.dwarf(), &unit, &entry)
                        .ok()
                        .flatten();
                    let call_site = self.inline_call_site_info(&unit, &entry, address);
                    inline_chain.push(InlineFrame {
                        context: Some(InlineContextId { die }),
                        call_site,
                        abstract_origin,
                        concrete_die: die,
                        function_name,
                    });
                }
                _ => {}
            }
        }

        Ok((Some(cu), function, lexical_scopes, inline_chain))
    }

    fn resolve_variables_by_offsets_at_address_with_cfa(
        &self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&crate::index::CfiIndex>,
    ) -> Result<Vec<crate::parser::ParsedVariable>> {
        let items_with_depths = items
            .iter()
            .map(|(cu_off, die_off)| (*cu_off, *die_off, 0))
            .collect::<Vec<_>>();
        self.resolve_variables_by_offsets_at_address_with_cfa_and_depths(
            address,
            &items_with_depths,
            get_cfa,
            function_context,
            cfi_index,
        )
    }

    fn resolve_variables_by_offsets_at_address_with_cfa_and_depths(
        &self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset, usize)],
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&crate::index::CfiIndex>,
    ) -> Result<Vec<crate::parser::ParsedVariable>> {
        let mut vars = Vec::with_capacity(items.len());
        for (cu_off, die_off, scope_depth) in items.iter().cloned() {
            let header = self.dwarf.unit_header(cu_off)?;
            let unit = self.dwarf.unit(header)?;
            let entry = unit.entry(die_off)?;
            if let Some(v) = self.detailed_parser.parse_variable_entry_with_mode(
                &entry,
                &unit,
                &self.dwarf,
                address,
                get_cfa,
                function_context,
                cfi_index,
                scope_depth,
            )? {
                vars.push(v);
            }
        }
        Ok(vars)
    }

    pub(crate) fn resolve_type_shallow_by_name_with_tags_and_loc(
        &self,
        name: &str,
        tags: &[gimli::DwTag],
    ) -> Option<(crate::TypeInfo, TypeLoc)> {
        if let Err(error) = self.ensure_debug_info_for_type_name(name) {
            tracing::warn!(
                "Failed to load indexed DWARF for type '{}' in {}: {}",
                name,
                self.module_path().display(),
                error
            );
        }
        for &tag in tags {
            let loc = self
                .type_name_index
                .read()
                .expect("type name index lock poisoned")
                .find_aggregate_definition(name, tag);
            if let Some(loc) = loc {
                let ty = self.detailed_shallow_type(loc.cu_offset, loc.die_offset)?;
                return Some((
                    ty,
                    TypeLoc {
                        cu_off: loc.cu_offset,
                        die_off: loc.die_offset,
                    },
                ));
            }
        }

        let typedef = self
            .type_name_index
            .read()
            .expect("type name index lock poisoned")
            .find_typedef(name);
        if let Some(td) = typedef {
            let dwarf = self.dwarf();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Ok(Some(type_loc)) =
                            resolve_type_ref_with_origins(dwarf, &entry, &unit)
                        {
                            let ty =
                                self.detailed_shallow_type(type_loc.cu_off, type_loc.die_off)?;
                            return Some((ty, type_loc));
                        }
                        let ty = crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        )?;
                        return Some((
                            ty,
                            TypeLoc {
                                cu_off: td.cu_offset,
                                die_off: td.die_offset,
                            },
                        ));
                    }
                }
            }
        }

        None
    }

    pub(crate) fn get_visible_variables_at_address_best_effort_with_diagnostics(
        &self,
        module: crate::ModuleId,
        address: u64,
    ) -> Result<(
        Vec<crate::parser::ParsedVariable>,
        Vec<VariableQueryDiagnostic>,
    )> {
        self.ensure_block_index_for_address(address);

        let func = self
            .block_index
            .read()
            .expect("block index lock poisoned")
            .find_function_by_pc(address)
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "StrictIndex: no function found for address 0x{address:x} in block index"
                )
            })?;

        let fb_result = self.compute_frame_base_for_pc(&func, address);
        let cfa_result = if fb_result.is_none() {
            if self.unwind_info.has_cfi() {
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

        let var_refs = func.variables_at_pc_with_scope_depth(address);
        let cfi_index = self.unwind_info.cfi_index().cloned();
        let mut variables = Vec::with_capacity(var_refs.len());
        let mut diagnostics = Vec::new();

        for (var_ref, scope_depth) in var_refs {
            let item = [(var_ref.cu_offset, var_ref.die_offset, scope_depth)];
            let mut resolved = match self
                .resolve_variables_by_offsets_at_address_with_cfa_and_depths(
                    address,
                    &item,
                    Some(&get_cfa_closure),
                    Some(&func),
                    cfi_index.as_ref(),
                ) {
                Ok(vars) => vars,
                Err(error) => {
                    let detail = error.to_string();
                    diagnostics.push(VariableQueryDiagnostic {
                        pc: address,
                        name: self.variable_name_for_ref(&var_ref),
                        scope_depth,
                        availability: Self::variable_eval_error_availability(&error, &detail),
                        detail,
                    });
                    tracing::debug!(
                        "Skipping visible variable at 0x{:x} due to DWARF evaluation error: {}",
                        address,
                        error
                    );
                    continue;
                }
            };

            let Some(mut variable) = resolved.pop() else {
                continue;
            };
            self.attach_variable_identity(
                module,
                var_ref.cu_offset,
                var_ref.die_offset,
                &mut variable,
            );

            variables.push(variable);
        }

        let mut seen_param_names = std::collections::HashSet::new();
        variables.retain(|variable| {
            !variable.is_parameter
                || seen_param_names.insert((variable.name.clone(), variable.scope_depth))
        });
        Ok((variables, diagnostics))
    }

    pub(crate) fn function_parameters(
        &self,
        function: FunctionId,
    ) -> Result<Vec<FunctionParameter>> {
        let cu_off = gimli::DebugInfoOffset(function.declaration.cu.0 as usize);
        let die_off = gimli::UnitOffset(function.declaration.offset as usize);
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(cu_off)?;
        let unit = dwarf.unit(header)?;
        let entry = unit.entry(die_off)?;

        let params = self.direct_function_parameters(dwarf, &unit, &entry)?;
        if !params.is_empty() {
            return Ok(params);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((_, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, &unit, value)?
                {
                    let params =
                        self.direct_function_parameters(dwarf, &origin_unit, &origin_entry)?;
                    if !params.is_empty() {
                        return Ok(params);
                    }
                }
            }
        }

        Ok(Vec::new())
    }

    fn direct_function_parameters(
        &self,
        dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
    ) -> Result<Vec<FunctionParameter>> {
        let mut params = Vec::new();
        let mut tree = unit.entries_tree(Some(entry.offset()))?;
        let root = tree.root()?;
        let mut children = root.children();

        while let Some(child) = children.next()? {
            let child_entry = child.entry();
            if child_entry.tag() != gimli::constants::DW_TAG_formal_parameter {
                continue;
            }

            params.push(self.function_parameter_from_entry(dwarf, unit, child_entry)?);
        }

        Ok(params)
    }

    fn function_parameter_from_entry(
        &self,
        dwarf: &gimli::Dwarf<crate::binary::DwarfReader>,
        unit: &gimli::Unit<crate::binary::DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<crate::binary::DwarfReader>,
    ) -> Result<FunctionParameter> {
        let name = resolve_name_with_origins(dwarf, unit, entry)?.unwrap_or_default();
        let type_name = resolve_type_ref_with_origins(dwarf, entry, unit)?
            .and_then(|loc| self.detailed_shallow_type(loc.cu_off, loc.die_off))
            .map(|ty| ty.type_name())
            .unwrap_or_else(|| "unknown".to_string());
        let is_artificial =
            resolve_attr_with_unit_origins(entry, unit, gimli::constants::DW_AT_artificial)?
                .is_some_and(|value| match value {
                    gimli::AttributeValue::Flag(v) => v,
                    gimli::AttributeValue::Data1(v) => v != 0,
                    gimli::AttributeValue::Data2(v) => v != 0,
                    gimli::AttributeValue::Data4(v) => v != 0,
                    gimli::AttributeValue::Data8(v) => v != 0,
                    gimli::AttributeValue::Udata(v) => v != 0,
                    _ => false,
                });

        Ok(FunctionParameter {
            name,
            type_name,
            is_artificial,
        })
    }

    fn variable_name_for_ref(&self, var_ref: &VarRef) -> Option<String> {
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(var_ref.cu_offset).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let entry = unit.entry(var_ref.die_offset).ok()?;
        resolve_name_with_origins(dwarf, &unit, &entry)
            .ok()
            .flatten()
    }

    fn variable_eval_error_availability(error: &anyhow::Error, detail: &str) -> Availability {
        if let Some(op) = crate::dwarf_expr::ops::unsupported_op_from_error(error) {
            Availability::Unsupported(UnsupportedReason::DwarfOp { op: op.to_string() })
        } else {
            Availability::Unsupported(UnsupportedReason::ExpressionShape {
                detail: detail.to_string(),
            })
        }
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
                    let cfa = match val {
                        gimli::AttributeValue::Exprloc(expr) => {
                            ExpressionEvaluator::parse_expression_as_cfa_in_unit(
                                expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                expr.0.endian(),
                                &unit,
                                dwarf,
                                pc,
                                None,
                                None,
                                None,
                            )
                            .ok()
                            .flatten()
                        }
                        gimli::AttributeValue::LocationListsRef(offset) => {
                            ExpressionEvaluator::parse_location_lists_as_cfa(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset.0),
                                pc,
                                None,
                                None,
                                None,
                            )
                            .ok()
                            .flatten()
                        }
                        gimli::AttributeValue::DebugLocListsIndex(index) => dwarf
                            .locations_offset(&unit, index)
                            .ok()
                            .and_then(|offset| {
                                ExpressionEvaluator::parse_location_lists_as_cfa(
                                    &unit, dwarf, offset, pc, None, None, None,
                                )
                                .ok()
                                .flatten()
                            }),
                        gimli::AttributeValue::SecOffset(offset) => {
                            ExpressionEvaluator::parse_location_lists_as_cfa(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset),
                                pc,
                                None,
                                None,
                                None,
                            )
                            .ok()
                            .flatten()
                        }
                        _ => None,
                    };

                    if let Some(cfa) = cfa {
                        return Some(cfa);
                    }
                }
            }
        }

        None
    }

    pub(crate) fn detailed_shallow_type(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.dwarf();
        let header = dwarf.unit_header(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let entry = unit.entry(die_off).ok()?;
        let definition = complete_aggregate_declaration_entry(
            dwarf,
            &self
                .type_name_index
                .read()
                .expect("type name index lock poisoned"),
            &unit,
            &entry,
        );
        if let Some((def_cu_off, def_die_off)) = definition {
            let def_header = dwarf.unit_header(def_cu_off).ok()?;
            let def_unit = dwarf.unit(def_header).ok()?;
            return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                dwarf,
                &def_unit,
                def_die_off,
            );
        }

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
        match resolve_type_ref_with_origins(dwarf, &entry, &unit) {
            Ok(Some(type_loc)) => self.detailed_shallow_type(type_loc.cu_off, type_loc.die_off),
            _ => None,
        }
    }

    pub(crate) fn resolve_variables_by_offsets_at_address(
        &self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
    ) -> Result<Vec<crate::parser::ParsedVariable>> {
        self.resolve_variables_by_offsets_at_address_with_cfa(address, items, None, None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{FunctionDieKind, IndexEntry, IndexFlags};
    use crate::index::{LightweightIndex, TypeNameIndex};
    use gimli::constants;
    use gimli::write::{
        AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec, LineProgram,
        Sections, Unit,
    };
    use gimli::{DebugInfoOffset, Format, LittleEndian};
    use std::collections::HashMap;
    use std::sync::Arc;

    type AggregateFixture = (
        gimli::Dwarf<DwarfReader>,
        gimli::Unit<DwarfReader>,
        gimli::UnitOffset,
        DebugInfoOffset,
        gimli::UnitOffset,
        Arc<TypeNameIndex>,
    );

    fn build_declaration_completion_fixture() -> AggregateFixture {
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

        build_fixture_from_dwarf(dwarf, true, false)
    }

    fn build_empty_definition_fixture() -> AggregateFixture {
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

        build_fixture_from_dwarf(dwarf, false, false)
    }

    fn build_fixture_from_dwarf(
        mut dwarf: WriteDwarf,
        source_is_declaration: bool,
        source_has_children: bool,
    ) -> AggregateFixture {
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
        let read_dwarf = dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));

        let mut units = read_dwarf.units();
        let source_header = units.next().unwrap().unwrap();
        let full_header = units.next().unwrap().unwrap();
        let source_cu_off = source_header.debug_info_offset().unwrap();
        let full_cu_off = full_header.debug_info_offset().unwrap();

        let source_unit = read_dwarf.unit(source_header).unwrap();
        let full_unit = read_dwarf.unit(full_header).unwrap();
        let source_struct_off = find_struct_offset(
            &read_dwarf,
            &source_unit,
            "Foo",
            source_is_declaration,
            source_has_children,
        );
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
                representative_addr: None,
                entry_pc: None,
                function_kind: FunctionDieKind::NotFunction,
            }],
        );
        let type_index = Arc::new(TypeNameIndex::build_from_lightweight(
            &LightweightIndex::from_builder_data(HashMap::new(), HashMap::new(), types),
        ));

        (
            read_dwarf,
            source_unit,
            source_struct_off,
            if source_is_declaration {
                full_cu_off
            } else {
                source_cu_off
            },
            full_struct_off,
            type_index,
        )
    }

    fn find_struct_offset(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
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
        unit: &gimli::Unit<DwarfReader>,
        die: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> bool {
        let mut entries = unit.entries_at_offset(die.offset()).unwrap();
        let _ = entries.next_entry().unwrap();
        entries.next_dfs().unwrap().is_some()
    }

    #[test]
    fn aggregate_completion_uses_declaration_flag_despite_later_siblings() {
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

        let resolved =
            complete_aggregate_declaration_entry(&dwarf, &type_index, &decl_unit, &decl_struct_die);

        assert_eq!(resolved, Some((def_cu_off, def_struct_off)));
    }

    #[test]
    fn aggregate_completion_does_not_rebind_empty_definitions() {
        let (dwarf, empty_unit, empty_struct_off, _source_cu_off, full_struct_off, type_index) =
            build_empty_definition_fixture();
        let empty_struct_die = empty_unit.entry(empty_struct_off).unwrap();

        assert!(!empty_struct_die.has_children());
        assert!(empty_struct_die
            .attr(constants::DW_AT_declaration)
            .is_none());

        let resolved = complete_aggregate_declaration_entry(
            &dwarf,
            &type_index,
            &empty_unit,
            &empty_struct_die,
        );

        assert_eq!(resolved, None);
        assert_ne!(empty_struct_off, full_struct_off);
    }
}

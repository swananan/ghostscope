use super::*;

fn metadata_access_size(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<ghostscope_dwarf::MemoryAccessSize> {
    let size = projection.resolved_type.summary.size();
    exact_memory_access_size(size, &format!("indirect value {role} member"))
}

fn exact_memory_access_size(size: u64, role: &str) -> Result<ghostscope_dwarf::MemoryAccessSize> {
    // Keep this exact; `from_size` falls back to U64 for unknown widths.
    match size {
        1 => Ok(ghostscope_dwarf::MemoryAccessSize::U8),
        2 => Ok(ghostscope_dwarf::MemoryAccessSize::U16),
        4 => Ok(ghostscope_dwarf::MemoryAccessSize::U32),
        8 => Ok(ghostscope_dwarf::MemoryAccessSize::U64),
        _ => Err(CodeGenError::DwarfError(format!(
            "{role} has unsupported DWARF size {size}"
        ))),
    }
}

fn metadata_member(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<(u64, ghostscope_dwarf::MemoryAccessSize)> {
    let access_size = metadata_access_size(projection, role)?;
    let offset = projected_member_offset(projection, role)?;
    Ok((offset, access_size))
}

fn projected_member_offset(
    projection: &ghostscope_dwarf::TypeProjection,
    role: &str,
) -> Result<u64> {
    match &projection.layout {
        ghostscope_dwarf::TypeProjectionLayout::Member { offset } => Ok(*offset),
        layout => Err(CodeGenError::DwarfError(format!(
            "semantic value {role} projection must be a member, got {layout:?}"
        ))),
    }
}

fn is_known_zero_sized_type(type_info: &ghostscope_dwarf::TypeInfo) -> bool {
    match type_info {
        ghostscope_dwarf::TypeInfo::BaseType { name, size: 0, .. } if name == "()" => true,
        ghostscope_dwarf::TypeInfo::StructType { size: 0, .. }
        | ghostscope_dwarf::TypeInfo::UnionType { size: 0, .. }
        | ghostscope_dwarf::TypeInfo::ArrayType {
            total_size: Some(0),
            ..
        } => true,
        ghostscope_dwarf::TypeInfo::TypedefType {
            underlying_type, ..
        }
        | ghostscope_dwarf::TypeInfo::QualifiedType {
            underlying_type, ..
        } => is_known_zero_sized_type(underlying_type),
        _ => false,
    }
}

fn inline_view_data_len(
    physical_type: &ghostscope_dwarf::TypeInfo,
    output_type: &ghostscope_dwarf::TypeInfo,
) -> Result<usize> {
    let physical_size = usize::try_from(physical_type.size()).map_err(|_| {
        CodeGenError::DwarfError("inline semantic root size does not fit this host".to_string())
    })?;
    let output_size = usize::try_from(output_type.size()).map_err(|_| {
        CodeGenError::DwarfError("inline semantic view size does not fit this host".to_string())
    })?;
    if output_size != physical_size {
        return Err(CodeGenError::DwarfError(format!(
            "inline semantic view size {output_size} does not match DWARF root size {physical_size}"
        )));
    }
    if output_size == 0 && !is_known_zero_sized_type(output_type) {
        return Err(CodeGenError::DwarfError(
            "inline semantic view has an unknown zero-byte layout".to_string(),
        ));
    }
    Ok(output_size)
}

fn projected_view_source(
    output_type: &ghostscope_dwarf::TypeInfo,
    fields: &[ghostscope_dwarf::ProjectedViewField],
) -> Result<(usize, Vec<ProjectedViewFieldSource>)> {
    let ghostscope_dwarf::TypeInfo::StructType { size, members, .. } = output_type else {
        return Err(CodeGenError::DwarfError(
            "projected semantic view must be a struct".to_string(),
        ));
    };
    if members.len() != fields.len() {
        return Err(CodeGenError::DwarfError(
            "projected semantic fields do not match the output type".to_string(),
        ));
    }

    let data_len = usize::try_from(*size).map_err(|_| {
        CodeGenError::DwarfError("projected semantic view size does not fit this host".to_string())
    })?;
    if data_len > u16::MAX as usize {
        return Err(CodeGenError::DwarfError(format!(
            "projected semantic view size {data_len} exceeds the protocol limit"
        )));
    }
    let mut sources = Vec::with_capacity(fields.len());
    let mut ranges = Vec::with_capacity(fields.len());
    for (member, field) in members.iter().zip(fields) {
        if member.offset != field.output_offset
            || member.member_type != field.value.resolved_type.summary
        {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' does not match its output member",
                member.name
            )));
        }
        let output_offset = usize::try_from(field.output_offset).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' offset does not fit this host",
                member.name
            ))
        })?;
        let value_len = usize::try_from(member.member_type.size()).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' size does not fit this host",
                member.name
            ))
        })?;
        let end = output_offset.checked_add(value_len).ok_or_else(|| {
            CodeGenError::DwarfError(format!(
                "projected semantic field '{}' end overflow",
                member.name
            ))
        })?;
        if end > data_len || (value_len == 0 && !is_known_zero_sized_type(&member.member_type)) {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' exceeds its output layout",
                member.name
            )));
        }
        if value_len > 0
            && ranges
                .iter()
                .any(|(start, range_end)| output_offset < *range_end && *start < end)
        {
            return Err(CodeGenError::DwarfError(format!(
                "projected semantic field '{}' overlaps another output member",
                member.name
            )));
        }
        ranges.push((output_offset, end));

        let mut steps = Vec::with_capacity(field.value.steps.len());
        for step in &field.value.steps {
            steps.push(match step {
                ghostscope_dwarf::ProjectedValueStep::Member { offset } => {
                    ProjectedViewStep::Member { offset: *offset }
                }
                ghostscope_dwarf::ProjectedValueStep::Dereference { pointer_size } => {
                    ProjectedViewStep::Dereference {
                        pointer_size: exact_memory_access_size(
                            *pointer_size,
                            "projected semantic pointer",
                        )?,
                    }
                }
            });
        }
        sources.push(ProjectedViewFieldSource {
            output_offset,
            value_len,
            steps,
        });
    }

    Ok((data_len, sources))
}

fn sequence_capture_limits(cap: usize, element_stride: u64) -> Result<(usize, usize, usize)> {
    let stride = usize::try_from(element_stride).map_err(|_| {
        CodeGenError::DwarfError(format!(
            "sequence element DWARF size {element_stride} does not fit this host"
        ))
    })?;
    let (max_elements, max_len) = if stride == 0 {
        // A byte cap cannot bound a ZST payload, so use the configured value
        // as its logical element-count cap.
        (cap, 0)
    } else {
        let max_elements = cap / stride;
        (max_elements, max_elements * stride)
    };
    let data_len = ghostscope_protocol::INDIRECT_SEQUENCE_HEADER_SIZE.saturating_add(max_len);
    Ok((max_elements, max_len, data_len))
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) const UNKNOWN_CHAR_ARRAY_READ_FALLBACK: usize = 256;

    fn semantic_value_read_plan(
        &self,
        resolved_type: &ghostscope_dwarf::ResolvedType,
        type_module_path: Option<&std::path::Path>,
    ) -> Result<Option<ghostscope_dwarf::ValueReadPlan>> {
        let Some(analyzer) = self.process_analyzer else {
            return Ok(None);
        };
        analyzer
            .value_read_plan(resolved_type, type_module_path)
            .map_err(|error| CodeGenError::DwarfError(error.to_string()))
    }

    fn complex_arg_from_value_read_plan(
        &mut self,
        display_name: String,
        dwarf_type: ghostscope_dwarf::TypeInfo,
        descriptor: RuntimeAddress<'ctx>,
        plan: ghostscope_dwarf::ValueReadPlan,
    ) -> Result<ComplexArg<'ctx>> {
        let cap = self.compile_options.mem_dump_cap as usize;
        let ghostscope_dwarf::ValueReadPlan {
            presentation,
            capture,
        } = plan;
        let mut output_type = dwarf_type;
        let (data_len, source) = match capture {
            ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value } => {
                let offset = projected_member_offset(&value, "projected value")?;
                output_type = value.resolved_type.summary;
                let data_len = Self::compute_read_size_for_type(&output_type);
                if data_len == 0 {
                    if is_known_zero_sized_type(&output_type) {
                        (0, ComplexArgSource::ImmediateBytes { bytes: Vec::new() })
                    } else {
                        return Err(CodeGenError::TypeSizeNotAvailable(display_name));
                    }
                } else {
                    let address = if offset == 0 {
                        descriptor
                    } else {
                        let offset_value = self.context.i64_type().const_int(offset, false);
                        let address = self
                            .builder
                            .build_int_add(
                                descriptor.value,
                                offset_value,
                                "semantic_projected_value_address",
                            )
                            .map_err(|error| CodeGenError::Builder(error.to_string()))?;
                        descriptor.with_value(address)
                    };
                    (
                        data_len,
                        ComplexArgSource::MemDump {
                            address,
                            len: data_len,
                        },
                    )
                }
            }
            ghostscope_dwarf::ValueCapturePlan::InlineView {
                output_type: view_type,
            } => {
                let data_len = inline_view_data_len(&output_type, &view_type)?;
                output_type = view_type;
                if data_len == 0 {
                    (0, ComplexArgSource::ImmediateBytes { bytes: Vec::new() })
                } else {
                    (
                        data_len,
                        ComplexArgSource::MemDump {
                            address: descriptor,
                            len: data_len,
                        },
                    )
                }
            }
            ghostscope_dwarf::ValueCapturePlan::ProjectedView {
                output_type: view_type,
                fields,
            } => {
                let (data_len, fields) = projected_view_source(&view_type, &fields)?;
                output_type = view_type;
                (
                    data_len,
                    ComplexArgSource::ProjectedView { descriptor, fields },
                )
            }
            ghostscope_dwarf::ValueCapturePlan::IndirectBytes { data, length } => {
                let (data_offset, data_access_size) = metadata_member(&data, "data")?;
                let (length_offset, length_access_size) = metadata_member(&length, "length")?;
                let data_len =
                    ghostscope_protocol::INDIRECT_BYTES_LENGTH_PREFIX_SIZE.saturating_add(cap);
                (
                    data_len,
                    ComplexArgSource::IndirectBytes {
                        descriptor,
                        data_offset,
                        data_access_size,
                        length_offset,
                        length_access_size,
                        max_len: cap,
                    },
                )
            }
            ghostscope_dwarf::ValueCapturePlan::IndirectSequence {
                data,
                length,
                element_stride,
            } => {
                let (data_offset, data_access_size) = metadata_member(&data, "data")?;
                let (length_offset, length_access_size) = metadata_member(&length, "length")?;
                let (max_elements, max_len, data_len) =
                    sequence_capture_limits(cap, element_stride)?;
                (
                    data_len,
                    ComplexArgSource::IndirectSequence {
                        descriptor,
                        data_offset,
                        data_access_size,
                        length_offset,
                        length_access_size,
                        element_stride,
                        max_elements,
                        max_len,
                    },
                )
            }
            ghostscope_dwarf::ValueCapturePlan::IndirectRingSequence {
                data,
                start,
                length,
                capacity,
                element_stride,
            } => {
                let (data_offset, data_access_size) = metadata_member(&data, "data")?;
                let (start_offset, start_access_size) = metadata_member(&start, "start")?;
                let length = match *length {
                    ghostscope_dwarf::RingSequenceLength::Explicit(length) => {
                        let (offset, access_size) = metadata_member(&length, "length")?;
                        RingSequenceLengthSource::Explicit {
                            offset,
                            access_size,
                        }
                    }
                    ghostscope_dwarf::RingSequenceLength::End(end) => {
                        let (offset, access_size) = metadata_member(&end, "end")?;
                        RingSequenceLengthSource::End {
                            offset,
                            access_size,
                        }
                    }
                };
                let (capacity_offset, capacity_access_size) =
                    metadata_member(&capacity, "capacity")?;
                let (max_elements, max_len, data_len) =
                    sequence_capture_limits(cap, element_stride)?;
                (
                    data_len,
                    ComplexArgSource::IndirectRingSequence {
                        descriptor,
                        data_offset,
                        data_access_size,
                        start_offset,
                        start_access_size,
                        length,
                        capacity_offset,
                        capacity_access_size,
                        element_stride,
                        max_elements,
                        max_len,
                    },
                )
            }
        };

        Ok(ComplexArg {
            var_name_index: self.trace_context.add_variable_name(display_name)?,
            type_index: self
                .trace_context
                .add_type_with_presentation(output_type, presentation)?,
            access_path: Vec::new(),
            data_len,
            source,
        })
    }

    pub(super) fn complex_arg_from_dwarf_read_plan(
        &mut self,
        plan: ghostscope_dwarf::VariableReadPlan,
        display_name: Option<String>,
    ) -> Result<ComplexArg<'ctx>> {
        let pc_address = self.get_compile_time_context()?.pc_address;
        let semantic_plan = if let Some(analyzer) = self.process_analyzer {
            let resolved_type = analyzer
                .resolved_type_for_plan(&plan)
                .map_err(|error| CodeGenError::DwarfError(error.to_string()))?;
            match resolved_type {
                Some(resolved_type) => {
                    self.semantic_value_read_plan(&resolved_type, plan.module_path.as_deref())?
                }
                None => None,
            }
        } else {
            None
        };
        let materialized = self.variable_read_plan_to_materialization(plan, pc_address)?;
        let display_name = display_name.unwrap_or_else(|| materialized.name.clone());

        match &materialized.materialization {
            ghostscope_dwarf::VariableMaterialization::Unavailable {
                availability: ghostscope_dwarf::Availability::OptimizedOut,
            } => {
                let optimized_type = ghostscope_dwarf::TypeInfo::OptimizedOut {
                    name: materialized.name.clone(),
                };
                Ok(ComplexArg {
                    var_name_index: self.trace_context.add_variable_name(display_name)?,
                    type_index: self.trace_context.add_type(optimized_type)?,
                    access_path: Vec::new(),
                    data_len: 0,
                    source: ComplexArgSource::ImmediateBytes { bytes: Vec::new() },
                })
            }
            ghostscope_dwarf::VariableMaterialization::Unavailable { availability } => {
                Err(Self::dwarf_expression_unavailable_error(
                    &materialized.name,
                    availability,
                    pc_address,
                ))
            }
            ghostscope_dwarf::VariableMaterialization::UserMemoryRead { address } => {
                let dwarf_type = materialized.dwarf_type.clone().ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "Expression has no DWARF type information".to_string(),
                    )
                })?;
                let module_hint =
                    Self::module_path_for_offsets(materialized.module_path.as_deref());
                if let Some(semantic_plan) = semantic_plan {
                    let descriptor =
                        self.resolve_planned_address(address, None, module_hint.as_deref())?;
                    return self.complex_arg_from_value_read_plan(
                        display_name,
                        dwarf_type,
                        descriptor,
                        semantic_plan,
                    );
                }
                let data_len = Self::compute_read_size_for_type(&dwarf_type);
                if data_len == 0 {
                    return Err(CodeGenError::TypeSizeNotAvailable(display_name));
                }
                Ok(ComplexArg {
                    var_name_index: self.trace_context.add_variable_name(display_name)?,
                    type_index: self.trace_context.add_type(dwarf_type.clone())?,
                    access_path: Vec::new(),
                    data_len,
                    source: ComplexArgSource::RuntimeRead {
                        address: address.clone(),
                        dwarf_type,
                        module_for_offsets: module_hint,
                    },
                })
            }
            ghostscope_dwarf::VariableMaterialization::DirectValue { .. } => {
                let dwarf_type = materialized.dwarf_type.clone().ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "Expression has no DWARF type information".to_string(),
                    )
                })?;
                if let Some(ghostscope_dwarf::ValueReadPlan {
                    presentation,
                    capture:
                        ghostscope_dwarf::ValueCapturePlan::ProjectedValue { value: projected },
                }) = semantic_plan.as_ref()
                {
                    let projected_type = &projected.resolved_type.summary;
                    if Self::compute_read_size_for_type(projected_type) == 0
                        && is_known_zero_sized_type(projected_type)
                    {
                        return Ok(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(display_name)?,
                            type_index: self.trace_context.add_type_with_presentation(
                                projected_type.clone(),
                                presentation.clone(),
                            )?,
                            access_path: Vec::new(),
                            data_len: 0,
                            source: ComplexArgSource::ImmediateBytes { bytes: Vec::new() },
                        });
                    }
                }
                if let Some(ghostscope_dwarf::ValueReadPlan {
                    presentation,
                    capture:
                        ghostscope_dwarf::ValueCapturePlan::InlineView { output_type },
                }) = semantic_plan.as_ref()
                {
                    let data_len = inline_view_data_len(&dwarf_type, output_type)?;
                    if data_len == 0 {
                        return Ok(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(display_name)?,
                            type_index: self.trace_context.add_type_with_presentation(
                                output_type.clone(),
                                presentation.clone(),
                            )?,
                            access_path: Vec::new(),
                            data_len: 0,
                            source: ComplexArgSource::ImmediateBytes { bytes: Vec::new() },
                        });
                    }
                }
                let value =
                    self.variable_materialization_to_llvm_value(&materialized, pc_address, None)?;
                let value = match value {
                    BasicValueEnum::IntValue(value) => value,
                    BasicValueEnum::PointerValue(value) => self
                        .builder
                        .build_ptr_to_int(value, self.context.i64_type(), "direct_ptr_to_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    _ => {
                        return Err(CodeGenError::DwarfError(format!(
                            "direct DWARF value '{}' did not lower to an integer",
                            materialized.name
                        )))
                    }
                };
                if let Some(semantic_plan) = semantic_plan {
                    match semantic_plan.capture {
                        ghostscope_dwarf::ValueCapturePlan::ProjectedValue {
                            value: projected,
                        } => {
                            let offset =
                                projected_member_offset(&projected, "projected value")?;
                            let projected_type = projected.resolved_type.summary;
                            let data_len = Self::compute_read_size_for_type(&projected_type);
                            let container_len = Self::compute_read_size_for_type(&dwarf_type);
                            let projected_end = usize::try_from(offset)
                                .ok()
                                .and_then(|offset| offset.checked_add(data_len));
                            if data_len == 0
                                || data_len > 8
                                || projected_end
                                    .is_none_or(|end| end > container_len || end > 8)
                            {
                                return Err(CodeGenError::DwarfError(format!(
                                    "direct semantic projection for '{}' does not fit one eBPF register",
                                    materialized.name
                                )));
                            }
                            let value = if offset == 0 {
                                value
                            } else {
                                let shift = value.get_type().const_int(offset * 8, false);
                                self.builder
                                    .build_right_shift(
                                        value,
                                        shift,
                                        false,
                                        "semantic_projected_direct_value",
                                    )
                                    .map_err(|error| {
                                        CodeGenError::Builder(error.to_string())
                                    })?
                            };
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(display_name)?,
                                type_index: self.trace_context.add_type_with_presentation(
                                    projected_type,
                                    semantic_plan.presentation,
                                )?,
                                access_path: Vec::new(),
                                data_len,
                                source: ComplexArgSource::ComputedInt {
                                    value,
                                    byte_len: data_len,
                                },
                            });
                        }
                        ghostscope_dwarf::ValueCapturePlan::InlineView { output_type } => {
                            let data_len = inline_view_data_len(&dwarf_type, &output_type)?;
                            if data_len == 0 || data_len > 8 {
                                return Err(CodeGenError::DwarfError(format!(
                                    "direct semantic view for '{}' does not fit one eBPF register",
                                    materialized.name
                                )));
                            }
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(display_name)?,
                                type_index: self.trace_context.add_type_with_presentation(
                                    output_type,
                                    semantic_plan.presentation,
                                )?,
                                access_path: Vec::new(),
                                data_len,
                                source: ComplexArgSource::ComputedInt {
                                    value,
                                    byte_len: data_len,
                                },
                            });
                        }
                        ghostscope_dwarf::ValueCapturePlan::ProjectedView { .. } => {
                            return Err(CodeGenError::DwarfError(format!(
                                "direct semantic view for '{}' requires an address-backed root",
                                materialized.name
                            )));
                        }
                        _ => {}
                    }
                }
                let data_len = Self::compute_read_size_for_type(&dwarf_type).clamp(1, 8);
                Ok(ComplexArg {
                    var_name_index: self.trace_context.add_variable_name(display_name)?,
                    type_index: self.trace_context.add_type(dwarf_type)?,
                    access_path: Vec::new(),
                    data_len,
                    source: ComplexArgSource::ComputedInt { value, byte_len: data_len },
                })
            }
            ghostscope_dwarf::VariableMaterialization::Composite { .. } => Err(
                CodeGenError::DwarfError(format!(
                    "DWARF variable '{}' is split across pieces; piece reconstruction is not implemented",
                    materialized.name
                )),
            ),
        }
    }

    fn complex_arg_from_dynamic_lvalue(
        &mut self,
        expr: &crate::script::ast::Expr,
        lvalue: crate::ebpf::expression::DynamicLvalue<'ctx>,
    ) -> Result<ComplexArg<'ctx>> {
        if let Some(plan) = self.semantic_value_read_plan(
            &lvalue.type_info.resolved_type,
            lvalue.type_info.type_module_path.as_deref(),
        )? {
            return self.complex_arg_from_value_read_plan(
                self.expr_to_name(expr),
                lvalue.type_info.resolved_type.summary,
                lvalue.address,
                plan,
            );
        }
        let dwarf_type = lvalue.type_info.resolved_type.summary;
        let data_len = Self::compute_read_size_for_type(&dwarf_type);
        if data_len == 0 {
            return Err(CodeGenError::TypeSizeNotAvailable(self.expr_to_name(expr)));
        }

        Ok(ComplexArg {
            var_name_index: self
                .trace_context
                .add_variable_name(self.expr_to_name(expr))?,
            type_index: self.trace_context.add_type(dwarf_type)?,
            access_path: Vec::new(),
            data_len,
            source: ComplexArgSource::MemDump {
                address: lvalue.address,
                len: data_len,
            },
        })
    }

    fn complex_arg_from_cast_expr(
        &mut self,
        source_expr: &crate::script::ast::Expr,
        target_type: &str,
    ) -> Result<ComplexArg<'ctx>> {
        let dwarf_type = self.resolve_cast_target_type(target_type)?;
        let display_name = format!(
            "cast({}, \"{}\")",
            self.expr_to_name(source_expr),
            target_type
        );
        let var_name_index = self.trace_context.add_variable_name(display_name.clone())?;
        let type_index = self.trace_context.add_type(dwarf_type.clone())?;

        if matches!(
            ghostscope_dwarf::strip_type_aliases(&dwarf_type),
            ghostscope_dwarf::TypeInfo::PointerType { .. }
        ) {
            let value = self.cast_source_pointer_value(source_expr)?.value;
            return Ok(ComplexArg {
                var_name_index,
                type_index,
                access_path: Vec::new(),
                data_len: 8,
                source: ComplexArgSource::ComputedInt { value, byte_len: 8 },
            });
        }

        if ghostscope_dwarf::c_integer_comparison_type(&dwarf_type).is_some() {
            let cast_expr = crate::script::ast::Expr::Cast {
                expr: Box::new(source_expr.clone()),
                target_type: target_type.to_string(),
            };
            let value = match self.compile_expr(&cast_expr)? {
                BasicValueEnum::IntValue(value) => value,
                BasicValueEnum::PointerValue(value) => self
                    .builder
                    .build_ptr_to_int(value, self.context.i64_type(), "cast_arg_ptr_to_i64")
                    .map_err(|err| CodeGenError::Builder(err.to_string()))?,
                _ => {
                    return Err(CodeGenError::TypeError(
                        "cast expression did not produce an integer value".to_string(),
                    ))
                }
            };
            let byte_len = Self::cast_value_byte_len(&dwarf_type).unwrap_or(8);
            return Ok(ComplexArg {
                var_name_index,
                type_index,
                access_path: Vec::new(),
                data_len: byte_len,
                source: ComplexArgSource::ComputedInt { value, byte_len },
            });
        }

        let address = self.cast_source_memory_address(source_expr)?;
        let data_len = Self::compute_read_size_for_type(&dwarf_type);
        if data_len == 0 {
            return Err(CodeGenError::TypeSizeNotAvailable(display_name));
        }
        Ok(ComplexArg {
            var_name_index,
            type_index,
            access_path: Vec::new(),
            data_len,
            source: ComplexArgSource::MemDump {
                address,
                len: data_len,
            },
        })
    }

    /// Unified expression resolver: returns a ComplexArg carrying
    /// a consistent var_name_index/type_index/access_path/data_len/source
    /// with strict priority: script variables -> DWARF (locals/params/globals).
    pub(super) fn resolve_expr_to_arg(
        &mut self,
        expr: &crate::script::ast::Expr,
    ) -> Result<ComplexArg<'ctx>> {
        use crate::script::ast::Expr as E;
        match expr {
            // 0) Alias variables: resolve to address and render as pointer value
            E::Variable(name) if self.alias_variable_exists(name) => {
                let aliased = self.get_alias_variable(name).expect("alias exists");
                let addr_i64 = self.resolve_ptr_i64_from_expr(&aliased)?;
                let var_name_index = self.trace_context.add_variable_name(name.clone())?;
                Ok(ComplexArg {
                    var_name_index,
                    type_index: self.add_synthesized_type_index_for_kind(TypeKind::Pointer)?,
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::ComputedInt {
                        value: addr_i64,
                        byte_len: 8,
                    },
                })
            }
            // 1) Script variables first
            E::Variable(name) if self.variable_exists(name) => {
                let val = self.load_variable(name)?;
                let var_name_index = self.trace_context.add_variable_name(name.clone())?;
                // If this is a string variable, print its contents instead of address
                if self
                    .get_variable_type(name)
                    .is_some_and(|t| matches!(t, crate::script::VarType::String))
                {
                    let bytes_opt = self.get_string_variable_bytes(name).cloned();
                    if let Some(bytes) = bytes_opt {
                        // Build a char[] type with length=bytes.len()
                        let char_type = ghostscope_dwarf::TypeInfo::BaseType {
                            name: "char".to_string(),
                            size: 1,
                            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16,
                        };
                        let array_type = ghostscope_dwarf::TypeInfo::ArrayType {
                            element_type: Box::new(char_type),
                            element_count: Some(bytes.len() as u64),
                            total_size: Some(bytes.len() as u64),
                        };
                        return Ok(ComplexArg {
                            var_name_index,
                            type_index: self.trace_context.add_type(array_type)?,
                            access_path: Vec::new(),
                            data_len: bytes.len(),
                            source: ComplexArgSource::ImmediateBytes { bytes },
                        });
                    }
                }
                match val {
                    BasicValueEnum::IntValue(iv) => {
                        // Preserve signedness for display: map bit width to I8/I16/I32/I64
                        let bitw = iv.get_type().get_bit_width();
                        let (kind, byte_len) = if bitw == 1 {
                            (TypeKind::Bool, 1)
                        } else if bitw <= 8 {
                            (TypeKind::I8, 1)
                        } else if bitw <= 16 {
                            (TypeKind::I16, 2)
                        } else if bitw <= 32 {
                            (TypeKind::I32, 4)
                        } else {
                            (TypeKind::I64, 8)
                        };
                        Ok(ComplexArg {
                            var_name_index,
                            type_index: self.add_synthesized_type_index_for_kind(kind)?,
                            access_path: Vec::new(),
                            data_len: byte_len,
                            source: ComplexArgSource::ComputedInt {
                                value: iv,
                                byte_len,
                            },
                        })
                    }
                    BasicValueEnum::PointerValue(pv) => {
                        // Non-string pointer variable: print as address (hex)
                        let iv = self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "ptr_to_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(ComplexArg {
                            var_name_index,
                            type_index: self
                                .add_synthesized_type_index_for_kind(TypeKind::Pointer)?,
                            access_path: Vec::new(),
                            data_len: 8,
                            source: ComplexArgSource::ComputedInt {
                                value: iv,
                                byte_len: 8,
                            },
                        })
                    }
                    _ => Err(CodeGenError::TypeError(
                        "Unsupported script variable type for print".to_string(),
                    )),
                }
            }

            // 2) String literal -> Immediate bytes (for formatted args)
            E::String(s) => {
                let mut bytes = s.as_bytes().to_vec();
                bytes.push(0);
                let char_type = ghostscope_dwarf::TypeInfo::BaseType {
                    name: "char".to_string(),
                    size: 1,
                    encoding: ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16,
                };
                let array_type = ghostscope_dwarf::TypeInfo::ArrayType {
                    element_type: Box::new(char_type),
                    element_count: Some(bytes.len() as u64),
                    total_size: Some(bytes.len() as u64),
                };
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name("__str_literal".to_string())?,
                    type_index: self.trace_context.add_type(array_type)?,
                    access_path: Vec::new(),
                    data_len: bytes.len(),
                    source: ComplexArgSource::ImmediateBytes { bytes },
                })
            }

            // 3) Integer literal -> Immediate i64 bytes
            E::Int(v) => {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&(*v).to_le_bytes());
                let int_type = ghostscope_dwarf::TypeInfo::BaseType {
                    name: "i64".to_string(),
                    size: 8,
                    encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
                };
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name("__int_literal".to_string())?,
                    type_index: self.trace_context.add_type(int_type)?,
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::ImmediateBytes { bytes },
                })
            }

            // 3b) Explicit forced cast/reinterpret view.
            E::Cast { expr, target_type } => self.complex_arg_from_cast_expr(expr, target_type),

            // 4) AddressOf: return AddressValue (pointer payload will be produced)
            E::AddressOf(inner) => {
                if let Some(lvalue) = self.dynamic_lvalue_address_and_type(inner)? {
                    let ptr_ty = ghostscope_dwarf::TypeInfo::PointerType {
                        target_type: Box::new(lvalue.type_info.resolved_type.summary),
                        size: 8,
                    };
                    return Ok(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(expr))?,
                        type_index: self.trace_context.add_type(ptr_ty)?,
                        access_path: Vec::new(),
                        data_len: 8,
                        source: ComplexArgSource::ComputedAddress {
                            address: lvalue.address,
                        },
                    });
                }

                let var = self
                    .query_dwarf_for_complex_expr(inner)?
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{inner:?}")))?;
                let pc_address = self.get_compile_time_context()?.pc_address;
                let materialized = self.variable_read_plan_to_materialization(var, pc_address)?;
                let inner_ty = materialized.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
                })?;
                let ptr_ty = ghostscope_dwarf::TypeInfo::PointerType {
                    target_type: Box::new(inner_ty.clone()),
                    size: 8,
                };
                let address = match materialized.materialization {
                    ghostscope_dwarf::VariableMaterialization::UserMemoryRead { address } => {
                        address
                    }
                    ghostscope_dwarf::VariableMaterialization::Unavailable { availability } => {
                        return Err(Self::dwarf_expression_unavailable_error(
                            &materialized.name,
                            &availability,
                            pc_address,
                        ))
                    }
                    _ => {
                        return Err(CodeGenError::DwarfError(format!(
                            "cannot take address of value-backed DWARF expression '{}'",
                            materialized.name
                        )))
                    }
                };
                let module_hint =
                    Self::module_path_for_offsets(materialized.module_path.as_deref());
                Ok(ComplexArg {
                    var_name_index: self
                        .trace_context
                        .add_variable_name(self.expr_to_name(expr))?,
                    type_index: self.trace_context.add_type(ptr_ty)?,
                    access_path: Vec::new(),
                    data_len: 8,
                    source: ComplexArgSource::AddressValue {
                        address,
                        module_for_offsets: module_hint,
                    },
                })
            }

            // 5) Complex lvalue shapes -> DWARF runtime read
            expr @ (E::MemberAccess(_, _)
            | E::TupleAccess(_, _)
            | E::ArrayAccess(_, _)
            | E::PointerDeref(_)
            | E::ChainAccess(_)) => {
                if let Some(lvalue) = self.dynamic_lvalue_address_and_type(expr)? {
                    return self.complex_arg_from_dynamic_lvalue(expr, lvalue);
                }

                if let E::ArrayAccess(array_expr, index_expr) = expr {
                    if let Some((BasicValueEnum::IntValue(value), _element_type)) =
                        self.compile_dynamic_array_access_value(array_expr, index_expr)?
                    {
                        let bitw = value.get_type().get_bit_width();
                        let (kind, byte_len) = if bitw == 1 {
                            (TypeKind::Bool, 1)
                        } else if bitw <= 8 {
                            (TypeKind::I8, 1)
                        } else if bitw <= 16 {
                            (TypeKind::I16, 2)
                        } else if bitw <= 32 {
                            (TypeKind::I32, 4)
                        } else {
                            (TypeKind::I64, 8)
                        };
                        return Ok(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(self.expr_to_name(expr))?,
                            type_index: self.add_synthesized_type_index_for_kind(kind)?,
                            access_path: Vec::new(),
                            data_len: byte_len,
                            source: ComplexArgSource::ComputedInt { value, byte_len },
                        });
                    }
                }
                if let E::MemberAccess(obj_expr, field) = expr {
                    if let Some((BasicValueEnum::IntValue(value), _member_type)) =
                        self.compile_dynamic_member_access_value(obj_expr, field)?
                    {
                        let bitw = value.get_type().get_bit_width();
                        let (kind, byte_len) = if bitw == 1 {
                            (TypeKind::Bool, 1)
                        } else if bitw <= 8 {
                            (TypeKind::I8, 1)
                        } else if bitw <= 16 {
                            (TypeKind::I16, 2)
                        } else if bitw <= 32 {
                            (TypeKind::I32, 4)
                        } else {
                            (TypeKind::I64, 8)
                        };
                        return Ok(ComplexArg {
                            var_name_index: self
                                .trace_context
                                .add_variable_name(self.expr_to_name(expr))?,
                            type_index: self.add_synthesized_type_index_for_kind(kind)?,
                            access_path: Vec::new(),
                            data_len: byte_len,
                            source: ComplexArgSource::ComputedInt { value, byte_len },
                        });
                    }
                }

                let plan = self
                    .query_dwarf_for_complex_expr_plan(expr)?
                    .ok_or_else(|| CodeGenError::VariableNotFound(format!("{expr:?}")))?;
                let display_name = if matches!(expr, E::PointerDeref(_)) {
                    Some(self.expr_to_name(expr))
                } else {
                    None
                };
                self.complex_arg_from_dwarf_read_plan(plan, display_name)
            }

            // 6) Variable not in script scope → DWARF variable or computed fast-path for simple scalars
            E::Variable(name) => {
                if let Some(v) = self.query_dwarf_for_variable(name)? {
                    self.complex_arg_from_dwarf_read_plan(v, None)
                } else {
                    Err(CodeGenError::VariableNotInScope(name.clone()))
                }
            }

            // 7) Pointer arithmetic (ptr +/- K) → typed runtime read at computed address
            E::BinaryOp { .. } => {
                if let Some(lvalue) = self.dynamic_lvalue_address_and_type(expr)? {
                    return self.complex_arg_from_dynamic_lvalue(expr, lvalue);
                }

                // Support: ptr + int, int + ptr, ptr - int (int may be negative)
                // Only allow when ptr side resolves to DWARF pointer/array; the offset must be an integer literal for now.
                // We emit a RuntimeRead with computed location, preserving the pointed-to DWARF type.
                let pointer_arithmetic = self.pointer_arithmetic_parts_expanding_aliases(expr)?;

                // Try DWARF resolution for the pointer side
                if let Some((ptr_side, index)) = pointer_arithmetic {
                    if let Some(var) = self.query_dwarf_for_complex_expr(&ptr_side)? {
                        if var
                            .dwarf_type
                            .as_ref()
                            .is_some_and(ghostscope_dwarf::is_pointer_or_array_type)
                        {
                            let pointed_plan =
                                self.plan_dwarf_pointer_element_index(&var, index)?;
                            let pc_address = self.get_compile_time_context()?.pc_address;
                            let materialized = self
                                .variable_read_plan_to_materialization(pointed_plan, pc_address)?;
                            let elem_ty = materialized.dwarf_type.clone().ok_or_else(|| {
                                CodeGenError::DwarfError(
                                    "Expression has no DWARF type information".to_string(),
                                )
                            })?;
                            let address =
                                match materialized.materialization {
                                    ghostscope_dwarf::VariableMaterialization::UserMemoryRead {
                                        address,
                                    } => address,
                                    ghostscope_dwarf::VariableMaterialization::Unavailable {
                                        availability,
                                    } => {
                                        return Err(Self::dwarf_expression_unavailable_error(
                                            &materialized.name,
                                            &availability,
                                            pc_address,
                                        ))
                                    }
                                    _ => return Err(CodeGenError::DwarfError(
                                        "pointer arithmetic did not produce an address-backed plan"
                                            .to_string(),
                                    )),
                                };
                            let data_len = Self::compute_read_size_for_type(&elem_ty);
                            let module_hint =
                                Self::module_path_for_offsets(materialized.module_path.as_deref());
                            if data_len == 0 {
                                // Fallback for unsized/void targets: print computed address as pointer
                                let ptr_ti = ghostscope_dwarf::TypeInfo::PointerType {
                                    target_type: Box::new(elem_ty.clone()),
                                    size: 8,
                                };
                                return Ok(ComplexArg {
                                    var_name_index: self
                                        .trace_context
                                        .add_variable_name(self.expr_to_name(expr))?,
                                    type_index: self.trace_context.add_type(ptr_ti)?,
                                    access_path: Vec::new(),
                                    data_len: 8,
                                    source: ComplexArgSource::AddressValue {
                                        address,
                                        module_for_offsets: module_hint,
                                    },
                                });
                            }
                            return Ok(ComplexArg {
                                var_name_index: self
                                    .trace_context
                                    .add_variable_name(self.expr_to_name(expr))?,
                                type_index: self.trace_context.add_type(elem_ty.clone())?,
                                access_path: Vec::new(),
                                data_len,
                                source: ComplexArgSource::RuntimeRead {
                                    address,
                                    dwarf_type: elem_ty,
                                    module_for_offsets: module_hint,
                                },
                            });
                        }
                    }
                }

                // If pointer side cannot be resolved as DWARF pointer/array, fall back to computed int
                let compiled = self.compile_expr(expr)?;
                if let BasicValueEnum::IntValue(iv) = compiled {
                    let bitw = iv.get_type().get_bit_width();
                    let (kind, byte_len) = if bitw == 1 {
                        (TypeKind::Bool, 1)
                    } else if bitw <= 8 {
                        (TypeKind::I8, 1)
                    } else if bitw <= 16 {
                        (TypeKind::I16, 2)
                    } else if bitw <= 32 {
                        (TypeKind::I32, 4)
                    } else {
                        (TypeKind::I64, 8)
                    };
                    Ok(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(expr))?,
                        type_index: self.add_synthesized_type_index_for_kind(kind)?,
                        access_path: Vec::new(),
                        data_len: byte_len,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len,
                        },
                    })
                } else {
                    Err(CodeGenError::TypeError(
                        "Non-integer expression not supported in print".to_string(),
                    ))
                }
            }

            // Binary and other rvalue expressions → compile to computed int
            other => {
                let compiled = self.compile_expr(other)?;
                if let BasicValueEnum::IntValue(iv) = compiled {
                    let bitw = iv.get_type().get_bit_width();
                    let (kind, byte_len) = if bitw == 1 {
                        (TypeKind::Bool, 1)
                    } else if bitw <= 8 {
                        (TypeKind::I8, 1)
                    } else if bitw <= 16 {
                        (TypeKind::I16, 2)
                    } else if bitw <= 32 {
                        (TypeKind::I32, 4)
                    } else {
                        (TypeKind::I64, 8)
                    };
                    Ok(ComplexArg {
                        var_name_index: self
                            .trace_context
                            .add_variable_name(self.expr_to_name(other))?,
                        type_index: self.add_synthesized_type_index_for_kind(kind)?,
                        access_path: Vec::new(),
                        data_len: byte_len,
                        source: ComplexArgSource::ComputedInt {
                            value: iv,
                            byte_len,
                        },
                    })
                } else {
                    Err(CodeGenError::TypeError(
                        "Non-integer expression not supported in print".to_string(),
                    ))
                }
            }
        }
    }

    /// Emit a single PrintComplexVariable or a single-arg PrintComplexFormat depending on the arg source.
    pub(super) fn emit_print_from_arg(&mut self, arg: ComplexArg<'ctx>) -> Result<u16> {
        match arg.source {
            ComplexArgSource::ComputedInt { value, byte_len } => {
                self.generate_print_complex_variable_computed(
                    arg.var_name_index,
                    arg.type_index,
                    byte_len,
                    value,
                )?;
                Ok(1)
            }
            ComplexArgSource::RuntimeRead {
                address,
                ref dwarf_type,
                module_for_offsets,
            } => {
                let meta = PrintVarRuntimeMeta {
                    var_name_index: arg.var_name_index,
                    type_index: arg.type_index,
                    access_path: String::new(),
                    data_len_limit: arg.data_len,
                };
                self.generate_print_complex_variable_runtime(
                    meta,
                    &address,
                    dwarf_type,
                    module_for_offsets.as_deref(),
                )?;
                Ok(1)
            }
            ComplexArgSource::AddressValue { .. }
            | ComplexArgSource::ComputedAddress { .. }
            | ComplexArgSource::ImmediateBytes { .. } => {
                // Use ComplexFormat with "{}" to render address/immediate nicely
                let fmt_idx = self.trace_context.add_string("{}".to_string())?;
                self.generate_print_complex_format_instruction(fmt_idx, &[arg])?;
                Ok(1)
            }
            ComplexArgSource::MemDump { .. }
            | ComplexArgSource::MemDumpDynamic { .. }
            | ComplexArgSource::IndirectBytes { .. }
            | ComplexArgSource::IndirectSequence { .. }
            | ComplexArgSource::IndirectRingSequence { .. }
            | ComplexArgSource::ProjectedView { .. } => {
                // Use ComplexFormat with "{}"; generate_print_complex_format_instruction handles MemDump
                let fmt_idx = self.trace_context.add_string("{}".to_string())?;
                self.generate_print_complex_format_instruction(fmt_idx, &[arg])?;
                Ok(1)
            }
        }
    }
    /// Generate PrintComplexVariable instruction that embeds a computed integer value (no runtime read)
    pub(super) fn is_char_byte_typeinfo(t: &ghostscope_dwarf::TypeInfo) -> bool {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::BaseType { size, encoding, .. } => {
                *size == 1
                    && (*encoding == ghostscope_dwarf::constants::DW_ATE_unsigned_char.0 as u16
                        || *encoding == ghostscope_dwarf::constants::DW_ATE_signed_char.0 as u16
                        || *encoding == ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16
                        || *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16)
            }
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => Self::is_char_byte_typeinfo(underlying_type),
            _ => false,
        }
    }

    /// Compute read size for a given DWARF type.
    /// Keep strict behavior for general unsized arrays; only apply a bounded fallback for char[].
    pub(super) fn compute_read_size_for_type(t: &ghostscope_dwarf::TypeInfo) -> usize {
        use ghostscope_dwarf::TypeInfo as TI;
        match t {
            TI::ArrayType {
                element_type,
                element_count,
                total_size,
            } => {
                // Prefer DWARF-provided total size
                if let Some(ts) = total_size {
                    return *ts as usize;
                }
                // Fallback for arrays without total_size: need element_count * elem_size
                let elem_size = element_type.size() as usize;
                if elem_size == 0 {
                    return 0;
                }
                if let Some(cnt) = element_count {
                    return elem_size * (*cnt as usize);
                }
                // Some toolchains emit extern/definition pairs where char[] has no bound in DWARF.
                // Keep other unsized arrays strict to avoid silently over-reading unknown layouts.
                if Self::is_char_byte_typeinfo(element_type) {
                    return Self::UNKNOWN_CHAR_ARRAY_READ_FALLBACK;
                }
                0
            }
            TI::TypedefType {
                underlying_type, ..
            }
            | TI::QualifiedType {
                underlying_type, ..
            } => Self::compute_read_size_for_type(underlying_type),
            _ => t.size() as usize,
        }
    }

    pub(super) fn unwrap_alias_candidate_dwarf_type(
        mut t: &ghostscope_dwarf::TypeInfo,
    ) -> &ghostscope_dwarf::TypeInfo {
        while let ghostscope_dwarf::TypeInfo::TypedefType {
            underlying_type, ..
        }
        | ghostscope_dwarf::TypeInfo::QualifiedType {
            underlying_type, ..
        } = t
        {
            t = underlying_type.as_ref();
        }
        t
    }

    pub(super) fn is_aliasable_dwarf_type(t: &ghostscope_dwarf::TypeInfo) -> bool {
        matches!(
            Self::unwrap_alias_candidate_dwarf_type(t),
            ghostscope_dwarf::TypeInfo::PointerType { .. }
                | ghostscope_dwarf::TypeInfo::ArrayType { .. }
                | ghostscope_dwarf::TypeInfo::StructType { .. }
                | ghostscope_dwarf::TypeInfo::UnionType { .. }
        )
    }

    pub(super) fn expr_to_name(&self, expr: &crate::script::ast::Expr) -> String {
        use crate::script::ast::Expr as E;
        fn inner(e: &E) -> String {
            match e {
                E::Variable(s) => s.clone(),
                E::MemberAccess(obj, field) => format!("{}.{field}", inner(obj)),
                E::TupleAccess(obj, index) => format!("{}.{index}", inner(obj)),
                E::ArrayAccess(arr, idx) => format!("{}[{}]", inner(arr), inner(idx)),
                E::PointerDeref(p) => format!("*{}", inner(p)),
                E::AddressOf(p) => format!("&{}", inner(p)),
                E::Cast { expr, target_type } => {
                    format!("cast({}, \"{}\")", inner(expr), target_type)
                }
                E::ChainAccess(v) => v.join("."),
                E::Int(v) => v.to_string(),
                E::String(s) => format!("\"{s}\""),
                E::Float(v) => format!("{v}"),
                E::UnaryNot(e1) => format!("!{}", inner(e1)),
                E::UnaryBitNot(e1) => format!("~{}", inner(e1)),
                E::Bool(v) => v.to_string(),
                E::SpecialVar(s) => format!("${s}"),
                E::BuiltinCall { name, args } => {
                    let arg_strs: Vec<String> = args.iter().map(inner).collect();
                    format!("{}({})", name, arg_strs.join(", "))
                }
                E::BinaryOp { left, op, right } => {
                    let op_str = match op {
                        crate::script::ast::BinaryOp::Add => "+",
                        crate::script::ast::BinaryOp::Subtract => "-",
                        crate::script::ast::BinaryOp::Multiply => "*",
                        crate::script::ast::BinaryOp::Divide => "/",
                        crate::script::ast::BinaryOp::Modulo => "%",
                        crate::script::ast::BinaryOp::BitAnd => "&",
                        crate::script::ast::BinaryOp::BitXor => "^",
                        crate::script::ast::BinaryOp::BitOr => "|",
                        crate::script::ast::BinaryOp::ShiftLeft => "<<",
                        crate::script::ast::BinaryOp::ShiftRight => ">>",
                        crate::script::ast::BinaryOp::Equal => "==",
                        crate::script::ast::BinaryOp::NotEqual => "!=",
                        crate::script::ast::BinaryOp::LessThan => "<",
                        crate::script::ast::BinaryOp::LessEqual => "<=",
                        crate::script::ast::BinaryOp::GreaterThan => ">",
                        crate::script::ast::BinaryOp::GreaterEqual => ">=",
                        crate::script::ast::BinaryOp::LogicalAnd => "&&",
                        crate::script::ast::BinaryOp::LogicalOr => "||",
                    };
                    format!("({}{}{})", inner(left), op_str, inner(right))
                }
            }
        }
        let s_full = inner(expr);
        const MAX_NAME: usize = 96;
        if s_full.chars().count() > MAX_NAME {
            // Keep space for ellipsis
            let keep = MAX_NAME.saturating_sub(3);
            let mut acc = String::with_capacity(MAX_NAME);
            for (i, ch) in s_full.chars().enumerate() {
                if i >= keep {
                    break;
                }
                acc.push(ch);
            }
            acc.push_str("...");
            acc
        } else {
            s_full
        }
    }

    pub(super) fn expr_contains_builtin(expr: &crate::script::ast::Expr) -> bool {
        use crate::script::ast::Expr as E;

        match expr {
            E::BuiltinCall { .. } => true,
            E::UnaryNot(inner)
            | E::UnaryBitNot(inner)
            | E::PointerDeref(inner)
            | E::AddressOf(inner)
            | E::MemberAccess(inner, _)
            | E::TupleAccess(inner, _) => Self::expr_contains_builtin(inner),
            E::Cast { expr, .. } => Self::expr_contains_builtin(expr),
            E::ArrayAccess(base, index) => {
                Self::expr_contains_builtin(base) || Self::expr_contains_builtin(index)
            }
            E::BinaryOp { left, right, .. } => {
                Self::expr_contains_builtin(left) || Self::expr_contains_builtin(right)
            }
            E::Int(_)
            | E::Float(_)
            | E::String(_)
            | E::Bool(_)
            | E::Variable(_)
            | E::ChainAccess(_)
            | E::SpecialVar(_) => false,
        }
    }

    pub(super) fn compile_print_expr_with_builtin_exprerror<T, F>(
        &mut self,
        expr: &crate::script::ast::Expr,
        compile: F,
    ) -> Result<T>
    where
        F: FnOnce(&mut Self) -> Result<T>,
    {
        if !Self::expr_contains_builtin(expr) {
            return compile(self);
        }

        let prev_context_active = self.condition_context_active;
        if prev_context_active {
            return compile(self);
        }

        let expr_index = self.trace_context.add_string(self.expr_to_name(expr))?;
        let entry_event_bytes = self.compile_time_event_bytes_upper_bound;

        self.reset_condition_error()?;
        self.condition_context_active = true;
        let compiled = compile(self);
        self.condition_context_active = prev_context_active;
        let compiled = compiled?;

        let current_function = self
            .builder
            .get_insert_block()
            .ok_or_else(|| CodeGenError::LLVMError("No current basic block".to_string()))?
            .get_parent()
            .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;
        let err_block = self
            .context
            .append_basic_block(current_function, "print_expr_err_block");
        let ok_block = self
            .context
            .append_basic_block(current_function, "print_expr_ok_block");
        let merge_block = self
            .context
            .append_basic_block(current_function, "print_expr_merge_block");
        let cond_err_pred = self.build_condition_error_predicate()?;
        self.builder
            .build_conditional_branch(cond_err_pred, err_block, ok_block)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch on print expr error: {e}"))
            })?;

        self.builder.position_at_end(err_block);
        self.compile_time_event_bytes_upper_bound = entry_event_bytes;
        self.emit_current_condition_exprerror(expr_index, "print_expr")?;
        let err_path_event_bytes = self.compile_time_event_bytes_upper_bound;
        self.builder
            .build_unconditional_branch(merge_block)
            .map_err(|e| {
                CodeGenError::LLVMError(format!(
                    "Failed to branch from print expr error block: {e}"
                ))
            })?;

        self.builder.position_at_end(ok_block);
        self.compile_time_event_bytes_upper_bound = entry_event_bytes;
        self.builder
            .build_unconditional_branch(merge_block)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch from print expr ok block: {e}"))
            })?;

        self.builder.position_at_end(merge_block);
        self.compile_time_event_bytes_upper_bound = entry_event_bytes.max(err_path_event_bytes);
        Ok(compiled)
    }

    pub(super) fn emit_current_condition_exprerror(
        &mut self,
        expr_index: u16,
        name_prefix: &str,
    ) -> Result<()> {
        let cond_err_ptr = self.get_or_create_cond_error_global();
        let err_code = self
            .builder
            .build_load(
                self.context.i8_type(),
                cond_err_ptr,
                &format!("{name_prefix}_err_code"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let cond_err_addr_ptr = self.get_or_create_cond_error_addr_global();
        let err_addr = self
            .builder
            .build_load(
                self.context.i64_type(),
                cond_err_addr_ptr,
                &format!("{name_prefix}_err_addr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let cond_err_flags_ptr = self.get_or_create_cond_error_flags_global();
        let err_flags = self
            .builder
            .build_load(
                self.context.i8_type(),
                cond_err_flags_ptr,
                &format!("{name_prefix}_err_flags"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.generate_expr_error(expr_index, err_code, err_flags, err_addr)
    }

    /// Heuristic to decide if an expression should be bound as a DWARF alias variable.
    /// Prefer shapes that resolve to a runtime address via DWARF or address-of:
    /// - AddressOf(...)
    /// - Member/Array/PointerDeref/Chain access
    /// - Variable that is a DWARF-backed symbol (not a script var)
    /// - Offset arithmetic on top of an aliasy expression: alias +/- integer expression
    pub(super) fn is_alias_candidate_expr(&mut self, expr: &crate::script::ast::Expr) -> bool {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;
        match expr {
            // Alias variable names are alias candidates
            E::Variable(name) if self.alias_variable_exists(name) => true,
            // Explicit address-of is always an alias
            E::AddressOf(_) => true,
            E::Cast { target_type, .. } => self
                .resolve_cast_target_type(target_type)
                .ok()
                .is_some_and(|ty| {
                    matches!(
                        ghostscope_dwarf::strip_type_aliases(&ty),
                        ghostscope_dwarf::TypeInfo::PointerType { .. }
                            | ghostscope_dwarf::TypeInfo::ArrayType { .. }
                            | ghostscope_dwarf::TypeInfo::StructType { .. }
                            | ghostscope_dwarf::TypeInfo::UnionType { .. }
                    )
                }),
            // Constant offset on top of an alias-eligible expression
            E::BinaryOp {
                left,
                op: BO::Add,
                right,
            } => {
                let left_is_alias = self.is_alias_candidate_expr(left);
                let right_is_alias = self.is_alias_candidate_expr(right);
                (left_is_alias && !right_is_alias) || (right_is_alias && !left_is_alias)
            }
            E::BinaryOp {
                left,
                op: BO::Subtract,
                right,
            } => self.is_alias_candidate_expr(left) && !self.is_alias_candidate_expr(right),
            // Otherwise, only keep address-like or aggregate DWARF expressions as aliases.
            // Scalar DWARF expressions should stay concrete so `let n = foo.len;` behaves
            // like an integer script variable and remains usable in capture-length formatting.
            other => self
                .query_dwarf_for_complex_expr(other)
                .ok()
                .flatten()
                .and_then(|var| var.dwarf_type)
                .is_some_and(|ty| Self::is_aliasable_dwarf_type(&ty)),
        }
    }

    // removed old helpers (pure lvalue/binary_op detection) — unified resolver handles shapes
}

#[cfg(test)]
mod semantic_value_tests {
    use super::*;
    use ghostscope_dwarf::{
        MemoryAccessSize, ProjectedValueRead, ProjectedValueStep, ProjectedViewField, ResolvedType,
        StructMember, TypeIdentity, TypeInfo, TypeProjection, TypeProjectionLayout,
    };

    fn projection(size: u64) -> TypeProjection {
        let encoding = ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16;
        TypeProjection {
            layout: TypeProjectionLayout::Member { offset: 0 },
            resolved_type: ResolvedType::new(
                TypeInfo::BaseType {
                    name: "metadata".to_string(),
                    size,
                    encoding,
                },
                TypeIdentity::Unknown,
                None,
            ),
        }
    }

    #[test]
    fn maps_indirect_metadata_size_from_projected_dwarf_type() {
        assert_eq!(
            metadata_access_size(&projection(4), "data").unwrap(),
            MemoryAccessSize::U32
        );
        assert_eq!(
            metadata_access_size(&projection(8), "length").unwrap(),
            MemoryAccessSize::U64
        );
    }

    #[test]
    fn rejects_unsupported_indirect_metadata_size() {
        let projected = projection(3);
        let error = metadata_access_size(&projected, "data").unwrap_err();

        assert!(error.to_string().contains("unsupported DWARF size 3"));
    }

    #[test]
    fn reads_projected_value_offset_without_assuming_field_names() {
        let mut projected = projection(4);
        projected.layout = TypeProjectionLayout::Member { offset: 12 };

        assert_eq!(
            projected_member_offset(&projected, "projected value").unwrap(),
            12
        );

        projected.layout = TypeProjectionLayout::Dereference;
        let error = projected_member_offset(&projected, "projected value").unwrap_err();
        assert!(error.to_string().contains("must be a member"));
    }

    #[test]
    fn distinguishes_known_zero_sized_types_from_unknown_layouts() {
        let unit = TypeInfo::BaseType {
            name: "()".to_string(),
            size: 0,
            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
        };
        let unknown = TypeInfo::UnknownType {
            name: "T".to_string(),
        };

        assert!(is_known_zero_sized_type(&unit));
        assert!(!is_known_zero_sized_type(&unknown));
    }

    #[test]
    fn inline_view_requires_the_exact_dwarf_root_size() {
        let physical = TypeInfo::StructType {
            name: "Physical".to_string(),
            size: 16,
            members: Vec::new(),
        };
        let view = TypeInfo::StructType {
            name: "Semantic".to_string(),
            size: 16,
            members: Vec::new(),
        };
        assert_eq!(inline_view_data_len(&physical, &view).unwrap(), 16);

        let undersized = TypeInfo::StructType {
            name: "Semantic".to_string(),
            size: 8,
            members: Vec::new(),
        };
        let error = inline_view_data_len(&physical, &undersized).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match DWARF root size 16"));
    }

    fn projected_field(
        output_offset: u64,
        summary: TypeInfo,
        steps: Vec<ProjectedValueStep>,
    ) -> ProjectedViewField {
        ProjectedViewField {
            output_offset,
            value: ProjectedValueRead {
                steps,
                resolved_type: ResolvedType::new(summary, TypeIdentity::Unknown, None),
            },
        }
    }

    fn output_member(name: &str, member_type: TypeInfo, offset: u64) -> StructMember {
        StructMember {
            name: name.to_string(),
            member_type,
            offset,
            bit_offset: None,
            bit_size: None,
        }
    }

    #[test]
    fn projected_view_uses_exact_output_and_pointer_layouts() {
        let value_type = TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let borrow_type = TypeInfo::BaseType {
            name: "isize".to_string(),
            size: 8,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let output_type = TypeInfo::StructType {
            name: "Ref".to_string(),
            size: 12,
            members: vec![
                output_member("*value", value_type.clone(), 0),
                output_member("borrow", borrow_type.clone(), 4),
            ],
        };
        let fields = vec![
            projected_field(
                0,
                value_type,
                vec![
                    ProjectedValueStep::Member { offset: 8 },
                    ProjectedValueStep::Dereference { pointer_size: 8 },
                ],
            ),
            projected_field(
                4,
                borrow_type,
                vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
            ),
        ];

        let (data_len, sources) = projected_view_source(&output_type, &fields).unwrap();
        assert_eq!(data_len, 12);
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].output_offset, 0);
        assert_eq!(sources[0].value_len, 4);
        assert!(matches!(
            sources[0].steps.as_slice(),
            [
                ProjectedViewStep::Member { offset: 8 },
                ProjectedViewStep::Dereference {
                    pointer_size: MemoryAccessSize::U64
                }
            ]
        ));
    }

    #[test]
    fn projected_view_accepts_packed_zero_sized_fields() {
        let unit = TypeInfo::BaseType {
            name: "()".to_string(),
            size: 0,
            encoding: ghostscope_dwarf::constants::DW_ATE_unsigned.0 as u16,
        };
        let borrow = TypeInfo::BaseType {
            name: "isize".to_string(),
            size: 8,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let output_type = TypeInfo::StructType {
            name: "Ref".to_string(),
            size: 8,
            members: vec![
                output_member("*value", unit.clone(), 0),
                output_member("borrow", borrow.clone(), 0),
            ],
        };
        let fields = vec![
            projected_field(
                0,
                unit,
                vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
            ),
            projected_field(
                0,
                borrow,
                vec![ProjectedValueStep::Dereference { pointer_size: 8 }],
            ),
        ];

        let (data_len, sources) = projected_view_source(&output_type, &fields).unwrap();
        assert_eq!(data_len, 8);
        assert_eq!(sources[0].value_len, 0);
        assert_eq!(sources[1].output_offset, 0);
    }

    #[test]
    fn projected_view_rejects_invalid_protocol_and_field_layouts() {
        let oversized = TypeInfo::StructType {
            name: "Oversized".to_string(),
            size: u16::MAX as u64 + 1,
            members: Vec::new(),
        };
        let error = projected_view_source(&oversized, &[]).unwrap_err();
        assert!(error.to_string().contains("exceeds the protocol limit"));

        let value_type = TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let overlapping = TypeInfo::StructType {
            name: "Overlap".to_string(),
            size: 6,
            members: vec![
                output_member("left", value_type.clone(), 0),
                output_member("right", value_type.clone(), 2),
            ],
        };
        let fields = vec![
            projected_field(0, value_type.clone(), Vec::new()),
            projected_field(2, value_type.clone(), Vec::new()),
        ];
        let error = projected_view_source(&overlapping, &fields).unwrap_err();
        assert!(error.to_string().contains("overlaps another output member"));

        let output = TypeInfo::StructType {
            name: "Pointer".to_string(),
            size: 4,
            members: vec![output_member("value", value_type.clone(), 0)],
        };
        let fields = vec![projected_field(
            0,
            value_type,
            vec![ProjectedValueStep::Dereference { pointer_size: 3 }],
        )];
        let error = projected_view_source(&output, &fields).unwrap_err();
        assert!(error.to_string().contains("unsupported DWARF size 3"));
    }
}

use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn emit_complex_format_nested_value(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        value: &NestedValueSource,
        reserved_len: usize,
    ) -> Result<()> {
        if reserved_len < value.total_len {
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_fail()?;
            return Ok(());
        }
        self.emit_nested_value_root(status_ptr, var_data_ptr, descriptor, value)?;
        self.emit_nested_value_children(status_ptr, var_data_ptr, descriptor, value)
    }

    fn emit_nested_value_root(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        value: &NestedValueSource,
    ) -> Result<()> {
        match &value.root {
            NestedValueRootSource::ProjectedValue { offset, len } => {
                if *len == 0 {
                    return Ok(());
                }
                let address = if *offset == 0 {
                    *descriptor
                } else {
                    let address = self
                        .builder
                        .build_int_add(
                            descriptor.value,
                            self.context.i64_type().const_int(*offset, false),
                            "nested_projected_value_address",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    descriptor.with_value(address)
                };
                self.emit_complex_format_memdump(
                    status_ptr,
                    payload_ptr,
                    &address,
                    *len,
                    value.root_payload_len,
                )
            }
            NestedValueRootSource::InlineView { len } => {
                if *len == 0 {
                    Ok(())
                } else {
                    self.emit_complex_format_memdump(
                        status_ptr,
                        payload_ptr,
                        descriptor,
                        *len,
                        value.root_payload_len,
                    )
                }
            }
            NestedValueRootSource::ProjectedView { fields } => self
                .emit_complex_format_projected_view(
                    status_ptr,
                    payload_ptr,
                    descriptor,
                    fields,
                    value.root_payload_len,
                ),
            NestedValueRootSource::IndirectBytes {
                data_offset,
                data_access_size,
                length_offset,
                length_access_size,
                excluded_tail_bytes,
                max_len,
            } => self.emit_complex_format_indirect(
                status_ptr,
                payload_ptr,
                descriptor,
                value.root_payload_len,
                IndirectCaptureConfig {
                    data_offset: *data_offset,
                    data_access_size: *data_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    excluded_tail_bytes: *excluded_tail_bytes,
                    max_len: *max_len,
                    shape: IndirectCaptureShape::Bytes,
                },
            ),
            NestedValueRootSource::IndirectSequence {
                data_offset,
                data_access_size,
                length_offset,
                length_access_size,
                element_stride,
                max_elements,
                max_len,
            } => self.emit_complex_format_indirect(
                status_ptr,
                payload_ptr,
                descriptor,
                value.root_payload_len,
                IndirectCaptureConfig {
                    data_offset: *data_offset,
                    data_access_size: *data_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    excluded_tail_bytes: 0,
                    max_len: *max_len,
                    shape: IndirectCaptureShape::Sequence {
                        element_stride: *element_stride,
                        max_elements: *max_elements,
                        ring: None,
                    },
                },
            ),
            NestedValueRootSource::IndirectRingSequence {
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
            } => {
                let (length_offset, length_access_size, length_kind) = match length {
                    RingSequenceLengthSource::Explicit {
                        offset,
                        access_size,
                    } => (*offset, *access_size, RingCaptureLengthKind::Explicit),
                    RingSequenceLengthSource::End {
                        offset,
                        access_size,
                    } => (*offset, *access_size, RingCaptureLengthKind::End),
                };
                self.emit_complex_format_indirect(
                    status_ptr,
                    payload_ptr,
                    descriptor,
                    value.root_payload_len,
                    IndirectCaptureConfig {
                        data_offset: *data_offset,
                        data_access_size: *data_access_size,
                        length_offset,
                        length_access_size,
                        excluded_tail_bytes: 0,
                        max_len: *max_len,
                        shape: IndirectCaptureShape::Sequence {
                            element_stride: *element_stride,
                            max_elements: *max_elements,
                            ring: Some(RingCaptureConfig {
                                start_offset: *start_offset,
                                start_access_size: *start_access_size,
                                capacity_offset: *capacity_offset,
                                capacity_access_size: *capacity_access_size,
                                length_kind,
                            }),
                        },
                    },
                )
            }
            NestedValueRootSource::IndirectHashTable {
                control_offset,
                control_access_size,
                length_offset,
                length_access_size,
                bucket_mask_offset,
                bucket_mask_access_size,
                entry_stride,
                occupancy,
                buckets,
                bucket_order,
                max_buckets,
            } => self.emit_complex_format_hash_table(
                status_ptr,
                payload_ptr,
                descriptor,
                value.root_payload_len,
                HashTableCaptureConfig {
                    control_offset: *control_offset,
                    control_access_size: *control_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    bucket_mask_offset: *bucket_mask_offset,
                    bucket_mask_access_size: *bucket_mask_access_size,
                    entry_stride: *entry_stride,
                    occupancy: *occupancy,
                    buckets: *buckets,
                    bucket_order: *bucket_order,
                    max_buckets: *max_buckets,
                },
            ),
            NestedValueRootSource::IndirectBTree {
                root_pointer_offset,
                root_pointer_access_size,
                root_height_offset,
                root_height_access_size,
                length_offset,
                length_access_size,
                node_length_offset,
                node_length_access_size,
                keys,
                values,
                edges,
                node_capacity,
                max_nodes,
            } => self.emit_complex_format_btree(
                status_ptr,
                payload_ptr,
                descriptor,
                value.root_payload_len,
                BTreeCaptureConfig {
                    root_pointer_offset: *root_pointer_offset,
                    root_pointer_access_size: *root_pointer_access_size,
                    root_height_offset: *root_height_offset,
                    root_height_access_size: *root_height_access_size,
                    length_offset: *length_offset,
                    length_access_size: *length_access_size,
                    node_length_offset: *node_length_offset,
                    node_length_access_size: *node_length_access_size,
                    keys: *keys,
                    values: *values,
                    edges: *edges,
                    node_capacity: *node_capacity,
                    max_nodes: *max_nodes,
                },
            ),
        }
    }

    fn emit_nested_value_children(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        value: &NestedValueSource,
    ) -> Result<()> {
        if matches!(value.children, NestedValueChildrenSource::None) {
            return Ok(());
        }

        let function = self.current_function("compile nested semantic children")?;
        let children_block = self
            .context
            .append_basic_block(function, "nested_children_ready");
        let finish_block = self
            .context
            .append_basic_block(function, "nested_children_finish");
        let status = self
            .builder
            .build_load(self.context.i8_type(), status_ptr, "nested_root_status")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                status,
                self.context.i8_type().const_zero(),
                "nested_root_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let can_capture = if matches!(
            value.children,
            NestedValueChildrenSource::Sequence { .. }
                | NestedValueChildrenSource::HashTable { .. }
        ) {
            let truncated = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    status,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                    "nested_root_truncated",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_or(ok, truncated, "nested_root_has_elements")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        } else {
            ok
        };
        self.builder
            .build_conditional_branch(can_capture, children_block, finish_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(children_block);
        match &value.children {
            NestedValueChildrenSource::None => unreachable!("handled before branching"),
            NestedValueChildrenSource::ProjectedValue { slot_offset, child } => {
                let NestedValueRootSource::ProjectedValue { offset, .. } = value.root else {
                    return Err(CodeGenError::DwarfError(
                        "nested projected child does not match its root capture".to_string(),
                    ));
                };
                let child_descriptor = if offset == 0 {
                    *descriptor
                } else {
                    let address = self
                        .builder
                        .build_int_add(
                            descriptor.value,
                            self.context.i64_type().const_int(offset, false),
                            "nested_projected_child_address",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    descriptor.with_value(address)
                };
                self.emit_nested_child_slot(payload_ptr, *slot_offset, &child_descriptor, child)?;
            }
            NestedValueChildrenSource::ProjectedView { fields } => {
                for (index, field) in fields.iter().enumerate() {
                    self.emit_nested_projected_field(payload_ptr, descriptor, field, index)?;
                }
            }
            NestedValueChildrenSource::Variant { fields } => {
                // Branches can share slots. Initialize every distinct header
                // before any active branch writes over the shared region.
                let mut initialized_slots = Vec::new();
                for field in fields {
                    if initialized_slots.contains(&field.field.slot_offset) {
                        continue;
                    }
                    self.initialize_nested_child_header(
                        payload_ptr,
                        field.field.slot_offset,
                        VariableStatus::AccessError,
                    )?;
                    initialized_slots.push(field.field.slot_offset);
                }
                for (index, field) in fields.iter().enumerate() {
                    self.emit_nested_variant_field(payload_ptr, descriptor, field, index)?;
                }
            }
            NestedValueChildrenSource::Sequence {
                first_slot_offset,
                slot_stride,
                slot_count,
                element,
                metadata,
            } => self.emit_nested_sequence_children(
                status_ptr,
                payload_ptr,
                descriptor,
                *first_slot_offset,
                *slot_stride,
                *slot_count,
                element,
                metadata,
                finish_block,
            )?,
            NestedValueChildrenSource::HashTable {
                first_slot_offset,
                bucket_slot_stride,
                bucket_count,
                fields,
                metadata,
            } => self.emit_nested_hash_table_children(
                payload_ptr,
                descriptor,
                *first_slot_offset,
                *bucket_slot_stride,
                *bucket_count,
                fields,
                metadata,
                finish_block,
            )?,
        }
        if self
            .builder
            .get_insert_block()
            .is_some_and(|block| block.get_terminator().is_none())
        {
            self.builder
                .build_unconditional_branch(finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        self.builder.position_at_end(finish_block);
        Ok(())
    }

    pub(super) fn emit_nested_child_slot(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        slot_offset: usize,
        descriptor: &RuntimeAddress<'ctx>,
        child: &NestedValueSource,
    ) -> Result<()> {
        let (status_ptr, payload_ptr) =
            self.initialize_nested_child_header(parent_payload, slot_offset, VariableStatus::Ok)?;
        self.emit_nested_value_root(status_ptr, payload_ptr, descriptor, child)?;
        self.emit_nested_value_children(status_ptr, payload_ptr, descriptor, child)
    }

    fn initialize_nested_child_header(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        slot_offset: usize,
        status: VariableStatus,
    ) -> Result<(PointerValue<'ctx>, PointerValue<'ctx>)> {
        let (status_ptr, payload_ptr) = self.nested_child_pointers(parent_payload, slot_offset)?;
        self.emit_complex_format_immediate_bytes(
            status_ptr,
            &[0; ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE],
        )?;
        self.builder
            .build_store(
                status_ptr,
                self.context.i8_type().const_int(status as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        Ok((status_ptr, payload_ptr))
    }

    fn nested_child_pointers(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        slot_offset: usize,
    ) -> Result<(PointerValue<'ctx>, PointerValue<'ctx>)> {
        let i32_type = self.context.i32_type();
        // SAFETY: every nested slot offset is computed from the statically
        // reserved parent payload.
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    parent_payload,
                    &[i32_type.const_int(slot_offset as u64, false)],
                    "nested_child_status",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        // SAFETY: the fixed child header is part of every reserved slot.
        let payload_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    status_ptr,
                    &[i32_type.const_int(
                        ghostscope_protocol::NESTED_VALUE_CHILD_HEADER_SIZE as u64,
                        false,
                    )],
                    "nested_child_payload",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        Ok((status_ptr, payload_ptr))
    }

    fn emit_nested_projected_field(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        field: &NestedValueFieldSource,
        field_index: usize,
    ) -> Result<()> {
        let (status_ptr, payload_ptr) = self.initialize_nested_child_header(
            parent_payload,
            field.slot_offset,
            VariableStatus::Ok,
        )?;
        let function = self.current_function("compile nested projected field")?;
        let finish_block = self.context.append_basic_block(
            function,
            &format!("nested_projected_field_{field_index}_finish"),
        );
        let address = self.resolve_nested_projected_address(
            *descriptor,
            &field.steps,
            status_ptr,
            payload_ptr,
            field.child.total_len,
            finish_block,
            field_index,
        )?;
        self.emit_nested_value_root(status_ptr, payload_ptr, &address, &field.child)?;
        self.emit_nested_value_children(status_ptr, payload_ptr, &address, &field.child)?;
        if self
            .builder
            .get_insert_block()
            .is_some_and(|block| block.get_terminator().is_none())
        {
            self.builder
                .build_unconditional_branch(finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        self.builder.position_at_end(finish_block);
        Ok(())
    }

    fn emit_nested_variant_field(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        variant_field: &NestedValueVariantFieldSource,
        field_index: usize,
    ) -> Result<()> {
        let active =
            self.emit_nested_variant_condition(descriptor, &variant_field.condition, field_index)?;
        let function = self.current_function("compile nested variant field")?;
        let active_block = self
            .context
            .append_basic_block(function, &format!("nested_variant_{field_index}_active"));
        let finish_block = self
            .context
            .append_basic_block(function, &format!("nested_variant_{field_index}_finish"));
        self.builder
            .build_conditional_branch(active, active_block, finish_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(active_block);
        self.emit_nested_projected_field(
            parent_payload,
            descriptor,
            &variant_field.field,
            field_index,
        )?;
        if self
            .builder
            .get_insert_block()
            .is_some_and(|block| block.get_terminator().is_none())
        {
            self.builder
                .build_unconditional_branch(finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        self.builder.position_at_end(finish_block);
        Ok(())
    }

    fn emit_nested_variant_condition(
        &mut self,
        descriptor: &RuntimeAddress<'ctx>,
        condition: &NestedValueVariantConditionSource,
        field_index: usize,
    ) -> Result<IntValue<'ctx>> {
        let NestedValueVariantConditionSource::Discriminant {
            offset,
            access_size,
            signed,
            ranges,
            inverted,
        } = condition
        else {
            return Ok(self.context.bool_type().const_int(1, false));
        };

        let address = if *offset == 0 {
            *descriptor
        } else {
            let value = self
                .builder
                .build_int_add(
                    descriptor.value,
                    self.context.i64_type().const_int(*offset, false),
                    &format!("nested_variant_{field_index}_discriminant_address"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            descriptor.with_value(value)
        };
        let (value, failed) = self.generate_memory_read_with_fail_flag(
            address,
            *access_size,
            &format!("nested_variant_{field_index}_discriminant"),
        )?;
        let mut value = value.into_int_value();
        if *signed && access_size.bytes() < std::mem::size_of::<u64>() {
            let shift = u64::try_from(
                (std::mem::size_of::<u64>() - access_size.bytes())
                    .checked_mul(8)
                    .expect("discriminant width is bounded by u64"),
            )
            .expect("discriminant shift fits u64");
            let shift = self.context.i64_type().const_int(shift, false);
            value = self
                .builder
                .build_left_shift(
                    value,
                    shift,
                    &format!("nested_variant_{field_index}_sign_shift_left"),
                )
                .and_then(|value| {
                    self.builder.build_right_shift(
                        value,
                        shift,
                        true,
                        &format!("nested_variant_{field_index}_sign_extend"),
                    )
                })
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        let mut matched = self.context.bool_type().const_zero();
        for (range_index, range) in ranges.iter().enumerate() {
            let (start, end, lower_predicate, upper_predicate) = match (range.start, range.end) {
                (
                    ghostscope_dwarf::DiscriminantValue::Signed(start),
                    ghostscope_dwarf::DiscriminantValue::Signed(end),
                ) if *signed => (
                    start as u64,
                    end as u64,
                    inkwell::IntPredicate::SGE,
                    inkwell::IntPredicate::SLE,
                ),
                (
                    ghostscope_dwarf::DiscriminantValue::Unsigned(start),
                    ghostscope_dwarf::DiscriminantValue::Unsigned(end),
                ) if !*signed => (
                    start,
                    end,
                    inkwell::IntPredicate::UGE,
                    inkwell::IntPredicate::ULE,
                ),
                _ => {
                    return Err(CodeGenError::DwarfError(
                        "nested variant discriminant range has inconsistent signedness".to_string(),
                    ));
                }
            };
            let lower = self
                .builder
                .build_int_compare(
                    lower_predicate,
                    value,
                    self.context.i64_type().const_int(start, false),
                    &format!("nested_variant_{field_index}_{range_index}_lower"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let upper = self
                .builder
                .build_int_compare(
                    upper_predicate,
                    value,
                    self.context.i64_type().const_int(end, false),
                    &format!("nested_variant_{field_index}_{range_index}_upper"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let in_range = self
                .builder
                .build_and(
                    lower,
                    upper,
                    &format!("nested_variant_{field_index}_{range_index}_in_range"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            matched = self
                .builder
                .build_or(
                    matched,
                    in_range,
                    &format!("nested_variant_{field_index}_{range_index}_matched"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        if *inverted {
            matched = self
                .builder
                .build_not(
                    matched,
                    &format!("nested_variant_{field_index}_default_branch"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        let read_ok = self
            .builder
            .build_not(
                failed,
                &format!("nested_variant_{field_index}_discriminant_read_ok"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder
            .build_and(
                matched,
                read_ok,
                &format!("nested_variant_{field_index}_active"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_nested_projected_address(
        &mut self,
        mut address: RuntimeAddress<'ctx>,
        steps: &[ProjectedViewStep],
        status_ptr: PointerValue<'ctx>,
        payload_ptr: PointerValue<'ctx>,
        reserved_len: usize,
        finish_block: inkwell::basic_block::BasicBlock<'ctx>,
        field_index: usize,
    ) -> Result<RuntimeAddress<'ctx>> {
        let function = self.current_function("resolve nested projected address")?;
        for (step_index, step) in steps.iter().enumerate() {
            match step {
                ProjectedViewStep::Member { offset } => {
                    if *offset != 0 {
                        let value = self
                            .builder
                            .build_int_add(
                                address.value,
                                self.context.i64_type().const_int(*offset, false),
                                &format!("nested_projected_{field_index}_{step_index}_member"),
                            )
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                        address = address.with_value(value);
                    }
                }
                ProjectedViewStep::Dereference { pointer_size } => {
                    let read = self.generate_memory_read_with_diagnostics(
                        address,
                        *pointer_size,
                        Some(status_ptr),
                        &format!("nested_projected_{field_index}_{step_index}_pointer"),
                    )?;
                    let ok = self
                        .builder
                        .build_not(
                            read.combined_fail,
                            &format!("nested_projected_{field_index}_{step_index}_ok"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let ok_block = self.context.append_basic_block(
                        function,
                        &format!("nested_projected_{field_index}_{step_index}_pointer_ok"),
                    );
                    let error_block = self.context.append_basic_block(
                        function,
                        &format!("nested_projected_{field_index}_{step_index}_pointer_error"),
                    );
                    self.builder
                        .build_conditional_branch(ok, ok_block, error_block)
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder.position_at_end(error_block);
                    self.emit_complex_format_read_error_payload(
                        payload_ptr,
                        reserved_len,
                        read.helper_result,
                        address.value,
                    )?;
                    self.builder
                        .build_unconditional_branch(finish_block)
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder.position_at_end(ok_block);
                    address = RuntimeAddress::available(read.value.into_int_value(), self.context);
                }
            }
        }
        Ok(address)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_nested_sequence_children(
        &mut self,
        _status_ptr: PointerValue<'ctx>,
        parent_payload: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        first_slot_offset: usize,
        slot_stride: usize,
        slot_count: usize,
        element: &NestedValueSource,
        metadata: &NestedSequenceMetadataSource,
        finish_block: inkwell::basic_block::BasicBlock<'ctx>,
    ) -> Result<()> {
        let function = self.current_function("compile nested sequence children")?;
        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        for index in 0..slot_count {
            let slot_offset = first_slot_offset
                .checked_add(index.checked_mul(slot_stride).ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested sequence child slot offset overflow".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested sequence child slot offset overflow".to_string(),
                    )
                })?;
            self.initialize_nested_child_header(
                parent_payload,
                slot_offset,
                VariableStatus::AccessError,
            )?;
        }
        let data_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(metadata.data_offset, false),
                "nested_sequence_data_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let data_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(data_member),
            metadata.data_access_size,
            None,
            "nested_sequence_data",
        )?;
        let mut metadata_failed = data_read.combined_fail;
        let ring_reads = if let Some(ring) = metadata.ring {
            let start_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.start_offset, false),
                    "nested_sequence_start_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let start_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(start_member),
                ring.start_access_size,
                None,
                "nested_sequence_start",
            )?;
            metadata_failed = self
                .builder
                .build_or(
                    metadata_failed,
                    start_read.combined_fail,
                    "nested_sequence_start_failed",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let capacity_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.capacity_offset, false),
                    "nested_sequence_capacity_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let capacity_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(capacity_member),
                ring.capacity_access_size,
                None,
                "nested_sequence_capacity",
            )?;
            metadata_failed = self
                .builder
                .build_or(
                    metadata_failed,
                    capacity_read.combined_fail,
                    "nested_sequence_capacity_failed",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            Some((
                start_read.value.into_int_value(),
                capacity_read.value.into_int_value(),
            ))
        } else {
            None
        };

        let metadata_ok_block = self
            .context
            .append_basic_block(function, "nested_sequence_metadata_ok");
        self.builder
            .build_conditional_branch(metadata_failed, finish_block, metadata_ok_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(metadata_ok_block);

        // SAFETY: the root sequence payload always reserves its two-u64 header.
        let captured_count_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    parent_payload,
                    &[i32_type.const_int(
                        ghostscope_protocol::INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET as u64,
                        false,
                    )],
                    "nested_sequence_captured_count_i8",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let captured_count_ptr = self
            .builder
            .build_pointer_cast(
                captured_count_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "nested_sequence_captured_count",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_count = self
            .builder
            .build_load(i64_type, captured_count_ptr, "nested_sequence_captured")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let data_address = data_read.value.into_int_value();
        let stride = i64_type.const_int(metadata.element_stride, false);

        for index in 0..slot_count {
            let slot_offset = first_slot_offset
                .checked_add(index.checked_mul(slot_stride).ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested sequence child slot offset overflow".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested sequence child slot offset overflow".to_string(),
                    )
                })?;
            let active = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    i64_type.const_int(index as u64, false),
                    captured_count,
                    &format!("nested_sequence_{index}_active"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let active_block = self
                .context
                .append_basic_block(function, &format!("nested_sequence_{index}_capture"));
            let continue_block = self
                .context
                .append_basic_block(function, &format!("nested_sequence_{index}_continue"));
            self.builder
                .build_conditional_branch(active, active_block, continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(active_block);

            let logical_index = i64_type.const_int(index as u64, false);
            let physical_index = if let Some((start, capacity)) = ring_reads {
                let unwrapped = self
                    .builder
                    .build_int_add(start, logical_index, "nested_sequence_unwrapped_index")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wrapped = self
                    .builder
                    .build_int_sub(unwrapped, capacity, "nested_sequence_wrapped_index")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wraps = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGE,
                        unwrapped,
                        capacity,
                        "nested_sequence_index_wraps",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_select(wraps, wrapped, unwrapped, "nested_sequence_physical_index")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value()
            } else {
                logical_index
            };
            let byte_offset = self
                .builder
                .build_int_mul(physical_index, stride, "nested_sequence_element_offset")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let address = self
                .builder
                .build_int_add(data_address, byte_offset, "nested_sequence_element_address")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let child_descriptor = RuntimeAddress::available(address, self.context);
            self.emit_nested_child_slot(parent_payload, slot_offset, &child_descriptor, element)?;
            if self
                .builder
                .get_insert_block()
                .is_some_and(|block| block.get_terminator().is_none())
            {
                self.builder
                    .build_unconditional_branch(continue_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            }
            self.builder.position_at_end(continue_block);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn emit_nested_hash_table_children(
        &mut self,
        parent_payload: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        first_slot_offset: usize,
        bucket_slot_stride: usize,
        bucket_count: usize,
        fields: &[NestedHashTableFieldSource],
        metadata: &NestedHashTableMetadataSource,
        finish_block: inkwell::basic_block::BasicBlock<'ctx>,
    ) -> Result<()> {
        let function = self.current_function("compile nested hash-table children")?;
        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let occupancy_width = metadata
            .occupancy
            .byte_width()
            .and_then(|width| usize::try_from(width).ok())
            .ok_or_else(|| {
                CodeGenError::DwarfError("invalid nested hash-table occupancy width".to_string())
            })?;

        for bucket_index in 0..bucket_count {
            let bucket_slot_offset = bucket_index
                .checked_mul(bucket_slot_stride)
                .and_then(|offset| first_slot_offset.checked_add(offset))
                .ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested hash-table bucket slot offset overflow".to_string(),
                    )
                })?;
            for field in fields {
                let slot_offset = bucket_slot_offset
                    .checked_add(field.slot_offset)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested hash-table field slot offset overflow".to_string(),
                        )
                    })?;
                self.initialize_nested_child_header(
                    parent_payload,
                    slot_offset,
                    VariableStatus::AccessError,
                )?;
            }
        }

        let (pointer_offset, pointer_access_size) = match metadata.buckets {
            HashTableBucketSource::Forward {
                data_offset,
                data_access_size,
            } => (data_offset, data_access_size),
            HashTableBucketSource::ReverseFromControl
            | HashTableBucketSource::LegacyAfterControl { .. } => {
                (metadata.control_offset, metadata.control_access_size)
            }
        };
        let pointer_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(pointer_offset, false),
                "nested_hash_table_pointer_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let pointer_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(pointer_member),
            pointer_access_size,
            None,
            "nested_hash_table_pointer",
        )?;
        let metadata_ok_block = self
            .context
            .append_basic_block(function, "nested_hash_table_metadata_ok");
        self.builder
            .build_conditional_branch(pointer_read.combined_fail, finish_block, metadata_ok_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(metadata_ok_block);

        // SAFETY: the hash-table root capture reserves the complete fixed
        // header.
        let captured_buckets_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    parent_payload,
                    &[i32_type.const_int(
                        ghostscope_protocol::HASH_TABLE_CAPTURED_BUCKETS_OFFSET as u64,
                        false,
                    )],
                    "nested_hash_table_captured_buckets_i8",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let captured_buckets_ptr = self
            .builder
            .build_pointer_cast(
                captured_buckets_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "nested_hash_table_captured_buckets",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_buckets = self
            .builder
            .build_load(i64_type, captured_buckets_ptr, "nested_hash_table_captured")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();

        let raw_pointer = pointer_read.value.into_int_value();
        let bucket_base = match metadata.buckets {
            HashTableBucketSource::Forward { .. } => raw_pointer,
            HashTableBucketSource::ReverseFromControl => raw_pointer,
            HashTableBucketSource::LegacyAfterControl {
                entry_alignment,
                pointer_tag_mask,
            } => {
                let control_address = self
                    .builder
                    .build_and(
                        raw_pointer,
                        i64_type.const_int(!pointer_tag_mask, false),
                        "nested_hash_table_legacy_control",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                // SAFETY: the hash-table root capture reserves the complete
                // fixed header.
                let capacity_ptr_i8 = unsafe {
                    self.builder
                        .build_gep(
                            i8_type,
                            parent_payload,
                            &[i32_type.const_int(
                                ghostscope_protocol::HASH_TABLE_CAPACITY_OFFSET as u64,
                                false,
                            )],
                            "nested_hash_table_capacity_i8",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                };
                let capacity_ptr = self
                    .builder
                    .build_pointer_cast(
                        capacity_ptr_i8,
                        self.context.ptr_type(AddressSpace::default()),
                        "nested_hash_table_capacity",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let capacity = self
                    .builder
                    .build_load(i64_type, capacity_ptr, "nested_hash_table_capacity_value")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let hash_words_len = self
                    .builder
                    .build_int_mul(
                        capacity,
                        i64_type.const_int(occupancy_width as u64, false),
                        "nested_hash_table_legacy_hash_words_len",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let padded_len = self
                    .builder
                    .build_int_add(
                        hash_words_len,
                        i64_type.const_int(entry_alignment - 1, false),
                        "nested_hash_table_legacy_padded_len",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let aligned_len = self
                    .builder
                    .build_and(
                        padded_len,
                        i64_type.const_int(!(entry_alignment - 1), false),
                        "nested_hash_table_legacy_aligned_len",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_int_add(
                        control_address,
                        aligned_len,
                        "nested_hash_table_legacy_bucket_base",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            }
        };
        let entry_stride = i64_type.const_int(metadata.entry_stride, false);

        for bucket_index in 0..bucket_count {
            let index_value = i64_type.const_int(bucket_index as u64, false);
            let captured = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    index_value,
                    captured_buckets,
                    &format!("nested_hash_table_{bucket_index}_captured"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let occupancy_offset = ghostscope_protocol::HASH_TABLE_HEADER_SIZE
                .checked_add(bucket_index.checked_mul(occupancy_width).ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested hash-table occupancy offset overflow".to_string(),
                    )
                })?)
                .ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested hash-table occupancy offset overflow".to_string(),
                    )
                })?;
            let mut nonzero = None;
            for byte_index in 0..occupancy_width {
                let byte_offset = occupancy_offset.checked_add(byte_index).ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested hash-table occupancy byte offset overflow".to_string(),
                    )
                })?;
                // SAFETY: planning bounds every occupancy byte to the reserved
                // hash-table root payload.
                let byte_ptr = unsafe {
                    self.builder
                        .build_gep(
                            i8_type,
                            parent_payload,
                            &[i32_type.const_int(byte_offset as u64, false)],
                            &format!("nested_hash_table_{bucket_index}_{byte_index}_occupancy_ptr"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                };
                let byte = self
                    .builder
                    .build_load(
                        i8_type,
                        byte_ptr,
                        &format!("nested_hash_table_{bucket_index}_{byte_index}_occupancy"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let byte_nonzero = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::NE,
                        byte,
                        i8_type.const_zero(),
                        &format!("nested_hash_table_{bucket_index}_{byte_index}_occupancy_nonzero"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                nonzero = Some(match nonzero {
                    Some(previous) => self
                        .builder
                        .build_or(
                            previous,
                            byte_nonzero,
                            &format!("nested_hash_table_{bucket_index}_occupancy_nonzero"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                    None => byte_nonzero,
                });
            }
            let occupied = match metadata.occupancy {
                ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear => {
                    // SAFETY: occupancy_offset selects the first reserved byte
                    // for this bucket.
                    let byte_ptr = unsafe {
                        self.builder
                            .build_gep(
                                i8_type,
                                parent_payload,
                                &[i32_type.const_int(occupancy_offset as u64, false)],
                                &format!("nested_hash_table_{bucket_index}_control_ptr"),
                            )
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    };
                    let control = self
                        .builder
                        .build_load(
                            i8_type,
                            byte_ptr,
                            &format!("nested_hash_table_{bucket_index}_control"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                        .into_int_value();
                    let high_bit = self
                        .builder
                        .build_and(
                            control,
                            i8_type.const_int(0x80, false),
                            &format!("nested_hash_table_{bucket_index}_control_high_bit"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder
                        .build_int_compare(
                            inkwell::IntPredicate::EQ,
                            high_bit,
                            i8_type.const_zero(),
                            &format!("nested_hash_table_{bucket_index}_occupied"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                }
                ghostscope_dwarf::HashTableOccupancy::NonZeroWord { .. } => {
                    nonzero.ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested hash-table occupancy has no bytes".to_string(),
                        )
                    })?
                }
            };
            let active = self
                .builder
                .build_and(
                    captured,
                    occupied,
                    &format!("nested_hash_table_{bucket_index}_active"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let active_block = self.context.append_basic_block(
                function,
                &format!("nested_hash_table_{bucket_index}_capture"),
            );
            let continue_block = self.context.append_basic_block(
                function,
                &format!("nested_hash_table_{bucket_index}_continue"),
            );
            self.builder
                .build_conditional_branch(active, active_block, continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(active_block);

            let entry_offset = self
                .builder
                .build_int_mul(
                    index_value,
                    entry_stride,
                    &format!("nested_hash_table_{bucket_index}_entry_offset"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let entry_address = match metadata.buckets {
                HashTableBucketSource::ReverseFromControl => self
                    .builder
                    .build_int_sub(
                        bucket_base,
                        self.builder
                            .build_int_add(
                                entry_offset,
                                entry_stride,
                                &format!("nested_hash_table_{bucket_index}_reverse_entry_end"),
                            )
                            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                        &format!("nested_hash_table_{bucket_index}_entry_address"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                HashTableBucketSource::Forward { .. }
                | HashTableBucketSource::LegacyAfterControl { .. } => self
                    .builder
                    .build_int_add(
                        bucket_base,
                        entry_offset,
                        &format!("nested_hash_table_{bucket_index}_entry_address"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            };
            let bucket_slot_offset = bucket_index
                .checked_mul(bucket_slot_stride)
                .and_then(|offset| first_slot_offset.checked_add(offset))
                .ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "nested hash-table bucket slot offset overflow".to_string(),
                    )
                })?;
            for field in fields {
                let field_address = self
                    .builder
                    .build_int_add(
                        entry_address,
                        i64_type.const_int(field.entry_offset, false),
                        &format!(
                            "nested_hash_table_{bucket_index}_field_{}_address",
                            field.field_index
                        ),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let slot_offset = bucket_slot_offset
                    .checked_add(field.slot_offset)
                    .ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "nested hash-table field slot offset overflow".to_string(),
                        )
                    })?;
                self.emit_nested_child_slot(
                    parent_payload,
                    slot_offset,
                    &RuntimeAddress::available(field_address, self.context),
                    &field.child,
                )?;
            }
            if self
                .builder
                .get_insert_block()
                .is_some_and(|block| block.get_terminator().is_none())
            {
                self.builder
                    .build_unconditional_branch(continue_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            }
            self.builder.position_at_end(continue_block);
        }
        Ok(())
    }
}

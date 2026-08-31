use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn emit_complex_format_indirect(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        reserved_len: usize,
        capture: IndirectCaptureConfig,
    ) -> Result<()> {
        let prefix_len = capture.shape.prefix_len();
        if reserved_len < prefix_len {
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

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let ring_config = match capture.shape {
            IndirectCaptureShape::Sequence { ring, .. } => ring,
            IndirectCaptureShape::Bytes => None,
        };
        let data_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.data_offset, false),
                "indirect_data_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length_member = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.length_offset, false),
                "indirect_length_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let data_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(data_member),
            capture.data_access_size,
            Some(status_ptr),
            "indirect_data_metadata",
        )?;
        let data_address = data_read.value.into_int_value();
        let length_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(length_member),
            capture.length_access_size,
            Some(status_ptr),
            "indirect_length_metadata",
        )?;
        let length_value = length_read.value.into_int_value();
        let ring_reads = if let Some(ring) = ring_config {
            let start_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.start_offset, false),
                    "indirect_ring_start_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let start_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(start_member),
                ring.start_access_size,
                Some(status_ptr),
                "indirect_ring_start_metadata",
            )?;
            let capacity_member = self
                .builder
                .build_int_add(
                    descriptor.value,
                    i64_type.const_int(ring.capacity_offset, false),
                    "indirect_ring_capacity_member",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let capacity_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(capacity_member),
                ring.capacity_access_size,
                Some(status_ptr),
                "indirect_ring_capacity_metadata",
            )?;
            Some((
                ring,
                start_member,
                start_read,
                capacity_member,
                capacity_read,
            ))
        } else {
            None
        };

        let mut original_len = if capture.excluded_tail_bytes == 0 {
            length_value
        } else {
            let excluded_tail = i64_type.const_int(capture.excluded_tail_bytes, false);
            let has_excluded_tail = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    length_value,
                    excluded_tail,
                    "indirect_has_excluded_tail",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let adjusted_length = self
                .builder
                .build_int_sub(length_value, excluded_tail, "indirect_adjusted_length")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_select(
                    has_excluded_tail,
                    adjusted_length,
                    i64_type.const_zero(),
                    "indirect_logical_length",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value()
        };
        let mut ring_start = None;
        let mut ring_capacity = None;
        let mut ring_metadata_valid = None;
        if let Some((ring, _, start_read, _, capacity_read)) = &ring_reads {
            let start = start_read.value.into_int_value();
            let capacity = capacity_read.value.into_int_value();
            if matches!(ring.length_kind, RingCaptureLengthKind::End) {
                let direct_distance = self
                    .builder
                    .build_int_sub(length_value, start, "indirect_ring_direct_distance")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wrapped_prefix = self
                    .builder
                    .build_int_sub(capacity, start, "indirect_ring_wrapped_prefix")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let wrapped_distance = self
                    .builder
                    .build_int_add(
                        wrapped_prefix,
                        length_value,
                        "indirect_ring_wrapped_distance",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let no_wrap = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGE,
                        length_value,
                        start,
                        "indirect_ring_no_wrap",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                original_len = self
                    .builder
                    .build_select(
                        no_wrap,
                        direct_distance,
                        wrapped_distance,
                        "indirect_ring_distance",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
            }

            let capacity_nonzero = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    capacity,
                    i64_type.const_zero(),
                    "indirect_ring_capacity_nonzero",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let start_in_bounds = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    start,
                    capacity,
                    "indirect_ring_start_in_bounds",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let length_valid = match ring.length_kind {
                RingCaptureLengthKind::Explicit => self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULE,
                        original_len,
                        capacity,
                        "indirect_ring_length_in_bounds",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                RingCaptureLengthKind::End => self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULT,
                        length_value,
                        capacity,
                        "indirect_ring_end_in_bounds",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            };
            let indices_valid = self
                .builder
                .build_and(
                    capacity_nonzero,
                    start_in_bounds,
                    "indirect_ring_indices_valid",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            ring_metadata_valid = Some(
                self.builder
                    .build_and(indices_valid, length_valid, "indirect_ring_metadata_valid")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            );
            ring_start = Some(start);
            ring_capacity = Some(capacity);
        }

        let current_status = self
            .builder
            .build_load(
                self.context.i8_type(),
                status_ptr,
                "indirect_metadata_status",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let metadata_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                self.context.i8_type().const_zero(),
                "indirect_metadata_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let function = self.current_function("compile indirect value capture")?;
        let metadata_ok_block = self
            .context
            .append_basic_block(function, "indirect_metadata_ok");
        let metadata_error_block = self
            .context
            .append_basic_block(function, "indirect_metadata_error");
        let continue_block = self
            .context
            .append_basic_block(function, "indirect_continue");
        self.builder
            .build_conditional_branch(metadata_ok, metadata_ok_block, metadata_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_error_block);
        let metadata_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
                "indirect_metadata_read_error",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let metadata_payload_block = self
            .context
            .append_basic_block(function, "indirect_metadata_error_payload");
        self.builder
            .build_conditional_branch(metadata_read_error, metadata_payload_block, continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_payload_block);
        let (mut metadata_helper_result, mut metadata_error_address) = ring_reads
            .as_ref()
            .map(|(_, _, _, capacity_member, capacity_read)| {
                (capacity_read.helper_result, *capacity_member)
            })
            .unwrap_or((length_read.helper_result, length_member));
        if let Some((_, start_member, start_read, _, _)) = &ring_reads {
            (metadata_helper_result, metadata_error_address) = self
                .select_indirect_metadata_failure(
                    start_read,
                    *start_member,
                    metadata_helper_result,
                    metadata_error_address,
                    "indirect_ring_start",
                )?;
        }
        (metadata_helper_result, metadata_error_address) = self.select_indirect_metadata_failure(
            &length_read,
            length_member,
            metadata_helper_result,
            metadata_error_address,
            "indirect_length",
        )?;
        (metadata_helper_result, metadata_error_address) = self.select_indirect_metadata_failure(
            &data_read,
            data_member,
            metadata_helper_result,
            metadata_error_address,
            "indirect_data",
        )?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            metadata_helper_result,
            metadata_error_address,
        )?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_ok_block);
        let length_prefix_ptr = self
            .builder
            .build_pointer_cast(var_data_ptr, ptr_type, "indirect_length_prefix")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder
            .build_store(length_prefix_ptr, original_len)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        if matches!(capture.shape, IndirectCaptureShape::Sequence { .. }) {
            // SAFETY: sequence payloads reserve the complete two-u64 header.
            let captured_count_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type.const_int(
                            ghostscope_protocol::INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET as u64,
                            false,
                        )],
                        "indirect_captured_count_ptr_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let captured_count_ptr = self
                .builder
                .build_pointer_cast(
                    captured_count_ptr_i8,
                    ptr_type,
                    "indirect_captured_count_ptr",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(captured_count_ptr, i64_type.const_zero())
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        let is_empty = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_len,
                i64_type.const_zero(),
                "indirect_is_empty",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let empty_block = self.context.append_basic_block(function, "indirect_empty");
        let nonempty_block = self
            .context
            .append_basic_block(function, "indirect_nonempty");
        self.builder
            .build_conditional_branch(is_empty, empty_block, nonempty_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(empty_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ZeroLength as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(nonempty_block);
        if let Some(metadata_valid) = ring_metadata_valid {
            let ring_valid_block = self
                .context
                .append_basic_block(function, "indirect_ring_valid");
            let ring_invalid_block = self
                .context
                .append_basic_block(function, "indirect_ring_invalid");
            self.builder
                .build_conditional_branch(metadata_valid, ring_valid_block, ring_invalid_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_invalid_block);
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::AccessError as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_valid_block);
        }
        let capture_capacity =
            indirect_capture_capacity(reserved_len, capture.max_len, capture.shape);
        let (unit_size, max_units) = match capture.shape {
            IndirectCaptureShape::Bytes => (1usize, capture_capacity),
            IndirectCaptureShape::Sequence {
                element_stride,
                max_elements,
                ..
            } => {
                let stride = usize::try_from(element_stride).map_err(|_| {
                    CodeGenError::DwarfError(format!(
                        "sequence element DWARF size {element_stride} does not fit this host"
                    ))
                })?;
                let payload_elements = capture_capacity.checked_div(stride).unwrap_or(max_elements);
                (stride, max_elements.min(payload_elements))
            }
        };
        let capture_limit = i64_type.const_int(max_units as u64, false);
        let is_truncated = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                original_len,
                capture_limit,
                "indirect_is_truncated",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_units = self
            .builder
            .build_select(
                is_truncated,
                capture_limit,
                original_len,
                "indirect_captured_units",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();

        if matches!(capture.shape, IndirectCaptureShape::Sequence { .. }) {
            // SAFETY: sequence payloads reserve the complete two-u64 header.
            let captured_count_ptr_i8 = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        var_data_ptr,
                        &[i32_type.const_int(
                            ghostscope_protocol::INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET as u64,
                            false,
                        )],
                        "indirect_captured_count_ptr_i8_nonempty",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let captured_count_ptr = self
                .builder
                .build_pointer_cast(
                    captured_count_ptr_i8,
                    ptr_type,
                    "indirect_captured_count_ptr_nonempty",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder
                .build_store(captured_count_ptr, captured_units)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        if max_units == 0 || unit_size == 0 {
            let truncated_block = self
                .context
                .append_basic_block(function, "indirect_no_read_truncated");
            let complete_block = self
                .context
                .append_basic_block(function, "indirect_no_read_complete");
            self.builder
                .build_conditional_branch(is_truncated, truncated_block, complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(truncated_block);
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(complete_block);
            self.mark_any_success()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(continue_block);
            return Ok(());
        }

        let is_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                data_address,
                i64_type.const_zero(),
                "indirect_data_is_null",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let null_block = self.context.append_basic_block(function, "indirect_null");
        let read_block = self.context.append_basic_block(function, "indirect_read");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_block);
        // SAFETY: reserved_len includes the fixed length prefix.
        let byte_payload_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    var_data_ptr,
                    &[i32_type.const_int(prefix_len as u64, false)],
                    "indirect_byte_payload",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let destination = self
            .builder
            .build_pointer_cast(byte_payload_ptr, ptr_type, "indirect_destination")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let read_outcome;
        if let (Some(start), Some(capacity)) = (ring_start, ring_capacity) {
            let available_before_wrap = self
                .builder
                .build_int_sub(capacity, start, "indirect_ring_available_before_wrap")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let wraps = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    captured_units,
                    available_before_wrap,
                    "indirect_ring_wraps",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_units = self
                .builder
                .build_select(
                    wraps,
                    available_before_wrap,
                    captured_units,
                    "indirect_ring_first_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let stride = i64_type.const_int(unit_size as u64, false);
            let start_offset = self
                .builder
                .build_int_mul(start, stride, "indirect_ring_start_offset")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_address = self
                .builder
                .build_int_add(data_address, start_offset, "indirect_ring_first_address")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_len = self
                .builder
                .build_int_mul(first_units, stride, "indirect_ring_first_len")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_len_i32 = self
                .builder
                .build_int_truncate(first_len, i32_type, "indirect_ring_first_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_len_i32 = self.clamp_probe_read_length(
                first_len_i32,
                capture_capacity,
                "indirect_ring_first_len",
            )?;
            let first_payload_len = self
                .builder
                .build_int_z_extend(first_len_i32, i64_type, "indirect_ring_first_payload_len")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_source = self
                .builder
                .build_int_to_ptr(first_address, ptr_type, "indirect_ring_first_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            // SAFETY: first_payload_len is the verifier-bounded helper length,
            // so it cannot exceed the reserved sequence payload.
            let second_payload_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        byte_payload_ptr,
                        &[first_payload_len],
                        "indirect_ring_second_payload",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let second_destination = self
                .builder
                .build_pointer_cast(
                    second_payload_ptr,
                    ptr_type,
                    "indirect_ring_second_destination",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let first_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        destination.into(),
                        first_len_i32.into(),
                        first_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_indirect_ring_first",
                )?
                .into_int_value();

            let second_read_block = self
                .context
                .append_basic_block(function, "indirect_ring_second_read");
            let no_second_read_block = self
                .context
                .append_basic_block(function, "indirect_ring_no_second_read");
            let ring_read_complete_block = self
                .context
                .append_basic_block(function, "indirect_ring_read_complete");
            self.builder
                .build_conditional_branch(wraps, second_read_block, no_second_read_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(no_second_read_block);
            self.builder
                .build_unconditional_branch(ring_read_complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(second_read_block);
            let unbounded_second_units = self
                .builder
                .build_int_sub(
                    captured_units,
                    available_before_wrap,
                    "indirect_ring_unbounded_second_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_units_exceed_limit = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    unbounded_second_units,
                    capture_limit,
                    "indirect_ring_second_units_exceed_limit",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_units = self
                .builder
                .build_select(
                    second_units_exceed_limit,
                    capture_limit,
                    unbounded_second_units,
                    "indirect_ring_second_units",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let second_len = self
                .builder
                .build_int_mul(second_units, stride, "indirect_ring_second_len")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_len_limit = i64_type.const_int(capture_capacity as u64, false);
            let second_len_exceeds_limit = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGT,
                    second_len,
                    second_len_limit,
                    "indirect_ring_second_len_exceeds_limit",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bounded_second_len = self
                .builder
                .build_select(
                    second_len_exceeds_limit,
                    second_len_limit,
                    second_len,
                    "indirect_ring_bounded_second_len",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let second_len_i32 = self
                .builder
                .build_int_truncate(bounded_second_len, i32_type, "indirect_ring_second_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_len_i32 = self.clamp_probe_read_length(
                second_len_i32,
                capture_capacity,
                "indirect_ring_second_len_i32",
            )?;
            let second_source = self
                .builder
                .build_int_to_ptr(data_address, ptr_type, "indirect_ring_second_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let second_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        second_destination.into(),
                        second_len_i32.into(),
                        second_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_indirect_ring_second",
                )?
                .into_int_value();
            self.builder
                .build_unconditional_branch(ring_read_complete_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(ring_read_complete_block);
            let second_result_phi = self
                .builder
                .build_phi(i64_type, "indirect_ring_second_result")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            second_result_phi.add_incoming(&[
                (&i64_type.const_zero(), no_second_read_block),
                (&second_result, second_read_block),
            ]);
            let second_result = second_result_phi.as_basic_value().into_int_value();
            let first_failed = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    first_result,
                    i64_type.const_zero(),
                    "indirect_ring_first_failed",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_result = self
                .builder
                .build_select(
                    first_failed,
                    first_result,
                    second_result,
                    "indirect_ring_read_result",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let read_error_address = self
                .builder
                .build_select(
                    first_failed,
                    first_address,
                    data_address,
                    "indirect_ring_read_error_address",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                .into_int_value();
            let read_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    read_result,
                    i64_type.const_zero(),
                    "indirect_ring_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            read_outcome = (read_result, read_error_address, read_ok);
        } else {
            let read_len = self
                .builder
                .build_int_mul(
                    captured_units,
                    i64_type.const_int(unit_size as u64, false),
                    "indirect_read_len_bytes",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_len = self
                .builder
                .build_int_truncate(read_len, i32_type, "indirect_read_len_i32")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_len =
                self.clamp_probe_read_length(read_len, capture_capacity, "indirect_read_len")?;
            let source = self
                .builder
                .build_int_to_ptr(data_address, ptr_type, "indirect_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let read_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[destination.into(), read_len.into(), source.into()],
                    i64_type.into(),
                    "probe_read_user_indirect",
                )?
                .into_int_value();
            let read_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    read_result,
                    i64_type.const_zero(),
                    "indirect_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            read_outcome = (read_result, data_address, read_ok);
        }
        let (read_result, read_error_address, read_ok) = read_outcome;
        let read_ok_block = self
            .context
            .append_basic_block(function, "indirect_read_ok");
        let read_error_block = self
            .context
            .append_basic_block(function, "indirect_read_error");
        self.builder
            .build_conditional_branch(read_ok, read_ok_block, read_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_error_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            read_result,
            read_error_address,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(read_ok_block);
        let truncated_block = self
            .context
            .append_basic_block(function, "indirect_truncated");
        let complete_block = self
            .context
            .append_basic_block(function, "indirect_complete");
        self.builder
            .build_conditional_branch(is_truncated, truncated_block, complete_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(truncated_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Truncated as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(complete_block);
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(continue_block);
        Ok(())
    }
}

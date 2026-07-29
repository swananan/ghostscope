use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn emit_complex_format_hash_table(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        reserved_len: usize,
        capture: HashTableCaptureConfig,
    ) -> Result<()> {
        let header_len = ghostscope_protocol::HASH_TABLE_HEADER_SIZE;
        if reserved_len < header_len {
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

        let stride = usize::try_from(capture.entry_stride).map_err(|_| {
            CodeGenError::DwarfError(format!(
                "hash-table entry DWARF size {} does not fit this host",
                capture.entry_stride
            ))
        })?;
        let occupancy_width = capture
            .occupancy
            .byte_width()
            .and_then(|width| usize::try_from(width).ok())
            .ok_or_else(|| {
                CodeGenError::DwarfError("invalid hash-table occupancy width".to_string())
            })?;
        let layout_matches = matches!(
            (capture.bucket_order, capture.occupancy, capture.buckets),
            (
                ghostscope_dwarf::HashTableBucketOrder::Forward,
                ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
                HashTableBucketSource::Forward { .. }
            ) | (
                ghostscope_dwarf::HashTableBucketOrder::Reverse,
                ghostscope_dwarf::HashTableOccupancy::ControlByteHighBitClear,
                HashTableBucketSource::ReverseFromControl
            ) | (
                ghostscope_dwarf::HashTableBucketOrder::Forward,
                ghostscope_dwarf::HashTableOccupancy::NonZeroWord { .. },
                HashTableBucketSource::LegacyAfterControl { .. }
            )
        );
        if !layout_matches {
            return Err(CodeGenError::DwarfError(
                "hash-table occupancy and bucket source do not match".to_string(),
            ));
        }
        if let HashTableBucketSource::LegacyAfterControl {
            entry_alignment,
            pointer_tag_mask,
        } = capture.buckets
        {
            let valid_alignment = entry_alignment.is_power_of_two()
                && (capture.entry_stride == 0 || entry_alignment <= capture.entry_stride);
            let valid_tag = occupancy_width.is_power_of_two()
                && pointer_tag_mask & !(occupancy_width as u64 - 1) == 0;
            if !valid_alignment
                || !valid_tag
                || occupancy_width != capture.control_access_size.bytes()
            {
                return Err(CodeGenError::DwarfError(
                    "invalid legacy hash-table storage layout".to_string(),
                ));
            }
        }
        let bytes_per_bucket = stride.checked_add(occupancy_width).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket capture size overflow".to_string())
        })?;
        let reservation_buckets = reserved_len
            .saturating_sub(header_len)
            .checked_div(bytes_per_bucket)
            .unwrap_or(0);
        let max_buckets = capture.max_buckets.min(reservation_buckets);
        let max_control_bytes = max_buckets.checked_mul(occupancy_width).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table control payload overflow".to_string())
        })?;
        let bucket_payload_offset = header_len.checked_add(max_control_bytes).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket offset overflow".to_string())
        })?;
        let max_bucket_bytes = max_buckets.checked_mul(stride).ok_or_else(|| {
            CodeGenError::DwarfError("hash-table bucket payload overflow".to_string())
        })?;
        if max_control_bytes > u32::MAX as usize || max_bucket_bytes > u32::MAX as usize {
            return Err(CodeGenError::DwarfError(
                "hash-table capture exceeds the eBPF helper length width".to_string(),
            ));
        }

        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let member_address = |offset: u64, name: &str| {
            self.builder
                .build_int_add(descriptor.value, i64_type.const_int(offset, false), name)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))
        };
        let control_member = member_address(capture.control_offset, "hash_table_control_member")?;
        let length_member = member_address(capture.length_offset, "hash_table_length_member")?;
        let bucket_mask_member =
            member_address(capture.bucket_mask_offset, "hash_table_bucket_mask_member")?;
        let data_member = match capture.buckets {
            HashTableBucketSource::Forward {
                data_offset,
                data_access_size,
            } => Some((
                member_address(data_offset, "hash_table_data_member")?,
                data_access_size,
            )),
            HashTableBucketSource::ReverseFromControl
            | HashTableBucketSource::LegacyAfterControl { .. } => None,
        };
        let control_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(control_member),
            capture.control_access_size,
            Some(status_ptr),
            "hash_table_control_metadata",
        )?;
        let length_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(length_member),
            capture.length_access_size,
            Some(status_ptr),
            "hash_table_length_metadata",
        )?;
        let bucket_mask_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(bucket_mask_member),
            capture.bucket_mask_access_size,
            Some(status_ptr),
            "hash_table_bucket_mask_metadata",
        )?;
        let data_read = if let Some((address, access_size)) = data_member {
            let read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(address),
                access_size,
                Some(status_ptr),
                "hash_table_data_metadata",
            )?;
            Some((address, read))
        } else {
            None
        };

        let current_status = self
            .builder
            .build_load(i8_type, status_ptr, "hash_table_metadata_status")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let metadata_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                i8_type.const_zero(),
                "hash_table_metadata_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let function = self.current_function("compile hash-table value capture")?;
        let metadata_ok_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_ok");
        let metadata_error_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_error");
        let continue_block = self
            .context
            .append_basic_block(function, "hash_table_continue");
        self.builder
            .build_conditional_branch(metadata_ok, metadata_ok_block, metadata_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_error_block);
        let metadata_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current_status,
                i8_type.const_int(VariableStatus::ReadError as u64, false),
                "hash_table_metadata_read_error",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let metadata_payload_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_error_payload");
        self.builder
            .build_conditional_branch(metadata_read_error, metadata_payload_block, continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_payload_block);
        let (mut helper_result, mut error_address) =
            (bucket_mask_read.helper_result, bucket_mask_member);
        if let Some((data_member, data_read)) = &data_read {
            (helper_result, error_address) = self.select_indirect_metadata_failure(
                data_read,
                *data_member,
                helper_result,
                error_address,
                "hash_table_data",
            )?;
        }
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &bucket_mask_read,
            bucket_mask_member,
            helper_result,
            error_address,
            "hash_table_bucket_mask",
        )?;
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &length_read,
            length_member,
            helper_result,
            error_address,
            "hash_table_length",
        )?;
        (helper_result, error_address) = self.select_indirect_metadata_failure(
            &control_read,
            control_member,
            helper_result,
            error_address,
            "hash_table_control",
        )?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            helper_result,
            error_address,
        )?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(metadata_ok_block);
        let raw_control_address = control_read.value.into_int_value();
        let control_address = match capture.buckets {
            HashTableBucketSource::LegacyAfterControl {
                pointer_tag_mask, ..
            } => self
                .builder
                .build_and(
                    raw_control_address,
                    i64_type.const_int(!pointer_tag_mask, false),
                    "hash_table_legacy_control_address",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
            HashTableBucketSource::Forward { .. } | HashTableBucketSource::ReverseFromControl => {
                raw_control_address
            }
        };
        let original_count = length_read.value.into_int_value();
        let bucket_mask = bucket_mask_read.value.into_int_value();
        let capacity = self
            .builder
            .build_int_add(
                bucket_mask,
                i64_type.const_int(1, false),
                "hash_table_capacity",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let capacity_nonzero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                capacity,
                i64_type.const_zero(),
                "hash_table_capacity_nonzero",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let count_zero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_count,
                i64_type.const_zero(),
                "hash_table_count_zero",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let capacity_valid = self
            .builder
            .build_or(capacity_nonzero, count_zero, "hash_table_capacity_valid")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length_valid = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                original_count,
                capacity,
                "hash_table_length_valid",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let mut metadata_valid = self
            .builder
            .build_and(capacity_valid, length_valid, "hash_table_metadata_valid")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        if let HashTableBucketSource::LegacyAfterControl {
            entry_alignment, ..
        } = capture.buckets
        {
            let alignment_padding = entry_alignment - 1;
            let max_capacity = (u64::MAX - alignment_padding) / occupancy_width as u64;
            let capacity_fits = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULE,
                    capacity,
                    i64_type.const_int(max_capacity, false),
                    "hash_table_legacy_capacity_fits",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            metadata_valid = self
                .builder
                .build_and(
                    metadata_valid,
                    capacity_fits,
                    "hash_table_legacy_metadata_valid",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }
        let valid_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_valid");
        let invalid_block = self
            .context
            .append_basic_block(function, "hash_table_metadata_invalid");
        self.builder
            .build_conditional_branch(metadata_valid, valid_block, invalid_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(invalid_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::AccessError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(valid_block);
        self.store_complex_payload_u64(var_data_ptr, 0, original_count, "hash_table_item_count")?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPACITY_OFFSET,
            capacity,
            "hash_table_capacity_header",
        )?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPTURED_BUCKETS_OFFSET,
            i64_type.const_zero(),
            "hash_table_captured_buckets_empty",
        )?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_BUCKET_DATA_OFFSET,
            i64_type.const_int(bucket_payload_offset as u64, false),
            "hash_table_bucket_payload_offset",
        )?;
        let is_empty = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_count,
                i64_type.const_zero(),
                "hash_table_is_empty",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let empty_block = self
            .context
            .append_basic_block(function, "hash_table_empty");
        let nonempty_block = self
            .context
            .append_basic_block(function, "hash_table_nonempty");
        self.builder
            .build_conditional_branch(is_empty, empty_block, nonempty_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(empty_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::ZeroLength as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(nonempty_block);
        if max_buckets == 0 {
            self.builder
                .build_store(
                    status_ptr,
                    i8_type.const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(continue_block);
            return Ok(());
        }

        let capture_limit = i64_type.const_int(max_buckets as u64, false);
        let capacity_exceeds_limit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGT,
                capacity,
                capture_limit,
                "hash_table_capacity_exceeds_limit",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let captured_buckets = self
            .builder
            .build_select(
                capacity_exceeds_limit,
                capture_limit,
                capacity,
                "hash_table_captured_buckets",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::HASH_TABLE_CAPTURED_BUCKETS_OFFSET,
            captured_buckets,
            "hash_table_captured_buckets_header",
        )?;

        let data_address = data_read
            .as_ref()
            .map(|(_, read)| read.value.into_int_value());
        let control_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                control_address,
                i64_type.const_zero(),
                "hash_table_control_null",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let pointer_null = if stride > 0 {
            if let Some(data_address) = data_address {
                let data_null = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        data_address,
                        i64_type.const_zero(),
                        "hash_table_data_null",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_or(control_null, data_null, "hash_table_pointer_null")
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            } else {
                control_null
            }
        } else {
            control_null
        };
        let null_block = self
            .context
            .append_basic_block(function, "hash_table_null_pointer");
        let control_read_block = self
            .context
            .append_basic_block(function, "hash_table_read_controls");
        self.builder
            .build_conditional_branch(pointer_null, null_block, control_read_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_read_block);
        // SAFETY: the hash-table header and maximum occupancy bytes are
        // included in the reservation validated above.
        let control_destination_i8 = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    var_data_ptr,
                    &[i32_type.const_int(header_len as u64, false)],
                    "hash_table_control_destination_i8",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        let control_destination = self
            .builder
            .build_pointer_cast(
                control_destination_i8,
                ptr_type,
                "hash_table_control_destination",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_length_i64 = self
            .builder
            .build_int_mul(
                captured_buckets,
                i64_type.const_int(occupancy_width as u64, false),
                "hash_table_control_length_i64",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_length = self
            .builder
            .build_int_truncate(control_length_i64, i32_type, "hash_table_control_length")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_length = self.clamp_probe_read_length(
            control_length,
            max_control_bytes,
            "hash_table_control_length",
        )?;
        let control_source = self
            .builder
            .build_int_to_ptr(control_address, ptr_type, "hash_table_control_source")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_result = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[
                    control_destination.into(),
                    control_length.into(),
                    control_source.into(),
                ],
                i64_type.into(),
                "probe_read_user_hash_table_controls",
            )?
            .into_int_value();
        let control_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                control_result,
                i64_type.const_zero(),
                "hash_table_control_read_ok",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let control_ok_block = self
            .context
            .append_basic_block(function, "hash_table_control_read_ok");
        let control_error_block = self
            .context
            .append_basic_block(function, "hash_table_control_read_error");
        self.builder
            .build_conditional_branch(control_ok, control_ok_block, control_error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_error_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::ReadError as u64, false),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            control_result,
            control_address,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(continue_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(control_ok_block);
        let finish_read_block = if stride == 0 {
            control_ok_block
        } else {
            // SAFETY: bucket_payload_offset and max_bucket_bytes were derived
            // from the same reservation, so this fixed destination is in bounds.
            let bucket_destination_i8 = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        var_data_ptr,
                        &[i32_type.const_int(bucket_payload_offset as u64, false)],
                        "hash_table_bucket_destination_i8",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            };
            let bucket_destination = self
                .builder
                .build_pointer_cast(
                    bucket_destination_i8,
                    ptr_type,
                    "hash_table_bucket_destination",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_length_i64 = self
                .builder
                .build_int_mul(
                    captured_buckets,
                    i64_type.const_int(stride as u64, false),
                    "hash_table_bucket_length_i64",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_length = self
                .builder
                .build_int_truncate(bucket_length_i64, i32_type, "hash_table_bucket_length")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_length = self.clamp_probe_read_length(
                bucket_length,
                max_bucket_bytes,
                "hash_table_bucket_length",
            )?;
            let bucket_source_address = match capture.buckets {
                HashTableBucketSource::Forward { .. } => data_address.ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "forward hash-table capture is missing a data pointer".to_string(),
                    )
                })?,
                HashTableBucketSource::ReverseFromControl => self
                    .builder
                    .build_int_sub(
                        control_address,
                        bucket_length_i64,
                        "hash_table_reverse_bucket_source",
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?,
                HashTableBucketSource::LegacyAfterControl {
                    entry_alignment, ..
                } => {
                    let hash_words_len = self
                        .builder
                        .build_int_mul(
                            capacity,
                            i64_type.const_int(occupancy_width as u64, false),
                            "hash_table_legacy_hash_words_length",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let padded_hash_words_len = self
                        .builder
                        .build_int_add(
                            hash_words_len,
                            i64_type.const_int(entry_alignment - 1, false),
                            "hash_table_legacy_hash_words_padded_length",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let aligned_hash_words_len = self
                        .builder
                        .build_and(
                            padded_hash_words_len,
                            i64_type.const_int(!(entry_alignment - 1), false),
                            "hash_table_legacy_hash_words_aligned_length",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder
                        .build_int_add(
                            control_address,
                            aligned_hash_words_len,
                            "hash_table_legacy_bucket_source",
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                }
            };
            let bucket_source = self
                .builder
                .build_int_to_ptr(bucket_source_address, ptr_type, "hash_table_bucket_source")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_result = self
                .create_bpf_helper_call(
                    BPF_FUNC_probe_read_user as u64,
                    &[
                        bucket_destination.into(),
                        bucket_length.into(),
                        bucket_source.into(),
                    ],
                    i64_type.into(),
                    "probe_read_user_hash_table_buckets",
                )?
                .into_int_value();
            let bucket_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    bucket_result,
                    i64_type.const_zero(),
                    "hash_table_bucket_read_ok",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let bucket_ok_block = self
                .context
                .append_basic_block(function, "hash_table_bucket_read_ok");
            let bucket_error_block = self
                .context
                .append_basic_block(function, "hash_table_bucket_read_error");
            self.builder
                .build_conditional_branch(bucket_ok, bucket_ok_block, bucket_error_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

            self.builder.position_at_end(bucket_error_block);
            self.builder
                .build_store(
                    status_ptr,
                    i8_type.const_int(VariableStatus::ReadError as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.emit_complex_format_read_error_payload(
                var_data_ptr,
                reserved_len,
                bucket_result,
                bucket_source_address,
            )?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(continue_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            bucket_ok_block
        };

        self.builder.position_at_end(finish_read_block);
        let truncated_block = self
            .context
            .append_basic_block(function, "hash_table_truncated");
        let complete_block = self
            .context
            .append_basic_block(function, "hash_table_complete");
        self.builder
            .build_conditional_branch(capacity_exceeds_limit, truncated_block, complete_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(truncated_block);
        self.builder
            .build_store(
                status_ptr,
                i8_type.const_int(VariableStatus::Truncated as u64, false),
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

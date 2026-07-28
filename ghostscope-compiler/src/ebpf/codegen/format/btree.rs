use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    fn btree_payload_u64_ptr(
        &self,
        data_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<PointerValue<'ctx>> {
        // SAFETY: every caller derives the fixed offset from the validated
        // B-Tree reservation and record layout.
        let field_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("{name}_i8"),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
        };
        self.builder
            .build_pointer_cast(
                field_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                name,
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))
    }

    fn continue_after_btree_scalar_read(
        &mut self,
        read: &crate::ebpf::helper_functions::MemoryReadDiagnostics<'ctx>,
        address: IntValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        reserved_len: usize,
        abort_block: inkwell::basic_block::BasicBlock<'ctx>,
        name: &str,
    ) -> Result<()> {
        let function = self.current_function("compile B-Tree scalar read")?;
        let ok_block = self
            .context
            .append_basic_block(function, &format!("{name}_ok"));
        let error_block = self
            .context
            .append_basic_block(function, &format!("{name}_error"));
        self.builder
            .build_conditional_branch(read.combined_fail, error_block, ok_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(error_block);
        self.emit_complex_format_read_error_payload(
            var_data_ptr,
            reserved_len,
            read.helper_result,
            address,
        )?;
        self.builder
            .build_unconditional_branch(abort_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(ok_block);
        Ok(())
    }

    fn emit_btree_bulk_read(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        reserved_len: usize,
        abort_block: inkwell::basic_block::BasicBlock<'ctx>,
        read: BTreeBulkRead<'ctx, '_>,
    ) -> Result<()> {
        let BTreeBulkRead {
            destination_offset,
            source_address,
            length,
            max_len,
            name,
        } = read;
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let destination = self.btree_payload_u64_ptr(
            var_data_ptr,
            destination_offset,
            &format!("{name}_destination"),
        )?;
        let source = self
            .builder
            .build_int_to_ptr(source_address, ptr_type, &format!("{name}_source"))
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length = self
            .builder
            .build_int_truncate(length, i32_type, &format!("{name}_length"))
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length = self.clamp_probe_read_length(length, max_len, &format!("{name}_length"))?;
        let result = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[destination.into(), length.into(), source.into()],
                i64_type.into(),
                &format!("probe_read_user_{name}"),
            )?
            .into_int_value();
        let ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                result,
                i64_type.const_zero(),
                &format!("{name}_ok"),
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let function = self.current_function("compile B-Tree bulk read")?;
        let ok_block = self
            .context
            .append_basic_block(function, &format!("{name}_read_ok"));
        let error_block = self
            .context
            .append_basic_block(function, &format!("{name}_read_error"));
        self.builder
            .build_conditional_branch(ok, ok_block, error_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(error_block);
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
            result,
            source_address,
        )?;
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(abort_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(ok_block);
        Ok(())
    }

    pub(super) fn emit_complex_format_btree(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        var_data_ptr: PointerValue<'ctx>,
        descriptor: &RuntimeAddress<'ctx>,
        reserved_len: usize,
        capture: BTreeCaptureConfig,
    ) -> Result<()> {
        let header_len = ghostscope_protocol::BTREE_HEADER_SIZE;
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

        let capacity = usize::try_from(capture.node_capacity).map_err(|_| {
            CodeGenError::DwarfError("B-Tree capacity does not fit this host".to_string())
        })?;
        let key_stride = usize::try_from(capture.keys.slot_stride).map_err(|_| {
            CodeGenError::DwarfError("B-Tree key stride does not fit this host".to_string())
        })?;
        let value_stride = capture
            .values
            .map(|values| {
                usize::try_from(values.slot_stride).map_err(|_| {
                    CodeGenError::DwarfError(
                        "B-Tree value stride does not fit this host".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or(0);
        let key_bytes = capacity
            .checked_mul(key_stride)
            .ok_or_else(|| CodeGenError::DwarfError("B-Tree key payload overflow".to_string()))?;
        let value_bytes = capacity
            .checked_mul(value_stride)
            .ok_or_else(|| CodeGenError::DwarfError("B-Tree value payload overflow".to_string()))?;
        let values_offset = ghostscope_protocol::BTREE_NODE_HEADER_SIZE
            .checked_add(key_bytes)
            .ok_or_else(|| CodeGenError::DwarfError("B-Tree value offset overflow".to_string()))?;
        let record_size = values_offset
            .checked_add(value_bytes)
            .ok_or_else(|| CodeGenError::DwarfError("B-Tree record size overflow".to_string()))?;
        let reservation_nodes = reserved_len
            .saturating_sub(header_len)
            .checked_div(record_size)
            .unwrap_or(0);
        let node_slots = capture.max_nodes.min(reservation_nodes);
        if capture.edges.edge_count != capture.node_capacity.saturating_add(1)
            || capture.edges.pointer_access_size.bytes() != capture.root_pointer_access_size.bytes()
        {
            return Err(CodeGenError::DwarfError(
                "B-Tree edge layout does not match its DWARF node capacity".to_string(),
            ));
        }
        let edge_count = usize::try_from(capture.edges.edge_count).map_err(|_| {
            CodeGenError::DwarfError("B-Tree edge count does not fit this host".to_string())
        })?;

        let i8_type = self.context.i8_type();
        let i64_type = self.context.i64_type();
        let function = self.current_function("compile B-Tree value capture")?;
        let abort_block = self.context.append_basic_block(function, "btree_abort");
        let invalid_block = self.context.append_basic_block(function, "btree_invalid");
        let finish_block = self.context.append_basic_block(function, "btree_finish");
        let truncated_ptr = self.build_entry_alloca(i8_type, "btree_frontier_truncated")?;
        self.builder
            .build_store(truncated_ptr, i8_type.const_zero())
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        let length_address = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.length_offset, false),
                "btree_length_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let root_pointer_address = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.root_pointer_offset, false),
                "btree_root_pointer_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let root_height_address = self
            .builder
            .build_int_add(
                descriptor.value,
                i64_type.const_int(capture.root_height_offset, false),
                "btree_root_height_member",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let length_read = self.generate_memory_read_with_diagnostics(
            descriptor.with_value(length_address),
            capture.length_access_size,
            Some(status_ptr),
            "btree_length_metadata",
        )?;
        self.continue_after_btree_scalar_read(
            &length_read,
            length_address,
            var_data_ptr,
            reserved_len,
            abort_block,
            "btree_length",
        )?;
        let original_count = length_read.value.into_int_value();
        self.store_complex_payload_u64(var_data_ptr, 0, original_count, "btree_item_count")?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::BTREE_NODE_SLOT_COUNT_OFFSET,
            i64_type.const_int(node_slots as u64, false),
            "btree_node_slots",
        )?;
        self.store_complex_payload_u64(
            var_data_ptr,
            ghostscope_protocol::BTREE_CAPTURED_ITEM_COUNT_OFFSET,
            i64_type.const_zero(),
            "btree_captured_items_empty",
        )?;
        for slot in 0..node_slots {
            let record_offset = header_len
                .checked_add(slot.checked_mul(record_size).ok_or_else(|| {
                    CodeGenError::DwarfError("B-Tree record offset overflow".to_string())
                })?)
                .ok_or_else(|| {
                    CodeGenError::DwarfError("B-Tree record offset overflow".to_string())
                })?;
            self.store_complex_payload_u64(
                var_data_ptr,
                record_offset,
                i64_type.const_zero(),
                &format!("btree_node_{slot}_empty"),
            )?;
        }

        let is_empty = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                original_count,
                i64_type.const_zero(),
                "btree_is_empty",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let empty_block = self.context.append_basic_block(function, "btree_empty");
        let nonempty_block = self.context.append_basic_block(function, "btree_nonempty");
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
            .build_unconditional_branch(abort_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(nonempty_block);
        if node_slots == 0 {
            self.builder
                .build_store(
                    status_ptr,
                    i8_type.const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.mark_any_success()?;
            self.mark_any_fail()?;
            self.builder
                .build_unconditional_branch(abort_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        } else {
            let root_pointer_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(root_pointer_address),
                capture.root_pointer_access_size,
                Some(status_ptr),
                "btree_root_pointer_metadata",
            )?;
            self.continue_after_btree_scalar_read(
                &root_pointer_read,
                root_pointer_address,
                var_data_ptr,
                reserved_len,
                abort_block,
                "btree_root_pointer",
            )?;
            let root_pointer = root_pointer_read.value.into_int_value();
            let root_height_read = self.generate_memory_read_with_diagnostics(
                descriptor.with_value(root_height_address),
                capture.root_height_access_size,
                Some(status_ptr),
                "btree_root_height_metadata",
            )?;
            self.continue_after_btree_scalar_read(
                &root_height_read,
                root_height_address,
                var_data_ptr,
                reserved_len,
                abort_block,
                "btree_root_height",
            )?;
            let root_height = root_height_read.value.into_int_value();
            let root_nonnull = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    root_pointer,
                    i64_type.const_zero(),
                    "btree_root_nonnull",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let height_valid = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    root_height,
                    i64_type
                        .const_int((capture.root_pointer_access_size.bytes() * 8) as u64, false),
                    "btree_root_height_valid",
                )
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let root_valid = self
                .builder
                .build_and(root_nonnull, height_valid, "btree_root_valid")
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            let root_valid_block = self
                .context
                .append_basic_block(function, "btree_root_valid");
            self.builder
                .build_conditional_branch(root_valid, root_valid_block, invalid_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
            self.builder.position_at_end(root_valid_block);
            self.store_complex_payload_u64(
                var_data_ptr,
                header_len,
                root_pointer,
                "btree_root_node",
            )?;
            self.store_complex_payload_u64(
                var_data_ptr,
                header_len + ghostscope_protocol::BTREE_NODE_HEIGHT_OFFSET,
                root_height,
                "btree_root_node_height",
            )?;

            for slot in 0..node_slots {
                let record_offset = header_len + slot * record_size;
                let node_ptr = self.btree_payload_u64_ptr(
                    var_data_ptr,
                    record_offset,
                    &format!("btree_node_{slot}_address_ptr"),
                )?;
                let node_address = self
                    .builder
                    .build_load(i64_type, node_ptr, &format!("btree_node_{slot}_address"))
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let present = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::NE,
                        node_address,
                        i64_type.const_zero(),
                        &format!("btree_node_{slot}_present"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let capture_block = self
                    .context
                    .append_basic_block(function, &format!("btree_node_{slot}_capture"));
                let next_block = self
                    .context
                    .append_basic_block(function, &format!("btree_node_{slot}_next"));
                self.builder
                    .build_conditional_branch(present, capture_block, next_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder.position_at_end(capture_block);

                let height_ptr = self.btree_payload_u64_ptr(
                    var_data_ptr,
                    record_offset + ghostscope_protocol::BTREE_NODE_HEIGHT_OFFSET,
                    &format!("btree_node_{slot}_height_ptr"),
                )?;
                let height = self
                    .builder
                    .build_load(i64_type, height_ptr, &format!("btree_node_{slot}_height"))
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let length_address = self
                    .builder
                    .build_int_add(
                        node_address,
                        i64_type.const_int(capture.node_length_offset, false),
                        &format!("btree_node_{slot}_length_address"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let node_length_read = self.generate_memory_read_with_diagnostics(
                    descriptor.with_value(length_address),
                    capture.node_length_access_size,
                    Some(status_ptr),
                    &format!("btree_node_{slot}_length"),
                )?;
                self.continue_after_btree_scalar_read(
                    &node_length_read,
                    length_address,
                    var_data_ptr,
                    reserved_len,
                    abort_block,
                    &format!("btree_node_{slot}_length"),
                )?;
                let node_length = node_length_read.value.into_int_value();
                let length_valid = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULE,
                        node_length,
                        i64_type.const_int(capture.node_capacity, false),
                        &format!("btree_node_{slot}_length_valid"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let node_valid_block = self
                    .context
                    .append_basic_block(function, &format!("btree_node_{slot}_valid"));
                self.builder
                    .build_conditional_branch(length_valid, node_valid_block, invalid_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder.position_at_end(node_valid_block);
                self.store_complex_payload_u64(
                    var_data_ptr,
                    record_offset + ghostscope_protocol::BTREE_NODE_LENGTH_OFFSET,
                    node_length,
                    &format!("btree_node_{slot}_stored_length"),
                )?;
                let captured_ptr = self.btree_payload_u64_ptr(
                    var_data_ptr,
                    ghostscope_protocol::BTREE_CAPTURED_ITEM_COUNT_OFFSET,
                    &format!("btree_node_{slot}_captured_ptr"),
                )?;
                let captured_items = self
                    .builder
                    .build_load(
                        i64_type,
                        captured_ptr,
                        &format!("btree_node_{slot}_captured_items"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let captured_items = self
                    .builder
                    .build_int_add(
                        captured_items,
                        node_length,
                        &format!("btree_node_{slot}_captured_items_next"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_store(captured_ptr, captured_items)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

                if key_stride > 0 {
                    let source = self
                        .builder
                        .build_int_add(
                            node_address,
                            i64_type.const_int(capture.keys.offset, false),
                            &format!("btree_node_{slot}_keys_source"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let length = self
                        .builder
                        .build_int_mul(
                            node_length,
                            i64_type.const_int(key_stride as u64, false),
                            &format!("btree_node_{slot}_keys_length"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.emit_btree_bulk_read(
                        status_ptr,
                        var_data_ptr,
                        reserved_len,
                        abort_block,
                        BTreeBulkRead {
                            destination_offset: record_offset
                                + ghostscope_protocol::BTREE_NODE_HEADER_SIZE,
                            source_address: source,
                            length,
                            max_len: key_bytes,
                            name: &format!("btree_node_{slot}_keys"),
                        },
                    )?;
                }
                if let Some(values) = capture.values.filter(|_| value_stride > 0) {
                    let source = self
                        .builder
                        .build_int_add(
                            node_address,
                            i64_type.const_int(values.offset, false),
                            &format!("btree_node_{slot}_values_source"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let length = self
                        .builder
                        .build_int_mul(
                            node_length,
                            i64_type.const_int(value_stride as u64, false),
                            &format!("btree_node_{slot}_values_length"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.emit_btree_bulk_read(
                        status_ptr,
                        var_data_ptr,
                        reserved_len,
                        abort_block,
                        BTreeBulkRead {
                            destination_offset: record_offset + values_offset,
                            source_address: source,
                            length,
                            max_len: value_bytes,
                            name: &format!("btree_node_{slot}_values"),
                        },
                    )?;
                }

                let child_base = slot
                    .checked_mul(edge_count)
                    .and_then(|value| value.checked_add(1))
                    .ok_or_else(|| {
                        CodeGenError::DwarfError("B-Tree child slot overflow".to_string())
                    })?;
                let available_edges = node_slots.saturating_sub(child_base).min(edge_count);
                for edge in 0..available_edges {
                    let internal = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::UGT,
                            height,
                            i64_type.const_zero(),
                            &format!("btree_node_{slot}_edge_{edge}_internal"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let initialized = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::ULE,
                            i64_type.const_int(edge as u64, false),
                            node_length,
                            &format!("btree_node_{slot}_edge_{edge}_initialized"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let should_read = self
                        .builder
                        .build_and(
                            internal,
                            initialized,
                            &format!("btree_node_{slot}_edge_{edge}_read"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let read_block = self.context.append_basic_block(
                        function,
                        &format!("btree_node_{slot}_edge_{edge}_read"),
                    );
                    let edge_next = self.context.append_basic_block(
                        function,
                        &format!("btree_node_{slot}_edge_{edge}_next"),
                    );
                    self.builder
                        .build_conditional_branch(should_read, read_block, edge_next)
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder.position_at_end(read_block);
                    let edge_offset = capture
                        .edges
                        .offset_from_leaf
                        .checked_add(
                            (edge as u64)
                                .checked_mul(capture.edges.slot_stride)
                                .ok_or_else(|| {
                                    CodeGenError::DwarfError(
                                        "B-Tree edge offset overflow".to_string(),
                                    )
                                })?,
                        )
                        .and_then(|offset| offset.checked_add(capture.edges.pointer_offset))
                        .ok_or_else(|| {
                            CodeGenError::DwarfError("B-Tree edge offset overflow".to_string())
                        })?;
                    let edge_address = self
                        .builder
                        .build_int_add(
                            node_address,
                            i64_type.const_int(edge_offset, false),
                            &format!("btree_node_{slot}_edge_{edge}_address"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let edge_read = self.generate_memory_read_with_diagnostics(
                        descriptor.with_value(edge_address),
                        capture.edges.pointer_access_size,
                        Some(status_ptr),
                        &format!("btree_node_{slot}_edge_{edge}"),
                    )?;
                    self.continue_after_btree_scalar_read(
                        &edge_read,
                        edge_address,
                        var_data_ptr,
                        reserved_len,
                        abort_block,
                        &format!("btree_node_{slot}_edge_{edge}"),
                    )?;
                    let child_address = edge_read.value.into_int_value();
                    let child_nonnull = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            child_address,
                            i64_type.const_zero(),
                            &format!("btree_node_{slot}_edge_{edge}_nonnull"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    let child_valid = self.context.append_basic_block(
                        function,
                        &format!("btree_node_{slot}_edge_{edge}_valid"),
                    );
                    self.builder
                        .build_conditional_branch(child_nonnull, child_valid, invalid_block)
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder.position_at_end(child_valid);
                    let child_slot = child_base + edge;
                    let child_offset = header_len + child_slot * record_size;
                    self.store_complex_payload_u64(
                        var_data_ptr,
                        child_offset,
                        child_address,
                        &format!("btree_node_{slot}_edge_{edge}_child"),
                    )?;
                    let child_height = self
                        .builder
                        .build_int_sub(
                            height,
                            i64_type.const_int(1, false),
                            &format!("btree_node_{slot}_edge_{edge}_child_height"),
                        )
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.store_complex_payload_u64(
                        var_data_ptr,
                        child_offset + ghostscope_protocol::BTREE_NODE_HEIGHT_OFFSET,
                        child_height,
                        &format!("btree_node_{slot}_edge_{edge}_stored_height"),
                    )?;
                    self.builder
                        .build_unconditional_branch(edge_next)
                        .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                    self.builder.position_at_end(edge_next);
                }

                let is_internal = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGT,
                        height,
                        i64_type.const_zero(),
                        &format!("btree_node_{slot}_frontier_internal"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let misses_edge = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::UGE,
                        node_length,
                        i64_type.const_int(available_edges as u64, false),
                        &format!("btree_node_{slot}_frontier_missing"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let frontier_truncated = self
                    .builder
                    .build_and(
                        is_internal,
                        misses_edge,
                        &format!("btree_node_{slot}_frontier_truncated"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                let old_truncated = self
                    .builder
                    .build_load(
                        i8_type,
                        truncated_ptr,
                        &format!("btree_node_{slot}_old_truncated"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
                    .into_int_value();
                let new_truncated = self
                    .builder
                    .build_select(
                        frontier_truncated,
                        i8_type.const_int(1, false),
                        old_truncated,
                        &format!("btree_node_{slot}_new_truncated"),
                    )
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_store(truncated_ptr, new_truncated)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder
                    .build_unconditional_branch(next_block)
                    .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
                self.builder.position_at_end(next_block);
            }
            self.builder
                .build_unconditional_branch(finish_block)
                .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        }

        self.builder.position_at_end(finish_block);
        let captured_ptr = self.btree_payload_u64_ptr(
            var_data_ptr,
            ghostscope_protocol::BTREE_CAPTURED_ITEM_COUNT_OFFSET,
            "btree_final_captured_ptr",
        )?;
        let captured_items = self
            .builder
            .build_load(i64_type, captured_ptr, "btree_final_captured_items")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let captured_valid = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                captured_items,
                original_count,
                "btree_captured_count_valid",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let count_complete = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                captured_items,
                original_count,
                "btree_count_complete",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let frontier_truncated = self
            .builder
            .build_load(i8_type, truncated_ptr, "btree_frontier_truncated_final")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?
            .into_int_value();
        let frontier_complete = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                frontier_truncated,
                i8_type.const_zero(),
                "btree_frontier_complete",
            )
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let complete = self
            .builder
            .build_and(count_complete, frontier_complete, "btree_complete")
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        let count_valid_block = self
            .context
            .append_basic_block(function, "btree_captured_count_valid");
        self.builder
            .build_conditional_branch(captured_valid, count_valid_block, invalid_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(count_valid_block);
        let complete_block = self.context.append_basic_block(function, "btree_complete");
        let truncated_block = self.context.append_basic_block(function, "btree_truncated");
        self.builder
            .build_conditional_branch(complete, complete_block, truncated_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(complete_block);
        self.mark_any_success()?;
        self.builder
            .build_unconditional_branch(abort_block)
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
            .build_unconditional_branch(abort_block)
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
            .build_unconditional_branch(abort_block)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;

        self.builder.position_at_end(abort_block);
        Ok(())
    }
}

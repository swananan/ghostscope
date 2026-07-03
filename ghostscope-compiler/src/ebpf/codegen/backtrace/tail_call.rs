use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn generate_tail_call_backtrace_instruction(
        &mut self,
        plan: &BacktraceInstructionPlan,
    ) -> Result<()> {
        let depth = plan.depth;
        let flags = plan.flags;
        info!(
            "Generating tail-call Backtrace instruction: depth={}",
            depth
        );

        let payload_size = plan.payload_size;
        let instruction_size = plan.instruction_size;
        let offset_ptr = self.event_offset_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("event_offset not allocated in entry block".to_string())
        })?;
        let inst_offset = self
            .builder
            .build_load(self.context.i32_type(), offset_ptr, "bt_tail_inst_offset")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(instruction_size as u64)?
            .into_value_after_runtime_returns();

        self.store_u8_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, inst_type),
            InstructionType::Backtrace as u8,
            "bt_inst_type",
        )?;
        self.store_u16_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, data_length),
            payload_size as u16,
            "bt_data_length",
        )?;

        let data_base = INSTRUCTION_HEADER_SIZE;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET,
            depth,
            "bt_requested_depth",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            1,
            "bt_frame_count",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FLAGS_OFFSET,
            flags,
            "bt_flags",
        )?;
        self.store_u16_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            0,
            "bt_error_code",
        )?;

        let Some(compile_ctx) = self.current_compile_time_context.clone() else {
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                0,
                "bt_frame_count_no_context",
            )?;
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                BacktraceStatus::DwarfUnavailable as u8,
                "bt_status_no_context",
            )?;
            return Ok(());
        };

        let module_cookie = self.cookie_for_module_or_fallback(&compile_ctx.module_path);
        let module_cookie_value = self.context.i64_type().const_int(module_cookie, false);
        let pt_regs = self.get_pt_regs_parameter()?;
        let raw_ip = self.load_dwarf_register_i64(X86_64_DWARF_RIP, pt_regs)?;
        let initial_rsp = self.load_dwarf_register_i64(X86_64_DWARF_RSP, pt_regs)?;
        let initial_rbp = self.load_dwarf_register_i64(X86_64_DWARF_RBP, pt_regs)?;
        let (module_bias, offsets_found) = self.generate_runtime_address_from_offsets(
            self.context.i64_type().const_zero(),
            0,
            module_cookie,
        )?;
        let normalized_pc = self.normalized_pc_from_raw(raw_ip, module_bias, offsets_found)?;
        let caller_fallback_found = self.backtrace_module_fallback_found(offsets_found);

        self.store_backtrace_frame(
            inst_buffer,
            0,
            module_cookie_value,
            normalized_pc,
            raw_ip,
            0,
        )?;

        if depth == 1 {
            let status =
                self.status_or_offsets_unavailable(BacktraceStatus::Truncated, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_depth_one",
            )?;
            return Ok(());
        }

        if self.backtrace_unwind_rows.is_empty() {
            let status = self
                .status_or_offsets_unavailable(BacktraceStatus::NoUnwindRowsForPc, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_no_rows",
            )?;
            return Ok(());
        }

        let row = match self
            .usable_backtrace_unwind_row_for_pc(&compile_ctx.module_path, compile_ctx.pc_address)
        {
            BacktraceUnwindRowForPc::Usable(row) => row,
            row_status => {
                let initial_status = self.status_for_backtrace_unwind_row_for_pc(&row_status);
                let status = self.status_or_offsets_unavailable(initial_status, offsets_found)?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    status,
                    "bt_status_no_initial_row",
                )?;
                return Ok(());
            }
        };

        let status =
            self.status_or_offsets_unavailable(BacktraceStatus::ReadError, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_tail_initial_status",
        )?;

        let scratch = self.allocate_backtrace_scratch()?;
        let current_fn = self.current_function("initialize bt tail-call state")?;
        let done_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_done");
        let i64_type = self.context.i64_type();
        let ip_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_ip")?;
        let rsp_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_rsp")?;
        let rbp_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_rbp")?;
        let module_bias_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_module_bias")?;
        let module_cookie_ptr =
            self.build_entry_alloca(i64_type, "bt_tail_prefix_module_cookie")?;
        let module_found_ptr =
            self.build_entry_alloca(self.context.bool_type(), "bt_tail_prefix_module_found")?;
        self.builder
            .build_store(module_bias_ptr, module_bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, module_cookie_value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, offsets_found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let runtime_row = self.runtime_row_from_static(row);
        let state = BtRegisterState {
            ip: raw_ip,
            rsp: initial_rsp,
            rbp: initial_rbp,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let initial_store_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_initial_store_frame");
        let initial_stop_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_initial_stop");
        self.builder
            .build_conditional_branch(validation.valid, initial_store_block, initial_stop_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_stop_block);
        let stop_status = self.status_for_backtrace_stop(
            validation.complete,
            validation.error_code,
            offsets_found,
        )?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            stop_status,
            "bt_tail_initial_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_tail_initial_stop_error_code",
        )?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie_value,
            module_bias,
            caller_fallback_found,
            "bt_tail_initial_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame(inst_buffer, 1, frame_module.cookie, next_pc, next.ip, 0)?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            2,
            "bt_tail_initial_frame_count",
        )?;
        let status = if depth == 2 {
            BacktraceStatus::Truncated
        } else {
            BacktraceStatus::ReadError
        };
        let status = self.status_or_offsets_unavailable(status, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_tail_initial_status_after_frame",
        )?;
        self.builder
            .build_store(ip_ptr, next.ip)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rsp_ptr, next.rsp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rbp_ptr, next.rbp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_bias_ptr, frame_module.bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, frame_module.cookie)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, frame_module.found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        if depth == 2 {
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder.position_at_end(done_block);
            return Ok(());
        }

        let prefix_depth = depth.min(BPF_INLINE_BACKTRACE_FRAME_LIMIT);
        for frame_index in 2..prefix_depth {
            let current_ip = self.load_i64(ip_ptr, "bt_tail_prefix_lookup_ip")?;
            let current_module_bias =
                self.load_i64(module_bias_ptr, "bt_tail_prefix_lookup_module_bias")?;
            let current_module_cookie =
                self.load_i64(module_cookie_ptr, "bt_tail_prefix_lookup_module_cookie")?;
            let current_module_found =
                self.load_bool(module_found_ptr, "bt_tail_prefix_lookup_module_found")?;
            let lookup_raw = self.add_signed_offset(current_ip, -1, "bt_tail_prefix_lookup_raw")?;
            let lookup_pc = self.backtrace_lookup_pc_from_raw(
                lookup_raw,
                current_module_bias,
                current_module_found,
            )?;
            let runtime_row = self.lookup_backtrace_unwind_row(
                lookup_pc,
                current_module_cookie,
                &scratch.row,
                &format!("bt_tail_prefix_frame_{frame_index}_row"),
            )?;
            let found_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_row_found");
            let missing_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_row_missing");
            self.builder
                .build_conditional_branch(runtime_row.found, found_block, missing_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(missing_block);
            let status = self.status_or_offsets_unavailable(
                BacktraceStatus::NoUnwindRowsForPc,
                current_module_found,
            )?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_tail_prefix_status_missing_row",
            )?;
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(found_block);
            let state = BtRegisterState {
                ip: self.load_i64(ip_ptr, "bt_tail_prefix_current_ip")?,
                rsp: self.load_i64(rsp_ptr, "bt_tail_prefix_current_rsp")?,
                rbp: self.load_i64(rbp_ptr, "bt_tail_prefix_current_rbp")?,
            };
            let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
            let validation = self.validate_backtrace_next_frame(state, next)?;
            let store_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_store_frame");
            let stop_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_stop");
            self.builder
                .build_conditional_branch(validation.valid, store_block, stop_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(stop_block);
            let stop_status = self.status_for_backtrace_stop(
                validation.complete,
                validation.error_code,
                current_module_found,
            )?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                stop_status,
                "bt_tail_prefix_stop_status",
            )?;
            self.store_u16_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
                validation.error_code,
                "bt_tail_prefix_stop_error_code",
            )?;
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(store_block);
            let frame_module = self.resolve_backtrace_frame_module(
                next.ip,
                current_module_cookie,
                current_module_bias,
                self.backtrace_module_fallback_found(current_module_found),
                &format!("bt_tail_prefix_frame_{frame_index}_module"),
            )?;
            let next_pc =
                self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
            self.store_backtrace_frame(
                inst_buffer,
                frame_index as usize,
                frame_module.cookie,
                next_pc,
                next.ip,
                0,
            )?;
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                frame_index + 1,
                "bt_tail_prefix_frame_count",
            )?;
            let status = if frame_index + 1 == depth {
                BacktraceStatus::Truncated
            } else {
                BacktraceStatus::ReadError
            };
            let status = self.status_or_offsets_unavailable(status, current_module_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_tail_prefix_status_after_frame",
            )?;
            self.builder
                .build_store(ip_ptr, next.ip)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(rsp_ptr, next.rsp)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(rbp_ptr, next.rbp)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_bias_ptr, frame_module.bias)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_cookie_ptr, frame_module.cookie)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_found_ptr, frame_module.found)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            if frame_index + 1 == depth {
                self.builder
                    .build_unconditional_branch(done_block)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
        }

        if prefix_depth == depth {
            self.builder.position_at_end(done_block);
            return Ok(());
        }

        let tail_slot = self.next_backtrace_tail_call_slot;
        self.next_backtrace_tail_call_slot = self.next_backtrace_tail_call_slot.saturating_add(1);
        if self.pending_backtrace_tail_call.is_none() {
            let step_program_name = format!(
                "{}_bt_step",
                self.current_function("name bt tail-call step")?
                    .get_name()
                    .to_string_lossy()
            );
            self.pending_backtrace_tail_call =
                Some(crate::ebpf::context::PendingBacktraceTailCall {
                    step_program_name,
                    depth,
                    instruction_size,
                });
        }

        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;

        let state_ptr = self.lookup_bt_state_ptr(tail_slot as u32)?;
        let state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_state_is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let init_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_init");
        let null_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_null");
        self.builder
            .build_conditional_branch(state_is_null, null_block, init_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(null_block);
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            BacktraceStatus::InternalError as u8,
            "bt_status_state_null",
        )?;
        self.builder
            .build_store(tail_enabled_ptr, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(init_block);
        let tail_ip = self.load_i64(ip_ptr, "bt_tail_state_prefix_ip")?;
        let tail_rsp = self.load_i64(rsp_ptr, "bt_tail_state_prefix_rsp")?;
        let tail_rbp = self.load_i64(rbp_ptr, "bt_tail_state_prefix_rbp")?;
        let tail_module_bias = self.load_i64(module_bias_ptr, "bt_tail_state_module_bias")?;
        let tail_module_cookie = self.load_i64(module_cookie_ptr, "bt_tail_state_module_cookie")?;
        let tail_module_found = self.load_bool(module_found_ptr, "bt_tail_state_module_found")?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            tail_ip,
            "bt_state_ip",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            tail_rsp,
            "bt_state_rsp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            tail_rbp,
            "bt_state_rbp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            tail_module_bias,
            "bt_state_module_bias",
        )?;
        self.store_u64_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            tail_module_cookie,
            "bt_state_module_cookie",
        )?;
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET,
            inst_offset,
            "bt_state_inst_offset",
        )?;
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            self.context.i32_type().const_zero(),
            "bt_state_event_size",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            prefix_depth,
            "bt_state_frame_count",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_REQUESTED_DEPTH_OFFSET,
            depth,
            "bt_state_requested_depth",
        )?;
        let offsets_found_u8 = self.bool_to_u8(tail_module_found, "bt_offsets_found_u8")?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            offsets_found_u8,
            "bt_state_offsets_found",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            1,
            "bt_state_tail_calls",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FLAGS_OFFSET,
            flags,
            "bt_state_flags",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            tail_slot,
            "bt_state_active_slot",
        )?;
        self.store_u16_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_ERROR_CODE_OFFSET,
            BACKTRACE_ERROR_NONE,
            "bt_state_error_code",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            crate::BACKTRACE_TAIL_NO_NEXT_SLOT,
            "bt_state_next_slot",
        )?;
        self.link_backtrace_tail_slot(tail_slot, offsets_found_u8, done_block)?;

        self.builder.position_at_end(done_block);
        Ok(())
    }

    pub(crate) fn finish_event_after_instructions(&mut self) -> Result<()> {
        let Some(plan) = self.pending_backtrace_tail_call.clone() else {
            return self.emit_accumulated_event_output_from_stack_offset();
        };

        let main_block = self.current_insert_block("finish bt tail-call event")?;
        let main_pm_key_alloca = self.pm_key_alloca;
        self.generate_backtrace_tail_call_step_program(&plan)?;
        self.pm_key_alloca = main_pm_key_alloca;
        self.builder.position_at_end(main_block);

        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;
        let enabled_value = self
            .builder
            .build_load(
                self.context.i8_type(),
                tail_enabled_ptr,
                "bt_tail_enabled_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let enabled = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                enabled_value,
                self.context.i8_type().const_zero(),
                "bt_tail_enabled",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self.current_function("finish bt tail-call event")?;
        let tail_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch");
        let output_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_fallback_output");
        self.builder
            .build_conditional_branch(enabled, tail_block, output_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(tail_block);
        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state0_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_tail_dispatch_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch_state_ok");
        self.builder
            .build_conditional_branch(state0_is_null, output_block, state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state_ok_block);
        let active_slot = self.load_row_i8(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            "bt_tail_dispatch_active_slot",
        )?;
        let state_ptr = self.lookup_bt_state_ptr_dynamic(active_slot)?;
        let state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_tail_dispatch_active_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let active_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch_active_state_ok");
        self.builder
            .build_conditional_branch(state_is_null, output_block, active_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(active_state_ok_block);
        let event_size = self
            .builder
            .build_load(
                self.context.i32_type(),
                self.event_offset_alloca.ok_or_else(|| {
                    CodeGenError::LLVMError("event_offset not allocated in entry block".to_string())
                })?,
                "bt_tail_event_size",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            event_size,
            "bt_tail_state_event_size",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.builder
            .build_unconditional_branch(output_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(output_block);
        self.emit_accumulated_event_output_from_stack_offset()
    }

    pub(super) fn generate_backtrace_tail_call_step_program(
        &mut self,
        plan: &crate::ebpf::context::PendingBacktraceTailCall,
    ) -> Result<()> {
        self.create_tail_call_function(&plan.step_program_name)?;
        let current_fn = self.current_function("generate bt tail-call step")?;
        let return_block = self
            .context
            .append_basic_block(current_fn, "bt_step_return");
        let state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_state_ok");
        let accum_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_accum_ok");
        let bounds_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_bounds_ok");
        let inst_bounds_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_inst_bounds_ok");
        let finalize_block = self
            .context
            .append_basic_block(current_fn, "bt_step_finalize");

        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_step_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(state_is_null, return_block, state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state_ok_block);
        let active_slot = self.load_row_i8(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            "bt_step_active_slot",
        )?;
        let state_ptr = self.lookup_bt_state_ptr_dynamic(active_slot)?;
        let active_state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_step_active_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let active_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_active_state_ok");
        self.builder
            .build_conditional_branch(active_state_is_null, return_block, active_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(active_state_ok_block);
        let accum_buffer = self.lookup_percpu_value_ptr("event_accum_buffer", 0)?;
        let accum_is_null = self
            .builder
            .build_is_null(accum_buffer, "bt_step_accum_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(accum_is_null, return_block, accum_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(accum_ok_block);
        let inst_offset = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET,
            "bt_step_inst_offset",
        )?;
        let event_size = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            "bt_step_event_size",
        )?;
        let max_event_size = self
            .context
            .i32_type()
            .const_int(self.compile_options.max_trace_event_size as u64, false);
        let max_inst_offset = self.context.i32_type().const_int(
            self.compile_options
                .max_trace_event_size
                .saturating_sub(plan.instruction_size as u32) as u64,
            false,
        );
        let inst_in_bounds = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                inst_offset,
                max_inst_offset,
                "bt_step_inst_offset_in_bounds",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(inst_in_bounds, inst_bounds_ok_block, return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(inst_bounds_ok_block);
        let event_in_bounds = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                event_size,
                max_event_size,
                "bt_step_event_size_in_bounds",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(event_in_bounds, bounds_ok_block, return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(bounds_ok_block);
        let inst_offset_i64 = self
            .builder
            .build_int_z_extend(
                inst_offset,
                self.context.i64_type(),
                "bt_step_inst_offset_i64",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let inst_buffer =
            self.dynamic_byte_gep(accum_buffer, inst_offset_i64, "bt_step_inst_buffer")?;
        let scratch = self.allocate_backtrace_scratch()?;
        for _ in 0..BPF_BACKTRACE_FRAMES_PER_TAIL_CALL {
            self.generate_backtrace_tail_call_step_iteration(
                plan.depth,
                state_ptr,
                inst_buffer,
                &scratch,
                finalize_block,
            )?;
        }

        let tail_calls = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            "bt_step_tail_calls",
        )?;
        let can_tail_call = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULT,
                tail_calls,
                self.context
                    .i8_type()
                    .const_int(BPF_BACKTRACE_MAX_STEP_INVOCATIONS as u64, false),
                "bt_step_can_tail_call",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let self_tail_block = self
            .context
            .append_basic_block(current_fn, "bt_step_self_tail");
        let tail_budget_done = self
            .context
            .append_basic_block(current_fn, "bt_step_tail_budget_done");
        self.builder
            .build_conditional_branch(can_tail_call, self_tail_block, tail_budget_done)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(tail_budget_done);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(self_tail_block);
        let next_tail_calls = self
            .builder
            .build_int_add(
                tail_calls,
                self.context.i8_type().const_int(1, false),
                "bt_step_next_tail_calls",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            next_tail_calls,
            "bt_step_store_tail_calls",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::InternalError,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(finalize_block);
        let next_slot = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            "bt_final_next_slot",
        )?;
        let has_next_slot = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next_slot,
                self.context
                    .i8_type()
                    .const_int(crate::BACKTRACE_TAIL_NO_NEXT_SLOT as u64, false),
                "bt_final_has_next_slot",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let tail_calls = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            "bt_final_tail_calls",
        )?;
        let can_tail_call_next = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULT,
                tail_calls,
                self.context
                    .i8_type()
                    .const_int(BPF_BACKTRACE_MAX_STEP_INVOCATIONS as u64, false),
                "bt_final_can_tail_call_next",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_continue_next = self
            .builder
            .build_and(
                has_next_slot,
                can_tail_call_next,
                "bt_final_should_continue_next_slot",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_final_next_slot");
        let emit_block = self.context.append_basic_block(current_fn, "bt_final_emit");
        self.builder
            .build_conditional_branch(should_continue_next, next_slot_block, emit_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(next_slot_block);
        self.store_u8_value(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            next_slot,
            "bt_store_active_slot",
        )?;
        let next_state_ptr = self.lookup_bt_state_ptr_dynamic(next_slot)?;
        let next_state_is_null = self
            .builder
            .build_is_null(next_state_ptr, "bt_next_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_next_state_ok");
        self.builder
            .build_conditional_branch(next_state_is_null, emit_block, next_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(next_state_ok_block);
        self.store_state_i32(
            next_state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            event_size,
            "bt_next_slot_event_size",
        )?;
        let next_tail_calls = self
            .builder
            .build_int_add(
                tail_calls,
                self.context.i8_type().const_int(1, false),
                "bt_next_slot_tail_calls",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            next_state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            next_tail_calls,
            "bt_next_slot_store_tail_calls",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.builder
            .build_unconditional_branch(emit_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(emit_block);
        self.emit_tail_final_event(state_ptr, accum_buffer)?;
        self.builder
            .build_unconditional_branch(return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(return_block);
        self.build_return_zero()
    }

    pub(super) fn generate_backtrace_tail_call_step_iteration(
        &mut self,
        depth: u8,
        state_ptr: PointerValue<'ctx>,
        inst_buffer: PointerValue<'ctx>,
        scratch: &BtScratch<'ctx>,
        finalize_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("generate bt tail-call step iteration")?;
        let depth_block = self
            .context
            .append_basic_block(current_fn, "bt_step_depth_done");
        let unwind_block = self
            .context
            .append_basic_block(current_fn, "bt_step_unwind");
        let frame_count = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            "bt_step_frame_count",
        )?;
        let depth_value = self.context.i8_type().const_int(depth as u64, false);
        let at_depth = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                frame_count,
                depth_value,
                "bt_step_at_depth",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(at_depth, depth_block, unwind_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(depth_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(unwind_block);
        let current_ip = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            "bt_step_current_ip",
        )?;
        let current_rsp = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            "bt_step_current_rsp",
        )?;
        let current_rbp = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            "bt_step_current_rbp",
        )?;
        let module_bias = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            "bt_step_module_bias",
        )?;
        let module_cookie = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            "bt_step_module_cookie",
        )?;
        let offsets_found_u8 = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            "bt_step_offsets_found_u8",
        )?;
        let offsets_found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                offsets_found_u8,
                self.context.i8_type().const_zero(),
                "bt_step_offsets_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let caller_fallback_found = self.backtrace_module_fallback_found(offsets_found);
        let is_first_unwind = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                frame_count,
                self.context.i8_type().const_int(1, false),
                "bt_step_first_unwind",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let caller_lookup_ip =
            self.add_signed_offset(current_ip, -1, "bt_step_caller_lookup_ip")?;
        let lookup_raw = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_first_unwind,
                current_ip.into(),
                caller_lookup_ip.into(),
                "bt_step_lookup_raw",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let lookup_pc =
            self.backtrace_lookup_pc_from_raw(lookup_raw, module_bias, offsets_found)?;
        let runtime_row = self.lookup_backtrace_unwind_row(
            lookup_pc,
            module_cookie,
            &scratch.row,
            "bt_step_row",
        )?;
        let row_found_block = self
            .context
            .append_basic_block(current_fn, "bt_step_row_found");
        let row_missing_block = self
            .context
            .append_basic_block(current_fn, "bt_step_row_missing");
        self.builder
            .build_conditional_branch(runtime_row.found, row_found_block, row_missing_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(row_missing_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::NoUnwindRowsForPc,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(row_found_block);
        let state = BtRegisterState {
            ip: current_ip,
            rsp: current_rsp,
            rbp: current_rbp,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let store_block = self
            .context
            .append_basic_block(current_fn, "bt_step_store_frame");
        let stop_block = self.context.append_basic_block(current_fn, "bt_step_stop");
        self.builder
            .build_conditional_branch(validation.valid, store_block, stop_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(stop_block);
        let stop_status = self.status_for_backtrace_stop(
            validation.complete,
            validation.error_code,
            offsets_found,
        )?;
        self.store_u8_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_STATUS_OFFSET,
            stop_status,
            "bt_step_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_step_stop_error",
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie,
            module_bias,
            caller_fallback_found,
            "bt_step_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame_dynamic(
            inst_buffer,
            frame_count,
            depth.saturating_sub(1),
            frame_module.cookie,
            next_pc,
            next.ip,
        )?;
        let next_count = self
            .builder
            .build_int_add(
                frame_count,
                self.context.i8_type().const_int(1, false),
                "bt_step_next_frame_count",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            next_count,
            "bt_step_state_frame_count",
        )?;
        self.store_u8_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            next_count,
            "bt_step_inst_frame_count",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            next.ip,
            "bt_step_state_next_ip",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            next.rsp,
            "bt_step_state_next_rsp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            next.rbp,
            "bt_step_state_next_rbp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            frame_module.bias,
            "bt_step_state_next_module_bias",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            frame_module.cookie,
            "bt_step_state_next_module_cookie",
        )?;
        let next_offsets_found_u8 =
            self.bool_to_u8(frame_module.found, "bt_step_next_offsets_found_u8")?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            next_offsets_found_u8,
            "bt_step_state_next_offsets_found",
        )?;

        let reached_depth = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                next_count,
                depth_value,
                "bt_step_reached_depth",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let reached_depth_block = self
            .context
            .append_basic_block(current_fn, "bt_step_reached_depth");
        let continue_block = self
            .context
            .append_basic_block(current_fn, "bt_step_continue");
        self.builder
            .build_conditional_branch(reached_depth, reached_depth_block, continue_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(reached_depth_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(continue_block);
        Ok(())
    }

    pub(super) fn emit_bpf_tail_call(&mut self, index: u32) -> Result<()> {
        let ctx = self.get_pt_regs_parameter()?;
        let prog_array = self.lookup_bt_prog_array_ptr()?;
        let args = [
            ctx.into(),
            prog_array.into(),
            self.context
                .i32_type()
                .const_int(index as u64, false)
                .into(),
        ];
        let _ = self.create_bpf_helper_call(
            BPF_FUNC_tail_call as u64,
            &args,
            self.context.i64_type().into(),
            "bt_bpf_tail_call",
        )?;
        Ok(())
    }

    pub(super) fn store_tail_backtrace_status(
        &self,
        inst_buffer: PointerValue<'ctx>,
        status: BacktraceStatus,
        error_code: u16,
    ) -> Result<()> {
        self.store_u8_const(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_STATUS_OFFSET,
            status as u8,
            "bt_tail_status",
        )?;
        self.store_u16_const(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            error_code,
            "bt_tail_error_code",
        )
    }

    pub(super) fn emit_tail_final_event(
        &mut self,
        state_ptr: PointerValue<'ctx>,
        accum_buffer: PointerValue<'ctx>,
    ) -> Result<()> {
        let event_size = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            "bt_final_event_size",
        )?;
        self.emit_accumulated_event_output(accum_buffer, event_size)
    }

    pub(super) fn build_return_zero(&mut self) -> Result<()> {
        self.builder
            .build_return(Some(&self.context.i32_type().const_zero()))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }
}

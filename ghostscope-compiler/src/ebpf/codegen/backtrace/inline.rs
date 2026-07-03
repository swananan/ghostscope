use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Generate a DWARF-backed Backtrace instruction.
    ///
    /// eBPF records `(module_cookie, normalized_pc, raw_ip)` frames and advances
    /// the unwind state from compact DWARF CFI rows. Userspace owns final source
    /// line and inline-chain symbolization.
    pub(super) fn generate_inline_backtrace_instruction(
        &mut self,
        plan: &BacktraceInstructionPlan,
    ) -> Result<()> {
        let depth = plan.depth;
        let flags = plan.flags;
        info!("Generating Backtrace instruction: depth={}", depth);

        let payload_size = plan.payload_size;
        let instruction_size = plan.instruction_size;
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

        let row = self
            .usable_backtrace_unwind_row_for_pc(&compile_ctx.module_path, compile_ctx.pc_address);
        let initial_status = self.status_for_backtrace_unwind_row_for_pc(&row);
        let status = self.status_or_offsets_unavailable(initial_status, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_initial_status",
        )?;

        let BacktraceUnwindRowForPc::Usable(row) = row else {
            return Ok(());
        };

        let i64_type = self.context.i64_type();
        let ip_ptr = self.build_entry_alloca(i64_type, "bt_state_ip")?;
        let rsp_ptr = self.build_entry_alloca(i64_type, "bt_state_rsp")?;
        let rbp_ptr = self.build_entry_alloca(i64_type, "bt_state_rbp")?;
        let module_bias_ptr = self.build_entry_alloca(i64_type, "bt_state_module_bias")?;
        let module_cookie_ptr = self.build_entry_alloca(i64_type, "bt_state_module_cookie")?;
        let module_found_ptr =
            self.build_entry_alloca(self.context.bool_type(), "bt_state_module_found")?;
        let scratch = self.allocate_backtrace_scratch()?;
        self.builder
            .build_store(ip_ptr, raw_ip)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let initial_rsp = self.load_dwarf_register_i64(X86_64_DWARF_RSP, pt_regs)?;
        let initial_rbp = self.load_dwarf_register_i64(X86_64_DWARF_RBP, pt_regs)?;
        self.builder
            .build_store(rsp_ptr, initial_rsp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rbp_ptr, initial_rbp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_bias_ptr, module_bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, module_cookie_value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, offsets_found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let current_fn = self.current_function("generate DWARF backtrace")?;
        let done = self.context.append_basic_block(current_fn, "bt_done");

        let runtime_row = self.runtime_row_from_static(row);
        let state = BtRegisterState {
            ip: self.load_i64(ip_ptr, "bt_initial_current_ip")?,
            rsp: self.load_i64(rsp_ptr, "bt_initial_current_rsp")?,
            rbp: self.load_i64(rbp_ptr, "bt_initial_current_rbp")?,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let initial_store_block = self
            .context
            .append_basic_block(current_fn, "bt_initial_store_frame");
        let initial_stop_block = self
            .context
            .append_basic_block(current_fn, "bt_initial_stop");
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
            "bt_initial_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_initial_stop_error_code",
        )?;
        self.builder
            .build_unconditional_branch(done)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie_value,
            module_bias,
            caller_fallback_found,
            "bt_initial_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame(inst_buffer, 1, frame_module.cookie, next_pc, next.ip, 0)?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            2,
            "bt_initial_frame_count",
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
            "bt_initial_status_after_frame",
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
                .build_unconditional_branch(done)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else if self.backtrace_unwind_rows.is_empty() {
            let status = self
                .status_or_offsets_unavailable(BacktraceStatus::NoUnwindRowsForPc, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_no_rows",
            )?;
            self.builder
                .build_unconditional_branch(done)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else {
            let inline_depth = depth.min(BPF_INLINE_BACKTRACE_FRAME_LIMIT);
            for frame_index in 2..inline_depth {
                let current_ip = self.load_i64(ip_ptr, "bt_lookup_ip")?;
                let current_module_bias =
                    self.load_i64(module_bias_ptr, "bt_lookup_module_bias")?;
                let current_module_cookie =
                    self.load_i64(module_cookie_ptr, "bt_lookup_module_cookie")?;
                let current_module_found =
                    self.load_bool(module_found_ptr, "bt_lookup_module_found")?;
                let lookup_raw = self.add_signed_offset(current_ip, -1, "bt_lookup_raw")?;
                let lookup_pc = self.backtrace_lookup_pc_from_raw(
                    lookup_raw,
                    current_module_bias,
                    current_module_found,
                )?;
                let runtime_row = self.lookup_backtrace_unwind_row(
                    lookup_pc,
                    current_module_cookie,
                    &scratch.row,
                    &format!("bt_frame_{frame_index}_row"),
                )?;
                let found_block = self.context.append_basic_block(current_fn, "bt_row_found");
                let missing_block = self
                    .context
                    .append_basic_block(current_fn, "bt_row_missing");
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
                    "bt_status_missing_row",
                )?;
                self.builder
                    .build_unconditional_branch(done)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(found_block);
                let state = BtRegisterState {
                    ip: self.load_i64(ip_ptr, "bt_current_ip")?,
                    rsp: self.load_i64(rsp_ptr, "bt_current_rsp")?,
                    rbp: self.load_i64(rbp_ptr, "bt_current_rbp")?,
                };
                let next =
                    self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
                let validation = self.validate_backtrace_next_frame(state, next)?;
                let store_block = self
                    .context
                    .append_basic_block(current_fn, "bt_store_frame");
                let stop_block = self.context.append_basic_block(current_fn, "bt_stop");
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
                    "bt_status_stop",
                )?;
                self.store_u16_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
                    validation.error_code,
                    "bt_error_code_stop",
                )?;
                self.builder
                    .build_unconditional_branch(done)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(store_block);
                let frame_module = self.resolve_backtrace_frame_module(
                    next.ip,
                    current_module_cookie,
                    current_module_bias,
                    self.backtrace_module_fallback_found(current_module_found),
                    &format!("bt_frame_{frame_index}_module"),
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
                    "bt_frame_count",
                )?;
                let next_status = if frame_index + 1 == inline_depth {
                    BacktraceStatus::Truncated
                } else {
                    BacktraceStatus::ReadError
                };
                let next_status =
                    self.status_or_offsets_unavailable(next_status, current_module_found)?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    next_status,
                    "bt_status_after_frame",
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

                if frame_index + 1 == inline_depth {
                    self.builder
                        .build_unconditional_branch(done)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                }
            }
        }

        self.builder.position_at_end(done);
        Ok(())
    }
}

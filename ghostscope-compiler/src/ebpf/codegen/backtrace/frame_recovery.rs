use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn recover_next_frame_from_runtime_row(
        &mut self,
        row: &RuntimeBtUnwindRow<'ctx>,
        state: BtRegisterState<'ctx>,
        scratch: &BtScratch<'ctx>,
    ) -> Result<BtNextFrame<'ctx>> {
        let cfa_base = self.select_register_state(row.cfa_register, state, "bt_cfa_base")?;
        let cfa = self
            .builder
            .build_int_add(cfa_base, row.cfa_offset, "bt_runtime_cfa")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let ra_addr = self
            .builder
            .build_int_add(cfa, row.ra_offset, "bt_runtime_ra_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(
                scratch.next_error_code_ptr,
                self.context
                    .i16_type()
                    .const_int(BACKTRACE_ERROR_NONE as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let (ra_from_memory, ra_read_failed) = self.generate_memory_read_with_fail_flag(
            RuntimeAddress::available(ra_addr, self.context),
            MemoryAccessSize::U64,
            "bt_ra_read",
        )?;
        let ra_from_memory = ra_from_memory.into_int_value();
        let ra_uses_memory = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_AT_CFA_OFFSET,
            "bt_ra_at_kind",
        )?;
        let ra_read_failed = self
            .builder
            .build_and(ra_read_failed, ra_uses_memory, "bt_ra_read_failed")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_backtrace_error_code_if(
            scratch.next_error_code_ptr,
            ra_read_failed,
            BACKTRACE_ERROR_RETURN_ADDRESS_READ,
            "bt_ra_error_code",
        )?;
        let ra_from_val = self
            .builder
            .build_int_add(cfa, row.ra_offset, "bt_runtime_ra_val")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ra_from_register = self.select_register_state(row.ra_register, state, "bt_ra_reg")?;
        let ra_is_val = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_VAL_CFA_OFFSET,
            "bt_ra_val_kind",
        )?;
        let ra_is_register = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_REGISTER,
            "bt_ra_reg_kind",
        )?;
        let ra_is_same = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_SAME_VALUE,
            "bt_ra_same_kind",
        )?;
        let ra_is_register_like = self
            .builder
            .build_or(ra_is_register, ra_is_same, "bt_ra_register_like")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ra_value_or_memory = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ra_is_val,
                ra_from_val.into(),
                ra_from_memory.into(),
                "bt_ra_val_or_memory",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let next_ip = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ra_is_register_like,
                ra_from_register.into(),
                ra_value_or_memory.into(),
                "bt_next_ip",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let next_rbp = self.recover_rbp_from_runtime_row(
            row,
            cfa,
            state,
            scratch.next_rbp_ptr,
            scratch.next_error_code_ptr,
        )?;
        let error_code = self.load_i16(scratch.next_error_code_ptr, "bt_next_error_code_value")?;

        Ok(BtNextFrame {
            ip: next_ip,
            rsp: cfa,
            rbp: next_rbp,
            error_code,
        })
    }

    pub(super) fn validate_backtrace_next_frame(
        &self,
        state: BtRegisterState<'ctx>,
        next: BtNextFrame<'ctx>,
    ) -> Result<BtFrameValidation<'ctx>> {
        let i64_type = self.context.i64_type();
        let i16_type = self.context.i16_type();
        let zero = i64_type.const_zero();
        let zero_i16 = i16_type.const_zero();
        let min_user_ip = i64_type.const_int(0x1000, false);
        let high_byte_mask = i64_type.const_int(0xff00_0000_0000_0000, false);

        let no_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                next.error_code,
                zero_i16,
                "bt_no_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_high_enough = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                next.ip,
                min_user_ip,
                "bt_next_ip_user_min",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_high_byte = self
            .builder
            .build_and(next.ip, high_byte_mask, "bt_next_ip_high_byte")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_is_zero = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, next.ip, zero, "bt_next_ip_zero")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_not_kernel_like = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                ip_high_byte,
                zero,
                "bt_next_ip_not_kernel_like",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_nonzero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.rsp,
                zero,
                "bt_next_cfa_nonzero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_changed = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.rsp,
                state.rsp,
                "bt_next_cfa_changed",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_changed = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.ip,
                state.ip,
                "bt_next_ip_changed",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_progress = self
            .builder
            .build_or(cfa_changed, ip_changed, "bt_next_frame_progress")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let ip_valid = self
            .builder
            .build_and(ip_high_enough, ip_not_kernel_like, "bt_next_ip_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_valid = self
            .builder
            .build_and(cfa_nonzero, cfa_progress, "bt_next_cfa_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_shape_valid = self
            .builder
            .build_and(ip_valid, cfa_valid, "bt_next_frame_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let valid = self
            .builder
            .build_and(
                no_read_error,
                frame_shape_valid,
                "bt_next_frame_valid_no_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let complete = self
            .builder
            .build_and(no_read_error, ip_is_zero, "bt_next_frame_complete")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let mut error_code = next.error_code;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            ip_high_enough,
            BACKTRACE_ERROR_NEXT_IP_BELOW_USER,
            "bt_next_ip_below_user_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            ip_not_kernel_like,
            BACKTRACE_ERROR_NEXT_IP_KERNEL_LIKE,
            "bt_next_ip_kernel_like_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            cfa_nonzero,
            BACKTRACE_ERROR_NEXT_CFA_ZERO,
            "bt_next_cfa_zero_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            cfa_progress,
            BACKTRACE_ERROR_NEXT_CFA_NOT_ADVANCING,
            "bt_next_cfa_not_advancing_code",
        )?;
        error_code = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                complete,
                self.context
                    .i16_type()
                    .const_int(BACKTRACE_ERROR_NONE as u64, false)
                    .into(),
                error_code.into(),
                "bt_complete_error_code",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        Ok(BtFrameValidation {
            valid,
            complete,
            error_code,
        })
    }

    pub(super) fn select_backtrace_error_code_if(
        &self,
        current: IntValue<'ctx>,
        condition_ok: IntValue<'ctx>,
        error_code: u16,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let i16_type = self.context.i16_type();
        let current_is_none = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current,
                i16_type.const_int(BACKTRACE_ERROR_NONE as u64, false),
                &format!("{name}_current_none"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let condition_failed = self
            .builder
            .build_not(condition_ok, &format!("{name}_condition_failed"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_set = self
            .builder
            .build_and(
                current_is_none,
                condition_failed,
                &format!("{name}_should_set"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                should_set,
                i16_type.const_int(error_code as u64, false).into(),
                current.into(),
                name,
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn store_backtrace_error_code_if(
        &self,
        error_code_ptr: PointerValue<'ctx>,
        condition: IntValue<'ctx>,
        error_code: u16,
        name: &str,
    ) -> Result<()> {
        let current = self.load_i16(error_code_ptr, &format!("{name}_current"))?;
        let i16_type = self.context.i16_type();
        let current_is_none = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current,
                i16_type.const_int(BACKTRACE_ERROR_NONE as u64, false),
                &format!("{name}_current_none"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_set = self
            .builder
            .build_and(condition, current_is_none, &format!("{name}_should_set"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                should_set,
                i16_type.const_int(error_code as u64, false).into(),
                current.into(),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(error_code_ptr, next)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn recover_rbp_from_runtime_row(
        &mut self,
        row: &RuntimeBtUnwindRow<'ctx>,
        cfa: IntValue<'ctx>,
        state: BtRegisterState<'ctx>,
        next_rbp_ptr: PointerValue<'ctx>,
        next_error_code_ptr: PointerValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let is_at = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_AT_CFA_OFFSET,
            "bt_rbp_at_kind",
        )?;
        let cfa_uses_rbp = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                row.cfa_register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RBP as u64, false),
                "bt_rbp_cfa_uses_rbp",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_offset_is_frame_pointer_call_frame = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                row.cfa_offset,
                self.context.i64_type().const_int(16, false),
                "bt_rbp_cfa_offset_is_16",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_pointer_call_frame = self
            .builder
            .build_and(
                cfa_uses_rbp,
                cfa_offset_is_frame_pointer_call_frame,
                "bt_rbp_frame_pointer_call_frame",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_at = self
            .builder
            .build_or(
                is_at,
                frame_pointer_call_frame,
                "bt_rbp_at_or_frame_pointer",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_offset = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                frame_pointer_call_frame,
                self.context
                    .i64_type()
                    .const_int((-16i64) as u64, true)
                    .into(),
                row.rbp_offset.into(),
                "bt_rbp_effective_offset",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let current_fn = self.current_function("recover bt rbp")?;
        let at_block = self.context.append_basic_block(current_fn, "bt_rbp_at");
        let non_at_block = self.context.append_basic_block(current_fn, "bt_rbp_non_at");
        let join_block = self.context.append_basic_block(current_fn, "bt_rbp_join");
        self.builder
            .build_conditional_branch(is_at, at_block, non_at_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(at_block);
        let rbp_addr = self
            .builder
            .build_int_add(cfa, rbp_offset, "bt_runtime_rbp_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let (rbp_from_memory, rbp_read_failed) = self.generate_memory_read_with_fail_flag(
            RuntimeAddress::available(rbp_addr, self.context),
            MemoryAccessSize::U64,
            "bt_rbp_read",
        )?;
        self.store_backtrace_error_code_if(
            next_error_code_ptr,
            rbp_read_failed,
            BACKTRACE_ERROR_FRAME_POINTER_READ,
            "bt_rbp_error_code",
        )?;
        self.builder
            .build_store(next_rbp_ptr, rbp_from_memory.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(join_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(non_at_block);
        let rbp_from_val = self
            .builder
            .build_int_add(cfa, row.rbp_offset, "bt_runtime_rbp_val")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_from_register =
            self.select_register_state(row.rbp_register, state, "bt_rbp_reg")?;
        let rbp_is_val = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_VAL_CFA_OFFSET,
            "bt_rbp_val_kind",
        )?;
        let rbp_is_register = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_REGISTER,
            "bt_rbp_reg_kind",
        )?;
        let rbp_is_same = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_SAME_VALUE,
            "bt_rbp_same_kind",
        )?;
        let rbp_is_register_like = self
            .builder
            .build_or(rbp_is_register, rbp_is_same, "bt_rbp_register_like")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_value_or_current = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                rbp_is_val,
                rbp_from_val.into(),
                state.rbp.into(),
                "bt_rbp_val_or_current",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let rbp_non_at = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                rbp_is_register_like,
                rbp_from_register.into(),
                rbp_value_or_current.into(),
                "bt_rbp_non_at_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.builder
            .build_store(next_rbp_ptr, rbp_non_at)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(join_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(join_block);
        self.load_i64(next_rbp_ptr, "bt_next_rbp_value")
    }

    pub(super) fn select_register_state(
        &self,
        register: IntValue<'ctx>,
        state: BtRegisterState<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let is_rbp = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RBP as u64, false),
                &format!("{name}_is_rbp"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_rip = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RIP as u64, false),
                &format!("{name}_is_rip"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_or_rsp = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_rbp,
                state.rbp.into(),
                state.rsp.into(),
                &format!("{name}_rbp_or_rsp"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_rip,
                state.ip.into(),
                rbp_or_rsp.into(),
                name,
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn is_recovery_kind(
        &self,
        kind: IntValue<'ctx>,
        expected: u8,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        self.builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                kind,
                self.context.i8_type().const_int(expected as u64, false),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn lookup_bt_unwind_row_ptr(
        &mut self,
        row_index: IntValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let map_global = self
            .module
            .get_global("bt_unwind_rows")
            .ok_or_else(|| CodeGenError::LLVMError("bt_unwind_rows map not found".to_string()))?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                "bt_unwind_rows_map_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let key_arr_ty = i32_type.array_type(4);
        let zero = i32_type.const_zero();
        // SAFETY: pm_key_alloca is a [4 x i32] entry-block alloca and [0, 0]
        // addresses its first element, which is sufficient for an Array u32 key.
        let key_ptr = unsafe {
            self.builder
                .build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[zero, zero],
                    "bt_unwind_row_key_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, row_index)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, "bt_unwind_row_key_void")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            "bt_unwind_row_lookup",
        )?;
        match result {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_unwind_rows lookup did not return pointer".to_string(),
            )),
        }
    }

    pub(super) fn lookup_bt_state_ptr(&mut self, key_const: u32) -> Result<PointerValue<'ctx>> {
        self.lookup_percpu_value_ptr("bt_state", key_const)
    }

    pub(super) fn lookup_bt_state_ptr_dynamic(
        &mut self,
        state_index: IntValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let map_global = self
            .map_manager
            .get_map(&self.module, "bt_state")
            .map_err(|e| CodeGenError::LLVMError(format!("Map not found bt_state: {e}")))?;
        let map_ptr = self
            .builder
            .build_bit_cast(map_global, ptr_type, "bt_state_map_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key = match state_index
            .get_type()
            .get_bit_width()
            .cmp(&i32_type.get_bit_width())
        {
            std::cmp::Ordering::Equal => state_index,
            std::cmp::Ordering::Less => self
                .builder
                .build_int_z_extend(state_index, i32_type, "bt_state_key_i32")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(state_index, i32_type, "bt_state_key_i32")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
        };

        let key_arr_ty = i32_type.array_type(4);
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let zero = i32_type.const_zero();
        // SAFETY: pm_key_alloca is a [4 x i32] entry-block alloca and [0, 0]
        // addresses its first element, which is sufficient for an Array u32 key.
        let key_ptr = unsafe {
            self.builder
                .build_gep(key_arr_ty, key_alloca, &[zero, zero], "bt_state_key_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, key)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, "bt_state_key_void")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            "bt_state_lookup",
        )?;
        match result {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_state lookup did not return pointer".to_string(),
            )),
        }
    }

    pub(super) fn lookup_bt_prog_array_ptr(&mut self) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("bt_prog_array")
            .ok_or_else(|| CodeGenError::LLVMError("bt_prog_array map not found".to_string()))?;
        let map_ptr = self
            .builder
            .build_bit_cast(map_global.as_pointer_value(), ptr_type, "bt_prog_array_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        match map_ptr {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_prog_array cast did not return pointer".to_string(),
            )),
        }
    }

    pub(super) fn get_or_create_backtrace_tail_enabled_flag(
        &mut self,
    ) -> Result<PointerValue<'ctx>> {
        if let Some(ptr) = self.backtrace_tail_enabled_alloca {
            return Ok(ptr);
        }

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for bt tail flag allocation".to_string())
        })?;
        let current_fn = self.current_function("allocate bt tail flag")?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for bt tail flag allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(self.context.i8_type(), "bt_tail_enabled")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(alloca, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);
        self.backtrace_tail_enabled_alloca = Some(alloca);
        Ok(alloca)
    }

    pub(super) fn get_or_create_backtrace_tail_last_slot(&mut self) -> Result<PointerValue<'ctx>> {
        if let Some(ptr) = self.backtrace_tail_last_slot_alloca {
            return Ok(ptr);
        }

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for bt tail slot allocation".to_string())
        })?;
        let current_fn = self.current_function("allocate bt tail slot")?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for bt tail slot allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(self.context.i8_type(), "bt_tail_last_slot")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(
                alloca,
                self.context
                    .i8_type()
                    .const_int(crate::BACKTRACE_TAIL_NO_NEXT_SLOT as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);
        self.backtrace_tail_last_slot_alloca = Some(alloca);
        Ok(alloca)
    }

    pub(super) fn link_backtrace_tail_slot(
        &mut self,
        tail_slot: u8,
        offsets_found_u8: IntValue<'ctx>,
        done_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("link bt tail slot")?;
        let offsets_found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                offsets_found_u8,
                self.context.i8_type().const_zero(),
                "bt_tail_link_offsets_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let link_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_slot");
        self.builder
            .build_conditional_branch(offsets_found, link_block, done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(link_block);
        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state0_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_tail_link_state0_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let state0_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_state0_ok");
        self.builder
            .build_conditional_branch(state0_is_null, done_block, state0_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state0_ok_block);
        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;
        let last_slot_ptr = self.get_or_create_backtrace_tail_last_slot()?;
        let enabled_value = self
            .builder
            .build_load(
                self.context.i8_type(),
                tail_enabled_ptr,
                "bt_tail_link_enabled_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let has_prev_slot = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                enabled_value,
                self.context.i8_type().const_zero(),
                "bt_tail_link_has_prev",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let first_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_first");
        let append_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_append");
        let linked_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_linked");
        self.builder
            .build_conditional_branch(has_prev_slot, append_slot_block, first_slot_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(first_slot_block);
        self.store_u8_const(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            tail_slot,
            "bt_tail_link_active_slot",
        )?;
        self.builder
            .build_unconditional_branch(linked_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(append_slot_block);
        let prev_slot = self.load_i8(last_slot_ptr, "bt_tail_link_prev_slot")?;
        let prev_state_ptr = self.lookup_bt_state_ptr_dynamic(prev_slot)?;
        let prev_state_is_null = self
            .builder
            .build_is_null(prev_state_ptr, "bt_tail_link_prev_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let prev_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_prev_ok");
        self.builder
            .build_conditional_branch(prev_state_is_null, first_slot_block, prev_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(prev_state_ok_block);
        self.store_u8_const(
            prev_state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            tail_slot,
            "bt_tail_link_prev_next_slot",
        )?;
        self.builder
            .build_unconditional_branch(linked_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(linked_block);
        self.builder
            .build_store(
                last_slot_ptr,
                self.context.i8_type().const_int(tail_slot as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(tail_enabled_ptr, self.context.i8_type().const_int(1, false))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn store_state_i64(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<()> {
        self.store_u64_value(base, offset, value, name)
    }

    pub(super) fn store_state_i32(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<()> {
        let ptr = self.byte_gep(base, offset, name)?;
        let ptr = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_u32_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(ptr, value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn load_state_i32(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(base, offset, name)?;
        let ptr = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_u32_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(self
            .builder
            .build_load(self.context.i32_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_row_i64(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        let ptr = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_i64_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(self
            .builder
            .build_load(self.context.i64_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_row_i16(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        Ok(self
            .builder
            .build_load(self.context.i16_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_row_i8(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        Ok(self
            .builder
            .build_load(self.context.i8_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_i8(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i8_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_bool(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.bool_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_i32(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i32_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_i16(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i16_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_i64(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i64_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    pub(super) fn load_dwarf_register_i64(
        &mut self,
        reg: u16,
        pt_regs: PointerValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let value = self.load_register_value(reg, pt_regs)?;
        match value {
            BasicValueEnum::IntValue(value) => Ok(value),
            _ => Err(CodeGenError::RegisterMappingError(format!(
                "DWARF register {reg} did not load as integer"
            ))),
        }
    }

    pub(super) fn add_signed_offset(
        &self,
        base: IntValue<'ctx>,
        offset: i64,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        if offset == 0 {
            return Ok(base);
        }
        self.builder
            .build_int_add(
                base,
                self.context.i64_type().const_int(offset as u64, true),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn normalized_pc_from_raw(
        &self,
        raw_ip: IntValue<'ctx>,
        module_bias: IntValue<'ctx>,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let rebased = self
            .builder
            .build_int_sub(raw_ip, module_bias, "bt_normalized_pc")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                rebased.into(),
                raw_ip.into(),
                "bt_pc_or_raw",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }
}

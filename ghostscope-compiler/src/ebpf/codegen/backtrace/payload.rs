use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn bool_to_u8(&self, value: IntValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                value,
                self.context.i8_type().const_int(1, false).into(),
                self.context.i8_type().const_zero().into(),
                name,
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn status_or_offsets_unavailable(
        &self,
        status: BacktraceStatus,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                self.context
                    .i8_type()
                    .const_int(status as u64, false)
                    .into(),
                self.context
                    .i8_type()
                    .const_int(BacktraceStatus::OffsetsUnavailable as u64, false)
                    .into(),
                "bt_status_or_offsets",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn status_for_backtrace_stop(
        &self,
        complete: IntValue<'ctx>,
        error_code: IntValue<'ctx>,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let ra_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                error_code,
                i16_type.const_int(BACKTRACE_ERROR_RETURN_ADDRESS_READ as u64, false),
                "bt_status_ra_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                error_code,
                i16_type.const_int(BACKTRACE_ERROR_FRAME_POINTER_READ as u64, false),
                "bt_status_rbp_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let read_error = self
            .builder
            .build_or(ra_read_error, rbp_read_error, "bt_status_read_error_flag")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let error_status = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                read_error,
                i8_type
                    .const_int(BacktraceStatus::ReadError as u64, false)
                    .into(),
                i8_type
                    .const_int(BacktraceStatus::InvalidFrame as u64, false)
                    .into(),
                "bt_status_for_error_code",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let backtrace_status = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                complete,
                i8_type
                    .const_int(BacktraceStatus::Complete as u64, false)
                    .into(),
                error_status,
                "bt_status_for_stop",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                backtrace_status,
                i8_type
                    .const_int(BacktraceStatus::OffsetsUnavailable as u64, false)
                    .into(),
                "bt_status_or_offsets_for_error_code",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    pub(super) fn store_backtrace_frame(
        &self,
        inst_buffer: PointerValue<'ctx>,
        frame_index: usize,
        module_cookie: IntValue<'ctx>,
        pc: IntValue<'ctx>,
        raw_ip: IntValue<'ctx>,
        flags: u16,
    ) -> Result<()> {
        let frame_base =
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_SIZE + frame_index * BACKTRACE_FRAME_DATA_SIZE;
        self.store_u64_value(
            inst_buffer,
            frame_base + BACKTRACE_FRAME_MODULE_COOKIE_OFFSET,
            module_cookie,
            "bt_frame_cookie",
        )?;
        self.store_u64_value(
            inst_buffer,
            frame_base + BACKTRACE_FRAME_PC_OFFSET,
            pc,
            "bt_frame_pc",
        )?;
        self.store_u64_value(
            inst_buffer,
            frame_base + BACKTRACE_FRAME_RAW_IP_OFFSET,
            raw_ip,
            "bt_frame_raw_ip",
        )?;
        self.store_u16_const(
            inst_buffer,
            frame_base + BACKTRACE_FRAME_FLAGS_OFFSET,
            flags,
            "bt_frame_flags",
        )
    }

    pub(super) fn store_backtrace_frame_dynamic(
        &self,
        inst_buffer: PointerValue<'ctx>,
        frame_index: IntValue<'ctx>,
        max_frame_index: u8,
        module_cookie: IntValue<'ctx>,
        pc: IntValue<'ctx>,
        raw_ip: IntValue<'ctx>,
    ) -> Result<()> {
        let i64_type = self.context.i64_type();
        let frame_index_i64 = if frame_index.get_type().get_bit_width() == i64_type.get_bit_width()
        {
            frame_index
        } else {
            self.builder
                .build_int_z_extend(frame_index, i64_type, "bt_frame_index_i64")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let max_frame_index = i64_type.const_int(max_frame_index as u64, false);
        let frame_index_in_bounds = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                frame_index_i64,
                max_frame_index,
                "bt_frame_index_in_bounds",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_index_i64 = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                frame_index_in_bounds,
                frame_index_i64.into(),
                max_frame_index.into(),
                "bt_frame_index_bounded",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let frame_stride = i64_type.const_int(BACKTRACE_FRAME_DATA_SIZE as u64, false);
        let frame_offset = self
            .builder
            .build_int_mul(frame_index_i64, frame_stride, "bt_dynamic_frame_offset")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let base_offset = i64_type.const_int(
            (INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_SIZE) as u64,
            false,
        );
        let frame_base_offset = self
            .builder
            .build_int_add(base_offset, frame_offset, "bt_dynamic_frame_base_offset")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_base =
            self.dynamic_byte_gep(inst_buffer, frame_base_offset, "bt_dynamic_frame")?;

        self.store_u64_value(
            frame_base,
            BACKTRACE_FRAME_MODULE_COOKIE_OFFSET,
            module_cookie,
            "bt_frame_cookie",
        )?;
        self.store_u64_value(frame_base, BACKTRACE_FRAME_PC_OFFSET, pc, "bt_frame_pc")?;
        self.store_u64_value(
            frame_base,
            BACKTRACE_FRAME_RAW_IP_OFFSET,
            raw_ip,
            "bt_frame_raw_ip",
        )?;
        self.store_u16_const(
            frame_base,
            BACKTRACE_FRAME_FLAGS_OFFSET,
            0,
            "bt_frame_flags",
        )
    }

    pub(super) fn store_u8_const(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: u8,
        name: &str,
    ) -> Result<()> {
        self.store_u8_value(
            base,
            offset,
            self.context.i8_type().const_int(value as u64, false),
            name,
        )
    }

    pub(super) fn store_u8_value(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<()> {
        let ptr = self.byte_gep(base, offset, name)?;
        self.builder
            .build_store(ptr, value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn store_u16_const(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: u16,
        name: &str,
    ) -> Result<()> {
        self.store_u16_value(
            base,
            offset,
            self.context.i16_type().const_int(value as u64, false),
            name,
        )
    }

    pub(super) fn store_u16_value(
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
                &format!("{name}_u16_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(ptr, value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn store_u64_value(
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
                &format!("{name}_u64_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(ptr, value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(super) fn byte_gep(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<PointerValue<'ctx>> {
        // SAFETY: callers pass offsets within the instruction region reserved for
        // this Backtrace instruction.
        unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    base,
                    &[self.context.i32_type().const_int(offset as u64, false)],
                    &format!("{name}_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        }
    }

    pub(super) fn dynamic_byte_gep(
        &self,
        base: PointerValue<'ctx>,
        offset: IntValue<'ctx>,
        name: &str,
    ) -> Result<PointerValue<'ctx>> {
        // SAFETY: callers guard the dynamic offset against the per-CPU buffer
        // size before using the returned pointer.
        unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    base,
                    &[offset],
                    &format!("{name}_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        }
    }
}

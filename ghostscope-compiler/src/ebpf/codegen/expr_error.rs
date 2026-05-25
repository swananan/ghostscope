use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Generate ExprError instruction with expression string index and error code/flags
    pub fn generate_expr_error(
        &mut self,
        expr_string_index: u16,
        error_code_iv: inkwell::values::IntValue<'ctx>,
        flags_iv: inkwell::values::IntValue<'ctx>,
        failing_addr_iv: inkwell::values::IntValue<'ctx>,
    ) -> Result<()> {
        // Reserve space in accumulation buffer for this instruction
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(
                (INSTRUCTION_HEADER_SIZE + EXPR_ERROR_DATA_SIZE) as u64,
            )?
            .into_value_after_runtime_returns();

        // Store instruction type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::ExprError as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // data_length
        // SAFETY: inst_buffer points at a reserved ExprError instruction region
        // and data_length is within InstructionHeader.
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(INSTRUCTION_HEADER_DATA_LENGTH_OFFSET as u64, false)],
                    "exprerr_data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(EXPR_ERROR_DATA_SIZE as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Payload fields after header
        // SAFETY: the payload immediately follows InstructionHeader in the
        // reserved ExprError instruction region.
        let si_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        (INSTRUCTION_HEADER_SIZE + EXPR_ERROR_DATA_STRING_INDEX_OFFSET) as u64,
                        false,
                    )],
                    "exprerr_si_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get string_index GEP: {e}"))
                })?
        };
        let si_i16_ptr = self
            .builder
            .build_pointer_cast(
                si_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_si_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast string_index ptr: {e}"))
            })?;
        let si_val = self
            .context
            .i16_type()
            .const_int(expr_string_index as u64, false);
        self.builder
            .build_store(si_i16_ptr, si_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store string_index: {e}")))?;

        // SAFETY: error_code offset is within ExprErrorData in the reserved payload.
        let ec_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        (INSTRUCTION_HEADER_SIZE + EXPR_ERROR_DATA_ERROR_CODE_OFFSET) as u64,
                        false,
                    )],
                    "exprerr_ec_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get error_code GEP: {e}"))
                })?
        };
        // Truncate/extend runtime error code to i8
        let ec_i8 = if error_code_iv.get_type().get_bit_width() == 8 {
            error_code_iv
        } else if error_code_iv.get_type().get_bit_width() > 8 {
            self.builder
                .build_int_truncate(error_code_iv, self.context.i8_type(), "ec_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(error_code_iv, self.context.i8_type(), "ec_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(ec_ptr, ec_i8)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store error_code: {e}")))?;
        // SAFETY: flags offset is within ExprErrorData in the reserved payload.
        let fl_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        (INSTRUCTION_HEADER_SIZE + EXPR_ERROR_DATA_FLAGS_OFFSET) as u64,
                        false,
                    )],
                    "exprerr_flags_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get flags GEP: {e}")))?
        };
        // Truncate/extend runtime flags to i8
        let fl_i8 = if flags_iv.get_type().get_bit_width() == 8 {
            flags_iv
        } else if flags_iv.get_type().get_bit_width() > 8 {
            self.builder
                .build_int_truncate(flags_iv, self.context.i8_type(), "fl_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(flags_iv, self.context.i8_type(), "fl_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(fl_ptr, fl_i8)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store flags: {e}")))?;

        // SAFETY: failing_addr offset is within ExprErrorData in the reserved payload.
        let addr_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        (INSTRUCTION_HEADER_SIZE + EXPR_ERROR_DATA_FAILING_ADDR_OFFSET) as u64,
                        false,
                    )],
                    "exprerr_addr_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {e}")))?
        };
        let addr_i64 = if failing_addr_iv.get_type().get_bit_width() == 64 {
            failing_addr_iv
        } else if failing_addr_iv.get_type().get_bit_width() > 64 {
            self.builder
                .build_int_truncate(failing_addr_iv, self.context.i64_type(), "addr_trunc")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            self.builder
                .build_int_z_extend(failing_addr_iv, self.context.i64_type(), "addr_zext")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let addr_ptr_cast = self
            .builder
            .build_pointer_cast(
                addr_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "exprerr_addr_i64_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(addr_ptr_cast, addr_i64)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store failing_addr: {e}")))?;

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
}

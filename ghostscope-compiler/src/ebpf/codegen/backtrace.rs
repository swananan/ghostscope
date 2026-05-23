use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    // PrintVariableError instruction has been removed; compile-time errors are returned as Err,
    // runtime errors are carried via per-variable status in Print* instructions.

    /// Generate Backtrace instruction
    pub fn generate_backtrace_instruction(&mut self, depth: u8) -> Result<()> {
        info!("Generating Backtrace instruction: depth={}", depth);

        // Reserve space directly for Backtrace instruction
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(
                (std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<BacktraceData>())
                    as u64,
            )?
            .into_value_after_runtime_returns();

        // Write InstructionHeader.inst_type
        let inst_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, inst_type) as u64,
                        false,
                    )],
                    "bt_inst_type_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get inst_type GEP: {e}")))?
        };
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::Backtrace as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // Write InstructionHeader.data_length (u16)
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(
                        std::mem::offset_of!(InstructionHeader, data_length) as u64,
                        false,
                    )],
                    "bt_data_length_ptr",
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
                "bt_data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let dl_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<BacktraceData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, dl_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Already accumulated; EndInstruction will send the whole event. Depth currently unused at BPF level.
        Ok(())
    }
}

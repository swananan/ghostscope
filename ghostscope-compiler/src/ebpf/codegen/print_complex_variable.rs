use super::*;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn generate_print_complex_variable_computed(
        &mut self,
        var_name_index: u16,
        type_index: u16,
        byte_len: usize,
        value: IntValue<'ctx>,
    ) -> Result<()> {
        // Build sizes
        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_struct_size = std::mem::size_of::<PrintComplexVariableData>();
        let access_path_len: usize = 0; // computed expr has no access path
        let total_data_length = data_struct_size + access_path_len + byte_len;
        let total_size = header_size + total_data_length;

        // Reserve space directly in the per-CPU accumulation buffer
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(total_size as u64)?
            .into_value_after_runtime_returns();

        // Write InstructionHeader.inst_type
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // Write data_length (u16) at offset 1
        // SAFETY: inst_buffer points at a reserved PrintComplexVariable instruction
        // region and offset 1 is the InstructionHeader data_length field.
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Data pointer (after header)
        // SAFETY: data_ptr starts immediately after InstructionHeader in the
        // reserved instruction region.
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {e}")))?
        };

        // var_name_index (u16)
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(var_name_index as u64, false);
        let var_name_index_off =
            std::mem::offset_of!(PrintComplexVariableData, var_name_index) as u64;
        // SAFETY: var_name_index_off is generated from PrintComplexVariableData.
        let var_name_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(var_name_index_off, false)],
                    "var_name_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {e}"))
                })?
        };
        let var_name_index_ptr_i16 = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {e}"))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var_name_index: {e}")))?;

        // type_index (u16)
        let type_index_offset = std::mem::offset_of!(PrintComplexVariableData, type_index) as u64;
        // SAFETY: type_index_offset is generated from PrintComplexVariableData.
        let type_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(type_index_offset, false)],
                    "type_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {e}"))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {e}")))?;
        let type_index_val = self.context.i16_type().const_int(type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {e}")))?;

        // access_path_len (u8) = 0
        let access_path_len_off =
            std::mem::offset_of!(PrintComplexVariableData, access_path_len) as u64;
        // SAFETY: access_path_len_off is generated from PrintComplexVariableData.
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_off, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {e}"))
                })?
        };
        self.builder
            .build_store(access_path_len_ptr, self.context.i8_type().const_zero())
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {e}"))
            })?;

        // status (u8) = 0
        let status_off = std::mem::offset_of!(PrintComplexVariableData, status) as u64;
        // SAFETY: status_off is generated from PrintComplexVariableData.
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(status_off, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        self.builder
            .build_store(status_ptr, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // data_len (u16)
        let data_len_off = std::mem::offset_of!(PrintComplexVariableData, data_len) as u64;
        // SAFETY: data_len_off is generated from PrintComplexVariableData.
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_off, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data_len GEP: {e}")))?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {e}")))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(byte_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;

        // variable data starts right after PrintComplexVariableData (no access path)
        // SAFETY: total_size reserved byte_len bytes after PrintComplexVariableData.
        let var_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(data_struct_size as u64, false)],
                    "var_data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get var_data GEP: {e}")))?
        };

        // Store computed integer value into payload according to byte_len
        match byte_len {
            1 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw == 1 {
                    // Booleans must serialize as 0/1
                    self.builder
                        .build_int_z_extend(value, self.context.i8_type(), "expr_zext_bool_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw < 8 {
                    self.builder
                        .build_int_s_extend(value, self.context.i8_type(), "expr_sext_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 8 {
                    self.builder
                        .build_int_truncate(value, self.context.i8_type(), "expr_trunc_i8")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                self.builder
                    .build_store(var_data_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            2 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 16 {
                    self.builder
                        .build_int_s_extend(value, self.context.i16_type(), "expr_sext_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 16 {
                    self.builder
                        .build_int_truncate(value, self.context.i16_type(), "expr_trunc_i16")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i16_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i16_ptr_ty, "expr_i16_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            4 => {
                let bitw = value.get_type().get_bit_width();
                let v = if bitw < 32 {
                    self.builder
                        .build_int_s_extend(value, self.context.i32_type(), "expr_sext_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else if bitw > 32 {
                    self.builder
                        .build_int_truncate(value, self.context.i32_type(), "expr_trunc_i32")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i32_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i32_ptr_ty, "expr_i32_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            8 => {
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_s_extend(value, self.context.i64_type(), "expr_sext_i64")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                let i64_ptr_ty = self.context.ptr_type(AddressSpace::default());
                let cast_ptr = self
                    .builder
                    .build_pointer_cast(var_data_ptr, i64_ptr_ty, "expr_i64_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(cast_ptr, v64)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
            n => {
                // Fallback: write lowest n bytes little-endian
                let v64 = if value.get_type().get_bit_width() < 64 {
                    self.builder
                        .build_int_s_extend(value, self.context.i64_type(), "expr_sext_fallback")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                } else {
                    value
                };
                for i in 0..n {
                    let shift = self.context.i64_type().const_int((i * 8) as u64, false);
                    let shifted = self
                        .builder
                        .build_right_shift(v64, shift, false, &format!("expr_shr_{i}"))
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let byte = self
                        .builder
                        .build_int_truncate(
                            shifted,
                            self.context.i8_type(),
                            &format!("expr_byte_{i}"),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    // SAFETY: i is bounded by byte_len and var_data_ptr covers byte_len bytes.
                    let byte_ptr = unsafe {
                        self.builder
                            .build_gep(
                                self.context.i8_type(),
                                var_data_ptr,
                                &[self.context.i32_type().const_int(i as u64, false)],
                                &format!("expr_byte_ptr_{i}"),
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    };
                    self.builder
                        .build_store(byte_ptr, byte)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                }
            }
        }

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
    /// Generate PrintComplexVariable instruction and copy data at runtime using probe_read_user
    pub(super) fn generate_print_complex_variable_runtime(
        &mut self,
        meta: PrintVarRuntimeMeta,
        address: &ghostscope_dwarf::PlannedAddress,
        dwarf_type: &ghostscope_dwarf::TypeInfo,
        module_hint: Option<&str>,
    ) -> Result<()> {
        tracing::trace!(
            var_name_index = meta.var_name_index,
            type_index = meta.type_index,
            access_path = %meta.access_path,
            type_size = dwarf_type.size(),
            data_len_limit = meta.data_len_limit,
            address = ?address,
            "generate_print_complex_variable_runtime: begin"
        );
        // Compute sizes first, then reserve instruction region directly in accumulation buffer

        // Compute sizes
        let access_path_bytes = meta.access_path.as_bytes();
        let access_path_len = std::cmp::min(access_path_bytes.len(), 255); // u8 max
        let type_size = dwarf_type.size() as usize;
        let mut data_len = std::cmp::min(type_size, meta.data_len_limit);
        if data_len > u16::MAX as usize {
            data_len = u16::MAX as usize;
        }

        let header_size = std::mem::size_of::<InstructionHeader>();
        let data_struct_size = std::mem::size_of::<PrintComplexVariableData>();
        // Reserve enough space to hold either the value (read_len) or an error payload (12 bytes)
        let reserved_payload = std::cmp::max(data_len, 12);
        let total_data_length = data_struct_size + access_path_len + reserved_payload;
        let total_size = header_size + total_data_length;
        tracing::trace!(
            header_size,
            data_struct_size,
            access_path_len,
            data_len,
            total_data_length,
            total_size,
            "generate_print_complex_variable_runtime: sizes computed"
        );

        // Reserve space now that sizes are known
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(total_size as u64)?
            .into_value_after_runtime_returns();

        // Avoid memset; reserved map value bytes are zero-initialized

        // Write InstructionHeader.inst_type at offset 0
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::PrintComplexVariable as u64, false);
        self.builder
            .build_store(inst_buffer, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;
        tracing::trace!(
            "generate_print_complex_variable_runtime: wrote inst_type=PrintComplexVariable"
        );

        // Write InstructionHeader
        // data_length field (u16) at offset 1
        // SAFETY: inst_buffer points at a reserved PrintComplexVariable instruction
        // region and offset 1 is the InstructionHeader data_length field.
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(1, false)],
                    "data_length_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {e}"))
                })?
        };
        let data_length_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_ptr_cast",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        self.builder
            .build_store(
                data_length_ptr_cast,
                self.context
                    .i16_type()
                    .const_int(total_data_length as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;
        tracing::trace!(
            data_length = total_data_length,
            "generate_print_complex_variable_runtime: wrote data_length"
        );

        // Data pointer (after header)
        // SAFETY: data_ptr starts immediately after InstructionHeader in the
        // reserved instruction region.
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    inst_buffer,
                    &[self.context.i32_type().const_int(header_size as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data GEP: {e}")))?
        };

        // var_name_index (u16)
        let var_name_index_val = self
            .context
            .i16_type()
            .const_int(meta.var_name_index as u64, false);
        // Store var_name_index at offset offsetof(PrintComplexVariableData, var_name_index)
        let var_name_index_off =
            std::mem::offset_of!(PrintComplexVariableData, var_name_index) as u64;
        // SAFETY: var_name_index_off is generated from PrintComplexVariableData.
        let var_name_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(var_name_index_off, false)],
                    "var_name_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get var_name_index GEP: {e}"))
                })?
        };
        let var_name_index_ptr_i16 = self
            .builder
            .build_pointer_cast(
                var_name_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "var_name_index_ptr_i16",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast var_name_index ptr: {e}"))
            })?;
        self.builder
            .build_store(var_name_index_ptr_i16, var_name_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store var_name_index: {e}")))?;
        tracing::trace!(
            var_name_index = meta.var_name_index,
            "generate_print_complex_variable_runtime: wrote var_name_index"
        );

        // type_index (u16) right after var_name_index
        // type_index at offset offsetof(PrintComplexVariableData, type_index) = 2
        let type_index_offset = std::mem::offset_of!(PrintComplexVariableData, type_index) as u64;
        // SAFETY: type_index_offset is generated from PrintComplexVariableData.
        let type_index_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(type_index_offset, false)],
                    "type_index_ptr_i8",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get type_index GEP: {e}"))
                })?
        };
        let type_index_ptr = self
            .builder
            .build_pointer_cast(
                type_index_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "type_index_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast type_index ptr: {e}")))?;
        let type_index_val = self
            .context
            .i16_type()
            .const_int(meta.type_index as u64, false);
        self.builder
            .build_store(type_index_ptr, type_index_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store type_index: {e}")))?;
        tracing::trace!(
            type_index = meta.type_index,
            "generate_print_complex_variable_runtime: wrote type_index"
        );

        // access_path_len (u8)
        // access_path_len at offset offsetof(..., access_path_len)
        let access_path_len_off =
            std::mem::offset_of!(PrintComplexVariableData, access_path_len) as u64;
        // SAFETY: access_path_len_off is generated from PrintComplexVariableData.
        let access_path_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len_off, false)],
                    "access_path_len_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path_len GEP: {e}"))
                })?
        };
        self.builder
            .build_store(
                access_path_len_ptr,
                self.context
                    .i8_type()
                    .const_int(access_path_len as u64, false),
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path_len: {e}"))
            })?;
        tracing::trace!(
            access_path_len,
            "generate_print_complex_variable_runtime: wrote access_path_len"
        );

        // status (u8) at offset offsetof(..., status)
        let status_off = std::mem::offset_of!(PrintComplexVariableData, status) as u64;
        // SAFETY: status_off is generated from PrintComplexVariableData.
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(status_off, false)],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::Ok as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // (Optimized-out handling moved below after data_len pointer is available)

        // data_len (u16)
        let data_len_off = std::mem::offset_of!(PrintComplexVariableData, data_len) as u64;
        // SAFETY: data_len_off is generated from PrintComplexVariableData.
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(data_len_off, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get data_len GEP: {e}")))?
        };
        let data_len_ptr_cast = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_ptr_i16",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_len ptr: {e}")))?;
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(data_len as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_len: {e}")))?;
        tracing::trace!(
            data_len,
            "generate_print_complex_variable_runtime: wrote data_len"
        );

        // Optimized-out case is handled earlier by resolving to an OptimizedOut type and ImmediateBytes path.

        // access_path bytes start after PrintComplexVariableData
        // SAFETY: total_size reserved access_path_len bytes after PrintComplexVariableData.
        let access_path_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    data_ptr,
                    &[self.context.i32_type().const_int(
                        std::mem::size_of::<PrintComplexVariableData>() as u64,
                        false,
                    )],
                    "access_path_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get access_path GEP: {e}"))
                })?
        };

        // Copy access path bytes
        for (i, &byte) in access_path_bytes.iter().enumerate().take(access_path_len) {
            // SAFETY: i is bounded by access_path_len and access_path_ptr covers that region.
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        self.context.i8_type(),
                        access_path_ptr,
                        &[self.context.i32_type().const_int(i as u64, false)],
                        &format!("access_path_byte_{i}"),
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to get access_path byte GEP: {e}"))
                    })?
            };
            let byte_val = self.context.i8_type().const_int(byte as u64, false);
            self.builder.build_store(byte_ptr, byte_val).map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store access_path byte: {e}"))
            })?;
        }
        if access_path_len > 0 {
            tracing::trace!("generate_print_complex_variable_runtime: wrote access_path bytes");
        }

        // Variable data starts after access_path
        // SAFETY: variable_data_ptr starts after the reserved access_path bytes and
        // total_size reserved the payload region.
        let variable_data_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    access_path_ptr,
                    &[self
                        .context
                        .i32_type()
                        .const_int(access_path_len as u64, false)],
                    "variable_data_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get variable_data GEP: {e}"))
                })?
        };

        // Compute source address with ASLR-aware helper, honoring module hint
        // Prefer a previously recorded module path for offsets; fall back handled in helper
        let src_addr = self.resolve_planned_address(address, Some(status_ptr), module_hint)?;
        tracing::trace!(src_addr = %src_addr.value, "generate_print_complex_variable_runtime: computed src_addr");

        // Setup common types and casts
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let dst_ptr = self
            .builder
            .build_bit_cast(variable_data_ptr, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let size_val = i32_type.const_int(data_len as u64, false);
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr.value, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let offsets_found = src_addr.offsets_found;
        let current_fn = self.current_function("generate print complex variable runtime")?;
        let cont_block = self.context.append_basic_block(current_fn, "after_read");
        let skip_block = self.context.append_basic_block(current_fn, "offsets_skip");
        let found_block = self.context.append_basic_block(current_fn, "offsets_found");
        self.builder
            .build_conditional_branch(offsets_found, found_block, skip_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(skip_block);
        self.mark_any_fail()?;
        self.builder
            .build_store(data_len_ptr_cast, self.context.i16_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(found_block);

        // Branch: NULL deref if src_addr == 0
        let zero64 = i64_type.const_zero();
        let is_null = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, src_addr.value, zero64, "is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_block = self.context.append_basic_block(current_fn, "null_deref");
        let read_block = self.context.append_basic_block(current_fn, "read_user");
        self.builder
            .build_conditional_branch(is_null, null_block, read_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // NULL path
        self.builder.position_at_end(null_block);
        self.builder
            .build_store(
                status_ptr,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::NullDeref as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 0
        self.builder
            .build_store(data_len_ptr_cast, self.context.i16_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Read path
        self.builder.position_at_end(read_block);
        let ret = self
            .create_bpf_helper_call(
                BPF_FUNC_probe_read_user as u64,
                &[dst_ptr, size_val.into(), src_ptr.into()],
                i32_type.into(),
                "probe_read_user",
            )?
            .into_int_value();
        let is_err = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                ret,
                i32_type.const_zero(),
                "ret_lt_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let err_block = self.context.append_basic_block(current_fn, "read_err");
        let ok_block = self.context.append_basic_block(current_fn, "read_ok");
        self.builder
            .build_conditional_branch(is_err, err_block, ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Error: status=2 (read_user failed); attach errno+addr payload and set data_len=12
        self.builder.position_at_end(err_block);
        // Only set ReadError if status is still Ok (preserve OffsetsUnavailable etc.)
        let cur_status1 = self
            .builder
            .build_load(self.context.i8_type(), status_ptr, "cur_status1")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_ok1 = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                cur_status1.into_int_value(),
                self.context.i8_type().const_zero(),
                "status_is_ok1",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let readerr_val = self
            .context
            .i8_type()
            .const_int(VariableStatus::ReadError as u64, false)
            .into();
        let new_status1 = self
            .builder
            .build_select(is_ok1, readerr_val, cur_status1, "status_after_readerr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(status_ptr, new_status1)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // data_len = 12 (errno:i32 + addr:u64)
        self.builder
            .build_store(
                data_len_ptr_cast,
                self.context.i16_type().const_int(12, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // write errno at [0..4]
        let errno_ptr = self
            .builder
            .build_pointer_cast(
                variable_data_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "errno_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast errno ptr: {e}")))?;
        let errno = self.build_errno_i32(ret, "readerr_errno_i32")?;
        self.builder
            .build_store(errno_ptr, errno)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store errno: {e}")))?;
        // write addr at [4..12]
        // SAFETY: the error payload reserves 12 bytes, so addr starts at byte 4.
        let addr_ptr_i8 = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    variable_data_ptr,
                    &[self.context.i32_type().const_int(4, false)],
                    "addr_ptr_i8",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get addr GEP: {e}")))?
        };
        let addr_ptr = self
            .builder
            .build_pointer_cast(
                addr_ptr_i8,
                self.context.ptr_type(AddressSpace::default()),
                "addr_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast addr ptr: {e}")))?;
        self.builder
            .build_store(addr_ptr, src_addr.value)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store addr: {e}")))?;
        // mark fail
        self.mark_any_fail()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // OK path: status=0; optional truncated if data_len_limit < dwarf_type.size()
        self.builder.position_at_end(ok_block);
        if data_len < dwarf_type.size() as usize {
            // truncated
            self.builder
                .build_store(
                    status_ptr,
                    self.context
                        .i8_type()
                        .const_int(VariableStatus::Truncated as u64, false),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            // mark both success and fail
            self.mark_any_success()?;
            self.mark_any_fail()?;
        } else {
            // success
            self.mark_any_success()?;
        }
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Continue
        self.builder.position_at_end(cont_block);

        // Already accumulated; EndInstruction will send the whole event
        Ok(())
    }
}

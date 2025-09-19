//! Protocol message handling
//!
//! This module handles ringbuf message formatting and transmission
//! according to ghostscope-protocol specifications.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::Expr;
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;
use tracing::{debug, info, warn};

impl<'ctx> EbpfContext<'ctx> {
    /// Compile print statements
    pub fn compile_print(&mut self, expr: &Expr) -> Result<()> {
        match expr {
            Expr::Variable(var_name) => {
                info!("Printing variable: {}", var_name);
                self.send_variable_data(var_name)
            }
            Expr::String(value) => {
                info!("Printing string literal: {}", value);
                self.send_string_literal(value)
            }
            Expr::Int(value) => {
                info!("Printing integer literal: {}", value);
                self.send_integer_literal(*value)
            }
            Expr::Float(value) => {
                info!("Printing float literal: {}", value);
                self.send_float_literal(*value)
            }
            _ => {
                warn!("Unsupported print expression type, falling back to basic compilation");
                let _value = self.compile_expr(expr)?;
                Ok(())
            }
        }
    }

    /// Generate backtrace (placeholder)
    pub fn generate_backtrace(&mut self) -> Result<()> {
        info!("Generating backtrace");
        // For now, this is a placeholder
        // A real implementation would generate stack walking code
        Ok(())
    }

    /// Send variable data using protocol format
    fn send_variable_data(&mut self, var_name: &str) -> Result<()> {
        debug!("Generating LLVM IR for variable: {}", var_name);

        // Get compile-time context for DWARF queries
        let compile_context = self.get_compile_time_context()?.clone();
        debug!(
            "Using compile-time context: PC 0x{:x}, module '{}' for DWARF query of '{}'",
            compile_context.pc_address, compile_context.module_path, var_name
        );

        // Query DWARF for variable information
        let variable_with_eval = match self.query_dwarf_for_variable(var_name)? {
            Some(var) => var,
            None => return Err(CodeGenError::VariableNotFound(var_name.to_string())),
        };

        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Variable has no DWARF type information".to_string())
        })?;

        // Use evaluate_result_to_llvm_value to get the computed value
        let computed_value = self.evaluate_result_to_llvm_value(
            &variable_with_eval.evaluation_result,
            dwarf_type,
            var_name,
            compile_context.pc_address,
        )?;

        // Create protocol message storage
        let msg_storage = self.create_protocol_message_storage();

        // Build message header
        self.build_message_header(msg_storage)?;

        // Build variable data header
        self.build_variable_data_header(msg_storage)?;

        // Build variable entry with computed value
        self.build_variable_entry_from_llvm_value(
            msg_storage,
            var_name,
            dwarf_type,
            computed_value,
        )?;

        // Calculate total message length and update header
        let total_len = self.calculate_message_length(var_name, dwarf_type)?;
        self.update_message_length(msg_storage, total_len)?;

        // Send to ringbuf
        self.create_ringbuf_output(msg_storage, total_len as u64)?;

        Ok(())
    }

    /// Send string literal using protocol format
    fn send_string_literal(&mut self, value: &str) -> Result<()> {
        // Create a string constant in the module
        let str_ptr = self.create_string_constant(value)?;
        let str_len = value.len() as u64;

        // Create protocol message for string literal
        self.build_and_send_string_literal_message(str_ptr, str_len, value)
    }

    /// Send integer literal using protocol format
    fn send_integer_literal(&mut self, value: i64) -> Result<()> {
        let int_val = self.context.i64_type().const_int(value as u64, false);
        self.build_and_send_integer_literal_message(int_val, value)
    }

    /// Send float literal using protocol format
    fn send_float_literal(&mut self, value: f64) -> Result<()> {
        let float_val = self.context.f64_type().const_float(value);
        self.build_and_send_float_literal_message(float_val, value)
    }

    /// Create a string constant in the module
    fn create_string_constant(&mut self, value: &str) -> Result<PointerValue<'ctx>> {
        let i8_type = self.context.i8_type();
        let str_type = i8_type.array_type(value.len() as u32 + 1); // +1 for null terminator

        let global_str =
            self.module
                .add_global(str_type, Some(AddressSpace::default()), "_str_literal");

        // Create string with null terminator
        let mut str_with_null = value.to_string();
        str_with_null.push('\0');
        let string_val = self.context.const_string(str_with_null.as_bytes(), false);

        global_str.set_initializer(&string_val);

        // Return pointer to the string
        Ok(global_str.as_pointer_value())
    }

    /// Create storage area for protocol message
    fn create_protocol_message_storage(&mut self) -> PointerValue<'ctx> {
        // Create large enough global buffer to store protocol message (max 4KB)
        let buffer_size = 4096;
        let i8_type = self.context.i8_type();
        let buffer_type = i8_type.array_type(buffer_size);

        let buffer = self.module.add_global(
            buffer_type,
            Some(AddressSpace::default()),
            "_protocol_msg_buffer",
        );
        buffer.set_initializer(&buffer_type.const_zero());
        buffer.as_pointer_value()
    }

    /// Build message header (MessageHeader: 8 bytes)
    fn build_message_header(&mut self, buffer: PointerValue<'ctx>) -> Result<()> {
        use ghostscope_protocol::{consts, MessageType};

        let i32_type = self.context.i32_type();
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();

        // MessageHeader structure: [magic:u32, msg_type:u8, flags:u8, length:u16]
        let magic = i32_type.const_int(consts::MAGIC.into(), false);
        let msg_type = i8_type.const_int(MessageType::VariableData as u8 as u64, false);
        let flags = i8_type.const_int(0, false);

        // Write magic (offset 0)
        let magic_u32_ptr = self
            .builder
            .build_pointer_cast(
                buffer,
                self.context.ptr_type(AddressSpace::default()),
                "magic_u32_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(magic_u32_ptr, magic)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write msg_type (offset 4)
        let msg_type_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(4, false)],
                    "msg_type_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        self.builder
            .build_store(msg_type_ptr, msg_type)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write flags (offset 5)
        let flags_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[self.context.i32_type().const_int(5, false)],
                    "flags_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        self.builder
            .build_store(flags_ptr, flags)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Build variable data message header (VariableDataMessage: 24 bytes)
    fn build_variable_data_header(&mut self, buffer: PointerValue<'ctx>) -> Result<()> {
        use ghostscope_protocol::consts;

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let i16_type = self.context.i16_type();

        let header_size = consts::MESSAGE_HEADER_SIZE as u64;

        // VariableDataMessage: [trace_id:u64, timestamp:u64, pid:u32, tid:u32, var_count:u16, reserved:u16]
        let trace_id_value = self.current_trace_id.unwrap_or(0) as u64;
        let trace_id = i64_type.const_int(trace_id_value, false);
        let timestamp = self.get_current_timestamp()?; // Get real timestamp from bpf_ktime_get_ns

        // Get real PID/TID using bpf_get_current_pid_tgid()
        let pid_tgid_result = self.get_current_pid_tgid()?;
        let pid = self
            .builder
            .build_int_truncate(pid_tgid_result, i32_type, "pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let shift_32 = i64_type.const_int(32, false);
        let tid_64 = self
            .builder
            .build_right_shift(pid_tgid_result, shift_32, false, "tid_64")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let tid = self
            .builder
            .build_int_truncate(tid_64, i32_type, "tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let var_count = i16_type.const_int(1, false); // Single variable
        let _reserved = i16_type.const_int(0, false);

        // Write fields to buffer at proper offsets
        // trace_id at offset header_size + 0
        let trace_id_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(header_size, false)],
                    "trace_id_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let trace_id_i64_ptr = self
            .builder
            .build_pointer_cast(
                trace_id_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "trace_id_i64_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(trace_id_i64_ptr, trace_id)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // timestamp at offset header_size + 8
        let timestamp_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(header_size + 8, false)],
                    "timestamp_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let timestamp_i64_ptr = self
            .builder
            .build_pointer_cast(
                timestamp_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "timestamp_i64_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(timestamp_i64_ptr, timestamp)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // pid at offset header_size + 16
        let pid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(header_size + 16, false)],
                    "pid_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let pid_i32_ptr = self
            .builder
            .build_pointer_cast(
                pid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "pid_i32_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(pid_i32_ptr, pid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // tid at offset header_size + 20
        let tid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(header_size + 20, false)],
                    "tid_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let tid_i32_ptr = self
            .builder
            .build_pointer_cast(
                tid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "tid_i32_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(tid_i32_ptr, tid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // var_count at offset header_size + 24
        let var_count_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(header_size + 24, false)],
                    "var_count_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let var_count_i16_ptr = self
            .builder
            .build_pointer_cast(
                var_count_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "var_count_i16_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder
            .build_store(var_count_i16_ptr, var_count)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Build and send string literal message
    fn build_and_send_string_literal_message(
        &mut self,
        _str_ptr: PointerValue<'ctx>,
        _str_len: u64,
        value: &str,
    ) -> Result<()> {
        // TODO: Implement full protocol message building
        debug!("Sending string literal message: {}", value);
        Ok(())
    }

    /// Build and send integer literal message
    fn build_and_send_integer_literal_message(
        &mut self,
        _int_val: IntValue<'ctx>,
        value: i64,
    ) -> Result<()> {
        // TODO: Implement full protocol message building
        debug!("Sending integer literal message: {}", value);
        Ok(())
    }

    /// Build and send float literal message
    fn build_and_send_float_literal_message(
        &mut self,
        _float_val: inkwell::values::FloatValue<'ctx>,
        value: f64,
    ) -> Result<()> {
        // TODO: Implement full protocol message building
        debug!("Sending float literal message: {}", value);
        Ok(())
    }

    /// Build variable entry from LLVM value
    fn build_variable_entry_from_llvm_value(
        &mut self,
        buffer: PointerValue<'ctx>,
        var_name: &str,
        dwarf_type: &ghostscope_dwarf::DwarfType,
        computed_value: BasicValueEnum<'ctx>,
    ) -> Result<()> {
        use ghostscope_protocol::consts;

        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();

        // Calculate entry offset: MessageHeader(8) + VariableDataMessage(24) = 32
        let entry_offset =
            (consts::MESSAGE_HEADER_SIZE + consts::VARIABLE_DATA_MESSAGE_SIZE) as u32;

        // VariableEntry structure: [name_len:u8, type_encoding:u8, data_len:u16]
        let name_bytes = var_name.as_bytes();
        let name_len = name_bytes.len().min(255) as u8; // Clamp to u8 max

        // Determine type encoding from DWARF type
        let type_encoding = self.dwarf_type_to_protocol_encoding(dwarf_type);

        // Determine data size from DWARF type
        let data_size = self.get_dwarf_type_size(dwarf_type) as u16;

        info!(
            "Building variable entry: name='{}' (len={}), type={:?}, data_size={}",
            var_name, name_len, type_encoding, data_size
        );

        // Write name_len at entry_offset + 0
        let name_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[i32_type.const_int(entry_offset as u64, false)],
                    "name_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(name_len_ptr, i8_type.const_int(name_len as u64, false))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write type_encoding at entry_offset + 1
        let type_encoding_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[i32_type.const_int((entry_offset + 1) as u64, false)],
                    "type_encoding_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        self.builder
            .build_store(
                type_encoding_ptr,
                i8_type.const_int(type_encoding as u8 as u64, false),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write data_len at entry_offset + 2 (as u16)
        let data_len_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[i32_type.const_int((entry_offset + 2) as u64, false)],
                    "data_len_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let data_len_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_len_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_len_i16_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_store(
                data_len_i16_ptr,
                i16_type.const_int(data_size as u64, false),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // Write variable name at entry_offset + 4
        let name_start_offset = entry_offset + 4;
        for (i, &byte) in name_bytes.iter().enumerate() {
            let byte_ptr = unsafe {
                self.builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[i32_type.const_int((name_start_offset + i as u32) as u64, false)],
                        "name_byte_ptr",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            self.builder
                .build_store(byte_ptr, i8_type.const_int(byte as u64, false))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        // Write variable data at entry_offset + 4 + name_len
        let data_start_offset = name_start_offset + name_len as u32;
        self.write_llvm_value_to_buffer(buffer, data_start_offset, computed_value, data_size)?;

        Ok(())
    }

    /// Write LLVM value to buffer at specified offset
    fn write_llvm_value_to_buffer(
        &mut self,
        buffer: PointerValue<'ctx>,
        offset: u32,
        value: BasicValueEnum<'ctx>,
        data_size: u16,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();

        // Get pointer to data location in buffer
        let data_ptr = unsafe {
            self.builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[i32_type.const_int(offset as u64, false)],
                    "data_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        match value {
            BasicValueEnum::IntValue(int_val) => {
                // Cast data_ptr to appropriate integer type pointer
                let target_type = self.context.ptr_type(AddressSpace::default());

                let typed_ptr = self
                    .builder
                    .build_pointer_cast(data_ptr, target_type, "typed_data_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                // Truncate or extend value to match target size
                let adjusted_value = match data_size {
                    1 => self
                        .builder
                        .build_int_truncate(int_val, self.context.i8_type(), "truncated")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    2 => self
                        .builder
                        .build_int_truncate(int_val, self.context.i16_type(), "truncated")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    4 => self
                        .builder
                        .build_int_truncate(int_val, self.context.i32_type(), "truncated")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    8 => int_val,
                    _ => int_val,
                };

                self.builder
                    .build_store(typed_ptr, adjusted_value)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            BasicValueEnum::FloatValue(float_val) => {
                // Cast data_ptr to appropriate float type pointer
                let target_type = self.context.ptr_type(AddressSpace::default());

                let typed_ptr = self
                    .builder
                    .build_pointer_cast(data_ptr, target_type, "typed_data_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                self.builder
                    .build_store(typed_ptr, float_val)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            BasicValueEnum::PointerValue(ptr_val) => {
                // Convert pointer to integer and store
                let ptr_as_int = self
                    .builder
                    .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                let ptr_type = self.context.ptr_type(AddressSpace::default());
                let typed_ptr = self
                    .builder
                    .build_pointer_cast(data_ptr, ptr_type, "typed_data_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                self.builder
                    .build_store(typed_ptr, ptr_as_int)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
            _ => {
                return Err(CodeGenError::TypeError(
                    "Unsupported value type for buffer write".to_string(),
                ));
            }
        }

        Ok(())
    }

    /// Calculate total message length
    fn calculate_message_length(
        &self,
        var_name: &str,
        dwarf_type: &ghostscope_dwarf::DwarfType,
    ) -> Result<usize> {
        use ghostscope_protocol::consts;

        let header_size = consts::MESSAGE_HEADER_SIZE;
        let var_data_size = consts::VARIABLE_DATA_MESSAGE_SIZE;
        let var_entry_size = 4; // VariableEntry struct
        let name_size = var_name.len();
        let data_size = self.get_dwarf_type_size(dwarf_type) as usize;

        Ok(header_size + var_data_size + var_entry_size + name_size + data_size)
    }

    /// Update message length in header
    fn update_message_length(
        &mut self,
        buffer: PointerValue<'ctx>,
        total_len: usize,
    ) -> Result<()> {
        let length_offset = 6; // MessageHeader.length is at offset 6
        let i32_type = self.context.i32_type();
        let i16_type = self.context.i16_type();

        let length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    buffer,
                    &[i32_type.const_int(length_offset, false)],
                    "length_ptr",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        let length_i16_ptr = self
            .builder
            .build_pointer_cast(
                length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "length_i16_ptr",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let length_val = i16_type.const_int(total_len as u64, false);
        self.builder
            .build_store(length_i16_ptr, length_val)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        Ok(())
    }

    /// Send direct value as variable
    fn send_direct_value_as_variable(
        &mut self,
        var_name: &str,
        _dwarf_type: &ghostscope_dwarf::DwarfType,
        _value: inkwell::values::BasicValueEnum<'ctx>,
    ) -> Result<()> {
        // TODO: Implement direct value variable message
        debug!("Sending direct value as variable: {}", var_name);
        Ok(())
    }

    /// Send optimized out variable message
    fn send_optimized_variable_message(
        &mut self,
        var_name: &str,
        _dwarf_type: &ghostscope_dwarf::DwarfType,
    ) -> Result<()> {
        // TODO: Implement optimized out message
        debug!("Sending optimized out variable message: {}", var_name);
        Ok(())
    }
}

use crate::CodeGenError;
use ghostscope_protocol::{consts, log_levels};
use inkwell::values::{FunctionValue, GlobalValue, IntValue, PointerValue};
use inkwell::{builder::Builder, context::Context, module::Module, AddressSpace};
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, CodeGenError>;

/// Debug logger for eBPF LLVM IR generation
/// Handles all debug output, logging, and runtime value inspection
pub struct DebugLogger<'ctx> {
    context: &'ctx Context,
}

impl<'ctx> DebugLogger<'ctx> {
    pub fn new(context: &'ctx Context) -> Self {
        Self { context }
    }

    /// Generate RBP debug output using standalone parameters to avoid borrowing conflicts
    pub fn generate_rbp_debug_standalone(
        context: &'ctx Context,
        builder: &'ctx Builder<'ctx>,
        module: &'ctx Module<'ctx>,
        var_name: &str,
        rbp_value: IntValue<'ctx>,
    ) -> Result<()> {
        let temp_logger = DebugLogger::new(context);
        temp_logger.generate_debug_rbp_hex(builder, module, var_name, rbp_value)
    }

    /// Generate debug output to print variable address in hex
    pub fn generate_debug_hex_output(
        &self,
        builder: &'ctx Builder<'ctx>,
        module: &'ctx Module<'ctx>,
        var_name: &str,
        address: IntValue<'ctx>,
    ) -> Result<()> {
        // Use new log message system instead of bpf_trace_printk
        let addr_val = address.get_zero_extended_constant().unwrap_or(0);
        let debug_msg = format!(
            "var:{} addr:0x{:x} rsp:<ebpf_unavailable>",
            var_name, addr_val
        );
        self.send_log_message(builder, module, log_levels::DEBUG, &debug_msg)?;

        Ok(())
    }

    /// Generate debug output for RBP register value in hex
    pub fn generate_debug_rbp_hex(
        &self,
        builder: &'ctx Builder<'ctx>,
        module: &'ctx Module<'ctx>,
        var_name: &str,
        rbp_value: IntValue<'ctx>,
    ) -> Result<()> {
        // Extract RBP value if it's a compile-time constant, otherwise indicate runtime value
        if let Some(rbp_const) = rbp_value.get_zero_extended_constant() {
            let debug_msg = format!("var:{} rbp:0x{:x}", var_name, rbp_const);
            self.send_log_message(builder, module, log_levels::DEBUG, &debug_msg)?;
        } else {
            let debug_msg = format!("var:{} rbp:<runtime_dynamic>", var_name);
            self.send_log_message(builder, module, log_levels::DEBUG, &debug_msg)?;
        }

        Ok(())
    }

    /// Generate debug output for bpf_probe_read_user return value
    pub fn generate_debug_probe_read_result(
        &self,
        builder: &'ctx Builder<'ctx>,
        module: &'ctx Module<'ctx>,
        var_name: &str,
        result_value: IntValue<'ctx>,
    ) -> Result<()> {
        // Use new log message system instead of bpf_trace_printk
        let result_val = result_value.get_sign_extended_constant().unwrap_or(-1);
        let debug_msg = format!(
            "var:{} probe_read_result:{} dst:kernel_buf size:8",
            var_name, result_val
        );
        self.send_log_message(builder, module, log_levels::DEBUG, &debug_msg)?;

        Ok(())
    }

    /// Send log message using new protocol format (replaces bpf_trace_printk)
    fn send_log_message(
        &self,
        builder: &'ctx Builder<'ctx>,
        module: &'ctx Module<'ctx>,
        log_level: u8,
        message: &str,
    ) -> Result<()> {
        let msg_storage = self.create_protocol_message_storage(module);
        self.build_log_message_header(builder, msg_storage, log_level, message.len() as u16)?;
        self.write_log_message_content(builder, msg_storage, message)?;
        self.finalize_and_send_log_message(builder, msg_storage, message.len())?;

        Ok(())
    }

    /// Create protocol message storage area
    fn create_protocol_message_storage(&self, module: &'ctx Module<'ctx>) -> PointerValue<'ctx> {
        let buffer_size = 1024u32;
        let i8_type = self.context.i8_type();
        let array_type = i8_type.array_type(buffer_size);

        let global_buffer = module.add_global(array_type, None, "protocol_msg_buffer");
        global_buffer.set_initializer(&i8_type.const_array(&[]));

        global_buffer.as_pointer_value()
    }

    /// Build log message header using protocol constants
    fn build_log_message_header(
        &self,
        builder: &'ctx Builder<'ctx>,
        buffer: PointerValue<'ctx>,
        log_level: u8,
        message_len: u16,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        // Build MessageHeader (8 bytes)
        self.write_message_header(builder, buffer)?;

        // Build LogMessage header (32 bytes)
        let log_msg_offset = consts::MESSAGE_HEADER_SIZE as usize;

        // trace_id (8 bytes)
        let trace_id = i64_type.const_int(consts::DEFAULT_TRACE_ID, false);
        self.write_field_at_offset(builder, buffer, log_msg_offset, trace_id)?;

        // timestamp (8 bytes)
        let timestamp = self.get_current_time();
        self.write_field_at_offset(builder, buffer, log_msg_offset + 8, timestamp)?;

        // pid/tid (4+4 bytes)
        let pid_tgid = self.get_current_pid_tgid();
        let pid = builder
            .build_right_shift(pid_tgid, i64_type.const_int(32, false), false, "pid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let tid = builder
            .build_and(pid_tgid, i64_type.const_int(0xFFFFFFFF, false), "tid")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let pid_val = builder
            .build_int_truncate(pid, i32_type, "pid_val")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let tid_val = builder
            .build_int_truncate(tid, i32_type, "tid_val")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.write_field_at_offset(builder, buffer, log_msg_offset + 16, pid_val)?;
        self.write_field_at_offset(builder, buffer, log_msg_offset + 20, tid_val)?;

        // log_level (1 byte)
        let log_level_val = i8_type.const_int(log_level as u64, false);
        self.write_field_at_offset(builder, buffer, log_msg_offset + 24, log_level_val)?;

        // reserved[3] (3 bytes) - zero
        let zero_byte = i8_type.const_int(0, false);
        for i in 0..3 {
            self.write_field_at_offset(builder, buffer, log_msg_offset + 25 + i, zero_byte)?;
        }

        // message_len (2 bytes)
        let msg_len_val = i16_type.const_int(message_len as u64, false);
        self.write_field_at_offset(builder, buffer, log_msg_offset + 28, msg_len_val)?;

        // reserved2 (2 bytes) - zero
        let zero_word = i16_type.const_int(0, false);
        self.write_field_at_offset(builder, buffer, log_msg_offset + 30, zero_word)?;

        Ok(())
    }

    /// Write MessageHeader using protocol constants
    fn write_message_header(
        &self,
        builder: &'ctx Builder<'ctx>,
        buffer: PointerValue<'ctx>,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();

        // Magic bytes from protocol constants
        let magic_bytes = consts::MAGIC.to_le_bytes();
        for (i, &byte) in magic_bytes.iter().enumerate() {
            let byte_val = i8_type.const_int(byte as u64, false);
            self.write_field_at_offset(builder, buffer, i, byte_val)?;
        }

        // Message type (Log)
        let msg_type = i8_type.const_int(0, false); // Log type is 0
        self.write_field_at_offset(builder, buffer, 4, msg_type)?;

        // Reserved byte
        let reserved = i8_type.const_int(0, false);
        self.write_field_at_offset(builder, buffer, 5, reserved)?;

        // Length (will be updated later)
        let length_placeholder = i16_type.const_int(0, false);
        self.write_field_at_offset(builder, buffer, 6, length_placeholder)?;

        Ok(())
    }

    /// Write a field at specific offset in buffer
    fn write_field_at_offset<T>(
        &self,
        builder: &'ctx Builder<'ctx>,
        buffer: PointerValue<'ctx>,
        offset: usize,
        value: T,
    ) -> Result<()>
    where
        T: inkwell::values::BasicValue<'ctx> + inkwell::values::AnyValue<'ctx>,
    {
        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();

        let field_ptr = unsafe {
            builder
                .build_gep(
                    i8_type,
                    buffer,
                    &[i32_type.const_int(offset as u64, false)],
                    &format!("field_ptr_{}", offset),
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };

        if let Some(value_size) = value.as_any_value_enum().get_type().size_of() {
            let i8_size = i8_type.size_of();
            if value_size.get_zero_extended_constant().unwrap_or(0)
                > i8_size.get_zero_extended_constant().unwrap_or(0)
            {
                let field_cast = builder
                    .build_pointer_cast(
                        field_ptr,
                        self.context.ptr_type(AddressSpace::default()),
                        &format!("field_cast_{}", offset),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                builder
                    .build_store(field_cast, value)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            } else {
                builder
                    .build_store(field_ptr, value)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            }
        } else {
            // If we can't get size info, just store directly
            builder
                .build_store(field_ptr, value)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        Ok(())
    }

    /// Write log message content to buffer
    fn write_log_message_content(
        &self,
        builder: &'ctx Builder<'ctx>,
        buffer: PointerValue<'ctx>,
        message: &str,
    ) -> Result<()> {
        let message_offset =
            consts::MESSAGE_HEADER_SIZE as usize + consts::LOG_MESSAGE_SIZE as usize;
        let i8_type = self.context.i8_type();
        let i32_type = self.context.i32_type();

        for (i, byte) in message.as_bytes().iter().enumerate() {
            let char_ptr = unsafe {
                builder
                    .build_gep(
                        i8_type,
                        buffer,
                        &[i32_type.const_int((message_offset + i) as u64, false)],
                        &format!("log_char_{}", i),
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let char_val = i8_type.const_int(*byte as u64, false);
            builder
                .build_store(char_ptr, char_val)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }

        Ok(())
    }

    /// Finalize message and send to ringbuf
    fn finalize_and_send_log_message(
        &self,
        builder: &'ctx Builder<'ctx>,
        buffer: PointerValue<'ctx>,
        message_len: usize,
    ) -> Result<()> {
        let total_len =
            consts::MESSAGE_HEADER_SIZE as usize + consts::LOG_MESSAGE_SIZE as usize + message_len;

        // Update total length in MessageHeader
        let i16_type = self.context.i16_type();
        let length_val = i16_type.const_int(total_len as u64, false);
        self.write_field_at_offset(builder, buffer, 6, length_val)?;

        // Send to ringbuf (placeholder - actual implementation needs ringbuf map access)
        // TODO: This needs to be implemented by passing ringbuf map reference

        Ok(())
    }

    /// Get current time using eBPF helper
    fn get_current_time(&self) -> IntValue<'ctx> {
        // This would call bpf_ktime_get_ns() helper (ID: 5)
        // For now, return a placeholder
        self.context.i64_type().const_int(0, false)
    }

    /// Get current pid/tgid using eBPF helper  
    fn get_current_pid_tgid(&self) -> IntValue<'ctx> {
        // This would call bpf_get_current_pid_tgid() helper (ID: 14)
        // For now, return a placeholder
        self.context.i64_type().const_int(0, false)
    }

    // Legacy bpf_trace_printk support methods (for fallback)

    /// Get or create bpf_trace_printk function declaration
    pub fn get_trace_printk_fn(&self, module: &'ctx Module<'ctx>) -> FunctionValue<'ctx> {
        if let Some(fn_val) = module.get_function("bpf_trace_printk") {
            return fn_val;
        }

        // Create function type for bpf_trace_printk
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let trace_printk_type = i32_type.fn_type(&[ptr_type.into()], true);

        // Declare the function
        let trace_printk_fn = module.add_function("bpf_trace_printk", trace_printk_type, None);
        trace_printk_fn.set_linkage(inkwell::module::Linkage::External);
        trace_printk_fn
    }

    /// Create global string constant for bpf_trace_printk format
    pub fn create_format_string_global(
        &self,
        module: &'ctx Module<'ctx>,
        format_str: &str,
    ) -> Result<GlobalValue<'ctx>> {
        let i8_type = self.context.i8_type();
        let string_type = i8_type.array_type(format_str.len() as u32 + 1);

        let mut string_bytes: Vec<_> = format_str
            .as_bytes()
            .iter()
            .map(|&b| i8_type.const_int(b as u64, false))
            .collect();
        string_bytes.push(i8_type.const_int(0, false)); // null terminator

        let string_const = i8_type.const_array(&string_bytes);
        let global = module.add_global(string_type, None, "debug_format_str");
        global.set_initializer(&string_const);

        Ok(global)
    }
}

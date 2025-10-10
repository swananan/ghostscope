//! Instruction transmission and ringbuf messaging
//!
//! This module handles the staged transmission of trace events via ringbuf:
//! Header → Message → Instructions → EndInstruction

use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_protocol::trace_event::{EndInstructionData, TraceEventHeader, TraceEventMessage};
use ghostscope_protocol::{consts, InstructionType};
use inkwell::values::PointerValue;
use inkwell::AddressSpace;
use tracing::info;

impl<'ctx> EbpfContext<'ctx> {
    /// Get or create the PerfEventArray accumulation buffer
    fn get_or_create_perf_accumulation_buffer(&mut self) -> PointerValue<'ctx> {
        // Check if buffer already exists
        if let Some(existing) = self.module.get_global("_perf_accumulation_buffer") {
            return existing.as_pointer_value();
        }

        // Create buffer for accumulating all trace data (size from protocol)
        let buffer_size = self.compile_options.max_trace_event_size;
        let i8_type = self.context.i8_type();
        let buffer_type = i8_type.array_type(buffer_size);

        let buffer = self.module.add_global(
            buffer_type,
            Some(AddressSpace::default()),
            "_perf_accumulation_buffer",
        );
        buffer.set_initializer(&buffer_type.const_zero());
        buffer.as_pointer_value()
    }

    /// Get or create the PerfEventArray buffer offset tracker (i32 global)
    fn get_or_create_perf_buffer_offset(&mut self) -> PointerValue<'ctx> {
        // Check if offset tracker already exists
        if let Some(existing) = self.module.get_global("_perf_buffer_offset") {
            return existing.as_pointer_value();
        }

        // Create i32 global for tracking current buffer offset
        let i32_type = self.context.i32_type();
        let offset_global = self.module.add_global(
            i32_type,
            Some(AddressSpace::default()),
            "_perf_buffer_offset",
        );
        offset_global.set_initializer(&i32_type.const_zero());
        offset_global.as_pointer_value()
    }

    /// Write data to accumulation buffer (PerfEventArray) or send immediately (RingBuf)
    pub fn write_to_accumulation_buffer_or_send(
        &mut self,
        data: PointerValue<'ctx>,
        size: u64,
    ) -> Result<()> {
        match self.compile_options.event_map_type {
            crate::EventMapType::RingBuf => {
                // RingBuf: Send immediately (existing behavior)
                self.create_event_output(data, size)?;
            }
            crate::EventMapType::PerfEventArray => {
                // PerfEventArray: Accumulate data into buffer
                let accum_buffer = self.get_or_create_perf_accumulation_buffer();
                let offset_ptr = self.get_or_create_perf_buffer_offset();

                // Load current offset
                let offset_val = self
                    .builder
                    .build_load(self.context.i32_type(), offset_ptr, "offset")
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to load offset: {e}")))?
                    .into_int_value();

                let buffer_size = self
                    .context
                    .i32_type()
                    .const_int(self.compile_options.max_trace_event_size as u64, false);

                // Get current block and parent function for branching
                let current_block = self.builder.get_insert_block().unwrap();
                let parent_fn = current_block.get_parent().unwrap();

                // Check 1: Ensure offset itself is bounded (offset < buffer_size)
                // This is critical for eBPF verifier to accept the pointer arithmetic
                let offset_in_bounds = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULT,
                        offset_val,
                        buffer_size,
                        "offset_in_bounds",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to compare offset: {e}"))
                    })?;

                let overflow_block = self
                    .context
                    .append_basic_block(parent_fn, "buffer_overflow");
                let check_write_block = self
                    .context
                    .append_basic_block(parent_fn, "check_write_size");

                self.builder
                    .build_conditional_branch(offset_in_bounds, check_write_block, overflow_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to build first branch: {e}"))
                    })?;

                // Check 2: Ensure offset + size doesn't exceed buffer
                self.builder.position_at_end(check_write_block);

                let size_i32 = self.context.i32_type().const_int(size, false);
                let new_offset_val = self
                    .builder
                    .build_int_add(offset_val, size_i32, "new_offset")
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to add size: {e}")))?;

                let write_fits = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::ULE,
                        new_offset_val,
                        buffer_size,
                        "write_fits",
                    )
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to compare write size: {e}"))
                    })?;

                let continue_block = self
                    .context
                    .append_basic_block(parent_fn, "continue_accumulate");

                self.builder
                    .build_conditional_branch(write_fits, continue_block, overflow_block)
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to build second branch: {e}"))
                    })?;

                // Overflow block: Reset offset to 0 and return early
                // This ensures subsequent trace events can start fresh
                self.builder.position_at_end(overflow_block);
                self.builder
                    .build_store(offset_ptr, self.context.i32_type().const_zero())
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to reset offset: {e}")))?;
                self.builder
                    .build_return(Some(&self.context.i32_type().const_zero()))
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to build return: {e}")))?;

                // Continue block: Both checks passed, safe to write
                self.builder.position_at_end(continue_block);

                // Manual pointer arithmetic with bounded offset
                // Zero-extend offset from i32 to i64 (unsigned)
                let offset_i64 = self
                    .builder
                    .build_int_z_extend(offset_val, self.context.i64_type(), "offset_i64")
                    .map_err(|e| {
                        CodeGenError::LLVMError(format!("Failed to extend offset: {e}"))
                    })?;

                // Use GEP with i64 to avoid sign extension
                let dest_ptr = unsafe {
                    self.builder
                        .build_gep(
                            self.context.i8_type(),
                            accum_buffer,
                            &[offset_i64],
                            "dest_ptr",
                        )
                        .map_err(|e| {
                            CodeGenError::LLVMError(format!("Failed to get dest GEP: {e}"))
                        })?
                };

                // memcpy: dest_ptr = data (size bytes)
                self.builder
                    .build_memcpy(
                        dest_ptr,
                        1,
                        data,
                        1,
                        self.context.i64_type().const_int(size, false),
                    )
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to memcpy: {e}")))?;

                // Update offset: offset += size
                // Reuse new_offset_val calculated earlier (line 108-115) to avoid redundant computation
                self.builder
                    .build_store(offset_ptr, new_offset_val)
                    .map_err(|e| CodeGenError::LLVMError(format!("Failed to store offset: {e}")))?;
            }
        }
        Ok(())
    }

    /// Send TraceEventHeader as first segment
    pub fn send_trace_event_header(&mut self) -> Result<()> {
        info!("Sending TraceEventHeader segment");

        // For PerfEventArray: Reset accumulation buffer offset to 0
        if matches!(
            self.compile_options.event_map_type,
            crate::EventMapType::PerfEventArray
        ) {
            let offset_ptr = self.get_or_create_perf_buffer_offset();
            self.builder
                .build_store(offset_ptr, self.context.i32_type().const_zero())
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to reset offset: {e}")))?;
        }

        let header_buffer = self.create_instruction_buffer();

        // Buffer is a zero-initialized global; explicit memset is unnecessary and not BPF-safe.
        let header_size = std::mem::size_of::<TraceEventHeader>() as u64;

        // Write TraceEventHeader
        // magic at offset 0 (only field needed)
        let magic_ptr = header_buffer;
        let magic_u32_ptr = self
            .builder
            .build_pointer_cast(
                magic_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "magic_u32_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast magic ptr: {e}")))?;
        let magic_val = self
            .context
            .i32_type()
            .const_int(ghostscope_protocol::consts::MAGIC.into(), false);
        self.builder
            .build_store(magic_u32_ptr, magic_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store magic: {e}")))?;

        // Send header segment (RingBuf) or accumulate (PerfEventArray)
        self.write_to_accumulation_buffer_or_send(header_buffer, header_size)?;

        Ok(())
    }

    /// Send TraceEventMessage as second segment
    pub fn send_trace_event_message(&mut self, trace_id: u64) -> Result<()> {
        info!(
            "Sending TraceEventMessage segment for trace_id: {}",
            trace_id
        );

        let message_buffer = self.create_instruction_buffer();

        // Buffer is zero-initialized; avoid memset which is not allowed in eBPF.
        let message_size = std::mem::size_of::<TraceEventMessage>() as u64;

        // Write TraceEventMessage
        // trace_id at offset 0
        let trace_id_ptr = message_buffer;
        let trace_id_u64_ptr = self
            .builder
            .build_pointer_cast(
                trace_id_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "trace_id_u64_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast trace_id ptr: {e}")))?;
        let trace_id_val = self.context.i64_type().const_int(trace_id, false);
        self.builder
            .build_store(trace_id_u64_ptr, trace_id_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store trace_id: {e}")))?;

        // timestamp at offset 8
        let timestamp = self.get_current_timestamp()?;
        let timestamp_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    message_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(consts::TRACE_EVENT_MESSAGE_TIMESTAMP_OFFSET as u64, false)],
                    "timestamp_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get timestamp GEP: {e}")))?
        };
        let timestamp_u64_ptr = self
            .builder
            .build_pointer_cast(
                timestamp_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "timestamp_u64_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast timestamp ptr: {e}")))?;
        self.builder
            .build_store(timestamp_u64_ptr, timestamp)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store timestamp: {e}")))?;

        // pid and tid at offset 16 and 20
        let pid_tgid_result = self.get_current_pid_tgid()?;
        let i32_type = self.context.i32_type();
        let pid = self
            .builder
            .build_int_truncate(pid_tgid_result, i32_type, "pid")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to truncate pid: {e}")))?;
        let shift_32 = self.context.i64_type().const_int(32, false);
        let tid_64 = self
            .builder
            .build_right_shift(pid_tgid_result, shift_32, false, "tid_64")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to shift tid: {e}")))?;
        let tid = self
            .builder
            .build_int_truncate(tid_64, i32_type, "tid")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to truncate tid: {e}")))?;

        // Store pid at offset 16
        let pid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    message_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(consts::TRACE_EVENT_MESSAGE_PID_OFFSET as u64, false)],
                    "pid_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get pid GEP: {e}")))?
        };
        let pid_u32_ptr = self
            .builder
            .build_pointer_cast(
                pid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "pid_u32_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast pid ptr: {e}")))?;
        self.builder
            .build_store(pid_u32_ptr, pid)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store pid: {e}")))?;

        // Store tid at offset 20
        let tid_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    message_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(consts::TRACE_EVENT_MESSAGE_TID_OFFSET as u64, false)],
                    "tid_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get tid GEP: {e}")))?
        };
        let tid_u32_ptr = self
            .builder
            .build_pointer_cast(
                tid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "tid_u32_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast tid ptr: {e}")))?;
        self.builder
            .build_store(tid_u32_ptr, tid)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store tid: {e}")))?;

        // Send message segment (RingBuf) or accumulate (PerfEventArray)
        self.write_to_accumulation_buffer_or_send(message_buffer, message_size)?;

        Ok(())
    }

    /// Send EndInstruction as final segment
    pub fn send_end_instruction(&mut self, total_instructions: u16) -> Result<()> {
        info!(
            "Sending EndInstruction segment with {} total instructions",
            total_instructions
        );

        let end_buffer = self.create_instruction_buffer();

        // Avoid memset; buffer is zero-initialized as global
        let total_size =
            (std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>()
                + std::mem::size_of::<EndInstructionData>()) as u64;

        // Write InstructionHeader
        // inst_type at offset 0
        let inst_type_ptr = end_buffer;
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::EndInstruction as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {e}")))?;

        // data_length at offset 1
        let data_length_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    end_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(consts::INSTRUCTION_HEADER_DATA_LENGTH_OFFSET as u64, false)],
                    "data_length_ptr",
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
                "data_length_i16_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {e}")))?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<EndInstructionData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {e}")))?;

        // Write EndInstructionData at offset 4
        // total_instructions
        let total_instructions_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    end_buffer,
                    &[self
                        .context
                        .i32_type()
                        .const_int(consts::END_INSTRUCTION_DATA_OFFSET as u64, false)],
                    "total_instructions_ptr",
                )
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get total_instructions GEP: {e}"))
                })?
        };
        let total_instructions_i16_ptr = self
            .builder
            .build_pointer_cast(
                total_instructions_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "total_instructions_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast total_instructions ptr: {e}"))
            })?;
        let total_instructions_val = self
            .context
            .i16_type()
            .const_int(total_instructions as u64, false);
        self.builder
            .build_store(total_instructions_i16_ptr, total_instructions_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store total_instructions: {e}"))
            })?;

        // execution_status at offset 6
        let status_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i8_type(),
                    end_buffer,
                    &[self.context.i32_type().const_int(
                        (consts::END_INSTRUCTION_DATA_OFFSET
                            + consts::END_INSTRUCTION_EXECUTION_STATUS_OFFSET)
                            as u64,
                        false,
                    )],
                    "status_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {e}")))?
        };
        // Compute execution_status from runtime flags _gs_any_fail and _gs_any_success
        let any_fail_ptr = self.get_or_create_flag_global("_gs_any_fail");
        let any_succ_ptr = self.get_or_create_flag_global("_gs_any_success");

        let any_fail_val = self
            .builder
            .build_load(self.context.i8_type(), any_fail_ptr, "any_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to load any_fail: {e}")))?
            .into_int_value();
        let any_succ_val = self
            .builder
            .build_load(self.context.i8_type(), any_succ_ptr, "any_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to load any_succ: {e}")))?
            .into_int_value();

        let zero = self.context.i8_type().const_zero();
        let is_fail = self
            .builder
            .build_int_compare(inkwell::IntPredicate::NE, any_fail_val, zero, "is_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cmp any_fail: {e}")))?;
        let is_succ = self
            .builder
            .build_int_compare(inkwell::IntPredicate::NE, any_succ_val, zero, "is_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cmp any_succ: {e}")))?;

        // status = if is_fail && !is_succ => 2
        //        else if is_fail && is_succ => 1
        //        else 0
        let not_succ = self
            .builder
            .build_not(is_succ, "not_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build not: {e}")))?;
        let only_fail = self
            .builder
            .build_and(is_fail, not_succ, "only_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build and: {e}")))?;
        let both = self
            .builder
            .build_and(is_fail, is_succ, "both")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build and: {e}")))?;

        let two = self.context.i8_type().const_int(2, false);
        let one = self.context.i8_type().const_int(1, false);
        let sel1 = self
            .builder
            .build_select(only_fail, two, zero, "status_sel1")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build select: {e}")))?
            .into_int_value();
        let sel2 = self
            .builder
            .build_select(both, one, sel1, "status_sel2")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build select: {e}")))?
            .into_int_value();

        self.builder
            .build_store(status_ptr, sel2)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {e}")))?;

        // Accumulate end instruction (RingBuf sends immediately, PerfEventArray accumulates)
        self.write_to_accumulation_buffer_or_send(end_buffer, total_size)?;

        // For PerfEventArray: Now send the entire accumulated buffer in one call
        if matches!(
            self.compile_options.event_map_type,
            crate::EventMapType::PerfEventArray
        ) {
            let accum_buffer = self.get_or_create_perf_accumulation_buffer();
            let offset_ptr = self.get_or_create_perf_buffer_offset();

            // Load total accumulated size
            let total_accumulated_size = self
                .builder
                .build_load(self.context.i32_type(), offset_ptr, "total_size")
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to load total size: {e}")))?
                .into_int_value();

            // Convert i32 to i64 for size parameter
            let total_size_i64 = self
                .builder
                .build_int_z_extend(
                    total_accumulated_size,
                    self.context.i64_type(),
                    "total_size_i64",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to extend size: {e}")))?;

            // Send entire accumulated buffer via perf_event_output
            self.create_perf_event_output_dynamic(accum_buffer, total_size_i64)?;

            // Reset offset to 0 after sending to ensure clean state for next trace event
            self.builder
                .build_store(offset_ptr, self.context.i32_type().const_zero())
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to reset offset after send: {e}"))
                })?;

            info!("Sent entire accumulated buffer via PerfEventArray and reset offset");
        }

        Ok(())
    }

    /// Create a global instruction buffer to avoid eBPF dynamic stack allocation
    pub fn create_instruction_buffer(&mut self) -> PointerValue<'ctx> {
        // Create a global buffer for instructions
        // Increased to support complex variable payloads up to ~2KB plus headers
        let buffer_size = 4096; // Sufficient for instruction data
        let i8_type = self.context.i8_type();
        let buffer_type = i8_type.array_type(buffer_size);

        let buffer = self.module.add_global(
            buffer_type,
            Some(AddressSpace::default()),
            "_instruction_buffer",
        );
        buffer.set_initializer(&buffer_type.const_zero());
        buffer.as_pointer_value()
    }
}

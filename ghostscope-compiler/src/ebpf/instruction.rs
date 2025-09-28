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
    /// Send TraceEventHeader as first segment
    pub fn send_trace_event_header(&mut self) -> Result<()> {
        info!("Sending TraceEventHeader segment");

        let header_buffer = self.create_instruction_buffer();

        // Clear buffer
        let header_size = std::mem::size_of::<TraceEventHeader>() as u64;
        self.builder
            .build_memset(
                header_buffer,
                1, // alignment
                self.context.i8_type().const_zero(),
                self.context.i64_type().const_int(header_size, false),
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to clear header buffer: {}", e))
            })?;

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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast magic ptr: {}", e)))?;
        let magic_val = self
            .context
            .i32_type()
            .const_int(ghostscope_protocol::consts::MAGIC.into(), false);
        self.builder
            .build_store(magic_u32_ptr, magic_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store magic: {}", e)))?;

        // Send header segment
        self.create_ringbuf_output(header_buffer, header_size)?;

        Ok(())
    }

    /// Send TraceEventMessage as second segment
    pub fn send_trace_event_message(&mut self, trace_id: u64) -> Result<()> {
        info!(
            "Sending TraceEventMessage segment for trace_id: {}",
            trace_id
        );

        let message_buffer = self.create_instruction_buffer();

        // Clear buffer
        let message_size = std::mem::size_of::<TraceEventMessage>() as u64;
        self.builder
            .build_memset(
                message_buffer,
                1, // alignment
                self.context.i8_type().const_zero(),
                self.context.i64_type().const_int(message_size, false),
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to clear message buffer: {}", e))
            })?;

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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast trace_id ptr: {}", e)))?;
        let trace_id_val = self.context.i64_type().const_int(trace_id, false);
        self.builder
            .build_store(trace_id_u64_ptr, trace_id_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store trace_id: {}", e)))?;

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
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to get timestamp GEP: {}", e))
                })?
        };
        let timestamp_u64_ptr = self
            .builder
            .build_pointer_cast(
                timestamp_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "timestamp_u64_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast timestamp ptr: {}", e)))?;
        self.builder
            .build_store(timestamp_u64_ptr, timestamp)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store timestamp: {}", e)))?;

        // pid and tid at offset 16 and 20
        let pid_tgid_result = self.get_current_pid_tgid()?;
        let i32_type = self.context.i32_type();
        let pid = self
            .builder
            .build_int_truncate(pid_tgid_result, i32_type, "pid")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to truncate pid: {}", e)))?;
        let shift_32 = self.context.i64_type().const_int(32, false);
        let tid_64 = self
            .builder
            .build_right_shift(pid_tgid_result, shift_32, false, "tid_64")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to shift tid: {}", e)))?;
        let tid = self
            .builder
            .build_int_truncate(tid_64, i32_type, "tid")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to truncate tid: {}", e)))?;

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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get pid GEP: {}", e)))?
        };
        let pid_u32_ptr = self
            .builder
            .build_pointer_cast(
                pid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "pid_u32_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast pid ptr: {}", e)))?;
        self.builder
            .build_store(pid_u32_ptr, pid)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store pid: {}", e)))?;

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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get tid GEP: {}", e)))?
        };
        let tid_u32_ptr = self
            .builder
            .build_pointer_cast(
                tid_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "tid_u32_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cast tid ptr: {}", e)))?;
        self.builder
            .build_store(tid_u32_ptr, tid)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store tid: {}", e)))?;

        // Send message segment
        self.create_ringbuf_output(message_buffer, message_size)?;

        Ok(())
    }

    /// Send EndInstruction as final segment
    pub fn send_end_instruction(&mut self, total_instructions: u16) -> Result<()> {
        info!(
            "Sending EndInstruction segment with {} total instructions",
            total_instructions
        );

        let end_buffer = self.create_instruction_buffer();

        // Clear buffer
        let total_size =
            (std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>()
                + std::mem::size_of::<EndInstructionData>()) as u64;
        self.builder
            .build_memset(
                end_buffer,
                1, // alignment
                self.context.i8_type().const_zero(),
                self.context.i64_type().const_int(total_size, false),
            )
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to clear end buffer: {}", e)))?;

        // Write InstructionHeader
        // inst_type at offset 0
        let inst_type_ptr = end_buffer;
        let inst_type_val = self
            .context
            .i8_type()
            .const_int(InstructionType::EndInstruction as u64, false);
        self.builder
            .build_store(inst_type_ptr, inst_type_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store inst_type: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get data_length GEP: {}", e))
                })?
        };
        let data_length_i16_ptr = self
            .builder
            .build_pointer_cast(
                data_length_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "data_length_i16_ptr",
            )
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast data_length ptr: {}", e))
            })?;
        let data_length_val = self
            .context
            .i16_type()
            .const_int(std::mem::size_of::<EndInstructionData>() as u64, false);
        self.builder
            .build_store(data_length_i16_ptr, data_length_val)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store data_length: {}", e)))?;

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
                    CodeGenError::LLVMError(format!("Failed to get total_instructions GEP: {}", e))
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
                CodeGenError::LLVMError(format!("Failed to cast total_instructions ptr: {}", e))
            })?;
        let total_instructions_val = self
            .context
            .i16_type()
            .const_int(total_instructions as u64, false);
        self.builder
            .build_store(total_instructions_i16_ptr, total_instructions_val)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to store total_instructions: {}", e))
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
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to get status GEP: {}", e)))?
        };
        // Compute execution_status from runtime flags _gs_any_fail and _gs_any_success
        let any_fail_ptr = self.get_or_create_flag_global("_gs_any_fail");
        let any_succ_ptr = self.get_or_create_flag_global("_gs_any_success");

        let any_fail_val = self
            .builder
            .build_load(self.context.i8_type(), any_fail_ptr, "any_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to load any_fail: {}", e)))?
            .into_int_value();
        let any_succ_val = self
            .builder
            .build_load(self.context.i8_type(), any_succ_ptr, "any_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to load any_succ: {}", e)))?
            .into_int_value();

        let zero = self.context.i8_type().const_zero();
        let is_fail = self
            .builder
            .build_int_compare(inkwell::IntPredicate::NE, any_fail_val, zero, "is_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cmp any_fail: {}", e)))?;
        let is_succ = self
            .builder
            .build_int_compare(inkwell::IntPredicate::NE, any_succ_val, zero, "is_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to cmp any_succ: {}", e)))?;

        // status = if is_fail && !is_succ => 2
        //        else if is_fail && is_succ => 1
        //        else 0
        let not_succ = self
            .builder
            .build_not(is_succ, "not_succ")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build not: {}", e)))?;
        let only_fail = self
            .builder
            .build_and(is_fail, not_succ, "only_fail")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build and: {}", e)))?;
        let both = self
            .builder
            .build_and(is_fail, is_succ, "both")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build and: {}", e)))?;

        let two = self.context.i8_type().const_int(2, false);
        let one = self.context.i8_type().const_int(1, false);
        let sel1 = self
            .builder
            .build_select(only_fail, two, zero, "status_sel1")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build select: {}", e)))?
            .into_int_value();
        let sel2 = self
            .builder
            .build_select(both, one, sel1, "status_sel2")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to build select: {}", e)))?
            .into_int_value();

        self.builder
            .build_store(status_ptr, sel2)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store status: {}", e)))?;

        // Send end instruction segment
        self.create_ringbuf_output(end_buffer, total_size)?;

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

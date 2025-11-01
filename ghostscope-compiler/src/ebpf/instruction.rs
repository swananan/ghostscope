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
    /// Reserve `size` bytes in the per-CPU accumulation buffer and return a pointer to the
    /// beginning of the reserved region. On overflow, resets the event offset and returns
    /// from the eBPF program early (mirrors existing control-flow style used elsewhere).
    fn reserve_event_space(&mut self, size: u64) -> PointerValue<'ctx> {
        let i32_ty = self.context.i32_type();
        let i64_ty = self.context.i64_type();

        // Lookup accumulation buffer value pointer; early-return if NULL
        let accum_buffer = self.get_or_create_perf_accumulation_buffer();
        let offset_ptr = self.get_or_create_perf_buffer_offset();

        // Load current offset
        let offset_val = self
            .builder
            .build_load(i32_ty, offset_ptr, "offset")
            .expect("Failed to load offset")
            .into_int_value();

        let buffer_size = i32_ty.const_int(self.compile_options.max_trace_event_size as u64, false);
        let req_size_i32 = i32_ty.const_int(size, false);

        // Branching blocks
        let current_block = self.builder.get_insert_block().unwrap();
        let parent_fn = current_block.get_parent().unwrap();
        let bb_overflow = self
            .context
            .append_basic_block(parent_fn, "reserve_overflow");
        let bb_check_size = self
            .context
            .append_basic_block(parent_fn, "reserve_check_size");
        let bb_check_fit = self
            .context
            .append_basic_block(parent_fn, "reserve_check_fit");

        // if (offset < buffer_size) goto check_size else overflow
        let off_in = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULT,
                offset_val,
                buffer_size,
                "off_in",
            )
            .expect("cmp failed");
        self.builder
            .build_conditional_branch(off_in, bb_check_size, bb_overflow)
            .expect("branch failed");

        // overflow: reset offset and return 0
        self.builder.position_at_end(bb_overflow);
        self.builder
            .build_store(offset_ptr, i32_ty.const_zero())
            .expect("reset store failed");
        self.builder
            .build_return(Some(&i32_ty.const_zero()))
            .expect("return failed");

        // check_size: require size <= buffer_size to avoid underflow in (buffer_size - size)
        self.builder.position_at_end(bb_check_size);
        let size_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                req_size_i32,
                buffer_size,
                "size_ok",
            )
            .expect("cmp failed");
        self.builder
            .build_conditional_branch(size_ok, bb_check_fit, bb_overflow)
            .expect("branch failed");

        // check_fit: need offset <= buffer_size - size (safe: no underflow)
        self.builder.position_at_end(bb_check_fit);
        let limit = self
            .builder
            .build_int_sub(buffer_size, req_size_i32, "limit")
            .expect("sub failed");
        let fits = self
            .builder
            .build_int_compare(inkwell::IntPredicate::ULE, offset_val, limit, "fits")
            .expect("cmp failed");
        let bb_ok = self.context.append_basic_block(parent_fn, "reserve_ok");
        self.builder
            .build_conditional_branch(fits, bb_ok, bb_overflow)
            .expect("branch2 failed");

        // ok: compute dest, bump offset, return dest
        self.builder.position_at_end(bb_ok);
        let off64 = self
            .builder
            .build_int_z_extend(offset_val, i64_ty, "off64")
            .expect("zext failed");
        let dest_i8 = unsafe {
            self.builder
                .build_gep(self.context.i8_type(), accum_buffer, &[off64], "dest_i8")
                .expect("gep failed")
        };
        let new_off = self
            .builder
            .build_int_add(offset_val, req_size_i32, "new_off")
            .expect("add failed");
        self.builder
            .build_store(offset_ptr, new_off)
            .expect("store new_off failed");

        dest_i8
    }

    /// Wrapper to reserve instruction region directly in the accumulation buffer.
    pub(crate) fn reserve_instruction_region(&mut self, size: u64) -> PointerValue<'ctx> {
        self.reserve_event_space(size)
    }
    /// Get per-CPU accumulation buffer pointer (event_accum_buffer[0]) and return early if null.
    fn get_or_create_perf_accumulation_buffer(&mut self) -> PointerValue<'ctx> {
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let val_ptr = self
            .lookup_percpu_value_ptr("event_accum_buffer", 0)
            .expect("event_accum_buffer lookup failed");

        // if (val_ptr == NULL) return 0;
        let is_null = self
            .builder
            .build_is_null(val_ptr, "accum_buf_is_null")
            .expect("build_is_null failed");
        let current_fn = self
            .builder
            .get_insert_block()
            .unwrap()
            .get_parent()
            .unwrap();
        let cont_bb = self
            .context
            .append_basic_block(current_fn, "accum_buf_cont");
        let ret_bb = self.context.append_basic_block(current_fn, "accum_buf_ret");
        self.builder
            .build_conditional_branch(is_null, ret_bb, cont_bb)
            .expect("build_conditional_branch failed");
        // return 0 in ret_bb
        self.builder.position_at_end(ret_bb);
        self.builder
            .build_return(Some(&self.context.i32_type().const_zero()))
            .expect("build_return failed");
        // continue in cont_bb
        self.builder.position_at_end(cont_bb);

        // Cast to i8* if necessary (keep as generic pointer; loads/stores will cast as needed)
        self.builder
            .build_bit_cast(val_ptr, ptr_ty, "accum_buf_ptr")
            .expect("bitcast failed")
            .into_pointer_value()
    }

    /// Get pointer to per-invocation stack event offset (u32)
    fn get_or_create_perf_buffer_offset(&mut self) -> PointerValue<'ctx> {
        self.event_offset_alloca
            .expect("event_offset not allocated in entry block")
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

        // Buffer is a zero-initialized map value region; explicit memset is unnecessary and not BPF-safe.
        let header_size = std::mem::size_of::<TraceEventHeader>() as u64;
        let header_buffer = self.reserve_instruction_region(header_size);

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

        // Already wrote into the accumulation buffer; no copy needed

        Ok(())
    }

    /// Send TraceEventMessage as second segment
    pub fn send_trace_event_message(&mut self, trace_id: u64) -> Result<()> {
        info!(
            "Sending TraceEventMessage segment for trace_id: {}",
            trace_id
        );

        // Buffer is zero-initialized in map value; avoid memset which is not allowed in eBPF.
        let message_size = std::mem::size_of::<TraceEventMessage>() as u64;
        let message_buffer = self.reserve_instruction_region(message_size);

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

        // Already wrote into the accumulation buffer; no copy needed

        Ok(())
    }

    /// Send EndInstruction as final segment
    pub fn send_end_instruction(&mut self, total_instructions: u16) -> Result<()> {
        info!(
            "Sending EndInstruction segment with {} total instructions",
            total_instructions
        );

        // Avoid memset; destination is in accumulation buffer
        let total_size =
            (std::mem::size_of::<ghostscope_protocol::trace_event::InstructionHeader>()
                + std::mem::size_of::<EndInstructionData>()) as u64;
        let end_buffer = self.reserve_instruction_region(total_size);

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

        // Already accumulated in per-CPU buffer; no extra copy needed

        // End: send the entire accumulated buffer once (RingBuf or PerfEventArray)
        {
            let accum_buffer = self.get_or_create_perf_accumulation_buffer();
            let offset_ptr = self.get_or_create_perf_buffer_offset();

            // Load total accumulated size (u32)
            let total_accumulated_size = self
                .builder
                .build_load(self.context.i32_type(), offset_ptr, "total_size")
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to load total size: {e}")))?
                .into_int_value();

            // Clamp size to [0, max_trace_event_size] to satisfy verifier bounded access
            let max_size_i32 = self
                .context
                .i32_type()
                .const_int(self.compile_options.max_trace_event_size as u64, false);
            let size_le_max = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULE,
                    total_accumulated_size,
                    max_size_i32,
                    "size_le_max",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to compare end size: {e}")))?;
            let clamped_size_i32 = self
                .builder
                .build_select(
                    size_le_max,
                    total_accumulated_size,
                    max_size_i32,
                    "clamped_size_i32",
                )
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to select clamp size: {e}")))?
                .into_int_value();

            // Convert i32 to i64 for size parameter
            let total_size_i64 = self
                .builder
                .build_int_z_extend(clamped_size_i32, self.context.i64_type(), "total_size_i64")
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to extend size: {e}")))?;

            match self.compile_options.event_map_type {
                crate::EventMapType::PerfEventArray => {
                    // Single-shot perf send
                    self.create_perf_event_output_dynamic(accum_buffer, total_size_i64)?;
                }
                crate::EventMapType::RingBuf => {
                    // Single-shot ringbuf send
                    self.create_ringbuf_output_dynamic(accum_buffer, total_size_i64)?;
                }
            }

            // Reset offset to 0 after sending to ensure clean state for next trace event
            self.builder
                .build_store(offset_ptr, self.context.i32_type().const_zero())
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to reset offset after send: {e}"))
                })?;
        }

        Ok(())
    }
}

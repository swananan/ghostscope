//! Instruction transmission and ringbuf messaging
//!
//! This module handles the staged transmission of trace events via ringbuf:
//! Header → Message → Instructions → EndInstruction

use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_protocol::trace_event::{EndInstructionData, TraceEventHeader, TraceEventMessage};
use ghostscope_protocol::{consts, InstructionType};
use inkwell::basic_block::BasicBlock;
use inkwell::values::{FunctionValue, PointerValue};
use inkwell::AddressSpace;
use tracing::info;

#[cfg(test)]
const fn split_pid_tgid(pid_tgid: u64) -> (u32, u32) {
    ((pid_tgid >> 32) as u32, pid_tgid as u32)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RuntimeEarlyReturnReason {
    AccumulationBufferNull,
    EventBufferOverflow,
}

#[derive(Clone, Copy)]
pub(crate) struct RuntimeEarlyReturn<'ctx> {
    reason: RuntimeEarlyReturnReason,
    block: BasicBlock<'ctx>,
}

#[derive(Clone, Copy)]
pub(crate) struct CodegenContinuation<'ctx> {
    function: FunctionValue<'ctx>,
    block: BasicBlock<'ctx>,
}

pub(crate) struct RuntimeReturnAwareValue<'ctx, T> {
    value: T,
    continuation: CodegenContinuation<'ctx>,
    early_returns: Vec<RuntimeEarlyReturn<'ctx>>,
}

impl<'ctx, T> RuntimeReturnAwareValue<'ctx, T> {
    pub(crate) fn into_value_after_runtime_returns(self) -> T {
        let Self {
            value,
            continuation,
            early_returns,
        } = self;
        let _ = (&continuation.function, &continuation.block);
        for early_return in &early_returns {
            let _ = (&early_return.reason, &early_return.block);
        }
        value
    }
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Reserve `size` bytes in the per-CPU accumulation buffer and return a pointer to the
    /// beginning of the reserved region. On overflow, resets the event offset and returns
    /// from the eBPF program early (mirrors existing control-flow style used elsewhere).
    fn reserve_event_space_or_return_zero(
        &mut self,
        size: u64,
    ) -> Result<RuntimeReturnAwareValue<'ctx, PointerValue<'ctx>>> {
        let i32_ty = self.context.i32_type();
        let i64_ty = self.context.i64_type();

        // Lookup accumulation buffer value pointer; early-return if NULL
        let accum_buffer_lookup = self.get_or_create_perf_accumulation_buffer_or_return_zero()?;
        let accum_buffer = accum_buffer_lookup.value;
        let mut early_returns = accum_buffer_lookup.early_returns;
        let offset_ptr = self.get_or_create_perf_buffer_offset()?;

        // Load current offset
        let offset_val = self
            .builder
            .build_load(i32_ty, offset_ptr, "offset")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to load offset: {e}")))?
            .into_int_value();

        let buffer_size = i32_ty.const_int(self.compile_options.max_trace_event_size as u64, false);
        let req_size_i32 = i32_ty.const_int(size, false);

        // Branching blocks
        let CodegenContinuation {
            function: parent_fn,
            ..
        } = self.current_codegen_continuation("reserve event space")?;
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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to compare offset: {e}")))?;
        self.builder
            .build_conditional_branch(off_in, bb_check_size, bb_overflow)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch on offset bounds: {e}"))
            })?;

        // overflow: reset offset and return 0
        self.builder.position_at_end(bb_overflow);
        self.builder
            .build_store(offset_ptr, i32_ty.const_zero())
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to reset offset: {e}")))?;
        self.builder
            .build_return(Some(&i32_ty.const_zero()))
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to build overflow return: {e}"))
            })?;
        early_returns.push(RuntimeEarlyReturn {
            reason: RuntimeEarlyReturnReason::EventBufferOverflow,
            block: bb_overflow,
        });

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
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to compare reserve size: {e}")))?;
        self.builder
            .build_conditional_branch(size_ok, bb_check_fit, bb_overflow)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch on reserve size: {e}"))
            })?;

        // check_fit: need offset <= buffer_size - size (safe: no underflow)
        self.builder.position_at_end(bb_check_fit);
        let limit = self
            .builder
            .build_int_sub(buffer_size, req_size_i32, "limit")
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to compute reserve limit: {e}"))
            })?;
        let fits = self
            .builder
            .build_int_compare(inkwell::IntPredicate::ULE, offset_val, limit, "fits")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to compare reserve fit: {e}")))?;
        let bb_ok = self.context.append_basic_block(parent_fn, "reserve_ok");
        self.builder
            .build_conditional_branch(fits, bb_ok, bb_overflow)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch on reserve fit: {e}"))
            })?;

        // ok: compute dest, bump offset, return dest
        self.builder.position_at_end(bb_ok);
        let off64 = self
            .builder
            .build_int_z_extend(offset_val, i64_ty, "off64")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to extend offset: {e}")))?;
        // SAFETY: the reserve bounds check proved offset_val..offset_val+size fits
        // inside the accumulation buffer.
        let dest_i8 = unsafe {
            self.builder
                .build_gep(self.context.i8_type(), accum_buffer, &[off64], "dest_i8")
                .map_err(|e| {
                    CodeGenError::LLVMError(format!("Failed to compute destination: {e}"))
                })?
        };
        let new_off = self
            .builder
            .build_int_add(offset_val, req_size_i32, "new_off")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to update offset: {e}")))?;
        self.builder
            .build_store(offset_ptr, new_off)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store updated offset: {e}")))?;
        self.compile_time_event_bytes_upper_bound = self
            .compile_time_event_bytes_upper_bound
            .saturating_add(size as usize);

        Ok(RuntimeReturnAwareValue {
            value: dest_i8,
            continuation: CodegenContinuation {
                function: parent_fn,
                block: bb_ok,
            },
            early_returns,
        })
    }

    /// Wrapper to reserve instruction region directly in the accumulation buffer.
    pub(crate) fn reserve_instruction_region_or_return_zero(
        &mut self,
        size: u64,
    ) -> Result<RuntimeReturnAwareValue<'ctx, PointerValue<'ctx>>> {
        self.reserve_event_space_or_return_zero(size)
    }

    /// Get per-CPU accumulation buffer pointer (event_accum_buffer[0]) and return early if null.
    fn get_or_create_perf_accumulation_buffer_or_return_zero(
        &mut self,
    ) -> Result<RuntimeReturnAwareValue<'ctx, PointerValue<'ctx>>> {
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let val_ptr = self.lookup_percpu_value_ptr("event_accum_buffer", 0)?;

        // if (val_ptr == NULL) return 0;
        let is_null = self
            .builder
            .build_is_null(val_ptr, "accum_buf_is_null")
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to check buffer null: {e}")))?;
        let current_fn = self
            .current_codegen_continuation("check accumulation buffer")?
            .function;
        let cont_bb = self
            .context
            .append_basic_block(current_fn, "accum_buf_cont");
        let ret_bb = self.context.append_basic_block(current_fn, "accum_buf_ret");
        self.builder
            .build_conditional_branch(is_null, ret_bb, cont_bb)
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to branch on accumulation buffer: {e}"))
            })?;
        // return 0 in ret_bb
        self.builder.position_at_end(ret_bb);
        self.builder
            .build_return(Some(&self.context.i32_type().const_zero()))
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to build accumulation buffer return: {e}"))
            })?;
        // continue in cont_bb
        self.builder.position_at_end(cont_bb);

        // Cast to i8* if necessary (keep as generic pointer; loads/stores will cast as needed)
        let accum_buffer = self
            .builder
            .build_bit_cast(val_ptr, ptr_ty, "accum_buf_ptr")
            .map_err(|e| {
                CodeGenError::LLVMError(format!("Failed to cast accumulation buffer: {e}"))
            })?;
        let accum_buffer = match accum_buffer {
            inkwell::values::BasicValueEnum::PointerValue(ptr) => ptr,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "Accumulation buffer cast did not produce a pointer".to_string(),
                ));
            }
        };

        Ok(RuntimeReturnAwareValue {
            value: accum_buffer,
            continuation: CodegenContinuation {
                function: current_fn,
                block: cont_bb,
            },
            early_returns: vec![RuntimeEarlyReturn {
                reason: RuntimeEarlyReturnReason::AccumulationBufferNull,
                block: ret_bb,
            }],
        })
    }

    /// Get pointer to per-invocation stack event offset (u32)
    fn get_or_create_perf_buffer_offset(&self) -> Result<PointerValue<'ctx>> {
        self.event_offset_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("event_offset not allocated in entry block".to_string())
        })
    }

    fn current_codegen_continuation(&self, op: &str) -> Result<CodegenContinuation<'ctx>> {
        let block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::Builder(format!("{op} requires an active insert block"))
        })?;
        let function = block
            .get_parent()
            .ok_or_else(|| CodeGenError::Builder(format!("{op} requires a parent function")))?;
        Ok(CodegenContinuation { function, block })
    }

    /// Send TraceEventHeader as first segment
    pub fn send_trace_event_header(&mut self) -> Result<()> {
        info!("Sending TraceEventHeader segment");
        self.compile_time_event_bytes_upper_bound = 0;

        // For PerfEventArray: Reset accumulation buffer offset to 0
        if matches!(
            self.compile_options.event_map_type,
            crate::EventMapType::PerfEventArray
        ) {
            let offset_ptr = self.get_or_create_perf_buffer_offset()?;
            self.builder
                .build_store(offset_ptr, self.context.i32_type().const_zero())
                .map_err(|e| CodeGenError::LLVMError(format!("Failed to reset offset: {e}")))?;
        }

        // Buffer is a zero-initialized map value region; explicit memset is unnecessary and not BPF-safe.
        let header_size = std::mem::size_of::<TraceEventHeader>() as u64;
        let header_buffer = self
            .reserve_instruction_region_or_return_zero(header_size)?
            .into_value_after_runtime_returns();

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
        let message_buffer = self
            .reserve_instruction_region_or_return_zero(message_size)?
            .into_value_after_runtime_returns();

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
        // SAFETY: message_buffer points at a reserved trace event header region
        // and the timestamp offset is within that header.
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

        // Keep transport metadata on host/event semantics. Namespace-aware
        // `$pid`/`$tid` remain available through the special var path.
        let (event_pid, event_tid) = self.get_host_pid_tid_values()?;

        // Store pid at offset 16
        // SAFETY: message_buffer points at a reserved trace event header region
        // and the pid offset is within that header.
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
            .build_store(pid_u32_ptr, event_pid)
            .map_err(|e| CodeGenError::LLVMError(format!("Failed to store pid: {e}")))?;

        // Store tid at offset 20
        // SAFETY: message_buffer points at a reserved trace event header region
        // and the tid offset is within that header.
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
            .build_store(tid_u32_ptr, event_tid)
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
        let end_buffer = self
            .reserve_instruction_region_or_return_zero(total_size)?
            .into_value_after_runtime_returns();

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
        // SAFETY: end_buffer points at a reserved EndInstruction region and
        // data_length is within InstructionHeader.
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
        // SAFETY: EndInstructionData starts at END_INSTRUCTION_DATA_OFFSET inside
        // the reserved EndInstruction region.
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
        // SAFETY: execution_status offset is within EndInstructionData in the
        // reserved EndInstruction region.
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
            let accum_buffer = self
                .get_or_create_perf_accumulation_buffer_or_return_zero()?
                .into_value_after_runtime_returns();
            let offset_ptr = self.get_or_create_perf_buffer_offset()?;

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

#[cfg(test)]
mod tests {
    use super::split_pid_tgid;

    #[test]
    fn split_pid_tgid_uses_tgid_for_pid_and_pid_for_tid() {
        let raw = (0x1122_3344_u64 << 32) | 0x5566_7788;

        let (pid, tid) = split_pid_tgid(raw);

        assert_eq!(pid, 0x1122_3344);
        assert_eq!(tid, 0x5566_7788);
    }
}

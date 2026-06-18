use super::backtrace_plan::{
    BacktraceEmitMode, BacktraceInstructionPlan, BPF_INLINE_BACKTRACE_FRAME_LIMIT,
};
use super::*;
use crate::script::BacktraceStatement;
use aya_ebpf_bindings::bindings::bpf_func_id::{BPF_FUNC_map_lookup_elem, BPF_FUNC_tail_call};
use ghostscope_dwarf::{CompactUnwindRow, MemoryAccessSize, ModuleAddress};
use inkwell::basic_block::BasicBlock;
use inkwell::values::BasicMetadataValueEnum;
use std::path::PathBuf;

const X86_64_DWARF_RIP: u16 = 16;
const X86_64_DWARF_RBP: u16 = 6;
const X86_64_DWARF_RSP: u16 = 7;
const BPF_BACKTRACE_FRAMES_PER_TAIL_CALL: u8 = 4;
const BPF_BACKTRACE_MAX_STEP_INVOCATIONS: u8 = 32;
const BPF_BACKTRACE_STEP_PROG_INDEX: u32 = 0;

struct RuntimeBtUnwindRow<'ctx> {
    found: IntValue<'ctx>,
    cfa_register: IntValue<'ctx>,
    cfa_offset: IntValue<'ctx>,
    ra_kind: IntValue<'ctx>,
    ra_register: IntValue<'ctx>,
    ra_offset: IntValue<'ctx>,
    rbp_kind: IntValue<'ctx>,
    rbp_register: IntValue<'ctx>,
    rbp_offset: IntValue<'ctx>,
}

struct BtFrameModule<'ctx> {
    cookie: IntValue<'ctx>,
    bias: IntValue<'ctx>,
    found: IntValue<'ctx>,
}

struct BtRowBounds<'ctx> {
    start: IntValue<'ctx>,
    end: IntValue<'ctx>,
}

struct BtModuleRangeMeta<'ctx> {
    found: IntValue<'ctx>,
    active_slot: IntValue<'ctx>,
    count: IntValue<'ctx>,
}

struct BtModuleRangeValue<'ctx> {
    found: IntValue<'ctx>,
    base: IntValue<'ctx>,
    end: IntValue<'ctx>,
    text: IntValue<'ctx>,
    cookie: IntValue<'ctx>,
}

struct RuntimeBtRowScratch<'ctx> {
    found_ptr: PointerValue<'ctx>,
    cfa_register_ptr: PointerValue<'ctx>,
    cfa_offset_ptr: PointerValue<'ctx>,
    ra_kind_ptr: PointerValue<'ctx>,
    ra_register_ptr: PointerValue<'ctx>,
    ra_offset_ptr: PointerValue<'ctx>,
    rbp_kind_ptr: PointerValue<'ctx>,
    rbp_register_ptr: PointerValue<'ctx>,
    rbp_offset_ptr: PointerValue<'ctx>,
}

struct BtScratch<'ctx> {
    row: RuntimeBtRowScratch<'ctx>,
    next_rbp_ptr: PointerValue<'ctx>,
    next_error_code_ptr: PointerValue<'ctx>,
}

#[derive(Clone, Copy)]
struct BtRegisterState<'ctx> {
    ip: IntValue<'ctx>,
    rsp: IntValue<'ctx>,
    rbp: IntValue<'ctx>,
}

#[derive(Clone, Copy)]
struct BtNextFrame<'ctx> {
    ip: IntValue<'ctx>,
    rsp: IntValue<'ctx>,
    rbp: IntValue<'ctx>,
    error_code: IntValue<'ctx>,
}

struct BtFrameValidation<'ctx> {
    valid: IntValue<'ctx>,
    complete: IntValue<'ctx>,
    error_code: IntValue<'ctx>,
}

enum BacktraceUnwindRowForPc {
    Usable(ghostscope_protocol::BacktraceUnwindRow),
    Missing,
    Unsupported,
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub fn generate_backtrace_instruction(&mut self, stmt: &BacktraceStatement) -> Result<()> {
        let plan = self.plan_backtrace_instruction(stmt);
        if matches!(plan.mode, BacktraceEmitMode::TailCall) {
            return self.generate_tail_call_backtrace_instruction(&plan);
        }

        self.generate_inline_backtrace_instruction(&plan)
    }

    /// Generate a DWARF-backed Backtrace instruction.
    ///
    /// eBPF records `(module_cookie, normalized_pc, raw_ip)` frames and advances
    /// the unwind state from compact DWARF CFI rows. Userspace owns final source
    /// line and inline-chain symbolization.
    fn generate_inline_backtrace_instruction(
        &mut self,
        plan: &BacktraceInstructionPlan,
    ) -> Result<()> {
        let depth = plan.depth;
        let flags = plan.flags;
        info!("Generating Backtrace instruction: depth={}", depth);

        let payload_size = plan.payload_size;
        let instruction_size = plan.instruction_size;
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(instruction_size as u64)?
            .into_value_after_runtime_returns();

        self.store_u8_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, inst_type),
            InstructionType::Backtrace as u8,
            "bt_inst_type",
        )?;
        self.store_u16_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, data_length),
            payload_size as u16,
            "bt_data_length",
        )?;

        let data_base = INSTRUCTION_HEADER_SIZE;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET,
            depth,
            "bt_requested_depth",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            1,
            "bt_frame_count",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FLAGS_OFFSET,
            flags,
            "bt_flags",
        )?;
        self.store_u16_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            0,
            "bt_error_code",
        )?;

        let Some(compile_ctx) = self.current_compile_time_context.clone() else {
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                0,
                "bt_frame_count_no_context",
            )?;
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                BacktraceStatus::DwarfUnavailable as u8,
                "bt_status_no_context",
            )?;
            return Ok(());
        };

        let module_cookie = self.cookie_for_module_or_fallback(&compile_ctx.module_path);
        let module_cookie_value = self.context.i64_type().const_int(module_cookie, false);
        let pt_regs = self.get_pt_regs_parameter()?;
        let raw_ip = self.load_dwarf_register_i64(X86_64_DWARF_RIP, pt_regs)?;
        let (module_bias, offsets_found) = self.generate_runtime_address_from_offsets(
            self.context.i64_type().const_zero(),
            0,
            module_cookie,
        )?;
        let normalized_pc = self.normalized_pc_from_raw(raw_ip, module_bias, offsets_found)?;
        let caller_fallback_found = self.backtrace_module_fallback_found(offsets_found);

        self.store_backtrace_frame(
            inst_buffer,
            0,
            module_cookie_value,
            normalized_pc,
            raw_ip,
            0,
        )?;

        if depth == 1 {
            let status =
                self.status_or_offsets_unavailable(BacktraceStatus::Truncated, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_depth_one",
            )?;
            return Ok(());
        }

        let row = self
            .usable_backtrace_unwind_row_for_pc(&compile_ctx.module_path, compile_ctx.pc_address);
        let initial_status = self.status_for_backtrace_unwind_row_for_pc(&row);
        let status = self.status_or_offsets_unavailable(initial_status, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_initial_status",
        )?;

        let BacktraceUnwindRowForPc::Usable(row) = row else {
            return Ok(());
        };

        let i64_type = self.context.i64_type();
        let ip_ptr = self.build_entry_alloca(i64_type, "bt_state_ip")?;
        let rsp_ptr = self.build_entry_alloca(i64_type, "bt_state_rsp")?;
        let rbp_ptr = self.build_entry_alloca(i64_type, "bt_state_rbp")?;
        let module_bias_ptr = self.build_entry_alloca(i64_type, "bt_state_module_bias")?;
        let module_cookie_ptr = self.build_entry_alloca(i64_type, "bt_state_module_cookie")?;
        let module_found_ptr =
            self.build_entry_alloca(self.context.bool_type(), "bt_state_module_found")?;
        let scratch = self.allocate_backtrace_scratch()?;
        self.builder
            .build_store(ip_ptr, raw_ip)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let initial_rsp = self.load_dwarf_register_i64(X86_64_DWARF_RSP, pt_regs)?;
        let initial_rbp = self.load_dwarf_register_i64(X86_64_DWARF_RBP, pt_regs)?;
        self.builder
            .build_store(rsp_ptr, initial_rsp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rbp_ptr, initial_rbp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_bias_ptr, module_bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, module_cookie_value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, offsets_found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let current_fn = self.current_function("generate DWARF backtrace")?;
        let done = self.context.append_basic_block(current_fn, "bt_done");

        let runtime_row = self.runtime_row_from_static(row);
        let state = BtRegisterState {
            ip: self.load_i64(ip_ptr, "bt_initial_current_ip")?,
            rsp: self.load_i64(rsp_ptr, "bt_initial_current_rsp")?,
            rbp: self.load_i64(rbp_ptr, "bt_initial_current_rbp")?,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let initial_store_block = self
            .context
            .append_basic_block(current_fn, "bt_initial_store_frame");
        let initial_stop_block = self
            .context
            .append_basic_block(current_fn, "bt_initial_stop");
        self.builder
            .build_conditional_branch(validation.valid, initial_store_block, initial_stop_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_stop_block);
        let stop_status = self.status_for_backtrace_stop(
            validation.complete,
            validation.error_code,
            offsets_found,
        )?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            stop_status,
            "bt_initial_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_initial_stop_error_code",
        )?;
        self.builder
            .build_unconditional_branch(done)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie_value,
            module_bias,
            caller_fallback_found,
            "bt_initial_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame(inst_buffer, 1, frame_module.cookie, next_pc, next.ip, 0)?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            2,
            "bt_initial_frame_count",
        )?;
        let status = if depth == 2 {
            BacktraceStatus::Truncated
        } else {
            BacktraceStatus::ReadError
        };
        let status = self.status_or_offsets_unavailable(status, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_initial_status_after_frame",
        )?;
        self.builder
            .build_store(ip_ptr, next.ip)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rsp_ptr, next.rsp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rbp_ptr, next.rbp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_bias_ptr, frame_module.bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, frame_module.cookie)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, frame_module.found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        if depth == 2 {
            self.builder
                .build_unconditional_branch(done)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else if self.backtrace_unwind_rows.is_empty() {
            let status = self
                .status_or_offsets_unavailable(BacktraceStatus::NoUnwindRowsForPc, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_no_rows",
            )?;
            self.builder
                .build_unconditional_branch(done)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else {
            let inline_depth = depth.min(BPF_INLINE_BACKTRACE_FRAME_LIMIT);
            for frame_index in 2..inline_depth {
                let current_ip = self.load_i64(ip_ptr, "bt_lookup_ip")?;
                let current_module_bias =
                    self.load_i64(module_bias_ptr, "bt_lookup_module_bias")?;
                let current_module_cookie =
                    self.load_i64(module_cookie_ptr, "bt_lookup_module_cookie")?;
                let current_module_found =
                    self.load_bool(module_found_ptr, "bt_lookup_module_found")?;
                let lookup_raw = self.add_signed_offset(current_ip, -1, "bt_lookup_raw")?;
                let lookup_pc = self.backtrace_lookup_pc_from_raw(
                    lookup_raw,
                    current_module_bias,
                    current_module_found,
                )?;
                let runtime_row = self.lookup_backtrace_unwind_row(
                    lookup_pc,
                    current_module_cookie,
                    &scratch.row,
                    &format!("bt_frame_{frame_index}_row"),
                )?;
                let found_block = self.context.append_basic_block(current_fn, "bt_row_found");
                let missing_block = self
                    .context
                    .append_basic_block(current_fn, "bt_row_missing");
                self.builder
                    .build_conditional_branch(runtime_row.found, found_block, missing_block)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(missing_block);
                let status = self.status_or_offsets_unavailable(
                    BacktraceStatus::NoUnwindRowsForPc,
                    current_module_found,
                )?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    status,
                    "bt_status_missing_row",
                )?;
                self.builder
                    .build_unconditional_branch(done)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(found_block);
                let state = BtRegisterState {
                    ip: self.load_i64(ip_ptr, "bt_current_ip")?,
                    rsp: self.load_i64(rsp_ptr, "bt_current_rsp")?,
                    rbp: self.load_i64(rbp_ptr, "bt_current_rbp")?,
                };
                let next =
                    self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
                let validation = self.validate_backtrace_next_frame(state, next)?;
                let store_block = self
                    .context
                    .append_basic_block(current_fn, "bt_store_frame");
                let stop_block = self.context.append_basic_block(current_fn, "bt_stop");
                self.builder
                    .build_conditional_branch(validation.valid, store_block, stop_block)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(stop_block);
                let stop_status = self.status_for_backtrace_stop(
                    validation.complete,
                    validation.error_code,
                    current_module_found,
                )?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    stop_status,
                    "bt_status_stop",
                )?;
                self.store_u16_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
                    validation.error_code,
                    "bt_error_code_stop",
                )?;
                self.builder
                    .build_unconditional_branch(done)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                self.builder.position_at_end(store_block);
                let frame_module = self.resolve_backtrace_frame_module(
                    next.ip,
                    current_module_cookie,
                    current_module_bias,
                    self.backtrace_module_fallback_found(current_module_found),
                    &format!("bt_frame_{frame_index}_module"),
                )?;
                let next_pc =
                    self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
                self.store_backtrace_frame(
                    inst_buffer,
                    frame_index as usize,
                    frame_module.cookie,
                    next_pc,
                    next.ip,
                    0,
                )?;
                self.store_u8_const(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                    frame_index + 1,
                    "bt_frame_count",
                )?;
                let next_status = if frame_index + 1 == inline_depth {
                    BacktraceStatus::Truncated
                } else {
                    BacktraceStatus::ReadError
                };
                let next_status =
                    self.status_or_offsets_unavailable(next_status, current_module_found)?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    next_status,
                    "bt_status_after_frame",
                )?;
                self.builder
                    .build_store(ip_ptr, next.ip)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(rsp_ptr, next.rsp)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(rbp_ptr, next.rbp)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(module_bias_ptr, frame_module.bias)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(module_cookie_ptr, frame_module.cookie)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.builder
                    .build_store(module_found_ptr, frame_module.found)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                if frame_index + 1 == inline_depth {
                    self.builder
                        .build_unconditional_branch(done)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                }
            }
        }

        self.builder.position_at_end(done);
        Ok(())
    }

    fn generate_tail_call_backtrace_instruction(
        &mut self,
        plan: &BacktraceInstructionPlan,
    ) -> Result<()> {
        let depth = plan.depth;
        let flags = plan.flags;
        info!(
            "Generating tail-call Backtrace instruction: depth={}",
            depth
        );

        let payload_size = plan.payload_size;
        let instruction_size = plan.instruction_size;
        let offset_ptr = self.event_offset_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("event_offset not allocated in entry block".to_string())
        })?;
        let inst_offset = self
            .builder
            .build_load(self.context.i32_type(), offset_ptr, "bt_tail_inst_offset")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let inst_buffer = self
            .reserve_instruction_region_or_return_zero(instruction_size as u64)?
            .into_value_after_runtime_returns();

        self.store_u8_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, inst_type),
            InstructionType::Backtrace as u8,
            "bt_inst_type",
        )?;
        self.store_u16_const(
            inst_buffer,
            std::mem::offset_of!(InstructionHeader, data_length),
            payload_size as u16,
            "bt_data_length",
        )?;

        let data_base = INSTRUCTION_HEADER_SIZE;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET,
            depth,
            "bt_requested_depth",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            1,
            "bt_frame_count",
        )?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FLAGS_OFFSET,
            flags,
            "bt_flags",
        )?;
        self.store_u16_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            0,
            "bt_error_code",
        )?;

        let Some(compile_ctx) = self.current_compile_time_context.clone() else {
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                0,
                "bt_frame_count_no_context",
            )?;
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                BacktraceStatus::DwarfUnavailable as u8,
                "bt_status_no_context",
            )?;
            return Ok(());
        };

        let module_cookie = self.cookie_for_module_or_fallback(&compile_ctx.module_path);
        let module_cookie_value = self.context.i64_type().const_int(module_cookie, false);
        let pt_regs = self.get_pt_regs_parameter()?;
        let raw_ip = self.load_dwarf_register_i64(X86_64_DWARF_RIP, pt_regs)?;
        let initial_rsp = self.load_dwarf_register_i64(X86_64_DWARF_RSP, pt_regs)?;
        let initial_rbp = self.load_dwarf_register_i64(X86_64_DWARF_RBP, pt_regs)?;
        let (module_bias, offsets_found) = self.generate_runtime_address_from_offsets(
            self.context.i64_type().const_zero(),
            0,
            module_cookie,
        )?;
        let normalized_pc = self.normalized_pc_from_raw(raw_ip, module_bias, offsets_found)?;
        let caller_fallback_found = self.backtrace_module_fallback_found(offsets_found);

        self.store_backtrace_frame(
            inst_buffer,
            0,
            module_cookie_value,
            normalized_pc,
            raw_ip,
            0,
        )?;

        if depth == 1 {
            let status =
                self.status_or_offsets_unavailable(BacktraceStatus::Truncated, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_depth_one",
            )?;
            return Ok(());
        }

        if self.backtrace_unwind_rows.is_empty() {
            let status = self
                .status_or_offsets_unavailable(BacktraceStatus::NoUnwindRowsForPc, offsets_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_status_no_rows",
            )?;
            return Ok(());
        }

        let row = match self
            .usable_backtrace_unwind_row_for_pc(&compile_ctx.module_path, compile_ctx.pc_address)
        {
            BacktraceUnwindRowForPc::Usable(row) => row,
            row_status => {
                let initial_status = self.status_for_backtrace_unwind_row_for_pc(&row_status);
                let status = self.status_or_offsets_unavailable(initial_status, offsets_found)?;
                self.store_u8_value(
                    inst_buffer,
                    data_base + BACKTRACE_DATA_STATUS_OFFSET,
                    status,
                    "bt_status_no_initial_row",
                )?;
                return Ok(());
            }
        };

        let status =
            self.status_or_offsets_unavailable(BacktraceStatus::ReadError, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_tail_initial_status",
        )?;

        let scratch = self.allocate_backtrace_scratch()?;
        let current_fn = self.current_function("initialize bt tail-call state")?;
        let done_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_done");
        let i64_type = self.context.i64_type();
        let ip_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_ip")?;
        let rsp_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_rsp")?;
        let rbp_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_rbp")?;
        let module_bias_ptr = self.build_entry_alloca(i64_type, "bt_tail_prefix_module_bias")?;
        let module_cookie_ptr =
            self.build_entry_alloca(i64_type, "bt_tail_prefix_module_cookie")?;
        let module_found_ptr =
            self.build_entry_alloca(self.context.bool_type(), "bt_tail_prefix_module_found")?;
        self.builder
            .build_store(module_bias_ptr, module_bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, module_cookie_value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, offsets_found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let runtime_row = self.runtime_row_from_static(row);
        let state = BtRegisterState {
            ip: raw_ip,
            rsp: initial_rsp,
            rbp: initial_rbp,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let initial_store_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_initial_store_frame");
        let initial_stop_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_initial_stop");
        self.builder
            .build_conditional_branch(validation.valid, initial_store_block, initial_stop_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_stop_block);
        let stop_status = self.status_for_backtrace_stop(
            validation.complete,
            validation.error_code,
            offsets_found,
        )?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            stop_status,
            "bt_tail_initial_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_tail_initial_stop_error_code",
        )?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(initial_store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie_value,
            module_bias,
            caller_fallback_found,
            "bt_tail_initial_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame(inst_buffer, 1, frame_module.cookie, next_pc, next.ip, 0)?;
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            2,
            "bt_tail_initial_frame_count",
        )?;
        let status = if depth == 2 {
            BacktraceStatus::Truncated
        } else {
            BacktraceStatus::ReadError
        };
        let status = self.status_or_offsets_unavailable(status, offsets_found)?;
        self.store_u8_value(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            status,
            "bt_tail_initial_status_after_frame",
        )?;
        self.builder
            .build_store(ip_ptr, next.ip)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rsp_ptr, next.rsp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(rbp_ptr, next.rbp)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_bias_ptr, frame_module.bias)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_cookie_ptr, frame_module.cookie)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(module_found_ptr, frame_module.found)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        if depth == 2 {
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder.position_at_end(done_block);
            return Ok(());
        }

        let prefix_depth = depth.min(BPF_INLINE_BACKTRACE_FRAME_LIMIT);
        for frame_index in 2..prefix_depth {
            let current_ip = self.load_i64(ip_ptr, "bt_tail_prefix_lookup_ip")?;
            let current_module_bias =
                self.load_i64(module_bias_ptr, "bt_tail_prefix_lookup_module_bias")?;
            let current_module_cookie =
                self.load_i64(module_cookie_ptr, "bt_tail_prefix_lookup_module_cookie")?;
            let current_module_found =
                self.load_bool(module_found_ptr, "bt_tail_prefix_lookup_module_found")?;
            let lookup_raw = self.add_signed_offset(current_ip, -1, "bt_tail_prefix_lookup_raw")?;
            let lookup_pc = self.backtrace_lookup_pc_from_raw(
                lookup_raw,
                current_module_bias,
                current_module_found,
            )?;
            let runtime_row = self.lookup_backtrace_unwind_row(
                lookup_pc,
                current_module_cookie,
                &scratch.row,
                &format!("bt_tail_prefix_frame_{frame_index}_row"),
            )?;
            let found_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_row_found");
            let missing_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_row_missing");
            self.builder
                .build_conditional_branch(runtime_row.found, found_block, missing_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(missing_block);
            let status = self.status_or_offsets_unavailable(
                BacktraceStatus::NoUnwindRowsForPc,
                current_module_found,
            )?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_tail_prefix_status_missing_row",
            )?;
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(found_block);
            let state = BtRegisterState {
                ip: self.load_i64(ip_ptr, "bt_tail_prefix_current_ip")?,
                rsp: self.load_i64(rsp_ptr, "bt_tail_prefix_current_rsp")?,
                rbp: self.load_i64(rbp_ptr, "bt_tail_prefix_current_rbp")?,
            };
            let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, &scratch)?;
            let validation = self.validate_backtrace_next_frame(state, next)?;
            let store_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_store_frame");
            let stop_block = self
                .context
                .append_basic_block(current_fn, "bt_tail_prefix_stop");
            self.builder
                .build_conditional_branch(validation.valid, store_block, stop_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(stop_block);
            let stop_status = self.status_for_backtrace_stop(
                validation.complete,
                validation.error_code,
                current_module_found,
            )?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                stop_status,
                "bt_tail_prefix_stop_status",
            )?;
            self.store_u16_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_ERROR_CODE_OFFSET,
                validation.error_code,
                "bt_tail_prefix_stop_error_code",
            )?;
            self.builder
                .build_unconditional_branch(done_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(store_block);
            let frame_module = self.resolve_backtrace_frame_module(
                next.ip,
                current_module_cookie,
                current_module_bias,
                self.backtrace_module_fallback_found(current_module_found),
                &format!("bt_tail_prefix_frame_{frame_index}_module"),
            )?;
            let next_pc =
                self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
            self.store_backtrace_frame(
                inst_buffer,
                frame_index as usize,
                frame_module.cookie,
                next_pc,
                next.ip,
                0,
            )?;
            self.store_u8_const(
                inst_buffer,
                data_base + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
                frame_index + 1,
                "bt_tail_prefix_frame_count",
            )?;
            let status = if frame_index + 1 == depth {
                BacktraceStatus::Truncated
            } else {
                BacktraceStatus::ReadError
            };
            let status = self.status_or_offsets_unavailable(status, current_module_found)?;
            self.store_u8_value(
                inst_buffer,
                data_base + BACKTRACE_DATA_STATUS_OFFSET,
                status,
                "bt_tail_prefix_status_after_frame",
            )?;
            self.builder
                .build_store(ip_ptr, next.ip)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(rsp_ptr, next.rsp)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(rbp_ptr, next.rbp)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_bias_ptr, frame_module.bias)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_cookie_ptr, frame_module.cookie)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(module_found_ptr, frame_module.found)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            if frame_index + 1 == depth {
                self.builder
                    .build_unconditional_branch(done_block)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            }
        }

        if prefix_depth == depth {
            self.builder.position_at_end(done_block);
            return Ok(());
        }

        let tail_slot = self.next_backtrace_tail_call_slot;
        self.next_backtrace_tail_call_slot = self.next_backtrace_tail_call_slot.saturating_add(1);
        if self.pending_backtrace_tail_call.is_none() {
            let step_program_name = format!(
                "{}_bt_step",
                self.current_function("name bt tail-call step")?
                    .get_name()
                    .to_string_lossy()
            );
            self.pending_backtrace_tail_call =
                Some(crate::ebpf::context::PendingBacktraceTailCall {
                    step_program_name,
                    depth,
                    instruction_size,
                });
        }

        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;

        let state_ptr = self.lookup_bt_state_ptr(tail_slot as u32)?;
        let state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_state_is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let init_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_init");
        let null_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_state_null");
        self.builder
            .build_conditional_branch(state_is_null, null_block, init_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(null_block);
        self.store_u8_const(
            inst_buffer,
            data_base + BACKTRACE_DATA_STATUS_OFFSET,
            BacktraceStatus::InternalError as u8,
            "bt_status_state_null",
        )?;
        self.builder
            .build_store(tail_enabled_ptr, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(init_block);
        let tail_ip = self.load_i64(ip_ptr, "bt_tail_state_prefix_ip")?;
        let tail_rsp = self.load_i64(rsp_ptr, "bt_tail_state_prefix_rsp")?;
        let tail_rbp = self.load_i64(rbp_ptr, "bt_tail_state_prefix_rbp")?;
        let tail_module_bias = self.load_i64(module_bias_ptr, "bt_tail_state_module_bias")?;
        let tail_module_cookie = self.load_i64(module_cookie_ptr, "bt_tail_state_module_cookie")?;
        let tail_module_found = self.load_bool(module_found_ptr, "bt_tail_state_module_found")?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            tail_ip,
            "bt_state_ip",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            tail_rsp,
            "bt_state_rsp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            tail_rbp,
            "bt_state_rbp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            tail_module_bias,
            "bt_state_module_bias",
        )?;
        self.store_u64_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            tail_module_cookie,
            "bt_state_module_cookie",
        )?;
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET,
            inst_offset,
            "bt_state_inst_offset",
        )?;
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            self.context.i32_type().const_zero(),
            "bt_state_event_size",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            prefix_depth,
            "bt_state_frame_count",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_REQUESTED_DEPTH_OFFSET,
            depth,
            "bt_state_requested_depth",
        )?;
        let offsets_found_u8 = self.bool_to_u8(tail_module_found, "bt_offsets_found_u8")?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            offsets_found_u8,
            "bt_state_offsets_found",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            1,
            "bt_state_tail_calls",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FLAGS_OFFSET,
            flags,
            "bt_state_flags",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            tail_slot,
            "bt_state_active_slot",
        )?;
        self.store_u16_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_ERROR_CODE_OFFSET,
            BACKTRACE_ERROR_NONE,
            "bt_state_error_code",
        )?;
        self.store_u8_const(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            crate::BACKTRACE_TAIL_NO_NEXT_SLOT,
            "bt_state_next_slot",
        )?;
        self.link_backtrace_tail_slot(tail_slot, offsets_found_u8, done_block)?;

        self.builder.position_at_end(done_block);
        Ok(())
    }

    pub(crate) fn finish_event_after_instructions(&mut self) -> Result<()> {
        let Some(plan) = self.pending_backtrace_tail_call.clone() else {
            return self.emit_accumulated_event_output_from_stack_offset();
        };

        let main_block = self.current_insert_block("finish bt tail-call event")?;
        let main_pm_key_alloca = self.pm_key_alloca;
        self.generate_backtrace_tail_call_step_program(&plan)?;
        self.pm_key_alloca = main_pm_key_alloca;
        self.builder.position_at_end(main_block);

        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;
        let enabled_value = self
            .builder
            .build_load(
                self.context.i8_type(),
                tail_enabled_ptr,
                "bt_tail_enabled_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let enabled = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                enabled_value,
                self.context.i8_type().const_zero(),
                "bt_tail_enabled",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self.current_function("finish bt tail-call event")?;
        let tail_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch");
        let output_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_fallback_output");
        self.builder
            .build_conditional_branch(enabled, tail_block, output_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(tail_block);
        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state0_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_tail_dispatch_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch_state_ok");
        self.builder
            .build_conditional_branch(state0_is_null, output_block, state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state_ok_block);
        let active_slot = self.load_row_i8(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            "bt_tail_dispatch_active_slot",
        )?;
        let state_ptr = self.lookup_bt_state_ptr_dynamic(active_slot)?;
        let state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_tail_dispatch_active_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let active_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_dispatch_active_state_ok");
        self.builder
            .build_conditional_branch(state_is_null, output_block, active_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(active_state_ok_block);
        let event_size = self
            .builder
            .build_load(
                self.context.i32_type(),
                self.event_offset_alloca.ok_or_else(|| {
                    CodeGenError::LLVMError("event_offset not allocated in entry block".to_string())
                })?,
                "bt_tail_event_size",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.store_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            event_size,
            "bt_tail_state_event_size",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.builder
            .build_unconditional_branch(output_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(output_block);
        self.emit_accumulated_event_output_from_stack_offset()
    }

    fn generate_backtrace_tail_call_step_program(
        &mut self,
        plan: &crate::ebpf::context::PendingBacktraceTailCall,
    ) -> Result<()> {
        self.create_tail_call_function(&plan.step_program_name)?;
        let current_fn = self.current_function("generate bt tail-call step")?;
        let return_block = self
            .context
            .append_basic_block(current_fn, "bt_step_return");
        let state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_state_ok");
        let accum_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_accum_ok");
        let bounds_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_bounds_ok");
        let inst_bounds_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_inst_bounds_ok");
        let finalize_block = self
            .context
            .append_basic_block(current_fn, "bt_step_finalize");

        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_step_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(state_is_null, return_block, state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state_ok_block);
        let active_slot = self.load_row_i8(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            "bt_step_active_slot",
        )?;
        let state_ptr = self.lookup_bt_state_ptr_dynamic(active_slot)?;
        let active_state_is_null = self
            .builder
            .build_is_null(state_ptr, "bt_step_active_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let active_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_step_active_state_ok");
        self.builder
            .build_conditional_branch(active_state_is_null, return_block, active_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(active_state_ok_block);
        let accum_buffer = self.lookup_percpu_value_ptr("event_accum_buffer", 0)?;
        let accum_is_null = self
            .builder
            .build_is_null(accum_buffer, "bt_step_accum_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(accum_is_null, return_block, accum_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(accum_ok_block);
        let inst_offset = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET,
            "bt_step_inst_offset",
        )?;
        let event_size = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            "bt_step_event_size",
        )?;
        let max_event_size = self
            .context
            .i32_type()
            .const_int(self.compile_options.max_trace_event_size as u64, false);
        let max_inst_offset = self.context.i32_type().const_int(
            self.compile_options
                .max_trace_event_size
                .saturating_sub(plan.instruction_size as u32) as u64,
            false,
        );
        let inst_in_bounds = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                inst_offset,
                max_inst_offset,
                "bt_step_inst_offset_in_bounds",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(inst_in_bounds, inst_bounds_ok_block, return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(inst_bounds_ok_block);
        let event_in_bounds = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULE,
                event_size,
                max_event_size,
                "bt_step_event_size_in_bounds",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(event_in_bounds, bounds_ok_block, return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(bounds_ok_block);
        let inst_offset_i64 = self
            .builder
            .build_int_z_extend(
                inst_offset,
                self.context.i64_type(),
                "bt_step_inst_offset_i64",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let inst_buffer =
            self.dynamic_byte_gep(accum_buffer, inst_offset_i64, "bt_step_inst_buffer")?;
        let scratch = self.allocate_backtrace_scratch()?;
        for _ in 0..BPF_BACKTRACE_FRAMES_PER_TAIL_CALL {
            self.generate_backtrace_tail_call_step_iteration(
                plan.depth,
                state_ptr,
                inst_buffer,
                &scratch,
                finalize_block,
            )?;
        }

        let tail_calls = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            "bt_step_tail_calls",
        )?;
        let can_tail_call = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULT,
                tail_calls,
                self.context
                    .i8_type()
                    .const_int(BPF_BACKTRACE_MAX_STEP_INVOCATIONS as u64, false),
                "bt_step_can_tail_call",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let self_tail_block = self
            .context
            .append_basic_block(current_fn, "bt_step_self_tail");
        let tail_budget_done = self
            .context
            .append_basic_block(current_fn, "bt_step_tail_budget_done");
        self.builder
            .build_conditional_branch(can_tail_call, self_tail_block, tail_budget_done)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(tail_budget_done);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(self_tail_block);
        let next_tail_calls = self
            .builder
            .build_int_add(
                tail_calls,
                self.context.i8_type().const_int(1, false),
                "bt_step_next_tail_calls",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            next_tail_calls,
            "bt_step_store_tail_calls",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::InternalError,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(finalize_block);
        let next_slot = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            "bt_final_next_slot",
        )?;
        let has_next_slot = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next_slot,
                self.context
                    .i8_type()
                    .const_int(crate::BACKTRACE_TAIL_NO_NEXT_SLOT as u64, false),
                "bt_final_has_next_slot",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let tail_calls = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            "bt_final_tail_calls",
        )?;
        let can_tail_call_next = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::ULT,
                tail_calls,
                self.context
                    .i8_type()
                    .const_int(BPF_BACKTRACE_MAX_STEP_INVOCATIONS as u64, false),
                "bt_final_can_tail_call_next",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_continue_next = self
            .builder
            .build_and(
                has_next_slot,
                can_tail_call_next,
                "bt_final_should_continue_next_slot",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_final_next_slot");
        let emit_block = self.context.append_basic_block(current_fn, "bt_final_emit");
        self.builder
            .build_conditional_branch(should_continue_next, next_slot_block, emit_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(next_slot_block);
        self.store_u8_value(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            next_slot,
            "bt_store_active_slot",
        )?;
        let next_state_ptr = self.lookup_bt_state_ptr_dynamic(next_slot)?;
        let next_state_is_null = self
            .builder
            .build_is_null(next_state_ptr, "bt_next_state_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_next_state_ok");
        self.builder
            .build_conditional_branch(next_state_is_null, emit_block, next_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(next_state_ok_block);
        self.store_state_i32(
            next_state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            event_size,
            "bt_next_slot_event_size",
        )?;
        let next_tail_calls = self
            .builder
            .build_int_add(
                tail_calls,
                self.context.i8_type().const_int(1, false),
                "bt_next_slot_tail_calls",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            next_state_ptr,
            crate::BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
            next_tail_calls,
            "bt_next_slot_store_tail_calls",
        )?;
        self.emit_bpf_tail_call(BPF_BACKTRACE_STEP_PROG_INDEX)?;
        self.builder
            .build_unconditional_branch(emit_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(emit_block);
        self.emit_tail_final_event(state_ptr, accum_buffer)?;
        self.builder
            .build_unconditional_branch(return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(return_block);
        self.build_return_zero()
    }

    fn generate_backtrace_tail_call_step_iteration(
        &mut self,
        depth: u8,
        state_ptr: PointerValue<'ctx>,
        inst_buffer: PointerValue<'ctx>,
        scratch: &BtScratch<'ctx>,
        finalize_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("generate bt tail-call step iteration")?;
        let depth_block = self
            .context
            .append_basic_block(current_fn, "bt_step_depth_done");
        let unwind_block = self
            .context
            .append_basic_block(current_fn, "bt_step_unwind");
        let frame_count = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            "bt_step_frame_count",
        )?;
        let depth_value = self.context.i8_type().const_int(depth as u64, false);
        let at_depth = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                frame_count,
                depth_value,
                "bt_step_at_depth",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(at_depth, depth_block, unwind_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(depth_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(unwind_block);
        let current_ip = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            "bt_step_current_ip",
        )?;
        let current_rsp = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            "bt_step_current_rsp",
        )?;
        let current_rbp = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            "bt_step_current_rbp",
        )?;
        let module_bias = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            "bt_step_module_bias",
        )?;
        let module_cookie = self.load_row_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            "bt_step_module_cookie",
        )?;
        let offsets_found_u8 = self.load_row_i8(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            "bt_step_offsets_found_u8",
        )?;
        let offsets_found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                offsets_found_u8,
                self.context.i8_type().const_zero(),
                "bt_step_offsets_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let caller_fallback_found = self.backtrace_module_fallback_found(offsets_found);
        let is_first_unwind = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                frame_count,
                self.context.i8_type().const_int(1, false),
                "bt_step_first_unwind",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let caller_lookup_ip =
            self.add_signed_offset(current_ip, -1, "bt_step_caller_lookup_ip")?;
        let lookup_raw = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_first_unwind,
                current_ip.into(),
                caller_lookup_ip.into(),
                "bt_step_lookup_raw",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let lookup_pc =
            self.backtrace_lookup_pc_from_raw(lookup_raw, module_bias, offsets_found)?;
        let runtime_row = self.lookup_backtrace_unwind_row(
            lookup_pc,
            module_cookie,
            &scratch.row,
            "bt_step_row",
        )?;
        let row_found_block = self
            .context
            .append_basic_block(current_fn, "bt_step_row_found");
        let row_missing_block = self
            .context
            .append_basic_block(current_fn, "bt_step_row_missing");
        self.builder
            .build_conditional_branch(runtime_row.found, row_found_block, row_missing_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(row_missing_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::NoUnwindRowsForPc,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(row_found_block);
        let state = BtRegisterState {
            ip: current_ip,
            rsp: current_rsp,
            rbp: current_rbp,
        };
        let next = self.recover_next_frame_from_runtime_row(&runtime_row, state, scratch)?;
        let validation = self.validate_backtrace_next_frame(state, next)?;
        let store_block = self
            .context
            .append_basic_block(current_fn, "bt_step_store_frame");
        let stop_block = self.context.append_basic_block(current_fn, "bt_step_stop");
        self.builder
            .build_conditional_branch(validation.valid, store_block, stop_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(stop_block);
        let stop_status = self.status_for_backtrace_stop(
            validation.complete,
            validation.error_code,
            offsets_found,
        )?;
        self.store_u8_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_STATUS_OFFSET,
            stop_status,
            "bt_step_stop_status",
        )?;
        self.store_u16_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            validation.error_code,
            "bt_step_stop_error",
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(store_block);
        let frame_module = self.resolve_backtrace_frame_module(
            next.ip,
            module_cookie,
            module_bias,
            caller_fallback_found,
            "bt_step_frame_module",
        )?;
        let next_pc =
            self.normalized_pc_from_raw(next.ip, frame_module.bias, frame_module.found)?;
        self.store_backtrace_frame_dynamic(
            inst_buffer,
            frame_count,
            depth.saturating_sub(1),
            frame_module.cookie,
            next_pc,
            next.ip,
        )?;
        let next_count = self
            .builder
            .build_int_add(
                frame_count,
                self.context.i8_type().const_int(1, false),
                "bt_step_next_frame_count",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
            next_count,
            "bt_step_state_frame_count",
        )?;
        self.store_u8_value(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_FRAME_COUNT_OFFSET,
            next_count,
            "bt_step_inst_frame_count",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
            next.ip,
            "bt_step_state_next_ip",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
            next.rsp,
            "bt_step_state_next_rsp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET,
            next.rbp,
            "bt_step_state_next_rbp",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
            frame_module.bias,
            "bt_step_state_next_module_bias",
        )?;
        self.store_state_i64(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET,
            frame_module.cookie,
            "bt_step_state_next_module_cookie",
        )?;
        let next_offsets_found_u8 =
            self.bool_to_u8(frame_module.found, "bt_step_next_offsets_found_u8")?;
        self.store_u8_value(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET,
            next_offsets_found_u8,
            "bt_step_state_next_offsets_found",
        )?;

        let reached_depth = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                next_count,
                depth_value,
                "bt_step_reached_depth",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let reached_depth_block = self
            .context
            .append_basic_block(current_fn, "bt_step_reached_depth");
        let continue_block = self
            .context
            .append_basic_block(current_fn, "bt_step_continue");
        self.builder
            .build_conditional_branch(reached_depth, reached_depth_block, continue_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(reached_depth_block);
        self.store_tail_backtrace_status(
            inst_buffer,
            BacktraceStatus::Truncated,
            BACKTRACE_ERROR_NONE,
        )?;
        self.builder
            .build_unconditional_branch(finalize_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(continue_block);
        Ok(())
    }

    fn emit_bpf_tail_call(&mut self, index: u32) -> Result<()> {
        let ctx = self.get_pt_regs_parameter()?;
        let prog_array = self.lookup_bt_prog_array_ptr()?;
        let args = [
            ctx.into(),
            prog_array.into(),
            self.context
                .i32_type()
                .const_int(index as u64, false)
                .into(),
        ];
        let _ = self.create_bpf_helper_call(
            BPF_FUNC_tail_call as u64,
            &args,
            self.context.i64_type().into(),
            "bt_bpf_tail_call",
        )?;
        Ok(())
    }

    fn store_tail_backtrace_status(
        &self,
        inst_buffer: PointerValue<'ctx>,
        status: BacktraceStatus,
        error_code: u16,
    ) -> Result<()> {
        self.store_u8_const(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_STATUS_OFFSET,
            status as u8,
            "bt_tail_status",
        )?;
        self.store_u16_const(
            inst_buffer,
            INSTRUCTION_HEADER_SIZE + BACKTRACE_DATA_ERROR_CODE_OFFSET,
            error_code,
            "bt_tail_error_code",
        )
    }

    fn emit_tail_final_event(
        &mut self,
        state_ptr: PointerValue<'ctx>,
        accum_buffer: PointerValue<'ctx>,
    ) -> Result<()> {
        let event_size = self.load_state_i32(
            state_ptr,
            crate::BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
            "bt_final_event_size",
        )?;
        self.emit_accumulated_event_output(accum_buffer, event_size)
    }

    fn build_return_zero(&mut self) -> Result<()> {
        self.builder
            .build_return(Some(&self.context.i32_type().const_zero()))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn compact_unwind_row_for_backtrace(
        &self,
        module_path: &str,
        pc: u64,
    ) -> Option<CompactUnwindRow> {
        let analyzer = self.process_analyzer?;
        let module_address = ModuleAddress::new(PathBuf::from(module_path), pc);
        let ctx = analyzer.resolve_pc(&module_address).ok()?;
        analyzer.compact_unwind_row_for_context(&ctx).ok().flatten()
    }

    fn usable_backtrace_unwind_row_for_pc(
        &self,
        module_path: &str,
        pc: u64,
    ) -> BacktraceUnwindRowForPc {
        let Some(row) = self.compact_unwind_row_for_backtrace(module_path, pc) else {
            return BacktraceUnwindRowForPc::Missing;
        };
        match crate::backtrace_unwind_row_from_compact(&row) {
            Some(row) => BacktraceUnwindRowForPc::Usable(row),
            None => BacktraceUnwindRowForPc::Unsupported,
        }
    }

    fn status_for_backtrace_unwind_row_for_pc(
        &self,
        row: &BacktraceUnwindRowForPc,
    ) -> BacktraceStatus {
        match row {
            BacktraceUnwindRowForPc::Usable(_) => BacktraceStatus::ReadError,
            BacktraceUnwindRowForPc::Missing if self.process_analyzer.is_some() => {
                BacktraceStatus::NoUnwindRowsForPc
            }
            BacktraceUnwindRowForPc::Unsupported if self.process_analyzer.is_some() => {
                BacktraceStatus::UnsupportedCfi
            }
            BacktraceUnwindRowForPc::Missing | BacktraceUnwindRowForPc::Unsupported => {
                BacktraceStatus::DwarfUnavailable
            }
        }
    }

    fn runtime_row_from_static(
        &self,
        row: ghostscope_protocol::BacktraceUnwindRow,
    ) -> RuntimeBtUnwindRow<'ctx> {
        let i8_type = self.context.i8_type();
        let i16_type = self.context.i16_type();
        let i64_type = self.context.i64_type();
        RuntimeBtUnwindRow {
            found: self.context.bool_type().const_int(1, false),
            cfa_register: i16_type.const_int(row.cfa_register as u64, false),
            cfa_offset: i64_type.const_int(row.cfa_offset as u64, true),
            ra_kind: i8_type.const_int(row.ra_kind as u64, false),
            ra_register: i16_type.const_int(row.ra_register as u64, false),
            ra_offset: i64_type.const_int(row.ra_offset as u64, true),
            rbp_kind: i8_type.const_int(row.rbp_kind as u64, false),
            rbp_register: i16_type.const_int(row.rbp_register as u64, false),
            rbp_offset: i64_type.const_int(row.rbp_offset as u64, true),
        }
    }

    fn allocate_backtrace_scratch(&self) -> Result<BtScratch<'ctx>> {
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();

        Ok(BtScratch {
            row: RuntimeBtRowScratch {
                found_ptr: self.build_entry_alloca(i32_type, "bt_row_found")?,
                cfa_register_ptr: self.build_entry_alloca(i16_type, "bt_row_cfa_register")?,
                cfa_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_cfa_offset")?,
                ra_kind_ptr: self.build_entry_alloca(self.context.i8_type(), "bt_row_ra_kind")?,
                ra_register_ptr: self.build_entry_alloca(i16_type, "bt_row_ra_register")?,
                ra_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_ra_offset")?,
                rbp_kind_ptr: self.build_entry_alloca(self.context.i8_type(), "bt_row_rbp_kind")?,
                rbp_register_ptr: self.build_entry_alloca(i16_type, "bt_row_rbp_register")?,
                rbp_offset_ptr: self.build_entry_alloca(i64_type, "bt_row_rbp_offset")?,
            },
            next_rbp_ptr: self.build_entry_alloca(i64_type, "bt_next_rbp")?,
            next_error_code_ptr: self.build_entry_alloca(i16_type, "bt_next_error_code")?,
        })
    }

    fn lookup_backtrace_unwind_row(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        module_cookie: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
        name_prefix: &str,
    ) -> Result<RuntimeBtUnwindRow<'ctx>> {
        let bounds = self.backtrace_unwind_row_bounds_for_module(module_cookie, name_prefix)?;
        self.lookup_backtrace_unwind_row_in_range(normalized_pc, bounds.start, bounds.end, scratch)
    }

    fn backtrace_unwind_row_bounds_for_module(
        &mut self,
        module_cookie: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtRowBounds<'ctx>> {
        let i32_type = self.context.i32_type();
        if self.backtrace_module_row_ranges.is_empty() {
            return Ok(BtRowBounds {
                start: i32_type.const_zero(),
                end: i32_type.const_int(self.backtrace_unwind_rows.len() as u64, false),
            });
        }

        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("bt_module_row_ranges")
            .ok_or_else(|| {
                CodeGenError::LLVMError("bt_module_row_ranges map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_row_ranges_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca =
            self.build_entry_alloca(i64_type, &format!("{name_prefix}_row_range_key"))?;
        self.builder
            .build_store(key_alloca, module_cookie)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(
                key_alloca,
                ptr_type,
                &format!("{name_prefix}_row_range_key_void"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            &format!("{name_prefix}_row_range_lookup"),
        )?;
        let range_ptr = match result {
            BasicValueEnum::PointerValue(ptr) => ptr,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "bt_module_row_ranges lookup did not return pointer".to_string(),
                ))
            }
        };
        let is_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                self.builder
                    .build_ptr_to_int(
                        range_ptr,
                        i64_type,
                        &format!("{name_prefix}_row_range_ptr_i64"),
                    )
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
                i64_type.const_zero(),
                &format!("{name_prefix}_row_range_is_null"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let current_fn = self.current_function("lookup bt row range")?;
        let found_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_found_row_range"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_miss_row_range"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_cont_row_range"));
        self.builder
            .build_conditional_branch(is_null, miss_block, found_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(found_block);
        let load_range_field = |offset: usize,
                                field_name: &str,
                                ctx: &mut EbpfContext<'ctx, 'dw>|
         -> Result<IntValue<'ctx>> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: range_ptr is a non-null BacktraceModuleRowRange pointer
            // returned by bpf_map_lookup_elem, and offsets are shared ABI
            // constants from ghostscope-protocol.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), range_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            Ok(ctx
                .builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value())
        };
        let found_start = load_range_field(
            ghostscope_protocol::BACKTRACE_MODULE_ROW_RANGE_ROW_START_OFFSET,
            &format!("{name_prefix}_row_range_start"),
            self,
        )?;
        let found_end = load_range_field(
            ghostscope_protocol::BACKTRACE_MODULE_ROW_RANGE_ROW_END_OFFSET,
            &format!("{name_prefix}_row_range_end"),
            self,
        )?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let found_end_block = self.current_insert_block("finish bt row range found block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end_block = self.current_insert_block("finish bt row range miss block")?;

        self.builder.position_at_end(cont_block);
        let start_phi = self
            .builder
            .build_phi(i32_type, &format!("{name_prefix}_row_start_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        start_phi.add_incoming(&[
            (&found_start, found_end_block),
            (&i32_type.const_zero(), miss_end_block),
        ]);
        let end_phi = self
            .builder
            .build_phi(i32_type, &format!("{name_prefix}_row_end_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        end_phi.add_incoming(&[
            (&found_end, found_end_block),
            (&i32_type.const_zero(), miss_end_block),
        ]);

        Ok(BtRowBounds {
            start: start_phi.as_basic_value().into_int_value(),
            end: end_phi.as_basic_value().into_int_value(),
        })
    }

    fn lookup_backtrace_unwind_row_in_range(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        row_start: IntValue<'ctx>,
        row_end: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
    ) -> Result<RuntimeBtUnwindRow<'ctx>> {
        let row_count = self.backtrace_unwind_row_map_entries() as usize;
        let i16_type = self.context.i16_type();
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let i8_type = self.context.i8_type();
        let sentinel = i32_type.const_int(row_count as u64, false);

        self.builder
            .build_store(scratch.found_ptr, sentinel)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_kind_ptr, i8_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_kind_ptr, i8_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_register_ptr, i16_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_offset_ptr, i64_type.const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let current_fn = self.current_function("lookup bt unwind row")?;
        let return_block = self
            .context
            .append_basic_block(current_fn, "bt_row_lookup_return");
        if row_count == 0 {
            self.builder
                .build_unconditional_branch(return_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        } else {
            let lo_ptr = self.build_entry_alloca(i32_type, "bt_row_lo")?;
            let hi_ptr = self.build_entry_alloca(i32_type, "bt_row_hi")?;
            self.builder
                .build_store(lo_ptr, row_start)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(hi_ptr, row_end)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.emit_backtrace_row_runtime_binary_search(
                normalized_pc,
                scratch,
                lo_ptr,
                hi_ptr,
                row_count,
                return_block,
            )?;
        }
        self.builder.position_at_end(return_block);
        let final_found_idx = self.load_i32(scratch.found_ptr, "bt_final_found_idx")?;
        let found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                final_found_idx,
                sentinel,
                "bt_final_row_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(RuntimeBtUnwindRow {
            found,
            cfa_register: self.load_i16(scratch.cfa_register_ptr, "bt_final_cfa_reg")?,
            cfa_offset: self.load_i64(scratch.cfa_offset_ptr, "bt_final_cfa_off")?,
            ra_kind: self.load_i8(scratch.ra_kind_ptr, "bt_final_ra_kind")?,
            ra_register: self.load_i16(scratch.ra_register_ptr, "bt_final_ra_reg")?,
            ra_offset: self.load_i64(scratch.ra_offset_ptr, "bt_final_ra_off")?,
            rbp_kind: self.load_i8(scratch.rbp_kind_ptr, "bt_final_rbp_kind")?,
            rbp_register: self.load_i16(scratch.rbp_register_ptr, "bt_final_rbp_reg")?,
            rbp_offset: self.load_i64(scratch.rbp_offset_ptr, "bt_final_rbp_off")?,
        })
    }

    fn emit_backtrace_row_runtime_binary_search(
        &mut self,
        normalized_pc: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
        lo_ptr: PointerValue<'ctx>,
        hi_ptr: PointerValue<'ctx>,
        row_count: usize,
        return_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("emit bt row lookup tree")?;
        let i32_type = self.context.i32_type();
        let sentinel = i32_type.const_int(row_count as u64, false);
        let max_steps = backtrace_row_binary_search_steps(row_count);

        for _ in 0..max_steps {
            let found_idx = self.load_i32(scratch.found_ptr, "bt_lookup_found_idx")?;
            let not_found = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    found_idx,
                    sentinel,
                    "bt_lookup_not_found",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let lo = self.load_i32(lo_ptr, "bt_lookup_lo")?;
            let hi = self.load_i32(hi_ptr, "bt_lookup_hi")?;
            let range_active = self
                .builder
                .build_int_compare(inkwell::IntPredicate::ULT, lo, hi, "bt_lookup_range_active")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let should_search = self
                .builder
                .build_and(not_found, range_active, "bt_lookup_should_search")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            let search_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_search");
            let skip_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_skip");
            let after_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_after");
            self.builder
                .build_conditional_branch(should_search, search_block, skip_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(skip_block);
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(search_block);
            let lo_plus_hi = self
                .builder
                .build_int_add(lo, hi, "bt_lookup_lo_plus_hi")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let mid = self
                .builder
                .build_right_shift(
                    lo_plus_hi,
                    i32_type.const_int(1, false),
                    false,
                    "bt_lookup_mid",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let row_ptr = self.lookup_bt_unwind_row_ptr(mid)?;
            let row_is_null = self
                .builder
                .build_is_null(row_ptr, "bt_lookup_row_is_null")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let row_null_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_row_null");
            let row_load_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_row_load");
            self.builder
                .build_conditional_branch(row_is_null, row_null_block, row_load_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(row_null_block);
            self.builder
                .build_store(lo_ptr, hi)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(row_load_block);
            let pc_start = self.load_row_i64(
                row_ptr,
                crate::BACKTRACE_UNWIND_ROW_PC_START_OFFSET,
                "bt_lookup_row_pc_start",
            )?;
            let pc_end = self.load_row_i64(
                row_ptr,
                crate::BACKTRACE_UNWIND_ROW_PC_END_OFFSET,
                "bt_lookup_row_pc_end",
            )?;
            let before = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    normalized_pc,
                    pc_start,
                    "bt_lookup_pc_before",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_before");
            let not_before_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_not_before");
            self.builder
                .build_conditional_branch(before, before_block, not_before_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(before_block);
            self.builder
                .build_store(hi_ptr, mid)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(not_before_block);
            let after = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    normalized_pc,
                    pc_end,
                    "bt_lookup_pc_after",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let after_range_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_after_range");
            let match_block = self
                .context
                .append_basic_block(current_fn, "bt_lookup_match");
            self.builder
                .build_conditional_branch(after, after_range_block, match_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(after_range_block);
            let mid_plus_one = self
                .builder
                .build_int_add(mid, i32_type.const_int(1, false), "bt_lookup_mid_plus_one")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_store(lo_ptr, mid_plus_one)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(match_block);
            self.store_backtrace_unwind_row_from_ptr(row_ptr, mid, scratch)?;
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(after_block);
        }

        self.builder
            .build_unconditional_branch(return_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn store_backtrace_unwind_row_from_ptr(
        &self,
        row_ptr: PointerValue<'ctx>,
        row_index: IntValue<'ctx>,
        scratch: &RuntimeBtRowScratch<'ctx>,
    ) -> Result<()> {
        self.builder
            .build_store(scratch.found_ptr, row_index)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_CFA_REGISTER_OFFSET,
            "bt_tree_row_cfa_reg",
        )?;
        let cfa_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_CFA_OFFSET_OFFSET,
            "bt_tree_row_cfa_off",
        )?;
        let ra_kind = self.load_row_i8(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_KIND_OFFSET,
            "bt_tree_row_ra_kind",
        )?;
        let ra_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_REGISTER_OFFSET,
            "bt_tree_row_ra_reg",
        )?;
        let ra_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RA_OFFSET_OFFSET,
            "bt_tree_row_ra_off",
        )?;
        let rbp_kind = self.load_row_i8(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_KIND_OFFSET,
            "bt_tree_row_rbp_kind",
        )?;
        let rbp_register = self.load_row_i16(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_REGISTER_OFFSET,
            "bt_tree_row_rbp_reg",
        )?;
        let rbp_offset = self.load_row_i64(
            row_ptr,
            crate::BACKTRACE_UNWIND_ROW_RBP_OFFSET_OFFSET,
            "bt_tree_row_rbp_off",
        )?;
        self.builder
            .build_store(scratch.cfa_register_ptr, cfa_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.cfa_offset_ptr, cfa_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_kind_ptr, ra_kind)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_register_ptr, ra_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.ra_offset_ptr, ra_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_kind_ptr, rbp_kind)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_register_ptr, rbp_register)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(scratch.rbp_offset_ptr, rbp_offset)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn recover_next_frame_from_runtime_row(
        &mut self,
        row: &RuntimeBtUnwindRow<'ctx>,
        state: BtRegisterState<'ctx>,
        scratch: &BtScratch<'ctx>,
    ) -> Result<BtNextFrame<'ctx>> {
        let cfa_base = self.select_register_state(row.cfa_register, state, "bt_cfa_base")?;
        let cfa = self
            .builder
            .build_int_add(cfa_base, row.cfa_offset, "bt_runtime_cfa")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let ra_addr = self
            .builder
            .build_int_add(cfa, row.ra_offset, "bt_runtime_ra_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(
                scratch.next_error_code_ptr,
                self.context
                    .i16_type()
                    .const_int(BACKTRACE_ERROR_NONE as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let (ra_from_memory, ra_read_failed) = self.generate_memory_read_with_fail_flag(
            RuntimeAddress::available(ra_addr, self.context),
            MemoryAccessSize::U64,
            "bt_ra_read",
        )?;
        let ra_from_memory = ra_from_memory.into_int_value();
        let ra_uses_memory = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_AT_CFA_OFFSET,
            "bt_ra_at_kind",
        )?;
        let ra_read_failed = self
            .builder
            .build_and(ra_read_failed, ra_uses_memory, "bt_ra_read_failed")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.store_backtrace_error_code_if(
            scratch.next_error_code_ptr,
            ra_read_failed,
            BACKTRACE_ERROR_RETURN_ADDRESS_READ,
            "bt_ra_error_code",
        )?;
        let ra_from_val = self
            .builder
            .build_int_add(cfa, row.ra_offset, "bt_runtime_ra_val")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ra_from_register = self.select_register_state(row.ra_register, state, "bt_ra_reg")?;
        let ra_is_val = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_VAL_CFA_OFFSET,
            "bt_ra_val_kind",
        )?;
        let ra_is_register = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_REGISTER,
            "bt_ra_reg_kind",
        )?;
        let ra_is_same = self.is_recovery_kind(
            row.ra_kind,
            crate::BACKTRACE_RECOVERY_SAME_VALUE,
            "bt_ra_same_kind",
        )?;
        let ra_is_register_like = self
            .builder
            .build_or(ra_is_register, ra_is_same, "bt_ra_register_like")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ra_value_or_memory = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ra_is_val,
                ra_from_val.into(),
                ra_from_memory.into(),
                "bt_ra_val_or_memory",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let next_ip = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                ra_is_register_like,
                ra_from_register.into(),
                ra_value_or_memory.into(),
                "bt_next_ip",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let next_rbp = self.recover_rbp_from_runtime_row(
            row,
            cfa,
            state,
            scratch.next_rbp_ptr,
            scratch.next_error_code_ptr,
        )?;
        let error_code = self.load_i16(scratch.next_error_code_ptr, "bt_next_error_code_value")?;

        Ok(BtNextFrame {
            ip: next_ip,
            rsp: cfa,
            rbp: next_rbp,
            error_code,
        })
    }

    fn validate_backtrace_next_frame(
        &self,
        state: BtRegisterState<'ctx>,
        next: BtNextFrame<'ctx>,
    ) -> Result<BtFrameValidation<'ctx>> {
        let i64_type = self.context.i64_type();
        let i16_type = self.context.i16_type();
        let zero = i64_type.const_zero();
        let zero_i16 = i16_type.const_zero();
        let min_user_ip = i64_type.const_int(0x1000, false);
        let high_byte_mask = i64_type.const_int(0xff00_0000_0000_0000, false);

        let no_read_error = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                next.error_code,
                zero_i16,
                "bt_no_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_high_enough = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::UGE,
                next.ip,
                min_user_ip,
                "bt_next_ip_user_min",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_high_byte = self
            .builder
            .build_and(next.ip, high_byte_mask, "bt_next_ip_high_byte")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_is_zero = self
            .builder
            .build_int_compare(inkwell::IntPredicate::EQ, next.ip, zero, "bt_next_ip_zero")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_not_kernel_like = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                ip_high_byte,
                zero,
                "bt_next_ip_not_kernel_like",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_nonzero = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.rsp,
                zero,
                "bt_next_cfa_nonzero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_changed = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.rsp,
                state.rsp,
                "bt_next_cfa_changed",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ip_changed = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                next.ip,
                state.ip,
                "bt_next_ip_changed",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_progress = self
            .builder
            .build_or(cfa_changed, ip_changed, "bt_next_frame_progress")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let ip_valid = self
            .builder
            .build_and(ip_high_enough, ip_not_kernel_like, "bt_next_ip_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_valid = self
            .builder
            .build_and(cfa_nonzero, cfa_progress, "bt_next_cfa_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_shape_valid = self
            .builder
            .build_and(ip_valid, cfa_valid, "bt_next_frame_valid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let valid = self
            .builder
            .build_and(
                no_read_error,
                frame_shape_valid,
                "bt_next_frame_valid_no_read_error",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let complete = self
            .builder
            .build_and(no_read_error, ip_is_zero, "bt_next_frame_complete")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let mut error_code = next.error_code;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            ip_high_enough,
            BACKTRACE_ERROR_NEXT_IP_BELOW_USER,
            "bt_next_ip_below_user_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            ip_not_kernel_like,
            BACKTRACE_ERROR_NEXT_IP_KERNEL_LIKE,
            "bt_next_ip_kernel_like_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            cfa_nonzero,
            BACKTRACE_ERROR_NEXT_CFA_ZERO,
            "bt_next_cfa_zero_code",
        )?;
        error_code = self.select_backtrace_error_code_if(
            error_code,
            cfa_progress,
            BACKTRACE_ERROR_NEXT_CFA_NOT_ADVANCING,
            "bt_next_cfa_not_advancing_code",
        )?;
        error_code = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                complete,
                self.context
                    .i16_type()
                    .const_int(BACKTRACE_ERROR_NONE as u64, false)
                    .into(),
                error_code.into(),
                "bt_complete_error_code",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        Ok(BtFrameValidation {
            valid,
            complete,
            error_code,
        })
    }

    fn select_backtrace_error_code_if(
        &self,
        current: IntValue<'ctx>,
        condition_ok: IntValue<'ctx>,
        error_code: u16,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let i16_type = self.context.i16_type();
        let current_is_none = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current,
                i16_type.const_int(BACKTRACE_ERROR_NONE as u64, false),
                &format!("{name}_current_none"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let condition_failed = self
            .builder
            .build_not(condition_ok, &format!("{name}_condition_failed"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_set = self
            .builder
            .build_and(
                current_is_none,
                condition_failed,
                &format!("{name}_should_set"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                should_set,
                i16_type.const_int(error_code as u64, false).into(),
                current.into(),
                name,
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    fn store_backtrace_error_code_if(
        &self,
        error_code_ptr: PointerValue<'ctx>,
        condition: IntValue<'ctx>,
        error_code: u16,
        name: &str,
    ) -> Result<()> {
        let current = self.load_i16(error_code_ptr, &format!("{name}_current"))?;
        let i16_type = self.context.i16_type();
        let current_is_none = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                current,
                i16_type.const_int(BACKTRACE_ERROR_NONE as u64, false),
                &format!("{name}_current_none"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_set = self
            .builder
            .build_and(condition, current_is_none, &format!("{name}_should_set"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let next = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                should_set,
                i16_type.const_int(error_code as u64, false).into(),
                current.into(),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(error_code_ptr, next)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn recover_rbp_from_runtime_row(
        &mut self,
        row: &RuntimeBtUnwindRow<'ctx>,
        cfa: IntValue<'ctx>,
        state: BtRegisterState<'ctx>,
        next_rbp_ptr: PointerValue<'ctx>,
        next_error_code_ptr: PointerValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let is_at = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_AT_CFA_OFFSET,
            "bt_rbp_at_kind",
        )?;
        let cfa_uses_rbp = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                row.cfa_register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RBP as u64, false),
                "bt_rbp_cfa_uses_rbp",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cfa_offset_is_frame_pointer_call_frame = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                row.cfa_offset,
                self.context.i64_type().const_int(16, false),
                "bt_rbp_cfa_offset_is_16",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let frame_pointer_call_frame = self
            .builder
            .build_and(
                cfa_uses_rbp,
                cfa_offset_is_frame_pointer_call_frame,
                "bt_rbp_frame_pointer_call_frame",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_at = self
            .builder
            .build_or(
                is_at,
                frame_pointer_call_frame,
                "bt_rbp_at_or_frame_pointer",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_offset = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                frame_pointer_call_frame,
                self.context
                    .i64_type()
                    .const_int((-16i64) as u64, true)
                    .into(),
                row.rbp_offset.into(),
                "bt_rbp_effective_offset",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let current_fn = self.current_function("recover bt rbp")?;
        let at_block = self.context.append_basic_block(current_fn, "bt_rbp_at");
        let non_at_block = self.context.append_basic_block(current_fn, "bt_rbp_non_at");
        let join_block = self.context.append_basic_block(current_fn, "bt_rbp_join");
        self.builder
            .build_conditional_branch(is_at, at_block, non_at_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(at_block);
        let rbp_addr = self
            .builder
            .build_int_add(cfa, rbp_offset, "bt_runtime_rbp_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let (rbp_from_memory, rbp_read_failed) = self.generate_memory_read_with_fail_flag(
            RuntimeAddress::available(rbp_addr, self.context),
            MemoryAccessSize::U64,
            "bt_rbp_read",
        )?;
        self.store_backtrace_error_code_if(
            next_error_code_ptr,
            rbp_read_failed,
            BACKTRACE_ERROR_FRAME_POINTER_READ,
            "bt_rbp_error_code",
        )?;
        self.builder
            .build_store(next_rbp_ptr, rbp_from_memory.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(join_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(non_at_block);
        let rbp_from_val = self
            .builder
            .build_int_add(cfa, row.rbp_offset, "bt_runtime_rbp_val")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_from_register =
            self.select_register_state(row.rbp_register, state, "bt_rbp_reg")?;
        let rbp_is_val = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_VAL_CFA_OFFSET,
            "bt_rbp_val_kind",
        )?;
        let rbp_is_register = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_REGISTER,
            "bt_rbp_reg_kind",
        )?;
        let rbp_is_same = self.is_recovery_kind(
            row.rbp_kind,
            crate::BACKTRACE_RECOVERY_SAME_VALUE,
            "bt_rbp_same_kind",
        )?;
        let rbp_is_register_like = self
            .builder
            .build_or(rbp_is_register, rbp_is_same, "bt_rbp_register_like")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_value_or_current = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                rbp_is_val,
                rbp_from_val.into(),
                state.rbp.into(),
                "bt_rbp_val_or_current",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let rbp_non_at = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                rbp_is_register_like,
                rbp_from_register.into(),
                rbp_value_or_current.into(),
                "bt_rbp_non_at_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.builder
            .build_store(next_rbp_ptr, rbp_non_at)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(join_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(join_block);
        self.load_i64(next_rbp_ptr, "bt_next_rbp_value")
    }

    fn select_register_state(
        &self,
        register: IntValue<'ctx>,
        state: BtRegisterState<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let is_rbp = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RBP as u64, false),
                &format!("{name}_is_rbp"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_rip = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                register,
                self.context
                    .i16_type()
                    .const_int(X86_64_DWARF_RIP as u64, false),
                &format!("{name}_is_rip"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let rbp_or_rsp = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_rbp,
                state.rbp.into(),
                state.rsp.into(),
                &format!("{name}_rbp_or_rsp"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                is_rip,
                state.ip.into(),
                rbp_or_rsp.into(),
                name,
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    fn is_recovery_kind(
        &self,
        kind: IntValue<'ctx>,
        expected: u8,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        self.builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                kind,
                self.context.i8_type().const_int(expected as u64, false),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    fn lookup_bt_unwind_row_ptr(
        &mut self,
        row_index: IntValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let map_global = self
            .module
            .get_global("bt_unwind_rows")
            .ok_or_else(|| CodeGenError::LLVMError("bt_unwind_rows map not found".to_string()))?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                "bt_unwind_rows_map_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let key_arr_ty = i32_type.array_type(4);
        let zero = i32_type.const_zero();
        // SAFETY: pm_key_alloca is a [4 x i32] entry-block alloca and [0, 0]
        // addresses its first element, which is sufficient for an Array u32 key.
        let key_ptr = unsafe {
            self.builder
                .build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[zero, zero],
                    "bt_unwind_row_key_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, row_index)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, "bt_unwind_row_key_void")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            "bt_unwind_row_lookup",
        )?;
        match result {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_unwind_rows lookup did not return pointer".to_string(),
            )),
        }
    }

    fn lookup_bt_state_ptr(&mut self, key_const: u32) -> Result<PointerValue<'ctx>> {
        self.lookup_percpu_value_ptr("bt_state", key_const)
    }

    fn lookup_bt_state_ptr_dynamic(
        &mut self,
        state_index: IntValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let i32_type = self.context.i32_type();
        let map_global = self
            .map_manager
            .get_map(&self.module, "bt_state")
            .map_err(|e| CodeGenError::LLVMError(format!("Map not found bt_state: {e}")))?;
        let map_ptr = self
            .builder
            .build_bit_cast(map_global, ptr_type, "bt_state_map_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key = match state_index
            .get_type()
            .get_bit_width()
            .cmp(&i32_type.get_bit_width())
        {
            std::cmp::Ordering::Equal => state_index,
            std::cmp::Ordering::Less => self
                .builder
                .build_int_z_extend(state_index, i32_type, "bt_state_key_i32")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
            std::cmp::Ordering::Greater => self
                .builder
                .build_int_truncate(state_index, i32_type, "bt_state_key_i32")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
        };

        let key_arr_ty = i32_type.array_type(4);
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let zero = i32_type.const_zero();
        // SAFETY: pm_key_alloca is a [4 x i32] entry-block alloca and [0, 0]
        // addresses its first element, which is sufficient for an Array u32 key.
        let key_ptr = unsafe {
            self.builder
                .build_gep(key_arr_ty, key_alloca, &[zero, zero], "bt_state_key_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, key)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, "bt_state_key_void")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let result = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_type.into(),
            "bt_state_lookup",
        )?;
        match result {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_state lookup did not return pointer".to_string(),
            )),
        }
    }

    fn lookup_bt_prog_array_ptr(&mut self) -> Result<PointerValue<'ctx>> {
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("bt_prog_array")
            .ok_or_else(|| CodeGenError::LLVMError("bt_prog_array map not found".to_string()))?;
        let map_ptr = self
            .builder
            .build_bit_cast(map_global.as_pointer_value(), ptr_type, "bt_prog_array_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        match map_ptr {
            BasicValueEnum::PointerValue(ptr) => Ok(ptr),
            _ => Err(CodeGenError::LLVMError(
                "bt_prog_array cast did not return pointer".to_string(),
            )),
        }
    }

    fn get_or_create_backtrace_tail_enabled_flag(&mut self) -> Result<PointerValue<'ctx>> {
        if let Some(ptr) = self.backtrace_tail_enabled_alloca {
            return Ok(ptr);
        }

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for bt tail flag allocation".to_string())
        })?;
        let current_fn = self.current_function("allocate bt tail flag")?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for bt tail flag allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(self.context.i8_type(), "bt_tail_enabled")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(alloca, self.context.i8_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);
        self.backtrace_tail_enabled_alloca = Some(alloca);
        Ok(alloca)
    }

    fn get_or_create_backtrace_tail_last_slot(&mut self) -> Result<PointerValue<'ctx>> {
        if let Some(ptr) = self.backtrace_tail_last_slot_alloca {
            return Ok(ptr);
        }

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for bt tail slot allocation".to_string())
        })?;
        let current_fn = self.current_function("allocate bt tail slot")?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for bt tail slot allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(self.context.i8_type(), "bt_tail_last_slot")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(
                alloca,
                self.context
                    .i8_type()
                    .const_int(crate::BACKTRACE_TAIL_NO_NEXT_SLOT as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);
        self.backtrace_tail_last_slot_alloca = Some(alloca);
        Ok(alloca)
    }

    fn link_backtrace_tail_slot(
        &mut self,
        tail_slot: u8,
        offsets_found_u8: IntValue<'ctx>,
        done_block: BasicBlock<'ctx>,
    ) -> Result<()> {
        let current_fn = self.current_function("link bt tail slot")?;
        let offsets_found = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                offsets_found_u8,
                self.context.i8_type().const_zero(),
                "bt_tail_link_offsets_found",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let link_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_slot");
        self.builder
            .build_conditional_branch(offsets_found, link_block, done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(link_block);
        let state0_ptr = self.lookup_bt_state_ptr(0)?;
        let state0_is_null = self
            .builder
            .build_is_null(state0_ptr, "bt_tail_link_state0_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let state0_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_state0_ok");
        self.builder
            .build_conditional_branch(state0_is_null, done_block, state0_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(state0_ok_block);
        let tail_enabled_ptr = self.get_or_create_backtrace_tail_enabled_flag()?;
        let last_slot_ptr = self.get_or_create_backtrace_tail_last_slot()?;
        let enabled_value = self
            .builder
            .build_load(
                self.context.i8_type(),
                tail_enabled_ptr,
                "bt_tail_link_enabled_value",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let has_prev_slot = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                enabled_value,
                self.context.i8_type().const_zero(),
                "bt_tail_link_has_prev",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let first_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_first");
        let append_slot_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_append");
        let linked_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_linked");
        self.builder
            .build_conditional_branch(has_prev_slot, append_slot_block, first_slot_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(first_slot_block);
        self.store_u8_const(
            state0_ptr,
            crate::BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET,
            tail_slot,
            "bt_tail_link_active_slot",
        )?;
        self.builder
            .build_unconditional_branch(linked_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(append_slot_block);
        let prev_slot = self.load_i8(last_slot_ptr, "bt_tail_link_prev_slot")?;
        let prev_state_ptr = self.lookup_bt_state_ptr_dynamic(prev_slot)?;
        let prev_state_is_null = self
            .builder
            .build_is_null(prev_state_ptr, "bt_tail_link_prev_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let prev_state_ok_block = self
            .context
            .append_basic_block(current_fn, "bt_tail_link_prev_ok");
        self.builder
            .build_conditional_branch(prev_state_is_null, first_slot_block, prev_state_ok_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(prev_state_ok_block);
        self.store_u8_const(
            prev_state_ptr,
            crate::BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
            tail_slot,
            "bt_tail_link_prev_next_slot",
        )?;
        self.builder
            .build_unconditional_branch(linked_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(linked_block);
        self.builder
            .build_store(
                last_slot_ptr,
                self.context.i8_type().const_int(tail_slot as u64, false),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(tail_enabled_ptr, self.context.i8_type().const_int(1, false))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn store_state_i64(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<()> {
        self.store_u64_value(base, offset, value, name)
    }

    fn store_state_i32(
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
                &format!("{name}_u32_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(ptr, value)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    fn load_state_i32(
        &self,
        base: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(base, offset, name)?;
        let ptr = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_u32_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(self
            .builder
            .build_load(self.context.i32_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_row_i64(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        let ptr = self
            .builder
            .build_pointer_cast(
                ptr,
                self.context.ptr_type(AddressSpace::default()),
                &format!("{name}_i64_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(self
            .builder
            .build_load(self.context.i64_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_row_i16(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        Ok(self
            .builder
            .build_load(self.context.i16_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_row_i8(
        &self,
        row_ptr: PointerValue<'ctx>,
        offset: usize,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let ptr = self.byte_gep(row_ptr, offset, name)?;
        Ok(self
            .builder
            .build_load(self.context.i8_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_i8(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i8_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_bool(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.bool_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_i32(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i32_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_i16(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i16_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_i64(&self, ptr: PointerValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        Ok(self
            .builder
            .build_load(self.context.i64_type(), ptr, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value())
    }

    fn load_dwarf_register_i64(
        &mut self,
        reg: u16,
        pt_regs: PointerValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let value = self.load_register_value(reg, pt_regs)?;
        match value {
            BasicValueEnum::IntValue(value) => Ok(value),
            _ => Err(CodeGenError::RegisterMappingError(format!(
                "DWARF register {reg} did not load as integer"
            ))),
        }
    }

    fn add_signed_offset(
        &self,
        base: IntValue<'ctx>,
        offset: i64,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        if offset == 0 {
            return Ok(base);
        }
        self.builder
            .build_int_add(
                base,
                self.context.i64_type().const_int(offset as u64, true),
                name,
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    fn normalized_pc_from_raw(
        &self,
        raw_ip: IntValue<'ctx>,
        module_bias: IntValue<'ctx>,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        let rebased = self
            .builder
            .build_int_sub(raw_ip, module_bias, "bt_normalized_pc")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                rebased.into(),
                raw_ip.into(),
                "bt_pc_or_raw",
            )
            .map(|value| value.into_int_value())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    fn lookup_proc_module_range_meta(
        &mut self,
        pid: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtModuleRangeMeta<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("proc_module_range_meta")
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_range_meta map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_meta_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let key_arr_ty = i32_type.array_type(4);
        let zero = i32_type.const_zero();
        // SAFETY: key_alloca is the [4 x i32] pm_key stack slot and [0, 0]
        // addresses the pid key element for proc_module_range_meta.
        let key_ptr = unsafe {
            self.builder
                .build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[zero, zero],
                    &format!("{name_prefix}_meta_key_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, pid)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_arg = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, &format!("{name_prefix}_meta_key_arg"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let lookup_id = i64_type.const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(
                lookup_id,
                ptr_type,
                &format!("{name_prefix}_meta_lookup_fn"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let args: Vec<BasicMetadataValueEnum> = vec![map_ptr.into(), key_arg.into()];
        let value_ptr_any = self
            .builder
            .build_indirect_call(
                lookup_fn_type,
                lookup_fn_ptr,
                &args,
                &format!("{name_prefix}_meta_lookup"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_range_meta lookup returned void".to_string())
            })?;
        let value_ptr = match value_ptr_any {
            BasicValueEnum::PointerValue(p) => p,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "proc_module_range_meta lookup did not return pointer".to_string(),
                ));
            }
        };
        let current_fn = self.current_function("lookup proc module range meta")?;
        let hit_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_hit"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_miss"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_meta_cont"));
        let value_ptr_int = self
            .builder
            .build_ptr_to_int(
                value_ptr,
                i64_type,
                &format!("{name_prefix}_meta_value_ptr_int"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_hit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                value_ptr_int,
                i64_type.const_zero(),
                &format!("{name_prefix}_meta_found"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_hit, hit_block, miss_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(hit_block);
        let load_i32_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeMeta returned by
            // bpf_map_lookup_elem and offset is an i32 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let active_slot = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_META_ACTIVE_SLOT_OFFSET,
            &format!("{name_prefix}_meta_active_slot"),
            self,
        )?;
        let count = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_META_COUNT_OFFSET,
            &format!("{name_prefix}_meta_count"),
            self,
        )?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let hit_end = self.current_insert_block("finish module range meta hit block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end = self.current_insert_block("finish module range meta miss block")?;

        self.builder.position_at_end(cont_block);
        let found_type = self.context.bool_type();
        let found_phi = self
            .builder
            .build_phi(found_type, &format!("{name_prefix}_meta_found_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        found_phi.add_incoming(&[
            (&found_type.const_int(1, false), hit_end),
            (&found_type.const_zero(), miss_end),
        ]);
        let phi_i32 = |ctx: &mut EbpfContext<'ctx, 'dw>, name: &str, hit_value: IntValue<'ctx>| {
            let phi = ctx
                .builder
                .build_phi(ctx.context.i32_type(), name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            phi.add_incoming(&[
                (&hit_value, hit_end),
                (&ctx.context.i32_type().const_zero(), miss_end),
            ]);
            Ok(phi.as_basic_value().into_int_value())
        };
        Ok(BtModuleRangeMeta {
            found: found_phi.as_basic_value().into_int_value(),
            active_slot: phi_i32(self, &format!("{name_prefix}_meta_slot_phi"), active_slot)?,
            count: phi_i32(self, &format!("{name_prefix}_meta_count_phi"), count)?,
        })
    }

    fn lookup_proc_module_range_value(
        &mut self,
        pid: IntValue<'ctx>,
        slot: IntValue<'ctx>,
        index: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtModuleRangeValue<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_global = self
            .module
            .get_global("proc_module_ranges")
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_ranges map not found".to_string())
            })?;
        let map_ptr = self
            .builder
            .build_bit_cast(
                map_global.as_pointer_value(),
                ptr_type,
                &format!("{name_prefix}_range_map_ptr"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        self.builder
            .build_store(key_alloca, i32_type.array_type(4).const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let store_key_u32 = |offset: usize,
                             value: IntValue<'ctx>,
                             field_name: &str,
                             ctx: &mut EbpfContext<'ctx, 'dw>|
         -> Result<()> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: key_alloca is the ProcModuleRangeKey stack slot and
            // offset is one of its u32 field offsets.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), key_alloca, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_store(field_ptr, value)
                .map(|_| ())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_PID_OFFSET,
            pid,
            &format!("{name_prefix}_range_key_pid"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_SLOT_OFFSET,
            slot,
            &format!("{name_prefix}_range_key_slot"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_INDEX_OFFSET,
            index,
            &format!("{name_prefix}_range_key_index"),
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_RANGE_KEY_PAD_OFFSET,
            i32_type.const_zero(),
            &format!("{name_prefix}_range_key_pad"),
            self,
        )?;
        let key_arg = self
            .builder
            .build_bit_cast(
                key_alloca,
                ptr_type,
                &format!("{name_prefix}_range_key_arg"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let lookup_id = i64_type.const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(
                lookup_id,
                ptr_type,
                &format!("{name_prefix}_range_lookup_fn"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let args: Vec<BasicMetadataValueEnum> = vec![map_ptr.into(), key_arg.into()];
        let value_ptr_any = self
            .builder
            .build_indirect_call(
                lookup_fn_type,
                lookup_fn_ptr,
                &args,
                &format!("{name_prefix}_range_lookup"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_ranges lookup returned void".to_string())
            })?;
        let value_ptr = match value_ptr_any {
            BasicValueEnum::PointerValue(p) => p,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "proc_module_ranges lookup did not return pointer".to_string(),
                ));
            }
        };
        let current_fn = self.current_function("lookup proc module range value")?;
        let hit_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_hit"));
        let miss_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_miss"));
        let cont_block = self
            .context
            .append_basic_block(current_fn, &format!("{name_prefix}_range_cont"));
        let value_ptr_int = self
            .builder
            .build_ptr_to_int(
                value_ptr,
                i64_type,
                &format!("{name_prefix}_range_value_ptr_int"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let is_hit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                value_ptr_int,
                i64_type.const_zero(),
                &format!("{name_prefix}_range_found"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_hit, hit_block, miss_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(hit_block);
        let load_i64_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeValue returned by
            // bpf_map_lookup_elem and offset is a u64 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i64_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let load_i32_field = |offset: usize, field_name: &str, ctx: &mut EbpfContext<'ctx, 'dw>| {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: value_ptr points at ProcModuleRangeValue returned by
            // bpf_map_lookup_elem and offset is a u32 field offset.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), value_ptr, &[offset_i32], field_name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_load(ctx.context.i32_type(), field_ptr, field_name)
                .map(|value| value.into_int_value())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))
        };
        let base = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_BASE_OFFSET,
            &format!("{name_prefix}_range_base"),
            self,
        )?;
        let end = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_END_OFFSET,
            &format!("{name_prefix}_range_end"),
            self,
        )?;
        let text = load_i64_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_TEXT_OFFSET,
            &format!("{name_prefix}_range_text"),
            self,
        )?;
        let cookie_lo = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_COOKIE_LO_OFFSET,
            &format!("{name_prefix}_range_cookie_lo"),
            self,
        )?;
        let cookie_hi = load_i32_field(
            ghostscope_protocol::PROC_MODULE_RANGE_VALUE_COOKIE_HI_OFFSET,
            &format!("{name_prefix}_range_cookie_hi"),
            self,
        )?;
        let cookie_lo64 = self
            .builder
            .build_int_z_extend(cookie_lo, i64_type, &format!("{name_prefix}_cookie_lo64"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie_hi64 = self
            .builder
            .build_int_z_extend(cookie_hi, i64_type, &format!("{name_prefix}_cookie_hi64"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie_hi_shifted = self
            .builder
            .build_left_shift(
                cookie_hi64,
                i64_type.const_int(32, false),
                &format!("{name_prefix}_cookie_hi_shift"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let cookie = self
            .builder
            .build_or(
                cookie_lo64,
                cookie_hi_shifted,
                &format!("{name_prefix}_cookie"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let hit_end = self.current_insert_block("finish module range value hit block")?;

        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let miss_end = self.current_insert_block("finish module range value miss block")?;

        self.builder.position_at_end(cont_block);
        let zero_i64 = i64_type.const_zero();
        let found_type = self.context.bool_type();
        let found_phi = self
            .builder
            .build_phi(found_type, &format!("{name_prefix}_range_found_phi"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        found_phi.add_incoming(&[
            (&found_type.const_int(1, false), hit_end),
            (&found_type.const_zero(), miss_end),
        ]);
        let phi_i64 = |ctx: &mut EbpfContext<'ctx, 'dw>, name: &str, hit_value: IntValue<'ctx>| {
            let phi = ctx
                .builder
                .build_phi(ctx.context.i64_type(), name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            phi.add_incoming(&[(&hit_value, hit_end), (&zero_i64, miss_end)]);
            Ok(phi.as_basic_value().into_int_value())
        };
        Ok(BtModuleRangeValue {
            found: found_phi.as_basic_value().into_int_value(),
            base: phi_i64(self, &format!("{name_prefix}_range_base_phi"), base)?,
            end: phi_i64(self, &format!("{name_prefix}_range_end_phi"), end)?,
            text: phi_i64(self, &format!("{name_prefix}_range_text_phi"), text)?,
            cookie: phi_i64(self, &format!("{name_prefix}_range_cookie_phi"), cookie)?,
        })
    }

    fn lookup_backtrace_frame_module_in_ranges(
        &mut self,
        raw_ip: IntValue<'ctx>,
        pid: IntValue<'ctx>,
        meta: BtModuleRangeMeta<'ctx>,
        fallback_cookie: IntValue<'ctx>,
        fallback_bias: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtFrameModule<'ctx>> {
        let i32_type = self.context.i32_type();
        let i64_type = self.context.i64_type();
        let bool_type = self.context.bool_type();
        let max_steps = backtrace_row_binary_search_steps(
            (self.compile_options.proc_module_offsets_max_entries as usize).saturating_mul(2),
        );
        let current_fn = self.current_function("lookup backtrace frame module")?;

        let mut found = bool_type.const_zero();
        let mut cookie = fallback_cookie;
        let mut bias = fallback_bias;
        let mut lo = i32_type.const_zero();
        let mut hi = meta.count;

        for step in 0..max_steps {
            let not_found = self
                .builder
                .build_not(found, &format!("{name_prefix}_{step}_not_found"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range_active = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    lo,
                    hi,
                    &format!("{name_prefix}_{step}_active"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let pending = self
                .builder
                .build_and(
                    not_found,
                    range_active,
                    &format!("{name_prefix}_{step}_pending"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let should_search = self
                .builder
                .build_and(
                    pending,
                    meta.found,
                    &format!("{name_prefix}_{step}_should_search"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let search_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_search"));
            let skip_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_skip"));
            let after_block = self
                .context
                .append_basic_block(current_fn, &format!("{name_prefix}_{step}_after"));
            self.builder
                .build_conditional_branch(should_search, search_block, skip_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(skip_block);
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let skip_end = self.current_insert_block("finish module range skip block")?;

            self.builder.position_at_end(search_block);
            let lo_plus_hi = self
                .builder
                .build_int_add(lo, hi, &format!("{name_prefix}_{step}_lo_plus_hi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let mid = self
                .builder
                .build_right_shift(
                    lo_plus_hi,
                    i32_type.const_int(1, false),
                    false,
                    &format!("{name_prefix}_{step}_mid"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range = self.lookup_proc_module_range_value(
                pid,
                meta.active_slot,
                mid,
                &format!("{name_prefix}_{step}"),
            )?;
            let at_or_after_base = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    raw_ip,
                    range.base,
                    &format!("{name_prefix}_{step}_after_base"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_end = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    raw_ip,
                    range.end,
                    &format!("{name_prefix}_{step}_before_end"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let in_bounds = self
                .builder
                .build_and(
                    at_or_after_base,
                    before_end,
                    &format!("{name_prefix}_{step}_in_bounds"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let in_range = self
                .builder
                .build_and(
                    range.found,
                    in_bounds,
                    &format!("{name_prefix}_{step}_in_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let before_range = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::ULT,
                    raw_ip,
                    range.base,
                    &format!("{name_prefix}_{step}_before_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let after_range = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::UGE,
                    raw_ip,
                    range.end,
                    &format!("{name_prefix}_{step}_after_range"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let found_next = self
                .builder
                .build_or(found, in_range, &format!("{name_prefix}_{step}_found_next"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let selected_cookie = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    in_range,
                    range.cookie.into(),
                    cookie.into(),
                    &format!("{name_prefix}_{step}_selected_cookie"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let selected_bias = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    in_range,
                    range.text.into(),
                    bias.into(),
                    &format!("{name_prefix}_{step}_selected_bias"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let mid_plus_one = self
                .builder
                .build_int_add(
                    mid,
                    i32_type.const_int(1, false),
                    &format!("{name_prefix}_{step}_mid_plus_one"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let range_missing = self
                .builder
                .build_not(range.found, &format!("{name_prefix}_{step}_range_missing"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let hi_next = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    before_range,
                    mid.into(),
                    hi.into(),
                    &format!("{name_prefix}_{step}_hi_next"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let lo_after = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    after_range,
                    mid_plus_one.into(),
                    lo.into(),
                    &format!("{name_prefix}_{step}_lo_after"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            let lo_next = self
                .builder
                .build_select::<BasicValueEnum<'ctx>, _>(
                    range_missing,
                    hi.into(),
                    lo_after.into(),
                    &format!("{name_prefix}_{step}_lo_next"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            self.builder
                .build_unconditional_branch(after_block)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let search_end = self.current_insert_block("finish module range search block")?;

            self.builder.position_at_end(after_block);

            let found_phi = self
                .builder
                .build_phi(bool_type, &format!("{name_prefix}_{step}_found_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            found_phi.add_incoming(&[(&found_next, search_end), (&found, skip_end)]);
            found = found_phi.as_basic_value().into_int_value();

            let cookie_phi = self
                .builder
                .build_phi(i64_type, &format!("{name_prefix}_{step}_cookie_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            cookie_phi.add_incoming(&[(&selected_cookie, search_end), (&cookie, skip_end)]);
            cookie = cookie_phi.as_basic_value().into_int_value();

            let bias_phi = self
                .builder
                .build_phi(i64_type, &format!("{name_prefix}_{step}_bias_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            bias_phi.add_incoming(&[(&selected_bias, search_end), (&bias, skip_end)]);
            bias = bias_phi.as_basic_value().into_int_value();

            let lo_phi = self
                .builder
                .build_phi(i32_type, &format!("{name_prefix}_{step}_lo_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            lo_phi.add_incoming(&[(&lo_next, search_end), (&lo, skip_end)]);
            lo = lo_phi.as_basic_value().into_int_value();

            let hi_phi = self
                .builder
                .build_phi(i32_type, &format!("{name_prefix}_{step}_hi_phi"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            hi_phi.add_incoming(&[(&hi_next, search_end), (&hi, skip_end)]);
            hi = hi_phi.as_basic_value().into_int_value();
        }

        Ok(BtFrameModule {
            cookie,
            bias,
            found,
        })
    }

    fn resolve_backtrace_frame_module(
        &mut self,
        raw_ip: IntValue<'ctx>,
        fallback_cookie: IntValue<'ctx>,
        fallback_bias: IntValue<'ctx>,
        fallback_found: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<BtFrameModule<'ctx>> {
        if self.backtrace_module_row_ranges.is_empty() {
            return Ok(BtFrameModule {
                cookie: fallback_cookie,
                bias: fallback_bias,
                found: fallback_found,
            });
        }

        let pid = self.proc_module_pid_key(name_prefix)?;
        let meta = self.lookup_proc_module_range_meta(pid, name_prefix)?;
        self.lookup_backtrace_frame_module_in_ranges(
            raw_ip,
            pid,
            meta,
            fallback_cookie,
            fallback_bias,
            name_prefix,
        )
    }

    fn backtrace_module_fallback_found(&self, found: IntValue<'ctx>) -> IntValue<'ctx> {
        if self.backtrace_module_row_ranges.is_empty() {
            found
        } else {
            self.context.bool_type().const_zero()
        }
    }

    fn backtrace_lookup_pc_from_raw(
        &self,
        raw_ip: IntValue<'ctx>,
        module_bias: IntValue<'ctx>,
        offsets_found: IntValue<'ctx>,
    ) -> Result<IntValue<'ctx>> {
        self.normalized_pc_from_raw(raw_ip, module_bias, offsets_found)
    }

    fn bool_to_u8(&self, value: IntValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
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

    fn status_or_offsets_unavailable(
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

    fn status_for_backtrace_stop(
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

    fn store_backtrace_frame(
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

    fn store_backtrace_frame_dynamic(
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

    fn store_u8_const(
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

    fn store_u8_value(
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

    fn store_u16_const(
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

    fn store_u16_value(
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

    fn store_u64_value(
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

    fn byte_gep(
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

    fn dynamic_byte_gep(
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

    fn build_entry_alloca<T>(&self, ty: T, name: &str) -> Result<PointerValue<'ctx>>
    where
        T: inkwell::types::BasicType<'ctx>,
    {
        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for bt stack allocation".to_string())
        })?;
        let current_fn = self.current_function("allocate bt scratch")?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for bt stack allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(ty, name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);
        Ok(alloca)
    }
}

fn backtrace_row_binary_search_steps(row_count: usize) -> usize {
    if row_count <= 1 {
        1
    } else {
        (usize::BITS - (row_count - 1).leading_zeros()) as usize + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::context::BacktraceModuleRowRangeEntry;
    use crate::CompileOptions;
    use inkwell::AddressSpace;

    #[test]
    fn binary_search_steps_cover_power_of_two_row_counts() {
        assert_eq!(backtrace_row_binary_search_steps(0), 1);
        assert_eq!(backtrace_row_binary_search_steps(1), 1);
        assert_eq!(backtrace_row_binary_search_steps(2), 2);
        assert_eq!(backtrace_row_binary_search_steps(4), 3);
        assert_eq!(backtrace_row_binary_search_steps(8), 4);
    }

    #[test]
    fn binary_search_steps_cover_non_power_of_two_row_counts() {
        assert_eq!(backtrace_row_binary_search_steps(3), 3);
        assert_eq!(backtrace_row_binary_search_steps(5), 4);
        assert_eq!(backtrace_row_binary_search_steps(9), 5);
    }

    #[test]
    fn runtime_backtrace_frame_module_resolution_generates_range_lookups() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "bt_frame_module_test", Some(0), &opts).expect("ctx");
        let i64_type = context.i64_type();
        for map_name in ["proc_module_range_meta", "proc_module_ranges"] {
            let map_global =
                ctx.module
                    .add_global(i64_type, Some(AddressSpace::default()), map_name);
            map_global.set_initializer(&i64_type.const_zero());
        }

        let fn_type = context.i32_type().fn_type(&[], false);
        let function = ctx.module.add_function("bt_frame_module", fn_type, None);
        let entry = context.append_basic_block(function, "entry");
        ctx.builder.position_at_end(entry);
        let key_type = context.i32_type().array_type(4);
        ctx.pm_key_alloca = Some(
            ctx.builder
                .build_alloca(key_type, "pm_key")
                .expect("pm_key alloca"),
        );
        ctx.backtrace_module_row_ranges = vec![
            BacktraceModuleRowRangeEntry {
                cookie: 0x1111,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: 0,
                    row_end: 1,
                },
            },
            BacktraceModuleRowRangeEntry {
                cookie: 0x2222,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: 1,
                    row_end: 2,
                },
            },
        ];

        let frame_module = ctx
            .resolve_backtrace_frame_module(
                i64_type.const_int(0x7f00_1234, false),
                i64_type.const_int(0x1111, false),
                i64_type.const_zero(),
                context.bool_type().const_zero(),
                "test_bt_frame_module",
            )
            .expect("resolve frame module");
        ctx.store_u64_value(
            ctx.pm_key_alloca.expect("pm key"),
            0,
            frame_module.cookie,
            "selected_cookie",
        )
        .expect("store selected cookie");

        let ir = ctx.module.print_to_string().to_string();
        assert!(
            ir.contains("proc_module_range_meta")
                && ir.contains("proc_module_ranges")
                && ir.contains("test_bt_frame_module_0_range_base")
                && ir.contains("test_bt_frame_module_0_range_end"),
            "resolver should use the per-PID module range index\nIR:\n{ir}"
        );
        assert!(
            ir.contains("test_bt_frame_module_0_range_cookie")
                && !ir.contains("proc_module_offsets"),
            "resolver should select a module cookie without scanning offsets\nIR:\n{ir}"
        );
    }

    #[test]
    fn runtime_backtrace_row_bounds_cover_all_prepared_modules() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "bt_row_bounds_test", Some(0), &opts).expect("ctx");

        let fn_type = context
            .i32_type()
            .fn_type(&[context.i64_type().into()], false);
        let function = ctx.module.add_function("bt_row_bounds", fn_type, None);
        let entry = context.append_basic_block(function, "entry");
        ctx.builder.position_at_end(entry);
        let map_global = ctx.module.add_global(
            context.i64_type(),
            Some(AddressSpace::default()),
            "bt_module_row_ranges",
        );
        map_global.set_initializer(&context.i64_type().const_zero());
        let key_type = context.i32_type().array_type(4);
        ctx.pm_key_alloca = Some(
            ctx.builder
                .build_alloca(key_type, "pm_key")
                .expect("pm_key alloca"),
        );

        ctx.backtrace_module_row_ranges = (0..=32)
            .map(|idx| BacktraceModuleRowRangeEntry {
                cookie: 0x1000 + idx as u64,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: (idx * 2) as u32,
                    row_end: (idx * 2 + 2) as u32,
                },
            })
            .collect();

        let bounds = ctx
            .backtrace_unwind_row_bounds_for_module(
                function
                    .get_first_param()
                    .expect("module cookie param")
                    .into_int_value(),
                "test_bt_row_bounds",
            )
            .expect("row bounds");
        ctx.builder
            .build_return(Some(&bounds.end))
            .expect("return bounds end");

        let ir = ctx.module.print_to_string().to_string();
        assert!(
            ir.contains("bt_module_row_ranges")
                && ir.contains("test_bt_row_bounds_row_range_lookup"),
            "row bounds lookup should use the module range map\nIR:\n{ir}"
        );
        assert!(
            !ir.contains("module_matches"),
            "row bounds lookup should not use static candidate comparisons\nIR:\n{ir}"
        );
        assert!(
            !ir.contains("row_range_cookie_lo") && !ir.contains("row_range_cookie_hi"),
            "row bounds lookup should store the native u64 module cookie\nIR:\n{ir}"
        );
    }
}

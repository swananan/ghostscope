//! Sleepable uprobes can overlap on the same CPU while faulting in user memory.
//! Keep their event and tail-call state in one non-evicting entry per host pid_tgid.
//! Uprobes cannot re-enter userspace on the same task before returning; NOEXIST
//! also rejects unexpected re-entry instead of overwriting an active invocation.

use super::context::{CodeGenError, EbpfContext, Result};
use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_map_delete_elem, BPF_FUNC_map_lookup_elem,
    BPF_FUNC_map_update_elem,
};
use inkwell::values::{InstructionOpcode, IntValue, PointerValue};
use inkwell::{AddressSpace, IntPredicate};

// Bound concurrent in-flight invocations, not the total number of traced tasks.
// Preallocation is required by older sleepable-program verifiers. Never use LRU:
// evicting a sleeping owner's entry would invalidate its tail-call handoff.
const MAX_IN_FLIGHT_INVOCATIONS: u64 = 128;
const STATE_MAP: &str = "invocation_state";
const ZERO_TEMPLATE: &str = "invocation_zero";

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    fn invocation_backtrace_offset(&self) -> u64 {
        u64::from(self.compile_options.max_trace_event_size).next_multiple_of(8)
    }

    pub(super) fn create_sleepable_invocation_map(&mut self, has_tail_calls: bool) -> Result<()> {
        let tail_bytes = if has_tail_calls {
            u64::from(self.backtrace_tail_call_slots.max(1))
                * crate::BACKTRACE_TAIL_STATE_SIZE as u64
        } else {
            0
        };
        let size = u32::try_from(self.invocation_backtrace_offset() + tail_bytes)
            .map_err(|_| CodeGenError::LLVMError("invocation state is too large".into()))?;
        self.map_manager
            .create_hash_map(
                &self.module,
                &self.di_builder,
                &self.compile_unit,
                STATE_MAP,
                MAX_IN_FLIGHT_INVOCATIONS,
                (8, u64::from(size)),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // Map insertion needs a full initialized value, too large for the BPF
        // stack. This template is read-only; no invocation ever writes into it.
        let ty = self.context.i8_type().array_type(size);
        let template = self.module.add_global(ty, None, ZERO_TEMPLATE);
        template.set_initializer(&ty.const_zero());
        template.set_constant(true);
        template.set_section(Some(".rodata"));
        template.set_alignment(8);
        Ok(())
    }

    pub(crate) fn initialize_sleepable_invocation(&mut self, create: bool) -> Result<()> {
        let function = self.current_function("initialize invocation state")?;
        let i64_ty = self.context.i64_type();
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let map = self
            .map_manager
            .get_map(&self.module, STATE_MAP)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key = self.get_or_create_invocation_scratch("invocation_key", i64_ty)?;
        let owned_key = self.get_or_create_invocation_scratch("invocation_owned_key", i64_ty)?;
        self.invocation_cleanup_keys.insert(function, owned_key);
        let pid_tgid = self
            .create_bpf_helper_call(
                BPF_FUNC_get_current_pid_tgid as u64,
                &[],
                i64_ty.into(),
                "invocation_pid_tgid",
            )?
            .into_int_value();
        self.builder
            .build_store(key, pid_tgid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let failed = self
            .context
            .append_basic_block(function, "invocation_failed");
        if create {
            let template = self.module.get_global(ZERO_TEMPLATE).ok_or_else(|| {
                CodeGenError::LLVMError("invocation zero template missing".into())
            })?;
            let status = self
                .create_bpf_helper_call(
                    BPF_FUNC_map_update_elem as u64,
                    &[
                        map.into(),
                        key.into(),
                        template.as_pointer_value().into(),
                        i64_ty.const_int(1, false).into(),
                    ], // BPF_NOEXIST
                    i64_ty.into(),
                    "invocation_acquire",
                )?
                .into_int_value();
            let success = self
                .builder
                .build_int_compare(
                    IntPredicate::EQ,
                    status,
                    i64_ty.const_zero(),
                    "invocation_acquired",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let acquired = self
                .context
                .append_basic_block(function, "invocation_acquired");
            self.builder
                .build_conditional_branch(success, acquired, failed)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(acquired);
        }
        // A tail program inherits ownership from the successful main program.
        // An unsuccessful NOEXIST insertion never reaches this store, so its
        // return cannot delete another invocation's state.
        self.builder
            .build_store(owned_key, pid_tgid)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let state = self
            .create_bpf_helper_call(
                BPF_FUNC_map_lookup_elem as u64,
                &[map.into(), key.into()],
                ptr_ty.into(),
                "invocation_lookup",
            )?
            .into_pointer_value();
        let missing = self
            .builder
            .build_is_null(state, "invocation_missing")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let ready = self
            .context
            .append_basic_block(function, "invocation_ready");
        self.builder
            .build_conditional_branch(missing, failed, ready)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder.position_at_end(failed);
        self.increment_event_loss_counter()?;
        self.builder
            .build_return(Some(&self.context.i32_type().const_zero()))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder.position_at_end(ready);
        self.event_accumulation_buffers.insert(function, state);
        Ok(())
    }

    pub(crate) fn lookup_sleepable_bt_state(
        &mut self,
        index: IntValue<'ctx>,
    ) -> Result<PointerValue<'ctx>> {
        let buffer = self.current_event_accumulation_buffer()?;
        let i64_ty = self.context.i64_type();
        let index = self
            .builder
            .build_int_z_extend(index, i64_ty, "invocation_bt_index")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let function = self.current_function("lookup invocation backtrace state")?;
        let valid = self
            .builder
            .build_int_compare(
                IntPredicate::ULT,
                index,
                i64_ty.const_int(u64::from(self.backtrace_tail_call_slots.max(1)), false),
                "invocation_bt_in_bounds",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let before = self.current_insert_block("lookup invocation backtrace state")?;
        let hit = self
            .context
            .append_basic_block(function, "invocation_bt_hit");
        let done = self
            .context
            .append_basic_block(function, "invocation_bt_done");
        self.builder
            .build_conditional_branch(valid, hit, done)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder.position_at_end(hit);
        let offset = self
            .builder
            .build_int_mul(
                index,
                i64_ty.const_int(crate::BACKTRACE_TAIL_STATE_SIZE as u64, false),
                "invocation_bt_stride",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let offset = self
            .builder
            .build_int_add(
                offset,
                i64_ty.const_int(self.invocation_backtrace_offset(), false),
                "invocation_bt_offset",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        // SAFETY: index is bounded by the allocated slot count, and the aligned
        // backtrace array follows the event buffer in this map value.
        let state = unsafe {
            self.builder.build_gep(
                self.context.i8_type(),
                buffer,
                &[offset],
                "invocation_bt_state",
            )
        }
        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_unconditional_branch(done)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder.position_at_end(done);
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let phi = self
            .builder
            .build_phi(ptr_ty, "invocation_bt_result")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        phi.add_incoming(&[(&ptr_ty.const_null(), before), (&state, hit)]);
        Ok(phi.as_basic_value().into_pointer_value())
    }

    /// Instrument every exit after code generation, including filters, overflow,
    /// aborts and failed tail calls. A successful tail call never executes a ret
    /// instruction, so ownership lives until the final step actually returns.
    pub(super) fn finalize_invocation_cleanup(&mut self) -> Result<()> {
        let owners: Vec<_> = self
            .invocation_cleanup_keys
            .iter()
            .map(|(f, p)| (*f, *p))
            .collect();
        for (function, key) in owners {
            let returns: Vec<_> = function
                .get_basic_blocks()
                .into_iter()
                .filter_map(|block| block.get_terminator())
                .filter(|inst| inst.get_opcode() == InstructionOpcode::Return)
                .collect();
            for ret in returns {
                let block = ret
                    .get_parent()
                    .ok_or_else(|| CodeGenError::LLVMError("return has no block".into()))?;
                ret.remove_from_basic_block();
                self.builder.position_at_end(block);
                let owner = self
                    .builder
                    .build_load(self.context.i64_type(), key, "invocation_owner")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into_int_value();
                let owns = self
                    .builder
                    .build_int_compare(
                        IntPredicate::NE,
                        owner,
                        self.context.i64_type().const_zero(),
                        "invocation_owns_state",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let cleanup = self
                    .context
                    .append_basic_block(function, "invocation_cleanup");
                let done = self
                    .context
                    .append_basic_block(function, "invocation_return");
                self.builder
                    .build_conditional_branch(owns, cleanup, done)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder.position_at_end(cleanup);
                let map = self
                    .map_manager
                    .get_map(&self.module, STATE_MAP)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                self.create_bpf_helper_call(
                    BPF_FUNC_map_delete_elem as u64,
                    &[map.into(), key.into()],
                    self.context.i64_type().into(),
                    "invocation_release",
                )?;
                self.builder
                    .build_unconditional_branch(done)
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder.position_at_end(done);
                self.builder.insert_instruction(&ret, None);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use inkwell::values::AnyValue;

    #[test]
    fn sleepable_program_uses_readonly_template_and_cleans_filtered_exits() {
        let llvm = inkwell::context::Context::create();
        let mut options = crate::CompileOptions::default();
        options.runtime_capabilities.sleepable_uprobe = true;
        let mut ctx = EbpfContext::new(&llvm, "invocation", Some(0), &options).unwrap();
        ctx.compile_program(
            &crate::script::Program::new(),
            "probe",
            &[],
            Some(123),
            None,
            None,
        )
        .unwrap();
        ctx.module.verify().unwrap();
        assert!(ctx.module.get_global("event_accum_buffer").is_none());
        assert!(ctx.module.get_global("bt_state").is_none());
        assert!(ctx.module.get_global(ZERO_TEMPLATE).unwrap().is_constant());
        let ir = ctx.module.print_to_string().to_string();
        assert!(ir.contains("atomicrmw add"), "{ir}");
        assert!(ir.contains("monotonic"), "{ir}");
        assert!(ir.contains("invocation_release"), "{ir}");
        // Even the PID filter, emitted before acquisition, gets a guarded exit.
        let function = ctx.module.get_function("probe").unwrap();
        for block in function.get_basic_blocks() {
            if block
                .get_terminator()
                .is_some_and(|i| i.get_opcode() == InstructionOpcode::Return)
            {
                assert!(block
                    .get_name()
                    .to_str()
                    .unwrap()
                    .starts_with("invocation_return"));
            }
        }
    }

    #[test]
    fn tail_program_inherits_state_without_inserting_or_zeroing_it() {
        let llvm = inkwell::context::Context::create();
        let mut options = crate::CompileOptions::default();
        options.runtime_capabilities.sleepable_uprobe = true;
        let mut ctx = EbpfContext::new(&llvm, "tail_ownership", Some(0), &options).unwrap();
        ctx.backtrace_tail_call_slots = 3;
        ctx.create_sleepable_invocation_map(true).unwrap();
        ctx.map_manager
            .create_event_loss_counter_map(
                &ctx.module,
                &ctx.di_builder,
                &ctx.compile_unit,
                "event_loss_counters",
                1,
            )
            .unwrap();
        for (name, create) in [("main", true), ("step", false)] {
            ctx.create_basic_ebpf_function(name).unwrap();
            ctx.__test_alloc_pm_key().unwrap();
            ctx.initialize_sleepable_invocation(create).unwrap();
            let slot = ctx
                .lookup_sleepable_bt_state(llvm.i8_type().const_int(2, false))
                .unwrap();
            // A consumer must check the nullable result before using it.
            ctx.builder.build_is_null(slot, "slot_missing").unwrap();
            ctx.builder
                .build_return(Some(&llvm.i32_type().const_zero()))
                .unwrap();
        }
        ctx.finalize_invocation_cleanup().unwrap();
        ctx.module.verify().unwrap();
        let main = ctx
            .module
            .get_function("main")
            .unwrap()
            .print_to_string()
            .to_string();
        let step = ctx
            .module
            .get_function("step")
            .unwrap()
            .print_to_string()
            .to_string();
        assert!(main.contains("invocation_acquire"));
        assert!(!step.contains("invocation_acquire") && !step.contains(ZERO_TEMPLATE));
        assert!(step.contains("invocation_lookup") && step.contains("invocation_release"));
        assert!(step.contains("invocation_bt_state"));
    }
}

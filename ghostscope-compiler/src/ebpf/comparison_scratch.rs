//! Comparison buffers must not consume the BPF stack, even when many individually
//! small buffers are used. Lay out every function's buffers in one owned hash
//! entry after code generation, when the complete footprint is known.
use super::context::{CodeGenError, EbpfContext, Result};
use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_map_delete_elem, BPF_FUNC_map_lookup_elem,
    BPF_FUNC_map_update_elem,
};
use inkwell::{values::InstructionOpcode, AddressSpace, IntPredicate};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn finalize_comparison_buffers(&mut self) -> Result<()> {
        let buffers = std::mem::take(&mut self.comparison_buffers);
        // Module order keeps object generation deterministic.
        for (number, function) in self.module.get_functions().enumerate() {
            let local: Vec<_> = buffers.iter().filter(|(f, _, _)| *f == function).collect();
            if local.is_empty() {
                continue;
            }
            let bytes = local
                .iter()
                .try_fold(0u32, |n, (_, _, size)| {
                    n.checked_add(size.next_multiple_of(8)).ok_or_else(|| {
                        CodeGenError::LLVMError("comparison scratch is too large".into())
                    })
                })?
                .max(8);
            let name = format!("cmp_scratch_{number}");
            self.map_manager
                .create_hash_map(
                    &self.module,
                    &self.di_builder,
                    &self.compile_unit,
                    &name,
                    128,
                    (8, u64::from(bytes)),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let map = self
                .map_manager
                .get_map(&self.module, &name)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let ty = self.context.i8_type().array_type(bytes);
            let zero = self
                .module
                .add_global(ty, None, &format!("cmp_zero_{number}"));
            zero.set_initializer(&ty.const_zero());
            zero.set_constant(true);
            zero.set_section(Some(".rodata"));
            zero.set_alignment(8);

            // Only original exits own an entry. Acquisition failures below must
            // not delete another invocation's entry after a NOEXIST rejection.
            let returns: Vec<_> = function
                .get_basic_blocks()
                .into_iter()
                .filter_map(|b| b.get_terminator())
                .filter(|i| i.get_opcode() == InstructionOpcode::Return)
                .collect();
            let original = function.get_first_basic_block().ok_or_else(|| {
                CodeGenError::LLVMError("comparison function has no entry".into())
            })?;
            let entry = self
                .context
                .prepend_basic_block(original, "comparison_entry");
            self.builder.position_at_end(entry);
            let i64_ty = self.context.i64_type();
            let key = self
                .builder
                .build_alloca(i64_ty, "comparison_key")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let pid_tgid = self.create_bpf_helper_call(
                BPF_FUNC_get_current_pid_tgid as u64,
                &[],
                i64_ty.into(),
                "comparison_pid_tgid",
            )?;
            self.builder
                .build_store(key, pid_tgid)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let acquired = self
                .create_bpf_helper_call(
                    BPF_FUNC_map_update_elem as u64,
                    &[
                        map.into(),
                        key.into(),
                        zero.as_pointer_value().into(),
                        i64_ty.const_int(1, false).into(),
                    ],
                    i64_ty.into(),
                    "comparison_acquire",
                )?
                .into_int_value();
            let success = self
                .builder
                .build_int_compare(
                    IntPredicate::EQ,
                    acquired,
                    i64_ty.const_zero(),
                    "comparison_acquired",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let lookup = self
                .context
                .append_basic_block(function, "comparison_lookup");
            let failed = self
                .context
                .append_basic_block(function, "comparison_failed");
            self.builder
                .build_conditional_branch(success, lookup, failed)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(lookup);
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let state = self
                .create_bpf_helper_call(
                    BPF_FUNC_map_lookup_elem as u64,
                    &[map.into(), key.into()],
                    ptr_ty.into(),
                    "comparison_state",
                )?
                .into_pointer_value();
            let missing = self
                .builder
                .build_is_null(state, "comparison_missing")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let release = self
                .context
                .append_basic_block(function, "comparison_release_missing");
            let ready = self
                .context
                .append_basic_block(function, "comparison_ready");
            self.builder
                .build_conditional_branch(missing, release, ready)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(release);
            self.create_bpf_helper_call(
                BPF_FUNC_map_delete_elem as u64,
                &[map.into(), key.into()],
                i64_ty.into(),
                "comparison_release",
            )?;
            self.builder
                .build_unconditional_branch(failed)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            self.builder.position_at_end(failed);
            // The original function's pm_key has not been initialized yet.
            let saved_key = self.pm_key_alloca;
            self.pm_key_alloca = Some(self.get_or_create_invocation_scratch(
                "comparison_loss_key",
                self.context.i32_type().array_type(4),
            )?);
            self.increment_event_loss_counter()?;
            self.pm_key_alloca = saved_key;
            self.builder
                .build_return(Some(&self.context.i32_type().const_zero()))
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            self.builder.position_at_end(ready);
            let mut offset = 0u64;
            for (_, placeholder, size) in local {
                // SAFETY: each aligned slice lies inside this map's full value.
                let ptr = unsafe {
                    self.builder.build_gep(
                        self.context.i8_type(),
                        state,
                        &[i64_ty.const_int(offset, false)],
                        "comparison_buffer",
                    )
                }
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                placeholder.replace_all_uses_with(ptr);
                placeholder
                    .as_instruction()
                    .ok_or_else(|| {
                        CodeGenError::LLVMError("comparison placeholder is not an alloca".into())
                    })?
                    .erase_from_basic_block();
                offset += u64::from(size.next_multiple_of(8));
            }
            self.builder
                .build_unconditional_branch(original)
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;

            // Fixed stack slots must remain in LLVM's entry block. In particular,
            // leaving the old entry allocas behind makes BPF instruction selection
            // treat them as unsupported dynamic allocations.
            let allocas: Vec<_> = std::iter::successors(original.get_first_instruction(), |i| {
                i.get_next_instruction()
            })
            .filter(|i| i.get_opcode() == InstructionOpcode::Alloca)
            .collect();
            for alloca in allocas {
                alloca.remove_from_basic_block();
                self.builder.position_before(
                    &entry.get_first_instruction().ok_or_else(|| {
                        CodeGenError::LLVMError("comparison entry is empty".into())
                    })?,
                );
                self.builder.insert_instruction(&alloca, None);
            }

            // Scratch is dead after script evaluation, including on a successful
            // tail call that never executes a return in this function. Failed
            // tail calls can delete again on return; deletion is idempotent and
            // the same task cannot start another invocation in between.
            let tails: Vec<_> = self
                .comparison_tail_calls
                .iter()
                .copied()
                .filter(|i| i.get_parent().and_then(|b| b.get_parent()) == Some(function))
                .collect();
            for exit in returns.into_iter().chain(tails) {
                self.builder.position_before(&exit);
                self.create_bpf_helper_call(
                    BPF_FUNC_map_delete_elem as u64,
                    &[map.into(), key.into()],
                    i64_ty.into(),
                    "comparison_release",
                )?;
            }
        }
        Ok(())
    }
}

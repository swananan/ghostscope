//! eBPF helper function management
//!
//! This module handles eBPF helper function calls, register mapping, and pt_regs
//! access for different target architectures.

use super::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_get_current_task, BPF_FUNC_ktime_get_ns,
    BPF_FUNC_map_lookup_elem, BPF_FUNC_perf_event_output, BPF_FUNC_probe_read_kernel,
    BPF_FUNC_probe_read_user, BPF_FUNC_probe_read_user_str, BPF_FUNC_ringbuf_output,
};
use ghostscope_dwarf::MemoryAccessSize;
use ghostscope_platform::register_mapping;
use ghostscope_protocol::trace_event::VariableStatus;
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::values::{BasicMetadataValueEnum, BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;

struct ProbeReadResult<'ctx> {
    loaded_i64: IntValue<'ctx>,
    combined_fail: IntValue<'ctx>,
    not_found: IntValue<'ctx>,
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    fn get_or_create_tls_scratch_buffer(&mut self) -> Result<PointerValue<'ctx>> {
        if let Some(alloca) = self.tls_scratch_alloca {
            return Ok(alloca);
        }

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for TLS scratch allocation".to_string())
        })?;
        let current_fn = current_block.get_parent().ok_or_else(|| {
            CodeGenError::LLVMError("no current function for TLS scratch allocation".to_string())
        })?;
        let entry_block = current_fn.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for TLS scratch allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let scratch = self
            .builder
            .build_alloca(self.context.i64_type(), "tls_scratch")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(current_block);

        self.tls_scratch_alloca = Some(scratch);
        Ok(scratch)
    }

    fn get_probe_read_scratch_buffer(
        &mut self,
        result_size: usize,
        name_prefix: &str,
    ) -> Result<PointerValue<'ctx>> {
        if result_size <= 4 {
            if let Some(key_alloca) = self.pm_key_alloca {
                // Safe aliasing: the map key stack slot is only reused after the
                // preceding map lookup has consumed it, and before any later
                // lookup rewrites it on the current straight-line code path.
                //
                // Keep this reuse limited to <=4-byte reads. `pm_key_alloca` is a
                // `[4 x i32]` stack slot, so it only guarantees i32 alignment; the
                // U64/pointer read paths later issue an `i64` load and therefore
                // need an 8-byte-aligned scratch buffer.
                let i32_type = self.context.i32_type();
                let key_arr_ty = i32_type.array_type(4);
                let zero = i32_type.const_zero();
                // SAFETY: pm_key_alloca is a [4 x i32] entry-block alloca and
                // [0, 0] addresses its first byte-compatible element.
                return unsafe {
                    self.builder
                        .build_gep(
                            key_arr_ty,
                            key_alloca,
                            &[zero, zero],
                            &format!("{name_prefix}_scratch_i8"),
                        )
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))
                };
            }
        }

        let buffer_name = format!("_temp_read_buffer_{result_size}");
        let global_buffer = match self.module.get_global(&buffer_name) {
            Some(existing) => existing.as_pointer_value(),
            None => {
                let array_type = self.context.i8_type().array_type(result_size as u32);
                let global =
                    self.module
                        .add_global(array_type, Some(AddressSpace::default()), &buffer_name);
                global.set_initializer(&array_type.const_zero());
                global.as_pointer_value()
            }
        };
        Ok(global_buffer)
    }

    pub fn lookup_proc_pid_alias(
        &mut self,
        runtime_pid: IntValue<'ctx>,
        name_prefix: &str,
    ) -> Result<IntValue<'ctx>> {
        let Some(map_global) = self.module.get_global("pid_aliases") else {
            return Ok(runtime_pid);
        };

        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let map_ptr = map_global.as_pointer_value();
        let map_ptr_cast = self
            .builder
            .build_bit_cast(map_ptr, ptr_type, &format!("{name_prefix}_map_ptr"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let key_arr_ty = i32_type.array_type(4);
        let zero = i32_type.const_zero();
        // SAFETY: key_alloca is the [4 x i32] pm_key stack slot and [0, 0]
        // addresses the pid key element.
        let key_ptr = unsafe {
            self.builder
                .build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[zero, zero],
                    &format!("{name_prefix}_alias_key_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(key_ptr, runtime_pid)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_arg = self
            .builder
            .build_bit_cast(key_ptr, ptr_type, &format!("{name_prefix}_alias_key_arg"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let lookup_id = self
            .context
            .i64_type()
            .const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(lookup_id, ptr_type, &format!("{name_prefix}_lookup_fn"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let lookup_args: Vec<BasicMetadataValueEnum> = vec![map_ptr_cast.into(), key_arg.into()];
        let value_ptr_any = self
            .builder
            .build_indirect_call(
                lookup_fn_type,
                lookup_fn_ptr,
                &lookup_args,
                &format!("{name_prefix}_alias_lookup"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("pid_aliases lookup returned void".to_string())
            })?;

        let value_ptr = match value_ptr_any {
            BasicValueEnum::PointerValue(p) => p,
            _ => {
                return Err(CodeGenError::LLVMError(
                    "pid_aliases lookup did not return pointer".to_string(),
                ));
            }
        };

        let helper_fn = self.current_function("lookup proc pid alias")?;
        let alias_hit_block = self
            .context
            .append_basic_block(helper_fn, &format!("{name_prefix}_alias_hit"));
        let alias_miss_block = self
            .context
            .append_basic_block(helper_fn, &format!("{name_prefix}_alias_miss"));
        let alias_cont_block = self
            .context
            .append_basic_block(helper_fn, &format!("{name_prefix}_alias_cont"));

        let i64_type = self.context.i64_type();
        let value_ptr_int = self
            .builder
            .build_ptr_to_int(
                value_ptr,
                i64_type,
                &format!("{name_prefix}_alias_value_ptr_int"),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let is_hit = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                value_ptr_int,
                i64_type.const_zero(),
                &format!("{name_prefix}_alias_found"),
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_hit, alias_hit_block, alias_miss_block)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        self.builder.position_at_end(alias_hit_block);
        let alias_value = self
            .builder
            .build_load(i32_type, value_ptr, &format!("{name_prefix}_alias_value"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        self.builder
            .build_unconditional_branch(alias_cont_block)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let alias_hit_end = self.current_insert_block("finish pid alias hit block")?;

        self.builder.position_at_end(alias_miss_block);
        self.builder
            .build_unconditional_branch(alias_cont_block)
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let alias_miss_end = self.current_insert_block("finish pid alias miss block")?;

        self.builder.position_at_end(alias_cont_block);
        let alias_phi = self
            .builder
            .build_phi(i32_type, &format!("{name_prefix}_alias_pid"))
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        alias_phi.add_incoming(&[
            (&alias_value, alias_hit_end),
            (&runtime_pid, alias_miss_end),
        ]);

        Ok(alias_phi.as_basic_value().into_int_value())
    }

    /// Get or create a static i8 buffer global of a given size, returning its ArrayType and pointer
    pub fn get_or_create_i8_buffer(
        &mut self,
        size: u32,
        name_prefix: &str,
    ) -> (
        inkwell::types::ArrayType<'ctx>,
        inkwell::values::PointerValue<'ctx>,
    ) {
        let array_ty = self.context.i8_type().array_type(size);
        let name = format!("{name_prefix}_{size}");
        let global_ptr = match self.module.get_global(&name) {
            Some(g) => g.as_pointer_value(),
            None => {
                let g = self
                    .module
                    .add_global(array_ty, Some(AddressSpace::default()), &name);
                g.set_initializer(&array_ty.const_zero());
                g.as_pointer_value()
            }
        };
        (array_ty, global_ptr)
    }

    /// Read a user C-string into a static buffer using bpf_probe_read_user_str.
    /// Returns (buffer_ptr, len_including_nul).
    pub(crate) fn read_user_cstr_into_buffer(
        &mut self,
        src_addr: RuntimeAddress<'ctx>,
        size: u32,
        name_prefix: &str,
    ) -> Result<(
        inkwell::values::PointerValue<'ctx>,
        inkwell::values::IntValue<'ctx>,
        inkwell::types::ArrayType<'ctx>,
    )> {
        let (arr_ty, buf_global) = self.get_or_create_i8_buffer(size, name_prefix);

        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        // Cast addresses to void pointers
        let dst_ptr = self
            .builder
            .build_bit_cast(buf_global, ptr_ty, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr.value, ptr_ty, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                src_ptr.into(),
                ptr_ty.const_null().into(),
                "cstr_src_or_null",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();

        // Helper signature: long fn(void *dst, u32 size, const void *src)
        let i64_ty = self.context.i64_type();
        let i32_ty = self.context.i32_type();
        let effective_size = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                i32_ty.const_int(size as u64, false).into(),
                i32_ty.const_zero().into(),
                "cstr_size_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let args: [inkwell::values::BasicValueEnum; 3] = [
            dst_ptr,
            effective_size.into(),
            inkwell::values::BasicValueEnum::PointerValue(src_ptr),
        ];
        let ret = self.create_bpf_helper_call(
            BPF_FUNC_probe_read_user_str as u64,
            &args,
            i64_ty.into(),
            "probe_read_user_str",
        )?;
        let len = if let inkwell::values::BasicValueEnum::IntValue(iv) = ret {
            iv
        } else {
            return Err(CodeGenError::LLVMError(
                "probe_read_user_str did not return integer".to_string(),
            ));
        };
        let len = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                len.into(),
                i64_ty.const_zero().into(),
                "cstr_len_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        Ok((buf_global, len, arr_ty))
    }

    /// Read raw user bytes into a static buffer using bpf_probe_read_user.
    /// Returns (buffer_ptr, status==0?).
    pub(crate) fn read_user_bytes_into_buffer(
        &mut self,
        src_addr: RuntimeAddress<'ctx>,
        size: u32,
        name_prefix: &str,
    ) -> Result<(
        inkwell::values::PointerValue<'ctx>,
        inkwell::values::IntValue<'ctx>,
        inkwell::types::ArrayType<'ctx>,
    )> {
        let (arr_ty, buf_global) = self.get_or_create_i8_buffer(size, name_prefix);
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let i32_ty = self.context.i32_type();
        let i64_ty = self.context.i64_type();
        // Cast addresses to void pointers
        let dst_ptr = self
            .builder
            .build_bit_cast(buf_global, ptr_ty, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_int_to_ptr(src_addr.value, ptr_ty, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                src_ptr.into(),
                ptr_ty.const_null().into(),
                "bytes_src_or_null",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();
        let effective_size = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                i32_ty.const_int(size as u64, false).into(),
                i32_ty.const_zero().into(),
                "bytes_size_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();

        let args: [inkwell::values::BasicValueEnum; 3] = [
            dst_ptr,
            effective_size.into(),
            inkwell::values::BasicValueEnum::PointerValue(src_ptr),
        ];
        // Helper returns long (0 on success, -errno on failure)
        let ret = self.create_bpf_helper_call(
            BPF_FUNC_probe_read_user as u64,
            &args,
            i64_ty.into(),
            "probe_read_user",
        )?;
        let status = if let inkwell::values::BasicValueEnum::IntValue(iv) = ret {
            iv
        } else {
            return Err(CodeGenError::LLVMError(
                "probe_read_user did not return integer".to_string(),
            ));
        };
        let status = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                src_addr.offsets_found,
                status.into(),
                i64_ty.const_int(u64::MAX, true).into(),
                "bytes_status_or_missing_offsets",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        Ok((buf_global, status, arr_ty))
    }
    /// Compute runtime address from link-time address using proc_module_offsets map
    /// section_type: 0=text, 1=rodata, 2=data, 3=bss; other values fallback to data
    pub fn generate_runtime_address_from_offsets(
        &mut self,
        link_addr: IntValue<'ctx>,
        section_type: u8,
        module_cookie: u64,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        const BPF_FUNC_GET_NS_CURRENT_PID_TGID: u64 = 120;
        const BPF_PIDNS_INFO_SIZE: u64 = 8; // struct { u32 pid; u32 tgid; }

        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Resolve map global pointer
        let map_global = self
            .module
            .get_global("proc_module_offsets")
            .ok_or_else(|| {
                CodeGenError::LLVMError("proc_module_offsets map not found".to_string())
            })?;
        let map_ptr = map_global.as_pointer_value();
        let map_ptr_cast = self
            .builder
            .build_bit_cast(map_ptr, ptr_type, "map_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Use per-invocation key buffer [4 x u32] pre-allocated in entry block
        // struct { u32 pid; u32 pad; u32 cookie_lo; u32 cookie_hi; }
        let i32_type = self.context.i32_type();
        let key_arr_ty = i32_type.array_type(4);
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        // Resolve the pid key used for proc_module_offsets lookup.
        // Host mode uses host TGID, while NamespaceTgid mode uses namespace TGID
        // from bpf_get_ns_current_pid_tgid().
        let helper_id = i64_type.const_int(BPF_FUNC_get_current_pid_tgid as u64, false);
        let helper_fn_type = i64_type.fn_type(&[], false);
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(helper_id, ptr_type, "get_pid_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let pid_tgid = self
            .builder
            .build_indirect_call(helper_fn_type, helper_fn_ptr, &[], "pid_tgid")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("get_current_pid_tgid returned void".to_string())
            })?;
        let host_tgid = if let BasicValueEnum::IntValue(v) = pid_tgid {
            // pid = upper 32 bits
            let shifted = self
                .builder
                .build_right_shift(v, i64_type.const_int(32, false), false, "pid_shift")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            self.builder
                .build_int_truncate(shifted, i32_type, "pid32")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        } else {
            return Err(CodeGenError::LLVMError(
                "pid_tgid is not IntValue".to_string(),
            ));
        };

        let ns_spec = self
            .compile_options
            .proc_offsets_pid_ns
            .and_then(|pid_ns| pid_ns.helper_dev_inode());

        let runtime_pid = if let Some((pid_ns_dev, pid_ns_inode)) = ns_spec {
            // Reuse key_alloca as temporary helper output buffer: [pid:u32, tgid:u32].
            self.builder
                .build_store(key_alloca, key_arr_ty.const_zero())
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let pidns_info_ptr = self
                .builder
                .build_bit_cast(key_alloca, ptr_type, "offset_pidns_info_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let helper_args = [
                i64_type.const_int(pid_ns_dev, false).into(),
                i64_type.const_int(pid_ns_inode, false).into(),
                pidns_info_ptr,
                i64_type.const_int(BPF_PIDNS_INFO_SIZE, false).into(),
            ];
            let helper_ret = self.create_bpf_helper_call(
                BPF_FUNC_GET_NS_CURRENT_PID_TGID,
                &helper_args,
                i64_type.into(),
                "offset_ns_pid_tgid_ret",
            )?;
            let helper_ret = match helper_ret {
                BasicValueEnum::IntValue(v) => v,
                _ => {
                    return Err(CodeGenError::LLVMError(
                        "bpf_get_ns_current_pid_tgid did not return integer".to_string(),
                    ));
                }
            };
            let helper_ok = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    helper_ret,
                    i64_type.const_zero(),
                    "offset_ns_helper_ok",
                )
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            // SAFETY: key_alloca temporarily holds the two-field pid namespace
            // helper result, so [0, 1] addresses the tgid field.
            let ns_tgid_ptr = unsafe {
                self.builder.build_gep(
                    key_arr_ty,
                    key_alloca,
                    &[i32_type.const_zero(), i32_type.const_int(1, false)],
                    "offset_ns_tgid_ptr",
                )
            }
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let ns_tgid = self
                .builder
                .build_load(i32_type, ns_tgid_ptr, "offset_ns_tgid")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                .into_int_value();
            // The proc_module_offsets map is populated from `/proc/<proc_pid>/maps`,
            // so its key must use the same PID namespace view GhostScope used for
            // those `/proc` reads. This is *not* necessarily the same namespace
            // used for `$pid`/`$tid` or NamespaceTgid filtering.
            self.builder
                .build_select(helper_ok, ns_tgid, host_tgid, "offset_pid_key")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                .into_int_value()
        } else {
            host_tgid
        };
        let pid = self.lookup_proc_pid_alias(runtime_pid, "offset_pid")?;

        let store_key_u32 = |offset: usize,
                             value: IntValue<'ctx>,
                             name: &str,
                             ctx: &mut EbpfContext<'ctx, 'dw>|
         -> Result<()> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: key_alloca is the ProcModuleKey stack slot. `offset`
            // comes from ghostscope_protocol::bpf_abi field offsets.
            let ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), key_alloca, &[offset_i32], name)
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            ctx.builder
                .build_store(ptr, value)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            Ok(())
        };

        store_key_u32(
            ghostscope_protocol::PROC_MODULE_KEY_PID_OFFSET,
            pid,
            "pm_key_pid_ptr",
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_KEY_PAD_OFFSET,
            self.context.i32_type().const_zero(),
            "pm_key_pad_ptr",
            self,
        )?;

        let cookie_lo = i32_type.const_int(module_cookie & 0xffff_ffff, false);
        let cookie_hi = i32_type.const_int(module_cookie >> 32, false);
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_KEY_COOKIE_LO_OFFSET,
            cookie_lo,
            "pm_key_cookie_lo_ptr",
            self,
        )?;
        store_key_u32(
            ghostscope_protocol::PROC_MODULE_KEY_COOKIE_HI_OFFSET,
            cookie_hi,
            "pm_key_cookie_hi_ptr",
            self,
        )?;

        // Call bpf_map_lookup_elem(map, &key)
        let lookup_id = i64_type.const_int(BPF_FUNC_map_lookup_elem as u64, false);
        let lookup_fn_type = ptr_type.fn_type(&[ptr_type.into(), ptr_type.into()], false);
        let lookup_fn_ptr = self
            .builder
            .build_int_to_ptr(lookup_id, ptr_type, "lookup_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        // Pass pointer to the beginning of the key buffer (void*)
        let key_arg = self
            .builder
            .build_bit_cast(key_alloca, ptr_type, "key_arg")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let args: Vec<BasicMetadataValueEnum> = vec![map_ptr_cast.into(), key_arg.into()];
        let val_ptr_any = self
            .builder
            .build_indirect_call(lookup_fn_type, lookup_fn_ptr, &args, "val_ptr_any")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .try_as_basic_value()
            .left()
            .ok_or_else(|| CodeGenError::LLVMError("map_lookup_elem returned void".to_string()))?;

        let null_ptr = ptr_type.const_null();
        let current_fn = self.current_function("generate module offset lookup")?;
        let found_block = self.context.append_basic_block(current_fn, "found_offsets");
        let miss_block = self.context.append_basic_block(current_fn, "miss_offsets");
        let cont_block = self.context.append_basic_block(current_fn, "cont_offsets");

        // Compare against NULL
        let val_ptr = if let BasicValueEnum::PointerValue(p) = val_ptr_any {
            p
        } else {
            null_ptr
        };
        let is_null = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                self.builder
                    .build_ptr_to_int(val_ptr, i64_type, "val_ptr_i64")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
                i64_type.const_zero(),
                "is_null_offsets",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_null, miss_block, found_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Found: load the requested field from ProcModuleOffsetsValue. The
        // byte offsets are shared through ghostscope_protocol::bpf_abi because
        // this map is an ABI between generated eBPF and userspace.
        self.builder.position_at_end(found_block);
        let load_field = |offset: usize,
                          ctx: &mut EbpfContext<'ctx, 'dw>,
                          base: PointerValue<'ctx>|
         -> Result<IntValue<'ctx>> {
            let offset_i32 = ctx.context.i32_type().const_int(offset as u64, false);
            // SAFETY: `base` points at ProcModuleOffsetsValue returned by
            // bpf_map_lookup_elem. `offset` is one of its u64 field offsets.
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i8_type(), base, &[offset_i32], "field_ptr")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            };
            let loaded = ctx
                .builder
                .build_load(ctx.context.i64_type(), field_ptr, "loaded_offset")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            if let BasicValueEnum::IntValue(iv) = loaded {
                Ok(iv)
            } else {
                Err(CodeGenError::LLVMError("offset load failed".to_string()))
            }
        };
        let st = section_type;
        let off_text = load_field(
            ghostscope_protocol::PROC_MODULE_OFFSETS_VALUE_TEXT_OFFSET,
            self,
            val_ptr,
        )?;
        let off_rodata = load_field(
            ghostscope_protocol::PROC_MODULE_OFFSETS_VALUE_RODATA_OFFSET,
            self,
            val_ptr,
        )?;
        let off_data = load_field(
            ghostscope_protocol::PROC_MODULE_OFFSETS_VALUE_DATA_OFFSET,
            self,
            val_ptr,
        )?;
        let off_bss = load_field(
            ghostscope_protocol::PROC_MODULE_OFFSETS_VALUE_BSS_OFFSET,
            self,
            val_ptr,
        )?;
        // Build a bottom-up cascade to preserve earlier choices:
        // tmp  = (section==data)   ? off_data   : off_bss
        // tmp2 = (section==rodata) ? off_rodata : tmp
        // off  = (section==text)   ? off_text  : tmp2
        let st_val = i32_type.const_int(st as u64, false);
        let eq_text = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                st_val,
                i32_type.const_int(0, false),
                "is_text",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let eq_ro = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                st_val,
                i32_type.const_int(1, false),
                "is_ro",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let eq_da = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                st_val,
                i32_type.const_int(2, false),
                "is_da",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let tmp_any = self
            .builder
            .build_select(eq_da, off_data, off_bss, "sel_data_bss")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let tmp = tmp_any.into_int_value();

        let tmp2_any = self
            .builder
            .build_select(eq_ro, off_rodata, tmp, "sel_rodata_else")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let tmp2 = tmp2_any.into_int_value();

        let off_final_any = self
            .builder
            .build_select(eq_text, off_text, tmp2, "sel_text_else")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let off_final = off_final_any.into_int_value();
        let rt_addr = self
            .builder
            .build_int_add(link_addr, off_final, "runtime_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Miss: return link_addr as-is (will likely fault and set ReadError)
        self.builder.position_at_end(miss_block);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Phi to merge address
        self.builder.position_at_end(cont_block);
        let phi = self
            .builder
            .build_phi(i64_type, "addr_phi")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        phi.add_incoming(&[(&rt_addr, found_block), (&link_addr, miss_block)]);
        let final_addr = phi.as_basic_value().into_int_value();

        // Phi to merge found-flag (i1): 1 on found, 0 on miss
        let i1_type = self.context.bool_type();
        let one = i1_type.const_int(1, false);
        let zero = i1_type.const_int(0, false);
        let flag_phi = self
            .builder
            .build_phi(i1_type, "off_found_phi")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        flag_phi.add_incoming(&[(&one, found_block), (&zero, miss_block)]);
        let found_flag = flag_phi.as_basic_value().into_int_value();

        Ok((final_addr, found_flag))
    }
    /// Load a register value from pt_regs
    pub fn load_register_value(
        &mut self,
        reg_num: u16,
        pt_regs_ptr: PointerValue<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Map DWARF register number to pt_regs offset
        let pt_regs_offset = self.dwarf_reg_to_pt_regs_offset(reg_num)?;

        // Calculate pointer to register in pt_regs structure
        let i64_type = self.context.i64_type();
        let offset_value = i64_type.const_int(pt_regs_offset as u64, false);

        // SAFETY: pt_regs_offset was converted to a u64 slot index by the platform
        // register mapping, so the generated access targets a pt_regs register slot.
        let reg_ptr = unsafe {
            self.builder
                .build_gep(
                    i64_type,
                    pt_regs_ptr,
                    &[offset_value],
                    &format!("reg_{reg_num}_ptr"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };

        // Load the register value
        let reg_value = self
            .builder
            .build_load(i64_type, reg_ptr, &format!("reg_{reg_num}"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        if let BasicValueEnum::IntValue(_) = reg_value {
            Ok(reg_value)
        } else {
            Err(CodeGenError::RegisterMappingError(format!(
                "Failed to load register {reg_num} as integer"
            )))
        }
    }

    fn probe_read_user_core(
        &mut self,
        address: RuntimeAddress<'ctx>,
        size: MemoryAccessSize,
        name_suffix: &str,
    ) -> Result<ProbeReadResult<'ctx>> {
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let offsets_found = address.offsets_found;
        let not_found = self
            .builder
            .build_not(offsets_found, "offsets_miss")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let result_size = size.bytes();
        let scratch_buffer = self.get_probe_read_scratch_buffer(result_size, name_suffix)?;
        let dst_ptr = self
            .builder
            .build_bit_cast(scratch_buffer, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let base_src_ptr = self
            .builder
            .build_int_to_ptr(address.value, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let null_ptr = ptr_type.const_null();
        let src_ptr = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                base_src_ptr.into(),
                null_ptr.into(),
                "src_or_null",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();

        let i32_type = self.context.i32_type();
        let helper_id = i64_type.const_int(BPF_FUNC_probe_read_user as u64, false);
        let helper_fn_type =
            i32_type.fn_type(&[ptr_type.into(), i32_type.into(), ptr_type.into()], false);
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(helper_id, ptr_type, "probe_read_user_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let size_val = i32_type.const_int(result_size as u64, false);
        let zero_i32 = i32_type.const_zero();
        let effective_size = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                size_val.into(),
                zero_i32.into(),
                "size_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let call_args: Vec<BasicMetadataValueEnum> =
            vec![dst_ptr.into(), effective_size.into(), src_ptr.into()];

        let call_site = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &call_args,
                "probe_read_result",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ret_iv = call_site.try_as_basic_value().left().ok_or_else(|| {
            CodeGenError::LLVMError("Expected integer return from helper".to_string())
        })?;
        let ret_i32 = ret_iv.into_int_value();
        let read_fail = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::NE,
                ret_i32,
                i32_type.const_zero(),
                "read_fail",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let combined_fail = self
            .builder
            .build_or(read_fail, not_found, "combined_fail")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let result_type: BasicTypeEnum = match size {
            MemoryAccessSize::U8 => self.context.i8_type().into(),
            MemoryAccessSize::U16 => self.context.i16_type().into(),
            MemoryAccessSize::U32 => self.context.i32_type().into(),
            MemoryAccessSize::U64 => self.context.i64_type().into(),
        };
        let typed_ptr = self
            .builder
            .build_bit_cast(
                scratch_buffer,
                self.context.ptr_type(AddressSpace::default()),
                "typed_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let loaded_value = self
            .builder
            .build_load(result_type, typed_ptr.into_pointer_value(), "loaded_value")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let loaded_i64 = if let BasicValueEnum::IntValue(int_val) = loaded_value {
            if int_val.get_type().get_bit_width() < 64 {
                self.builder
                    .build_int_z_extend(int_val, i64_type, "extended")
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            } else {
                int_val
            }
        } else {
            return Err(CodeGenError::MemoryAccessError(
                "Expected integer value from memory read".to_string(),
            ));
        };

        Ok(ProbeReadResult {
            loaded_i64,
            combined_fail,
            not_found,
        })
    }

    fn update_any_fail_flag(
        &mut self,
        combined_fail: IntValue<'ctx>,
        name_suffix: &str,
    ) -> Result<()> {
        let i8_type = self.context.i8_type();
        let fail_i8 = self
            .builder
            .build_int_z_extend(combined_fail, i8_type, &format!("fail_i8_{name_suffix}"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let fail_ptr = self.get_or_create_flag_global("_gs_any_fail");
        let cur_fail = self
            .builder
            .build_load(i8_type, fail_ptr, &format!("cur_fail_{name_suffix}"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let new_fail = self
            .builder
            .build_or(cur_fail, fail_i8, &format!("fail_or_miss_{name_suffix}"))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(fail_ptr, new_fail)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    pub(crate) fn store_variable_read_status(
        &mut self,
        status_ptr: PointerValue<'ctx>,
        combined_fail: IntValue<'ctx>,
        not_found: IntValue<'ctx>,
        name_suffix: &str,
    ) -> Result<()> {
        let cur_status = self
            .builder
            .build_load(
                self.context.i8_type(),
                status_ptr,
                &format!("cur_status_{name_suffix}"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let is_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                cur_status,
                self.context.i8_type().const_zero(),
                &format!("status_is_ok_{name_suffix}"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let desired_status = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                not_found,
                self.context
                    .i8_type()
                    .const_int(VariableStatus::OffsetsUnavailable as u64, false)
                    .into(),
                self.context
                    .i8_type()
                    .const_int(VariableStatus::ReadError as u64, false)
                    .into(),
                &format!("desired_read_status_{name_suffix}"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let should_store = self
            .builder
            .build_and(
                is_ok,
                combined_fail,
                &format!("should_store_read_status_{name_suffix}"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let new_status = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                should_store,
                desired_status,
                cur_status.into(),
                &format!("new_status_{name_suffix}"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(status_ptr, new_status)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    /// Generate memory read using bpf_probe_read_user
    pub(crate) fn generate_memory_read(
        &mut self,
        address: RuntimeAddress<'ctx>,
        size: MemoryAccessSize,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        let zero_const = self.context.i64_type().const_zero();
        let ProbeReadResult {
            loaded_i64,
            combined_fail,
            not_found,
        } = self.probe_read_user_core(address, size, "probe_read_user")?;

        if let Some(status_ptr) = status_ptr {
            self.store_variable_read_status(
                status_ptr,
                combined_fail,
                not_found,
                "probe_read_user",
            )?;
        }
        self.update_any_fail_flag(combined_fail, "probe_read_user")?;

        let zero_bv: BasicValueEnum = zero_const.into();
        let val_bv: BasicValueEnum = loaded_i64.into();
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                combined_fail,
                zero_bv,
                val_bv,
                "value_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
    }

    /// Generate a user memory read and return both the zero-on-failure value and failure flag.
    pub(crate) fn generate_memory_read_with_fail_flag(
        &mut self,
        address: RuntimeAddress<'ctx>,
        size: MemoryAccessSize,
        name_suffix: &str,
    ) -> Result<(BasicValueEnum<'ctx>, IntValue<'ctx>)> {
        let zero_const = self.context.i64_type().const_zero();
        let ProbeReadResult {
            loaded_i64,
            combined_fail,
            ..
        } = self.probe_read_user_core(address, size, name_suffix)?;

        self.update_any_fail_flag(combined_fail, name_suffix)?;

        let zero_bv: BasicValueEnum = zero_const.into();
        let val_bv: BasicValueEnum = loaded_i64.into();
        let value = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                combined_fail,
                zero_bv,
                val_bv,
                &format!("{name_suffix}_value_or_zero"),
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok((value, combined_fail))
    }

    /// Generate memory read with runtime status capture (for control-flow conditions).
    /// On helper failure, sets condition error code (if active) and returns zero value.
    pub(crate) fn generate_memory_read_with_status(
        &mut self,
        address: RuntimeAddress<'ctx>,
        size: MemoryAccessSize,
    ) -> Result<BasicValueEnum<'ctx>> {
        let zero_const = self.context.i64_type().const_zero();
        let ProbeReadResult {
            loaded_i64,
            combined_fail,
            ..
        } = self.probe_read_user_core(address, size, "probe_read_user_cf")?;

        let func = self.current_function("generate memory read with status")?;
        let set_block = self.context.append_basic_block(func, "set_cond_err");
        let cont_block = self.context.append_basic_block(func, "read_cont");
        self.builder
            .build_conditional_branch(combined_fail, set_block, cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(set_block);
        let _ = self.set_condition_error_if_unset(2u8);
        let _ = self.set_condition_error_addr_if_unset(address.value);
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder.position_at_end(cont_block);

        let zero_bv: BasicValueEnum = zero_const.into();
        let val_bv: BasicValueEnum = loaded_i64.into();
        let sel_bv = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(combined_fail, zero_bv, val_bv, "val_or_zero")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.update_any_fail_flag(combined_fail, "probe_read_user_cf")?;
        Ok(sel_bv)
    }
    /// Map DWARF register number to pt_regs offset (simplified)
    pub fn dwarf_reg_to_pt_regs_offset(&self, dwarf_reg: u16) -> Result<usize> {
        // Use platform-specific register mapping to get byte offset
        let byte_offset = register_mapping::dwarf_reg_to_pt_regs_byte_offset(dwarf_reg)
            .ok_or_else(|| match register_mapping::dwarf_reg_to_name(dwarf_reg) {
                Some(reg_name) if reg_name.starts_with("XMM") => {
                    CodeGenError::RegisterMappingError(format!(
                        "Unsupported DWARF register: {dwarf_reg} ({reg_name}) is a SIMD/FP register; uprobe pt_regs does not expose XMM register values, so optimized float by-value parameters are unavailable unless the compiler spills them to memory"
                    ))
                }
                Some(reg_name) => CodeGenError::RegisterMappingError(format!(
                    "Unsupported DWARF register: {dwarf_reg} ({reg_name})"
                )),
                None => CodeGenError::RegisterMappingError(format!(
                    "Unsupported DWARF register: {dwarf_reg}"
                )),
            })?;

        // Convert byte offset to u64 array index for pt_regs access
        let u64_index = byte_offset / core::mem::size_of::<u64>();
        Ok(u64_index)
    }

    /// Create eBPF helper call using the correct calling convention
    /// This creates an indirect call through the eBPF helper mechanism
    pub fn create_bpf_helper_call(
        &mut self,
        helper_id: u64,
        args: &[BasicValueEnum<'ctx>],
        return_type: BasicTypeEnum<'ctx>,
        call_name: &str,
    ) -> Result<BasicValueEnum<'ctx>> {
        use inkwell::types::BasicMetadataTypeEnum;

        // Create function type for the helper
        let arg_types: Vec<BasicMetadataTypeEnum> =
            args.iter().map(|arg| arg.get_type().into()).collect();
        let fn_type = return_type.fn_type(&arg_types, false);

        // Convert helper ID to function pointer for indirect call
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        let helper_id_val = i64_type.const_int(helper_id, false);
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(helper_id_val, ptr_type, "helper_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Convert args to metadata values
        let metadata_args: Vec<BasicMetadataValueEnum> =
            args.iter().map(|arg| (*arg).into()).collect();

        // Make the indirect call
        let call_result = self
            .builder
            .build_indirect_call(fn_type, helper_fn_ptr, &metadata_args, call_name)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Convert CallSiteValue to BasicValueEnum
        Ok(call_result.try_as_basic_value().left().unwrap_or_else(|| {
            // If it's void, return a null value of the expected type
            return_type.const_zero()
        }))
    }

    /// Get current timestamp using bpf_ktime_get_ns
    pub fn get_current_timestamp(&mut self) -> Result<IntValue<'ctx>> {
        let i64_type = self.context.i64_type();

        // Call bpf_ktime_get_ns() - takes no arguments
        let timestamp = self.create_bpf_helper_call(
            BPF_FUNC_ktime_get_ns as u64,
            &[],
            i64_type.into(),
            "timestamp",
        )?;

        if let BasicValueEnum::IntValue(int_val) = timestamp {
            Ok(int_val)
        } else {
            Err(CodeGenError::LLVMError(
                "bpf_ktime_get_ns did not return integer".to_string(),
            ))
        }
    }

    /// Get current PID/TID using bpf_get_current_pid_tgid
    pub fn get_current_pid_tgid(&mut self) -> Result<IntValue<'ctx>> {
        let i64_type = self.context.i64_type();

        // Call bpf_get_current_pid_tgid() - returns combined PID/TID
        let pid_tgid = self.create_bpf_helper_call(
            BPF_FUNC_get_current_pid_tgid as u64,
            &[],
            i64_type.into(),
            "pid_tgid",
        )?;

        if let BasicValueEnum::IntValue(int_val) = pid_tgid {
            Ok(int_val)
        } else {
            Err(CodeGenError::LLVMError(
                "bpf_get_current_pid_tgid did not return integer".to_string(),
            ))
        }
    }

    pub(crate) fn generate_static_tls_address(
        &mut self,
        tls_offset: RuntimeAddress<'ctx>,
        module_hint: Option<&str>,
    ) -> Result<RuntimeAddress<'ctx>> {
        let module_path = match module_hint {
            Some(module_path) => module_path.to_string(),
            None => self.get_compile_time_context()?.module_path.clone(),
        };
        if ghostscope_process::is_shared_object(std::path::Path::new(&module_path)) {
            return Err(CodeGenError::NotImplemented(format!(
                "dynamic/shared-library TLS is not supported yet for DW_OP_form_tls_address in {module_path}; only x86_64 executable static TLS is currently supported"
            )));
        }
        let tls_bias =
            ghostscope_platform::static_tls_bias_for_elf(std::path::Path::new(&module_path))
                .map_err(|err| {
                    CodeGenError::LLVMError(format!(
                        "failed to read static TLS layout for {module_path}: {err}"
                    ))
                })?
                .ok_or_else(|| {
                    CodeGenError::LLVMError(format!(
                        "module {module_path} does not contain a PT_TLS segment"
                    ))
                })?;
        let fsbase_offset = ghostscope_platform::current_task_fsbase_offset().map_err(|err| {
            CodeGenError::LLVMError(format!(
                "failed to resolve task_struct.thread.fsbase offset from kernel BTF: {err}"
            ))
        })?;

        let i64_type = self.context.i64_type();
        let i32_type = self.context.i32_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());
        let task_ptr_value = self.create_bpf_helper_call(
            BPF_FUNC_get_current_task as u64,
            &[],
            i64_type.into(),
            "current_task",
        )?;
        let BasicValueEnum::IntValue(task_ptr_int) = task_ptr_value else {
            return Err(CodeGenError::LLVMError(
                "bpf_get_current_task did not return integer".to_string(),
            ));
        };
        let fsbase_field_addr = self
            .builder
            .build_int_add(
                task_ptr_int,
                i64_type.const_int(fsbase_offset, false),
                "task_fsbase_addr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_int_to_ptr(fsbase_field_addr, ptr_type, "task_fsbase_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let scratch_buffer = self.get_or_create_tls_scratch_buffer()?;
        let dst_ptr = self
            .builder
            .build_bit_cast(scratch_buffer, ptr_type, "tls_fsbase_dst")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let helper_id = i64_type.const_int(BPF_FUNC_probe_read_kernel as u64, false);
        let helper_fn_type =
            i32_type.fn_type(&[ptr_type.into(), i32_type.into(), ptr_type.into()], false);
        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(helper_id, ptr_type, "probe_read_kernel_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let call_args: Vec<BasicMetadataValueEnum> = vec![
            dst_ptr.into(),
            i32_type.const_int(8, false).into(),
            src_ptr.into(),
        ];
        let call_site = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &call_args,
                "probe_read_kernel_result",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let ret_i32 = call_site
            .try_as_basic_value()
            .left()
            .ok_or_else(|| {
                CodeGenError::LLVMError("Expected integer return from helper".to_string())
            })?
            .into_int_value();
        let read_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                ret_i32,
                i32_type.const_zero(),
                "tls_fsbase_read_ok",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let read_fail = self
            .builder
            .build_not(read_ok, "tls_fsbase_read_fail")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.update_any_fail_flag(read_fail, "tls_fsbase")?;

        let typed_ptr = self
            .builder
            .build_bit_cast(scratch_buffer, ptr_type, "tls_fsbase_typed_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_pointer_value();
        let fsbase = self
            .builder
            .build_load(i64_type, typed_ptr, "tls_fsbase")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let tls_base = self
            .builder
            .build_int_add(
                fsbase,
                i64_type.const_int(tls_bias as u64, true),
                "tls_static_base",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let tls_addr = self
            .builder
            .build_int_add(tls_base, tls_offset.value, "tls_addr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let offsets_found = self
            .builder
            .build_and(tls_offset.offsets_found, read_ok, "tls_addr_available")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let value = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                offsets_found,
                tls_addr.into(),
                i64_type.const_zero().into(),
                "tls_addr_or_zero",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();

        Ok(RuntimeAddress::with_offsets_found(value, offsets_found))
    }

    /// Create event output using either RingBuf or PerfEventArray based on compile options
    /// This is the unified interface that should be used for all event output
    pub fn create_event_output(&mut self, data: PointerValue<'ctx>, size: u64) -> Result<()> {
        match self.compile_options.event_map_type {
            crate::EventMapType::RingBuf => self.create_ringbuf_output_internal(data, size),
            crate::EventMapType::PerfEventArray => {
                self.create_perf_event_output_internal(data, size)
            }
        }
    }

    fn increment_event_loss_counter(&mut self) -> Result<()> {
        let i64_type = self.context.i64_type();

        let counter_ptr = self.lookup_percpu_value_ptr("event_loss_counters", 0)?;
        let current_fn = self
            .builder
            .get_insert_block()
            .and_then(|block| block.get_parent())
            .ok_or_else(|| {
                CodeGenError::LLVMError(
                    "Cannot increment event loss counter outside a function".to_string(),
                )
            })?;
        let counter_hit_block = self
            .context
            .append_basic_block(current_fn, "event_loss_counter_hit");
        let counter_done_block = self
            .context
            .append_basic_block(current_fn, "event_loss_counter_done");
        let is_null = self
            .builder
            .build_is_null(counter_ptr, "event_loss_counter_is_null")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_conditional_branch(is_null, counter_done_block, counter_hit_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(counter_hit_block);
        let current = self
            .builder
            .build_load(i64_type, counter_ptr, "event_loss_counter")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
            .into_int_value();
        let next = self
            .builder
            .build_int_add(
                current,
                i64_type.const_int(1, false),
                "event_loss_counter_next",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(counter_ptr, next)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_unconditional_branch(counter_done_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(counter_done_block);
        Ok(())
    }

    fn record_event_output_loss_on_error(&mut self, output_result: IntValue<'ctx>) -> Result<()> {
        let i64_type = self.context.i64_type();
        let current_fn = self
            .builder
            .get_insert_block()
            .and_then(|block| block.get_parent())
            .ok_or_else(|| {
                CodeGenError::LLVMError(
                    "Cannot record event output loss outside a function".to_string(),
                )
            })?;
        let output_failed = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::SLT,
                output_result,
                i64_type.const_zero(),
                "event_output_failed",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let loss_block = self
            .context
            .append_basic_block(current_fn, "event_output_loss");
        let cont_block = self
            .context
            .append_basic_block(current_fn, "event_output_after_loss_check");
        self.builder
            .build_conditional_branch(output_failed, loss_block, cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(loss_block);
        self.increment_event_loss_counter()?;
        self.builder
            .build_unconditional_branch(cont_block)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        self.builder.position_at_end(cont_block);
        Ok(())
    }

    /// Create ringbuf output using bpf_ringbuf_output (internal implementation)
    fn create_ringbuf_output_internal(
        &mut self,
        data: PointerValue<'ctx>,
        size: u64,
    ) -> Result<()> {
        let i64_type = self.context.i64_type();

        // Get ringbuf map
        let ringbuf_global = self
            .map_manager
            .get_ringbuf_map(&self.module, "ringbuf")
            .map_err(|e| {
                CodeGenError::MemoryAccessError(format!("Failed to get ringbuf map: {e}"))
            })?;

        // Arguments: map, data, size, flags
        let args = [
            ringbuf_global.into(),
            data.into(),
            i64_type.const_int(size, false).into(),
            i64_type.const_zero().into(), // flags = 0
        ];

        let result = self.create_bpf_helper_call(
            BPF_FUNC_ringbuf_output as u64,
            &args,
            i64_type.into(),
            "ringbuf_output",
        )?;
        let BasicValueEnum::IntValue(result) = result else {
            return Err(CodeGenError::LLVMError(
                "bpf_ringbuf_output did not return integer".to_string(),
            ));
        };
        self.record_event_output_loss_on_error(result)?;

        Ok(())
    }

    /// Create ringbuf output with dynamic size (IntValue)
    pub fn create_ringbuf_output_dynamic(
        &mut self,
        data: PointerValue<'ctx>,
        size: IntValue<'ctx>,
    ) -> Result<()> {
        let i64_type = self.context.i64_type();

        // Get ringbuf map
        let ringbuf_global = self
            .map_manager
            .get_ringbuf_map(&self.module, "ringbuf")
            .map_err(|e| {
                CodeGenError::MemoryAccessError(format!("Failed to get ringbuf map: {e}"))
            })?;

        // Arguments: map, data, size (dynamic), flags
        let args = [
            ringbuf_global.into(),
            data.into(),
            size.into(),
            i64_type.const_zero().into(), // flags = 0
        ];

        let result = self.create_bpf_helper_call(
            BPF_FUNC_ringbuf_output as u64,
            &args,
            i64_type.into(),
            "ringbuf_output",
        )?;
        let BasicValueEnum::IntValue(result) = result else {
            return Err(CodeGenError::LLVMError(
                "bpf_ringbuf_output did not return integer".to_string(),
            ));
        };
        self.record_event_output_loss_on_error(result)?;

        Ok(())
    }

    /// Lookup per-CPU map value pointer for a given map name and u32 key constant
    pub fn lookup_percpu_value_ptr(
        &mut self,
        map_name: &str,
        key_const: u32,
    ) -> Result<PointerValue<'ctx>> {
        let ptr_ty = self.context.ptr_type(AddressSpace::default());
        let i32_ty = self.context.i32_type();
        let map_global = self
            .map_manager
            .get_map(&self.module, map_name)
            .map_err(|e| CodeGenError::LLVMError(format!("Map not found {map_name}: {e}")))?;
        let map_ptr = self
            .builder
            .build_bit_cast(map_global, ptr_ty, "map_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Prepare stack key in the entry-block alloca (reuse pm_key's first i32 slot)
        let key_arr_ty = i32_ty.array_type(4);
        let key_alloca = self.pm_key_alloca.ok_or_else(|| {
            CodeGenError::LLVMError("pm_key not allocated in entry block".to_string())
        })?;
        let zero = i32_ty.const_zero();
        // SAFETY: key_alloca is the [4 x i32] pm_key stack slot and [0, 0]
        // addresses the first key element.
        let base_i32_ptr = unsafe {
            self.builder
                .build_gep(key_arr_ty, key_alloca, &[zero, zero], "percpu_key_i32_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(base_i32_ptr, i32_ty.const_int(key_const as u64, false))
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let key_ptr = self
            .builder
            .build_bit_cast(base_i32_ptr, ptr_ty, "key_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // long bpf_map_lookup_elem(void *map, const void *key) -> void *
        let ret = self.create_bpf_helper_call(
            BPF_FUNC_map_lookup_elem as u64,
            &[map_ptr, key_ptr],
            ptr_ty.into(),
            "map_lookup_elem",
        )?;
        let val_ptr = if let BasicValueEnum::PointerValue(p) = ret {
            p
        } else {
            return Err(CodeGenError::LLVMError(
                "map_lookup_elem did not return pointer".to_string(),
            ));
        };
        Ok(val_ptr)
    }

    /// Create perf event output using bpf_perf_event_output (internal implementation)
    fn create_perf_event_output_internal(
        &mut self,
        data: PointerValue<'ctx>,
        size: u64,
    ) -> Result<()> {
        let size_val = self.context.i64_type().const_int(size, false);
        self.create_perf_event_output_dynamic(data, size_val)
    }

    /// Create perf event output with dynamic size (IntValue)
    pub fn create_perf_event_output_dynamic(
        &mut self,
        data: PointerValue<'ctx>,
        size: IntValue<'ctx>,
    ) -> Result<()> {
        let i64_type = self.context.i64_type();

        // Get the current pt_regs pointer (first argument to eBPF program)
        let ctx_param = self
            .builder
            .get_insert_block()
            .and_then(|bb| bb.get_parent())
            .and_then(|func| func.get_first_param())
            .ok_or_else(|| {
                CodeGenError::LLVMError("Failed to get context parameter".to_string())
            })?;

        // Get perf event array map
        let events_global = self
            .map_manager
            .get_perf_map(&self.module, "events")
            .map_err(|e| {
                CodeGenError::MemoryAccessError(format!("Failed to get perf event map: {e}"))
            })?;

        // Arguments: ctx, map, flags, data, size
        // flags = BPF_F_CURRENT_CPU (0xFFFFFFFF) means use current CPU
        let args = [
            ctx_param,
            events_global.into(),
            i64_type.const_int(0xFFFFFFFF_u64, false).into(), // BPF_F_CURRENT_CPU
            data.into(),
            size.into(),
        ];

        let result = self.create_bpf_helper_call(
            BPF_FUNC_perf_event_output as u64,
            &args,
            i64_type.into(),
            "perf_event_output",
        )?;
        let BasicValueEnum::IntValue(result) = result else {
            return Err(CodeGenError::LLVMError(
                "bpf_perf_event_output did not return integer".to_string(),
            ));
        };
        self.record_event_output_loss_on_error(result)?;

        Ok(())
    }
}

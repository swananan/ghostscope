//! eBPF helper function management
//!
//! This module handles eBPF helper function calls, register mapping, and pt_regs
//! access for different target architectures.

use super::context::{CodeGenError, EbpfContext, Result};
use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_ktime_get_ns, BPF_FUNC_map_lookup_elem,
    BPF_FUNC_probe_read_user, BPF_FUNC_ringbuf_output,
};
use ghostscope_dwarf::MemoryAccessSize;
use ghostscope_platform::register_mapping;
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::values::{BasicMetadataValueEnum, BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;
use tracing::info;

impl<'ctx> EbpfContext<'ctx> {
    /// Compute runtime address from link-time address using proc_module_offsets map
    /// section_type: 0=text, 1=rodata, 2=data, 3=bss; other values fallback to data
    pub fn generate_runtime_address_from_offsets(
        &mut self,
        link_addr: IntValue<'ctx>,
        section_type: u8,
        module_cookie: u64,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
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
        // Get i32* to the first element (&key[0])
        let zero = i32_type.const_zero();
        let base_i32_ptr = unsafe {
            self.builder
                .build_gep(key_arr_ty, key_alloca, &[zero, zero], "pm_key_i32_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };

        // Write pid (u32)
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
        let pid = if let BasicValueEnum::IntValue(v) = pid_tgid {
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

        // Store pid at key[0]
        self.builder
            .build_store(base_i32_ptr, pid)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Zero padding at key[1] for deterministic key bytes
        let idx1 = i32_type.const_int(1, false);
        let pad_ptr = unsafe {
            self.builder
                .build_gep(self.context.i32_type(), base_i32_ptr, &[idx1], "pad_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(pad_ptr, self.context.i32_type().const_zero())
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Store cookie_lo at key[2] and cookie_hi at key[3] (key[1] is padding for 8-byte alignment)
        let cookie_lo = i32_type.const_int(module_cookie & 0xffff_ffff, false);
        let cookie_hi = i32_type.const_int(module_cookie >> 32, false);
        let idx2 = i32_type.const_int(2, false);
        let idx3 = i32_type.const_int(3, false);
        // key[1] left as padding = 0 by default
        let cookie_lo_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i32_type(),
                    base_i32_ptr,
                    &[idx2],
                    "cookie_lo_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        let cookie_hi_ptr = unsafe {
            self.builder
                .build_gep(
                    self.context.i32_type(),
                    base_i32_ptr,
                    &[idx3],
                    "cookie_hi_ptr",
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };
        self.builder
            .build_store(cookie_lo_ptr, cookie_lo)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(cookie_hi_ptr, cookie_hi)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

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
        let found_block = self.context.append_basic_block(
            self.builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap(),
            "found_offsets",
        );
        let miss_block = self.context.append_basic_block(
            self.builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap(),
            "miss_offsets",
        );
        let cont_block = self.context.append_basic_block(
            self.builder
                .get_insert_block()
                .unwrap()
                .get_parent()
                .unwrap(),
            "cont_offsets",
        );

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

        // Found: load appropriate offset based on section_type
        self.builder.position_at_end(found_block);
        // Cast value pointer (void*) to i64* for loading 64-bit offsets
        // Use opaque pointer type (LLVM15+): model as generic pointer
        let i64_ptr_ty = self.context.ptr_type(AddressSpace::default());
        let val_u64_ptr = self
            .builder
            .build_pointer_cast(val_ptr, i64_ptr_ty, "val_u64_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let load_field = |idx: u64,
                          ctx: &mut EbpfContext<'ctx>,
                          base: PointerValue<'ctx>|
         -> Result<IntValue<'ctx>> {
            // GEP in i64 element space
            let idx_i32 = ctx.context.i32_type().const_int(idx, false);
            let field_ptr = unsafe {
                ctx.builder
                    .build_gep(ctx.context.i64_type(), base, &[idx_i32], "field_ptr_i64")
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
        let off_text = load_field(0, self, val_u64_ptr)?;
        let off_rodata = load_field(1, self, val_u64_ptr)?;
        let off_data = load_field(2, self, val_u64_ptr)?;
        let off_bss = load_field(3, self, val_u64_ptr)?;
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
        // Check cache first
        if let Some(cached_value) = self.register_cache.get(&reg_num) {
            return Ok((*cached_value).into());
        }

        // Map DWARF register number to pt_regs offset
        let pt_regs_offset = self.dwarf_reg_to_pt_regs_offset(reg_num)?;

        // Calculate pointer to register in pt_regs structure
        let i64_type = self.context.i64_type();
        let offset_value = i64_type.const_int(pt_regs_offset as u64, false);

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

        if let BasicValueEnum::IntValue(int_val) = reg_value {
            // Cache the value
            self.register_cache.insert(reg_num, int_val);
            Ok(reg_value)
        } else {
            Err(CodeGenError::RegisterMappingError(format!(
                "Failed to load register {} as integer",
                reg_num
            )))
        }
    }

    /// Generate memory read using bpf_probe_read_user
    pub fn generate_memory_read(
        &mut self,
        addr: IntValue<'ctx>,
        size: MemoryAccessSize,
    ) -> Result<BasicValueEnum<'ctx>> {
        let i64_type = self.context.i64_type();
        let ptr_type = self.context.ptr_type(AddressSpace::default());

        // Use static global buffer instead of dynamic allocation (eBPF doesn't support alloca)
        let result_size = size.bytes();

        // Get or create a static global buffer for temporary reads
        let buffer_name = format!("_temp_read_buffer_{result_size}");
        let global_buffer = match self.module.get_global(&buffer_name) {
            Some(existing) => existing.as_pointer_value(),
            None => {
                // Create new global buffer
                let array_type = self.context.i8_type().array_type(result_size as u32);
                let global =
                    self.module
                        .add_global(array_type, Some(AddressSpace::default()), &buffer_name);
                global.set_initializer(&array_type.const_zero());
                global.as_pointer_value()
            }
        };

        let stack_ptr = global_buffer;

        // Cast addresses to void pointers
        let dst_ptr = self
            .builder
            .build_bit_cast(stack_ptr, ptr_type, "dst_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let src_ptr = self
            .builder
            .build_int_to_ptr(addr, ptr_type, "src_ptr")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Use eBPF helper calling convention - convert helper ID to function pointer
        let i32_type = self.context.i32_type();
        let helper_id = i64_type.const_int(BPF_FUNC_probe_read_user as u64, false);
        info!(
            "Using eBPF helper function BPF_FUNC_probe_read_user with ID: {}",
            BPF_FUNC_probe_read_user
        );

        // Log all helper function IDs for debugging
        info!("Helper function IDs: probe_read_user={}, ringbuf_output={}, get_current_pid_tgid={}, ktime_get_ns={}",
              BPF_FUNC_probe_read_user, BPF_FUNC_ringbuf_output, BPF_FUNC_get_current_pid_tgid, BPF_FUNC_ktime_get_ns);
        let helper_fn_type = i32_type.fn_type(
            &[
                ptr_type.into(), // dst
                i32_type.into(), // size (note: i32, not i64)
                ptr_type.into(), // src
            ],
            false,
        );

        let helper_fn_ptr = self
            .builder
            .build_int_to_ptr(helper_id, ptr_type, "probe_read_user_fn")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        let size_val = i32_type.const_int(result_size as u64, false);

        // Convert args to BasicMetadataValueEnum for indirect call
        let call_args: Vec<BasicMetadataValueEnum> =
            vec![dst_ptr.into(), size_val.into(), src_ptr.into()];

        let _call_result = self
            .builder
            .build_indirect_call(
                helper_fn_type,
                helper_fn_ptr,
                &call_args,
                "probe_read_result",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        // Load the result based on size
        let result_type: BasicTypeEnum = match size {
            MemoryAccessSize::U8 => self.context.i8_type().into(),
            MemoryAccessSize::U16 => self.context.i16_type().into(),
            MemoryAccessSize::U32 => self.context.i32_type().into(),
            MemoryAccessSize::U64 => self.context.i64_type().into(),
        };

        let typed_ptr = self
            .builder
            .build_bit_cast(
                stack_ptr,
                self.context.ptr_type(AddressSpace::default()),
                "typed_ptr",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

        if let BasicValueEnum::PointerValue(ptr) = typed_ptr {
            let loaded_value = self
                .builder
                .build_load(result_type, ptr, "loaded_value")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            // Extend to i64 if needed
            if let BasicValueEnum::IntValue(int_val) = loaded_value {
                if int_val.get_type().get_bit_width() < 64 {
                    let extended = self
                        .builder
                        .build_int_z_extend(int_val, i64_type, "extended")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    Ok(extended.into())
                } else {
                    Ok(loaded_value)
                }
            } else {
                Ok(loaded_value)
            }
        } else {
            Err(CodeGenError::MemoryAccessError(
                "Failed to cast result pointer".to_string(),
            ))
        }
    }

    /// Map DWARF register number to pt_regs offset (simplified)
    pub fn dwarf_reg_to_pt_regs_offset(&self, dwarf_reg: u16) -> Result<usize> {
        // Use platform-specific register mapping to get byte offset
        let byte_offset = register_mapping::dwarf_reg_to_pt_regs_byte_offset(dwarf_reg)
            .ok_or_else(|| {
                CodeGenError::RegisterMappingError(format!(
                    "Unsupported DWARF register: {}",
                    dwarf_reg
                ))
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

    /// Create ringbuf output using bpf_ringbuf_output
    pub fn create_ringbuf_output(&mut self, data: PointerValue<'ctx>, size: u64) -> Result<()> {
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

        let _result = self.create_bpf_helper_call(
            BPF_FUNC_ringbuf_output as u64,
            &args,
            i64_type.into(),
            "ringbuf_output",
        )?;

        Ok(())
    }
}

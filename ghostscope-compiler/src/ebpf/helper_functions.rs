//! eBPF helper function management
//!
//! This module handles eBPF helper function calls, register mapping, and pt_regs
//! access for different target architectures.

use super::context::{CodeGenError, EbpfContext, Result};
use aya_ebpf_bindings::bindings::bpf_func_id::{
    BPF_FUNC_get_current_pid_tgid, BPF_FUNC_ktime_get_ns, BPF_FUNC_probe_read_user,
    BPF_FUNC_ringbuf_output, BPF_FUNC_trace_printk,
};
use ghostscope_dwarf::MemoryAccessSize;
use ghostscope_platform::register_mapping;
use inkwell::types::{BasicType, BasicTypeEnum};
use inkwell::values::{BasicMetadataValueEnum, BasicValue, BasicValueEnum, IntValue, PointerValue};
use inkwell::{AddressSpace, IntPredicate};
use std::collections::HashMap;
use tracing::{debug, info, warn};

impl<'ctx> EbpfContext<'ctx> {
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
                    &format!("reg_{}_ptr", reg_num),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
        };

        // Load the register value
        let reg_value = self
            .builder
            .build_load(i64_type, reg_ptr, &format!("reg_{}", reg_num))
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

        // Allocate stack space for the result
        let result_size = size.bytes();
        let array_type = self.context.i8_type().array_type(result_size as u32);
        let stack_ptr = self
            .builder
            .build_alloca(array_type, "read_buffer")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

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
                result_type.ptr_type(AddressSpace::default()),
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
                CodeGenError::MemoryAccessError(format!("Failed to get ringbuf map: {}", e))
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

//! DWARF debugging information bridge
//!
//! This module handles integration with DWARF debug information for
//! variable type resolution and evaluation result processing.

use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_dwarf::{
    ComputeStep, DirectValueResult, EvaluationResult, LocationResult, MemoryAccessSize, TypeInfo,
    VariableWithEvaluation,
};
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use tracing::{debug, warn};

impl<'ctx> EbpfContext<'ctx> {
    /// Convert EvaluationResult to LLVM value
    pub fn evaluate_result_to_llvm_value(
        &mut self,
        evaluation_result: &EvaluationResult,
        dwarf_type: &TypeInfo,
        var_name: &str,
        pc_address: u64,
    ) -> Result<BasicValueEnum<'ctx>> {
        debug!(
            "Converting EvaluationResult to LLVM value for variable: {}",
            var_name
        );
        debug!("Evaluation context PC address: 0x{:x}", pc_address);

        // Get pt_regs parameter
        let pt_regs_ptr = self.get_pt_regs_parameter()?;

        match evaluation_result {
            EvaluationResult::DirectValue(direct) => {
                self.generate_direct_value(direct, pt_regs_ptr)
            }
            EvaluationResult::MemoryLocation(location) => {
                self.generate_memory_location(location, pt_regs_ptr, dwarf_type)
            }
            EvaluationResult::Optimized => {
                debug!("Variable {} is optimized out", var_name);
                // Return a placeholder value for optimized out variables
                Ok(self.context.i64_type().const_zero().into())
            }
            EvaluationResult::Composite(members) => {
                debug!(
                    "Variable {} is composite with {} members",
                    var_name,
                    members.len()
                );
                // For now, just return the first member if available
                if let Some(first_member) = members.first() {
                    self.evaluate_result_to_llvm_value(
                        &first_member.location,
                        dwarf_type,
                        var_name,
                        pc_address,
                    )
                } else {
                    Ok(self.context.i64_type().const_zero().into())
                }
            }
        }
    }

    /// Convert an EvaluationResult into a concrete address (IntValue) when possible
    /// Returns error for unsupported cases (e.g., direct values without an address)
    pub fn evaluation_result_to_address(
        &mut self,
        evaluation_result: &EvaluationResult,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<IntValue<'ctx>> {
        self.evaluation_result_to_address_with_hint(evaluation_result, status_ptr, None)
    }

    /// Variant that allows passing an explicit module hint for offsets lookup
    pub fn evaluation_result_to_address_with_hint(
        &mut self,
        evaluation_result: &EvaluationResult,
        status_ptr: Option<PointerValue<'ctx>>,
        module_hint: Option<&str>,
    ) -> Result<IntValue<'ctx>> {
        let pt_regs_ptr = self.get_pt_regs_parameter()?;
        match evaluation_result {
            EvaluationResult::MemoryLocation(LocationResult::Address(addr)) => {
                // Link-time address (global/static): attempt to apply ASLR offsets if possible
                if let Some(analyzer_ptr) = self.process_analyzer {
                    let analyzer = unsafe { &mut *analyzer_ptr };
                    let ctx = self.get_compile_time_context()?;
                    let module_for_offsets = module_hint
                        .map(|s| s.to_string())
                        .or_else(|| self.current_resolved_var_module_path.clone())
                        .unwrap_or_else(|| ctx.module_path.clone());
                    if let Ok(offsets) = analyzer.compute_section_offsets() {
                        if let Some((_, cookie, sect_offs)) = offsets
                            .iter()
                            .find(|(p, _, _)| p.to_string_lossy() == module_for_offsets)
                        {
                            let st = analyzer
                                .classify_section_for_address(&module_for_offsets, *addr)
                                .unwrap_or(ghostscope_dwarf::core::SectionType::Data);
                            let st_code: u8 = match st {
                                ghostscope_dwarf::core::SectionType::Text => 0,
                                ghostscope_dwarf::core::SectionType::Rodata => 1,
                                ghostscope_dwarf::core::SectionType::Data => 2,
                                ghostscope_dwarf::core::SectionType::Bss => 3,
                                _ => 2,
                            };
                            let link_val = self.context.i64_type().const_int(*addr, false);
                            let sect_bias = match st {
                                ghostscope_dwarf::core::SectionType::Text => sect_offs.text,
                                ghostscope_dwarf::core::SectionType::Rodata => sect_offs.rodata,
                                ghostscope_dwarf::core::SectionType::Data => sect_offs.data,
                                ghostscope_dwarf::core::SectionType::Bss => sect_offs.bss,
                                _ => 0,
                            };
                            if sect_bias == 0 {
                                self.current_resolved_var_module_path = None;
                                return Ok(link_val);
                            }
                            let (rt_addr, found_flag) = self
                                .generate_runtime_address_from_offsets(
                                    link_val, st_code, *cookie,
                                )?;
                            // If offsets miss and we can record status, set OffsetsUnavailable preserving prior non-OK
                            if let Some(sp) = status_ptr {
                                let is_miss = self
                                    .builder
                                    .build_int_compare(
                                        inkwell::IntPredicate::EQ,
                                        found_flag,
                                        self.context.bool_type().const_zero(),
                                        "is_off_miss",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let cur_status = self
                                    .builder
                                    .build_load(self.context.i8_type(), sp, "cur_status")
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let is_ok = self
                                    .builder
                                    .build_int_compare(
                                        inkwell::IntPredicate::EQ,
                                        cur_status.into_int_value(),
                                        self.context.i8_type().const_zero(),
                                        "status_is_ok",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let should_store = self
                                    .builder
                                    .build_and(is_miss, is_ok, "store_offsets_unavail")
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                let new_status = self
                                    .builder
                                    .build_select(
                                        should_store,
                                        self.context
                                            .i8_type()
                                            .const_int(ghostscope_protocol::VariableStatus::OffsetsUnavailable as u64, false)
                                            .into(),
                                        cur_status,
                                        "new_status",
                                    )
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                self.builder
                                    .build_store(sp, new_status)
                                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            }
                            self.current_resolved_var_module_path = None;
                            return Ok(rt_addr);
                        }
                    }
                }
                // Fallback: return link-time address
                self.current_resolved_var_module_path = None;
                Ok(self.context.i64_type().const_int(*addr, false))
            }
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                ..
            }) => {
                let reg_val = self.load_register_value(*register, pt_regs_ptr)?;
                if let BasicValueEnum::IntValue(reg_i) = reg_val {
                    if let Some(ofs) = offset {
                        let ofs_val = self.context.i64_type().const_int(*ofs as u64, true);
                        let sum = self
                            .builder
                            .build_int_add(reg_i, ofs_val, "addr_with_offset")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        Ok(sum)
                    } else {
                        Ok(reg_i)
                    }
                } else {
                    Err(CodeGenError::RegisterMappingError(
                        "Register value is not integer".to_string(),
                    ))
                }
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                // Try to fold constant-only address expressions (e.g., global + const offset)
                // If foldable, treat as link-time address and apply ASLR offsets via map.
                let mut const_stack: Vec<i64> = Vec::new();
                let mut foldable = true;
                for s in steps.iter() {
                    match s {
                        ComputeStep::PushConstant(v) => const_stack.push(*v),
                        ComputeStep::Add => {
                            if const_stack.len() >= 2 {
                                let b = const_stack.pop().unwrap();
                                let a = const_stack.pop().unwrap();
                                const_stack.push(a.saturating_add(b));
                            } else {
                                foldable = false;
                                break;
                            }
                        }
                        // Any register load or deref means runtime-derived address; not foldable
                        ComputeStep::LoadRegister(_) | ComputeStep::Dereference { .. } => {
                            foldable = false;
                            break;
                        }
                        _ => {
                            // Unknown/non-add op: treat as non-foldable
                            foldable = false;
                            break;
                        }
                    }
                }

                if foldable && const_stack.len() == 1 {
                    let link_addr_u = const_stack[0] as u64;
                    if let Some(analyzer_ptr) = self.process_analyzer {
                        let analyzer = unsafe { &mut *analyzer_ptr };
                        let ctx = self.get_compile_time_context()?;
                        let module_for_offsets = module_hint
                            .map(|s| s.to_string())
                            .or_else(|| self.current_resolved_var_module_path.clone())
                            .unwrap_or_else(|| ctx.module_path.clone());
                        if let Ok(offsets) = analyzer.compute_section_offsets() {
                            if let Some((_, cookie, sect_offs)) = offsets
                                .iter()
                                .find(|(p, _, _)| p.to_string_lossy() == module_for_offsets)
                            {
                                let st = analyzer
                                    .classify_section_for_address(&module_for_offsets, link_addr_u)
                                    .unwrap_or(ghostscope_dwarf::core::SectionType::Data);
                                let st_code: u8 = match st {
                                    ghostscope_dwarf::core::SectionType::Text => 0,
                                    ghostscope_dwarf::core::SectionType::Rodata => 1,
                                    ghostscope_dwarf::core::SectionType::Data => 2,
                                    ghostscope_dwarf::core::SectionType::Bss => 3,
                                    _ => 2,
                                };
                                // If we have no bias at all for this section, return link address
                                let sect_bias = match st {
                                    ghostscope_dwarf::core::SectionType::Text => sect_offs.text,
                                    ghostscope_dwarf::core::SectionType::Rodata => sect_offs.rodata,
                                    ghostscope_dwarf::core::SectionType::Data => sect_offs.data,
                                    ghostscope_dwarf::core::SectionType::Bss => sect_offs.bss,
                                    _ => 0,
                                };
                                let link_val =
                                    self.context.i64_type().const_int(link_addr_u, false);
                                if sect_bias == 0 {
                                    self.current_resolved_var_module_path = None;
                                    return Ok(link_val);
                                }
                                let (rt_addr, found_flag) = self
                                    .generate_runtime_address_from_offsets(
                                        link_val, st_code, *cookie,
                                    )?;
                                if let Some(sp) = status_ptr {
                                    let is_miss = self
                                        .builder
                                        .build_int_compare(
                                            inkwell::IntPredicate::EQ,
                                            found_flag,
                                            self.context.bool_type().const_zero(),
                                            "is_off_miss",
                                        )
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                    let cur_status = self
                                        .builder
                                        .build_load(self.context.i8_type(), sp, "cur_status")
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                    let is_ok = self
                                        .builder
                                        .build_int_compare(
                                            inkwell::IntPredicate::EQ,
                                            cur_status.into_int_value(),
                                            self.context.i8_type().const_zero(),
                                            "status_is_ok",
                                        )
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                    let should_store = self
                                        .builder
                                        .build_and(is_miss, is_ok, "store_offsets_unavail")
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                    let new_status = self
                                        .builder
                                        .build_select(
                                            should_store,
                                            self.context
                                                .i8_type()
                                                .const_int(ghostscope_protocol::VariableStatus::OffsetsUnavailable as u64, false)
                                                .into(),
                                            cur_status,
                                            "new_status",
                                        )
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                    self.builder
                                        .build_store(sp, new_status)
                                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                }
                                self.current_resolved_var_module_path = None;
                                return Ok(rt_addr);
                            }
                        }
                    }
                    // Analyzer missing or offsets not available: return link-time address
                    self.current_resolved_var_module_path = None;
                    return Ok(self.context.i64_type().const_int(link_addr_u, false));
                }

                // Attempt: if steps start with PushConstant(base) and first dynamic op is Dereference
                // (with no LoadRegister before it), apply ASLR offsets to base and continue
                if let Some(ComputeStep::PushConstant(base_const)) = steps.first() {
                    // Scan until first Dereference or LoadRegister
                    let mut saw_reg = false;
                    let mut saw_deref = false;
                    for s in &steps[1..] {
                        match s {
                            ComputeStep::LoadRegister(_) => {
                                saw_reg = true;
                                break;
                            }
                            ComputeStep::Dereference { .. } => {
                                saw_deref = true;
                                break;
                            }
                            _ => {}
                        }
                    }
                    if saw_deref && !saw_reg {
                        let link_addr_u = *base_const as u64;
                        if let Some(analyzer_ptr) = self.process_analyzer {
                            let analyzer = unsafe { &mut *analyzer_ptr };
                            let ctx = self.get_compile_time_context()?;
                            let module_for_offsets = module_hint
                                .map(|s| s.to_string())
                                .or_else(|| self.current_resolved_var_module_path.clone())
                                .unwrap_or_else(|| ctx.module_path.clone());
                            if let Ok(offsets) = analyzer.compute_section_offsets() {
                                if let Some((_, cookie, sect_offs)) = offsets
                                    .iter()
                                    .find(|(p, _, _)| p.to_string_lossy() == module_for_offsets)
                                {
                                    let st = analyzer
                                        .classify_section_for_address(
                                            &module_for_offsets,
                                            link_addr_u,
                                        )
                                        .unwrap_or(ghostscope_dwarf::core::SectionType::Data);
                                    let st_code: u8 = match st {
                                        ghostscope_dwarf::core::SectionType::Text => 0,
                                        ghostscope_dwarf::core::SectionType::Rodata => 1,
                                        ghostscope_dwarf::core::SectionType::Data => 2,
                                        ghostscope_dwarf::core::SectionType::Bss => 3,
                                        _ => 2,
                                    };
                                    let sect_bias = match st {
                                        ghostscope_dwarf::core::SectionType::Text => sect_offs.text,
                                        ghostscope_dwarf::core::SectionType::Rodata => {
                                            sect_offs.rodata
                                        }
                                        ghostscope_dwarf::core::SectionType::Data => sect_offs.data,
                                        ghostscope_dwarf::core::SectionType::Bss => sect_offs.bss,
                                        _ => 0,
                                    };
                                    let link_val =
                                        self.context.i64_type().const_int(link_addr_u, false);
                                    let rt_base = if sect_bias == 0 {
                                        link_val
                                    } else {
                                        let (rt, found_flag) = self
                                            .generate_runtime_address_from_offsets(
                                                link_val, st_code, *cookie,
                                            )?;
                                        if let Some(sp) = status_ptr {
                                            let is_miss = self
                                                .builder
                                                .build_int_compare(
                                                    inkwell::IntPredicate::EQ,
                                                    found_flag,
                                                    self.context.bool_type().const_zero(),
                                                    "is_off_miss",
                                                )
                                                .map_err(|e| {
                                                    CodeGenError::LLVMError(e.to_string())
                                                })?;
                                            let cur_status = self
                                                .builder
                                                .build_load(
                                                    self.context.i8_type(),
                                                    sp,
                                                    "cur_status",
                                                )
                                                .map_err(|e| {
                                                    CodeGenError::LLVMError(e.to_string())
                                                })?;
                                            let is_ok = self
                                                .builder
                                                .build_int_compare(
                                                    inkwell::IntPredicate::EQ,
                                                    cur_status.into_int_value(),
                                                    self.context.i8_type().const_zero(),
                                                    "status_is_ok",
                                                )
                                                .map_err(|e| {
                                                    CodeGenError::LLVMError(e.to_string())
                                                })?;
                                            let should_store = self
                                                .builder
                                                .build_and(is_miss, is_ok, "store_offsets_unavail")
                                                .map_err(|e| {
                                                    CodeGenError::LLVMError(e.to_string())
                                                })?;
                                            let new_status = self
                                                .builder
                                                .build_select(
                                                    should_store,
                                                    self.context
                                                        .i8_type()
                                                        .const_int(ghostscope_protocol::VariableStatus::OffsetsUnavailable as u64, false)
                                                        .into(),
                                                    cur_status,
                                                    "new_status",
                                                )
                                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                                            self.builder.build_store(sp, new_status).map_err(
                                                |e| CodeGenError::LLVMError(e.to_string()),
                                            )?;
                                        }
                                        rt
                                    };
                                    // Execute remaining steps with rt_base pre-pushed
                                    let rest = &steps[1..];
                                    let val = self.generate_compute_steps(
                                        rest,
                                        pt_regs_ptr,
                                        None,
                                        status_ptr,
                                        Some(rt_base),
                                    )?;
                                    if let BasicValueEnum::IntValue(i) = val {
                                        return Ok(i);
                                    } else {
                                        return Err(CodeGenError::LLVMError(
                                            "Computed location did not produce integer".to_string(),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                // Fallback: execute steps at runtime and use the result directly (no offsets)
                let val =
                    self.generate_compute_steps(steps, pt_regs_ptr, None, status_ptr, None)?;
                if let BasicValueEnum::IntValue(i) = val {
                    Ok(i)
                } else {
                    Err(CodeGenError::LLVMError(
                        "Computed location did not produce integer".to_string(),
                    ))
                }
            }
            _ => Err(CodeGenError::NotImplemented(
                "Unable to compute address from evaluation result".to_string(),
            )),
        }
    }

    /// Convert DWARF type size to MemoryAccessSize
    fn dwarf_type_to_memory_access_size(&self, dwarf_type: &TypeInfo) -> MemoryAccessSize {
        let size = self.get_dwarf_type_size(dwarf_type);
        match size {
            1 => MemoryAccessSize::U8,
            2 => MemoryAccessSize::U16,
            4 => MemoryAccessSize::U32,
            8 => MemoryAccessSize::U64,
            _ => MemoryAccessSize::U64, // Default to U64 for unknown sizes
        }
    }

    /// Generate LLVM IR for direct value result
    fn generate_direct_value(
        &mut self,
        direct: &DirectValueResult,
        pt_regs_ptr: PointerValue<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        match direct {
            DirectValueResult::Constant(value) => {
                debug!("Generating constant: {}", value);
                Ok(self
                    .context
                    .i64_type()
                    .const_int(*value as u64, true)
                    .into())
            }

            DirectValueResult::ImplicitValue(bytes) => {
                debug!("Generating implicit value: {} bytes", bytes.len());
                // Convert bytes to integer value (little-endian)
                let mut value: u64 = 0;
                for (i, &byte) in bytes.iter().enumerate().take(8) {
                    value |= (byte as u64) << (i * 8);
                }
                Ok(self.context.i64_type().const_int(value, false).into())
            }

            DirectValueResult::RegisterValue(reg_num) => {
                debug!("Generating register value: {}", reg_num);
                let reg_value = self.load_register_value(*reg_num, pt_regs_ptr)?;
                Ok(reg_value)
            }

            DirectValueResult::ComputedValue { steps, result_size } => {
                debug!("Generating computed value: {} steps", steps.len());
                self.generate_compute_steps(steps, pt_regs_ptr, Some(*result_size), None, None)
            }
        }
    }

    /// Generate LLVM IR for memory location result
    fn generate_memory_location(
        &mut self,
        location: &LocationResult,
        pt_regs_ptr: PointerValue<'ctx>,
        dwarf_type: &TypeInfo,
    ) -> Result<BasicValueEnum<'ctx>> {
        match location {
            LocationResult::Address(addr) => {
                debug!("Generating absolute address: 0x{:x}", addr);
                let addr_value = self.context.i64_type().const_int(*addr, false);
                // Use DWARF type size for memory access
                let access_size = self.dwarf_type_to_memory_access_size(dwarf_type);
                self.generate_memory_read(addr_value, access_size)
            }

            LocationResult::RegisterAddress {
                register,
                offset,
                size,
            } => {
                debug!(
                    "Generating register address: reg{} {:+}",
                    register,
                    offset.unwrap_or(0)
                );

                // Load register value
                let reg_value = self.load_register_value(*register, pt_regs_ptr)?;

                // Add offset if present
                let final_addr = if let Some(offset) = offset {
                    let offset_value = self.context.i64_type().const_int(*offset as u64, true);
                    if let BasicValueEnum::IntValue(reg_int) = reg_value {
                        self.builder
                            .build_int_add(reg_int, offset_value, "addr_with_offset")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                    } else {
                        return Err(CodeGenError::RegisterMappingError(
                            "Register value is not integer".to_string(),
                        ));
                    }
                } else if let BasicValueEnum::IntValue(reg_int) = reg_value {
                    reg_int
                } else {
                    return Err(CodeGenError::RegisterMappingError(
                        "Register value is not integer".to_string(),
                    ));
                };

                // Determine memory access size - prefer LocationResult size if available, otherwise use DWARF type
                let access_size = size
                    .map(|s| match s {
                        1 => MemoryAccessSize::U8,
                        2 => MemoryAccessSize::U16,
                        4 => MemoryAccessSize::U32,
                        _ => MemoryAccessSize::U64,
                    })
                    .unwrap_or_else(|| self.dwarf_type_to_memory_access_size(dwarf_type));

                self.generate_memory_read(final_addr, access_size)
            }

            LocationResult::ComputedLocation { steps } => {
                debug!("Generating computed location: {} steps", steps.len());
                // Execute steps to compute the address
                let addr_value =
                    self.generate_compute_steps(steps, pt_regs_ptr, None, None, None)?;
                if let BasicValueEnum::IntValue(addr) = addr_value {
                    // Use DWARF type size for memory access
                    let access_size = self.dwarf_type_to_memory_access_size(dwarf_type);
                    self.generate_memory_read(addr, access_size)
                } else {
                    Err(CodeGenError::LLVMError(
                        "Address computation must return integer".to_string(),
                    ))
                }
            }
        }
    }

    /// Execute a sequence of compute steps
    fn generate_compute_steps(
        &mut self,
        steps: &[ComputeStep],
        pt_regs_ptr: PointerValue<'ctx>,
        _result_size: Option<MemoryAccessSize>,
        status_ptr: Option<PointerValue<'ctx>>,
        initial_top: Option<IntValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Implement stack-based computation
        let mut stack: Vec<IntValue<'ctx>> = Vec::new();
        // Track a runtime null-pointer flag from dereference steps; when true, subsequent
        // arithmetic will be masked to zero to avoid reads at small offsets from NULL.
        let mut deref_null_flag: Option<inkwell::values::IntValue> = None;
        if let Some(top) = initial_top {
            stack.push(top);
        }

        for step in steps {
            match step {
                ComputeStep::LoadRegister(reg_num) => {
                    let reg_value = self.load_register_value(*reg_num, pt_regs_ptr)?;
                    if let BasicValueEnum::IntValue(int_val) = reg_value {
                        stack.push(int_val);
                    } else {
                        return Err(CodeGenError::RegisterMappingError(format!(
                            "Register {reg_num} did not return integer value"
                        )));
                    }
                }

                ComputeStep::PushConstant(value) => {
                    let const_val = self.context.i64_type().const_int(*value as u64, true);
                    stack.push(const_val);
                }

                ComputeStep::Add => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let sum_val = self
                            .builder
                            .build_int_add(a, b, "add")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        if let Some(nf) = deref_null_flag {
                            let masked_bv = self
                                .builder
                                .build_select::<inkwell::values::BasicValueEnum<'ctx>, _>(
                                    nf,
                                    self.context.i64_type().const_zero().into(),
                                    sum_val.into(),
                                    "add_masked",
                                )
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            stack.push(masked_bv.into_int_value());
                        } else {
                            stack.push(sum_val);
                        }
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in Add".to_string(),
                        ));
                    }
                }

                ComputeStep::Sub => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_int_sub(a, b, "sub")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in Sub".to_string(),
                        ));
                    }
                }

                ComputeStep::Mul => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_int_mul(a, b, "mul")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in Mul".to_string(),
                        ));
                    }
                }

                ComputeStep::Div => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_int_signed_div(a, b, "div")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in Div".to_string(),
                        ));
                    }
                }

                ComputeStep::And => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_and(a, b, "and")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in BitwiseAnd".to_string(),
                        ));
                    }
                }

                ComputeStep::Or => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_or(a, b, "or")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in BitwiseOr".to_string(),
                        ));
                    }
                }

                ComputeStep::Xor => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_xor(a, b, "xor")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in BitwiseXor".to_string(),
                        ));
                    }
                }

                ComputeStep::Shl => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_left_shift(a, b, "shl")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in ShiftLeft".to_string(),
                        ));
                    }
                }

                ComputeStep::Shr => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        let result = self
                            .builder
                            .build_right_shift(a, b, false, "shr")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in ShiftRight".to_string(),
                        ));
                    }
                }

                ComputeStep::Dereference { size } => {
                    if let Some(addr) = stack.pop() {
                        // Null guard: if addr == 0, set NullDeref (if status_ptr provided and current is Ok)
                        let zero64 = self.context.i64_type().const_zero();
                        let is_null = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                addr,
                                zero64,
                                "is_null_deref",
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                        let cur_fn = self
                            .builder
                            .get_insert_block()
                            .unwrap()
                            .get_parent()
                            .unwrap();
                        let null_bb = self.context.append_basic_block(cur_fn, "deref_null");
                        let read_bb = self.context.append_basic_block(cur_fn, "deref_read");
                        let cont_bb = self.context.append_basic_block(cur_fn, "deref_cont");
                        self.builder
                            .build_conditional_branch(is_null, null_bb, read_bb)
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                        // Null path: optionally set status=NullDeref if currently Ok, branch to cont
                        self.builder.position_at_end(null_bb);
                        let null_val = self.context.i64_type().const_zero();
                        if let Some(sp) = status_ptr {
                            let cur_status = self
                                .builder
                                .build_load(self.context.i8_type(), sp, "cur_status")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                                .into_int_value();
                            let is_ok = self
                                .builder
                                .build_int_compare(
                                    inkwell::IntPredicate::EQ,
                                    cur_status,
                                    self.context.i8_type().const_zero(),
                                    "status_is_ok",
                                )
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            let then_val = self.context.i8_type().const_int(
                                ghostscope_protocol::VariableStatus::NullDeref as u64,
                                false,
                            );
                            let new_status_bv = self
                                .builder
                                .build_select::<inkwell::values::BasicValueEnum<'ctx>, _>(
                                    is_ok,
                                    then_val.into(),
                                    cur_status.into(),
                                    "new_status",
                                )
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            self.builder
                                .build_store(sp, new_status_bv)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        self.builder
                            .build_unconditional_branch(cont_bb)
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                        // Read path: load pointer-sized value into tmp then branch to cont
                        self.builder.position_at_end(read_bb);
                        let access_size = *size;
                        let loaded_bv = self.generate_memory_read(addr, access_size)?;
                        let loaded_int = if let BasicValueEnum::IntValue(int_val) = loaded_bv {
                            int_val
                        } else {
                            return Err(CodeGenError::LLVMError(
                                "Memory load did not return integer".to_string(),
                            ));
                        };
                        self.builder
                            .build_unconditional_branch(cont_bb)
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                        // Continue at cont: create PHI to merge null/read values, push once
                        self.builder.position_at_end(cont_bb);
                        let phi = self
                            .builder
                            .build_phi(self.context.i64_type(), "deref_phi")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        phi.add_incoming(&[(&null_val, null_bb), (&loaded_int, read_bb)]);
                        let merged = phi.as_basic_value().into_int_value();
                        // Update null flag based on loaded pointer value being zero
                        let is_zero_ptr = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                merged,
                                self.context.i64_type().const_zero(),
                                "is_zero_ptr",
                            )
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        deref_null_flag = Some(match deref_null_flag {
                            Some(prev) => self
                                .builder
                                .build_or(prev, is_zero_ptr, "null_or")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
                            None => is_zero_ptr,
                        });
                        if let (Some(sp), Some(nf)) = (status_ptr, deref_null_flag) {
                            // Only store NullDeref if currently OK and nf is true
                            let cur_status = self
                                .builder
                                .build_load(self.context.i8_type(), sp, "cur_status")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?
                                .into_int_value();
                            let is_ok = self
                                .builder
                                .build_int_compare(
                                    inkwell::IntPredicate::EQ,
                                    cur_status,
                                    self.context.i8_type().const_zero(),
                                    "status_is_ok2",
                                )
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            let should_store = self
                                .builder
                                .build_and(is_ok, nf, "store_null_deref_from_ptr")
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            let then_val = self.context.i8_type().const_int(
                                ghostscope_protocol::VariableStatus::NullDeref as u64,
                                false,
                            );
                            let new_status_bv = self
                                .builder
                                .build_select::<inkwell::values::BasicValueEnum<'ctx>, _>(
                                    should_store,
                                    then_val.into(),
                                    cur_status.into(),
                                    "new_status2",
                                )
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                            self.builder
                                .build_store(sp, new_status_bv)
                                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        }
                        stack.push(merged);
                    } else {
                        return Err(CodeGenError::LLVMError(
                            "Stack underflow in LoadMemory".to_string(),
                        ));
                    }
                }

                // Add catch-all for unimplemented operations
                _ => {
                    warn!("Unimplemented ComputeStep: {:?}", step);
                    return Err(CodeGenError::NotImplemented(format!(
                        "ComputeStep {:?} not yet implemented",
                        step
                    )));
                }
            }
        }

        if stack.len() == 1 {
            Ok(stack.pop().unwrap().into())
        } else {
            Err(CodeGenError::LLVMError(format!(
                "Invalid stack state after computation: {} elements remaining",
                stack.len()
            )))
        }
    }

    /// Query DWARF for complex expression (supports member access, array access, etc.)
    pub fn query_dwarf_for_complex_expr(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<Option<VariableWithEvaluation>> {
        use crate::script::Expr;

        match expr {
            // Simple variable lookup
            Expr::Variable(var_name) => self.query_dwarf_for_variable(var_name),

            // Member access: obj.field
            Expr::MemberAccess(obj_expr, field_name) => {
                self.query_dwarf_for_member_access(obj_expr, field_name)
            }

            // Array access: arr[index]
            Expr::ArrayAccess(array_expr, index_expr) => {
                self.query_dwarf_for_array_access(array_expr, index_expr)
            }

            // Chain access: person.name.first
            Expr::ChainAccess(chain) => self.query_dwarf_for_chain_access(chain),

            // Pointer dereference: *ptr
            Expr::PointerDeref(expr) => self.query_dwarf_for_pointer_deref(expr),

            // Other expression types are not supported for DWARF queries
            _ => Ok(None),
        }
    }

    /// Query DWARF for variable information
    pub fn query_dwarf_for_variable(
        &mut self,
        var_name: &str,
    ) -> Result<Option<VariableWithEvaluation>> {
        if self.process_analyzer.is_none() {
            return Err(CodeGenError::DwarfError(
                "No DWARF analyzer available".to_string(),
            ));
        }

        let context = self.get_compile_time_context()?;
        let pc_address = context.pc_address;
        let module_path = &context.module_path;

        debug!(
            "Querying DWARF for variable '{}' at PC 0x{:x} in module '{}'",
            var_name, pc_address, module_path
        );

        // Query DWARF analyzer for variable
        let analyzer = unsafe { &mut *(self.process_analyzer.unwrap()) };

        let module_address = ghostscope_dwarf::ModuleAddress::new(
            std::path::PathBuf::from(module_path.clone()),
            pc_address,
        );

        match analyzer.get_all_variables_at_address(&module_address) {
            Ok(vars) => {
                // Look for the specific variable by name
                if let Some(var_result) = vars.iter().find(|v| v.name == var_name).or_else(|| {
                    // GCC/Clang may synthesize names like r@entry; try a tolerant match
                    let prefix = format!("{var_name}@");
                    vars.iter().find(|v| v.name.starts_with(&prefix))
                }) {
                    debug!("Found DWARF variable: {}", var_name);
                    Ok(Some(var_result.clone()))
                } else {
                    debug!(
                        "Variable '{}' not found in DWARF locals/params, trying globals",
                        var_name
                    );
                    // Global fallback: search per-module first, then cross-module
                    let mut matches = analyzer.find_global_variables_by_name(var_name);
                    if matches.is_empty() {
                        return Ok(None);
                    }
                    // Prefer current module
                    let preferred: Vec<(
                        std::path::PathBuf,
                        ghostscope_dwarf::core::GlobalVariableInfo,
                    )> = matches
                        .iter()
                        .filter(|(p, _)| p.to_string_lossy() == module_path.as_str())
                        .cloned()
                        .collect();
                    let chosen = if preferred.len() == 1 {
                        Some(preferred[0].clone())
                    } else if preferred.is_empty() && matches.len() == 1 {
                        Some(matches.remove(0))
                    } else {
                        // Ambiguous across modules; bail out explicitly
                        debug!(
                            "Global '{}' is ambiguous across modules ({} matches)",
                            var_name,
                            matches.len()
                        );
                        return Err(CodeGenError::DwarfError(format!(
                            "Ambiguous global '{}': {} matches",
                            var_name,
                            matches.len()
                        )));
                    };

                    if let Some((mpath, info)) = chosen {
                        // Resolve variable by CU/DIE offsets in that module
                        let gv = analyzer
                            .resolve_variable_by_offsets_in_module(
                                &mpath,
                                info.unit_offset,
                                info.die_offset,
                            )
                            .map_err(|e| CodeGenError::DwarfError(e.to_string()))?;
                        // Record module hint for codegen (ASLR offsets lookup)
                        self.current_resolved_var_module_path =
                            Some(mpath.to_string_lossy().to_string());
                        Ok(Some(gv))
                    } else {
                        Ok(None)
                    }
                }
            }
            Err(e) => {
                debug!("DWARF query error for '{}': {}", var_name, e);
                Err(CodeGenError::DwarfError(format!(
                    "DWARF query failed: {}",
                    e
                )))
            }
        }
    }

    /// Get DWARF type size in bytes
    #[allow(clippy::only_used_in_recursion)]
    pub fn get_dwarf_type_size(&self, dwarf_type: &TypeInfo) -> u64 {
        match dwarf_type {
            TypeInfo::BaseType { size, .. } => *size,
            TypeInfo::PointerType { size, .. } => *size,
            TypeInfo::ArrayType { total_size, .. } => total_size.unwrap_or(0),
            TypeInfo::StructType { size, .. } => *size,
            TypeInfo::UnionType { size, .. } => *size,
            TypeInfo::EnumType { size, .. } => *size,
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => {
                // Read size equals the storage type size
                self.get_dwarf_type_size(underlying_type)
            }
            TypeInfo::TypedefType {
                underlying_type, ..
            } => self.get_dwarf_type_size(underlying_type),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => self.get_dwarf_type_size(underlying_type),
            TypeInfo::FunctionType { .. } => 8, // Function pointer size
            TypeInfo::UnknownType { .. } => 0,
            TypeInfo::OptimizedOut { .. } => 0, // Optimized out has no size
        }
    }

    /// Query DWARF for member access (obj.field)
    pub fn query_dwarf_for_member_access(
        &mut self,
        obj_expr: &crate::script::Expr,
        field_name: &str,
    ) -> Result<Option<VariableWithEvaluation>> {
        // Support simple variable base and fall back to global/static lowering
        if let crate::script::Expr::Variable(base_name) = obj_expr {
            let Some(analyzer_ptr) = self.process_analyzer else {
                return Err(CodeGenError::DwarfError(
                    "No DWARF analyzer available".to_string(),
                ));
            };
            let analyzer = unsafe { &mut *analyzer_ptr };
            let ctx = self.get_compile_time_context()?;
            let module_address = ghostscope_dwarf::ModuleAddress::new(
                std::path::PathBuf::from(ctx.module_path.clone()),
                ctx.pc_address,
            );
            // Try current module at PC first
            match analyzer.plan_chain_access(&module_address, base_name, &[field_name.to_string()])
            {
                Ok(Some(var)) => return Ok(Some(var)),
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("member planner miss at current module: {}", e);
                }
            }

            // Fallback: globals across modules (prefer static-offset lowering)
            let matches = analyzer.find_global_variables_by_name(base_name);
            if matches.is_empty() {
                return Ok(None);
            }
            // Build preferred order (current module first)
            let cur_mod = ctx.module_path.clone();
            let mut ordered: Vec<(
                &std::path::PathBuf,
                &ghostscope_dwarf::core::GlobalVariableInfo,
            )> = Vec::new();
            if let Some((mpath, info)) = matches
                .iter()
                .find(|(p, _)| p.to_string_lossy() == cur_mod.as_str())
            {
                ordered.push((mpath, info));
            }
            for (mpath, info) in &matches {
                if mpath.to_string_lossy() != cur_mod.as_str() {
                    ordered.push((mpath, info));
                }
            }

            for (mpath, info) in &ordered {
                if let Some(link) = info.link_address {
                    if let Ok(Some((off, final_ty))) = analyzer.compute_global_member_static_offset(
                        mpath,
                        link,
                        info.unit_offset,
                        info.die_offset,
                        &[field_name.to_string()],
                    ) {
                        let name = format!("{}.{}", base_name, field_name);
                        let v = VariableWithEvaluation {
                            name,
                            type_name: final_ty.type_name(),
                            dwarf_type: Some(final_ty),
                            evaluation_result: ghostscope_dwarf::EvaluationResult::MemoryLocation(
                                ghostscope_dwarf::LocationResult::Address(link + off),
                            ),
                            scope_depth: 0,
                            is_parameter: false,
                            is_artificial: false,
                        };
                        self.current_resolved_var_module_path =
                            Some(mpath.to_string_lossy().to_string());
                        return Ok(Some(v));
                    }
                }
                // Planner fallback inside module (addr=0)
                let ma = ghostscope_dwarf::ModuleAddress::new((*mpath).clone(), 0);
                match analyzer.plan_chain_access(&ma, base_name, &[field_name.to_string()]) {
                    Ok(Some(v)) => {
                        self.current_resolved_var_module_path =
                            Some(mpath.to_string_lossy().to_string());
                        return Ok(Some(v));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        tracing::debug!(
                            "member planner miss in module '{}': {}",
                            mpath.display(),
                            e
                        );
                    }
                }
            }

            Ok(None)
        } else {
            Err(CodeGenError::NotImplemented(
                "MemberAccess base must be a simple variable (use chain access)".to_string(),
            ))
        }
    }

    /// Query DWARF for array access (arr[index])
    pub fn query_dwarf_for_array_access(
        &mut self,
        array_expr: &crate::script::Expr,
        index_expr: &crate::script::Expr,
    ) -> Result<Option<VariableWithEvaluation>> {
        // First, resolve the base array
        let base_var = match self.query_dwarf_for_complex_expr(array_expr)? {
            Some(var) => var,
            None => return Ok(None),
        };

        // Get the array's type
        let array_type = match &base_var.dwarf_type {
            Some(type_info) => type_info,
            None => return Ok(None),
        };

        // Extract element type from array type
        let element_type = match array_type {
            TypeInfo::ArrayType { element_type, .. } => element_type.as_ref().clone(),
            _ => return Ok(None), // Not an array type
        };

        // Calculate element size for address computation
        let element_size = element_type.size();

        // For indexing, create a computed location representing: base + (index * element_size)
        // Only literal integer indices are supported at this stage
        let index_value: i64 = match index_expr {
            crate::script::Expr::Int(v) => *v,
            _ => {
                return Err(CodeGenError::NotImplemented(
                    "Only literal integer array indices are supported (TODO)".to_string(),
                ))
            }
        };
        let element_evaluation_result = match &base_var.evaluation_result {
            EvaluationResult::DirectValue(_) => {
                // If base is a value, we can't do array indexing
                return Ok(None);
            }
            EvaluationResult::MemoryLocation(location) => {
                // Create a computed location that includes the array indexing calculation
                let array_access_steps =
                    self.create_array_access_steps(location, element_size, index_value);
                EvaluationResult::MemoryLocation(LocationResult::ComputedLocation {
                    steps: array_access_steps,
                })
            }
            EvaluationResult::Optimized => {
                return Ok(None);
            }
            EvaluationResult::Composite(_) => {
                // Array access on composite locations is complex, skip for now
                return Ok(None);
            }
        };

        let element_var = VariableWithEvaluation {
            name: format!("{}[index]", self.expr_to_string(array_expr)),
            type_name: self.type_info_to_name(&element_type),
            dwarf_type: Some(element_type),
            evaluation_result: element_evaluation_result,
            scope_depth: base_var.scope_depth,
            is_parameter: false,
            is_artificial: false,
        };

        Ok(Some(element_var))
    }

    /// Query DWARF for chain access (person.name.first)
    pub fn query_dwarf_for_chain_access(
        &mut self,
        chain: &[String],
    ) -> Result<Option<VariableWithEvaluation>> {
        if chain.is_empty() {
            return Ok(None);
        }
        // If chain has only one element, treat it as a simple variable and reuse variable lookup.
        if chain.len() == 1 {
            return self.query_dwarf_for_variable(&chain[0]);
        }
        // Planner path only; do not fallback. If planning fails, surface an error.
        let Some(analyzer_ptr) = self.process_analyzer else {
            return Err(CodeGenError::DwarfError(
                "No DWARF analyzer available".to_string(),
            ));
        };
        let analyzer = unsafe { &mut *analyzer_ptr };
        let ctx = self.get_compile_time_context()?;
        // First attempt: current module at current PC (locals/params)
        let module_address = ghostscope_dwarf::ModuleAddress::new(
            std::path::PathBuf::from(ctx.module_path.clone()),
            ctx.pc_address,
        );
        match analyzer.plan_chain_access(&module_address, &chain[0], &chain[1..]) {
            Ok(Some(var)) => return Ok(Some(var)),
            Ok(None) => {}
            Err(e) => {
                // Treat planner errors as a miss and continue to global fallback
                tracing::debug!("chain planner miss at current module: {}", e);
            }
        }

        // Fallback: global base across modules. Prefer static-offset lowering for globals.
        let base = &chain[0];
        let rest = &chain[1..];
        let matches = analyzer.find_global_variables_by_name(base);
        if matches.is_empty() {
            return Ok(None);
        }
        // Build preferred order with metadata (current module first)
        let cur_mod = ctx.module_path.clone();
        let mut ordered: Vec<(
            &std::path::PathBuf,
            &ghostscope_dwarf::core::GlobalVariableInfo,
        )> = Vec::new();
        if let Some((mpath, info)) = matches
            .iter()
            .find(|(p, _)| p.to_string_lossy() == cur_mod.as_str())
        {
            ordered.push((mpath, info));
        }
        for (mpath, info) in &matches {
            if mpath.to_string_lossy() != cur_mod.as_str() {
                ordered.push((mpath, info));
            }
        }

        // Try static-offset lowering first; fall back to planner if needed
        for (mpath, info) in &ordered {
            if let Some(link) = info.link_address {
                if let Ok(Some((off, final_ty))) = analyzer.compute_global_member_static_offset(
                    mpath,
                    link,
                    info.unit_offset,
                    info.die_offset,
                    rest,
                ) {
                    let name = if rest.is_empty() {
                        base.clone()
                    } else {
                        format!("{base}.{}", rest.join("."))
                    };
                    let v = VariableWithEvaluation {
                        name,
                        type_name: final_ty.type_name(),
                        dwarf_type: Some(final_ty),
                        evaluation_result: ghostscope_dwarf::EvaluationResult::MemoryLocation(
                            ghostscope_dwarf::LocationResult::Address(link + off),
                        ),
                        scope_depth: 0,
                        is_parameter: false,
                        is_artificial: false,
                    };
                    self.current_resolved_var_module_path =
                        Some(mpath.to_string_lossy().to_string());
                    return Ok(Some(v));
                }
            }
            // Planner fallback (addr=0 inside module)
            let ma = ghostscope_dwarf::ModuleAddress::new((*mpath).clone(), 0);
            match analyzer.plan_chain_access(&ma, base, rest) {
                Ok(Some(v)) => {
                    self.current_resolved_var_module_path =
                        Some(mpath.to_string_lossy().to_string());
                    return Ok(Some(v));
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::debug!("chain planner miss in module '{}': {}", mpath.display(), e);
                }
            }
        }

        Ok(None)
        // unreachable
    }

    /// Query DWARF for pointer dereference (*ptr)
    pub fn query_dwarf_for_pointer_deref(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<Option<VariableWithEvaluation>> {
        // First, resolve the pointer expression
        let ptr_var = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => return Ok(None),
        };

        // Get the pointer's type
        let ptr_type = match &ptr_var.dwarf_type {
            Some(type_info) => type_info,
            None => return Ok(None),
        };

        // Extract pointed-to type from pointer type
        let mut pointed_type = match ptr_type {
            TypeInfo::PointerType { target_type, .. } => target_type.as_ref().clone(),
            _ => return Ok(None), // Not a pointer type
        };

        // Upgrade UnknownType(target_name) using analyzer/type index to get a shallow type.
        // 1) Struct/union/class/enum: try analyzer shallow lookup by name (module-scoped first)
        // 2) Do NOT猜测内建类型大小 — 仅使用 DWARF 基础类型条目
        if let TypeInfo::UnknownType { name } = &pointed_type {
            let mut candidate_names: Vec<String> = Vec::new();
            if !name.is_empty() && name != "void" {
                candidate_names.push(name.clone());
            }
            // Fallback: derive from pointer variable's pretty type name, e.g., "GlobalState*" => "GlobalState"
            if candidate_names.is_empty() {
                let tn = ptr_var.type_name.trim().to_string();
                if let Some(idx) = tn.find('*') {
                    let mut base = tn[..idx].trim().to_string();
                    // Strip common qualifiers and tags
                    for prefix in [
                        "const ",
                        "volatile ",
                        "restrict ",
                        "struct ",
                        "class ",
                        "union ",
                    ] {
                        if base.starts_with(prefix) {
                            base = base[prefix.len()..].trim().to_string();
                        }
                    }
                    if !base.is_empty() && base != "void" {
                        candidate_names.push(base);
                    }
                }
            }
            if let Some(analyzer_ptr) = self.process_analyzer {
                let analyzer = unsafe { &mut *analyzer_ptr };
                let ctx = self.get_compile_time_context()?;
                let mut alias_used: Option<String> = None;
                for n in candidate_names {
                    // Prefer cross-module definitions first to avoid forward decls with size=0 in current CU
                    let mut upgraded: Option<TypeInfo> = None;
                    // struct/class
                    if let Some(ti) = analyzer.resolve_struct_type_shallow_by_name(&n) {
                        if ti.size() > 0 {
                            upgraded = Some(ti);
                        }
                    }
                    if upgraded.is_none() {
                        if let Some(ti) = analyzer
                            .resolve_struct_type_shallow_by_name_in_module(&ctx.module_path, &n)
                        {
                            if ti.size() > 0 {
                                upgraded = Some(ti);
                            }
                        }
                    }
                    // union
                    if upgraded.is_none() {
                        if let Some(ti) = analyzer.resolve_union_type_shallow_by_name(&n) {
                            if ti.size() > 0 {
                                upgraded = Some(ti);
                            }
                        }
                    }
                    if upgraded.is_none() {
                        if let Some(ti) = analyzer
                            .resolve_union_type_shallow_by_name_in_module(&ctx.module_path, &n)
                        {
                            if ti.size() > 0 {
                                upgraded = Some(ti);
                            }
                        }
                    }
                    // enum
                    if upgraded.is_none() {
                        if let Some(ti) = analyzer.resolve_enum_type_shallow_by_name(&n) {
                            if ti.size() > 0 {
                                upgraded = Some(ti);
                            }
                        }
                    }
                    if upgraded.is_none() {
                        if let Some(ti) = analyzer
                            .resolve_enum_type_shallow_by_name_in_module(&ctx.module_path, &n)
                        {
                            if ti.size() > 0 {
                                upgraded = Some(ti);
                            }
                        }
                    }
                    if let Some(ti) = upgraded {
                        pointed_type = ti;
                        alias_used = Some(n.clone());
                        break;
                    }
                }

                // If we upgraded to an aggregate and have an alias name, wrap it as a typedef
                if let Some(alias) = alias_used {
                    match &pointed_type {
                        TypeInfo::StructType { .. }
                        | TypeInfo::UnionType { .. }
                        | TypeInfo::EnumType { .. } => {
                            pointed_type = TypeInfo::TypedefType {
                                name: alias,
                                underlying_type: Box::new(pointed_type.clone()),
                            };
                        }
                        _ => {}
                    }
                }
            }
        }

        // Create dereferenced variable
        let deref_var = VariableWithEvaluation {
            name: format!("*{}", self.expr_to_string(expr)),
            type_name: self.type_info_to_name(&pointed_type),
            dwarf_type: Some(pointed_type),
            evaluation_result: self.compute_pointer_dereference(&ptr_var.evaluation_result)?,
            scope_depth: ptr_var.scope_depth,
            is_parameter: false,
            is_artificial: false,
        };

        Ok(Some(deref_var))
    }

    /// Helper: Compute pointer dereference
    fn compute_pointer_dereference(
        &self,
        ptr_result: &EvaluationResult,
    ) -> Result<EvaluationResult> {
        use ghostscope_dwarf::{ComputeStep, LocationResult, MemoryAccessSize};

        match ptr_result {
            // If the pointer is a memory location, we need to read that location first,
            // then use the result as an address for another read
            EvaluationResult::MemoryLocation(location) => {
                let steps = [
                    self.location_to_compute_steps(location),
                    // Then dereference the pointer (read from the computed address)
                    vec![ComputeStep::Dereference {
                        size: MemoryAccessSize::U64,
                    }],
                ]
                .concat();

                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::ComputedLocation { steps },
                ))
            }
            // If the pointer value is held directly (common for function parameters)
            // interpret the value as an address to the pointed-to object.
            EvaluationResult::DirectValue(dv) => {
                use ghostscope_dwarf::DirectValueResult as DV;
                match dv {
                    DV::RegisterValue(reg) => Ok(EvaluationResult::MemoryLocation(
                        LocationResult::RegisterAddress {
                            register: *reg,
                            offset: None,
                            size: None,
                        },
                    )),
                    DV::Constant(val) => Ok(EvaluationResult::MemoryLocation(
                        LocationResult::Address(*val as u64),
                    )),
                    DV::ImplicitValue(bytes) => {
                        // Assemble up to 8 bytes little-endian into u64
                        let mut v: u64 = 0;
                        for (i, b) in bytes.iter().take(8).enumerate() {
                            v |= (*b as u64) << (8 * i);
                        }
                        Ok(EvaluationResult::MemoryLocation(LocationResult::Address(v)))
                    }
                    DV::ComputedValue { steps, .. } => Ok(EvaluationResult::MemoryLocation(
                        LocationResult::ComputedLocation {
                            steps: steps.clone(),
                        },
                    )),
                }
            }
            _ => Err(CodeGenError::NotImplemented(
                "Unsupported pointer dereference scenario".to_string(),
            )),
        }
    }

    /// Helper: Convert location to compute steps
    fn location_to_compute_steps(&self, location: &LocationResult) -> Vec<ComputeStep> {
        use ghostscope_dwarf::{ComputeStep, LocationResult};

        match location {
            LocationResult::Address(addr) => {
                vec![ComputeStep::PushConstant(*addr as i64)]
            }
            LocationResult::RegisterAddress {
                register, offset, ..
            } => {
                let mut steps = vec![ComputeStep::LoadRegister(*register)];
                if let Some(offset) = offset {
                    steps.push(ComputeStep::PushConstant(*offset));
                    steps.push(ComputeStep::Add);
                }
                steps
            }
            LocationResult::ComputedLocation { steps } => steps.clone(),
        }
    }

    /// Helper: Convert expression to string for debugging
    #[allow(clippy::only_used_in_recursion)]
    fn expr_to_string(&self, expr: &crate::script::Expr) -> String {
        use crate::script::Expr;

        match expr {
            Expr::Variable(name) => name.clone(),
            Expr::MemberAccess(obj, field) => format!("{}.{}", self.expr_to_string(obj), field),
            Expr::ArrayAccess(arr, _) => format!("{}[index]", self.expr_to_string(arr)),
            Expr::ChainAccess(chain) => chain.join("."),
            Expr::PointerDeref(expr) => format!("*{}", self.expr_to_string(expr)),
            _ => "expr".to_string(),
        }
    }

    /// Helper: Extract readable name from TypeInfo
    #[allow(clippy::only_used_in_recursion)]
    fn type_info_to_name(&self, type_info: &TypeInfo) -> String {
        match type_info {
            TypeInfo::BaseType { name, .. } => name.clone(),
            TypeInfo::PointerType { target_type, .. } => {
                format!("{}*", self.type_info_to_name(target_type))
            }
            TypeInfo::ArrayType {
                element_type,
                element_count,
                ..
            } => {
                if let Some(count) = element_count {
                    format!("{}[{}]", self.type_info_to_name(element_type), count)
                } else {
                    format!("{}[]", self.type_info_to_name(element_type))
                }
            }
            TypeInfo::StructType { name, .. } => format!("struct {}", name),
            TypeInfo::UnionType { name, .. } => format!("union {}", name),
            TypeInfo::EnumType { name, .. } => format!("enum {}", name),
            TypeInfo::BitfieldType {
                underlying_type,
                bit_offset,
                bit_size,
            } => {
                format!(
                    "bitfield<{}:{}> {}",
                    bit_offset,
                    bit_size,
                    self.type_info_to_name(underlying_type)
                )
            }
            TypeInfo::TypedefType { name, .. } => name.clone(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => self.type_info_to_name(underlying_type),
            TypeInfo::FunctionType { .. } => "function".to_string(),
            TypeInfo::UnknownType { name } => name.clone(),
            TypeInfo::OptimizedOut { name } => format!("<optimized_out> {name}"),
        }
    }

    /// Create computation steps for array access: base_address + (index * element_size)
    fn create_array_access_steps(
        &self,
        base_location: &LocationResult,
        element_size: u64,
        index: i64,
    ) -> Vec<ComputeStep> {
        let mut steps = Vec::new();

        // First, get the base address computation steps
        match base_location {
            LocationResult::Address(addr) => {
                steps.push(ComputeStep::PushConstant(*addr as i64));
            }
            LocationResult::RegisterAddress {
                register, offset, ..
            } => {
                steps.push(ComputeStep::LoadRegister(*register));
                if let Some(offset) = offset {
                    if *offset != 0 {
                        steps.push(ComputeStep::PushConstant(*offset));
                        steps.push(ComputeStep::Add);
                    }
                }
            }
            LocationResult::ComputedLocation { steps: base_steps } => {
                steps.extend(base_steps.clone());
            }
        }

        // Now add array indexing computation: current_address + (index * element_size)
        steps.push(ComputeStep::PushConstant(index)); // literal index
        steps.push(ComputeStep::PushConstant(element_size as i64)); // element_size
        steps.push(ComputeStep::Mul); // index * element_size
        steps.push(ComputeStep::Add); // base_address + (index * element_size)

        steps
    }
}

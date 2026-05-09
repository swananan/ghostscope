//! DWARF debugging information bridge
//!
//! This module handles integration with DWARF debug information for
//! variable type resolution and read-plan lowering.

use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_dwarf::{
    AddressOrigin, Availability, EntryValueCase, MemoryAccessSize, PlanExprOp, PlannedAddress,
    PlannedAddressKind, RuntimeComputedExpr, SectionType, TypeInfo, VariableAccessPath,
    VariableAccessSegment, VariableLocation, VariableMaterializationPlan, VariableReadPlan,
};
use ghostscope_process::module_probe;
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use tracing::{debug, warn};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    /// Compute a stable cookie for a module when per-PID offsets are unavailable (via coordinator).
    fn fallback_cookie_from_module_path(&self, module_path: &str) -> u64 {
        module_probe::cookie_for_path(module_path)
    }

    /// Compute section code for an address within a module (text=0, rodata=1, data=2, bss=3).
    fn section_code_for_address(&mut self, module_path: &str, link_addr: u64) -> u8 {
        if let Some(analyzer) = self.process_analyzer {
            if let Some(st) = analyzer.classify_section_for_address(module_path, link_addr) {
                return match st {
                    SectionType::Text => 0,
                    SectionType::Rodata => 1,
                    SectionType::Data => 2,
                    SectionType::Bss => 3,
                    _ => 2,
                };
            }
        }
        2
    }

    /// Compute cookie for module using coordinator policy.
    fn cookie_for_module_or_fallback(&mut self, module_path: &str) -> u64 {
        self.fallback_cookie_from_module_path(module_path)
    }
    /// Helper: unwrap typedef/qualified wrappers to the underlying type
    fn unwrap_type_aliases(mut t: &TypeInfo) -> &TypeInfo {
        loop {
            match t {
                TypeInfo::TypedefType {
                    underlying_type, ..
                } => t = underlying_type.as_ref(),
                TypeInfo::QualifiedType {
                    underlying_type, ..
                } => t = underlying_type.as_ref(),
                _ => break,
            }
        }
        t
    }

    /// Helper: determine if a DWARF type represents an aggregate (struct/union/array)
    fn is_aggregate_type(&self, t: &TypeInfo) -> bool {
        matches!(
            Self::unwrap_type_aliases(t),
            TypeInfo::StructType { .. } | TypeInfo::UnionType { .. } | TypeInfo::ArrayType { .. }
        )
    }
    fn planned_value_to_llvm_value(
        &mut self,
        value: &ghostscope_dwarf::PlannedValue,
        var_name: &str,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        let pt_regs_ptr = self.get_pt_regs_parameter()?;
        match value {
            ghostscope_dwarf::PlannedValue::Constant { value, .. } => Ok(self
                .context
                .i64_type()
                .const_int(*value as u64, true)
                .into()),
            ghostscope_dwarf::PlannedValue::RegisterValue { dwarf_reg, .. } => {
                debug!("Generating register value: {dwarf_reg}");
                self.load_register_value(*dwarf_reg, pt_regs_ptr)
            }
            ghostscope_dwarf::PlannedValue::RuntimeComputed { expr, result_size } => {
                debug!(
                    "Generating runtime-computed value: {} steps",
                    expr.ops().len()
                );
                let runtime_status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    status_ptr
                };
                self.generate_runtime_expr_ops(
                    expr.ops(),
                    pt_regs_ptr,
                    Some(*result_size),
                    runtime_status_ptr,
                    None,
                )
            }
            ghostscope_dwarf::PlannedValue::ImplicitBytes(bytes) => {
                debug!("Generating implicit value: {} bytes", bytes.len());
                let mut value: u64 = 0;
                for (i, &byte) in bytes.iter().enumerate().take(8) {
                    value |= (byte as u64) << (i * 8);
                }
                Ok(self.context.i64_type().const_int(value, false).into())
            }
            ghostscope_dwarf::PlannedValue::AddressValue { address, .. } => {
                debug!("Generating address direct value for variable: {var_name}");
                let runtime_status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    status_ptr
                };
                self.planned_address_to_llvm_address(address, runtime_status_ptr, None)
                    .map(Into::into)
            }
        }
    }

    pub fn planned_address_to_llvm_address(
        &mut self,
        address: &PlannedAddress,
        status_ptr: Option<PointerValue<'ctx>>,
        module_hint: Option<&str>,
    ) -> Result<IntValue<'ctx>> {
        let pt_regs_ptr = self.get_pt_regs_parameter()?;
        self.store_offsets_found_const(true)?;

        match address.origin {
            AddressOrigin::LinkTime => {
                let link_addr = address.constant_link_time_address().ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "read plan marked address as link-time without a constant address"
                            .to_string(),
                    )
                })?;
                self.runtime_address_from_link_time_address(link_addr, status_ptr, module_hint)
            }
            AddressOrigin::LinkTimeBase => {
                let (link_addr, tail_steps) =
                    address.link_time_base_and_runtime_tail().ok_or_else(|| {
                        CodeGenError::DwarfError(
                            "read plan marked address as link-time-base without a base address"
                                .to_string(),
                        )
                    })?;
                let runtime_base = self.runtime_address_from_link_time_address(
                    link_addr,
                    status_ptr,
                    module_hint,
                )?;
                let value = self.generate_runtime_expr_ops(
                    tail_steps,
                    pt_regs_ptr,
                    None,
                    status_ptr,
                    Some(runtime_base),
                )?;
                match value {
                    BasicValueEnum::IntValue(value) => Ok(value),
                    _ => Err(CodeGenError::LLVMError(
                        "Computed address did not produce integer".to_string(),
                    )),
                }
            }
            AddressOrigin::RuntimeDerived | AddressOrigin::Unknown => {
                self.planned_address_without_rebase(address, pt_regs_ptr, status_ptr)
            }
        }
    }

    fn planned_address_without_rebase(
        &mut self,
        address: &PlannedAddress,
        pt_regs_ptr: PointerValue<'ctx>,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<IntValue<'ctx>> {
        match &address.kind {
            PlannedAddressKind::Constant { address } => {
                Ok(self.context.i64_type().const_int(*address, false))
            }
            PlannedAddressKind::RegisterOffset { dwarf_reg, offset } => {
                let reg_val = self.load_register_value(*dwarf_reg, pt_regs_ptr)?;
                if let BasicValueEnum::IntValue(reg_i) = reg_val {
                    if *offset != 0 {
                        let ofs_val = self.context.i64_type().const_int(*offset as u64, true);
                        self.builder
                            .build_int_add(reg_i, ofs_val, "addr_with_offset")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))
                    } else {
                        Ok(reg_i)
                    }
                } else {
                    Err(CodeGenError::RegisterMappingError(
                        "Register value is not integer".to_string(),
                    ))
                }
            }
            PlannedAddressKind::RuntimeComputed { expr } => {
                self.runtime_expr_to_unrebased_address(expr, pt_regs_ptr, status_ptr)
            }
            PlannedAddressKind::FrameBaseRelative { .. } => Err(CodeGenError::NotImplemented(
                "Frame-base-relative planned address requires resolved frame base".to_string(),
            )),
        }
    }

    fn runtime_expr_to_unrebased_address(
        &mut self,
        expr: &RuntimeComputedExpr,
        pt_regs_ptr: PointerValue<'ctx>,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<IntValue<'ctx>> {
        let val =
            self.generate_runtime_expr_ops(expr.ops(), pt_regs_ptr, None, status_ptr, None)?;
        match val {
            BasicValueEnum::IntValue(value) => Ok(value),
            _ => Err(CodeGenError::LLVMError(
                "Computed address did not produce integer".to_string(),
            )),
        }
    }

    fn runtime_address_from_link_time_address(
        &mut self,
        link_addr: u64,
        status_ptr: Option<PointerValue<'ctx>>,
        module_hint: Option<&str>,
    ) -> Result<IntValue<'ctx>> {
        let ctx = self.get_compile_time_context()?;
        let module_for_offsets = module_hint
            .map(|s| s.to_string())
            .or_else(|| self.current_resolved_var_module_path.clone())
            .unwrap_or_else(|| ctx.module_path.clone());
        let st_code = self.section_code_for_address(&module_for_offsets, link_addr);
        let cookie = self.cookie_for_module_or_fallback(&module_for_offsets);
        let link_val = self.context.i64_type().const_int(link_addr, false);
        let (rt_addr, found_flag) =
            self.generate_runtime_address_from_offsets(link_val, st_code, cookie)?;
        self.store_offsets_unavailable_status(status_ptr, found_flag)?;
        self.store_offsets_found_flag(found_flag)?;
        self.current_resolved_var_module_path = None;
        Ok(rt_addr)
    }

    fn store_offsets_unavailable_status(
        &self,
        status_ptr: Option<PointerValue<'ctx>>,
        found_flag: IntValue<'ctx>,
    ) -> Result<()> {
        let Some(sp) = status_ptr else {
            return Ok(());
        };

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
                    .const_int(
                        ghostscope_protocol::VariableStatus::OffsetsUnavailable as u64,
                        false,
                    )
                    .into(),
                cur_status,
                "new_status",
            )
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        self.builder
            .build_store(sp, new_status)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(())
    }

    /// Convert DWARF type size to MemoryAccessSize
    fn dwarf_type_to_memory_access_size(&self, dwarf_type: &TypeInfo) -> MemoryAccessSize {
        MemoryAccessSize::from_size(dwarf_type.size())
    }

    fn is_signed_integer_type(dwarf_type: &TypeInfo) -> bool {
        match dwarf_type {
            TypeInfo::BaseType { encoding, .. } => {
                *encoding == ghostscope_dwarf::constants::DW_ATE_signed.0 as u16
                    || *encoding == ghostscope_dwarf::constants::DW_ATE_signed_char.0 as u16
            }
            TypeInfo::EnumType { base_type, .. } => Self::is_signed_integer_type(base_type),
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => Self::is_signed_integer_type(underlying_type),
            TypeInfo::TypedefType {
                underlying_type, ..
            }
            | TypeInfo::QualifiedType {
                underlying_type, ..
            } => Self::is_signed_integer_type(underlying_type),
            _ => false,
        }
    }

    fn sign_extend_memory_read_if_needed(
        &self,
        value: BasicValueEnum<'ctx>,
        dwarf_type: &TypeInfo,
        access_size: MemoryAccessSize,
    ) -> Result<BasicValueEnum<'ctx>> {
        if !Self::is_signed_integer_type(dwarf_type) || matches!(access_size, MemoryAccessSize::U64)
        {
            return Ok(value);
        }

        let int_value = value.into_int_value();
        let narrow_type = match access_size {
            MemoryAccessSize::U8 => self.context.i8_type(),
            MemoryAccessSize::U16 => self.context.i16_type(),
            MemoryAccessSize::U32 => self.context.i32_type(),
            MemoryAccessSize::U64 => unreachable!("U64 values do not need sign extension"),
        };
        let narrowed = self
            .builder
            .build_int_truncate(int_value, narrow_type, "signed_mem_trunc")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let extended = self
            .builder
            .build_int_s_extend(narrowed, self.context.i64_type(), "signed_mem_sext")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        Ok(extended.into())
    }

    pub(super) fn variable_read_plan_to_materialization(
        &self,
        plan: VariableReadPlan,
        pc_address: u64,
    ) -> Result<VariableMaterializationPlan> {
        let materialization = plan.materialization_plan(&self.compile_options.runtime_capabilities);
        if !materialization.availability.is_available()
            && materialization.availability != Availability::OptimizedOut
        {
            return Err(Self::dwarf_expression_unavailable_error(
                &materialization.name,
                &materialization.availability,
                pc_address,
            ));
        }

        if materialization.availability != Availability::OptimizedOut
            && matches!(
                materialization.materialization,
                ghostscope_dwarf::VariableMaterialization::UserMemoryRead { .. }
            )
        {
            materialization.dwarf_type.as_ref().ok_or_else(|| {
                CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
            })?;
        }

        Ok(materialization)
    }

    pub fn variable_materialization_to_llvm_value(
        &mut self,
        materialization: &VariableMaterializationPlan,
        pc_address: u64,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        match &materialization.materialization {
            ghostscope_dwarf::VariableMaterialization::DirectValue { value } => {
                self.planned_value_to_llvm_value(value, &materialization.name, status_ptr)
            }
            ghostscope_dwarf::VariableMaterialization::UserMemoryRead { address } => {
                let dwarf_type = materialization.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError(
                        "Expression has no DWARF type information".to_string(),
                    )
                })?;
                self.generate_memory_location_from_planned_address(address, dwarf_type, status_ptr)
            }
            ghostscope_dwarf::VariableMaterialization::Unavailable { availability } => {
                Err(Self::dwarf_expression_unavailable_error(
                    &materialization.name,
                    availability,
                    pc_address,
                ))
            }
            ghostscope_dwarf::VariableMaterialization::Composite { .. } => {
                Err(CodeGenError::DwarfError(format!(
                    "DWARF variable '{}' is split across pieces; piece reconstruction is not implemented",
                    materialization.name
                )))
            }
        }
    }

    pub(super) fn variable_read_plan_to_llvm_value(
        &mut self,
        plan: &VariableReadPlan,
        pc_address: u64,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        let materialized = self.variable_read_plan_to_materialization(plan.clone(), pc_address)?;
        self.variable_materialization_to_llvm_value(&materialized, pc_address, status_ptr)
    }

    pub(super) fn variable_read_plan_to_lvalue_address_with_hint(
        &mut self,
        plan: &VariableReadPlan,
        pc_address: u64,
        status_ptr: Option<PointerValue<'ctx>>,
        module_hint: Option<&str>,
    ) -> Result<IntValue<'ctx>> {
        if !plan.availability.is_available() {
            return Err(Self::dwarf_expression_unavailable_error(
                &plan.name,
                &plan.availability,
                pc_address,
            ));
        }

        let address = match &plan.location {
            VariableLocation::Address(_)
            | VariableLocation::RegisterAddress { .. }
            | VariableLocation::FrameBaseRelative { .. }
            | VariableLocation::ComputedAddress(_) => {
                PlannedAddress::from_location(plan.location.clone()).ok_or_else(|| {
                    CodeGenError::DwarfError(format!(
                        "DWARF variable '{}' has an address-backed location that could not be planned",
                        plan.name
                    ))
                })?
            }
            VariableLocation::OptimizedOut => {
                return Err(Self::dwarf_expression_unavailable_error(
                    &plan.name,
                    &Availability::OptimizedOut,
                    pc_address,
                ))
            }
            VariableLocation::Pieces(_) => {
                return Err(CodeGenError::DwarfError(format!(
                    "DWARF variable '{}' is split across pieces; piece reconstruction is not implemented",
                    plan.name
                )))
            }
            VariableLocation::AbsoluteAddressValue(_)
            | VariableLocation::RegisterValue { .. }
            | VariableLocation::ComputedValue(_)
            | VariableLocation::ImplicitValue(_) => {
                return Err(CodeGenError::DwarfError(format!(
                    "cannot take address of value-backed DWARF expression '{}'",
                    plan.name
                )))
            }
            VariableLocation::Unknown => {
                return Err(CodeGenError::DwarfError(format!(
                    "DWARF variable '{}' has unknown location",
                    plan.name
                )))
            }
        };

        self.planned_address_to_llvm_address(&address, status_ptr, module_hint)
    }

    fn generate_memory_location_from_planned_address(
        &mut self,
        address: &PlannedAddress,
        dwarf_type: &TypeInfo,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<BasicValueEnum<'ctx>> {
        let module_hint = self.current_resolved_var_module_path.clone();
        let runtime_status_ptr = if self.condition_context_active {
            Some(self.get_or_create_cond_error_global())
        } else {
            status_ptr
        };
        let addr = self.planned_address_to_llvm_address(
            address,
            runtime_status_ptr,
            module_hint.as_deref(),
        )?;

        if self.is_aggregate_type(dwarf_type) {
            let ptr_ty = self.context.ptr_type(inkwell::AddressSpace::default());
            let as_ptr = self
                .builder
                .build_int_to_ptr(addr, ptr_ty, "aggregate_addr_as_ptr")
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            return Ok(as_ptr.into());
        }

        let access_size = self.dwarf_type_to_memory_access_size(dwarf_type);
        let read_value = if self.condition_context_active {
            self.generate_memory_read_with_status(addr, access_size)
        } else {
            self.generate_memory_read(addr, access_size, status_ptr)
        }?;

        self.sign_extend_memory_read_if_needed(read_value, dwarf_type, access_size)
    }

    /// Execute a semantic runtime expression selected by DWARF read planning.
    fn generate_runtime_expr_ops(
        &mut self,
        ops: &[PlanExprOp],
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

        for op in ops {
            match op {
                PlanExprOp::LoadRegister(dwarf_reg) => {
                    let reg_value = self.load_register_value(*dwarf_reg, pt_regs_ptr)?;
                    if let BasicValueEnum::IntValue(int_val) = reg_value {
                        stack.push(int_val);
                    } else {
                        return Err(CodeGenError::RegisterMappingError(format!(
                            "Register {dwarf_reg} did not return integer value"
                        )));
                    }
                }

                PlanExprOp::PushConstant(value) => {
                    let const_val = self.context.i64_type().const_int(*value as u64, true);
                    stack.push(const_val);
                }

                PlanExprOp::Add => {
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

                PlanExprOp::Sub => {
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

                PlanExprOp::Mul => {
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

                PlanExprOp::Div => {
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

                PlanExprOp::And => {
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

                PlanExprOp::Or => {
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

                PlanExprOp::Xor => {
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

                PlanExprOp::Shl => {
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

                PlanExprOp::Shr => {
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

                PlanExprOp::Dereference { size } => {
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
                        let loaded_bv = if self.condition_context_active {
                            self.generate_memory_read_with_status(addr, access_size)?
                        } else {
                            self.generate_memory_read(addr, access_size, status_ptr)?
                        };
                        let loaded_int = if let BasicValueEnum::IntValue(int_val) = loaded_bv {
                            int_val
                        } else {
                            return Err(CodeGenError::LLVMError(
                                "Memory load did not return integer".to_string(),
                            ));
                        };
                        let value_block = self.builder.get_insert_block().ok_or_else(|| {
                            CodeGenError::LLVMError(
                                "No insertion block after dereference read".to_string(),
                            )
                        })?;
                        self.builder
                            .build_unconditional_branch(cont_bb)
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                        // Continue at cont: create PHI to merge null/read values, push once
                        self.builder.position_at_end(cont_bb);
                        let phi = self
                            .builder
                            .build_phi(self.context.i64_type(), "deref_phi")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        phi.add_incoming(&[(&null_val, null_bb), (&loaded_int, value_block)]);
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

                PlanExprOp::EntryValueLookup {
                    caller_pc_steps,
                    cases,
                } => {
                    let value = self.generate_entry_value_lookup(
                        caller_pc_steps,
                        cases,
                        pt_regs_ptr,
                        _result_size,
                        status_ptr,
                    )?;
                    stack.push(value);
                }

                // Add catch-all for unimplemented operations
                _ => {
                    warn!("Unimplemented runtime expression op: {:?}", op);
                    return Err(CodeGenError::NotImplemented(format!(
                        "runtime expression op {op:?} not yet implemented"
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

    fn generate_entry_value_lookup(
        &mut self,
        caller_pc_ops: &[PlanExprOp],
        cases: &[EntryValueCase],
        pt_regs_ptr: PointerValue<'ctx>,
        result_size: Option<MemoryAccessSize>,
        status_ptr: Option<PointerValue<'ctx>>,
    ) -> Result<IntValue<'ctx>> {
        if cases.is_empty() {
            return Err(CodeGenError::LLVMError(
                "EntryValueLookup requires at least one case".to_string(),
            ));
        }

        let caller_pc = self
            .generate_runtime_expr_ops(
                caller_pc_ops,
                pt_regs_ptr,
                Some(MemoryAccessSize::U64),
                status_ptr,
                None,
            )?
            .into_int_value();

        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("No insertion block for EntryValueLookup".to_string())
        })?;
        let current_fn = current_block.get_parent().ok_or_else(|| {
            CodeGenError::LLVMError("No parent function for EntryValueLookup".to_string())
        })?;
        let merge_bb = self
            .context
            .append_basic_block(current_fn, "entry_value_merge");
        let default_bb = self
            .context
            .append_basic_block(current_fn, "entry_value_default");

        let module_for_offsets = {
            let ctx = self.get_compile_time_context()?;
            self.current_resolved_var_module_path
                .clone()
                .unwrap_or_else(|| ctx.module_path.clone())
        };
        let module_cookie = self.cookie_for_module_or_fallback(&module_for_offsets);
        let mut incoming_values = Vec::with_capacity(cases.len() + 1);
        let mut any_missing_offsets = None;

        for (index, case) in cases.iter().enumerate() {
            let st_code = self.section_code_for_address(&module_for_offsets, case.caller_return_pc);
            let link_pc = self
                .context
                .i64_type()
                .const_int(case.caller_return_pc, false);
            let (runtime_return_pc, found_flag) =
                self.generate_runtime_address_from_offsets(link_pc, st_code, module_cookie)?;
            let missing_offsets = self
                .builder
                .build_not(found_flag, &format!("entry_value_missing_{index}"))
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            any_missing_offsets = Some(match any_missing_offsets {
                Some(prev) => self
                    .builder
                    .build_or(
                        prev,
                        missing_offsets,
                        &format!("entry_value_missing_or_{index}"),
                    )
                    .map_err(|e| CodeGenError::LLVMError(e.to_string()))?,
                None => missing_offsets,
            });

            let is_match = self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::EQ,
                    caller_pc,
                    runtime_return_pc,
                    &format!("entry_value_match_{index}"),
                )
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            let case_bb = self
                .context
                .append_basic_block(current_fn, &format!("entry_value_case_{index}"));
            let next_bb = if index + 1 == cases.len() {
                default_bb
            } else {
                self.context
                    .append_basic_block(current_fn, &format!("entry_value_check_{}", index + 1))
            };
            self.builder
                .build_conditional_branch(is_match, case_bb, next_bb)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

            self.builder.position_at_end(case_bb);
            let case_value = self
                .generate_runtime_expr_ops(
                    &case.value_steps,
                    pt_regs_ptr,
                    result_size,
                    status_ptr,
                    None,
                )?
                .into_int_value();
            let case_value_block = self.builder.get_insert_block().ok_or_else(|| {
                CodeGenError::LLVMError(
                    "No insertion block after EntryValueLookup case".to_string(),
                )
            })?;
            self.builder
                .build_unconditional_branch(merge_bb)
                .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
            incoming_values.push((case_value, case_value_block));

            self.builder.position_at_end(next_bb);
        }

        self.builder.position_at_end(default_bb);
        if let Some(sp) = status_ptr {
            self.store_variable_read_status(
                sp,
                self.context.bool_type().const_int(1, false),
                any_missing_offsets.unwrap_or_else(|| self.context.bool_type().const_zero()),
                "entry_value_default",
            )?;
        }
        let default_value = self.context.i64_type().const_zero();
        let default_value_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("No default block for EntryValueLookup".to_string())
        })?;
        self.builder
            .build_unconditional_branch(merge_bb)
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        incoming_values.push((default_value, default_value_block));

        self.builder.position_at_end(merge_bb);
        let phi = self
            .builder
            .build_phi(self.context.i64_type(), "entry_value_phi")
            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
        let incoming_refs: Vec<(&dyn inkwell::values::BasicValue<'ctx>, _)> = incoming_values
            .iter()
            .map(|(value, block)| (value as &dyn inkwell::values::BasicValue<'ctx>, *block))
            .collect();
        phi.add_incoming(&incoming_refs);

        Ok(phi.as_basic_value().into_int_value())
    }

    fn expand_dwarf_aliases(&self, expr: &crate::script::Expr) -> Result<crate::script::Expr> {
        fn expand_aliases(
            ctx: &crate::ebpf::context::EbpfContext<'_, '_>,
            e: &crate::script::Expr,
            visited: &mut std::collections::HashSet<String>,
            depth: usize,
        ) -> std::result::Result<crate::script::Expr, super::context::CodeGenError> {
            use crate::script::Expr as E;
            const MAX_DEPTH: usize = 64;
            if depth > MAX_DEPTH {
                return Err(super::context::CodeGenError::TypeError(
                    "alias expansion depth exceeded (cycle?)".to_string(),
                ));
            }
            Ok(match e {
                E::Variable(name) => {
                    if ctx.alias_variable_exists(name) {
                        if !visited.insert(name.clone()) {
                            return Err(super::context::CodeGenError::TypeError(format!(
                                "alias cycle detected for '{name}'"
                            )));
                        }
                        if let Some(t) = ctx.get_alias_variable(name) {
                            let res = expand_aliases(ctx, &t, visited, depth + 1)?;
                            visited.remove(name);
                            res
                        } else {
                            e.clone()
                        }
                    } else {
                        e.clone()
                    }
                }
                E::MemberAccess(obj, field) => {
                    let base = expand_aliases(ctx, obj, visited, depth + 1)?;
                    E::MemberAccess(Box::new(base), field.clone())
                }
                E::ArrayAccess(arr, idx) => {
                    let base = expand_aliases(ctx, arr, visited, depth + 1)?;
                    let idx2 = expand_aliases(ctx, idx, visited, depth + 1)?;
                    E::ArrayAccess(Box::new(base), Box::new(idx2))
                }
                E::PointerDeref(inner) => {
                    let in2 = expand_aliases(ctx, inner, visited, depth + 1)?;
                    E::PointerDeref(Box::new(in2))
                }
                E::AddressOf(inner) => {
                    let in2 = expand_aliases(ctx, inner, visited, depth + 1)?;
                    E::AddressOf(Box::new(in2))
                }
                E::ChainAccess(chain) => {
                    if chain.is_empty() {
                        return Ok(e.clone());
                    }
                    let head = &chain[0];
                    if ctx.alias_variable_exists(head) {
                        if !visited.insert(head.clone()) {
                            return Err(super::context::CodeGenError::TypeError(format!(
                                "alias cycle detected for '{head}'"
                            )));
                        }
                        if let Some(alias_expr) = ctx.get_alias_variable(head) {
                            let mut acc = expand_aliases(ctx, &alias_expr, visited, depth + 1)?;
                            for seg in &chain[1..] {
                                acc = E::MemberAccess(Box::new(acc), seg.clone());
                            }
                            visited.remove(head);
                            acc
                        } else {
                            e.clone()
                        }
                    } else {
                        e.clone()
                    }
                }
                E::BuiltinCall { name, args } => E::BuiltinCall {
                    name: name.clone(),
                    args: args
                        .iter()
                        .map(|a| expand_aliases(ctx, a, visited, depth + 1))
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                },
                E::BinaryOp { left, op, right } => E::BinaryOp {
                    left: Box::new(expand_aliases(ctx, left, visited, depth + 1)?),
                    op: op.clone(),
                    right: Box::new(expand_aliases(ctx, right, visited, depth + 1)?),
                },
                _ => e.clone(),
            })
        }

        let mut visited = std::collections::HashSet::new();
        expand_aliases(self, expr, &mut visited, 0)
    }

    pub(super) fn query_dwarf_for_complex_expr_plan(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<Option<VariableReadPlan>> {
        use crate::script::Expr;

        let expanded = self.expand_dwarf_aliases(expr)?;
        match &expanded {
            Expr::Variable(var_name) => self.query_dwarf_for_variable_plan(var_name),
            Expr::MemberAccess(_, _)
            | Expr::ArrayAccess(_, _)
            | Expr::ChainAccess(_)
            | Expr::PointerDeref(_) => {
                if let Some((base, access_path)) = Self::access_path_from_expr(&expanded)? {
                    self.query_dwarf_for_pc_access_plan(&base, &access_path)
                } else {
                    Ok(None)
                }
            }
            _ => Ok(None),
        }
    }

    /// Query DWARF for complex expression (supports member access, array access, etc.)
    pub fn query_dwarf_for_complex_expr(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<Option<VariableReadPlan>> {
        self.query_dwarf_for_complex_expr_plan(expr)
    }

    /// Query DWARF for a PC-sensitive local variable read plan.
    fn query_dwarf_for_variable_plan(
        &mut self,
        var_name: &str,
    ) -> Result<Option<VariableReadPlan>> {
        let context = self.get_compile_time_context()?;
        let pc_address = context.pc_address;
        let module_path = context.module_path.clone();

        debug!(
            "Querying DWARF variable plan for '{}' at PC 0x{:x} in module '{}'",
            var_name, pc_address, module_path
        );

        let analyzer = self
            .process_analyzer
            .ok_or_else(|| CodeGenError::DwarfError("No DWARF analyzer available".to_string()))?;
        let prefer_module = std::path::PathBuf::from(module_path);
        let module_address =
            ghostscope_dwarf::ModuleAddress::new(prefer_module.clone(), pc_address);

        let pc_plan = match analyzer.resolve_pc(&module_address) {
            Ok(pc_context) => match analyzer.plan_variable_by_name(&pc_context, var_name) {
                Ok(Some(plan)) => {
                    debug!("Found DWARF variable '{}' via PC variable plan", var_name);
                    Some(plan)
                }
                Ok(None) => {
                    debug!(
                        "Variable '{}' not found in PC variable plan; trying global read plan",
                        var_name
                    );
                    None
                }
                Err(err) => {
                    let message = err.to_string();
                    if message.starts_with("Ambiguous variable")
                        || message.starts_with("Unavailable variable")
                    {
                        return Err(CodeGenError::DwarfError(message));
                    }
                    debug!(
                        "PC variable plan lookup error for '{}': {message}; trying global read plan",
                        var_name
                    );
                    None
                }
            },
            Err(err) => {
                debug!(
                    "PC context resolution failed for '{}': {err}; trying global read plan",
                    var_name
                );
                None
            }
        };

        if pc_plan.is_some() {
            return Ok(pc_plan);
        }

        if let Some((global_module, plan)) = analyzer
            .plan_global_access_read_plan(&prefer_module, var_name, &VariableAccessPath::default())
            .map_err(|err| CodeGenError::DwarfError(err.to_string()))?
        {
            debug!("Found DWARF global '{}' via variable read plan", var_name);
            self.current_resolved_var_module_path =
                Some(global_module.to_string_lossy().to_string());
            return Ok(Some(plan));
        }

        debug!("Variable '{var_name}' not found in read plans");
        Ok(None)
    }

    /// Query DWARF for variable information
    pub fn query_dwarf_for_variable(&mut self, var_name: &str) -> Result<Option<VariableReadPlan>> {
        let context = self.get_compile_time_context()?;
        let pc_address = context.pc_address;

        debug!(
            "Querying DWARF for variable '{}' at PC 0x{:x} in module '{}'",
            var_name, pc_address, context.module_path
        );

        self.query_dwarf_for_variable_plan(var_name)
    }

    fn query_dwarf_for_pc_access_plan(
        &mut self,
        base_name: &str,
        access_path: &VariableAccessPath,
    ) -> Result<Option<VariableReadPlan>> {
        if access_path.segments.is_empty() {
            return self.query_dwarf_for_variable_plan(base_name);
        }

        let path_text = Self::access_path_to_string(base_name, access_path);
        let context = self.get_compile_time_context()?;
        let pc_address = context.pc_address;
        let module_path = context.module_path.clone();
        let prefer_module = std::path::PathBuf::from(module_path.clone());
        let analyzer = self
            .process_analyzer
            .ok_or_else(|| CodeGenError::DwarfError("No DWARF analyzer available".to_string()))?;
        let module_address =
            ghostscope_dwarf::ModuleAddress::new(prefer_module.clone(), pc_address);

        match analyzer.resolve_pc(&module_address) {
            Ok(pc_context) => {
                match analyzer.plan_variable_access_by_name(&pc_context, base_name, access_path) {
                    Ok(Some(plan)) => {
                        debug!("Found DWARF access '{path_text}' via PC variable access plan");
                        return Ok(Some(plan));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        let message = err.to_string();
                        debug!(
                            "PC variable access plan lookup failed for '{path_text}': {message}"
                        );
                        return Err(CodeGenError::DwarfError(message));
                    }
                }
            }
            Err(err) => {
                debug!(
                    "PC context resolution failed for '{path_text}': {err}; trying global read plan"
                );
            }
        }

        if let Some((module_path, plan)) = analyzer
            .plan_global_access_read_plan(&prefer_module, base_name, access_path)
            .map_err(|err| CodeGenError::DwarfError(err.to_string()))?
        {
            debug!("Found DWARF global access '{path_text}' via variable read plan");
            self.current_resolved_var_module_path = Some(module_path.to_string_lossy().to_string());
            return Ok(Some(plan));
        }

        Ok(None)
    }

    fn access_path_to_string(base_name: &str, access_path: &VariableAccessPath) -> String {
        let mut out = base_name.to_string();
        for segment in &access_path.segments {
            match segment {
                VariableAccessSegment::Field(field) => {
                    out.push('.');
                    out.push_str(field);
                }
                VariableAccessSegment::ArrayIndex(index) => {
                    out.push('[');
                    out.push_str(&index.to_string());
                    out.push(']');
                }
                VariableAccessSegment::Dereference => {
                    out.push_str(".*");
                }
            }
        }
        out
    }

    fn access_path_from_expr(
        expr: &crate::script::Expr,
    ) -> Result<Option<(String, VariableAccessPath)>> {
        fn append_segments(
            expr: &crate::script::Expr,
            segments: &mut Vec<VariableAccessSegment>,
        ) -> Result<Option<String>> {
            match expr {
                crate::script::Expr::Variable(name) => Ok(Some(name.clone())),
                crate::script::Expr::ChainAccess(chain) => {
                    let Some(base) = chain.first() else {
                        return Ok(None);
                    };
                    segments.extend(chain[1..].iter().cloned().map(VariableAccessSegment::Field));
                    Ok(Some(base.clone()))
                }
                crate::script::Expr::MemberAccess(obj, field) => {
                    let Some(base) = append_segments(obj, segments)? else {
                        return Ok(None);
                    };
                    segments.push(VariableAccessSegment::Field(field.clone()));
                    Ok(Some(base))
                }
                crate::script::Expr::ArrayAccess(array, index) => {
                    let Some(base) = append_segments(array, segments)? else {
                        return Ok(None);
                    };
                    let crate::script::Expr::Int(index) = index.as_ref() else {
                        return Err(CodeGenError::NotImplemented(
                            "Only literal integer array indices are supported (TODO)".to_string(),
                        ));
                    };
                    segments.push(VariableAccessSegment::ArrayIndex(*index));
                    Ok(Some(base))
                }
                crate::script::Expr::PointerDeref(inner) => {
                    let Some(base) = append_segments(inner, segments)? else {
                        return Ok(None);
                    };
                    segments.push(VariableAccessSegment::Dereference);
                    Ok(Some(base))
                }
                _ => Ok(None),
            }
        }

        let mut segments = Vec::new();
        let Some(base) = append_segments(expr, &mut segments)? else {
            return Ok(None);
        };
        Ok(Some((base, VariableAccessPath::new(segments))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::script::Expr;
    use ghostscope_dwarf::AddressExpr;
    use ghostscope_dwarf::PlanExprOp;
    use ghostscope_dwarf::Provenance;
    use inkwell::context::Context as LlvmContext;

    fn read_plan(
        name: &str,
        type_name: &str,
        dwarf_type: Option<TypeInfo>,
        location: VariableLocation,
        availability: Availability,
    ) -> VariableReadPlan {
        VariableReadPlan {
            name: name.to_string(),
            type_name: type_name.to_string(),
            access_path: VariableAccessPath::default(),
            dwarf_type,
            declaration: None,
            type_id: None,
            location,
            availability,
            scope_depth: 0,
            is_parameter: false,
            is_artificial: false,
            pc_range: None,
            inline_context: None,
            provenance: Provenance::DirectDie,
        }
    }

    #[test]
    fn access_path_from_expr_flattens_member_array_member_paths() {
        let expr = Expr::MemberAccess(
            Box::new(Expr::ArrayAccess(
                Box::new(Expr::MemberAccess(
                    Box::new(Expr::Variable("request".to_string())),
                    "headers".to_string(),
                )),
                Box::new(Expr::Int(2)),
            )),
            "len".to_string(),
        );

        let (base, path) = EbpfContext::<'static, 'static>::access_path_from_expr(&expr)
            .expect("access path should parse")
            .expect("expression should be flattenable");

        assert_eq!(base, "request");
        assert_eq!(
            path.segments,
            vec![
                VariableAccessSegment::Field("headers".to_string()),
                VariableAccessSegment::ArrayIndex(2),
                VariableAccessSegment::Field("len".to_string()),
            ]
        );
        assert_eq!(
            EbpfContext::<'static, 'static>::access_path_to_string(&base, &path),
            "request.headers[2].len"
        );
    }

    #[test]
    fn access_path_from_expr_rejects_dynamic_array_index() {
        let expr = Expr::ArrayAccess(
            Box::new(Expr::Variable("items".to_string())),
            Box::new(Expr::Variable("idx".to_string())),
        );

        let err = EbpfContext::<'static, 'static>::access_path_from_expr(&expr)
            .expect_err("dynamic array index should be rejected");

        assert!(matches!(err, CodeGenError::NotImplemented(_)));
        assert!(err.to_string().contains("literal integer array indices"));
    }

    #[test]
    fn access_path_from_expr_flattens_pointer_deref_segments() {
        let expr = Expr::MemberAccess(
            Box::new(Expr::PointerDeref(Box::new(Expr::MemberAccess(
                Box::new(Expr::Variable("request".to_string())),
                "current".to_string(),
            )))),
            "state".to_string(),
        );

        let (base, path) = EbpfContext::<'static, 'static>::access_path_from_expr(&expr)
            .expect("access path should parse")
            .expect("expression should be flattenable");

        assert_eq!(base, "request");
        assert_eq!(
            path.segments,
            vec![
                VariableAccessSegment::Field("current".to_string()),
                VariableAccessSegment::Dereference,
                VariableAccessSegment::Field("state".to_string()),
            ]
        );
        assert_eq!(
            EbpfContext::<'static, 'static>::access_path_to_string(&base, &path),
            "request.current.*.state"
        );
    }

    #[test]
    fn aggregate_address_returns_pointer_for_struct_and_array() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "agg_ptr", Some(0), &opts).expect("ctx");
        // Ensure we have a function/pt_regs to satisfy builders
        ctx.create_basic_ebpf_function("f").expect("fn");
        // Ensure the ASLR offsets map exists in the module for unified codegen path
        ctx.__test_ensure_proc_offsets_map().expect("map");
        // Allocate per-invocation pm_key on the stack
        ctx.__test_alloc_pm_key().expect("pm_key");
        // Provide a minimal compile-time context so address rebasing has a module path
        ctx.set_compile_time_context(0, "/nonexistent/module".to_string());

        // Struct type
        let st = ghostscope_protocol::TypeInfo::StructType {
            name: "S".to_string(),
            size: 80,
            members: vec![],
        };
        let location = VariableLocation::Address(AddressExpr::constant(0x1000));
        let plan = read_plan(
            "S",
            "S",
            Some(st),
            location.clone(),
            Availability::Available,
        );
        let v = ctx
            .variable_read_plan_to_llvm_value(&plan, 0, None)
            .expect("eval");
        match v {
            BasicValueEnum::PointerValue(_) => {}
            other => panic!("expected PointerValue for struct, got {other:?}"),
        }

        // Array type
        let arr = ghostscope_protocol::TypeInfo::ArrayType {
            element_type: Box::new(ghostscope_protocol::TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
            }),
            element_count: Some(4),
            total_size: Some(16),
        };
        let plan = read_plan("A", "int[4]", Some(arr), location, Availability::Available);
        let v2 = ctx
            .variable_read_plan_to_llvm_value(&plan, 0, None)
            .expect("eval2");
        match v2 {
            BasicValueEnum::PointerValue(_) => {}
            other => panic!("expected PointerValue for array, got {other:?}"),
        }
    }

    #[test]
    fn scalar_address_reads_value() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "scalar_val", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");
        // Ensure the ASLR offsets map exists in the module for unified codegen path
        ctx.__test_ensure_proc_offsets_map().expect("map");
        // Allocate per-invocation pm_key on the stack
        ctx.__test_alloc_pm_key().expect("pm_key");
        // Provide a minimal compile-time context so address rebasing has a module path
        ctx.set_compile_time_context(0, "/nonexistent/module".to_string());

        // Base int type
        let bt = ghostscope_protocol::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let location = VariableLocation::Address(AddressExpr::constant(0x2000));
        let plan = read_plan("x", "int", Some(bt), location, Availability::Available);
        let v = ctx
            .variable_read_plan_to_llvm_value(&plan, 0, None)
            .expect("eval");
        match v {
            BasicValueEnum::IntValue(_) => {}
            other => panic!("expected IntValue for scalar, got {other:?}"),
        }
        assert!(
            ctx.module.get_global("_temp_read_buffer_4").is_none(),
            "scalar reads should use per-invocation scratch, not shared temp globals"
        );
    }

    #[test]
    fn absolute_address_value_lowers_as_rebased_direct_value() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "abs_addr_value", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");
        ctx.__test_ensure_proc_offsets_map().expect("map");
        ctx.__test_alloc_pm_key().expect("pm_key");
        ctx.set_compile_time_context(0, "/nonexistent/module".to_string());

        let ptr_ty = ghostscope_protocol::TypeInfo::PointerType {
            target_type: Box::new(ghostscope_protocol::TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
            }),
            size: 8,
        };
        let location = VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x2000));
        let plan = read_plan(
            "ptr",
            "int*",
            Some(ptr_ty),
            location,
            Availability::Available,
        );

        let value = ctx
            .variable_read_plan_to_llvm_value(&plan, 0, None)
            .expect("absolute address value should lower");
        assert!(matches!(value, BasicValueEnum::IntValue(_)));
    }

    #[test]
    fn optimized_result_is_rejected_as_unavailable_value() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "optimized_value", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");

        let ty = ghostscope_protocol::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let plan = read_plan(
            "x",
            "int",
            Some(ty),
            VariableLocation::OptimizedOut,
            Availability::OptimizedOut,
        );

        let err = ctx
            .variable_read_plan_to_llvm_value(&plan, 0x1234, None)
            .expect_err("optimized value should not lower to a placeholder");

        assert!(
            matches!(err, CodeGenError::VariableUnavailable(_)),
            "unexpected error: {err:?}"
        );
        assert!(err.to_string().contains("optimized out"));
        assert!(err.to_string().contains("0x1234"));
    }

    #[test]
    fn piece_locations_are_rejected_instead_of_using_first_piece() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "piece_value", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");

        let ty = ghostscope_protocol::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let location = VariableLocation::Pieces(vec![ghostscope_dwarf::PieceLocation {
            bit_offset: 0,
            bit_size: 32,
            location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
        }]);
        let plan = read_plan("split", "int", Some(ty), location, Availability::Available);

        let err = ctx
            .variable_read_plan_to_llvm_value(&plan, 0x1234, None)
            .expect_err("split pieces should not silently use the first piece");

        assert!(matches!(err, CodeGenError::DwarfError(_)));
        assert!(err.to_string().contains("split across pieces"));
    }

    #[test]
    fn unavailable_error_formats_structured_dwarf_reason() {
        let err = EbpfContext::dwarf_expression_unavailable_error(
            "x",
            &Availability::Unsupported(ghostscope_dwarf::UnsupportedReason::ExpressionShape {
                detail: "estimated BPF stack use 64 bytes exceeds capability limit 16".to_string(),
            }),
            0xbeef,
        );
        let message = err.to_string();

        assert!(matches!(err, CodeGenError::VariableUnavailable(_)));
        assert!(message.contains("unsupported DWARF expression shape"));
        assert!(message.contains("estimated BPF stack use 64 bytes"));
        assert!(!message.contains("ExpressionShape"));
    }

    #[test]
    fn unavailable_error_formats_runtime_requirement() {
        let err = EbpfContext::dwarf_expression_unavailable_error(
            "ptr",
            &Availability::Requires(ghostscope_dwarf::RuntimeRequirement::UserMemoryRead),
            0xcafe,
        );
        let message = err.to_string();

        assert!(matches!(err, CodeGenError::VariableUnavailable(_)));
        assert!(message.contains("user-memory read support"));
        assert!(!message.contains("UserMemoryRead"));
    }

    #[test]
    fn read_plan_lowering_uses_compile_option_runtime_capabilities() {
        let llctx = LlvmContext::create();
        let mut opts = crate::CompileOptions::default();
        opts.runtime_capabilities.max_bpf_stack_bytes = 0;
        let ctx = EbpfContext::new(&llctx, "runtime_caps", Some(0), &opts).expect("ctx");
        let dwarf_type = ghostscope_protocol::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let plan = VariableReadPlan {
            name: "x".to_string(),
            type_name: "int".to_string(),
            access_path: VariableAccessPath::default(),
            dwarf_type: Some(dwarf_type),
            declaration: None,
            type_id: None,
            location: VariableLocation::Address(AddressExpr::constant(0x1000)),
            availability: Availability::Available,
            scope_depth: 0,
            is_parameter: false,
            is_artificial: false,
            pc_range: None,
            inline_context: None,
            provenance: Provenance::DirectDie,
        };

        let err = ctx
            .variable_read_plan_to_materialization(plan, 0x1234)
            .expect_err("zero stack capability should reject the read plan");

        assert!(matches!(err, CodeGenError::VariableUnavailable(_)));
        assert!(err.to_string().contains("capability limit 0"));
    }

    #[test]
    fn optimized_out_read_plan_preserves_marker_conversion() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let ctx = EbpfContext::new(&llctx, "optimized_marker", Some(0), &opts).expect("ctx");
        let dwarf_type = ghostscope_protocol::TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
        };
        let plan = VariableReadPlan {
            name: "x".to_string(),
            type_name: "int".to_string(),
            access_path: VariableAccessPath::default(),
            dwarf_type: Some(dwarf_type),
            declaration: None,
            type_id: None,
            location: VariableLocation::OptimizedOut,
            availability: Availability::OptimizedOut,
            scope_depth: 0,
            is_parameter: false,
            is_artificial: false,
            pc_range: None,
            inline_context: None,
            provenance: Provenance::DirectDie,
        };

        let materialized = ctx
            .variable_read_plan_to_materialization(plan, 0x1234)
            .expect("optimized-out runtime metadata should remain printable");
        assert_eq!(materialized.availability, Availability::OptimizedOut);
        assert!(matches!(
            materialized.materialization,
            ghostscope_dwarf::VariableMaterialization::Unavailable {
                availability: Availability::OptimizedOut
            }
        ));
    }

    #[test]
    fn computed_location_supports_dereference_before_trailing_arithmetic() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "computed_addr", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");
        ctx.__test_ensure_proc_offsets_map().expect("map");
        ctx.__test_alloc_pm_key().expect("pm_key");
        ctx.set_compile_time_context(0, "/nonexistent/module".to_string());

        let location = VariableLocation::ComputedAddress(vec![
            PlanExprOp::PushConstant(0x3000),
            PlanExprOp::Dereference {
                size: MemoryAccessSize::U64,
            },
            PlanExprOp::PushConstant(16),
            PlanExprOp::Add,
        ]);

        let address = PlannedAddress::from_location(location)
            .expect("computed location should materialize as a planned address");
        let addr = ctx
            .planned_address_to_llvm_address(&address, None, None)
            .expect("computed address with mid-stream dereference should compile");
        assert_eq!(addr.get_type().get_bit_width(), 64);
    }

    #[test]
    fn lvalue_address_read_plan_does_not_require_dwarf_type() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "untyped_lvalue_addr", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");
        ctx.__test_ensure_proc_offsets_map().expect("map");
        ctx.__test_alloc_pm_key().expect("pm_key");
        ctx.set_compile_time_context(0x1234, "/nonexistent/module".to_string());

        let plan = read_plan(
            "untyped",
            "<unknown>",
            None,
            VariableLocation::Address(AddressExpr::constant(0x1000)),
            Availability::Available,
        );

        let addr = ctx
            .variable_read_plan_to_lvalue_address_with_hint(&plan, 0x1234, None, None)
            .expect("address-only read plan should not require DWARF type info");

        assert_eq!(addr.get_type().get_bit_width(), 64);
    }

    #[test]
    fn lvalue_address_rejects_absolute_address_values() {
        let llctx = LlvmContext::create();
        let opts = crate::CompileOptions::default();
        let mut ctx = EbpfContext::new(&llctx, "value_backed_lvalue", Some(0), &opts).expect("ctx");
        ctx.create_basic_ebpf_function("f").expect("fn");

        let ty = ghostscope_protocol::TypeInfo::PointerType {
            target_type: Box::new(ghostscope_protocol::TypeInfo::BaseType {
                name: "int".to_string(),
                size: 4,
                encoding: ghostscope_dwarf::constants::DW_ATE_signed.0 as u16,
            }),
            size: 8,
        };
        let plan = read_plan(
            "ptr",
            "int*",
            Some(ty),
            VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x2000)),
            Availability::Available,
        );

        let err = ctx
            .variable_read_plan_to_lvalue_address_with_hint(&plan, 0x1234, None, None)
            .expect_err("value-backed locations should not support address-of");

        assert!(matches!(err, CodeGenError::DwarfError(_)));
        assert!(err.to_string().contains("value-backed"));
    }
}

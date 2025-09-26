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
                self.generate_compute_steps(steps, pt_regs_ptr, Some(*result_size))
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
                let addr_value = self.generate_compute_steps(steps, pt_regs_ptr, None)?;
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
    ) -> Result<BasicValueEnum<'ctx>> {
        // Implement stack-based computation
        let mut stack: Vec<IntValue<'ctx>> = Vec::new();

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
                        let result = self
                            .builder
                            .build_int_add(a, b, "add")
                            .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                        stack.push(result);
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
                        let access_size = *size;
                        let loaded_value = self.generate_memory_read(addr, access_size)?;
                        if let BasicValueEnum::IntValue(int_val) = loaded_value {
                            stack.push(int_val);
                        } else {
                            return Err(CodeGenError::LLVMError(
                                "Memory load did not return integer".to_string(),
                            ));
                        }
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
                if let Some(var_result) = vars.iter().find(|v| v.name == var_name) {
                    debug!("Found DWARF variable: {}", var_name);
                    Ok(Some(var_result.clone()))
                } else {
                    debug!("Variable '{}' not found in DWARF info", var_name);
                    Ok(None)
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
        // First, resolve the base object
        let base_var = match self.query_dwarf_for_complex_expr(obj_expr)? {
            Some(var) => var,
            None => return Ok(None),
        };

        // Get the object's type
        let obj_type = match &base_var.dwarf_type {
            Some(type_info) => type_info,
            None => return Ok(None),
        };

        // Find the member in the struct type
        let member_info = self.find_struct_member(obj_type, field_name)?;
        let member_info = match member_info {
            Some(info) => info,
            None => return Ok(None),
        };

        // Create a new VariableWithEvaluation for the member
        let member_var = VariableWithEvaluation {
            name: format!("{}.{}", self.expr_to_string(obj_expr), field_name),
            type_name: self.type_info_to_name(&member_info.member_type),
            dwarf_type: Some(member_info.member_type.clone()),
            evaluation_result: self
                .compute_member_address(&base_var.evaluation_result, member_info.offset)?,
            scope_depth: base_var.scope_depth,
            is_parameter: false,
            is_artificial: false,
        };

        Ok(Some(member_var))
    }

    /// Query DWARF for array access (arr[index])
    pub fn query_dwarf_for_array_access(
        &mut self,
        array_expr: &crate::script::Expr,
        _index_expr: &crate::script::Expr,
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

        // For dynamic indexing, we need to create a computed location that includes offset calculation
        // The evaluation result should represent: base_address + (index * element_size)
        let element_evaluation_result = match &base_var.evaluation_result {
            EvaluationResult::DirectValue(_) => {
                // If base is a value, we can't do array indexing
                return Ok(None);
            }
            EvaluationResult::MemoryLocation(location) => {
                // Create a computed location that includes the array indexing calculation
                let array_access_steps = self.create_array_access_steps(location, element_size);
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

        // Start with the first variable in the chain
        let mut current_var = match self.query_dwarf_for_variable(&chain[0])? {
            Some(var) => var,
            None => return Ok(None),
        };

        // Follow the chain for remaining members
        for field_name in chain.iter().skip(1) {
            let current_type = match &current_var.dwarf_type {
                Some(type_info) => type_info,
                None => return Ok(None),
            };

            let member_info = self.find_struct_member(current_type, field_name)?;
            let member_info = match member_info {
                Some(info) => info,
                None => return Ok(None),
            };

            // Update current_var to point to the member
            current_var = VariableWithEvaluation {
                name: format!("{}.{}", current_var.name, field_name),
                type_name: self.type_info_to_name(&member_info.member_type),
                dwarf_type: Some(member_info.member_type.clone()),
                evaluation_result: self
                    .compute_member_address(&current_var.evaluation_result, member_info.offset)?,
                scope_depth: current_var.scope_depth,
                is_parameter: false,
                is_artificial: false,
            };
        }

        Ok(Some(current_var))
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
        let pointed_type = match ptr_type {
            TypeInfo::PointerType { target_type, .. } => target_type.as_ref().clone(),
            _ => return Ok(None), // Not a pointer type
        };

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

    /// Helper: Find struct member information by name
    #[allow(clippy::only_used_in_recursion)]
    fn find_struct_member(
        &self,
        type_info: &TypeInfo,
        field_name: &str,
    ) -> Result<Option<StructMemberInfo>> {
        match type_info {
            TypeInfo::StructType { members, .. } => {
                for member in members {
                    if member.name == field_name {
                        return Ok(Some(StructMemberInfo {
                            offset: member.offset,
                            member_type: member.member_type.clone(),
                        }));
                    }
                }
                Ok(None)
            }
            // Handle typedef/qualified types by following the underlying type
            TypeInfo::TypedefType {
                underlying_type, ..
            } => self.find_struct_member(underlying_type, field_name),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => self.find_struct_member(underlying_type, field_name),
            _ => Ok(None),
        }
    }

    /// Helper: Compute member address by adding offset to base address
    fn compute_member_address(
        &self,
        base_result: &EvaluationResult,
        member_offset: u64,
    ) -> Result<EvaluationResult> {
        use ghostscope_dwarf::{ComputeStep, LocationResult};

        match base_result {
            EvaluationResult::MemoryLocation(LocationResult::Address(base_addr)) => {
                // Simple case: base is absolute address
                Ok(EvaluationResult::MemoryLocation(LocationResult::Address(
                    base_addr + member_offset,
                )))
            }
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                size,
            }) => {
                // Add member offset to existing register offset
                let new_offset = offset.unwrap_or(0) + member_offset as i64;
                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::RegisterAddress {
                        register: *register,
                        offset: Some(new_offset),
                        size: *size,
                    },
                ))
            }
            // For computed locations, add offset to the computation
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                let mut new_steps = steps.clone();
                new_steps.push(ComputeStep::PushConstant(member_offset as i64));
                new_steps.push(ComputeStep::Add);
                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::ComputedLocation { steps: new_steps },
                ))
            }
            // For direct values, we can't compute member access
            _ => Err(CodeGenError::NotImplemented(
                "Member access on direct values not supported".to_string(),
            )),
        }
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
            // If the pointer is a direct value, use it as an address
            EvaluationResult::DirectValue(_) => {
                // The pointer value itself becomes the address to read from
                // This is complex to implement generically, return error for now
                Err(CodeGenError::NotImplemented(
                    "Pointer dereference of direct values not yet implemented".to_string(),
                ))
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
        // Note: For now, we assume index is 0 as a placeholder.
        // In a full implementation, the index would need to be evaluated at runtime.
        // This is a simplified version that assumes constant index of 0.
        steps.push(ComputeStep::PushConstant(0)); // index (placeholder)
        steps.push(ComputeStep::PushConstant(element_size as i64)); // element_size
        steps.push(ComputeStep::Mul); // index * element_size
        steps.push(ComputeStep::Add); // base_address + (index * element_size)

        steps
    }
}

/// Information about a struct member
#[derive(Debug, Clone)]
struct StructMemberInfo {
    offset: u64,
    member_type: TypeInfo,
}

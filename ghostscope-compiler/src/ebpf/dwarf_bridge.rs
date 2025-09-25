//! DWARF debugging information bridge
//!
//! This module handles integration with DWARF debug information for
//! variable type resolution and evaluation result processing.

use super::context::{CodeGenError, EbpfContext, Result};
use ghostscope_dwarf::{
    ComputeStep, DirectValueResult, DwarfType, EvaluationResult, LocationResult, MemoryAccessSize,
    VariableWithEvaluation,
};
use ghostscope_protocol::TypeEncoding;
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use tracing::{debug, warn};

impl<'ctx> EbpfContext<'ctx> {
    /// Convert EvaluationResult to LLVM value
    pub fn evaluate_result_to_llvm_value(
        &mut self,
        evaluation_result: &EvaluationResult,
        dwarf_type: &DwarfType,
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
    fn dwarf_type_to_memory_access_size(&self, dwarf_type: &DwarfType) -> MemoryAccessSize {
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
        dwarf_type: &DwarfType,
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

    /// Convert DWARF type to protocol encoding
    #[allow(clippy::only_used_in_recursion)]
    pub fn dwarf_type_to_protocol_encoding(&self, dwarf_type: &DwarfType) -> TypeEncoding {
        match dwarf_type {
            DwarfType::BaseType { size, encoding, .. } => {
                // Use numeric constants instead of gimli constants for now
                // Consider both encoding and size for proper type mapping
                match encoding.0 {
                    1 => TypeEncoding::Pointer, // DW_ATE_address
                    2 => TypeEncoding::Bool,    // DW_ATE_boolean
                    4 => match size {
                        // DW_ATE_float
                        4 => TypeEncoding::F32,
                        8 => TypeEncoding::F64,
                        _ => TypeEncoding::F64, // Default to F64
                    },
                    5 => match size {
                        // DW_ATE_signed
                        1 => TypeEncoding::I8,
                        2 => TypeEncoding::I16,
                        4 => TypeEncoding::I32,
                        8 => TypeEncoding::I64,
                        _ => TypeEncoding::I64, // Default to I64
                    },
                    7 => match size {
                        // DW_ATE_unsigned
                        1 => TypeEncoding::U8,
                        2 => TypeEncoding::U16,
                        4 => TypeEncoding::U32,
                        8 => TypeEncoding::U64,
                        _ => TypeEncoding::U64, // Default to U64
                    },
                    6 => TypeEncoding::I8, // DW_ATE_signed_char
                    8 => TypeEncoding::U8, // DW_ATE_unsigned_char
                    _ => TypeEncoding::U8, // Default to byte for unknown encoding
                }
            }
            DwarfType::PointerType { .. } => TypeEncoding::Pointer,
            DwarfType::ArrayType { .. } => TypeEncoding::Array,
            DwarfType::StructType { .. } => TypeEncoding::Struct,
            DwarfType::UnionType { .. } => TypeEncoding::Union,
            DwarfType::EnumType { .. } => TypeEncoding::I32, // Treat enum as integer
            DwarfType::TypedefType {
                underlying_type, ..
            } => self.dwarf_type_to_protocol_encoding(underlying_type),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => self.dwarf_type_to_protocol_encoding(underlying_type),
            DwarfType::FunctionType { .. } => TypeEncoding::Pointer,
            DwarfType::UnknownType { .. } => TypeEncoding::U8, // Default to byte for unknown types
        }
    }

    /// Get DWARF type size in bytes
    #[allow(clippy::only_used_in_recursion)]
    pub fn get_dwarf_type_size(&self, dwarf_type: &DwarfType) -> u64 {
        match dwarf_type {
            DwarfType::BaseType { size, .. } => *size,
            DwarfType::PointerType { size, .. } => *size,
            DwarfType::ArrayType { total_size, .. } => total_size.unwrap_or(0),
            DwarfType::StructType { size, .. } => *size,
            DwarfType::UnionType { size, .. } => *size,
            DwarfType::EnumType { size, .. } => *size,
            DwarfType::TypedefType {
                underlying_type, ..
            } => self.get_dwarf_type_size(underlying_type),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => self.get_dwarf_type_size(underlying_type),
            DwarfType::FunctionType { .. } => 8, // Function pointer size
            DwarfType::UnknownType { .. } => 0,
        }
    }
}

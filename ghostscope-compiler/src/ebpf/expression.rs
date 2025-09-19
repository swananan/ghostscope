//! Expression compilation for eBPF code generation
//!
//! This module handles compilation of various expression types to LLVM IR.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{BinaryOp, Expr};
use inkwell::values::BasicValueEnum;
use inkwell::AddressSpace;
use tracing::debug;

impl<'ctx> EbpfContext<'ctx> {
    /// Compile an expression
    pub fn compile_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        match expr {
            Expr::Int(value) => {
                let int_value = self.context.i64_type().const_int(*value as u64, false);
                Ok(int_value.into())
            }
            Expr::Float(value) => {
                let float_value = self.context.f64_type().const_float(*value);
                Ok(float_value.into())
            }
            Expr::String(value) => {
                // Create string constant using a simpler approach
                let string_value = self.context.const_string(value.as_bytes(), true);
                let global = self
                    .module
                    .add_global(string_value.get_type(), None, "str_const");
                global.set_initializer(&string_value);

                let ptr_type = self.context.ptr_type(AddressSpace::default());
                Ok(self
                    .builder
                    .build_bit_cast(global.as_pointer_value(), ptr_type, "str_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    .into())
            }
            Expr::Variable(var_name) => {
                // Use the unified evaluation logic for DWARF variables
                debug!("Compiling variable expression: {}", var_name);

                let compile_context = self.get_compile_time_context()?.clone();
                let variable_with_eval = match self.query_dwarf_for_variable(var_name)? {
                    Some(var) => var,
                    None => return Err(CodeGenError::VariableNotFound(var_name.to_string())),
                };

                let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
                    CodeGenError::DwarfError("Variable has no DWARF type information".to_string())
                })?;

                // Use the unified evaluation logic
                self.evaluate_result_to_llvm_value(
                    &variable_with_eval.evaluation_result,
                    dwarf_type,
                    var_name,
                    compile_context.pc_address,
                )
            }
            Expr::SpecialVar(name) => self.handle_special_variable(name),
            Expr::BinaryOp { left, op, right } => {
                let left_val = self.compile_expr(left)?;
                let right_val = self.compile_expr(right)?;
                self.compile_binary_op(left_val, op.clone(), right_val)
            }
            Expr::MemberAccess(obj, field) => {
                let obj_val = self.compile_expr(obj)?;
                self.compile_member_access(obj_val, field)
            }
            Expr::PointerDeref(expr) => {
                let ptr_val = self.compile_expr(expr)?;
                self.compile_pointer_deref(ptr_val)
            }
        }
    }

    /// Handle special variables like $pid, $tid, etc.
    pub fn handle_special_variable(&mut self, name: &str) -> Result<BasicValueEnum<'ctx>> {
        match name {
            "pid" => {
                // Use BPF helper to get current PID
                let pid_tgid = self.get_current_pid_tgid()?;
                let pid_mask = self.context.i64_type().const_int(0xFFFFFFFF, false);
                let pid = self
                    .builder
                    .build_and(pid_tgid, pid_mask, "pid")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(pid.into())
            }
            "tid" => {
                // Use BPF helper to get current TID (thread ID)
                let pid_tgid = self.get_current_pid_tgid()?;
                let tid = self
                    .builder
                    .build_right_shift(
                        pid_tgid,
                        self.context.i64_type().const_int(32, false),
                        false,
                        "tid",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(tid.into())
            }
            "timestamp" => {
                // Use BPF helper to get current timestamp
                let ts = self.get_current_timestamp()?;
                Ok(ts.into())
            }
            _ => Err(CodeGenError::NotImplemented(format!(
                "Special variable ${} not implemented",
                name
            ))),
        }
    }

    /// Compile binary operations
    pub fn compile_binary_op(
        &mut self,
        left: BasicValueEnum<'ctx>,
        op: BinaryOp,
        right: BasicValueEnum<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        use inkwell::values::BasicValueEnum::*;

        match (left, right) {
            (IntValue(left_int), IntValue(right_int)) => {
                let result = match op {
                    BinaryOp::Add => self
                        .builder
                        .build_int_add(left_int, right_int, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Subtract => self
                        .builder
                        .build_int_sub(left_int, right_int, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Multiply => self
                        .builder
                        .build_int_mul(left_int, right_int, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    BinaryOp::Divide => self
                        .builder
                        .build_int_signed_div(left_int, right_int, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                };
                Ok(result.into())
            }
            (FloatValue(left_float), FloatValue(right_float)) => match op {
                BinaryOp::Add => {
                    let result = self
                        .builder
                        .build_float_add(left_float, right_float, "add")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Subtract => {
                    let result = self
                        .builder
                        .build_float_sub(left_float, right_float, "sub")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Multiply => {
                    let result = self
                        .builder
                        .build_float_mul(left_float, right_float, "mul")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::Divide => {
                    let result = self
                        .builder
                        .build_float_div(left_float, right_float, "div")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
            },
            _ => Err(CodeGenError::TypeError(format!(
                "Type mismatch in binary operation {:?}",
                op
            ))),
        }
    }

    /// Compile member access (struct.field)
    pub fn compile_member_access(
        &mut self,
        _obj: BasicValueEnum<'ctx>,
        _field: &str,
    ) -> Result<BasicValueEnum<'ctx>> {
        // TODO: Implement struct member access with DWARF type info
        Err(CodeGenError::NotImplemented(
            "Member access not yet implemented".to_string(),
        ))
    }

    /// Compile pointer dereference (*ptr)
    pub fn compile_pointer_deref(
        &mut self,
        ptr: BasicValueEnum<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        if let BasicValueEnum::PointerValue(ptr_val) = ptr {
            // Convert pointer to IntValue first
            let ptr_as_int = self
                .builder
                .build_ptr_to_int(ptr_val, self.context.i64_type(), "ptr_as_int")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            // Use BPF helper to safely read from user memory
            self.generate_memory_read(ptr_as_int, ghostscope_dwarf::MemoryAccessSize::U64)
        } else {
            Err(CodeGenError::TypeError(
                "Cannot dereference non-pointer value".to_string(),
            ))
        }
    }
}

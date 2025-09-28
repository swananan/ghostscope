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
                debug!(
                    "compile_expr: Int literal {} compiled to IntValue with bit width {}",
                    value,
                    int_value.get_type().get_bit_width()
                );
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
                let cast_ptr = self
                    .builder
                    .build_bit_cast(global.as_pointer_value(), ptr_type, "str_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(cast_ptr)
            }
            Expr::Variable(var_name) => {
                debug!("compile_expr: Compiling variable expression: {}", var_name);

                // First check if it's a script-defined variable
                if self.variable_exists(var_name) {
                    debug!("compile_expr: Found script variable: {}", var_name);
                    let loaded_value = self.load_variable(var_name)?;
                    debug!(
                        "compile_expr: Loaded variable '{}' with type: {:?}",
                        var_name,
                        loaded_value.get_type()
                    );
                    match &loaded_value {
                        BasicValueEnum::IntValue(iv) => debug!(
                            "compile_expr: Variable '{}' is IntValue with bit width {}",
                            var_name,
                            iv.get_type().get_bit_width()
                        ),
                        BasicValueEnum::FloatValue(_) => {
                            debug!("compile_expr: Variable '{}' is FloatValue", var_name)
                        }
                        BasicValueEnum::PointerValue(_) => {
                            debug!("compile_expr: Variable '{}' is PointerValue", var_name)
                        }
                        _ => debug!("compile_expr: Variable '{}' is other type", var_name),
                    }
                    return Ok(loaded_value);
                }

                // If not found in script variables, try DWARF variables
                debug!(
                    "Variable '{}' not found in script variables, checking DWARF",
                    var_name
                );
                self.compile_dwarf_expression(expr)
            }
            Expr::SpecialVar(name) => self.handle_special_variable(name),
            Expr::BinaryOp { left, op, right } => {
                let left_val = self.compile_expr(left)?;
                let right_val = self.compile_expr(right)?;
                self.compile_binary_op(left_val, op.clone(), right_val)
            }
            Expr::MemberAccess(_, _) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::PointerDeref(_) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::AddressOf(inner) => {
                // Take address of an lvalue expression via DWARF evaluation result
                // 1) Resolve complex expr to get EvaluationResult
                let var = self.query_dwarf_for_complex_expr(inner)?.ok_or_else(|| {
                    super::context::CodeGenError::TypeError(
                        "cannot take address of unresolved expression".to_string(),
                    )
                })?;
                // 2) Convert evaluation result to an address (i64)
                match self.evaluation_result_to_address(&var.evaluation_result) {
                    Ok(addr) => Ok(addr.into()),
                    Err(_) => Err(super::context::CodeGenError::TypeError(
                        "cannot take address of rvalue".to_string(),
                    )),
                }
            }
            Expr::ArrayAccess(_, _) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
            Expr::ChainAccess(_) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
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

        // Debug logging to understand the actual types
        debug!("compile_binary_op: op={:?}", op);
        debug!("compile_binary_op: left type = {:?}", left.get_type());
        debug!("compile_binary_op: right type = {:?}", right.get_type());
        match &left {
            IntValue(iv) => debug!(
                "compile_binary_op: left is IntValue with bit width {}",
                iv.get_type().get_bit_width()
            ),
            FloatValue(_) => debug!("compile_binary_op: left is FloatValue"),
            PointerValue(_) => debug!("compile_binary_op: left is PointerValue"),
            _ => debug!("compile_binary_op: left is other type"),
        }
        match &right {
            IntValue(iv) => debug!(
                "compile_binary_op: right is IntValue with bit width {}",
                iv.get_type().get_bit_width()
            ),
            FloatValue(_) => debug!("compile_binary_op: right is FloatValue"),
            PointerValue(_) => debug!("compile_binary_op: right is PointerValue"),
            _ => debug!("compile_binary_op: right is other type"),
        }

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
                    // Comparison operators
                    BinaryOp::Equal => {
                        let result = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::EQ, left_int, right_int, "eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::NotEqual => {
                        let result = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, right_int, "ne")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LessThan => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SLT,
                                left_int,
                                right_int,
                                "lt",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LessEqual => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SLE,
                                left_int,
                                right_int,
                                "le",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterThan => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SGT,
                                left_int,
                                right_int,
                                "gt",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterEqual => {
                        let result = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::SGE,
                                left_int,
                                right_int,
                                "ge",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    // Logical operators (for boolean values represented as i1 or i64)
                    BinaryOp::LogicalAnd => {
                        let result = self
                            .builder
                            .build_and(left_int, right_int, "and")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LogicalOr => {
                        let result = self
                            .builder
                            .build_or(left_int, right_int, "or")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
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
                // Float comparison operators
                BinaryOp::Equal => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OEQ,
                            left_float,
                            right_float,
                            "eq",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::NotEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::ONE,
                            left_float,
                            right_float,
                            "ne",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::LessThan => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OLT,
                            left_float,
                            right_float,
                            "lt",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::LessEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OLE,
                            left_float,
                            right_float,
                            "le",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::GreaterThan => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OGT,
                            left_float,
                            right_float,
                            "gt",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                BinaryOp::GreaterEqual => {
                    let result = self
                        .builder
                        .build_float_compare(
                            inkwell::FloatPredicate::OGE,
                            left_float,
                            right_float,
                            "ge",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(result.into())
                }
                _ => Err(CodeGenError::NotImplemented(format!(
                    "Float binary operation {:?} not implemented",
                    op
                ))),
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
        obj_expr: &Expr,
        field: &str,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Create a MemberAccess expression and use the unified DWARF compilation
        let member_access_expr = Expr::MemberAccess(Box::new(obj_expr.clone()), field.to_string());
        self.compile_dwarf_expression(&member_access_expr)
    }

    /// Compile pointer dereference (*ptr)
    pub fn compile_pointer_deref(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        // Create a PointerDeref expression and use the unified DWARF compilation
        let pointer_deref_expr = Expr::PointerDeref(Box::new(expr.clone()));
        self.compile_dwarf_expression(&pointer_deref_expr)
    }

    /// Compile array access (arr[index])
    pub fn compile_array_access(
        &mut self,
        array_expr: &Expr,
        index_expr: &Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Create an ArrayAccess expression and use the unified DWARF compilation
        let array_access_expr =
            Expr::ArrayAccess(Box::new(array_expr.clone()), Box::new(index_expr.clone()));
        self.compile_dwarf_expression(&array_access_expr)
    }

    /// Compile chain access (person.name.first)
    pub fn compile_chain_access(&mut self, chain: &[String]) -> Result<BasicValueEnum<'ctx>> {
        // Create a ChainAccess expression and use the unified DWARF compilation
        let chain_access_expr = Expr::ChainAccess(chain.to_vec());
        self.compile_dwarf_expression(&chain_access_expr)
    }

    /// Unified DWARF expression compilation
    pub fn compile_dwarf_expression(
        &mut self,
        expr: &crate::script::Expr,
    ) -> Result<BasicValueEnum<'ctx>> {
        debug!(
            "compile_dwarf_expression: Compiling complex expression: {:?}",
            expr
        );

        // Query DWARF for the complex expression
        let compile_context = self.get_compile_time_context()?.clone();
        let variable_with_eval = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => {
                let expr_str = self.expr_to_debug_string(expr);
                return Err(CodeGenError::VariableNotFound(expr_str));
            }
        };

        let dwarf_type = variable_with_eval.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
        })?;

        debug!(
            "compile_dwarf_expression: Found DWARF info for expression '{}' with type: {:?}",
            variable_with_eval.name, dwarf_type
        );

        // Use the unified evaluation logic to generate LLVM IR
        self.evaluate_result_to_llvm_value(
            &variable_with_eval.evaluation_result,
            dwarf_type,
            &variable_with_eval.name,
            compile_context.pc_address,
        )
    }

    /// Helper: Convert expression to string for debugging
    #[allow(clippy::only_used_in_recursion)]
    fn expr_to_debug_string(&self, expr: &crate::script::Expr) -> String {
        use crate::script::Expr;

        match expr {
            Expr::Variable(name) => name.clone(),
            Expr::MemberAccess(obj, field) => {
                format!("{}.{}", self.expr_to_debug_string(obj), field)
            }
            Expr::ArrayAccess(arr, _) => format!("{}[index]", self.expr_to_debug_string(arr)),
            Expr::ChainAccess(chain) => chain.join("."),
            Expr::PointerDeref(expr) => format!("*{}", self.expr_to_debug_string(expr)),
            _ => "expr".to_string(),
        }
    }
}

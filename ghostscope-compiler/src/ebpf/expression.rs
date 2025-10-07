//! Expression compilation for eBPF code generation
//!
//! This module handles compilation of various expression types to LLVM IR.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{BinaryOp, Expr};
use inkwell::values::BasicValueEnum;
use inkwell::AddressSpace;
use tracing::debug;

// Read cap for string builtins (strncmp/starts_with)
pub const STRING_BUILTIN_READ_CAP: u32 = 64;

impl<'ctx> EbpfContext<'ctx> {
    /// Builtin strncmp/starts_with implementation: bounded byte-compare without NUL requirement.
    fn compile_strncmp_builtin(
        &mut self,
        dwarf_expr: &Expr,
        lit: &str,
        n: u32,
    ) -> Result<BasicValueEnum<'ctx>> {
        // Resolve DWARF expression to get address or pointer value
        let var = self
            .query_dwarf_for_complex_expr(dwarf_expr)?
            .ok_or_else(|| CodeGenError::TypeError("builtin requires DWARF expression".into()))?;

        // Determine pointer value (i64) of the target memory
        let ptr_i64 = if let Some(dty) = var.dwarf_type.as_ref() {
            // Try full value first
            let val_any = self.evaluate_result_to_llvm_value(
                &var.evaluation_result,
                dty,
                &var.name,
                self.get_compile_time_context()?.pc_address,
            )?;
            match val_any {
                BasicValueEnum::IntValue(iv) => iv,
                BasicValueEnum::PointerValue(pv) => self
                    .builder
                    .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                _ => {
                    // Fallback: read pointer from address
                    let module_hint = self.current_resolved_var_module_path.clone();
                    let addr = self.evaluation_result_to_address_with_hint(
                        &var.evaluation_result,
                        None,
                        module_hint.as_deref(),
                    )?;
                    let val_any =
                        self.generate_memory_read(addr, ghostscope_dwarf::MemoryAccessSize::U64)?;
                    match val_any {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::LLVMError(
                                "pointer load did not return integer".into(),
                            ))
                        }
                    }
                }
            }
        } else {
            // No DWARF type: compute address then read pointer-sized value
            let module_hint = self.current_resolved_var_module_path.clone();
            let addr = self.evaluation_result_to_address_with_hint(
                &var.evaluation_result,
                None,
                module_hint.as_deref(),
            )?;
            let val_any =
                self.generate_memory_read(addr, ghostscope_dwarf::MemoryAccessSize::U64)?;
            match val_any {
                BasicValueEnum::IntValue(iv) => iv,
                _ => {
                    return Err(CodeGenError::LLVMError(
                        "pointer load did not return integer".into(),
                    ))
                }
            }
        };

        // Cap read length for safety
        let max_n = std::cmp::min(n, STRING_BUILTIN_READ_CAP);
        let lit_len = std::cmp::min(lit.len() as u32, STRING_BUILTIN_READ_CAP);
        let cmp_len = std::cmp::min(max_n, lit_len);

        // Read bytes into buffer
        let (buf_global, status, arr_ty) =
            self.read_user_bytes_into_buffer(ptr_i64, cmp_len, "_gs_bi_strncmp")?;
        let status_ok = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                status,
                self.context.i64_type().const_zero(),
                "rd_ok",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        // XOR/OR accumulation over cmp_len bytes
        let i32_ty = self.context.i32_type();
        let idx0 = i32_ty.const_zero();
        let mut acc = self.context.i8_type().const_zero();
        for (i, b) in lit.as_bytes().iter().take(cmp_len as usize).enumerate() {
            let idx_i = i32_ty.const_int(i as u64, false);
            let ptr_i = unsafe {
                self.builder
                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            };
            let ch = self
                .builder
                .build_load(self.context.i8_type(), ptr_i, "ch")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            let ch = match ch {
                BasicValueEnum::IntValue(iv) => iv,
                _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
            };
            let expect = self.context.i8_type().const_int(*b as u64, false);
            let diff = self
                .builder
                .build_xor(ch, expect, "diff")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
            acc = self
                .builder
                .build_or(acc, diff, "acc_or")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        }
        let eq_bytes = self
            .builder
            .build_int_compare(
                inkwell::IntPredicate::EQ,
                acc,
                self.context.i8_type().const_zero(),
                "acc_zero",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

        let result = self
            .builder
            .build_and(status_ok, eq_bytes, "strncmp_and")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        Ok(result.into())
    }
    /// Compile an expression
    pub fn compile_expr(&mut self, expr: &Expr) -> Result<BasicValueEnum<'ctx>> {
        match expr {
            Expr::Int(value) => {
                // Treat script integer literals as signed i64 constants
                let int_value = self.context.i64_type().const_int(*value as u64, true);
                debug!(
                    "compile_expr: Int literal {} compiled to IntValue with bit width {}",
                    value,
                    int_value.get_type().get_bit_width()
                );
                Ok(int_value.into())
            }
            Expr::Float(_value) => Err(CodeGenError::TypeError(
                "Floating point expressions are not supported".to_string(),
            )),
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
            Expr::Bool(value) => {
                // Represent booleans as i1 for logical/compare consistency
                let b = self
                    .context
                    .bool_type()
                    .const_int(if *value { 1 } else { 0 }, false);
                Ok(b.into())
            }
            Expr::UnaryNot(inner) => {
                // Compile operand to integer and compare EQ to zero to produce boolean not
                let v = self.compile_expr(inner)?;
                let iv = match v {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "Logical NOT requires integer/boolean operand".to_string(),
                        ))
                    }
                };
                let zero = iv.get_type().const_zero();
                let res = self
                    .builder
                    .build_int_compare(inkwell::IntPredicate::EQ, iv, zero, "not_eq0")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(res.into())
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
            Expr::BuiltinCall { name, args } => match name.as_str() {
                "strncmp" => {
                    if args.len() != 3 {
                        return Err(CodeGenError::TypeError(
                            "strncmp expects 3 arguments".into(),
                        ));
                    }
                    let n = match &args[2] {
                        Expr::Int(v) if *v >= 0 => *v as u32,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "strncmp length must be a non-negative integer literal".into(),
                            ))
                        }
                    };
                    let lit = match &args[1] {
                        Expr::String(s) => s.as_str(),
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "strncmp second argument must be a string literal".into(),
                            ))
                        }
                    };
                    self.compile_strncmp_builtin(&args[0], lit, n)
                }
                "starts_with" => {
                    if args.len() != 2 {
                        return Err(CodeGenError::TypeError(
                            "starts_with expects 2 arguments".into(),
                        ));
                    }
                    let lit = match &args[1] {
                        Expr::String(s) => s.as_str(),
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "starts_with second argument must be a string literal".into(),
                            ))
                        }
                    };
                    self.compile_strncmp_builtin(&args[0], lit, lit.len() as u32)
                }
                _ => Err(CodeGenError::NotImplemented(format!(
                    "Unknown builtin function: {}",
                    name
                ))),
            },
            Expr::BinaryOp { left, op, right } => {
                // String comparison fast-path: script string vs DWARF char*/char[N]
                if matches!(op, BinaryOp::Equal | BinaryOp::NotEqual) {
                    if let (Expr::String(lit), other) = (&**left, &**right) {
                        return self.compile_string_comparison(
                            other,
                            lit,
                            matches!(op, BinaryOp::Equal),
                        );
                    } else if let (other, Expr::String(lit)) = (&**left, &**right) {
                        return self.compile_string_comparison(
                            other,
                            lit,
                            matches!(op, BinaryOp::Equal),
                        );
                    }
                }
                // Implement short-circuit for logical OR (||) and logical AND (&&)
                if matches!(op, BinaryOp::LogicalOr) {
                    // Evaluate LHS to boolean (non-zero => true)
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer operands".to_string(),
                            ))
                        }
                    };
                    let lhs_zero = lhs_int.get_type().const_zero();
                    let lhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            lhs_int,
                            lhs_zero,
                            "lor_lhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // Prepare control flow blocks
                    let curr_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block".to_string())
                    })?;
                    let func = curr_block
                        .get_parent()
                        .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;
                    let rhs_block = self.context.append_basic_block(func, "lor_rhs");
                    let merge_block = self.context.append_basic_block(func, "lor_merge");

                    // If lhs is true, jump directly to merge (short-circuit)
                    self.builder
                        .build_conditional_branch(lhs_bool, merge_block, rhs_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // RHS path: compute boolean only if needed
                    self.builder.position_at_end(rhs_block);
                    let rhs_val = self.compile_expr(right)?;
                    let rhs_int = match rhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer operands".to_string(),
                            ))
                        }
                    };
                    let rhs_zero = rhs_int.get_type().const_zero();
                    let rhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            rhs_int,
                            rhs_zero,
                            "lor_rhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    // Capture the actual block where RHS computation ended
                    let rhs_end_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block after RHS".to_string())
                    })?;
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Merge: phi of i1: true from LHS-true, RHS bool from rhs_block
                    self.builder.position_at_end(merge_block);
                    let i1 = self.context.bool_type();
                    let phi = self
                        .builder
                        .build_phi(i1, "lor_phi")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let one = i1.const_int(1, false);
                    phi.add_incoming(&[(&one, curr_block), (&rhs_bool, rhs_end_block)]);
                    return Ok(phi.as_basic_value());
                } else if matches!(op, BinaryOp::LogicalAnd) {
                    // Evaluate LHS to boolean (non-zero => true)
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer operands".to_string(),
                            ))
                        }
                    };
                    let lhs_zero = lhs_int.get_type().const_zero();
                    let lhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            lhs_int,
                            lhs_zero,
                            "land_lhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                    // Prepare control flow: if lhs is true, evaluate rhs; else short-circuit to false
                    let curr_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block".to_string())
                    })?;
                    let func = curr_block
                        .get_parent()
                        .ok_or_else(|| CodeGenError::LLVMError("No parent function".to_string()))?;
                    let rhs_block = self.context.append_basic_block(func, "land_rhs");
                    let merge_block = self.context.append_basic_block(func, "land_merge");

                    // If lhs is true, go compute rhs; else jump to merge with false
                    self.builder
                        .build_conditional_branch(lhs_bool, rhs_block, merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // RHS path
                    self.builder.position_at_end(rhs_block);
                    let rhs_val = self.compile_expr(right)?;
                    let rhs_int = match rhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer operands".to_string(),
                            ))
                        }
                    };
                    let rhs_zero = rhs_int.get_type().const_zero();
                    let rhs_bool = self
                        .builder
                        .build_int_compare(
                            inkwell::IntPredicate::NE,
                            rhs_int,
                            rhs_zero,
                            "land_rhs_nz",
                        )
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let rhs_end_block = self.builder.get_insert_block().ok_or_else(|| {
                        CodeGenError::LLVMError("No current basic block after RHS".to_string())
                    })?;
                    self.builder
                        .build_unconditional_branch(merge_block)
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;

                    // Merge: phi(i1) with false from LHS=false path, RHS bool from rhs path
                    self.builder.position_at_end(merge_block);
                    let i1 = self.context.bool_type();
                    let phi = self
                        .builder
                        .build_phi(i1, "land_phi")
                        .map_err(|e| CodeGenError::LLVMError(e.to_string()))?;
                    let zero = i1.const_zero();
                    phi.add_incoming(&[(&rhs_bool, rhs_end_block), (&zero, curr_block)]);
                    return Ok(phi.as_basic_value());
                }

                // Default eager evaluation for other binary ops
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
                // Address-of with ASLR-aware hint: compute runtime address using module hint
                let var = self.query_dwarf_for_complex_expr(inner)?.ok_or_else(|| {
                    super::context::CodeGenError::TypeError(
                        "cannot take address of unresolved expression".to_string(),
                    )
                })?;
                // Use current resolved hint if available (set during DWARF resolution)
                let module_hint = self.current_resolved_var_module_path.clone();
                match self.evaluation_result_to_address_with_hint(
                    &var.evaluation_result,
                    None,
                    module_hint.as_deref(),
                ) {
                    Ok(addr_i64) => {
                        let ptr_ty = self.context.ptr_type(AddressSpace::default());
                        let as_ptr = self
                            .builder
                            .build_int_to_ptr(addr_i64, ptr_ty, "addr_as_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(as_ptr.into())
                    }
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
                    // Logical operators with boolean semantics (non-zero is true)
                    BinaryOp::LogicalAnd => {
                        let lz = left_int.get_type().const_zero();
                        let rz = right_int.get_type().const_zero();
                        let lbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, lz, "lhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let rbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, right_int, rz, "rhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let result = self
                            .builder
                            .build_and(lbool, rbool, "and_bool")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LogicalOr => {
                        let lz = left_int.get_type().const_zero();
                        let rz = right_int.get_type().const_zero();
                        let lbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, left_int, lz, "lhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let rbool = self
                            .builder
                            .build_int_compare(inkwell::IntPredicate::NE, right_int, rz, "rhs_nz")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let result = self
                            .builder
                            .build_or(lbool, rbool, "or_bool")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                };
                Ok(result.into())
            }
            // Pointer equality/inequality comparisons
            (PointerValue(lp), IntValue(ri)) | (IntValue(ri), PointerValue(lp)) => {
                match op {
                    BinaryOp::Equal | BinaryOp::NotEqual => {
                        let lpi64 = self
                            .builder
                            .build_ptr_to_int(lp, self.context.i64_type(), "ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        // Normalize RHS to i64
                        let rbw = ri.get_type().get_bit_width();
                        let ri64 = if rbw < 64 {
                            self.builder
                                .build_int_z_extend(ri, self.context.i64_type(), "rhs_zext_i64")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        } else if rbw > 64 {
                            self.builder
                                .build_int_truncate(ri, self.context.i64_type(), "rhs_trunc_i64")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        } else {
                            ri
                        };
                        let pred = if matches!(op, BinaryOp::Equal) {
                            inkwell::IntPredicate::EQ
                        } else {
                            inkwell::IntPredicate::NE
                        };
                        let cmp = self
                            .builder
                            .build_int_compare(pred, lpi64, ri64, "ptr_cmp")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        Ok(cmp.into())
                    }
                    _ => Err(CodeGenError::TypeError(format!(
                        "Type mismatch in binary operation {:?}",
                        op
                    ))),
                }
            }
            (PointerValue(lp), PointerValue(rp)) => match op {
                BinaryOp::Equal | BinaryOp::NotEqual => {
                    let lpi64 = self
                        .builder
                        .build_ptr_to_int(lp, self.context.i64_type(), "l_ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let rpi64 = self
                        .builder
                        .build_ptr_to_int(rp, self.context.i64_type(), "r_ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let pred = if matches!(op, BinaryOp::Equal) {
                        inkwell::IntPredicate::EQ
                    } else {
                        inkwell::IntPredicate::NE
                    };
                    let cmp = self
                        .builder
                        .build_int_compare(pred, lpi64, rpi64, "ptr_ptr_cmp")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    Ok(cmp.into())
                }
                _ => Err(CodeGenError::TypeError(format!(
                    "Type mismatch in binary operation {:?}",
                    op
                ))),
            },
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

impl<'ctx> EbpfContext<'ctx> {
    /// Compile comparison between a DWARF-side expression and a script string literal.
    /// Supports char* and char[N] according to design in string_comparison.md.
    fn compile_string_comparison(
        &mut self,
        dwarf_expr: &Expr,
        lit: &str,
        is_equal: bool,
    ) -> Result<BasicValueEnum<'ctx>> {
        use ghostscope_dwarf::TypeInfo as TI;

        // Query DWARF for the non-string side to obtain evaluation and type info
        let var = self
            .query_dwarf_for_complex_expr(dwarf_expr)?
            .ok_or_else(|| {
                CodeGenError::TypeError(
                    "string comparison requires DWARF variable/expression".into(),
                )
            })?;
        // Try DWARF type first; if unavailable, fall back to type_name string parsing
        let dwarf_type_opt = var.dwarf_type.as_ref();

        enum ParsedKind {
            PtrChar,
            ArrChar(Option<u32>),
            Other,
        }
        fn parse_type_name(name: &str) -> ParsedKind {
            let lower = name.to_lowercase();
            let has_char = lower.contains("char");
            let is_ptr = lower.contains('*');
            if has_char && is_ptr {
                return ParsedKind::PtrChar;
            }
            if has_char && lower.contains('[') {
                // Try to extract N inside brackets
                let mut n: Option<u32> = None;
                if let Some(start) = lower.find('[') {
                    if let Some(end) = lower[start + 1..].find(']') {
                        let inside = &lower[start + 1..start + 1 + end];
                        let digits: String =
                            inside.chars().filter(|c| c.is_ascii_digit()).collect();
                        if !digits.is_empty() {
                            if let Ok(v) = digits.parse::<u32>() {
                                n = Some(v);
                            }
                        }
                    }
                }
                return ParsedKind::ArrChar(n);
            }
            ParsedKind::Other
        }

        // Helper to peel typedef/qualifier wrappers
        fn unwrap_aliases(t: &TI) -> &TI {
            let mut cur = t;
            loop {
                match cur {
                    TI::TypedefType {
                        underlying_type, ..
                    } => cur = underlying_type.as_ref(),
                    TI::QualifiedType {
                        underlying_type, ..
                    } => cur = underlying_type.as_ref(),
                    _ => break,
                }
            }
            cur
        }

        // Compute runtime address of the DWARF expression
        let module_hint = self.current_resolved_var_module_path.clone();
        let addr = self.evaluation_result_to_address_with_hint(
            &var.evaluation_result,
            None,
            module_hint.as_deref(),
        )?;

        let lit_bytes = lit.as_bytes();
        let lit_len = lit_bytes.len() as u32;
        let one = self.context.bool_type().const_int(1, false);
        let zero = self.context.bool_type().const_zero();

        // Build final boolean accumulator
        let result = match dwarf_type_opt.map(unwrap_aliases) {
            // char* / const char*
            Some(TI::PointerType { target_type, .. }) => {
                // Ensure pointee is char-like
                let base = unwrap_aliases(target_type.as_ref());
                let is_char_like = matches!(base, TI::BaseType { name, size, .. } if name.contains("char") && *size == 1);
                if !is_char_like {
                    return Err(CodeGenError::TypeError(
                        "automatic string comparison only supports char*".into(),
                    ));
                }

                // Evaluate expression to pointer value and read up to L+1 bytes
                let val_any = self.evaluate_result_to_llvm_value(
                    &var.evaluation_result,
                    var.dwarf_type.as_ref().unwrap(),
                    &var.name,
                    self.get_compile_time_context()?.pc_address,
                )?;
                let ptr_i64 = match val_any {
                    BasicValueEnum::IntValue(iv) => iv,
                    BasicValueEnum::PointerValue(pv) => self
                        .builder
                        .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "pointer value must be integer or pointer".into(),
                        ))
                    }
                };
                let need = lit_len + 1;
                let (buf_global, ret_len, arr_ty) =
                    self.read_user_cstr_into_buffer(ptr_i64, need, "_gs_strbuf")?;

                // ret_len must equal L+1
                let i64_ty = self.context.i64_type();
                let expect_len = i64_ty.const_int(need as u64, false);
                let len_ok = self
                    .builder
                    .build_int_compare(inkwell::IntPredicate::EQ, ret_len, expect_len, "str_len_ok")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                // buf[L] must be '\0'
                let i32_ty = self.context.i32_type();
                let idx0 = i32_ty.const_zero();
                let idx_l = i32_ty.const_int(lit_len as u64, false);
                let char_ptr = unsafe {
                    self.builder
                        .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let c = self
                    .builder
                    .build_load(self.context.i8_type(), char_ptr, "c_l")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let c = match c {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                };
                let nul_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        c,
                        self.context.i8_type().const_zero(),
                        "nul_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                // Compare first L bytes using XOR/OR accumulation to reduce branchiness
                let mut acc = self.context.i8_type().const_zero();
                for (i, b) in lit_bytes.iter().enumerate() {
                    let idx_i = i32_ty.const_int(i as u64, false);
                    let ptr_i = unsafe {
                        self.builder
                            .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };
                    let ch = self
                        .builder
                        .build_load(self.context.i8_type(), ptr_i, "ch")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ch = match ch {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                    };
                    let expect = self.context.i8_type().const_int(*b as u64, false);
                    let diff = self
                        .builder
                        .build_xor(ch, expect, "diff")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, diff, "acc_or")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                }
                let eq_bytes = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        acc,
                        self.context.i8_type().const_zero(),
                        "acc_zero",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let ok1 = self
                    .builder
                    .build_and(len_ok, nul_ok, "ok_len_nul")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder
                    .build_and(ok1, eq_bytes, "str_eq")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            // char[N]
            Some(TI::ArrayType {
                element_type,
                element_count,
                total_size,
            }) => {
                let elem = unwrap_aliases(element_type.as_ref());
                let is_char_like = matches!(elem, TI::BaseType { name, size, .. } if name.contains("char") && *size == 1);
                if !is_char_like {
                    return Err(CodeGenError::TypeError(
                        "automatic string comparison only supports char[N]".into(),
                    ));
                }
                // Determine N (element count)
                let n_opt = element_count.or_else(|| total_size.map(|ts| ts));
                let n = if let Some(nv) = n_opt { nv as u32 } else { 0 };
                if n == 0 {
                    return Err(CodeGenError::TypeError(
                        "array size unknown for char[N] comparison".into(),
                    ));
                }
                // If L+1 > N, compile-time false
                if lit_len + 1 > n {
                    // Return const false (or true if '!=' requested)
                    return Ok((if is_equal { zero } else { one }).into());
                }
                // Read exactly L+1 bytes
                let (buf_global, status, arr_ty) =
                    self.read_user_bytes_into_buffer(addr, lit_len + 1, "_gs_arrbuf")?;
                // status == 0
                let status_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        status,
                        self.context.i64_type().const_zero(),
                        "rd_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                // buf[L] must be '\0'
                let i32_ty = self.context.i32_type();
                let idx0 = i32_ty.const_zero();
                let idx_l = i32_ty.const_int(lit_len as u64, false);
                let char_ptr = unsafe {
                    self.builder
                        .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                };
                let c = self
                    .builder
                    .build_load(self.context.i8_type(), char_ptr, "c_l")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let c = match c {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                };
                let nul_ok = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        c,
                        self.context.i8_type().const_zero(),
                        "nul_ok",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                // Compare first L bytes using XOR/OR accumulation
                let mut acc = self.context.i8_type().const_zero();
                for (i, b) in lit_bytes.iter().enumerate() {
                    let idx_i = i32_ty.const_int(i as u64, false);
                    let ptr_i = unsafe {
                        self.builder
                            .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    };
                    let ch = self
                        .builder
                        .build_load(self.context.i8_type(), ptr_i, "ch")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    let ch = match ch {
                        BasicValueEnum::IntValue(iv) => iv,
                        _ => return Err(CodeGenError::LLVMError("load did not return i8".into())),
                    };
                    let expect = self.context.i8_type().const_int(*b as u64, false);
                    let diff = self
                        .builder
                        .build_xor(ch, expect, "diff")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    acc = self
                        .builder
                        .build_or(acc, diff, "acc_or")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                }
                let eq_bytes = self
                    .builder
                    .build_int_compare(
                        inkwell::IntPredicate::EQ,
                        acc,
                        self.context.i8_type().const_zero(),
                        "acc_zero",
                    )
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                let ok1 = self
                    .builder
                    .build_and(status_ok, nul_ok, "ok_len_nul")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                self.builder
                    .build_and(ok1, eq_bytes, "arr_eq")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
            }
            None => {
                // Fallback using type_name string
                match parse_type_name(&var.type_name) {
                    ParsedKind::PtrChar => {
                        // Load pointer value from variable location (assume 64-bit)
                        let ptr_any = self
                            .generate_memory_read(addr, ghostscope_dwarf::MemoryAccessSize::U64)?;
                        let ptr_i64 = match ptr_any {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "pointer load did not return integer".to_string(),
                                ))
                            }
                        };
                        let need = lit_len + 1;
                        let (buf_global, ret_len, arr_ty) =
                            self.read_user_cstr_into_buffer(ptr_i64, need, "_gs_strbuf")?;

                        let i64_ty = self.context.i64_type();
                        let expect_len = i64_ty.const_int(need as u64, false);
                        let len_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                ret_len,
                                expect_len,
                                "str_len_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                        let i32_ty = self.context.i32_type();
                        let idx0 = i32_ty.const_zero();
                        let idx_l = i32_ty.const_int(lit_len as u64, false);
                        let char_ptr = unsafe {
                            self.builder
                                .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        };
                        let c = self
                            .builder
                            .build_load(self.context.i8_type(), char_ptr, "c_l")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let c = match c {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "load did not return i8".into(),
                                ))
                            }
                        };
                        let nul_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                c,
                                self.context.i8_type().const_zero(),
                                "nul_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;

                        let mut acc = self.context.i8_type().const_zero();
                        for (i, b) in lit_bytes.iter().enumerate() {
                            let idx_i = i32_ty.const_int(i as u64, false);
                            let ptr_i = unsafe {
                                self.builder
                                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            };
                            let ch = self
                                .builder
                                .build_load(self.context.i8_type(), ptr_i, "ch")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            let ch = match ch {
                                BasicValueEnum::IntValue(iv) => iv,
                                _ => {
                                    return Err(CodeGenError::LLVMError(
                                        "load did not return i8".into(),
                                    ))
                                }
                            };
                            let expect = self.context.i8_type().const_int(*b as u64, false);
                            let diff = self
                                .builder
                                .build_xor(ch, expect, "diff")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            acc = self
                                .builder
                                .build_or(acc, diff, "acc_or")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        }
                        let eq_bytes = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                acc,
                                self.context.i8_type().const_zero(),
                                "acc_zero",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let ok1 = self
                            .builder
                            .build_and(len_ok, nul_ok, "ok_len_nul")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        self.builder
                            .build_and(ok1, eq_bytes, "str_eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                    ParsedKind::ArrChar(n_opt) => {
                        // If we know N and L+1>N, return false; else read L+1 bytes
                        if let Some(n) = n_opt {
                            if lit_len + 1 > n {
                                return Ok((if is_equal { zero } else { one }).into());
                            }
                        }
                        let (buf_global, status, arr_ty) =
                            self.read_user_bytes_into_buffer(addr, lit_len + 1, "_gs_arrbuf")?;
                        let status_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                status,
                                self.context.i64_type().const_zero(),
                                "rd_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let i32_ty = self.context.i32_type();
                        let idx0 = i32_ty.const_zero();
                        let idx_l = i32_ty.const_int(lit_len as u64, false);
                        let char_ptr = unsafe {
                            self.builder
                                .build_gep(arr_ty, buf_global, &[idx0, idx_l], "nul_ptr")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?
                        };
                        let c = self
                            .builder
                            .build_load(self.context.i8_type(), char_ptr, "c_l")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let c = match c {
                            BasicValueEnum::IntValue(iv) => iv,
                            _ => {
                                return Err(CodeGenError::LLVMError(
                                    "load did not return i8".into(),
                                ))
                            }
                        };
                        let nul_ok = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                c,
                                self.context.i8_type().const_zero(),
                                "nul_ok",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let mut acc = self.context.i8_type().const_zero();
                        for (i, b) in lit_bytes.iter().enumerate() {
                            let idx_i = i32_ty.const_int(i as u64, false);
                            let ptr_i = unsafe {
                                self.builder
                                    .build_gep(arr_ty, buf_global, &[idx0, idx_i], "ch_ptr")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?
                            };
                            let ch = self
                                .builder
                                .build_load(self.context.i8_type(), ptr_i, "ch")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            let ch = match ch {
                                BasicValueEnum::IntValue(iv) => iv,
                                _ => {
                                    return Err(CodeGenError::LLVMError(
                                        "load did not return i8".into(),
                                    ))
                                }
                            };
                            let expect = self.context.i8_type().const_int(*b as u64, false);
                            let diff = self
                                .builder
                                .build_xor(ch, expect, "diff")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            acc = self
                                .builder
                                .build_or(acc, diff, "acc_or")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        }
                        let eq_bytes = self
                            .builder
                            .build_int_compare(
                                inkwell::IntPredicate::EQ,
                                acc,
                                self.context.i8_type().const_zero(),
                                "acc_zero",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        let ok1 = self
                            .builder
                            .build_and(status_ok, nul_ok, "ok_len_nul")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        self.builder
                            .build_and(ok1, eq_bytes, "arr_eq")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                    ParsedKind::Other => {
                        return Err(CodeGenError::TypeError(format!(
                            "string comparison unsupported for type name '{}' without DWARF type",
                            var.type_name
                        )));
                    }
                }
            }
            Some(_) => {
                return Err(CodeGenError::TypeError(
                    "string comparison only supports char* or char[N]".into(),
                ));
            }
        };

        // Apply == / !=
        let final_bool = if is_equal {
            result
        } else {
            self.builder
                .build_not(result, "not_eq")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        };
        Ok(final_bool.into())
    }
}

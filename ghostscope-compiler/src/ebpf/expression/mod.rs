//! Expression compilation for eBPF code generation
//!
//! This module handles compilation of various expression types to LLVM IR.

use super::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use super::expression_plan::{BinaryEmitKind, BuiltinCallPlan};
use crate::script::Expr;
use ghostscope_dwarf::{CIntegerComparisonType, TypeInfo as DwarfType};
use inkwell::values::BasicValueEnum;
use inkwell::AddressSpace;

mod binary;
mod builtins;
mod casts;
mod dwarf_access;
mod runtime_address;
mod special_vars;
use std::path::PathBuf;
use tracing::debug;

// compare cap is provided via compile_options.compare_cap (config: ebpf.compare_cap)

#[derive(Clone)]
pub(super) struct DynamicTypeInfo {
    pub(super) dwarf_type: DwarfType,
    pub(super) module_path: Option<PathBuf>,
}

pub(super) struct DynamicLvalue<'ctx> {
    pub(super) address: RuntimeAddress<'ctx>,
    pub(super) type_info: DynamicTypeInfo,
}

struct IndexableElementInfo {
    element_type: DwarfType,
    stride: u64,
    module_path: Option<PathBuf>,
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
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
            Expr::UnaryBitNot(inner) => {
                let unsigned_width = self
                    .dwarf_integer_comparison_expr(inner)
                    .map(CIntegerComparisonType::promoted)
                    .and_then(|integer_type| {
                        integer_type
                            .is_unsigned
                            .then_some((integer_type.size * 8) as u32)
                    });
                let v = self.compile_expr(inner)?;
                let iv = match v {
                    BasicValueEnum::IntValue(iv) => iv,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "Bitwise NOT requires integer/boolean operand".to_string(),
                        ))
                    }
                };
                if let Some(bit_width) = unsigned_width {
                    let iv =
                        self.normalize_int_for_unsigned_compare(iv, bit_width, "bitnot_unsigned")?;
                    let result = self
                        .builder
                        .build_xor(iv, iv.get_type().const_all_ones(), "bitnot")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    return self
                        .zero_extend_int_to_i64_if_needed(result, "bitnot_zext_i64")
                        .map(|value| value.into());
                }
                let iv = if iv.get_type().get_bit_width() == 1 {
                    self.builder
                        .build_int_z_extend(iv, self.context.i64_type(), "bitnot_bool_i64")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?
                } else {
                    iv
                };
                let all_ones = iv.get_type().const_all_ones();
                let result = self
                    .builder
                    .build_xor(iv, all_ones, "bitnot")
                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                Ok(result.into())
            }
            Expr::Variable(var_name) => {
                debug!("compile_expr: Compiling variable expression: {}", var_name);

                // First: DWARF alias variable takes precedence
                if self.alias_variable_exists(var_name) {
                    debug!(
                        "compile_expr: '{}' is an alias variable; resolving to runtime address",
                        var_name
                    );
                    let aliased = self
                        .get_alias_variable(var_name)
                        .expect("alias existence just checked");
                    // Resolve to i64 address then cast to ptr
                    let addr_i64 = self.resolve_ptr_i64_from_expr(&aliased)?;
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let as_ptr = self
                        .builder
                        .build_int_to_ptr(addr_i64, ptr_ty, "alias_as_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    return Ok(as_ptr.into());
                }

                // Then check if it's a concrete script-defined variable
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

                // If not found in script variables nor alias map, try DWARF variables
                debug!(
                    "Variable '{}' not found in script variables, checking DWARF",
                    var_name
                );
                // If not a DWARF variable either, treat as out-of-scope script name for friendliness
                match self.query_dwarf_for_variable(var_name) {
                    Ok(Some(_)) => self.compile_dwarf_expression(expr),
                    Ok(None) => Err(CodeGenError::VariableNotInScope(var_name.clone())),
                    Err(e) => Err(CodeGenError::DwarfError(e.to_string())),
                }
            }
            Expr::SpecialVar(name) => {
                // Accept both "$pid" and "pid" forms from the parser
                let sanitized = name.trim_start_matches('$');
                self.handle_special_variable(sanitized)
            }
            Expr::BuiltinCall { name, args } => match self.plan_builtin_call(name, args)? {
                BuiltinCallPlan::Memcmp => {
                    self.compile_memcmp_builtin(&args[0], &args[1], &args[2])
                }
                BuiltinCallPlan::Strncmp => {
                    // Accept string on either side: string literal or script string variable
                    fn extract_script_string(
                        this: &mut EbpfContext<'_, '_>,
                        e: &Expr,
                    ) -> Option<String> {
                        match e {
                            Expr::String(s) => Some(s.clone()),
                            Expr::Variable(name) => this
                                .get_variable_type(name)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                                .then(|| {
                                    this.get_string_variable_bytes(name).map(|b| {
                                        let cut = b.iter().position(|&x| x == 0).unwrap_or(b.len());
                                        String::from_utf8_lossy(&b[..cut]).to_string()
                                    })
                                })
                                .flatten(),
                            _ => None,
                        }
                    }
                    let left_str = extract_script_string(self, &args[0]);
                    let right_str = extract_script_string(self, &args[1]);
                    match (left_str, right_str) {
                        (Some(ls), Some(rs)) => {
                            let left_expr = Expr::String(ls);
                            self.compile_strncmp_builtin(&left_expr, &rs, &args[2])
                        }
                        (Some(ls), None) => self.compile_strncmp_builtin(&args[1], &ls, &args[2]),
                        (None, Some(rs)) => self.compile_strncmp_builtin(&args[0], &rs, &args[2]),
                        (None, None) => Err(CodeGenError::TypeError(
                            "strncmp requires at least one string argument (string literal or script string variable) as the first or second parameter".into(),
                        )),
                    }
                }
                BuiltinCallPlan::StartsWith => {
                    // Accept string on either side (literal or script string var)
                    fn extract_script_string(
                        this: &mut EbpfContext<'_, '_>,
                        e: &Expr,
                    ) -> Option<String> {
                        match e {
                            Expr::String(s) => Some(s.clone()),
                            Expr::Variable(name) => this
                                .get_variable_type(name)
                                .is_some_and(|t| matches!(t, crate::script::VarType::String))
                                .then(|| {
                                    this.get_string_variable_bytes(name).map(|b| {
                                        let cut = b.iter().position(|&x| x == 0).unwrap_or(b.len());
                                        String::from_utf8_lossy(&b[..cut]).to_string()
                                    })
                                })
                                .flatten(),
                            _ => None,
                        }
                    }
                    let s0 = extract_script_string(self, &args[0]);
                    let s1 = extract_script_string(self, &args[1]);
                    match (s0, s1) {
                        (Some(a), Some(b)) => {
                            // both strings -> compile-time fold
                            let ok = a.as_bytes().starts_with(b.as_bytes());
                            let bv = self.context.bool_type().const_int(ok as u64, false);
                            Ok(bv.into())
                        }
                        (Some(a), None) => {
                            let n_expr = Expr::Int(a.len() as i64);
                            self.compile_strncmp_builtin(&args[1], &a, &n_expr)
                        }
                        (None, Some(b)) => {
                            let n_expr = Expr::Int(b.len() as i64);
                            self.compile_strncmp_builtin(&args[0], &b, &n_expr)
                        }
                        (None, None) => Err(CodeGenError::TypeError(
                            "starts_with requires at least one string argument (string literal or script string variable) as the first or second parameter".into(),
                        )),
                    }
                }
            },
            Expr::BinaryOp { left, op, right } => {
                let binary_plan = self.plan_binary_expr(left, op, right)?;
                if let BinaryEmitKind::StringComparison(string_plan) = &binary_plan.emit_kind {
                    let other = if string_plan.literal_on_left {
                        right.as_ref()
                    } else {
                        left.as_ref()
                    };
                    return self.compile_string_comparison(
                        other,
                        &string_plan.literal,
                        string_plan.equal,
                    );
                }
                // Implement short-circuit for logical OR (||) and logical AND (&&)
                if matches!(&binary_plan.emit_kind, BinaryEmitKind::LogicalOr) {
                    // Evaluate LHS to boolean (non-zero => true). Accept integer or pointer.
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "lor_lhs_ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer or pointer operands".to_string(),
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
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "lor_rhs_ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical OR requires integer or pointer operands".to_string(),
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
                } else if matches!(&binary_plan.emit_kind, BinaryEmitKind::LogicalAnd) {
                    // Evaluate LHS to boolean (non-zero => true). Accept integer or pointer.
                    let lhs_val = self.compile_expr(left)?;
                    let lhs_int = match lhs_val {
                        BasicValueEnum::IntValue(iv) => iv,
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "land_lhs_ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer or pointer operands".to_string(),
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
                        BasicValueEnum::PointerValue(pv) => self
                            .builder
                            .build_ptr_to_int(pv, self.context.i64_type(), "land_rhs_ptr_as_i64")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?,
                        _ => {
                            return Err(CodeGenError::TypeError(
                                "Logical AND requires integer or pointer operands".to_string(),
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
                self.compile_binary_op_with_ordering(
                    left_val,
                    binary_plan.op,
                    right_val,
                    binary_plan.integer_semantics,
                )
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
                // Address-of computes runtime addresses using the module origin carried by the plan.
                // Transparently support alias variables: &alias -> address of aliased DWARF expression
                let target_inner: &Expr = if let Expr::Variable(var_name) = inner.as_ref() {
                    if self.alias_variable_exists(var_name) {
                        // Use the aliased target expression (by-value) and query DWARF on it
                        let aliased = self
                            .get_alias_variable(var_name)
                            .expect("alias existence just checked");
                        let var =
                            self.query_dwarf_for_complex_expr(&aliased)?
                                .ok_or_else(|| {
                                    super::context::CodeGenError::TypeError(
                                        "cannot take address of unresolved expression".to_string(),
                                    )
                                })?;
                        let pc_address = self.get_compile_time_context()?.pc_address;
                        match self.variable_read_plan_to_runtime_address(&var, pc_address, None) {
                            Ok(address) => {
                                let ptr_ty = self.context.ptr_type(AddressSpace::default());
                                let as_ptr = self
                                    .builder
                                    .build_int_to_ptr(address.value, ptr_ty, "addr_as_ptr")
                                    .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                                return Ok(as_ptr.into());
                            }
                            Err(_) => {
                                return Err(super::context::CodeGenError::TypeError(
                                    "cannot take address of rvalue".to_string(),
                                ));
                            }
                        }
                    } else {
                        inner.as_ref()
                    }
                } else {
                    inner.as_ref()
                };

                if let Some(lvalue) = self.dynamic_lvalue_address_and_type(target_inner)? {
                    let ptr_ty = self.context.ptr_type(AddressSpace::default());
                    let as_ptr = self
                        .builder
                        .build_int_to_ptr(lvalue.address.value, ptr_ty, "addr_as_ptr")
                        .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                    return Ok(as_ptr.into());
                }

                let var = self
                    .query_dwarf_for_complex_expr(target_inner)?
                    .ok_or_else(|| {
                        super::context::CodeGenError::TypeError(
                            "cannot take address of unresolved expression".to_string(),
                        )
                    })?;
                let pc_address = self.get_compile_time_context()?.pc_address;
                match self.variable_read_plan_to_runtime_address(&var, pc_address, None) {
                    Ok(address) => {
                        let ptr_ty = self.context.ptr_type(AddressSpace::default());
                        let as_ptr = self
                            .builder
                            .build_int_to_ptr(address.value, ptr_ty, "addr_as_ptr")
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
            Expr::Cast {
                expr: inner,
                target_type,
            } => self.compile_cast_expr_value(inner, target_type),
            Expr::ChainAccess(_) => {
                // Use unified DWARF expression compilation
                self.compile_dwarf_expression(expr)
            }
        }
    }
}

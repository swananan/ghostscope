use crate::ebpf::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::Expr;
use ghostscope_dwarf::{CIntegerComparisonPlan, CIntegerComparisonType, TypeInfo as DwarfType};
use inkwell::values::BasicValueEnum;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    fn is_dwarf_pointer_or_array_arg(&mut self, expr: &Expr) -> Result<bool> {
        let Some(var) = self.query_dwarf_for_complex_expr(expr)? else {
            return Ok(false);
        };
        let Some(ty) = var.dwarf_type.as_ref() else {
            return Ok(false);
        };
        let ty = ghostscope_dwarf::strip_type_aliases(ty);
        Ok(matches!(
            ty,
            DwarfType::PointerType { .. } | DwarfType::ArrayType { .. }
        ))
    }

    pub(super) fn dwarf_integer_comparison_expr(
        &mut self,
        expr: &Expr,
    ) -> Option<CIntegerComparisonType> {
        if let Expr::Cast { target_type, .. } = expr {
            return self
                .resolve_cast_target_type(target_type)
                .ok()
                .and_then(|ty| ghostscope_dwarf::c_integer_comparison_type(&ty));
        }

        if let Ok(Some(var)) = self.query_dwarf_for_complex_expr(expr) {
            if let Some(ref ty) = var.dwarf_type {
                return ghostscope_dwarf::c_integer_comparison_type(ty);
            }
        }
        None
    }

    fn integer_comparison_plan_for_exprs(
        &mut self,
        left: &Expr,
        right: &Expr,
    ) -> Option<CIntegerComparisonPlan> {
        let left_ty = self.dwarf_integer_comparison_expr(left);
        let right_ty = self.dwarf_integer_comparison_expr(right);
        if left_ty.is_none() && right_ty.is_none() {
            return None;
        }

        Some(ghostscope_dwarf::usual_c_arithmetic_comparison_plan(
            left_ty.unwrap_or_else(CIntegerComparisonType::signed_i64),
            right_ty.unwrap_or_else(CIntegerComparisonType::signed_i64),
        ))
    }

    pub(in crate::ebpf) fn unsigned_ordering_width_for_exprs(
        &mut self,
        left: &Expr,
        right: &Expr,
    ) -> Option<u32> {
        let plan = self.integer_comparison_plan_for_exprs(left, right)?;
        if plan.is_unsigned {
            Some((plan.size * 8) as u32)
        } else {
            None
        }
    }

    pub(in crate::ebpf) fn unsigned_shift_width_for_expr(&mut self, expr: &Expr) -> Option<u32> {
        let c_type = self.dwarf_integer_comparison_expr(expr)?.promoted();
        if c_type.is_unsigned {
            Some((c_type.size * 8) as u32)
        } else {
            None
        }
    }

    /// Ensure that when an expression refers to a DWARF-backed variable (not via address-of),
    /// the variable's DWARF type is a pointer or array (decays to pointer for memcmp/strncmp).
    pub(super) fn ensure_dwarf_pointer_arg(&mut self, e: &Expr, where_ctx: &str) -> Result<()> {
        // Allow explicit address-of forms (&expr), which purposefully produce a pointer
        if matches!(e, Expr::AddressOf(_)) {
            return Ok(());
        }
        if let Some((ptr_side, _)) = self.pointer_arithmetic_parts_expanding_aliases(e)? {
            if matches!(&ptr_side, Expr::AddressOf(_))
                || self
                    .is_dwarf_pointer_or_array_arg(&ptr_side)
                    .unwrap_or(false)
            {
                return Ok(());
            }
        }
        if self.is_dynamic_pointer_arithmetic_expr(e)?
            || self.expands_to_nonliteral_pointer_arithmetic(e)?
        {
            return Ok(());
        }
        match self.query_dwarf_for_complex_expr(e) {
            Ok(Some(var)) => {
                let Some(ty) = var.dwarf_type.as_ref() else {
                    return Err(CodeGenError::TypeError(format!(
                        "{where_ctx}: DWARF variable has no type information"
                    )));
                };
                let ty = ghostscope_dwarf::strip_type_aliases(ty);
                if !matches!(
                    ty,
                    DwarfType::PointerType { .. } | DwarfType::ArrayType { .. }
                ) {
                    return Err(CodeGenError::TypeError(format!(
                        "{where_ctx}: only pointer or array DWARF variables are supported"
                    )));
                }
                Ok(())
            }
            // No DWARF info or analyzer missing: allow script-level pointer values
            Ok(None) | Err(_) => match self.compile_expr(e) {
                Ok(BasicValueEnum::PointerValue(_)) => Ok(()),
                _ => Err(CodeGenError::TypeError(format!(
                    "{where_ctx}: expression is not a pointer"
                ))),
            },
        }
    }

    fn is_dynamic_pointer_arithmetic_expr(&mut self, expr: &Expr) -> Result<bool> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;

        let E::BinaryOp { left, op, right } = expr else {
            return Ok(false);
        };

        match op {
            BO::Add => Ok(self.is_dynamic_indexable_pointer_base(left)?
                || self.is_dynamic_indexable_pointer_base(right)?),
            BO::Subtract => self.is_dynamic_indexable_pointer_base(left),
            _ => Ok(false),
        }
    }

    fn is_dynamic_indexable_pointer_base(&mut self, expr: &Expr) -> Result<bool> {
        if matches!(expr, Expr::AddressOf(_)) {
            return Ok(true);
        }

        if self.cast_index_base(expr)?.is_some() {
            return Ok(true);
        }

        if self
            .query_dwarf_for_complex_expr(expr)
            .ok()
            .flatten()
            .and_then(|var| var.dwarf_type)
            .is_some_and(|ty| ghostscope_dwarf::is_pointer_or_array_type(&ty))
        {
            return Ok(true);
        }

        let expanded = self.expand_alias_variable_expr(expr)?;
        if matches!(expanded, Expr::AddressOf(_)) {
            return Ok(true);
        }
        let Some((base_expr, _static_index)) =
            self.pointer_arithmetic_parts_expanding_aliases(&expanded)?
        else {
            return Ok(false);
        };

        Ok(self
            .query_dwarf_for_complex_expr(&base_expr)
            .ok()
            .flatten()
            .and_then(|var| var.dwarf_type)
            .is_some_and(|ty| ghostscope_dwarf::is_pointer_or_array_type(&ty)))
    }

    pub(super) fn expands_to_nonliteral_pointer_arithmetic(&mut self, expr: &Expr) -> Result<bool> {
        let expanded = self.expand_alias_variable_expr(expr)?;
        self.is_nonliteral_pointer_arithmetic_expr(&expanded)
    }

    fn is_nonliteral_pointer_arithmetic_expr(&mut self, expr: &Expr) -> Result<bool> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;

        let E::BinaryOp { left, op, right } = expr else {
            return Ok(false);
        };

        match op {
            BO::Add => {
                let left_is_ptr = self.is_dynamic_indexable_pointer_base(left)?;
                let right_is_ptr = self.is_dynamic_indexable_pointer_base(right)?;
                let left_is_literal = Self::integer_literal_value(left).is_some();
                let right_is_literal = Self::integer_literal_value(right).is_some();

                if (left_is_ptr && !right_is_ptr && !right_is_literal)
                    || (right_is_ptr && !left_is_ptr && !left_is_literal)
                {
                    return Ok(true);
                }

                Ok(self.expands_to_nonliteral_pointer_arithmetic(left)?
                    || self.expands_to_nonliteral_pointer_arithmetic(right)?)
            }
            BO::Subtract => {
                let left_is_ptr = self.is_dynamic_indexable_pointer_base(left)?;
                let right_is_literal = Self::integer_literal_value(right).is_some();

                if left_is_ptr && !right_is_literal {
                    return Ok(true);
                }

                self.expands_to_nonliteral_pointer_arithmetic(left)
            }
            _ => Ok(false),
        }
    }

    /// Resolve an expression to an i64 pointer value. Accepts integer (address) and pointer values;
    /// falls back to DWARF evaluation for complex expressions.
    pub(crate) fn resolve_ptr_i64_from_expr(
        &mut self,
        e: &Expr,
    ) -> Result<inkwell::values::IntValue<'ctx>> {
        self.resolve_runtime_address_from_expr(e)
            .map(|address| address.value)
    }

    pub(crate) fn resolve_runtime_address_from_expr(
        &mut self,
        e: &Expr,
    ) -> Result<RuntimeAddress<'ctx>> {
        let mut visited = std::collections::HashSet::new();
        self.resolve_runtime_address_from_expr_internal(e, &mut visited, 0)
    }

    fn resolve_runtime_address_from_expr_internal(
        &mut self,
        e: &Expr,
        visited: &mut std::collections::HashSet<String>,
        depth: usize,
    ) -> Result<RuntimeAddress<'ctx>> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;
        use inkwell::values::BasicValueEnum::*;
        const MAX_DEPTH: usize = 64;
        if depth > MAX_DEPTH {
            return Err(CodeGenError::TypeError(
                "alias expansion depth exceeded (cycle?)".into(),
            ));
        }
        if let E::Cast { expr, target_type } = e {
            let target_type_info = self.resolve_cast_target_type(target_type)?;
            if Self::cast_pointer_target_type(&target_type_info).is_some() {
                return self.cast_source_pointer_value(expr);
            }
            return self.cast_source_memory_address(expr);
        }
        // Alias variable indirection: resolve its target expression first
        if let E::Variable(name) = e {
            if self.alias_variable_exists(name) {
                if !visited.insert(name.clone()) {
                    return Err(CodeGenError::TypeError(format!(
                        "alias cycle detected for '{name}'"
                    )));
                }
                if let Some(target) = self.get_alias_variable(name) {
                    let r = self.resolve_runtime_address_from_expr_internal(
                        &target,
                        visited,
                        depth + 1,
                    );
                    visited.remove(name);
                    return r;
                }
            }
        }
        // Special-case: explicit address-of must yield a pointer-sized address
        if let E::AddressOf(inner) = e {
            // Support alias variables transparently: &alias -> address of aliased DWARF expr
            let resolved_inner: &E = if let E::Variable(name) = inner.as_ref() {
                if self.alias_variable_exists(name) {
                    // Owned target for query
                    if let Some(target) = self.get_alias_variable(name) {
                        if let Some(var) = self.query_dwarf_for_complex_expr(&target)? {
                            let status_ptr = if self.condition_context_active {
                                Some(self.get_or_create_cond_error_global())
                            } else {
                                None
                            };
                            let pc_address = self.get_compile_time_context()?.pc_address;
                            return self.variable_read_plan_to_runtime_address(
                                &var, pc_address, status_ptr,
                            );
                        } else {
                            return Err(CodeGenError::TypeError(
                                "cannot take address of unresolved expression".into(),
                            ));
                        }
                    } else {
                        return Err(CodeGenError::TypeError(
                            "cannot take address of unresolved expression".into(),
                        ));
                    }
                } else {
                    inner.as_ref()
                }
            } else {
                inner.as_ref()
            };

            if let E::ArrayAccess(array_expr, index_expr) = resolved_inner {
                if let Some(element_lvalue) =
                    self.compile_dynamic_array_element_address(array_expr, index_expr)?
                {
                    return Ok(element_lvalue.address);
                }
            }

            if let Some(lvalue) = self.dynamic_lvalue_address_and_type(resolved_inner)? {
                return Ok(lvalue.address);
            }

            if let Some(var) = self.query_dwarf_for_complex_expr(resolved_inner)? {
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                let pc_address = self.get_compile_time_context()?.pc_address;
                return self.variable_read_plan_to_runtime_address(&var, pc_address, status_ptr);
            } else {
                return Err(CodeGenError::TypeError(
                    "cannot take address of unresolved expression".into(),
                ));
            }
        }

        if let Some(address) = self.dynamic_pointer_arithmetic_address(e)? {
            return Ok(address);
        }

        if let Some((ptr_side, index)) = self.pointer_arithmetic_parts_expanding_aliases(e)? {
            if matches!(&ptr_side, E::AddressOf(_)) {
                let base =
                    self.resolve_runtime_address_from_expr_internal(&ptr_side, visited, depth + 1)?;
                let off = self.context.i64_type().const_int(index as u64, false);
                let value = self
                    .builder
                    .build_int_add(base.value, off, "ptr_add")
                    .map_err(|err| CodeGenError::Builder(err.to_string()))?;
                return Ok(base.with_value(value));
            } else if let Some((element_info, base_address)) = self.cast_index_base(&ptr_side)? {
                let index_value = self.context.i64_type().const_int(index as u64, true);
                return self
                    .dynamic_lvalue_from_indexable_base(
                        element_info,
                        base_address,
                        index_value,
                        "cast_ptr_add",
                    )
                    .map(|lvalue| lvalue.address);
            } else if let Some(var) = self.query_dwarf_for_complex_expr(&ptr_side)? {
                if var.dwarf_type.is_some() {
                    let pointed_plan = self.plan_dwarf_pointer_element_index(&var, index)?;
                    let status_ptr = if self.condition_context_active {
                        Some(self.get_or_create_cond_error_global())
                    } else {
                        None
                    };
                    let pc_address = self.get_compile_time_context()?.pc_address;
                    return self.variable_read_plan_to_runtime_address(
                        &pointed_plan,
                        pc_address,
                        status_ptr,
                    );
                }
            }
        }

        // Support constant-offset addressing: (alias_expr + K) or (K + alias_expr)
        if let E::BinaryOp { left, op, right } = e {
            if matches!(op, BO::Add) {
                // alias + K
                if let Some(k) = Self::integer_literal_value(right) {
                    if let Ok(base) =
                        self.resolve_runtime_address_from_expr_internal(left, visited, depth + 1)
                    {
                        let off = self.context.i64_type().const_int(k as u64, false);
                        let value = self
                            .builder
                            .build_int_add(base.value, off, "ptr_add")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(base.with_value(value));
                    }
                }
                // K + alias
                if let Some(k) = Self::integer_literal_value(left) {
                    if let Ok(base) =
                        self.resolve_runtime_address_from_expr_internal(right, visited, depth + 1)
                    {
                        let off = self.context.i64_type().const_int(k as u64, false);
                        let value = self
                            .builder
                            .build_int_add(base.value, off, "ptr_add")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(base.with_value(value));
                    }
                }
            } else if matches!(op, BO::Subtract) {
                if let Some(k) = Self::integer_literal_value(right) {
                    if let Ok(base) =
                        self.resolve_runtime_address_from_expr_internal(left, visited, depth + 1)
                    {
                        let off = self
                            .context
                            .i64_type()
                            .const_int(k.wrapping_neg() as u64, false);
                        let value = self
                            .builder
                            .build_int_add(base.value, off, "ptr_sub")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(base.with_value(value));
                    }
                }
            }
        }
        // Prefer DWARF-based address resolution first so that array/aggregate
        // expressions decay to their base address rather than loading values.
        if let Ok(Some(var)) = self.query_dwarf_for_complex_expr(e) {
            if let Some(dty) = var.dwarf_type.as_ref() {
                let dty = ghostscope_dwarf::strip_type_aliases(dty);
                match dty {
                    DwarfType::PointerType { .. } => {
                        let pc_address = self.get_compile_time_context()?.pc_address;
                        let val_any =
                            self.variable_read_plan_to_llvm_value(&var, pc_address, None)?;
                        match val_any {
                            IntValue(iv) => Ok(RuntimeAddress::available(iv, self.context)),
                            PointerValue(pv) => self
                                .builder
                                .build_ptr_to_int(pv, self.context.i64_type(), "ptr_as_i64")
                                .map(|value| RuntimeAddress::available(value, self.context))
                                .map_err(|e| CodeGenError::Builder(e.to_string())),
                            _ => Err(CodeGenError::TypeError(
                                "DWARF value is not pointer/integer".into(),
                            )),
                        }
                    }
                    DwarfType::ArrayType { .. } => {
                        // Use the base address of the array as pointer
                        let status_ptr = if self.condition_context_active {
                            Some(self.get_or_create_cond_error_global())
                        } else {
                            None
                        };
                        let pc_address = self.get_compile_time_context()?.pc_address;
                        self.variable_read_plan_to_runtime_address(&var, pc_address, status_ptr)
                    }
                    _ => Err(CodeGenError::TypeError(
                        "DWARF value is not pointer/array".into(),
                    )),
                }
            } else {
                let status_ptr = if self.condition_context_active {
                    Some(self.get_or_create_cond_error_global())
                } else {
                    None
                };
                let pc_address = self.get_compile_time_context()?.pc_address;
                self.variable_read_plan_to_runtime_address(&var, pc_address, status_ptr)
            }
        } else {
            // No DWARF-backed address and not an address-of/alias+const: reject script-level pointers.
            Err(CodeGenError::TypeError(
                "expression is not a pointer/address".into(),
            ))
        }
    }

    fn dynamic_pointer_arithmetic_address(
        &mut self,
        expr: &Expr,
    ) -> Result<Option<RuntimeAddress<'ctx>>> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;

        let E::BinaryOp { left, op, right } = expr else {
            return Ok(None);
        };

        match op {
            BO::Add => {
                if let Some(address) = self.dynamic_raw_address_candidate(left, right, false)? {
                    return Ok(Some(address));
                }
                if let Some(address) = self.dynamic_raw_address_candidate(right, left, false)? {
                    return Ok(Some(address));
                }
                if let Some(address) = self.dynamic_index_address_candidate(left, right)? {
                    return Ok(Some(address));
                }
                self.dynamic_index_address_candidate(right, left)
            }
            BO::Subtract => {
                if let Some(address) = self.dynamic_raw_address_candidate(left, right, true)? {
                    return Ok(Some(address));
                }
                let negative_right = E::BinaryOp {
                    left: Box::new(E::Int(0)),
                    op: BO::Subtract,
                    right: right.clone(),
                };
                self.dynamic_index_address_candidate(left, &negative_right)
            }
            _ => Ok(None),
        }
    }

    fn dynamic_raw_address_candidate(
        &mut self,
        base_expr: &Expr,
        offset_expr: &Expr,
        subtract: bool,
    ) -> Result<Option<RuntimeAddress<'ctx>>> {
        if Self::integer_literal_value(offset_expr).is_some() {
            return Ok(None);
        }

        let expanded_base = self.expand_alias_variable_expr(base_expr)?;
        if !matches!(expanded_base, Expr::AddressOf(_)) {
            return Ok(None);
        }

        let base_address = self.resolve_runtime_address_from_expr(&expanded_base)?;
        let offset = match self.compile_expr(offset_expr)? {
            BasicValueEnum::IntValue(value) => {
                self.normalize_int_to_i64(value, "dynamic_raw_offset_i64")?
            }
            _ => {
                return Err(CodeGenError::TypeError(
                    "raw address offset expression must compile to an integer".to_string(),
                ))
            }
        };
        let offset = if subtract {
            self.builder
                .build_int_neg(offset, "dynamic_raw_offset_neg")
                .map_err(|err| CodeGenError::Builder(err.to_string()))?
        } else {
            offset
        };
        let address = self
            .builder
            .build_int_add(base_address.value, offset, "dynamic_raw_address")
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;
        Ok(Some(base_address.with_value(address)))
    }

    fn dynamic_index_address_candidate(
        &mut self,
        base_expr: &Expr,
        index_expr: &Expr,
    ) -> Result<Option<RuntimeAddress<'ctx>>> {
        match self.compile_dynamic_array_element_address(base_expr, index_expr) {
            Ok(Some(element_lvalue)) => Ok(Some(element_lvalue.address)),
            Ok(None) => Ok(None),
            Err(CodeGenError::VariableNotFound(_))
            | Err(CodeGenError::VariableNotInScope(_))
            | Err(CodeGenError::TypeError(_)) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

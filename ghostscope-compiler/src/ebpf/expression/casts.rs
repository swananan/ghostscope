use super::{DynamicLvalue, DynamicTypeInfo, IndexableElementInfo};
use crate::ebpf::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::Expr;
use ghostscope_dwarf::TypeInfo as DwarfType;
use inkwell::values::{BasicValueEnum, IntValue};
use inkwell::AddressSpace;
use std::path::{Path, PathBuf};

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(in crate::ebpf) fn is_dwarf_aggregate_expr(&mut self, expr: &Expr) -> bool {
        if let Expr::Cast { target_type, .. } = expr {
            return self
                .resolve_cast_target_type(target_type)
                .ok()
                .is_some_and(|ty| ghostscope_dwarf::is_c_aggregate_type(&ty));
        }

        if let Ok(Some(var)) = self.query_dwarf_for_complex_expr(expr) {
            if let Some(ref ty) = var.dwarf_type {
                return ghostscope_dwarf::is_c_aggregate_type(ty);
            }
        }
        false
    }

    /// Heuristic check: whether an expression should be treated as a pointer/address
    /// Returns true for:
    /// - Explicit address-of forms (&expr)
    /// - Script string literals (compile to pointer data)
    /// - Alias variables bound to addresses
    /// - DWARF-backed expressions whose type is pointer or array
    pub(in crate::ebpf) fn is_pointer_like_expr(&mut self, expr: &Expr) -> bool {
        use crate::script::Expr as E;
        match expr {
            E::AddressOf(_) => return true,
            E::String(_) => return true,
            E::Cast { target_type, .. } => {
                if self
                    .resolve_cast_target_type(target_type)
                    .ok()
                    .is_some_and(|ty| {
                        matches!(
                            ghostscope_dwarf::strip_type_aliases(&ty),
                            DwarfType::PointerType { .. } | DwarfType::ArrayType { .. }
                        )
                    })
                {
                    return true;
                }
            }
            E::Variable(name) => {
                if self.alias_variable_exists(name) {
                    return true;
                }
            }
            _ => {}
        }

        if let Ok(Some(var)) = self.query_dwarf_for_complex_expr(expr) {
            if let Some(ref ty) = var.dwarf_type {
                if ghostscope_dwarf::is_c_pointer_or_array_type(ty) {
                    return true;
                }
            }
        }
        false
    }

    pub(in crate::ebpf) fn resolve_cast_target_type(&self, target_type: &str) -> Result<DwarfType> {
        let analyzer = self.process_analyzer;
        let resolved = if let Some(context) = self.current_compile_time_context.as_ref() {
            let module_path = Path::new(&context.module_path);
            analyzer
                .map(|analyzer| analyzer.try_resolve_type_spec_in_module(module_path, target_type))
                .transpose()
                .map_err(|err| CodeGenError::DwarfError(err.to_string()))?
                .flatten()
                .or_else(|| ghostscope_dwarf::DwarfAnalyzer::resolve_builtin_type_spec(target_type))
        } else {
            analyzer
                .map(|analyzer| analyzer.try_resolve_type_spec(target_type))
                .transpose()
                .map_err(|err| CodeGenError::DwarfError(err.to_string()))?
                .flatten()
                .or_else(|| ghostscope_dwarf::DwarfAnalyzer::resolve_builtin_type_spec(target_type))
        };

        resolved.ok_or_else(|| {
            CodeGenError::DwarfError(format!("cast target type '{target_type}' was not found"))
        })
    }

    pub(super) fn cast_pointer_target_type(target_type: &DwarfType) -> Option<DwarfType> {
        match ghostscope_dwarf::strip_type_aliases(target_type) {
            DwarfType::PointerType { target_type, .. } => Some(target_type.as_ref().clone()),
            _ => None,
        }
    }

    fn is_float_dwarf_type(target_type: &DwarfType) -> bool {
        match ghostscope_dwarf::strip_type_aliases(target_type) {
            DwarfType::BaseType { encoding, .. } => {
                *encoding == ghostscope_dwarf::constants::DW_ATE_float.0 as u16
            }
            _ => false,
        }
    }

    fn is_bool_dwarf_type(target_type: &DwarfType) -> bool {
        match ghostscope_dwarf::strip_type_aliases(target_type) {
            DwarfType::BaseType { encoding, .. } => {
                *encoding == ghostscope_dwarf::constants::DW_ATE_boolean.0 as u16
            }
            _ => false,
        }
    }

    pub(in crate::ebpf) fn cast_value_byte_len(target_type: &DwarfType) -> Option<usize> {
        if matches!(
            ghostscope_dwarf::strip_type_aliases(target_type),
            DwarfType::PointerType { .. }
        ) {
            return Some(8);
        }

        if let Some(integer_type) = ghostscope_dwarf::c_integer_comparison_type(target_type) {
            return Some(integer_type.size.clamp(1, 8) as usize);
        }

        None
    }

    pub(in crate::ebpf) fn cast_source_pointer_value(
        &mut self,
        expr: &Expr,
    ) -> Result<RuntimeAddress<'ctx>> {
        if let Ok(address) = self.resolve_runtime_address_from_expr(expr) {
            return Ok(address);
        }

        match self.compile_expr(expr)? {
            BasicValueEnum::IntValue(value) => Ok(RuntimeAddress::available(
                self.normalize_int_to_i64(value, "cast_ptr_i64")?,
                self.context,
            )),
            BasicValueEnum::PointerValue(value) => self
                .builder
                .build_ptr_to_int(value, self.context.i64_type(), "cast_ptr_value")
                .map(|value| RuntimeAddress::available(value, self.context))
                .map_err(|err| CodeGenError::Builder(err.to_string())),
            _ => Err(CodeGenError::TypeError(
                "cast source expression did not produce an address-sized value".to_string(),
            )),
        }
    }

    pub(in crate::ebpf) fn cast_source_memory_address(
        &mut self,
        expr: &Expr,
    ) -> Result<RuntimeAddress<'ctx>> {
        if let Ok(address) = self.resolve_runtime_address_from_expr(expr) {
            return Ok(address);
        }

        if let Some(plan) = self.query_dwarf_for_complex_expr(expr)? {
            let status_ptr = if self.condition_context_active {
                Some(self.get_or_create_cond_error_global())
            } else {
                None
            };
            let pc_address = self.get_compile_time_context()?.pc_address;
            if let Ok(address) =
                self.variable_read_plan_to_runtime_address(&plan, pc_address, status_ptr)
            {
                return Ok(address);
            }
        }

        match self.compile_expr(expr)? {
            BasicValueEnum::IntValue(value) => Ok(RuntimeAddress::available(
                self.normalize_int_to_i64(value, "cast_mem_i64")?,
                self.context,
            )),
            BasicValueEnum::PointerValue(value) => self
                .builder
                .build_ptr_to_int(value, self.context.i64_type(), "cast_mem_ptr")
                .map(|value| RuntimeAddress::available(value, self.context))
                .map_err(|err| CodeGenError::Builder(err.to_string())),
            _ => Err(CodeGenError::TypeError(
                "cast source expression is not addressable".to_string(),
            )),
        }
    }

    pub(super) fn cast_lvalue_address_and_type(
        &mut self,
        expr: &Expr,
        target_type: &str,
    ) -> Result<DynamicLvalue<'ctx>> {
        let target_type = self.resolve_cast_target_type(target_type)?;
        let module_path = self
            .current_compile_time_context
            .as_ref()
            .map(|context| PathBuf::from(&context.module_path));

        if let Some(pointee_type) = Self::cast_pointer_target_type(&target_type) {
            let address = self.cast_source_pointer_value(expr)?;
            return Ok(DynamicLvalue {
                address,
                type_info: DynamicTypeInfo {
                    dwarf_type: pointee_type,
                    module_path,
                    type_id: None,
                },
            });
        }

        let address = self.cast_source_memory_address(expr)?;
        Ok(DynamicLvalue {
            address,
            type_info: DynamicTypeInfo {
                dwarf_type: target_type,
                module_path,
                type_id: None,
            },
        })
    }

    pub(super) fn cast_index_base(
        &mut self,
        expr: &Expr,
    ) -> Result<Option<(IndexableElementInfo, RuntimeAddress<'ctx>)>> {
        let Expr::Cast {
            expr: source_expr,
            target_type,
        } = expr
        else {
            return Ok(None);
        };

        let target_type = self.resolve_cast_target_type(target_type)?;
        let module_path = self
            .current_compile_time_context
            .as_ref()
            .map(|context| PathBuf::from(&context.module_path));

        match ghostscope_dwarf::strip_type_aliases(&target_type) {
            DwarfType::PointerType { .. } => {
                let Some(element_info) =
                    Self::indexable_info_from_type(&target_type, module_path, None)
                else {
                    return Ok(None);
                };
                let base_address = self.cast_source_pointer_value(source_expr)?;
                Ok(Some((element_info, base_address)))
            }
            DwarfType::ArrayType { .. } => {
                let Some(element_info) =
                    Self::indexable_info_from_type(&target_type, module_path, None)
                else {
                    return Ok(None);
                };
                let base_address = self.cast_source_memory_address(source_expr)?;
                Ok(Some((element_info, base_address)))
            }
            _ => Ok(None),
        }
    }

    pub(super) fn indexable_info_from_type(
        dwarf_type: &DwarfType,
        module_path: Option<PathBuf>,
        type_id: Option<ghostscope_dwarf::TypeId>,
    ) -> Option<IndexableElementInfo> {
        ghostscope_dwarf::indexable_element_layout(dwarf_type).map(|layout| IndexableElementInfo {
            element_type: layout.element_type,
            stride: layout.stride,
            module_path,
            type_id,
        })
    }

    pub(super) fn compiled_pointer_value_to_runtime_address(
        &mut self,
        value: BasicValueEnum<'ctx>,
        int_name: &str,
        ptr_name: &str,
        error_message: &'static str,
    ) -> Result<RuntimeAddress<'ctx>> {
        match value {
            BasicValueEnum::IntValue(value) => Ok(RuntimeAddress::available(
                self.normalize_int_to_i64(value, int_name)?,
                self.context,
            )),
            BasicValueEnum::PointerValue(value) => self
                .builder
                .build_ptr_to_int(value, self.context.i64_type(), ptr_name)
                .map(|value| RuntimeAddress::available(value, self.context))
                .map_err(|err| CodeGenError::Builder(err.to_string())),
            _ => Err(CodeGenError::TypeError(error_message.to_string())),
        }
    }

    pub(super) fn dynamic_lvalue_from_indexable_base(
        &mut self,
        element_info: IndexableElementInfo,
        base_address: RuntimeAddress<'ctx>,
        index_value: IntValue<'ctx>,
        name: &str,
    ) -> Result<DynamicLvalue<'ctx>> {
        let stride_value = self
            .context
            .i64_type()
            .const_int(element_info.stride, false);
        let byte_offset = self
            .builder
            .build_int_mul(index_value, stride_value, &format!("{name}_byte_offset"))
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;
        let element_address = self
            .builder
            .build_int_add(
                base_address.value,
                byte_offset,
                &format!("{name}_element_address"),
            )
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;

        Ok(DynamicLvalue {
            address: base_address.with_value(element_address),
            type_info: DynamicTypeInfo {
                dwarf_type: element_info.element_type,
                module_path: element_info.module_path,
                type_id: element_info.type_id,
            },
        })
    }

    pub(super) fn dynamic_lvalue_from_const_pointer_arithmetic(
        &mut self,
        expr: &Expr,
    ) -> Result<Option<DynamicLvalue<'ctx>>> {
        let Some((base_expr, index)) = self.pointer_arithmetic_parts_expanding_aliases(expr)?
        else {
            return Ok(None);
        };
        let Some((element_info, base_address)) = self.cast_index_base(&base_expr)? else {
            return Ok(None);
        };
        let index_value = self.context.i64_type().const_int(index as u64, true);
        self.dynamic_lvalue_from_indexable_base(
            element_info,
            base_address,
            index_value,
            "dynamic_cast_ptr_arith",
        )
        .map(Some)
    }

    fn compile_cast_integer_value(
        &mut self,
        expr: &Expr,
        target_type: &DwarfType,
    ) -> Result<IntValue<'ctx>> {
        let value = match self.compile_expr(expr)? {
            BasicValueEnum::IntValue(value) => value,
            BasicValueEnum::PointerValue(value) => self
                .builder
                .build_ptr_to_int(value, self.context.i64_type(), "cast_int_ptr")
                .map_err(|err| CodeGenError::Builder(err.to_string()))?,
            _ => {
                return Err(CodeGenError::TypeError(
                    "integer cast source must be an integer or pointer".to_string(),
                ))
            }
        };

        if Self::is_bool_dwarf_type(target_type) {
            let value = self.normalize_int_to_i64(value, "cast_bool_i64")?;
            return self
                .builder
                .build_int_compare(
                    inkwell::IntPredicate::NE,
                    value,
                    self.context.i64_type().const_zero(),
                    "cast_bool",
                )
                .map_err(|err| CodeGenError::Builder(err.to_string()));
        }

        let Some(integer_type) = ghostscope_dwarf::c_integer_comparison_type(target_type) else {
            return Err(CodeGenError::TypeError(format!(
                "cast target '{}' is not an integer type",
                target_type.type_name()
            )));
        };

        let bit_width = integer_type.size.saturating_mul(8).clamp(1, 64) as u32;
        let target_int_type = self.context.custom_width_int_type(bit_width);
        let current_width = value.get_type().get_bit_width();
        let narrowed = if current_width > bit_width {
            self.builder
                .build_int_truncate(value, target_int_type, "cast_int_trunc")
                .map_err(|err| CodeGenError::Builder(err.to_string()))?
        } else if current_width < bit_width {
            if integer_type.is_unsigned || current_width == 1 {
                self.builder
                    .build_int_z_extend(value, target_int_type, "cast_int_zext")
                    .map_err(|err| CodeGenError::Builder(err.to_string()))?
            } else {
                self.builder
                    .build_int_s_extend(value, target_int_type, "cast_int_sext")
                    .map_err(|err| CodeGenError::Builder(err.to_string()))?
            }
        } else {
            value
        };

        if bit_width == 64 {
            return Ok(narrowed);
        }

        if integer_type.is_unsigned {
            self.builder
                .build_int_z_extend(narrowed, self.context.i64_type(), "cast_int_zext_i64")
                .map_err(|err| CodeGenError::Builder(err.to_string()))
        } else {
            self.builder
                .build_int_s_extend(narrowed, self.context.i64_type(), "cast_int_sext_i64")
                .map_err(|err| CodeGenError::Builder(err.to_string()))
        }
    }

    pub(super) fn compile_cast_expr_value(
        &mut self,
        expr: &Expr,
        target_type: &str,
    ) -> Result<BasicValueEnum<'ctx>> {
        let target_type = self.resolve_cast_target_type(target_type)?;

        if Self::cast_pointer_target_type(&target_type).is_some() {
            let address = self.cast_source_pointer_value(expr)?;
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            return self
                .builder
                .build_int_to_ptr(address.value, ptr_ty, "cast_as_ptr")
                .map(|value| value.into())
                .map_err(|err| CodeGenError::Builder(err.to_string()));
        }

        if ghostscope_dwarf::is_c_aggregate_type(&target_type) {
            let address = self.cast_source_memory_address(expr)?;
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            return self
                .builder
                .build_int_to_ptr(address.value, ptr_ty, "cast_aggregate_ptr")
                .map(|value| value.into())
                .map_err(|err| CodeGenError::Builder(err.to_string()));
        }

        if ghostscope_dwarf::c_integer_comparison_type(&target_type).is_some() {
            return self
                .compile_cast_integer_value(expr, &target_type)
                .map(|value| value.into());
        }

        if Self::is_float_dwarf_type(&target_type) {
            return Err(CodeGenError::TypeError(
                "floating-point casts are only supported for memory reads/printing".to_string(),
            ));
        }

        Err(CodeGenError::TypeError(format!(
            "cast target '{}' is not supported as a value expression",
            target_type.type_name()
        )))
    }

    pub(crate) fn integer_literal_value(expr: &Expr) -> Option<i64> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;

        match expr {
            E::Int(value) => Some(*value),
            E::BinaryOp {
                left,
                op: BO::Add,
                right,
            } => {
                Self::integer_literal_value(left)?.checked_add(Self::integer_literal_value(right)?)
            }
            E::BinaryOp {
                left,
                op: BO::Subtract,
                right,
            } => {
                Self::integer_literal_value(left)?.checked_sub(Self::integer_literal_value(right)?)
            }
            E::BinaryOp {
                left,
                op: BO::Multiply,
                right,
            } => {
                Self::integer_literal_value(left)?.checked_mul(Self::integer_literal_value(right)?)
            }
            E::BinaryOp {
                left,
                op: BO::Divide,
                right,
            } => {
                Self::integer_literal_value(left)?.checked_div(Self::integer_literal_value(right)?)
            }
            E::BinaryOp {
                left,
                op: BO::Modulo,
                right,
            } => {
                Self::integer_literal_value(left)?.checked_rem(Self::integer_literal_value(right)?)
            }
            E::BinaryOp {
                left,
                op: BO::BitAnd,
                right,
            } => Some(Self::integer_literal_value(left)? & Self::integer_literal_value(right)?),
            E::BinaryOp {
                left,
                op: BO::BitXor,
                right,
            } => Some(Self::integer_literal_value(left)? ^ Self::integer_literal_value(right)?),
            E::BinaryOp {
                left,
                op: BO::BitOr,
                right,
            } => Some(Self::integer_literal_value(left)? | Self::integer_literal_value(right)?),
            E::BinaryOp {
                left,
                op: BO::ShiftLeft,
                right,
            } => {
                let shift = u32::try_from(Self::integer_literal_value(right)?).ok()?;
                Self::integer_literal_value(left)?.checked_shl(shift)
            }
            E::BinaryOp {
                left,
                op: BO::ShiftRight,
                right,
            } => {
                let shift = u32::try_from(Self::integer_literal_value(right)?).ok()?;
                Self::integer_literal_value(left)?.checked_shr(shift)
            }
            E::UnaryBitNot(inner) => Some(!Self::integer_literal_value(inner)?),
            _ => None,
        }
    }

    pub(in crate::ebpf) fn pointer_arithmetic_parts(expr: &Expr) -> Option<(&Expr, i64)> {
        use crate::script::ast::Expr as E;

        fn collect_offset(expr: &Expr, acc: i64) -> Option<(&Expr, i64)> {
            use crate::script::ast::BinaryOp as BO;
            use crate::script::ast::Expr as E;

            match expr {
                E::BinaryOp {
                    left,
                    op: BO::Add,
                    right,
                } => match (&**left, &**right) {
                    (ptr_side, int_expr)
                        if EbpfContext::<'static, 'static>::integer_literal_value(int_expr)
                            .is_some() =>
                    {
                        let index =
                            EbpfContext::<'static, 'static>::integer_literal_value(int_expr)?;
                        collect_offset(ptr_side, acc.checked_add(index)?)
                    }
                    (int_expr, ptr_side)
                        if EbpfContext::<'static, 'static>::integer_literal_value(int_expr)
                            .is_some() =>
                    {
                        let index =
                            EbpfContext::<'static, 'static>::integer_literal_value(int_expr)?;
                        collect_offset(ptr_side, acc.checked_add(index)?)
                    }
                    _ => Some((expr, acc)),
                },
                E::BinaryOp {
                    left,
                    op: BO::Subtract,
                    right,
                } => match &**right {
                    int_expr
                        if EbpfContext::<'static, 'static>::integer_literal_value(int_expr)
                            .is_some() =>
                    {
                        let index =
                            EbpfContext::<'static, 'static>::integer_literal_value(int_expr)?;
                        collect_offset(left, acc.checked_sub(index)?)
                    }
                    _ => Some((expr, acc)),
                },
                _ => Some((expr, acc)),
            }
        }

        let E::BinaryOp { .. } = expr else {
            return None;
        };

        let (base, index) = collect_offset(expr, 0)?;
        match base {
            E::BinaryOp { .. } => None,
            _ => Some((base, index)),
        }
    }

    pub(in crate::ebpf) fn pointer_arithmetic_parts_expanding_aliases(
        &self,
        expr: &Expr,
    ) -> Result<Option<(Expr, i64)>> {
        let Some((base, index)) = Self::pointer_arithmetic_parts(expr) else {
            return Ok(None);
        };

        let mut base = base.clone();
        let mut index = index;
        let mut visited = std::collections::HashSet::new();

        loop {
            let Expr::Variable(name) = &base else {
                break;
            };
            if !self.alias_variable_exists(name) {
                break;
            }
            if !visited.insert(name.clone()) {
                return Err(CodeGenError::TypeError(format!(
                    "alias cycle detected for '{name}'"
                )));
            }
            let Some(target) = self.get_alias_variable(name) else {
                break;
            };
            if let Some((alias_base, alias_index)) = Self::pointer_arithmetic_parts(&target) {
                index = alias_index.checked_add(index).ok_or_else(|| {
                    CodeGenError::TypeError("pointer arithmetic offset overflow".to_string())
                })?;
                base = alias_base.clone();
            } else {
                base = target;
            }
        }

        Ok(Some((base, index)))
    }
}

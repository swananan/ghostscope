use super::{DynamicLvalue, DynamicTypeInfo, IndexableElementInfo};
use crate::ebpf::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::Expr;
use ghostscope_dwarf::{
    AmbiguityReason, Availability, RuntimeRequirement, TypeInfo as DwarfType, TypeLayoutError,
    UnsupportedReason, VariableAccessSegment, VariableReadPlan,
};
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;
use std::path::{Path, PathBuf};
use tracing::debug;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
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
        if let Some((value, _element_type)) =
            self.compile_dynamic_array_access_value(array_expr, index_expr)?
        {
            return Ok(value);
        }

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

        if let crate::script::Expr::Cast {
            expr: inner,
            target_type,
        } = expr
        {
            return self.compile_cast_expr_value(inner, target_type);
        }

        if let crate::script::Expr::ArrayAccess(array_expr, index_expr) = expr {
            if let Some((value, _element_type)) =
                self.compile_dynamic_array_access_value(array_expr, index_expr)?
            {
                return Ok(value);
            }
        }
        if let crate::script::Expr::MemberAccess(obj_expr, field) = expr {
            if let Some((value, _member_type)) =
                self.compile_dynamic_member_access_value(obj_expr, field)?
            {
                return Ok(value);
            }
        }
        if let crate::script::Expr::TupleAccess(obj_expr, index) = expr {
            if let Some((value, _member_type)) =
                self.compile_dynamic_tuple_access_value(obj_expr, *index)?
            {
                return Ok(value);
            }
        }
        if matches!(expr, crate::script::Expr::PointerDeref(_)) {
            if let Some(lvalue) = self.dynamic_lvalue_address_and_type(expr)? {
                return self
                    .read_dynamic_address_value(lvalue.address, &lvalue.type_info.dwarf_type);
            }
        }

        // Query DWARF for the complex expression
        let compile_context = self.get_compile_time_context()?.clone();
        let variable_plan = match self.query_dwarf_for_complex_expr(expr)? {
            Some(var) => var,
            None => {
                let expr_str = Self::expr_to_debug_string(expr);
                return Err(CodeGenError::VariableNotFound(expr_str));
            }
        };

        let materialized =
            self.variable_read_plan_to_materialization(variable_plan, compile_context.pc_address)?;
        let dwarf_type = materialized.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Expression has no DWARF type information".to_string())
        })?;

        debug!(
            "compile_dwarf_expression: Found DWARF info for expression '{}' with type: {:?}",
            materialized.name, dwarf_type
        );

        self.variable_materialization_to_llvm_value(&materialized, compile_context.pc_address, None)
    }

    pub(in crate::ebpf) fn compile_dynamic_array_access_value(
        &mut self,
        array_expr: &Expr,
        index_expr: &Expr,
    ) -> Result<Option<(BasicValueEnum<'ctx>, DwarfType)>> {
        let Some(element_lvalue) =
            self.compile_dynamic_array_element_address(array_expr, index_expr)?
        else {
            return Ok(None);
        };

        let value = self.read_dynamic_address_value(
            element_lvalue.address,
            &element_lvalue.type_info.dwarf_type,
        )?;
        Ok(Some((value, element_lvalue.type_info.dwarf_type)))
    }

    pub(in crate::ebpf) fn compile_dynamic_member_access_value(
        &mut self,
        obj_expr: &Expr,
        field: &str,
    ) -> Result<Option<(BasicValueEnum<'ctx>, DwarfType)>> {
        let Some(object_lvalue) = self.dynamic_lvalue_address_and_type(obj_expr)? else {
            return Ok(None);
        };

        let Some(element_lvalue) = self.dynamic_member_base_address_and_type(object_lvalue)? else {
            return Ok(None);
        };
        let (member_offset, member_type) =
            self.dynamic_member_offset_and_type(&element_lvalue.type_info, field)?;

        let member_offset = self.context.i64_type().const_int(member_offset, false);
        let member_address = self
            .builder
            .build_int_add(
                element_lvalue.address.value,
                member_offset,
                "dynamic_member_address",
            )
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;
        let value = self.read_dynamic_address_value(
            element_lvalue.address.with_value(member_address),
            &member_type,
        )?;
        Ok(Some((value, member_type)))
    }

    pub(in crate::ebpf) fn compile_dynamic_tuple_access_value(
        &mut self,
        obj_expr: &Expr,
        index: u32,
    ) -> Result<Option<(BasicValueEnum<'ctx>, DwarfType)>> {
        let tuple_expr = Expr::TupleAccess(Box::new(obj_expr.clone()), index);
        let Some(member_lvalue) = self.dynamic_lvalue_address_and_type(&tuple_expr)? else {
            return Ok(None);
        };
        let member_type = member_lvalue.type_info.dwarf_type;
        let value = self.read_dynamic_address_value(member_lvalue.address, &member_type)?;
        Ok(Some((value, member_type)))
    }

    pub(in crate::ebpf) fn dynamic_lvalue_address_and_type(
        &mut self,
        expr: &Expr,
    ) -> Result<Option<DynamicLvalue<'ctx>>> {
        if let Expr::Variable(name) = expr {
            if self.alias_variable_exists(name) {
                let expanded = self.expand_alias_variable_expr(expr)?;
                return self.dynamic_lvalue_address_and_type(&expanded);
            }
        }

        if let Expr::Cast {
            expr: inner,
            target_type,
        } = expr
        {
            return self
                .cast_lvalue_address_and_type(inner, target_type)
                .map(Some);
        }

        if let Expr::PointerDeref(inner) = expr {
            let expanded_inner = self.expand_alias_variable_expr(inner)?;
            if matches!(expanded_inner, Expr::Cast { .. }) {
                return self.dynamic_lvalue_address_and_type(&expanded_inner);
            }
            if let Expr::BinaryOp { .. } = expanded_inner {
                if let Some(lvalue) = self.dynamic_lvalue_address_and_type(&expanded_inner)? {
                    return Ok(Some(lvalue));
                }
            }
        }

        if let Expr::ArrayAccess(array_expr, index_expr) = expr {
            return self.compile_dynamic_array_element_address(array_expr, index_expr);
        }

        if let Some(lvalue) = self.dynamic_lvalue_from_const_pointer_arithmetic(expr)? {
            return Ok(Some(lvalue));
        }

        if self.expands_to_nonliteral_pointer_arithmetic(expr)? {
            let Some(element_info) = self.indexable_element_type_and_stride(expr)? else {
                return Ok(None);
            };
            let element_address = self.resolve_runtime_address_from_expr(expr)?;
            return Ok(Some(DynamicLvalue {
                address: element_address,
                type_info: DynamicTypeInfo {
                    dwarf_type: element_info.element_type,
                    module_path: element_info.module_path,
                    type_id: element_info.type_id,
                },
            }));
        }

        if let Expr::MemberAccess(obj_expr, field) = expr {
            let Some(object_lvalue) = self.dynamic_lvalue_address_and_type(obj_expr)? else {
                return Ok(None);
            };
            let Some(base_lvalue) = self.dynamic_member_base_address_and_type(object_lvalue)?
            else {
                return Ok(None);
            };
            let (member_offset, member_type) =
                self.dynamic_member_offset_and_type(&base_lvalue.type_info, field)?;
            let member_type_id = self.project_dynamic_type_id(
                base_lvalue.type_info.type_id,
                &VariableAccessSegment::Field(field.clone()),
            )?;
            let member_offset = self.context.i64_type().const_int(member_offset, false);
            let member_address = self
                .builder
                .build_int_add(
                    base_lvalue.address.value,
                    member_offset,
                    "dynamic_member_lvalue_address",
                )
                .map_err(|err| CodeGenError::Builder(err.to_string()))?;
            return Ok(Some(DynamicLvalue {
                address: base_lvalue.address.with_value(member_address),
                type_info: DynamicTypeInfo {
                    dwarf_type: member_type,
                    module_path: base_lvalue.type_info.module_path,
                    type_id: member_type_id,
                },
            }));
        }

        if let Expr::TupleAccess(obj_expr, index) = expr {
            let Some(object_lvalue) = self.dynamic_lvalue_address_and_type(obj_expr)? else {
                return Ok(None);
            };
            let Some(base_lvalue) = self.dynamic_member_base_address_and_type(object_lvalue)?
            else {
                return Ok(None);
            };
            let module_path = base_lvalue.type_info.module_path.clone();
            let (member_offset, member_type) =
                self.dynamic_tuple_offset_and_type(&base_lvalue.type_info, *index)?;
            let member_type_id = self.project_dynamic_type_id(
                base_lvalue.type_info.type_id,
                &VariableAccessSegment::TupleIndex(*index),
            )?;
            let member_offset = self.context.i64_type().const_int(member_offset, false);
            let member_address = self
                .builder
                .build_int_add(
                    base_lvalue.address.value,
                    member_offset,
                    "dynamic_tuple_lvalue_address",
                )
                .map_err(|err| CodeGenError::Builder(err.to_string()))?;
            return Ok(Some(DynamicLvalue {
                address: base_lvalue.address.with_value(member_address),
                type_info: DynamicTypeInfo {
                    dwarf_type: member_type,
                    module_path,
                    type_id: member_type_id,
                },
            }));
        }

        Ok(None)
    }

    fn dynamic_member_base_address_and_type(
        &mut self,
        object: DynamicLvalue<'ctx>,
    ) -> Result<Option<DynamicLvalue<'ctx>>> {
        let module_path = object.type_info.module_path.clone();
        let type_id = object.type_info.type_id;
        let object_type = self.complete_dynamic_member_element_type(
            object.type_info.dwarf_type,
            module_path.as_deref(),
        );
        match ghostscope_dwarf::strip_type_aliases(&object_type) {
            DwarfType::StructType { .. } | DwarfType::UnionType { .. } => Ok(Some(DynamicLvalue {
                address: object.address,
                type_info: DynamicTypeInfo {
                    dwarf_type: object_type,
                    module_path,
                    type_id,
                },
            })),
            DwarfType::PointerType { target_type, .. } => {
                let pointer_value =
                    self.read_dynamic_address_value(object.address, &object_type)?;
                let pointer_value = match pointer_value {
                    BasicValueEnum::IntValue(value) => {
                        self.normalize_int_to_i64(value, "dynamic_member_pointer_i64")?
                    }
                    BasicValueEnum::PointerValue(value) => self
                        .builder
                        .build_ptr_to_int(
                            value,
                            self.context.i64_type(),
                            "dynamic_member_pointer_ptr",
                        )
                        .map_err(|err| CodeGenError::Builder(err.to_string()))?,
                    _ => {
                        return Err(CodeGenError::TypeError(
                            "dynamic member pointer base did not compile to an address".to_string(),
                        ))
                    }
                };
                let target_type = self.complete_dynamic_member_element_type(
                    target_type.as_ref().clone(),
                    module_path.as_deref(),
                );
                Ok(Some(DynamicLvalue {
                    address: RuntimeAddress::available(pointer_value, self.context),
                    type_info: DynamicTypeInfo {
                        dwarf_type: target_type,
                        module_path,
                        type_id,
                    },
                }))
            }
            _ => Ok(None),
        }
    }

    fn dynamic_member_offset_and_type(
        &self,
        aggregate: &DynamicTypeInfo,
        field: &str,
    ) -> Result<(u64, DwarfType)> {
        let aggregate_type = self.complete_dynamic_member_element_type(
            aggregate.dwarf_type.clone(),
            aggregate.module_path.as_deref(),
        );
        match ghostscope_dwarf::member_layout(&aggregate_type, field) {
            Ok(layout) => Ok((layout.offset, layout.member_type)),
            Err(err @ TypeLayoutError::UnknownMember { .. }) => {
                Err(CodeGenError::DwarfError(err.to_string()))
            }
            Err(err @ TypeLayoutError::InvalidMemberBase { .. }) => {
                Err(CodeGenError::TypeError(err.to_string()))
            }
        }
    }

    fn dynamic_tuple_offset_and_type(
        &self,
        aggregate: &DynamicTypeInfo,
        index: u32,
    ) -> Result<(u64, DwarfType)> {
        let aggregate_type = self.complete_dynamic_member_element_type(
            aggregate.dwarf_type.clone(),
            aggregate.module_path.as_deref(),
        );
        let analyzer = self
            .process_analyzer
            .ok_or_else(|| CodeGenError::DwarfError("No DWARF analyzer available".to_string()))?;
        let fallback_module_path = self
            .current_compile_time_context
            .as_ref()
            .map(|context| PathBuf::from(&context.module_path));
        let module_path = aggregate
            .module_path
            .as_deref()
            .or(fallback_module_path.as_deref())
            .ok_or_else(|| {
                CodeGenError::DwarfError("Tuple projection has no originating module".to_string())
            })?;
        let layout = match aggregate.type_id {
            Some(type_id) => analyzer.tuple_member_layout(type_id, &aggregate_type, index),
            None => analyzer.tuple_member_layout_in_module(module_path, &aggregate_type, index),
        }
        .map_err(|error| CodeGenError::DwarfError(error.to_string()))?;
        Ok((layout.offset, layout.member_type))
    }

    fn project_dynamic_type_id(
        &self,
        current: Option<ghostscope_dwarf::TypeId>,
        segment: &VariableAccessSegment,
    ) -> Result<Option<ghostscope_dwarf::TypeId>> {
        let Some(current) = current else {
            return Ok(None);
        };
        self.process_analyzer
            .ok_or_else(|| CodeGenError::DwarfError("No DWARF analyzer available".to_string()))?
            .project_type_id(current, segment)
            .map_err(|error| CodeGenError::DwarfError(error.to_string()))
    }

    fn dynamic_array_base_from_plan(
        &mut self,
        array_plan: &VariableReadPlan,
        pc_address: u64,
        status_ptr: Option<PointerValue<'ctx>>,
        static_index: i64,
    ) -> Result<(IndexableElementInfo, RuntimeAddress<'ctx>, i64)> {
        let module_path = array_plan.module_path.clone();
        let array_type = array_plan.dwarf_type.as_ref().ok_or_else(|| {
            CodeGenError::DwarfError("Array expression has no DWARF type information".to_string())
        })?;
        let element_type_id = self
            .project_dynamic_type_id(array_plan.type_id, &VariableAccessSegment::ArrayIndex(0))?;
        let element_info = Self::indexable_info_from_type(array_type, module_path, element_type_id)
            .ok_or_else(|| {
                CodeGenError::TypeError(format!(
                    "dynamic array index requires array or pointer type, got '{}'",
                    array_type.type_name()
                ))
            })?;

        match ghostscope_dwarf::strip_type_aliases(array_type) {
            DwarfType::ArrayType { .. } => {
                let base_address =
                    self.variable_read_plan_to_runtime_address(array_plan, pc_address, status_ptr)?;
                Ok((element_info, base_address, static_index))
            }
            DwarfType::PointerType { .. } => {
                let pointer_value =
                    self.variable_read_plan_to_llvm_value(array_plan, pc_address, status_ptr)?;
                let base_address = self.compiled_pointer_value_to_runtime_address(
                    pointer_value,
                    "dynamic_array_base_i64",
                    "dynamic_array_base_ptr",
                    "array base pointer did not compile to an address",
                )?;
                Ok((element_info, base_address, static_index))
            }
            _ => unreachable!("indexable_info_from_type accepts only array or pointer types"),
        }
    }

    pub(super) fn compile_dynamic_array_element_address(
        &mut self,
        array_expr: &Expr,
        index_expr: &Expr,
    ) -> Result<Option<DynamicLvalue<'ctx>>> {
        let literal_index = Self::integer_literal_value(index_expr);
        let expanded_array_expr = self.expand_alias_variable_expr(array_expr)?;
        let has_dynamic_base =
            self.expands_to_nonliteral_pointer_arithmetic(&expanded_array_expr)?;
        let cast_base = self.cast_index_base(&expanded_array_expr)?;

        if literal_index.is_some() && !has_dynamic_base && cast_base.is_none() {
            return Ok(None);
        }

        let compile_context = self.get_compile_time_context()?.clone();
        let status_ptr = if self.condition_context_active {
            Some(self.get_or_create_cond_error_global())
        } else {
            None
        };

        let (element_info, base_address, static_index) = if let Some((element_info, base_address)) =
            cast_base
        {
            (element_info, base_address, 0)
        } else {
            match self.query_dwarf_for_complex_expr(array_expr)? {
                Some(array_plan) => self.dynamic_array_base_from_plan(
                    &array_plan,
                    compile_context.pc_address,
                    status_ptr,
                    0,
                )?,
                None => {
                    if let Some((base_expr, static_index)) =
                        self.pointer_arithmetic_parts_expanding_aliases(&expanded_array_expr)?
                    {
                        let array_plan = self
                            .query_dwarf_for_complex_expr(&base_expr)?
                            .ok_or_else(|| {
                                CodeGenError::VariableNotFound(Self::expr_to_debug_string(
                                    &base_expr,
                                ))
                            })?;
                        self.dynamic_array_base_from_plan(
                            &array_plan,
                            compile_context.pc_address,
                            status_ptr,
                            static_index,
                        )?
                    } else if has_dynamic_base {
                        let element_info = self
                            .indexable_element_type_and_stride(&expanded_array_expr)?
                            .ok_or_else(|| {
                                CodeGenError::VariableNotFound(Self::expr_to_debug_string(
                                    array_expr,
                                ))
                            })?;
                        let base_address =
                            self.resolve_runtime_address_from_expr(&expanded_array_expr)?;
                        (element_info, base_address, 0)
                    } else if let Some(array_lvalue) =
                        self.dynamic_lvalue_address_and_type(&expanded_array_expr)?
                    {
                        let module_path = array_lvalue.type_info.module_path.clone();
                        let element_type_id = self.project_dynamic_type_id(
                            array_lvalue.type_info.type_id,
                            &VariableAccessSegment::ArrayIndex(0),
                        )?;
                        let element_info = Self::indexable_info_from_type(
                            &array_lvalue.type_info.dwarf_type,
                            module_path,
                            element_type_id,
                        )
                        .ok_or_else(|| {
                            CodeGenError::TypeError(format!(
                                "dynamic array index requires array or pointer type, got '{}'",
                                array_lvalue.type_info.dwarf_type.type_name()
                            ))
                        })?;
                        match ghostscope_dwarf::strip_type_aliases(
                            &array_lvalue.type_info.dwarf_type,
                        ) {
                            DwarfType::ArrayType { .. } => (element_info, array_lvalue.address, 0),
                            DwarfType::PointerType { .. } => {
                                let pointer_value = self.read_dynamic_address_value(
                                    array_lvalue.address,
                                    &array_lvalue.type_info.dwarf_type,
                                )?;
                                let base_address = self.compiled_pointer_value_to_runtime_address(
                                    pointer_value,
                                    "dynamic_array_member_ptr_i64",
                                    "dynamic_array_member_ptr",
                                    "array member pointer did not compile to an address",
                                )?;
                                (element_info, base_address, 0)
                            }
                            _ => unreachable!(
                                "indexable_info_from_type accepts only array or pointer types"
                            ),
                        }
                    } else {
                        return Err(CodeGenError::VariableNotFound(Self::expr_to_debug_string(
                            array_expr,
                        )));
                    }
                }
            }
        };

        let index_value = if let Some(index) = literal_index {
            self.context.i64_type().const_int(index as u64, true)
        } else {
            match self.compile_expr(index_expr)? {
                BasicValueEnum::IntValue(value) => {
                    self.normalize_int_to_i64(value, "dynamic_array_index_i64")?
                }
                _ => {
                    return Err(CodeGenError::TypeError(
                        "array index expression must compile to an integer".to_string(),
                    ))
                }
            }
        };
        let index_value = if static_index == 0 {
            index_value
        } else {
            let static_index_value = self.context.i64_type().const_int(static_index as u64, true);
            self.builder
                .build_int_add(
                    index_value,
                    static_index_value,
                    "dynamic_array_static_index",
                )
                .map_err(|err| CodeGenError::Builder(err.to_string()))?
        };
        let stride_value = self
            .context
            .i64_type()
            .const_int(element_info.stride, false);
        let byte_offset = self
            .builder
            .build_int_mul(index_value, stride_value, "dynamic_array_byte_offset")
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;
        let element_address = self
            .builder
            .build_int_add(
                base_address.value,
                byte_offset,
                "dynamic_array_element_address",
            )
            .map_err(|err| CodeGenError::Builder(err.to_string()))?;

        Ok(Some(DynamicLvalue {
            address: base_address.with_value(element_address),
            type_info: DynamicTypeInfo {
                dwarf_type: element_info.element_type,
                module_path: element_info.module_path,
                type_id: element_info.type_id,
            },
        }))
    }

    fn indexable_element_type_and_stride(
        &mut self,
        expr: &Expr,
    ) -> Result<Option<IndexableElementInfo>> {
        use crate::script::ast::BinaryOp as BO;
        use crate::script::ast::Expr as E;

        let expanded = self.expand_alias_variable_expr(expr)?;

        if let Some((element_info, _base_address)) = self.cast_index_base(&expanded)? {
            return Ok(Some(element_info));
        }

        if let Some(plan) = self.query_dwarf_for_complex_expr(&expanded)? {
            if let Some(dwarf_type) = plan.dwarf_type.as_ref() {
                let element_type_id = self
                    .project_dynamic_type_id(plan.type_id, &VariableAccessSegment::ArrayIndex(0))?;
                if let Some(info) = Self::indexable_info_from_type(
                    dwarf_type,
                    plan.module_path.clone(),
                    element_type_id,
                ) {
                    return Ok(Some(info));
                }
            }
        }

        if let Some((base_expr, _static_index)) =
            self.pointer_arithmetic_parts_expanding_aliases(&expanded)?
        {
            if let Some(plan) = self.query_dwarf_for_complex_expr(&base_expr)? {
                if let Some(dwarf_type) = plan.dwarf_type.as_ref() {
                    let element_type_id = self.project_dynamic_type_id(
                        plan.type_id,
                        &VariableAccessSegment::ArrayIndex(0),
                    )?;
                    if let Some(info) = Self::indexable_info_from_type(
                        dwarf_type,
                        plan.module_path.clone(),
                        element_type_id,
                    ) {
                        return Ok(Some(info));
                    }
                }
            }
        }

        match expanded {
            E::BinaryOp {
                ref left,
                op: BO::Add,
                ref right,
            } => {
                if let Some(info) = self.indexable_element_type_and_stride(left)? {
                    return Ok(Some(info));
                }
                self.indexable_element_type_and_stride(right)
            }
            E::BinaryOp {
                ref left,
                op: BO::Subtract,
                ..
            } => self.indexable_element_type_and_stride(left),
            _ => Ok(None),
        }
    }

    fn complete_dynamic_member_element_type(
        &self,
        element_type: DwarfType,
        module_path: Option<&Path>,
    ) -> DwarfType {
        let Some(analyzer) = self.process_analyzer else {
            return element_type;
        };
        let fallback_module_path = self
            .current_compile_time_context
            .as_ref()
            .map(|ctx| PathBuf::from(&ctx.module_path));
        let lookup_module_path = module_path.or(fallback_module_path.as_deref());

        if let Some(module_path) = lookup_module_path {
            analyzer.complete_shallow_unknown_aggregate_type_in_module(module_path, element_type)
        } else {
            analyzer.complete_shallow_unknown_aggregate_type(element_type)
        }
    }

    fn read_dynamic_address_value(
        &mut self,
        address: RuntimeAddress<'ctx>,
        dwarf_type: &DwarfType,
    ) -> Result<BasicValueEnum<'ctx>> {
        if ghostscope_dwarf::is_c_aggregate_type(dwarf_type) {
            let ptr_ty = self.context.ptr_type(AddressSpace::default());
            let as_ptr = self
                .builder
                .build_int_to_ptr(address.value, ptr_ty, "dynamic_aggregate_ptr")
                .map_err(|err| CodeGenError::Builder(err.to_string()))?;
            return Ok(as_ptr.into());
        }

        let access_size = self.dwarf_type_to_memory_access_size(dwarf_type);
        let value = if self.condition_context_active {
            self.generate_memory_read_with_status(address, access_size)?
        } else {
            self.generate_memory_read(address, access_size, None)?
        };
        self.sign_extend_memory_read_if_needed(value, dwarf_type, access_size)
    }

    pub(super) fn expand_alias_variable_expr(&self, expr: &Expr) -> Result<Expr> {
        let mut expanded = expr.clone();
        let mut visited = std::collections::HashSet::new();

        loop {
            let Expr::Variable(name) = &expanded else {
                return Ok(expanded);
            };
            if !self.alias_variable_exists(name) {
                return Ok(expanded);
            }
            if !visited.insert(name.clone()) {
                return Err(CodeGenError::TypeError(format!(
                    "alias cycle detected for '{name}'"
                )));
            }
            let Some(target) = self.get_alias_variable(name) else {
                return Ok(expanded);
            };
            expanded = target;
        }
    }

    pub(super) fn normalize_int_to_i64(
        &self,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let width = value.get_type().get_bit_width();
        if width == 64 {
            return Ok(value);
        }

        if width < 64 {
            return self
                .builder
                .build_int_s_extend(value, self.context.i64_type(), name)
                .map_err(|err| CodeGenError::Builder(err.to_string()));
        }

        self.builder
            .build_int_truncate(value, self.context.i64_type(), name)
            .map_err(|err| CodeGenError::Builder(err.to_string()))
    }

    pub(crate) fn dwarf_expression_unavailable_error(
        name: &str,
        availability: &Availability,
        pc_address: u64,
    ) -> CodeGenError {
        let reason = Self::format_availability_reason(availability);
        CodeGenError::VariableUnavailable(format!(
            "'{name}' is {reason}; cannot use it as a value expression at PC 0x{pc_address:x}"
        ))
    }

    pub(crate) fn dwarf_lvalue_address_unavailable_error(
        name: &str,
        availability: &Availability,
        pc_address: u64,
    ) -> CodeGenError {
        let reason = Self::format_availability_reason(availability);
        CodeGenError::VariableUnavailable(format!(
            "'{name}' is {reason}; cannot take its address at PC 0x{pc_address:x}"
        ))
    }

    fn format_availability_reason(availability: &Availability) -> String {
        match availability {
            Availability::OptimizedOut => "optimized out at the selected probe PC".to_string(),
            Availability::NotInScope => "not in scope at the selected probe PC".to_string(),
            Availability::Unsupported(reason) => {
                format!(
                    "unsupported DWARF semantic shape: {}",
                    Self::format_unsupported_reason(reason)
                )
            }
            Availability::Requires(requirement) => {
                format!(
                    "requires unavailable runtime support: {}",
                    Self::format_runtime_requirement(requirement)
                )
            }
            Availability::Ambiguous(reason) => {
                format!(
                    "ambiguous DWARF semantic result: {}",
                    Self::format_ambiguity_reason(reason)
                )
            }
            Availability::Available | Availability::PartiallyAvailable => "available".to_string(),
        }
    }

    fn format_unsupported_reason(reason: &UnsupportedReason) -> String {
        match reason {
            UnsupportedReason::DwarfOp { op } => format!("unsupported DWARF op {op}"),
            UnsupportedReason::ExpressionShape { detail } => {
                format!("unsupported DWARF expression shape: {detail}")
            }
            UnsupportedReason::TypeLayout { detail } => {
                format!("unsupported type layout: {detail}")
            }
            UnsupportedReason::AddressClass { detail } => {
                format!("unsupported address class: {detail}")
            }
            UnsupportedReason::RegisterMapping { dwarf_reg } => {
                format!("unsupported DWARF register mapping for register {dwarf_reg}")
            }
        }
    }

    fn format_runtime_requirement(requirement: &RuntimeRequirement) -> &'static str {
        match requirement {
            RuntimeRequirement::CallerFrame => "caller-frame recovery",
            RuntimeRequirement::SleepableUprobe => "sleepable uprobe support",
            RuntimeRequirement::UserMemoryRead => "user-memory read support",
            RuntimeRequirement::DwarfCfiRecovery => "DWARF CFI recovery",
        }
    }

    fn format_ambiguity_reason(reason: &AmbiguityReason) -> String {
        match reason {
            AmbiguityReason::InlineContext { detail } => {
                format!("ambiguous inline context: {detail}")
            }
            AmbiguityReason::VariableDeclaration { detail } => {
                format!("ambiguous variable declaration: {detail}")
            }
            AmbiguityReason::TypeResolution { detail } => {
                format!("ambiguous type resolution: {detail}")
            }
        }
    }

    /// Helper: Convert expression to string for debugging
    fn expr_to_debug_string(expr: &crate::script::Expr) -> String {
        use crate::script::Expr;

        match expr {
            Expr::Variable(name) => name.clone(),
            Expr::MemberAccess(obj, field) => {
                format!("{}.{}", Self::expr_to_debug_string(obj), field)
            }
            Expr::TupleAccess(obj, index) => {
                format!("{}.{}", Self::expr_to_debug_string(obj), index)
            }
            Expr::ArrayAccess(arr, _) => format!("{}[index]", Self::expr_to_debug_string(arr)),
            Expr::Cast { expr, target_type } => format!(
                "cast({}, \"{}\")",
                Self::expr_to_debug_string(expr),
                target_type
            ),
            Expr::ChainAccess(chain) => chain.join("."),
            Expr::PointerDeref(expr) => format!("*{}", Self::expr_to_debug_string(expr)),
            _ => "expr".to_string(),
        }
    }
}

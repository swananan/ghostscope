use crate::ebpf::context::{CodeGenError, EbpfContext, Result};
use crate::ebpf::expression_plan::BinaryIntegerSemantics;
use crate::script::BinaryOp;
use inkwell::values::{BasicValueEnum, IntValue};
use tracing::debug;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub fn compile_binary_op(
        &mut self,
        left: BasicValueEnum<'ctx>,
        op: BinaryOp,
        right: BasicValueEnum<'ctx>,
    ) -> Result<BasicValueEnum<'ctx>> {
        self.compile_binary_op_with_ordering(left, op, right, BinaryIntegerSemantics::default())
    }

    pub(crate) fn build_signed_int_div_via_udiv(
        &mut self,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let int_type = left.get_type();
        let zero = int_type.const_zero();
        let left_is_neg = self
            .builder
            .build_int_compare(inkwell::IntPredicate::SLT, left, zero, "sdiv_lhs_neg")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let right_is_neg = self
            .builder
            .build_int_compare(inkwell::IntPredicate::SLT, right, zero, "sdiv_rhs_neg")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_left = self
            .builder
            .build_int_sub(zero, left, "sdiv_lhs_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_right = self
            .builder
            .build_int_sub(zero, right, "sdiv_rhs_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let abs_left = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                left_is_neg,
                neg_left.into(),
                left.into(),
                "sdiv_lhs_abs",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let abs_right = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                right_is_neg,
                neg_right.into(),
                right.into(),
                "sdiv_rhs_abs",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let abs_quotient = self
            .builder
            .build_int_unsigned_div(abs_left, abs_right, "sdiv_abs_udiv")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let negative_result = self
            .builder
            .build_xor(left_is_neg, right_is_neg, "sdiv_result_neg")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_quotient = self
            .builder
            .build_int_sub(zero, abs_quotient, "sdiv_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                negative_result,
                neg_quotient.into(),
                abs_quotient.into(),
                name,
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))
            .map(|value| value.into_int_value())
    }

    pub(crate) fn build_signed_int_rem_via_urem(
        &mut self,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let int_type = left.get_type();
        let zero = int_type.const_zero();
        let left_is_neg = self
            .builder
            .build_int_compare(inkwell::IntPredicate::SLT, left, zero, "srem_lhs_neg")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let right_is_neg = self
            .builder
            .build_int_compare(inkwell::IntPredicate::SLT, right, zero, "srem_rhs_neg")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_left = self
            .builder
            .build_int_sub(zero, left, "srem_lhs_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_right = self
            .builder
            .build_int_sub(zero, right, "srem_rhs_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let abs_left = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                left_is_neg,
                neg_left.into(),
                left.into(),
                "srem_lhs_abs",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let abs_right = self
            .builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                right_is_neg,
                neg_right.into(),
                right.into(),
                "srem_rhs_abs",
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))?
            .into_int_value();
        let abs_remainder = self
            .builder
            .build_int_unsigned_rem(abs_left, abs_right, "srem_abs_urem")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        let neg_remainder = self
            .builder
            .build_int_sub(zero, abs_remainder, "srem_negated")
            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
        self.builder
            .build_select::<BasicValueEnum<'ctx>, _>(
                left_is_neg,
                neg_remainder.into(),
                abs_remainder.into(),
                name,
            )
            .map_err(|e| CodeGenError::Builder(e.to_string()))
            .map(|value| value.into_int_value())
    }

    pub(super) fn normalize_int_for_unsigned_compare(
        &mut self,
        value: IntValue<'ctx>,
        bit_width: u32,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        let current_width = value.get_type().get_bit_width();
        if current_width == bit_width {
            return Ok(value);
        }

        let target_type = self.context.custom_width_int_type(bit_width);
        if current_width > bit_width {
            self.builder
                .build_int_truncate(value, target_type, name)
                .map_err(|e| CodeGenError::Builder(e.to_string()))
        } else {
            self.builder
                .build_int_z_extend(value, target_type, name)
                .map_err(|e| CodeGenError::Builder(e.to_string()))
        }
    }

    fn align_int_widths_for_binary_op(
        &mut self,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        let left_width = left.get_type().get_bit_width();
        let right_width = right.get_type().get_bit_width();
        if left_width == right_width {
            return Ok((left, right));
        }

        let target_width = left_width.max(right_width);
        let target_type = self.context.custom_width_int_type(target_width);
        let left = if left_width < target_width {
            self.builder
                .build_int_z_extend(left, target_type, "lhs_width_align")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        } else {
            left
        };
        let right = if right_width < target_width {
            self.builder
                .build_int_z_extend(right, target_type, "rhs_width_align")
                .map_err(|e| CodeGenError::Builder(e.to_string()))?
        } else {
            right
        };
        Ok((left, right))
    }

    fn mask_shift_amount(&mut self, amount: IntValue<'ctx>, name: &str) -> Result<IntValue<'ctx>> {
        let bit_width = amount.get_type().get_bit_width();
        let mask = amount
            .get_type()
            .const_int(u64::from(bit_width.saturating_sub(1)), false);
        self.builder
            .build_and(amount, mask, name)
            .map_err(|e| CodeGenError::Builder(e.to_string()))
    }

    fn normalize_ints_for_unsigned_width(
        &mut self,
        left: IntValue<'ctx>,
        right: IntValue<'ctx>,
        bit_width: u32,
        name: &str,
    ) -> Result<(IntValue<'ctx>, IntValue<'ctx>)> {
        let left = self.normalize_int_for_unsigned_compare(
            left,
            bit_width,
            &format!("{name}_lhs_unsigned"),
        )?;
        let right = self.normalize_int_for_unsigned_compare(
            right,
            bit_width,
            &format!("{name}_rhs_unsigned"),
        )?;
        Ok((left, right))
    }

    pub(super) fn zero_extend_int_to_i64_if_needed(
        &mut self,
        value: IntValue<'ctx>,
        name: &str,
    ) -> Result<IntValue<'ctx>> {
        if value.get_type().get_bit_width() >= 64 {
            return Ok(value);
        }
        self.builder
            .build_int_z_extend(value, self.context.i64_type(), name)
            .map_err(|e| CodeGenError::Builder(e.to_string()))
    }

    pub(super) fn compile_binary_op_with_ordering(
        &mut self,
        left: BasicValueEnum<'ctx>,
        op: BinaryOp,
        right: BasicValueEnum<'ctx>,
        integer_semantics: BinaryIntegerSemantics,
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
                let (left_int, right_int) =
                    self.align_int_widths_for_binary_op(left_int, right_int)?;
                let unsigned_cmp_values = if let Some(bit_width) =
                    integer_semantics.unsigned_ordering_width
                {
                    Some((
                        self.normalize_int_for_unsigned_compare(
                            left_int,
                            bit_width,
                            "lhs_unsigned_cmp",
                        )?,
                        self.normalize_int_for_unsigned_compare(
                            right_int,
                            bit_width,
                            "rhs_unsigned_cmp",
                        )?,
                    ))
                } else {
                    None
                };
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
                    BinaryOp::Divide => {
                        if let Some(bit_width) = integer_semantics.unsigned_division_width {
                            let (left_int, right_int) = self.normalize_ints_for_unsigned_width(
                                left_int,
                                right_int,
                                bit_width,
                                "div",
                            )?;
                            let result = self
                                .builder
                                .build_int_unsigned_div(left_int, right_int, "div")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            self.zero_extend_int_to_i64_if_needed(result, "div_zext_i64")?
                        } else {
                            self.build_signed_int_div_via_udiv(left_int, right_int, "div")?
                        }
                    }
                    BinaryOp::Modulo => {
                        if let Some(bit_width) = integer_semantics.unsigned_division_width {
                            let (left_int, right_int) = self.normalize_ints_for_unsigned_width(
                                left_int,
                                right_int,
                                bit_width,
                                "mod",
                            )?;
                            let result = self
                                .builder
                                .build_int_unsigned_rem(left_int, right_int, "mod")
                                .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                            self.zero_extend_int_to_i64_if_needed(result, "mod_zext_i64")?
                        } else {
                            self.build_signed_int_rem_via_urem(left_int, right_int, "mod")?
                        }
                    }
                    BinaryOp::BitAnd => {
                        let (left_int, right_int) =
                            if let Some(bit_width) = integer_semantics.unsigned_bitwise_width {
                                self.normalize_ints_for_unsigned_width(
                                    left_int,
                                    right_int,
                                    bit_width,
                                    "bitand",
                                )?
                            } else {
                                (left_int, right_int)
                            };
                        let result = self
                            .builder
                            .build_and(left_int, right_int, "bitand")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        if integer_semantics.unsigned_bitwise_width.is_some() {
                            self.zero_extend_int_to_i64_if_needed(result, "bitand_zext_i64")?
                        } else {
                            result
                        }
                    }
                    BinaryOp::BitXor => {
                        let (left_int, right_int) =
                            if let Some(bit_width) = integer_semantics.unsigned_bitwise_width {
                                self.normalize_ints_for_unsigned_width(
                                    left_int,
                                    right_int,
                                    bit_width,
                                    "bitxor",
                                )?
                            } else {
                                (left_int, right_int)
                            };
                        let result = self
                            .builder
                            .build_xor(left_int, right_int, "bitxor")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        if integer_semantics.unsigned_bitwise_width.is_some() {
                            self.zero_extend_int_to_i64_if_needed(result, "bitxor_zext_i64")?
                        } else {
                            result
                        }
                    }
                    BinaryOp::BitOr => {
                        let (left_int, right_int) =
                            if let Some(bit_width) = integer_semantics.unsigned_bitwise_width {
                                self.normalize_ints_for_unsigned_width(
                                    left_int,
                                    right_int,
                                    bit_width,
                                    "bitor",
                                )?
                            } else {
                                (left_int, right_int)
                            };
                        let result = self
                            .builder
                            .build_or(left_int, right_int, "bitor")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        if integer_semantics.unsigned_bitwise_width.is_some() {
                            self.zero_extend_int_to_i64_if_needed(result, "bitor_zext_i64")?
                        } else {
                            result
                        }
                    }
                    BinaryOp::ShiftLeft => {
                        let right_int = self.mask_shift_amount(right_int, "shl_rhs_mask")?;
                        self.builder
                            .build_left_shift(left_int, right_int, "shl")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
                    BinaryOp::ShiftRight => {
                        let right_int = self.mask_shift_amount(right_int, "shr_rhs_mask")?;
                        self.builder
                            .build_right_shift(
                                left_int,
                                right_int,
                                integer_semantics.unsigned_right_shift_width.is_none(),
                                "shr",
                            )
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?
                    }
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
                        let predicate = if integer_semantics.unsigned_ordering_width.is_some() {
                            inkwell::IntPredicate::ULT
                        } else {
                            inkwell::IntPredicate::SLT
                        };
                        let (left_cmp, right_cmp) =
                            unsigned_cmp_values.unwrap_or((left_int, right_int));
                        let result = self
                            .builder
                            .build_int_compare(predicate, left_cmp, right_cmp, "lt")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::LessEqual => {
                        let predicate = if integer_semantics.unsigned_ordering_width.is_some() {
                            inkwell::IntPredicate::ULE
                        } else {
                            inkwell::IntPredicate::SLE
                        };
                        let (left_cmp, right_cmp) =
                            unsigned_cmp_values.unwrap_or((left_int, right_int));
                        let result = self
                            .builder
                            .build_int_compare(predicate, left_cmp, right_cmp, "le")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterThan => {
                        let predicate = if integer_semantics.unsigned_ordering_width.is_some() {
                            inkwell::IntPredicate::UGT
                        } else {
                            inkwell::IntPredicate::SGT
                        };
                        let (left_cmp, right_cmp) =
                            unsigned_cmp_values.unwrap_or((left_int, right_int));
                        let result = self
                            .builder
                            .build_int_compare(predicate, left_cmp, right_cmp, "gt")
                            .map_err(|e| CodeGenError::Builder(e.to_string()))?;
                        return Ok(result.into());
                    }
                    BinaryOp::GreaterEqual => {
                        let predicate = if integer_semantics.unsigned_ordering_width.is_some() {
                            inkwell::IntPredicate::UGE
                        } else {
                            inkwell::IntPredicate::SGE
                        };
                        let (left_cmp, right_cmp) =
                            unsigned_cmp_values.unwrap_or((left_int, right_int));
                        let result = self
                            .builder
                            .build_int_compare(predicate, left_cmp, right_cmp, "ge")
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
                    _ => Err(CodeGenError::TypeError(
                        "Unsupported operation between aggregate address/pointer and integer: only '==' and '!=' are allowed. If you meant to offset an address, use '&expr +/- <integer literal>' in an alias/address context, or access a scalar field.".to_string(),
                    )),
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
                _ => Err(CodeGenError::TypeError(
                    "Pointer ordered comparison ('<', '<=', '>', '>=') is not supported. Use '==' or '!=' to compare addresses. If you need to adjust an address, use '&expr +/- <integer literal>' in an alias/address context; to compare values, select a scalar field (e.g., 'obj.field')."
                        .to_string(),
                )),
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
                    "Float binary operation {op:?} not implemented"
                ))),
            },
            _ => Err(CodeGenError::TypeError(format!(
                "Type mismatch in binary operation {op:?}"
            ))),
        }
    }
}

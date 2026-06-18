//! eBPF expression semantic planning.
//!
//! This module keeps expression classification and policy decisions separate
//! from LLVM IR construction. The emitter still owns block layout and helper
//! calls; the plan records what semantic path should be emitted.

use super::context::{CodeGenError, EbpfContext, Result};
use crate::script::{BinaryOp, Expr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct BinaryIntegerSemantics {
    pub(super) unsigned_ordering_width: Option<u32>,
    pub(super) unsigned_division_width: Option<u32>,
    pub(super) unsigned_bitwise_width: Option<u32>,
    pub(super) unsigned_right_shift_width: Option<u32>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BinaryEmitKind {
    LogicalOr,
    LogicalAnd,
    StringComparison(StringComparisonPlan),
    Eager,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StringComparisonPlan {
    pub(super) literal: String,
    pub(super) literal_on_left: bool,
    pub(super) equal: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) struct BinaryExprPlan {
    pub(super) op: BinaryOp,
    pub(super) emit_kind: BinaryEmitKind,
    pub(super) integer_semantics: BinaryIntegerSemantics,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BuiltinCallPlan {
    Memcmp,
    Strncmp,
    StartsWith,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SpecialVarPlan {
    Pid,
    Tid,
    HostPid,
    InputPid,
    Timestamp,
    Pc,
    Sp,
}

impl SpecialVarPlan {
    pub(super) fn supported_display() -> &'static str {
        "$pid, $tid, $host_pid, $input_pid, $timestamp, $pc, $sp"
    }
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(super) fn plan_builtin_call(&self, name: &str, args: &[Expr]) -> Result<BuiltinCallPlan> {
        match name {
            "memcmp" => {
                if args.len() != 3 {
                    return Err(CodeGenError::TypeError("memcmp expects 3 arguments".into()));
                }
                Ok(BuiltinCallPlan::Memcmp)
            }
            "strncmp" => {
                if args.len() != 3 {
                    return Err(CodeGenError::TypeError(
                        "strncmp expects 3 arguments".into(),
                    ));
                }
                Ok(BuiltinCallPlan::Strncmp)
            }
            "starts_with" => {
                if args.len() != 2 {
                    return Err(CodeGenError::TypeError(
                        "starts_with expects 2 arguments".into(),
                    ));
                }
                Ok(BuiltinCallPlan::StartsWith)
            }
            _ => Err(CodeGenError::NotImplemented(format!(
                "Unknown builtin function: {name}"
            ))),
        }
    }

    pub(super) fn plan_special_variable(&self, name: &str) -> Result<SpecialVarPlan> {
        match name {
            "pid" => Ok(SpecialVarPlan::Pid),
            "tid" => Ok(SpecialVarPlan::Tid),
            "host_pid" => Ok(SpecialVarPlan::HostPid),
            "input_pid" => Ok(SpecialVarPlan::InputPid),
            "timestamp" => Ok(SpecialVarPlan::Timestamp),
            "pc" => Ok(SpecialVarPlan::Pc),
            "sp" => Ok(SpecialVarPlan::Sp),
            _ => Err(CodeGenError::NotImplemented(format!(
                "Unknown special variable '${name}'. Supported: {}",
                SpecialVarPlan::supported_display()
            ))),
        }
    }

    pub(super) fn plan_binary_expr(
        &mut self,
        left: &Expr,
        op: &BinaryOp,
        right: &Expr,
    ) -> Result<BinaryExprPlan> {
        let shape = BinaryOpShape::from_op(op);

        if (shape.is_integer_op || shape.is_ordered)
            && (self.is_dwarf_aggregate_expr(left) || self.is_dwarf_aggregate_expr(right))
        {
            return Err(CodeGenError::TypeError(
                "Unsupported arithmetic/ordered comparison involving struct/union/array, or unsupported bitwise operation involving struct/union/array. Select a scalar field (e.g., 'obj.field'), or use '&expr +/- <integer literal>' in an alias/address context if you need a raw address."
                    .to_string(),
            ));
        }

        if shape.is_ordered && (self.is_pointer_like_expr(left) || self.is_pointer_like_expr(right))
        {
            return Err(CodeGenError::TypeError(
                "Pointer ordered comparison ('<', '<=', '>', '>=') is not supported. Use '==' or '!=' to compare addresses. If you need to adjust an address, use '&expr +/- <integer literal>' in an alias/address context; to compare values, select a scalar field (e.g., 'obj.field')."
                    .to_string(),
            ));
        }

        let emit_kind = match op {
            BinaryOp::Equal | BinaryOp::NotEqual => {
                if let Expr::String(literal) = left {
                    BinaryEmitKind::StringComparison(StringComparisonPlan {
                        literal: literal.clone(),
                        literal_on_left: true,
                        equal: matches!(op, BinaryOp::Equal),
                    })
                } else if let Expr::String(literal) = right {
                    BinaryEmitKind::StringComparison(StringComparisonPlan {
                        literal: literal.clone(),
                        literal_on_left: false,
                        equal: matches!(op, BinaryOp::Equal),
                    })
                } else {
                    BinaryEmitKind::Eager
                }
            }
            BinaryOp::LogicalOr => BinaryEmitKind::LogicalOr,
            BinaryOp::LogicalAnd => BinaryEmitKind::LogicalAnd,
            _ => BinaryEmitKind::Eager,
        };

        let integer_semantics = if matches!(emit_kind, BinaryEmitKind::Eager) {
            BinaryIntegerSemantics {
                unsigned_ordering_width: shape
                    .is_ordered
                    .then(|| self.unsigned_ordering_width_for_exprs(left, right))
                    .flatten(),
                unsigned_division_width: shape
                    .is_division
                    .then(|| self.unsigned_ordering_width_for_exprs(left, right))
                    .flatten(),
                unsigned_bitwise_width: shape
                    .is_bitwise
                    .then(|| self.unsigned_ordering_width_for_exprs(left, right))
                    .flatten(),
                unsigned_right_shift_width: matches!(op, BinaryOp::ShiftRight)
                    .then(|| self.unsigned_shift_width_for_expr(left))
                    .flatten(),
            }
        } else {
            BinaryIntegerSemantics::default()
        };

        Ok(BinaryExprPlan {
            op: op.clone(),
            emit_kind,
            integer_semantics,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BinaryOpShape {
    is_integer_op: bool,
    is_ordered: bool,
    is_division: bool,
    is_bitwise: bool,
}

impl BinaryOpShape {
    fn from_op(op: &BinaryOp) -> Self {
        Self {
            is_integer_op: matches!(
                op,
                BinaryOp::Add
                    | BinaryOp::Subtract
                    | BinaryOp::Multiply
                    | BinaryOp::Divide
                    | BinaryOp::Modulo
                    | BinaryOp::BitAnd
                    | BinaryOp::BitXor
                    | BinaryOp::BitOr
                    | BinaryOp::ShiftLeft
                    | BinaryOp::ShiftRight
            ),
            is_ordered: matches!(
                op,
                BinaryOp::LessThan
                    | BinaryOp::LessEqual
                    | BinaryOp::GreaterThan
                    | BinaryOp::GreaterEqual
            ),
            is_division: matches!(op, BinaryOp::Divide | BinaryOp::Modulo),
            is_bitwise: matches!(op, BinaryOp::BitAnd | BinaryOp::BitXor | BinaryOp::BitOr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_plan_validates_arity() {
        let context = inkwell::context::Context::create();
        let ctx = EbpfContext::new(&context, "test", None, &crate::CompileOptions::default())
            .expect("context");

        assert_eq!(
            ctx.plan_builtin_call("memcmp", &[Expr::Int(1), Expr::Int(2), Expr::Int(3)])
                .unwrap(),
            BuiltinCallPlan::Memcmp
        );
        assert!(ctx.plan_builtin_call("memcmp", &[Expr::Int(1)]).is_err());
        assert!(ctx.plan_builtin_call("unknown", &[]).is_err());
    }

    #[test]
    fn special_var_plan_accepts_documented_names() {
        let context = inkwell::context::Context::create();
        let ctx = EbpfContext::new(&context, "test", None, &crate::CompileOptions::default())
            .expect("context");

        assert_eq!(
            ctx.plan_special_variable("pid").unwrap(),
            SpecialVarPlan::Pid
        );
        assert_eq!(ctx.plan_special_variable("sp").unwrap(), SpecialVarPlan::Sp);
        assert!(ctx.plan_special_variable("bogus").is_err());
    }

    #[test]
    fn binary_shape_classifies_ops_for_planning() {
        let add = BinaryOpShape::from_op(&BinaryOp::Add);
        assert!(add.is_integer_op);
        assert!(!add.is_ordered);

        let lt = BinaryOpShape::from_op(&BinaryOp::LessThan);
        assert!(!lt.is_integer_op);
        assert!(lt.is_ordered);

        let bit_and = BinaryOpShape::from_op(&BinaryOp::BitAnd);
        assert!(bit_and.is_bitwise);
    }
}

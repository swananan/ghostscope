use super::*;
use crate::script::{Expr, VarType};

impl EbpfContext<'_, '_> {
    pub(super) fn validate_format_argument_types(
        &mut self,
        template: &FormatTemplate,
        args: &[Expr],
    ) -> Result<()> {
        let required = template.script_argument_count();
        if required != args.len() {
            return Err(CodeGenError::TypeError(format!(
                "Format expects {required} argument(s) but received {}",
                args.len()
            )));
        }
        let mut cursor = 0;
        for slot in template.slots() {
            match &slot.length {
                FormatLength::Dynamic => self.validate_format_length(
                    &args[cursor],
                    &format!("Format '{slot}' length argument {}", cursor + 1),
                )?,
                FormatLength::Capture(name) => {
                    if !self.variable_exists(name) {
                        return Err(CodeGenError::TypeError(format!(
                            "Format '{slot}' capture length variable '{name}' not found"
                        )));
                    }
                    self.validate_format_length(
                        &Expr::Variable(name.clone()),
                        &format!("Format '{slot}' capture length variable '{name}'"),
                    )?;
                }
                _ => {}
            }
            cursor += slot.script_argument_count();
        }
        Ok(())
    }

    fn validate_format_length(&mut self, expr: &Expr, context: &str) -> Result<()> {
        // LLVM represents DWARF pointers as integers, so checking IntValue alone
        // would silently accept a pointer as a byte count. Resolve aliases and
        // inspect source types before lowering the expression.
        let expr = self.expand_dwarf_aliases(expr)?;
        let integer = match &expr {
            Expr::Int(_) | Expr::Bool(_) => Some(true),
            Expr::String(_) | Expr::Float(_) | Expr::AddressOf(_) => Some(false),
            Expr::Variable(name) if self.variable_exists(name) => Some(matches!(
                self.get_variable_type(name),
                Some(VarType::Int | VarType::Bool)
            )),
            Expr::Cast { target_type, .. } => Some(
                ghostscope_dwarf::c_integer_comparison_type(
                    &self.resolve_cast_target_type(target_type)?,
                )
                .is_some(),
            ),
            Expr::BinaryOp {
                left,
                op: crate::script::BinaryOp::Add | crate::script::BinaryOp::Subtract,
                right,
            } => {
                self.validate_format_length(left, context)?;
                self.validate_format_length(right, context)?;
                Some(true)
            }
            _ => self
                .query_dwarf_for_access_type(&expr)
                .ok()
                .flatten()
                .map(|ty| ghostscope_dwarf::c_integer_comparison_type(&ty).is_some()),
        };
        if integer == Some(false) {
            return Err(CodeGenError::TypeError(format!(
                "{context} must be an integer; '{}' is not an integer length",
                self.expr_to_name(&expr)
            )));
        }
        // Unknown expressions still go through normal expression compilation;
        // this preserves missing-variable and unavailable-DWARF diagnostics.
        Ok(())
    }
}

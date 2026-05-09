//! CFA DWARF expression lowering.

use crate::{
    core::{MemoryAccessSize, PlanExprOp, Result},
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode},
};
use anyhow::anyhow;
use gimli::Reader;

/// Parse CFA DWARF expression operations into a `PlanExprOp` sequence.
pub(crate) fn parse_expression<R>(reader: R, encoding: gimli::Encoding) -> Result<Vec<PlanExprOp>>
where
    R: Reader<Offset = usize>,
{
    let mut steps = Vec::new();

    for op in expr_errors::hard(
        DwarfExprMode::Cfa,
        crate::dwarf_expr::ops::parse_ops(reader, encoding, "CFA expression"),
    )? {
        match op {
            gimli::Operation::Register { register } => {
                steps.push(PlanExprOp::LoadRegister(register.0));
            }
            gimli::Operation::RegisterOffset {
                register, offset, ..
            } => {
                steps.push(PlanExprOp::LoadRegister(register.0));
                if offset != 0 {
                    steps.push(PlanExprOp::PushConstant(offset));
                    steps.push(PlanExprOp::Add);
                }
            }
            gimli::Operation::PlusConstant { value } => {
                steps.push(PlanExprOp::PushConstant(value as i64));
                steps.push(PlanExprOp::Add);
            }
            gimli::Operation::UnsignedConstant { value } => {
                steps.push(PlanExprOp::PushConstant(value as i64));
            }
            gimli::Operation::SignedConstant { value } => {
                steps.push(PlanExprOp::PushConstant(value));
            }
            gimli::Operation::Deref { size, space, .. } => {
                if space {
                    return Err(anyhow!("unsupported CFA expression operation: {:?}", op));
                }
                let size = match size {
                    1 => MemoryAccessSize::U8,
                    2 => MemoryAccessSize::U16,
                    4 => MemoryAccessSize::U32,
                    8 => MemoryAccessSize::U64,
                    _ => {
                        return Err(anyhow!(
                            "unsupported CFA expression dereference size {} in operation: {:?}",
                            size,
                            op
                        ))
                    }
                };
                steps.push(PlanExprOp::Dereference { size });
            }
            gimli::Operation::Plus => steps.push(PlanExprOp::Add),
            gimli::Operation::Minus => steps.push(PlanExprOp::Sub),
            gimli::Operation::Mul => steps.push(PlanExprOp::Mul),
            gimli::Operation::And => steps.push(PlanExprOp::And),
            gimli::Operation::Or => steps.push(PlanExprOp::Or),
            gimli::Operation::Xor => steps.push(PlanExprOp::Xor),
            gimli::Operation::Nop => {}
            _ => {
                return Err(anyhow!("unsupported CFA expression operation: {:?}", op));
            }
        }
    }

    Ok(steps)
}

#[cfg(test)]
mod tests {
    use super::parse_expression;
    use crate::core::{MemoryAccessSize, PlanExprOp};
    use gimli::{EndianSlice, RunTimeEndian};

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        }
    }

    fn parse_test_expr(bytes: &[u8]) -> crate::core::Result<Vec<PlanExprOp>> {
        parse_expression(
            EndianSlice::new(bytes, RunTimeEndian::Little),
            test_encoding(),
        )
    }

    #[test]
    fn cfa_expression_parses_unsigned_constant() {
        let steps = parse_test_expr(&[0x10, 0x2a]).expect("DW_OP_constu should parse");
        assert_eq!(steps, vec![PlanExprOp::PushConstant(42)]);
    }

    #[test]
    fn cfa_expression_parses_signed_constant() {
        let steps = parse_test_expr(&[0x11, 0x7f]).expect("DW_OP_consts should parse");
        assert_eq!(steps, vec![PlanExprOp::PushConstant(-1)]);
    }

    #[test]
    fn cfa_expression_parses_dereference() {
        let steps = parse_test_expr(&[0x70, 0x00, 0x06]).expect("DW_OP_deref should parse");
        assert_eq!(
            steps,
            vec![
                PlanExprOp::LoadRegister(0),
                PlanExprOp::Dereference {
                    size: MemoryAccessSize::U64,
                },
            ]
        );
    }

    #[test]
    fn cfa_expression_rejects_unknown_opcode_after_valid_prefix() {
        let error = parse_test_expr(&[0x70, 0x00, 0xff])
            .expect_err("unknown CFI expression opcode must not be skipped");

        assert!(
            error.to_string().contains("failed to parse"),
            "unexpected error: {error}"
        );
    }
}

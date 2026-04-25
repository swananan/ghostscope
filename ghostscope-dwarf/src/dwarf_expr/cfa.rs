//! CFA DWARF expression lowering.

use crate::{
    core::{ComputeStep, MemoryAccessSize, Result},
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode},
};
use anyhow::anyhow;
use gimli::Reader;

/// Parse CFA DWARF expression operations into a `ComputeStep` sequence.
pub(crate) fn parse_expression<R>(reader: R, encoding: gimli::Encoding) -> Result<Vec<ComputeStep>>
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
                steps.push(ComputeStep::LoadRegister(register.0));
            }
            gimli::Operation::RegisterOffset {
                register, offset, ..
            } => {
                steps.push(ComputeStep::LoadRegister(register.0));
                if offset != 0 {
                    steps.push(ComputeStep::PushConstant(offset));
                    steps.push(ComputeStep::Add);
                }
            }
            gimli::Operation::PlusConstant { value } => {
                steps.push(ComputeStep::PushConstant(value as i64));
                steps.push(ComputeStep::Add);
            }
            gimli::Operation::UnsignedConstant { value } => {
                steps.push(ComputeStep::PushConstant(value as i64));
            }
            gimli::Operation::SignedConstant { value } => {
                steps.push(ComputeStep::PushConstant(value));
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
                steps.push(ComputeStep::Dereference { size });
            }
            gimli::Operation::Plus => steps.push(ComputeStep::Add),
            gimli::Operation::Minus => steps.push(ComputeStep::Sub),
            gimli::Operation::Mul => steps.push(ComputeStep::Mul),
            gimli::Operation::And => steps.push(ComputeStep::And),
            gimli::Operation::Or => steps.push(ComputeStep::Or),
            gimli::Operation::Xor => steps.push(ComputeStep::Xor),
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
    use crate::core::{ComputeStep, MemoryAccessSize};
    use gimli::{EndianSlice, RunTimeEndian};

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        }
    }

    fn parse_test_expr(bytes: &[u8]) -> crate::core::Result<Vec<ComputeStep>> {
        parse_expression(
            EndianSlice::new(bytes, RunTimeEndian::Little),
            test_encoding(),
        )
    }

    #[test]
    fn cfa_expression_parses_unsigned_constant() {
        let steps = parse_test_expr(&[0x10, 0x2a]).expect("DW_OP_constu should parse");
        assert_eq!(steps, vec![ComputeStep::PushConstant(42)]);
    }

    #[test]
    fn cfa_expression_parses_signed_constant() {
        let steps = parse_test_expr(&[0x11, 0x7f]).expect("DW_OP_consts should parse");
        assert_eq!(steps, vec![ComputeStep::PushConstant(-1)]);
    }

    #[test]
    fn cfa_expression_parses_dereference() {
        let steps = parse_test_expr(&[0x70, 0x00, 0x06]).expect("DW_OP_deref should parse");
        assert_eq!(
            steps,
            vec![
                ComputeStep::LoadRegister(0),
                ComputeStep::Dereference {
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

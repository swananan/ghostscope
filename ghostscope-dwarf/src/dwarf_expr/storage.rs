//! Storage-address DWARF expression helpers for index-time discovery.

use crate::{
    binary::DwarfReader,
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode},
};
use gimli::{Operation, Reader};

pub(crate) fn absolute_address(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    expr: gimli::Expression<DwarfReader>,
) -> Option<u64> {
    let operations = expr_errors::soft_value(
        DwarfExprMode::StorageAddress,
        crate::dwarf_expr::ops::parse_ops(
            expr.0,
            unit.encoding(),
            "absolute storage address expression",
        ),
    )?;

    absolute_address_from_ops(&operations, |index| dwarf.address(unit, index).ok())
}

fn absolute_address_from_ops<R, F>(operations: &[Operation<R>], mut resolve_addrx: F) -> Option<u64>
where
    R: Reader<Offset = usize>,
    F: FnMut(gimli::DebugAddrIndex<usize>) -> Option<u64>,
{
    match operations {
        [Operation::Address { address }] => Some(*address),
        // clang/LLVM commonly encodes function-scoped statics in DWARF5 as a
        // single `DW_OP_addrx` op. This is still a true storage location, just
        // indirected through `.debug_addr`.
        [Operation::AddressIndex { index }] => resolve_addrx(*index),
        [Operation::UnsignedConstant { value }] => Some(*value),
        // Anything more complex may be a computed value or a composite
        // location. In particular, `DW_OP_stack_value` means the expression
        // yields a value, not a storage address, so treating it as global
        // storage would misindex optimized locals.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::absolute_address_from_ops;
    use crate::dwarf_expr::{errors as expr_errors, modes::DwarfExprMode};
    use gimli::{EndianSlice, RunTimeEndian};

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 5,
            address_size: 8,
        }
    }

    fn parse_test_expr(bytes: &[u8]) -> Option<u64> {
        let operations = expr_errors::soft_value(
            DwarfExprMode::StorageAddress,
            crate::dwarf_expr::ops::parse_ops(
                EndianSlice::new(bytes, RunTimeEndian::Little),
                test_encoding(),
                "test storage address expression",
            ),
        )?;
        absolute_address_from_ops(&operations, |index| Some(0x1000 + index.0 as u64))
    }

    #[test]
    fn storage_address_parses_dw_op_addr() {
        let address = parse_test_expr(&[0x03, 0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0]);
        assert_eq!(address, Some(0x1234_5678));
    }

    #[test]
    fn storage_address_parses_dw_op_addrx() {
        let address = parse_test_expr(&[gimli::constants::DW_OP_addrx.0, 0x2a]);
        assert_eq!(address, Some(0x102a));
    }

    #[test]
    fn storage_address_parses_legacy_constu_address() {
        let address = parse_test_expr(&[0x10, 0x2a]);
        assert_eq!(address, Some(42));
    }

    #[test]
    fn storage_address_rejects_stack_value_expression() {
        let address = parse_test_expr(&[0x10, 0x2a, gimli::constants::DW_OP_stack_value.0]);
        assert_eq!(address, None);
    }

    #[test]
    fn storage_address_parse_error_downgrades_to_none() {
        let address = parse_test_expr(&[0xff]);
        assert_eq!(address, None);
    }
}

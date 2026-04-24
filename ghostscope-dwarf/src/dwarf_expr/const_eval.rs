//! Constant-only DWARF expression helpers.

use crate::{binary::DwarfReader, core::Result};

pub(crate) fn eval_const_offset(
    expr: &gimli::Expression<DwarfReader>,
    encoding: gimli::Encoding,
) -> Result<Option<u64>> {
    let Some(op) = crate::dwarf_expr::ops::parse_single_op(
        expr.0.clone(),
        encoding,
        "constant DWARF expression",
    )?
    else {
        return Ok(None);
    };

    match op {
        gimli::Operation::UnsignedConstant { value } => Ok(Some(value)),
        gimli::Operation::SignedConstant { value } if value >= 0 => Ok(Some(value as u64)),
        gimli::Operation::PlusConstant { value } => Ok(Some(value)),
        _ => Ok(None),
    }
}

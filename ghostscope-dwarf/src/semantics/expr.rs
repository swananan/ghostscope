use crate::binary::DwarfReader;
use gimli::Reader;

pub(crate) fn eval_member_offset_expr(expr: &gimli::Expression<DwarfReader>) -> Option<u64> {
    let mut reader = expr.0.clone();
    if reader.is_empty() {
        return None;
    }

    match reader.read_u8().ok()? {
        0x10 => reader.read_uleb128().ok(), // DW_OP_constu
        0x11 => reader.read_sleb128().ok().map(|value| value as u64), // DW_OP_consts
        0x23 => reader.read_uleb128().ok(), // DW_OP_plus_uconst
        _ => None,
    }
}

use gimli::{EndianArcSlice, EndianSlice, LittleEndian, Reader};

pub(crate) fn eval_member_offset_expr(
    expr: &gimli::Expression<EndianArcSlice<LittleEndian>>,
) -> Option<u64> {
    let bytes_cow = expr.0.to_slice().ok()?;
    let bytes: &[u8] = &bytes_cow;
    if bytes.is_empty() {
        return None;
    }

    let mut reader = EndianSlice::new(bytes, LittleEndian);
    match reader.read_u8().ok()? {
        0x10 => reader.read_uleb128().ok(), // DW_OP_constu
        0x11 => reader.read_sleb128().ok().map(|value| value as u64), // DW_OP_consts
        0x23 => reader.read_uleb128().ok(), // DW_OP_plus_uconst
        _ => None,
    }
}

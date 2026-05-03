//! Shared gimli operation walker for DWARF expressions.

use crate::core::Result;
use gimli::{Operation, Reader};

#[derive(Debug, thiserror::Error)]
#[error("unsupported {context} operation {op}: {detail}")]
pub(crate) struct UnsupportedDwarfOpError {
    context: String,
    op: &'static str,
    detail: String,
}

impl UnsupportedDwarfOpError {
    pub(crate) fn op(&self) -> &'static str {
        self.op
    }
}

pub(crate) fn parse_ops<R>(
    mut reader: R,
    encoding: gimli::Encoding,
    context: &str,
) -> Result<Vec<Operation<R>>>
where
    R: Reader<Offset = usize>,
{
    let total_len = reader.len();
    let mut operations = Vec::new();
    while !reader.is_empty() {
        let offset = total_len - reader.len();
        let op = Operation::parse(&mut reader, encoding).map_err(|error| {
            anyhow::anyhow!("failed to parse {context} operation at byte offset {offset}: {error}")
        })?;
        operations.push(op);
    }
    Ok(operations)
}

pub(crate) fn parse_single_op<R>(
    reader: R,
    encoding: gimli::Encoding,
    context: &str,
) -> Result<Option<Operation<R>>>
where
    R: Reader<Offset = usize>,
{
    let mut operations = parse_ops(reader, encoding, context)?;
    if operations.len() > 1 {
        return Ok(None);
    }
    Ok(operations.pop())
}

pub(crate) fn any_op<R, F>(
    mut reader: R,
    encoding: gimli::Encoding,
    context: &str,
    mut predicate: F,
) -> Result<bool>
where
    R: Reader<Offset = usize>,
    F: FnMut(&Operation<R>) -> bool,
{
    let total_len = reader.len();
    while !reader.is_empty() {
        let offset = total_len - reader.len();
        let op = Operation::parse(&mut reader, encoding).map_err(|error| {
            anyhow::anyhow!("failed to parse {context} operation at byte offset {offset}: {error}")
        })?;
        if predicate(&op) {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn operation_name<R>(op: &Operation<R>) -> &'static str
where
    R: Reader<Offset = usize>,
{
    match op {
        Operation::Deref { space: true, .. } => "DW_OP_xderef*",
        Operation::Deref { size: 0, .. } => "DW_OP_deref",
        Operation::Deref { .. } => "DW_OP_deref_size",
        Operation::Drop => "DW_OP_drop",
        Operation::Pick { index: 0 } => "DW_OP_dup",
        Operation::Pick { index: 1 } => "DW_OP_over",
        Operation::Pick { .. } => "DW_OP_pick",
        Operation::Swap => "DW_OP_swap",
        Operation::Rot => "DW_OP_rot",
        Operation::Abs => "DW_OP_abs",
        Operation::And => "DW_OP_and",
        Operation::Div => "DW_OP_div",
        Operation::Minus => "DW_OP_minus",
        Operation::Mod => "DW_OP_mod",
        Operation::Mul => "DW_OP_mul",
        Operation::Neg => "DW_OP_neg",
        Operation::Not => "DW_OP_not",
        Operation::Or => "DW_OP_or",
        Operation::Plus => "DW_OP_plus",
        Operation::PlusConstant { .. } => "DW_OP_plus_uconst",
        Operation::Shl => "DW_OP_shl",
        Operation::Shr => "DW_OP_shr",
        Operation::Shra => "DW_OP_shra",
        Operation::Xor => "DW_OP_xor",
        Operation::Bra { .. } => "DW_OP_bra",
        Operation::Eq => "DW_OP_eq",
        Operation::Ge => "DW_OP_ge",
        Operation::Gt => "DW_OP_gt",
        Operation::Le => "DW_OP_le",
        Operation::Lt => "DW_OP_lt",
        Operation::Ne => "DW_OP_ne",
        Operation::Skip { .. } => "DW_OP_skip",
        Operation::UnsignedConstant { .. } => "DW_OP_lit*/DW_OP_const*u",
        Operation::SignedConstant { .. } => "DW_OP_const*s",
        Operation::Register { .. } => "DW_OP_reg*/DW_OP_regx",
        Operation::RegisterOffset { .. } => "DW_OP_breg*/DW_OP_bregx",
        Operation::FrameOffset { .. } => "DW_OP_fbreg",
        Operation::Nop => "DW_OP_nop",
        Operation::PushObjectAddress => "DW_OP_push_object_address",
        Operation::Call { .. } => "DW_OP_call*",
        Operation::VariableValue { .. } => "DW_OP_GNU_variable_value",
        Operation::TLS => "DW_OP_form_tls_address",
        Operation::CallFrameCFA => "DW_OP_call_frame_cfa",
        Operation::Piece {
            bit_offset: Some(_),
            ..
        } => "DW_OP_bit_piece",
        Operation::Piece { .. } => "DW_OP_piece",
        Operation::ImplicitValue { .. } => "DW_OP_implicit_value",
        Operation::StackValue => "DW_OP_stack_value",
        Operation::ImplicitPointer { .. } => "DW_OP_implicit_pointer",
        Operation::EntryValue { .. } => "DW_OP_entry_value",
        Operation::ParameterRef { .. } => "DW_OP_GNU_parameter_ref",
        Operation::Address { .. } => "DW_OP_addr",
        Operation::AddressIndex { .. } => "DW_OP_addrx",
        Operation::ConstantIndex { .. } => "DW_OP_constx",
        Operation::TypedLiteral { .. } => "DW_OP_const_type",
        Operation::Convert { .. } => "DW_OP_convert",
        Operation::Reinterpret { .. } => "DW_OP_reinterpret",
        Operation::Uninitialized => "DW_OP_GNU_uninit",
        Operation::WasmLocal { .. } => "DW_OP_WASM_location(local)",
        Operation::WasmGlobal { .. } => "DW_OP_WASM_location(global)",
        Operation::WasmStack { .. } => "DW_OP_WASM_location(stack)",
    }
}

pub(crate) fn unsupported_operation_error<R>(context: &str, op: &Operation<R>) -> anyhow::Error
where
    R: Reader<Offset = usize>,
{
    unsupported_operation_error_with_detail(context, op, format!("{op:?}"))
}

pub(crate) fn unsupported_operation_error_with_detail<R>(
    context: &str,
    op: &Operation<R>,
    detail: impl Into<String>,
) -> anyhow::Error
where
    R: Reader<Offset = usize>,
{
    UnsupportedDwarfOpError {
        context: context.to_string(),
        op: operation_name(op),
        detail: detail.into(),
    }
    .into()
}

pub(crate) fn unsupported_op_from_error(error: &anyhow::Error) -> Option<&'static str> {
    error
        .downcast_ref::<UnsupportedDwarfOpError>()
        .map(UnsupportedDwarfOpError::op)
}

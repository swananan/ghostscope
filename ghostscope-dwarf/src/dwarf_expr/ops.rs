//! Shared gimli operation walker for DWARF expressions.

use crate::core::Result;
use gimli::{Operation, Reader};

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

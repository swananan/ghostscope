//! Core types and utilities for ghostscope-dwarf

use crate::binary::DwarfReader;

pub mod demangle;
pub mod errors;
pub mod evaluation;
pub mod mapping;
pub mod symbol_names;
pub mod types;

pub use demangle::*;
pub use errors::*;
pub use evaluation::*;
pub use mapping::*;
pub(crate) use symbol_names::*;
pub use types::*;

pub(crate) fn attr_u64(value: gimli::AttributeValue<DwarfReader>) -> Option<u64> {
    match value {
        gimli::AttributeValue::Udata(v) => Some(v),
        gimli::AttributeValue::Sdata(v) if v >= 0 => Some(v as u64),
        gimli::AttributeValue::Data1(v) => Some(v as u64),
        gimli::AttributeValue::Data2(v) => Some(v as u64),
        gimli::AttributeValue::Data4(v) => Some(v as u64),
        gimli::AttributeValue::Data8(v) => Some(v),
        _ => None,
    }
}

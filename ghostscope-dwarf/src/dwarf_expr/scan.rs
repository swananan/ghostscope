//! Lightweight DWARF expression scans that do not lower expressions.

use crate::{binary::DwarfReader, core::Result};

pub(crate) fn contains_entry_value(
    expr: gimli::Expression<DwarfReader>,
    encoding: gimli::Encoding,
) -> Result<bool> {
    crate::dwarf_expr::ops::any_op(expr.0, encoding, "DWARF expression scan", |op| {
        matches!(op, gimli::Operation::EntryValue { .. })
    })
}

#[cfg(test)]
mod tests {
    use super::contains_entry_value;
    use crate::binary::dwarf_reader_from_arc;
    use std::sync::Arc;

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 4,
            address_size: 8,
        }
    }

    fn expr(bytes: &[u8]) -> gimli::Expression<crate::binary::DwarfReader> {
        let data: Arc<[u8]> = Arc::from(bytes);
        gimli::Expression(dwarf_reader_from_arc(data))
    }

    #[test]
    fn entry_value_scan_stops_after_match() {
        let expression = expr(&[0xa3, 0x01, 0x50, 0xff]);
        assert!(contains_entry_value(expression, test_encoding()).unwrap());
    }

    #[test]
    fn entry_value_scan_errors_before_match() {
        let expression = expr(&[0xff, 0xa3, 0x01, 0x50]);
        assert!(contains_entry_value(expression, test_encoding()).is_err());
    }
}

//! Object-aware DWARF locations. Section offsets alone are not identities.

use super::{DwarfData, DwarfReader};
use crate::DwarfObjectId;
use gimli::Reader;

impl DwarfObjectId {
    pub(crate) fn dwarf(self, root: &DwarfData) -> gimli::Result<&DwarfData> {
        match self {
            Self::Primary => Ok(root),
            Self::Supplementary => root.sup().ok_or(gimli::Error::MissingUnitDie),
        }
    }
}

pub(crate) fn unit_object(root: &DwarfData, unit: &gimli::Unit<DwarfReader>) -> DwarfObjectId {
    if root.sup().is_none() {
        return DwarfObjectId::Primary;
    }
    // ReaderOffsetId identifies the backing allocation, including decompressed
    // sections. Equal numerical offsets in two objects remain distinct.
    let supplementary = unit
        .header
        .range_from(unit.header.root_offset()..)
        .ok()
        .and_then(|reader| root.lookup_offset_id(reader.offset_id()))
        .is_some_and(|(supplementary, _, _)| supplementary);
    if supplementary {
        DwarfObjectId::Supplementary
    } else {
        DwarfObjectId::Primary
    }
}

pub(crate) fn unit_dwarf<'a>(
    root: &'a DwarfData,
    unit: &gimli::Unit<DwarfReader>,
) -> gimli::Result<&'a DwarfData> {
    unit_object(root, unit).dwarf(root)
}

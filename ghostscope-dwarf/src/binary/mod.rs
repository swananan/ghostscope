pub(crate) mod debuglink;
pub(crate) mod mapped_file;

pub(crate) use debuglink::try_load_debug_file;
#[cfg(test)]
pub(crate) use mapped_file::dwarf_reader_from_arc;
pub(crate) use mapped_file::{
    dwarf_endian_from_object, dwarf_reader_from_arc_with_endian, empty_dwarf_reader_with_endian,
    DwarfData, DwarfEndian, DwarfReader, MappedFile,
};

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use object::{Endianness, Object};

/// Internal helper for mmap-backed file access and object parsing.
#[derive(Debug)]
pub(crate) struct MappedFile {
    pub data: memmap2::Mmap,
    pub path: PathBuf,
}

impl MappedFile {
    /// Open and memory-map a file.
    pub fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = std::fs::File::open(&path)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };
        Ok(Self { data: mmap, path })
    }

    /// Borrow the mapped file bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..]
    }

    /// Parse the mapped file as an object file.
    pub fn parse_object(&self) -> object::Result<object::File<'_>> {
        object::File::parse(self.as_bytes())
    }

    /// Create a DWARF reader over the whole mapped file.
    pub fn dwarf_reader(file: Arc<Self>, endian: DwarfEndian) -> DwarfReader {
        DwarfReader::new(DwarfBytes::Mapped(file), endian)
    }

    /// Create a DWARF reader over a file range without copying the mapped data.
    pub fn dwarf_reader_range(
        file: Arc<Self>,
        start: u64,
        size: u64,
        endian: DwarfEndian,
    ) -> Option<DwarfReader> {
        let start = usize::try_from(start).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        if end > file.as_bytes().len() {
            return None;
        }
        Some(Self::dwarf_reader(file, endian).range(start..end))
    }
}

/// Shared backing storage for gimli readers.
#[derive(Clone, Debug)]
pub(crate) enum DwarfBytes {
    Owned(Arc<[u8]>),
    Mapped(Arc<MappedFile>),
}

impl Deref for DwarfBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Mapped(file) => file.as_bytes(),
        }
    }
}

unsafe impl gimli::StableDeref for DwarfBytes {}
unsafe impl gimli::CloneStableDeref for DwarfBytes {}

pub(crate) type DwarfEndian = gimli::RunTimeEndian;
pub(crate) type DwarfReader = gimli::EndianReader<DwarfEndian, DwarfBytes>;
pub(crate) type DwarfData = gimli::Dwarf<DwarfReader>;

#[cfg(test)]
pub(crate) fn dwarf_reader_from_arc(bytes: Arc<[u8]>) -> DwarfReader {
    dwarf_reader_from_arc_with_endian(bytes, gimli::RunTimeEndian::Little)
}

pub(crate) fn dwarf_reader_from_arc_with_endian(
    bytes: Arc<[u8]>,
    endian: DwarfEndian,
) -> DwarfReader {
    DwarfReader::new(DwarfBytes::Owned(bytes), endian)
}

pub(crate) fn empty_dwarf_reader_with_endian(endian: DwarfEndian) -> DwarfReader {
    DwarfReader::new(DwarfBytes::Owned(Arc::<[u8]>::from(&[][..])), endian)
}

pub(crate) fn dwarf_endian_from_object(object: &object::File<'_>) -> DwarfEndian {
    match object.endianness() {
        Endianness::Little => gimli::RunTimeEndian::Little,
        Endianness::Big => gimli::RunTimeEndian::Big,
    }
}

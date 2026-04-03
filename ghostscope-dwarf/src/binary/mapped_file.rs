use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Arc;

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
    pub fn dwarf_reader(file: Arc<Self>) -> DwarfReader {
        DwarfReader::new(DwarfBytes::Mapped(file), gimli::LittleEndian)
    }

    /// Create a DWARF reader over a file range without copying the mapped data.
    pub fn dwarf_reader_range(file: Arc<Self>, start: u64, size: u64) -> Option<DwarfReader> {
        let start = usize::try_from(start).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        if end > file.as_bytes().len() {
            return None;
        }
        Some(Self::dwarf_reader(file).range(start..end))
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

pub(crate) type DwarfReader = gimli::EndianReader<gimli::LittleEndian, DwarfBytes>;
pub(crate) type DwarfData = gimli::Dwarf<DwarfReader>;

pub(crate) fn dwarf_reader_from_arc(bytes: Arc<[u8]>) -> DwarfReader {
    DwarfReader::new(DwarfBytes::Owned(bytes), gimli::LittleEndian)
}

pub(crate) fn empty_dwarf_reader() -> DwarfReader {
    dwarf_reader_from_arc(Arc::<[u8]>::from(&[][..]))
}

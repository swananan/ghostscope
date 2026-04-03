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

    /// Copy a file range from the mapped file into an owned Arc-backed slice.
    pub fn copy_file_range_to_arc(&self, start: u64, size: u64) -> Option<Arc<[u8]>> {
        let start = usize::try_from(start).ok()?;
        let size = usize::try_from(size).ok()?;
        let end = start.checked_add(size)?;
        let bytes = self.as_bytes().get(start..end)?;
        Some(Arc::from(bytes))
    }

    /// Return an empty owned byte slice for missing sections.
    pub fn empty_arc_bytes() -> Arc<[u8]> {
        Arc::<[u8]>::from(&[][..])
    }
}

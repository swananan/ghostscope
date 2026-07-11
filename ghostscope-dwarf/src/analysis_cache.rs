use crate::{
    binary::MappedFile,
    core::{FunctionDieKind, IndexEntry, IndexFlags},
    index::{
        encode_mapped_line_row, LightweightFileIndex, LightweightIndex, LineMappingTable,
        ScopedFileIndexManager, MAPPED_LINE_PATH_INDEX_SIZE, MAPPED_LINE_ROW_SIZE,
    },
    parser::{CompilationUnit, DwarfParseResult, DwarfParseStats, SourceFile},
};
use anyhow::{Context, Result};
use bincode::Options;
use memmap2::MmapOptions;
use object::Object;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, DirBuilder, OpenOptions},
    io::{BufWriter, Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::UNIX_EPOCH,
};

const CACHE_MAGIC: [u8; 8] = *b"GSANLYS\0";
const CACHE_SCHEMA_VERSION: u32 = 2;
const CACHE_FILE_PREFIX_LEN: usize = 24;
const MAX_CACHE_HEADER_BYTES: u64 = 64 * 1024;
const MAX_CACHE_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CACHE_FILE_BYTES: u64 =
    CACHE_FILE_PREFIX_LEN as u64 + MAX_CACHE_HEADER_BYTES + MAX_CACHE_PAYLOAD_BYTES;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct AnalysisCache {
    directory: PathBuf,
    writable: bool,
}

impl AnalysisCache {
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            writable: true,
        }
    }

    pub fn read_only(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            writable: false,
        }
    }

    pub fn default_directory() -> PathBuf {
        dirs::cache_dir()
            .or_else(|| dirs::home_dir().map(|home| home.join(".cache")))
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "ghostscope-{}",
                    // SAFETY: geteuid has no preconditions and does not mutate memory.
                    unsafe { libc::geteuid() }
                ))
            })
            .join("ghostscope")
            .join("analysis")
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn is_writable(&self) -> bool {
        self.writable
    }

    pub(crate) fn load(
        &self,
        binary: &MappedFile,
        debug_file: &MappedFile,
    ) -> Result<Option<DwarfParseResult>> {
        let identity = CacheIdentity::new(binary, debug_file)?;
        let path = self.entry_path(&identity)?;
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("Failed to open analysis cache {}", path.display()));
            }
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("Failed to inspect analysis cache {}", path.display()))?;
        anyhow::ensure!(
            metadata.is_file(),
            "Analysis cache {} is not a regular file",
            path.display()
        );
        anyhow::ensure!(
            metadata.len() <= MAX_CACHE_FILE_BYTES,
            "Analysis cache {} is {} bytes, exceeding the {} byte limit",
            path.display(),
            metadata.len(),
            MAX_CACHE_FILE_BYTES
        );
        anyhow::ensure!(
            metadata.len() >= CACHE_FILE_PREFIX_LEN as u64,
            "Analysis cache {} is too short",
            path.display()
        );

        let snapshot_len = usize::try_from(metadata.len())?;
        let mut snapshot = MmapOptions::new()
            .len(snapshot_len)
            .map_anon()
            .with_context(|| format!("Failed to allocate cache snapshot for {}", path.display()))?;
        file.read_exact(&mut snapshot)
            .with_context(|| format!("Failed to snapshot analysis cache {}", path.display()))?;
        let data =
            Arc::new(snapshot.make_read_only().with_context(|| {
                format!("Failed to protect cache snapshot for {}", path.display())
            })?);
        let prefix = data
            .get(..CACHE_FILE_PREFIX_LEN)
            .with_context(|| format!("Failed to read analysis cache header {}", path.display()))?;
        anyhow::ensure!(
            prefix[..CACHE_MAGIC.len()] == CACHE_MAGIC,
            "Analysis cache {} has an invalid magic value",
            path.display()
        );

        let schema_version = u32::from_le_bytes(prefix[8..12].try_into()?);
        if schema_version != CACHE_SCHEMA_VERSION {
            anyhow::bail!(
                "Cache schema {schema_version} does not match supported schema \
                 {CACHE_SCHEMA_VERSION}"
            );
        }
        let header_len = u64::from(u32::from_le_bytes(prefix[12..16].try_into()?));
        let payload_len = u64::from_le_bytes(prefix[16..24].try_into()?);
        anyhow::ensure!(
            header_len > 0 && header_len <= MAX_CACHE_HEADER_BYTES,
            "Analysis cache {} has invalid header length {}",
            path.display(),
            header_len
        );
        anyhow::ensure!(
            payload_len > 0 && payload_len <= MAX_CACHE_PAYLOAD_BYTES,
            "Analysis cache {} has invalid payload length {}",
            path.display(),
            payload_len
        );
        let expected_len = (CACHE_FILE_PREFIX_LEN as u64)
            .checked_add(header_len)
            .and_then(|length| length.checked_add(payload_len))
            .context("Analysis cache length overflow")?;
        anyhow::ensure!(
            metadata.len() == expected_len,
            "Analysis cache {} length mismatch: expected {}, found {}",
            path.display(),
            expected_len,
            metadata.len()
        );

        let header_start = CACHE_FILE_PREFIX_LEN;
        let header_len = usize::try_from(header_len)?;
        let header_end = header_start
            .checked_add(header_len)
            .context("Analysis cache header offset overflow")?;
        let header: CacheHeader = deserialize_cache_slice(
            data.get(header_start..header_end)
                .context("Analysis cache header is out of bounds")?,
            "header",
            &path,
        )?;
        if header.package_version != env!("CARGO_PKG_VERSION") {
            anyhow::bail!(
                "Cache was prepared by GhostScope {}, current version is {}",
                header.package_version,
                env!("CARGO_PKG_VERSION")
            );
        }
        if header.identity != identity {
            anyhow::bail!("Cached target or debug-file identity does not match");
        }

        let metadata_len = usize::try_from(header.layout.metadata_len)?;
        anyhow::ensure!(metadata_len > 0, "Analysis cache metadata is empty");
        let line_row_count = usize::try_from(header.layout.line_row_count)?;
        let path_index_count = usize::try_from(header.layout.path_index_count)?;
        let rows_len = line_row_count
            .checked_mul(MAPPED_LINE_ROW_SIZE)
            .context("Analysis cache line row length overflow")?;
        let path_index_len = path_index_count
            .checked_mul(MAPPED_LINE_PATH_INDEX_SIZE)
            .context("Analysis cache line path index length overflow")?;
        let calculated_payload_len = metadata_len
            .checked_add(rows_len)
            .and_then(|length| length.checked_add(path_index_len))
            .context("Analysis cache payload layout overflow")?;
        anyhow::ensure!(
            calculated_payload_len == usize::try_from(payload_len)?,
            "Analysis cache payload layout does not match its encoded length"
        );
        anyhow::ensure!(
            path_index_count <= line_row_count,
            "Analysis cache line path index has more entries than line rows"
        );

        let payload_start = header_end;
        let metadata_end = payload_start
            .checked_add(metadata_len)
            .context("Analysis cache metadata offset overflow")?;
        let rows_offset = metadata_end;
        let path_index_offset = rows_offset
            .checked_add(rows_len)
            .context("Analysis cache line path index offset overflow")?;
        let mut payload: CachedParseResult = deserialize_cache_slice(
            data.get(payload_start..metadata_end)
                .context("Analysis cache metadata is out of bounds")?,
            "metadata",
            &path,
        )?;
        let strings: Arc<[Arc<str>]> = std::mem::take(&mut payload.strings)
            .into_iter()
            .map(Arc::<str>::from)
            .collect::<Vec<_>>()
            .into();
        let line_mapping = LineMappingTable::from_mapped_cache(
            data,
            rows_offset,
            line_row_count,
            path_index_offset,
            path_index_count,
            Arc::clone(&strings),
            &payload.line_path_ids,
        )?;

        payload.into_parse_result(&strings, line_mapping).map(Some)
    }

    pub(crate) fn store(
        &self,
        binary: &MappedFile,
        debug_file: &MappedFile,
        parse_result: &DwarfParseResult,
    ) -> Result<PathBuf> {
        let identity = CacheIdentity::new(binary, debug_file)?;
        let path = self.entry_path(&identity)?;
        let directory = path
            .parent()
            .context("Analysis cache entry has no parent directory")?;
        create_private_directory(directory)?;

        let line_entries = parse_result.line_mapping.cache_entries();
        anyhow::ensure!(
            line_entries.len() <= u32::MAX as usize,
            "Analysis cache has too many line rows"
        );
        let (payload, string_ids) =
            CachedParseResult::from_parse_result(parse_result, &line_entries)?;
        let line_string_ids = line_entries
            .iter()
            .map(|entry| {
                Ok((
                    cached_string_id(&string_ids, &entry.file_path)?,
                    cached_string_id(&string_ids, &entry.compilation_unit)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut path_order = line_entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| !entry.file_path.is_empty())
            .map(|(index, _)| u32::try_from(index))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        path_order.sort_unstable_by_key(|&row_index| {
            let index = row_index as usize;
            let entry = &line_entries[index];
            (
                line_string_ids[index].0,
                entry.line,
                entry.address,
                row_index,
            )
        });

        let metadata_len = cache_codec().serialized_size(&payload)?;
        let line_row_count = u64::try_from(line_entries.len())?;
        let path_index_count = u64::try_from(path_order.len())?;
        let rows_len = line_row_count
            .checked_mul(u64::try_from(MAPPED_LINE_ROW_SIZE)?)
            .context("Analysis cache line row length overflow")?;
        let path_index_len = path_index_count
            .checked_mul(u64::try_from(MAPPED_LINE_PATH_INDEX_SIZE)?)
            .context("Analysis cache line path index length overflow")?;
        let payload_len = metadata_len
            .checked_add(rows_len)
            .and_then(|length| length.checked_add(path_index_len))
            .context("Analysis cache payload length overflow")?;
        let header = CacheHeader {
            package_version: env!("CARGO_PKG_VERSION").to_string(),
            identity,
            layout: CachePayloadLayout {
                metadata_len,
                line_row_count,
                path_index_count,
            },
        };
        let header_len = cache_codec().serialized_size(&header)?;
        anyhow::ensure!(
            header_len > 0 && header_len <= MAX_CACHE_HEADER_BYTES,
            "Analysis cache header is {header_len} bytes, exceeding the \
             {MAX_CACHE_HEADER_BYTES} byte limit"
        );
        anyhow::ensure!(
            payload_len > 0 && payload_len <= MAX_CACHE_PAYLOAD_BYTES,
            "Analysis cache payload is {payload_len} bytes, exceeding the \
             {MAX_CACHE_PAYLOAD_BYTES} byte limit"
        );
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = directory.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("analysis-cache"),
            std::process::id(),
            sequence
        ));

        let write_result = (|| -> Result<()> {
            let file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp_path)
                .with_context(|| {
                    format!(
                        "Failed to create temporary analysis cache {}",
                        temp_path.display()
                    )
                })?;
            let mut writer = BufWriter::new(file);
            writer.write_all(&CACHE_MAGIC)?;
            writer.write_all(&CACHE_SCHEMA_VERSION.to_le_bytes())?;
            writer.write_all(&u32::try_from(header_len)?.to_le_bytes())?;
            writer.write_all(&payload_len.to_le_bytes())?;
            cache_codec()
                .serialize_into(&mut writer, &header)
                .with_context(|| {
                    format!(
                        "Failed to encode analysis cache header {}",
                        temp_path.display()
                    )
                })?;
            cache_codec()
                .serialize_into(&mut writer, &payload)
                .with_context(|| {
                    format!(
                        "Failed to encode analysis cache metadata {}",
                        temp_path.display()
                    )
                })?;
            for (index, entry) in line_entries.iter().enumerate() {
                let (path_id, compilation_unit_id) = line_string_ids[index];
                writer.write_all(&encode_mapped_line_row(entry, path_id, compilation_unit_id))?;
            }
            for row_index in &path_order {
                writer.write_all(&row_index.to_le_bytes())?;
            }
            writer.flush()?;
            writer.get_ref().sync_all()?;
            fs::rename(&temp_path, &path).with_context(|| {
                format!(
                    "Failed to publish analysis cache {} as {}",
                    temp_path.display(),
                    path.display()
                )
            })?;
            Ok(())
        })();

        if write_result.is_err() {
            let _ = fs::remove_file(&temp_path);
        }
        write_result?;
        Ok(path)
    }

    fn entry_path(&self, identity: &CacheIdentity) -> Result<PathBuf> {
        let encoded = cache_codec().serialize(identity)?;
        let hash = fnv1a64(&encoded);
        Ok(self
            .directory
            .join(format!("v{CACHE_SCHEMA_VERSION}"))
            .join(format!("{hash:016x}.bin")))
    }
}

fn cache_codec() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
}

fn deserialize_cache_slice<T: DeserializeOwned>(
    encoded: &[u8],
    part: &str,
    path: &Path,
) -> Result<T> {
    let decoded = catch_unwind(AssertUnwindSafe(|| {
        cache_codec()
            .with_limit(encoded.len() as u64)
            .deserialize(encoded)
    }))
    .map_err(|_| {
        anyhow::anyhow!(
            "Analysis cache {} decoder panicked while reading {}",
            path.display(),
            part
        )
    })?
    .with_context(|| {
        format!(
            "Failed to decode analysis cache {} {}",
            part,
            path.display()
        )
    })?;
    Ok(decoded)
}

fn create_private_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(path).map_err(|error| {
        anyhow::anyhow!(
            "Failed to create analysis cache directory {}: {error}",
            path.display()
        )
    })
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CacheIdentity {
    binary: FileIdentity,
    debug_file: FileIdentity,
}

impl CacheIdentity {
    fn new(binary: &MappedFile, debug_file: &MappedFile) -> Result<Self> {
        Ok(Self {
            binary: FileIdentity::new(binary)?,
            debug_file: FileIdentity::new(debug_file)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    byte_len: u64,
    build_id: Option<Vec<u8>>,
    fallback_device: Option<u64>,
    fallback_inode: Option<u64>,
    fallback_ctime_secs: Option<i64>,
    fallback_ctime_nanos: Option<i64>,
    fallback_hash: Option<u64>,
    modified_secs: Option<u64>,
    modified_nanos: Option<u32>,
}

impl FileIdentity {
    fn new(file: &MappedFile) -> Result<Self> {
        let build_id = file
            .parse_object()
            .ok()
            .and_then(|object| object.build_id().ok().flatten().map(ToOwned::to_owned));
        let metadata = fs::metadata(&file.path).ok();
        let modified = metadata
            .as_ref()
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok());
        let (
            fallback_device,
            fallback_inode,
            fallback_ctime_secs,
            fallback_ctime_nanos,
            fallback_hash,
        ) = if build_id.is_some() {
            (None, None, None, None, None)
        } else if let Some(metadata) = metadata.as_ref() {
            (
                Some(metadata.dev()),
                Some(metadata.ino()),
                Some(metadata.ctime()),
                Some(metadata.ctime_nsec()),
                None,
            )
        } else {
            (None, None, None, None, Some(fnv1a64(file.as_bytes())))
        };

        Ok(Self {
            byte_len: u64::try_from(file.as_bytes().len())
                .context("Mapped object length does not fit in u64")?,
            build_id,
            // Avoid a full-file hash on the startup path for objects without a
            // build ID. Device, inode, size, mtime, and ctime identify the
            // mapped file and invalidate the cache after in-place updates. A
            // content hash remains as a fallback if the mapped path disappears.
            fallback_device,
            fallback_inode,
            fallback_ctime_secs,
            fallback_ctime_nanos,
            fallback_hash,
            modified_secs: modified.map(|duration| duration.as_secs()),
            modified_nanos: modified.map(|duration| duration.subsec_nanos()),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CacheHeader {
    package_version: String,
    identity: CacheIdentity,
    layout: CachePayloadLayout,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
struct CachePayloadLayout {
    metadata_len: u64,
    line_row_count: u64,
    path_index_count: u64,
}

#[derive(Serialize, Deserialize)]
struct CachedParseResult {
    strings: Vec<String>,
    index_entries: Vec<CachedIndexEntry>,
    cu_ranges: Vec<CachedCuRange>,
    line_path_ids: Vec<u32>,
    file_indices: Vec<CachedScopedFileIndex>,
    compilation_units: Vec<(u32, CachedCompilationUnit)>,
    stats: CachedParseStats,
}

impl CachedParseResult {
    fn from_parse_result(
        result: &DwarfParseResult,
        line_entries: &[std::borrow::Cow<'_, crate::core::LineEntry>],
    ) -> Result<(Self, HashMap<String, u32>)> {
        let mut interner = StringInterner::default();
        for entry in result.lightweight_index.cache_entries() {
            interner.intern(&entry.name)?;
        }

        let mut file_indices = result
            .scoped_file_manager
            .cache_file_indices()
            .collect::<Vec<_>>();
        file_indices.sort_by_key(|(cu_name, _)| *cu_name);
        for (cu_name, index) in &file_indices {
            interner.intern(cu_name)?;
            if let Some(comp_dir) = index.cache_comp_dir() {
                interner.intern(comp_dir)?;
            }
            for directory in index.cache_directories() {
                interner.intern(directory)?;
            }
            for entry in index.file_entries() {
                interner.intern(&entry.filename)?;
            }
        }

        let mut compilation_units = result.compilation_units.iter().collect::<Vec<_>>();
        compilation_units.sort_by_key(|(name, _)| *name);
        for (name, unit) in &compilation_units {
            interner.intern(name)?;
            interner.intern(&unit.base_directory)?;
            for directory in &unit.include_directories {
                interner.intern(directory)?;
            }
            for file in &unit.files {
                interner.intern(&file.directory_path)?;
                interner.intern(&file.filename)?;
                interner.intern(&file.full_path)?;
            }
        }
        for entry in line_entries {
            interner.intern(&entry.file_path)?;
            interner.intern(&entry.compilation_unit)?;
        }

        let mut line_path_ids = line_entries
            .iter()
            .filter(|entry| !entry.file_path.is_empty())
            .map(|entry| interner.id(&entry.file_path))
            .collect::<Result<Vec<_>>>()?;
        line_path_ids.sort_unstable();
        line_path_ids.dedup();

        let cached_file_indices = file_indices
            .into_iter()
            .map(|(cu_name, index)| CachedScopedFileIndex::from_index(cu_name, index, &interner))
            .collect::<Result<Vec<_>>>()?;
        let cached_compilation_units = compilation_units
            .into_iter()
            .map(|(name, unit)| {
                Ok((
                    interner.id(name)?,
                    CachedCompilationUnit::from_unit(unit, &interner)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut payload = Self {
            strings: Vec::new(),
            index_entries: result
                .lightweight_index
                .cache_entries()
                .iter()
                .map(|entry| CachedIndexEntry::from_index_entry(entry, &interner))
                .collect::<Result<Vec<_>>>()?,
            cu_ranges: result
                .lightweight_index
                .cache_cu_ranges()
                .into_iter()
                .map(|(start, end, cu)| CachedCuRange {
                    start,
                    end,
                    cu_offset: cu.0 as u64,
                })
                .collect(),
            line_path_ids,
            file_indices: cached_file_indices,
            compilation_units: cached_compilation_units,
            stats: CachedParseStats::from(&result.stats),
        };
        let StringInterner { strings, ids } = interner;
        payload.strings = strings;
        Ok((payload, ids))
    }

    fn into_parse_result(
        self,
        strings: &[Arc<str>],
        line_mapping: LineMappingTable,
    ) -> Result<DwarfParseResult> {
        let mut scoped_file_manager = ScopedFileIndexManager::new();
        for cached in self.file_indices {
            let (cu_name, index) = cached.into_index(strings)?;
            scoped_file_manager.add_compilation_unit(cu_name, index);
        }

        let index_entries = self
            .index_entries
            .into_iter()
            .map(|entry| entry.into_index_entry(strings))
            .collect::<Result<Vec<_>>>()?;
        let cu_ranges = self
            .cu_ranges
            .into_iter()
            .map(|range| {
                Ok((
                    range.start,
                    range.end,
                    gimli::DebugInfoOffset(usize::try_from(range.cu_offset)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let compilation_units = self
            .compilation_units
            .into_iter()
            .map(|(name_id, unit)| {
                Ok((
                    cached_string(strings, name_id, "compilation unit name")?.to_string(),
                    unit.into_compilation_unit(strings)?,
                ))
            })
            .collect::<Result<HashMap<_, _>>>()?;

        Ok(DwarfParseResult {
            lightweight_index: LightweightIndex::from_cached_entries(index_entries, cu_ranges),
            line_mapping,
            scoped_file_manager,
            compilation_units,
            stats: self.stats.into_parse_stats(),
        })
    }
}

#[derive(Default)]
struct StringInterner {
    strings: Vec<String>,
    ids: HashMap<String, u32>,
}

impl StringInterner {
    fn intern(&mut self, value: &str) -> Result<u32> {
        if let Some(&id) = self.ids.get(value) {
            return Ok(id);
        }
        let id = u32::try_from(self.strings.len()).context("Too many cached strings")?;
        let value = value.to_string();
        self.strings.push(value.clone());
        self.ids.insert(value, id);
        Ok(id)
    }

    fn id(&self, value: &str) -> Result<u32> {
        cached_string_id(&self.ids, value)
    }
}

fn cached_string_id(ids: &HashMap<String, u32>, value: &str) -> Result<u32> {
    ids.get(value)
        .copied()
        .with_context(|| format!("Cached string was not interned: {value:?}"))
}

fn cached_string<'a>(strings: &'a [Arc<str>], id: u32, field: &str) -> Result<&'a Arc<str>> {
    strings
        .get(id as usize)
        .with_context(|| format!("Cached {field} string ID {id} is out of bounds"))
}

#[derive(Serialize, Deserialize)]
struct CachedIndexEntry {
    name_id: u32,
    die_offset: u64,
    unit_offset: u64,
    tag: u16,
    flags: CachedIndexFlags,
    language: Option<u16>,
    representative_addr: Option<u64>,
    entry_pc: Option<u64>,
    function_kind: u8,
}

impl CachedIndexEntry {
    fn from_index_entry(entry: &IndexEntry, strings: &StringInterner) -> Result<Self> {
        Ok(Self {
            name_id: strings.id(&entry.name)?,
            die_offset: entry.die_offset.0 as u64,
            unit_offset: entry.unit_offset.0 as u64,
            tag: entry.tag.0,
            flags: CachedIndexFlags::from(entry.flags),
            language: entry.language.map(|language| language.0),
            representative_addr: entry.representative_addr,
            entry_pc: entry.entry_pc,
            function_kind: match entry.function_kind {
                FunctionDieKind::NotFunction => 0,
                FunctionDieKind::AbstractSubprogram => 1,
                FunctionDieKind::ConcreteSubprogram => 2,
                FunctionDieKind::InlineInstance => 3,
            },
        })
    }

    fn into_index_entry(self, strings: &[Arc<str>]) -> Result<IndexEntry> {
        let function_kind = match self.function_kind {
            0 => FunctionDieKind::NotFunction,
            1 => FunctionDieKind::AbstractSubprogram,
            2 => FunctionDieKind::ConcreteSubprogram,
            3 => FunctionDieKind::InlineInstance,
            value => anyhow::bail!("Invalid cached function kind {value}"),
        };

        Ok(IndexEntry {
            name: Arc::clone(cached_string(strings, self.name_id, "index name")?),
            die_offset: gimli::UnitOffset(usize::try_from(self.die_offset)?),
            unit_offset: gimli::DebugInfoOffset(usize::try_from(self.unit_offset)?),
            tag: gimli::DwTag(self.tag),
            flags: self.flags.into_index_flags(),
            language: self.language.map(gimli::DwLang),
            representative_addr: self.representative_addr,
            entry_pc: self.entry_pc,
            function_kind,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CachedIndexFlags {
    is_static: bool,
    is_main: bool,
    has_inline_attribute: bool,
    is_linkage: bool,
    is_type_declaration: bool,
    is_synthesized: bool,
}

impl From<IndexFlags> for CachedIndexFlags {
    fn from(flags: IndexFlags) -> Self {
        Self {
            is_static: flags.is_static,
            is_main: flags.is_main,
            has_inline_attribute: flags.has_inline_attribute,
            is_linkage: flags.is_linkage,
            is_type_declaration: flags.is_type_declaration,
            is_synthesized: flags.is_synthesized,
        }
    }
}

impl CachedIndexFlags {
    fn into_index_flags(self) -> IndexFlags {
        IndexFlags {
            is_static: self.is_static,
            is_main: self.is_main,
            has_inline_attribute: self.has_inline_attribute,
            is_linkage: self.is_linkage,
            is_type_declaration: self.is_type_declaration,
            is_synthesized: self.is_synthesized,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CachedCuRange {
    start: u64,
    end: u64,
    cu_offset: u64,
}

#[derive(Serialize, Deserialize)]
struct CachedScopedFileIndex {
    cu_name_id: u32,
    comp_dir_id: Option<u32>,
    directory_ids: Vec<u32>,
    dwarf_version: u16,
    files: Vec<CachedFileEntry>,
}

impl CachedScopedFileIndex {
    fn from_index(
        cu_name: &str,
        index: &LightweightFileIndex,
        strings: &StringInterner,
    ) -> Result<Self> {
        Ok(Self {
            cu_name_id: strings.id(cu_name)?,
            comp_dir_id: index
                .cache_comp_dir()
                .map(|directory| strings.id(directory))
                .transpose()?,
            directory_ids: index
                .cache_directories()
                .map(|directory| strings.id(directory))
                .collect::<Result<Vec<_>>>()?,
            dwarf_version: index.cache_dwarf_version(),
            files: index
                .file_entries()
                .iter()
                .map(|entry| {
                    Ok(CachedFileEntry {
                        file_index: entry.file_index,
                        directory_index: entry.directory_index,
                        filename_id: strings.id(&entry.filename)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn into_index(self, strings: &[Arc<str>]) -> Result<(String, LightweightFileIndex)> {
        let comp_dir = self
            .comp_dir_id
            .map(|id| cached_string(strings, id, "compilation directory"))
            .transpose()?
            .map(ToString::to_string);
        let mut index = LightweightFileIndex::new(comp_dir, self.dwarf_version);
        for directory_id in self.directory_ids {
            index
                .add_directory(cached_string(strings, directory_id, "line directory")?.to_string());
        }
        for file in self.files {
            index.add_file_entry(
                file.file_index,
                file.directory_index,
                cached_string(strings, file.filename_id, "line filename")?.to_string(),
            );
        }
        Ok((
            cached_string(strings, self.cu_name_id, "scoped CU name")?.to_string(),
            index,
        ))
    }
}

#[derive(Serialize, Deserialize)]
struct CachedFileEntry {
    file_index: u64,
    directory_index: u64,
    filename_id: u32,
}

#[derive(Serialize, Deserialize)]
struct CachedCompilationUnit {
    base_directory_id: u32,
    include_directory_ids: Vec<u32>,
    files: Vec<CachedSourceFile>,
}

impl CachedCompilationUnit {
    fn from_unit(unit: &CompilationUnit, strings: &StringInterner) -> Result<Self> {
        Ok(Self {
            base_directory_id: strings.id(&unit.base_directory)?,
            include_directory_ids: unit
                .include_directories
                .iter()
                .map(|directory| strings.id(directory))
                .collect::<Result<Vec<_>>>()?,
            files: unit
                .files
                .iter()
                .map(|file| CachedSourceFile::from_file(file, strings))
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn into_compilation_unit(self, strings: &[Arc<str>]) -> Result<CompilationUnit> {
        Ok(CompilationUnit {
            base_directory: cached_string(strings, self.base_directory_id, "CU base directory")?
                .to_string(),
            include_directories: self
                .include_directory_ids
                .into_iter()
                .map(|id| Ok(cached_string(strings, id, "CU include directory")?.to_string()))
                .collect::<Result<Vec<_>>>()?,
            files: self
                .files
                .into_iter()
                .map(|file| file.into_source_file(strings))
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CachedSourceFile {
    directory_path_id: u32,
    filename_id: u32,
    full_path_id: u32,
}

impl CachedSourceFile {
    fn from_file(file: &SourceFile, strings: &StringInterner) -> Result<Self> {
        Ok(Self {
            directory_path_id: strings.id(&file.directory_path)?,
            filename_id: strings.id(&file.filename)?,
            full_path_id: strings.id(&file.full_path)?,
        })
    }

    fn into_source_file(self, strings: &[Arc<str>]) -> Result<SourceFile> {
        Ok(SourceFile {
            directory_path: cached_string(strings, self.directory_path_id, "source directory")?
                .to_string(),
            filename: cached_string(strings, self.filename_id, "source filename")?.to_string(),
            full_path: cached_string(strings, self.full_path_id, "source full path")?.to_string(),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CachedParseStats {
    total_functions: u64,
    total_variables: u64,
    total_line_entries: u64,
    total_files: u64,
}

impl From<&DwarfParseStats> for CachedParseStats {
    fn from(stats: &DwarfParseStats) -> Self {
        Self {
            total_functions: stats.total_functions as u64,
            total_variables: stats.total_variables as u64,
            total_line_entries: stats.total_line_entries as u64,
            total_files: stats.total_files as u64,
        }
    }
}

impl CachedParseStats {
    fn into_parse_stats(self) -> DwarfParseStats {
        DwarfParseStats {
            total_functions: self.total_functions as usize,
            total_variables: self.total_variables as usize,
            total_line_entries: self.total_line_entries as usize,
            total_files: self.total_files as usize,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::LineEntry;
    use std::sync::Arc;

    fn sample_parse_result() -> DwarfParseResult {
        let entry = IndexEntry {
            name: Arc::from("cache_probe"),
            die_offset: gimli::UnitOffset(12),
            unit_offset: gimli::DebugInfoOffset(4),
            tag: gimli::constants::DW_TAG_subprogram,
            flags: IndexFlags::default(),
            language: Some(gimli::constants::DW_LANG_C11),
            representative_addr: Some(0x1234),
            entry_pc: None,
            function_kind: FunctionDieKind::ConcreteSubprogram,
        };
        let lightweight_index = LightweightIndex::from_cached_entries(
            vec![entry],
            vec![(0x1200, 0x1300, gimli::DebugInfoOffset(4))],
        );

        let mut file_index = LightweightFileIndex::new(Some("/src".to_string()), 4);
        file_index.add_file_entry(1, 0, "cache.c".to_string());
        let mut scoped_file_manager = ScopedFileIndexManager::new();
        scoped_file_manager.add_compilation_unit("cache.c".to_string(), file_index);
        let line_mapping = LineMappingTable::from_entries_with_scoped_manager(
            vec![LineEntry {
                address: 0x1234,
                end_address: Some(0x1240),
                file_path: String::new(),
                file_index: 1,
                compilation_unit: Arc::from("cache.c"),
                line: 17,
                column: 3,
                is_stmt: true,
                prologue_end: true,
            }],
            &scoped_file_manager,
        );

        DwarfParseResult {
            lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units: HashMap::from([(
                "cache.c".to_string(),
                CompilationUnit {
                    base_directory: "/src".to_string(),
                    include_directories: vec!["/src/include".to_string()],
                    files: vec![SourceFile {
                        directory_path: "/src".to_string(),
                        filename: "cache.c".to_string(),
                        full_path: "/src/cache.c".to_string(),
                    }],
                },
            )]),
            stats: DwarfParseStats {
                total_functions: 1,
                total_variables: 0,
                total_line_entries: 1,
                total_files: 1,
            },
        }
    }

    #[test]
    fn cache_round_trip_restores_lookup_indices() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        fs::write(&module_path, b"not-an-elf-cache-fixture").unwrap();
        let mapped = MappedFile::open(&module_path).unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));

        let entry_path = cache
            .store(&mapped, &mapped, &sample_parse_result())
            .unwrap();
        let restored = cache.load(&mapped, &mapped).unwrap().unwrap();

        assert!(entry_path.is_file());
        assert!(restored.line_mapping.is_mapped());
        assert_eq!(restored.stats.total_functions, 1);
        assert_eq!(
            restored
                .lightweight_index
                .find_dies_by_function_name("cache_probe")
                .len(),
            1
        );
        assert_eq!(
            restored
                .line_mapping
                .lookup_addresses_by_path("/src/cache.c", 17),
            vec![0x1234]
        );
        assert_eq!(
            restored
                .line_mapping
                .lookup_line(0x1235)
                .map(|entry| entry.line),
            Some(17)
        );
        assert!(restored.line_mapping.lookup_line(0x1240).is_none());
        assert_eq!(
            restored
                .line_mapping
                .lookup_all_lines_at_address(0x1234)
                .len(),
            1
        );
        assert_eq!(
            restored
                .scoped_file_manager
                .lookup_by_scoped_index("cache.c", 1)
                .as_deref(),
            Some("/src/cache.c")
        );
    }

    #[test]
    fn changed_debug_file_does_not_reuse_cache_entry() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        let debug_path = temp.path().join("module.debug");
        fs::write(&module_path, b"stable-module-fixture").unwrap();
        fs::write(&debug_path, b"first-debug-cache-fixture").unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));
        let mapped = MappedFile::open(&module_path).unwrap();
        let debug = MappedFile::open(&debug_path).unwrap();
        cache
            .store(&mapped, &debug, &sample_parse_result())
            .unwrap();
        drop(debug);

        fs::write(&debug_path, b"second-debug-cache-fixture-with-new-size").unwrap();
        let changed_debug = MappedFile::open(&debug_path).unwrap();

        assert!(cache.load(&mapped, &changed_debug).unwrap().is_none());
    }

    #[test]
    fn forged_metadata_length_returns_error_without_panicking() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        fs::write(&module_path, b"not-an-elf-cache-fixture").unwrap();
        let mapped = MappedFile::open(&module_path).unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));
        let entry_path = cache
            .store(&mapped, &mapped, &sample_parse_result())
            .unwrap();

        let mut encoded = fs::read(&entry_path).unwrap();
        let header_len = u32::from_le_bytes(encoded[12..16].try_into().unwrap()) as usize;
        let payload_offset = CACHE_FILE_PREFIX_LEN + header_len;
        // The metadata begins with a Vec length followed by the first entry's
        // String length. Forge the String length to exercise the bounded
        // decoder before it can allocate from an untrusted size.
        encoded[payload_offset + 8..payload_offset + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        fs::write(&entry_path, encoded).unwrap();

        let outcome = catch_unwind(AssertUnwindSafe(|| cache.load(&mapped, &mapped)));
        assert!(outcome.is_ok(), "malformed cache must not panic");
        let error = match outcome.unwrap() {
            Ok(_) => panic!("malformed cache unexpectedly decoded"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("Failed to decode analysis cache metadata"),
            "unexpected cache error: {error}"
        );
    }

    #[test]
    fn oversized_cache_is_rejected_before_decoding() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        fs::write(&module_path, b"not-an-elf-cache-fixture").unwrap();
        let mapped = MappedFile::open(&module_path).unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));
        let entry_path = cache
            .store(&mapped, &mapped, &sample_parse_result())
            .unwrap();
        OpenOptions::new()
            .write(true)
            .open(&entry_path)
            .unwrap()
            .set_len(MAX_CACHE_FILE_BYTES + 1)
            .unwrap();

        let error = match cache.load(&mapped, &mapped) {
            Ok(_) => panic!("oversized cache unexpectedly decoded"),
            Err(error) => error.to_string(),
        };
        assert!(
            error.contains("exceeding") && error.contains("byte limit"),
            "unexpected cache error: {error}"
        );
    }

    #[test]
    fn invalid_mapped_line_string_id_does_not_panic() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        fs::write(&module_path, b"not-an-elf-cache-fixture").unwrap();
        let mapped = MappedFile::open(&module_path).unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));
        let entry_path = cache
            .store(&mapped, &mapped, &sample_parse_result())
            .unwrap();

        let mut encoded = fs::read(&entry_path).unwrap();
        let header_len = u32::from_le_bytes(encoded[12..16].try_into().unwrap()) as usize;
        let header: CacheHeader = cache_codec()
            .deserialize(&encoded[CACHE_FILE_PREFIX_LEN..CACHE_FILE_PREFIX_LEN + header_len])
            .unwrap();
        let row_offset = CACHE_FILE_PREFIX_LEN + header_len + header.layout.metadata_len as usize;
        encoded[row_offset + 16..row_offset + 20].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&entry_path, encoded).unwrap();

        let restored = cache.load(&mapped, &mapped).unwrap().unwrap();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            (
                restored.line_mapping.lookup_line(0x1234),
                restored
                    .line_mapping
                    .lookup_addresses_by_path("/src/cache.c", 17),
            )
        }));
        assert!(outcome.is_ok(), "malformed mapped rows must not panic");
        let (line, addresses) = outcome.unwrap();
        assert!(line.is_none());
        assert!(addresses.is_empty());
    }

    #[test]
    fn loaded_cache_is_stable_after_backing_file_is_truncated() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.bin");
        fs::write(&module_path, b"not-an-elf-cache-fixture").unwrap();
        let mapped = MappedFile::open(&module_path).unwrap();
        let cache = AnalysisCache::new(temp.path().join("cache"));
        let entry_path = cache
            .store(&mapped, &mapped, &sample_parse_result())
            .unwrap();
        let restored = cache.load(&mapped, &mapped).unwrap().unwrap();

        OpenOptions::new()
            .write(true)
            .open(entry_path)
            .unwrap()
            .set_len(0)
            .unwrap();

        assert_eq!(
            restored
                .line_mapping
                .lookup_addresses_by_path("/src/cache.c", 17),
            vec![0x1234]
        );
    }
}

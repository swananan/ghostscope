use crate::{
    binary::MappedFile,
    index::{
        lightweight_file_index::LightweightFileEntry, CuNameIndex, GdbSymbolKind,
        LightweightFileIndex, LightweightIndex, LineMappingTable, ScopedFileIndexManager,
    },
    parser::{CompilationUnit, DwarfParseResult, SourceFile},
};
use anyhow::{Context, Result};
use bincode::Options;
use object::Object;
use rayon::prelude::*;
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
};

const CACHE_MAGIC: [u8; 8] = *b"GSANLYS\0";
// Bump for changes to the persisted layout or index-construction semantics,
// even when the package version stays unchanged.
const CACHE_SCHEMA_VERSION: u32 = 4;
const CACHE_FILE_PREFIX_LEN: usize = 24;
const MAX_CACHE_HEADER_BYTES: u64 = 64 * 1024;
const MAX_CACHE_PAYLOAD_BYTES: u64 = 512 * 1024 * 1024;
const MAX_CACHE_FILE_BYTES: u64 =
    CACHE_FILE_PREFIX_LEN as u64 + MAX_CACHE_HEADER_BYTES + MAX_CACHE_PAYLOAD_BYTES;
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

mod maintenance;

#[derive(Debug, Clone)]
pub struct AnalysisCache {
    directory: PathBuf,
    writable: bool,
    max_size_bytes: u64,
}

impl AnalysisCache {
    pub const DEFAULT_MAX_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            writable: true,
            max_size_bytes: Self::DEFAULT_MAX_SIZE_BYTES,
        }
    }

    /// Never create or replace payloads. Successful reads may update recency
    /// metadata; failure to do so does not prevent using a shared cache.
    pub fn read_only(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            writable: false,
            max_size_bytes: Self::DEFAULT_MAX_SIZE_BYTES,
        }
    }

    /// Total logical bytes managed by prepare, including reserved output space.
    pub fn with_max_size_bytes(mut self, max_size_bytes: u64) -> Self {
        self.max_size_bytes = max_size_bytes;
        self
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
        supplementary: Option<&MappedFile>,
    ) -> Result<Option<PreparedAnalysis>> {
        let identity = CacheIdentity::new(binary, debug_file, supplementary)?;
        let path = self.entry_path(&identity)?;
        // A prepare hit must also enforce a newly lowered budget. Hold the same
        // writer lock across validation and pruning so its entry stays present.
        let maintenance = if self.writable {
            if !self.directory.try_exists()? {
                return Ok(None);
            }
            Some(maintenance::Maintenance::acquire(&self.directory)?)
        } else {
            None
        };
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
        let mut data = Vec::new();
        data.try_reserve_exact(snapshot_len)
            .context("Failed to allocate cache snapshot")?;
        data.resize(snapshot_len, 0);
        file.read_exact(&mut data)
            .with_context(|| format!("Failed to snapshot analysis cache {}", path.display()))?;
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

        anyhow::ensure!(
            crc32fast::hash(&data[header_end..]) == header.payload_crc32,
            "Analysis cache payload checksum mismatch"
        );
        let payload: CachedAnalysis = deserialize_cache_slice(
            data.get(header_end..)
                .context("Analysis cache payload is out of bounds")?,
            "payload",
            &path,
        )?;
        let result = payload.into_parse_result(debug_file.as_bytes().len())?;
        maintenance::record_hit(&file, &metadata);
        if let Some(maintenance) = maintenance {
            maintenance.prune(self.max_size_bytes, 0, Some(&path))?;
        }
        Ok(Some(result))
    }

    pub(crate) fn store(
        &self,
        binary: &MappedFile,
        debug_file: &MappedFile,
        supplementary: Option<&MappedFile>,
        parse_result: &DwarfParseResult,
        all_units: &[gimli::DebugInfoOffset],
    ) -> Result<PathBuf> {
        let identity = CacheIdentity::new(binary, debug_file, supplementary)?;
        let path = self.entry_path(&identity)?;
        let directory = path
            .parent()
            .context("Analysis cache entry has no parent directory")?;
        create_private_directory(directory)?;

        let payload = CachedAnalysis::from_parse_result(parse_result, all_units)?;
        let payload = cache_codec().serialize(&payload)?;
        let payload_len = payload.len() as u64;
        let header = CacheHeader {
            package_version: env!("CARGO_PKG_VERSION").to_string(),
            identity,
            payload_crc32: crc32fast::hash(&payload),
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
        let file_len = CACHE_FILE_PREFIX_LEN as u64 + header_len + payload_len;
        anyhow::ensure!(file_len <= self.max_size_bytes,
            "Prepared analysis cache entry is {file_len} bytes, exceeding the configured {} byte cache size limit",
            self.max_size_bytes);
        let maintenance = maintenance::Maintenance::acquire(&self.directory)?;
        maintenance.prune(self.max_size_bytes, file_len, None)?;
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temp_path = directory.join(format!(
            ".{}.{}.{}.tmp",
            path.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("analysis-cache"),
            std::process::id(),
            sequence
        ));

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
        let write_result = (|| -> Result<()> {
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
            writer.write_all(&payload)?;
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
    supplementary: Option<FileIdentity>,
}

impl CacheIdentity {
    fn new(
        binary: &MappedFile,
        debug_file: &MappedFile,
        supplementary: Option<&MappedFile>,
    ) -> Result<Self> {
        Ok(Self {
            binary: FileIdentity::new(binary)?,
            debug_file: FileIdentity::new(debug_file)?,
            supplementary: supplementary.map(FileIdentity::new).transpose()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    byte_len: u64,
    build_id: Option<Vec<u8>>,
    device: u64,
    inode: u64,
    ctime_secs: i64,
    ctime_nanos: i64,
    modified_secs: i64,
    modified_nanos: i64,
}

impl FileIdentity {
    fn new(file: &MappedFile) -> Result<Self> {
        let build_id = file
            .parse_object()
            .ok()
            .and_then(|object| object.build_id().ok().flatten().map(ToOwned::to_owned));
        // Identity comes from the descriptor that supplied the mapping, not a
        // second lookup of a path that might now name a replacement inode.
        let metadata = file
            .metadata
            .as_ref()
            .context("Mapped file has no descriptor identity")?;
        Ok(Self {
            byte_len: u64::try_from(file.as_bytes().len())?,
            build_id,
            device: metadata.dev(),
            inode: metadata.ino(),
            ctime_secs: metadata.ctime(),
            ctime_nanos: metadata.ctime_nsec(),
            modified_secs: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
        })
    }
}

#[derive(Serialize, Deserialize)]
struct CacheHeader {
    package_version: String,
    identity: CacheIdentity,
    payload_crc32: u32,
}

/// A prepared index selects CUs, but never substitutes for their concrete DIEs.
pub(crate) struct PreparedAnalysis {
    pub parse_result: crate::parser::DwarfParseResult,
    pub names: CuNameIndex,
}

#[derive(Serialize, Deserialize)]
struct CachedAnalysis {
    strings: Vec<String>,
    units: Vec<u64>,
    names: Vec<(u8, u32, Vec<u32>)>,
    ranges: Vec<(u64, u64, u32)>,
    line_units: Vec<CachedLineUnit>,
    source_units: Vec<(u32, Vec<u32>)>,
    index_stats: (usize, usize, usize),
    parse_stats: (usize, usize, usize, usize),
}

#[derive(Serialize, Deserialize)]
struct CachedLineUnit {
    unit: u32,
    comp_dir: Option<u32>,
    directories: Vec<u32>,
    version: u16,
    files: Vec<(u64, u64, u32)>,
    base_directory: u32,
    include_directories: Vec<u32>,
    sources: Vec<(u32, u32, u32)>,
}

impl CachedAnalysis {
    fn from_parse_result(
        result: &DwarfParseResult,
        all_units: &[gimli::DebugInfoOffset],
    ) -> Result<Self> {
        let mut strings = StringInterner::default();
        let mut units = all_units.to_vec();
        units.sort_unstable_by_key(|unit| unit.0);
        units.dedup();
        let unit_ids: HashMap<_, _> = units
            .iter()
            .enumerate()
            .map(|(i, &unit)| Ok((unit, u32::try_from(i)?)))
            .collect::<Result<_>>()?;
        let unit_id = |unit: gimli::DebugInfoOffset| -> Result<u32> {
            unit_ids
                .get(&unit)
                .copied()
                .context("Cache references an unknown compilation unit")
        };
        let names = result
            .lightweight_index
            .cache_names()
            .into_iter()
            .map(|(kind, name, offsets)| {
                Ok((
                    kind,
                    strings.intern(&name)?,
                    offsets.into_iter().map(unit_id).collect::<Result<_>>()?,
                ))
            })
            .collect::<Result<_>>()?;
        let ranges = result
            .lightweight_index
            .cache_cu_ranges()
            .into_iter()
            .map(|(start, end, unit)| Ok((start, end, unit_id(unit)?)))
            .collect::<Result<_>>()?;
        let mut line_units = Vec::new();
        for &unit in &units {
            let Some(info) = result.compilation_units.get(&unit) else {
                continue;
            };
            let index = result
                .scoped_file_manager
                .get_cu_file_index(unit)
                .context("Missing prepared CU file index")?;
            let (comp_dir, directories, version) = index.cache_parts();
            line_units.push(CachedLineUnit {
                unit: unit_id(unit)?,
                comp_dir: comp_dir.map(|s| strings.intern(s)).transpose()?,
                directories: directories
                    .iter()
                    .map(|s| strings.intern(s))
                    .collect::<Result<_>>()?,
                version,
                files: index
                    .file_entries()
                    .iter()
                    .map(|file| {
                        Ok((
                            file.file_index,
                            file.directory_index,
                            strings.intern(&file.filename)?,
                        ))
                    })
                    .collect::<Result<_>>()?,
                base_directory: strings.intern(&info.base_directory)?,
                include_directories: info
                    .include_directories
                    .iter()
                    .map(|s| strings.intern(s))
                    .collect::<Result<_>>()?,
                sources: info
                    .files
                    .iter()
                    .map(|file| {
                        Ok((
                            strings.intern(&file.directory_path)?,
                            strings.intern(&file.filename)?,
                            strings.intern(&file.full_path)?,
                        ))
                    })
                    .collect::<Result<_>>()?,
            });
        }
        let source_units = result
            .line_source_unit_offsets
            .iter()
            .map(|(path, offsets)| {
                Ok((
                    strings.intern(path)?,
                    offsets
                        .iter()
                        .copied()
                        .map(unit_id)
                        .collect::<Result<_>>()?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            strings: strings.strings,
            units: units.into_iter().map(|u| u.0 as u64).collect(),
            names,
            ranges,
            line_units,
            source_units,
            index_stats: result.lightweight_index.get_stats(),
            parse_stats: (
                result.stats.total_functions,
                result.stats.total_variables,
                result.stats.total_line_entries,
                result.stats.total_files,
            ),
        })
    }

    fn into_parse_result(self, debug_file_len: usize) -> Result<PreparedAnalysis> {
        let strings = self.strings;
        let shared_strings: Vec<Arc<str>> = strings.iter().map(|s| Arc::from(s.as_str())).collect();
        let shared_string = |id: u32| -> Result<Arc<str>> {
            shared_strings
                .get(id as usize)
                .cloned()
                .context("Cached string ID is out of bounds")
        };
        let string = |id: u32| -> Result<String> {
            strings
                .get(id as usize)
                .cloned()
                .context("Cached string ID is out of bounds")
        };
        let units = self
            .units
            .into_iter()
            .map(|offset| {
                let offset = usize::try_from(offset)?;
                anyhow::ensure!(offset < debug_file_len, "Cached CU offset is out of bounds");
                Ok(gimli::DebugInfoOffset(offset))
            })
            .collect::<Result<Vec<_>>>()?;
        anyhow::ensure!(
            units.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "Cached CU offsets are not strictly ordered"
        );
        let unit = |id: u32| -> Result<gimli::DebugInfoOffset> {
            units
                .get(id as usize)
                .copied()
                .context("Cached CU ID is out of bounds")
        };
        let mut names = CuNameIndex::new(units.clone()).with_prepared_stats(self.index_stats);
        for (kind, name, offsets) in self.names {
            let kind = match kind {
                0 => GdbSymbolKind::Function,
                1 => GdbSymbolKind::Variable,
                2 => GdbSymbolKind::Type,
                _ => anyhow::bail!("Invalid cached name kind"),
            };
            let name = string(name)?;
            names.insert_prepared(
                name,
                offsets.into_iter().map(unit).collect::<Result<_>>()?,
                kind,
            );
        }
        let ranges = self
            .ranges
            .into_iter()
            .map(|(start, end, offset)| {
                anyhow::ensure!(start < end, "Invalid cached CU range");
                Ok((start, end, unit(offset)?))
            })
            .collect::<Result<_>>()?;
        let line_units = self
            .line_units
            .into_par_iter()
            .map(|cached| -> Result<_> {
                let unit = unit(cached.unit)?;
                let count = cached.files.len() as u64;
                let files = cached
                    .files
                    .into_iter()
                    .map(|(file, directory, name)| -> Result<_> {
                        // Path caches are indexed by the original DWARF file number.
                        anyhow::ensure!(file <= count, "Cached file index is out of bounds");
                        Ok(LightweightFileEntry {
                            file_index: file,
                            directory_index: directory,
                            filename: shared_string(name)?,
                        })
                    })
                    .collect::<Result<_>>()?;
                let index = LightweightFileIndex::from_prepared_parts(
                    cached.comp_dir.map(shared_string).transpose()?,
                    cached
                        .directories
                        .into_iter()
                        .map(shared_string)
                        .collect::<Result<_>>()?,
                    cached.version,
                    files,
                );
                let info = CompilationUnit {
                    base_directory: string(cached.base_directory)?,
                    include_directories: cached
                        .include_directories
                        .into_iter()
                        .map(string)
                        .collect::<Result<_>>()?,
                    files: cached
                        .sources
                        .into_iter()
                        .map(|(dir, name, path)| {
                            Ok(SourceFile {
                                directory_path: string(dir)?,
                                filename: string(name)?,
                                full_path: string(path)?,
                            })
                        })
                        .collect::<Result<_>>()?,
                };
                Ok((unit, index, info))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut scoped_file_manager = ScopedFileIndexManager::new();
        let mut compilation_units = HashMap::new();
        for (unit, index, info) in line_units {
            anyhow::ensure!(
                compilation_units.insert(unit, info).is_none(),
                "Duplicate cached line CU"
            );
            scoped_file_manager.add_compilation_unit(unit, index);
        }
        let line_source_unit_offsets = self
            .source_units
            .into_iter()
            .map(|(path, offsets)| {
                Ok((
                    string(path)?,
                    offsets.into_iter().map(unit).collect::<Result<Vec<_>>>()?,
                ))
            })
            .collect::<Result<_>>()?;
        let (total_functions, total_variables, total_line_entries, total_files) = self.parse_stats;
        anyhow::ensure!(
            total_line_entries == 0,
            "Prepared analysis must leave line rows lazy"
        );
        Ok(PreparedAnalysis {
            parse_result: DwarfParseResult {
                lightweight_index: LightweightIndex::from_cached_cu_ranges(ranges),
                line_mapping: LineMappingTable::from_entries_with_scoped_manager(
                    Vec::new(),
                    &scoped_file_manager,
                ),
                scoped_file_manager,
                compilation_units,
                line_source_unit_offsets,
                stats: crate::parser::fast_parser::DwarfParseStats {
                    total_functions,
                    total_variables,
                    total_line_entries,
                    total_files,
                },
            },
            names,
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
        self.strings.push(value.to_owned());
        self.ids.insert(value.to_owned(), id);
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{FunctionDieKind, IndexEntry, IndexFlags};
    use crate::index::LightweightIndexShard;
    use std::sync::Arc;
    const UNITS: &[gimli::DebugInfoOffset] =
        &[gimli::DebugInfoOffset(4), gimli::DebugInfoOffset(8)];

    fn sample() -> DwarfParseResult {
        let mut shard = LightweightIndexShard::default();
        shard.push_function_entry(
            "lookup_alias".into(),
            IndexEntry {
                name: Arc::from("display_name"),
                die_offset: gimli::UnitOffset(12),
                unit_offset: gimli::DebugInfoOffset(4),
                lexical_scope: Some(gimli::UnitOffset(8)),
                tag: gimli::DW_TAG_subprogram,
                flags: IndexFlags::default(),
                language: Some(gimli::DW_LANG_C11),
                representative_addr: Some(0x1234),
                entry_pc: None,
                function_kind: FunctionDieKind::ConcreteSubprogram,
            },
        );
        let mut scoped_file_manager = ScopedFileIndexManager::new();
        let mut compilation_units = HashMap::new();
        let mut line_source_unit_offsets = HashMap::new();
        for (&unit, dir) in UNITS.iter().zip(["/first", "/second"]) {
            let mut index = LightweightFileIndex::new(Some(dir.into()), 4);
            index.add_file_entry(1, 0, "same.c".into());
            scoped_file_manager.add_compilation_unit(unit, index);
            compilation_units.insert(
                unit,
                CompilationUnit {
                    base_directory: dir.into(),
                    include_directories: Vec::new(),
                    files: vec![SourceFile {
                        directory_path: dir.into(),
                        filename: "same.c".into(),
                        full_path: format!("{dir}/same.c"),
                    }],
                },
            );
            line_source_unit_offsets.insert(format!("{dir}/same.c"), vec![unit]);
        }
        line_source_unit_offsets.insert("same.c".into(), UNITS.to_vec());
        DwarfParseResult {
            lightweight_index: LightweightIndex::from_shards(vec![shard]),
            line_mapping: LineMappingTable::from_entries_with_scoped_manager(
                Vec::new(),
                &scoped_file_manager,
            ),
            scoped_file_manager,
            compilation_units,
            line_source_unit_offsets,
            stats: crate::parser::fast_parser::DwarfParseStats {
                total_functions: 1,
                total_variables: 0,
                total_line_entries: 0,
                total_files: 2,
            },
        }
    }

    fn fixture() -> (tempfile::TempDir, MappedFile, AnalysisCache) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("module");
        fs::write(&path, b"not-an-elf-fixture").unwrap();
        let mapped = MappedFile::open(path).unwrap();
        let cache = AnalysisCache::new(dir.path().join("cache"));
        (dir, mapped, cache)
    }

    #[test]
    fn round_trip_preserves_aliases_and_cu_scoped_file_headers() {
        for version in [4, 5] {
            check_scoped_header_round_trip(version);
        }
    }

    fn check_scoped_header_round_trip(version: u16) {
        let (_dir, mapped, cache) = fixture();
        let first_file = u64::from(version < 5);
        let mut result = sample();
        for (&unit, dir) in UNITS.iter().zip(["/first", "/second"]) {
            let mut index = LightweightFileIndex::new(Some(dir.into()), version);
            if version >= 5 {
                index.add_directory(dir.into());
            }
            index.add_file_entry(first_file, 0, "same.c".into());
            result.scoped_file_manager.add_compilation_unit(unit, index);
        }
        cache.store(&mapped, &mapped, None, &result, UNITS).unwrap();
        let restored = cache.load(&mapped, &mapped, None).unwrap().unwrap();
        assert_eq!(
            restored
                .names
                .lookup_units("lookup_alias", GdbSymbolKind::Function, false),
            vec![UNITS[0]]
        );
        assert_eq!(restored.parse_result.lightweight_index.entry_count(), 0);
        assert_eq!(
            restored.parse_result.line_source_unit_offsets["same.c"],
            UNITS
        );
        for (&unit, dir) in UNITS.iter().zip(["/first", "/second"]) {
            assert_eq!(
                restored
                    .parse_result
                    .scoped_file_manager
                    .lookup_by_scoped_index(unit, first_file),
                Some(format!("{dir}/same.c"))
            );
        }
    }

    #[test]
    fn supplementary_identity_is_required_and_invalidates_on_change() {
        let (dir, mapped, cache) = fixture();
        let path = dir.path().join("supplementary");
        fs::write(&path, b"first supplement").unwrap();
        let supplement = MappedFile::open(&path).unwrap();
        cache
            .store(&mapped, &mapped, Some(&supplement), &sample(), UNITS)
            .unwrap();
        assert!(cache
            .load(&mapped, &mapped, Some(&supplement))
            .unwrap()
            .is_some());
        assert!(cache.load(&mapped, &mapped, None).unwrap().is_none());
        let replacement = dir.path().join("replacement");
        fs::write(&replacement, b"other supplement").unwrap();
        fs::rename(replacement, &path).unwrap();
        let changed = MappedFile::open(&path).unwrap();
        assert!(cache
            .load(&mapped, &mapped, Some(&changed))
            .unwrap()
            .is_none());
        // The old mapping keeps its own identity even though its path changed.
        assert!(cache
            .load(&mapped, &mapped, Some(&supplement))
            .unwrap()
            .is_some());
    }

    fn rewrite_payload(path: &Path, change: impl FnOnce(&mut Vec<u8>), checksum: bool) {
        let encoded = fs::read(path).unwrap();
        let header_len = u32::from_le_bytes(encoded[12..16].try_into().unwrap()) as usize;
        let header_end = CACHE_FILE_PREFIX_LEN + header_len;
        let mut header: CacheHeader = cache_codec()
            .deserialize(&encoded[CACHE_FILE_PREFIX_LEN..header_end])
            .unwrap();
        let mut payload = encoded[header_end..].to_vec();
        change(&mut payload);
        if checksum {
            header.payload_crc32 = crc32fast::hash(&payload);
        }
        let mut out = encoded[..CACHE_FILE_PREFIX_LEN].to_vec();
        out[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        out.extend(cache_codec().serialize(&header).unwrap());
        out.extend(payload);
        fs::write(path, out).unwrap();
    }

    #[test]
    fn corrupt_payload_is_rejected_before_decode() {
        let (_dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        rewrite_payload(&path, |payload| payload[20] ^= 1, false);
        let result = cache.load(&mapped, &mapped, None);
        assert!(result
            .err()
            .unwrap()
            .to_string()
            .contains("checksum mismatch"));
    }

    #[test]
    fn forged_string_length_is_bounded_even_with_valid_checksum() {
        let (_dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        rewrite_payload(
            &path,
            |payload| payload[8..16].copy_from_slice(&u64::MAX.to_le_bytes()),
            true,
        );
        assert!(cache.load(&mapped, &mapped, None).is_err());
    }

    #[test]
    fn invalid_name_reference_is_rejected() {
        let (_dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        rewrite_payload(
            &path,
            |payload| {
                let mut index: CachedAnalysis = cache_codec().deserialize(payload).unwrap();
                index.units.clear();
                *payload = cache_codec().serialize(&index).unwrap();
            },
            true,
        );
        assert!(cache.load(&mapped, &mapped, None).is_err());
    }

    #[test]
    fn oversized_file_number_is_rejected_before_building_path_caches() {
        let (_dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        rewrite_payload(
            &path,
            |payload| {
                let mut index: CachedAnalysis = cache_codec().deserialize(payload).unwrap();
                index.line_units[0].files[0].0 = u64::MAX;
                *payload = cache_codec().serialize(&index).unwrap();
            },
            true,
        );
        assert!(cache
            .load(&mapped, &mapped, None)
            .err()
            .unwrap()
            .to_string()
            .contains("file index is out of bounds"));
    }

    #[test]
    fn incompatible_truncated_oversized_and_symlink_entries_are_rejected() {
        let (dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        let encoded = fs::read(&path).unwrap();
        let mut old = encoded.clone();
        old[8..12].copy_from_slice(&2_u32.to_le_bytes());
        fs::write(&path, old).unwrap();
        assert!(cache.load(&mapped, &mapped, None).is_err());
        fs::write(&path, &encoded[..encoded.len() - 1]).unwrap();
        assert!(cache.load(&mapped, &mapped, None).is_err());
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_CACHE_FILE_BYTES + 1)
            .unwrap();
        assert!(cache.load(&mapped, &mapped, None).is_err());
        fs::remove_file(&path).unwrap();
        let other = dir.path().join("other");
        fs::write(&other, encoded).unwrap();
        std::os::unix::fs::symlink(other, &path).unwrap();
        assert!(cache.load(&mapped, &mapped, None).is_err());
    }

    #[test]
    fn loaded_index_survives_cache_truncation_and_reader_does_not_write() {
        let (_dir, mapped, cache) = fixture();
        let reader = AnalysisCache::read_only(cache.directory());
        assert!(reader.load(&mapped, &mapped, None).unwrap().is_none());
        assert!(!reader.directory().exists());
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        let restored = reader.load(&mapped, &mapped, None).unwrap().unwrap();
        fs::write(path, []).unwrap();
        assert_eq!(
            restored
                .names
                .lookup_units("lookup_alias", GdbSymbolKind::Function, false)
                .len(),
            1
        );
    }

    #[test]
    fn real_hits_drive_eviction_and_loaded_snapshots_survive_it() {
        let (dir, first, cache) = fixture();
        let first_path = cache.store(&first, &first, None, &sample(), UNITS).unwrap();
        let entry_size = fs::metadata(&first_path).unwrap().len();
        let cache = cache.with_max_size_bytes(2 * entry_size);
        let module = |name: &str| {
            let path = dir.path().join(name);
            fs::write(&path, b"another module").unwrap();
            MappedFile::open(path).unwrap()
        };
        let second = module("second");
        let second_path = cache
            .store(&second, &second, None, &sample(), UNITS)
            .unwrap();
        let third = module("third");
        assert!(cache
            .clone()
            .with_max_size_bytes(entry_size - 1)
            .store(&third, &third, None, &sample(), UNITS)
            .is_err());
        assert!(first_path.exists() && second_path.exists());
        std::fs::File::open(&first_path)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH)
            .unwrap();
        std::fs::File::open(&second_path)
            .unwrap()
            .set_modified(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1))
            .unwrap();
        let restored = AnalysisCache::read_only(cache.directory())
            .load(&first, &first, None)
            .unwrap()
            .unwrap();
        let third_path = cache.store(&third, &third, None, &sample(), UNITS).unwrap();
        assert!(first_path.exists() && third_path.exists());
        assert!(!second_path.exists());
        let cache = cache.with_max_size_bytes(entry_size);
        assert!(cache.load(&third, &third, None).unwrap().is_some());
        assert!(!first_path.exists());
        assert!(third_path.exists());
        assert_eq!(
            restored
                .names
                .lookup_units("lookup_alias", GdbSymbolKind::Function, false),
            vec![UNITS[0]]
        );
    }

    #[test]
    fn concurrent_preparations_obey_one_shared_budget() {
        let (dir, mapped, cache) = fixture();
        let path = cache
            .store(&mapped, &mapped, None, &sample(), UNITS)
            .unwrap();
        let entry_size = fs::metadata(path).unwrap().len();
        let cache = cache.with_max_size_bytes(2 * entry_size);
        let barrier = Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for i in 0..8 {
            let path = dir.path().join(format!("module-{i}"));
            fs::write(&path, b"another module").unwrap();
            let cache = cache.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                let mapped = MappedFile::open(path).unwrap();
                barrier.wait();
                cache
                    .store(&mapped, &mapped, None, &sample(), UNITS)
                    .unwrap();
                mapped
            }));
        }
        let modules = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        let files = fs::read_dir(cache.directory().join(format!("v{CACHE_SCHEMA_VERSION}")))
            .unwrap()
            .map(|entry| entry.unwrap())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 2);
        assert!(
            files
                .iter()
                .map(|entry| entry.metadata().unwrap().len())
                .sum::<u64>()
                <= 2 * entry_size
        );
        let reader = AnalysisCache::read_only(cache.directory());
        assert_eq!(
            modules
                .iter()
                .filter(|mapped| reader.load(mapped, mapped, None).unwrap().is_some())
                .count(),
            2
        );
    }
}

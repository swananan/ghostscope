use crate::{
    binary::MappedFile,
    core::{FunctionDieKind, IndexEntry, IndexFlags},
    index::{lightweight_index::NameIndexShard, LightweightIndex},
    parser::DebugParseResult,
};
use anyhow::{Context, Result};
use bincode::Options;
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
};

const CACHE_MAGIC: [u8; 8] = *b"GSANLYS\0";
const CACHE_SCHEMA_VERSION: u32 = 3;
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
        supplementary: Option<&MappedFile>,
    ) -> Result<Option<DebugParseResult>> {
        let identity = CacheIdentity::new(binary, debug_file, supplementary)?;
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
        let mut data = Vec::new();
        data.try_reserve_exact(snapshot_len).context("Failed to allocate cache snapshot")?;
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
        let payload: CachedDebugIndex = deserialize_cache_slice(
            data.get(header_end..)
                .context("Analysis cache payload is out of bounds")?,
            "payload",
            &path,
        )?;
        payload.into_parse_result().map(Some)
    }

    pub(crate) fn store(
        &self,
        binary: &MappedFile,
        debug_file: &MappedFile,
        supplementary: Option<&MappedFile>,
        parse_result: &DebugParseResult,
    ) -> Result<PathBuf> {
        let identity = CacheIdentity::new(binary, debug_file, supplementary)?;
        let path = self.entry_path(&identity)?;
        let directory = path
            .parent()
            .context("Analysis cache entry has no parent directory")?;
        create_private_directory(directory)?;

        let payload = CachedDebugIndex::from_parse_result(parse_result)?;
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

/// Only full debug_info scans are persisted. Line headers/rows and native
/// accelerator indexes retain the normal loader's ownership and lazy behavior.
#[derive(Serialize, Deserialize)]
struct CachedDebugIndex {
    strings: Vec<String>,
    entries: Vec<CachedIndexEntry>,
    names: Vec<NameIndexShard>,
    cu_ranges: Vec<CachedCuRange>,
    functions_count: usize,
    variables_count: usize,
}

impl CachedDebugIndex {
    fn from_parse_result(result: &DebugParseResult) -> Result<Self> {
        let mut strings = StringInterner::default();
        for entry in result.lightweight_index.cache_entries() {
            strings.intern(&entry.name)?;
        }
        let entries = result
            .lightweight_index
            .cache_entries()
            .iter()
            .map(|entry| CachedIndexEntry::from_index_entry(entry, &strings))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            strings: strings.strings,
            entries,
            names: result.lightweight_index.cache_names(),
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
            functions_count: result.functions_count,
            variables_count: result.variables_count,
        })
    }

    fn into_parse_result(self) -> Result<DebugParseResult> {
        let strings: Vec<Arc<str>> = self.strings.into_iter().map(Arc::from).collect();
        let entries = self
            .entries
            .into_iter()
            .map(|entry| entry.into_index_entry(&strings))
            .collect::<Result<Vec<_>>>()?;
        let ranges = self
            .cu_ranges
            .into_iter()
            .map(|range| {
                anyhow::ensure!(range.start < range.end, "Invalid cached CU range");
                Ok((
                    range.start,
                    range.end,
                    gimli::DebugInfoOffset(usize::try_from(range.cu_offset)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(DebugParseResult {
            lightweight_index: LightweightIndex::from_cached_entries(entries, self.names, ranges)?,
            functions_count: self.functions_count,
            variables_count: self.variables_count,
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
    lexical_scope: Option<u64>,
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
            lexical_scope: entry.lexical_scope.map(|offset| offset.0 as u64),
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
            lexical_scope: self
                .lexical_scope
                .map(|offset| usize::try_from(offset).map(gimli::UnitOffset))
                .transpose()?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::LightweightIndexShard;

    fn sample() -> DebugParseResult {
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
        DebugParseResult {
            lightweight_index: LightweightIndex::from_shards(vec![shard]),
            functions_count: 1,
            variables_count: 0,
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
    fn round_trip_preserves_aliases_and_lexical_scope() {
        let (_dir, mapped, cache) = fixture();
        cache.store(&mapped, &mapped, None, &sample()).unwrap();
        let restored = cache.load(&mapped, &mapped, None).unwrap().unwrap();
        let entries = restored
            .lightweight_index
            .find_dies_by_function_name("lookup_alias");
        assert_eq!(entries.len(), 1);
        assert_eq!(&*entries[0].name, "display_name");
        assert_eq!(entries[0].lexical_scope, Some(gimli::UnitOffset(8)));
        assert_eq!(restored.functions_count, 1);
    }

    #[test]
    fn supplementary_identity_is_required_and_invalidates_on_change() {
        let (dir, mapped, cache) = fixture();
        let path = dir.path().join("supplementary");
        fs::write(&path, b"first supplement").unwrap();
        let supplement = MappedFile::open(&path).unwrap();
        cache
            .store(&mapped, &mapped, Some(&supplement), &sample())
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
        let path = cache.store(&mapped, &mapped, None, &sample()).unwrap();
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
        let path = cache.store(&mapped, &mapped, None, &sample()).unwrap();
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
        let path = cache.store(&mapped, &mapped, None, &sample()).unwrap();
        rewrite_payload(
            &path,
            |payload| {
                let mut index: CachedDebugIndex = cache_codec().deserialize(payload).unwrap();
                index.entries.clear();
                *payload = cache_codec().serialize(&index).unwrap();
            },
            true,
        );
        assert!(cache.load(&mapped, &mapped, None).is_err());
    }

    #[test]
    fn incompatible_truncated_oversized_and_symlink_entries_are_rejected() {
        let (dir, mapped, cache) = fixture();
        let path = cache.store(&mapped, &mapped, None, &sample()).unwrap();
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
        let path = cache.store(&mapped, &mapped, None, &sample()).unwrap();
        let restored = reader.load(&mapped, &mapped, None).unwrap().unwrap();
        fs::write(path, []).unwrap();
        assert_eq!(
            restored
                .lightweight_index
                .find_dies_by_function_name("lookup_alias")
                .len(),
            1
        );
    }
}

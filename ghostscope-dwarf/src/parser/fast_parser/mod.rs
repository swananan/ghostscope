//! Unified DWARF parser - true single-pass parsing

use crate::{
    binary::{dwarf_reader_from_arc_with_endian, DwarfReader},
    core::{FunctionDieKind, IndexEntry, LineEntry, Result},
    index::{
        directory_from_index, resolve_file_path, LightweightFileIndex, LightweightIndex,
        LightweightIndexShard, LineMappingTable, ScopedFileIndexManager,
    },
};
use gimli::{Reader, Section};
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::debug;

fn is_gdb2_name_index(header: &gimli::NameIndexHeader<DwarfReader>) -> Result<bool> {
    let Some(augmentation) = header.augmentation_string() else {
        return Ok(false);
    };
    Ok(augmentation.to_slice()?.starts_with(b"GDB2"))
}

fn checked_debug_names_table_size(count: u32, width: usize) -> Result<usize> {
    usize::try_from(count)?
        .checked_mul(width)
        .ok_or_else(|| anyhow::anyhow!(".debug_names table size overflow"))
}

fn gdb2_abbreviation_range(
    header: &gimli::NameIndexHeader<DwarfReader>,
) -> Result<std::ops::Range<usize>> {
    let word_size = usize::from(header.format().word_size());
    let initial_length_size = match header.format() {
        gimli::Format::Dwarf32 => 4,
        gimli::Format::Dwarf64 => 12,
    };
    let augmentation_size = header.augmentation_string().map_or(0, gimli::Reader::len);
    let padded_augmentation_size = augmentation_size
        .checked_add(3)
        .ok_or_else(|| anyhow::anyhow!(".debug_names augmentation size overflow"))?
        & !3;

    let mut start = header
        .offset()
        .0
        .checked_add(initial_length_size + 2 + 2 + 7 * std::mem::size_of::<u32>())
        .and_then(|offset| offset.checked_add(padded_augmentation_size))
        .ok_or_else(|| anyhow::anyhow!(".debug_names header size overflow"))?;
    for size in [
        checked_debug_names_table_size(header.compile_unit_count(), word_size)?,
        checked_debug_names_table_size(header.local_type_unit_count(), word_size)?,
        checked_debug_names_table_size(
            header.foreign_type_unit_count(),
            std::mem::size_of::<u64>(),
        )?,
        checked_debug_names_table_size(header.bucket_count(), std::mem::size_of::<u32>())?,
        if header.bucket_count() == 0 {
            0
        } else {
            checked_debug_names_table_size(header.name_count(), std::mem::size_of::<u32>())?
        },
        checked_debug_names_table_size(header.name_count(), word_size)?,
        checked_debug_names_table_size(header.name_count(), word_size)?,
    ] {
        start = start
            .checked_add(size)
            .ok_or_else(|| anyhow::anyhow!(".debug_names table offset overflow"))?;
    }
    let end = start
        .checked_add(usize::try_from(header.abbrev_table_size())?)
        .ok_or_else(|| anyhow::anyhow!(".debug_names abbreviation size overflow"))?;
    Ok(start..end)
}

fn read_debug_names_uleb128(bytes: &[u8], offset: &mut usize, end: usize) -> Result<u64> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    loop {
        if *offset >= end {
            anyhow::bail!("truncated .debug_names abbreviation table");
        }
        let byte = bytes[*offset];
        *offset += 1;
        let low_bits = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && low_bits > 1) {
            anyhow::bail!("overflowing ULEB128 in .debug_names abbreviation table");
        }
        value |= low_bits << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
    }
}

fn patch_gdb2_abbreviations(
    bytes: &mut [u8],
    range: std::ops::Range<usize>,
    format: gimli::Format,
) -> Result<()> {
    if range.end > bytes.len() {
        anyhow::bail!(".debug_names abbreviation table is out of bounds");
    }
    let replacement = match format {
        gimli::Format::Dwarf32 => gimli::constants::DW_FORM_ref4.0,
        gimli::Format::Dwarf64 => gimli::constants::DW_FORM_ref8.0,
    };
    let mut offset = range.start;
    while offset < range.end {
        let code = read_debug_names_uleb128(bytes, &mut offset, range.end)?;
        if code == 0 {
            break;
        }
        read_debug_names_uleb128(bytes, &mut offset, range.end)?;

        loop {
            let name = read_debug_names_uleb128(bytes, &mut offset, range.end)?;
            let form_offset = offset;
            let form = read_debug_names_uleb128(bytes, &mut offset, range.end)?;
            if name == 0 && form == 0 {
                break;
            }
            if name == 0 || form == 0 {
                anyhow::bail!("invalid .debug_names abbreviation attribute");
            }
            if name == u64::from(gimli::constants::DW_IDX_die_offset.0)
                && form == u64::from(gimli::constants::DW_FORM_ref_addr.0)
            {
                if offset != form_offset + 1 {
                    anyhow::bail!("unsupported GDB2 DW_FORM_ref_addr encoding");
                }
                bytes[form_offset] = u8::try_from(replacement)?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Default)]
struct FunctionMetadata {
    name: Option<Arc<str>>,
    has_inline_attribute: bool,
    is_linkage_name: bool,
    is_external: Option<bool>,
}

#[derive(Clone)]
struct FunctionEntrySeed {
    die_offset: gimli::UnitOffset,
    tag: gimli::DwTag,
    unit_offset: gimli::DebugInfoOffset,
    flags: crate::core::IndexFlags,
    language: Option<gimli::DwLang>,
    representative_addr: Option<u64>,
    entry_pc: Option<u64>,
    function_kind: FunctionDieKind,
}

#[derive(Clone, Default)]
struct RawDieAttrs {
    name: Option<Arc<str>>,
    linkage_name: Option<Arc<str>>,
    has_inline_attribute: bool,
    is_external: Option<bool>,
    is_declaration: Option<bool>,
    low_pc: Option<u64>,
    high_pc: Option<u64>,
    high_pc_offset: Option<u64>,
    ranges_attr: Option<gimli::AttributeValue<DwarfReader>>,
    entry_pc: Option<u64>,
    location_attr: Option<gimli::AttributeValue<DwarfReader>>,
    has_main_subprogram: bool,
    abstract_origin: Option<DieRef>,
    specification: Option<DieRef>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum DieRef {
    Unit(gimli::UnitOffset),
    DebugInfo(gimli::DebugInfoOffset),
}

struct ResolvedRawDieAttrs {
    unit: Option<gimli::Unit<DwarfReader>>,
    offset: gimli::UnitOffset,
    absolute_offset: gimli::DebugInfoOffset,
    attrs: RawDieAttrs,
}

/// Compilation unit information with associated directories and files.
#[derive(Debug, Clone)]
pub(crate) struct CompilationUnit {
    /// Base directory for this compilation unit.
    pub base_directory: String,
    /// All include directories for this compilation unit.
    pub include_directories: Vec<String>,
    /// Files within this compilation unit.
    pub files: Vec<SourceFile>,
}

/// Source file information extracted from DWARF debug info.
#[derive(Debug, Clone)]
pub(crate) struct SourceFile {
    /// Directory path (resolved from include_directories).
    pub directory_path: String,
    /// Just the filename (basename).
    pub filename: String,
    /// Full resolved path.
    pub full_path: String,
}

type InfoShard = LightweightIndexShard;

// Shard for line info per CU
#[derive(Default)]
struct LineShard {
    line_entries: Vec<crate::core::LineEntry>,
    compilation_units: HashMap<String, CompilationUnit>,
    source_unit_offsets: Vec<(String, gimli::DebugInfoOffset)>,
    file_indices: Vec<(String, LightweightFileIndex)>,
    files_count: usize,
}

/// Complete result of DWARF parsing
pub(crate) struct DwarfParseResult {
    pub lightweight_index: LightweightIndex,
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
    pub line_source_unit_offsets: HashMap<String, Vec<gimli::DebugInfoOffset>>,
    pub stats: DwarfParseStats,
}

/// Result of line information parsing (for parallel processing)
pub(crate) struct LineParseResult {
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
    pub source_unit_offsets: HashMap<String, Vec<gimli::DebugInfoOffset>>,
    pub line_entries_count: usize,
    pub files_count: usize,
}

/// Result of debug information parsing (for parallel processing)
pub(crate) struct DebugParseResult {
    pub lightweight_index: LightweightIndex,
    pub functions_count: usize,
    pub variables_count: usize,
}

/// Parsing statistics for logging and debugging
#[derive(Debug, Clone)]
pub(crate) struct DwarfParseStats {
    pub total_functions: usize,
    pub total_variables: usize,
    pub total_line_entries: usize,
    pub total_files: usize,
}

/// Unified DWARF parser - parses everything in optimized single pass
pub(crate) struct DwarfParser<'a> {
    dwarf: &'a gimli::Dwarf<DwarfReader>,
}

/// Internal builder for accumulating parse results
impl<'a> DwarfParser<'a> {
    fn process_unit_shard(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        unit_offset: gimli::DebugInfoOffset,
        cu_language: Option<gimli::DwLang>,
    ) -> Result<InfoShard> {
        let mut shard = InfoShard::default();
        let mut entries = unit.entries_raw(None)?;
        let mut metadata_cache: HashMap<gimli::DebugInfoOffset, FunctionMetadata> = HashMap::new();
        let mut tag_stack: Vec<gimli::DwTag> = Vec::new();
        while !entries.is_empty() {
            let d: usize = entries.next_depth() as usize;
            let entry_offset = entries.next_offset();
            while tag_stack.len() > d {
                tag_stack.pop();
            }
            let Some(abbrev) = entries.read_abbreviation()? else {
                continue;
            };
            let tag = abbrev.tag();
            let needs_full_entry = matches!(
                tag,
                gimli::constants::DW_TAG_subprogram
                    | gimli::constants::DW_TAG_inlined_subroutine
                    | gimli::constants::DW_TAG_variable
                    | gimli::constants::DW_TAG_structure_type
                    | gimli::constants::DW_TAG_class_type
                    | gimli::constants::DW_TAG_union_type
                    | gimli::constants::DW_TAG_enumeration_type
                    | gimli::constants::DW_TAG_typedef
            );

            if !needs_full_entry {
                // Most DIEs are not indexable. Skip their attributes without materializing
                // a full DebuggingInformationEntry so template-heavy CUs stay cheaper.
                entries.skip_attributes(abbrev.attributes())?;
                tag_stack.push(tag);
                continue;
            }

            let raw_attrs = self.read_selected_raw_attrs(unit, &mut entries, abbrev)?;

            match tag {
                gimli::constants::DW_TAG_subprogram => {
                    let mut visited = HashSet::new();
                    let metadata = self.resolve_function_metadata_from_raw(
                        unit,
                        entry_offset,
                        &raw_attrs,
                        &mut metadata_cache,
                        &mut visited,
                    )?;
                    if let Some(name) = metadata.name.as_ref() {
                        let representative_addr =
                            self.extract_representative_address_from_raw(unit, &raw_attrs)?;
                        let entry_pc_cached = raw_attrs.entry_pc;
                        let function_kind =
                            Self::classify_function_kind(tag, representative_addr, entry_pc_cached);
                        let is_main = Self::is_main_function_from_raw(&raw_attrs, name.as_ref());
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or_else(|| Self::is_static_symbol_from_raw(&raw_attrs));
                        let flags = crate::core::IndexFlags {
                            is_static,
                            is_main,
                            has_inline_attribute: metadata.has_inline_attribute,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let linkage_name = raw_attrs.linkage_name.as_ref().map(Arc::clone);
                        let seed = FunctionEntrySeed {
                            die_offset: entry_offset,
                            tag,
                            unit_offset,
                            flags,
                            language: cu_language,
                            representative_addr,
                            entry_pc: entry_pc_cached,
                            function_kind,
                        };
                        Self::push_function_entries(
                            &mut shard,
                            Arc::clone(name),
                            linkage_name,
                            &seed,
                        );
                    }
                }
                gimli::constants::DW_TAG_inlined_subroutine => {
                    let mut visited = HashSet::new();
                    let metadata = self.resolve_function_metadata_from_raw(
                        unit,
                        entry_offset,
                        &raw_attrs,
                        &mut metadata_cache,
                        &mut visited,
                    )?;
                    if let Some(name) = metadata.name.as_ref() {
                        let representative_addr =
                            self.extract_representative_address_from_raw(unit, &raw_attrs)?;
                        let entry_pc_cached = raw_attrs.entry_pc;
                        let function_kind =
                            Self::classify_function_kind(tag, representative_addr, entry_pc_cached);
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or(false);
                        let flags = crate::core::IndexFlags {
                            is_static,
                            has_inline_attribute: metadata.has_inline_attribute,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let linkage_name = raw_attrs.linkage_name.as_ref().map(Arc::clone);
                        let seed = FunctionEntrySeed {
                            die_offset: entry_offset,
                            tag,
                            unit_offset,
                            flags,
                            language: cu_language,
                            representative_addr,
                            entry_pc: entry_pc_cached,
                            function_kind,
                        };
                        Self::push_function_entries(
                            &mut shard,
                            Arc::clone(name),
                            linkage_name,
                            &seed,
                        );
                    }
                }
                gimli::constants::DW_TAG_variable => {
                    tracing::trace!(
                        "Evaluating global variable DIE {:?} in CU {:?}",
                        entry_offset,
                        unit_offset
                    );
                    let var_addr = self.extract_variable_address_from_raw(unit, &raw_attrs)?;
                    let is_static_symbol =
                        Self::is_static_variable_symbol_from_raw(&raw_attrs, var_addr);
                    let in_function_scope = tag_stack.iter().any(|t| {
                        *t == gimli::constants::DW_TAG_subprogram
                            || *t == gimli::constants::DW_TAG_inlined_subroutine
                    });
                    if in_function_scope && !is_static_symbol {
                        tracing::trace!(
                            "Skipping variable at {:?} (in function scope, stack={:?})",
                            entry_offset,
                            tag_stack
                        );
                        // Skip local variables
                        tag_stack.push(tag);
                        continue;
                    } else if in_function_scope {
                        // Rust (and some C compilers) sometimes nest file-scoped statics under the
                        // function that first references them, even though DW_AT_location uses
                        // DW_OP_addr. Treat only absolute-address-backed statics as true globals;
                        // stack/register locals must stay out of the global index.
                        tracing::trace!(
                            "Treating static variable at {:?} as global despite function scope (stack={:?})",
                            entry_offset,
                            tag_stack
                        );
                    }
                    if Self::is_declaration_from_raw(&raw_attrs) {
                        tracing::trace!(
                            "Skipping variable at {:?} (declaration-only DIE)",
                            entry_offset
                        );
                        tag_stack.push(tag);
                        continue;
                    }
                    let mut collected_names: Vec<(Arc<str>, bool)> = Vec::new();
                    let mut push_unique_name = |candidate: Arc<str>, is_linkage_alias: bool| {
                        if candidate.is_empty() {
                            return;
                        }
                        if collected_names
                            .iter()
                            .any(|(existing, _)| existing.as_ref() == candidate.as_ref())
                        {
                            return;
                        }
                        collected_names.push((candidate, is_linkage_alias));
                    };

                    let mut visited = HashSet::with_capacity(4);
                    if let Some(name) =
                        self.resolve_name_from_raw(unit, entry_offset, &raw_attrs, &mut visited)?
                    {
                        push_unique_name(name, false);
                    }

                    if let Some(linkage_name) = raw_attrs.linkage_name.as_ref() {
                        push_unique_name(Arc::clone(linkage_name), true);
                    }

                    if collected_names.is_empty() {
                        tracing::trace!(
                            "DWARF variable at {:?} missing usable name (CU lang={:?}); skipping alias registration",
                            entry_offset,
                            cu_language
                        );
                        tag_stack.push(tag);
                        continue;
                    }

                    let flags = crate::core::IndexFlags {
                        is_static: is_static_symbol,
                        ..Default::default()
                    };

                    for (name, is_linkage_alias) in collected_names {
                        let mut entry_flags = flags;
                        entry_flags.is_linkage = is_linkage_alias;
                        let index_entry = IndexEntry {
                            name: Arc::clone(&name),
                            die_offset: entry_offset,
                            unit_offset,
                            tag,
                            flags: entry_flags,
                            language: cu_language,
                            representative_addr: var_addr,
                            entry_pc: None,
                            function_kind: FunctionDieKind::NotFunction,
                        };
                        tracing::trace!(
                            "Registering variable alias '{}' (linkage={}, lang={:?}, die={:?})",
                            name,
                            entry_flags.is_linkage,
                            cu_language,
                            entry_offset
                        );
                        shard.push_variable_entry(name.to_string(), index_entry);
                    }
                }
                gimli::constants::DW_TAG_structure_type
                | gimli::constants::DW_TAG_class_type
                | gimli::constants::DW_TAG_union_type
                | gimli::constants::DW_TAG_enumeration_type
                | gimli::constants::DW_TAG_typedef => {
                    let mut visited = HashSet::with_capacity(4);
                    if let Some(name) =
                        self.resolve_name_from_raw(unit, entry_offset, &raw_attrs, &mut visited)?
                    {
                        let is_decl = Self::is_declaration_from_raw(&raw_attrs);
                        let flags = crate::core::IndexFlags {
                            is_type_declaration: is_decl,
                            ..Default::default()
                        };
                        let index_entry = IndexEntry {
                            name: Arc::clone(&name),
                            die_offset: entry_offset,
                            unit_offset,
                            tag,
                            flags,
                            language: cu_language,
                            representative_addr: None,
                            entry_pc: None,
                            function_kind: FunctionDieKind::NotFunction,
                        };
                        shard.push_type_entry(name.to_string(), index_entry);
                    }
                }
                _ => {}
            }
            tag_stack.push(tag);
        }
        Ok(shard)
    }
    pub fn new(dwarf: &'a gimli::Dwarf<DwarfReader>) -> Self {
        Self { dwarf }
    }

    fn classify_function_kind(
        tag: gimli::DwTag,
        representative_addr: Option<u64>,
        entry_pc: Option<u64>,
    ) -> FunctionDieKind {
        match tag {
            gimli::constants::DW_TAG_inlined_subroutine => FunctionDieKind::InlineInstance,
            gimli::constants::DW_TAG_subprogram => {
                if representative_addr.is_some() || entry_pc.is_some() {
                    FunctionDieKind::ConcreteSubprogram
                } else {
                    FunctionDieKind::AbstractSubprogram
                }
            }
            _ => FunctionDieKind::NotFunction,
        }
    }

    fn build_function_index_entry(name: Arc<str>, seed: &FunctionEntrySeed) -> IndexEntry {
        IndexEntry {
            name,
            die_offset: seed.die_offset,
            unit_offset: seed.unit_offset,
            tag: seed.tag,
            flags: seed.flags,
            language: seed.language,
            representative_addr: seed.representative_addr,
            entry_pc: seed.entry_pc,
            function_kind: seed.function_kind,
        }
    }

    fn push_function_entries(
        shard: &mut InfoShard,
        name: Arc<str>,
        linkage_name: Option<Arc<str>>,
        seed: &FunctionEntrySeed,
    ) {
        shard.push_function_entry(
            name.to_string(),
            Self::build_function_index_entry(Arc::clone(&name), seed),
        );

        if let Some(linkage_name) =
            linkage_name.filter(|linkage_name| linkage_name.as_ref() != name.as_ref())
        {
            let mut alias_seed = seed.clone();
            let mut alias_flags = alias_seed.flags;
            alias_flags.is_linkage = true;
            alias_seed.flags = alias_flags;
            shard.push_function_entry(
                linkage_name.to_string(),
                Self::build_function_index_entry(linkage_name, &alias_seed),
            );
        }
    }

    fn extract_attr_string(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        attr_value: gimli::AttributeValue<DwarfReader>,
    ) -> Result<Option<Arc<str>>> {
        if let Ok(string) = dwarf.attr_string(unit, attr_value) {
            if let Ok(s_str) = string.to_string_lossy() {
                return Ok(Some(Arc::<str>::from(s_str.into_owned())));
            }
        }
        Ok(None)
    }

    /// Process single compilation unit - decoupled debug_line and debug_info processing
    // Helper methods (extracted from unified_builder.rs)
    fn die_ref(
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
    ) -> Option<DieRef> {
        match value {
            gimli::AttributeValue::UnitRef(offset) => Some(DieRef::Unit(offset)),
            gimli::AttributeValue::DebugInfoRef(offset) => {
                if let Some(unit_offset) = offset.to_unit_offset(&unit.header) {
                    Some(DieRef::Unit(unit_offset))
                } else {
                    Some(DieRef::DebugInfo(offset))
                }
            }
            _ => None,
        }
    }

    fn should_read_raw_attr(attr: gimli::DwAt) -> bool {
        matches!(
            attr,
            gimli::constants::DW_AT_name
                | gimli::constants::DW_AT_linkage_name
                | gimli::constants::DW_AT_MIPS_linkage_name
                | gimli::constants::DW_AT_inline
                | gimli::constants::DW_AT_external
                | gimli::constants::DW_AT_declaration
                | gimli::constants::DW_AT_low_pc
                | gimli::constants::DW_AT_high_pc
                | gimli::constants::DW_AT_ranges
                | gimli::constants::DW_AT_entry_pc
                | gimli::constants::DW_AT_location
                | gimli::constants::DW_AT_main_subprogram
                | gimli::constants::DW_AT_abstract_origin
                | gimli::constants::DW_AT_specification
        )
    }

    fn read_selected_raw_attrs(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entries: &mut gimli::EntriesRaw<'_, DwarfReader>,
        abbrev: &gimli::Abbreviation,
    ) -> Result<RawDieAttrs> {
        let mut attrs = RawDieAttrs::default();
        for spec in abbrev.attributes() {
            if !Self::should_read_raw_attr(spec.name()) {
                entries.skip_attributes(std::slice::from_ref(spec))?;
                continue;
            }

            let attr = entries.read_attribute(*spec)?;
            let value = attr.value();
            match attr.name() {
                gimli::constants::DW_AT_name => {
                    attrs.name = Self::extract_attr_string(self.dwarf, unit, value)?;
                }
                gimli::constants::DW_AT_linkage_name
                | gimli::constants::DW_AT_MIPS_linkage_name => {
                    if attrs.linkage_name.is_none() {
                        attrs.linkage_name = Self::extract_attr_string(self.dwarf, unit, value)?;
                    }
                }
                gimli::constants::DW_AT_inline => {
                    if let gimli::AttributeValue::Inline(inline_attr) = value {
                        attrs.has_inline_attribute = inline_attr == gimli::DW_INL_inlined
                            || inline_attr == gimli::DW_INL_declared_inlined;
                    }
                }
                gimli::constants::DW_AT_external => {
                    attrs.is_external = Self::flag_attr_value(value);
                }
                gimli::constants::DW_AT_declaration => {
                    attrs.is_declaration = Self::flag_attr_value(value);
                }
                gimli::constants::DW_AT_low_pc => match value {
                    gimli::AttributeValue::Addr(addr) => attrs.low_pc = Some(addr),
                    gimli::AttributeValue::DebugAddrIndex(index) => {
                        attrs.low_pc = self.dwarf.address(unit, index).ok();
                    }
                    _ => {}
                },
                gimli::constants::DW_AT_high_pc => match value {
                    gimli::AttributeValue::Addr(addr) => attrs.high_pc = Some(addr),
                    _ => attrs.high_pc_offset = Self::high_pc_offset_value(value),
                },
                gimli::constants::DW_AT_ranges => {
                    attrs.ranges_attr = Some(value);
                }
                gimli::constants::DW_AT_entry_pc => match value {
                    gimli::AttributeValue::Addr(addr) => attrs.entry_pc = Some(addr),
                    gimli::AttributeValue::DebugAddrIndex(index) => {
                        attrs.entry_pc = self.dwarf.address(unit, index).ok();
                    }
                    _ => {}
                },
                gimli::constants::DW_AT_location => {
                    attrs.location_attr = Some(value);
                }
                gimli::constants::DW_AT_main_subprogram => {
                    attrs.has_main_subprogram = true;
                }
                gimli::constants::DW_AT_abstract_origin => {
                    attrs.abstract_origin = Self::die_ref(unit, value);
                }
                gimli::constants::DW_AT_specification => {
                    attrs.specification = Self::die_ref(unit, value);
                }
                _ => {}
            }
        }
        Ok(attrs)
    }

    fn read_attrs_for_die_ref(
        &self,
        current_unit: &gimli::Unit<DwarfReader>,
        reference: DieRef,
    ) -> Result<Option<ResolvedRawDieAttrs>> {
        match reference {
            DieRef::Unit(unit_offset) => {
                let Some(debug_info_offset) =
                    unit_offset.to_debug_info_offset(&current_unit.header)
                else {
                    return Ok(None);
                };
                let attrs = self.read_selected_raw_attrs_at(current_unit, unit_offset)?;
                Ok(Some(ResolvedRawDieAttrs {
                    unit: None,
                    offset: unit_offset,
                    absolute_offset: debug_info_offset,
                    attrs,
                }))
            }
            DieRef::DebugInfo(debug_info_offset) => {
                if let Some(unit_offset) = debug_info_offset.to_unit_offset(&current_unit.header) {
                    let attrs = self.read_selected_raw_attrs_at(current_unit, unit_offset)?;
                    return Ok(Some(ResolvedRawDieAttrs {
                        unit: None,
                        offset: unit_offset,
                        absolute_offset: debug_info_offset,
                        attrs,
                    }));
                }

                let mut units = self.dwarf.units();
                while let Some(header) = units.next()? {
                    if let Some(unit_offset) = debug_info_offset.to_unit_offset(&header) {
                        let unit = self.dwarf.unit(header)?;
                        let attrs = self.read_selected_raw_attrs_at(&unit, unit_offset)?;
                        return Ok(Some(ResolvedRawDieAttrs {
                            unit: Some(unit),
                            offset: unit_offset,
                            absolute_offset: debug_info_offset,
                            attrs,
                        }));
                    }
                }
                Ok(None)
            }
        }
    }

    fn read_selected_raw_attrs_at(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        offset: gimli::UnitOffset,
    ) -> Result<RawDieAttrs> {
        let mut entries = unit.entries_raw(Some(offset))?;
        let Some(abbrev) = entries.read_abbreviation()? else {
            return Ok(RawDieAttrs::default());
        };
        self.read_selected_raw_attrs(unit, &mut entries, abbrev)
    }

    fn resolve_name_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entry_offset: gimli::UnitOffset,
        attrs: &RawDieAttrs,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<Option<Arc<str>>> {
        if let Some(name) = attrs.name.as_ref() {
            return Ok(Some(Arc::clone(name)));
        }

        let Some(entry_abs) = entry_offset.to_debug_info_offset(&unit.header) else {
            return Ok(None);
        };
        if !visited.insert(entry_abs) {
            return Ok(None);
        }

        let mut resolved = None;
        for origin_ref in [attrs.specification, attrs.abstract_origin]
            .into_iter()
            .flatten()
        {
            let Some(origin) = self.read_attrs_for_die_ref(unit, origin_ref)? else {
                continue;
            };
            if visited.contains(&origin.absolute_offset) {
                continue;
            }

            let origin_unit = origin.unit.as_ref().unwrap_or(unit);
            if let Some(name) =
                self.resolve_name_from_raw(origin_unit, origin.offset, &origin.attrs, visited)?
            {
                resolved = Some(name);
                break;
            }
        }

        visited.remove(&entry_abs);
        Ok(resolved)
    }

    fn resolve_function_metadata_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entry_offset: gimli::UnitOffset,
        attrs: &RawDieAttrs,
        cache: &mut HashMap<gimli::DebugInfoOffset, FunctionMetadata>,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<FunctionMetadata> {
        let Some(entry_abs) = entry_offset.to_debug_info_offset(&unit.header) else {
            return Ok(FunctionMetadata::default());
        };
        if let Some(cached) = cache.get(&entry_abs) {
            return Ok(cached.clone());
        }

        if !visited.insert(entry_abs) {
            return Ok(FunctionMetadata::default());
        }

        let mut metadata = FunctionMetadata::default();
        let mut name_visited = HashSet::with_capacity(4);
        if let Some(name) =
            self.resolve_name_from_raw(unit, entry_offset, attrs, &mut name_visited)?
        {
            metadata.name = Some(name);
        } else if let Some(name) = attrs.linkage_name.as_ref() {
            metadata.name = Some(Arc::clone(name));
            metadata.is_linkage_name = true;
        }

        metadata.has_inline_attribute = attrs.has_inline_attribute;
        metadata.is_external = attrs.is_external;

        let mut merge_from_origin = |origin_ref: DieRef| -> Result<()> {
            let Some(origin) = self.read_attrs_for_die_ref(unit, origin_ref)? else {
                return Ok(());
            };
            if visited.contains(&origin.absolute_offset) {
                return Ok(());
            }

            let origin_metadata = if let Some(cached) = cache.get(&origin.absolute_offset) {
                cached.clone()
            } else {
                let origin_unit = origin.unit.as_ref().unwrap_or(unit);
                self.resolve_function_metadata_from_raw(
                    origin_unit,
                    origin.offset,
                    &origin.attrs,
                    cache,
                    visited,
                )?
            };

            if metadata.name.is_none() {
                metadata.name = origin_metadata.name.as_ref().map(Arc::clone);
            }
            if metadata.is_external.is_none() {
                metadata.is_external = origin_metadata.is_external;
            }
            metadata.is_linkage_name |= origin_metadata.is_linkage_name;
            Ok(())
        };

        if let Some(origin_offset) = attrs.abstract_origin {
            merge_from_origin(origin_offset)?;
        }

        if let Some(origin_offset) = attrs.specification {
            merge_from_origin(origin_offset)?;
        }

        visited.remove(&entry_abs);
        cache.insert(entry_abs, metadata.clone());
        Ok(metadata)
    }

    fn flag_attr_value(value: gimli::AttributeValue<DwarfReader>) -> Option<bool> {
        match value {
            gimli::AttributeValue::Flag(v) => Some(v),
            _ => None,
        }
    }

    fn flush_pending_line_entries(
        out: &mut Vec<LineEntry>,
        pending: &mut Vec<LineEntry>,
        end_address: Option<u64>,
    ) {
        for mut entry in std::mem::take(pending) {
            // Equal endpoints are zero-length rows, not unknown-length rows.
            entry.end_address = end_address;
            out.push(entry);
        }
    }

    fn high_pc_offset_value(value: gimli::AttributeValue<DwarfReader>) -> Option<u64> {
        match value {
            gimli::AttributeValue::Udata(offset) => Some(offset),
            gimli::AttributeValue::Data1(offset) => Some(offset as u64),
            gimli::AttributeValue::Data2(offset) => Some(offset as u64),
            gimli::AttributeValue::Data4(offset) => Some(offset as u64),
            gimli::AttributeValue::Data8(offset) => Some(offset),
            _ => None,
        }
    }

    fn is_static_symbol_from_raw(attrs: &RawDieAttrs) -> bool {
        attrs
            .is_external
            .map(|is_external| !is_external)
            .unwrap_or(true)
    }

    // DW_AT_external only answers "is this visible outside the CU?".
    // That is enough to identify extern globals, but not enough to separate
    // file-scope statics from function locals: both are commonly non-external.
    //
    // For variables nested under a function, only keep them in the global index
    // when DWARF gives us a true absolute storage location. This distinction is
    // important for optimized locals:
    //
    //   DW_OP_addr <foo>; DW_OP_stack_value
    //
    // means "the variable's value is the address <foo>", not "the variable is
    // stored at <foo>". GCC emits that form for locals such as:
    //
    //   const char *p = "hi";
    //
    // so we must not treat every address-valued expression as proof of static
    // storage. Only pure address location expressions should survive this gate.
    fn is_static_variable_symbol_from_raw(
        attrs: &RawDieAttrs,
        absolute_address: Option<u64>,
    ) -> bool {
        if let Some(is_external) = attrs.is_external {
            return !is_external;
        }

        // DW_AT_external is often omitted on local stack/register variables. Only keep
        // function-scoped variables in the global index when DWARF gives them a true
        // absolute storage address.
        absolute_address.is_some()
    }

    fn is_declaration_from_raw(attrs: &RawDieAttrs) -> bool {
        attrs.is_declaration.unwrap_or(false)
    }

    fn extract_representative_address_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        attrs: &RawDieAttrs,
    ) -> Result<Option<u64>> {
        if let Some(low_pc) = attrs.low_pc {
            return Ok(Some(low_pc));
        }

        if let Some(entry_pc) = attrs.entry_pc {
            return Ok(Some(entry_pc));
        }

        self.peek_first_range_start_from_raw(unit, attrs)
    }

    fn peek_first_range_start_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        attrs: &RawDieAttrs,
    ) -> Result<Option<u64>> {
        let Some(ranges_attr) = attrs.ranges_attr.clone() else {
            return Ok(None);
        };

        let ranges_offset = match ranges_attr {
            gimli::AttributeValue::RangeListsRef(offset) => {
                self.dwarf.ranges_offset_from_raw(unit, offset)
            }
            gimli::AttributeValue::DebugRngListsIndex(index) => {
                self.dwarf.ranges_offset(unit, index)?
            }
            gimli::AttributeValue::SecOffset(offset) => gimli::RangeListsOffset(offset),
            _ => return Ok(None),
        };

        let mut ranges_iter = self.dwarf.ranges(unit, ranges_offset)?;
        while let Some(range) = ranges_iter.next()? {
            let begin = range.begin;
            let end = range.end;
            if begin > end {
                continue;
            }

            return Ok(Some(begin));
        }

        Ok(None)
    }

    /// Extract a variable's absolute storage address from DW_AT_location.
    ///
    /// This is intentionally narrower than "any expression that mentions an address".
    /// For indexing globals/statics we only care about expressions that describe a
    /// storage location, such as:
    ///
    ///   - DW_AT_location = Addr(...)
    ///   - Exprloc([DW_OP_addr ...])
    ///   - Exprloc([DW_OP_addrx ...]) resolved through `.debug_addr`
    ///   - Exprloc([DW_OP_constu ...]) in the legacy constant-as-address form
    ///
    /// We must reject value expressions like:
    ///
    ///   - DW_OP_addr ...; DW_OP_stack_value
    ///   - DW_OP_addrx ...; DW_OP_stack_value
    ///
    /// because those describe the variable's value, not a place where the
    /// variable itself lives. Optimized locals that hold constant addresses are
    /// commonly encoded this way.
    fn extract_variable_address_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        attrs: &RawDieAttrs,
    ) -> Result<Option<u64>> {
        let Some(location_attr) = attrs.location_attr.clone() else {
            return Ok(None);
        };

        match location_attr {
            gimli::AttributeValue::Addr(a) => Ok(Some(a)),
            gimli::AttributeValue::Exprloc(expr) => Ok(
                self.extract_absolute_storage_address_from_expr(unit, gimli::Expression(expr.0))
            ),
            gimli::AttributeValue::LocationListsRef(offs) => {
                if let Ok(mut locations) = self
                    .dwarf
                    .locations(unit, gimli::LocationListsOffset(offs.0))
                {
                    while let Ok(Some(loc)) = locations.next() {
                        if let Some(address) = self.extract_absolute_storage_address_from_expr(
                            unit,
                            gimli::Expression(loc.data.0),
                        ) {
                            return Ok(Some(address));
                        }
                    }
                }
                Ok(None)
            }
            gimli::AttributeValue::DebugLocListsIndex(index) => {
                if let Ok(offset) = self.dwarf.locations_offset(unit, index) {
                    if let Ok(mut locations) = self.dwarf.locations(unit, offset) {
                        while let Ok(Some(loc)) = locations.next() {
                            if let Some(address) = self.extract_absolute_storage_address_from_expr(
                                unit,
                                gimli::Expression(loc.data.0),
                            ) {
                                return Ok(Some(address));
                            }
                        }
                    }
                }
                Ok(None)
            }
            gimli::AttributeValue::SecOffset(off) => {
                if let Ok(mut locations) =
                    self.dwarf.locations(unit, gimli::LocationListsOffset(off))
                {
                    while let Ok(Some(loc)) = locations.next() {
                        if let Some(address) = self.extract_absolute_storage_address_from_expr(
                            unit,
                            gimli::Expression(loc.data.0),
                        ) {
                            return Ok(Some(address));
                        }
                    }
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn extract_absolute_storage_address_from_expr(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        expr: gimli::Expression<DwarfReader>,
    ) -> Option<u64> {
        crate::dwarf_expr::storage::absolute_address(self.dwarf, unit, expr)
    }

    // Additional helper methods for GDB-style cooked index

    fn is_main_function_from_raw(attrs: &RawDieAttrs, name: &str) -> bool {
        attrs.has_main_subprogram || name == "main" || name == "_main"
    }

    fn extract_language(
        &self,
        _dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
    ) -> Option<gimli::DwLang> {
        // Try to get language from compilation unit
        let mut entries = unit.entries();
        if let Ok(Some(cu_entry)) = entries.next_dfs() {
            if cu_entry.tag() == gimli::constants::DW_TAG_compile_unit {
                if let Some(lang_attr) = cu_entry.attr(gimli::constants::DW_AT_language) {
                    if let gimli::AttributeValue::Language(lang) = lang_attr.value() {
                        return Some(lang);
                    }
                }
            }
        }
        None
    }

    /// Parse debug_line sections (for parallel processing)
    #[cfg(test)]
    pub fn parse_line_info(&self, module_path: &str) -> Result<LineParseResult> {
        self.parse_line_info_units(module_path, None, true)
    }

    pub(crate) fn parse_line_headers(&self, module_path: &str) -> Result<LineParseResult> {
        self.parse_line_info_units(module_path, None, false)
    }

    pub(crate) fn parse_line_info_cus(
        &self,
        module_path: &str,
        unit_offsets: &[gimli::DebugInfoOffset],
    ) -> Result<LineParseResult> {
        self.parse_line_info_units(module_path, Some(unit_offsets), true)
    }

    fn parse_line_info_units(
        &self,
        module_path: &str,
        unit_offsets: Option<&[gimli::DebugInfoOffset]>,
        include_rows: bool,
    ) -> Result<LineParseResult> {
        debug!("Starting debug_line-only parsing for: {}", module_path);

        // Collect CU headers once
        let mut headers: Vec<gimli::UnitHeader<DwarfReader>> =
            if let Some(unit_offsets) = unit_offsets {
                unit_offsets
                    .iter()
                    .map(|unit_offset| self.dwarf.unit_header(*unit_offset).map_err(Into::into))
                    .collect::<Result<_>>()?
            } else {
                let mut headers = Vec::new();
                let mut units = self.dwarf.units();
                while let Some(header) = units.next()? {
                    headers.push(header);
                }
                headers
            };

        // Sort headers by size (descending) for better load balance under work-stealing
        headers.sort_by_key(|h| std::cmp::Reverse(h.length_including_self() as u64));

        // Parallel process each CU into shards
        let shard_results: Vec<Result<LineShard>> = headers
            .into_par_iter()
            .map(|unit_header| -> Result<LineShard> {
                let mut shard = LineShard::default();
                let version = unit_header.version();
                let unit = self.dwarf.unit(unit_header)?;
                if let Some(ref line_program) = unit.line_program {
                    // CU name and comp_dir
                    let cu_name = Self::extract_cu_name_from_dwarf(self.dwarf, &unit)
                        .unwrap_or_else(|| "unknown".to_string());
                    let comp_dir = Self::extract_comp_dir_from_dwarf(self.dwarf, &unit);

                    // Build file index for this CU
                    let mut file_index = LightweightFileIndex::new(comp_dir, version);
                    let header = line_program.header();
                    for dir_entry in header.include_directories() {
                        if let Ok(dir_path) = self.dwarf.attr_string(&unit, dir_entry.clone()) {
                            if let Ok(s_str) = dir_path.to_string_lossy() {
                                file_index.add_directory(s_str.into_owned());
                            }
                        }
                    }
                    for (file_idx, file_entry) in header.file_names().iter().enumerate() {
                        let file_index_value = if header.version() >= 5 {
                            file_idx as u64
                        } else {
                            (file_idx + 1) as u64
                        };
                        if let Ok(filename) = self.dwarf.attr_string(&unit, file_entry.path_name())
                        {
                            let dir_index = file_entry.directory_index();
                            if let Ok(s_str) = filename.to_string_lossy() {
                                file_index.add_file_entry(
                                    file_index_value,
                                    dir_index,
                                    s_str.into_owned(),
                                );
                            }
                        }
                    }

                    // Build rich compilation unit metadata
                    let compilation_unit = Self::extract_file_info_from_line_program_static(
                        self.dwarf,
                        &unit,
                        line_program,
                    )?;
                    if let Some(unit_offset) = unit.header.debug_info_offset() {
                        for file in &compilation_unit.files {
                            for source_path in [&file.full_path, &file.filename] {
                                if !source_path.is_empty() {
                                    shard
                                        .source_unit_offsets
                                        .push((source_path.clone(), unit_offset));
                                }
                            }
                        }
                    }
                    shard.files_count += compilation_unit.files.len();
                    shard
                        .compilation_units
                        .insert(cu_name.clone(), compilation_unit);
                    shard.file_indices.push((cu_name.clone(), file_index));

                    // Extract line rows for this CU only when a query needs them.
                    if include_rows {
                        let (line_program, sequences) = line_program.clone().sequences()?;
                        for seq in sequences {
                            let mut rows = line_program.resume_from(&seq);
                            let mut pending_entries: Vec<LineEntry> = Vec::new();
                            let mut pending_address: Option<u64> = None;
                            while let Some((_, line_row)) = rows.next_row()? {
                                let row_address = line_row.address();
                                if line_row.end_sequence() {
                                    Self::flush_pending_line_entries(
                                        &mut shard.line_entries,
                                        &mut pending_entries,
                                        Some(row_address),
                                    );
                                    pending_address = None;
                                    continue;
                                }

                                if let Some(address) = pending_address {
                                    if row_address > address {
                                        Self::flush_pending_line_entries(
                                            &mut shard.line_entries,
                                            &mut pending_entries,
                                            Some(row_address),
                                        );
                                        pending_address = Some(row_address);
                                    } else if row_address < address {
                                        Self::flush_pending_line_entries(
                                            &mut shard.line_entries,
                                            &mut pending_entries,
                                            None,
                                        );
                                        pending_address = Some(row_address);
                                    }
                                } else {
                                    pending_address = Some(row_address);
                                }

                                let column = match line_row.column() {
                                    gimli::ColumnType::LeftEdge => 0,
                                    gimli::ColumnType::Column(x) => x.get(),
                                };
                                pending_entries.push(LineEntry {
                                    address: row_address,
                                    end_address: None,
                                    file_path: String::new(),
                                    file_index: line_row.file_index(),
                                    compilation_unit: std::sync::Arc::from(cu_name.as_str()),
                                    line: line_row.line().map(|l| l.get()).unwrap_or(0),
                                    column,
                                    is_stmt: line_row.is_stmt(),
                                    prologue_end: line_row.prologue_end(),
                                });
                            }
                            Self::flush_pending_line_entries(
                                &mut shard.line_entries,
                                &mut pending_entries,
                                None,
                            );
                        }
                    }
                }
                Ok(shard)
            })
            .collect();

        // Combine shards
        let mut scoped_file_manager = ScopedFileIndexManager::new();
        let mut line_entries = Vec::new();
        let mut compilation_units: HashMap<String, CompilationUnit> = HashMap::new();
        let mut source_unit_offsets: HashMap<String, Vec<gimli::DebugInfoOffset>> = HashMap::new();
        let mut total_files = 0usize;

        for sr in shard_results {
            let shard = sr?;
            total_files += shard.files_count;
            line_entries.extend(shard.line_entries);
            for (cu, cuinfo) in shard.compilation_units {
                compilation_units.insert(cu, cuinfo);
            }
            for (source_path, unit_offset) in shard.source_unit_offsets {
                source_unit_offsets
                    .entry(source_path)
                    .or_default()
                    .push(unit_offset);
            }
            for (cu, fi) in shard.file_indices {
                scoped_file_manager.add_compilation_unit(cu, fi);
            }
        }
        for offsets in source_unit_offsets.values_mut() {
            offsets.sort_unstable_by_key(|offset| offset.0);
            offsets.dedup();
        }

        // Build final line mapping
        let total_line_entries = line_entries.len();
        let line_mapping =
            LineMappingTable::from_entries_with_scoped_manager(line_entries, &scoped_file_manager);

        debug!(
            "Completed debug_line parsing for {}: {} line entries, {} files, {} compilation units",
            module_path,
            total_line_entries,
            total_files,
            compilation_units.len()
        );

        Ok(LineParseResult {
            line_mapping,
            scoped_file_manager,
            compilation_units,
            source_unit_offsets,
            line_entries_count: total_line_entries,
            files_count: total_files,
        })
    }

    fn compatible_debug_names(&self) -> Result<gimli::DebugNames<DwarfReader>> {
        let mut patches = Vec::new();
        let mut headers = self.dwarf.debug_names.headers();
        while let Some(header) = headers.next()? {
            if is_gdb2_name_index(&header)? {
                patches.push((gdb2_abbreviation_range(&header)?, header.format()));
            }
        }
        if patches.is_empty() {
            return Ok(self.dwarf.debug_names.clone());
        }

        let reader = self.dwarf.debug_names.reader();
        let endian = reader.endian();
        let mut bytes = reader.to_slice()?.into_owned();
        for (range, format) in patches {
            patch_gdb2_abbreviations(&mut bytes, range, format)?;
        }
        Ok(gimli::DebugNames::from(dwarf_reader_from_arc_with_endian(
            Arc::from(bytes),
            endian,
        )))
    }

    fn debug_names_die_offset(
        &self,
        unit_offset: gimli::DebugInfoOffset,
        die_offset: gimli::UnitOffset,
        gdb2: bool,
    ) -> Result<gimli::UnitOffset> {
        if !gdb2 {
            return Ok(die_offset);
        }

        let relative = die_offset.0.checked_sub(unit_offset.0).ok_or_else(|| {
            anyhow::anyhow!(
                "GDB2 .debug_names DIE offset 0x{:x} precedes CU 0x{:x}",
                die_offset.0,
                unit_offset.0
            )
        })?;
        let header = self.dwarf.unit_header(unit_offset)?;
        if relative >= header.length_including_self() {
            anyhow::bail!(
                "GDB2 .debug_names DIE offset 0x{:x} is outside CU 0x{:x}",
                die_offset.0,
                unit_offset.0
            );
        }
        Ok(gimli::UnitOffset(relative))
    }

    /// Parse debug_info sections (for parallel processing)
    pub(crate) fn parse_debug_names(&self, module_path: &str) -> Result<Option<DebugParseResult>> {
        debug!("Starting .debug_names parsing for: {}", module_path);
        let debug_names = self.compatible_debug_names()?;
        let mut headers = debug_names.headers();
        let mut shards = Vec::new();
        let mut saw_index = false;

        while let Some(header) = headers.next()? {
            saw_index = true;
            let gdb2 = is_gdb2_name_index(&header)?;
            let names = header.index()?;
            let mut shard = LightweightIndexShard::default();

            for name_index in names.names() {
                let name = names
                    .name_string(name_index, &self.dwarf.debug_str)?
                    .to_string_lossy()?
                    .into_owned();
                let mut entries = names.name_entries(name_index)?;
                while let Some(entry) = entries.next()? {
                    let unit_offset = match entry.type_unit(&names)? {
                        Some(gimli::NameTypeUnit::Local(unit)) => unit,
                        Some(gimli::NameTypeUnit::Foreign(_)) => continue,
                        None => {
                            let Some(cu) = entry
                                .compile_unit(&names)?
                                .or(names.default_compile_unit()?)
                            else {
                                continue;
                            };
                            cu
                        }
                    };
                    let Some(die_offset) = entry.die_offset()? else {
                        continue;
                    };
                    let die_offset = self.debug_names_die_offset(unit_offset, die_offset, gdb2)?;
                    let tag = entry.tag;
                    let function_kind = match tag {
                        gimli::constants::DW_TAG_subprogram => FunctionDieKind::ConcreteSubprogram,
                        gimli::constants::DW_TAG_inlined_subroutine => {
                            FunctionDieKind::InlineInstance
                        }
                        _ => FunctionDieKind::NotFunction,
                    };
                    let index_entry = IndexEntry {
                        name: Arc::from(name.as_str()),
                        die_offset,
                        unit_offset,
                        tag,
                        flags: crate::core::IndexFlags {
                            is_main: name == "main" || name == "_main",
                            ..Default::default()
                        },
                        language: None,
                        representative_addr: None,
                        entry_pc: None,
                        function_kind,
                    };

                    match tag {
                        gimli::constants::DW_TAG_subprogram
                        | gimli::constants::DW_TAG_inlined_subroutine => {
                            shard.push_function_entry(name.clone(), index_entry);
                        }
                        gimli::constants::DW_TAG_variable => {
                            shard.push_variable_entry(name.clone(), index_entry);
                        }
                        gimli::constants::DW_TAG_structure_type
                        | gimli::constants::DW_TAG_class_type
                        | gimli::constants::DW_TAG_union_type
                        | gimli::constants::DW_TAG_enumeration_type
                        | gimli::constants::DW_TAG_typedef => {
                            shard.push_type_entry(name.clone(), index_entry);
                        }
                        _ => {}
                    }
                }
            }
            shards.push(shard);
        }

        if !saw_index {
            return Ok(None);
        }

        let mut lightweight_index = LightweightIndex::from_shards(shards);
        let functions_count = lightweight_index.get_stats().0;
        let variables_count = lightweight_index.get_stats().1;
        let has_aranges = lightweight_index.build_cu_maps_from_aranges(self.dwarf);
        let has_root_ranges = lightweight_index.build_cu_maps_from_roots(self.dwarf);
        let has_cu_ranges = has_aranges || has_root_ranges;
        if !has_cu_ranges && functions_count > 0 {
            anyhow::bail!(
                ".debug_names for {module_path} has functions but no usable address-to-CU ranges",
            );
        }

        debug!(
            "Completed .debug_names parsing for {}: {} functions, {} variables",
            module_path, functions_count, variables_count
        );
        Ok(Some(DebugParseResult {
            lightweight_index,
            functions_count,
            variables_count,
        }))
    }

    pub(crate) fn parse_debug_info_cus(
        &self,
        unit_offsets: &[gimli::DebugInfoOffset],
    ) -> Result<Vec<LightweightIndexShard>> {
        unit_offsets
            .par_iter()
            .map(|unit_offset| {
                let header = self.dwarf.unit_header(*unit_offset)?;
                let unit = self.dwarf.unit(header)?;
                let cu_lang = self.extract_language(self.dwarf, &unit);
                self.process_unit_shard(&unit, *unit_offset, cu_lang)
            })
            .collect()
    }

    pub(crate) fn initialize_lazy_debug_info(&self) -> DebugParseResult {
        let mut lightweight_index = LightweightIndex::new();
        lightweight_index.build_cu_maps_from_aranges(self.dwarf);
        DebugParseResult {
            lightweight_index,
            functions_count: 0,
            variables_count: 0,
        }
    }

    /// Parse debug_info sections (for parallel processing)
    pub fn parse_debug_info(&self, module_path: &str) -> Result<DebugParseResult> {
        debug!("Starting debug_info-only parsing for: {}", module_path);
        // Collect headers once
        let mut headers: Vec<gimli::UnitHeader<DwarfReader>> = Vec::new();
        let mut units = self.dwarf.units();
        while let Some(header) = units.next()? {
            headers.push(header);
        }

        // Always process in parallel at CU granularity, and propagate per-CU errors
        let shard_results: Vec<Result<InfoShard>> = headers
            .into_par_iter()
            .map(|header| -> Result<InfoShard> {
                match header.debug_info_offset() {
                    Some(unit_off) => {
                        let unit = self.dwarf.unit(header)?;
                        let cu_lang = self.extract_language(self.dwarf, &unit);
                        self.process_unit_shard(&unit, unit_off, cu_lang)
                    }
                    _ => Ok(InfoShard::default()),
                }
            })
            .collect();

        let mut shards = Vec::with_capacity(shard_results.len());
        for sr in shard_results {
            shards.push(sr?);
        }

        let mut lightweight_index = LightweightIndex::from_shards(shards);
        let functions_count = lightweight_index.get_function_names().len();
        let variables_count = lightweight_index.get_variable_names().len();
        // Build per-CU function address maps
        lightweight_index.build_cu_maps(self.dwarf);
        // Prefer CU range map from .debug_aranges if available
        let _ = lightweight_index.build_cu_maps_from_aranges(self.dwarf);

        debug!(
            "Completed debug_info parsing for {}: {} functions, {} variables",
            module_path, functions_count, variables_count
        );

        Ok(DebugParseResult {
            lightweight_index,
            functions_count,
            variables_count,
        })
    }

    /// Combine parallel parse results into unified result
    pub fn combine_parallel_results(
        line_result: LineParseResult,
        info_result: DebugParseResult,
        module_path: String,
    ) -> DwarfParseResult {
        debug!("Assembling parallel parse results for: {}", module_path);

        let LineParseResult {
            line_mapping,
            scoped_file_manager,
            compilation_units,
            source_unit_offsets,
            line_entries_count,
            files_count,
        } = line_result;

        let stats = DwarfParseStats {
            total_functions: info_result.functions_count,
            total_variables: info_result.variables_count,
            total_line_entries: line_entries_count,
            total_files: files_count,
        };

        DwarfParseResult {
            lightweight_index: info_result.lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units,
            line_source_unit_offsets: source_unit_offsets,
            stats,
        }
    }

    // ===== Static methods for parallel processing =====

    /// Static version of extract_file_info_from_line_program for parallel use
    fn extract_file_info_from_line_program_static(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        line_program: &gimli::IncompleteLineProgram<DwarfReader>,
    ) -> Result<CompilationUnit> {
        let cu_name = Self::extract_cu_name_from_dwarf(dwarf, unit)
            .unwrap_or_else(|| format!("unknown_cu_{:?}", unit.header.offset()));

        debug!("Extracting files from compilation unit: {}", cu_name);

        let header = line_program.header();
        let mut compilation_unit = CompilationUnit {
            base_directory: Self::extract_comp_dir_from_dwarf(dwarf, unit)
                .unwrap_or_else(|| ".".to_string()),
            include_directories: Vec::new(),
            files: Vec::new(),
        };

        // Extract include directories
        compilation_unit.include_directories = header
            .include_directories()
            .iter()
            .enumerate()
            .map(|(i, path)| {
                let path_str = dwarf
                    .attr_string(unit, path.clone())
                    .ok()
                    .and_then(|s| s.to_string_lossy().ok().map(|cow| cow.into_owned()))
                    .unwrap_or_else(|| format!("unknown_dir_{i}"));
                tracing::trace!("Include directory [{}]: '{}'", i + 1, path_str);
                path_str
            })
            .collect();

        // Extract file entries
        for (file_index, file_entry) in header.file_names().iter().enumerate() {
            match Self::extract_source_file_static(
                dwarf,
                unit,
                file_index as u64,
                file_entry,
                &cu_name,
                compilation_unit.base_directory.as_str(),
                &compilation_unit.include_directories,
            ) {
                Ok(source_file) => {
                    compilation_unit.files.push(source_file);
                }
                Err(e) => {
                    tracing::trace!("Skipping file entry {}: {}", file_index, e);
                }
            }
        }

        tracing::trace!(
            "Extracted {} files from compilation unit {}",
            compilation_unit.files.len(),
            cu_name
        );

        Ok(compilation_unit)
    }

    fn extract_cu_name_from_dwarf(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let entry = entries.next_dfs().ok()??;

        if let Some(name_attr) = entry.attr_value(gimli::constants::DW_AT_name) {
            if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                if let Ok(s_str) = name.to_string_lossy() {
                    return Some(s_str.into_owned());
                }
            }
        }

        None
    }

    fn extract_comp_dir_from_dwarf(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let entry = entries.next_dfs().ok()??;

        if let Some(comp_dir_attr) = entry.attr_value(gimli::constants::DW_AT_comp_dir) {
            if let Ok(comp_dir) = dwarf.attr_string(unit, comp_dir_attr) {
                if let Ok(s_str) = comp_dir.to_string_lossy() {
                    return Some(s_str.into_owned());
                }
            }
        }

        None
    }

    fn extract_source_file_static(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        file_index: u64,
        file_entry: &gimli::FileEntry<DwarfReader>,
        compilation_unit: &str,
        base_directory: &str,
        include_directories: &[String],
    ) -> anyhow::Result<SourceFile> {
        // Get directory path
        let dir_index = file_entry.directory_index();
        let directory_path = directory_from_index(
            unit.header.version(),
            base_directory,
            include_directories,
            dir_index,
        );

        // Get filename
        let filename = dwarf
            .attr_string(unit, file_entry.path_name())
            .ok()
            .and_then(|s| s.to_string_lossy().ok().map(|cow| cow.into_owned()))
            .unwrap_or_else(|| "unknown".to_string());

        // Filter out system files
        if filename == "<built-in>" {
            return Err(anyhow::anyhow!("Skipping system file"));
        }

        let full_path = resolve_file_path(
            unit.header.version(),
            base_directory,
            include_directories,
            dir_index,
            &filename,
        );

        tracing::trace!(
            "extract_source_file_static: cu='{}', file_index={}, dir_index={}, directory_path='{}', filename='{}', full_path='{}'",
            compilation_unit, file_index, dir_index, directory_path, filename, full_path
        );

        Ok(SourceFile {
            directory_path,
            filename,
            full_path,
        })
    }
}

#[cfg(test)]
mod tests;

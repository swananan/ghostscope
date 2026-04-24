//! Unified DWARF parser - true single-pass parsing

use crate::{
    binary::DwarfReader,
    core::{FunctionDieKind, IndexEntry, Result},
    index::{
        directory_from_index, resolve_file_path, LightweightFileIndex, LightweightIndex,
        LightweightIndexShard, LineMappingTable, ScopedFileIndexManager,
    },
};
use gimli::Reader;
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tracing::debug;

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
    abstract_origin: Option<gimli::UnitOffset>,
    specification: Option<gimli::UnitOffset>,
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
    file_indices: Vec<(String, LightweightFileIndex)>,
    files_count: usize,
}

/// Complete result of DWARF parsing
pub(crate) struct DwarfParseResult {
    pub lightweight_index: LightweightIndex,
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
    pub stats: DwarfParseStats,
}

/// Result of line information parsing (for parallel processing)
pub(crate) struct LineParseResult {
    pub line_mapping: LineMappingTable,
    pub scoped_file_manager: ScopedFileIndexManager,
    pub compilation_units: HashMap<String, CompilationUnit>,
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
        let mut metadata_cache: HashMap<gimli::UnitOffset, FunctionMetadata> = HashMap::new();
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
    fn same_unit_ref(
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
    ) -> Option<gimli::UnitOffset> {
        match value {
            gimli::AttributeValue::UnitRef(offset) => Some(offset),
            gimli::AttributeValue::DebugInfoRef(offset) => offset.to_unit_offset(&unit.header),
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
                    attrs.abstract_origin = Self::same_unit_ref(unit, value);
                }
                gimli::constants::DW_AT_specification => {
                    attrs.specification = Self::same_unit_ref(unit, value);
                }
                _ => {}
            }
        }
        Ok(attrs)
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
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<Option<Arc<str>>> {
        if let Some(name) = attrs.name.as_ref() {
            return Ok(Some(Arc::clone(name)));
        }

        if !visited.insert(entry_offset) {
            return Ok(None);
        }

        let mut resolved = None;
        for origin_offset in [attrs.specification, attrs.abstract_origin]
            .into_iter()
            .flatten()
        {
            if visited.contains(&origin_offset) {
                continue;
            }

            let origin_attrs = self.read_selected_raw_attrs_at(unit, origin_offset)?;
            if let Some(name) =
                self.resolve_name_from_raw(unit, origin_offset, &origin_attrs, visited)?
            {
                resolved = Some(name);
                break;
            }
        }

        visited.remove(&entry_offset);
        Ok(resolved)
    }

    fn resolve_function_metadata_from_raw(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entry_offset: gimli::UnitOffset,
        attrs: &RawDieAttrs,
        cache: &mut HashMap<gimli::UnitOffset, FunctionMetadata>,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<FunctionMetadata> {
        if let Some(cached) = cache.get(&entry_offset) {
            return Ok(cached.clone());
        }

        if !visited.insert(entry_offset) {
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

        let mut merge_from_origin = |origin_offset: gimli::UnitOffset| -> Result<()> {
            if visited.contains(&origin_offset) {
                return Ok(());
            }

            let origin_metadata = if let Some(cached) = cache.get(&origin_offset) {
                cached.clone()
            } else {
                let origin_attrs = self.read_selected_raw_attrs_at(unit, origin_offset)?;
                self.resolve_function_metadata_from_raw(
                    unit,
                    origin_offset,
                    &origin_attrs,
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

        visited.remove(&entry_offset);
        cache.insert(entry_offset, metadata.clone());
        Ok(metadata)
    }

    fn flag_attr_value(value: gimli::AttributeValue<DwarfReader>) -> Option<bool> {
        match value {
            gimli::AttributeValue::Flag(v) => Some(v),
            _ => None,
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
        let operations = crate::dwarf_expr::ops::parse_ops(
            expr.0,
            unit.encoding(),
            "absolute storage address expression",
        )
        .ok()?;

        match operations.as_slice() {
            [gimli::Operation::Address { address }] => Some(*address),
            // clang/LLVM commonly encodes function-scoped statics in DWARF5 as a
            // single `DW_OP_addrx` op. This is still a true storage location, just
            // indirected through `.debug_addr`.
            [gimli::Operation::AddressIndex { index }] => self.dwarf.address(unit, *index).ok(),
            [gimli::Operation::UnsignedConstant { value }] => Some(*value),
            // Anything more complex may be a computed value or a composite
            // location. In particular, `DW_OP_stack_value` means the expression
            // yields a value, not a storage address, so treating it as global
            // storage would misindex optimized locals.
            _ => None,
        }
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
    pub fn parse_line_info(&self, module_path: &str) -> Result<LineParseResult> {
        debug!("Starting debug_line-only parsing for: {}", module_path);

        // Collect CU headers once
        let mut headers: Vec<gimli::UnitHeader<DwarfReader>> = Vec::new();
        let mut units = self.dwarf.units();
        while let Ok(Some(h)) = units.next() {
            headers.push(h);
        }

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
                    shard.files_count += compilation_unit.files.len();
                    shard
                        .compilation_units
                        .insert(cu_name.clone(), compilation_unit);
                    shard.file_indices.push((cu_name.clone(), file_index));

                    // Extract line rows for this CU
                    let (line_program, sequences) = line_program.clone().sequences()?;
                    for seq in sequences {
                        let mut rows = line_program.resume_from(&seq);
                        while let Some((_, line_row)) = rows.next_row()? {
                            let column = match line_row.column() {
                                gimli::ColumnType::LeftEdge => 0,
                                gimli::ColumnType::Column(x) => x.get(),
                            };
                            shard.line_entries.push(crate::core::LineEntry {
                                address: line_row.address(),
                                file_path: String::new(),
                                file_index: line_row.file_index(),
                                compilation_unit: std::sync::Arc::from(cu_name.as_str()),
                                line: line_row.line().map(|l| l.get()).unwrap_or(0),
                                column,
                                is_stmt: line_row.is_stmt(),
                                prologue_end: line_row.prologue_end(),
                                epilogue_begin: line_row.epilogue_begin(),
                                end_sequence: line_row.end_sequence(),
                            });
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
        let mut total_files = 0usize;

        for sr in shard_results {
            let shard = sr?;
            total_files += shard.files_count;
            line_entries.extend(shard.line_entries);
            for (cu, cuinfo) in shard.compilation_units {
                compilation_units.insert(cu, cuinfo);
            }
            for (cu, fi) in shard.file_indices {
                scoped_file_manager.add_compilation_unit(cu, fi);
            }
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
            line_entries_count: total_line_entries,
            files_count: total_files,
        })
    }

    /// Parse debug_info sections (for parallel processing)
    pub fn parse_debug_info(&self, module_path: &str) -> Result<DebugParseResult> {
        debug!("Starting debug_info-only parsing for: {}", module_path);
        // Collect headers once
        let mut headers: Vec<gimli::UnitHeader<DwarfReader>> = Vec::new();
        let mut units = self.dwarf.units();
        while let Ok(Some(h)) = units.next() {
            headers.push(h);
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
mod tests {
    use super::*;
    use crate::binary::dwarf_reader_from_arc;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Sections, Unit,
    };
    use gimli::{Format, LittleEndian};
    use object::{Object, ObjectSection};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use tempfile::TempPath;

    fn build_variable_index_fixture() -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let global_id = unit.add(root, gimli::constants::DW_TAG_variable);
        let global = unit.get_mut(global_id);
        global.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"real_global".to_vec()),
        );
        global.set(
            gimli::constants::DW_AT_external,
            WriteAttributeValue::Flag(true),
        );
        let mut global_loc = WriteExpression::new();
        global_loc.op_addr(Address::Constant(0x401000));
        global.set(
            gimli::constants::DW_AT_location,
            WriteAttributeValue::Exprloc(global_loc),
        );

        let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
        unit.get_mut(subprogram_id).set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"touch".to_vec()),
        );

        let local_static_id = unit.add(subprogram_id, gimli::constants::DW_TAG_variable);
        let local_static = unit.get_mut(local_static_id);
        local_static.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"local_static".to_vec()),
        );
        let mut local_static_loc = WriteExpression::new();
        local_static_loc.op_addr(Address::Constant(0x402000));
        local_static.set(
            gimli::constants::DW_AT_location,
            WriteAttributeValue::Exprloc(local_static_loc),
        );

        let local_ptr_id = unit.add(subprogram_id, gimli::constants::DW_TAG_variable);
        let local_ptr = unit.get_mut(local_ptr_id);
        local_ptr.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"p".to_vec()),
        );
        let mut local_ptr_loc = WriteExpression::new();
        local_ptr_loc.op_addr(Address::Constant(0x403000));
        local_ptr_loc.op(gimli::constants::DW_OP_stack_value);
        local_ptr.set(
            gimli::constants::DW_AT_location,
            WriteAttributeValue::Exprloc(local_ptr_loc),
        );

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_inline_origin_fixture() -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let abstract_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
        let abstract_fn = unit.get_mut(abstract_id);
        abstract_fn.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"CGPsend".to_vec()),
        );
        abstract_fn.set(
            gimli::constants::DW_AT_inline,
            WriteAttributeValue::Inline(gimli::DW_INL_inlined),
        );
        abstract_fn.set(
            gimli::constants::DW_AT_external,
            WriteAttributeValue::Flag(true),
        );

        let concrete_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
        let concrete_fn = unit.get_mut(concrete_id);
        concrete_fn.set(
            gimli::constants::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(abstract_id),
        );
        concrete_fn.set(
            gimli::constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x8e97c0)),
        );
        concrete_fn.set(
            gimli::constants::DW_AT_high_pc,
            WriteAttributeValue::Udata(0x420),
        );

        let inlined_id = unit.add(root, gimli::constants::DW_TAG_inlined_subroutine);
        unit.get_mut(inlined_id).set(
            gimli::constants::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(abstract_id),
        );

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_multi_cu_shared_function_fixture() -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();

        for (cu_name, low_pc) in [("unit_one.rs", 0x401000_u64), ("unit_two.rs", 0x402000_u64)] {
            let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
            let unit = dwarf.units.get_mut(unit_id);
            let root = unit.root();
            unit.get_mut(root).set(
                gimli::constants::DW_AT_name,
                WriteAttributeValue::String(cu_name.as_bytes().to_vec()),
            );

            let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
            let subprogram = unit.get_mut(subprogram_id);
            subprogram.set(
                gimli::constants::DW_AT_name,
                WriteAttributeValue::String(b"shared".to_vec()),
            );
            subprogram.set(
                gimli::constants::DW_AT_low_pc,
                WriteAttributeValue::Address(Address::Constant(low_pc)),
            );
            subprogram.set(
                gimli::constants::DW_AT_high_pc,
                WriteAttributeValue::Udata(0x20),
            );
        }

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn build_cu_body_lookup_fixture() -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();
        unit.get_mut(root).set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"body_lookup_unit".to_vec()),
        );

        let subprogram_id = unit.add(root, gimli::constants::DW_TAG_subprogram);
        let subprogram = unit.get_mut(subprogram_id);
        subprogram.set(
            gimli::constants::DW_AT_name,
            WriteAttributeValue::String(b"body_lookup".to_vec()),
        );
        subprogram.set(
            gimli::constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x401000)),
        );
        subprogram.set(
            gimli::constants::DW_AT_high_pc,
            WriteAttributeValue::Udata(0x40),
        );

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
    }

    fn clang_available() -> bool {
        Command::new("clang")
            .arg("--version")
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    fn compile_inline_callsite_fixture_with_clang_dwarf5() -> anyhow::Result<TempPath> {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| anyhow::anyhow!("ghostscope-dwarf has no workspace parent"))?
            .to_path_buf();
        let source = workspace_root
            .join("e2e-tests/tests/fixtures/inline_callsite_program/inline_callsite_program.c");
        let binary = tempfile::Builder::new()
            .prefix("ghostscope-fast-parser-")
            .tempfile()?
            .into_temp_path();
        let binary_path = binary.to_path_buf();

        let compile_output = Command::new("clang")
            .args(["-Wall", "-Wextra", "-gdwarf-5", "-O3"])
            .arg("-o")
            .arg(&binary_path)
            .arg(&source)
            .output()
            .map_err(|e| anyhow::anyhow!("Failed to run clang for {}: {}", source.display(), e))?;

        if compile_output.status.success() {
            Ok(binary)
        } else {
            let stderr = String::from_utf8_lossy(&compile_output.stderr);
            Err(anyhow::anyhow!(
                "Failed to compile {} with clang -gdwarf-5 -O3: {}",
                source.display(),
                stderr
            ))
        }
    }

    fn load_dwarf_from_binary(path: &Path) -> anyhow::Result<gimli::Dwarf<DwarfReader>> {
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", path.display(), e))?;
        let object = object::File::parse(&*bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", path.display(), e))?;
        let dwarf = gimli::Dwarf::load(|id| {
            let section_data = object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .map(|data| data.into_owned())
                .unwrap_or_default();
            Ok::<_, gimli::Error>(dwarf_reader_from_arc(Arc::<[u8]>::from(section_data)))
        })?;
        Ok(dwarf)
    }

    fn read_uleb128(input: &[u8], offset: &mut usize) -> anyhow::Result<u64> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = *input
                .get(*offset)
                .ok_or_else(|| anyhow::anyhow!("Unexpected EOF while reading ULEB128"))?;
            *offset += 1;
            let low_bits = u64::from(byte & 0x7f);
            anyhow::ensure!(
                shift < 64 && !(shift == 63 && low_bits > 1),
                "ULEB128 value exceeds u64"
            );
            value |= low_bits << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
        }
    }

    #[test]
    fn read_uleb128_rejects_values_that_overflow_u64() {
        let overflow = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
        let mut offset = 0;
        let err = read_uleb128(&overflow, &mut offset).expect_err("overflow should be rejected");
        assert!(
            err.to_string().contains("exceeds u64"),
            "unexpected overflow error: {err}"
        );
    }

    fn patch_inlined_subroutine_low_pc_to_entry_pc(abbrev: &mut [u8]) -> anyhow::Result<usize> {
        let mut offset = 0;
        let mut patched = 0;

        while offset < abbrev.len() {
            let code = read_uleb128(abbrev, &mut offset)?;
            if code == 0 {
                continue;
            }

            let tag = read_uleb128(abbrev, &mut offset)?;
            let _has_children = *abbrev
                .get(offset)
                .ok_or_else(|| anyhow::anyhow!("Missing abbrev children byte"))?;
            offset += 1;

            loop {
                let name_offset = offset;
                let name = read_uleb128(abbrev, &mut offset)?;
                let form = read_uleb128(abbrev, &mut offset)?;
                if name == 0 && form == 0 {
                    break;
                }

                let is_addrx_form = form == u64::from(gimli::constants::DW_FORM_addrx.0)
                    || form == u64::from(gimli::constants::DW_FORM_addrx1.0)
                    || form == u64::from(gimli::constants::DW_FORM_addrx2.0)
                    || form == u64::from(gimli::constants::DW_FORM_addrx3.0)
                    || form == u64::from(gimli::constants::DW_FORM_addrx4.0);
                if tag == u64::from(gimli::constants::DW_TAG_inlined_subroutine.0)
                    && name == u64::from(gimli::constants::DW_AT_low_pc.0)
                    && is_addrx_form
                {
                    *abbrev
                        .get_mut(name_offset)
                        .ok_or_else(|| anyhow::anyhow!("Invalid abbrev attribute offset"))? =
                        gimli::constants::DW_AT_entry_pc.0 as u8;
                    patched += 1;
                }
            }
        }

        Ok(patched)
    }

    fn rewrite_inline_fixture_entry_pc_attr(input_path: &Path) -> anyhow::Result<TempPath> {
        let mut bytes = std::fs::read(input_path)
            .map_err(|e| anyhow::anyhow!("Failed to read {}: {}", input_path.display(), e))?;
        let (abbrev_offset, abbrev_size) = {
            let object = object::File::parse(&*bytes)
                .map_err(|e| anyhow::anyhow!("Failed to parse {}: {}", input_path.display(), e))?;
            let section = object.section_by_name(".debug_abbrev").ok_or_else(|| {
                anyhow::anyhow!("{} is missing .debug_abbrev", input_path.display())
            })?;
            section.file_range().ok_or_else(|| {
                anyhow::anyhow!(
                    "{} has no file range for .debug_abbrev",
                    input_path.display()
                )
            })?
        };

        let patched = patch_inlined_subroutine_low_pc_to_entry_pc(
            &mut bytes[abbrev_offset as usize..(abbrev_offset + abbrev_size) as usize],
        )?;
        anyhow::ensure!(
            patched > 0,
            "Expected to patch at least one inline low_pc abbrev in {}",
            input_path.display()
        );

        let output = tempfile::Builder::new()
            .prefix(".ghostscope-fast-parser-patched-")
            .tempfile()?
            .into_temp_path();
        std::fs::write(&output, &bytes)?;
        let perms = std::fs::metadata(input_path)?.permissions().mode();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(perms))?;
        Ok(output)
    }

    fn has_inline_entry_pc_debug_addr_index(dwarf: &gimli::Dwarf<DwarfReader>) -> bool {
        let mut units = dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let Ok(unit) = dwarf.unit(header) else {
                continue;
            };
            let mut entries = unit.entries();
            while let Ok(Some(entry)) = entries.next_dfs() {
                if entry.tag() != gimli::constants::DW_TAG_inlined_subroutine {
                    continue;
                }
                if let Some(attr) = entry.attr(gimli::constants::DW_AT_entry_pc) {
                    if matches!(attr.value(), gimli::AttributeValue::DebugAddrIndex(_)) {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[test]
    fn parse_debug_info_skips_stack_value_address_locals_from_global_index() {
        let dwarf = build_variable_index_fixture();
        let parser = DwarfParser { dwarf: &dwarf };

        let result = parser.parse_debug_info("synthetic").unwrap();
        let real_global = result
            .lightweight_index
            .find_variables_by_name("real_global");
        let local_static = result
            .lightweight_index
            .find_variables_by_name("local_static");
        let optimized_local = result.lightweight_index.find_variables_by_name("p");

        assert_eq!(
            real_global.len(),
            1,
            "real global should remain indexed: {real_global:?}"
        );
        assert_eq!(
            local_static.len(),
            1,
            "function-scoped static with real storage should remain indexed: {local_static:?}"
        );
        assert!(
            optimized_local.is_empty(),
            "address-valued optimized local must not be indexed as a global: {optimized_local:?}"
        );
    }

    #[test]
    fn parse_debug_info_keeps_concrete_abstract_origin_subprogram_non_inline() {
        // Regression scenario:
        // GCC/Clang can emit all three DIE shapes for one logical function:
        // 1. an abstract DW_TAG_subprogram marked DW_AT_inline,
        // 2. a concrete out-of-line DW_TAG_subprogram with DW_AT_abstract_origin,
        // 3. one or more DW_TAG_inlined_subroutine instances.
        //
        // The bug was that merge_from_origin copied the abstract function's
        // inline attribute from (1) onto (2) and downstream code treated that
        // as if the concrete body were an inline instance.
        // Once that happened, the concrete body was routed through the inline
        // address-selection path and could pick the wrong cold-partition PC.
        //
        // This test keeps the synthetic DIE graph minimal and asserts the parser
        // preserves the intended split:
        // - abstract definition stays inline
        // - concrete out-of-line body stays non-inline
        // - inlined_subroutine instance stays inline
        let dwarf = build_inline_origin_fixture();
        let parser = DwarfParser { dwarf: &dwarf };

        let result = parser.parse_debug_info("synthetic").unwrap();
        let entries = result
            .lightweight_index
            .find_dies_by_function_name("CGPsend");

        let concrete_entries: Vec<_> = entries
            .iter()
            .copied()
            .filter(|entry| {
                entry.function_kind() == crate::core::FunctionDieKind::ConcreteSubprogram
            })
            .collect();
        let abstract_entries: Vec<_> = entries
            .iter()
            .copied()
            .filter(|entry| {
                entry.function_kind() == crate::core::FunctionDieKind::AbstractSubprogram
            })
            .collect();
        let inlined_entries: Vec<_> = entries
            .iter()
            .copied()
            .filter(|entry| entry.function_kind() == crate::core::FunctionDieKind::InlineInstance)
            .collect();

        assert_eq!(
            concrete_entries.len(),
            1,
            "concrete out-of-line subprogram should stay non-inline: {entries:?}"
        );
        assert_eq!(
            abstract_entries.len(),
            1,
            "only the abstract inline definition should carry the inline flag: {entries:?}"
        );
        assert_eq!(
            inlined_entries.len(),
            1,
            "expected one inlined subroutine instance: {entries:?}"
        );
        assert!(
            inlined_entries[0].is_inline_instance(),
            "DW_TAG_inlined_subroutine must remain an inline instance: {entries:?}"
        );
        assert!(
            !concrete_entries[0].flags.has_inline_attribute,
            "concrete out-of-line body should not inherit the abstract inline attribute: {entries:?}"
        );
        assert!(
            abstract_entries[0].flags.has_inline_attribute,
            "abstract definition should retain its original DW_AT_inline attribute: {entries:?}"
        );
    }

    #[test]
    fn parse_debug_info_keeps_sharded_name_lookup_without_duplicate_keys() {
        let dwarf = build_multi_cu_shared_function_fixture();
        let parser = DwarfParser { dwarf: &dwarf };

        let result = parser.parse_debug_info("synthetic").unwrap();
        let entries = result
            .lightweight_index
            .find_dies_by_function_name("shared");
        let names = result.lightweight_index.get_function_names();

        assert_eq!(
            result.functions_count, 1,
            "unique function-name count should stay deduplicated across shards"
        );
        assert_eq!(
            entries.len(),
            2,
            "function lookup should fan out across CU shards: {entries:?}"
        );
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_str() == "shared")
                .count(),
            1,
            "function name listing should not duplicate shard-local keys: {names:?}"
        );
    }

    #[test]
    fn parse_debug_info_builds_fallback_cu_map_for_function_body_addresses() {
        let dwarf = build_cu_body_lookup_fixture();
        let parser = DwarfParser { dwarf: &dwarf };

        let result = parser.parse_debug_info("synthetic").unwrap();
        let entry = result
            .lightweight_index
            .find_function_by_address(0x401020, |entry| {
                let header = dwarf.unit_header(entry.unit_offset).ok()?;
                let unit = dwarf.unit(header).ok()?;
                let die = unit.entry(entry.die_offset).ok()?;
                crate::parser::RangeExtractor::extract_all_ranges(&die, &unit, &dwarf).ok()
            })
            .expect("function body address should resolve through fallback CU map");

        assert_eq!(entry.name.as_ref(), "body_lookup");
        assert_eq!(
            result.lightweight_index.find_cu_by_address(0x401020),
            Some(entry.unit_offset),
            "fallback CU map should cover addresses inside the function body, not just the representative address"
        );
    }

    #[test]
    fn parse_debug_info_resolves_debug_addr_index_entry_pc_for_inline_instances() {
        if !clang_available() {
            eprintln!("Skipping fast_parser DWARF5 entry_pc regression: clang is unavailable");
            return;
        }

        let patched_binary = {
            let binary = compile_inline_callsite_fixture_with_clang_dwarf5()
                .expect("clang dwarf5 inline fixture should compile");
            rewrite_inline_fixture_entry_pc_attr(binary.as_ref())
                .expect("inline fixture abbrev should rewrite low_pc addrx into entry_pc addrx")
        };
        let dwarf = load_dwarf_from_binary(patched_binary.as_ref())
            .expect("compiled inline fixture should load as DWARF");
        assert!(
            has_inline_entry_pc_debug_addr_index(&dwarf),
            "patched inline fixture should expose an inlined_subroutine DW_AT_entry_pc via DW_FORM_addrx/.debug_addr"
        );

        let parser = DwarfParser { dwarf: &dwarf };
        let result = parser
            .parse_debug_info(patched_binary.to_string_lossy().as_ref())
            .expect("fast parser should index patched clang dwarf5 inline fixture");

        let inline_entries: Vec<_> = ["add3", "consume_state"]
            .into_iter()
            .flat_map(|name| {
                result
                    .lightweight_index
                    .find_dies_by_function_name(name)
                    .iter()
                    .copied()
                    .filter(|entry| {
                        entry.function_kind() == crate::core::FunctionDieKind::InlineInstance
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        assert!(
            !inline_entries.is_empty(),
            "expected inline entries for clang dwarf5 inline fixture"
        );
        assert!(
            inline_entries.iter().any(|entry| entry.entry_pc.is_some()),
            "fast parser should resolve DW_FORM_addrx-backed DW_AT_entry_pc values for inline instances: {inline_entries:?}"
        );
    }
}

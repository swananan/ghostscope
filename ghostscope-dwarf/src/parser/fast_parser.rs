//! Unified DWARF parser - true single-pass parsing

use super::fast_paths::resolve_name_in_unit_fast;
use crate::{
    binary::DwarfReader,
    core::{
        demangle::{demangle_by_lang, demangled_leaf},
        FunctionDieKind, IndexEntry, Result,
    },
    index::{
        directory_from_index, resolve_file_path, LightweightFileIndex, LightweightIndex,
        LightweightIndexShard, LineMappingTable, ScopedFileIndexManager,
    },
    parser::RangeExtractor,
};
use gimli::Reader;
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[derive(Clone, Default)]
struct FunctionMetadata {
    name: Option<String>,
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
    address_ranges: Vec<(u64, u64)>,
    entry_pc: Option<u64>,
    function_kind: FunctionDieKind,
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
        let mut entries = unit.entries();
        let mut metadata_cache: HashMap<gimli::UnitOffset, FunctionMetadata> = HashMap::new();
        let mut tag_stack: Vec<gimli::DwTag> = Vec::new();
        while let Some(entry) = entries.next_dfs()? {
            let d: usize = entry.depth() as usize;
            while tag_stack.len() > d {
                tag_stack.pop();
            }
            match entry.tag() {
                gimli::constants::DW_TAG_subprogram => {
                    let mut visited = HashSet::new();
                    let metadata = self.resolve_function_metadata(
                        self.dwarf,
                        unit,
                        entry,
                        &mut metadata_cache,
                        &mut visited,
                    )?;
                    if let Some(name) = metadata.name.clone() {
                        let address_ranges =
                            self.extract_address_ranges(self.dwarf, unit, entry)?;
                        let entry_pc_cached = self.extract_entry_pc(entry)?;
                        let function_kind = Self::classify_function_kind(
                            entry.tag(),
                            &address_ranges,
                            entry_pc_cached,
                        );
                        let is_main = self.is_main_function(entry, &name).unwrap_or(false);
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or_else(|| self.is_static_symbol(entry).unwrap_or(false));
                        let flags = crate::core::IndexFlags {
                            is_static,
                            is_main,
                            is_inline_instance: function_kind == FunctionDieKind::InlineInstance,
                            has_inline_attribute: metadata.has_inline_attribute,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let linkage_name = self
                            .extract_linkage_name(self.dwarf, unit, entry)?
                            .map(|(linkage_name, _)| linkage_name);
                        let seed = FunctionEntrySeed {
                            die_offset: entry.offset(),
                            tag: entry.tag(),
                            unit_offset,
                            flags,
                            language: cu_language,
                            address_ranges,
                            entry_pc: entry_pc_cached,
                            function_kind,
                        };
                        Self::push_function_entries(&mut shard, &name, linkage_name, &seed);
                    }
                }
                gimli::constants::DW_TAG_inlined_subroutine => {
                    let mut visited = HashSet::new();
                    let metadata = self.resolve_function_metadata(
                        self.dwarf,
                        unit,
                        entry,
                        &mut metadata_cache,
                        &mut visited,
                    )?;
                    if let Some(name) = metadata.name.clone() {
                        let address_ranges =
                            self.extract_address_ranges(self.dwarf, unit, entry)?;
                        let entry_pc_cached = self.extract_entry_pc(entry)?;
                        let function_kind = Self::classify_function_kind(
                            entry.tag(),
                            &address_ranges,
                            entry_pc_cached,
                        );
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or(false);
                        let flags = crate::core::IndexFlags {
                            is_static,
                            is_inline_instance: function_kind == FunctionDieKind::InlineInstance,
                            has_inline_attribute: metadata.has_inline_attribute,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let linkage_name = self
                            .extract_linkage_name(self.dwarf, unit, entry)?
                            .map(|(linkage_name, _)| linkage_name);
                        let seed = FunctionEntrySeed {
                            die_offset: entry.offset(),
                            tag: entry.tag(),
                            unit_offset,
                            flags,
                            language: cu_language,
                            address_ranges,
                            entry_pc: entry_pc_cached,
                            function_kind,
                        };
                        Self::push_function_entries(&mut shard, &name, linkage_name, &seed);
                    }
                }
                gimli::constants::DW_TAG_variable => {
                    tracing::trace!(
                        "Evaluating global variable DIE {:?} in CU {:?}",
                        entry.offset(),
                        unit_offset
                    );
                    let var_addr = self.extract_variable_address(entry, unit)?;
                    let is_static_symbol = self
                        .is_static_variable_symbol(entry, var_addr)
                        .unwrap_or(false);
                    let in_function_scope = tag_stack.iter().any(|t| {
                        *t == gimli::constants::DW_TAG_subprogram
                            || *t == gimli::constants::DW_TAG_inlined_subroutine
                    });
                    if in_function_scope && !is_static_symbol {
                        tracing::trace!(
                            "Skipping variable at {:?} (in function scope, stack={:?})",
                            entry.offset(),
                            tag_stack
                        );
                        // Skip local variables
                        tag_stack.push(entry.tag());
                        continue;
                    } else if in_function_scope {
                        // Rust (and some C compilers) sometimes nest file-scoped statics under the
                        // function that first references them, even though DW_AT_location uses
                        // DW_OP_addr. Treat only absolute-address-backed statics as true globals;
                        // stack/register locals must stay out of the global index.
                        tracing::trace!(
                            "Treating static variable at {:?} as global despite function scope (stack={:?})",
                            entry.offset(),
                            tag_stack
                        );
                    }
                    if Self::is_declaration(entry).unwrap_or(false) {
                        tracing::trace!(
                            "Skipping variable at {:?} (declaration-only DIE)",
                            entry.offset()
                        );
                        tag_stack.push(entry.tag());
                        continue;
                    }
                    let mut collected_names: Vec<(String, bool)> = Vec::new();
                    let mut push_unique_name = |candidate: String, is_linkage_alias: bool| {
                        if candidate.is_empty() {
                            return;
                        }
                        if collected_names
                            .iter()
                            .any(|(existing, _)| existing == &candidate)
                        {
                            return;
                        }
                        collected_names.push((candidate, is_linkage_alias));
                    };

                    let mut have_primary_name = false;
                    if let Some(name) = self.extract_name(self.dwarf, unit, entry)? {
                        push_unique_name(name, false);
                        have_primary_name = true;
                    }

                    if let Some((linkage_name, _)) =
                        self.extract_linkage_name(self.dwarf, unit, entry)?
                    {
                        if let Some(demangled) =
                            demangle_by_lang(cu_language, linkage_name.as_str())
                        {
                            let leaf = demangled_leaf(&demangled);
                            push_unique_name(leaf, false);
                            have_primary_name = true;
                        }
                        push_unique_name(linkage_name.clone(), true);
                    }

                    if !have_primary_name {
                        tracing::trace!(
                            "DWARF variable at {:?} missing usable name (CU lang={:?}); skipping alias registration",
                            entry.offset(),
                            cu_language
                        );
                        tag_stack.push(entry.tag());
                        continue;
                    }

                    let flags = crate::core::IndexFlags {
                        is_static: is_static_symbol,
                        ..Default::default()
                    };
                    let var_ranges = var_addr.map(|a| vec![(a, a)]).unwrap_or_default();

                    for (name, is_linkage_alias) in collected_names {
                        let mut entry_flags = flags;
                        entry_flags.is_linkage = is_linkage_alias;
                        let index_entry = IndexEntry {
                            name: std::sync::Arc::from(name.as_str()),
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: entry.tag(),
                            flags: entry_flags,
                            language: cu_language,
                            address_ranges: var_ranges.clone(),
                            entry_pc: None,
                            function_kind: FunctionDieKind::NotFunction,
                        };
                        tracing::trace!(
                            "Registering variable alias '{}' (linkage={}, lang={:?}, die={:?})",
                            name,
                            entry_flags.is_linkage,
                            cu_language,
                            entry.offset()
                        );
                        shard.push_variable_entry(name.clone(), index_entry);
                    }
                }
                gimli::constants::DW_TAG_structure_type
                | gimli::constants::DW_TAG_class_type
                | gimli::constants::DW_TAG_union_type
                | gimli::constants::DW_TAG_enumeration_type
                | gimli::constants::DW_TAG_typedef => {
                    if let Some(name) = self.extract_name(self.dwarf, unit, entry)? {
                        let is_decl = Self::bool_attr(entry, gimli::constants::DW_AT_declaration)?
                            .unwrap_or(false);
                        let flags = crate::core::IndexFlags {
                            is_type_declaration: is_decl,
                            ..Default::default()
                        };
                        let index_entry = IndexEntry {
                            name: std::sync::Arc::from(name.as_str()),
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: entry.tag(),
                            flags,
                            language: cu_language,
                            address_ranges: Vec::new(),
                            entry_pc: None,
                            function_kind: FunctionDieKind::NotFunction,
                        };
                        shard.push_type_entry(name, index_entry);
                    }
                }
                _ => {}
            }
            tag_stack.push(entry.tag());
        }
        Ok(shard)
    }
    pub fn new(dwarf: &'a gimli::Dwarf<DwarfReader>) -> Self {
        Self { dwarf }
    }

    fn classify_function_kind(
        tag: gimli::DwTag,
        address_ranges: &[(u64, u64)],
        entry_pc: Option<u64>,
    ) -> FunctionDieKind {
        match tag {
            gimli::constants::DW_TAG_inlined_subroutine => FunctionDieKind::InlineInstance,
            gimli::constants::DW_TAG_subprogram => {
                if !address_ranges.is_empty() || entry_pc.is_some() {
                    FunctionDieKind::ConcreteSubprogram
                } else {
                    FunctionDieKind::AbstractSubprogram
                }
            }
            _ => FunctionDieKind::NotFunction,
        }
    }

    fn build_function_index_entry(name: &str, seed: &FunctionEntrySeed) -> IndexEntry {
        IndexEntry {
            name: std::sync::Arc::from(name),
            die_offset: seed.die_offset,
            unit_offset: seed.unit_offset,
            tag: seed.tag,
            flags: seed.flags,
            language: seed.language,
            address_ranges: seed.address_ranges.clone(),
            entry_pc: seed.entry_pc,
            function_kind: seed.function_kind,
        }
    }

    fn push_function_entries(
        shard: &mut InfoShard,
        name: &str,
        linkage_name: Option<String>,
        seed: &FunctionEntrySeed,
    ) {
        shard.push_function_entry(
            name.to_owned(),
            Self::build_function_index_entry(name, seed),
        );

        if let Some(linkage_name) = linkage_name.filter(|linkage_name| linkage_name != name) {
            let mut alias_seed = seed.clone();
            let mut alias_flags = alias_seed.flags;
            alias_flags.is_linkage = true;
            alias_seed.flags = alias_flags;
            shard.push_function_entry(
                linkage_name.clone(),
                Self::build_function_index_entry(&linkage_name, &alias_seed),
            );
        }
    }

    fn extract_attr_string(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        attr_value: gimli::AttributeValue<DwarfReader>,
    ) -> Result<Option<String>> {
        if let Ok(string) = dwarf.attr_string(unit, attr_value) {
            if let Ok(s_str) = string.to_string_lossy() {
                return Ok(Some(s_str.into_owned()));
            }
        }
        Ok(None)
    }

    /// Process single compilation unit - decoupled debug_line and debug_info processing
    // Helper methods (extracted from unified_builder.rs)
    fn extract_name(
        &self,
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<String>> {
        Ok(resolve_name_in_unit_fast(dwarf, unit, entry)?)
    }

    fn extract_linkage_name(
        &self,
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<(String, bool)>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_linkage_name) {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_MIPS_linkage_name) {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        Ok(None)
    }

    fn extract_inline_attribute(
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_inline) {
            if let gimli::AttributeValue::Inline(inline_attr) = attr.value() {
                return Ok(inline_attr == gimli::DW_INL_inlined
                    || inline_attr == gimli::DW_INL_declared_inlined);
            }
        }
        Ok(false)
    }

    fn resolve_function_metadata(
        &self,
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        cache: &mut HashMap<gimli::UnitOffset, FunctionMetadata>,
        visited: &mut HashSet<gimli::UnitOffset>,
    ) -> Result<FunctionMetadata> {
        let offset = entry.offset();
        if let Some(cached) = cache.get(&offset) {
            return Ok(cached.clone());
        }

        if !visited.insert(offset) {
            return Ok(FunctionMetadata::default());
        }

        let mut metadata = FunctionMetadata::default();
        if let Some(name) = self.extract_name(dwarf, unit, entry)? {
            metadata.name = Some(name);
        } else if let Some((name, is_linkage)) = self.extract_linkage_name(dwarf, unit, entry)? {
            metadata.name = Some(name);
            metadata.is_linkage_name = is_linkage;
        }

        metadata.has_inline_attribute = Self::extract_inline_attribute(entry)?;

        metadata.is_external = Self::bool_attr(entry, gimli::constants::DW_AT_external)?;

        let mut merge_from_origin = |origin_offset: gimli::UnitOffset| -> Result<()> {
            if visited.contains(&origin_offset) {
                return Ok(());
            }

            let origin_entry = unit.entry(origin_offset)?;
            let origin_metadata =
                self.resolve_function_metadata(dwarf, unit, &origin_entry, cache, visited)?;

            if metadata.name.is_none() {
                metadata.name = origin_metadata.name.clone();
            }
            if metadata.is_external.is_none() {
                metadata.is_external = origin_metadata.is_external;
            }
            metadata.is_linkage_name |= origin_metadata.is_linkage_name;
            Ok(())
        };

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_abstract_origin) {
            match attr.value() {
                gimli::AttributeValue::UnitRef(unit_ref) => {
                    merge_from_origin(unit_ref)?;
                }
                gimli::AttributeValue::DebugInfoRef(debug_info_ref) => {
                    if let Some(unit_ref) = debug_info_ref.to_unit_offset(&unit.header) {
                        merge_from_origin(unit_ref)?;
                    }
                }
                _ => {}
            }
        }

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_specification) {
            match attr.value() {
                gimli::AttributeValue::UnitRef(unit_ref) => {
                    merge_from_origin(unit_ref)?;
                }
                gimli::AttributeValue::DebugInfoRef(debug_info_ref) => {
                    if let Some(unit_ref) = debug_info_ref.to_unit_offset(&unit.header) {
                        merge_from_origin(unit_ref)?;
                    }
                }
                _ => {}
            }
        }

        visited.remove(&offset);
        cache.insert(offset, metadata.clone());
        Ok(metadata)
    }

    fn bool_attr(
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        attr: gimli::DwAt,
    ) -> Result<Option<bool>> {
        let Some(attr) = entry.attr(attr) else {
            return Ok(None);
        };
        Ok(match attr.value() {
            gimli::AttributeValue::Flag(v) => Some(v),
            _ => None,
        })
    }

    fn is_static_symbol(
        &self,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<bool> {
        if let Some(is_external) = Self::bool_attr(entry, gimli::constants::DW_AT_external)? {
            return Ok(!is_external);
        }
        Ok(true)
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
    fn is_static_variable_symbol(
        &self,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        absolute_address: Option<u64>,
    ) -> Result<bool> {
        if let Some(is_external) = Self::bool_attr(entry, gimli::constants::DW_AT_external)? {
            return Ok(!is_external);
        }

        // DW_AT_external is often omitted on local stack/register variables. Only keep
        // function-scoped variables in the global index when DWARF gives them a true
        // absolute storage address.
        Ok(absolute_address.is_some())
    }

    fn is_declaration(entry: &gimli::DebuggingInformationEntry<DwarfReader>) -> Result<bool> {
        Ok(Self::bool_attr(entry, gimli::constants::DW_AT_declaration)?.unwrap_or(false))
    }

    /// Extract all address ranges from DIE (for functions)
    /// Supports DW_AT_low_pc/high_pc and DW_AT_ranges (returns all ranges)
    fn extract_address_ranges(
        &self,
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Vec<(u64, u64)>> {
        // Use RangeExtractor for unified logic
        RangeExtractor::extract_all_ranges(entry, unit, dwarf)
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
    fn extract_variable_address(
        &self,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
    ) -> Result<Option<u64>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_location) {
            match attr.value() {
                gimli::AttributeValue::Addr(a) => return Ok(Some(a)),
                gimli::AttributeValue::Exprloc(expr) => {
                    return Ok(self.extract_absolute_storage_address_from_expr(
                        unit,
                        gimli::Expression(expr.0),
                    ));
                }
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
                }
                _ => {}
            }
        }
        Ok(None)
    }

    fn extract_absolute_storage_address_from_expr(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        mut expr: gimli::Expression<DwarfReader>,
    ) -> Option<u64> {
        let mut operations = Vec::new();
        while let Ok(op) = gimli::Operation::parse(&mut expr.0, unit.encoding()) {
            operations.push(op);
        }

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

    fn extract_entry_pc(
        &self,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<u64>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_entry_pc) {
            if let gimli::AttributeValue::Addr(addr) = attr.value() {
                return Ok(Some(addr));
            }
        }
        Ok(None)
    }

    // Additional helper methods for GDB-style cooked index

    fn is_main_function(
        &self,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        name: &str,
    ) -> Result<bool> {
        // Check for DW_AT_main_subprogram attribute
        if entry
            .attr(gimli::constants::DW_AT_main_subprogram)
            .is_some()
        {
            return Ok(true);
        }

        // Also check common main function names
        Ok(name == "main" || name == "_main")
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
        lightweight_index.build_cu_maps();
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
    use std::sync::Arc;

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
}

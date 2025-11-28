//! Unified DWARF parser - true single-pass parsing

use crate::{
    core::{
        demangle::{demangle_by_lang, demangled_leaf},
        IndexEntry, Result,
    },
    data::{
        directory_from_index, resolve_file_path, LightweightFileIndex, LightweightIndex,
        LineMappingTable, ScopedFileIndexManager,
    },
    parser::RangeExtractor,
};
use gimli::{EndianArcSlice, LittleEndian, Reader};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use tracing::debug;

#[derive(Clone, Default)]
struct FunctionMetadata {
    name: Option<String>,
    is_inline: bool,
    is_linkage_name: bool,
    is_external: Option<bool>,
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

// Shard container for per-CU parsed results (functions/variables/types)
#[derive(Default)]
struct InfoShard {
    functions: HashMap<String, Vec<IndexEntry>>,
    variables: HashMap<String, Vec<IndexEntry>>,
    types: HashMap<String, Vec<IndexEntry>>,
}

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
    dwarf: &'a gimli::Dwarf<EndianArcSlice<LittleEndian>>,
}

/// Internal builder for accumulating parse results
impl<'a> DwarfParser<'a> {
    fn process_unit_shard(
        &self,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        unit_offset: gimli::DebugInfoOffset,
        cu_language: Option<gimli::DwLang>,
    ) -> Result<InfoShard> {
        let mut shard = InfoShard::default();
        let mut entries = unit.entries();
        let mut metadata_cache: HashMap<gimli::UnitOffset, FunctionMetadata> = HashMap::new();
        let mut tag_stack: Vec<gimli::DwTag> = Vec::new();
        while let Some((depth, entry)) = entries.next_dfs()? {
            let d: usize = depth as usize;
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
                        let is_main = self.is_main_function(entry, &name).unwrap_or(false);
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or_else(|| self.is_static_symbol(entry).unwrap_or(false));
                        let flags = crate::core::IndexFlags {
                            is_static,
                            is_main,
                            is_inline: metadata.is_inline,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let address_ranges =
                            self.extract_address_ranges(self.dwarf, unit, entry)?;
                        let entry_pc_cached = self.extract_entry_pc(entry)?;
                        let index_entry = IndexEntry {
                            name: std::sync::Arc::from(name.as_str()),
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: entry.tag(),
                            flags,
                            language: cu_language,
                            address_ranges: address_ranges.clone(),
                            entry_pc: entry_pc_cached,
                        };
                        shard
                            .functions
                            .entry(name.clone())
                            .or_default()
                            .push(index_entry);
                        if let Some((linkage_name, _)) =
                            self.extract_linkage_name(self.dwarf, unit, entry)?
                        {
                            if linkage_name != metadata.name.clone().unwrap_or_default() {
                                let mut alias_flags = flags;
                                alias_flags.is_linkage = true;
                                let index_entry_linkage = IndexEntry {
                                    name: std::sync::Arc::from(linkage_name.as_str()),
                                    die_offset: entry.offset(),
                                    unit_offset,
                                    tag: entry.tag(),
                                    flags: alias_flags,
                                    language: cu_language,
                                    address_ranges: address_ranges.clone(),
                                    entry_pc: entry_pc_cached,
                                };
                                shard
                                    .functions
                                    .entry(linkage_name)
                                    .or_default()
                                    .push(index_entry_linkage);
                            }
                        }
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
                        let is_static = metadata
                            .is_external
                            .map(|external| !external)
                            .unwrap_or(false);
                        let flags = crate::core::IndexFlags {
                            is_static,
                            is_inline: true,
                            is_linkage: metadata.is_linkage_name,
                            ..Default::default()
                        };
                        let address_ranges =
                            self.extract_address_ranges(self.dwarf, unit, entry)?;
                        let entry_pc_cached = self.extract_entry_pc(entry)?;
                        let index_entry = IndexEntry {
                            name: std::sync::Arc::from(name.as_str()),
                            die_offset: entry.offset(),
                            unit_offset,
                            tag: entry.tag(),
                            flags,
                            language: cu_language,
                            address_ranges: address_ranges.clone(),
                            entry_pc: entry_pc_cached,
                        };
                        shard
                            .functions
                            .entry(name.clone())
                            .or_default()
                            .push(index_entry);
                        if let Some((linkage_name, _)) =
                            self.extract_linkage_name(self.dwarf, unit, entry)?
                        {
                            if linkage_name != metadata.name.clone().unwrap_or_default() {
                                let mut alias_flags = flags;
                                alias_flags.is_linkage = true;
                                let index_entry_linkage = IndexEntry {
                                    name: std::sync::Arc::from(linkage_name.as_str()),
                                    die_offset: entry.offset(),
                                    unit_offset,
                                    tag: entry.tag(),
                                    flags: alias_flags,
                                    language: cu_language,
                                    address_ranges: address_ranges.clone(),
                                    entry_pc: entry_pc_cached,
                                };
                                shard
                                    .functions
                                    .entry(linkage_name)
                                    .or_default()
                                    .push(index_entry_linkage);
                            }
                        }
                    }
                }
                gimli::constants::DW_TAG_variable => {
                    tracing::trace!(
                        "Evaluating global variable DIE {:?} in CU {:?}",
                        entry.offset(),
                        unit_offset
                    );
                    let is_static_symbol = self.is_static_symbol(entry).unwrap_or(false);
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
                        // DW_OP_addr. When DW_AT_external is false we treat them as true globals.
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
                    let var_addr = self.extract_variable_address(entry, unit)?;
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
                        };
                        tracing::trace!(
                            "Registering variable alias '{}' (linkage={}, lang={:?}, die={:?})",
                            name,
                            entry_flags.is_linkage,
                            cu_language,
                            entry.offset()
                        );
                        shard
                            .variables
                            .entry(name.clone())
                            .or_default()
                            .push(index_entry);
                    }
                }
                gimli::constants::DW_TAG_structure_type
                | gimli::constants::DW_TAG_class_type
                | gimli::constants::DW_TAG_union_type
                | gimli::constants::DW_TAG_enumeration_type
                | gimli::constants::DW_TAG_typedef => {
                    if let Some(name) = self.extract_name(self.dwarf, unit, entry)? {
                        let is_decl = match entry.attr(gimli::constants::DW_AT_declaration)? {
                            Some(attr) => matches!(attr.value(), gimli::AttributeValue::Flag(true)),
                            None => false,
                        };
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
                        };
                        shard.types.entry(name).or_default().push(index_entry);
                    }
                }
                _ => {}
            }
            tag_stack.push(entry.tag());
        }
        Ok(shard)
    }
    pub fn new(dwarf: &'a gimli::Dwarf<EndianArcSlice<LittleEndian>>) -> Self {
        Self { dwarf }
    }

    fn extract_attr_string(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        attr_value: gimli::AttributeValue<EndianArcSlice<LittleEndian>>,
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
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<String>> {
        // Prefer local DW_AT_name
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_name)? {
            if let Ok(name) = dwarf.attr_string(unit, attr.value()) {
                if let Ok(s_str) = name.to_string_lossy() {
                    return Ok(Some(s_str.into_owned()));
                }
            }
        }

        // Fall back to DW_AT_specification / DW_AT_abstract_origin to resolve name
        // Common for globals defined in .c and declared in headers: definition DIE refers to declaration DIE for the name
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_specification)? {
            if let Some(n) = Self::resolve_name_via_ref(dwarf, unit, attr.value())? {
                return Ok(Some(n));
            }
        }
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_abstract_origin)? {
            if let Some(n) = Self::resolve_name_via_ref(dwarf, unit, attr.value())? {
                return Ok(Some(n));
            }
        }

        Ok(None)
    }

    fn resolve_name_via_ref(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        value: gimli::AttributeValue<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<String>> {
        match value {
            gimli::AttributeValue::UnitRef(uoff) => {
                if let Ok(spec_entry) = unit.entry(uoff) {
                    if let Some(attr) = spec_entry.attr(gimli::constants::DW_AT_name)? {
                        if let Ok(name) = dwarf.attr_string(unit, attr.value()) {
                            if let Ok(s_str) = name.to_string_lossy() {
                                return Ok(Some(s_str.into_owned()));
                            }
                        }
                    }
                }
            }
            gimli::AttributeValue::DebugInfoRef(_dioff) => {
                // Cross-unit specification is rare for our use cases; skip to keep fast path simple
                // and avoid heavy cross-CU resolution here.
            }
            _ => {}
        }
        Ok(None)
    }

    fn extract_linkage_name(
        &self,
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<(String, bool)>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_linkage_name)? {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_MIPS_linkage_name)? {
            if let Some(name) = Self::extract_attr_string(dwarf, unit, attr.value())? {
                return Ok(Some((name, true)));
            }
        }
        Ok(None)
    }

    fn extract_inline_flag(
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_inline)? {
            if let gimli::AttributeValue::Inline(inline_attr) = attr.value() {
                return Ok(inline_attr == gimli::DW_INL_inlined
                    || inline_attr == gimli::DW_INL_declared_inlined);
            }
        }
        Ok(false)
    }

    fn resolve_function_metadata(
        &self,
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
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

        metadata.is_inline = Self::extract_inline_flag(entry)?;

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_external)? {
            if let gimli::AttributeValue::Flag(flag) = attr.value() {
                metadata.is_external = Some(flag);
            }
        }

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
            metadata.is_inline |= origin_metadata.is_inline;
            if metadata.is_external.is_none() {
                metadata.is_external = origin_metadata.is_external;
            }
            metadata.is_linkage_name |= origin_metadata.is_linkage_name;
            Ok(())
        };

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_abstract_origin)? {
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

        if let Some(attr) = entry.attr(gimli::constants::DW_AT_specification)? {
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

    fn is_static_symbol(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_external)? {
            if let gimli::AttributeValue::Flag(is_external) = attr.value() {
                return Ok(!is_external);
            }
        }
        Ok(true)
    }

    fn is_declaration(
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<bool> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_declaration)? {
            if let gimli::AttributeValue::Flag(is_decl) = attr.value() {
                return Ok(is_decl);
            }
        }
        Ok(false)
    }

    /// Extract all address ranges from DIE (for functions)
    /// Supports DW_AT_low_pc/high_pc and DW_AT_ranges (returns all ranges)
    fn extract_address_ranges(
        &self,
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<Vec<(u64, u64)>> {
        // Use RangeExtractor for unified logic
        RangeExtractor::extract_all_ranges(entry, unit, dwarf)
    }

    /// Extract variable address from DIE (DW_AT_location)
    /// Supports direct Addr and simple Exprloc with DW_OP_addr or constant-as-address
    fn extract_variable_address(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<u64>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_location)? {
            match attr.value() {
                gimli::AttributeValue::Addr(a) => return Ok(Some(a)),
                gimli::AttributeValue::Exprloc(expr) => {
                    // Fast-parse the expression to detect absolute address
                    let mut e = gimli::Expression(expr.0);
                    // Scan operations; accept first absolute address
                    while let Ok(op) = gimli::Operation::parse(&mut e.0, unit.encoding()) {
                        match op {
                            gimli::Operation::Address { address } => return Ok(Some(address)),
                            gimli::Operation::UnsignedConstant { value } => {
                                // If expression is a single unsigned constant and not stack_value,
                                // DWARF interprets it as memory location (address). We cannot
                                // easily know if there will be a StackValue later without full scan.
                                // Do a conservative approach: if there are no more operations, treat as address.
                                let next = gimli::Operation::parse(&mut e.0, unit.encoding());
                                if next.is_err() {
                                    return Ok(Some(value));
                                }
                            }
                            _ => {}
                        }
                    }
                }
                gimli::AttributeValue::LocationListsRef(offs) => {
                    if let Ok(mut locations) = self
                        .dwarf
                        .locations(unit, gimli::LocationListsOffset(offs.0))
                    {
                        while let Ok(Some(loc)) = locations.next() {
                            // Try to parse this entry's expression and see if it's a constant address
                            let mut e = gimli::Expression(loc.data.0);
                            while let Ok(op) = gimli::Operation::parse(&mut e.0, unit.encoding()) {
                                match op {
                                    gimli::Operation::Address { address } => {
                                        return Ok(Some(address))
                                    }
                                    gimli::Operation::UnsignedConstant { value } => {
                                        // Heuristic: treat single-constant expression as address
                                        let next =
                                            gimli::Operation::parse(&mut e.0, unit.encoding());
                                        if next.is_err() {
                                            return Ok(Some(value));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                gimli::AttributeValue::SecOffset(off) => {
                    if let Ok(mut locations) =
                        self.dwarf.locations(unit, gimli::LocationListsOffset(off))
                    {
                        while let Ok(Some(loc)) = locations.next() {
                            let mut e = gimli::Expression(loc.data.0);
                            while let Ok(op) = gimli::Operation::parse(&mut e.0, unit.encoding()) {
                                match op {
                                    gimli::Operation::Address { address } => {
                                        return Ok(Some(address))
                                    }
                                    gimli::Operation::UnsignedConstant { value } => {
                                        let next =
                                            gimli::Operation::parse(&mut e.0, unit.encoding());
                                        if next.is_err() {
                                            return Ok(Some(value));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(None)
    }

    fn extract_entry_pc(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
    ) -> Result<Option<u64>> {
        if let Some(attr) = entry.attr(gimli::constants::DW_AT_entry_pc)? {
            if let gimli::AttributeValue::Addr(addr) = attr.value() {
                return Ok(Some(addr));
            }
        }
        Ok(None)
    }

    // Additional helper methods for GDB-style cooked index

    fn is_main_function(
        &self,
        entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
        name: &str,
    ) -> Result<bool> {
        // Check for DW_AT_main_subprogram attribute
        if entry
            .attr(gimli::constants::DW_AT_main_subprogram)?
            .is_some()
        {
            return Ok(true);
        }

        // Also check common main function names
        Ok(name == "main" || name == "_main")
    }

    fn extract_language(
        &self,
        _dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> Option<gimli::DwLang> {
        // Try to get language from compilation unit
        let mut entries = unit.entries();
        if let Ok(Some((_, cu_entry))) = entries.next_dfs() {
            if cu_entry.tag() == gimli::constants::DW_TAG_compile_unit {
                if let Ok(Some(lang_attr)) = cu_entry.attr(gimli::constants::DW_AT_language) {
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
        let mut headers: Vec<gimli::UnitHeader<EndianArcSlice<LittleEndian>>> = Vec::new();
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
        let mut headers: Vec<gimli::UnitHeader<EndianArcSlice<LittleEndian>>> = Vec::new();
        let mut units = self.dwarf.units();
        while let Ok(Some(h)) = units.next() {
            headers.push(h);
        }

        let mut functions: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        let mut variables: HashMap<String, Vec<IndexEntry>> = HashMap::new();
        let mut types: HashMap<String, Vec<IndexEntry>> = HashMap::new();

        // Always process in parallel at CU granularity, and propagate per-CU errors
        let shard_results: Vec<Result<InfoShard>> = headers
            .into_par_iter()
            .map(|header| -> Result<InfoShard> {
                match header.offset() {
                    gimli::UnitSectionOffset::DebugInfoOffset(unit_off) => {
                        let unit = self.dwarf.unit(header)?;
                        let cu_lang = self.extract_language(self.dwarf, &unit);
                        self.process_unit_shard(&unit, unit_off, cu_lang)
                    }
                    _ => Ok(InfoShard::default()),
                }
            })
            .collect();

        for sr in shard_results {
            let shard = sr?;
            for (k, mut v) in shard.functions {
                functions.entry(k).or_default().append(&mut v);
            }
            for (k, mut v) in shard.variables {
                variables.entry(k).or_default().append(&mut v);
            }
            for (k, mut v) in shard.types {
                types.entry(k).or_default().append(&mut v);
            }
        }

        // Stabilize entry order for determinism: sort by (unit_offset, die_offset)
        let sort_entries = |m: &mut HashMap<String, Vec<IndexEntry>>| {
            for vec in m.values_mut() {
                vec.sort_by(|a, b| {
                    let ka = (a.unit_offset.0, a.die_offset.0);
                    let kb = (b.unit_offset.0, b.die_offset.0);
                    ka.cmp(&kb)
                });
            }
        };
        sort_entries(&mut functions);
        sort_entries(&mut variables);
        sort_entries(&mut types);

        let functions_count = functions.len();
        let variables_count = variables.len();
        let mut lightweight_index =
            LightweightIndex::from_builder_data(functions, variables, types);
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
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        line_program: &gimli::IncompleteLineProgram<EndianArcSlice<LittleEndian>>,
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
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let (_, entry) = entries.next_dfs().ok()??;

        if let Ok(Some(name_attr)) = entry.attr_value(gimli::constants::DW_AT_name) {
            if let Ok(name) = dwarf.attr_string(unit, name_attr) {
                if let Ok(s_str) = name.to_string_lossy() {
                    return Some(s_str.into_owned());
                }
            }
        }

        None
    }

    fn extract_comp_dir_from_dwarf(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
    ) -> Option<String> {
        let mut entries = unit.entries();
        let (_, entry) = entries.next_dfs().ok()??;

        if let Ok(Some(comp_dir_attr)) = entry.attr_value(gimli::constants::DW_AT_comp_dir) {
            if let Ok(comp_dir) = dwarf.attr_string(unit, comp_dir_attr) {
                if let Ok(s_str) = comp_dir.to_string_lossy() {
                    return Some(s_str.into_owned());
                }
            }
        }

        None
    }

    fn extract_source_file_static(
        dwarf: &gimli::Dwarf<EndianArcSlice<LittleEndian>>,
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        file_index: u64,
        file_entry: &gimli::FileEntry<EndianArcSlice<LittleEndian>>,
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

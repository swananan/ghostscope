//! Single module DWARF data management (simplified and restructured)

/// Constants for intelligent file selection scoring
mod file_selection_scoring {
    /// Search range in bytes when looking for alternative source file entries
    pub const SEARCH_RANGE_BYTES: u64 = 100;

    /// Strong preference for non-header files (*.c, *.cpp, *.rs vs *.h, *.hpp)
    pub const NON_HEADER_BONUS: i32 = 1000;

    /// Moderate preference when compilation unit filename matches source filename
    pub const COMPILATION_UNIT_MATCH_BONUS: i32 = 500;

    /// Preference for non-system paths (not in /usr/, /lib/)
    pub const NON_SYSTEM_PATH_BONUS: i32 = 200;

    /// Preference for statement boundaries (is_stmt = true)
    pub const STATEMENT_BOUNDARY_BONUS: i32 = 100;

    /// Heavy penalty for entries without resolvable file paths
    pub const NO_PATH_PENALTY: i32 = -1000;
}

use crate::{
    binary::{empty_dwarf_reader, try_load_debug_file, DwarfData, DwarfReader, MappedFile},
    core::{mapping::ModuleMapping, GlobalVariableInfo, Result, SectionType, SourceLocation},
    index::{
        BlockIndex, BlockIndexBuilder, CfiIndex, FunctionBlocks, LightweightIndex,
        LineMappingTable, ScopedFileIndexManager, TypeNameIndex, VarRef,
    },
    parser::{CompilationUnit, ExpressionEvaluator, SourceFile},
    resolver::{ChainSpec, OnDemandResolver},
    semantics::{
        range_contains_pc, resolve_attr_with_unit_origins, resolve_name_with_origins,
        resolve_origin_entry,
    },
};
use gimli::Reader;
use object::{Object, ObjectSection, ObjectSegment};
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Instant,
};

// Clippy: factor complex HashMap<String, Vec<usize>> type into an alias
type NameIndex = HashMap<String, Vec<usize>>;

#[derive(Debug, Default)]
struct DemangledNameMaps {
    function_map: NameIndex,
    function_leaf_map: NameIndex,
    variable_map: NameIndex,
    variable_leaf_map: NameIndex,
}

#[derive(Debug)]
struct DemangledMapEntry {
    idx: usize,
    tag: gimli::DwTag,
    full: Option<String>,
    full_normalized: Option<String>,
    leaf: String,
    leaf_normalized: Option<String>,
}

/// Complete DWARF data for a single module
#[derive(Debug)]
pub(crate) struct ModuleData {
    /// Module mapping info (from proc mapping)
    module_mapping: ModuleMapping,
    /// Lightweight index (startup time)
    lightweight_index: LightweightIndex,
    /// Line mapping table (address→line lookup)
    line_mapping: LineMappingTable,
    /// Lightweight scoped file index manager (primary file management)
    scoped_file_manager: ScopedFileIndexManager,
    /// Compilation unit metadata (base dir, include dirs, file list)
    compilation_units: HashMap<String, CompilationUnit>,
    /// CFI index for CFA lookup
    cfi_index: Option<CfiIndex>,
    /// On-demand resolver (for detailed parsing)
    resolver: OnDemandResolver,
    /// Memory mapped file for DWARF data (may be debug file via .gnu_debuglink)
    _dwarf_mapped_file: std::sync::Arc<MappedFile>,
    /// Memory mapped file for binary (used for vaddr to file offset calculation)
    _binary_mapped_file: std::sync::Arc<MappedFile>,
    /// Per-function block/variable index (blockvector-like)
    block_index: BlockIndex,
    /// Type name index for cross-CU completion
    type_name_index: TypeNameIndex,
    /// Demangled name maps for flexible lookups, built eagerly during module load.
    demangled_maps: DemangledNameMaps,
}

impl ModuleData {
    // Find the innermost inline node containing the PC
    fn find_innermost_inline_node(func: &FunctionBlocks, pc: u64) -> Option<usize> {
        let path = func.block_path_for_pc(pc);
        path.iter()
            .rev()
            .find(|&&idx| func.nodes[idx].entry_pc.is_some())
            .copied()
    }

    // Try to apply call-site parameter mapping for an inline node at a given PC
    fn try_apply_call_site_mapping(
        &self,
        func: &FunctionBlocks,
        inline_idx: usize,
        address: u64,
        vars: &mut [crate::VariableWithEvaluation],
        _var_refs: &[VarRef],
        get_cfa: &dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>,
    ) {
        let dwarf = self.resolver.dwarf_ref();
        let header = match dwarf.unit_header(func.cu_offset) {
            Ok(h) => h,
            Err(_) => return,
        };
        let unit = match dwarf.unit(header) {
            Ok(u) => u,
            Err(_) => return,
        };
        let node = &func.nodes[inline_idx];
        let inline_die = match node.die_offset.and_then(|off| unit.entry(off).ok()) {
            Some(e) => e,
            None => return,
        };
        if inline_die.tag() != gimli::constants::DW_TAG_inlined_subroutine {
            return;
        }
        // Get abstract origin to determine parameter order and names
        let origin_off = match inline_die.attr_value(gimli::constants::DW_AT_abstract_origin) {
            Some(gimli::AttributeValue::UnitRef(o)) => o,
            _ => return,
        };

        // Collect origin formal parameter names in order
        let mut origin_param_names: Vec<String> = Vec::new();
        if let Ok(mut it) = unit.entries_at_offset(origin_off) {
            let _ = it.next_entry();
            while let Ok(Some(e)) = it.next_dfs() {
                if e.depth() <= 0 {
                    break;
                }
                if e.depth() > 1 {
                    continue;
                }
                if e.tag() == gimli::constants::DW_TAG_formal_parameter {
                    if let Some(a) = e.attr(gimli::constants::DW_AT_name) {
                        if let Ok(s) = dwarf.attr_string(&unit, a.value()) {
                            if let Ok(ss) = s.to_string_lossy() {
                                origin_param_names.push(ss.into_owned());
                            }
                        }
                    }
                }
            }
        }
        if origin_param_names.is_empty() {
            return;
        }

        // Search call_site(_parameter) under the inline node
        let mut param_values: Vec<Option<crate::core::EvaluationResult>> =
            vec![None; origin_param_names.len()];
        if let Ok(mut it) = unit.entries_at_offset(node.die_offset.unwrap()) {
            let _ = it.next_entry();
            while let Ok(Some(e)) = it.next_dfs() {
                if e.depth() <= 0 {
                    break;
                }
                if e.depth() > 1 {
                    continue;
                }
                if e.tag() == gimli::constants::DW_TAG_call_site
                    || e.tag() == gimli::constants::DW_TAG_GNU_call_site
                {
                    // Iterate its children for parameters
                    if let Ok(mut pit) = unit.entries_at_offset(e.offset()) {
                        let _ = pit.next_entry();
                        while let Ok(Some(pe)) = pit.next_dfs() {
                            if pe.depth() <= 0 {
                                break;
                            }
                            if pe.depth() > 1 {
                                continue;
                            }
                            if pe.tag() == gimli::constants::DW_TAG_call_site_parameter
                                || pe.tag() == gimli::constants::DW_TAG_GNU_call_site_parameter
                            {
                                // Prefer DW_AT_location (exprloc); fallback to DW_AT_const_value
                                let loc_attr = pe.attr_value(gimli::constants::DW_AT_location);
                                if let Some(gimli::AttributeValue::Exprloc(expr)) = loc_attr {
                                    if let Ok(ev) = ExpressionEvaluator::parse_expression_in_unit(
                                        expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                        &unit,
                                        dwarf,
                                        address,
                                        Some(get_cfa),
                                    ) {
                                        if let Some(slot) =
                                            param_values.iter_mut().find(|v| v.is_none())
                                        {
                                            *slot = Some(ev);
                                        }
                                    }
                                } else if let Some(cv) =
                                    pe.attr_value(gimli::constants::DW_AT_const_value)
                                {
                                    use crate::core::DirectValueResult as DV;
                                    use crate::core::EvaluationResult as ER;
                                    let ev = match cv {
                                        gimli::AttributeValue::Udata(u) => {
                                            ER::DirectValue(DV::Constant(u as i64))
                                        }
                                        gimli::AttributeValue::Sdata(s) => {
                                            ER::DirectValue(DV::Constant(s))
                                        }
                                        gimli::AttributeValue::Data1(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data2(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data4(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Data8(d) => {
                                            ER::DirectValue(DV::Constant(d as i64))
                                        }
                                        gimli::AttributeValue::Block(b) => match b.to_slice() {
                                            Ok(bytes) => {
                                                ER::DirectValue(DV::ImplicitValue(bytes.to_vec()))
                                            }
                                            Err(_) => ER::Optimized,
                                        },
                                        _ => ER::Optimized,
                                    };
                                    if let Some(slot) =
                                        param_values.iter_mut().find(|v| v.is_none())
                                    {
                                        *slot = Some(ev);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if param_values.iter().all(|v| v.is_none()) {
            return;
        }

        // Apply recovered values to vars by matching name to origin parameter names
        for v in vars.iter_mut() {
            if !v.is_parameter {
                continue;
            }
            if !matches!(
                v.evaluation_result,
                crate::core::EvaluationResult::Optimized
            ) {
                continue;
            }
            let name = v.name.as_str();
            if let Some(pos) = origin_param_names.iter().position(|n| n == name) {
                if let Some(Some(ev)) = param_values.get(pos) {
                    v.evaluation_result = ev.clone();
                }
            }
        }
    }
    /// Parallel loading: debug_info || debug_line || CFI simultaneously
    pub(crate) async fn load_parallel(
        module_mapping: ModuleMapping,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
    ) -> Result<Self> {
        tracing::info!("Parallel loading for: {}", module_mapping.path.display());
        Self::load_internal_parallel(module_mapping, debug_search_paths, allow_loose_debug_match)
            .await
    }

    /// Resolve a struct/class type by name using only indexes + shallow resolution (no scanning).
    ///
    /// Preferred order:
    ///  1) aggregate definition by name (struct/class) via TypeNameIndex
    ///  2) typedef by name -> follow DW_AT_type once -> shallow resolve underlying aggregate
    ///     No fallback scanning; returns None on miss.
    pub(crate) fn resolve_struct_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        // 1) Try aggregate definition first
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_structure_type)
            .or_else(|| {
                self.type_name_index
                    .find_aggregate_definition(name, gimli::constants::DW_TAG_class_type)
            })
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        // 2) Try typedef by name, then peel one layer to underlying type and shallow resolve
        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.resolver.dwarf_ref();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        // As a last resort, return shallow typedef itself
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    /// Resolve a union type by name using only indexes + shallow resolution.
    pub(crate) fn resolve_union_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_union_type)
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.resolver.dwarf_ref();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    /// Resolve an enum type by name using only indexes + shallow resolution.
    pub(crate) fn resolve_enum_type_shallow_by_name(
        &mut self,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        if let Some(loc) = self
            .type_name_index
            .find_aggregate_definition(name, gimli::constants::DW_TAG_enumeration_type)
        {
            return self.detailed_shallow_type(loc.cu_offset, loc.die_offset);
        }

        if let Some(td) = self.type_name_index.find_typedef(name) {
            let dwarf = self.resolver.dwarf_ref();
            if let Ok(header) = dwarf.unit_header(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Some(gimli::AttributeValue::UnitRef(under)) =
                            entry.attr_value(gimli::DW_AT_type)
                        {
                            return self.detailed_shallow_type(td.cu_offset, under);
                        }
                        return crate::parser::DetailedParser::resolve_type_shallow_at_offset(
                            dwarf,
                            &unit,
                            td.die_offset,
                        );
                    }
                }
            }
        }

        None
    }

    /// Parallel internal load implementation - true parallelism for debug_info || debug_line || CFI
    async fn load_internal_parallel(
        module_mapping: ModuleMapping,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
    ) -> Result<Self> {
        let load_started_at = Instant::now();
        tracing::debug!(
            "Loading module in parallel: {}",
            module_mapping.path.display()
        );

        // Memory map the binary file
        let binary_mapped = std::sync::Arc::new(MappedFile::open(&module_mapping.path)?);

        // Try to load DWARF sections from the binary file first
        let dwarf_result = Self::load_dwarf_sections(&binary_mapped);

        // Check if we need to search for separate debug file
        let (dwarf, mapped_file_for_dwarf) = match dwarf_result {
            Ok(dwarf_data) => {
                // Check if we actually have debug info sections
                if Self::has_debug_info(&dwarf_data) {
                    tracing::debug!(
                        "Found debug info in binary: {}",
                        module_mapping.path.display()
                    );
                    (
                        std::sync::Arc::new(dwarf_data),
                        std::sync::Arc::clone(&binary_mapped),
                    )
                } else {
                    // No debug info, try to find separate debug file
                    tracing::info!(
                        "No debug info in binary, searching for .gnu_debuglink: {}",
                        module_mapping.path.display()
                    );
                    match try_load_debug_file(
                        &module_mapping.path,
                        debug_search_paths,
                        allow_loose_debug_match,
                    )? {
                        Some(debug_mapped) => {
                            tracing::info!(
                                "Loading DWARF from separate debug file: {}",
                                debug_mapped.path.display()
                            );
                            let debug_mapped = std::sync::Arc::new(debug_mapped);
                            let debug_dwarf = Self::load_dwarf_sections(&debug_mapped)?;
                            (std::sync::Arc::new(debug_dwarf), debug_mapped)
                        }
                        None => {
                            // No debug file found, use original (possibly empty) dwarf
                            tracing::warn!(
                                "No separate debug file found for: {}",
                                module_mapping.path.display()
                            );
                            (
                                std::sync::Arc::new(dwarf_data),
                                std::sync::Arc::clone(&binary_mapped),
                            )
                        }
                    }
                }
            }
            Err(e) => {
                tracing::error!(
                    "Failed to parse DWARF from {}: {}",
                    module_mapping.path.display(),
                    e
                );
                return Err(e);
            }
        };

        // Use mapped_file_for_dwarf which is either binary or debug file
        let mapped_file = mapped_file_for_dwarf;

        tracing::debug!(
            "Starting parallel DWARF parsing with true debug_line || debug_info parallelism..."
        );

        // Parse DWARF components with reduced blocking threads:
        // - One spawn_blocking orchestrates debug_line || debug_info via rayon::join
        // - One spawn_blocking builds CFI
        let (pair_result, cfi_index_result) = tokio::try_join!(
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<(crate::parser::LineParseResult, crate::parser::DebugParseResult)> {
                    let (line_res, info_res) = rayon::join(
                        || {
                            let parser = crate::parser::DwarfParser::new(&dwarf);
                            parser.parse_line_info(&module_path)
                        },
                        || {
                            let parser = crate::parser::DwarfParser::new(&dwarf);
                            parser.parse_debug_info(&module_path)
                        },
                    );
                    match (line_res, info_res) {
                        (Ok(l), Ok(i)) => Ok((l, i)),
                        (Err(e), _) => Err(e),
                        (_, Err(e)) => Err(e),
                    }
                }
            }),
            // Parse CFI independently from binary file (not debug file)
            tokio::task::spawn_blocking({
                let binary_for_cfi = std::sync::Arc::clone(&binary_mapped);
                let module_path = module_mapping.path.clone();
                move || -> Result<Option<CfiIndex>> {
                    match CfiIndex::from_mapped_file(binary_for_cfi) {
                        Ok(cfi) => {
                            tracing::info!(
                                "CFI index initialized successfully for {}",
                                module_path.display()
                            );
                            Ok(Some(cfi))
                        }
                        Err(e) => {
                            tracing::warn!(
                                "Failed to initialize CFI index for {}: {}",
                                module_path.display(),
                                e
                            );
                            Ok(None)
                        }
                    }
                }
            })
        )?;

        // Unwrap the spawn_blocking results
        let (line_result, info_result) = pair_result?;
        let cfi_index = cfi_index_result?;

        // Assemble parallel results into unified result
        let parse_result = crate::parser::DwarfParser::combine_parallel_results(
            line_result,
            info_result,
            module_mapping.path.to_string_lossy().to_string(),
        );
        let parse_elapsed_ms = load_started_at.elapsed().as_millis();

        // Optionally log CFI stats to ensure associated APIs are exercised
        if let Some(ref cfi) = cfi_index {
            let stats = cfi.get_stats();
            tracing::info!(
                "CFI stats: has_eh_frame_hdr={}, fast_lookup={}",
                stats.has_eh_frame_hdr,
                stats.has_fast_lookup
            );
            if cfi.has_fast_lookup() {
                tracing::debug!("CFI fast lookup enabled");
            }
        }

        let crate::parser::DwarfParseResult {
            lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units,
            stats,
        } = parse_result;
        let index_started_at = Instant::now();
        let (lightweight_index, type_name_index, demangled_maps) =
            tokio::task::spawn_blocking(move || {
                let (type_name_index, demangled_maps) = rayon::join(
                    || TypeNameIndex::build_from_lightweight(&lightweight_index),
                    || Self::build_demangled_maps(&lightweight_index),
                );
                (lightweight_index, type_name_index, demangled_maps)
            })
            .await?;
        let type_index_arc = std::sync::Arc::new(type_name_index.clone());

        // Create resolver with parsed data and type index
        let resolver = OnDemandResolver::new_with_type_index(
            std::sync::Arc::try_unwrap(dwarf)
                .map_err(|_| anyhow::anyhow!("Failed to unwrap DWARF Arc"))?,
            type_index_arc,
        );

        // Determine load state based on parallel loading results
        let mut warnings = Vec::new();
        if cfi_index.is_none() {
            warnings.push("CFI index failed to initialize".to_string());
        }

        if !warnings.is_empty() {
            for warning in &warnings {
                tracing::warn!(
                    "Module {} loaded with warning: {}",
                    module_mapping.path.display(),
                    warning
                );
            }
        }

        let state_label = if warnings.is_empty() {
            "Success"
        } else {
            "PartialSuccess"
        };
        let index_elapsed_ms = index_started_at.elapsed().as_millis();

        let module = Self {
            module_mapping: module_mapping.clone(),
            lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units,
            cfi_index,
            resolver,
            block_index: BlockIndex::new(),
            type_name_index,
            _dwarf_mapped_file: mapped_file,
            _binary_mapped_file: binary_mapped,
            demangled_maps,
        };

        tracing::info!(
            "True parallel loading completed for {}: {} functions, {} variables, {} line entries, {} files (state: {}, parse_ms: {}, index_ms: {}, total_ms: {})",
            module.module_mapping.path.display(),
            stats.total_functions,
            stats.total_variables,
            stats.total_line_entries,
            stats.total_files,
            state_label,
            parse_elapsed_ms,
            index_elapsed_ms,
            load_started_at.elapsed().as_millis()
        );

        Ok(module)
    }

    /// Check if DWARF data contains debug information
    ///
    /// Returns true if .debug_info section has at least one compilation unit
    fn has_debug_info(dwarf: &DwarfData) -> bool {
        // Try to get the first unit header - need to check if it actually exists
        match dwarf.units().next() {
            Ok(Some(_)) => true, // Has at least one unit
            _ => false,          // No units or error
        }
    }

    /// Load DWARF sections using gimli over mmap-backed readers.
    fn load_dwarf_sections(file_data: &std::sync::Arc<MappedFile>) -> Result<DwarfData> {
        // Parse object file
        let object = file_data.parse_object()?;

        // Load DWARF sections
        let load_section = |id: gimli::SectionId| -> Result<_> {
            if let Some(section) = object.section_by_name(id.name()) {
                // Get section file range
                if let Some((start, size)) = section.file_range() {
                    MappedFile::dwarf_reader_range(std::sync::Arc::clone(file_data), start, size)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Invalid DWARF section range for {}", id.name())
                        })
                } else {
                    // Section has no file range
                    Ok(empty_dwarf_reader())
                }
            } else {
                // Return empty slice if section not found
                Ok(empty_dwarf_reader())
            }
        };

        let dwarf = gimli::Dwarf::load(load_section)?;
        Ok(dwarf)
    }

    /// Convert a virtual address (DWARF PC) to an ELF file offset using PT_LOAD segments
    /// Returns None if no containing segment is found
    pub(crate) fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        // Use binary file (not debug file) for segment calculation
        if self._binary_mapped_file.data.is_empty() {
            return None;
        }
        let data: &[u8] = &self._binary_mapped_file.data;
        let obj = match object::File::parse(data) {
            Ok(f) => f,
            Err(_) => return None,
        };

        for seg in obj.segments() {
            let svaddr = seg.address();
            let ssize = seg.size();
            if ssize == 0 {
                continue;
            }
            if vaddr >= svaddr && vaddr < svaddr + ssize {
                let (file_off, _file_sz) = seg.file_range();
                let delta = vaddr - svaddr;
                return Some(file_off.saturating_add(delta));
            }
        }

        None
    }

    /// Lookup function addresses by name
    pub(crate) fn lookup_function_addresses(&self, name: &str) -> Vec<u64> {
        tracing::debug!("ModuleData: looking up function '{}'", name);

        // Get function entries from lightweight index
        let entries = self.lightweight_index.find_dies_by_function_name(name);
        let mut addresses = Vec::new();

        for entry in entries {
            addresses.extend(self.compute_addresses_for_entry(entry));
        }

        tracing::debug!(
            "ModuleData: function '{}' resolved to {} addresses: {:?}",
            name,
            addresses.len(),
            addresses
        );
        addresses.sort_unstable();
        addresses.dedup();
        addresses
    }

    /// Get all variables visible at the given address with EvaluationResult
    pub(crate) fn get_all_variables_at_address(
        &mut self,
        address: u64,
    ) -> Result<Vec<crate::VariableWithEvaluation>> {
        let t0 = Instant::now();
        let mut built_funcs: usize = 0;
        let mut build_ms: u128 = 0;
        tracing::info!(
            "DWARF:get_vars module='{}' addr=0x{:x}",
            self.module_mapping.path.display(),
            address
        );
        // Try block index fast path. If no function yet, build lazily for the CU containing this address.
        if self.block_index.find_function_by_pc(address).is_none() {
            let b0 = Instant::now();
            if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                let builder = BlockIndexBuilder::new(self.resolver.dwarf_ref());
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    tracing::info!(
                        "BlockIndex: built {} functions for CU {:?}",
                        funcs.len(),
                        cu_off
                    );
                    built_funcs += funcs.len();
                    self.block_index.add_functions(funcs);
                }
            }
            build_ms = b0.elapsed().as_millis();
        }

        if let Some(func) = self.block_index.find_function_by_pc(address) {
            let vars_in_func = func.nodes.iter().map(|n| n.variables.len()).sum::<usize>();
            tracing::info!(
                "DWARF:get_vars fast_path_hit addr=0x{:x} vars_in_func={} built_funcs={} build_ms={} total_ms={}",
                address,
                vars_in_func,
                built_funcs,
                build_ms,
                t0.elapsed().as_millis()
            );
            // Precompute preferred frame base: DW_AT_frame_base first, fallback to CFI CFA
            let fb_result = self.compute_frame_base_for_pc(func, address);
            let cfa_result = if fb_result.is_none() {
                if self.cfi_index.is_some() {
                    match self.get_cfa_result(address) {
                        Ok(Some(cfa)) => Some(cfa),
                        _ => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };
            let get_cfa_closure = move |addr: u64| -> Result<Option<crate::core::CfaResult>> {
                if addr == address {
                    if let Some(fb) = fb_result.clone() {
                        return Ok(Some(fb));
                    }
                    return Ok(cfa_result.clone());
                }
                Ok(None)
            };
            let var_refs = func.variables_at_pc(address);
            if !var_refs.is_empty() {
                let items: Vec<(gimli::DebugInfoOffset, gimli::UnitOffset)> = var_refs
                    .iter()
                    .map(|v| (v.cu_offset, v.die_offset))
                    .collect();
                let mut vars = self.resolver.resolve_variables_by_offsets_at_address(
                    address,
                    &items,
                    Some(&get_cfa_closure),
                )?;

                // Attach shallow type info for simple path variables when missing
                let dwarf_ref = self.resolver.dwarf_ref();
                for (idx, var_out) in vars.iter_mut().enumerate() {
                    if var_out.dwarf_type.is_none() {
                        let vr = &var_refs[idx];
                        if let Ok(header) = dwarf_ref.unit_header(vr.cu_offset) {
                            if let Ok(unit) = dwarf_ref.unit(header) {
                                if let Ok(entry) = unit.entry(vr.die_offset) {
                                    let planner = crate::planner::AccessPlanner::new(dwarf_ref);
                                    if let Ok(Some(type_loc)) =
                                        planner.resolve_type_ref_with_origins_public(&entry, &unit)
                                    {
                                        if let Some(ty) = self.detailed_shallow_type(
                                            type_loc.cu_off,
                                            type_loc.die_off,
                                        ) {
                                            var_out.type_name = ty.type_name();
                                            var_out.dwarf_type = Some(ty);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Call-site parameter mapping for inline: if inline parameters are optimized at this PC,
                // try to recover their value from DW_TAG_call_site/_parameter under the inline node.
                if let Some(inline_idx) = Self::find_innermost_inline_node(func, address) {
                    self.try_apply_call_site_mapping(
                        func,
                        inline_idx,
                        address,
                        &mut vars,
                        &var_refs,
                        &get_cfa_closure,
                    );
                }

                // Prefer non-optimized duplicates: if multiple entries share the same name,
                // keep the one with the most informative EvaluationResult.
                // Minimal de-dup for parameters: keep first occurrence per name.
                let mut seen_param_names: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                let mut filtered: Vec<crate::VariableWithEvaluation> =
                    Vec::with_capacity(vars.len());
                for v in vars.into_iter() {
                    if v.is_parameter {
                        if seen_param_names.insert(v.name.clone()) {
                            filtered.push(v);
                        } else {
                            // drop duplicate parameter with same name
                        }
                    } else {
                        filtered.push(v);
                    }
                }

                tracing::info!(
                    "DWARF:get_vars resolved {} vars total_ms={}",
                    filtered.len(),
                    t0.elapsed().as_millis()
                );
                return Ok(filtered);
            }
        }

        // Strict index: do not fallback to scanning
        Err(anyhow::anyhow!(
            "StrictIndex: no function found for address 0x{:x} in block index",
            address
        ))
    }

    /// Plan a chain access (e.g., r.headers_in) and synthesize a VariableWithEvaluation
    pub(crate) fn plan_chain_access(
        &mut self,
        address: u64,
        base_var: &str,
        chain: &[String],
    ) -> Result<Option<crate::VariableWithEvaluation>> {
        let t0 = Instant::now();
        let mut built_funcs: usize = 0;
        let mut build_ms: u128 = 0;
        tracing::info!(
            "DWARF:plan_chain module='{}' addr=0x{:x} base='{}' chain_len={}",
            self.module_mapping.path.display(),
            address,
            base_var,
            chain.len()
        );
        // Build block index lazily and try fast path
        if self.block_index.find_function_by_pc(address).is_none() {
            let b0 = Instant::now();
            let builder = BlockIndexBuilder::new(self.resolver.dwarf_ref());
            // Prefer building only the containing subprogram if we can identify it
            if let Some(func_entry) = self.lightweight_index.find_function_by_address(address) {
                if let Some(fb) =
                    builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
                {
                    self.block_index.add_functions(vec![fb]);
                    built_funcs += 1;
                }
            } else if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                // Fallback: identify CU via fast map and build-for-unit
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    built_funcs += funcs.len();
                    self.block_index.add_functions(funcs);
                }
            }
            build_ms = b0.elapsed().as_millis();
        }

        if let Some(func) = self.block_index.find_function_by_pc(address) {
            // CFA closure as before
            let cfa_result = if self.cfi_index.is_some() {
                match self.get_cfa_result(address) {
                    Ok(Some(cfa)) => Some(cfa),
                    _ => None,
                }
            } else {
                None
            };
            let get_cfa_closure = move |addr: u64| -> Result<Option<crate::core::CfaResult>> {
                if addr == address {
                    Ok(cfa_result.clone())
                } else {
                    Ok(None)
                }
            };

            // Find variable DIE by name among visible vars
            let dwarf = self.resolver.dwarf_ref();
            let header = dwarf.unit_header(func.cu_offset)?;
            let unit = dwarf.unit(header)?;
            let candidates = func.variables_at_pc(address);
            tracing::info!(
                "DWARF:plan_chain fast_path_hit addr=0x{:x} candidates={} built_funcs={} build_ms={}",
                address,
                candidates.len(),
                built_funcs,
                build_ms
            );
            // Log candidate variable names for diagnosis
            let mut cand_names: Vec<String> = Vec::new();
            for v in &candidates {
                let e = unit.entry(v.die_offset)?;
                if let Some(name) = resolve_name_with_origins(dwarf, &unit, &e)? {
                    cand_names.push(name);
                }
            }
            tracing::info!("DWARF:plan_chain candidates_names={:?}", cand_names);

            for v in candidates {
                let e = unit.entry(v.die_offset)?;
                if let Some(n) = resolve_name_with_origins(dwarf, &unit, &e)? {
                    if n == base_var || n.starts_with(&format!("{base_var}@")) {
                        // Chain empty: short-circuit to base variable (avoid heavy type resolution)
                        if chain.is_empty() {
                            let one = vec![(func.cu_offset, v.die_offset)];
                            let t1 = Instant::now();
                            let vars = self.resolver.resolve_variables_by_offsets_at_address(
                                address,
                                &one,
                                Some(&get_cfa_closure),
                            )?;
                            let mut var_opt = vars.into_iter().next();
                            let mut type_ms = 0u128;
                            if let Some(ref mut var0) = var_opt {
                                if var0.dwarf_type.is_none() {
                                    // Resolve base variable type strictly via DWARF type DIE
                                    let dwarf = self.resolver.dwarf_ref();
                                    let header = dwarf.unit_header(func.cu_offset)?;
                                    let unit = dwarf.unit(header)?;
                                    let e = unit.entry(v.die_offset)?;
                                    let planner = crate::planner::AccessPlanner::new(dwarf);
                                    if let Some(type_loc) =
                                        planner.resolve_type_ref_with_origins_public(&e, &unit)?
                                    {
                                        let tstart = Instant::now();
                                        if let Some(ty) = self.detailed_shallow_type(
                                            type_loc.cu_off,
                                            type_loc.die_off,
                                        ) {
                                            type_ms = tstart.elapsed().as_millis();
                                            var0.type_name = ty.type_name();
                                            var0.dwarf_type = Some(ty);
                                        }
                                    }
                                }
                            }
                            tracing::info!(
                                "DWARF:plan_chain var_match='{}' resolve_base_ms={} type_ms={} total_ms={}",
                                n,
                                t1.elapsed().as_millis(),
                                type_ms,
                                t0.elapsed().as_millis()
                            );
                            return Ok(var_opt);
                        }

                        // Non-empty chain: plan from the base variable
                        let t1 = Instant::now();
                        let res = self.resolver.plan_chain_access_from_var(
                            address,
                            func.cu_offset,
                            func.die_offset,
                            v.die_offset,
                            ChainSpec {
                                base: base_var,
                                fields: chain,
                            },
                            Some(&get_cfa_closure),
                        )?;
                        tracing::info!(
                            "DWARF:plan_chain var_match='{}' plan_ms={} total_ms={}",
                            n,
                            t1.elapsed().as_millis(),
                            t0.elapsed().as_millis()
                        );
                        return Ok(res);
                    }
                }
            }
        }
        // Fallback: try planning from a CU-scope global/static variable with the same base name
        // This enables expressions like G_STATE.counter when G_STATE is a global.
        let globals = self.find_global_variables_by_name(base_var);
        if !globals.is_empty() {
            // Try each candidate until one plans successfully
            for info in globals {
                let spec = ChainSpec {
                    base: base_var,
                    fields: chain,
                };
                match self.resolver.plan_chain_access_from_var(
                    address,
                    info.unit_offset,
                    // subprogram_die is unused in planner path; pass the var die offset for logging consistency
                    info.die_offset,
                    info.die_offset,
                    spec,
                    None,
                ) {
                    Ok(Some(v)) => {
                        tracing::info!(
                            "DWARF:plan_chain(global) success base='{}' total_ms={}",
                            base_var,
                            t0.elapsed().as_millis()
                        );
                        return Ok(Some(v));
                    }
                    Ok(None) => continue,
                    Err(e) => {
                        tracing::debug!(
                            "DWARF:plan_chain(global) candidate failed for base='{}': {}",
                            base_var,
                            e
                        );
                        continue;
                    }
                }
            }
        }

        // Strict index: do not fallback further
        let err = anyhow::anyhow!(
            "StrictIndex: no function found for address 0x{:x} or no matching base var '{}' (plan_chain)",
            address,
            base_var
        );
        tracing::info!(
            "DWARF:plan_chain miss addr=0x{:x} built_funcs={} build_ms={} total_ms={} err={}",
            address,
            built_funcs,
            build_ms,
            t0.elapsed().as_millis(),
            err
        );
        Err(err)
    }

    /// Compute static byte offset for a global variable's member chain in this module
    pub(crate) fn compute_global_member_static_offset(
        &mut self,
        cu_off: gimli::DebugInfoOffset,
        var_die: gimli::UnitOffset,
        link_address: u64,
        fields: &[String],
    ) -> Result<Option<(u64, crate::TypeInfo)>> {
        self.resolver
            .compute_member_offset_for_global(0, cu_off, var_die, link_address, fields)
    }

    /// Lookup source location at address (line mapping + file manager)
    pub(crate) fn lookup_source_location(&self, address: u64) -> Option<SourceLocation> {
        // Get all line entries at this exact address to handle overlapping instructions
        let all_line_entries = self.line_mapping.lookup_all_lines_at_address(address);

        if all_line_entries.is_empty() {
            // Fallback to closest address lookup
            if let Some(line_entry) = self.line_mapping.lookup_line(address) {
                return self.create_source_location_from_entry(line_entry);
            }
            return None;
        }

        // Check if we should use alternative file selection for header files
        let best_entry = if all_line_entries.len() == 1 {
            let entry = all_line_entries[0];
            self.find_alternative_source_file(entry).unwrap_or(entry)
        } else {
            // Multiple entries: use smart selection
            self.select_best_line_entry(&all_line_entries)
        };

        self.create_source_location_from_entry(best_entry)
    }

    /// Lightweight classification: determine if the given address is inside an inline instance
    pub(crate) fn is_inline_at(&mut self, address: u64) -> Option<bool> {
        // Ensure block index has the containing function built (lazy build similar to variable lookup)
        if self.block_index.find_function_by_pc(address).is_none() {
            let builder = BlockIndexBuilder::new(self.resolver.dwarf_ref());
            // Prefer building only the containing subprogram if we can identify it via lightweight index
            if let Some(func_entry) = self.lightweight_index.find_function_by_address(address) {
                if let Some(fb) =
                    builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
                {
                    self.block_index.add_functions(vec![fb]);
                }
            } else if let Some(cu_off) = self.lightweight_index.find_cu_by_address(address) {
                if let Some(funcs) = builder.build_for_unit(cu_off) {
                    self.block_index.add_functions(funcs);
                }
            }
        }

        let func = self.block_index.find_function_by_pc(address)?;

        // Find the innermost inline-capable node containing this PC
        if let Some(inline_idx) = Self::find_innermost_inline_node(func, address) {
            // Verify the DIE tag is actually an inlined_subroutine
            let dwarf = self.resolver.dwarf_ref();
            if let Ok(header) = dwarf.unit_header(func.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Some(off) = func.nodes[inline_idx].die_offset {
                        if let Ok(entry) = unit.entry(off) {
                            return Some(
                                entry.tag() == gimli::constants::DW_TAG_inlined_subroutine,
                            );
                        }
                    }
                }
            }
        }

        Some(false)
    }

    /// Find alternative source file when current entry points to header file
    fn find_alternative_source_file<'a>(
        &'a self,
        entry: &'a crate::core::LineEntry,
    ) -> Option<&'a crate::core::LineEntry> {
        // Get the file path for this entry
        let current_file_path = self.get_file_path_for_entry(entry)?;

        // Check if current file is a header
        let is_header = current_file_path.ends_with(".h")
            || current_file_path.ends_with(".hpp")
            || current_file_path.ends_with(".hxx")
            || current_file_path.contains("/include/")
            || current_file_path.contains("/usr/include/");

        if !is_header {
            return None; // Current file is already a source file
        }

        tracing::debug!(
            "find_alternative_source_file: current entry points to header '{}', looking for main source alternative",
            current_file_path
        );

        // Look for entries at nearby addresses that point to main source files
        let search_range = file_selection_scoring::SEARCH_RANGE_BYTES;
        let start_addr = entry.address.saturating_sub(search_range);
        let end_addr = entry.address.saturating_add(search_range);

        // Search through all line entries in the range
        for (addr, candidate_entry) in self.line_mapping.get_entries_in_range(start_addr, end_addr)
        {
            {
                // Skip if same compilation unit (to avoid circular references)
                if candidate_entry.compilation_unit != entry.compilation_unit {
                    continue;
                }

                // Check if this candidate points to a main source file
                if let Some(candidate_file_path) = self.get_file_path_for_entry(candidate_entry) {
                    let is_candidate_header = candidate_file_path.ends_with(".h")
                        || candidate_file_path.ends_with(".hpp")
                        || candidate_file_path.ends_with(".hxx")
                        || candidate_file_path.contains("/include/")
                        || candidate_file_path.contains("/usr/include/");

                    if !is_candidate_header {
                        tracing::debug!(
                            "find_alternative_source_file: found alternative source file '{}' at address 0x{:x}",
                            candidate_file_path, addr
                        );

                        // Create a synthetic entry with the source file but original line number
                        // This is a bit hacky, but it works for our use case
                        return Some(candidate_entry);
                    }
                }
            }
        }

        // Fallback: try to find any main source file in the same compilation unit
        if let Some(cu_file_index) = self
            .scoped_file_manager
            .get_cu_file_index(&entry.compilation_unit)
        {
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    let is_source = full_path.ends_with(".c")
                        || full_path.ends_with(".cpp")
                        || full_path.ends_with(".cc")
                        || full_path.ends_with(".rs")
                        || (full_path.contains(&*entry.compilation_unit)
                            && !full_path.ends_with(".h"));

                    if is_source {
                        tracing::debug!(
                            "find_alternative_source_file: using main source file '{}' from compilation unit",
                            full_path
                        );

                        // Return the original entry - we'll modify the file lookup in create_source_location_from_entry
                        return None; // We'll handle this in the create_source_location_from_entry method
                    }
                }
            }
        }

        None
    }

    /// Select the best line entry from multiple candidates
    fn select_best_line_entry<'a>(
        &self,
        entries: &[&'a crate::core::LineEntry],
    ) -> &'a crate::core::LineEntry {
        if entries.len() == 1 {
            return entries[0];
        }

        tracing::debug!(
            "select_best_line_entry: {} candidates at address 0x{:x}",
            entries.len(),
            entries[0].address
        );

        // Priority rules for file selection:
        // 1. Prefer .c/.cpp/.rs files over .h/.hpp files (main source over headers)
        // 2. Prefer files with compilation_unit name matching filename
        // 3. Prefer longer paths (more specific)
        // 4. Prefer entries with is_stmt=true (statement boundaries)

        let mut best = entries[0];
        let mut best_score = self.score_line_entry(best);

        for &entry in entries.iter().skip(1) {
            let score = self.score_line_entry(entry);
            tracing::debug!(
                "  candidate: {}:{} (stmt={}, score={})",
                self.get_file_path_for_entry(entry)
                    .unwrap_or("unknown".to_string()),
                entry.line,
                entry.is_stmt,
                score
            );

            if score > best_score {
                best = entry;
                best_score = score;
            }
        }

        tracing::debug!(
            "select_best_line_entry: selected {} (score={})",
            self.get_file_path_for_entry(best)
                .unwrap_or("unknown".to_string()),
            best_score
        );

        best
    }

    /// Score a line entry for smart selection (higher is better)
    fn score_line_entry(&self, entry: &crate::core::LineEntry) -> i32 {
        let mut score = 0;

        // Get file path for scoring
        let file_path = match self.get_file_path_for_entry(entry) {
            Some(path) => path,
            None => return file_selection_scoring::NO_PATH_PENALTY,
        };

        // Rule 1: Prefer main source files over headers
        let is_header = file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/");

        if !is_header {
            score += file_selection_scoring::NON_HEADER_BONUS;
        }

        // Rule 2: Prefer files where compilation unit matches filename
        if let Some(filename) = std::path::Path::new(&file_path).file_stem() {
            if let Some(cu_stem) = std::path::Path::new(entry.compilation_unit.as_ref()).file_stem()
            {
                if filename == cu_stem {
                    score += file_selection_scoring::COMPILATION_UNIT_MATCH_BONUS;
                }
            }
        }

        // Rule 3: Prefer longer/more specific paths
        score += file_path.len() as i32;

        // Rule 4: Prefer statement boundaries
        if entry.is_stmt {
            score += file_selection_scoring::STATEMENT_BOUNDARY_BONUS;
        }

        // Rule 5: Prefer non-system paths
        if !file_path.starts_with("/usr/") && !file_path.starts_with("/lib/") {
            score += file_selection_scoring::NON_SYSTEM_PATH_BONUS;
        }

        score
    }

    /// Helper to get file path for a line entry
    fn get_file_path_for_entry(&self, entry: &crate::core::LineEntry) -> Option<String> {
        // First check if the entry already has a file path filled in (avoids redundant lookups)
        if !entry.file_path.is_empty() {
            return Some(entry.file_path.clone());
        }

        // Fallback to file index lookup if needed
        if let Some(full_path) = self
            .scoped_file_manager
            .lookup_by_scoped_index(&entry.compilation_unit, entry.file_index)
        {
            return Some(full_path);
        }

        Some(entry.compilation_unit.to_string())
    }

    /// Create SourceLocation from line entry
    fn create_source_location_from_entry(
        &self,
        line_entry: &crate::core::LineEntry,
    ) -> Option<SourceLocation> {
        tracing::debug!(
            "create_source_location_from_entry: line_entry.file_path='{}', line_entry.file_index={}, compilation_unit='{}'",
            line_entry.file_path, line_entry.file_index, line_entry.compilation_unit
        );

        // Check if compilation_unit itself is a file path (contains path separators)
        // If so, try to resolve it to a full path by combining with base directory
        if line_entry.compilation_unit.contains('/')
            && (line_entry.compilation_unit.ends_with(".c")
                || line_entry.compilation_unit.ends_with(".cpp")
                || line_entry.compilation_unit.ends_with(".cc")
                || line_entry.compilation_unit.ends_with(".rs"))
        {
            // If CU name already looks like a path, prefer the resolved full path directly.
            // Avoid reconstructing "base_dir + CU" which can duplicate subpaths (e.g., src/core/src/core).
            if let Some(resolved_full_path) = self
                .scoped_file_manager
                .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
            {
                // Only use the resolved path when it actually looks like a proper path.
                if self.is_path_like(&resolved_full_path) {
                    tracing::debug!(
                        "create_source_location_from_entry: CU looks like path; using resolved full path '{}'",
                        resolved_full_path
                    );
                    return Some(SourceLocation {
                        file_path: resolved_full_path,
                        line_number: line_entry.line as u32,
                        column: Some(line_entry.column as u32),
                        address: line_entry.address,
                    });
                } else {
                    // Resolved result degraded to bare filename; keep CU path as it is richer
                    tracing::debug!(
                        "create_source_location_from_entry: resolved full path is bare filename; keeping CU '{}'",
                        line_entry.compilation_unit
                    );
                    return Some(SourceLocation {
                        file_path: line_entry.compilation_unit.to_string(),
                        line_number: line_entry.line as u32,
                        column: Some(line_entry.column as u32),
                        address: line_entry.address,
                    });
                }
            }

            // Fallback to CU string if resolution failed
            return Some(SourceLocation {
                file_path: line_entry.compilation_unit.to_string(),
                line_number: line_entry.line as u32,
                column: Some(line_entry.column as u32),
                address: line_entry.address,
            });
        }

        // Try to find a better file if current one is a header
        let preferred_file_path = {
            // Always returns Some(String) (falls back to filename when no dir info). Handle degradation here.
            let current_path = self
                .scoped_file_manager
                .lookup_by_scoped_index(&line_entry.compilation_unit, line_entry.file_index)
                .unwrap_or_else(|| line_entry.file_path.clone());

            tracing::debug!(
                "create_source_location_from_entry: found file via ScopedFileIndexManager: '{}'",
                current_path
            );

            if self.is_path_like(&current_path) {
                // If current file is a header, try to find the main source file
                if self.is_header_file(&current_path) {
                    if let Some(alternative_path) =
                        self.find_main_source_file_in_cu(&line_entry.compilation_unit)
                    {
                        tracing::debug!(
                            "create_source_location_from_entry: replaced header '{}' with main source '{}'",
                            current_path, alternative_path
                        );
                        alternative_path
                    } else {
                        current_path
                    }
                } else {
                    current_path
                }
            } else if !line_entry.file_path.is_empty() && self.is_path_like(&line_entry.file_path) {
                tracing::debug!(
                    "create_source_location_from_entry: using line entry file_path: '{}' (scoped result was bare)",
                    line_entry.file_path
                );
                line_entry.file_path.clone()
            } else if self.is_path_like(line_entry.compilation_unit.as_ref()) {
                tracing::debug!(
                    "create_source_location_from_entry: using CU path: '{}' (scoped result was bare)",
                    line_entry.compilation_unit
                );
                line_entry.compilation_unit.to_string()
            } else {
                // Last resort: keep the bare filename
                current_path
            }
        };

        tracing::debug!(
            "create_source_location_from_entry: final file_path='{}'",
            preferred_file_path
        );

        Some(SourceLocation {
            file_path: preferred_file_path,
            line_number: line_entry.line as u32,
            column: Some(line_entry.column as u32),
            address: line_entry.address,
        })
    }

    /// Heuristic: whether a string looks like a path (has directory components)
    fn is_path_like(&self, s: &str) -> bool {
        // Prefer simple heuristic for Unix-like paths used in our environment
        s.contains('/')
    }

    /// Check if a file path is a header file
    fn is_header_file(&self, file_path: &str) -> bool {
        file_path.ends_with(".h")
            || file_path.ends_with(".hpp")
            || file_path.ends_with(".hxx")
            || file_path.contains("/include/")
            || file_path.contains("/usr/include/")
    }

    /// Find the main source file in the compilation unit
    fn find_main_source_file_in_cu(&self, compilation_unit: &str) -> Option<String> {
        if let Some(cu_file_index) = self.scoped_file_manager.get_cu_file_index(compilation_unit) {
            tracing::debug!(
                "find_main_source_file_in_cu: searching for main source file in CU '{}'",
                compilation_unit
            );

            // First priority: look for files that match the compilation unit name
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !self.is_header_file(&full_path) {
                        // Check if this file matches the compilation unit name
                        if let Some(cu_stem) = std::path::Path::new(compilation_unit).file_stem() {
                            if let Some(file_stem) = std::path::Path::new(&full_path).file_stem() {
                                if cu_stem == file_stem {
                                    tracing::debug!(
                                        "find_main_source_file_in_cu: found matching source file '{}'",
                                        full_path
                                    );
                                    return Some(full_path);
                                }
                            }
                        }
                    }
                }
            }

            // Second priority: any non-header file
            for file_entry in cu_file_index.file_entries() {
                if let Some(full_path) = file_entry.get_full_path(cu_file_index) {
                    if !self.is_header_file(&full_path) {
                        tracing::debug!(
                            "find_main_source_file_in_cu: found alternative source file '{}'",
                            full_path
                        );
                        return Some(full_path);
                    }
                }
            }
        }

        None
    }

    /// Get module path
    pub(crate) fn module_path(&self) -> &PathBuf {
        &self.module_mapping.path
    }

    /// Get module mapping info
    pub(crate) fn module_mapping(&self) -> &ModuleMapping {
        &self.module_mapping
    }

    /// Get function names for debugging
    pub(crate) fn get_function_names(&self) -> Vec<&String> {
        self.lightweight_index.get_function_names()
    }

    /// Get variable names for debugging
    pub(crate) fn get_variable_names(&self) -> Vec<&String> {
        self.lightweight_index.get_variable_names()
    }

    /// Get lightweight index for stats access
    pub(crate) fn get_lightweight_index(&self) -> &LightweightIndex {
        &self.lightweight_index
    }

    /// Get line header count for debugging (legacy compatibility)
    pub(crate) fn get_line_header_count(&self) -> usize {
        self.scoped_file_manager.get_stats().1
    }

    /// Check if DWARF debug information is available (including debug link)
    pub(crate) fn has_dwarf_info(&self) -> bool {
        self.get_line_header_count() > 0
    }

    /// Get debug file path (if different from binary, e.g., via .gnu_debuglink)
    pub(crate) fn get_debug_file_path(&self) -> Option<PathBuf> {
        let dwarf_path = &self._dwarf_mapped_file.path;
        let binary_path = &self._binary_mapped_file.path;

        // If DWARF file path is different from binary path, it's a separate debug file
        if dwarf_path != binary_path {
            Some(dwarf_path.clone())
        } else {
            None
        }
    }

    /// Get cache statistics
    pub(crate) fn get_cache_stats(&self) -> (usize, usize) {
        self.resolver.get_cache_stats()
    }

    /// Get CFA result at given PC
    pub(crate) fn get_cfa_result(&self, pc: u64) -> Result<Option<crate::core::CfaResult>> {
        match &self.cfi_index {
            Some(cfi) => Ok(Some(cfi.get_cfa_result(pc)?)),
            None => Ok(None),
        }
    }

    /// Compute DW_AT_frame_base for the innermost block that contains the PC, falling back to function scope.
    /// Returns a CfaResult representing the frame base expression (register+offset or expression steps).
    fn compute_frame_base_for_pc(
        &self,
        func: &FunctionBlocks,
        pc: u64,
    ) -> Option<crate::core::CfaResult> {
        let dwarf = self.resolver.dwarf_ref();
        let header = dwarf.unit_header(func.cu_offset).ok()?;
        let unit = dwarf.unit(header).ok()?;
        // From innermost block to outermost (root at 0)
        let path = func.block_path_for_pc(pc);
        let mut candidates: Vec<gimli::UnitOffset> = Vec::new();
        for &idx in path.iter().rev() {
            if idx == 0 {
                candidates.push(func.die_offset);
            } else if let Some(off) = func.nodes.get(idx).and_then(|n| n.die_offset) {
                candidates.push(off);
            }
        }

        for off in candidates {
            if let Ok(entry) = unit.entry(off) {
                if let Ok(Some(val)) = resolve_attr_with_unit_origins(
                    &entry,
                    &unit,
                    gimli::constants::DW_AT_frame_base,
                ) {
                    // Evaluate to EvaluationResult using existing evaluator paths
                    let eval_res = match val {
                        gimli::AttributeValue::Exprloc(expr) => {
                            ExpressionEvaluator::parse_expression_in_unit(
                                expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                &unit,
                                dwarf,
                                pc,
                                None,
                            )
                            .ok()
                        }
                        gimli::AttributeValue::LocationListsRef(offset) => {
                            ExpressionEvaluator::parse_location_lists(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset.0),
                                pc,
                                None,
                            )
                            .ok()
                        }
                        gimli::AttributeValue::SecOffset(offset) => {
                            ExpressionEvaluator::parse_location_lists(
                                &unit,
                                dwarf,
                                gimli::LocationListsOffset(offset),
                                pc,
                                None,
                            )
                            .ok()
                        }
                        _ => None,
                    };

                    if let Some(er) = eval_res {
                        use crate::core::{
                            CfaResult, ComputeStep, EvaluationResult, LocationResult,
                        };
                        // Map EvaluationResult to CfaResult
                        let cfa = match er {
                            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                                register,
                                offset,
                                ..
                            }) => CfaResult::RegisterPlusOffset {
                                register,
                                offset: offset.unwrap_or(0),
                            },
                            EvaluationResult::MemoryLocation(
                                LocationResult::ComputedLocation { steps },
                            ) => CfaResult::Expression { steps },
                            EvaluationResult::MemoryLocation(LocationResult::Address(addr)) => {
                                CfaResult::Expression {
                                    steps: vec![ComputeStep::PushConstant(addr as i64)],
                                }
                            }
                            EvaluationResult::DirectValue(
                                crate::core::DirectValueResult::Constant(c),
                            ) => CfaResult::Expression {
                                steps: vec![ComputeStep::PushConstant(c)],
                            },
                            EvaluationResult::DirectValue(
                                crate::core::DirectValueResult::ImplicitValue(bytes),
                            ) => {
                                // Treat as constant pointer if size matches u64, else skip
                                if bytes.len() == 8 {
                                    let mut arr = [0u8; 8];
                                    arr.copy_from_slice(&bytes);
                                    let v = u64::from_le_bytes(arr) as i64;
                                    CfaResult::Expression {
                                        steps: vec![ComputeStep::PushConstant(v)],
                                    }
                                } else {
                                    continue;
                                }
                            }
                            _ => continue,
                        };
                        return Some(cfa);
                    }
                }
            }
        }

        None
    }

    /// Build demangled name maps from the lightweight index
    fn build_demangled_maps(ix: &LightweightIndex) -> DemangledNameMaps {
        fn normalize_sig(s: &str) -> String {
            let mut out = s.replace(", ", ",");
            out = out.replace("( ", "(");
            out = out.replace(" )", ")");
            out = out.replace(" ,", ",");
            out
        }

        fn normalized_variant(s: &str) -> Option<String> {
            let norm = normalize_sig(s);
            (norm != s).then_some(norm)
        }

        let mut fn_full: NameIndex = HashMap::new();
        let mut fn_leaf: NameIndex = HashMap::new();
        let mut var_full: NameIndex = HashMap::new();
        let mut var_leaf: NameIndex = HashMap::new();
        let (_, _, total) = ix.get_stats();
        let mut demangle_jobs = Vec::new();
        let mut seen_jobs: HashSet<(u16, std::sync::Arc<str>)> = HashSet::new();
        for idx in 0..total {
            let Some(entry) = ix.entry(idx) else {
                continue;
            };
            if !matches!(
                entry.tag,
                gimli::constants::DW_TAG_subprogram
                    | gimli::constants::DW_TAG_inlined_subroutine
                    | gimli::constants::DW_TAG_variable
            ) {
                continue;
            }
            let should_attempt_demangle = entry.flags.is_linkage
                || crate::core::is_likely_mangled(entry.language, entry.name.as_ref());
            if !should_attempt_demangle {
                continue;
            }
            let lang_code: u16 = entry.language.map(|l| l.0).unwrap_or(u16::MAX);
            let key = (lang_code, entry.name.clone());
            if seen_jobs.insert(key.clone()) {
                demangle_jobs.push((key, entry.language));
            }
        }

        let demangle_cache: HashMap<(u16, std::sync::Arc<str>), String> = demangle_jobs
            .into_par_iter()
            .filter_map(|(key, lang)| {
                crate::core::demangle_by_lang(lang, key.1.as_ref())
                    .map(|demangled| (key, demangled))
            })
            .collect();

        let indexed_entries: Vec<Option<DemangledMapEntry>> = (0..total)
            .into_par_iter()
            .map(|idx| {
                let entry = ix.entry(idx)?;
                if !matches!(
                    entry.tag,
                    gimli::constants::DW_TAG_subprogram
                        | gimli::constants::DW_TAG_inlined_subroutine
                        | gimli::constants::DW_TAG_variable
                ) {
                    return None;
                }

                let demangled_opt = if entry.flags.is_linkage
                    || crate::core::is_likely_mangled(entry.language, entry.name.as_ref())
                {
                    let lang_code: u16 = entry.language.map(|l| l.0).unwrap_or(u16::MAX);
                    demangle_cache
                        .get(&(lang_code, entry.name.clone()))
                        .cloned()
                } else {
                    None
                };

                Some(if let Some(full) = demangled_opt {
                    let leaf = crate::core::demangled_leaf(&full);
                    DemangledMapEntry {
                        idx,
                        tag: entry.tag,
                        full: Some(full.clone()),
                        full_normalized: normalized_variant(&full),
                        leaf_normalized: normalized_variant(&leaf),
                        leaf,
                    }
                } else {
                    let leaf = entry
                        .name
                        .rsplit("::")
                        .next()
                        .unwrap_or(entry.name.as_ref())
                        .to_string();
                    DemangledMapEntry {
                        idx,
                        tag: entry.tag,
                        full: None,
                        full_normalized: None,
                        leaf_normalized: normalized_variant(&leaf),
                        leaf,
                    }
                })
            })
            .collect();

        for entry in indexed_entries.into_iter().flatten() {
            match entry.tag {
                gimli::constants::DW_TAG_subprogram
                | gimli::constants::DW_TAG_inlined_subroutine => {
                    if let Some(full) = entry.full {
                        fn_full.entry(full).or_default().push(entry.idx);
                    }
                    if let Some(full_norm) = entry.full_normalized {
                        fn_full.entry(full_norm).or_default().push(entry.idx);
                    }
                    fn_leaf.entry(entry.leaf).or_default().push(entry.idx);
                    if let Some(leaf_norm) = entry.leaf_normalized {
                        fn_leaf.entry(leaf_norm).or_default().push(entry.idx);
                    }
                }
                gimli::constants::DW_TAG_variable => {
                    if let Some(full) = entry.full {
                        var_full.entry(full).or_default().push(entry.idx);
                    }
                    if let Some(full_norm) = entry.full_normalized {
                        var_full.entry(full_norm).or_default().push(entry.idx);
                    }
                    var_leaf.entry(entry.leaf).or_default().push(entry.idx);
                    if let Some(leaf_norm) = entry.leaf_normalized {
                        var_leaf.entry(leaf_norm).or_default().push(entry.idx);
                    }
                }
                _ => {}
            }
        }

        DemangledNameMaps {
            function_map: fn_full,
            function_leaf_map: fn_leaf,
            variable_map: var_full,
            variable_leaf_map: var_leaf,
        }
    }

    /// Compute addresses for a function entry (deterministic ordering)
    ///
    /// Semantics
    /// - Inline (DW_TAG_inlined_subroutine):
    ///   Return exactly one address per inline DIE. Prefer DW_AT_entry_pc only
    ///   when it falls inside the DIE's own ranges; some producers point
    ///   entry_pc at caller-side setup code instead of the inlined body. If the
    ///   validated entry_pc is missing, preserve the first DWARF-emitted range
    ///   start so hot/cold partitioning does not drift to a lower-address cold
    ///   fragment; only fall back to the minimum range start as a final
    ///   recovery path. Intentionally do not scan for is_stmt here to preserve
    ///   entry-like behavior and keep entry-view locations available.
    /// - Non-inline (DW_TAG_subprogram):
    ///   For each selected executable range, return the first executable address
    ///   after the prologue (prologue-skip). If any formal parameter's active
    ///   location at the selected probe PC uses DW_OP_entry_value, prefer the
    ///   true entry (range start) to preserve entry context. When DW_AT_ranges
    ///   contains partitioned hot/cold code,
    ///   prefer the range containing DW_AT_entry_pc; otherwise preserve the
    ///   first DWARF-emitted range because compilers typically list the entry/
    ///   hot partition first even when a later address sort would put `.cold`
    ///   code ahead of it.
    ///
    /// Determinism
    /// - A sorted copy of the DIE's ranges (ascending by start) is used for all
    ///   computations to ensure stable behavior across compilers/toolchains.
    fn compute_addresses_for_entry(&self, entry: &crate::core::IndexEntry) -> Vec<u64> {
        let mut out = Vec::new();
        match entry.function_kind() {
            crate::core::FunctionDieKind::InlineInstance => {
                // Debug: print ranges & entry_pc once per inline entry
                let mut ranges = entry.address_ranges.clone();
                ranges.sort_unstable_by_key(|(s, _)| *s);
                if !ranges.is_empty() {
                    let parts: Vec<String> = ranges
                        .iter()
                        .map(|(s, e)| format!("(0x{s:x},0x{e:x})"))
                        .collect();
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    let rlen = ranges.len();
                    let rlist = parts.join(", ");
                    tracing::debug!(
                        "Inline '{}' entry_pc={epc_dbg} ranges({rlen}): [{rlist}]",
                        entry.name
                    );
                } else {
                    let epc_dbg = entry
                        .entry_pc
                        .map(|v| format!("0x{v:x}"))
                        .unwrap_or("None".to_string());
                    tracing::debug!("Inline '{}' has no ranges; entry_pc={epc_dbg}", entry.name);
                }

                if let Some(addr) = Self::selected_inline_address(entry) {
                    tracing::debug!("Inline '{}' selected=0x{addr:x}", entry.name);
                    out.push(addr);
                } else {
                    tracing::warn!(
                        "Inline entry has no usable address (no ranges/entry_pc): unit_off={:?}, die_off={:?}",
                        entry.unit_offset,
                        entry.die_offset
                    );
                }
            }
            crate::core::FunctionDieKind::ConcreteSubprogram => {
                let nranges = Self::selected_non_inline_ranges(entry);
                for (start, end) in &nranges {
                    let candidate = {
                        let first_exec = self.line_mapping.find_first_executable_address(*start);
                        Self::selected_non_inline_probe_address(*start, *end, first_exec)
                    };
                    // Only force the true entry when the location active at the
                    // probe PC already relies on DW_OP_entry_value. Some optimized
                    // functions switch to entry_value later in the body, but still
                    // have stable register locations at the first executable
                    // instruction after the prologue.
                    let prefer_entry = self
                        .function_uses_entry_value_at(entry, candidate)
                        .unwrap_or(false);
                    let addr = if prefer_entry { *start } else { candidate };
                    if prefer_entry {
                        tracing::debug!(
                            "Non-inline '{}' entry_value active at 0x{candidate:x}, using entry start=0x{start:x}",
                            entry.name,
                        );
                    } else {
                        let off = addr.saturating_sub(*start);
                        tracing::debug!(
                            "Non-inline '{}' start=0x{start:x} first_exec=0x{addr:x} (+0x{off:x})",
                            entry.name
                        );
                        if addr == *start {
                            tracing::debug!(
                                "Non-inline '{}' kept entry start because prologue-skip candidate escaped range [0x{start:x}, 0x{end:x})",
                                entry.name
                            );
                        }
                    }
                    out.push(addr);
                }
            }
            crate::core::FunctionDieKind::AbstractSubprogram => {
                tracing::debug!(
                    "Skipping abstract subprogram '{}' with no concrete code ranges",
                    entry.name
                );
            }
            crate::core::FunctionDieKind::NotFunction => {}
        }
        out
    }

    fn selected_inline_address(entry: &crate::core::IndexEntry) -> Option<u64> {
        let first_start = entry.address_ranges.first().map(|(start, _)| *start);
        let low_pc = entry.address_ranges.iter().map(|(start, _)| *start).min();

        entry.validated_entry_pc().or(first_start).or(low_pc)
    }

    fn selected_non_inline_ranges(entry: &crate::core::IndexEntry) -> Vec<(u64, u64)> {
        let ranges = entry.address_ranges.clone();
        if ranges.len() <= 1 {
            return ranges;
        }

        if let Some(entry_pc) = entry.entry_pc {
            if let Some(range) = ranges
                .iter()
                .copied()
                .find(|(start, end)| *start <= entry_pc && entry_pc < *end)
            {
                return vec![range];
            }
        }

        vec![ranges[0]]
    }

    fn selected_non_inline_probe_address(start: u64, end: u64, candidate: u64) -> u64 {
        if start <= candidate && candidate < end {
            candidate
        } else {
            start
        }
    }

    /// Check if this subprogram uses DW_OP_entry_value for any formal parameter
    /// location active at the given PC.
    fn function_uses_entry_value_at(
        &self,
        idx_entry: &crate::core::IndexEntry,
        pc: u64,
    ) -> Result<bool> {
        let dwarf = self.resolver.dwarf_ref();
        let header = dwarf
            .unit_header(idx_entry.unit_offset)
            .map_err(|e| anyhow::anyhow!("unit header error: {}", e))?;
        let unit = dwarf
            .unit(header)
            .map_err(|e| anyhow::anyhow!("unit load error: {}", e))?;
        let entry = unit
            .entry(idx_entry.die_offset)
            .map_err(|e| anyhow::anyhow!("entry load error: {}", e))?;
        Self::subprogram_uses_entry_value_at(dwarf, &unit, &entry, pc)
    }

    #[cfg(test)]
    fn subprogram_uses_entry_value(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_inner(dwarf, unit, entry, &mut visited)
    }

    fn subprogram_uses_entry_value_at(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: u64,
    ) -> Result<bool> {
        let mut visited = HashSet::with_capacity(4);
        if let Some(entry_abs) = entry.offset().to_debug_info_offset(&unit.header) {
            visited.insert(entry_abs);
        }

        Self::subprogram_uses_entry_value_at_inner(dwarf, unit, entry, pc, &mut visited)
    }

    #[cfg(test)]
    fn subprogram_uses_entry_value_inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<bool> {
        if entry.tag() != gimli::constants::DW_TAG_subprogram {
            return Ok(false);
        }

        if let Some(uses_entry_value) =
            Self::direct_formal_parameters_entry_value_state(unit, entry)?
        {
            return Ok(uses_entry_value);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((origin_abs, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)
                        .map_err(|e| anyhow::anyhow!("origin resolution error: {}", e))?
                {
                    if visited.insert(origin_abs)
                        && Self::subprogram_uses_entry_value_inner(
                            dwarf,
                            &origin_unit,
                            &origin_entry,
                            visited,
                        )?
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn subprogram_uses_entry_value_at_inner(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: u64,
        visited: &mut HashSet<gimli::DebugInfoOffset>,
    ) -> Result<bool> {
        if entry.tag() != gimli::constants::DW_TAG_subprogram {
            return Ok(false);
        }

        if let Some(uses_entry_value) =
            Self::direct_formal_parameters_entry_value_state_at_pc(dwarf, unit, entry, pc)?
        {
            return Ok(uses_entry_value);
        }

        for origin_attr in [
            gimli::constants::DW_AT_abstract_origin,
            gimli::constants::DW_AT_specification,
        ] {
            if let Some(value) = entry.attr_value(origin_attr) {
                if let Some((origin_abs, origin_unit, origin_entry)) =
                    resolve_origin_entry(dwarf, unit, value)
                        .map_err(|e| anyhow::anyhow!("origin resolution error: {}", e))?
                {
                    if visited.insert(origin_abs)
                        && Self::subprogram_uses_entry_value_at_inner(
                            dwarf,
                            &origin_unit,
                            &origin_entry,
                            pc,
                            visited,
                        )?
                    {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    #[cfg(test)]
    fn direct_formal_parameters_entry_value_state(
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Result<Option<bool>> {
        let mut saw_parameter = false;

        if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
            if let Ok(root) = tree.root() {
                let mut children = root.children();
                while let Ok(Some(child)) = children.next() {
                    let e = child.entry();
                    if e.tag() != gimli::constants::DW_TAG_formal_parameter {
                        continue;
                    }
                    saw_parameter = true;

                    if let Ok(Some(gimli::AttributeValue::Exprloc(expr))) =
                        resolve_attr_with_unit_origins(e, unit, gimli::constants::DW_AT_location)
                    {
                        if Self::expression_uses_entry_value(unit, gimli::Expression(expr.0)) {
                            return Ok(Some(true));
                        }
                    }
                }
            }
        }

        if saw_parameter {
            Ok(Some(false))
        } else {
            Ok(None)
        }
    }

    fn direct_formal_parameters_entry_value_state_at_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        pc: u64,
    ) -> Result<Option<bool>> {
        let mut saw_parameter = false;

        if let Ok(mut tree) = unit.entries_tree(Some(entry.offset())) {
            if let Ok(root) = tree.root() {
                let mut children = root.children();
                while let Ok(Some(child)) = children.next() {
                    let e = child.entry();
                    if e.tag() != gimli::constants::DW_TAG_formal_parameter {
                        continue;
                    }
                    saw_parameter = true;

                    if let Ok(Some(value)) =
                        resolve_attr_with_unit_origins(e, unit, gimli::constants::DW_AT_location)
                    {
                        if Self::attribute_uses_entry_value_at_pc(dwarf, unit, value, pc)? {
                            return Ok(Some(true));
                        }
                    }
                }
            }
        }

        if saw_parameter {
            Ok(Some(false))
        } else {
            Ok(None)
        }
    }

    fn attribute_uses_entry_value_at_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        value: gimli::AttributeValue<DwarfReader>,
        pc: u64,
    ) -> Result<bool> {
        match value {
            gimli::AttributeValue::Exprloc(expr) => Ok(Self::expression_uses_entry_value(
                unit,
                gimli::Expression(expr.0),
            )),
            gimli::AttributeValue::LocationListsRef(offset) => {
                Self::location_list_uses_entry_value_at_pc(
                    dwarf,
                    unit,
                    gimli::LocationListsOffset(offset.0),
                    pc,
                )
            }
            gimli::AttributeValue::SecOffset(offset) => Self::location_list_uses_entry_value_at_pc(
                dwarf,
                unit,
                gimli::LocationListsOffset(offset),
                pc,
            ),
            _ => Ok(false),
        }
    }

    fn location_list_uses_entry_value_at_pc(
        dwarf: &gimli::Dwarf<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        pc: u64,
    ) -> Result<bool> {
        let mut raw_locations = match dwarf.raw_locations(unit, offset) {
            Ok(iter) => iter,
            Err(_) => return Ok(false),
        };

        let mut base_address = unit.low_pc;
        let mut default_location_uses_entry_value = None;
        while let Some(raw_entry) = raw_locations
            .next()
            .map_err(|e| anyhow::anyhow!("raw location list iteration error: {:?}", e))?
        {
            match raw_entry {
                gimli::RawLocListEntry::BaseAddress { addr } => {
                    base_address = addr;
                }
                gimli::RawLocListEntry::BaseAddressx { addr } => {
                    if let Ok(resolved) = dwarf.address(unit, addr) {
                        base_address = resolved;
                    }
                }
                gimli::RawLocListEntry::StartLength {
                    begin,
                    length,
                    data,
                } => {
                    if range_contains_pc(begin, begin.wrapping_add(length), pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartEnd { begin, end, data } => {
                    if range_contains_pc(begin, end, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::OffsetPair { begin, end, data }
                | gimli::RawLocListEntry::AddressOrOffsetPair { begin, end, data } => {
                    let start = base_address.wrapping_add(begin);
                    let end_addr = base_address.wrapping_add(end);
                    if range_contains_pc(start, end_addr, pc) {
                        return Ok(Self::expression_uses_entry_value(unit, data));
                    }
                }
                gimli::RawLocListEntry::StartxLength {
                    begin,
                    length,
                    data,
                } => {
                    if let Ok(start) = dwarf.address(unit, begin) {
                        if range_contains_pc(start, start.wrapping_add(length), pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::StartxEndx { begin, end, data } => {
                    if let (Ok(start), Ok(end_addr)) =
                        (dwarf.address(unit, begin), dwarf.address(unit, end))
                    {
                        if range_contains_pc(start, end_addr, pc) {
                            return Ok(Self::expression_uses_entry_value(unit, data));
                        }
                    }
                }
                gimli::RawLocListEntry::DefaultLocation { data } => {
                    default_location_uses_entry_value =
                        Some(Self::expression_uses_entry_value(unit, data));
                }
            }
        }

        Ok(default_location_uses_entry_value.unwrap_or(false))
    }

    fn expression_uses_entry_value(
        unit: &gimli::Unit<DwarfReader>,
        mut expression: gimli::Expression<DwarfReader>,
    ) -> bool {
        while let Ok(op) = gimli::Operation::parse(&mut expression.0, unit.encoding()) {
            if matches!(op, gimli::Operation::EntryValue { .. }) {
                return true;
            }
        }

        false
    }

    /// Lookup function addresses by any of: DW_AT_name, linkage name, or demangled name
    pub(crate) fn lookup_function_addresses_any(&self, name: &str) -> Vec<u64> {
        // Fast path: direct name (includes DW_AT_name and linkage names if present)
        let addrs = self.lookup_function_addresses(name);
        if !addrs.is_empty() {
            return addrs;
        }
        let demangled_maps = &self.demangled_maps;

        // Helper: normalize demangled signature spacing (e.g., "(int, int)" -> "(int,int)")
        let normalize_sig = |s: &str| -> Option<String> {
            if !s.contains('(') {
                return None;
            }
            let mut out = s.replace(", ", ",");
            out = out.replace("( ", "(");
            out = out.replace(" )", ")");
            out = out.replace(" ,", ",");
            if out != s {
                Some(out)
            } else {
                None
            }
        };

        // Demangled full match
        if let Some(indices) = demangled_maps.function_map.get(name) {
            let mut out = Vec::new();
            for &idx in indices {
                if let Some(entry) = self.lightweight_index.entry(idx) {
                    out.extend(self.compute_addresses_for_entry(entry));
                }
            }
            out.sort_unstable();
            out.dedup();
            if !out.is_empty() {
                return out;
            }
        }
        // Try normalized variant
        if let Some(norm) = normalize_sig(name) {
            if let Some(indices) = demangled_maps.function_map.get(&norm) {
                let mut out = Vec::new();
                for &idx in indices {
                    if let Some(entry) = self.lightweight_index.entry(idx) {
                        out.extend(self.compute_addresses_for_entry(entry));
                    }
                }
                out.sort_unstable();
                out.dedup();
                if !out.is_empty() {
                    return out;
                }
            }
        }

        // Demangled leaf match
        if let Some(indices) = demangled_maps.function_leaf_map.get(name) {
            let mut out = Vec::new();
            for &idx in indices {
                if let Some(entry) = self.lightweight_index.entry(idx) {
                    out.extend(self.compute_addresses_for_entry(entry));
                }
            }
            out.sort_unstable();
            out.dedup();
            if !out.is_empty() {
                return out;
            }
        }
        // Try normalized leaf variant
        if let Some(norm) = normalize_sig(name) {
            if let Some(indices) = demangled_maps.function_leaf_map.get(&norm) {
                let mut out = Vec::new();
                for &idx in indices {
                    if let Some(entry) = self.lightweight_index.entry(idx) {
                        out.extend(self.compute_addresses_for_entry(entry));
                    }
                }
                out.sort_unstable();
                out.dedup();
                if !out.is_empty() {
                    return out;
                }
            }
        }

        // Fallback: suffix match on known function names with namespace separators
        // e.g., match leaf "bar" to "ns::Foo::bar"
        let mut out = Vec::new();
        for key in self.lightweight_index.get_function_names() {
            if key.rsplit("::").next().map(|s| s == name).unwrap_or(false) {
                let entries = self.lightweight_index.find_dies_by_function_name(key);
                for e in entries {
                    out.extend(self.compute_addresses_for_entry(e));
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Find global/static variables by any name (DW_AT_name, linkage, or demangled)
    pub(crate) fn find_global_variables_by_name_any(&self, name: &str) -> Vec<GlobalVariableInfo> {
        let base = self.find_global_variables_by_name(name);
        if !base.is_empty() {
            return base;
        }
        let demangled_maps = &self.demangled_maps;

        // Build object file once for section classification
        let obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        // Track DIEs we've already emitted (unit_offset, die_offset)
        let mut seen_offsets: HashSet<(u64, u64)> = HashSet::new();

        // Try demangled full (preserve the demangled name that matched)
        if let Some(indices) = demangled_maps.variable_map.get(name) {
            for &idx in indices {
                if let Some(entry) = self.lightweight_index.entry(idx) {
                    let key = (entry.unit_offset.0 as u64, entry.die_offset.0 as u64);
                    if !seen_offsets.insert(key) {
                        continue;
                    }
                    let link_address = entry.address_ranges.first().and_then(|(lo, hi)| {
                        if lo == hi {
                            Some(*lo)
                        } else {
                            None
                        }
                    });
                    let section = link_address.and_then(|addr| self.classify_section(&obj, addr));
                    out.push(GlobalVariableInfo {
                        name: name.to_string(),
                        link_address,
                        section,
                        die_offset: entry.die_offset,
                        unit_offset: entry.unit_offset,
                    });
                }
            }
            if !out.is_empty() {
                return out;
            }
        }

        // Try demangled leaf (preserve the demangled name that matched)
        if let Some(indices) = demangled_maps.variable_leaf_map.get(name) {
            for &idx in indices {
                if let Some(entry) = self.lightweight_index.entry(idx) {
                    let key = (entry.unit_offset.0 as u64, entry.die_offset.0 as u64);
                    if !seen_offsets.insert(key) {
                        continue;
                    }
                    let link_address = entry.address_ranges.first().and_then(|(lo, hi)| {
                        if lo == hi {
                            Some(*lo)
                        } else {
                            None
                        }
                    });
                    let section = link_address.and_then(|addr| self.classify_section(&obj, addr));
                    out.push(GlobalVariableInfo {
                        name: name.to_string(),
                        link_address,
                        section,
                        die_offset: entry.die_offset,
                        unit_offset: entry.unit_offset,
                    });
                }
            }
        }

        if !out.is_empty() {
            return out;
        }

        // Fallback: suffix match on variable names with namespace separators
        let mut extra = Vec::new();
        for key in self.lightweight_index.get_variable_names() {
            if key.rsplit("::").next().map(|s| s == name).unwrap_or(false) {
                for e in self.lightweight_index.find_variables_by_name(key) {
                    let key = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
                    if !seen_offsets.insert(key) {
                        continue;
                    }
                    let link_address =
                        e.address_ranges
                            .first()
                            .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });
                    let section = link_address.and_then(|addr| self.classify_section(&obj, addr));
                    extra.push(GlobalVariableInfo {
                        // Preserve the requested (likely demangled/leaf) name for downstream comparisons
                        name: name.to_string(),
                        link_address,
                        section,
                        die_offset: e.die_offset,
                        unit_offset: e.unit_offset,
                    });
                }
            }
        }

        if !extra.is_empty() {
            return extra;
        }

        // Final fallback: scan all entries to match by exact or leaf name
        let mut scan = Vec::new();
        let (_, _, total) = self.lightweight_index.get_stats();
        for i in 0..total {
            if let Some(e) = self.lightweight_index.entry(i) {
                if e.tag != gimli::constants::DW_TAG_variable {
                    continue;
                }
                let key_offsets = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
                if !seen_offsets.insert(key_offsets) {
                    continue;
                }
                let last = e.name.rsplit("::").next().unwrap_or(e.name.as_ref());
                if last == name || e.name == name.into() {
                    let link_address =
                        e.address_ranges
                            .first()
                            .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });
                    let section = link_address.and_then(|addr| self.classify_section(&obj, addr));
                    scan.push(GlobalVariableInfo {
                        name: if last == name
                            || demangled_maps.variable_map.contains_key(name)
                            || demangled_maps.variable_leaf_map.contains_key(name)
                        {
                            name.to_string()
                        } else {
                            e.name.to_string()
                        },
                        link_address,
                        section,
                        die_offset: e.die_offset,
                        unit_offset: e.unit_offset,
                    });
                }
            }
        }

        if !scan.is_empty() {
            scan
        } else {
            out
        }
    }

    /// Helper: shallow resolve a type at (cu, die_off)
    fn detailed_shallow_type(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.resolver.dwarf_ref();
        let header = dwarf.unit_header(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        crate::parser::DetailedParser::resolve_type_shallow_at_offset(dwarf, &unit, die_off)
    }

    /// Compute shallow TypeInfo for a variable DIE located at (cu_off, die_off)
    pub(crate) fn shallow_type_for_variable_offsets(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.resolver.dwarf_ref();
        let header = dwarf.unit_header(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let entry = unit.entry(die_off).ok()?;
        let planner = crate::planner::AccessPlanner::new(dwarf);
        match planner.resolve_type_ref_with_origins_public(&entry, &unit) {
            Ok(Some(type_loc)) => self.detailed_shallow_type(type_loc.cu_off, type_loc.die_off),
            _ => None,
        }
    }

    /// Resolve variables by (CU, DIE) offsets at a given address context using the on-demand resolver
    pub(crate) fn resolve_variables_by_offsets_at_address(
        &mut self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
    ) -> Result<Vec<crate::VariableWithEvaluation>> {
        self.resolver
            .resolve_variables_by_offsets_at_address(address, items, None)
    }

    /// Lookup addresses by source file path and line number
    /// Returns addresses that correspond to the given source line
    pub(crate) fn lookup_addresses_by_source_line(
        &self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<u64> {
        // Use the new path-based lookup method
        let addresses = self
            .line_mapping
            .lookup_addresses_by_path(file_path, line_number as u64);

        if !addresses.is_empty() {
            tracing::info!(
                "Found {} addresses for {}:{} in module {}",
                addresses.len(),
                file_path,
                line_number,
                self.module_path().display()
            );
        } else {
            tracing::debug!(
                "No addresses found for {}:{} in module {}",
                file_path,
                line_number,
                self.module_path().display()
            );
        }

        addresses
    }

    /// Find symbol name by address (compatibility method)
    pub(crate) fn find_symbol_by_address(&self, address: u64) -> Option<String> {
        // Prefer optimized function lookup for readability; fallback to any DIE
        if let Some(entry) = self.lightweight_index.find_function_by_address(address) {
            return Some(entry.name.to_string());
        }
        self.lightweight_index
            .find_die_at_address(address)
            .map(|entry| entry.name.to_string())
    }

    /// Get all source files from stored compilation unit metadata
    pub(crate) fn get_all_files(&self) -> Vec<SourceFile> {
        let mut source_files = Vec::new();
        let mut seen_paths = HashSet::new();

        for cu in self.compilation_units.values() {
            for file in &cu.files {
                if seen_paths.insert(file.full_path.clone()) {
                    source_files.push(file.clone());
                }
            }
        }

        source_files.sort_by(|a, b| a.full_path.cmp(&b.full_path));
        source_files
    }

    /// Find global/static variables by name within this module (DWARF-only)
    /// Returns link-time address (if available) and best-effort section classification.
    pub(crate) fn find_global_variables_by_name(&self, name: &str) -> Vec<GlobalVariableInfo> {
        let mut out = Vec::new();
        let entries = self.lightweight_index.find_variables_by_name(name);
        let mut seen_offsets: HashSet<(u64, u64)> = HashSet::new();

        // Parse object file once for section classification
        let obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => {
                // Cannot classify sections, but still return entries with link_address
                for e in entries {
                    let key = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
                    if !seen_offsets.insert(key) {
                        continue;
                    }
                    let link_address =
                        e.address_ranges
                            .first()
                            .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });
                    out.push(GlobalVariableInfo {
                        name: e.name.to_string(),
                        link_address,
                        section: None,
                        die_offset: e.die_offset,
                        unit_offset: e.unit_offset,
                    });
                }
                return out;
            }
        };

        for e in entries {
            let key = (e.unit_offset.0 as u64, e.die_offset.0 as u64);
            if !seen_offsets.insert(key) {
                continue;
            }
            let link_address =
                e.address_ranges
                    .first()
                    .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });

            let section = link_address.and_then(|addr| self.classify_section(&obj, addr));

            out.push(GlobalVariableInfo {
                name: e.name.to_string(),
                link_address,
                section,
                die_offset: e.die_offset,
                unit_offset: e.unit_offset,
            });
        }

        out
    }

    fn classify_section(&self, obj: &object::File<'_>, addr: u64) -> Option<SectionType> {
        for sect in obj.sections() {
            let saddr = sect.address();
            let ssize = sect.size();
            if ssize == 0 {
                continue;
            }
            if addr >= saddr && addr < saddr + ssize {
                let name = sect.name().ok().unwrap_or("");
                let stype = if name == ".text" || name.starts_with(".text.") {
                    SectionType::Text
                } else if name == ".rodata"
                    || name.starts_with(".rodata")
                    || name.starts_with(".data.rel.ro")
                {
                    SectionType::Rodata
                } else if name == ".data" || name.starts_with(".data") {
                    SectionType::Data
                } else if name == ".bss" || name.starts_with(".bss.") {
                    SectionType::Bss
                } else {
                    SectionType::Unknown
                };
                return Some(stype);
            }
        }
        None
    }

    /// Public helper: classify a virtual address to a section type by parsing the module object
    pub(crate) fn classify_section_for_vaddr(&self, addr: u64) -> Option<SectionType> {
        match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(obj) => self.classify_section(&obj, addr),
            Err(_) => None,
        }
    }

    /// List all global/static variables with usable addresses in this module
    pub(crate) fn list_all_global_variables(&self) -> Vec<GlobalVariableInfo> {
        let mut out = Vec::new();
        // Parse object once for section classification
        let _obj = match object::File::parse(&self._binary_mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => {
                return out;
            }
        };

        for name in self.lightweight_index.get_variable_names() {
            for info in self.find_global_variables_by_name(name) {
                out.push(info);
            }
        }

        // find_global_variables_by_name already classifies section using obj
        out
    }
}

#[cfg(test)]
mod tests {
    use super::ModuleData;
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{FunctionDieKind, IndexEntry, IndexFlags};
    use crate::index::LightweightIndex;
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Location, LocationList, Sections, Unit,
    };
    use gimli::{Format, Register};
    use std::collections::HashMap;
    use std::sync::Arc;

    fn subprogram_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        IndexEntry {
            name: Arc::from("CGPsend"),
            die_offset: gimli::UnitOffset(0),
            unit_offset: gimli::DebugInfoOffset(0),
            tag: constants::DW_TAG_subprogram,
            flags: IndexFlags::default(),
            language: None,
            address_ranges: ranges.to_vec(),
            entry_pc,
            function_kind: FunctionDieKind::ConcreteSubprogram,
        }
    }

    fn inline_entry(ranges: &[(u64, u64)], entry_pc: Option<u64>) -> IndexEntry {
        let mut entry = subprogram_entry(ranges, entry_pc);
        entry.tag = constants::DW_TAG_inlined_subroutine;
        entry.flags.is_inline_instance = true;
        entry.function_kind = FunctionDieKind::InlineInstance;
        entry
    }

    fn build_origin_backed_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

    fn build_origin_backed_entry_value_override_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 4,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_override_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut origin_param_loc = WriteExpression::new();
        origin_param_loc.op_entry_value(inner);
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(origin_param_loc),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let concrete_param_id = unit.add(concrete_id, constants::DW_TAG_formal_parameter);
        let concrete_param = unit.get_mut(concrete_param_id);
        concrete_param.set(
            constants::DW_AT_abstract_origin,
            WriteAttributeValue::UnitRef(origin_param_id),
        );
        let mut concrete_param_loc = WriteExpression::new();
        concrete_param_loc.op_reg(Register(6));
        concrete_param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(concrete_param_loc),
        );

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

    fn build_origin_backed_entry_value_range_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_range_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut entry_value_loc = WriteExpression::new();
        entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x1477),
                data: direct_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1477),
                end: Address::Constant(0x147b),
                data: entry_value_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

    fn build_origin_backed_default_location_entry_value_fixture(
        origin_attr: gimli::DwAt,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let origin_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(origin_id).set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_default_location_target".to_vec()),
        );

        let origin_param_id = unit.add(origin_id, constants::DW_TAG_formal_parameter);
        let mut direct_loc = WriteExpression::new();
        direct_loc.op_reg(Register(5));
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(5));
        let mut default_entry_value_loc = WriteExpression::new();
        default_entry_value_loc.op_entry_value(inner);
        let loc_id = unit.locations.add(LocationList(vec![
            Location::DefaultLocation {
                data: default_entry_value_loc,
            },
            Location::StartEnd {
                begin: Address::Constant(0x1470),
                end: Address::Constant(0x147b),
                data: direct_loc,
            },
        ]));
        unit.get_mut(origin_param_id).set(
            constants::DW_AT_location,
            WriteAttributeValue::LocationListRef(loc_id),
        );

        let concrete_id = unit.add(root, constants::DW_TAG_subprogram);
        unit.get_mut(concrete_id)
            .set(origin_attr, WriteAttributeValue::UnitRef(origin_id));

        let mut sections = Sections::new(EndianVec::new(gimli::LittleEndian));
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

    fn first_unit(dwarf: &gimli::Dwarf<DwarfReader>) -> gimli::Unit<DwarfReader> {
        let mut units = dwarf.units();
        let header = units.next().unwrap().unwrap();
        dwarf.unit(header).unwrap()
    }

    fn find_subprogram_with_origin_attr(
        unit: &gimli::Unit<DwarfReader>,
        origin_attr: gimli::DwAt,
    ) -> gimli::UnitOffset {
        let mut tree = unit.entries_tree(None).unwrap();
        let root = tree.root().unwrap();
        let mut children = root.children();

        while let Some(child) = children.next().unwrap() {
            let entry = child.entry();
            if entry.tag() == constants::DW_TAG_subprogram
                && entry.attr_value(origin_attr).is_some()
            {
                return entry.offset();
            }
        }

        panic!("failed to find subprogram with origin attr {origin_attr:?}");
    }

    #[test]
    fn selected_non_inline_ranges_keeps_hot_partition_first_when_cold_has_lower_address() {
        let entry = subprogram_entry(&[(0x8e97c0, 0x8e9be0), (0x76e78e, 0x76e798)], None);

        assert_eq!(
            ModuleData::selected_non_inline_ranges(&entry),
            vec![(0x8e97c0, 0x8e9be0)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_keeps_single_contiguous_range() {
        let entry = subprogram_entry(&[(0x8ea060, 0x8eb07b)], None);

        assert_eq!(
            ModuleData::selected_non_inline_ranges(&entry),
            vec![(0x8ea060, 0x8eb07b)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_prefers_range_containing_entry_pc() {
        let entry = subprogram_entry(&[(0x100, 0x180), (0x200, 0x220)], Some(0x208));

        assert_eq!(
            ModuleData::selected_non_inline_ranges(&entry),
            vec![(0x200, 0x220)],
        );
    }

    #[test]
    fn selected_non_inline_ranges_without_entry_pc_keeps_first_range_even_if_later_range_is_larger()
    {
        let entry = subprogram_entry(&[(0x100, 0x110), (0x200, 0x260)], None);

        assert_eq!(
            ModuleData::selected_non_inline_ranges(&entry),
            vec![(0x100, 0x110)],
        );
    }

    #[test]
    fn selected_non_inline_probe_address_clamps_prologue_skip_to_function_range() {
        // Regression scenario:
        // The hot/cold fix intentionally prologue-skips non-inline functions by
        // asking the line table for the first executable PC after range start.
        // On optimized binaries the line table can sometimes return a PC from
        // the next function entirely. If we trust that blindly, function-level
        // tracing attaches to a sibling symbol and silently misses the target.
        //
        // This locks in the clamp: a candidate outside [start, end) must fall
        // back to the function's own start, while an in-range candidate is kept.
        assert_eq!(
            ModuleData::selected_non_inline_probe_address(0x1470, 0x147b, 0x14f2),
            0x1470
        );
        assert_eq!(
            ModuleData::selected_non_inline_probe_address(0x1470, 0x147b, 0x1474),
            0x1474
        );
    }

    #[test]
    fn selected_inline_address_prefers_entry_pc_over_cold_min_range() {
        // Regression scenario:
        // A DW_TAG_inlined_subroutine can carry multiple ranges, including a
        // lower-address cold fragment. Using min(range.start) would incorrectly
        // place the probe on the cold block even when DW_AT_entry_pc points at
        // the real hot entry into the inlined body.
        //
        // This test mirrors the CGPsend shape and ensures entry_pc wins.
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x8eb16a, 0x8eb1b0),
                (0x76e798, 0x76e7a2),
            ],
            Some(0x8eb16a),
        );

        assert_eq!(ModuleData::selected_inline_address(&entry), Some(0x8eb16a));
    }

    #[test]
    fn selected_inline_address_without_entry_pc_keeps_first_emitted_hot_range() {
        // Regression scenario:
        // Some inline DIEs omit DW_AT_entry_pc but still emit ranges in
        // compiler order, with the hot fragment first and a lower-address cold
        // fragment later. Sorting and taking min(range.start) reintroduces the
        // same cold-placement bug.
        //
        // This keeps the fallback policy stable: if entry_pc is missing, prefer
        // the first emitted range before considering a pure minimum.
        let entry = inline_entry(
            &[
                (0x8eb12b, 0x8eb139),
                (0x8eb150, 0x8eb157),
                (0x76e798, 0x76e7a2),
            ],
            None,
        );

        assert_eq!(ModuleData::selected_inline_address(&entry), Some(0x8eb12b));
    }

    #[test]
    fn selected_inline_address_ignores_entry_pc_outside_inline_ranges() {
        // Regression scenario:
        // Some optimized GCC builds emit an inlined_subroutine whose
        // DW_AT_entry_pc points at the caller-side setup block, while the
        // inline DIE's own ranges only cover the actual inlined body. Trusting
        // entry_pc unconditionally selects a PC where the inline parameters are
        // not in scope and later eBPF compilation fails with "Variable not in
        // scope".
        //
        // This mirrors the container CI failure shape: entry_pc=0x1215 but the
        // inline instance itself only covers [0x1289, 0x1293). A correct
        // selection must stay inside the inline DIE's own ranges.
        let entry = inline_entry(&[(0x1289, 0x1293)], Some(0x1215));

        assert_eq!(ModuleData::selected_inline_address(&entry), Some(0x1289));
    }

    #[test]
    fn selected_inline_address_keeps_entry_pc_only_point_scopes() {
        // Regression scenario:
        // Some inline/call-site DIEs are encoded as a single point with only
        // DW_AT_entry_pc and no ranges at all. Those scopes are still
        // addressable elsewhere in the DWARF pipeline, so inline address
        // selection must not drop them just because there is no range to
        // validate against.
        let entry = inline_entry(&[], Some(0x1289));

        assert_eq!(ModuleData::selected_inline_address(&entry), Some(0x1289));
    }

    #[test]
    fn subprogram_uses_entry_value_via_abstract_origin_parameters() {
        // Regression scenario:
        // After concrete out-of-line subprograms stopped inheriting is_inline,
        // they began using the non-inline address path again. That path needs to
        // know when parameter recovery depends on DW_OP_entry_value so it can
        // preserve the true entry PC instead of prologue-skipping.
        //
        // Optimized DWARF may place the formal parameters only on the abstract
        // origin, with the concrete subprogram inheriting them via
        // DW_AT_abstract_origin. This test ensures that inherited parameter DIEs
        // are still consulted for entry_value detection.
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            ModuleData::direct_formal_parameters_entry_value_state(&unit, &concrete).unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            ModuleData::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_abstract_origin"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_via_specification_parameters() {
        // Same as the abstract-origin case above, but for compilers that route
        // concrete subprograms through DW_AT_specification instead. Both origin
        // chains must preserve entry_value-driven entry selection.
        let dwarf = build_origin_backed_entry_value_fixture(constants::DW_AT_specification);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_specification);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            ModuleData::direct_formal_parameters_entry_value_state(&unit, &concrete).unwrap(),
            None,
            "concrete DIE should not expose direct parameter children in this fixture"
        );
        assert!(
            ModuleData::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "entry_value should be discovered through DW_AT_specification"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_does_not_override_concrete_parameter_locations() {
        // Regression scenario:
        // A concrete optimized subprogram may have its own formal_parameter
        // children that override the abstract origin's DW_AT_location, often via
        // DW_AT_abstract_origin on the parameter DIE itself. In that shape, the
        // concrete child is authoritative and origin-level entry_value must not
        // force prefer_entry=true.
        //
        // This test ensures direct concrete parameter locations win over the
        // origin's location expression.
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert_eq!(
            ModuleData::direct_formal_parameters_entry_value_state(&unit, &concrete).unwrap(),
            Some(false),
            "concrete DIE should treat its own parameter children as authoritative"
        );
        assert!(
            !ModuleData::subprogram_uses_entry_value(&dwarf, &unit, &concrete).unwrap(),
            "origin-level entry_value must not override concrete parameter locations"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_only_when_active_location_uses_it() {
        // Regression scenario:
        // The original entry_value check was too coarse: if any loclist segment
        // used DW_OP_entry_value anywhere in the function, we forced the probe
        // back to the raw entry. That breaks functions like optimized
        // calculate_something, where the first executable instruction still has
        // direct register locations and entry_value only appears later.
        //
        // This test builds that exact shape in miniature and verifies the new
        // rule: only the location expression active at the candidate probe PC
        // may trigger prefer_entry=true.
        let dwarf = build_origin_backed_entry_value_range_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !ModuleData::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474).unwrap(),
            "entry_value should not force the true entry while the active location is still a direct register"
        );
        assert!(
            ModuleData::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478).unwrap(),
            "entry_value should still be detected once the active location range switches to it"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_respects_concrete_parameter_overrides() {
        // This complements the test above: even with PC-sensitive loclist
        // evaluation, we must still honor concrete parameter overrides before
        // walking up to abstract origins/specifications. Otherwise an origin
        // loclist with entry_value could reclassify a concrete out-of-line body
        // that already exposed usable direct-register parameter locations.
        let dwarf =
            build_origin_backed_entry_value_override_fixture(constants::DW_AT_abstract_origin);
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !ModuleData::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1478).unwrap(),
            "concrete parameter locations must remain authoritative at the selected probe PC"
        );
    }

    #[test]
    fn subprogram_uses_entry_value_at_pc_prefers_specific_loclist_ranges_over_default_location() {
        // Regression scenario:
        // DWARF5 loclists may start with DW_LLE_default_location and then
        // override it with a later range-specific entry. gimli::locations()
        // normalizes the default to [0, u64::MAX), which can mask the later
        // specific range and incorrectly report entry_value everywhere.
        //
        // This fixture keeps entry_value in the default location but switches
        // to a direct register location for [0x1470, 0x147b). The specific
        // range must win at PCs inside that span, while the default still
        // applies outside it.
        let dwarf = build_origin_backed_default_location_entry_value_fixture(
            constants::DW_AT_abstract_origin,
        );
        let unit = first_unit(&dwarf);
        let concrete_offset =
            find_subprogram_with_origin_attr(&unit, constants::DW_AT_abstract_origin);
        let concrete = unit.entry(concrete_offset).unwrap();

        assert!(
            !ModuleData::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1474).unwrap(),
            "the specific direct-register range should override the default-location entry_value"
        );
        assert!(
            ModuleData::subprogram_uses_entry_value_at(&dwarf, &unit, &concrete, 0x1500).unwrap(),
            "outside the specific range, the default-location entry_value should still apply"
        );
    }

    #[test]
    fn build_demangled_maps_indexes_demangled_function_aliases() {
        let mangled = "_ZN2ns6Widget3runEv".to_string();
        let demangled =
            crate::core::demangle_by_lang(Some(gimli::DW_LANG_C_plus_plus_17), &mangled).unwrap();
        let leaf = crate::core::demangled_leaf(&demangled);

        let mut functions = HashMap::new();
        functions.insert(
            mangled.clone(),
            vec![IndexEntry {
                name: Arc::<str>::from(mangled.as_str()),
                die_offset: gimli::UnitOffset(0),
                unit_offset: gimli::DebugInfoOffset(0),
                tag: constants::DW_TAG_subprogram,
                flags: IndexFlags {
                    is_linkage: true,
                    ..Default::default()
                },
                language: Some(gimli::DW_LANG_C_plus_plus_17),
                address_ranges: vec![(0x1000, 0x1010)],
                entry_pc: Some(0x1000),
                function_kind: FunctionDieKind::ConcreteSubprogram,
            }],
        );

        let ix = LightweightIndex::from_builder_data(functions, HashMap::new(), HashMap::new());
        let maps = ModuleData::build_demangled_maps(&ix);

        assert_eq!(maps.function_map.get(&demangled), Some(&vec![0]));
        assert_eq!(maps.function_leaf_map.get(&leaf), Some(&vec![0]));
    }
}

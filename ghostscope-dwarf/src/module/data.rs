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
    core::{GlobalVariableInfo, MappedFile, Result, SectionType, SourceLocation},
    data::{
        CfiIndex, LightweightIndex, LineMappingTable, OnDemandResolver, ScopedFileIndexManager,
    },
    parser::{CompilationUnit, SourceFile},
    proc_mapping::ModuleMapping,
};
use gimli::{EndianSlice, LittleEndian};
use object::{Object, ObjectSection, ObjectSegment};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Instant,
};

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
    /// Memory mapped file (keep alive)
    _mapped_file: MappedFile,
    /// Per-function block/variable index (blockvector-like)
    block_index: crate::data::BlockIndex,
    /// Type name index for cross-CU completion
    type_name_index: crate::data::TypeNameIndex,
}

impl ModuleData {
    /// Parallel loading: debug_info || debug_line || CFI simultaneously
    pub(crate) async fn load_parallel(module_mapping: ModuleMapping) -> Result<Self> {
        tracing::info!("Parallel loading for: {}", module_mapping.path.display());
        Self::load_internal_parallel(module_mapping).await
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
            if let Ok(header) = dwarf.debug_info.header_from_offset(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Ok(Some(gimli::AttributeValue::UnitRef(under))) =
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
            if let Ok(header) = dwarf.debug_info.header_from_offset(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Ok(Some(gimli::AttributeValue::UnitRef(under))) =
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
            if let Ok(header) = dwarf.debug_info.header_from_offset(td.cu_offset) {
                if let Ok(unit) = dwarf.unit(header) {
                    if let Ok(entry) = unit.entry(td.die_offset) {
                        if let Ok(Some(gimli::AttributeValue::UnitRef(under))) =
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
    async fn load_internal_parallel(module_mapping: ModuleMapping) -> Result<Self> {
        tracing::debug!(
            "Loading module in parallel: {}",
            module_mapping.path.display()
        );

        // Memory map the file once
        let mapped_file = std::sync::Arc::new(Self::map_file(&module_mapping.path)?);

        // Parse object file
        let object = object::File::parse(&mapped_file.data[..])?;

        // Load DWARF sections
        let dwarf = std::sync::Arc::new(Self::load_dwarf_sections(&object)?);

        tracing::debug!(
            "Starting parallel DWARF parsing with true debug_line || debug_info parallelism..."
        );

        // Parse three components in parallel: debug_line || debug_info || CFI
        let (line_result, info_result, cfi_index_result) = tokio::try_join!(
            // Parse debug_line only
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<crate::parser::LineParseResult> {
                    let parser = crate::parser::DwarfParser::new(&dwarf);
                    parser.parse_line_info(&module_path)
                }
            }),
            // Parse debug_info only
            tokio::task::spawn_blocking({
                let dwarf = std::sync::Arc::clone(&dwarf);
                let module_path = module_mapping.path.to_string_lossy().to_string();
                move || -> Result<crate::parser::DebugParseResult> {
                    let parser = crate::parser::DwarfParser::new(&dwarf);
                    parser.parse_debug_info(&module_path)
                }
            }),
            // Parse CFI independently (uses raw file data)
            tokio::task::spawn_blocking({
                let mapped_file = std::sync::Arc::clone(&mapped_file);
                let module_path = module_mapping.path.clone();
                move || -> Result<Option<crate::data::CfiIndex>> {
                    // SAFETY: We keep the mapped file alive for the lifetime of the module
                    // The Arc ensures the memory remains valid during CFI parsing
                    let static_data: &'static [u8] =
                        unsafe { std::mem::transmute(&mapped_file.data[..]) };
                    match crate::data::CfiIndex::from_static_data(static_data) {
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
        let line_result = line_result?;
        let info_result = info_result?;
        let cfi_index = cfi_index_result?;

        // Assemble parallel results into unified result
        let parse_result = crate::parser::DwarfParser::combine_parallel_results(
            line_result,
            info_result,
            module_mapping.path.to_string_lossy().to_string(),
        );

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

        // Build type name index from lightweight index
        let type_name_index =
            crate::data::TypeNameIndex::build_from_lightweight(&parse_result.lightweight_index);
        let type_index_arc = std::sync::Arc::new(type_name_index.clone());

        // Create resolver with parsed data and type index
        let resolver = crate::data::OnDemandResolver::new_with_type_index(
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

        tracing::info!(
            "True parallel loading completed for {}: {} functions, {} variables, {} line entries, {} files (state: {:?})",
            module_mapping.path.display(),
            parse_result.stats.total_functions,
            parse_result.stats.total_variables,
            parse_result.stats.total_line_entries,
            parse_result.stats.total_files,
            state_label
        );

        Ok(Self {
            module_mapping: module_mapping.clone(),
            lightweight_index: parse_result.lightweight_index,
            line_mapping: parse_result.line_mapping,
            scoped_file_manager: parse_result.scoped_file_manager,
            compilation_units: parse_result.compilation_units,
            cfi_index,
            resolver,
            block_index: crate::data::BlockIndex::new(),
            type_name_index,
            _mapped_file: std::sync::Arc::try_unwrap(mapped_file)
                .map_err(|_| anyhow::anyhow!("Failed to unwrap MappedFile Arc"))?,
        })
    }

    /// Memory map the file
    fn map_file(path: &PathBuf) -> Result<MappedFile> {
        use std::fs::File;
        let file = File::open(path)?;
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file)? };

        Ok(MappedFile {
            data: mmap,
            path: path.clone(),
        })
    }

    /// Load DWARF sections using gimli
    fn load_dwarf_sections(
        object: &object::File,
    ) -> Result<gimli::Dwarf<EndianSlice<'static, LittleEndian>>> {
        // Load DWARF sections
        let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'static, LittleEndian>> {
            let data = object
                .section_by_name(id.name())
                .and_then(|section| section.uncompressed_data().ok())
                .unwrap_or(std::borrow::Cow::Borrowed(&[]));

            // SAFETY: We keep the mapped file alive for the lifetime of the module
            let data: &'static [u8] = unsafe { std::mem::transmute(data.as_ref()) };
            Ok(EndianSlice::new(data, LittleEndian))
        };

        let dwarf = gimli::Dwarf::load(load_section)?;
        Ok(dwarf)
    }

    /// Convert a virtual address (DWARF PC) to an ELF file offset using PT_LOAD segments
    /// Returns None if no containing segment is found
    pub(crate) fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        // Re-parse the object file on-demand from the mapped file
        if self._mapped_file.data.is_empty() {
            return None;
        }
        let data: &[u8] = &self._mapped_file.data;
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

    /// Lookup function addresses by name with prologue skipping for real functions
    pub(crate) fn lookup_function_addresses(&self, name: &str) -> Vec<u64> {
        tracing::debug!("ModuleData: looking up function '{}'", name);

        // Get function entries from lightweight index
        let entries = self.lightweight_index.find_dies_by_function_name(name);
        let mut addresses = Vec::new();

        for entry in entries {
            if entry.flags.is_inline {
                let mut candidate_addresses: Vec<u64> = entry
                    .address_ranges
                    .iter()
                    .map(|(start_addr, _)| *start_addr)
                    .collect();

                if let Some(entry_pc) = entry.entry_pc {
                    candidate_addresses.push(entry_pc);
                }

                candidate_addresses.sort_unstable();
                candidate_addresses.dedup();

                for candidate in candidate_addresses {
                    tracing::debug!(
                        "ModuleData: function '{}' is inline at 0x{:x}, registering address",
                        name,
                        candidate
                    );
                    if !addresses.contains(&candidate) {
                        addresses.push(candidate);
                    }
                }
            } else {
                for (start_addr, _end_addr) in &entry.address_ranges {
                    let executable_addr =
                        self.line_mapping.find_first_executable_address(*start_addr);
                    tracing::debug!(
                        "ModuleData: function '{}' is real function at 0x{:x}, first executable at 0x{:x} (offset +{})",
                        name, start_addr, executable_addr, executable_addr - start_addr
                    );
                    addresses.push(executable_addr);
                }
            }
        }

        tracing::debug!(
            "ModuleData: function '{}' resolved to {} addresses: {:?}",
            name,
            addresses.len(),
            addresses
        );
        addresses
    }

    /// Get all variables visible at the given address with EvaluationResult
    pub(crate) fn get_all_variables_at_address(
        &mut self,
        address: u64,
    ) -> Result<Vec<crate::data::VariableWithEvaluation>> {
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
            if let Some(e) = self.lightweight_index.find_die_at_address(address) {
                let cu_off = e.unit_offset;
                let builder = crate::data::BlockIndexBuilder::new(self.resolver.dwarf_ref());
                if e.tag == gimli::constants::DW_TAG_subprogram {
                    if let Some(fb) = builder.build_for_function(cu_off, e.die_offset) {
                        tracing::info!(
                            "BlockIndex: built 1 function '{}' for CU {:?}",
                            fb.name.clone().unwrap_or_else(|| "<anon>".to_string()),
                            cu_off
                        );
                        self.block_index.add_functions(vec![fb]);
                        built_funcs += 1;
                    }
                } else if let Some(funcs) = builder.build_for_unit(cu_off) {
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
                        if let Ok(header) = dwarf_ref.debug_info.header_from_offset(vr.cu_offset) {
                            if let Ok(unit) = dwarf_ref.unit(header) {
                                if let Ok(entry) = unit.entry(vr.die_offset) {
                                    let planner = crate::planner::AccessPlanner::new(dwarf_ref);
                                    if let Ok(Some(tdie)) =
                                        planner.resolve_type_ref_with_origins_public(&entry, &unit)
                                    {
                                        if let Some(ty) =
                                            self.detailed_shallow_type(vr.cu_offset, tdie)
                                        {
                                            var_out.type_name = ty.type_name();
                                            var_out.dwarf_type = Some(ty);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                tracing::info!(
                    "DWARF:get_vars resolved {} vars total_ms={}",
                    vars.len(),
                    t0.elapsed().as_millis()
                );
                return Ok(vars);
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
    ) -> Result<Option<crate::data::VariableWithEvaluation>> {
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
            let builder = crate::data::BlockIndexBuilder::new(self.resolver.dwarf_ref());
            // Prefer building only the containing subprogram if we can identify it
            if let Some(func_entry) = self.lightweight_index.find_function_by_address(address) {
                if let Some(fb) =
                    builder.build_for_function(func_entry.unit_offset, func_entry.die_offset)
                {
                    self.block_index.add_functions(vec![fb]);
                    built_funcs += 1;
                }
            } else if let Some(e) = self.lightweight_index.find_die_at_address(address) {
                // Fallback: if we only found a non-subprogram DIE, try to identify CU and build-for-unit
                let cu_off = e.unit_offset;
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
            let header = dwarf.debug_info.header_from_offset(func.cu_offset)?;
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
                if let Some(attr) = e.attr(gimli::DW_AT_name)? {
                    if let Ok(s) = dwarf.attr_string(&unit, attr.value()) {
                        cand_names.push(s.to_string_lossy().into_owned());
                    }
                }
            }
            tracing::info!("DWARF:plan_chain candidates_names={:?}", cand_names);

            for v in candidates {
                let e = unit.entry(v.die_offset)?;
                if let Some(attr) = e.attr(gimli::DW_AT_name)? {
                    if let Ok(s) = dwarf.attr_string(&unit, attr.value()) {
                        let n = s.to_string_lossy();
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
                                        let header =
                                            dwarf.debug_info.header_from_offset(func.cu_offset)?;
                                        let unit = dwarf.unit(header)?;
                                        let e = unit.entry(v.die_offset)?;
                                        let planner = crate::planner::AccessPlanner::new(dwarf);
                                        if let Some(type_die_off) = planner
                                            .resolve_type_ref_with_origins_public(&e, &unit)?
                                        {
                                            let tstart = Instant::now();
                                            if let Some(ty) = self
                                                .detailed_shallow_type(func.cu_offset, type_die_off)
                                            {
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
                                crate::data::on_demand_resolver::ChainSpec {
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
        }
        // Fallback: try planning from a CU-scope global/static variable with the same base name
        // This enables expressions like G_STATE.counter when G_STATE is a global.
        let globals = self.find_global_variables_by_name(base_var);
        if !globals.is_empty() {
            // Try each candidate until one plans successfully
            for info in globals {
                let spec = crate::data::on_demand_resolver::ChainSpec {
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
                        || (full_path.contains(&entry.compilation_unit)
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
            if let Some(cu_stem) = std::path::Path::new(&entry.compilation_unit).file_stem() {
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

        Some(entry.compilation_unit.clone())
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
                        file_path: line_entry.compilation_unit.clone(),
                        line_number: line_entry.line as u32,
                        column: Some(line_entry.column as u32),
                        address: line_entry.address,
                    });
                }
            }

            // Fallback to CU string if resolution failed
            return Some(SourceLocation {
                file_path: line_entry.compilation_unit.clone(),
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
            } else if self.is_path_like(&line_entry.compilation_unit) {
                tracing::debug!(
                    "create_source_location_from_entry: using CU path: '{}' (scoped result was bare)",
                    line_entry.compilation_unit
                );
                line_entry.compilation_unit.clone()
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
    pub(crate) fn get_lightweight_index(&self) -> &crate::data::LightweightIndex {
        &self.lightweight_index
    }

    /// Get line header count for debugging (legacy compatibility)
    pub(crate) fn get_line_header_count(&self) -> usize {
        self.scoped_file_manager.get_stats().1
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

    /// Helper: shallow resolve a type at (cu, die_off)
    fn detailed_shallow_type(
        &self,
        cu_off: gimli::DebugInfoOffset,
        die_off: gimli::UnitOffset,
    ) -> Option<crate::TypeInfo> {
        let dwarf = self.resolver.dwarf_ref();
        let header = dwarf.debug_info.header_from_offset(cu_off).ok()?;
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
        let header = dwarf.debug_info.header_from_offset(cu_off).ok()?;
        let unit = dwarf.unit(header).ok()?;
        let entry = unit.entry(die_off).ok()?;
        let planner = crate::planner::AccessPlanner::new(dwarf);
        match planner.resolve_type_ref_with_origins_public(&entry, &unit) {
            Ok(Some(type_die_off)) => self.detailed_shallow_type(cu_off, type_die_off),
            _ => None,
        }
    }

    /// Resolve variables by (CU, DIE) offsets at a given address context using the on-demand resolver
    pub(crate) fn resolve_variables_by_offsets_at_address(
        &mut self,
        address: u64,
        items: &[(gimli::DebugInfoOffset, gimli::UnitOffset)],
    ) -> Result<Vec<crate::data::VariableWithEvaluation>> {
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
        self.lightweight_index
            .find_die_at_address(address)
            .map(|entry| entry.name.clone())
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

        // Parse object file once for section classification
        let obj = match object::File::parse(&self._mapped_file.data[..]) {
            Ok(f) => f,
            Err(_) => {
                // Cannot classify sections, but still return entries with link_address
                for e in entries {
                    let link_address =
                        e.address_ranges
                            .first()
                            .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });
                    out.push(GlobalVariableInfo {
                        name: e.name.clone(),
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
            let link_address =
                e.address_ranges
                    .first()
                    .and_then(|(lo, hi)| if lo == hi { Some(*lo) } else { None });

            let section = link_address.and_then(|addr| self.classify_section(&obj, addr));

            out.push(GlobalVariableInfo {
                name: e.name.clone(),
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
                } else if name == ".rodata" || name.starts_with(".rodata") {
                    SectionType::Rodata
                } else if name == ".data" || name.starts_with(".data.") {
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
        match object::File::parse(&self._mapped_file.data[..]) {
            Ok(obj) => self.classify_section(&obj, addr),
            Err(_) => None,
        }
    }

    /// List all global/static variables with usable addresses in this module
    pub(crate) fn list_all_global_variables(&self) -> Vec<GlobalVariableInfo> {
        let mut out = Vec::new();
        // Parse object once for section classification
        let _obj = match object::File::parse(&self._mapped_file.data[..]) {
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

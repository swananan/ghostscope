use super::LoadedObjfile;
use crate::{
    binary::{
        dwarf_endian_from_object, empty_dwarf_reader_with_endian, try_load_debug_file, DwarfData,
        MappedFile,
    },
    core::{mapping::ModuleMapping, Result},
    index::{BlockIndex, CfiIndex, TypeNameIndex},
    parser::DetailedParser,
};
use ghostscope_debuginfod::{build_id_to_hex, DebuginfodClient};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use std::{collections::HashMap, path::Path, sync::Arc, time::Instant};

impl LoadedObjfile {
    /// Parallel loading: debug_info || debug_line || CFI simultaneously
    pub(crate) async fn load_parallel(
        module_mapping: ModuleMapping,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
    ) -> Result<Self> {
        tracing::info!("Parallel loading for: {}", module_mapping.path.display());
        Self::load_internal_parallel(
            module_mapping,
            debug_search_paths,
            allow_loose_debug_match,
            debuginfod_client,
        )
        .await
    }

    /// Parallel internal load implementation - true parallelism for debug_info || debug_line || CFI
    async fn load_internal_parallel(
        module_mapping: ModuleMapping,
        debug_search_paths: &[String],
        allow_loose_debug_match: bool,
        debuginfod_client: Option<Arc<DebuginfodClient>>,
    ) -> Result<Self> {
        let load_started_at = Instant::now();
        tracing::debug!(
            "Loading module in parallel: {}",
            module_mapping.path.display()
        );

        let binary_mapped = Arc::new(MappedFile::open(&module_mapping.path)?);
        let dwarf_result = Self::load_dwarf_sections(&binary_mapped);

        let (dwarf, mapped_file_for_dwarf) = match dwarf_result {
            Ok(dwarf_data) => {
                if Self::has_debug_info(&dwarf_data) {
                    tracing::debug!(
                        "Found debug info in binary: {}",
                        module_mapping.path.display()
                    );
                    (Arc::new(dwarf_data), Arc::clone(&binary_mapped))
                } else {
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
                            let debug_mapped = Arc::new(debug_mapped);
                            let debug_dwarf = Self::load_dwarf_sections(&debug_mapped)?;
                            (Arc::new(debug_dwarf), debug_mapped)
                        }
                        None => {
                            match Self::try_load_debuginfod_debug_file(
                                debuginfod_client.as_ref(),
                                &binary_mapped,
                                &module_mapping.path,
                            )
                            .await
                            {
                                Some((debug_dwarf, debug_mapped)) => {
                                    (Arc::new(debug_dwarf), debug_mapped)
                                }
                                None => {
                                    tracing::warn!(
                                        "No separate debug file found for: {}",
                                        module_mapping.path.display()
                                    );
                                    (Arc::new(dwarf_data), Arc::clone(&binary_mapped))
                                }
                            }
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

        let mapped_file = mapped_file_for_dwarf;

        tracing::debug!(
            "Starting parallel DWARF parsing with true debug_line || debug_info parallelism..."
        );

        let (pair_result, cfi_index_result) = tokio::try_join!(
            tokio::task::spawn_blocking({
                let dwarf = Arc::clone(&dwarf);
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
            tokio::task::spawn_blocking({
                let binary_for_cfi = Arc::clone(&binary_mapped);
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

        let (line_result, info_result) = pair_result?;
        let cfi_index = cfi_index_result?;

        let parse_result = crate::parser::DwarfParser::combine_parallel_results(
            line_result,
            info_result,
            module_mapping.path.to_string_lossy().to_string(),
        );
        let parse_elapsed_ms = load_started_at.elapsed().as_millis();

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
        let (lightweight_index, type_name_index) = tokio::task::spawn_blocking(move || {
            let type_name_index = TypeNameIndex::build_from_lightweight(&lightweight_index);
            (lightweight_index, type_name_index)
        })
        .await?;
        let type_name_index = Arc::new(type_name_index);
        let dwarf =
            Arc::try_unwrap(dwarf).map_err(|_| anyhow::anyhow!("Failed to unwrap DWARF Arc"))?;
        let mut detailed_parser = DetailedParser::new();
        detailed_parser.set_type_name_index(Arc::clone(&type_name_index));
        let text_symbol_starts_by_name = Self::collect_text_symbol_starts(&binary_mapped);

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
        let load_total_ms = load_started_at.elapsed().as_millis() as u64;

        let module = Self {
            module_mapping: module_mapping.clone(),
            lightweight_index,
            line_mapping,
            scoped_file_manager,
            compilation_units,
            cfi_index,
            dwarf,
            detailed_parser,
            block_index: std::sync::RwLock::new(BlockIndex::new()),
            type_name_index,
            _dwarf_mapped_file: mapped_file,
            _binary_mapped_file: binary_mapped,
            text_symbol_starts_by_name,
            load_parse_ms: parse_elapsed_ms as u64,
            load_index_ms: index_elapsed_ms as u64,
            load_total_ms,
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
            load_total_ms
        );

        Ok(module)
    }

    fn has_debug_info(dwarf: &DwarfData) -> bool {
        matches!(dwarf.units().next(), Ok(Some(_)))
    }

    async fn try_load_debuginfod_debug_file(
        debuginfod_client: Option<&Arc<DebuginfodClient>>,
        binary_mapped: &Arc<MappedFile>,
        module_path: &Path,
    ) -> Option<(DwarfData, Arc<MappedFile>)> {
        let client = debuginfod_client?;
        let build_id = match Self::build_id_for_debuginfod(binary_mapped, module_path) {
            Some(build_id) => build_id,
            None => return None,
        };
        let build_id_hex = build_id_to_hex(&build_id);

        tracing::info!(
            "Trying debuginfod debug info for {} (build-id={})",
            module_path.display(),
            build_id_hex
        );

        let fetched = match client.fetch_debuginfo(&build_id).await {
            Ok(Some(fetched)) => fetched,
            Ok(None) => {
                tracing::debug!(
                    "debuginfod had no debug info for {} (build-id={})",
                    module_path.display(),
                    build_id_hex
                );
                return None;
            }
            Err(err) => {
                tracing::warn!(
                    "debuginfod lookup failed for {} (build-id={}): {}",
                    module_path.display(),
                    build_id_hex,
                    err
                );
                return None;
            }
        };

        tracing::info!(
            "debuginfod returned debug info for {} from {} (path={}, from_cache={})",
            module_path.display(),
            fetched.url.as_deref().unwrap_or("<cache>"),
            fetched.path.display(),
            fetched.from_cache
        );

        let debug_mapped = match MappedFile::open(&fetched.path) {
            Ok(mapped) => Arc::new(mapped),
            Err(err) => {
                tracing::warn!(
                    "Failed to open debuginfod debug file {} for {}: {}",
                    fetched.path.display(),
                    module_path.display(),
                    err
                );
                return None;
            }
        };

        if !Self::debuginfod_debug_file_matches_build_id(&debug_mapped, &build_id, module_path) {
            return None;
        }

        let debug_dwarf = match Self::load_dwarf_sections(&debug_mapped) {
            Ok(dwarf) => dwarf,
            Err(err) => {
                tracing::warn!(
                    "Failed to load DWARF sections from debuginfod debug file {} for {}: {}",
                    debug_mapped.path.display(),
                    module_path.display(),
                    err
                );
                return None;
            }
        };

        if !Self::has_debug_info(&debug_dwarf) {
            tracing::warn!(
                "Ignoring debuginfod debug file {} for {} because it contains no .debug_info",
                debug_mapped.path.display(),
                module_path.display()
            );
            return None;
        }

        tracing::info!(
            "Loading DWARF from debuginfod debug file: {}",
            debug_mapped.path.display()
        );
        Some((debug_dwarf, debug_mapped))
    }

    fn build_id_for_debuginfod(binary_mapped: &MappedFile, module_path: &Path) -> Option<Vec<u8>> {
        let object = match binary_mapped.parse_object() {
            Ok(object) => object,
            Err(err) => {
                tracing::warn!(
                    "Failed to parse object while reading build-id for {}: {}",
                    module_path.display(),
                    err
                );
                return None;
            }
        };

        match object.build_id() {
            Ok(Some(build_id)) => Some(build_id.to_vec()),
            Ok(None) => {
                tracing::debug!(
                    "No build-id in {}; skipping debuginfod",
                    module_path.display()
                );
                None
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to read build-id from {}; skipping debuginfod: {}",
                    module_path.display(),
                    err
                );
                None
            }
        }
    }

    fn debuginfod_debug_file_matches_build_id(
        debug_mapped: &MappedFile,
        expected_build_id: &[u8],
        module_path: &Path,
    ) -> bool {
        let expected = build_id_to_hex(expected_build_id);
        let object = match debug_mapped.parse_object() {
            Ok(object) => object,
            Err(err) => {
                tracing::warn!(
                    "Ignoring debuginfod debug file {} for {}: failed to parse object: {}",
                    debug_mapped.path.display(),
                    module_path.display(),
                    err
                );
                return false;
            }
        };

        match object.build_id() {
            Ok(Some(actual_build_id)) if actual_build_id == expected_build_id => {
                tracing::info!(
                    "debuginfod build-id verification passed for {}: {}",
                    debug_mapped.path.display(),
                    expected
                );
                true
            }
            Ok(Some(actual_build_id)) => {
                tracing::warn!(
                    "Ignoring debuginfod debug file {} for {}: build-id mismatch expected={}, actual={}",
                    debug_mapped.path.display(),
                    module_path.display(),
                    expected,
                    build_id_to_hex(actual_build_id)
                );
                false
            }
            Ok(None) => {
                tracing::warn!(
                    "Ignoring debuginfod debug file {} for {}: missing build-id, expected={}",
                    debug_mapped.path.display(),
                    module_path.display(),
                    expected
                );
                false
            }
            Err(err) => {
                tracing::warn!(
                    "Ignoring debuginfod debug file {} for {}: failed to read build-id: {}",
                    debug_mapped.path.display(),
                    module_path.display(),
                    err
                );
                false
            }
        }
    }

    fn collect_text_symbol_starts(binary_mapped: &MappedFile) -> HashMap<String, Vec<u64>> {
        let object = match binary_mapped.parse_object() {
            Ok(object) => object,
            Err(err) => {
                tracing::warn!(
                    "Failed to parse object while building text symbol cache for {}: {}",
                    binary_mapped.path.display(),
                    err
                );
                return HashMap::new();
            }
        };

        let mut by_name: HashMap<String, Vec<u64>> = HashMap::new();
        for symbol in object.symbols() {
            if symbol.kind() != SymbolKind::Text {
                continue;
            }

            let Ok(name) = symbol.name() else {
                continue;
            };
            by_name
                .entry(name.to_string())
                .or_default()
                .push(symbol.address());
        }

        for starts in by_name.values_mut() {
            starts.sort_unstable();
            starts.dedup();
        }

        by_name
    }

    fn load_dwarf_sections(file_data: &Arc<MappedFile>) -> Result<DwarfData> {
        let object = file_data.parse_object()?;
        let endian = dwarf_endian_from_object(&object);

        let load_section = |id: gimli::SectionId| -> Result<_> {
            if let Some(section) = object.section_by_name(id.name()) {
                if let Some((start, size)) = section.file_range() {
                    MappedFile::dwarf_reader_range(Arc::clone(file_data), start, size, endian)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Invalid DWARF section range for {}", id.name())
                        })
                } else {
                    Ok(empty_dwarf_reader_with_endian(endian))
                }
            } else {
                Ok(empty_dwarf_reader_with_endian(endian))
            }
        };

        let dwarf = gimli::Dwarf::load(load_section)?;
        Ok(dwarf)
    }
}

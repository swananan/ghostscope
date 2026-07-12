//! Loaded object file: complete DWARF data for a single binary

use crate::{
    binary::{DwarfReader, MappedFile},
    core::{mapping::ModuleMapping, DebugInfoSource, Result},
    index::{
        BlockIndex, GdbIndex, GdbSymbolKind, LightweightIndex, LineMappingTable,
        ScopedFileIndexManager, TypeNameIndex,
    },
    objfile::ModuleUnwindInfo,
    parser::{CompilationUnit, DetailedParser, DwarfParser},
};
use object::{Object, ObjectSegment};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

type FunctionRangeCacheKey = (u64, u64);

/// Complete DWARF data for a single loaded object file.
#[derive(Debug)]
pub(crate) struct LoadedObjfile {
    pub(super) module_mapping: ModuleMapping,
    pub(super) lightweight_index: RwLock<LightweightIndex>,
    pub(super) line_mapping: RwLock<LineMappingTable>,
    pub(super) scoped_file_manager: RwLock<ScopedFileIndexManager>,
    pub(super) compilation_units: RwLock<HashMap<String, CompilationUnit>>,
    pub(super) line_source_unit_offsets: HashMap<String, Vec<gimli::DebugInfoOffset>>,
    pub(super) indexed_line_cus: Mutex<HashSet<gimli::DebugInfoOffset>>,
    pub(super) unwind_info: ModuleUnwindInfo,
    pub(super) dwarf: gimli::Dwarf<DwarfReader>,
    pub(super) detailed_parser: DetailedParser,
    pub(super) _dwarf_mapped_file: Arc<MappedFile>,
    pub(super) _binary_mapped_file: Arc<MappedFile>,
    pub(super) debug_info_source: DebugInfoSource,
    pub(super) entry_address: Option<u64>,
    pub(super) text_symbol_starts_by_name: HashMap<String, Vec<u64>>,
    pub(super) function_ranges_cache: RwLock<HashMap<FunctionRangeCacheKey, Vec<(u64, u64)>>>,
    pub(super) block_index: RwLock<BlockIndex>,
    pub(super) type_name_index: RwLock<TypeNameIndex>,
    pub(super) gdb_index: Option<GdbIndex>,
    pub(super) dwarf_index_status: crate::DwarfIndexStatus,
    pub(super) lazy_debug_info: bool,
    pub(super) indexed_debug_info_cus: Mutex<HashSet<gimli::DebugInfoOffset>>,
    pub(super) load_parse_ms: u64,
    pub(super) load_index_ms: u64,
    pub(super) load_total_ms: u64,
}

impl LoadedObjfile {
    pub(crate) fn module_path(&self) -> &PathBuf {
        &self.module_mapping.path
    }

    pub(crate) fn module_mapping(&self) -> &ModuleMapping {
        &self.module_mapping
    }

    pub(crate) fn update_runtime_mapping(
        &mut self,
        loaded_address: Option<u64>,
        load_bias: Option<u64>,
        size: u64,
    ) {
        self.module_mapping.loaded_address = loaded_address;
        self.module_mapping.load_bias = load_bias;
        self.module_mapping.size = size;
    }

    pub(crate) fn entry_address(&self) -> Option<u64> {
        self.entry_address
    }

    pub(crate) fn get_function_names(&self) -> Vec<String> {
        if let Some(index) = &self.gdb_index {
            match index.symbol_names(GdbSymbolKind::Function) {
                Ok(names) => return names.to_vec(),
                Err(error) => tracing::warn!(
                    "Failed to read .gdb_index function names for {}: {}",
                    self.module_path().display(),
                    error
                ),
            }
        }
        self.lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .get_function_names()
            .into_iter()
            .cloned()
            .collect()
    }

    pub(crate) fn get_variable_names(&self) -> Vec<String> {
        if let Some(index) = &self.gdb_index {
            match index.symbol_names(GdbSymbolKind::Variable) {
                Ok(names) => return names.to_vec(),
                Err(error) => tracing::warn!(
                    "Failed to read .gdb_index variable names for {}: {}",
                    self.module_path().display(),
                    error
                ),
            }
        }
        self.lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .get_variable_names()
            .into_iter()
            .cloned()
            .collect()
    }

    pub(crate) fn get_index_stats(&self) -> (usize, usize, usize) {
        if let Some(index) = &self.gdb_index {
            let functions = index
                .symbol_names(GdbSymbolKind::Function)
                .map_or(0, <[String]>::len);
            let variables = index
                .symbol_names(GdbSymbolKind::Variable)
                .map_or(0, <[String]>::len);
            let types = index
                .symbol_names(GdbSymbolKind::Type)
                .map_or(0, <[String]>::len);
            return (functions, variables, functions + variables + types);
        }
        self.lightweight_index
            .read()
            .expect("lightweight index lock poisoned")
            .get_stats()
    }

    pub(crate) fn dwarf_index_status(&self) -> &crate::DwarfIndexStatus {
        &self.dwarf_index_status
    }

    pub(crate) fn get_line_header_count(&self) -> usize {
        self.scoped_file_manager
            .read()
            .expect("scoped file index lock poisoned")
            .get_stats()
            .1
    }

    pub(crate) fn has_dwarf_info(&self) -> bool {
        self.get_line_header_count() > 0
    }

    pub(crate) fn get_debug_file_path(&self) -> Option<PathBuf> {
        let dwarf_path = &self._dwarf_mapped_file.path;
        let binary_path = &self._binary_mapped_file.path;

        if dwarf_path != binary_path {
            Some(dwarf_path.clone())
        } else {
            None
        }
    }

    pub(crate) fn get_debug_info_source(&self) -> &DebugInfoSource {
        &self.debug_info_source
    }

    pub(super) fn dwarf(&self) -> &gimli::Dwarf<DwarfReader> {
        &self.dwarf
    }

    pub(super) fn ensure_debug_info_for_symbol(
        &self,
        name: &str,
        kind: GdbSymbolKind,
        match_variants: bool,
    ) -> Result<()> {
        let Some(index) = &self.gdb_index else {
            return Ok(());
        };
        let symbols = if match_variants {
            index.lookup_matching_symbols(name, kind)?
        } else {
            index.lookup_symbol(name, kind)?
        };
        self.ensure_debug_info_cus(symbols.into_iter().map(|symbol| symbol.cu_offset))
    }

    pub(super) fn ensure_debug_info_for_address(&self, address: u64) -> Result<()> {
        if !self.lazy_debug_info {
            return Ok(());
        }
        let gdb_cu = self
            .gdb_index
            .as_ref()
            .map(|index| index.find_cu_by_address(address))
            .transpose()?
            .flatten();
        let cu_offset = gdb_cu.or_else(|| {
            self.lightweight_index
                .read()
                .expect("lightweight index lock poisoned")
                .find_cu_by_address(address)
        });
        let Some(cu_offset) = cu_offset else {
            return Ok(());
        };
        self.ensure_debug_info_cus(std::iter::once(cu_offset))
    }

    pub(super) fn ensure_debug_info_for_entries(
        &self,
        entries: &[crate::core::IndexEntry],
    ) -> Result<()> {
        if !self.lazy_debug_info {
            return Ok(());
        }
        self.ensure_debug_info_cus(entries.iter().map(|entry| entry.unit_offset))
    }

    pub(super) fn ensure_debug_info_for_type_name(&self, name: &str) -> Result<()> {
        self.ensure_debug_info_for_symbol(name, GdbSymbolKind::Type, true)?;
        if !self.lazy_debug_info {
            return Ok(());
        }
        let unit_offsets = self
            .type_name_index
            .read()
            .expect("type name index lock poisoned")
            .unit_offsets_for_name(name);
        self.ensure_debug_info_cus(unit_offsets)
    }

    pub(super) fn ensure_line_info_for_unit(
        &self,
        unit_offset: gimli::DebugInfoOffset,
    ) -> Result<()> {
        self.ensure_line_info_cus(std::iter::once(unit_offset))
    }

    pub(super) fn ensure_line_info_for_address(&self, address: u64) -> Result<()> {
        let gdb_cu = self
            .gdb_index
            .as_ref()
            .map(|index| index.find_cu_by_address(address))
            .transpose()?
            .flatten();
        let unit_offset = gdb_cu.or_else(|| {
            self.lightweight_index
                .read()
                .expect("lightweight index lock poisoned")
                .find_cu_by_address(address)
        });
        if let Some(unit_offset) = unit_offset {
            self.ensure_line_info_for_unit(unit_offset)?;
        }
        Ok(())
    }

    pub(super) fn ensure_line_info_for_source(&self, file_path: &str) -> Result<()> {
        let unit_offsets = self
            .line_source_unit_offsets
            .iter()
            .filter(|(indexed_path, _)| {
                crate::path_match::source_path_matches(indexed_path, file_path)
            })
            .flat_map(|(_, offsets)| offsets.iter().copied())
            .collect::<Vec<_>>();
        self.ensure_line_info_cus(unit_offsets)
    }

    fn ensure_debug_info_cus(
        &self,
        unit_offsets: impl IntoIterator<Item = gimli::DebugInfoOffset>,
    ) -> Result<()> {
        let mut loaded = self
            .indexed_debug_info_cus
            .lock()
            .expect("indexed CU lock poisoned");
        let mut missing = unit_offsets
            .into_iter()
            .filter(|unit_offset| !loaded.contains(unit_offset))
            .collect::<Vec<_>>();
        missing.sort_unstable_by_key(|offset| offset.0);
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }

        let shards = DwarfParser::new(&self.dwarf).parse_debug_info_cus(&missing)?;
        let mut lightweight_index = self
            .lightweight_index
            .write()
            .expect("lightweight index lock poisoned");
        lightweight_index.append_shards(shards);
        *self
            .type_name_index
            .write()
            .expect("type name index lock poisoned") =
            TypeNameIndex::build_from_lightweight(&lightweight_index);
        loaded.extend(missing);
        Ok(())
    }

    fn ensure_line_info_cus(
        &self,
        unit_offsets: impl IntoIterator<Item = gimli::DebugInfoOffset>,
    ) -> Result<()> {
        let mut loaded = self
            .indexed_line_cus
            .lock()
            .expect("indexed line CU lock poisoned");
        let mut missing = unit_offsets
            .into_iter()
            .filter(|unit_offset| !loaded.contains(unit_offset))
            .collect::<Vec<_>>();
        missing.sort_unstable_by_key(|offset| offset.0);
        missing.dedup();
        if missing.is_empty() {
            return Ok(());
        }

        let module_path = self.module_path().to_string_lossy();
        let result = DwarfParser::new(&self.dwarf).parse_line_info_cus(&module_path, &missing)?;
        self.line_mapping
            .write()
            .expect("line mapping lock poisoned")
            .extend(result.line_mapping);
        self.scoped_file_manager
            .write()
            .expect("scoped file index lock poisoned")
            .extend(result.scoped_file_manager);
        self.compilation_units
            .write()
            .expect("compilation unit lock poisoned")
            .extend(result.compilation_units);
        loaded.extend(missing);
        Ok(())
    }

    pub(crate) fn get_load_timing_ms(&self) -> (u64, u64, u64) {
        (self.load_parse_ms, self.load_index_ms, self.load_total_ms)
    }

    pub(crate) fn get_cfa_result(&self, pc: u64) -> Result<Option<crate::core::CfaResult>> {
        self.unwind_info.get_cfa_result(pc)
    }

    pub(crate) fn recover_caller_frame(
        &self,
        pc: u64,
        registers: &[u16],
    ) -> Result<Option<crate::core::CallerFrameRecovery>> {
        self.unwind_info.recover_caller_frame(pc, registers)
    }

    pub(crate) fn compact_unwind_table(
        &self,
        module: crate::ModuleId,
    ) -> Result<Option<Arc<crate::CompactUnwindTable>>> {
        self.unwind_info.compact_unwind_table(module)
    }

    pub(crate) fn compact_unwind_row(
        &self,
        module: crate::ModuleId,
        pc: u64,
    ) -> Result<Option<crate::CompactUnwindRow>> {
        self.unwind_info.compact_unwind_row(module, pc)
    }

    pub(crate) fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
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
}

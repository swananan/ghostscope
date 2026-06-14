//! Loaded object file: complete DWARF data for a single binary

use crate::{
    binary::{DwarfReader, MappedFile},
    core::{mapping::ModuleMapping, DebugInfoSource, Result},
    index::{
        BlockIndex, LightweightIndex, LineMappingTable, ScopedFileIndexManager, TypeNameIndex,
    },
    objfile::ModuleUnwindInfo,
    parser::{CompilationUnit, DetailedParser},
};
use object::{Object, ObjectSegment};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, RwLock},
};

type FunctionRangeCacheKey = (u64, u64);

/// Complete DWARF data for a single loaded object file.
#[derive(Debug)]
pub(crate) struct LoadedObjfile {
    pub(super) module_mapping: ModuleMapping,
    pub(super) lightweight_index: LightweightIndex,
    pub(super) line_mapping: LineMappingTable,
    pub(super) scoped_file_manager: ScopedFileIndexManager,
    pub(super) compilation_units: HashMap<String, CompilationUnit>,
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
    pub(super) type_name_index: Arc<TypeNameIndex>,
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

    pub(crate) fn get_function_names(&self) -> Vec<&String> {
        self.lightweight_index.get_function_names()
    }

    pub(crate) fn get_variable_names(&self) -> Vec<&String> {
        self.lightweight_index.get_variable_names()
    }

    pub(crate) fn get_lightweight_index(&self) -> &LightweightIndex {
        &self.lightweight_index
    }

    pub(crate) fn get_line_header_count(&self) -> usize {
        self.scoped_file_manager.get_stats().1
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

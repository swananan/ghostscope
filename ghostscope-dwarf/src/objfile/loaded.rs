//! Loaded object file: complete DWARF data for a single binary

use crate::{
    binary::MappedFile,
    core::{mapping::ModuleMapping, Result},
    index::{
        BlockIndex, CfiIndex, LightweightIndex, LineMappingTable, ScopedFileIndexManager,
        TypeNameIndex,
    },
    parser::CompilationUnit,
    resolver::OnDemandResolver,
};
use object::{Object, ObjectSegment};
use std::{collections::HashMap, path::PathBuf};

/// Complete DWARF data for a single loaded object file.
#[derive(Debug)]
pub(crate) struct LoadedObjfile {
    pub(super) module_mapping: ModuleMapping,
    pub(super) lightweight_index: LightweightIndex,
    pub(super) line_mapping: LineMappingTable,
    pub(super) scoped_file_manager: ScopedFileIndexManager,
    pub(super) compilation_units: HashMap<String, CompilationUnit>,
    pub(super) cfi_index: Option<CfiIndex>,
    pub(super) resolver: OnDemandResolver,
    pub(super) _dwarf_mapped_file: std::sync::Arc<MappedFile>,
    pub(super) _binary_mapped_file: std::sync::Arc<MappedFile>,
    pub(super) block_index: BlockIndex,
    pub(super) type_name_index: TypeNameIndex,
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

    pub(crate) fn get_cache_stats(&self) -> (usize, usize) {
        self.resolver.get_cache_stats()
    }

    pub(crate) fn get_load_timing_ms(&self) -> (u64, u64, u64) {
        (self.load_parse_ms, self.load_index_ms, self.load_total_ms)
    }

    pub(crate) fn get_cfa_result(&self, pc: u64) -> Result<Option<crate::core::CfaResult>> {
        match &self.cfi_index {
            Some(cfi) => Ok(Some(cfi.get_cfa_result(pc)?)),
            None => Ok(None),
        }
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

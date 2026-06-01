//! Module-local unwind data derived from `.eh_frame`.
//!
//! This intentionally stays separate from `.debug_info`/`.debug_line` data:
//! CFI is enough for stack unwinding even when source DWARF is unavailable.

use crate::{
    binary::MappedFile,
    core::{CallerFrameRecovery, CfaResult, Result},
    index::CfiIndex,
    CompactUnwindRow, CompactUnwindTable, ModuleId,
};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, RwLock},
};

#[derive(Debug)]
pub(crate) struct ModuleUnwindInfo {
    cfi_index: Option<CfiIndex>,
    compact_unwind_tables: RwLock<HashMap<ModuleId, Arc<CompactUnwindTable>>>,
}

impl ModuleUnwindInfo {
    pub(crate) fn from_mapped_file(file_data: Arc<MappedFile>, module_path: &Path) -> Self {
        let cfi_index = match CfiIndex::from_mapped_file(file_data) {
            Ok(cfi) => {
                tracing::info!(
                    "CFI index initialized successfully for {}",
                    module_path.display()
                );
                Some(cfi)
            }
            Err(error) => {
                tracing::warn!(
                    "Failed to initialize CFI index for {}: {}",
                    module_path.display(),
                    error
                );
                None
            }
        };

        Self {
            cfi_index,
            compact_unwind_tables: RwLock::new(HashMap::new()),
        }
    }

    pub(crate) fn has_cfi(&self) -> bool {
        self.cfi_index.is_some()
    }

    pub(crate) fn cfi_index(&self) -> Option<&CfiIndex> {
        self.cfi_index.as_ref()
    }

    pub(crate) fn get_cfa_result(&self, pc: u64) -> Result<Option<CfaResult>> {
        match &self.cfi_index {
            Some(cfi) => Ok(Some(cfi.get_cfa_result(pc)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn recover_caller_frame(
        &self,
        pc: u64,
        registers: &[u16],
    ) -> Result<Option<CallerFrameRecovery>> {
        match &self.cfi_index {
            Some(cfi) => Ok(Some(cfi.recover_caller_frame(pc, registers)?)),
            None => Ok(None),
        }
    }

    pub(crate) fn compact_unwind_table(
        &self,
        module: ModuleId,
    ) -> Result<Option<Arc<CompactUnwindTable>>> {
        let Some(cfi) = &self.cfi_index else {
            return Ok(None);
        };

        if let Some(table) = self
            .compact_unwind_tables
            .read()
            .expect("compact unwind table cache lock poisoned")
            .get(&module)
            .cloned()
        {
            return Ok(Some(table));
        }

        let table = Arc::new(cfi.compact_unwind_table(module)?);
        self.compact_unwind_tables
            .write()
            .expect("compact unwind table cache lock poisoned")
            .insert(module, Arc::clone(&table));
        Ok(Some(table))
    }

    pub(crate) fn compact_unwind_row(
        &self,
        module: ModuleId,
        pc: u64,
    ) -> Result<Option<CompactUnwindRow>> {
        Ok(self
            .compact_unwind_table(module)?
            .and_then(|table| table.row_for_pc(pc).cloned()))
    }
}

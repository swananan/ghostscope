//! Lightweight runtime unwind loading for modules discovered after tracing starts.

use crate::{binary::MappedFile, objfile::ModuleUnwindInfo, CompactUnwindTable, ModuleId, Result};
use anyhow::Context;
use object::{Object, ObjectSymbol, SymbolKind};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

pub(crate) const RUNTIME_TEXT_SYMBOLS_MAX_PER_MODULE: usize = 16_384;
const RUNTIME_TEXT_SYMBOL_NAME_MAX_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTextSymbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
}

#[derive(Debug)]
pub struct RuntimeBacktraceMetadata {
    pub unwind_table: Option<CompactUnwindTable>,
    pub text_symbols: Vec<RuntimeTextSymbol>,
}

/// Cooperative deadline shared by runtime module discovery and ELF parsing.
#[derive(Debug, Clone)]
pub struct RuntimeBacktraceLoadBudget {
    cancelled: Arc<AtomicBool>,
    deadline: Instant,
}

impl RuntimeBacktraceLoadBudget {
    pub fn new(timeout: Duration) -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + timeout,
        }
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn check(&self) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            anyhow::bail!(
                "runtime backtrace module loading was cancelled or exceeded its deadline"
            );
        }
        Ok(())
    }

    pub fn expired_or_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
}

/// Load only the compact CFI and ELF text symbols needed by runtime backtraces.
///
/// Unlike [`crate::DwarfAnalyzer`], this does not parse or retain `.debug_info`,
/// `.debug_line`, type indexes, or source metadata. The mapped object is dropped
/// after the compact rows and bounded symbol list have been built.
pub fn load_runtime_backtrace_metadata(
    module_path: PathBuf,
    max_rows: usize,
    budget: &RuntimeBacktraceLoadBudget,
) -> Result<RuntimeBacktraceMetadata> {
    budget.check()?;
    let mapped_file = Arc::new(
        MappedFile::open(&module_path)
            .with_context(|| format!("Failed to map runtime module {}", module_path.display()))?,
    );
    budget.check()?;
    let text_symbols = collect_text_symbols(&mapped_file, budget)?;
    budget.check()?;
    let unwind_info = ModuleUnwindInfo::from_mapped_file(mapped_file, &module_path);
    let unwind_table =
        unwind_info.compact_unwind_table_with_max_rows_and_check(ModuleId(0), max_rows, &|| {
            budget.check()
        })?;
    budget.check()?;
    Ok(RuntimeBacktraceMetadata {
        unwind_table,
        text_symbols,
    })
}

fn collect_text_symbols(
    mapped_file: &MappedFile,
    budget: &RuntimeBacktraceLoadBudget,
) -> Result<Vec<RuntimeTextSymbol>> {
    let object = match mapped_file.parse_object() {
        Ok(object) => object,
        Err(error) => {
            tracing::warn!(
                "Failed to parse runtime module symbols from {}: {}",
                mapped_file.path.display(),
                error
            );
            return Ok(Vec::new());
        }
    };

    let mut symbols = Vec::new();
    let mut truncated = false;
    // Prefer exported symbols, which are the most useful fallback for stripped
    // shared libraries, before spending the bounded budget on the full symtab.
    for symbol in object.dynamic_symbols() {
        budget.check()?;
        if symbols.len() >= RUNTIME_TEXT_SYMBOLS_MAX_PER_MODULE {
            truncated = true;
            break;
        }
        append_text_symbol(&mut symbols, symbol);
    }
    for symbol in object.symbols() {
        budget.check()?;
        if symbols.len() >= RUNTIME_TEXT_SYMBOLS_MAX_PER_MODULE {
            truncated = true;
            break;
        }
        append_text_symbol(&mut symbols, symbol);
    }

    symbols.sort_by(|left, right| {
        left.address
            .cmp(&right.address)
            .then_with(|| right.size.cmp(&left.size))
            .then_with(|| left.name.cmp(&right.name))
    });
    symbols.dedup_by(|left, right| left.address == right.address && left.name == right.name);
    if truncated {
        tracing::warn!(
            module = %mapped_file.path.display(),
            retained = symbols.len(),
            "Truncating runtime ELF text symbol index"
        );
    }
    Ok(symbols)
}

fn append_text_symbol<'a>(
    symbols: &mut Vec<RuntimeTextSymbol>,
    symbol: object::Symbol<'a, 'a, &'a [u8]>,
) {
    if symbol.kind() != SymbolKind::Text || symbol.address() == 0 {
        return;
    }
    let Ok(name) = symbol.name() else {
        return;
    };
    if name.len() > RUNTIME_TEXT_SYMBOL_NAME_MAX_BYTES {
        return;
    }
    symbols.push(RuntimeTextSymbol {
        name: name.to_string(),
        address: symbol.address(),
        size: symbol.size(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_bounded_backtrace_metadata_without_a_full_dwarf_analyzer() {
        let executable = std::env::current_exe().expect("test executable path");
        let budget = RuntimeBacktraceLoadBudget::new(Duration::from_secs(5));
        let metadata = load_runtime_backtrace_metadata(executable, 1, &budget)
            .expect("runtime backtrace metadata load");
        let table = metadata
            .unwind_table
            .expect("test executable should contain .eh_frame");

        assert_eq!(table.rows.len(), 1);
        assert!(!metadata.text_symbols.is_empty());
        assert!(metadata.text_symbols.len() <= RUNTIME_TEXT_SYMBOLS_MAX_PER_MODULE);
    }

    #[test]
    fn cancelled_budget_stops_before_mapping_a_module() {
        let executable = std::env::current_exe().expect("test executable path");
        let budget = RuntimeBacktraceLoadBudget::new(Duration::from_secs(5));
        budget.cancel();

        let error = load_runtime_backtrace_metadata(executable, 1, &budget)
            .expect_err("cancelled runtime load should fail");

        assert!(error.to_string().contains("cancelled"));
    }
}

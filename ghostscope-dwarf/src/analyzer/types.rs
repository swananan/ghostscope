use crate::{core::DebugInfoSource, semantics::VisibleVariable};
use std::path::PathBuf;

/// Events emitted during module loading process
#[derive(Debug, Clone)]
pub enum ModuleLoadingEvent {
    /// Module discovered during process scanning
    Discovered {
        module_path: String,
        current: usize,
        total: usize,
    },
    /// Module loading started
    LoadingStarted {
        module_path: String,
        current: usize,
        total: usize,
    },
    /// Module loading completed successfully
    LoadingCompleted {
        module_path: String,
        stats: ModuleLoadingStats,
        current: usize,
        total: usize,
    },
    /// Module loading failed
    LoadingFailed {
        module_path: String,
        error: String,
        current: usize,
        total: usize,
    },
}

/// Statistics for a loaded module
#[derive(Debug, Clone)]
pub struct ModuleLoadingStats {
    pub functions: usize,
    pub variables: usize,
    pub types: usize,
    pub debug_info_source: DebugInfoSource,
    pub load_time_ms: u64,
    pub parse_time_ms: u64,
    pub index_time_ms: u64,
    pub module_total_time_ms: u64,
}

/// Rich query result for a single address within a module.
#[derive(Debug, Clone)]
pub struct AddressQueryResult {
    pub module_path: PathBuf,
    pub address: u64,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub source_column: Option<u32>,
    pub function_name: Option<String>,
    pub is_inline: Option<bool>,
    pub variables: Vec<VisibleVariable>,
    pub parameters: Vec<VisibleVariable>,
}

/// Runtime mapping metadata for a loaded module.
#[derive(Debug, Clone)]
pub struct LoadedModuleRuntimeInfo {
    pub module_path: PathBuf,
    pub loaded_address: Option<u64>,
    pub load_bias: Option<u64>,
    pub size: u64,
}

/// Rich query result for a function lookup across modules.
#[derive(Debug, Clone)]
pub struct FunctionQueryResult {
    pub function_name: String,
    pub addresses: Vec<AddressQueryResult>,
}

/// Module statistics compatible with ghostscope-binary
#[derive(Debug, Clone)]
pub struct ModuleStats {
    pub total_modules: usize,
    pub executable_modules: usize,
    pub library_modules: usize,
    pub total_symbols: usize,
    pub modules_with_debug_info: usize,
}

/// Main executable information
#[derive(Debug, Clone)]
pub struct MainExecutableInfo {
    pub path: String,
}

/// Statistics for debugging and monitoring
#[derive(Debug, Clone)]
pub struct AnalyzerStats {
    pub pid: u32,
    pub module_count: usize,
    pub total_functions: usize,
    pub total_variables: usize,
    pub total_line_headers: usize,
}

/// Shared library information (compatible with ghostscope-ui)
#[derive(Debug, Clone)]
pub struct SharedLibraryInfo {
    pub from_address: u64,               // Starting address in memory
    pub to_address: u64,                 // Ending address in memory
    pub symbols_read: bool,              // Whether symbols were successfully read
    pub debug_info_available: bool,      // Whether debug information is available
    pub library_path: String,            // Full path to the library file
    pub size: u64,                       // Size of the library in memory
    pub debug_file_path: Option<String>, // Path to separate debug file (if via .gnu_debuglink)
}

/// Executable file information (for "info file" command)
#[derive(Debug, Clone)]
pub struct ExecutableFileInfo {
    pub file_path: String,
    pub file_type: String,
    pub entry_point: Option<u64>,
    pub has_symbols: bool,
    pub has_debug_info: bool,
    pub debug_file_path: Option<String>,
    pub text_section: Option<SectionInfo>,
    pub data_section: Option<SectionInfo>,
    pub mode_description: String,
}

/// Section information for executable files
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub start_address: u64,
    pub end_address: u64,
    pub size: u64,
}

/// Simple file information compatible with ghostscope-binary
#[derive(Debug, Clone)]
pub struct SimpleFileInfo {
    pub full_path: String,
    pub basename: String,
    pub directory: String,
}

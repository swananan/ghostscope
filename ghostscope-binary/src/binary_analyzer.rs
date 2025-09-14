use std::fs;
use std::path::PathBuf;
use tracing::{debug, info, warn};

use crate::debuglink;
use crate::dwarf;
use crate::symbol;
use crate::{BinaryError, Result};

/// Represents debug information for a binary
#[derive(Debug, Clone)]
pub(crate) struct DebugInfo {
    pub binary_path: PathBuf,
    pub debug_path: Option<PathBuf>,
    pub has_symbols: bool,
    pub has_debug_info: bool,
    pub entry_point: Option<u64>,
    pub base_address: u64,
}

/// Main interface for binary analysis
#[derive(Debug)]
pub(crate) struct BinaryAnalyzer {
    debug_info: DebugInfo,
    pub(crate) symbol_table: symbol::SymbolTable,
    dwarf_context: Option<dwarf::DwarfContext>,
}

impl BinaryAnalyzer {
    /// Create a new binary analyzer from PID
    ///
    /// # Arguments
    /// * `pid` - Process ID to analyze
    /// * `debug_path` - Optional explicit path to debug info file
    pub(crate) fn from_pid(pid: u32, debug_path: Option<&str>) -> Result<Self> {
        info!("Creating binary analyzer from PID: {}", pid);

        // Get binary path from PID
        let binary_path = get_binary_path_from_pid(pid)?;
        info!("Process {} binary path: {}", pid, binary_path.display());

        Self::new_from_path(&binary_path, debug_path)
    }

    /// Create a new binary analyzer
    ///
    /// # Arguments
    /// * `binary_path` - Path to the target binary (can be relative or absolute)
    /// * `debug_path` - Optional explicit path to debug info file
    pub(crate) fn new(binary_path: &str, debug_path: Option<&str>) -> Result<Self> {
        let binary_path = resolve_binary_path(binary_path)?;
        Self::new_from_path(&binary_path, debug_path)
    }

    /// Create analyzer from resolved binary path
    fn new_from_path(binary_path: &PathBuf, debug_path: Option<&str>) -> Result<Self> {
        let debug_path = if let Some(path) = debug_path {
            Some(PathBuf::from(path))
        } else {
            // Try to find debug info via gnu.debuglink
            debuglink::find_debug_info(&binary_path)?
        };

        info!("Found debug info: {:?}", debug_path);

        let debug_info = DebugInfo {
            binary_path: binary_path.clone(),
            debug_path: debug_path.clone(),
            has_symbols: false,
            has_debug_info: false,
            entry_point: None,
            base_address: 0,
        };

        // Load the binary and parse symbols
        let symbol_table = symbol::SymbolTable::load(&binary_path)?;

        // Load DWARF debug information if available
        let dwarf_context = if let Some(ref debug_path) = debug_path {
            Some(dwarf::DwarfContext::load(debug_path)?)
        } else {
            dwarf::DwarfContext::load_from_binary(&binary_path).ok()
        };

        // Update debug_info with actual loading results
        let mut debug_info = debug_info;
        debug_info.has_symbols = !symbol_table.is_empty();
        debug_info.has_debug_info = dwarf_context.is_some();

        Ok(Self {
            debug_info,
            symbol_table,
            dwarf_context,
        })
    }

    /// Get debug information summary
    pub(crate) fn debug_info(&self) -> &DebugInfo {
        &self.debug_info
    }

    /// Find symbol by name
    pub(crate) fn find_symbol(&self, name: &str) -> Option<&symbol::Symbol> {
        self.symbol_table.find_by_name(name)
    }

    /// Find symbol by address
    pub(crate) fn find_symbol_by_address(&self, addr: u64) -> Option<&symbol::Symbol> {
        self.symbol_table.find_by_address(addr)
    }

    /// Get function information at address
    pub(crate) fn get_function_info(&self, addr: u64) -> Option<dwarf::FunctionInfo> {
        self.dwarf_context.as_ref()?.get_function_info(addr)
    }

    /// Get source location for address
    pub(crate) fn get_source_location(&mut self, addr: u64) -> Option<dwarf::SourceLocation> {
        self.dwarf_context.as_mut()?.get_source_location(addr)
    }

    /// Get DWARF context for advanced debug information queries
    pub(crate) fn dwarf_context(&self) -> Option<&dwarf::DwarfContext> {
        self.dwarf_context.as_ref()
    }

    /// Get mutable DWARF context for advanced debug information queries
    pub(crate) fn dwarf_context_mut(&mut self) -> Option<&mut dwarf::DwarfContext> {
        self.dwarf_context.as_mut()
    }

    /// Get all addresses for a function name using DWARF information first
    /// Returns all addresses that correspond to the given function name
    pub(crate) fn get_all_function_addresses(&self, func_name: &str) -> Vec<u64> {
        // First try DWARF information
        if let Some(dwarf_context) = &self.dwarf_context {
            let addresses = dwarf_context.get_function_addresses_by_name(func_name);
            if !addresses.is_empty() {
                return addresses;
            }
        }

        // Fall back to symbol table (single address)
        if let Some(symbol) = self.find_symbol(func_name) {
            vec![symbol.address]
        } else {
            Vec::new()
        }
    }

    /// Get all addresses for a source line
    /// Returns all addresses that correspond to the given source line
    pub(crate) fn get_all_source_line_addresses(
        &mut self,
        file_path: &str,
        line_number: u32,
    ) -> Vec<u64> {
        if let Some(dwarf_context) = &mut self.dwarf_context {
            let line_mappings = dwarf_context.get_addresses_for_line(file_path, line_number);
            let mut addresses: Vec<u64> = line_mappings.into_iter().map(|m| m.address).collect();

            // Sort addresses for consistent display
            addresses.sort_unstable();
            addresses.dedup();
            addresses
        } else {
            Vec::new()
        }
    }

    /// Get variable size at specific address by variable name
    /// Returns the size in bytes for bpf_probe_read_user, or None if variable not found
    pub(crate) fn get_variable_size(&mut self, pc: u64, var_name: &str) -> Option<u64> {
        if let Some(dwarf_ctx) = &mut self.dwarf_context {
            let enhanced_vars = dwarf_ctx.get_enhanced_variable_locations(pc);
            for var_info in enhanced_vars {
                if var_info.variable.name == var_name {
                    return var_info.size;
                }
            }
        }
        None
    }

    /// Get frame base offset for a specific PC address
    /// This is the main interface for codegen to query CFI information
    /// Returns the offset to add to the base register (usually RBP) to get frame base
    pub(crate) fn get_frame_base_offset(&self, pc: u64) -> Option<i64> {
        self.dwarf_context.as_ref()?.get_frame_base_offset_at_pc(pc)
    }
}

/// Resolve binary path - handle relative paths and search in PATH if needed
fn resolve_binary_path(binary_path: &str) -> Result<PathBuf> {
    let path = PathBuf::from(binary_path);

    // If it's an absolute path, use it directly
    if path.is_absolute() {
        if path.exists() {
            return Ok(path);
        } else {
            return Err(BinaryError::NotFound(path));
        }
    }

    // If it contains a path separator, it's a relative path
    if binary_path.contains('/') {
        let current_dir = std::env::current_dir().map_err(BinaryError::Io)?;
        let full_path = current_dir.join(&path);
        if full_path.exists() {
            return Ok(full_path);
        } else {
            return Err(BinaryError::NotFound(full_path));
        }
    }

    // Otherwise, search in PATH
    if let Some(full_path) = search_in_path(binary_path) {
        Ok(full_path)
    } else {
        Err(BinaryError::NotFound(PathBuf::from(binary_path)))
    }
}

/// Search for binary in PATH environment variable
fn search_in_path(binary_name: &str) -> Option<PathBuf> {
    if let Ok(path_env) = std::env::var("PATH") {
        for path_dir in path_env.split(':') {
            let full_path = PathBuf::from(path_dir).join(binary_name);
            if full_path.exists() && full_path.is_file() {
                return Some(full_path);
            }
        }
    }
    None
}

/// Get binary path from process ID by reading /proc/PID/exe
fn get_binary_path_from_pid(pid: u32) -> Result<PathBuf> {
    let proc_exe_path = format!("/proc/{}/exe", pid);
    debug!("Reading process binary path from: {}", proc_exe_path);

    // Check if process exists
    if !PathBuf::from(&format!("/proc/{}", pid)).exists() {
        return Err(BinaryError::ProcessNotFound(pid));
    }

    // Read the symbolic link to get the actual binary path
    match fs::read_link(&proc_exe_path) {
        Ok(binary_path) => {
            info!(
                "Found binary path for PID {}: {}",
                pid,
                binary_path.display()
            );
            Ok(binary_path)
        }
        Err(e) => {
            warn!("Failed to read binary path for PID {}: {}", pid, e);
            Err(BinaryError::ProcessInfoError(format!(
                "Cannot read {}: {}",
                proc_exe_path, e
            )))
        }
    }
}

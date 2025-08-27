pub mod elf;
pub mod dwarf;
pub mod symbol;
pub mod debuglink;

use std::path::PathBuf;
use std::fs;
use thiserror::Error;
use tracing::{debug, info, warn};

#[derive(Debug, Error)]
pub enum BinaryError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Object parsing error: {0}")]
    Object(#[from] object::Error),
    
    #[error("DWARF parsing error: {0}")]
    Dwarf(#[from] gimli::Error),
    
    #[error("Binary not found: {0}")]
    NotFound(PathBuf),
    
    #[error("No debug information found")]
    NoDebugInfo,
    
    #[error("Invalid debug link: {0}")]
    InvalidDebugLink(String),
    
    #[error("Process not found: PID {0}")]
    ProcessNotFound(u32),
    
    #[error("Cannot read process info: {0}")]
    ProcessInfoError(String),
}

pub type Result<T> = std::result::Result<T, BinaryError>;

/// Represents debug information for a binary
#[derive(Debug, Clone)]
pub struct DebugInfo {
    pub binary_path: PathBuf,
    pub debug_path: Option<PathBuf>,
    pub has_symbols: bool,
    pub has_debug_info: bool,
    pub entry_point: Option<u64>,
    pub base_address: u64,
}

/// Main interface for binary analysis
#[derive(Debug)]
pub struct BinaryAnalyzer {
    debug_info: DebugInfo,
    pub symbol_table: symbol::SymbolTable,
    dwarf_context: Option<dwarf::DwarfContext>,
}

impl BinaryAnalyzer {
    /// Create a new binary analyzer from PID
    /// 
    /// # Arguments
    /// * `pid` - Process ID to analyze
    /// * `debug_path` - Optional explicit path to debug info file
    pub fn from_pid(pid: u32, debug_path: Option<&str>) -> Result<Self> {
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
    pub fn new(binary_path: &str, debug_path: Option<&str>) -> Result<Self> {
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
        
        Ok(Self {
            debug_info,
            symbol_table,
            dwarf_context,
        })
    }
    
    /// Get debug information summary
    pub fn debug_info(&self) -> &DebugInfo {
        &self.debug_info
    }
    
    /// Find symbol by name
    pub fn find_symbol(&self, name: &str) -> Option<&symbol::Symbol> {
        self.symbol_table.find_by_name(name)
    }
    
    /// Find symbol by address
    pub fn find_symbol_by_address(&self, addr: u64) -> Option<&symbol::Symbol> {
        self.symbol_table.find_by_address(addr)
    }
    
    /// Get function information at address
    pub fn get_function_info(&self, addr: u64) -> Option<dwarf::FunctionInfo> {
        self.dwarf_context.as_ref()?.get_function_info(addr)
    }
    
    /// Get source location for address
    pub fn get_source_location(&self, addr: u64) -> Option<dwarf::SourceLocation> {
        self.dwarf_context.as_ref()?.get_source_location(addr)
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
            info!("Found binary path for PID {}: {}", pid, binary_path.display());
            Ok(binary_path)
        }
        Err(e) => {
            warn!("Failed to read binary path for PID {}: {}", pid, e);
            Err(BinaryError::ProcessInfoError(format!("Cannot read {}: {}", proc_exe_path, e)))
        }
    }
}

/// Get process command line arguments from /proc/PID/cmdline
pub fn get_process_cmdline(pid: u32) -> Result<Vec<String>> {
    let proc_cmdline_path = format!("/proc/{}/cmdline", pid);
    debug!("Reading process command line from: {}", proc_cmdline_path);
    
    match fs::read(&proc_cmdline_path) {
        Ok(data) => {
            // cmdline is null-separated
            let cmdline: Vec<String> = data
                .split(|&b| b == 0)
                .filter(|arg| !arg.is_empty())
                .map(|arg| String::from_utf8_lossy(arg).to_string())
                .collect();
            
            debug!("Process {} command line: {:?}", pid, cmdline);
            Ok(cmdline)
        }
        Err(e) => {
            warn!("Failed to read command line for PID {}: {}", pid, e);
            Err(BinaryError::ProcessInfoError(format!("Cannot read {}: {}", proc_cmdline_path, e)))
        }
    }
}

pub fn hello() -> String {
    "Hello from ghostscope-binary!".to_string()
}
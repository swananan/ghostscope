//! Error types for the DWARF analysis library

use std::path::PathBuf;

/// Error types for the library
#[derive(thiserror::Error, Debug)]
pub enum DwarfError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("DWARF parsing error: {0}")]
    Gimli(#[from] gimli::Error),
    #[error("Object file error: {0}")]
    Object(#[from] object::Error),
    #[error("Module not found: {path}")]
    ModuleNotFound { path: PathBuf },
    #[error("Process not found: {pid}")]
    ProcessNotFound { pid: u32 },
    #[error("Module load error: {0}")]
    ModuleLoadError(String),
    #[error("Invalid DWARF data")]
    InvalidDwarf,
}

/// Result type used throughout the library
pub type Result<T> = anyhow::Result<T>;

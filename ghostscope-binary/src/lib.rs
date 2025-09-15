pub(crate) mod binary_analyzer;
pub(crate) mod cfi;
pub(crate) mod debuglink;
pub(crate) mod dwarf;
pub(crate) mod elf;
pub(crate) mod expression;
pub(crate) mod file;
pub(crate) mod line_lookup;
pub mod process;
pub(crate) mod scoped_variables;
pub(crate) mod symbol;

pub use dwarf::EnhancedVariableLocation;
pub use dwarf::{DwarfType, SourceLocation};
pub use expression::{
    AccessStep, ArithOp, DirectValueResult, EvaluationContext, EvaluationResult, LocationResult,
    RegisterAccess,
};
pub use process::{MemoryMapping, ModuleInfo, ModuleStats, ProcessAnalyzer, SharedLibraryInfo};

use std::path::PathBuf;
use thiserror::Error;

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

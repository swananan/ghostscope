//! Core data types for DWARF analysis

use std::path::PathBuf;
use std::sync::Arc;

/// Module address pair - combines module path with address offset
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModuleAddress {
    /// Path to the module/binary file
    pub module_path: std::path::PathBuf,
    /// Address offset within the module file (not virtual address)
    pub address: u64,
}

impl ModuleAddress {
    /// Create a new module address
    pub fn new(module_path: std::path::PathBuf, address: u64) -> Self {
        Self {
            module_path,
            address,
        }
    }

    /// Get module path as string for logging
    pub fn module_display(&self) -> std::path::Display<'_> {
        self.module_path.display()
    }
}

/// Source location information (address-based, not pc-based)
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file_path: String,
    pub line_number: u32,
    pub column: Option<u32>,
    pub address: u64,
}

/// Variable information result
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub type_name: String,
    pub location: Option<String>,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
}

/// Function information
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub low_address: u64,
    pub high_address: Option<u64>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
}

/// Line information from debug_line (address-based)
#[derive(Debug, Clone)]
pub struct LineInfo {
    pub line_number: u32,
    pub file_path: String,
    pub address: u64,
}

/// Memory mapped file data
#[derive(Debug)]
pub struct MappedFile {
    pub data: memmap2::Mmap,
    pub path: PathBuf,
}

/// Cooked index entry - inspired by GDB's cooked_index_entry
/// Extremely lightweight startup index, minimal memory footprint
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Entry name (function/variable name) - copied from DWARF
    pub name: Arc<str>,
    /// DIE offset in DWARF data (gimli native type)
    pub die_offset: gimli::UnitOffset,
    /// Compilation unit offset (gimli native type)
    pub unit_offset: gimli::DebugInfoOffset,
    /// DWARF tag (gimli native type)
    pub tag: gimli::DwTag,
    /// Index flags (inspired by GDB's cooked_index_flag)
    pub flags: IndexFlags,
    /// Language of the symbol
    pub language: Option<gimli::DwLang>,
    /// Address ranges for this entry (if applicable)
    /// For functions: vec![(low_pc, high_pc)] or multiple ranges from DW_AT_ranges
    /// For variables: vec![(address, address)] if static
    /// Empty vec if no address (e.g., types, inlined functions without concrete instances)
    pub address_ranges: Vec<(u64, u64)>,
    /// Optional DW_AT_entry_pc for inline/call site DIEs (single-point locations)
    pub entry_pc: Option<u64>,
}

/// Index flags (inspired by GDB's cooked_index_flag_enum)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct IndexFlags {
    /// True if this entry represents a "static" object
    pub is_static: bool,
    /// True if this is the program's main function
    pub is_main: bool,
    /// True if this is an inline function
    pub is_inline: bool,
    /// True if this entry uses the linkage name
    pub is_linkage: bool,
    /// True if this is just a type declaration (not definition)
    pub is_type_declaration: bool,
    /// True if this entry was synthesized (not directly from DWARF)
    pub is_synthesized: bool,
}

/// Line entry with flags (for debug_line parsing)
#[derive(Debug, Clone)]
pub struct LineEntry {
    pub address: u64,
    pub file_path: String, // Full file path for direct lookup
    pub file_index: u64,   // Original DWARF file index (kept for compatibility)
    pub compilation_unit: std::sync::Arc<str>, // Pooled CU name to reduce duplication
    pub line: u64,
    pub column: u64,
    pub is_stmt: bool,
    pub prologue_end: bool,
    pub epilogue_begin: bool,
    pub end_sequence: bool,
}

/// Program section classification for global/static variables
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Text,
    Rodata,
    Data,
    Bss,
    Unknown,
}

/// Lightweight global variable metadata resolved from DWARF/ELF
#[derive(Debug, Clone)]
pub struct GlobalVariableInfo {
    pub name: String,
    /// Link-time address from DWARF location (if available)
    pub link_address: Option<u64>,
    /// Best-effort section classification based on ELF section headers
    pub section: Option<SectionType>,
    /// For precise follow-up resolution/debugging
    pub die_offset: gimli::UnitOffset,
    pub unit_offset: gimli::DebugInfoOffset,
}

/// Re-export SectionOffsets from coordinator to keep a single definition/source of truth
pub use ghostscope_process::SectionOffsets;

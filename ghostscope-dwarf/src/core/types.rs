//! Core data types for DWARF analysis

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

/// Function information
#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub low_address: u64,
    pub high_address: Option<u64>,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
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
    /// Representative address for this entry (if applicable).
    ///
    /// For function-like DIEs this is a cheap parse-time seed used for indexing:
    /// `low_pc`, otherwise `entry_pc`, otherwise the first emitted
    /// `DW_AT_ranges` start. Full ranges are resolved on demand from DWARF.
    ///
    /// For variables this is the absolute storage address, when one exists.
    pub representative_addr: Option<u64>,
    /// Optional raw DW_AT_entry_pc for inline/call site DIEs.
    /// Callers should prefer `validated_entry_pc(ranges)` when selecting probe PCs.
    pub entry_pc: Option<u64>,
    /// Explicit function role classification assigned during parse.
    pub function_kind: FunctionDieKind,
}

impl IndexEntry {
    pub fn function_kind(&self) -> FunctionDieKind {
        self.function_kind
    }

    /// True when this DIE is a concrete DW_TAG_inlined_subroutine instance.
    pub fn is_inline_instance(&self) -> bool {
        self.function_kind() == FunctionDieKind::InlineInstance
    }

    /// Return entry_pc when it is usable as this DIE's own entry address.
    ///
    /// Most DIEs with an entry_pc also carry ranges, and some producers emit
    /// caller-side setup PCs that do not belong to the inline instance itself.
    /// Reject those out-of-range PCs. However, DWARF can also encode
    /// single-point inline/call-site scopes using only entry_pc and no ranges;
    /// in that shape the point entry_pc is the only addressable location and
    /// should be preserved.
    pub fn validated_entry_pc(&self, ranges: &[(u64, u64)]) -> Option<u64> {
        self.entry_pc.filter(|pc| {
            ranges.is_empty()
                || ranges
                    .iter()
                    .any(|(start, end)| *start <= *pc && *pc < *end)
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FunctionDieKind {
    #[default]
    NotFunction,
    /// Addressless DW_TAG_subprogram, typically an abstract definition or
    /// declaration-like node used only for origin/specification metadata.
    AbstractSubprogram,
    /// Concrete out-of-line DW_TAG_subprogram with executable code ranges.
    ConcreteSubprogram,
    /// Concrete DW_TAG_inlined_subroutine instance inside a caller.
    InlineInstance,
}

/// Index flags (inspired by GDB's cooked_index_flag_enum)
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct IndexFlags {
    /// True if this entry represents a "static" object
    pub is_static: bool,
    /// True if this is the program's main function
    pub is_main: bool,
    /// True if this DIE carries DW_AT_inline (or inherits that declaration).
    pub has_inline_attribute: bool,
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

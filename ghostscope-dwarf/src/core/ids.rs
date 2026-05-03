//! Stable semantic identifiers used by higher-level DWARF queries.

/// Stable identifier for a loaded module within one `DwarfAnalyzer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

/// Stable identifier for a compilation unit within a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CuId(pub u32);

/// Stable reference to a DIE within a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DieRef {
    pub module: ModuleId,
    pub cu: CuId,
    /// Unit-relative or absolute offset normalized by the producer of the id.
    pub offset: u64,
}

/// Stable identifier for a type DIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TypeId {
    pub module: ModuleId,
    pub cu: CuId,
    pub die: DieRef,
}

/// Stable identifier for a variable declaration DIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VariableId {
    pub declaration: DieRef,
}

/// Stable identifier for a function DIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionId {
    pub declaration: DieRef,
}

/// Stable identifier for a lexical scope DIE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeId {
    pub die: DieRef,
}

/// Stable identifier for an inline context inside a concrete function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct InlineContextId {
    pub die: DieRef,
}

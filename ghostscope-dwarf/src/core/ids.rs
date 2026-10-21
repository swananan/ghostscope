//! Stable semantic identifiers used by higher-level DWARF queries.

/// Stable identifier for a loaded module within one `DwarfAnalyzer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

/// Stable identifier for a compilation unit within a loaded module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CuId(pub u64, pub DwarfObjectId);

impl CuId {
    pub const fn primary(offset: u64) -> Self {
        Self(offset, DwarfObjectId::Primary)
    }
}

/// The object containing a DWARF unit. Offsets are local to this object.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DwarfObjectId {
    #[default]
    Primary,
    Supplementary,
}

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
    /// Primary CU importing a supplementary type. Supplies semantic attributes
    /// omitted by the physical partial unit, without changing its DIE location.
    pub importing_cu: Option<CuId>,
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

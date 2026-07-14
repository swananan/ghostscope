//! Source-language and producer context attached to DWARF-backed types.

use super::type_layout::{indexable_element_layout, strip_type_aliases};
use crate::core::{CuId, ModuleId, TypeId};
use crate::{TypeInfo, VariableAccessSegment};

/// Normalized source-language family for semantic dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceLanguage {
    C,
    Cpp,
    Rust,
    Other(u16),
    Unknown,
}

impl SourceLanguage {
    pub fn from_dwarf(language: Option<gimli::DwLang>) -> Self {
        match language {
            Some(
                gimli::DW_LANG_C89
                | gimli::DW_LANG_C
                | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11
                | gimli::DW_LANG_C17,
            ) => Self::C,
            Some(
                gimli::DW_LANG_C_plus_plus
                | gimli::DW_LANG_C_plus_plus_03
                | gimli::DW_LANG_C_plus_plus_11
                | gimli::DW_LANG_C_plus_plus_14
                | gimli::DW_LANG_C_plus_plus_17
                | gimli::DW_LANG_C_plus_plus_20,
            ) => Self::Cpp,
            Some(gimli::DW_LANG_Rust) => Self::Rust,
            Some(language) => Self::Other(language.0),
            None => Self::Unknown,
        }
    }
}

/// Raw compiler producer description from `DW_AT_producer`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProducerInfo {
    pub raw: String,
}

impl ProducerInfo {
    pub fn new(raw: impl Into<String>) -> Self {
        Self { raw: raw.into() }
    }
}

/// Metadata that controls language-aware interpretation for one compilation unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompilationUnitMetadata {
    pub module: ModuleId,
    pub cu: CuId,
    pub language: SourceLanguage,
    pub producer: Option<ProducerInfo>,
    pub dwarf_version: u16,
}

/// Stable origin for a type DIE.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TypeOrigin {
    pub module: ModuleId,
    pub cu: CuId,
    pub language: SourceLanguage,
    pub producer: Option<ProducerInfo>,
    pub dwarf_version: u16,
}

impl From<CompilationUnitMetadata> for TypeOrigin {
    fn from(metadata: CompilationUnitMetadata) -> Self {
        Self {
            module: metadata.module,
            cu: metadata.cu,
            language: metadata.language,
            producer: metadata.producer,
            dwarf_version: metadata.dwarf_version,
        }
    }
}

/// A protocol-compatible type summary plus its optional DWARF identity and origin.
#[derive(Debug, Clone, PartialEq)]
pub struct SemanticType {
    pub summary: TypeInfo,
    pub id: Option<TypeId>,
    pub origin: Option<TypeOrigin>,
}

impl SemanticType {
    pub fn new(summary: TypeInfo, id: Option<TypeId>, origin: Option<TypeOrigin>) -> Self {
        Self {
            summary,
            id,
            origin,
        }
    }
}

/// Identity for a type that may combine an exact DWARF DIE with script-created
/// pointer, array, or qualifier wrappers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeIdentity {
    Dwarf(TypeId),
    Synthetic {
        kind: SyntheticTypeKind,
        inner: Box<TypeIdentity>,
    },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyntheticTypeKind {
    Pointer,
    Array,
    Qualified,
}

impl TypeIdentity {
    pub fn from_dwarf(id: Option<TypeId>) -> Self {
        id.map(Self::Dwarf).unwrap_or(Self::Unknown)
    }

    pub fn synthetic(kind: SyntheticTypeKind, inner: Self) -> Self {
        Self::Synthetic {
            kind,
            inner: Box::new(inner),
        }
    }

    /// Return the exact DIE for this layout, allowing only transparent
    /// qualifier wrappers.
    pub fn layout_dwarf_id(&self) -> Option<TypeId> {
        match self {
            Self::Dwarf(id) => Some(*id),
            Self::Synthetic {
                kind: SyntheticTypeKind::Qualified,
                inner,
            } => inner.layout_dwarf_id(),
            Self::Synthetic { .. } | Self::Unknown => None,
        }
    }

    /// Return the underlying DWARF DIE through any script-created wrappers.
    pub fn underlying_dwarf_id(&self) -> Option<TypeId> {
        match self {
            Self::Dwarf(id) => Some(*id),
            Self::Synthetic { inner, .. } => inner.underlying_dwarf_id(),
            Self::Unknown => None,
        }
    }

    /// Resolve a projection that consumes only a structural synthetic wrapper.
    /// `None` means the projection needs DWARF or is invalid for this wrapper.
    pub(crate) fn project_structural(&self, segment: &VariableAccessSegment) -> Option<Self> {
        match self {
            Self::Dwarf(_) => None,
            Self::Synthetic {
                kind: SyntheticTypeKind::Qualified,
                inner,
            } => inner.project_structural(segment),
            Self::Synthetic {
                kind: SyntheticTypeKind::Pointer,
                inner,
            } => match segment {
                VariableAccessSegment::Dereference | VariableAccessSegment::ArrayIndex(_) => {
                    Some(inner.as_ref().clone())
                }
                VariableAccessSegment::Field(_) | VariableAccessSegment::TupleIndex(_) => None,
            },
            Self::Synthetic {
                kind: SyntheticTypeKind::Array,
                inner,
            } => match segment {
                VariableAccessSegment::ArrayIndex(_) => Some(inner.as_ref().clone()),
                _ => None,
            },
            Self::Unknown => match segment {
                VariableAccessSegment::Dereference | VariableAccessSegment::ArrayIndex(_) => {
                    Some(Self::Unknown)
                }
                VariableAccessSegment::Field(_) | VariableAccessSegment::TupleIndex(_) => None,
            },
        }
    }
}

impl Default for TypeIdentity {
    fn default() -> Self {
        Self::Unknown
    }
}

/// Operational type state carried across planning and compiler projections.
///
/// The summary supplies protocol-compatible physical layout, while identity
/// retains the DWARF DIE beneath any script-created wrappers.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedType {
    pub summary: TypeInfo,
    pub identity: TypeIdentity,
    pub origin: Option<TypeOrigin>,
}

impl ResolvedType {
    pub fn new(summary: TypeInfo, identity: TypeIdentity, origin: Option<TypeOrigin>) -> Self {
        Self {
            summary,
            identity,
            origin,
        }
    }

    pub fn synthetic(summary: TypeInfo) -> Self {
        Self::new(summary, TypeIdentity::Unknown, None)
    }

    pub fn from_semantic_type(semantic: SemanticType) -> Self {
        Self::new(
            semantic.summary,
            TypeIdentity::from_dwarf(semantic.id),
            semantic.origin,
        )
    }

    /// Project through a script-created pointer or array wrapper. Exact DWARF
    /// identities are delegated to the analyzer.
    pub fn project_structural(&self, segment: &VariableAccessSegment) -> Option<TypeProjection> {
        let (layout, summary) = match segment {
            VariableAccessSegment::Dereference => match strip_type_aliases(&self.summary) {
                TypeInfo::PointerType { target_type, .. } => (
                    TypeProjectionLayout::Dereference,
                    target_type.as_ref().clone(),
                ),
                _ => return None,
            },
            VariableAccessSegment::ArrayIndex(_) => {
                let element = indexable_element_layout(&self.summary)?;
                (
                    TypeProjectionLayout::Element {
                        stride: element.stride,
                    },
                    element.element_type,
                )
            }
            VariableAccessSegment::Field(_) | VariableAccessSegment::TupleIndex(_) => return None,
        };
        let identity = self.identity.project_structural(segment)?;

        Some(TypeProjection {
            layout,
            resolved_type: Self::new(summary, identity, self.origin.clone()),
        })
    }

    pub(crate) fn wrap(
        self,
        kind: SyntheticTypeKind,
        summary: impl FnOnce(TypeInfo) -> TypeInfo,
    ) -> Self {
        Self {
            summary: summary(self.summary),
            identity: TypeIdentity::synthetic(kind, self.identity),
            origin: self.origin,
        }
    }
}

/// Physical address operation and semantic type produced by one projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeProjectionLayout {
    Dereference,
    Member { offset: u64 },
    Element { stride: u64 },
}

/// Atomic result of projecting a resolved type through one access segment.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeProjection {
    pub layout: TypeProjectionLayout,
    pub resolved_type: ResolvedType,
}

#[cfg(test)]
mod tests {
    use super::{
        ResolvedType, SourceLanguage, SyntheticTypeKind, TypeIdentity, TypeProjectionLayout,
    };
    use crate::{CuId, DieRef, ModuleId, TypeId, TypeInfo, VariableAccessSegment};

    fn type_id() -> TypeId {
        TypeId {
            module: ModuleId(1),
            cu: CuId(2),
            die: DieRef {
                module: ModuleId(1),
                cu: CuId(2),
                offset: 3,
            },
        }
    }

    #[test]
    fn normalizes_supported_language_families() {
        assert_eq!(
            SourceLanguage::from_dwarf(Some(gimli::DW_LANG_C17)),
            SourceLanguage::C
        );
        assert_eq!(
            SourceLanguage::from_dwarf(Some(gimli::DW_LANG_C_plus_plus_20)),
            SourceLanguage::Cpp
        );
        assert_eq!(
            SourceLanguage::from_dwarf(Some(gimli::DW_LANG_Rust)),
            SourceLanguage::Rust
        );
    }

    #[test]
    fn preserves_unknown_language_codes() {
        let custom = gimli::DwLang(0x8abc);
        assert_eq!(
            SourceLanguage::from_dwarf(Some(custom)),
            SourceLanguage::Other(0x8abc)
        );
        assert_eq!(SourceLanguage::from_dwarf(None), SourceLanguage::Unknown);
    }

    #[test]
    fn layout_identity_looks_through_qualifiers_only() {
        let dwarf = TypeIdentity::Dwarf(type_id());
        let qualified = TypeIdentity::synthetic(SyntheticTypeKind::Qualified, dwarf.clone());
        let pointer = TypeIdentity::synthetic(SyntheticTypeKind::Pointer, qualified.clone());

        assert_eq!(qualified.layout_dwarf_id(), Some(type_id()));
        assert_eq!(pointer.layout_dwarf_id(), None);
        assert_eq!(dwarf.layout_dwarf_id(), Some(type_id()));
    }

    #[test]
    fn synthetic_projection_does_not_implicitly_consume_pointers_for_members() {
        let pointer = TypeIdentity::synthetic(
            SyntheticTypeKind::Pointer,
            TypeIdentity::synthetic(SyntheticTypeKind::Pointer, TypeIdentity::Dwarf(type_id())),
        );

        assert_eq!(
            pointer.project_structural(&VariableAccessSegment::Field("value".to_string())),
            None
        );
    }

    #[test]
    fn structural_projection_keeps_summary_and_identity_in_lockstep() {
        let pair = TypeInfo::StructType {
            name: "Pair".to_string(),
            size: 8,
            members: vec![],
        };
        let resolved = ResolvedType::new(
            TypeInfo::ArrayType {
                element_type: Box::new(TypeInfo::PointerType {
                    target_type: Box::new(pair.clone()),
                    size: 8,
                }),
                element_count: Some(2),
                total_size: Some(16),
            },
            TypeIdentity::synthetic(
                SyntheticTypeKind::Array,
                TypeIdentity::synthetic(SyntheticTypeKind::Pointer, TypeIdentity::Dwarf(type_id())),
            ),
            None,
        );

        let pointer = resolved
            .project_structural(&VariableAccessSegment::ArrayIndex(0))
            .expect("array element projection");
        assert_eq!(pointer.layout, TypeProjectionLayout::Element { stride: 8 });
        assert!(matches!(
            pointer.resolved_type.summary,
            TypeInfo::PointerType { .. }
        ));
        assert!(matches!(
            pointer.resolved_type.identity,
            TypeIdentity::Synthetic {
                kind: SyntheticTypeKind::Pointer,
                ..
            }
        ));

        let pair_projection = pointer
            .resolved_type
            .project_structural(&VariableAccessSegment::Dereference)
            .expect("pointer target projection");
        assert_eq!(pair_projection.layout, TypeProjectionLayout::Dereference);
        assert_eq!(pair_projection.resolved_type.summary, pair);
        assert_eq!(
            pair_projection.resolved_type.identity,
            TypeIdentity::Dwarf(type_id())
        );
    }
}

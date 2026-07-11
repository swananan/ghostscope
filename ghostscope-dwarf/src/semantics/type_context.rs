//! Source-language and producer context attached to DWARF-backed types.

use crate::core::{CuId, ModuleId, TypeId};
use crate::TypeInfo;

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

#[cfg(test)]
mod tests {
    use super::SourceLanguage;

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
}

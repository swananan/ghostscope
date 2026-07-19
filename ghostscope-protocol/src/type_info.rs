//! Type information system for GhostScope
//!
//! This module defines a comprehensive type system for representing type information from DWARF.
//! These types preserve the full richness of debugging information needed for accurate
//! memory reading and data formatting.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Type information with full fidelity from DWARF debugging data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeInfo {
    /// Base/primitive type (int, float, char, etc.)
    BaseType {
        name: String,
        size: u64,
        encoding: u16, // Store DwAte as u16 for serialization
    },

    /// Pointer type
    PointerType {
        target_type: Box<TypeInfo>,
        size: u64,
    },

    /// Array type
    ArrayType {
        element_type: Box<TypeInfo>,
        element_count: Option<u64>,
        total_size: Option<u64>,
    },

    /// Struct/class type
    StructType {
        name: String,
        size: u64,
        members: Vec<StructMember>,
    },

    /// Union type
    UnionType {
        name: String,
        size: u64,
        members: Vec<StructMember>,
    },

    /// Enum type
    EnumType {
        name: String,
        size: u64,
        base_type: Box<TypeInfo>,
        variants: Vec<EnumVariant>,
    },

    /// Typedef (type alias)
    TypedefType {
        name: String,
        underlying_type: Box<TypeInfo>,
    },

    /// Qualified type (const, volatile, restrict)
    QualifiedType {
        qualifier: TypeQualifier,
        underlying_type: Box<TypeInfo>,
    },

    /// Function type
    FunctionType {
        return_type: Option<Box<TypeInfo>>,
        parameters: Vec<TypeInfo>,
    },

    /// Bitfield type: a view over an underlying integer type with bit offset/size
    BitfieldType {
        underlying_type: Box<TypeInfo>,
        bit_offset: u8,
        bit_size: u8,
    },

    /// Unresolved or unknown type
    UnknownType { name: String },

    /// Optimized out type (variable was optimized away by compiler)
    OptimizedOut { name: String },

    /// Aggregate whose active fields are selected by DWARF variant parts.
    ///
    /// This is distinct from `EnumType`, which represents a scalar
    /// `DW_TAG_enumeration_type`. Rust enums with payloads are emitted as a
    /// structure containing `DW_TAG_variant_part` and `DW_TAG_variant` DIEs.
    /// Variant-bearing forms are appended after the legacy alternatives so
    /// their serialized discriminants remain stable.
    VariantType {
        name: String,
        size: u64,
        members: Vec<StructMember>,
        variant_parts: Vec<VariantPart>,
    },

    /// Scalar `DW_TAG_enumeration_type` marked with `DW_AT_enum_class`.
    ScopedEnumType {
        name: String,
        size: u64,
        base_type: Box<TypeInfo>,
        variants: Vec<ScopedEnumVariant>,
    },
}

/// Struct/union member information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructMember {
    pub name: String,
    pub member_type: TypeInfo,
    pub offset: u64,
    pub bit_offset: Option<u8>,
    pub bit_size: Option<u8>,
}

/// Enum variant information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// Enumerator of a scoped enum, preserving its DWARF signedness.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScopedEnumVariant {
    pub name: String,
    pub value: DiscriminantValue,
}

/// A `DW_TAG_variant_part` and the field used to select its active branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariantPart {
    /// `DW_AT_discr` points to this member. It is absent for univariant forms.
    pub discriminant: Option<StructMember>,
    pub variants: Vec<VariantCase>,
}

/// One `DW_TAG_variant` branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VariantCase {
    pub selector: VariantSelector,
    pub members: Vec<StructMember>,
    pub variant_parts: Vec<VariantPart>,
    /// Source-language presentation selected before the type enters the
    /// protocol. The formatter must not infer producer conventions from member
    /// names.
    #[serde(default)]
    pub payload_presentation: VariantPayloadPresentation,
}

/// Language-neutral rendering style for one variant payload.
///
/// DWARF describes the physical variant graph but does not distinguish tuple
/// payloads from named-field payloads. A source-language adapter supplies this
/// metadata when the producer convention is known.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VariantPayloadPresentation {
    /// Preserve the physical DWARF member view without producer-specific name
    /// inference.
    #[default]
    Dwarf,
    Unit,
    Tuple,
    Struct,
}

/// Values that activate a variant branch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum VariantSelector {
    /// Neither `DW_AT_discr_value` nor `DW_AT_discr_list` was present.
    Default,
    Ranges(Vec<DiscriminantRange>),
}

/// Inclusive discriminant range from `DW_AT_discr_value` or
/// `DW_AT_discr_list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiscriminantRange {
    pub start: DiscriminantValue,
    pub end: DiscriminantValue,
}

/// A discriminant preserves the signedness of its DWARF member type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiscriminantValue {
    Signed(i64),
    Unsigned(u64),
}

/// Type qualifiers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeQualifier {
    Const,
    Volatile,
    Restrict,
}

impl TypeInfo {
    /// Get the size in bytes of this type
    pub fn size(&self) -> u64 {
        match self {
            TypeInfo::BaseType { size, .. } => *size,
            TypeInfo::PointerType { size, .. } => *size,
            TypeInfo::ArrayType { total_size, .. } => total_size.unwrap_or(0),
            TypeInfo::StructType { size, .. } => *size,
            TypeInfo::UnionType { size, .. } => *size,
            TypeInfo::EnumType { size, .. } => *size,
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.size(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.size(),
            TypeInfo::FunctionType { .. } => 8, // Function pointer size
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => underlying_type.size(),
            TypeInfo::UnknownType { .. } => 0,
            TypeInfo::OptimizedOut { .. } => 0, // Optimized out has no size
            TypeInfo::VariantType { size, .. } => *size,
            TypeInfo::ScopedEnumType { size, .. } => *size,
        }
    }

    /// Format base type with encoding information (shared utility)
    fn format_base_type(name: &str, size: u64, encoding: u16) -> (String, String) {
        let human_readable = if encoding == gimli::constants::DW_ATE_boolean.0 as u16 {
            "bool".to_string()
        } else if encoding == gimli::constants::DW_ATE_float.0 as u16 {
            match size {
                4 => "f32".to_string(),
                8 => "f64".to_string(),
                _ => format!("float{size}"),
            }
        } else if encoding == gimli::constants::DW_ATE_signed.0 as u16
            || encoding == gimli::constants::DW_ATE_signed_char.0 as u16
        {
            match size {
                1 => "i8".to_string(),
                2 => "i16".to_string(),
                4 => "i32".to_string(),
                8 => "i64".to_string(),
                _ => format!("i{}", size * 8),
            }
        } else if encoding == gimli::constants::DW_ATE_unsigned.0 as u16
            || encoding == gimli::constants::DW_ATE_unsigned_char.0 as u16
        {
            match size {
                1 => "u8".to_string(),
                2 => "u16".to_string(),
                4 => "u32".to_string(),
                8 => "u64".to_string(),
                _ => format!("u{}", size * 8),
            }
        } else {
            name.to_string()
        };

        let encoding_str = if encoding == gimli::constants::DW_ATE_signed.0 as u16 {
            "signed"
        } else if encoding == gimli::constants::DW_ATE_unsigned.0 as u16 {
            "unsigned"
        } else if encoding == gimli::constants::DW_ATE_float.0 as u16 {
            "float"
        } else if encoding == gimli::constants::DW_ATE_boolean.0 as u16 {
            "bool"
        } else if encoding == gimli::constants::DW_ATE_address.0 as u16 {
            "address"
        } else if encoding == gimli::constants::DW_ATE_signed_char.0 as u16 {
            "signed char"
        } else if encoding == gimli::constants::DW_ATE_unsigned_char.0 as u16 {
            "unsigned char"
        } else {
            "unknown"
        };

        (human_readable, encoding_str.to_string())
    }

    /// Format qualifier string (shared utility)
    fn format_qualifier(qualifier: &TypeQualifier) -> &'static str {
        match qualifier {
            TypeQualifier::Const => "const",
            TypeQualifier::Volatile => "volatile",
            TypeQualifier::Restrict => "restrict",
        }
    }

    /// Get the type name for display
    pub fn type_name(&self) -> String {
        match self {
            TypeInfo::BaseType { name, .. } => name.clone(),
            TypeInfo::PointerType { target_type, .. } => {
                format!("{}*", target_type.type_name())
            }
            TypeInfo::ArrayType {
                element_type,
                element_count,
                ..
            } => {
                if let Some(count) = element_count {
                    format!("{}[{}]", element_type.type_name(), count)
                } else {
                    format!("{}[]", element_type.type_name())
                }
            }
            TypeInfo::StructType { name, .. } => format!("struct {name}"),
            TypeInfo::UnionType { name, .. } => format!("union {name}"),
            TypeInfo::EnumType { name, .. } => format!("enum {name}"),
            TypeInfo::TypedefType { name, .. } => name.clone(),
            TypeInfo::QualifiedType {
                qualifier,
                underlying_type,
            } => {
                format!(
                    "{} {}",
                    Self::format_qualifier(qualifier),
                    underlying_type.type_name()
                )
            }
            TypeInfo::FunctionType {
                return_type,
                parameters,
            } => {
                let return_str = return_type
                    .as_ref()
                    .map(|t| t.type_name())
                    .unwrap_or_else(|| "void".to_string());
                let param_str = parameters
                    .iter()
                    .map(|p| p.type_name())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!("{return_str} ({param_str})")
            }
            TypeInfo::BitfieldType {
                underlying_type,
                bit_offset,
                bit_size,
            } => format!(
                "bitfield<{}:{}> {}",
                bit_offset,
                bit_size,
                underlying_type.type_name()
            ),
            TypeInfo::UnknownType { name } => name.clone(),
            TypeInfo::OptimizedOut { name } => format!("<optimized_out> {name}"),
            TypeInfo::VariantType { name, .. } => format!("enum {name}"),
            TypeInfo::ScopedEnumType { name, .. } => format!("enum {name}"),
        }
    }

    /// Check if this is a signed integer type
    pub fn is_signed_int(&self) -> bool {
        match self {
            TypeInfo::BaseType { encoding, .. } => {
                *encoding == gimli::constants::DW_ATE_signed.0 as u16
            }
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.is_signed_int(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_signed_int(),
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => underlying_type.is_signed_int(),
            TypeInfo::EnumType { base_type, .. } | TypeInfo::ScopedEnumType { base_type, .. } => {
                base_type.is_signed_int()
            }
            TypeInfo::OptimizedOut { .. } => false,
            _ => false,
        }
    }

    /// Check if this is an unsigned integer type
    pub fn is_unsigned_int(&self) -> bool {
        match self {
            TypeInfo::BaseType { encoding, .. } => {
                *encoding == gimli::constants::DW_ATE_unsigned.0 as u16
            }
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.is_unsigned_int(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_unsigned_int(),
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => underlying_type.is_unsigned_int(),
            TypeInfo::EnumType { base_type, .. } | TypeInfo::ScopedEnumType { base_type, .. } => {
                base_type.is_unsigned_int()
            }
            TypeInfo::OptimizedOut { .. } => false,
            _ => false,
        }
    }

    /// Check if this is a floating point type
    pub fn is_float(&self) -> bool {
        match self {
            TypeInfo::BaseType { encoding, .. } => {
                *encoding == gimli::constants::DW_ATE_float.0 as u16
            }
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.is_float(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_float(),
            TypeInfo::OptimizedOut { .. } => false,
            _ => false,
        }
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        match self {
            TypeInfo::PointerType { .. } => true,
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.is_pointer(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_pointer(),
            _ => false,
        }
    }

    /// Check if this is an array type
    pub fn is_array(&self) -> bool {
        match self {
            TypeInfo::ArrayType { .. } => true,
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.is_array(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_array(),
            _ => false,
        }
    }

    /// Get the underlying type, skipping typedefs and qualifiers
    pub fn underlying_type(&self) -> &TypeInfo {
        match self {
            TypeInfo::TypedefType {
                underlying_type, ..
            } => underlying_type.underlying_type(),
            TypeInfo::QualifiedType {
                underlying_type, ..
            } => underlying_type.underlying_type(),
            TypeInfo::BitfieldType {
                underlying_type, ..
            } => underlying_type.underlying_type(),
            _ => self,
        }
    }

    /// Create a signed integer base type (compatibility method for compiler)
    pub fn signed_int(size: u64) -> Self {
        TypeInfo::BaseType {
            name: match size {
                1 => "i8",
                2 => "i16",
                4 => "i32",
                8 => "i64",
                _ => "iN",
            }
            .to_string(),
            size,
            encoding: gimli::constants::DW_ATE_signed.0 as u16,
        }
    }

    /// Create a floating point base type (compatibility method for compiler)
    pub fn float(size: u64) -> Self {
        TypeInfo::BaseType {
            name: match size {
                4 => "f32",
                8 => "f64",
                _ => "fN",
            }
            .to_string(),
            size,
            encoding: gimli::constants::DW_ATE_float.0 as u16,
        }
    }
}

/// Type cache for performance optimization
pub type TypeCache = HashMap<gimli::UnitOffset, Option<TypeInfo>>;

impl TypeInfo {}

impl fmt::Display for TypeInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeInfo::BaseType {
                name,
                size,
                encoding,
            } => {
                let (human_readable, _) = Self::format_base_type(name, *size, *encoding);
                write!(f, "{human_readable}")
            }
            TypeInfo::PointerType { target_type, .. } => {
                write!(f, "*{target_type}")
            }
            TypeInfo::ArrayType {
                element_type,
                element_count,
                ..
            } => match element_count {
                Some(n) => write!(f, "[{n} x {element_type}]"),
                None => write!(f, "[]{element_type}"),
            },
            TypeInfo::StructType { name, .. } => {
                if name.is_empty() {
                    write!(f, "struct")
                } else {
                    write!(f, "struct {name}")
                }
            }
            TypeInfo::UnionType { name, .. } => {
                if name.is_empty() {
                    write!(f, "union")
                } else {
                    write!(f, "union {name}")
                }
            }
            TypeInfo::EnumType { name, .. } => {
                if name.is_empty() {
                    write!(f, "enum")
                } else {
                    write!(f, "enum {name}")
                }
            }
            TypeInfo::BitfieldType {
                underlying_type,
                bit_offset,
                bit_size,
            } => {
                write!(f, "bitfield<{bit_offset}:{bit_size}> {underlying_type}")
            }
            TypeInfo::TypedefType {
                name,
                underlying_type,
            } => {
                if name.is_empty() {
                    write!(f, "{underlying_type}")
                } else {
                    write!(f, "{name}")
                }
            }
            TypeInfo::QualifiedType {
                qualifier,
                underlying_type,
            } => {
                write!(
                    f,
                    "{} {}",
                    Self::format_qualifier(qualifier),
                    underlying_type
                )
            }
            TypeInfo::FunctionType {
                return_type,
                parameters,
            } => {
                let params_str = parameters
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                match return_type {
                    Some(ret) => write!(f, "fn({params_str}) -> {ret}"),
                    None => write!(f, "fn({params_str})"),
                }
            }
            TypeInfo::UnknownType { name } => {
                if name.is_empty() {
                    write!(f, "unknown")
                } else {
                    write!(f, "{name}")
                }
            }
            TypeInfo::OptimizedOut { name } => {
                if name.is_empty() {
                    write!(f, "<optimized_out>")
                } else {
                    write!(f, "<optimized_out> {name}")
                }
            }
            TypeInfo::VariantType { name, .. } => {
                if name.is_empty() {
                    write!(f, "enum")
                } else {
                    write!(f, "enum {name}")
                }
            }
            TypeInfo::ScopedEnumType { name, .. } => {
                if name.is_empty() {
                    write!(f, "enum")
                } else {
                    write!(f, "enum {name}")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_variant_cases_default_to_dwarf_presentation() {
        let case: VariantCase = serde_json::from_value(serde_json::json!({
            "selector": "Default",
            "members": [],
            "variant_parts": []
        }))
        .unwrap();

        assert_eq!(case.payload_presentation, VariantPayloadPresentation::Dwarf);
    }
}

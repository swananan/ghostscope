//! DWARF type system for ghostscope-dwarf
//!
//! This module defines a comprehensive type system for representing DWARF type information.
//! Unlike the protocol types which are for communication, these types preserve the full
//! richness of DWARF debugging information.

use gimli::DwAte;
use std::collections::HashMap;
use std::fmt;

/// DWARF type information with full fidelity
#[derive(Debug, Clone, PartialEq)]
pub enum DwarfType {
    /// Base/primitive type (int, float, char, etc.)
    BaseType {
        name: String,
        size: u64,
        encoding: DwAte,
    },

    /// Pointer type
    PointerType {
        target_type: Box<DwarfType>,
        size: u64,
    },

    /// Array type
    ArrayType {
        element_type: Box<DwarfType>,
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
        base_type: Box<DwarfType>,
        variants: Vec<EnumVariant>,
    },

    /// Typedef (type alias)
    TypedefType {
        name: String,
        underlying_type: Box<DwarfType>,
    },

    /// Qualified type (const, volatile, restrict)
    QualifiedType {
        qualifier: TypeQualifier,
        underlying_type: Box<DwarfType>,
    },

    /// Function type
    FunctionType {
        return_type: Option<Box<DwarfType>>,
        parameters: Vec<DwarfType>,
    },

    /// Unresolved or unknown type
    UnknownType { name: String },
}

/// Struct/union member information
#[derive(Debug, Clone, PartialEq)]
pub struct StructMember {
    pub name: String,
    pub member_type: DwarfType,
    pub offset: u64,
    pub bit_offset: Option<u8>,
    pub bit_size: Option<u8>,
}

/// Enum variant information
#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    pub name: String,
    pub value: i64,
}

/// Type qualifiers
#[derive(Debug, Clone, PartialEq)]
pub enum TypeQualifier {
    Const,
    Volatile,
    Restrict,
}

impl DwarfType {
    /// Get the size in bytes of this type
    pub fn size(&self) -> u64 {
        match self {
            DwarfType::BaseType { size, .. } => *size,
            DwarfType::PointerType { size, .. } => *size,
            DwarfType::ArrayType { total_size, .. } => total_size.unwrap_or(0),
            DwarfType::StructType { size, .. } => *size,
            DwarfType::UnionType { size, .. } => *size,
            DwarfType::EnumType { size, .. } => *size,
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.size(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.size(),
            DwarfType::FunctionType { .. } => 8, // Function pointer size
            DwarfType::UnknownType { .. } => 0,
        }
    }

    /// Format base type with encoding information (shared utility)
    fn format_base_type(name: &str, size: u64, encoding: DwAte) -> (String, String) {
        let human_readable = if encoding == gimli::DW_ATE_boolean {
            "bool".to_string()
        } else if encoding == gimli::DW_ATE_float {
            match size {
                4 => "f32".to_string(),
                8 => "f64".to_string(),
                _ => format!("float{size}"),
            }
        } else if encoding == gimli::DW_ATE_signed || encoding == gimli::DW_ATE_signed_char {
            match size {
                1 => "i8".to_string(),
                2 => "i16".to_string(),
                4 => "i32".to_string(),
                8 => "i64".to_string(),
                _ => format!("i{}", size * 8),
            }
        } else if encoding == gimli::DW_ATE_unsigned || encoding == gimli::DW_ATE_unsigned_char {
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

        let encoding_str = if encoding == gimli::constants::DW_ATE_signed {
            "signed"
        } else if encoding == gimli::constants::DW_ATE_unsigned {
            "unsigned"
        } else if encoding == gimli::constants::DW_ATE_float {
            "float"
        } else if encoding == gimli::constants::DW_ATE_boolean {
            "bool"
        } else if encoding == gimli::constants::DW_ATE_address {
            "address"
        } else if encoding == gimli::constants::DW_ATE_signed_char {
            "signed char"
        } else if encoding == gimli::constants::DW_ATE_unsigned_char {
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
            DwarfType::BaseType { name, .. } => name.clone(),
            DwarfType::PointerType { target_type, .. } => {
                format!("{}*", target_type.type_name())
            }
            DwarfType::ArrayType {
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
            DwarfType::StructType { name, .. } => format!("struct {name}"),
            DwarfType::UnionType { name, .. } => format!("union {name}"),
            DwarfType::EnumType { name, .. } => format!("enum {name}"),
            DwarfType::TypedefType { name, .. } => name.clone(),
            DwarfType::QualifiedType {
                qualifier,
                underlying_type,
            } => {
                format!(
                    "{} {}",
                    Self::format_qualifier(qualifier),
                    underlying_type.type_name()
                )
            }
            DwarfType::FunctionType {
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
            DwarfType::UnknownType { name } => name.clone(),
        }
    }

    /// Check if this is a signed integer type
    pub fn is_signed_int(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => encoding.0 == gimli::constants::DW_ATE_signed.0,
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.is_signed_int(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_signed_int(),
            _ => false,
        }
    }

    /// Check if this is an unsigned integer type
    pub fn is_unsigned_int(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => {
                encoding.0 == gimli::constants::DW_ATE_unsigned.0
            }
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.is_unsigned_int(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_unsigned_int(),
            _ => false,
        }
    }

    /// Check if this is a floating point type
    pub fn is_float(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => encoding.0 == gimli::constants::DW_ATE_float.0,
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.is_float(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_float(),
            _ => false,
        }
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        match self {
            DwarfType::PointerType { .. } => true,
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.is_pointer(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_pointer(),
            _ => false,
        }
    }

    /// Check if this is an array type
    pub fn is_array(&self) -> bool {
        match self {
            DwarfType::ArrayType { .. } => true,
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.is_array(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.is_array(),
            _ => false,
        }
    }

    /// Get the underlying type, skipping typedefs and qualifiers
    pub fn underlying_type(&self) -> &DwarfType {
        match self {
            DwarfType::TypedefType {
                underlying_type, ..
            } => underlying_type.underlying_type(),
            DwarfType::QualifiedType {
                underlying_type, ..
            } => underlying_type.underlying_type(),
            _ => self,
        }
    }

    /// Create a signed integer base type (compatibility method for compiler)
    pub fn signed_int(size: u64) -> Self {
        DwarfType::BaseType {
            name: match size {
                1 => "i8",
                2 => "i16",
                4 => "i32",
                8 => "i64",
                _ => "iN",
            }
            .to_string(),
            size,
            encoding: gimli::DW_ATE_signed,
        }
    }

    /// Create a floating point base type (compatibility method for compiler)
    pub fn float(size: u64) -> Self {
        DwarfType::BaseType {
            name: match size {
                4 => "f32",
                8 => "f64",
                _ => "fN",
            }
            .to_string(),
            size,
            encoding: gimli::DW_ATE_float,
        }
    }
}

/// Type cache for performance optimization
pub type TypeCache = HashMap<gimli::UnitOffset, Option<DwarfType>>;

impl DwarfType {
    /// Convert type to human-readable string with size info (enhanced format)
    pub fn to_human_readable_with_size(&self) -> String {
        let type_name = self.to_human_readable();
        let size = self.size();
        if size > 0 {
            format!("{type_name} ({size}B)")
        } else {
            type_name
        }
    }

    /// Convert type to human-readable string (compatible with ghostscope-protocol)
    pub fn to_human_readable(&self) -> String {
        match self {
            DwarfType::BaseType {
                name,
                size,
                encoding,
            } => {
                let (human_readable, _) = Self::format_base_type(name, *size, *encoding);
                human_readable
            }
            DwarfType::PointerType { target_type, .. } => {
                format!("*{}", target_type.to_human_readable())
            }
            DwarfType::ArrayType {
                element_type,
                element_count,
                ..
            } => match element_count {
                Some(n) => format!("[{n} x {}]", element_type.to_human_readable()),
                None => format!("[]{}", element_type.to_human_readable()),
            },
            DwarfType::StructType { name, .. } => {
                if name.is_empty() {
                    "struct".to_string()
                } else {
                    format!("struct {name}")
                }
            }
            DwarfType::UnionType { name, .. } => {
                if name.is_empty() {
                    "union".to_string()
                } else {
                    format!("union {name}")
                }
            }
            DwarfType::EnumType { name, .. } => {
                if name.is_empty() {
                    "enum".to_string()
                } else {
                    format!("enum {name}")
                }
            }
            DwarfType::TypedefType {
                name,
                underlying_type,
            } => {
                if name.is_empty() {
                    underlying_type.to_human_readable()
                } else {
                    name.clone()
                }
            }
            DwarfType::QualifiedType {
                underlying_type,
                qualifier,
            } => {
                format!(
                    "{} {}",
                    Self::format_qualifier(qualifier),
                    underlying_type.to_human_readable()
                )
            }
            DwarfType::FunctionType {
                return_type,
                parameters,
            } => {
                let params_str = parameters
                    .iter()
                    .map(|p| p.to_human_readable())
                    .collect::<Vec<_>>()
                    .join(", ");
                match return_type {
                    Some(ret) => format!("fn({params_str}) -> {}", ret.to_human_readable()),
                    None => format!("fn({params_str})"),
                }
            }
            DwarfType::UnknownType { name } => {
                if name.is_empty() {
                    "unknown".to_string()
                } else {
                    name.clone()
                }
            }
        }
    }
}

impl fmt::Display for DwarfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DwarfType::BaseType {
                name,
                size,
                encoding,
            } => {
                let (_, encoding_str) = Self::format_base_type(name, *size, *encoding);
                write!(f, "{name} ({encoding_str} {size}B)")
            }
            DwarfType::PointerType { target_type, size } => {
                write!(f, "{target_type}* ({size}B)")
            }
            DwarfType::ArrayType {
                element_type,
                element_count,
                total_size,
            } => {
                if let Some(count) = element_count {
                    write!(f, "{element_type}[{count}]")?;
                } else {
                    write!(f, "{element_type}[]")?;
                }
                if let Some(size) = total_size {
                    write!(f, " ({size}B)")
                } else {
                    Ok(())
                }
            }
            DwarfType::StructType {
                name,
                size,
                members,
            } => {
                write!(f, "struct {} ({}B, {} members)", name, size, members.len())
            }
            DwarfType::UnionType {
                name,
                size,
                members,
            } => {
                write!(f, "union {} ({}B, {} members)", name, size, members.len())
            }
            DwarfType::EnumType {
                name,
                size,
                variants,
                ..
            } => {
                write!(f, "enum {} ({}B, {} variants)", name, size, variants.len())
            }
            DwarfType::TypedefType {
                name,
                underlying_type,
            } => {
                write!(f, "{name} -> {underlying_type}")
            }
            DwarfType::QualifiedType {
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
            DwarfType::FunctionType {
                return_type,
                parameters,
            } => {
                let return_str = return_type
                    .as_ref()
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "void".to_string());
                write!(f, "fn({} params) -> {}", parameters.len(), return_str)
            }
            DwarfType::UnknownType { name } => {
                write!(f, "unknown({name})")
            }
        }
    }
}

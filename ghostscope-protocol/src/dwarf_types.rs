use crate::TypeEncoding;
use gimli::DwAte;
use serde::{Deserialize, Serialize};
use std::fmt;

/// DWARF type information for variable type system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DwarfType {
    BaseType {
        name: String,
        size: u64,
        encoding: u8,
    },
    PointerType {
        target_type: Box<DwarfType>,
        size: u64,
    },
    ArrayType {
        element_type: Box<DwarfType>,
        size: Option<u64>,
    },
    StructType {
        name: String,
        size: u64,
        members: Vec<StructMember>,
    },
    UnknownType {
        name: String,
    },
}

impl DwarfType {
    /// Get the size in bytes of this DWARF type
    pub fn size(&self) -> u64 {
        match self {
            DwarfType::BaseType { size, .. } => *size,
            DwarfType::PointerType { size, .. } => *size,
            DwarfType::StructType { size, .. } => *size,
            DwarfType::ArrayType { size, .. } => size.unwrap_or(0),
            DwarfType::UnknownType { .. } => 0,
        }
    }

    /// Check if this is a signed integer type
    pub fn is_signed(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => *encoding == gimli::DW_ATE_signed.0,
            _ => false,
        }
    }

    /// Check if this is a pointer type
    pub fn is_pointer(&self) -> bool {
        matches!(self, DwarfType::PointerType { .. })
    }

    /// Get the type name for debugging
    pub fn type_name(&self) -> &str {
        match self {
            DwarfType::BaseType { name, .. } => name,
            DwarfType::PointerType { .. } => "pointer",
            DwarfType::StructType { name, .. } => name,
            DwarfType::ArrayType { .. } => "array",
            DwarfType::UnknownType { name } => name,
        }
    }

    /// Create a new BaseType with DwAte encoding
    pub fn new_base_type(name: String, size: u64, encoding: DwAte) -> Self {
        DwarfType::BaseType {
            name,
            size,
            encoding: encoding.0,
        }
    }

    /// Get the DwAte encoding for BaseType
    pub fn get_dwarf_encoding(&self) -> Option<DwAte> {
        match self {
            DwarfType::BaseType { encoding, .. } => Some(DwAte(*encoding)),
            _ => None,
        }
    }

    /// Check if this is an unsigned integer type
    pub fn is_unsigned(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => *encoding == gimli::DW_ATE_unsigned.0,
            _ => false,
        }
    }

    /// Check if this is a float type
    pub fn is_float(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => *encoding == gimli::DW_ATE_float.0,
            _ => false,
        }
    }

    /// Check if this is a boolean type
    pub fn is_boolean(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => *encoding == gimli::DW_ATE_boolean.0,
            _ => false,
        }
    }

    /// Check if this is an address type
    pub fn is_address(&self) -> bool {
        match self {
            DwarfType::BaseType { encoding, .. } => *encoding == gimli::DW_ATE_address.0,
            _ => false,
        }
    }

    /// Map this DWARF type to wire `TypeEncoding`
    pub fn to_type_encoding(&self) -> TypeEncoding {
        match self {
            DwarfType::BaseType { size, encoding, .. } => {
                let ate = DwAte(*encoding);
                match ate {
                    x if x == gimli::DW_ATE_signed || x == gimli::DW_ATE_signed_char => match *size
                    {
                        1 => TypeEncoding::I8,
                        2 => TypeEncoding::I16,
                        4 => TypeEncoding::I32,
                        8 => TypeEncoding::I64,
                        _ => TypeEncoding::Unknown,
                    },
                    x if x == gimli::DW_ATE_unsigned || x == gimli::DW_ATE_unsigned_char => {
                        match *size {
                            1 => TypeEncoding::U8,
                            2 => TypeEncoding::U16,
                            4 => TypeEncoding::U32,
                            8 => TypeEncoding::U64,
                            _ => TypeEncoding::Unknown,
                        }
                    }
                    x if x == gimli::DW_ATE_boolean => TypeEncoding::Bool,
                    x if x == gimli::DW_ATE_float => match *size {
                        4 => TypeEncoding::F32,
                        8 => TypeEncoding::F64,
                        _ => TypeEncoding::Unknown,
                    },
                    x if x == gimli::DW_ATE_address => TypeEncoding::Pointer,
                    _ => TypeEncoding::Unknown,
                }
            }
            DwarfType::PointerType { .. } => TypeEncoding::Pointer,
            DwarfType::ArrayType { .. } => TypeEncoding::Array,
            DwarfType::StructType { .. } => TypeEncoding::Struct,
            DwarfType::UnknownType { .. } => TypeEncoding::Unknown,
        }
    }

    /// Convenience: create a signed integer base type without needing gimli in dependents
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
            encoding: gimli::DW_ATE_signed.0,
        }
    }

    /// Convenience: create a floating point base type
    pub fn float(size: u64) -> Self {
        DwarfType::BaseType {
            name: match size {
                4 => "f32",
                8 => "f64",
                _ => "fN",
            }
            .to_string(),
            size,
            encoding: gimli::DW_ATE_float.0,
        }
    }

    /// Produce a concise, human-readable type description
    pub fn to_human_readable(&self) -> String {
        match self {
            DwarfType::BaseType {
                name,
                size,
                encoding,
            } => {
                let ate = DwAte(*encoding);
                if ate == gimli::DW_ATE_boolean {
                    return "bool".to_string();
                }
                if ate == gimli::DW_ATE_float {
                    return match *size {
                        4 => "f32".to_string(),
                        8 => "f64".to_string(),
                        _ => format!("float{}", size),
                    };
                }
                if ate == gimli::DW_ATE_signed || ate == gimli::DW_ATE_signed_char {
                    return match *size {
                        1 => "i8".to_string(),
                        2 => "i16".to_string(),
                        4 => "i32".to_string(),
                        8 => "i64".to_string(),
                        _ => format!("i{}", size * 8),
                    };
                }
                if ate == gimli::DW_ATE_unsigned || ate == gimli::DW_ATE_unsigned_char {
                    return match *size {
                        1 => "u8".to_string(),
                        2 => "u16".to_string(),
                        4 => "u32".to_string(),
                        8 => "u64".to_string(),
                        _ => format!("u{}", size * 8),
                    };
                }
                name.clone()
            }
            DwarfType::PointerType { target_type, .. } => {
                format!("*{}", target_type.to_human_readable())
            }
            DwarfType::ArrayType { element_type, size } => match size {
                Some(n) => format!("[{} x {}]", n, element_type.to_human_readable()),
                None => format!("[]{}", element_type.to_human_readable()),
            },
            DwarfType::StructType { name, .. } => {
                if name.is_empty() {
                    "struct".to_string()
                } else {
                    format!("struct {}", name)
                }
            }
            DwarfType::UnknownType { name } => "unknown".to_string(),
        }
    }
}

impl fmt::Display for DwarfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_human_readable())
    }
}

/// Struct member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructMember {
    pub name: String,
    pub type_info: DwarfType,
    pub offset: u64,
}

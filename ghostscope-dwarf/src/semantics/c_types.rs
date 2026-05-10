//! C type semantics derived from DWARF type information.
//!
//! This module keeps language-level type classification close to the DWARF
//! semantic layer so compiler backends do not need to duplicate C rules.

use crate::TypeInfo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CIntegerComparisonType {
    pub size: u64,
    pub is_unsigned: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CIntegerComparisonPlan {
    pub size: u64,
    pub is_unsigned: bool,
}

impl CIntegerComparisonType {
    pub fn promoted(self) -> Self {
        if self.size < 4 {
            Self {
                size: 4,
                is_unsigned: false,
            }
        } else {
            self
        }
    }

    pub fn signed_i64() -> Self {
        Self {
            size: 8,
            is_unsigned: false,
        }
    }
}

pub fn strip_type_aliases(mut ty: &TypeInfo) -> &TypeInfo {
    while let TypeInfo::TypedefType {
        underlying_type, ..
    }
    | TypeInfo::QualifiedType {
        underlying_type, ..
    } = ty
    {
        ty = underlying_type.as_ref();
    }
    ty
}

pub fn is_c_aggregate_type(ty: &TypeInfo) -> bool {
    matches!(
        strip_type_aliases(ty),
        TypeInfo::StructType { .. } | TypeInfo::UnionType { .. } | TypeInfo::ArrayType { .. }
    )
}

pub fn is_c_pointer_or_array_type(ty: &TypeInfo) -> bool {
    matches!(
        strip_type_aliases(ty),
        TypeInfo::PointerType { .. } | TypeInfo::ArrayType { .. }
    )
}

pub fn c_integer_comparison_type(ty: &TypeInfo) -> Option<CIntegerComparisonType> {
    match ty {
        TypeInfo::BaseType { encoding, size, .. } => {
            let is_unsigned = *encoding == crate::constants::DW_ATE_unsigned.0 as u16
                || *encoding == crate::constants::DW_ATE_unsigned_char.0 as u16;
            let is_signed = *encoding == crate::constants::DW_ATE_signed.0 as u16
                || *encoding == crate::constants::DW_ATE_signed_char.0 as u16
                || *encoding == crate::constants::DW_ATE_boolean.0 as u16;
            if is_unsigned || is_signed {
                Some(CIntegerComparisonType {
                    size: *size,
                    is_unsigned,
                })
            } else {
                None
            }
        }
        TypeInfo::EnumType {
            base_type, size, ..
        } => c_integer_comparison_type(base_type).map(|mut ty| {
            if ty.size == 0 {
                ty.size = *size;
            }
            ty
        }),
        TypeInfo::BitfieldType {
            underlying_type,
            bit_size,
            ..
        } => c_integer_comparison_type(underlying_type).map(|mut ty| {
            ty.size = (*bit_size as u64).max(1).div_ceil(8);
            ty
        }),
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => c_integer_comparison_type(underlying_type),
        _ => None,
    }
}

pub fn is_c_signed_integer_type(ty: &TypeInfo) -> bool {
    match ty {
        TypeInfo::BaseType { encoding, .. } => {
            *encoding == crate::constants::DW_ATE_signed.0 as u16
                || *encoding == crate::constants::DW_ATE_signed_char.0 as u16
        }
        TypeInfo::EnumType { base_type, .. } => is_c_signed_integer_type(base_type),
        TypeInfo::BitfieldType {
            underlying_type, ..
        } => is_c_signed_integer_type(underlying_type),
        TypeInfo::TypedefType {
            underlying_type, ..
        }
        | TypeInfo::QualifiedType {
            underlying_type, ..
        } => is_c_signed_integer_type(underlying_type),
        _ => false,
    }
}

pub fn usual_c_arithmetic_comparison_plan(
    left: CIntegerComparisonType,
    right: CIntegerComparisonType,
) -> CIntegerComparisonPlan {
    let left = left.promoted();
    let right = right.promoted();
    if left.is_unsigned == right.is_unsigned {
        return CIntegerComparisonPlan {
            size: left.size.max(right.size),
            is_unsigned: left.is_unsigned,
        };
    }

    let unsigned = if left.is_unsigned { left } else { right };
    let signed = if left.is_unsigned { right } else { left };
    if unsigned.size >= signed.size {
        CIntegerComparisonPlan {
            size: unsigned.size,
            is_unsigned: true,
        }
    } else {
        CIntegerComparisonPlan {
            size: signed.size,
            is_unsigned: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StructMember;

    fn int_type(name: &str, size: u64, encoding: u16) -> TypeInfo {
        TypeInfo::BaseType {
            name: name.to_string(),
            size,
            encoding,
        }
    }

    fn signed_int() -> TypeInfo {
        int_type("int", 4, crate::constants::DW_ATE_signed.0 as u16)
    }

    #[test]
    fn aggregate_classification_strips_aliases() {
        let struct_type = TypeInfo::StructType {
            name: "Request".to_string(),
            size: 4,
            members: vec![StructMember {
                name: "fd".to_string(),
                member_type: signed_int(),
                offset: 0,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let typedef = TypeInfo::TypedefType {
            name: "request_t".to_string(),
            underlying_type: Box::new(TypeInfo::QualifiedType {
                qualifier: crate::TypeQualifier::Const,
                underlying_type: Box::new(struct_type),
            }),
        };

        assert!(is_c_aggregate_type(&typedef));
    }

    #[test]
    fn pointer_or_array_classification_strips_aliases() {
        let array_type = TypeInfo::ArrayType {
            element_type: Box::new(signed_int()),
            element_count: Some(4),
            total_size: Some(16),
        };
        let typedef = TypeInfo::TypedefType {
            name: "int_array_t".to_string(),
            underlying_type: Box::new(array_type),
        };

        assert!(is_c_pointer_or_array_type(&typedef));
    }

    #[test]
    fn integer_comparison_type_handles_enums_and_bitfields() {
        let enum_type = TypeInfo::EnumType {
            name: "Mode".to_string(),
            size: 4,
            variants: vec![],
            base_type: Box::new(int_type(
                "unsigned int",
                0,
                crate::constants::DW_ATE_unsigned.0 as u16,
            )),
        };
        assert_eq!(
            c_integer_comparison_type(&enum_type),
            Some(CIntegerComparisonType {
                size: 4,
                is_unsigned: true,
            })
        );

        let bitfield_type = TypeInfo::BitfieldType {
            underlying_type: Box::new(signed_int()),
            bit_offset: 0,
            bit_size: 9,
        };
        assert_eq!(
            c_integer_comparison_type(&bitfield_type),
            Some(CIntegerComparisonType {
                size: 2,
                is_unsigned: false,
            })
        );
    }

    #[test]
    fn signed_integer_classification_excludes_boolean() {
        let bool_type = int_type("bool", 1, crate::constants::DW_ATE_boolean.0 as u16);
        assert_eq!(
            c_integer_comparison_type(&bool_type),
            Some(CIntegerComparisonType {
                size: 1,
                is_unsigned: false,
            })
        );
        assert!(!is_c_signed_integer_type(&bool_type));
        assert!(is_c_signed_integer_type(&signed_int()));
    }

    #[test]
    fn usual_comparison_plan_applies_integer_promotions() {
        let u8_type = CIntegerComparisonType {
            size: 1,
            is_unsigned: true,
        };
        let i8_type = CIntegerComparisonType {
            size: 1,
            is_unsigned: false,
        };

        assert_eq!(
            usual_c_arithmetic_comparison_plan(u8_type, i8_type),
            CIntegerComparisonPlan {
                size: 4,
                is_unsigned: false,
            }
        );
    }

    #[test]
    fn usual_comparison_plan_respects_unsigned_rank() {
        let u64_type = CIntegerComparisonType {
            size: 8,
            is_unsigned: true,
        };
        let i32_type = CIntegerComparisonType {
            size: 4,
            is_unsigned: false,
        };

        assert_eq!(
            usual_c_arithmetic_comparison_plan(u64_type, i32_type),
            CIntegerComparisonPlan {
                size: 8,
                is_unsigned: true,
            }
        );
    }
}

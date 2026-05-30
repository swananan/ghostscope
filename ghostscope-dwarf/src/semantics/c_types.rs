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

#[derive(Clone, Debug, PartialEq)]
pub struct MemberLayout {
    pub offset: u64,
    pub member_type: TypeInfo,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IndexableElementLayout {
    pub element_type: TypeInfo,
    pub stride: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TypeLayoutError {
    #[error("Unknown member '{field}' in {kind} '{type_name}' (known members: {members})")]
    UnknownMember {
        kind: &'static str,
        type_name: String,
        field: String,
        members: String,
    },

    #[error("member access requires struct or union type, got '{type_name}'")]
    InvalidMemberBase { type_name: String },
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

pub fn member_layout(ty: &TypeInfo, field: &str) -> Result<MemberLayout, TypeLayoutError> {
    match strip_type_aliases(ty) {
        TypeInfo::StructType { name, members, .. } => members
            .iter()
            .find(|member| member.name == field)
            .map(|member| MemberLayout {
                offset: member.offset,
                member_type: member.member_type.clone(),
            })
            .ok_or_else(|| unknown_member_error("struct", name, field, members)),
        TypeInfo::UnionType { name, members, .. } => members
            .iter()
            .find(|member| member.name == field)
            .map(|member| MemberLayout {
                offset: member.offset,
                member_type: member.member_type.clone(),
            })
            .ok_or_else(|| unknown_member_error("union", name, field, members)),
        other => Err(TypeLayoutError::InvalidMemberBase {
            type_name: other.type_name(),
        }),
    }
}

pub fn indexable_element_layout(ty: &TypeInfo) -> Option<IndexableElementLayout> {
    match strip_type_aliases(ty) {
        TypeInfo::ArrayType { element_type, .. } => Some(IndexableElementLayout {
            element_type: element_type.as_ref().clone(),
            stride: element_type.size().max(1),
        }),
        TypeInfo::PointerType { target_type, .. } => Some(IndexableElementLayout {
            element_type: target_type.as_ref().clone(),
            stride: target_type.size().max(1),
        }),
        _ => None,
    }
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

fn unknown_member_error(
    kind: &'static str,
    type_name: &str,
    field: &str,
    members: &[crate::StructMember],
) -> TypeLayoutError {
    let mut member_names = members
        .iter()
        .map(|member| member.name.clone())
        .collect::<Vec<_>>();
    member_names.sort();
    member_names.dedup();
    let list = if member_names.is_empty() {
        "<none>".to_string()
    } else {
        member_names.join(", ")
    };

    TypeLayoutError::UnknownMember {
        kind,
        type_name: type_name.to_string(),
        field: field.to_string(),
        members: list,
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
    fn member_and_index_layout_strip_aliases() {
        let signed_int = signed_int();
        let struct_type = TypeInfo::StructType {
            name: "Request".to_string(),
            size: 16,
            members: vec![StructMember {
                name: "fd".to_string(),
                member_type: signed_int.clone(),
                offset: 8,
                bit_offset: None,
                bit_size: None,
            }],
        };
        let qualified_struct = TypeInfo::QualifiedType {
            qualifier: crate::TypeQualifier::Const,
            underlying_type: Box::new(struct_type),
        };

        let layout = member_layout(&qualified_struct, "fd").expect("member layout");
        assert_eq!(layout.offset, 8);
        assert_eq!(layout.member_type, signed_int.clone());

        let pointer_type = TypeInfo::PointerType {
            target_type: Box::new(signed_int),
            size: 8,
        };
        let element = indexable_element_layout(&pointer_type).expect("pointer element layout");
        assert_eq!(element.stride, 4);
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

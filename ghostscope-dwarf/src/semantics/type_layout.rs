//! Language-neutral physical layout operations over normalized DWARF types.

use crate::TypeInfo;

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

pub fn is_aggregate_type(ty: &TypeInfo) -> bool {
    matches!(
        strip_type_aliases(ty),
        TypeInfo::StructType { .. } | TypeInfo::UnionType { .. } | TypeInfo::ArrayType { .. }
    )
}

pub fn is_pointer_or_array_type(ty: &TypeInfo) -> bool {
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

    fn signed_int() -> TypeInfo {
        TypeInfo::BaseType {
            name: "int".to_string(),
            size: 4,
            encoding: crate::constants::DW_ATE_signed.0 as u16,
        }
    }

    #[test]
    fn aggregate_and_index_classification_strip_aliases() {
        let array_type = TypeInfo::ArrayType {
            element_type: Box::new(signed_int()),
            element_count: Some(4),
            total_size: Some(16),
        };
        let typedef = TypeInfo::TypedefType {
            name: "int_array_t".to_string(),
            underlying_type: Box::new(array_type),
        };

        assert!(is_aggregate_type(&typedef));
        assert!(is_pointer_or_array_type(&typedef));
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
}

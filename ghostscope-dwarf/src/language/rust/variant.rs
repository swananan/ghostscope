use crate::{TypeInfo, VariantCase, VariantPart, VariantPayloadPresentation};

pub(super) fn annotate_type_info(type_info: &mut TypeInfo) {
    match type_info {
        TypeInfo::PointerType { target_type, .. }
        | TypeInfo::ArrayType {
            element_type: target_type,
            ..
        }
        | TypeInfo::TypedefType {
            underlying_type: target_type,
            ..
        }
        | TypeInfo::QualifiedType {
            underlying_type: target_type,
            ..
        }
        | TypeInfo::BitfieldType {
            underlying_type: target_type,
            ..
        }
        | TypeInfo::EnumType {
            base_type: target_type,
            ..
        }
        | TypeInfo::ScopedEnumType {
            base_type: target_type,
            ..
        } => annotate_type_info(target_type),
        TypeInfo::StructType { members, .. } | TypeInfo::UnionType { members, .. } => {
            annotate_members(members);
        }
        TypeInfo::FunctionType {
            return_type,
            parameters,
        } => {
            if let Some(return_type) = return_type {
                annotate_type_info(return_type);
            }
            for parameter in parameters {
                annotate_type_info(parameter);
            }
        }
        TypeInfo::VariantType {
            members,
            variant_parts,
            ..
        } => {
            annotate_members(members);
            annotate_variant_parts(variant_parts);
        }
        TypeInfo::BaseType { .. }
        | TypeInfo::UnknownType { .. }
        | TypeInfo::OptimizedOut { .. } => {}
    }
}

fn annotate_members(members: &mut [crate::StructMember]) {
    for member in members {
        annotate_type_info(&mut member.member_type);
    }
}

fn annotate_variant_parts(parts: &mut [VariantPart]) {
    for part in parts {
        if let Some(discriminant) = &mut part.discriminant {
            annotate_type_info(&mut discriminant.member_type);
        }
        for variant in &mut part.variants {
            variant.payload_presentation = rust_payload_presentation(variant);
            annotate_members(&mut variant.members);
            annotate_variant_parts(&mut variant.variant_parts);
        }
    }
}

fn rust_payload_presentation(variant: &VariantCase) -> VariantPayloadPresentation {
    // rustc emits one wrapper member per enum branch. Unit wrappers have no
    // fields, tuple payload fields are named `__0`, `__1`, and so on, and
    // struct payloads preserve their source field names. Active-branch
    // selection still comes entirely from the standard DWARF variant graph;
    // this producer convention controls presentation only.
    let [member] = variant.members.as_slice() else {
        return VariantPayloadPresentation::Dwarf;
    };
    let TypeInfo::StructType { members, .. } = member.member_type.underlying_type() else {
        return VariantPayloadPresentation::Dwarf;
    };
    if members.is_empty() {
        return VariantPayloadPresentation::Unit;
    }
    if members.iter().enumerate().all(|(index, field)| {
        u32::try_from(index)
            .ok()
            .is_some_and(|index| super::access::is_tuple_field_name(&field.name, index))
    }) {
        VariantPayloadPresentation::Tuple
    } else {
        VariantPayloadPresentation::Struct
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DiscriminantValue, StructMember, VariantSelector};

    fn member(name: &str, member_type: TypeInfo) -> StructMember {
        StructMember {
            name: name.to_string(),
            member_type,
            offset: 0,
            bit_offset: None,
            bit_size: None,
        }
    }

    fn payload(name: &str, members: Vec<StructMember>) -> StructMember {
        member(
            name,
            TypeInfo::StructType {
                name: name.to_string(),
                size: 4,
                members,
            },
        )
    }

    fn variant(name: &str, members: Vec<StructMember>) -> VariantCase {
        VariantCase {
            selector: VariantSelector::Default,
            members: vec![payload(name, members)],
            variant_parts: Vec::new(),
            payload_presentation: VariantPayloadPresentation::Dwarf,
        }
    }

    fn scalar() -> TypeInfo {
        TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: gimli::DW_ATE_signed.0 as u16,
        }
    }

    #[test]
    fn annotates_rust_variant_payload_shapes_recursively() {
        let variant_type = TypeInfo::VariantType {
            name: "Example".to_string(),
            size: 4,
            members: Vec::new(),
            variant_parts: vec![VariantPart {
                discriminant: None,
                variants: vec![
                    variant("Unit", Vec::new()),
                    variant(
                        "Tuple",
                        vec![member("__0", scalar()), member("__1", scalar())],
                    ),
                    variant(
                        "Struct",
                        vec![member("left", scalar()), member("right", scalar())],
                    ),
                ],
            }],
        };
        let mut type_info = TypeInfo::StructType {
            name: "Container".to_string(),
            size: 4,
            members: vec![member("nested", variant_type)],
        };

        crate::language::annotate_type_info(crate::SourceLanguage::Rust, &mut type_info);

        let TypeInfo::StructType { members, .. } = type_info else {
            panic!("expected container type");
        };
        let TypeInfo::VariantType { variant_parts, .. } = &members[0].member_type else {
            panic!("expected variant type");
        };
        let presentations = variant_parts[0]
            .variants
            .iter()
            .map(|variant| variant.payload_presentation)
            .collect::<Vec<_>>();
        assert_eq!(
            presentations,
            [
                VariantPayloadPresentation::Unit,
                VariantPayloadPresentation::Tuple,
                VariantPayloadPresentation::Struct,
            ]
        );
    }

    #[test]
    fn does_not_annotate_other_source_languages() {
        let mut type_info = TypeInfo::VariantType {
            name: "CppVariant".to_string(),
            size: 4,
            members: Vec::new(),
            variant_parts: vec![VariantPart {
                discriminant: None,
                variants: vec![variant("Value", vec![member("__0", scalar())])],
            }],
        };

        crate::language::annotate_type_info(crate::SourceLanguage::Cpp, &mut type_info);

        let TypeInfo::VariantType { variant_parts, .. } = type_info else {
            panic!("expected variant type");
        };
        assert_eq!(
            variant_parts[0].variants[0].payload_presentation,
            VariantPayloadPresentation::Dwarf
        );
    }

    #[test]
    fn rejects_non_contiguous_tuple_field_names() {
        let variant = variant(
            "AlmostTuple",
            vec![member("__0", scalar()), member("__2", scalar())],
        );
        assert_eq!(
            rust_payload_presentation(&variant),
            VariantPayloadPresentation::Struct
        );
    }

    #[test]
    fn leaves_non_struct_payloads_language_neutral() {
        let variant = VariantCase {
            selector: VariantSelector::Ranges(vec![crate::DiscriminantRange {
                start: DiscriminantValue::Unsigned(0),
                end: DiscriminantValue::Unsigned(0),
            }]),
            members: vec![member("Value", scalar())],
            variant_parts: Vec::new(),
            payload_presentation: VariantPayloadPresentation::Dwarf,
        };
        assert_eq!(
            rust_payload_presentation(&variant),
            VariantPayloadPresentation::Dwarf
        );
    }
}

use super::DwarfAnalyzer;
use crate::{
    semantics::{
        strip_type_aliases, ResolvedType, SemanticType, SyntheticTypeKind, VariableReadPlan,
    },
    type_syntax::c_style as type_spec,
};
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLookupAmbiguity {
    pub type_name: String,
    pub module_paths: Vec<PathBuf>,
}

impl fmt::Display for TypeLookupAmbiguity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let modules = self
            .module_paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(
            f,
            "type '{}' is ambiguous across loaded modules: {}",
            self.type_name, modules
        )
    }
}

impl std::error::Error for TypeLookupAmbiguity {}

impl DwarfAnalyzer {
    pub fn resolve_builtin_type_spec(type_spec: &str) -> Option<crate::TypeInfo> {
        Self::resolve_builtin_c_style_semantic_type_spec(type_spec).map(|resolved| resolved.summary)
    }

    /// Resolve the C-style type grammar accepted by GhostScope's `cast` DSL.
    pub fn resolve_builtin_c_style_semantic_type_spec(type_spec: &str) -> Option<ResolvedType> {
        resolve_c_style_semantic_type_spec_with(type_spec, |_| None)
    }

    pub fn resolve_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_c_style_semantic_type_spec_in_module(module_path, type_spec)
            .map(|resolved| resolved.summary)
    }

    pub fn resolve_c_style_semantic_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> Option<ResolvedType> {
        let module_path = module_path.as_ref().to_path_buf();
        resolve_c_style_semantic_type_spec_with(type_spec, |name| {
            self.resolve_named_semantic_type_in_module(&module_path, name)
                .or_else(|| self.resolve_named_semantic_type(name))
        })
    }

    pub fn try_resolve_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        self.try_resolve_c_style_semantic_type_spec_in_module(module_path, type_spec)
            .map(|resolved| resolved.map(|resolved| resolved.summary))
    }

    pub fn try_resolve_c_style_semantic_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> std::result::Result<Option<ResolvedType>, TypeLookupAmbiguity> {
        let module_path = module_path.as_ref().to_path_buf();
        try_resolve_c_style_semantic_type_spec_with(type_spec, |name| {
            if let Some(ty) = self.resolve_named_semantic_type_in_module(&module_path, name) {
                return Ok(Some(ty));
            }
            self.resolve_unique_named_semantic_type_outside_module(&module_path, name)
        })
    }

    pub fn resolve_type_spec(&self, type_spec: &str) -> Option<crate::TypeInfo> {
        self.resolve_c_style_semantic_type_spec(type_spec)
            .map(|resolved| resolved.summary)
    }

    pub fn resolve_c_style_semantic_type_spec(&self, type_spec: &str) -> Option<ResolvedType> {
        resolve_c_style_semantic_type_spec_with(type_spec, |name| {
            self.resolve_named_semantic_type(name)
        })
    }

    pub fn try_resolve_type_spec(
        &self,
        type_spec: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        self.try_resolve_c_style_semantic_type_spec(type_spec)
            .map(|resolved| resolved.map(|resolved| resolved.summary))
    }

    pub fn try_resolve_c_style_semantic_type_spec(
        &self,
        type_spec: &str,
    ) -> std::result::Result<Option<ResolvedType>, TypeLookupAmbiguity> {
        try_resolve_c_style_semantic_type_spec_with(type_spec, |name| {
            self.resolve_unique_named_semantic_type(name)
        })
    }

    fn resolve_semantic_type_shallow_by_name_in_module_with_tags<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
        tags: &[gimli::DwTag],
    ) -> Option<SemanticType> {
        let module_path = self.loaded_module_path_for(module_path)?.clone();
        let module = self.module_id_for_path(&module_path)?;
        let (summary, loc) = self
            .modules
            .get(&module_path)?
            .resolve_type_shallow_by_name_with_tags_and_loc(name, tags)?;
        let id = loc.type_id(module);
        Some(SemanticType::new(
            summary,
            Some(id),
            self.type_origin(id).ok().flatten(),
        ))
    }

    fn resolve_semantic_type_shallow_by_name_with_tags(
        &self,
        name: &str,
        tags: &[gimli::DwTag],
    ) -> Option<SemanticType> {
        self.sorted_module_paths()
            .into_iter()
            .find_map(|module_path| {
                self.resolve_semantic_type_shallow_by_name_in_module_with_tags(
                    module_path,
                    name,
                    tags,
                )
            })
    }

    fn resolve_named_semantic_type_in_module(
        &self,
        module_path: &Path,
        name: &str,
    ) -> Option<SemanticType> {
        let tags = [
            gimli::constants::DW_TAG_structure_type,
            gimli::constants::DW_TAG_class_type,
            gimli::constants::DW_TAG_union_type,
            gimli::constants::DW_TAG_enumeration_type,
        ];
        self.resolve_semantic_type_shallow_by_name_in_module_with_tags(module_path, name, &tags)
    }

    fn resolve_named_semantic_type(&self, name: &str) -> Option<SemanticType> {
        let tags = [
            gimli::constants::DW_TAG_structure_type,
            gimli::constants::DW_TAG_class_type,
            gimli::constants::DW_TAG_union_type,
            gimli::constants::DW_TAG_enumeration_type,
        ];
        self.resolve_semantic_type_shallow_by_name_with_tags(name, &tags)
    }

    fn resolve_unique_named_semantic_type_outside_module(
        &self,
        module_path: &Path,
        name: &str,
    ) -> std::result::Result<Option<SemanticType>, TypeLookupAmbiguity> {
        self.resolve_unique_named_semantic_type_with_filter(name, |candidate| {
            candidate != module_path
        })
    }

    fn resolve_unique_named_semantic_type(
        &self,
        name: &str,
    ) -> std::result::Result<Option<SemanticType>, TypeLookupAmbiguity> {
        self.resolve_unique_named_semantic_type_with_filter(name, |_| true)
    }

    fn resolve_unique_named_semantic_type_with_filter(
        &self,
        name: &str,
        include_module: impl Fn(&Path) -> bool,
    ) -> std::result::Result<Option<SemanticType>, TypeLookupAmbiguity> {
        let tags = [
            gimli::constants::DW_TAG_structure_type,
            gimli::constants::DW_TAG_class_type,
            gimli::constants::DW_TAG_union_type,
            gimli::constants::DW_TAG_enumeration_type,
        ];
        let mut matches = self
            .modules
            .iter()
            .filter(|(path, _)| include_module(path.as_path()))
            .filter_map(|(path, _)| {
                self.resolve_semantic_type_shallow_by_name_in_module_with_tags(path, name, &tags)
                    .map(|ty| (path.clone(), ty))
            })
            .collect::<Vec<_>>();

        if matches.len() > 1 {
            let mut module_paths = matches
                .iter()
                .map(|(path, _)| path.clone())
                .collect::<Vec<_>>();
            module_paths.sort();
            return Err(TypeLookupAmbiguity {
                type_name: name.to_string(),
                module_paths,
            });
        }

        Ok(matches.pop().map(|(_, ty)| ty))
    }

    pub(super) fn complete_unknown_pointer_target_type(
        &self,
        module_path: &Path,
        plan: &mut VariableReadPlan,
        pointer_type_name: &str,
    ) {
        let Some(dwarf_type) = plan.dwarf_type.clone() else {
            return;
        };

        let (unknown_name, pointer_size) = match dwarf_type {
            crate::TypeInfo::UnknownType { name } => (name, None),
            crate::TypeInfo::PointerType { target_type, size } => {
                let crate::TypeInfo::UnknownType { name } = *target_type else {
                    return;
                };
                (name, Some(size))
            }
            _ => return,
        };

        let mut candidate_names = Vec::new();
        if !unknown_name.is_empty() && unknown_name != "void" {
            candidate_names.push(unknown_name);
        }
        if candidate_names.is_empty() {
            if let Some(index) = pointer_type_name.find('*') {
                let mut base = pointer_type_name[..index].trim().to_string();
                for prefix in [
                    "const ",
                    "volatile ",
                    "restrict ",
                    "struct ",
                    "class ",
                    "union ",
                ] {
                    if base.starts_with(prefix) {
                        base = base[prefix.len()..].trim().to_string();
                    }
                }
                if !base.is_empty() && base != "void" {
                    candidate_names.push(base);
                }
            }
        }

        for candidate in candidate_names {
            let Some(upgraded) = self.resolve_shallow_named_pointer_target(module_path, &candidate)
            else {
                continue;
            };

            let upgraded = Self::named_type(candidate, upgraded);
            plan.dwarf_type = Some(if let Some(size) = pointer_size {
                crate::TypeInfo::PointerType {
                    target_type: Box::new(upgraded),
                    size,
                }
            } else {
                upgraded
            });
            if let Some(dwarf_type) = plan.dwarf_type.as_ref() {
                plan.type_name = dwarf_type.type_name();
            }
            return;
        }
    }

    pub fn complete_shallow_unknown_aggregate_type_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        ty: crate::TypeInfo,
    ) -> crate::TypeInfo {
        self.complete_shallow_unknown_aggregate_type_impl(Some(module_path.as_ref()), ty)
    }

    pub fn complete_shallow_unknown_aggregate_type(&self, ty: crate::TypeInfo) -> crate::TypeInfo {
        self.complete_shallow_unknown_aggregate_type_impl(None, ty)
    }

    fn complete_shallow_unknown_aggregate_type_impl(
        &self,
        module_path: Option<&Path>,
        ty: crate::TypeInfo,
    ) -> crate::TypeInfo {
        let candidate_name = match strip_type_aliases(&ty) {
            crate::TypeInfo::UnknownType { name } => Some(name.clone()),
            _ => None,
        };
        let Some(candidate_name) = candidate_name else {
            return ty;
        };
        let Some(resolved) =
            self.resolve_shallow_unknown_aggregate_name(module_path, &candidate_name)
        else {
            return ty;
        };

        match ty {
            crate::TypeInfo::TypedefType { name, .. } => crate::TypeInfo::TypedefType {
                name,
                underlying_type: Box::new(resolved),
            },
            crate::TypeInfo::QualifiedType {
                qualifier,
                underlying_type,
            } => {
                crate::TypeInfo::QualifiedType {
                    qualifier,
                    underlying_type: Box::new(self.complete_shallow_unknown_aggregate_type_impl(
                        module_path,
                        *underlying_type,
                    )),
                }
            }
            _ => resolved,
        }
    }

    fn resolve_shallow_unknown_aggregate_name(
        &self,
        module_path: Option<&Path>,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        let mut candidates = Vec::new();
        let mut push_candidate = |candidate: &str| {
            let candidate = candidate.trim();
            if !candidate.is_empty() && candidate != "void" {
                candidates.push(candidate.to_string());
            }
        };

        push_candidate(name);
        for prefix in [
            "const ",
            "volatile ",
            "restrict ",
            "struct ",
            "class ",
            "union ",
        ] {
            if let Some(stripped) = name.strip_prefix(prefix) {
                push_candidate(stripped);
            }
        }

        for candidate in candidates {
            if let Some(module_path) = module_path {
                let resolved = self
                    .resolve_struct_type_shallow_by_name_in_module(module_path, &candidate)
                    .or_else(|| {
                        self.resolve_union_type_shallow_by_name_in_module(module_path, &candidate)
                    });
                if let Some(resolved) = resolved.filter(|ty| ty.size() > 0) {
                    return Some(resolved);
                }
                continue;
            }

            let resolved = self
                .resolve_struct_type_shallow_by_name(&candidate)
                .or_else(|| self.resolve_union_type_shallow_by_name(&candidate));
            if let Some(resolved) = resolved.filter(|ty| ty.size() > 0) {
                return Some(resolved);
            }
        }

        None
    }

    fn named_type(name: String, ty: crate::TypeInfo) -> crate::TypeInfo {
        match ty {
            crate::TypeInfo::StructType { .. }
            | crate::TypeInfo::UnionType { .. }
            | crate::TypeInfo::EnumType { .. }
            | crate::TypeInfo::VariantType { .. }
            | crate::TypeInfo::ScopedEnumType { .. } => crate::TypeInfo::TypedefType {
                name,
                underlying_type: Box::new(ty),
            },
            _ => ty,
        }
    }

    fn resolve_shallow_named_pointer_target(
        &self,
        module_path: &Path,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        [
            self.resolve_struct_type_shallow_by_name(name),
            self.resolve_struct_type_shallow_by_name_in_module(module_path, name),
            self.resolve_union_type_shallow_by_name(name),
            self.resolve_union_type_shallow_by_name_in_module(module_path, name),
            self.resolve_enum_type_shallow_by_name(name),
            self.resolve_enum_type_shallow_by_name_in_module(module_path, name),
        ]
        .into_iter()
        .flatten()
        .find(|ty| ty.size() > 0)
    }

    /// Resolve struct/class by name (shallow) in a specific module using only indexes
    pub fn resolve_struct_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[
                gimli::constants::DW_TAG_structure_type,
                gimli::constants::DW_TAG_class_type,
            ],
        )
        .map(|semantic| semantic.summary)
    }

    /// Resolve struct/class by name (shallow) across modules (first match)
    pub fn resolve_struct_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_with_tags(
            name,
            &[
                gimli::constants::DW_TAG_structure_type,
                gimli::constants::DW_TAG_class_type,
            ],
        )
        .map(|semantic| semantic.summary)
    }

    /// Resolve union by name (shallow) in a specific module
    pub fn resolve_union_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[gimli::constants::DW_TAG_union_type],
        )
        .map(|semantic| semantic.summary)
    }

    /// Resolve union by name (shallow) across modules (first match)
    pub fn resolve_union_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_with_tags(
            name,
            &[gimli::constants::DW_TAG_union_type],
        )
        .map(|semantic| semantic.summary)
    }

    /// Resolve enum by name (shallow) in a specific module
    pub fn resolve_enum_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[gimli::constants::DW_TAG_enumeration_type],
        )
        .map(|semantic| semantic.summary)
    }

    /// Resolve enum by name (shallow) across modules (first match)
    pub fn resolve_enum_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_semantic_type_shallow_by_name_with_tags(
            name,
            &[gimli::constants::DW_TAG_enumeration_type],
        )
        .map(|semantic| semantic.summary)
    }
}

fn resolve_c_style_semantic_type_spec_with<F>(
    type_spec: &str,
    mut resolve_named: F,
) -> Option<ResolvedType>
where
    F: FnMut(&str) -> Option<SemanticType>,
{
    try_resolve_c_style_semantic_type_spec_with(type_spec, |name| {
        Ok::<_, std::convert::Infallible>(resolve_named(name))
    })
    .ok()
    .flatten()
}

fn try_resolve_c_style_semantic_type_spec_with<F, E>(
    type_spec: &str,
    mut resolve_named: F,
) -> std::result::Result<Option<ResolvedType>, E>
where
    F: FnMut(&str) -> std::result::Result<Option<SemanticType>, E>,
{
    let Some(spec) = type_spec::parse(type_spec) else {
        return Ok(None);
    };
    let mut resolved = if let Some(builtin) = builtin_type_spec(&spec.base) {
        ResolvedType::synthetic(builtin)
    } else if let Some(named) = resolve_named(&spec.base)? {
        ResolvedType::from_semantic_type(named)
    } else {
        return Ok(None);
    };

    for qualifier in spec.qualifiers.into_iter().rev() {
        resolved = resolved.wrap(SyntheticTypeKind::Qualified, |underlying_type| {
            crate::TypeInfo::QualifiedType {
                qualifier,
                underlying_type: Box::new(underlying_type),
            }
        });
    }

    for _ in 0..spec.pointer_count {
        resolved = resolved.wrap(SyntheticTypeKind::Pointer, |target_type| {
            crate::TypeInfo::PointerType {
                target_type: Box::new(target_type),
                size: 8,
            }
        });
    }

    for count in spec.arrays.into_iter().rev() {
        let element_size = resolved.summary.size();
        let total_size = count.and_then(|count| element_size.checked_mul(count));
        resolved = resolved.wrap(SyntheticTypeKind::Array, |element_type| {
            crate::TypeInfo::ArrayType {
                element_type: Box::new(element_type),
                element_count: count,
                total_size,
            }
        });
    }

    Ok(Some(resolved))
}

fn builtin_type_spec(spec: &str) -> Option<crate::TypeInfo> {
    let normalized = spec
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    let (name, size, encoding) = match normalized.as_str() {
        "void" => {
            return Some(crate::TypeInfo::UnknownType {
                name: "void".to_string(),
            })
        }
        "bool" | "_bool" => ("bool", 1, gimli::constants::DW_ATE_boolean.0 as u16),
        "char" | "signed char" | "i8" | "int8_t" | "__s8" => {
            ("i8", 1, gimli::constants::DW_ATE_signed_char.0 as u16)
        }
        "unsigned char" | "u8" | "uint8_t" | "__u8" | "byte" => {
            ("u8", 1, gimli::constants::DW_ATE_unsigned_char.0 as u16)
        }
        "short" | "short int" | "signed short" | "signed short int" | "i16" | "int16_t"
        | "__s16" => ("i16", 2, gimli::constants::DW_ATE_signed.0 as u16),
        "unsigned short" | "unsigned short int" | "u16" | "uint16_t" | "__u16" => {
            ("u16", 2, gimli::constants::DW_ATE_unsigned.0 as u16)
        }
        "int" | "signed" | "signed int" | "i32" | "int32_t" | "__s32" => {
            ("i32", 4, gimli::constants::DW_ATE_signed.0 as u16)
        }
        "unsigned" | "unsigned int" | "u32" | "uint32_t" | "__u32" => {
            ("u32", 4, gimli::constants::DW_ATE_unsigned.0 as u16)
        }
        "long"
        | "long int"
        | "signed long"
        | "signed long int"
        | "long long"
        | "long long int"
        | "signed long long"
        | "signed long long int"
        | "i64"
        | "int64_t"
        | "__s64"
        | "ssize_t" => ("i64", 8, gimli::constants::DW_ATE_signed.0 as u16),
        "unsigned long"
        | "unsigned long int"
        | "unsigned long long"
        | "unsigned long long int"
        | "u64"
        | "uint64_t"
        | "__u64"
        | "size_t" => ("u64", 8, gimli::constants::DW_ATE_unsigned.0 as u16),
        "float" | "f32" => ("f32", 4, gimli::constants::DW_ATE_float.0 as u16),
        "double" | "f64" => ("f64", 8, gimli::constants::DW_ATE_float.0 as u16),
        "long double" => ("long double", 16, gimli::constants::DW_ATE_float.0 as u16),
        _ => return None,
    };

    Some(crate::TypeInfo::BaseType {
        name: name.to_string(),
        size,
        encoding,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TypeIdentity;

    fn type_id() -> crate::TypeId {
        let module = crate::ModuleId(4);
        let cu = crate::CuId(8);
        crate::TypeId {
            module,
            cu,
            die: crate::DieRef {
                module,
                cu,
                offset: 16,
            },
        }
    }

    #[test]
    fn resolves_builtin_pointer_and_array_specs() {
        let ty = DwarfAnalyzer::resolve_builtin_type_spec("const unsigned int *[4]")
            .expect("type should resolve");
        let crate::TypeInfo::ArrayType {
            element_type,
            element_count,
            total_size,
        } = ty
        else {
            panic!("expected array type");
        };
        assert_eq!(element_count, Some(4));
        assert_eq!(total_size, Some(32));
        let crate::TypeInfo::PointerType { target_type, size } = *element_type else {
            panic!("expected pointer element");
        };
        assert_eq!(size, 8);
        assert!(matches!(
            *target_type,
            crate::TypeInfo::QualifiedType {
                qualifier: crate::TypeQualifier::Const,
                ..
            }
        ));
    }

    #[test]
    fn resolves_builtin_c_integer_aliases() {
        let ty = DwarfAnalyzer::resolve_builtin_type_spec("uint64_t").expect("type should resolve");
        assert_eq!(ty.size(), 8);
        assert!(ty.is_unsigned_int());
    }

    #[test]
    fn preserves_named_identity_under_synthetic_type_wrappers() {
        let resolved = resolve_c_style_semantic_type_spec_with("const Pair *[2]", |name| {
            (name == "Pair").then(|| {
                SemanticType::new(
                    crate::TypeInfo::StructType {
                        name: "Pair".to_string(),
                        size: 8,
                        members: vec![],
                    },
                    Some(type_id()),
                    None,
                )
            })
        })
        .expect("type spec");

        let TypeIdentity::Synthetic {
            kind: SyntheticTypeKind::Array,
            inner,
        } = resolved.identity
        else {
            panic!("expected synthetic array identity");
        };
        let TypeIdentity::Synthetic {
            kind: SyntheticTypeKind::Pointer,
            inner,
        } = *inner
        else {
            panic!("expected synthetic pointer identity");
        };
        let TypeIdentity::Synthetic {
            kind: SyntheticTypeKind::Qualified,
            inner,
        } = *inner
        else {
            panic!("expected synthetic qualifier identity");
        };
        assert_eq!(*inner, TypeIdentity::Dwarf(type_id()));

        let element = TypeIdentity::Synthetic {
            kind: SyntheticTypeKind::Array,
            inner: Box::new(TypeIdentity::synthetic(
                SyntheticTypeKind::Pointer,
                TypeIdentity::Dwarf(type_id()),
            )),
        }
        .project_structural(&crate::VariableAccessSegment::ArrayIndex(0))
        .expect("synthetic array projection");
        assert!(matches!(
            element,
            TypeIdentity::Synthetic {
                kind: SyntheticTypeKind::Pointer,
                ..
            }
        ));
    }
}

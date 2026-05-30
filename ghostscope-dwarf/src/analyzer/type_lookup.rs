use super::DwarfAnalyzer;
use crate::semantics::{strip_type_aliases, VariableReadPlan};
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
        resolve_type_spec_with(type_spec, |_| None)
    }

    pub fn resolve_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> Option<crate::TypeInfo> {
        let module_path = module_path.as_ref().to_path_buf();
        resolve_type_spec_with(type_spec, |name| {
            self.resolve_named_type_in_module(&module_path, name)
                .or_else(|| self.resolve_named_type(name))
        })
    }

    pub fn try_resolve_type_spec_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        type_spec: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        let module_path = module_path.as_ref().to_path_buf();
        try_resolve_type_spec_with(type_spec, |name| {
            if let Some(ty) = self.resolve_named_type_in_module(&module_path, name) {
                return Ok(Some(ty));
            }
            self.resolve_unique_named_type_outside_module(&module_path, name)
        })
    }

    pub fn resolve_type_spec(&self, type_spec: &str) -> Option<crate::TypeInfo> {
        resolve_type_spec_with(type_spec, |name| self.resolve_named_type(name))
    }

    pub fn try_resolve_type_spec(
        &self,
        type_spec: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        try_resolve_type_spec_with(type_spec, |name| self.resolve_unique_named_type(name))
    }

    fn resolve_type_shallow_by_name_in_module_with_tags<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
        tags: &[gimli::DwTag],
    ) -> Option<crate::TypeInfo> {
        let path_buf = module_path.as_ref().to_path_buf();
        self.modules
            .get(&path_buf)
            .and_then(|module_data| module_data.resolve_type_shallow_by_name_with_tags(name, tags))
    }

    fn resolve_type_shallow_by_name_with_tags(
        &self,
        name: &str,
        tags: &[gimli::DwTag],
    ) -> Option<crate::TypeInfo> {
        self.modules
            .values()
            .find_map(|module_data| module_data.resolve_type_shallow_by_name_with_tags(name, tags))
    }

    fn resolve_named_type_in_module(
        &self,
        module_path: &Path,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        let tags = [
            gimli::constants::DW_TAG_structure_type,
            gimli::constants::DW_TAG_class_type,
            gimli::constants::DW_TAG_union_type,
            gimli::constants::DW_TAG_enumeration_type,
        ];
        self.resolve_type_shallow_by_name_in_module_with_tags(module_path, name, &tags)
    }

    fn resolve_named_type(&self, name: &str) -> Option<crate::TypeInfo> {
        let tags = [
            gimli::constants::DW_TAG_structure_type,
            gimli::constants::DW_TAG_class_type,
            gimli::constants::DW_TAG_union_type,
            gimli::constants::DW_TAG_enumeration_type,
        ];
        self.resolve_type_shallow_by_name_with_tags(name, &tags)
    }

    fn resolve_unique_named_type_outside_module(
        &self,
        module_path: &Path,
        name: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        self.resolve_unique_named_type_with_filter(name, |candidate| candidate != module_path)
    }

    fn resolve_unique_named_type(
        &self,
        name: &str,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
        self.resolve_unique_named_type_with_filter(name, |_| true)
    }

    fn resolve_unique_named_type_with_filter(
        &self,
        name: &str,
        include_module: impl Fn(&Path) -> bool,
    ) -> std::result::Result<Option<crate::TypeInfo>, TypeLookupAmbiguity> {
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
            .filter_map(|(path, module_data)| {
                module_data
                    .resolve_type_shallow_by_name_with_tags(name, &tags)
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
            | crate::TypeInfo::EnumType { .. } => crate::TypeInfo::TypedefType {
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
        self.resolve_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[
                gimli::constants::DW_TAG_structure_type,
                gimli::constants::DW_TAG_class_type,
            ],
        )
    }

    /// Resolve struct/class by name (shallow) across modules (first match)
    pub fn resolve_struct_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_type_shallow_by_name_with_tags(
            name,
            &[
                gimli::constants::DW_TAG_structure_type,
                gimli::constants::DW_TAG_class_type,
            ],
        )
    }

    /// Resolve union by name (shallow) in a specific module
    pub fn resolve_union_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[gimli::constants::DW_TAG_union_type],
        )
    }

    /// Resolve union by name (shallow) across modules (first match)
    pub fn resolve_union_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_type_shallow_by_name_with_tags(name, &[gimli::constants::DW_TAG_union_type])
    }

    /// Resolve enum by name (shallow) in a specific module
    pub fn resolve_enum_type_shallow_by_name_in_module<P: AsRef<Path>>(
        &self,
        module_path: P,
        name: &str,
    ) -> Option<crate::TypeInfo> {
        self.resolve_type_shallow_by_name_in_module_with_tags(
            module_path,
            name,
            &[gimli::constants::DW_TAG_enumeration_type],
        )
    }

    /// Resolve enum by name (shallow) across modules (first match)
    pub fn resolve_enum_type_shallow_by_name(&self, name: &str) -> Option<crate::TypeInfo> {
        self.resolve_type_shallow_by_name_with_tags(
            name,
            &[gimli::constants::DW_TAG_enumeration_type],
        )
    }
}

fn resolve_type_spec_with<F>(type_spec: &str, mut resolve_named: F) -> Option<crate::TypeInfo>
where
    F: FnMut(&str) -> Option<crate::TypeInfo>,
{
    try_resolve_type_spec_with(type_spec, |name| {
        Ok::<_, std::convert::Infallible>(resolve_named(name))
    })
    .ok()
    .flatten()
}

fn try_resolve_type_spec_with<F, E>(
    type_spec: &str,
    mut resolve_named: F,
) -> std::result::Result<Option<crate::TypeInfo>, E>
where
    F: FnMut(&str) -> std::result::Result<Option<crate::TypeInfo>, E>,
{
    // TODO: This parser intentionally accepts only C/C++-style type specs for now.
    // Add an explicit TypeSpec/parser layer before extending this to Rust or other languages.
    let mut spec = type_spec.trim();
    if spec.is_empty() {
        return Ok(None);
    }

    let mut arrays = Vec::new();
    while let Some((base, count)) = take_array_suffix(spec) {
        arrays.push(count);
        spec = base.trim_end();
    }

    let mut pointer_count = 0usize;
    while let Some(base) = spec.strip_suffix('*') {
        pointer_count += 1;
        spec = base.trim_end();
    }

    let (qualifiers, base_spec) = strip_leading_qualifiers(spec);
    let Some(mut ty) = try_resolve_base_type_spec(base_spec, &mut resolve_named)? else {
        return Ok(None);
    };

    for qualifier in qualifiers.into_iter().rev() {
        ty = crate::TypeInfo::QualifiedType {
            qualifier,
            underlying_type: Box::new(ty),
        };
    }

    for _ in 0..pointer_count {
        ty = crate::TypeInfo::PointerType {
            target_type: Box::new(ty),
            size: 8,
        };
    }

    for count in arrays.into_iter().rev() {
        let element_size = ty.size();
        let total_size = count.and_then(|count| element_size.checked_mul(count));
        ty = crate::TypeInfo::ArrayType {
            element_type: Box::new(ty),
            element_count: count,
            total_size,
        };
    }

    Ok(Some(ty))
}

fn take_array_suffix(spec: &str) -> Option<(&str, Option<u64>)> {
    let spec = spec.trim_end();
    if !spec.ends_with(']') {
        return None;
    }
    let open = spec.rfind('[')?;
    let inside = spec[open + 1..spec.len() - 1].trim();
    let count = if inside.is_empty() {
        None
    } else {
        Some(inside.parse::<u64>().ok()?)
    };
    Some((&spec[..open], count))
}

fn strip_leading_qualifiers(mut spec: &str) -> (Vec<crate::TypeQualifier>, &str) {
    let mut qualifiers = Vec::new();
    loop {
        let trimmed = spec.trim_start();
        if let Some(rest) = trimmed.strip_prefix("const ") {
            qualifiers.push(crate::TypeQualifier::Const);
            spec = rest;
        } else if let Some(rest) = trimmed.strip_prefix("volatile ") {
            qualifiers.push(crate::TypeQualifier::Volatile);
            spec = rest;
        } else if let Some(rest) = trimmed.strip_prefix("restrict ") {
            qualifiers.push(crate::TypeQualifier::Restrict);
            spec = rest;
        } else {
            return (qualifiers, trimmed);
        }
    }
}

fn try_resolve_base_type_spec<F, E>(
    spec: &str,
    resolve_named: &mut F,
) -> std::result::Result<Option<crate::TypeInfo>, E>
where
    F: FnMut(&str) -> std::result::Result<Option<crate::TypeInfo>, E>,
{
    let spec = spec.trim();
    if let Some(ty) = builtin_type_spec(spec) {
        return Ok(Some(ty));
    }

    for prefix in ["struct ", "class ", "union ", "enum "] {
        if let Some(name) = spec.strip_prefix(prefix) {
            return resolve_named(name.trim());
        }
    }

    resolve_named(spec)
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
}

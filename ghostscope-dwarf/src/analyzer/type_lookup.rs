use super::DwarfAnalyzer;
use crate::semantics::VariableReadPlan;
use std::path::Path;

impl DwarfAnalyzer {
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

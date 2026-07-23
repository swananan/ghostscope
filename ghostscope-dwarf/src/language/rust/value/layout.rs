//! DWARF layout helpers shared by Rust value adapter families.

use crate::{strip_type_aliases, StructMember, TypeInfo};

pub(super) fn wrapped_pointer_path(
    root: &TypeInfo,
    mut data_path: Vec<String>,
) -> Option<Vec<String>> {
    let pointer_or_wrapper = resolve_member_path(root, &data_path)?;
    if !matches!(
        strip_type_aliases(pointer_or_wrapper.member_type),
        TypeInfo::PointerType { .. }
    ) {
        // Unique and NonNull changed shape in Rust 1.32 and 1.60. Follow the
        // first DWARF member, matching rust-gdb's compatibility helper.
        let TypeInfo::StructType { members, .. } =
            strip_type_aliases(pointer_or_wrapper.member_type)
        else {
            return None;
        };
        data_path.push(members.first()?.name.clone());
        let raw_pointer = resolve_member_path(root, &data_path)?;
        if !matches!(
            strip_type_aliases(raw_pointer.member_type),
            TypeInfo::PointerType { .. }
        ) {
            return None;
        }
    }

    Some(data_path)
}

pub(super) fn unsigned_metadata_path(
    root: &TypeInfo,
    mut path: Vec<String>,
    expected_size: u64,
) -> Option<Vec<String>> {
    let mut resolved = resolve_member_path(root, &path)?;
    if let TypeInfo::StructType { members, .. } = strip_type_aliases(resolved.member_type) {
        path.push(members.first()?.name.clone());
        resolved = resolve_member_path(root, &path)?;
    }

    matches!(
        strip_type_aliases(resolved.member_type),
        TypeInfo::BaseType { size, encoding, .. }
            if *size == expected_size && *encoding == gimli::DW_ATE_unsigned.0 as u16
    )
    .then_some(path)
}

pub(super) fn field_path(fields: &[&str]) -> Vec<String> {
    fields.iter().map(|field| (*field).to_string()).collect()
}

pub(super) fn prefixed_field_path(prefix: &[&str], fields: &[&str]) -> Vec<String> {
    prefix
        .iter()
        .chain(fields)
        .map(|field| (*field).to_string())
        .collect()
}

pub(super) fn unique_named_member<'a>(
    members: &'a [StructMember],
    name: &str,
) -> Option<&'a StructMember> {
    let mut matching = members.iter().filter(|member| member.name == name);
    let member = matching.next()?;
    matching.next().is_none().then_some(member)
}

pub(super) fn sole_struct_member(type_info: &TypeInfo) -> Option<&StructMember> {
    let TypeInfo::StructType { members, .. } = strip_type_aliases(type_info) else {
        return None;
    };
    let [member] = members.as_slice() else {
        return None;
    };
    Some(member)
}

pub(super) fn scalar_wrapper_target(type_info: &TypeInfo) -> Option<&TypeInfo> {
    let mut current = type_info;
    for _ in 0..16 {
        match strip_type_aliases(current) {
            TypeInfo::BaseType { .. } | TypeInfo::PointerType { .. } => return Some(current),
            TypeInfo::StructType { size, .. } => {
                let member = sole_struct_member(current)?;
                member_range(member, *size)?;
                current = &member.member_type;
            }
            _ => return None,
        }
    }
    None
}

pub(super) fn member_range(member: &StructMember, container_size: u64) -> Option<(u64, u64)> {
    if member.bit_offset.is_some() || member.bit_size.is_some() {
        return None;
    }
    let end = member.offset.checked_add(member.member_type.size())?;
    (end <= container_size).then_some((member.offset, end))
}

pub(super) fn ranges_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < left.1 && right.0 < right.1 && left.0 < right.1 && right.0 < left.1
}

pub(super) struct ResolvedMemberPath<'a> {
    pub(super) offset: u64,
    pub(super) member_type: &'a TypeInfo,
}

pub(super) fn resolve_member_path<'a>(
    root: &'a TypeInfo,
    path: &[String],
) -> Option<ResolvedMemberPath<'a>> {
    resolve_member_path_impl(root, path, false)
}

pub(super) fn resolve_member_path_allowing_zst<'a>(
    root: &'a TypeInfo,
    path: &[String],
) -> Option<ResolvedMemberPath<'a>> {
    resolve_member_path_impl(root, path, true)
}

fn resolve_member_path_impl<'a>(
    root: &'a TypeInfo,
    path: &[String],
    allow_zero_sized: bool,
) -> Option<ResolvedMemberPath<'a>> {
    let mut current = root;
    let mut offset = 0u64;

    for field in path {
        let TypeInfo::StructType { size, members, .. } = strip_type_aliases(current) else {
            return None;
        };
        let member = members.iter().find(|member| member.name == *field)?;
        let member_size = member.member_type.size();
        let member_end = member.offset.checked_add(member_size)?;
        if (!allow_zero_sized && member_size == 0)
            || member.bit_offset.is_some()
            || member.bit_size.is_some()
            || member_end > *size
        {
            return None;
        }
        offset = offset.checked_add(member.offset)?;
        current = &member.member_type;
    }

    Some(ResolvedMemberPath {
        offset,
        member_type: current,
    })
}

//! DWARF layout validation for Rust transparent, borrow, and owner wrappers.

use crate::language::adapter::{
    CompositeStructField, CompositeStructFieldCapture, CompositeStructLayout, ProjectedPathSegment,
    ProjectedStructField, ProjectedStructLayout, ProjectedStructPresentation,
    ProjectedValueRequirement,
};
use crate::{strip_type_aliases, StructMember, TypeInfo};

use super::layout::{
    member_range, ranges_overlap, resolve_member_path, resolve_member_path_allowing_zst,
    scalar_wrapper_target, sole_struct_member, unique_named_member,
};

pub(super) fn rust_nonzero_value_path(root: &TypeInfo) -> Option<Vec<String>> {
    // Rust 1.65-1.78 rust-gdb follows one sole member for legacy names such as
    // NonZeroU32. Rust 1.79 through the current 1.98 nightly follows a second
    // sole member for generic NonZero<T>. Neither printer depends on field
    // names, so derive the path, offsets, and widths from the concrete DIE.
    let TypeInfo::StructType { members, .. } = strip_type_aliases(root) else {
        return None;
    };
    let [outer] = members.as_slice() else {
        return None;
    };
    let mut value_path = vec![outer.name.clone()];
    if let TypeInfo::StructType {
        members: inner_members,
        ..
    } = strip_type_aliases(&outer.member_type)
    {
        let [inner] = inner_members.as_slice() else {
            return None;
        };
        value_path.push(inner.name.clone());
    };
    let value = resolve_member_path(root, &value_path)?;
    let TypeInfo::BaseType { size, encoding, .. } = strip_type_aliases(value.member_type) else {
        return None;
    };
    let integer_encoding = matches!(
        *encoding,
        encoding if encoding == gimli::DW_ATE_signed.0 as u16
            || encoding == gimli::DW_ATE_signed_char.0 as u16
            || encoding == gimli::DW_ATE_unsigned.0 as u16
            || encoding == gimli::DW_ATE_unsigned_char.0 as u16
    );
    let value_end = value.offset.checked_add(*size)?;

    (*size > 0 && integer_encoding && value_end <= root.size()).then_some(value_path)
}

pub(super) fn rust_cell_value_path(root: &TypeInfo) -> Option<Vec<String>> {
    // Rust 1.46 through the current 1.98 nightly rust-gdb provider reads two
    // nested `value` members. The provider has no version-specific fallback,
    // so validate the same unique-member shape but derive names, offsets, and
    // the projected type exclusively from the concrete DWARF DIEs.
    let TypeInfo::StructType { members, .. } = strip_type_aliases(root) else {
        return None;
    };
    let [outer] = members.as_slice() else {
        return None;
    };
    let TypeInfo::StructType {
        members: inner_members,
        ..
    } = strip_type_aliases(&outer.member_type)
    else {
        return None;
    };
    let [inner] = inner_members.as_slice() else {
        return None;
    };
    let value_path = vec![outer.name.clone(), inner.name.clone()];
    let value = resolve_member_path_allowing_zst(root, &value_path)?;
    let value_end = value.offset.checked_add(value.member_type.size())?;

    (!matches!(
        strip_type_aliases(value.member_type),
        TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
    ) && value_end <= root.size())
    .then_some(value_path)
}

pub(super) fn rust_ref_cell_layout(root: &TypeInfo) -> Option<ProjectedStructLayout> {
    // Rust 1.46 through the current 1.98 nightly rust-gdb provider reads
    // `value.value` and `borrow.value.value` without a version fallback. The
    // outer names establish those semantic roles; all inner names, offsets,
    // widths, and projected types below come from the concrete DWARF DIEs.
    let TypeInfo::StructType { members, .. } = strip_type_aliases(root) else {
        return None;
    };
    let value_outer = unique_named_member(members, "value")?;
    let borrow_outer = unique_named_member(members, "borrow")?;

    let value_inner = sole_struct_member(&value_outer.member_type)?;
    let value_path = vec![value_outer.name.clone(), value_inner.name.clone()];

    let borrow_cell_inner = sole_struct_member(&borrow_outer.member_type)?;
    let borrow_inner = sole_struct_member(&borrow_cell_inner.member_type)?;
    let borrow_path = vec![
        borrow_outer.name.clone(),
        borrow_cell_inner.name.clone(),
        borrow_inner.name.clone(),
    ];

    let value = resolve_member_path_allowing_zst(root, &value_path)?;
    let borrow = resolve_member_path(root, &borrow_path)?;
    let TypeInfo::BaseType { size, encoding, .. } = strip_type_aliases(borrow.member_type) else {
        return None;
    };
    let signed_state = *encoding == gimli::DW_ATE_signed.0 as u16
        || *encoding == gimli::DW_ATE_signed_char.0 as u16;
    let supported_width = matches!(*size, 1 | 2 | 4 | 8 | 16);
    let value_size = value.member_type.size();
    let value_end = value.offset.checked_add(value_size)?;
    let borrow_end = borrow.offset.checked_add(*size)?;
    let fields_overlap = value_size > 0 && value.offset < borrow_end && borrow.offset < value_end;

    if matches!(
        strip_type_aliases(value.member_type),
        TypeInfo::UnknownType { .. } | TypeInfo::OptimizedOut { .. }
    ) || !signed_state
        || !supported_width
        || value_end > root.size()
        || borrow_end > root.size()
        || fields_overlap
    {
        return None;
    }

    Some(ProjectedStructLayout {
        type_name: "RefCell",
        fields: vec![
            ProjectedStructField {
                name: "value",
                value_path,
            },
            ProjectedStructField {
                name: "borrow",
                value_path: borrow_path,
            },
        ],
        presentation: ProjectedStructPresentation::SignedState {
            state_field: "borrow",
            non_negative_label: "borrow",
            negative_label: "borrow_mut",
        },
    })
}

pub(super) fn rust_ref_layout(root: &TypeInfo) -> Option<CompositeStructLayout> {
    // The rust-gdb providers in Rust 1.46, 1.60, 1.70, 1.81, 1.88, 1.93,
    // 1.95, and 1.98 use one provider for Ref and RefMut. It dereferences
    // `value` and reads `borrow.borrow.value.value`, with no version fallback.
    // Rust 1.49 DWARF emits `value` as a raw pointer, while DWARF inspected
    // from Rust 1.81 through 1.98 emits a one-member NonNull wrapper. Follow
    // the concrete DIE in either case and keep every pointer read explicit
    // instead of assuming wrapper offsets.
    let TypeInfo::StructType {
        size: root_size,
        members,
        ..
    } = strip_type_aliases(root)
    else {
        return None;
    };
    let value_outer = unique_named_member(members, "value")?;
    let borrow_outer = unique_named_member(members, "borrow")?;
    let value_outer_range = member_range(value_outer, *root_size)?;
    let borrow_outer_range = member_range(borrow_outer, *root_size)?;
    if ranges_overlap(value_outer_range, borrow_outer_range) {
        return None;
    }

    let mut value_path = vec![ProjectedPathSegment::Member(value_outer.name.clone())];
    let value_pointer_size = match strip_type_aliases(&value_outer.member_type) {
        TypeInfo::PointerType { size, .. } => *size,
        TypeInfo::StructType { size, .. } => {
            let value_pointer = sole_struct_member(&value_outer.member_type)?;
            member_range(value_pointer, *size)?;
            let TypeInfo::PointerType { size, .. } = strip_type_aliases(&value_pointer.member_type)
            else {
                return None;
            };
            value_path.push(ProjectedPathSegment::Member(value_pointer.name.clone()));
            *size
        }
        _ => return None,
    };
    value_path.push(ProjectedPathSegment::Dereference);

    let borrow_wrapper_size = borrow_outer.member_type.size();
    let borrow_pointer = sole_struct_member(&borrow_outer.member_type)?;
    member_range(borrow_pointer, borrow_wrapper_size)?;
    let TypeInfo::PointerType {
        size: borrow_pointer_size,
        ..
    } = strip_type_aliases(&borrow_pointer.member_type)
    else {
        return None;
    };
    let borrow_path = vec![
        ProjectedPathSegment::Member(borrow_outer.name.clone()),
        ProjectedPathSegment::Member(borrow_pointer.name.clone()),
        ProjectedPathSegment::Dereference,
        ProjectedPathSegment::SoleMember,
        ProjectedPathSegment::SoleMember,
    ];

    let supported_pointer_width =
        matches!(value_pointer_size, 4 | 8) && value_pointer_size == *borrow_pointer_size;
    if !supported_pointer_width {
        return None;
    }

    Some(CompositeStructLayout {
        // rust-gdb deliberately uses the same summary for Ref and RefMut.
        type_name: "Ref",
        fields: vec![
            CompositeStructField {
                name: "*value",
                value_path,
                capture: CompositeStructFieldCapture::Value(
                    ProjectedValueRequirement::KnownSizedOrZst,
                ),
            },
            CompositeStructField {
                name: "borrow",
                value_path: borrow_path,
                capture: CompositeStructFieldCapture::Value(
                    ProjectedValueRequirement::SignedPointerSizedInteger,
                ),
            },
        ],
        presentation: ProjectedStructPresentation::SignedState {
            state_field: "borrow",
            non_negative_label: "borrow",
            negative_label: "borrow_mut",
        },
    })
}

pub(super) fn rust_reference_counted_layout(
    root: &TypeInfo,
    type_name: &'static str,
    value_member: &'static str,
    pointee_is_str: bool,
) -> Option<CompositeStructLayout> {
    // Rust 1.46, 1.60, 1.70, 1.81, 1.88, 1.93, and 1.95 use the same
    // rust-gdb provider paths for Rc and Arc. Rust 1.98 replaces the fixed
    // AtomicUsize path with scalar-wrapper unwrapping because Atomic<usize>
    // gained an alignment wrapper. Actual DWARF also renamed RcBox to RcInner
    // between 1.81 and 1.88. None of those private names or depths are needed
    // here: named semantic members select values, while every wrapper offset
    // and final scalar width comes from the concrete DIE.
    //
    // A sized pointee uses a thin pointer. Slice-like DSTs use rustc's
    // synthetic data_ptr/length aggregate in newer DWARF, while older rustc
    // versions may expose only the allocation pointer. We never infer or read
    // the omitted metadata here: an unsized pointee is represented by its
    // DWARF-projected address. This keeps Rc and Arc on one capture path and
    // avoids treating the first byte of str as a complete value.
    let TypeInfo::StructType {
        size: root_size,
        members,
        ..
    } = strip_type_aliases(root)
    else {
        return None;
    };
    let ptr_outer = unique_named_member(members, "ptr")?;
    member_range(ptr_outer, *root_size)?;
    let TypeInfo::StructType {
        size: ptr_wrapper_size,
        members: ptr_members,
        ..
    } = strip_type_aliases(&ptr_outer.member_type)
    else {
        return None;
    };
    let pointer = unique_named_member(ptr_members, "pointer")?;
    member_range(pointer, *ptr_wrapper_size)?;
    let mut inner_path = vec![
        ProjectedPathSegment::Member(ptr_outer.name.clone()),
        ProjectedPathSegment::Member(pointer.name.clone()),
    ];
    let address_only = if let Some(raw_pointer) = scalar_wrapper_target(&pointer.member_type) {
        let TypeInfo::PointerType {
            target_type,
            size: pointer_size,
        } = strip_type_aliases(raw_pointer)
        else {
            return None;
        };
        if !matches!(*pointer_size, 4 | 8) {
            return None;
        }
        inner_path.push(ProjectedPathSegment::UnwrapScalar);
        pointee_is_str || reference_counted_target_is_unsized(target_type, value_member)
    } else {
        let data_ptr = slice_wide_pointer_data_member(pointer)?;
        inner_path.push(ProjectedPathSegment::Member(data_ptr.name.clone()));
        true
    };
    inner_path.push(ProjectedPathSegment::Dereference);

    let mut value_path = inner_path.clone();
    value_path.push(ProjectedPathSegment::Member(value_member.to_string()));
    let mut strong_path = inner_path.clone();
    strong_path.push(ProjectedPathSegment::Member("strong".to_string()));
    strong_path.push(ProjectedPathSegment::UnwrapScalar);
    let mut weak_path = inner_path;
    weak_path.push(ProjectedPathSegment::Member("weak".to_string()));
    weak_path.push(ProjectedPathSegment::UnwrapScalar);

    Some(CompositeStructLayout {
        type_name,
        fields: vec![
            CompositeStructField {
                name: if address_only { "ptr" } else { "value" },
                value_path,
                capture: if address_only {
                    CompositeStructFieldCapture::Address
                } else {
                    CompositeStructFieldCapture::Value(ProjectedValueRequirement::KnownSizedOrZst)
                },
            },
            CompositeStructField {
                name: "strong",
                value_path: strong_path,
                capture: CompositeStructFieldCapture::Value(
                    ProjectedValueRequirement::UnsignedPointerSizedInteger,
                ),
            },
            CompositeStructField {
                name: "weak",
                value_path: weak_path,
                capture: CompositeStructFieldCapture::Value(
                    ProjectedValueRequirement::UnsignedPointerSizedInteger,
                ),
            },
        ],
        // Rc/Arc allocations hold one implicit weak entry while strong
        // owners exist. rust-gdb subtracts it from the public weak count.
        presentation: ProjectedStructPresentation::ReferenceCounted {
            strong_field: "strong",
            weak_field: "weak",
            implicit_weak: 1,
        },
    })
}

fn reference_counted_target_is_unsized(target: &TypeInfo, value_member: &str) -> bool {
    let TypeInfo::StructType { members, .. } = strip_type_aliases(target) else {
        return false;
    };
    let Some(value) = unique_named_member(members, value_member) else {
        return false;
    };
    matches!(
        strip_type_aliases(&value.member_type),
        TypeInfo::ArrayType {
            total_size: None,
            ..
        }
    )
}

fn slice_wide_pointer_data_member(pointer: &StructMember) -> Option<&StructMember> {
    let TypeInfo::StructType { size, members, .. } = strip_type_aliases(&pointer.member_type)
    else {
        return None;
    };
    let data = unique_named_member(members, "data_ptr")?;
    let length = unique_named_member(members, "length")?;
    let data_range = member_range(data, *size)?;
    let length_range = member_range(length, *size)?;
    if ranges_overlap(data_range, length_range) {
        return None;
    }
    let TypeInfo::PointerType {
        size: pointer_size, ..
    } = strip_type_aliases(&data.member_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: length_size,
        encoding,
        ..
    } = strip_type_aliases(&length.member_type)
    else {
        return None;
    };
    (matches!(*pointer_size, 4 | 8)
        && pointer_size == length_size
        && *encoding == gimli::DW_ATE_unsigned.0 as u16)
        .then_some(data)
}

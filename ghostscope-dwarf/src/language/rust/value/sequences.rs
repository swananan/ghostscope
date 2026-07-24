//! DWARF layout validation for Rust strings and sequence containers.

use crate::language::adapter::{
    IndirectSequenceKind, IndirectSequenceLayout, RingSequenceLengthKind,
};
use crate::{strip_type_aliases, TypeInfo};

use super::layout::{
    field_path, prefixed_field_path, resolve_member_path, unsigned_metadata_path,
    wrapped_pointer_path,
};

pub(super) fn rust_string_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    // rust-gdb uses `buf.ptr` through Rust 1.81 and `buf.inner.ptr` from
    // Rust 1.82 onward. Keep both paths and validate whichever DWARF exposes.
    const DATA_PATHS: &[&[&str]] = &[
        &["vec", "buf", "inner", "ptr", "pointer"],
        &["vec", "buf", "ptr", "pointer"],
    ];

    let length_path = field_path(&["vec", "len"]);
    for fields in DATA_PATHS {
        if let Some(layout) = validate_wrapped_pointer_layout(
            root,
            field_path(fields),
            length_path.clone(),
            IndirectSequenceKind::Utf8String,
        ) {
            return Some(layout);
        }
    }

    None
}

pub(super) fn rust_c_string_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    validate_indirect_sequence_layout(
        root,
        field_path(&["inner", "data_ptr"]),
        field_path(&["inner", "length"]),
        IndirectSequenceKind::NulTerminatedByteString,
    )
}

pub(super) fn rust_vec_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    // rust-gdb uses `buf.ptr` through Rust 1.81 and `buf.inner.ptr` from
    // Rust 1.82 onward. In the latter layout RawVecInner erases `T` to `u8`,
    // so the analyzer must recover the element type from the Vec DIE's first
    // DW_TAG_template_type_parameter instead of trusting the pointer target.
    const DATA_PATHS: &[&[&str]] = &[
        &["buf", "inner", "ptr", "pointer"],
        &["buf", "ptr", "pointer"],
    ];

    let length_path = field_path(&["len"]);
    for fields in DATA_PATHS {
        if let Some(layout) = validate_wrapped_pointer_layout(
            root,
            field_path(fields),
            length_path.clone(),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ) {
            return Some(layout);
        }
    }

    None
}

pub(super) fn rust_vec_deque_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    // Rust 1.67 replaced tail/head length derivation with head/len. Rust 1.82
    // moved RawVec under `inner`; 1.75 and 1.95 introduced transparent
    // wrappers around cap and head respectively. The validators below follow
    // those wrappers through their first DWARF member, as rust-gdb does.
    const CURRENT_STORAGE_PATHS: &[(&[&str], &[&str])] = &[
        (
            &["buf", "inner", "ptr", "pointer"],
            &["buf", "inner", "cap"],
        ),
        (&["buf", "ptr", "pointer"], &["buf", "cap"]),
    ];

    for (data_fields, capacity_fields) in CURRENT_STORAGE_PATHS {
        if let Some(layout) = validate_ring_sequence_layout(
            root,
            field_path(data_fields),
            field_path(&["head"]),
            field_path(&["len"]),
            RingSequenceLengthKind::Explicit,
            field_path(capacity_fields),
            IndirectSequenceKind::TypeParameter { index: 0 },
        ) {
            return Some(layout);
        }
    }

    validate_ring_sequence_layout(
        root,
        field_path(&["buf", "ptr", "pointer"]),
        field_path(&["tail"]),
        field_path(&["head"]),
        RingSequenceLengthKind::End,
        field_path(&["buf", "cap"]),
        IndirectSequenceKind::TypeParameter { index: 0 },
    )
}

pub(super) fn rust_os_string_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    rust_os_string_layout_with_prefix(root, &[])
}

pub(super) fn rust_path_buf_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
    // Rust's LLDB provider delegates PathBuf to its embedded OsString. Reuse
    // that official semantic path while deriving every wrapper and offset from
    // the concrete DWARF instead of assuming PathBuf's Rust layout.
    rust_os_string_layout_with_prefix(root, &["inner"])
}

fn rust_os_string_layout_with_prefix(
    root: &TypeInfo,
    prefix: &[&str],
) -> Option<IndirectSequenceLayout> {
    // Rust 1.82 moved RawVec's pointer under `inner`. Windows used the tuple
    // field `__0` for Wtf8Buf through 1.96 and now names that field `bytes`.
    // Unix exposes the Vec directly. These paths mirror rust-gdb; every
    // selected member offset and width is still read from DWARF.
    const PATHS: &[(&[&str], &[&str])] = &[
        (
            &["inner", "inner", "buf", "inner", "ptr", "pointer"],
            &["inner", "inner", "len"],
        ),
        (
            &["inner", "inner", "buf", "ptr", "pointer"],
            &["inner", "inner", "len"],
        ),
        (
            &["inner", "inner", "bytes", "buf", "inner", "ptr", "pointer"],
            &["inner", "inner", "bytes", "len"],
        ),
        (
            &["inner", "inner", "bytes", "buf", "ptr", "pointer"],
            &["inner", "inner", "bytes", "len"],
        ),
        (
            &["inner", "inner", "__0", "buf", "inner", "ptr", "pointer"],
            &["inner", "inner", "__0", "len"],
        ),
        (
            &["inner", "inner", "__0", "buf", "ptr", "pointer"],
            &["inner", "inner", "__0", "len"],
        ),
    ];

    for (data_fields, length_fields) in PATHS {
        if let Some(layout) = validate_wrapped_pointer_layout(
            root,
            prefixed_field_path(prefix, data_fields),
            prefixed_field_path(prefix, length_fields),
            IndirectSequenceKind::ByteString,
        ) {
            return Some(layout);
        }
    }

    None
}

fn validate_wrapped_pointer_layout(
    root: &TypeInfo,
    data_path: Vec<String>,
    length_path: Vec<String>,
    kind: IndirectSequenceKind,
) -> Option<IndirectSequenceLayout> {
    let data_path = wrapped_pointer_path(root, data_path)?;
    validate_indirect_sequence_layout(root, data_path, length_path, kind)
}

fn validate_ring_sequence_layout(
    root: &TypeInfo,
    data_path: Vec<String>,
    start_path: Vec<String>,
    length_path: Vec<String>,
    length_kind: RingSequenceLengthKind,
    capacity_path: Vec<String>,
    kind: IndirectSequenceKind,
) -> Option<IndirectSequenceLayout> {
    let data_path = wrapped_pointer_path(root, data_path)?;
    let data = resolve_member_path(root, &data_path)?;
    let TypeInfo::PointerType {
        size: pointer_size, ..
    } = strip_type_aliases(data.member_type)
    else {
        return None;
    };
    if *pointer_size == 0 {
        return None;
    }

    let start_path = unsigned_metadata_path(root, start_path, *pointer_size)?;
    let length_path = unsigned_metadata_path(root, length_path, *pointer_size)?;
    let capacity_path = unsigned_metadata_path(root, capacity_path, *pointer_size)?;
    let paths = [&data_path, &start_path, &length_path, &capacity_path];
    let mut ranges = Vec::with_capacity(paths.len());
    for path in paths {
        let member = resolve_member_path(root, path)?;
        let end = member.offset.checked_add(member.member_type.size())?;
        if end > root.size() {
            return None;
        }
        ranges.push((member.offset, end));
    }
    for (index, left) in ranges.iter().enumerate() {
        if ranges[index + 1..]
            .iter()
            .any(|right| left.0 < right.1 && right.0 < left.1)
        {
            return None;
        }
    }

    Some(IndirectSequenceLayout::ring(
        data_path,
        start_path,
        length_path,
        length_kind,
        capacity_path,
        kind,
    ))
}

pub(super) fn validate_indirect_sequence_layout(
    root: &TypeInfo,
    data_path: Vec<String>,
    length_path: Vec<String>,
    kind: IndirectSequenceKind,
) -> Option<IndirectSequenceLayout> {
    let data = resolve_member_path(root, &data_path)?;
    let length = resolve_member_path(root, &length_path)?;
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = strip_type_aliases(data.member_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: length_size,
        encoding: length_encoding,
        ..
    } = strip_type_aliases(length.member_type)
    else {
        return None;
    };

    let unsigned_byte_pointer = match strip_type_aliases(target_type) {
        TypeInfo::BaseType { size, encoding, .. } => {
            *size == 1
                && (*encoding == gimli::DW_ATE_unsigned.0 as u16
                    || *encoding == gimli::DW_ATE_unsigned_char.0 as u16)
        }
        _ => false,
    };
    let c_str_pointer = is_c_str_pointer_target(target_type);
    let unsigned_length = *length_encoding == gimli::DW_ATE_unsigned.0 as u16;
    // Aggregate size, member offsets, and metadata widths come from DWARF.
    let aggregate_size = root.size();
    let data_end = data.offset.checked_add(*pointer_size)?;
    let length_end = length.offset.checked_add(*length_size)?;
    let members_overlap = data.offset < length_end && length.offset < data_end;
    if *pointer_size == 0
        || *pointer_size != *length_size
        || (matches!(
            kind,
            IndirectSequenceKind::Utf8String | IndirectSequenceKind::ByteString
        ) && !unsigned_byte_pointer)
        || (matches!(kind, IndirectSequenceKind::NulTerminatedByteString)
            && !unsigned_byte_pointer
            && !c_str_pointer)
        || !unsigned_length
        || data_end > aggregate_size
        || length_end > aggregate_size
        || members_overlap
    {
        return None;
    }

    Some(IndirectSequenceLayout::contiguous(
        data_path,
        length_path,
        kind,
    ))
}

fn is_c_str_pointer_target(target: &TypeInfo) -> bool {
    if matches!(
        strip_type_aliases(target),
        TypeInfo::UnknownType { name } if name == "CStr" || name.ends_with("::CStr")
    ) {
        return true;
    }
    let TypeInfo::StructType {
        name,
        size,
        members,
    } = strip_type_aliases(target)
    else {
        return false;
    };
    if *size != 0
        || !(name == "CStr" || name.ends_with("::CStr"))
        || members.len() != 1
        || members[0].name != "inner"
        || members[0].offset != 0
    {
        return false;
    }

    is_c_char_storage(&members[0].member_type)
}

fn is_c_char_storage(storage: &TypeInfo) -> bool {
    let storage = strip_type_aliases(storage);
    let byte = match storage {
        TypeInfo::BaseType { .. } => storage,
        TypeInfo::ArrayType { element_type, .. } => strip_type_aliases(element_type),
        _ => return false,
    };
    matches!(
        byte,
        TypeInfo::BaseType { size: 1, encoding, .. }
            if matches!(
                *encoding,
                value
                    if value == gimli::DW_ATE_signed.0 as u16
                        || value == gimli::DW_ATE_signed_char.0 as u16
                        || value == gimli::DW_ATE_unsigned.0 as u16
                        || value == gimli::DW_ATE_unsigned_char.0 as u16
            )
    )
}

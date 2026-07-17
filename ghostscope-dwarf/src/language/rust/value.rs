use crate::{strip_type_aliases, ResolvedType, SourceLanguage, TypeInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueLayout {
    IndirectSequence(IndirectSequenceLayout),
    ProjectedValue { value_path: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndirectSequenceLayout {
    pub(crate) data_path: Vec<String>,
    pub(crate) addressing: IndirectSequenceAddressing,
    pub(crate) kind: IndirectSequenceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IndirectSequenceAddressing {
    Contiguous {
        length_path: Vec<String>,
    },
    Ring {
        start_path: Vec<String>,
        length_path: Vec<String>,
        length_kind: RingSequenceLengthKind,
        capacity_path: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RingSequenceLengthKind {
    Explicit,
    End,
}

impl IndirectSequenceLayout {
    fn contiguous(
        data_path: Vec<String>,
        length_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> Self {
        Self {
            data_path,
            addressing: IndirectSequenceAddressing::Contiguous { length_path },
            kind,
        }
    }

    fn ring(
        data_path: Vec<String>,
        start_path: Vec<String>,
        length_path: Vec<String>,
        length_kind: RingSequenceLengthKind,
        capacity_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> Self {
        Self {
            data_path,
            addressing: IndirectSequenceAddressing::Ring {
                start_path,
                length_path,
                length_kind,
                capacity_path,
            },
            kind,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndirectSequenceKind {
    Utf8String,
    ByteString,
    PointerTarget,
    TypeParameter { index: usize },
}

pub(super) fn requires_dwarf_qualified_name(current: &ResolvedType) -> bool {
    current.origin.as_ref().is_some_and(|origin| {
        origin.language == SourceLanguage::Rust
            && matches!(strip_type_aliases(&current.summary), TypeInfo::StructType { name, .. }
                if name == "String"
                    || name == "OsString"
                    || is_short_vec_name(name)
                    || is_short_vec_deque_name(name)
                    || is_short_box_str_name(name)
                    || is_short_nonzero_name(name))
    })
}

pub(super) fn resolve_value_layout(
    current: &ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> Option<ValueLayout> {
    if current.origin.as_ref()?.language != SourceLanguage::Rust {
        return None;
    }

    let TypeInfo::StructType { name, .. } = strip_type_aliases(&current.summary) else {
        return None;
    };

    if is_std_nonzero(name, dwarf_qualified_name) {
        return rust_nonzero_value_path(&current.summary)
            .map(|value_path| ValueLayout::ProjectedValue { value_path });
    }

    // rustc's bundled GDB printers have treated slice-like DWARF values as
    // `data_ptr` plus `length` since Rust 1.0, without field-name compatibility
    // branches. Older printers also removed explicit `'static` lifetimes before
    // classifying references. These are rustc debuginfo conventions, not Rust
    // ABI guarantees, so retain the language and structural checks around them.
    // See rust-lang/rust's `src/etc/gdb_rust_pretty_printing.py` and
    // `src/etc/gdb_providers.py`.
    let sequence = if matches!(
        name.as_str(),
        "&str" | "&mut str" | "&'static str" | "&'static mut str"
    ) {
        validate_indirect_sequence_layout(
            &current.summary,
            field_path(&["data_ptr"]),
            field_path(&["length"]),
            IndirectSequenceKind::Utf8String,
        )
    } else if is_slice_name(name) {
        validate_indirect_sequence_layout(
            &current.summary,
            field_path(&["data_ptr"]),
            field_path(&["length"]),
            IndirectSequenceKind::PointerTarget,
        )
    } else if is_std_box_str(name, dwarf_qualified_name) {
        // Rust 1.96 and older rust-gdb scripts had no Box<str> provider. The
        // current provider has no version fallback and reads data_ptr/length.
        // Accept the pre-allocator generic spelling when DWARF emits it, but
        // derive every physical detail from the concrete DIE.
        validate_indirect_sequence_layout(
            &current.summary,
            field_path(&["data_ptr"]),
            field_path(&["length"]),
            IndirectSequenceKind::Utf8String,
        )
    // rustc commonly stores only `String` in DW_AT_name and represents
    // `alloc::string` with enclosing namespace DIEs. GDB presents the
    // reconstructed qualified name to its Rust printer. Trust the equivalent
    // TypeId-backed name from the analyzer for identity; the member checks
    // below remain responsible only for version-specific physical layout.
    } else if is_std_string(name, dwarf_qualified_name) {
        rust_string_layout(&current.summary)
    } else if is_std_os_string(name, dwarf_qualified_name) {
        rust_os_string_layout(&current.summary)
    } else if is_std_vec(name, dwarf_qualified_name) {
        rust_vec_layout(&current.summary)
    } else if is_std_vec_deque(name, dwarf_qualified_name) {
        rust_vec_deque_layout(&current.summary)
    } else {
        None
    };

    sequence.map(ValueLayout::IndirectSequence)
}

fn is_slice_name(name: &str) -> bool {
    // Rust 1.30's GDB support stripped an explicit `'static` lifetime before
    // applying the same &[T]/&mut [T] classification used by current rust-gdb.
    let Some(referenced) = name
        .strip_prefix("&'static ")
        .or_else(|| name.strip_prefix('&'))
    else {
        return false;
    };
    let referenced = referenced.strip_prefix("mut ").unwrap_or(referenced);
    let Some(element) = referenced
        .strip_prefix('[')
        .and_then(|name| name.strip_suffix(']'))
    else {
        return false;
    };

    !element.is_empty()
}

fn is_short_vec_name(name: &str) -> bool {
    name.starts_with("Vec<") && name.ends_with('>')
}

fn is_short_vec_deque_name(name: &str) -> bool {
    name.starts_with("VecDeque<") && name.ends_with('>')
}

fn is_short_box_str_name(name: &str) -> bool {
    box_str_arguments(name, "Box<").is_some()
}

fn is_short_nonzero_name(name: &str) -> bool {
    is_generic_nonzero_name(name) || is_legacy_nonzero_name(name)
}

fn is_generic_nonzero_name(name: &str) -> bool {
    name.strip_prefix("NonZero<")
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_legacy_nonzero_name(name: &str) -> bool {
    matches!(
        name,
        "NonZeroI8"
            | "NonZeroI16"
            | "NonZeroI32"
            | "NonZeroI64"
            | "NonZeroI128"
            | "NonZeroIsize"
            | "NonZeroU8"
            | "NonZeroU16"
            | "NonZeroU32"
            | "NonZeroU64"
            | "NonZeroU128"
            | "NonZeroUsize"
    )
}

fn is_std_nonzero(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_nonzero_name(name)
        || (is_short_nonzero_name(name) && dwarf_qualified_name.is_some_and(is_std_nonzero_name))
}

fn is_std_nonzero_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("core::") else {
        return false;
    };
    let Some((module, type_name)) = path.rsplit_once("::") else {
        return false;
    };

    let valid_module = !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        });
    valid_module
        && (is_generic_nonzero_name(type_name)
            || ((module == "num" || module.starts_with("num::"))
                && is_legacy_nonzero_name(type_name)))
}

fn is_std_box_str(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_box_str_name(name)
        || (is_short_box_str_name(name) && dwarf_qualified_name.is_some_and(is_std_box_str_name))
}

fn is_std_box_str_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some((module, _)) = path
        .split_once("::Box<")
        .filter(|(_, arguments)| box_str_arguments(arguments, "").is_some())
    else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

fn box_str_arguments<'a>(name: &'a str, prefix: &str) -> Option<&'a str> {
    let arguments = name.strip_prefix(prefix)?.strip_suffix('>')?;
    (arguments == "str"
        || arguments
            .strip_prefix("str,")
            .is_some_and(|allocator| !allocator.is_empty()))
    .then_some(arguments)
}

fn is_std_string(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_string_name(name)
        || (name == "String" && dwarf_qualified_name.is_some_and(is_std_string_name))
}

fn is_std_string_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some(module) = path.strip_suffix("::String") else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

fn is_std_os_string(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_os_string_name(name)
        || (name == "OsString" && dwarf_qualified_name.is_some_and(is_std_os_string_name))
}

fn is_std_os_string_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("std::ffi::") else {
        return false;
    };
    let Some(module) = path.strip_suffix("::OsString") else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

fn is_std_vec(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_vec_name(name)
        || (is_short_vec_name(name) && dwarf_qualified_name.is_some_and(is_std_vec_name))
}

fn is_std_vec_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some((module, arguments)) = path.split_once("::Vec<") else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        && !arguments.is_empty()
        && arguments.ends_with('>')
}

fn is_std_vec_deque(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_vec_deque_name(name)
        || (is_short_vec_deque_name(name)
            && dwarf_qualified_name.is_some_and(is_std_vec_deque_name))
}

fn is_std_vec_deque_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let Some((module, arguments)) = path.split_once("::VecDeque<") else {
        return false;
    };

    !module.is_empty()
        && module.split("::").all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
        && !arguments.is_empty()
        && arguments.ends_with('>')
}

fn rust_nonzero_value_path(root: &TypeInfo) -> Option<Vec<String>> {
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

fn rust_string_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
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

fn rust_vec_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
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

fn rust_vec_deque_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
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

fn rust_os_string_layout(root: &TypeInfo) -> Option<IndirectSequenceLayout> {
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
            field_path(data_fields),
            field_path(length_fields),
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

fn wrapped_pointer_path(root: &TypeInfo, mut data_path: Vec<String>) -> Option<Vec<String>> {
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

fn unsigned_metadata_path(
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

fn field_path(fields: &[&str]) -> Vec<String> {
    fields.iter().map(|field| (*field).to_string()).collect()
}

struct ResolvedMemberPath<'a> {
    offset: u64,
    member_type: &'a TypeInfo,
}

fn resolve_member_path<'a>(root: &'a TypeInfo, path: &[String]) -> Option<ResolvedMemberPath<'a>> {
    let mut current = root;
    let mut offset = 0u64;

    for field in path {
        let TypeInfo::StructType { size, members, .. } = strip_type_aliases(current) else {
            return None;
        };
        let member = members.iter().find(|member| member.name == *field)?;
        let member_size = member.member_type.size();
        let member_end = member.offset.checked_add(member_size)?;
        if member_size == 0
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

fn validate_indirect_sequence_layout(
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

    let utf8_byte_pointer = match strip_type_aliases(target_type) {
        TypeInfo::BaseType { size, encoding, .. } => {
            *size == 1
                && (*encoding == gimli::DW_ATE_unsigned.0 as u16
                    || *encoding == gimli::DW_ATE_unsigned_char.0 as u16)
        }
        _ => false,
    };
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
        ) && !utf8_byte_pointer)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CuId, ModuleId, StructMember, TypeIdentity, TypeOrigin};

    struct RustStrLayout<'a> {
        name: &'a str,
        aggregate_size: u64,
        data_offset: u64,
        pointer_size: u64,
        length_offset: u64,
        length_size: u64,
        language: SourceLanguage,
    }

    fn rust_str_type(layout: RustStrLayout<'_>) -> ResolvedType {
        let byte = TypeInfo::BaseType {
            name: "u8".to_string(),
            size: 1,
            encoding: gimli::DW_ATE_unsigned.0 as u16,
        };
        ResolvedType::new(
            TypeInfo::StructType {
                name: layout.name.to_string(),
                size: layout.aggregate_size,
                members: vec![
                    StructMember {
                        name: "data_ptr".to_string(),
                        member_type: TypeInfo::PointerType {
                            target_type: Box::new(byte),
                            size: layout.pointer_size,
                        },
                        offset: layout.data_offset,
                        bit_offset: None,
                        bit_size: None,
                    },
                    StructMember {
                        name: "length".to_string(),
                        member_type: TypeInfo::BaseType {
                            name: "usize".to_string(),
                            size: layout.length_size,
                            encoding: gimli::DW_ATE_unsigned.0 as u16,
                        },
                        offset: layout.length_offset,
                        bit_offset: None,
                        bit_size: None,
                    },
                ],
            },
            TypeIdentity::Unknown,
            Some(TypeOrigin {
                module: ModuleId(0),
                cu: CuId(0),
                language: layout.language,
                producer: None,
                dwarf_version: 5,
            }),
        )
    }

    fn rust_str_type_64(name: &str, language: SourceLanguage) -> ResolvedType {
        rust_str_type(RustStrLayout {
            name,
            aggregate_size: 16,
            data_offset: 0,
            pointer_size: 8,
            length_offset: 8,
            length_size: 8,
            language,
        })
    }

    fn rust_slice_type_64(name: &str, language: SourceLanguage) -> ResolvedType {
        let mut current = rust_str_type_64(name, language);
        let TypeInfo::StructType { members, .. } = &mut current.summary else {
            unreachable!("test slice is a struct")
        };
        let TypeInfo::PointerType { target_type, .. } = &mut members[0].member_type else {
            unreachable!("test slice data_ptr is a pointer")
        };
        *target_type = Box::new(TypeInfo::BaseType {
            name: "i32".to_string(),
            size: 4,
            encoding: gimli::DW_ATE_signed.0 as u16,
        });
        current
    }

    fn member(name: &str, member_type: TypeInfo, offset: u64) -> StructMember {
        StructMember {
            name: name.to_string(),
            member_type,
            offset,
            bit_offset: None,
            bit_size: None,
        }
    }

    fn single_member_struct(name: &str, field: &str, inner: TypeInfo) -> TypeInfo {
        TypeInfo::StructType {
            name: name.to_string(),
            size: inner.size(),
            members: vec![member(field, inner, 0)],
        }
    }

    fn unsigned_type(name: &str, size: u64) -> TypeInfo {
        TypeInfo::BaseType {
            name: name.to_string(),
            size,
            encoding: gimli::DW_ATE_unsigned.0 as u16,
        }
    }

    fn indirect_contiguous(
        data_path: Vec<String>,
        length_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> ValueLayout {
        ValueLayout::IndirectSequence(IndirectSequenceLayout::contiguous(
            data_path,
            length_path,
            kind,
        ))
    }

    fn indirect_ring(
        data_path: Vec<String>,
        start_path: Vec<String>,
        length_path: Vec<String>,
        length_kind: RingSequenceLengthKind,
        capacity_path: Vec<String>,
        kind: IndirectSequenceKind,
    ) -> ValueLayout {
        ValueLayout::IndirectSequence(IndirectSequenceLayout::ring(
            data_path,
            start_path,
            length_path,
            length_kind,
            capacity_path,
            kind,
        ))
    }

    fn rust_nonzero_type(
        name: &str,
        outer_field: &str,
        inner_field: &str,
        value_type: TypeInfo,
        language: SourceLanguage,
    ) -> ResolvedType {
        let inner = single_member_struct("NonZeroInner", inner_field, value_type);
        ResolvedType::new(
            single_member_struct(name, outer_field, inner),
            TypeIdentity::Unknown,
            Some(TypeOrigin {
                module: ModuleId(0),
                cu: CuId(0),
                language,
                producer: None,
                dwarf_version: 5,
            }),
        )
    }

    fn rust_legacy_nonzero_type(
        name: &str,
        field: &str,
        value_type: TypeInfo,
        language: SourceLanguage,
    ) -> ResolvedType {
        ResolvedType::new(
            single_member_struct(name, field, value_type),
            TypeIdentity::Unknown,
            Some(TypeOrigin {
                module: ModuleId(0),
                cu: CuId(0),
                language,
                producer: None,
                dwarf_version: 4,
            }),
        )
    }

    fn rust_string_type(
        name: &str,
        language: SourceLanguage,
        pointer_size: u64,
        wraps_raw_pointer: bool,
        uses_raw_vec_inner: bool,
    ) -> ResolvedType {
        let raw_pointer = TypeInfo::PointerType {
            target_type: Box::new(unsigned_type("u8", 1)),
            size: pointer_size,
        };
        let unique_pointer = if wraps_raw_pointer {
            TypeInfo::StructType {
                name: "core::ptr::non_null::NonNull<u8>".to_string(),
                size: pointer_size,
                members: vec![member("pointer", raw_pointer, 0)],
            }
        } else {
            raw_pointer
        };
        let unique = TypeInfo::StructType {
            name: "core::ptr::unique::Unique<u8>".to_string(),
            size: pointer_size,
            members: vec![member("pointer", unique_pointer, 0)],
        };
        let raw_vec = if uses_raw_vec_inner {
            let raw_vec_inner = TypeInfo::StructType {
                name: "alloc::raw_vec::RawVecInner".to_string(),
                size: pointer_size * 2,
                members: vec![member("ptr", unique, pointer_size)],
            };
            TypeInfo::StructType {
                name: "alloc::raw_vec::RawVec<u8>".to_string(),
                size: pointer_size * 2,
                members: vec![member("inner", raw_vec_inner, 0)],
            }
        } else {
            TypeInfo::StructType {
                name: "alloc::raw_vec::RawVec<u8>".to_string(),
                size: pointer_size * 2,
                members: vec![member("ptr", unique, 0)],
            }
        };
        let vec_type = TypeInfo::StructType {
            name: "Vec<u8, alloc::alloc::Global>".to_string(),
            size: pointer_size * 3,
            members: vec![
                member("buf", raw_vec, 0),
                member(
                    "len",
                    unsigned_type("usize", pointer_size),
                    pointer_size * 2,
                ),
            ],
        };

        ResolvedType::new(
            TypeInfo::StructType {
                name: name.to_string(),
                size: pointer_size * 3,
                members: vec![member("vec", vec_type, 0)],
            },
            TypeIdentity::Unknown,
            Some(TypeOrigin {
                module: ModuleId(0),
                cu: CuId(0),
                language,
                producer: None,
                dwarf_version: 5,
            }),
        )
    }

    fn rust_vec_type(
        name: &str,
        language: SourceLanguage,
        pointer_size: u64,
        wraps_raw_pointer: bool,
        uses_raw_vec_inner: bool,
    ) -> ResolvedType {
        let string = rust_string_type(
            "alloc::string::String",
            language,
            pointer_size,
            wraps_raw_pointer,
            uses_raw_vec_inner,
        );
        let TypeInfo::StructType { members, .. } = string.summary else {
            unreachable!("test String is a struct")
        };
        let mut vec_type = members
            .into_iter()
            .next()
            .expect("test String has a Vec member")
            .member_type;
        let TypeInfo::StructType { name: vec_name, .. } = &mut vec_type else {
            unreachable!("test Vec is a struct")
        };
        *vec_name = name.to_string();

        ResolvedType::new(vec_type, TypeIdentity::Unknown, string.origin)
    }

    fn rust_os_string_type(
        name: &str,
        pointer_size: u64,
        uses_raw_vec_inner: bool,
        windows_vec_field: Option<&str>,
    ) -> ResolvedType {
        let vec = rust_vec_type(
            "alloc::vec::Vec<u8, alloc::alloc::Global>",
            SourceLanguage::Rust,
            pointer_size,
            true,
            uses_raw_vec_inner,
        );
        let origin = vec.origin;
        let platform_buffer = match windows_vec_field {
            Some(field) => single_member_struct("Wtf8Buf", field, vec.summary),
            None => vec.summary,
        };
        let buffer = single_member_struct("Buf", "inner", platform_buffer);
        let os_string = single_member_struct(name, "inner", buffer);

        ResolvedType::new(os_string, TypeIdentity::Unknown, origin)
    }

    struct VecDequeTestLayout<'a> {
        name: &'a str,
        pointer_size: u64,
        uses_raw_vec_inner: bool,
        wraps_capacity: bool,
        wraps_head: bool,
        uses_legacy_tail: bool,
    }

    fn rust_vec_deque_type(layout: VecDequeTestLayout<'_>) -> ResolvedType {
        let pointer_size = layout.pointer_size;
        let raw_pointer = TypeInfo::PointerType {
            target_type: Box::new(unsigned_type("u8", 1)),
            size: pointer_size,
        };
        let non_null = single_member_struct("NonNull<u8>", "pointer", raw_pointer);
        let unique = single_member_struct("Unique<u8>", "pointer", non_null);
        let capacity = if layout.wraps_capacity {
            single_member_struct(
                "alloc::raw_vec::Cap",
                "__0",
                unsigned_type("usize", pointer_size),
            )
        } else {
            unsigned_type("usize", pointer_size)
        };
        let raw_vec_storage = TypeInfo::StructType {
            name: "alloc::raw_vec::RawVecInner".to_string(),
            size: pointer_size * 2,
            members: vec![
                member("cap", capacity, 0),
                member("ptr", unique, pointer_size),
            ],
        };
        let raw_vec = if layout.uses_raw_vec_inner {
            single_member_struct("alloc::raw_vec::RawVec<i32>", "inner", raw_vec_storage)
        } else {
            raw_vec_storage
        };
        let head = if layout.wraps_head {
            single_member_struct(
                "alloc::collections::vec_deque::WrappedIndex",
                "__0",
                unsigned_type("usize", pointer_size),
            )
        } else {
            unsigned_type("usize", pointer_size)
        };
        let mut members = if layout.uses_legacy_tail {
            vec![
                member("tail", unsigned_type("usize", pointer_size), 0),
                member("head", head, pointer_size),
            ]
        } else {
            vec![
                member("head", head, 0),
                member("len", unsigned_type("usize", pointer_size), pointer_size),
            ]
        };
        members.push(member("buf", raw_vec, pointer_size * 2));

        ResolvedType::new(
            TypeInfo::StructType {
                name: layout.name.to_string(),
                size: pointer_size * 4,
                members,
            },
            TypeIdentity::Unknown,
            Some(TypeOrigin {
                module: ModuleId(0),
                cu: CuId(0),
                language: SourceLanguage::Rust,
                producer: None,
                dwarf_version: 5,
            }),
        )
    }

    #[test]
    fn recognizes_rust_str_layout() {
        let current = rust_str_type_64("&str", SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["data_ptr"]),
                field_path(&["length"]),
                IndirectSequenceKind::Utf8String,
            ))
        );
    }

    #[test]
    fn recognizes_supported_rust_str_names() {
        for name in ["&mut str", "&'static str", "&'static mut str"] {
            let current = rust_str_type_64(name, SourceLanguage::Rust);

            assert!(
                resolve_value_layout(&current, None).is_some(),
                "name={name}"
            );
        }
    }

    #[test]
    fn recognizes_rust_slice_layout_and_supported_names() {
        for name in [
            "&[i32]",
            "&mut [i32]",
            "&'static [i32]",
            "&'static mut [i32]",
        ] {
            let current = rust_slice_type_64(name, SourceLanguage::Rust);

            assert_eq!(
                resolve_value_layout(&current, None),
                Some(indirect_contiguous(
                    field_path(&["data_ptr"]),
                    field_path(&["length"]),
                    IndirectSequenceKind::PointerTarget,
                )),
                "name={name}"
            );
        }
    }

    #[test]
    fn does_not_classify_non_slice_reference_name() {
        let current = rust_slice_type_64("&[i32", SourceLanguage::Rust);

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn recognizes_std_box_str_with_current_and_legacy_type_names() {
        for name in [
            "alloc::boxed::Box<str, alloc::alloc::Global>",
            "alloc::boxed::Box<str>",
        ] {
            let current = rust_str_type_64(name, SourceLanguage::Rust);

            assert_eq!(
                resolve_value_layout(&current, None),
                Some(indirect_contiguous(
                    field_path(&["data_ptr"]),
                    field_path(&["length"]),
                    IndirectSequenceKind::Utf8String,
                )),
                "name={name}"
            );
        }

        let current = rust_str_type_64("Box<str, alloc::alloc::Global>", SourceLanguage::Rust);
        assert!(resolve_value_layout(
            &current,
            Some("alloc::boxed::Box<str, alloc::alloc::Global>"),
        )
        .is_some());
    }

    #[test]
    fn does_not_classify_box_str_from_another_namespace() {
        let current = rust_str_type_64("Box<str, alloc::alloc::Global>", SourceLanguage::Rust);

        assert_eq!(
            resolve_value_layout(&current, Some("app::Box<str, alloc::alloc::Global>"),),
            None
        );
        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn recognizes_unix_and_windows_os_string_layouts_across_versions() {
        type LayoutCase<'a> = (bool, Option<&'a str>, &'a [&'a str], &'a [&'a str]);

        let cases: &[LayoutCase<'_>] = &[
            (
                true,
                None,
                &[
                    "inner", "inner", "buf", "inner", "ptr", "pointer", "pointer",
                ],
                &["inner", "inner", "len"],
            ),
            (
                false,
                None,
                &["inner", "inner", "buf", "ptr", "pointer", "pointer"],
                &["inner", "inner", "len"],
            ),
            (
                true,
                Some("bytes"),
                &[
                    "inner", "inner", "bytes", "buf", "inner", "ptr", "pointer", "pointer",
                ],
                &["inner", "inner", "bytes", "len"],
            ),
            (
                false,
                Some("__0"),
                &["inner", "inner", "__0", "buf", "ptr", "pointer", "pointer"],
                &["inner", "inner", "__0", "len"],
            ),
        ];

        for (uses_raw_vec_inner, windows_field, data_fields, length_fields) in cases {
            let current = rust_os_string_type(
                "std::ffi::os_str::OsString",
                8,
                *uses_raw_vec_inner,
                *windows_field,
            );

            assert_eq!(
                resolve_value_layout(&current, None),
                Some(indirect_contiguous(
                    field_path(data_fields),
                    field_path(length_fields),
                    IndirectSequenceKind::ByteString,
                )),
                "raw_vec_inner={uses_raw_vec_inner} windows_field={windows_field:?}"
            );
        }
    }

    #[test]
    fn requires_standard_namespace_for_short_os_string_name() {
        let current = rust_os_string_type("OsString", 8, true, None);

        assert!(resolve_value_layout(&current, Some("std::ffi::os_str::OsString"),).is_some());
        assert_eq!(resolve_value_layout(&current, Some("app::OsString")), None);
        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn recognizes_32_bit_layout_from_dwarf() {
        let current = rust_str_type(RustStrLayout {
            name: "&str",
            aggregate_size: 8,
            data_offset: 0,
            pointer_size: 4,
            length_offset: 4,
            length_size: 4,
            language: SourceLanguage::Rust,
        });

        assert!(resolve_value_layout(&current, None).is_some());
    }

    #[test]
    fn rejects_mismatched_metadata_widths() {
        let current = rust_str_type(RustStrLayout {
            name: "&str",
            aggregate_size: 16,
            data_offset: 0,
            pointer_size: 8,
            length_offset: 8,
            length_size: 4,
            language: SourceLanguage::Rust,
        });

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn rejects_members_outside_aggregate() {
        let current = rust_str_type(RustStrLayout {
            name: "&str",
            aggregate_size: 8,
            data_offset: 0,
            pointer_size: 4,
            length_offset: 6,
            length_size: 4,
            language: SourceLanguage::Rust,
        });

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn rejects_overlapping_members() {
        let current = rust_str_type(RustStrLayout {
            name: "&str",
            aggregate_size: 8,
            data_offset: 0,
            pointer_size: 4,
            length_offset: 2,
            length_size: 4,
            language: SourceLanguage::Rust,
        });

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn does_not_apply_rust_adapter_to_other_languages() {
        assert_eq!(
            resolve_value_layout(&rust_str_type_64("&str", SourceLanguage::C), None,),
            None
        );
    }

    #[test]
    fn recognizes_current_std_string_layout() {
        let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);
        let layout =
            resolve_value_layout(&current, Some("alloc::string::String")).expect("String layout");

        assert_eq!(
            layout,
            indirect_contiguous(
                field_path(&["vec", "buf", "inner", "ptr", "pointer", "pointer"]),
                field_path(&["vec", "len"]),
                IndirectSequenceKind::Utf8String,
            )
        );
        let ValueLayout::IndirectSequence(layout) = layout else {
            panic!("String must use indirect sequence layout")
        };
        assert_eq!(
            resolve_member_path(&current.summary, &layout.data_path)
                .expect("data member")
                .offset,
            8
        );
        let IndirectSequenceAddressing::Contiguous { length_path } = &layout.addressing else {
            panic!("String must use contiguous addressing")
        };
        assert_eq!(
            resolve_member_path(&current.summary, length_path)
                .expect("length member")
                .offset,
            16
        );
    }

    #[test]
    fn recognizes_legacy_std_string_pointer_layout() {
        let current = rust_string_type(
            "alloc::string::String",
            SourceLanguage::Rust,
            8,
            false,
            true,
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["vec", "buf", "inner", "ptr", "pointer"]),
                field_path(&["vec", "len"]),
                IndirectSequenceKind::Utf8String,
            ))
        );
    }

    #[test]
    fn recognizes_pre_raw_vec_inner_string_layout() {
        let current = rust_string_type(
            "alloc::string::String",
            SourceLanguage::Rust,
            8,
            true,
            false,
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["vec", "buf", "ptr", "pointer", "pointer"]),
                field_path(&["vec", "len"]),
                IndirectSequenceKind::Utf8String,
            ))
        );
    }

    #[test]
    fn recognizes_32_bit_std_string_layout_from_dwarf() {
        let current =
            rust_string_type("alloc::string::String", SourceLanguage::Rust, 4, true, true);

        assert!(resolve_value_layout(&current, None).is_some());
    }

    #[test]
    fn does_not_classify_unrelated_string_type() {
        let current = rust_string_type("app::String", SourceLanguage::Rust, 8, true, true);

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn does_not_classify_short_string_from_another_namespace() {
        let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);

        assert_eq!(resolve_value_layout(&current, Some("app::String")), None);
    }

    #[test]
    fn does_not_classify_short_string_without_qualified_identity() {
        let current = rust_string_type("String", SourceLanguage::Rust, 8, true, true);

        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn recognizes_current_std_vec_layout() {
        let current = rust_vec_type(
            "Vec<i32, alloc::alloc::Global>",
            SourceLanguage::Rust,
            8,
            true,
            true,
        );

        assert_eq!(
            resolve_value_layout(&current, Some("alloc::vec::Vec<i32, alloc::alloc::Global>")),
            Some(indirect_contiguous(
                field_path(&["buf", "inner", "ptr", "pointer", "pointer"]),
                field_path(&["len"]),
                IndirectSequenceKind::TypeParameter { index: 0 },
            ))
        );
    }

    #[test]
    fn recognizes_pre_raw_vec_inner_vec_layout() {
        let current = rust_vec_type(
            "alloc::vec::Vec<i32, alloc::alloc::Global>",
            SourceLanguage::Rust,
            8,
            true,
            false,
        );

        assert_eq!(
            resolve_value_layout(&current, None),
            Some(indirect_contiguous(
                field_path(&["buf", "ptr", "pointer", "pointer"]),
                field_path(&["len"]),
                IndirectSequenceKind::TypeParameter { index: 0 },
            ))
        );
    }

    #[test]
    fn recognizes_vec_deque_layouts_across_rust_versions() {
        let current = rust_vec_deque_type(VecDequeTestLayout {
            name: "VecDeque<i32, alloc::alloc::Global>",
            pointer_size: 8,
            uses_raw_vec_inner: true,
            wraps_capacity: true,
            wraps_head: true,
            uses_legacy_tail: false,
        });
        assert_eq!(
            resolve_value_layout(
                &current,
                Some("alloc::collections::vec_deque::VecDeque<i32, alloc::alloc::Global>"),
            ),
            Some(indirect_ring(
                field_path(&["buf", "inner", "ptr", "pointer", "pointer"]),
                field_path(&["head", "__0"]),
                field_path(&["len"]),
                RingSequenceLengthKind::Explicit,
                field_path(&["buf", "inner", "cap", "__0"]),
                IndirectSequenceKind::TypeParameter { index: 0 },
            ))
        );

        let pre_raw_vec_inner = rust_vec_deque_type(VecDequeTestLayout {
            name: "alloc::collections::vec_deque::VecDeque<i32>",
            pointer_size: 4,
            uses_raw_vec_inner: false,
            wraps_capacity: false,
            wraps_head: false,
            uses_legacy_tail: false,
        });
        assert_eq!(
            resolve_value_layout(&pre_raw_vec_inner, None),
            Some(indirect_ring(
                field_path(&["buf", "ptr", "pointer", "pointer"]),
                field_path(&["head"]),
                field_path(&["len"]),
                RingSequenceLengthKind::Explicit,
                field_path(&["buf", "cap"]),
                IndirectSequenceKind::TypeParameter { index: 0 },
            ))
        );

        let legacy = rust_vec_deque_type(VecDequeTestLayout {
            name: "alloc::collections::vec_deque::VecDeque<i32>",
            pointer_size: 8,
            uses_raw_vec_inner: false,
            wraps_capacity: false,
            wraps_head: false,
            uses_legacy_tail: true,
        });
        assert_eq!(
            resolve_value_layout(&legacy, None),
            Some(indirect_ring(
                field_path(&["buf", "ptr", "pointer", "pointer"]),
                field_path(&["tail"]),
                field_path(&["head"]),
                RingSequenceLengthKind::End,
                field_path(&["buf", "cap"]),
                IndirectSequenceKind::TypeParameter { index: 0 },
            ))
        );
    }

    #[test]
    fn requires_standard_namespace_for_short_vec_deque_name() {
        let current = rust_vec_deque_type(VecDequeTestLayout {
            name: "VecDeque<i32>",
            pointer_size: 8,
            uses_raw_vec_inner: true,
            wraps_capacity: true,
            wraps_head: false,
            uses_legacy_tail: false,
        });

        assert!(resolve_value_layout(
            &current,
            Some("alloc::collections::vec_deque::VecDeque<i32>"),
        )
        .is_some());
        assert_eq!(
            resolve_value_layout(&current, Some("app::VecDeque<i32>")),
            None
        );
        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn does_not_classify_user_vec_from_another_namespace() {
        let current = rust_vec_type("Vec<i32>", SourceLanguage::Rust, 8, true, true);

        assert_eq!(resolve_value_layout(&current, Some("app::Vec<i32>")), None);
        assert_eq!(resolve_value_layout(&current, None), None);
    }

    #[test]
    fn recognizes_nonzero_by_namespace_and_unique_member_structure() {
        let current = rust_nonzero_type(
            "NonZero<u32>",
            "outer_from_dwarf",
            "inner_from_dwarf",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );

        assert_eq!(
            resolve_value_layout(&current, Some("core::num::nonzero::NonZero<u32>"),),
            Some(ValueLayout::ProjectedValue {
                value_path: field_path(&["outer_from_dwarf", "inner_from_dwarf"]),
            })
        );

        let legacy = rust_legacy_nonzero_type(
            "NonZeroU32",
            "legacy_field_from_dwarf",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&legacy, Some("core::num::nonzero::NonZeroU32"),),
            Some(ValueLayout::ProjectedValue {
                value_path: field_path(&["legacy_field_from_dwarf"]),
            })
        );

        let fully_qualified_legacy = rust_legacy_nonzero_type(
            "core::num::NonZeroI64",
            "__0",
            TypeInfo::BaseType {
                name: "i64".to_string(),
                size: 8,
                encoding: gimli::DW_ATE_signed.0 as u16,
            },
            SourceLanguage::Rust,
        );
        assert!(resolve_value_layout(&fully_qualified_legacy, None).is_some());

        let fully_qualified = rust_nonzero_type(
            "core::num::nonzero::NonZero<i128>",
            "__0",
            "__0",
            TypeInfo::BaseType {
                name: "i128".to_string(),
                size: 16,
                encoding: gimli::DW_ATE_signed.0 as u16,
            },
            SourceLanguage::Rust,
        );
        assert!(resolve_value_layout(&fully_qualified, None).is_some());
    }

    #[test]
    fn rejects_nonzero_lookalikes_and_invalid_layouts() {
        let current = rust_nonzero_type(
            "NonZero<u32>",
            "__0",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&current, Some("app::NonZero<u32>")),
            None
        );
        assert_eq!(resolve_value_layout(&current, None), None);

        let legacy = rust_legacy_nonzero_type(
            "NonZeroU32",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );
        assert_eq!(resolve_value_layout(&legacy, Some("app::NonZeroU32")), None);
        assert_eq!(resolve_value_layout(&legacy, None), None);

        let mut invalid = current.clone();
        let TypeInfo::StructType { members, .. } = &mut invalid.summary else {
            unreachable!("test NonZero is a struct")
        };
        members.push(member("extra", unsigned_type("u32", 4), 0));
        assert_eq!(
            resolve_value_layout(&invalid, Some("core::num::nonzero::NonZero<u32>"),),
            None
        );

        let non_rust = rust_nonzero_type(
            "core::num::nonzero::NonZero<u32>",
            "__0",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::C,
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn qualified_name_lookup_is_limited_to_ambiguous_rust_std_types() {
        assert!(requires_dwarf_qualified_name(&rust_string_type(
            "String",
            SourceLanguage::Rust,
            8,
            true,
            true,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_string_type(
            "alloc::string::String",
            SourceLanguage::Rust,
            8,
            true,
            true,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_string_type(
            "String",
            SourceLanguage::C,
            8,
            true,
            true,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_str_type_64(
            "&str",
            SourceLanguage::Rust,
        )));
        assert!(requires_dwarf_qualified_name(&rust_vec_type(
            "Vec<i32, alloc::alloc::Global>",
            SourceLanguage::Rust,
            8,
            true,
            true,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_vec_type(
            "alloc::vec::Vec<i32, alloc::alloc::Global>",
            SourceLanguage::Rust,
            8,
            true,
            true,
        )));
        assert!(requires_dwarf_qualified_name(&rust_vec_deque_type(
            VecDequeTestLayout {
                name: "VecDeque<i32>",
                pointer_size: 8,
                uses_raw_vec_inner: true,
                wraps_capacity: true,
                wraps_head: false,
                uses_legacy_tail: false,
            },
        )));
        assert!(!requires_dwarf_qualified_name(&rust_vec_deque_type(
            VecDequeTestLayout {
                name: "alloc::collections::vec_deque::VecDeque<i32>",
                pointer_size: 8,
                uses_raw_vec_inner: true,
                wraps_capacity: true,
                wraps_head: false,
                uses_legacy_tail: false,
            },
        )));
        assert!(requires_dwarf_qualified_name(&rust_str_type_64(
            "Box<str, alloc::alloc::Global>",
            SourceLanguage::Rust,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_str_type_64(
            "alloc::boxed::Box<str, alloc::alloc::Global>",
            SourceLanguage::Rust,
        )));
        assert!(requires_dwarf_qualified_name(&rust_os_string_type(
            "OsString", 8, true, None,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_os_string_type(
            "std::ffi::os_str::OsString",
            8,
            true,
            None,
        )));
        assert!(requires_dwarf_qualified_name(&rust_nonzero_type(
            "NonZero<u32>",
            "__0",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_nonzero_type(
            "core::num::nonzero::NonZero<u32>",
            "__0",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
        assert!(requires_dwarf_qualified_name(&rust_legacy_nonzero_type(
            "NonZeroU32",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_legacy_nonzero_type(
            "core::num::NonZeroU32",
            "__0",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
    }
}

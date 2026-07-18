use crate::{
    strip_type_aliases, HashTableBucketOrder, HashTableOccupancy, ResolvedType, SourceLanguage,
    StructMember, TypeInfo,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ValueLayout {
    IndirectSequence(IndirectSequenceLayout),
    ProjectedValue {
        value_path: Vec<String>,
        presentation: ProjectedValuePresentation,
    },
    ProjectedStruct(ProjectedStructLayout),
    CompositeStruct(CompositeStructLayout),
    HashTable(HashTableLayout),
    BTree(BTreeLayout),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BTreeLayout {
    pub(crate) map_path: Vec<String>,
    pub(crate) root_path: Vec<String>,
    pub(crate) length_path: Vec<String>,
    pub(crate) kind: BTreeKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BTreeKind {
    Map,
    Set,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashTableLayout {
    pub(crate) entry_type_path: Vec<String>,
    pub(crate) control_path: Vec<String>,
    pub(crate) length_path: Vec<String>,
    pub(crate) bucket_mask_path: Vec<String>,
    pub(crate) occupancy: HashTableOccupancy,
    pub(crate) buckets: HashTableBucketLayout,
    pub(crate) bucket_order: HashTableBucketOrder,
    pub(crate) kind: HashTableKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HashTableBucketLayout {
    Forward { data_path: Vec<String> },
    ReverseFromControl,
    LegacyAfterControl { pointer_tag_mask: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HashTableKind {
    Map,
    Set,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedValuePresentation {
    Transparent,
    SingleField {
        type_name: &'static str,
        field_name: &'static str,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedStructLayout {
    pub(crate) type_name: &'static str,
    pub(crate) fields: Vec<ProjectedStructField>,
    pub(crate) presentation: ProjectedStructPresentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectedStructField {
    pub(crate) name: &'static str,
    pub(crate) value_path: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedStructPresentation {
    SignedState {
        state_field: &'static str,
        non_negative_label: &'static str,
        negative_label: &'static str,
    },
    ReferenceCounted {
        strong_field: &'static str,
        weak_field: &'static str,
        implicit_weak: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompositeStructLayout {
    pub(crate) type_name: &'static str,
    pub(crate) fields: Vec<CompositeStructField>,
    pub(crate) presentation: ProjectedStructPresentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompositeStructField {
    pub(crate) name: &'static str,
    pub(crate) value_path: Vec<ProjectedPathSegment>,
    pub(crate) capture: CompositeStructFieldCapture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CompositeStructFieldCapture {
    Value(ProjectedValueRequirement),
    Address,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProjectedPathSegment {
    Member(String),
    SoleMember,
    UnwrapScalar,
    Dereference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectedValueRequirement {
    KnownSizedOrZst,
    SignedPointerSizedInteger,
    UnsignedPointerSizedInteger,
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
                    || is_short_nonzero_name(name)
                    || is_short_cell_name(name)
                    || is_short_ref_cell_name(name)
                    || is_short_ref_name(name)
                    || is_short_ref_mut_name(name)
                    || is_short_rc_name(name)
                    || is_short_arc_name(name)
                    || is_short_hash_map_name(name)
                    || is_short_hash_set_name(name)
                    || is_short_btree_map_name(name)
                    || is_short_btree_set_name(name))
    })
}

pub(super) fn resolve_value_layout(
    current: &ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> Option<ValueLayout> {
    if current.origin.as_ref()?.language != SourceLanguage::Rust {
        return None;
    }

    // rust-gdb does not select printers from the target CU's rustc version.
    // Its wrapper adds the invoking toolchain's `lib/rustlib/etc` directory,
    // while the target only requests the generic loader through
    // `.debug_gdb_scripts`. GhostScope may use `origin.rustc_version()` to
    // prioritize candidates, but never as proof of a private layout: every
    // branch below must validate type identity, member paths, offsets, and
    // widths from the target's DWARF. Any semantic fact DWARF cannot express
    // must be documented at the special case that relies on it.

    let TypeInfo::StructType { name, .. } = strip_type_aliases(&current.summary) else {
        return None;
    };

    if is_std_btree_map(name, dwarf_qualified_name) {
        return rust_btree_layout(&current.summary, BTreeKind::Map).map(ValueLayout::BTree);
    }

    if is_std_btree_set(name, dwarf_qualified_name) {
        return rust_btree_layout(&current.summary, BTreeKind::Set).map(ValueLayout::BTree);
    }

    if is_std_hash_map(name, dwarf_qualified_name) {
        return rust_hash_table_layout(&current.summary, HashTableKind::Map)
            .map(ValueLayout::HashTable);
    }

    if is_std_hash_set(name, dwarf_qualified_name) {
        return rust_hash_table_layout(&current.summary, HashTableKind::Set)
            .map(ValueLayout::HashTable);
    }

    if is_std_rc(name, dwarf_qualified_name) {
        let pointee_is_str = has_first_generic_argument(name, "Rc", "str")
            || dwarf_qualified_name
                .is_some_and(|name| has_first_generic_argument(name, "Rc", "str"));
        return rust_reference_counted_layout(&current.summary, "Rc", "value", pointee_is_str)
            .map(ValueLayout::CompositeStruct);
    }

    if is_std_arc(name, dwarf_qualified_name) {
        let pointee_is_str = has_first_generic_argument(name, "Arc", "str")
            || dwarf_qualified_name
                .is_some_and(|name| has_first_generic_argument(name, "Arc", "str"));
        return rust_reference_counted_layout(&current.summary, "Arc", "data", pointee_is_str)
            .map(ValueLayout::CompositeStruct);
    }

    if is_std_ref(name, dwarf_qualified_name) || is_std_ref_mut(name, dwarf_qualified_name) {
        return rust_ref_layout(&current.summary).map(ValueLayout::CompositeStruct);
    }

    if is_std_ref_cell(name, dwarf_qualified_name) {
        return rust_ref_cell_layout(&current.summary).map(ValueLayout::ProjectedStruct);
    }

    if is_std_cell(name, dwarf_qualified_name) {
        return rust_cell_value_path(&current.summary).map(|value_path| {
            ValueLayout::ProjectedValue {
                value_path,
                presentation: ProjectedValuePresentation::SingleField {
                    type_name: "Cell",
                    field_name: "value",
                },
            }
        });
    }

    if is_std_nonzero(name, dwarf_qualified_name) {
        return rust_nonzero_value_path(&current.summary).map(|value_path| {
            ValueLayout::ProjectedValue {
                value_path,
                presentation: ProjectedValuePresentation::Transparent,
            }
        });
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

fn is_short_cell_name(name: &str) -> bool {
    name.strip_prefix("Cell<")
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_short_ref_cell_name(name: &str) -> bool {
    name.strip_prefix("RefCell<")
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_short_ref_name(name: &str) -> bool {
    name.strip_prefix("Ref<")
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_short_ref_mut_name(name: &str) -> bool {
    name.strip_prefix("RefMut<")
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn is_short_rc_name(name: &str) -> bool {
    is_short_generic_name(name, "Rc")
}

fn is_short_arc_name(name: &str) -> bool {
    is_short_generic_name(name, "Arc")
}

fn is_short_hash_map_name(name: &str) -> bool {
    is_short_generic_name(name, "HashMap")
}

fn is_short_hash_set_name(name: &str) -> bool {
    is_short_generic_name(name, "HashSet")
}

fn is_short_btree_map_name(name: &str) -> bool {
    is_short_generic_name(name, "BTreeMap")
}

fn is_short_btree_set_name(name: &str) -> bool {
    is_short_generic_name(name, "BTreeSet")
}

fn is_short_generic_name(name: &str, type_name: &str) -> bool {
    let prefix = format!("{type_name}<");
    name.strip_prefix(&prefix)
        .and_then(|arguments| arguments.strip_suffix('>'))
        .is_some_and(|arguments| !arguments.is_empty())
}

fn has_first_generic_argument(name: &str, type_name: &str, expected: &str) -> bool {
    let short_prefix = format!("{type_name}<");
    let qualified_marker = format!("::{type_name}<");
    let arguments = name.strip_prefix(&short_prefix).or_else(|| {
        name.split_once(&qualified_marker)
            .map(|(_, arguments)| arguments)
    });
    arguments
        .and_then(|arguments| arguments.strip_suffix('>'))
        .and_then(|arguments| arguments.split(',').next())
        .is_some_and(|argument| argument.trim() == expected)
}

fn is_std_cell(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_cell_name(name)
        || (is_short_cell_name(name) && dwarf_qualified_name.is_some_and(is_std_cell_name))
}

fn is_std_cell_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("core::") else {
        return false;
    };
    let Some((module, arguments)) = path.split_once("::Cell<") else {
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

fn is_std_ref_cell(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_ref_cell_name(name)
        || (is_short_ref_cell_name(name) && dwarf_qualified_name.is_some_and(is_std_ref_cell_name))
}

fn is_std_ref_cell_name(name: &str) -> bool {
    let Some(path) = name.strip_prefix("core::") else {
        return false;
    };
    let Some((module, arguments)) = path.split_once("::RefCell<") else {
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

fn is_std_ref(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_ref_name(name)
        || (is_short_ref_name(name) && dwarf_qualified_name.is_some_and(is_std_ref_name))
}

fn is_std_ref_name(name: &str) -> bool {
    is_std_core_generic_name(name, "Ref")
}

fn is_std_ref_mut(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_ref_mut_name(name)
        || (is_short_ref_mut_name(name) && dwarf_qualified_name.is_some_and(is_std_ref_mut_name))
}

fn is_std_ref_mut_name(name: &str) -> bool {
    is_std_core_generic_name(name, "RefMut")
}

fn is_std_rc(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_rc_name(name)
        || (is_short_rc_name(name) && dwarf_qualified_name.is_some_and(is_std_rc_name))
}

fn is_std_rc_name(name: &str) -> bool {
    is_std_alloc_generic_name(name, "Rc")
}

fn is_std_arc(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_arc_name(name)
        || (is_short_arc_name(name) && dwarf_qualified_name.is_some_and(is_std_arc_name))
}

fn is_std_arc_name(name: &str) -> bool {
    is_std_alloc_generic_name(name, "Arc")
}

fn is_std_hash_map(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_hash_map_name(name)
        || (is_short_hash_map_name(name) && dwarf_qualified_name.is_some_and(is_std_hash_map_name))
}

fn is_std_hash_map_name(name: &str) -> bool {
    is_std_collections_generic_name(name, "HashMap")
}

fn is_std_hash_set(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_hash_set_name(name)
        || (is_short_hash_set_name(name) && dwarf_qualified_name.is_some_and(is_std_hash_set_name))
}

fn is_std_hash_set_name(name: &str) -> bool {
    is_std_collections_generic_name(name, "HashSet")
}

fn is_std_btree_map(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_btree_map_name(name)
        || (is_short_btree_map_name(name)
            && dwarf_qualified_name.is_some_and(is_std_btree_map_name))
}

fn is_std_btree_map_name(name: &str) -> bool {
    is_std_alloc_generic_name(name, "BTreeMap")
}

fn is_std_btree_set(name: &str, dwarf_qualified_name: Option<&str>) -> bool {
    is_std_btree_set_name(name)
        || (is_short_btree_set_name(name)
            && dwarf_qualified_name.is_some_and(is_std_btree_set_name))
}

fn is_std_btree_set_name(name: &str) -> bool {
    is_std_alloc_generic_name(name, "BTreeSet")
}

fn is_std_collections_generic_name(name: &str, type_name: &str) -> bool {
    let Some(path) = name.strip_prefix("std::collections::") else {
        return false;
    };
    let marker = format!("::{type_name}<");
    let Some((module, arguments)) = path.split_once(&marker) else {
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

fn is_std_core_generic_name(name: &str, type_name: &str) -> bool {
    let Some(path) = name.strip_prefix("core::") else {
        return false;
    };
    let marker = format!("::{type_name}<");
    let Some((module, arguments)) = path.split_once(&marker) else {
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

fn is_std_alloc_generic_name(name: &str, type_name: &str) -> bool {
    let Some(path) = name.strip_prefix("alloc::") else {
        return false;
    };
    let marker = format!("::{type_name}<");
    let Some((module, arguments)) = path.split_once(&marker) else {
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

fn rust_cell_value_path(root: &TypeInfo) -> Option<Vec<String>> {
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

fn rust_ref_cell_layout(root: &TypeInfo) -> Option<ProjectedStructLayout> {
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

fn rust_ref_layout(root: &TypeInfo) -> Option<CompositeStructLayout> {
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

fn rust_reference_counted_layout(
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

fn rust_hash_table_layout(root: &TypeInfo, kind: HashTableKind) -> Option<HashTableLayout> {
    // Rust 1.36-1.51 expose RawTable's metadata directly; Rust 1.52 moved it
    // under RawTable.table. HashSet wrapped std::HashMap through Rust 1.47 and
    // now wraps hashbrown::HashSet. rust-gdb keeps all four path combinations.
    // hashbrown also removed its dedicated `data` pointer: current tables place
    // entries immediately before `ctrl`, in reverse control-index order. These
    // are semantic compatibility branches only. Every selected member offset,
    // pointer width, entry type, and entry field layout is resolved from DWARF.
    // rust-gdb also retains a separate provider for Rust 1.35's pre-hashbrown
    // table. That layout stores pointer-sized hash words followed by aligned
    // pair storage in one allocation; validate it only after all hashbrown
    // paths fail.
    const MAP_PATHS: &[(&[&str], &[&str])] = &[
        (&["base", "table"], &["base", "table", "table"]),
        (&["base", "table"], &["base", "table"]),
    ];
    const SET_PATHS: &[(&[&str], &[&str])] = &[
        (
            &["base", "map", "table"],
            &["base", "map", "table", "table"],
        ),
        (&["base", "map", "table"], &["base", "map", "table"]),
        (
            &["map", "base", "table"],
            &["map", "base", "table", "table"],
        ),
        (&["map", "base", "table"], &["map", "base", "table"]),
    ];

    let paths = match kind {
        HashTableKind::Map => MAP_PATHS,
        HashTableKind::Set => SET_PATHS,
    };
    for (table_fields, metadata_fields) in paths {
        if let Some(layout) = validate_hash_table_layout(
            root,
            field_path(table_fields),
            field_path(metadata_fields),
            kind,
        ) {
            return Some(layout);
        }
    }
    validate_legacy_hash_table_layout(root, kind)
}

fn rust_btree_layout(root: &TypeInfo, kind: BTreeKind) -> Option<BTreeLayout> {
    // rust-gdb reads `length` and `root` from BTreeMap, while BTreeSet
    // delegates to its `map` member. Rust 1.35 stored Root directly and newer
    // releases wrap Root/NodeRef in Option, so the analyzer resolves those
    // concrete DIEs instead of encoding either shape in this classifier.
    let map_path = match kind {
        BTreeKind::Map => Vec::new(),
        BTreeKind::Set => field_path(&["map"]),
    };
    let map = if map_path.is_empty() {
        root
    } else {
        resolve_member_path(root, &map_path)?.member_type
    };
    let TypeInfo::StructType {
        size: map_size,
        members,
        ..
    } = strip_type_aliases(map)
    else {
        return None;
    };
    let root_member = unique_named_member(members, "root")?;
    let length_member = unique_named_member(members, "length")?;
    member_range(root_member, *map_size)?;
    member_range(length_member, *map_size)?;
    if ranges_overlap(
        (
            root_member.offset,
            root_member
                .offset
                .checked_add(root_member.member_type.size())?,
        ),
        (
            length_member.offset,
            length_member
                .offset
                .checked_add(length_member.member_type.size())?,
        ),
    ) {
        return None;
    }
    let TypeInfo::StructType {
        size: root_size, ..
    } = strip_type_aliases(&root_member.member_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: length_size,
        encoding,
        ..
    } = strip_type_aliases(&length_member.member_type)
    else {
        return None;
    };
    if *root_size == 0
        || !matches!(*length_size, 4 | 8)
        || *encoding != gimli::DW_ATE_unsigned.0 as u16
    {
        return None;
    }

    let mut root_path = map_path.clone();
    root_path.push(root_member.name.clone());
    let mut length_path = map_path.clone();
    length_path.push(length_member.name.clone());
    Some(BTreeLayout {
        map_path,
        root_path,
        length_path,
        kind,
    })
}

fn validate_hash_table_layout(
    root: &TypeInfo,
    table_path: Vec<String>,
    metadata_path: Vec<String>,
    kind: HashTableKind,
) -> Option<HashTableLayout> {
    let table = resolve_member_path(root, &table_path)?;
    if !matches!(
        strip_type_aliases(table.member_type),
        TypeInfo::StructType { .. }
    ) {
        return None;
    }
    let metadata = resolve_member_path(root, &metadata_path)?;
    let TypeInfo::StructType {
        members: metadata_members,
        ..
    } = strip_type_aliases(metadata.member_type)
    else {
        return None;
    };

    let mut control_path = metadata_path.clone();
    control_path.push("ctrl".to_string());
    let control_path = wrapped_pointer_path(root, control_path)?;
    let control = resolve_member_path(root, &control_path)?;
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = strip_type_aliases(control.member_type)
    else {
        return None;
    };
    let byte_control = matches!(
        strip_type_aliases(target_type),
        TypeInfo::BaseType { size: 1, encoding, .. }
            if *encoding == gimli::DW_ATE_unsigned.0 as u16
                || *encoding == gimli::DW_ATE_unsigned_char.0 as u16
    );
    if *pointer_size == 0 || !byte_control {
        return None;
    }

    let mut length_path = metadata_path.clone();
    length_path.push("items".to_string());
    let length_path = unsigned_metadata_path(root, length_path, *pointer_size)?;
    let mut bucket_mask_path = metadata_path.clone();
    bucket_mask_path.push("bucket_mask".to_string());
    let bucket_mask_path = unsigned_metadata_path(root, bucket_mask_path, *pointer_size)?;

    let has_data = unique_named_member(metadata_members, "data").is_some();
    let (buckets, bucket_order) = if has_data {
        let mut data_path = metadata_path;
        data_path.push("data".to_string());
        let data_path = wrapped_pointer_path(root, data_path)?;
        let data = resolve_member_path(root, &data_path)?;
        let TypeInfo::PointerType {
            size: data_pointer_size,
            ..
        } = strip_type_aliases(data.member_type)
        else {
            return None;
        };
        if data_pointer_size != pointer_size {
            return None;
        }
        (
            HashTableBucketLayout::Forward { data_path },
            HashTableBucketOrder::Forward,
        )
    } else {
        (
            HashTableBucketLayout::ReverseFromControl,
            HashTableBucketOrder::Reverse,
        )
    };

    let mut ranges = Vec::with_capacity(4);
    for path in [&control_path, &length_path, &bucket_mask_path] {
        let member = resolve_member_path(root, path)?;
        let end = member.offset.checked_add(member.member_type.size())?;
        if end > root.size() {
            return None;
        }
        ranges.push((member.offset, end));
    }
    if let HashTableBucketLayout::Forward { data_path } = &buckets {
        let member = resolve_member_path(root, data_path)?;
        let end = member.offset.checked_add(member.member_type.size())?;
        if end > root.size() {
            return None;
        }
        ranges.push((member.offset, end));
    }
    for (index, left) in ranges.iter().enumerate() {
        if ranges[index + 1..]
            .iter()
            .any(|right| ranges_overlap(*left, *right))
        {
            return None;
        }
    }

    Some(HashTableLayout {
        entry_type_path: table_path,
        control_path,
        length_path,
        bucket_mask_path,
        occupancy: HashTableOccupancy::ControlByteHighBitClear,
        buckets,
        bucket_order,
        kind,
    })
}

fn validate_legacy_hash_table_layout(
    root: &TypeInfo,
    kind: HashTableKind,
) -> Option<HashTableLayout> {
    let table_path = match kind {
        HashTableKind::Map => field_path(&["table"]),
        HashTableKind::Set => field_path(&["map", "table"]),
    };
    let table = resolve_member_path(root, &table_path)?;
    let TypeInfo::StructType {
        size: table_size,
        members,
        ..
    } = strip_type_aliases(table.member_type)
    else {
        return None;
    };
    if members.len() != 4 {
        return None;
    }
    let capacity_mask = unique_named_member(members, "capacity_mask")?;
    let size = unique_named_member(members, "size")?;
    let hashes = unique_named_member(members, "hashes")?;
    let marker = unique_named_member(members, "marker")?;
    for member in [capacity_mask, size, hashes, marker] {
        member_range(member, *table_size)?;
    }
    if !matches!(
        strip_type_aliases(&marker.member_type),
        TypeInfo::StructType { size: 0, .. }
    ) {
        return None;
    }

    let tagged_hash = sole_struct_member(&hashes.member_type)?;
    member_range(tagged_hash, hashes.member_type.size())?;
    let mut control_path = table_path.clone();
    control_path.push(hashes.name.clone());
    control_path.push(tagged_hash.name.clone());
    let control_path = wrapped_pointer_path(root, control_path)?;
    let control = resolve_member_path(root, &control_path)?;
    let TypeInfo::PointerType {
        target_type,
        size: pointer_size,
    } = strip_type_aliases(control.member_type)
    else {
        return None;
    };
    let TypeInfo::BaseType {
        size: word_size,
        encoding,
        ..
    } = strip_type_aliases(target_type)
    else {
        return None;
    };
    if !matches!(*pointer_size, 4 | 8)
        || word_size != pointer_size
        || *encoding != gimli::DW_ATE_unsigned.0 as u16
    {
        return None;
    }

    let mut length_path = table_path.clone();
    length_path.push(size.name.clone());
    let length_path = unsigned_metadata_path(root, length_path, *pointer_size)?;
    let mut bucket_mask_path = table_path.clone();
    bucket_mask_path.push(capacity_mask.name.clone());
    let bucket_mask_path = unsigned_metadata_path(root, bucket_mask_path, *pointer_size)?;
    let mut entry_type_path = table_path;
    entry_type_path.push(marker.name.clone());

    let paths = [&control_path, &length_path, &bucket_mask_path];
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
            .any(|right| ranges_overlap(*left, *right))
        {
            return None;
        }
    }

    Some(HashTableLayout {
        entry_type_path,
        control_path,
        length_path,
        bucket_mask_path,
        occupancy: HashTableOccupancy::NonZeroWord {
            word_size: *word_size,
        },
        // TaggedHashUintPtr reserves its low pointer bit in Rust 1.35. This is
        // the one implementation semantic unavailable in DWARF; widths,
        // offsets, entry layout, and alignment remain DWARF-derived.
        buckets: HashTableBucketLayout::LegacyAfterControl {
            pointer_tag_mask: 1,
        },
        bucket_order: HashTableBucketOrder::Forward,
        kind,
    })
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

fn unique_named_member<'a>(members: &'a [StructMember], name: &str) -> Option<&'a StructMember> {
    let mut matching = members.iter().filter(|member| member.name == name);
    let member = matching.next()?;
    matching.next().is_none().then_some(member)
}

fn sole_struct_member(type_info: &TypeInfo) -> Option<&StructMember> {
    let TypeInfo::StructType { members, .. } = strip_type_aliases(type_info) else {
        return None;
    };
    let [member] = members.as_slice() else {
        return None;
    };
    Some(member)
}

fn scalar_wrapper_target(type_info: &TypeInfo) -> Option<&TypeInfo> {
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

fn member_range(member: &StructMember, container_size: u64) -> Option<(u64, u64)> {
    if member.bit_offset.is_some() || member.bit_size.is_some() {
        return None;
    }
    let end = member.offset.checked_add(member.member_type.size())?;
    (end <= container_size).then_some((member.offset, end))
}

fn ranges_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < left.1 && right.0 < right.1 && left.0 < right.1 && right.0 < left.1
}

struct ResolvedMemberPath<'a> {
    offset: u64,
    member_type: &'a TypeInfo,
}

fn resolve_member_path<'a>(root: &'a TypeInfo, path: &[String]) -> Option<ResolvedMemberPath<'a>> {
    resolve_member_path_impl(root, path, false)
}

fn resolve_member_path_allowing_zst<'a>(
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

    fn signed_type(name: &str, size: u64) -> TypeInfo {
        TypeInfo::BaseType {
            name: name.to_string(),
            size,
            encoding: gimli::DW_ATE_signed.0 as u16,
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

    fn rust_cell_type(
        name: &str,
        outer_field: &str,
        inner_field: &str,
        value_type: TypeInfo,
        language: SourceLanguage,
    ) -> ResolvedType {
        let unsafe_cell = single_member_struct("UnsafeCell", inner_field, value_type);
        ResolvedType::new(
            single_member_struct(name, outer_field, unsafe_cell),
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

    struct RefCellTestLayout<'a> {
        name: &'a str,
        root_size: u64,
        value_offset: u64,
        borrow_offset: u64,
        borrow_size: u64,
        language: SourceLanguage,
    }

    fn rust_ref_cell_type(layout: RefCellTestLayout<'_>, value_type: TypeInfo) -> ResolvedType {
        let value = single_member_struct("UnsafeCell<T>", "value_inner_from_dwarf", value_type);
        let borrow = single_member_struct(
            "Cell<BorrowFlag>",
            "borrow_cell_inner_from_dwarf",
            single_member_struct(
                "UnsafeCell<BorrowFlag>",
                "borrow_inner_from_dwarf",
                signed_type("isize", layout.borrow_size),
            ),
        );
        ResolvedType::new(
            TypeInfo::StructType {
                name: layout.name.to_string(),
                size: layout.root_size,
                members: vec![
                    member("borrow", borrow, layout.borrow_offset),
                    member("value", value, layout.value_offset),
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

    struct RefTestLayout<'a> {
        name: &'a str,
        root_size: u64,
        value_offset: u64,
        borrow_offset: u64,
        value_pointer_size: u64,
        borrow_pointer_size: u64,
        language: SourceLanguage,
        marker: bool,
    }

    fn rust_ref_type(layout: RefTestLayout<'_>, value_type: TypeInfo) -> ResolvedType {
        let value_pointer = TypeInfo::PointerType {
            target_type: Box::new(value_type),
            size: layout.value_pointer_size,
        };
        let borrow_pointer = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::UnknownType {
                name: "Cell<isize>".to_string(),
            }),
            size: layout.borrow_pointer_size,
        };
        let mut members = vec![
            member(
                "borrow",
                single_member_struct("BorrowRef", "borrow_pointer_from_dwarf", borrow_pointer),
                layout.borrow_offset,
            ),
            member(
                "value",
                single_member_struct("NonNull<T>", "value_pointer_from_dwarf", value_pointer),
                layout.value_offset,
            ),
        ];
        if layout.marker {
            members.push(member(
                "marker",
                TypeInfo::StructType {
                    name: "PhantomData<T>".to_string(),
                    size: 0,
                    members: Vec::new(),
                },
                layout.root_size,
            ));
        }
        ResolvedType::new(
            TypeInfo::StructType {
                name: layout.name.to_string(),
                size: layout.root_size,
                members,
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

    fn rust_reference_counted_type(
        name: &str,
        pointer_size: u64,
        nested_pointer_wrapper: bool,
        language: SourceLanguage,
    ) -> ResolvedType {
        let raw_pointer = TypeInfo::PointerType {
            target_type: Box::new(TypeInfo::UnknownType {
                name: "RcOrArcInner<T>".to_string(),
            }),
            size: pointer_size,
        };
        let pointer = if nested_pointer_wrapper {
            single_member_struct("NonZero<*mut T>", "scalar_from_dwarf", raw_pointer)
        } else {
            raw_pointer
        };
        let ptr = TypeInfo::StructType {
            name: "NonNull<Inner<T>>".to_string(),
            size: pointer_size,
            members: vec![member("pointer", pointer, 0)],
        };
        ResolvedType::new(
            TypeInfo::StructType {
                name: name.to_string(),
                size: pointer_size,
                members: vec![
                    member("ptr", ptr, 0),
                    member(
                        "phantom",
                        TypeInfo::StructType {
                            name: "PhantomData<T>".to_string(),
                            size: 0,
                            members: Vec::new(),
                        },
                        pointer_size,
                    ),
                ],
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

    fn rust_reference_counted_dst_type(
        name: &str,
        type_name: &str,
        value_member: &str,
        pointer_size: u64,
        explicit_metadata: bool,
        language: SourceLanguage,
    ) -> ResolvedType {
        let counter = || {
            single_member_struct(
                "Cell<usize>",
                "value",
                single_member_struct(
                    "UnsafeCell<usize>",
                    "value",
                    unsigned_type("usize", pointer_size),
                ),
            )
        };
        let inner = TypeInfo::StructType {
            name: format!("{type_name}Inner<str>"),
            size: pointer_size * 2,
            members: vec![
                member("strong", counter(), 0),
                member("weak", counter(), pointer_size),
                member(
                    value_member,
                    TypeInfo::ArrayType {
                        element_type: Box::new(unsigned_type("u8", 1)),
                        element_count: None,
                        total_size: None,
                    },
                    pointer_size * 2,
                ),
            ],
        };
        let raw_pointer = TypeInfo::PointerType {
            target_type: Box::new(inner),
            size: pointer_size,
        };
        let pointer = if explicit_metadata {
            TypeInfo::StructType {
                name: format!("*const {type_name}Inner<str>"),
                size: pointer_size * 2,
                members: vec![
                    member("data_ptr", raw_pointer, 0),
                    member("length", unsigned_type("usize", pointer_size), pointer_size),
                ],
            }
        } else {
            raw_pointer
        };
        let ptr = TypeInfo::StructType {
            name: format!("NonNull<{type_name}Inner<str>>"),
            size: pointer.size(),
            members: vec![member("pointer", pointer, 0)],
        };
        ResolvedType::new(
            TypeInfo::StructType {
                name: name.to_string(),
                size: ptr.size(),
                members: vec![member("ptr", ptr, 0)],
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

    fn hash_table_metadata(pointer_size: u64, dedicated_data: bool) -> TypeInfo {
        let control_pointer = TypeInfo::PointerType {
            target_type: Box::new(unsigned_type("u8", 1)),
            size: pointer_size,
        };
        let control = single_member_struct("NonNull<u8>", "pointer", control_pointer);
        let mut members = vec![
            member("bucket_mask", unsigned_type("usize", pointer_size), 0),
            member("ctrl", control, pointer_size),
            member(
                "growth_left",
                unsigned_type("usize", pointer_size),
                pointer_size * 2,
            ),
            member(
                "items",
                unsigned_type("usize", pointer_size),
                pointer_size * 3,
            ),
        ];
        if dedicated_data {
            let entry_pointer = TypeInfo::PointerType {
                target_type: Box::new(TypeInfo::UnknownType {
                    name: "(K, V)".to_string(),
                }),
                size: pointer_size,
            };
            members.push(member(
                "data",
                single_member_struct("NonNull<(K, V)>", "pointer", entry_pointer),
                pointer_size * 4,
            ));
        }
        TypeInfo::StructType {
            name: "hashbrown::raw::RawTableInner".to_string(),
            size: pointer_size * if dedicated_data { 5 } else { 4 },
            members,
        }
    }

    fn rust_hash_collection_type(
        name: &str,
        kind: HashTableKind,
        pointer_size: u64,
        nested_metadata: bool,
        dedicated_data: bool,
        legacy_set_wrapper: bool,
        language: SourceLanguage,
    ) -> ResolvedType {
        let metadata = hash_table_metadata(pointer_size, dedicated_data);
        let raw_table = if nested_metadata {
            TypeInfo::StructType {
                name: "hashbrown::raw::RawTable<(K, V)>".to_string(),
                size: metadata.size(),
                members: vec![member("table", metadata, 0)],
            }
        } else {
            TypeInfo::StructType {
                name: "hashbrown::raw::RawTable<(K, V)>".to_string(),
                size: metadata.size(),
                members: match metadata {
                    TypeInfo::StructType { members, .. } => members,
                    _ => unreachable!("hash metadata is a struct"),
                },
            }
        };
        let hashbrown_map = TypeInfo::StructType {
            name: "hashbrown::map::HashMap<K, V>".to_string(),
            size: raw_table.size(),
            members: vec![member("table", raw_table, 0)],
        };
        let root = match (kind, legacy_set_wrapper) {
            (HashTableKind::Map, _) => TypeInfo::StructType {
                name: name.to_string(),
                size: hashbrown_map.size(),
                members: vec![member("base", hashbrown_map, 0)],
            },
            (HashTableKind::Set, false) => {
                let hashbrown_set = TypeInfo::StructType {
                    name: "hashbrown::set::HashSet<T>".to_string(),
                    size: hashbrown_map.size(),
                    members: vec![member("map", hashbrown_map, 0)],
                };
                TypeInfo::StructType {
                    name: name.to_string(),
                    size: hashbrown_set.size(),
                    members: vec![member("base", hashbrown_set, 0)],
                }
            }
            (HashTableKind::Set, true) => {
                let std_map = TypeInfo::StructType {
                    name: "std::collections::hash::map::HashMap<T, ()>".to_string(),
                    size: hashbrown_map.size(),
                    members: vec![member("base", hashbrown_map, 0)],
                };
                TypeInfo::StructType {
                    name: name.to_string(),
                    size: std_map.size(),
                    members: vec![member("map", std_map, 0)],
                }
            }
        };
        ResolvedType::new(
            root,
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

    fn rust_135_hash_collection_type(
        name: &str,
        kind: HashTableKind,
        pointer_size: u64,
        language: SourceLanguage,
    ) -> ResolvedType {
        let hash_word = unsigned_type("usize", pointer_size);
        let raw_pointer = TypeInfo::PointerType {
            target_type: Box::new(hash_word),
            size: pointer_size,
        };
        let unique = TypeInfo::StructType {
            name: "core::ptr::Unique<usize>".to_string(),
            size: pointer_size,
            members: vec![
                member("pointer", raw_pointer, 0),
                member(
                    "_marker",
                    TypeInfo::StructType {
                        name: "PhantomData<usize>".to_string(),
                        size: 0,
                        members: Vec::new(),
                    },
                    0,
                ),
            ],
        };
        let hashes = TypeInfo::StructType {
            name: "TaggedHashUintPtr".to_string(),
            size: pointer_size,
            members: vec![member("__0", unique, 0)],
        };
        let marker = TypeInfo::StructType {
            name: "PhantomData<(K, V)>".to_string(),
            size: 0,
            members: Vec::new(),
        };
        let raw_table = TypeInfo::StructType {
            name: "RawTable<K, V>".to_string(),
            size: pointer_size * 3,
            members: vec![
                member("capacity_mask", unsigned_type("usize", pointer_size), 0),
                member("size", unsigned_type("usize", pointer_size), pointer_size),
                member("hashes", hashes, pointer_size * 2),
                member("marker", marker, 0),
            ],
        };
        let map = TypeInfo::StructType {
            name: match kind {
                HashTableKind::Map => name.to_string(),
                HashTableKind::Set => "std::collections::hash::map::HashMap<K, ()>".to_string(),
            },
            size: pointer_size * 5,
            members: vec![
                member(
                    "hash_builder",
                    TypeInfo::StructType {
                        name: "RandomState".to_string(),
                        size: pointer_size * 2,
                        members: Vec::new(),
                    },
                    0,
                ),
                member("table", raw_table, pointer_size * 2),
                member(
                    "resize_policy",
                    TypeInfo::StructType {
                        name: "DefaultResizePolicy".to_string(),
                        size: 0,
                        members: Vec::new(),
                    },
                    0,
                ),
            ],
        };
        let root = match kind {
            HashTableKind::Map => map,
            HashTableKind::Set => TypeInfo::StructType {
                name: name.to_string(),
                size: map.size(),
                members: vec![member("map", map, 0)],
            },
        };
        ResolvedType::new(
            root,
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

    fn rust_btree_collection_type(
        name: &str,
        kind: BTreeKind,
        pointer_size: u64,
        language: SourceLanguage,
    ) -> ResolvedType {
        let root = TypeInfo::StructType {
            name: "Option<NodeRef<K, V>>".to_string(),
            size: pointer_size * 2,
            members: Vec::new(),
        };
        let map = TypeInfo::StructType {
            name: "alloc::collections::btree::map::BTreeMap<K, V>".to_string(),
            size: pointer_size * 3,
            members: vec![
                member("root", root, 0),
                member(
                    "length",
                    unsigned_type("usize", pointer_size),
                    pointer_size * 2,
                ),
            ],
        };
        let root = match kind {
            BTreeKind::Map => match map {
                TypeInfo::StructType { size, members, .. } => TypeInfo::StructType {
                    name: name.to_string(),
                    size,
                    members,
                },
                _ => unreachable!("test BTreeMap is a struct"),
            },
            BTreeKind::Set => TypeInfo::StructType {
                name: name.to_string(),
                size: map.size(),
                members: vec![member("map", map, 0)],
            },
        };
        ResolvedType::new(
            root,
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
                presentation: ProjectedValuePresentation::Transparent,
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
                presentation: ProjectedValuePresentation::Transparent,
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
    fn recognizes_cell_by_namespace_and_dwarf_member_structure() {
        let current = rust_cell_type(
            "Cell<(i32, u16)>",
            "outer_from_dwarf",
            "inner_from_dwarf",
            TypeInfo::StructType {
                name: "(i32, u16)".to_string(),
                size: 8,
                members: vec![
                    member("__0", signed_type("i32", 4), 0),
                    member("__1", unsigned_type("u16", 2), 4),
                ],
            },
            SourceLanguage::Rust,
        );

        assert_eq!(
            resolve_value_layout(&current, Some("core::cell::Cell<(i32, u16)>")),
            Some(ValueLayout::ProjectedValue {
                value_path: field_path(&["outer_from_dwarf", "inner_from_dwarf"]),
                presentation: ProjectedValuePresentation::SingleField {
                    type_name: "Cell",
                    field_name: "value",
                },
            })
        );

        let fully_qualified = rust_cell_type(
            "core::cell::Cell<u32>",
            "value",
            "value",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );
        assert!(resolve_value_layout(&fully_qualified, None).is_some());
    }

    #[test]
    fn rejects_cell_lookalikes_and_invalid_layouts() {
        let current = rust_cell_type(
            "Cell<u32>",
            "value",
            "value",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        );
        assert_eq!(resolve_value_layout(&current, Some("app::Cell<u32>")), None);
        assert_eq!(resolve_value_layout(&current, None), None);

        let mut invalid = current.clone();
        let TypeInfo::StructType { members, .. } = &mut invalid.summary else {
            unreachable!("test Cell is a struct")
        };
        let TypeInfo::StructType {
            members: inner_members,
            ..
        } = &mut members[0].member_type
        else {
            unreachable!("test Cell contains a struct")
        };
        inner_members.push(member("extra", unsigned_type("u32", 4), 0));
        assert_eq!(
            resolve_value_layout(&invalid, Some("core::cell::Cell<u32>")),
            None
        );

        let non_rust = rust_cell_type(
            "core::cell::Cell<u32>",
            "value",
            "value",
            unsigned_type("u32", 4),
            SourceLanguage::C,
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn recognizes_ref_cell_with_dwarf_derived_fields_and_widths() {
        let value_type = TypeInfo::StructType {
            name: "(i32, u16)".to_string(),
            size: 8,
            members: vec![
                member("__0", signed_type("i32", 4), 0),
                member("__1", unsigned_type("u16", 2), 4),
            ],
        };
        let current = rust_ref_cell_type(
            RefCellTestLayout {
                name: "RefCell<(i32, u16)>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            value_type,
        );

        assert_eq!(
            resolve_value_layout(&current, Some("core::cell::RefCell<(i32, u16)>")),
            Some(ValueLayout::ProjectedStruct(ProjectedStructLayout {
                type_name: "RefCell",
                fields: vec![
                    ProjectedStructField {
                        name: "value",
                        value_path: field_path(&["value", "value_inner_from_dwarf"]),
                    },
                    ProjectedStructField {
                        name: "borrow",
                        value_path: field_path(&[
                            "borrow",
                            "borrow_cell_inner_from_dwarf",
                            "borrow_inner_from_dwarf",
                        ]),
                    },
                ],
                presentation: ProjectedStructPresentation::SignedState {
                    state_field: "borrow",
                    non_negative_label: "borrow",
                    negative_label: "borrow_mut",
                },
            }))
        );

        let narrow = rust_ref_cell_type(
            RefCellTestLayout {
                name: "core::cell::RefCell<u16>",
                root_size: 8,
                value_offset: 0,
                borrow_offset: 4,
                borrow_size: 4,
                language: SourceLanguage::Rust,
            },
            unsigned_type("u16", 2),
        );
        assert!(resolve_value_layout(&narrow, None).is_some());

        let zst = rust_ref_cell_type(
            RefCellTestLayout {
                name: "core::cell::RefCell<()>",
                root_size: 8,
                value_offset: 0,
                borrow_offset: 0,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            TypeInfo::BaseType {
                name: "()".to_string(),
                size: 0,
                encoding: gimli::DW_ATE_unsigned.0 as u16,
            },
        );
        assert!(resolve_value_layout(&zst, None).is_some());
    }

    #[test]
    fn rejects_ref_cell_lookalikes_and_invalid_layouts() {
        let current = rust_ref_cell_type(
            RefCellTestLayout {
                name: "RefCell<u32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            unsigned_type("u32", 4),
        );
        assert_eq!(
            resolve_value_layout(&current, Some("app::RefCell<u32>")),
            None
        );
        assert_eq!(resolve_value_layout(&current, None), None);

        let mut unsigned_borrow = current.clone();
        let TypeInfo::StructType { members, .. } = &mut unsigned_borrow.summary else {
            unreachable!("test RefCell is a struct")
        };
        let TypeInfo::StructType {
            members: cell_members,
            ..
        } = &mut members[0].member_type
        else {
            unreachable!("test borrow field is a struct")
        };
        let TypeInfo::StructType {
            members: inner_members,
            ..
        } = &mut cell_members[0].member_type
        else {
            unreachable!("test borrow wrapper is a struct")
        };
        inner_members[0].member_type = unsigned_type("usize", 8);
        assert_eq!(
            resolve_value_layout(&unsigned_borrow, Some("core::cell::RefCell<u32>")),
            None
        );

        let overlapping = rust_ref_cell_type(
            RefCellTestLayout {
                name: "core::cell::RefCell<u64>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 4,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            unsigned_type("u64", 8),
        );
        assert_eq!(resolve_value_layout(&overlapping, None), None);

        let non_rust = rust_ref_cell_type(
            RefCellTestLayout {
                name: "core::cell::RefCell<u32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                borrow_size: 8,
                language: SourceLanguage::C,
            },
            unsigned_type("u32", 4),
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn recognizes_hash_collections_across_rust_raw_table_layouts() {
        let current_map = rust_hash_collection_type(
            "HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            true,
            false,
            false,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(
                &current_map,
                Some("std::collections::hash::map::HashMap<i32, u16>"),
            ),
            Some(ValueLayout::HashTable(HashTableLayout {
                entry_type_path: field_path(&["base", "table"]),
                control_path: field_path(&["base", "table", "table", "ctrl", "pointer",]),
                length_path: field_path(&["base", "table", "table", "items"]),
                bucket_mask_path: field_path(&["base", "table", "table", "bucket_mask",]),
                occupancy: HashTableOccupancy::ControlByteHighBitClear,
                buckets: HashTableBucketLayout::ReverseFromControl,
                bucket_order: HashTableBucketOrder::Reverse,
                kind: HashTableKind::Map,
            }))
        );

        let legacy_map = rust_hash_collection_type(
            "std::collections::hash::map::HashMap<i32, u16>",
            HashTableKind::Map,
            4,
            false,
            true,
            false,
            SourceLanguage::Rust,
        );
        let Some(ValueLayout::HashTable(legacy_map)) = resolve_value_layout(&legacy_map, None)
        else {
            panic!("expected legacy HashMap layout")
        };
        assert_eq!(legacy_map.entry_type_path, field_path(&["base", "table"]));
        assert_eq!(
            legacy_map.control_path,
            field_path(&["base", "table", "ctrl", "pointer"])
        );
        assert_eq!(
            legacy_map.buckets,
            HashTableBucketLayout::Forward {
                data_path: field_path(&["base", "table", "data", "pointer"]),
            }
        );
        assert_eq!(
            legacy_map.occupancy,
            HashTableOccupancy::ControlByteHighBitClear
        );
        assert_eq!(legacy_map.bucket_order, HashTableBucketOrder::Forward);

        let current_set = rust_hash_collection_type(
            "std::collections::hash::set::HashSet<i32>",
            HashTableKind::Set,
            8,
            true,
            false,
            false,
            SourceLanguage::Rust,
        );
        let Some(ValueLayout::HashTable(current_set)) = resolve_value_layout(&current_set, None)
        else {
            panic!("expected current HashSet layout")
        };
        assert_eq!(
            current_set.entry_type_path,
            field_path(&["base", "map", "table"])
        );
        assert_eq!(current_set.kind, HashTableKind::Set);

        let legacy_set = rust_hash_collection_type(
            "HashSet<i32>",
            HashTableKind::Set,
            8,
            false,
            true,
            true,
            SourceLanguage::Rust,
        );
        let Some(ValueLayout::HashTable(legacy_set)) = resolve_value_layout(
            &legacy_set,
            Some("std::collections::hash::set::HashSet<i32>"),
        ) else {
            panic!("expected legacy HashSet layout")
        };
        assert_eq!(
            legacy_set.entry_type_path,
            field_path(&["map", "base", "table"])
        );
        assert_eq!(legacy_set.bucket_order, HashTableBucketOrder::Forward);
    }

    #[test]
    fn recognizes_rust_135_hash_collections_from_legacy_table_metadata() {
        for (name, qualified_name, kind, table_path) in [
            (
                "HashMap<i32, u16>",
                "std::collections::hash::map::HashMap<i32, u16>",
                HashTableKind::Map,
                field_path(&["table"]),
            ),
            (
                "HashSet<i32>",
                "std::collections::hash::set::HashSet<i32>",
                HashTableKind::Set,
                field_path(&["map", "table"]),
            ),
        ] {
            let value = rust_135_hash_collection_type(name, kind, 8, SourceLanguage::Rust);
            let Some(ValueLayout::HashTable(layout)) =
                resolve_value_layout(&value, Some(qualified_name))
            else {
                panic!("expected Rust 1.35 hash-table layout for {name}")
            };
            let mut control_path = table_path.clone();
            control_path.extend(field_path(&["hashes", "__0", "pointer"]));
            let mut marker_path = table_path.clone();
            marker_path.push("marker".to_string());
            assert_eq!(layout.entry_type_path, marker_path);
            assert_eq!(layout.control_path, control_path);
            assert_eq!(
                layout.occupancy,
                HashTableOccupancy::NonZeroWord { word_size: 8 }
            );
            assert_eq!(
                layout.buckets,
                HashTableBucketLayout::LegacyAfterControl {
                    pointer_tag_mask: 1,
                }
            );
            assert_eq!(layout.bucket_order, HashTableBucketOrder::Forward);
        }
    }

    #[test]
    fn rejects_hash_collection_lookalikes_and_invalid_metadata() {
        let current = rust_hash_collection_type(
            "HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            true,
            false,
            false,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&current, Some("app::HashMap<i32, u16>")),
            None
        );
        assert_eq!(resolve_value_layout(&current, None), None);

        let mut invalid_width = current.clone();
        let TypeInfo::StructType { members, .. } = &mut invalid_width.summary else {
            unreachable!("test HashMap is a struct")
        };
        let TypeInfo::StructType {
            members: map_members,
            ..
        } = &mut members[0].member_type
        else {
            unreachable!("test base is a hashbrown map")
        };
        let TypeInfo::StructType {
            members: table_members,
            ..
        } = &mut map_members[0].member_type
        else {
            unreachable!("test table is a RawTable")
        };
        let TypeInfo::StructType {
            members: metadata_members,
            ..
        } = &mut table_members[0].member_type
        else {
            unreachable!("test table metadata is a struct")
        };
        metadata_members
            .iter_mut()
            .find(|member| member.name == "items")
            .expect("items member")
            .member_type = unsigned_type("u32", 4);
        assert_eq!(
            resolve_value_layout(
                &invalid_width,
                Some("std::collections::hash::map::HashMap<i32, u16>"),
            ),
            None
        );

        let non_rust = rust_hash_collection_type(
            "std::collections::hash::map::HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            true,
            false,
            false,
            SourceLanguage::C,
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);

        let legacy = rust_135_hash_collection_type(
            "HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&legacy, Some("app::HashMap<i32, u16>")),
            None
        );

        let mut invalid_legacy = legacy;
        let TypeInfo::StructType { members, .. } = &mut invalid_legacy.summary else {
            unreachable!("test legacy HashMap is a struct")
        };
        let TypeInfo::StructType {
            members: table_members,
            ..
        } = &mut members
            .iter_mut()
            .find(|member| member.name == "table")
            .expect("legacy table member")
            .member_type
        else {
            unreachable!("test legacy table is a struct")
        };
        let TypeInfo::StructType {
            members: tagged_members,
            ..
        } = &mut table_members
            .iter_mut()
            .find(|member| member.name == "hashes")
            .expect("legacy hashes member")
            .member_type
        else {
            unreachable!("test tagged hash pointer is a struct")
        };
        tagged_members.push(member("unexpected", unsigned_type("usize", 8), 0));
        assert_eq!(
            resolve_value_layout(
                &invalid_legacy,
                Some("std::collections::hash::map::HashMap<i32, u16>"),
            ),
            None
        );
    }

    #[test]
    fn recognizes_btree_collections_by_namespace_and_map_metadata() {
        let map = rust_btree_collection_type(
            "BTreeMap<i32, u16>",
            BTreeKind::Map,
            8,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(
                &map,
                Some("alloc::collections::btree::map::BTreeMap<i32, u16>"),
            ),
            Some(ValueLayout::BTree(BTreeLayout {
                map_path: Vec::new(),
                root_path: field_path(&["root"]),
                length_path: field_path(&["length"]),
                kind: BTreeKind::Map,
            }))
        );

        let set = rust_btree_collection_type(
            "alloc::collections::btree::set::BTreeSet<i32>",
            BTreeKind::Set,
            4,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&set, None),
            Some(ValueLayout::BTree(BTreeLayout {
                map_path: field_path(&["map"]),
                root_path: field_path(&["map", "root"]),
                length_path: field_path(&["map", "length"]),
                kind: BTreeKind::Set,
            }))
        );
    }

    #[test]
    fn rejects_btree_collection_lookalikes_and_invalid_metadata() {
        let map = rust_btree_collection_type(
            "BTreeMap<i32, u16>",
            BTreeKind::Map,
            8,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&map, Some("app::BTreeMap<i32, u16>")),
            None
        );
        assert_eq!(resolve_value_layout(&map, None), None);

        let mut missing_length = map.clone();
        let TypeInfo::StructType { members, .. } = &mut missing_length.summary else {
            unreachable!("test BTreeMap is a struct")
        };
        members.retain(|member| member.name != "length");
        assert_eq!(
            resolve_value_layout(
                &missing_length,
                Some("alloc::collections::btree::map::BTreeMap<i32, u16>"),
            ),
            None
        );

        let non_rust = rust_btree_collection_type(
            "alloc::collections::btree::map::BTreeMap<i32, u16>",
            BTreeKind::Map,
            8,
            SourceLanguage::C,
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn recognizes_rc_and_arc_with_dwarf_derived_pointer_wrappers() {
        let expected = |type_name, value_member: &str| {
            let inner_path = vec![
                ProjectedPathSegment::Member("ptr".to_string()),
                ProjectedPathSegment::Member("pointer".to_string()),
                ProjectedPathSegment::UnwrapScalar,
                ProjectedPathSegment::Dereference,
            ];
            let mut value_path = inner_path.clone();
            value_path.push(ProjectedPathSegment::Member(value_member.to_string()));
            let mut strong_path = inner_path.clone();
            strong_path.push(ProjectedPathSegment::Member("strong".to_string()));
            strong_path.push(ProjectedPathSegment::UnwrapScalar);
            let mut weak_path = inner_path;
            weak_path.push(ProjectedPathSegment::Member("weak".to_string()));
            weak_path.push(ProjectedPathSegment::UnwrapScalar);
            ValueLayout::CompositeStruct(CompositeStructLayout {
                type_name,
                fields: vec![
                    CompositeStructField {
                        name: "value",
                        value_path,
                        capture: CompositeStructFieldCapture::Value(
                            ProjectedValueRequirement::KnownSizedOrZst,
                        ),
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
                presentation: ProjectedStructPresentation::ReferenceCounted {
                    strong_field: "strong",
                    weak_field: "weak",
                    implicit_weak: 1,
                },
            })
        };

        let rc = rust_reference_counted_type("Rc<(i32, u16)>", 8, true, SourceLanguage::Rust);
        assert_eq!(
            resolve_value_layout(&rc, Some("alloc::rc::Rc<(i32, u16)>")),
            Some(expected("Rc", "value"))
        );

        let arc = rust_reference_counted_type(
            "alloc::sync::Arc<(i32, u16)>",
            4,
            false,
            SourceLanguage::Rust,
        );
        assert_eq!(
            resolve_value_layout(&arc, None),
            Some(expected("Arc", "data"))
        );
    }

    #[test]
    fn recognizes_rc_and_arc_dst_addresses_from_thin_and_wide_dwarf_pointers() {
        let expected = |type_name, value_member: &str, explicit_metadata| {
            let mut inner_path = vec![
                ProjectedPathSegment::Member("ptr".to_string()),
                ProjectedPathSegment::Member("pointer".to_string()),
            ];
            inner_path.push(if explicit_metadata {
                ProjectedPathSegment::Member("data_ptr".to_string())
            } else {
                ProjectedPathSegment::UnwrapScalar
            });
            inner_path.push(ProjectedPathSegment::Dereference);
            let mut value_path = inner_path.clone();
            value_path.push(ProjectedPathSegment::Member(value_member.to_string()));
            let mut strong_path = inner_path.clone();
            strong_path.push(ProjectedPathSegment::Member("strong".to_string()));
            strong_path.push(ProjectedPathSegment::UnwrapScalar);
            let mut weak_path = inner_path;
            weak_path.push(ProjectedPathSegment::Member("weak".to_string()));
            weak_path.push(ProjectedPathSegment::UnwrapScalar);
            ValueLayout::CompositeStruct(CompositeStructLayout {
                type_name,
                fields: vec![
                    CompositeStructField {
                        name: "ptr",
                        value_path,
                        capture: CompositeStructFieldCapture::Address,
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
                presentation: ProjectedStructPresentation::ReferenceCounted {
                    strong_field: "strong",
                    weak_field: "weak",
                    implicit_weak: 1,
                },
            })
        };

        for pointer_size in [4, 8] {
            for (type_name, value_member, qualified_name) in [
                ("Rc", "value", "alloc::rc::Rc<str>"),
                ("Arc", "data", "alloc::sync::Arc<str>"),
            ] {
                for explicit_metadata in [false, true] {
                    let current = rust_reference_counted_dst_type(
                        &format!("{type_name}<str>"),
                        type_name,
                        value_member,
                        pointer_size,
                        explicit_metadata,
                        SourceLanguage::Rust,
                    );
                    assert_eq!(
                        resolve_value_layout(&current, Some(qualified_name)),
                        Some(expected(type_name, value_member, explicit_metadata))
                    );
                }
            }
        }
    }

    #[test]
    fn recognizes_slice_dst_and_rejects_reference_counted_lookalikes() {
        let lookalike = rust_reference_counted_dst_type(
            "Rc<str>",
            "Rc",
            "value",
            8,
            true,
            SourceLanguage::Rust,
        );
        assert_eq!(resolve_value_layout(&lookalike, Some("app::Rc<str>")), None);

        let slice = rust_reference_counted_dst_type(
            "alloc::rc::Rc<[u8]>",
            "Rc",
            "value",
            8,
            true,
            SourceLanguage::Rust,
        );
        assert!(matches!(
            resolve_value_layout(&slice, None),
            Some(ValueLayout::CompositeStruct(CompositeStructLayout {
                fields,
                ..
            })) if fields[0].capture == CompositeStructFieldCapture::Address
        ));

        let non_rust = rust_reference_counted_dst_type(
            "alloc::rc::Rc<str>",
            "Rc",
            "value",
            8,
            true,
            SourceLanguage::C,
        );
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn rejects_rc_arc_lookalikes_and_non_scalar_pointers() {
        let lookalike = rust_reference_counted_type("Rc<i32>", 8, false, SourceLanguage::Rust);
        assert_eq!(resolve_value_layout(&lookalike, Some("app::Rc<i32>")), None);
        assert_eq!(resolve_value_layout(&lookalike, None), None);

        let narrow =
            rust_reference_counted_type("alloc::rc::Rc<i32>", 2, false, SourceLanguage::Rust);
        assert_eq!(resolve_value_layout(&narrow, None), None);

        let mut fat =
            rust_reference_counted_type("alloc::sync::Arc<str>", 8, false, SourceLanguage::Rust);
        let TypeInfo::StructType { members, .. } = &mut fat.summary else {
            unreachable!("test Arc is a struct")
        };
        let TypeInfo::StructType {
            members: ptr_members,
            ..
        } = &mut members[0].member_type
        else {
            unreachable!("test Arc ptr is a wrapper")
        };
        ptr_members[0].member_type = TypeInfo::StructType {
            name: "fat pointer".to_string(),
            size: 16,
            members: vec![
                member("data", unsigned_type("usize", 8), 0),
                member("length", unsigned_type("usize", 8), 8),
            ],
        };
        assert_eq!(resolve_value_layout(&fat, None), None);

        let non_rust =
            rust_reference_counted_type("alloc::rc::Rc<i32>", 8, false, SourceLanguage::C);
        assert_eq!(resolve_value_layout(&non_rust, None), None);
    }

    #[test]
    fn recognizes_ref_guards_with_dwarf_derived_pointer_layouts() {
        let current = rust_ref_type(
            RefTestLayout {
                name: "Ref<(i32, u16)>",
                root_size: 16,
                value_offset: 8,
                borrow_offset: 0,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language: SourceLanguage::Rust,
                marker: false,
            },
            TypeInfo::StructType {
                name: "(i32, u16)".to_string(),
                size: 8,
                members: Vec::new(),
            },
        );

        assert_eq!(
            resolve_value_layout(&current, Some("core::cell::Ref<(i32, u16)>")),
            Some(ValueLayout::CompositeStruct(CompositeStructLayout {
                type_name: "Ref",
                fields: vec![
                    CompositeStructField {
                        name: "*value",
                        value_path: vec![
                            ProjectedPathSegment::Member("value".to_string()),
                            ProjectedPathSegment::Member("value_pointer_from_dwarf".to_string(),),
                            ProjectedPathSegment::Dereference,
                        ],
                        capture: CompositeStructFieldCapture::Value(
                            ProjectedValueRequirement::KnownSizedOrZst,
                        ),
                    },
                    CompositeStructField {
                        name: "borrow",
                        value_path: vec![
                            ProjectedPathSegment::Member("borrow".to_string()),
                            ProjectedPathSegment::Member("borrow_pointer_from_dwarf".to_string(),),
                            ProjectedPathSegment::Dereference,
                            ProjectedPathSegment::SoleMember,
                            ProjectedPathSegment::SoleMember,
                        ],
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
            }))
        );

        let mut legacy = current.clone();
        let TypeInfo::StructType { members, .. } = &mut legacy.summary else {
            unreachable!("test Ref is a struct")
        };
        let value = members
            .iter_mut()
            .find(|member| member.name == "value")
            .expect("test Ref has a value member");
        let pointer_type = {
            let TypeInfo::StructType { members, .. } = &value.member_type else {
                unreachable!("current test Ref value is a pointer wrapper")
            };
            let [pointer] = members.as_slice() else {
                unreachable!("current test Ref value wrapper has one member")
            };
            pointer.member_type.clone()
        };
        value.member_type = pointer_type;
        let Some(ValueLayout::CompositeStruct(legacy_layout)) =
            resolve_value_layout(&legacy, Some("core::cell::Ref<(i32, u16)>"))
        else {
            panic!("legacy raw-pointer Ref layout should be recognized")
        };
        assert_eq!(
            legacy_layout.fields[0].value_path,
            vec![
                ProjectedPathSegment::Member("value".to_string()),
                ProjectedPathSegment::Dereference,
            ]
        );

        let ref_mut = rust_ref_type(
            RefTestLayout {
                name: "core::cell::RefMut<i32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language: SourceLanguage::Rust,
                marker: true,
            },
            signed_type("i32", 4),
        );
        assert!(resolve_value_layout(&ref_mut, None).is_some());
    }

    #[test]
    fn rejects_ref_guard_lookalikes_and_invalid_outer_layouts() {
        let make_ref = |name, language| {
            rust_ref_type(
                RefTestLayout {
                    name,
                    root_size: 16,
                    value_offset: 0,
                    borrow_offset: 8,
                    value_pointer_size: 8,
                    borrow_pointer_size: 8,
                    language,
                    marker: false,
                },
                signed_type("i32", 4),
            )
        };
        let current = make_ref("Ref<i32>", SourceLanguage::Rust);
        assert_eq!(resolve_value_layout(&current, Some("app::Ref<i32>")), None);
        assert_eq!(resolve_value_layout(&current, None), None);
        assert_eq!(
            resolve_value_layout(&make_ref("core::cell::Ref<i32>", SourceLanguage::C), None,),
            None
        );

        let overlapping = rust_ref_type(
            RefTestLayout {
                name: "core::cell::Ref<i32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 4,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language: SourceLanguage::Rust,
                marker: false,
            },
            signed_type("i32", 4),
        );
        assert_eq!(resolve_value_layout(&overlapping, None), None);

        let mismatched_widths = rust_ref_type(
            RefTestLayout {
                name: "core::cell::Ref<i32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                value_pointer_size: 8,
                borrow_pointer_size: 4,
                language: SourceLanguage::Rust,
                marker: false,
            },
            signed_type("i32", 4),
        );
        assert_eq!(resolve_value_layout(&mismatched_widths, None), None);

        let mut ambiguous_wrapper = make_ref("core::cell::Ref<i32>", SourceLanguage::Rust);
        let TypeInfo::StructType { members, .. } = &mut ambiguous_wrapper.summary else {
            unreachable!("test Ref is a struct")
        };
        let TypeInfo::StructType {
            members: value_members,
            ..
        } = &mut members[1].member_type
        else {
            unreachable!("test Ref value is a wrapper")
        };
        value_members.push(member("extra", signed_type("i32", 4), 0));
        assert_eq!(resolve_value_layout(&ambiguous_wrapper, None), None);
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
        assert!(requires_dwarf_qualified_name(&rust_hash_collection_type(
            "HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            true,
            false,
            false,
            SourceLanguage::Rust,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_hash_collection_type(
            "std::collections::hash::map::HashMap<i32, u16>",
            HashTableKind::Map,
            8,
            true,
            false,
            false,
            SourceLanguage::Rust,
        ),));
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
        assert!(requires_dwarf_qualified_name(&rust_cell_type(
            "Cell<u32>",
            "value",
            "value",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
        assert!(!requires_dwarf_qualified_name(&rust_cell_type(
            "core::cell::Cell<u32>",
            "value",
            "value",
            unsigned_type("u32", 4),
            SourceLanguage::Rust,
        )));
        assert!(requires_dwarf_qualified_name(&rust_ref_cell_type(
            RefCellTestLayout {
                name: "RefCell<u32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            unsigned_type("u32", 4),
        )));
        assert!(!requires_dwarf_qualified_name(&rust_ref_cell_type(
            RefCellTestLayout {
                name: "core::cell::RefCell<u32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                borrow_size: 8,
                language: SourceLanguage::Rust,
            },
            unsigned_type("u32", 4),
        )));
        assert!(requires_dwarf_qualified_name(&rust_ref_type(
            RefTestLayout {
                name: "Ref<i32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language: SourceLanguage::Rust,
                marker: false,
            },
            signed_type("i32", 4),
        )));
        assert!(!requires_dwarf_qualified_name(&rust_ref_type(
            RefTestLayout {
                name: "core::cell::RefMut<i32>",
                root_size: 16,
                value_offset: 0,
                borrow_offset: 8,
                value_pointer_size: 8,
                borrow_pointer_size: 8,
                language: SourceLanguage::Rust,
                marker: true,
            },
            signed_type("i32", 4),
        )));
        assert!(requires_dwarf_qualified_name(&rust_reference_counted_type(
            "Rc<i32>",
            8,
            false,
            SourceLanguage::Rust
        )));
        assert!(!requires_dwarf_qualified_name(
            &rust_reference_counted_type("alloc::sync::Arc<i32>", 8, false, SourceLanguage::Rust,)
        ));
    }
}

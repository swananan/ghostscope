mod collections;
mod identity;
mod layout;
mod sequences;
mod wrappers;

use crate::{strip_type_aliases, ResolvedType, SourceLanguage, TypeInfo};

use super::plan::{BTreeKind, BTreeLayout, HashTableKind, HashTableLayout};
use crate::language::adapter::{
    IndirectSequenceKind, ProjectedValuePresentation, ValueLayout as AdapterValueLayout,
    ValueLayoutResolution as AdapterValueLayoutResolution,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RustValueLayout {
    HashTable(HashTableLayout),
    BTree(BTreeLayout),
}

pub(crate) type ValueLayout = AdapterValueLayout<RustValueLayout>;
pub(crate) type ValueLayoutResolution = AdapterValueLayoutResolution<ValueLayout>;

pub(super) fn requires_dwarf_qualified_name(current: &ResolvedType) -> bool {
    if current.origin.as_ref().map(|origin| origin.language) != Some(SourceLanguage::Rust) {
        return false;
    }
    let TypeInfo::StructType { name, .. } = strip_type_aliases(&current.summary) else {
        return false;
    };
    matches!(
        identity::resolve(name, None),
        identity::IdentityResolution::RequiresQualifiedName
    )
}

#[cfg(test)]
pub(super) fn resolve_value_layout(
    current: &ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> Option<ValueLayout> {
    match diagnose_value_layout(current, dwarf_qualified_name) {
        ValueLayoutResolution::Applied { layout, .. } => Some(layout),
        ValueLayoutResolution::NotApplicable | ValueLayoutResolution::Rejected { .. } => None,
    }
}

pub(super) fn diagnose_value_layout(
    current: &ResolvedType,
    dwarf_qualified_name: Option<&str>,
) -> ValueLayoutResolution {
    // The language dispatcher is the production boundary. Keep this check so
    // direct internal calls cannot accidentally apply Rust identities to a
    // value from another source language.
    if current.origin.as_ref().map(|origin| origin.language) != Some(SourceLanguage::Rust) {
        return ValueLayoutResolution::NotApplicable;
    }

    // rust-gdb does not select printers from the target CU's rustc version.
    // Its wrapper adds the invoking toolchain's `lib/rustlib/etc` directory,
    // while the target only requests the generic loader through
    // `.debug_gdb_scripts`. GhostScope records the producer for diagnostics,
    // but every adapter below validates identity and physical target DWARF.
    let TypeInfo::StructType { name, .. } = strip_type_aliases(&current.summary) else {
        return ValueLayoutResolution::NotApplicable;
    };
    let adapter = match identity::resolve(name, dwarf_qualified_name) {
        identity::IdentityResolution::Recognized(adapter) => adapter,
        identity::IdentityResolution::RequiresQualifiedName
        | identity::IdentityResolution::NotApplicable => {
            return ValueLayoutResolution::NotApplicable;
        }
    };

    match adapter.resolve(&current.summary) {
        Some(layout) => ValueLayoutResolution::Applied {
            adapter: adapter.name(),
            layout,
        },
        None => ValueLayoutResolution::Rejected {
            adapter: adapter.name(),
            reason: adapter.layout_rejection_reason(),
        },
    }
}

/// Rust standard-library identities with optional semantic presentations.
///
/// Recognition selects a candidate; it never proves a physical layout.
/// `resolve` must validate every required member, offset, and width from the
/// target DWARF. Validation failure is a conservative rejection, and callers
/// must retain ordinary DWARF handling rather than require an adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RustValueAdapter {
    BTreeMap,
    BTreeSet,
    HashMap,
    HashSet,
    Rc { pointee_is_str: bool },
    Arc { pointee_is_str: bool },
    Ref,
    RefMut,
    RefCell,
    Cell,
    NonZero,
    PathReference,
    CStrReference,
    StrReference,
    SliceReference,
    BoxCStr,
    BoxStr,
    CString,
    String,
    OsString,
    PathBuf,
    Vec,
    VecDeque,
}

impl RustValueAdapter {
    fn name(self) -> &'static str {
        match self {
            Self::BTreeMap => "BTreeMap",
            Self::BTreeSet => "BTreeSet",
            Self::HashMap => "HashMap",
            Self::HashSet => "HashSet",
            Self::Rc { .. } => "Rc",
            Self::Arc { .. } => "Arc",
            Self::Ref => "Ref",
            Self::RefMut => "RefMut",
            Self::RefCell => "RefCell",
            Self::Cell => "Cell",
            Self::NonZero => "NonZero",
            Self::PathReference => "&Path",
            Self::CStrReference => "&CStr",
            Self::StrReference => "&str",
            Self::SliceReference => "slice reference",
            Self::BoxCStr => "Box<CStr>",
            Self::BoxStr => "Box<str>",
            Self::CString => "CString",
            Self::String => "String",
            Self::OsString => "OsString",
            Self::PathBuf => "PathBuf",
            Self::Vec => "Vec",
            Self::VecDeque => "VecDeque",
        }
    }

    fn resolve(self, root: &TypeInfo) -> Option<ValueLayout> {
        let layout = match self {
            Self::BTreeMap => {
                return collections::rust_btree_layout(root, BTreeKind::Map)
                    .map(|layout| ValueLayout::Extension(RustValueLayout::BTree(layout)))
            }
            Self::BTreeSet => {
                return collections::rust_btree_layout(root, BTreeKind::Set)
                    .map(|layout| ValueLayout::Extension(RustValueLayout::BTree(layout)))
            }
            Self::HashMap => {
                return collections::rust_hash_table_layout(root, HashTableKind::Map)
                    .map(|layout| ValueLayout::Extension(RustValueLayout::HashTable(layout)));
            }
            Self::HashSet => {
                return collections::rust_hash_table_layout(root, HashTableKind::Set)
                    .map(|layout| ValueLayout::Extension(RustValueLayout::HashTable(layout)));
            }
            Self::Rc { pointee_is_str } => {
                return wrappers::rust_reference_counted_layout(
                    root,
                    "Rc",
                    "value",
                    pointee_is_str,
                )
                .map(ValueLayout::CompositeStruct);
            }
            Self::Arc { pointee_is_str } => {
                return wrappers::rust_reference_counted_layout(
                    root,
                    "Arc",
                    "data",
                    pointee_is_str,
                )
                .map(ValueLayout::CompositeStruct);
            }
            Self::Ref | Self::RefMut => {
                return wrappers::rust_ref_layout(root).map(ValueLayout::CompositeStruct);
            }
            Self::RefCell => {
                return wrappers::rust_ref_cell_layout(root).map(ValueLayout::ProjectedStruct)
            }
            Self::Cell => {
                return wrappers::rust_cell_value_path(root).map(|value_path| {
                    ValueLayout::ProjectedValue {
                        value_path,
                        presentation: ProjectedValuePresentation::SingleField {
                            type_name: "Cell",
                            field_name: "value",
                        },
                    }
                });
            }
            Self::NonZero => {
                return wrappers::rust_nonzero_value_path(root).map(|value_path| {
                    ValueLayout::ProjectedValue {
                        value_path,
                        presentation: ProjectedValuePresentation::Transparent,
                    }
                });
            }
            Self::PathReference => sequences::validate_indirect_sequence_layout(
                root,
                layout::field_path(&["data_ptr"]),
                layout::field_path(&["length"]),
                IndirectSequenceKind::OpaqueByteString,
            ),
            Self::CStrReference | Self::BoxCStr => sequences::validate_indirect_sequence_layout(
                root,
                layout::field_path(&["data_ptr"]),
                layout::field_path(&["length"]),
                IndirectSequenceKind::NulTerminatedByteString,
            ),
            Self::StrReference => sequences::validate_indirect_sequence_layout(
                root,
                layout::field_path(&["data_ptr"]),
                layout::field_path(&["length"]),
                IndirectSequenceKind::Utf8String,
            ),
            Self::SliceReference => sequences::validate_indirect_sequence_layout(
                root,
                layout::field_path(&["data_ptr"]),
                layout::field_path(&["length"]),
                IndirectSequenceKind::PointerTarget,
            ),
            Self::BoxStr => sequences::validate_indirect_sequence_layout(
                root,
                layout::field_path(&["data_ptr"]),
                layout::field_path(&["length"]),
                IndirectSequenceKind::Utf8String,
            ),
            Self::CString => sequences::rust_c_string_layout(root),
            Self::String => sequences::rust_string_layout(root),
            Self::OsString => sequences::rust_os_string_layout(root),
            Self::PathBuf => sequences::rust_path_buf_layout(root),
            Self::Vec => sequences::rust_vec_layout(root),
            Self::VecDeque => sequences::rust_vec_deque_layout(root),
        };

        layout.map(ValueLayout::IndirectSequence)
    }

    fn layout_rejection_reason(self) -> &'static str {
        match self {
            Self::BTreeMap | Self::BTreeSet => concat!(
                "expected non-overlapping `root` and unsigned 4/8-byte `length` ",
                "members in the DWARF-described B-Tree map wrapper"
            ),
            Self::HashMap | Self::HashSet => concat!(
                "expected a supported std/hashbrown table path with byte control ",
                "pointer, pointer-width unsigned length and mask, and ",
                "non-overlapping metadata"
            ),
            Self::Rc { .. } | Self::Arc { .. } => concat!(
                "expected `ptr.pointer` to resolve to a supported thin or fat ",
                "allocation pointer whose target exposes value, strong, and weak ",
                "members with DWARF-derived widths"
            ),
            Self::Ref | Self::RefMut => concat!(
                "expected non-overlapping `value` and `borrow` wrappers with ",
                "matching 4/8-byte pointers and the rust-gdb borrow-state path"
            ),
            Self::RefCell => concat!(
                "expected non-overlapping `value` and signed `borrow` projections ",
                "within the root, with a supported 1/2/4/8/16-byte borrow width"
            ),
            Self::Cell => concat!(
                "expected two single-member wrappers ending in a known DWARF ",
                "value whose range is contained in the root"
            ),
            Self::NonZero => concat!(
                "expected one or two single-member wrappers ending in a nonzero-width ",
                "signed or unsigned DWARF integer contained in the root"
            ),
            Self::PathReference | Self::SliceReference => concat!(
                "expected non-overlapping `data_ptr` and unsigned `length` members ",
                "with equal nonzero DWARF widths and in-bounds ranges"
            ),
            Self::StrReference | Self::BoxStr => concat!(
                "expected non-overlapping `data_ptr` and unsigned `length` members ",
                "with equal nonzero widths and a one-byte unsigned pointer target"
            ),
            Self::CStrReference | Self::BoxCStr => concat!(
                "expected non-overlapping `data_ptr` and unsigned `length` members ",
                "with equal nonzero widths and a DWARF-described CStr target"
            ),
            Self::CString => concat!(
                "expected `inner.data_ptr` and `inner.length` with equal nonzero ",
                "widths and one-byte storage"
            ),
            Self::String => concat!(
                "expected `vec.buf[.inner].ptr` and `vec.len` through supported ",
                "single-member pointer wrappers, with pointer-width unsigned ",
                "length and a one-byte unsigned target"
            ),
            Self::OsString => concat!(
                "expected a supported Unix or Windows OsString Vec path with ",
                "pointer-width unsigned length and one-byte storage"
            ),
            Self::PathBuf => concat!(
                "expected `inner` to contain a supported OsString Vec path with ",
                "pointer-width unsigned length and one-byte storage"
            ),
            Self::Vec => concat!(
                "expected `buf[.inner].ptr` and `len` through supported pointer ",
                "wrappers, with equal nonzero pointer and unsigned length widths"
            ),
            Self::VecDeque => concat!(
                "expected a supported head/len or tail/head ring layout with a ",
                "DWARF pointer and non-overlapping pointer-width unsigned metadata"
            ),
        }
    }
}

#[cfg(test)]
mod tests;

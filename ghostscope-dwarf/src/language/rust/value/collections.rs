//! DWARF layout validation for Rust hash-table and B-Tree collections.

use crate::{strip_type_aliases, HashTableBucketOrder, HashTableOccupancy, TypeInfo};

use super::layout::{
    field_path, member_range, ranges_overlap, resolve_member_path, sole_struct_member,
    unique_named_member, unsigned_metadata_path, wrapped_pointer_path,
};
use crate::language::rust::plan::{
    BTreeKind, BTreeLayout, HashTableBucketLayout, HashTableKind, HashTableLayout,
};

pub(super) fn rust_hash_table_layout(
    root: &TypeInfo,
    kind: HashTableKind,
) -> Option<HashTableLayout> {
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

pub(super) fn rust_btree_layout(root: &TypeInfo, kind: BTreeKind) -> Option<BTreeLayout> {
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
    let root_size = match strip_type_aliases(&root_member.member_type) {
        TypeInfo::StructType { size, .. } | TypeInfo::VariantType { size, .. } => *size,
        _ => return None,
    };
    let TypeInfo::BaseType {
        size: length_size,
        encoding,
        ..
    } = strip_type_aliases(&length_member.member_type)
    else {
        return None;
    };
    if root_size == 0
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

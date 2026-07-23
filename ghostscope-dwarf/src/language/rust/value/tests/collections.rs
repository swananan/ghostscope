use super::*;

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
        Some(ValueLayout::Extension(RustValueLayout::HashTable(
            HashTableLayout {
                entry_type_path: field_path(&["base", "table"]),
                control_path: field_path(&["base", "table", "table", "ctrl", "pointer",]),
                length_path: field_path(&["base", "table", "table", "items"]),
                bucket_mask_path: field_path(&["base", "table", "table", "bucket_mask",]),
                occupancy: HashTableOccupancy::ControlByteHighBitClear,
                buckets: HashTableBucketLayout::ReverseFromControl,
                bucket_order: HashTableBucketOrder::Reverse,
                kind: HashTableKind::Map,
            },
        )))
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
    let Some(ValueLayout::Extension(RustValueLayout::HashTable(legacy_map))) =
        resolve_value_layout(&legacy_map, None)
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
    let Some(ValueLayout::Extension(RustValueLayout::HashTable(current_set))) =
        resolve_value_layout(&current_set, None)
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
    let Some(ValueLayout::Extension(RustValueLayout::HashTable(legacy_set))) = resolve_value_layout(
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
        let Some(ValueLayout::Extension(RustValueLayout::HashTable(layout))) =
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
        Some(ValueLayout::Extension(RustValueLayout::BTree(
            BTreeLayout {
                map_path: Vec::new(),
                root_path: field_path(&["root"]),
                length_path: field_path(&["length"]),
                kind: BTreeKind::Map,
            },
        )))
    );

    let set = rust_btree_collection_type(
        "alloc::collections::btree::set::BTreeSet<i32>",
        BTreeKind::Set,
        4,
        SourceLanguage::Rust,
    );
    assert_eq!(
        resolve_value_layout(&set, None),
        Some(ValueLayout::Extension(RustValueLayout::BTree(
            BTreeLayout {
                map_path: field_path(&["map"]),
                root_path: field_path(&["map", "root"]),
                length_path: field_path(&["map", "length"]),
                kind: BTreeKind::Set,
            },
        )))
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

//! Semantic value presentations carried alongside physical DWARF types.

use crate::TypeInfo;
use serde::{Deserialize, Serialize};

/// Number of bytes used to encode the original length of an indirect byte
/// sequence before its captured payload.
pub const INDIRECT_BYTES_LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<u64>();

/// Number of bytes used by an indirect sequence header. The first `u64` is
/// the original element count and the second is the captured element count.
pub const INDIRECT_SEQUENCE_HEADER_SIZE: usize = std::mem::size_of::<u64>() * 2;

/// Offset of the captured element count in an indirect sequence header.
pub const INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET: usize = std::mem::size_of::<u64>();

/// Fixed bytes before every nested child payload. The first byte stores a
/// `VariableStatus`; the remaining bytes keep child payloads naturally
/// separated and leave room for protocol evolution.
pub const NESTED_VALUE_CHILD_HEADER_SIZE: usize = std::mem::size_of::<u64>();

/// Offset of a nested child's `VariableStatus` within its fixed header.
pub const NESTED_VALUE_CHILD_STATUS_OFFSET: usize = 0;

/// Number of bytes used by a bounded hash-table payload. The header stores the
/// logical item count, table capacity, captured bucket count, and byte offset
/// of the bucket payload. Captured occupancy bytes and any unused reserved
/// occupancy headroom sit between the header and the bucket payload.
pub const HASH_TABLE_HEADER_SIZE: usize = std::mem::size_of::<u64>() * 4;

/// Offset of the runtime table capacity in a bounded hash-table header.
pub const HASH_TABLE_CAPACITY_OFFSET: usize = std::mem::size_of::<u64>();

/// Offset of the captured bucket count in a bounded hash-table header.
pub const HASH_TABLE_CAPTURED_BUCKETS_OFFSET: usize = std::mem::size_of::<u64>() * 2;

/// Offset of the bucket payload offset in a bounded hash-table header.
pub const HASH_TABLE_BUCKET_DATA_OFFSET: usize = std::mem::size_of::<u64>() * 3;

/// Number of bytes in a bounded B-Tree payload header. It stores the logical
/// item count, reserved node-slot count, and captured item count.
pub const BTREE_HEADER_SIZE: usize = std::mem::size_of::<u64>() * 3;

/// Offset of the reserved node-slot count in a B-Tree payload header.
pub const BTREE_NODE_SLOT_COUNT_OFFSET: usize = std::mem::size_of::<u64>();

/// Offset of the captured item count in a B-Tree payload header.
pub const BTREE_CAPTURED_ITEM_COUNT_OFFSET: usize = std::mem::size_of::<u64>() * 2;

/// Fixed metadata at the start of each captured B-Tree node slot. It stores
/// the node address, node height, and initialized key count.
pub const BTREE_NODE_HEADER_SIZE: usize = std::mem::size_of::<u64>() * 3;

/// Offset of a node's height in its B-Tree payload slot.
pub const BTREE_NODE_HEIGHT_OFFSET: usize = std::mem::size_of::<u64>();

/// Offset of a node's initialized key count in its B-Tree payload slot.
pub const BTREE_NODE_LENGTH_OFFSET: usize = std::mem::size_of::<u64>() * 2;

/// Physical order of captured buckets relative to their occupancy metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashTableBucketOrder {
    /// Bucket `i` is stored at increasing offsets from a dedicated data pointer.
    Forward,
    /// Bucket `i` is stored immediately before the control pointer, so a
    /// contiguous capture appears in reverse control-index order.
    Reverse,
}

/// Physical occupancy metadata stored for each captured hash-table bucket.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashTableOccupancy {
    /// One hashbrown control byte; its high bit is clear for occupied buckets.
    #[default]
    ControlByteHighBitClear,
    /// One fixed-width hash word; zero marks an empty bucket.
    NonZeroWord { word_size: u64 },
}

impl HashTableOccupancy {
    /// Number of payload bytes that describe one bucket's occupancy.
    pub fn byte_width(self) -> Option<u64> {
        match self {
            Self::ControlByteHighBitClear => Some(1),
            Self::NonZeroWord { word_size } => (word_size > 0).then_some(word_size),
        }
    }
}

/// One source-language value projected from a DWARF-described hash entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashTableFieldPresentation {
    pub offset: u64,
    pub field_type: Box<TypeInfo>,
}

/// Source-language interpretation of one physical hash-table entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HashTableEntryPresentation {
    Map {
        key: HashTableFieldPresentation,
        value: HashTableFieldPresentation,
    },
    Set {
        value: HashTableFieldPresentation,
    },
}

/// One logical B-Tree value embedded in a physical initialized-slot wrapper.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BTreeFieldPresentation {
    pub slot_stride: u64,
    pub value_offset: u64,
    pub field_type: Box<TypeInfo>,
}

/// Source-language interpretation of keys and values captured from B-Tree
/// node arrays.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BTreeEntryPresentation {
    Map {
        key: BTreeFieldPresentation,
        value: BTreeFieldPresentation,
    },
    Set {
        value: BTreeFieldPresentation,
    },
}

/// Type and semantic presentation for one statically reserved nested payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NestedValuePresentation {
    pub payload_len: u64,
    pub type_info: Box<TypeInfo>,
    pub presentation: Box<ValuePresentation>,
}

/// One nested payload slot at a fixed offset from its parent's payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NestedValueChildPresentation {
    pub slot_offset: u64,
    pub value: Box<NestedValuePresentation>,
}

/// One projected-view member whose raw bytes have a semantic child sidecar.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NestedValueFieldPresentation {
    pub field_index: u64,
    pub child: NestedValueChildPresentation,
}

/// Placement of recursively captured values after an existing root payload.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NestedValueChildrenPresentation {
    ProjectedValue {
        child: Box<NestedValueChildPresentation>,
    },
    ProjectedView {
        fields: Vec<NestedValueFieldPresentation>,
    },
    Sequence {
        first_slot_offset: u64,
        slot_stride: u64,
        slot_count: u64,
        element: Box<NestedValuePresentation>,
    },
}

/// User-space presentation selected for a captured value.
///
/// `Dwarf` preserves the existing physical-layout formatter. Other variants
/// define both the capture payload contract and its semantic rendering.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValuePresentation {
    #[default]
    Dwarf,
    /// A UTF-8 string encoded as an original-length `u64` followed by captured
    /// bytes. The byte payload may be shorter than the original length.
    Utf8String,
    /// A contiguous sequence encoded as original and captured element counts,
    /// followed by complete element bytes. The element type and stride come
    /// from DWARF rather than a source-language ABI assumption.
    Sequence {
        element_type: Box<TypeInfo>,
        element_stride: u64,
    },
    /// An arbitrary byte string using the same length-prefixed payload as
    /// `Utf8String`. Invalid UTF-8 bytes are rendered with `\xNN` escapes.
    ByteString,
    /// A projected DWARF value rendered as one named field of a semantic
    /// wrapper. The payload is the raw bytes of `type_info`.
    SingleField {
        type_name: String,
        field_name: String,
    },
    /// A projected struct whose signed state field selects one of two summary
    /// labels. The payload is the raw inline byte layout of `type_info`.
    SignedStateStruct {
        state_field: String,
        non_negative_label: String,
        negative_label: String,
    },
    /// A reference-counted struct whose summary exposes strong and weak
    /// counters. `implicit_weak` removes implementation-owned weak entries
    /// from both the summary and the rendered weak field.
    ReferenceCountedStruct {
        strong_field: String,
        weak_field: String,
        implicit_weak: u64,
    },
    /// A bounded sparse-table capture containing occupancy metadata and
    /// physical entries. Entry stride and projected key/value fields come from
    /// DWARF; the source-language adapter selects the occupancy semantics.
    HashTable {
        entry_stride: u64,
        bucket_order: HashTableBucketOrder,
        #[serde(default)]
        occupancy: HashTableOccupancy,
        entry: HashTableEntryPresentation,
    },
    /// A bounded breadth-first snapshot of Rust B-Tree nodes. Node capacity,
    /// physical slot strides, embedded value offsets, and value types all come
    /// from DWARF. User space reconstructs source order from the node slots.
    BTree {
        node_capacity: u64,
        entry: BTreeEntryPresentation,
    },
    /// An existing semantic root payload followed by fixed child slots. Child
    /// locations and presentations are compile-time metadata; each slot
    /// carries its own runtime status.
    Nested {
        root: Box<ValuePresentation>,
        root_payload_len: u64,
        children: Box<NestedValueChildrenPresentation>,
    },
}

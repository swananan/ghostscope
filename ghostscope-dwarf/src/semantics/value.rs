//! Semantic capture plans for values whose source-language meaning is not
//! represented by their physical DWARF aggregate alone.

use super::TypeProjection;
use ghostscope_protocol::ValuePresentation;

/// A language-selected presentation and the physical reads needed to produce
/// its protocol payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueReadPlan {
    pub presentation: ValuePresentation,
    pub capture: ValueCapturePlan,
}

/// Runtime source of a ring sequence's logical element count.
#[derive(Debug, Clone, PartialEq)]
pub enum RingSequenceLength {
    /// Read the element count directly from this member.
    Explicit(TypeProjection),
    /// Compute the wrapped distance from the start index to this end index.
    End(TypeProjection),
}

/// One DWARF-derived address operation used to locate a projected value.
#[derive(Debug, Clone, PartialEq)]
pub enum ProjectedValueStep {
    /// Add a concrete member offset to the current address.
    Member { offset: u64 },
    /// Read a pointer of the exact DWARF width from the current address.
    Dereference { pointer_size: u64 },
}

/// Runtime path and final semantic type for one projected value.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedValueRead {
    pub steps: Vec<ProjectedValueStep>,
    pub resolved_type: crate::ResolvedType,
}

/// One field assembled into a synthetic projected-view payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ProjectedViewField {
    pub output_offset: u64,
    pub value: ProjectedValueRead,
}

/// One initialized-slot array embedded in a Rust B-Tree leaf-node layout.
#[derive(Debug, Clone, PartialEq)]
pub struct BTreeArrayCapture {
    pub offset: u64,
    pub slot_stride: u64,
}

/// Child-pointer array embedded in the DWARF-described internal-node layout.
#[derive(Debug, Clone, PartialEq)]
pub struct BTreeEdgesCapture {
    pub offset_from_leaf: u64,
    pub slot_stride: u64,
    pub pointer_offset: u64,
    pub pointer_size: u64,
    pub edge_count: u64,
}

/// Runtime source of physical hash-table bucket bytes.
#[derive(Debug, Clone, PartialEq)]
pub enum HashTableBucketSource {
    /// Buckets start at a dedicated pointer projected from the descriptor.
    Forward { data: TypeProjection },
    /// Buckets are stored immediately before the control-byte pointer.
    ReverseFromControl,
    /// Rust 1.35 stores pairs after aligned pointer-sized hash words in one
    /// allocation. The low pointer bit is an implementation tag.
    LegacyAfterControl {
        entry_alignment: u64,
        pointer_tag_mask: u64,
    },
}

/// Physical capture strategy used by a semantic value adapter.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueCapturePlan {
    /// Read an embedded value at a DWARF-derived member projection and present
    /// it using the projected type rather than the physical wrapper type.
    ProjectedValue { value: TypeProjection },
    /// Read the physical root value in place, but register and format it using
    /// a DWARF-derived semantic view of selected embedded fields.
    InlineView { output_type: crate::TypeInfo },
    /// Assemble a synthetic struct from independently projected values. Every
    /// member offset, pointer width, and final type is derived from DWARF.
    ProjectedView {
        output_type: crate::TypeInfo,
        fields: Vec<ProjectedViewField>,
    },
    /// Read a pointer and length from an aggregate, then capture a bounded byte
    /// sequence from the pointer.
    IndirectBytes {
        data: TypeProjection,
        length: TypeProjection,
    },
    /// Read a pointer and logical element count from an aggregate, then capture
    /// a bounded number of complete, contiguous elements.
    IndirectSequence {
        data: TypeProjection,
        length: TypeProjection,
        element_stride: u64,
    },
    /// Read a ring-buffer descriptor, then normalize up to two physical
    /// segments into one logical sequence payload.
    IndirectRingSequence {
        data: TypeProjection,
        start: TypeProjection,
        length: Box<RingSequenceLength>,
        capacity: TypeProjection,
        element_stride: u64,
    },
    /// Read hash-table metadata and capture a bounded prefix of occupancy bytes
    /// plus their corresponding physical entries. The source-language adapter
    /// provides occupancy semantics; all paths, widths, and entry layout are
    /// derived from DWARF.
    IndirectHashTable {
        control: TypeProjection,
        length: TypeProjection,
        bucket_mask: TypeProjection,
        entry_stride: u64,
        occupancy: ghostscope_protocol::HashTableOccupancy,
        buckets: HashTableBucketSource,
        bucket_order: ghostscope_protocol::HashTableBucketOrder,
    },
    /// Capture a bounded breadth-first snapshot of a Rust B-Tree. Root and
    /// node metadata are projections of concrete DIEs; array capacities,
    /// strides, embedded pointer offsets, and widths are likewise DWARF
    /// derived.
    IndirectBTree {
        root_pointer: TypeProjection,
        root_height: TypeProjection,
        length: TypeProjection,
        node_length: TypeProjection,
        keys: BTreeArrayCapture,
        values: Option<BTreeArrayCapture>,
        edges: BTreeEdgesCapture,
        node_capacity: u64,
    },
}

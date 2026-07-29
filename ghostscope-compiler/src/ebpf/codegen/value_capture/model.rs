#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) enum RingSequenceLengthSource {
    Explicit {
        offset: u64,
        access_size: ghostscope_dwarf::MemoryAccessSize,
    },
    End {
        offset: u64,
        access_size: ghostscope_dwarf::MemoryAccessSize,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) enum ProjectedViewStep {
    Member {
        offset: u64,
    },
    Dereference {
        pointer_size: ghostscope_dwarf::MemoryAccessSize,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct ProjectedViewFieldSource {
    pub(in crate::ebpf::codegen) output_offset: usize,
    pub(in crate::ebpf::codegen) value_len: usize,
    pub(in crate::ebpf::codegen) steps: Vec<ProjectedViewStep>,
    pub(in crate::ebpf::codegen) capture: ghostscope_dwarf::ProjectedViewFieldCapture,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) struct BTreeArraySource {
    pub(in crate::ebpf::codegen) offset: u64,
    pub(in crate::ebpf::codegen) slot_stride: u64,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) struct BTreeEdgesSource {
    pub(in crate::ebpf::codegen) offset_from_leaf: u64,
    pub(in crate::ebpf::codegen) slot_stride: u64,
    pub(in crate::ebpf::codegen) pointer_offset: u64,
    pub(in crate::ebpf::codegen) pointer_access_size: ghostscope_dwarf::MemoryAccessSize,
    pub(in crate::ebpf::codegen) edge_count: u64,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) enum HashTableBucketSource {
    Forward {
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
    },
    ReverseFromControl,
    LegacyAfterControl {
        entry_alignment: u64,
        pointer_tag_mask: u64,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct NestedValueSource {
    pub(in crate::ebpf::codegen) output_type: ghostscope_dwarf::TypeInfo,
    pub(in crate::ebpf::codegen) presentation: ghostscope_dwarf::ValuePresentation,
    pub(in crate::ebpf::codegen) root_payload_len: usize,
    pub(in crate::ebpf::codegen) total_len: usize,
    pub(in crate::ebpf::codegen) root: NestedValueRootSource,
    pub(in crate::ebpf::codegen) children: NestedValueChildrenSource,
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) enum NestedValueRootSource {
    ProjectedValue {
        offset: u64,
        len: usize,
    },
    InlineView {
        len: usize,
    },
    ProjectedView {
        fields: Vec<ProjectedViewFieldSource>,
    },
    IndirectBytes {
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        excluded_tail_bytes: u64,
        max_len: usize,
    },
    IndirectSequence {
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        element_stride: u64,
        max_elements: usize,
        max_len: usize,
    },
    IndirectRingSequence {
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
        start_offset: u64,
        start_access_size: ghostscope_dwarf::MemoryAccessSize,
        length: RingSequenceLengthSource,
        capacity_offset: u64,
        capacity_access_size: ghostscope_dwarf::MemoryAccessSize,
        element_stride: u64,
        max_elements: usize,
        max_len: usize,
    },
    IndirectHashTable {
        control_offset: u64,
        control_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        bucket_mask_offset: u64,
        bucket_mask_access_size: ghostscope_dwarf::MemoryAccessSize,
        entry_stride: u64,
        occupancy: ghostscope_dwarf::HashTableOccupancy,
        buckets: HashTableBucketSource,
        bucket_order: ghostscope_dwarf::HashTableBucketOrder,
        max_buckets: usize,
    },
    IndirectBTree {
        root_pointer_offset: u64,
        root_pointer_access_size: ghostscope_dwarf::MemoryAccessSize,
        root_height_offset: u64,
        root_height_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        node_length_offset: u64,
        node_length_access_size: ghostscope_dwarf::MemoryAccessSize,
        keys: BTreeArraySource,
        values: Option<BTreeArraySource>,
        edges: BTreeEdgesSource,
        node_capacity: u64,
        max_nodes: usize,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) enum NestedValueChildrenSource {
    None,
    ProjectedValue {
        slot_offset: usize,
        child: Box<NestedValueSource>,
    },
    ProjectedView {
        fields: Vec<NestedValueFieldSource>,
    },
    Sequence {
        first_slot_offset: usize,
        slot_stride: usize,
        slot_count: usize,
        element: Box<NestedValueSource>,
        metadata: NestedSequenceMetadataSource,
    },
    HashTable {
        first_slot_offset: usize,
        bucket_slot_stride: usize,
        bucket_count: usize,
        fields: Vec<NestedHashTableFieldSource>,
        metadata: NestedHashTableMetadataSource,
    },
    Variant {
        fields: Vec<NestedValueVariantFieldSource>,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct NestedValueFieldSource {
    pub(in crate::ebpf::codegen) field_index: usize,
    pub(in crate::ebpf::codegen) slot_offset: usize,
    pub(in crate::ebpf::codegen) steps: Vec<ProjectedViewStep>,
    pub(in crate::ebpf::codegen) child: Box<NestedValueSource>,
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct NestedHashTableFieldSource {
    pub(in crate::ebpf::codegen) field_index: usize,
    pub(in crate::ebpf::codegen) entry_offset: u64,
    pub(in crate::ebpf::codegen) slot_offset: usize,
    pub(in crate::ebpf::codegen) child: Box<NestedValueSource>,
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct NestedValueVariantFieldSource {
    pub(in crate::ebpf::codegen) part_index: usize,
    pub(in crate::ebpf::codegen) variant_index: usize,
    pub(in crate::ebpf::codegen) member_index: usize,
    pub(in crate::ebpf::codegen) payload_field_index: usize,
    pub(in crate::ebpf::codegen) field: NestedValueFieldSource,
    pub(in crate::ebpf::codegen) condition: NestedValueVariantConditionSource,
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) enum NestedValueVariantConditionSource {
    Always,
    Discriminant {
        offset: u64,
        access_size: ghostscope_dwarf::MemoryAccessSize,
        signed: bool,
        ranges: Vec<ghostscope_dwarf::DiscriminantRange>,
        inverted: bool,
    },
}

#[derive(Debug, Clone)]
pub(in crate::ebpf::codegen) struct NestedSequenceMetadataSource {
    pub(in crate::ebpf::codegen) data_offset: u64,
    pub(in crate::ebpf::codegen) data_access_size: ghostscope_dwarf::MemoryAccessSize,
    pub(in crate::ebpf::codegen) element_stride: u64,
    pub(in crate::ebpf::codegen) ring: Option<NestedRingMetadataSource>,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) struct NestedHashTableMetadataSource {
    pub(in crate::ebpf::codegen) control_offset: u64,
    pub(in crate::ebpf::codegen) control_access_size: ghostscope_dwarf::MemoryAccessSize,
    pub(in crate::ebpf::codegen) entry_stride: u64,
    pub(in crate::ebpf::codegen) occupancy: ghostscope_dwarf::HashTableOccupancy,
    pub(in crate::ebpf::codegen) buckets: HashTableBucketSource,
}

#[derive(Debug, Clone, Copy)]
pub(in crate::ebpf::codegen) struct NestedRingMetadataSource {
    pub(in crate::ebpf::codegen) start_offset: u64,
    pub(in crate::ebpf::codegen) start_access_size: ghostscope_dwarf::MemoryAccessSize,
    pub(in crate::ebpf::codegen) capacity_offset: u64,
    pub(in crate::ebpf::codegen) capacity_access_size: ghostscope_dwarf::MemoryAccessSize,
}

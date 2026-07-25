//! Code generation for instructions
//!
//! This module handles the conversion from statements to compiled instructions
//! and generates LLVM IR for individual instructions.

use super::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::{PrintStatement, Program, Statement};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_protocol::trace_event::{
    BacktraceFrameData, BacktraceStatus, EndInstructionData, InstructionHeader,
    PrintComplexFormatData, PrintComplexVariableData, PrintStringIndexData, PrintVariableIndexData,
    VariableStatus, BACKTRACE_DATA_ERROR_CODE_OFFSET, BACKTRACE_DATA_FLAGS_OFFSET,
    BACKTRACE_DATA_FRAME_COUNT_OFFSET, BACKTRACE_DATA_REQUESTED_DEPTH_OFFSET, BACKTRACE_DATA_SIZE,
    BACKTRACE_DATA_STATUS_OFFSET, BACKTRACE_ERROR_FRAME_POINTER_READ,
    BACKTRACE_ERROR_NEXT_CFA_NOT_ADVANCING, BACKTRACE_ERROR_NEXT_CFA_ZERO,
    BACKTRACE_ERROR_NEXT_IP_BELOW_USER, BACKTRACE_ERROR_NEXT_IP_KERNEL_LIKE, BACKTRACE_ERROR_NONE,
    BACKTRACE_ERROR_RETURN_ADDRESS_READ, BACKTRACE_FLAG_FULL, BACKTRACE_FLAG_INLINE,
    BACKTRACE_FLAG_RAW, BACKTRACE_FRAME_DATA_SIZE, BACKTRACE_FRAME_FLAGS_OFFSET,
    BACKTRACE_FRAME_MODULE_COOKIE_OFFSET, BACKTRACE_FRAME_PC_OFFSET, BACKTRACE_FRAME_RAW_IP_OFFSET,
    EXPR_ERROR_DATA_ERROR_CODE_OFFSET, EXPR_ERROR_DATA_FAILING_ADDR_OFFSET,
    EXPR_ERROR_DATA_FLAGS_OFFSET, EXPR_ERROR_DATA_SIZE, EXPR_ERROR_DATA_STRING_INDEX_OFFSET,
    INSTRUCTION_HEADER_DATA_LENGTH_OFFSET, INSTRUCTION_HEADER_SIZE,
    PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_LEN_OFFSET, PRINT_COMPLEX_FORMAT_ARG_ACCESS_PATH_OFFSET,
    PRINT_COMPLEX_FORMAT_ARG_FIXED_HEADER_LEN, PRINT_COMPLEX_FORMAT_ARG_STATUS_OFFSET,
    PRINT_COMPLEX_FORMAT_ARG_TYPE_INDEX_OFFSET, PRINT_COMPLEX_FORMAT_DATA_ARG_COUNT_OFFSET,
    VARIABLE_READ_ERROR_PAYLOAD_ADDR_OFFSET, VARIABLE_READ_ERROR_PAYLOAD_ERRNO_OFFSET,
    VARIABLE_READ_ERROR_PAYLOAD_LEN,
};
use ghostscope_protocol::{InstructionType, TraceContext, TypeKind};
use inkwell::values::{BasicValueEnum, IntValue, PointerValue};
use inkwell::AddressSpace;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Parameters for generating a PrintComplexVariable with runtime read
#[derive(Debug, Clone)]
struct PrintVarRuntimeMeta {
    var_name_index: u16,
    type_index: u16,
    access_path: String,
    data_len_limit: usize,
}

#[derive(Debug, Clone, Copy)]
enum RingSequenceLengthSource {
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
enum ProjectedViewStep {
    Member {
        offset: u64,
    },
    Dereference {
        pointer_size: ghostscope_dwarf::MemoryAccessSize,
    },
}

#[derive(Debug, Clone)]
struct ProjectedViewFieldSource {
    output_offset: usize,
    value_len: usize,
    steps: Vec<ProjectedViewStep>,
    capture: ghostscope_dwarf::ProjectedViewFieldCapture,
}

#[derive(Debug, Clone, Copy)]
struct BTreeArraySource {
    offset: u64,
    slot_stride: u64,
}

#[derive(Debug, Clone, Copy)]
struct BTreeEdgesSource {
    offset_from_leaf: u64,
    slot_stride: u64,
    pointer_offset: u64,
    pointer_access_size: ghostscope_dwarf::MemoryAccessSize,
    edge_count: u64,
}

#[derive(Debug, Clone, Copy)]
enum HashTableBucketSource {
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
struct NestedValueSource {
    output_type: ghostscope_dwarf::TypeInfo,
    presentation: ghostscope_dwarf::ValuePresentation,
    root_payload_len: usize,
    total_len: usize,
    root: NestedValueRootSource,
    children: NestedValueChildrenSource,
}

#[derive(Debug, Clone)]
enum NestedValueRootSource {
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
enum NestedValueChildrenSource {
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
}

#[derive(Debug, Clone)]
struct NestedValueFieldSource {
    field_index: usize,
    slot_offset: usize,
    steps: Vec<ProjectedViewStep>,
    child: Box<NestedValueSource>,
}

#[derive(Debug, Clone)]
struct NestedSequenceMetadataSource {
    data_offset: u64,
    data_access_size: ghostscope_dwarf::MemoryAccessSize,
    element_stride: u64,
    ring: Option<NestedRingMetadataSource>,
}

#[derive(Debug, Clone, Copy)]
struct NestedRingMetadataSource {
    start_offset: u64,
    start_access_size: ghostscope_dwarf::MemoryAccessSize,
    capacity_offset: u64,
    capacity_access_size: ghostscope_dwarf::MemoryAccessSize,
}

/// Source for complex formatted argument data
#[derive(Debug, Clone)]
enum ComplexArgSource<'ctx> {
    RuntimeRead {
        address: ghostscope_dwarf::PlannedAddress,
        dwarf_type: ghostscope_dwarf::TypeInfo,
        module_for_offsets: Option<String>,
    },
    /// Memory dump from a pointer/byte address with a static length
    MemDump {
        address: RuntimeAddress<'ctx>,
        len: usize,
    },
    /// Memory dump with dynamic runtime length; bytes read up to min(len_value, max_len)
    MemDumpDynamic {
        address: RuntimeAddress<'ctx>,
        len_value: inkwell::values::IntValue<'ctx>,
        max_len: usize,
    },
    /// Bounded byte capture through a pointer-and-length descriptor.
    IndirectBytes {
        descriptor: RuntimeAddress<'ctx>,
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        excluded_tail_bytes: u64,
        max_len: usize,
    },
    /// Bounded capture of complete elements through a pointer-and-count
    /// descriptor.
    IndirectSequence {
        descriptor: RuntimeAddress<'ctx>,
        data_offset: u64,
        data_access_size: ghostscope_dwarf::MemoryAccessSize,
        length_offset: u64,
        length_access_size: ghostscope_dwarf::MemoryAccessSize,
        element_stride: u64,
        max_elements: usize,
        max_len: usize,
    },
    /// Bounded capture of a logical sequence split across a ring buffer.
    IndirectRingSequence {
        descriptor: RuntimeAddress<'ctx>,
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
    /// Bounded capture of a sparse hash-table prefix. Occupancy metadata and
    /// bucket bytes are stored separately in one semantic payload.
    IndirectHashTable {
        descriptor: RuntimeAddress<'ctx>,
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
        max_len: usize,
    },
    /// Bounded breadth-first capture of Rust B-Tree nodes.
    IndirectBTree {
        descriptor: RuntimeAddress<'ctx>,
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
        max_len: usize,
    },
    /// Assemble a synthetic struct from independently projected memory reads.
    ProjectedView {
        descriptor: RuntimeAddress<'ctx>,
        fields: Vec<ProjectedViewFieldSource>,
    },
    /// A root semantic capture plus fixed child sidecars.
    NestedValue {
        descriptor: RuntimeAddress<'ctx>,
        value: Box<NestedValueSource>,
    },
    ImmediateBytes {
        bytes: Vec<u8>,
    },
    AddressValue {
        address: ghostscope_dwarf::PlannedAddress,
        module_for_offsets: Option<String>,
    },
    ComputedAddress {
        address: RuntimeAddress<'ctx>,
    },
    // Newly added: a value computed in LLVM at runtime (e.g., expression result)
    ComputedInt {
        value: inkwell::values::IntValue<'ctx>,
        byte_len: usize, // typically 8
    },
}

/// Argument descriptor for PrintComplexFormat
#[derive(Debug, Clone)]
struct ComplexArg<'ctx> {
    var_name_index: u16,
    type_index: u16,
    access_path: Vec<u8>,
    data_len: usize,
    source: ComplexArgSource<'ctx>,
}

fn print_complex_format_instruction_budget(
    max_trace_event_size: usize,
    bytes_reserved_so_far: usize,
) -> usize {
    let end_instruction_size =
        std::mem::size_of::<InstructionHeader>() + std::mem::size_of::<EndInstructionData>();
    let event_budget = max_trace_event_size
        .saturating_sub(bytes_reserved_so_far)
        .saturating_sub(end_instruction_size);
    let instruction_budget_cap = std::mem::size_of::<InstructionHeader>() + u16::MAX as usize;
    event_budget.min(instruction_budget_cap)
}

fn distribute_budget_fairly(caps: &[usize], budget: usize) -> Vec<usize> {
    let mut allocations = vec![0; caps.len()];
    let mut active: Vec<usize> = caps
        .iter()
        .enumerate()
        .filter_map(|(idx, cap)| (*cap > 0).then_some(idx))
        .collect();
    let mut remaining = budget;

    while remaining > 0 && !active.is_empty() {
        let share = remaining / active.len();
        if share == 0 {
            for &idx in active.iter().take(remaining) {
                allocations[idx] += 1;
            }
            break;
        }

        let mut consumed = 0usize;
        let mut next_active = Vec::with_capacity(active.len());
        for idx in active {
            let cap_left = caps[idx].saturating_sub(allocations[idx]);
            let take = share.min(cap_left);
            allocations[idx] += take;
            consumed += take;
            if allocations[idx] < caps[idx] {
                next_active.push(idx);
            }
        }

        if consumed == 0 {
            break;
        }

        remaining = remaining.saturating_sub(consumed);
        active = next_active;
    }

    allocations
}

fn allocate_dynamic_payload_reservations(max_lens: &[usize], available: usize) -> Vec<usize> {
    if max_lens.is_empty() || available == 0 {
        return vec![0; max_lens.len()];
    }

    let base_caps = max_lens
        .iter()
        .map(|max_len| (*max_len).min(VARIABLE_READ_ERROR_PAYLOAD_LEN))
        .collect::<Vec<_>>();
    let base_budget = available.min(base_caps.iter().sum());
    let mut reservations = distribute_budget_fairly(&base_caps, base_budget);
    let remaining_budget = available.saturating_sub(reservations.iter().sum::<usize>());
    if remaining_budget == 0 {
        return reservations;
    }

    let extra_caps: Vec<usize> = max_lens
        .iter()
        .zip(reservations.iter())
        .map(|(max_len, reserved)| max_len.saturating_sub(*reserved))
        .collect();
    let extras = distribute_budget_fairly(&extra_caps, remaining_budget);
    for (reservation, extra) in reservations.iter_mut().zip(extras) {
        *reservation += extra;
    }

    reservations
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    fn build_entry_alloca<T>(&self, ty: T, name: &str) -> Result<PointerValue<'ctx>>
    where
        T: inkwell::types::BasicType<'ctx>,
    {
        let current_block = self.builder.get_insert_block().ok_or_else(|| {
            CodeGenError::LLVMError("no current block for stack allocation".to_string())
        })?;
        let function = self.current_function("allocate stack scratch")?;
        let entry_block = function.get_first_basic_block().ok_or_else(|| {
            CodeGenError::LLVMError("no entry block for stack allocation".to_string())
        })?;

        if let Some(first_instruction) = entry_block.get_first_instruction() {
            self.builder.position_before(&first_instruction);
        } else {
            self.builder.position_at_end(entry_block);
        }
        let alloca = self
            .builder
            .build_alloca(ty, name)
            .map_err(|error| CodeGenError::LLVMError(error.to_string()))?;
        self.builder.position_at_end(current_block);
        Ok(alloca)
    }
}

mod args;
mod backtrace;
mod expr_error;
mod format;
mod instruction_common;
mod print_complex_variable;
mod print_string_index;
mod print_variable_index;
mod statements;
mod types;

#[cfg(test)]
mod tests;

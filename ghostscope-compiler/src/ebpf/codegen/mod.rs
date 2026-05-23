//! Code generation for instructions
//!
//! This module handles the conversion from statements to compiled instructions
//! and generates LLVM IR for individual instructions.

use super::context::{CodeGenError, EbpfContext, Result, RuntimeAddress};
use crate::script::{PrintStatement, Program, Statement};
use aya_ebpf_bindings::bindings::bpf_func_id::BPF_FUNC_probe_read_user;
use ghostscope_protocol::trace_event::{
    BacktraceData, EndInstructionData, InstructionHeader, PrintComplexFormatData,
    PrintComplexVariableData, PrintStringIndexData, PrintVariableIndexData, VariableStatus,
};
use ghostscope_protocol::{InstructionType, TraceContext, TypeKind};
use inkwell::values::{BasicValueEnum, IntValue};
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
    ImmediateBytes {
        bytes: Vec<u8>,
    },
    AddressValue {
        address: ghostscope_dwarf::PlannedAddress,
        module_for_offsets: Option<String>,
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

const DYNAMIC_READ_ERROR_PAYLOAD_LEN: usize = 12;

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

    let base_caps = vec![DYNAMIC_READ_ERROR_PAYLOAD_LEN; max_lens.len()];
    let base_budget = available.min(DYNAMIC_READ_ERROR_PAYLOAD_LEN.saturating_mul(max_lens.len()));
    let mut reservations = distribute_budget_fairly(&base_caps, base_budget);
    let remaining_budget = available.saturating_sub(reservations.iter().sum::<usize>());
    if remaining_budget == 0 {
        return reservations;
    }

    let extra_caps: Vec<usize> = max_lens
        .iter()
        .zip(reservations.iter())
        .map(|(max_len, reserved)| {
            max_len
                .max(&DYNAMIC_READ_ERROR_PAYLOAD_LEN)
                .saturating_sub(*reserved)
        })
        .collect();
    let extras = distribute_budget_fairly(&extra_caps, remaining_budget);
    for (reservation, extra) in reservations.iter_mut().zip(extras) {
        *reservation += extra;
    }

    reservations
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

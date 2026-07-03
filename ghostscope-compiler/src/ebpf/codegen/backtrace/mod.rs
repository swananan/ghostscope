use super::*;
use crate::script::BacktraceStatement;
use aya_ebpf_bindings::bindings::bpf_func_id::{BPF_FUNC_map_lookup_elem, BPF_FUNC_tail_call};
use ghostscope_dwarf::{CompactUnwindRow, MemoryAccessSize, ModuleAddress};
use inkwell::basic_block::BasicBlock;
use inkwell::values::BasicMetadataValueEnum;
use std::path::PathBuf;

use plan::{BacktraceEmitMode, BacktraceInstructionPlan, BPF_INLINE_BACKTRACE_FRAME_LIMIT};

const X86_64_DWARF_RIP: u16 = 16;
const X86_64_DWARF_RBP: u16 = 6;
const X86_64_DWARF_RSP: u16 = 7;
const BPF_BACKTRACE_FRAMES_PER_TAIL_CALL: u8 = 4;
const BPF_BACKTRACE_MAX_STEP_INVOCATIONS: u8 = 32;
const BPF_BACKTRACE_STEP_PROG_INDEX: u32 = 0;

struct RuntimeBtUnwindRow<'ctx> {
    found: IntValue<'ctx>,
    cfa_register: IntValue<'ctx>,
    cfa_offset: IntValue<'ctx>,
    ra_kind: IntValue<'ctx>,
    ra_register: IntValue<'ctx>,
    ra_offset: IntValue<'ctx>,
    rbp_kind: IntValue<'ctx>,
    rbp_register: IntValue<'ctx>,
    rbp_offset: IntValue<'ctx>,
}

struct BtFrameModule<'ctx> {
    cookie: IntValue<'ctx>,
    bias: IntValue<'ctx>,
    found: IntValue<'ctx>,
}

struct BtRowBounds<'ctx> {
    start: IntValue<'ctx>,
    end: IntValue<'ctx>,
}

struct BtModuleRangeMeta<'ctx> {
    found: IntValue<'ctx>,
    active_slot: IntValue<'ctx>,
    count: IntValue<'ctx>,
}

struct BtModuleRangeValue<'ctx> {
    found: IntValue<'ctx>,
    base: IntValue<'ctx>,
    end: IntValue<'ctx>,
    text: IntValue<'ctx>,
    cookie: IntValue<'ctx>,
}

struct RuntimeBtRowScratch<'ctx> {
    found_ptr: PointerValue<'ctx>,
    cfa_register_ptr: PointerValue<'ctx>,
    cfa_offset_ptr: PointerValue<'ctx>,
    ra_kind_ptr: PointerValue<'ctx>,
    ra_register_ptr: PointerValue<'ctx>,
    ra_offset_ptr: PointerValue<'ctx>,
    rbp_kind_ptr: PointerValue<'ctx>,
    rbp_register_ptr: PointerValue<'ctx>,
    rbp_offset_ptr: PointerValue<'ctx>,
}

struct BtScratch<'ctx> {
    row: RuntimeBtRowScratch<'ctx>,
    next_rbp_ptr: PointerValue<'ctx>,
    next_error_code_ptr: PointerValue<'ctx>,
}

#[derive(Clone, Copy)]
struct BtRegisterState<'ctx> {
    ip: IntValue<'ctx>,
    rsp: IntValue<'ctx>,
    rbp: IntValue<'ctx>,
}

#[derive(Clone, Copy)]
struct BtNextFrame<'ctx> {
    ip: IntValue<'ctx>,
    rsp: IntValue<'ctx>,
    rbp: IntValue<'ctx>,
    error_code: IntValue<'ctx>,
}

struct BtFrameValidation<'ctx> {
    valid: IntValue<'ctx>,
    complete: IntValue<'ctx>,
    error_code: IntValue<'ctx>,
}

enum BacktraceUnwindRowForPc {
    Usable(ghostscope_protocol::BacktraceUnwindRow),
    Missing,
    Unsupported,
}

mod frame_recovery;
mod inline;
mod module_ranges;
mod payload;
mod plan;
mod tail_call;
mod unwind_rows;

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub fn generate_backtrace_instruction(&mut self, stmt: &BacktraceStatement) -> Result<()> {
        let plan = self.plan_backtrace_instruction(stmt);
        if matches!(plan.mode, BacktraceEmitMode::TailCall) {
            return self.generate_tail_call_backtrace_instruction(&plan);
        }

        self.generate_inline_backtrace_instruction(&plan)
    }
}

pub(super) fn backtrace_row_binary_search_steps(row_count: usize) -> usize {
    if row_count <= 1 {
        1
    } else {
        (usize::BITS - (row_count - 1).leading_zeros()) as usize + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::context::BacktraceModuleRowRangeEntry;
    use crate::CompileOptions;
    use inkwell::AddressSpace;

    #[test]
    fn binary_search_steps_cover_power_of_two_row_counts() {
        assert_eq!(backtrace_row_binary_search_steps(0), 1);
        assert_eq!(backtrace_row_binary_search_steps(1), 1);
        assert_eq!(backtrace_row_binary_search_steps(2), 2);
        assert_eq!(backtrace_row_binary_search_steps(4), 3);
        assert_eq!(backtrace_row_binary_search_steps(8), 4);
    }

    #[test]
    fn binary_search_steps_cover_non_power_of_two_row_counts() {
        assert_eq!(backtrace_row_binary_search_steps(3), 3);
        assert_eq!(backtrace_row_binary_search_steps(5), 4);
        assert_eq!(backtrace_row_binary_search_steps(9), 5);
    }

    #[test]
    fn runtime_backtrace_frame_module_resolution_generates_range_lookups() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "bt_frame_module_test", Some(0), &opts).expect("ctx");
        let i64_type = context.i64_type();
        for map_name in ["proc_module_range_meta", "proc_module_ranges"] {
            let map_global =
                ctx.module
                    .add_global(i64_type, Some(AddressSpace::default()), map_name);
            map_global.set_initializer(&i64_type.const_zero());
        }

        let fn_type = context.i32_type().fn_type(&[], false);
        let function = ctx.module.add_function("bt_frame_module", fn_type, None);
        let entry = context.append_basic_block(function, "entry");
        ctx.builder.position_at_end(entry);
        let key_type = context.i32_type().array_type(4);
        ctx.pm_key_alloca = Some(
            ctx.builder
                .build_alloca(key_type, "pm_key")
                .expect("pm_key alloca"),
        );
        ctx.backtrace_module_row_ranges = vec![
            BacktraceModuleRowRangeEntry {
                cookie: 0x1111,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: 0,
                    row_end: 1,
                },
            },
            BacktraceModuleRowRangeEntry {
                cookie: 0x2222,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: 1,
                    row_end: 2,
                },
            },
        ];

        let frame_module = ctx
            .resolve_backtrace_frame_module(
                i64_type.const_int(0x7f00_1234, false),
                i64_type.const_int(0x1111, false),
                i64_type.const_zero(),
                context.bool_type().const_zero(),
                "test_bt_frame_module",
            )
            .expect("resolve frame module");
        ctx.store_u64_value(
            ctx.pm_key_alloca.expect("pm key"),
            0,
            frame_module.cookie,
            "selected_cookie",
        )
        .expect("store selected cookie");

        let ir = ctx.module.print_to_string().to_string();
        assert!(
            ir.contains("proc_module_range_meta")
                && ir.contains("proc_module_ranges")
                && ir.contains("test_bt_frame_module_0_range_base")
                && ir.contains("test_bt_frame_module_0_range_end"),
            "resolver should use the per-PID module range index\nIR:\n{ir}"
        );
        assert!(
            ir.contains("test_bt_frame_module_0_range_cookie")
                && !ir.contains("proc_module_offsets"),
            "resolver should select a module cookie without scanning offsets\nIR:\n{ir}"
        );
    }

    #[test]
    fn runtime_backtrace_row_bounds_cover_all_prepared_modules() {
        let context = inkwell::context::Context::create();
        let opts = CompileOptions::default();
        let mut ctx =
            EbpfContext::new(&context, "bt_row_bounds_test", Some(0), &opts).expect("ctx");

        let fn_type = context
            .i32_type()
            .fn_type(&[context.i64_type().into()], false);
        let function = ctx.module.add_function("bt_row_bounds", fn_type, None);
        let entry = context.append_basic_block(function, "entry");
        ctx.builder.position_at_end(entry);
        let map_global = ctx.module.add_global(
            context.i64_type(),
            Some(AddressSpace::default()),
            "bt_module_row_ranges",
        );
        map_global.set_initializer(&context.i64_type().const_zero());
        let key_type = context.i32_type().array_type(4);
        ctx.pm_key_alloca = Some(
            ctx.builder
                .build_alloca(key_type, "pm_key")
                .expect("pm_key alloca"),
        );

        ctx.backtrace_module_row_ranges = (0..=32)
            .map(|idx| BacktraceModuleRowRangeEntry {
                cookie: 0x1000 + idx as u64,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: (idx * 2) as u32,
                    row_end: (idx * 2 + 2) as u32,
                },
            })
            .collect();

        let bounds = ctx
            .backtrace_unwind_row_bounds_for_module(
                function
                    .get_first_param()
                    .expect("module cookie param")
                    .into_int_value(),
                "test_bt_row_bounds",
            )
            .expect("row bounds");
        ctx.builder
            .build_return(Some(&bounds.end))
            .expect("return bounds end");

        let ir = ctx.module.print_to_string().to_string();
        assert!(
            ir.contains("bt_module_row_ranges")
                && ir.contains("test_bt_row_bounds_row_range_lookup"),
            "row bounds lookup should use the module range map\nIR:\n{ir}"
        );
        assert!(
            !ir.contains("module_matches"),
            "row bounds lookup should not use static candidate comparisons\nIR:\n{ir}"
        );
        assert!(
            !ir.contains("row_range_cookie_lo") && !ir.contains("row_range_cookie_hi"),
            "row bounds lookup should store the native u64 module cookie\nIR:\n{ir}"
        );
    }
}

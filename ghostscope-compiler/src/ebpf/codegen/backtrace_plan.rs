//! Backtrace semantic planning for eBPF codegen.
//!
//! This module decides which backtrace strategy and data dependencies are
//! required. The LLVM emitter in `backtrace.rs` owns the actual IR blocks,
//! helper calls, and ABI stores.

use super::*;
use crate::ebpf::context::BacktraceModuleRowRangeEntry;
use crate::script::{BacktraceStatement, Statement};
use ghostscope_dwarf::ModuleAddress;
use std::{path::PathBuf, time::Instant};

// DWARF row lookup expands into BPF branches, so large depths move to the
// tail-call step program after a short prefix to avoid LLVM branch-range limits.
pub(super) const BPF_INLINE_BACKTRACE_FRAME_LIMIT: u8 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BacktraceEmitMode {
    Inline,
    TailCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BacktraceInstructionPlan {
    pub(super) depth: u8,
    pub(super) flags: u8,
    pub(super) mode: BacktraceEmitMode,
    pub(super) payload_size: usize,
    pub(super) instruction_size: usize,
}

#[derive(Debug, Clone, Default)]
struct PreparedBacktraceUnwindRows {
    rows: Vec<ghostscope_protocol::BacktraceUnwindRow>,
    module_row_ranges: Vec<BacktraceModuleRowRangeEntry>,
    tail_call_slots: u8,
}

#[derive(Debug, Clone, Default)]
struct RuntimeBacktraceUnwindPlan {
    rows: Vec<ghostscope_protocol::BacktraceUnwindRow>,
    module_row_ranges: Vec<BacktraceModuleRowRangeEntry>,
}

impl<'ctx, 'dw> EbpfContext<'ctx, 'dw> {
    pub(crate) fn prepare_backtrace_unwind_rows(&mut self, statements: &[Statement]) {
        let prepared = self.plan_backtrace_unwind_rows(statements);
        self.backtrace_unwind_rows = prepared.rows;
        self.backtrace_module_row_ranges = prepared.module_row_ranges;
        self.backtrace_tail_call_slots = prepared.tail_call_slots.max(1);
        self.next_backtrace_tail_call_slot = 0;
    }

    fn plan_backtrace_unwind_rows(
        &mut self,
        statements: &[Statement],
    ) -> PreparedBacktraceUnwindRows {
        let mut prepared = PreparedBacktraceUnwindRows {
            tail_call_slots: 1,
            ..PreparedBacktraceUnwindRows::default()
        };
        if !statements_have_backtrace(statements) {
            return prepared;
        }

        let Some(analyzer) = self.process_analyzer else {
            return prepared;
        };
        let Some(compile_ctx) = self.current_compile_time_context.clone() else {
            return prepared;
        };

        let runtime_plan = self.runtime_backtrace_unwind_plan(analyzer);
        if !runtime_plan.rows.is_empty() {
            prepared.rows = runtime_plan.rows;
            prepared.module_row_ranges = runtime_plan.module_row_ranges;
            prepared.tail_call_slots = self.required_backtrace_tail_call_slots(statements);
            return prepared;
        }

        let module_address = ModuleAddress::new(
            PathBuf::from(&compile_ctx.module_path),
            compile_ctx.pc_address,
        );
        let Ok(ctx) = analyzer.resolve_pc(&module_address) else {
            return prepared;
        };
        let Ok(Some(table)) = analyzer.compact_unwind_table_for_context(&ctx) else {
            return prepared;
        };

        prepared.rows = table
            .rows
            .iter()
            .filter_map(crate::backtrace_unwind_row_from_compact)
            .collect();
        prepared.rows.sort_by_key(|row| (row.pc_start, row.pc_end));
        prepared.tail_call_slots = self.required_backtrace_tail_call_slots(statements);
        prepared
    }

    fn required_backtrace_tail_call_slots(&self, statements: &[Statement]) -> u8 {
        let depth = self
            .compile_options
            .backtrace_depth
            .clamp(1, crate::MAX_BACKTRACE_DEPTH);
        if depth <= BPF_INLINE_BACKTRACE_FRAME_LIMIT {
            return 1;
        }
        count_backtrace_statements(statements).clamp(1, u8::MAX as usize) as u8
    }

    fn runtime_backtrace_unwind_plan(
        &mut self,
        analyzer: &ghostscope_dwarf::DwarfAnalyzer,
    ) -> RuntimeBacktraceUnwindPlan {
        struct ModuleRows {
            cookie: u64,
            module_path: PathBuf,
            compact_rows: usize,
            bpf_rows: Vec<ghostscope_protocol::BacktraceUnwindRow>,
            elapsed_ms: u128,
        }

        let started_at = Instant::now();
        let mut modules = Vec::<ModuleRows>::new();
        for module in analyzer.loaded_module_runtime_info() {
            let Some(module_id) = analyzer.module_id_for_path(&module.module_path) else {
                continue;
            };
            let module_started_at = Instant::now();
            let Ok(Some(table)) = analyzer.compact_unwind_table_for_module(module_id) else {
                continue;
            };
            let mut bpf_rows = table
                .rows
                .iter()
                .filter_map(crate::backtrace_unwind_row_from_compact)
                .collect::<Vec<_>>();
            bpf_rows.sort_by_key(|row| (row.pc_start, row.pc_end));
            if bpf_rows.is_empty() {
                continue;
            }
            let module_path = module.module_path.to_string_lossy();
            let cookie = self.cookie_for_module_or_fallback(&module_path);
            if modules.iter().any(|module| module.cookie == cookie) {
                continue;
            }
            modules.push(ModuleRows {
                cookie,
                module_path: module.module_path.clone(),
                compact_rows: table.rows.len(),
                bpf_rows,
                elapsed_ms: module_started_at.elapsed().as_millis(),
            });
        }
        modules.sort_by_key(|module| module.cookie);

        let mut plan = RuntimeBacktraceUnwindPlan::default();
        for module in modules.iter() {
            let row_start = plan.rows.len();
            plan.rows.extend(module.bpf_rows.iter().copied());
            let row_end = plan.rows.len();
            plan.module_row_ranges.push(BacktraceModuleRowRangeEntry {
                cookie: module.cookie,
                range: ghostscope_protocol::BacktraceModuleRowRange {
                    row_start: row_start as u32,
                    row_end: row_end as u32,
                },
            });
            tracing::info!(
                module = %module.module_path.display(),
                compact_rows = module.compact_rows,
                bpf_rows = module.bpf_rows.len(),
                row_start,
                row_end,
                elapsed_ms = module.elapsed_ms,
                "Prepared module-normalized bt unwind rows for module"
            );
        }
        tracing::info!(
            modules = plan.module_row_ranges.len(),
            rows = plan.rows.len(),
            elapsed_ms = started_at.elapsed().as_millis(),
            "Prepared module-normalized runtime DWARF bt unwind rows"
        );
        plan
    }

    pub(super) fn plan_backtrace_instruction(
        &self,
        stmt: &BacktraceStatement,
    ) -> BacktraceInstructionPlan {
        let depth = self
            .compile_options
            .backtrace_depth
            .clamp(1, crate::MAX_BACKTRACE_DEPTH);
        let flags = backtrace_flags(stmt);
        let payload_size =
            BACKTRACE_DATA_SIZE + depth as usize * std::mem::size_of::<BacktraceFrameData>();
        let instruction_size = INSTRUCTION_HEADER_SIZE + payload_size;
        let mode = if depth > BPF_INLINE_BACKTRACE_FRAME_LIMIT
            && !self.backtrace_unwind_rows.is_empty()
            && self.current_compile_time_context.is_some()
        {
            BacktraceEmitMode::TailCall
        } else {
            BacktraceEmitMode::Inline
        };

        BacktraceInstructionPlan {
            depth,
            flags,
            mode,
            payload_size,
            instruction_size,
        }
    }
}

fn statements_have_backtrace(statements: &[Statement]) -> bool {
    count_backtrace_statements(statements) > 0
}

fn count_backtrace_statements(statements: &[Statement]) -> usize {
    statements.iter().map(count_statement_backtraces).sum()
}

fn count_statement_backtraces(statement: &Statement) -> usize {
    match statement {
        Statement::Backtrace(_) => 1,
        Statement::TracePoint { body, .. } | Statement::Block(body) => {
            count_backtrace_statements(body)
        }
        Statement::If {
            then_body,
            else_body,
            ..
        } => {
            count_backtrace_statements(then_body)
                + else_body
                    .as_deref()
                    .map(count_statement_backtraces)
                    .unwrap_or(0)
        }
        _ => 0,
    }
}

fn backtrace_flags(stmt: &BacktraceStatement) -> u8 {
    let mut flags = 0u8;
    if stmt.raw {
        flags |= BACKTRACE_FLAG_RAW;
    }
    if stmt.full {
        flags |= BACKTRACE_FLAG_FULL;
    }
    if stmt.inline {
        flags |= BACKTRACE_FLAG_INLINE;
    }
    flags
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ebpf::context::CompileTimeContext;

    #[test]
    fn count_backtrace_statements_walks_nested_control_flow() {
        let bt = Statement::Backtrace(BacktraceStatement::default());
        let program = vec![
            Statement::Block(vec![bt.clone()]),
            Statement::If {
                condition: crate::script::Expr::Bool(true),
                then_body: vec![bt.clone()],
                else_body: Some(Box::new(Statement::Block(vec![bt]))),
            },
        ];

        assert_eq!(count_backtrace_statements(&program), 3);
        assert!(statements_have_backtrace(&program));
    }

    #[test]
    fn backtrace_flags_follow_statement_options() {
        let flags = backtrace_flags(&BacktraceStatement {
            raw: true,
            full: true,
            inline: false,
        });

        assert_eq!(flags & BACKTRACE_FLAG_RAW, BACKTRACE_FLAG_RAW);
        assert_eq!(flags & BACKTRACE_FLAG_FULL, BACKTRACE_FLAG_FULL);
        assert_eq!(flags & BACKTRACE_FLAG_INLINE, 0);
    }

    #[test]
    fn instruction_plan_chooses_tail_call_only_when_runtime_rows_are_available() {
        let context = inkwell::context::Context::create();
        let mut ctx = EbpfContext::new(&context, "test", None, &crate::CompileOptions::default())
            .expect("context");
        let stmt = BacktraceStatement::default();

        assert_eq!(
            ctx.plan_backtrace_instruction(&stmt).mode,
            BacktraceEmitMode::Inline
        );

        ctx.backtrace_unwind_rows
            .push(ghostscope_protocol::BacktraceUnwindRow::default());
        ctx.current_compile_time_context = Some(CompileTimeContext {
            pc_address: 0x1234,
            module_path: "/bin/test".to_string(),
        });

        let plan = ctx.plan_backtrace_instruction(&stmt);
        assert_eq!(plan.mode, BacktraceEmitMode::TailCall);
        assert_eq!(
            plan.instruction_size,
            INSTRUCTION_HEADER_SIZE + plan.payload_size
        );
    }
}

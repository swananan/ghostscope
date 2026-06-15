// Keep library clippy-clean without allow attributes

pub mod ebpf;
pub mod script;

use crate::script::compiler::AstCompiler;
use ebpf::context::CodeGenError;
pub use ghostscope_dwarf::RuntimeCapabilities;
use ghostscope_dwarf::{CfaRulePlan, CompactUnwindRow, RegisterRecoveryPlan};
use ghostscope_process::module_probe;
pub use ghostscope_process::{PidFilterSpec, PidNamespaceId};
use script::parser::ParseError;
use std::borrow::Cow;
use tracing::info;

const X86_64_DWARF_RIP: u16 = 16;
const X86_64_DWARF_RBP: u16 = 6;
const X86_64_DWARF_RSP: u16 = 7;

pub fn hello() -> &'static str {
    "Hello from ghostscope-compiler!"
}

pub use ghostscope_protocol::bpf_abi::{
    BacktraceTailCallState, BacktraceUnwindRow, BACKTRACE_RA_AT_CFA_OFFSET, BACKTRACE_RA_REGISTER,
    BACKTRACE_RA_SAME_VALUE, BACKTRACE_RA_UNDEFINED, BACKTRACE_RA_VAL_CFA_OFFSET,
    BACKTRACE_RECOVERY_AT_CFA_OFFSET, BACKTRACE_RECOVERY_REGISTER, BACKTRACE_RECOVERY_SAME_VALUE,
    BACKTRACE_RECOVERY_UNDEFINED, BACKTRACE_RECOVERY_VAL_CFA_OFFSET, BACKTRACE_TAIL_NO_NEXT_SLOT,
    BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET, BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET,
    BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET, BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET,
    BACKTRACE_TAIL_STATE_ERROR_CODE_OFFSET, BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET,
    BACKTRACE_TAIL_STATE_FLAGS_OFFSET, BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET,
    BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET, BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET,
    BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET, BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET,
    BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET, BACKTRACE_TAIL_STATE_REQUESTED_DEPTH_OFFSET,
    BACKTRACE_TAIL_STATE_SIZE, BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET,
    BACKTRACE_UNWIND_ROW_CFA_OFFSET_OFFSET, BACKTRACE_UNWIND_ROW_CFA_REGISTER_OFFSET,
    BACKTRACE_UNWIND_ROW_PC_END_OFFSET, BACKTRACE_UNWIND_ROW_PC_START_OFFSET,
    BACKTRACE_UNWIND_ROW_RA_KIND_OFFSET, BACKTRACE_UNWIND_ROW_RA_OFFSET_OFFSET,
    BACKTRACE_UNWIND_ROW_RA_REGISTER_OFFSET, BACKTRACE_UNWIND_ROW_RBP_KIND_OFFSET,
    BACKTRACE_UNWIND_ROW_RBP_OFFSET_OFFSET, BACKTRACE_UNWIND_ROW_RBP_REGISTER_OFFSET,
    BACKTRACE_UNWIND_ROW_SIZE, BACKTRACE_UNWIND_WORDS_PER_ROW, BACKTRACE_UNWIND_WORD_CFA_OFFSET,
    BACKTRACE_UNWIND_WORD_PC_END, BACKTRACE_UNWIND_WORD_PC_START, BACKTRACE_UNWIND_WORD_RA_OFFSET,
    BACKTRACE_UNWIND_WORD_RBP_OFFSET, BACKTRACE_UNWIND_WORD_REGISTERS,
};

#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] Box<ParseError>),

    #[error("Code generation error: {0}")]
    CodeGen(#[from] CodeGenError),

    #[error("LLVM error: {0}")]
    LLVM(String),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, CompileError>;

impl From<ParseError> for CompileError {
    fn from(err: ParseError) -> Self {
        CompileError::Parse(Box::new(err))
    }
}

impl CompileError {
    pub fn user_message(&self) -> Cow<'_, str> {
        match self {
            CompileError::Parse(err) => Cow::Owned(format!("Parse error: {err}")),
            CompileError::CodeGen(err) => err.user_message(),
            CompileError::LLVM(message) | CompileError::Other(message) => Cow::Borrowed(message),
        }
    }
}

impl CodeGenError {
    pub fn user_message(&self) -> Cow<'_, str> {
        match self {
            CodeGenError::VariableNotInScope(name) => {
                Cow::Owned(format!("Use of variable '{name}' outside of its scope"))
            }
            CodeGenError::VariableUnavailable(message) => Cow::Borrowed(message),
            CodeGenError::TypeSizeNotAvailable(name) => Cow::Owned(format!(
                "Variable '{name}' has no concrete DWARF size at this probe PC"
            )),
            _ => Cow::Owned(self.to_string()),
        }
    }
}

// Public re-exports from script::compiler module
pub use script::compiler::{CompilationResult, UProbeConfig};

/// Event output map type for eBPF tracing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventMapType {
    /// BPF_MAP_TYPE_RINGBUF (requires kernel >= 5.8)
    RingBuf,
    /// BPF_MAP_TYPE_PERF_EVENT_ARRAY (kernel >= 4.3, fallback)
    PerfEventArray,
}

/// Compilation options including save options and eBPF map configuration
#[derive(Debug, Clone)]
pub struct CompileOptions {
    pub save_llvm_ir: bool,
    pub save_ebpf: bool,
    pub save_ast: bool,
    pub binary_path_hint: Option<String>,
    /// Explicit `-t` target path. When present, trace target resolution is
    /// scoped to this module even if DWARF was loaded from a `-p` PID.
    pub target_binary_path: Option<String>,
    pub ringbuf_size: u64,
    pub proc_module_offsets_max_entries: u64,
    /// Fixed capacity for DWARF compact CFI rows used by `bt`.
    pub backtrace_unwind_rows_max_entries: u32,
    pub perf_page_count: u32,
    pub event_map_type: EventMapType,
    /// Max bytes to read per memory-dump argument (format {:x}/{:s}).
    pub mem_dump_cap: u32,
    /// Max bytes to compare for string/memory comparisons (strncmp/starts_with/memcmp)
    pub compare_cap: u32,
    /// Max total bytes in a single trace event (used for PerfEventArray accumulation buffer size).
    pub max_trace_event_size: u32,
    /// Max DWARF-unwound frames captured by each `bt`/`backtrace` instruction.
    pub backtrace_depth: u8,
    /// Optional single-address filter: if set, only the Nth (1-based) address
    /// resolved for a target will be compiled. When None, compile all.
    pub selected_index: Option<usize>,
    /// Optional PID filter strategy override.
    /// When None, compiler falls back to HostTgid using compile_script(pid).
    pub pid_filter_spec: Option<PidFilterSpec>,
    /// Optional PID namespace context used by special vars like `$pid`/`$tid`.
    /// This is independent of PID filtering and is primarily for `-t` mode.
    pub special_pid_ns: Option<PidNamespaceId>,
    /// Optional PID namespace context used by `proc_module_offsets` lookups.
    ///
    /// In `-p` mode this only switches to the target PID-namespace view when
    /// GhostScope has an explicit namespace-local target PID that can be
    /// aliased back to the `/proc` key used to populate
    /// `proc_module_offsets`. Otherwise it stays on GhostScope's current
    /// `/proc`-visible PID view.
    ///
    /// In `-t` mode we continue to use GhostScope's own `/proc` view, because
    /// offsets are discovered from `/proc/<pid>/maps` in that namespace.
    pub proc_offsets_pid_ns: Option<PidNamespaceId>,
    /// Optional original `-p` input PID for `$input_pid`.
    /// This is only available in `-p` mode.
    pub input_pid: Option<u32>,
    /// Runtime/backend capabilities used to validate DWARF variable read plans.
    pub runtime_capabilities: RuntimeCapabilities,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            save_llvm_ir: false,
            save_ebpf: false,
            save_ast: false,
            binary_path_hint: None,
            target_binary_path: None,
            ringbuf_size: 262144,                  // 256KB
            proc_module_offsets_max_entries: 4096, // Default
            backtrace_unwind_rows_max_entries: DEFAULT_BACKTRACE_UNWIND_ROWS_MAX_ENTRIES,
            perf_page_count: 64,                   // 64 pages = 256KB per CPU
            event_map_type: EventMapType::RingBuf, // Default to RingBuf
            mem_dump_cap: 256,                     // Default per-arg dump cap (bytes)
            compare_cap: 64,                       // Default compare cap for strncmp/memcmp (bytes)
            max_trace_event_size: 32768,           // Default event size cap (32KB)
            backtrace_depth: DEFAULT_BACKTRACE_DEPTH,
            selected_index: None,
            pid_filter_spec: None,
            special_pid_ns: None,
            proc_offsets_pid_ns: None,
            input_pid: None,
            runtime_capabilities: RuntimeCapabilities::default(),
        }
    }
}

pub const DEFAULT_BACKTRACE_DEPTH: u8 = 128;
pub const MAX_BACKTRACE_DEPTH: u8 = 128;
pub const DEFAULT_BACKTRACE_UNWIND_ROWS_MAX_ENTRIES: u32 = 65_536;
pub const MIN_BACKTRACE_UNWIND_ROWS_MAX_ENTRIES: u32 = 1_024;
pub const MAX_BACKTRACE_UNWIND_ROWS_MAX_ENTRIES: u32 = 1_048_576;

pub fn module_cookie_for_path(module_path: &str) -> u64 {
    module_probe::cookie_for_path(module_path)
}

pub fn backtrace_unwind_row_from_compact(
    row: &CompactUnwindRow,
) -> Option<ghostscope_protocol::BacktraceUnwindRow> {
    if !row.bpf_supported {
        return None;
    }
    let CfaRulePlan::RegPlusOffset {
        register,
        offset: cfa_offset,
    } = &row.cfa
    else {
        return None;
    };
    if !backtrace_supported_state_register(*register) {
        return None;
    }

    let mut wire = ghostscope_protocol::BacktraceUnwindRow {
        pc_start: row.pc_start,
        pc_end: row.pc_end,
        cfa_offset: *cfa_offset,
        cfa_register: *register,
        ..Default::default()
    };

    match &row.return_address {
        RegisterRecoveryPlan::AtCfaOffset { offset } => {
            wire.ra_kind = BACKTRACE_RECOVERY_AT_CFA_OFFSET;
            wire.ra_offset = *offset;
            wire.ra_register = row.return_address_register;
        }
        _ => return None,
    }

    match row.rbp.as_ref() {
        Some(RegisterRecoveryPlan::AtCfaOffset { offset }) => {
            wire.rbp_kind = BACKTRACE_RECOVERY_AT_CFA_OFFSET;
            wire.rbp_offset = *offset;
            wire.rbp_register = X86_64_DWARF_RBP;
        }
        Some(RegisterRecoveryPlan::ValCfaOffset { offset }) => {
            wire.rbp_kind = BACKTRACE_RECOVERY_VAL_CFA_OFFSET;
            wire.rbp_offset = *offset;
            wire.rbp_register = X86_64_DWARF_RBP;
        }
        Some(RegisterRecoveryPlan::Register { register }) => {
            if !backtrace_supported_state_register(*register) {
                return None;
            }
            wire.rbp_kind = BACKTRACE_RECOVERY_REGISTER;
            wire.rbp_register = *register;
        }
        Some(RegisterRecoveryPlan::SameValue { register }) => {
            if !backtrace_supported_state_register(*register) {
                return None;
            }
            wire.rbp_kind = BACKTRACE_RECOVERY_SAME_VALUE;
            wire.rbp_register = *register;
        }
        Some(RegisterRecoveryPlan::Undefined) | None => {
            wire.rbp_kind = BACKTRACE_RECOVERY_SAME_VALUE;
            wire.rbp_register = X86_64_DWARF_RBP;
        }
        _ => return None,
    }

    Some(wire)
}

fn backtrace_supported_state_register(register: u16) -> bool {
    matches!(
        register,
        X86_64_DWARF_RIP | X86_64_DWARF_RBP | X86_64_DWARF_RSP
    )
}

/// Main compilation interface with DwarfAnalyzer (multi-module support)
///
/// This is the new multi-module interface that uses DwarfAnalyzer
/// to perform compilation across main executable and dynamic libraries
pub fn compile_script(
    script_source: &str,
    process_analyzer: &ghostscope_dwarf::DwarfAnalyzer,
    pid: Option<u32>,
    trace_id: Option<u32>,
    compile_options: &CompileOptions,
) -> Result<CompilationResult> {
    info!("Starting unified script compilation with DwarfAnalyzer (multi-module support)");

    // Step 1: Parse script to AST
    let program = script::parser::parse(script_source)?;
    info!("Parsed script with {} statements", program.statements.len());

    // Step 2: Use AstCompiler with full DwarfAnalyzer integration
    let mut compiler = AstCompiler::new(
        Some(process_analyzer),
        compile_options.binary_path_hint.clone(),
        trace_id.unwrap_or(0), // Default starting trace_id is 0 if not provided
        compile_options.clone(),
    );

    // Step 3: Compile using unified interface
    let result = compiler.compile_program(&program, pid)?;

    if result.uprobe_configs.is_empty() {
        if !result.failed_targets.is_empty() {
            tracing::warn!(
                "Compilation produced 0 uprobe configs; {} target(s) failed to compile",
                result.failed_targets.len()
            );
        } else {
            tracing::warn!(
                "Compilation completed with 0 uprobe configs (no attachable targets resolved)"
            );
        }
    } else {
        info!(
            "Successfully compiled script: {} trace points, {} uprobe configs",
            result.trace_count,
            result.uprobe_configs.len()
        );
    }

    // Concise summary for downstream logs
    info!(
        "Compilation summary: trace_points={}, uprobe_configs={}, failed_targets={}",
        result.trace_count,
        result.uprobe_configs.len(),
        result.failed_targets.len()
    );

    Ok(result)
}

/// Print AST for debugging
pub fn print_ast(program: &crate::script::Program) {
    info!("\n=== AST Tree ===");
    info!("Program:");
    for (i, stmt) in program.statements.iter().enumerate() {
        info!("  Statement {}: {:?}", i, stmt);
    }
    info!("=== End AST Tree ===\n");
}

/// Save AST to file
pub fn save_ast_to_file(program: &crate::script::Program, filename: &str) -> Result<()> {
    let mut ast_content = String::new();
    ast_content.push_str("=== AST Tree ===\n");
    ast_content.push_str("Program:\n");
    for (i, stmt) in program.statements.iter().enumerate() {
        ast_content.push_str(&format!("  Statement {i}: {stmt:?}\n"));
    }
    ast_content.push_str("=== End AST Tree ===\n");

    let file_path = format!("{filename}.txt");
    std::fs::write(&file_path, ast_content)
        .map_err(|e| CompileError::Other(format!("Failed to save AST file '{file_path}': {e}")))?;

    Ok(())
}

/// Format eBPF bytecode as hexadecimal string for inspection
pub fn format_ebpf_bytecode(bytecode: &[u8]) -> String {
    bytecode
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<String>>()
        .join(" ")
}

/// Generate filename for AST files
pub fn generate_file_name_for_ast(pid: Option<u32>, binary_path: Option<&str>) -> String {
    let pid_part = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let exec_part = binary_path
        .and_then(|path| std::path::Path::new(path).file_name())
        .and_then(|name| name.to_str())
        .unwrap_or("unknown");

    format!("gs_{pid_part}_{exec_part}_ast")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_message_strips_codegen_prefix_for_unavailable_variable() {
        let err = CompileError::CodeGen(CodeGenError::VariableUnavailable(
            "'x' is optimized out at the selected probe PC".to_string(),
        ));

        assert_eq!(
            err.user_message().as_ref(),
            "'x' is optimized out at the selected probe PC"
        );
    }

    #[test]
    fn user_message_formats_scope_errors_for_users() {
        let err = CompileError::CodeGen(CodeGenError::VariableNotInScope("x".to_string()));

        assert_eq!(
            err.user_message().as_ref(),
            "Use of variable 'x' outside of its scope"
        );
    }

    #[test]
    fn backtrace_unwind_row_layout_matches_bpf_map_value() {
        assert_eq!(BACKTRACE_UNWIND_ROW_SIZE, 56);
        assert_eq!(BACKTRACE_UNWIND_ROW_PC_START_OFFSET, 0);
        assert_eq!(BACKTRACE_UNWIND_ROW_PC_END_OFFSET, 8);
        assert_eq!(BACKTRACE_UNWIND_ROW_CFA_OFFSET_OFFSET, 16);
        assert_eq!(BACKTRACE_UNWIND_ROW_RA_OFFSET_OFFSET, 24);
        assert_eq!(BACKTRACE_UNWIND_ROW_RBP_OFFSET_OFFSET, 32);
        assert_eq!(BACKTRACE_UNWIND_ROW_CFA_REGISTER_OFFSET, 40);
        assert_eq!(BACKTRACE_UNWIND_ROW_RA_REGISTER_OFFSET, 42);
        assert_eq!(BACKTRACE_UNWIND_ROW_RBP_REGISTER_OFFSET, 44);
        assert_eq!(BACKTRACE_UNWIND_ROW_RA_KIND_OFFSET, 46);
        assert_eq!(BACKTRACE_UNWIND_ROW_RBP_KIND_OFFSET, 47);
    }

    #[test]
    fn backtrace_tail_call_state_layout_matches_bpf_accessors() {
        assert_eq!(BACKTRACE_TAIL_STATE_SIZE, 64);
        assert_eq!(BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET, 0);
        assert_eq!(BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET, 8);
        assert_eq!(BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET, 16);
        assert_eq!(BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET, 24);
        assert_eq!(BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET, 32);
        assert_eq!(BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET, 40);
        assert_eq!(BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET, 44);
        assert_eq!(BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET, 48);
        assert_eq!(BACKTRACE_TAIL_STATE_REQUESTED_DEPTH_OFFSET, 49);
        assert_eq!(BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET, 50);
        assert_eq!(BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET, 51);
        assert_eq!(BACKTRACE_TAIL_STATE_FLAGS_OFFSET, 52);
        assert_eq!(BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET, 53);
        assert_eq!(BACKTRACE_TAIL_STATE_ERROR_CODE_OFFSET, 54);
        assert_eq!(BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET, 56);
    }
}

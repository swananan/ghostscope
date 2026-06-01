//! Shared eBPF map key/value ABI.
//!
//! These layouts are consumed by generated eBPF bytecode and by userspace map
//! writers. Keep them numeric, `repr(C)`, and free of compiler/loader state.

/// Key for the pinned `proc_module_offsets` map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct ProcModuleKey {
    pub pid: u32,
    pub pad: u32,
    pub cookie_lo: u32,
    pub cookie_hi: u32,
}

impl ProcModuleKey {
    pub fn new(pid: u32, module_cookie: u64) -> Self {
        Self {
            pid,
            pad: 0,
            cookie_lo: module_cookie as u32,
            cookie_hi: (module_cookie >> 32) as u32,
        }
    }
}

pub const PROC_MODULE_KEY_PID_OFFSET: usize = std::mem::offset_of!(ProcModuleKey, pid);
pub const PROC_MODULE_KEY_PAD_OFFSET: usize = std::mem::offset_of!(ProcModuleKey, pad);
pub const PROC_MODULE_KEY_COOKIE_LO_OFFSET: usize = std::mem::offset_of!(ProcModuleKey, cookie_lo);
pub const PROC_MODULE_KEY_COOKIE_HI_OFFSET: usize = std::mem::offset_of!(ProcModuleKey, cookie_hi);
pub const PROC_MODULE_KEY_SIZE: usize = std::mem::size_of::<ProcModuleKey>();

/// Value for the pinned `proc_module_offsets` map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProcModuleOffsetsValue {
    pub text: u64,
    pub rodata: u64,
    pub data: u64,
    pub bss: u64,
}

impl ProcModuleOffsetsValue {
    pub fn new(text: u64, rodata: u64, data: u64, bss: u64) -> Self {
        Self {
            text,
            rodata,
            data,
            bss,
        }
    }
}

pub const PROC_MODULE_OFFSETS_VALUE_TEXT_OFFSET: usize =
    std::mem::offset_of!(ProcModuleOffsetsValue, text);
pub const PROC_MODULE_OFFSETS_VALUE_RODATA_OFFSET: usize =
    std::mem::offset_of!(ProcModuleOffsetsValue, rodata);
pub const PROC_MODULE_OFFSETS_VALUE_DATA_OFFSET: usize =
    std::mem::offset_of!(ProcModuleOffsetsValue, data);
pub const PROC_MODULE_OFFSETS_VALUE_BSS_OFFSET: usize =
    std::mem::offset_of!(ProcModuleOffsetsValue, bss);
pub const PROC_MODULE_OFFSETS_VALUE_SIZE: usize = std::mem::size_of::<ProcModuleOffsetsValue>();

/// Value for the pinned `pid_aliases` map.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PidAliasValue {
    pub proc_pid: u32,
}

pub const PID_ALIAS_VALUE_PROC_PID_OFFSET: usize = std::mem::offset_of!(PidAliasValue, proc_pid);
pub const PID_ALIAS_VALUE_SIZE: usize = std::mem::size_of::<PidAliasValue>();

/// BPF-facing compact DWARF CFI row used by the `bt` unwinder.
///
/// The row is intentionally numeric and path-free: userspace owns module
/// identity, DWARF parsing, and symbolization, while eBPF receives only the
/// compact rules it can execute safely.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BacktraceUnwindRow {
    pub pc_start: u64,
    pub pc_end: u64,
    pub cfa_offset: i64,
    pub ra_offset: i64,
    pub rbp_offset: i64,
    pub cfa_register: u16,
    pub ra_register: u16,
    pub rbp_register: u16,
    pub ra_kind: u8,
    pub rbp_kind: u8,
    pub reserved: [u8; 2],
}

pub const BACKTRACE_UNWIND_ROW_PC_START_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, pc_start);
pub const BACKTRACE_UNWIND_ROW_PC_END_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, pc_end);
pub const BACKTRACE_UNWIND_ROW_CFA_OFFSET_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, cfa_offset);
pub const BACKTRACE_UNWIND_ROW_RA_OFFSET_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, ra_offset);
pub const BACKTRACE_UNWIND_ROW_RBP_OFFSET_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, rbp_offset);
pub const BACKTRACE_UNWIND_ROW_CFA_REGISTER_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, cfa_register);
pub const BACKTRACE_UNWIND_ROW_RA_REGISTER_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, ra_register);
pub const BACKTRACE_UNWIND_ROW_RBP_REGISTER_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, rbp_register);
pub const BACKTRACE_UNWIND_ROW_RA_KIND_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, ra_kind);
pub const BACKTRACE_UNWIND_ROW_RBP_KIND_OFFSET: usize =
    std::mem::offset_of!(BacktraceUnwindRow, rbp_kind);
pub const BACKTRACE_UNWIND_ROW_SIZE: usize = std::mem::size_of::<BacktraceUnwindRow>();

pub const BACKTRACE_UNWIND_WORDS_PER_ROW: usize = 6;
pub const BACKTRACE_UNWIND_WORD_PC_START: usize = 0;
pub const BACKTRACE_UNWIND_WORD_PC_END: usize = 1;
pub const BACKTRACE_UNWIND_WORD_CFA_OFFSET: usize = 2;
pub const BACKTRACE_UNWIND_WORD_RA_OFFSET: usize = 3;
pub const BACKTRACE_UNWIND_WORD_RBP_OFFSET: usize = 4;
pub const BACKTRACE_UNWIND_WORD_REGISTERS: usize = 5;

pub fn backtrace_unwind_row_register_word(row: BacktraceUnwindRow) -> u64 {
    u64::from(row.cfa_register)
        | (u64::from(row.ra_register) << 16)
        | (u64::from(row.rbp_register) << 32)
        | (u64::from(row.ra_kind) << 48)
        | (u64::from(row.rbp_kind) << 56)
}

pub fn backtrace_unwind_row_word(row: BacktraceUnwindRow, word: usize) -> u64 {
    match word {
        BACKTRACE_UNWIND_WORD_PC_START => row.pc_start,
        BACKTRACE_UNWIND_WORD_PC_END => row.pc_end,
        BACKTRACE_UNWIND_WORD_CFA_OFFSET => row.cfa_offset as u64,
        BACKTRACE_UNWIND_WORD_RA_OFFSET => row.ra_offset as u64,
        BACKTRACE_UNWIND_WORD_RBP_OFFSET => row.rbp_offset as u64,
        BACKTRACE_UNWIND_WORD_REGISTERS => backtrace_unwind_row_register_word(row),
        _ => 0,
    }
}

pub fn backtrace_unwind_row_from_words(
    words: [u64; BACKTRACE_UNWIND_WORDS_PER_ROW],
) -> BacktraceUnwindRow {
    let registers = words[BACKTRACE_UNWIND_WORD_REGISTERS];
    BacktraceUnwindRow {
        pc_start: words[BACKTRACE_UNWIND_WORD_PC_START],
        pc_end: words[BACKTRACE_UNWIND_WORD_PC_END],
        cfa_offset: words[BACKTRACE_UNWIND_WORD_CFA_OFFSET] as i64,
        ra_offset: words[BACKTRACE_UNWIND_WORD_RA_OFFSET] as i64,
        rbp_offset: words[BACKTRACE_UNWIND_WORD_RBP_OFFSET] as i64,
        cfa_register: registers as u16,
        ra_register: (registers >> 16) as u16,
        rbp_register: (registers >> 32) as u16,
        ra_kind: (registers >> 48) as u8,
        rbp_kind: (registers >> 56) as u8,
        reserved: [0, 0],
    }
}

/// Per-CPU state carried across `bt` tail-call unwind programs.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BacktraceTailCallState {
    pub current_ip: u64,
    pub current_rsp: u64,
    pub current_rbp: u64,
    pub module_bias: u64,
    pub module_cookie: u64,
    pub inst_offset: u32,
    pub event_size: u32,
    pub frame_count: u8,
    pub requested_depth: u8,
    pub offsets_found: u8,
    pub tail_calls: u8,
    pub flags: u8,
    pub active_slot: u8,
    pub error_code: u16,
    pub next_slot: u8,
}

pub const BACKTRACE_TAIL_STATE_CURRENT_IP_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, current_ip);
pub const BACKTRACE_TAIL_STATE_CURRENT_RSP_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, current_rsp);
pub const BACKTRACE_TAIL_STATE_CURRENT_RBP_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, current_rbp);
pub const BACKTRACE_TAIL_STATE_MODULE_BIAS_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, module_bias);
pub const BACKTRACE_TAIL_STATE_MODULE_COOKIE_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, module_cookie);
pub const BACKTRACE_TAIL_STATE_INST_OFFSET_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, inst_offset);
pub const BACKTRACE_TAIL_STATE_EVENT_SIZE_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, event_size);
pub const BACKTRACE_TAIL_STATE_FRAME_COUNT_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, frame_count);
pub const BACKTRACE_TAIL_STATE_REQUESTED_DEPTH_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, requested_depth);
pub const BACKTRACE_TAIL_STATE_OFFSETS_FOUND_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, offsets_found);
pub const BACKTRACE_TAIL_STATE_TAIL_CALLS_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, tail_calls);
pub const BACKTRACE_TAIL_STATE_FLAGS_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, flags);
pub const BACKTRACE_TAIL_STATE_ACTIVE_SLOT_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, active_slot);
pub const BACKTRACE_TAIL_STATE_ERROR_CODE_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, error_code);
pub const BACKTRACE_TAIL_STATE_NEXT_SLOT_OFFSET: usize =
    std::mem::offset_of!(BacktraceTailCallState, next_slot);
pub const BACKTRACE_TAIL_STATE_SIZE: usize = std::mem::size_of::<BacktraceTailCallState>();
pub const BACKTRACE_TAIL_NO_NEXT_SLOT: u8 = u8::MAX;

pub const BACKTRACE_RECOVERY_UNDEFINED: u8 = 0;
pub const BACKTRACE_RECOVERY_AT_CFA_OFFSET: u8 = 1;
pub const BACKTRACE_RECOVERY_VAL_CFA_OFFSET: u8 = 2;
pub const BACKTRACE_RECOVERY_REGISTER: u8 = 3;
pub const BACKTRACE_RECOVERY_SAME_VALUE: u8 = 4;

pub const BACKTRACE_RA_UNDEFINED: u8 = BACKTRACE_RECOVERY_UNDEFINED;
pub const BACKTRACE_RA_AT_CFA_OFFSET: u8 = BACKTRACE_RECOVERY_AT_CFA_OFFSET;
pub const BACKTRACE_RA_VAL_CFA_OFFSET: u8 = BACKTRACE_RECOVERY_VAL_CFA_OFFSET;
pub const BACKTRACE_RA_REGISTER: u8 = BACKTRACE_RECOVERY_REGISTER;
pub const BACKTRACE_RA_SAME_VALUE: u8 = BACKTRACE_RECOVERY_SAME_VALUE;

#[cfg(feature = "aya-pod")]
mod aya_pod {
    use super::{
        BacktraceTailCallState, BacktraceUnwindRow, PidAliasValue, ProcModuleKey,
        ProcModuleOffsetsValue,
    };

    // SAFETY: ProcModuleKey is repr(C), Copy, 'static, and contains only
    // integer fields with no invalid bit patterns.
    unsafe impl aya::Pod for ProcModuleKey {}
    // SAFETY: ProcModuleOffsetsValue is repr(C), Copy, 'static, and contains
    // only integer fields with no invalid bit patterns.
    unsafe impl aya::Pod for ProcModuleOffsetsValue {}
    // SAFETY: PidAliasValue is repr(C), Copy, 'static, and contains only an
    // integer field with no invalid bit patterns.
    unsafe impl aya::Pod for PidAliasValue {}
    // SAFETY: BacktraceUnwindRow is repr(C), Copy, 'static, and contains only
    // integer fields with no invalid bit patterns.
    unsafe impl aya::Pod for BacktraceUnwindRow {}
    // SAFETY: BacktraceTailCallState is repr(C), Copy, 'static, and contains
    // only integer fields with no invalid bit patterns.
    unsafe impl aya::Pod for BacktraceTailCallState {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proc_module_offsets_layout_matches_bpf_maps() {
        assert_eq!(PROC_MODULE_KEY_SIZE, 16);
        assert_eq!(PROC_MODULE_KEY_PID_OFFSET, 0);
        assert_eq!(PROC_MODULE_KEY_PAD_OFFSET, 4);
        assert_eq!(PROC_MODULE_KEY_COOKIE_LO_OFFSET, 8);
        assert_eq!(PROC_MODULE_KEY_COOKIE_HI_OFFSET, 12);

        assert_eq!(PROC_MODULE_OFFSETS_VALUE_SIZE, 32);
        assert_eq!(PROC_MODULE_OFFSETS_VALUE_TEXT_OFFSET, 0);
        assert_eq!(PROC_MODULE_OFFSETS_VALUE_RODATA_OFFSET, 8);
        assert_eq!(PROC_MODULE_OFFSETS_VALUE_DATA_OFFSET, 16);
        assert_eq!(PROC_MODULE_OFFSETS_VALUE_BSS_OFFSET, 24);

        assert_eq!(PID_ALIAS_VALUE_SIZE, 4);
        assert_eq!(PID_ALIAS_VALUE_PROC_PID_OFFSET, 0);
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
        assert_eq!(BACKTRACE_UNWIND_WORDS_PER_ROW, 6);

        let row = BacktraceUnwindRow {
            pc_start: 0x10,
            pc_end: 0x20,
            cfa_offset: 128,
            ra_offset: -8,
            rbp_offset: -16,
            cfa_register: 7,
            ra_register: 16,
            rbp_register: 6,
            ra_kind: BACKTRACE_RA_AT_CFA_OFFSET,
            rbp_kind: BACKTRACE_RECOVERY_SAME_VALUE,
            reserved: [0, 0],
        };
        let words = [
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_PC_START),
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_PC_END),
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_CFA_OFFSET),
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_RA_OFFSET),
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_RBP_OFFSET),
            backtrace_unwind_row_word(row, BACKTRACE_UNWIND_WORD_REGISTERS),
        ];
        assert_eq!(backtrace_unwind_row_from_words(words), row);
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

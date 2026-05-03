use crate::core::{ComputeStep, ModuleId};

/// A compact, row-oriented unwind table derived from DWARF CFI.
#[derive(Debug, Clone, PartialEq)]
pub struct CompactUnwindTable {
    pub module: ModuleId,
    pub rows: Vec<CompactUnwindRow>,
    pub diagnostics: Vec<UnwindDiagnostic>,
}

impl CompactUnwindTable {
    pub fn row_for_pc(&self, pc: u64) -> Option<&CompactUnwindRow> {
        self.rows
            .iter()
            .find(|row| row.pc_start <= pc && pc < row.pc_end)
    }

    pub fn stats(&self) -> CompactUnwindStats {
        let bpf_supported_rows = self.rows.iter().filter(|row| row.bpf_supported).count();
        CompactUnwindStats {
            row_count: self.rows.len(),
            bpf_supported_rows,
            unsupported_rows: self.rows.len().saturating_sub(bpf_supported_rows),
            diagnostic_count: self.diagnostics.len(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactUnwindStats {
    pub row_count: usize,
    pub bpf_supported_rows: usize,
    pub unsupported_rows: usize,
    pub diagnostic_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompactUnwindRow {
    pub module: ModuleId,
    pub pc_start: u64,
    pub pc_end: u64,
    pub cfa: CfaRulePlan,
    pub return_address_register: u16,
    pub return_address: RegisterRecoveryPlan,
    pub sp: Option<RegisterRecoveryPlan>,
    pub rbp: Option<RegisterRecoveryPlan>,
    pub bpf_supported: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CfaRulePlan {
    RegPlusOffset { register: u16, offset: i64 },
    Expression { steps: Vec<ComputeStep> },
    Unsupported { reason: String },
}

impl CfaRulePlan {
    pub fn is_bpf_fast_path_supported(&self) -> bool {
        matches!(
            self,
            Self::RegPlusOffset {
                register: 6 | 7,
                ..
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegisterRecoveryPlan {
    Undefined,
    SameValue {
        register: u16,
    },
    Register {
        register: u16,
    },
    AtCfaOffset {
        offset: i64,
    },
    ValCfaOffset {
        offset: i64,
    },
    Constant {
        value: u64,
    },
    Expression {
        steps: Vec<ComputeStep>,
        dereference: bool,
    },
    Unsupported {
        reason: String,
    },
}

impl RegisterRecoveryPlan {
    pub fn is_bpf_fast_path_supported(&self) -> bool {
        matches!(
            self,
            Self::SameValue { .. }
                | Self::Register { .. }
                | Self::AtCfaOffset { .. }
                | Self::ValCfaOffset { .. }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwindDiagnostic {
    pub pc_start: u64,
    pub pc_end: u64,
    pub kind: UnwindDiagnosticKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindDiagnosticKind {
    UnsupportedCfaRule { reason: String },
    UnsupportedRegisterRule { register: u16, reason: String },
    MissingReturnAddressRule { register: u16 },
}

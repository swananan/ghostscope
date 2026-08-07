use crate::core::{ModuleId, PlanExprOp};

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
        let bpf_supported_rows = self
            .rows
            .iter()
            .filter(|row| row.bpf_fast_path_plan().is_ok())
            .count();
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfUnwindRowPlan {
    pub pc_start: u64,
    pub pc_end: u64,
    pub cfa_register: u16,
    pub cfa_offset: i64,
    pub return_address: BpfRecoveryPlan,
    pub rbp: BpfRecoveryPlan,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfRecoveryPlan {
    pub kind: BpfRecoveryKind,
    pub register: u16,
    pub offset: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfRecoveryKind {
    SameValue,
    Register,
    AtCfaOffset,
    ValCfaOffset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfUnwindRowRejection {
    UnsupportedCfaRule,
    UnsupportedCfaRegister { register: u16 },
    UnsupportedReturnAddressRule,
    UnsupportedReturnAddressRegister { register: u16 },
    UnsupportedFramePointerRule,
    UnsupportedFramePointerRegister { register: u16 },
}

const X86_64_DWARF_RIP: u16 = 16;
const X86_64_DWARF_RBP: u16 = 6;
const X86_64_DWARF_RSP: u16 = 7;

impl CompactUnwindRow {
    /// Lower this semantic row into the complete contract supported by the
    /// eBPF backtrace fast path.
    ///
    /// Keeping this conversion next to the semantic row gives statistics and
    /// wire encoding one source of truth. The caller stack pointer is the CFA,
    /// so the explicit `sp` recovery rule does not need a separate wire field.
    pub fn bpf_fast_path_plan(&self) -> Result<BpfUnwindRowPlan, BpfUnwindRowRejection> {
        let (cfa_register, cfa_offset) = match self.cfa {
            CfaRulePlan::RegPlusOffset { register, offset }
                if matches!(register, X86_64_DWARF_RBP | X86_64_DWARF_RSP) =>
            {
                (register, offset)
            }
            CfaRulePlan::RegPlusOffset { register, .. } => {
                return Err(BpfUnwindRowRejection::UnsupportedCfaRegister { register });
            }
            CfaRulePlan::Expression { .. } | CfaRulePlan::Unsupported { .. } => {
                return Err(BpfUnwindRowRejection::UnsupportedCfaRule);
            }
        };

        let return_address = bpf_recovery_plan(&self.return_address, self.return_address_register)
            .map_err(|rejection| match rejection {
                BpfRecoveryRejection::UnsupportedRule => {
                    BpfUnwindRowRejection::UnsupportedReturnAddressRule
                }
                BpfRecoveryRejection::UnsupportedRegister { register } => {
                    BpfUnwindRowRejection::UnsupportedReturnAddressRegister { register }
                }
            })?;

        let rbp_rule = self
            .rbp
            .as_ref()
            .filter(|rule| !matches!(rule, RegisterRecoveryPlan::Undefined));
        let rbp = match rbp_rule {
            Some(rule) => {
                bpf_recovery_plan(rule, X86_64_DWARF_RBP).map_err(|rejection| match rejection {
                    BpfRecoveryRejection::UnsupportedRule => {
                        BpfUnwindRowRejection::UnsupportedFramePointerRule
                    }
                    BpfRecoveryRejection::UnsupportedRegister { register } => {
                        BpfUnwindRowRejection::UnsupportedFramePointerRegister { register }
                    }
                })?
            }
            None => BpfRecoveryPlan {
                kind: BpfRecoveryKind::SameValue,
                register: X86_64_DWARF_RBP,
                offset: 0,
            },
        };

        Ok(BpfUnwindRowPlan {
            pc_start: self.pc_start,
            pc_end: self.pc_end,
            cfa_register,
            cfa_offset,
            return_address,
            rbp,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BpfRecoveryRejection {
    UnsupportedRule,
    UnsupportedRegister { register: u16 },
}

fn bpf_recovery_plan(
    rule: &RegisterRecoveryPlan,
    target_register: u16,
) -> Result<BpfRecoveryPlan, BpfRecoveryRejection> {
    let plan = match *rule {
        RegisterRecoveryPlan::SameValue { register } => BpfRecoveryPlan {
            kind: BpfRecoveryKind::SameValue,
            register,
            offset: 0,
        },
        RegisterRecoveryPlan::Register { register } => BpfRecoveryPlan {
            kind: BpfRecoveryKind::Register,
            register,
            offset: 0,
        },
        RegisterRecoveryPlan::AtCfaOffset { offset } => BpfRecoveryPlan {
            kind: BpfRecoveryKind::AtCfaOffset,
            register: target_register,
            offset,
        },
        RegisterRecoveryPlan::ValCfaOffset { offset } => BpfRecoveryPlan {
            kind: BpfRecoveryKind::ValCfaOffset,
            register: target_register,
            offset,
        },
        RegisterRecoveryPlan::Undefined
        | RegisterRecoveryPlan::Constant { .. }
        | RegisterRecoveryPlan::Expression { .. }
        | RegisterRecoveryPlan::Unsupported { .. } => {
            return Err(BpfRecoveryRejection::UnsupportedRule);
        }
    };

    if matches!(
        plan.kind,
        BpfRecoveryKind::SameValue | BpfRecoveryKind::Register
    ) && !matches!(
        plan.register,
        X86_64_DWARF_RIP | X86_64_DWARF_RBP | X86_64_DWARF_RSP
    ) {
        return Err(BpfRecoveryRejection::UnsupportedRegister {
            register: plan.register,
        });
    }

    Ok(plan)
}

#[derive(Debug, Clone, PartialEq)]
pub enum CfaRulePlan {
    RegPlusOffset { register: u16, offset: i64 },
    Expression { steps: Vec<PlanExprOp> },
    Unsupported { reason: String },
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
        steps: Vec<PlanExprOp>,
        dereference: bool,
    },
    Unsupported {
        reason: String,
    },
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

#[cfg(test)]
mod tests {
    use super::*;

    fn compact_row(return_address: RegisterRecoveryPlan) -> CompactUnwindRow {
        CompactUnwindRow {
            module: ModuleId(1),
            pc_start: 0x1000,
            pc_end: 0x1010,
            cfa: CfaRulePlan::RegPlusOffset {
                register: X86_64_DWARF_RSP,
                offset: 16,
            },
            return_address_register: X86_64_DWARF_RIP,
            return_address,
            sp: None,
            rbp: None,
        }
    }

    #[test]
    fn bpf_fast_path_plan_supports_every_runtime_recovery_kind() {
        let cases = [
            (
                RegisterRecoveryPlan::SameValue {
                    register: X86_64_DWARF_RIP,
                },
                BpfRecoveryPlan {
                    kind: BpfRecoveryKind::SameValue,
                    register: X86_64_DWARF_RIP,
                    offset: 0,
                },
            ),
            (
                RegisterRecoveryPlan::Register {
                    register: X86_64_DWARF_RBP,
                },
                BpfRecoveryPlan {
                    kind: BpfRecoveryKind::Register,
                    register: X86_64_DWARF_RBP,
                    offset: 0,
                },
            ),
            (
                RegisterRecoveryPlan::AtCfaOffset { offset: -8 },
                BpfRecoveryPlan {
                    kind: BpfRecoveryKind::AtCfaOffset,
                    register: X86_64_DWARF_RIP,
                    offset: -8,
                },
            ),
            (
                RegisterRecoveryPlan::ValCfaOffset { offset: -16 },
                BpfRecoveryPlan {
                    kind: BpfRecoveryKind::ValCfaOffset,
                    register: X86_64_DWARF_RIP,
                    offset: -16,
                },
            ),
        ];

        for (return_address, expected) in cases {
            let plan = compact_row(return_address)
                .bpf_fast_path_plan()
                .expect("recovery kind should be supported by the BPF fast path");
            assert_eq!(plan.return_address, expected);
        }
    }

    #[test]
    fn bpf_fast_path_plan_rejects_untracked_recovery_register() {
        let rejection = compact_row(RegisterRecoveryPlan::Register { register: 3 })
            .bpf_fast_path_plan()
            .expect_err("rbx is not present in the compact BPF register state");

        assert_eq!(
            rejection,
            BpfUnwindRowRejection::UnsupportedReturnAddressRegister { register: 3 }
        );
    }

    #[test]
    fn bpf_fast_path_plan_uses_cfa_as_caller_stack_pointer() {
        let mut row = compact_row(RegisterRecoveryPlan::AtCfaOffset { offset: -8 });
        row.sp = Some(RegisterRecoveryPlan::Expression {
            steps: Vec::new(),
            dereference: false,
        });

        assert!(row.bpf_fast_path_plan().is_ok());
    }

    #[test]
    fn compact_unwind_stats_use_the_fast_path_contract() {
        let supported = compact_row(RegisterRecoveryPlan::ValCfaOffset { offset: -8 });
        let unsupported = compact_row(RegisterRecoveryPlan::Constant { value: 0x1234 });
        let table = CompactUnwindTable {
            module: ModuleId(1),
            rows: vec![supported, unsupported],
            diagnostics: Vec::new(),
        };

        assert_eq!(
            table.stats(),
            CompactUnwindStats {
                row_count: 2,
                bpf_supported_rows: 1,
                unsupported_rows: 1,
                diagnostic_count: 0,
            }
        );
    }
}

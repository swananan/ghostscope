//! Precise semantic availability and diagnostic categories.

use crate::core::EvaluationResult;

/// Whether a semantic result is usable at the requested PC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
    Available,
    PartiallyAvailable,
    OptimizedOut,
    NotInScope,
    Unsupported(UnsupportedReason),
    Requires(RuntimeRequirement),
    Ambiguous(AmbiguityReason),
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available | Self::PartiallyAvailable)
    }

    pub fn from_evaluation_result(result: &EvaluationResult) -> Self {
        match result {
            EvaluationResult::Optimized => Self::OptimizedOut,
            EvaluationResult::Composite(pieces) => {
                if pieces.is_empty() {
                    Self::Available
                } else if pieces
                    .iter()
                    .all(|piece| matches!(piece.location, EvaluationResult::Optimized))
                {
                    Self::OptimizedOut
                } else if pieces
                    .iter()
                    .any(|piece| matches!(piece.location, EvaluationResult::Optimized))
                {
                    Self::PartiallyAvailable
                } else {
                    Self::Available
                }
            }
            _ => Self::Available,
        }
    }
}

impl From<&EvaluationResult> for Availability {
    fn from(value: &EvaluationResult) -> Self {
        Self::from_evaluation_result(value)
    }
}

/// DWARF or semantic shapes the current engine cannot represent yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnsupportedReason {
    DwarfOp { op: String },
    ExpressionShape { detail: String },
    TypeLayout { detail: String },
    AddressClass { detail: String },
    RegisterMapping { dwarf_reg: u16 },
}

/// Runtime feature required before a semantic plan can be lowered safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeRequirement {
    CallerFrame,
    SleepableUprobe,
    UserMemoryRead,
    DwarfCfiRecovery,
}

/// Reason a query could not pick one unambiguous semantic interpretation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AmbiguityReason {
    InlineContext { detail: String },
    VariableDeclaration { detail: String },
    TypeResolution { detail: String },
}

/// Where a semantic answer came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Provenance {
    DirectDie,
    AbstractOrigin,
    Specification,
    LocationList,
    CallSite,
    Cfi,
    Synthesized { detail: String },
}

/// Capabilities available to a future BPF lowering pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeCapabilities {
    pub regular_uprobe: bool,
    pub sleepable_uprobe: bool,
    pub uprobe_multi: bool,
    pub copy_from_user_task: bool,
    pub max_bpf_stack_bytes: usize,
    pub bounded_loops: bool,
    pub arch: TargetArch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    X86_64,
    Aarch64,
    Unknown,
}

impl TargetArch {
    pub fn current() -> Self {
        if cfg!(target_arch = "x86_64") {
            Self::X86_64
        } else if cfg!(target_arch = "aarch64") {
            Self::Aarch64
        } else {
            Self::Unknown
        }
    }
}

impl Default for RuntimeCapabilities {
    fn default() -> Self {
        Self {
            regular_uprobe: true,
            sleepable_uprobe: false,
            uprobe_multi: false,
            copy_from_user_task: false,
            max_bpf_stack_bytes: 512,
            bounded_loops: true,
            arch: TargetArch::current(),
        }
    }
}

/// User-memory helper strategy selected by a lowering plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperMode {
    NoUserMemoryRead,
    ProbeReadUser,
    CopyFromUserTask,
}

/// Coarse verifier risk surfaced before backend codegen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierRisk {
    Low,
    RequiresBoundedLoops,
    StackBudgetExceeded { estimated: usize, max: usize },
    Unsupported { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectValueResult, PieceResult};

    #[test]
    fn optimized_result_is_unavailable() {
        assert_eq!(
            Availability::from(&EvaluationResult::Optimized),
            Availability::OptimizedOut
        );
    }

    #[test]
    fn mixed_composite_result_is_partially_available() {
        let result = EvaluationResult::Composite(vec![
            PieceResult {
                location: EvaluationResult::DirectValue(DirectValueResult::RegisterValue(0)),
                size: 4,
                bit_offset: None,
            },
            PieceResult {
                location: EvaluationResult::Optimized,
                size: 4,
                bit_offset: Some(32),
            },
        ]);

        assert_eq!(
            Availability::from(&result),
            Availability::PartiallyAvailable
        );
    }
}

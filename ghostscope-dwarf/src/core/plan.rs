//! Neutral semantic plans produced before runtime-specific lowering.

use crate::core::{
    Availability, DirectValueResult, EvaluationResult, LocationResult, MemoryAccessSize, PlanExprOp,
};
use std::fmt;

/// Address expression that can be evaluated by a later lowering layer.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressExpr {
    pub steps: Vec<PlanExprOp>,
}

impl AddressExpr {
    pub fn constant(address: u64) -> Self {
        Self {
            steps: vec![PlanExprOp::PushConstant(address as i64)],
        }
    }

    pub fn register_relative(dwarf_reg: u16, offset: i64) -> Self {
        let mut steps = vec![PlanExprOp::LoadRegister(dwarf_reg)];
        if offset != 0 {
            steps.push(PlanExprOp::PushConstant(offset));
            steps.push(PlanExprOp::Add);
        }
        Self { steps }
    }
}

/// PC-sensitive variable location before BPF lowering.
#[derive(Debug, Clone, PartialEq)]
pub enum VariableLocation {
    Address(AddressExpr),
    AbsoluteAddressValue(AddressExpr),
    RegisterValue { dwarf_reg: u16 },
    RegisterAddress { dwarf_reg: u16, offset: i64 },
    FrameBaseRelative { offset: i64 },
    ComputedValue(Vec<PlanExprOp>),
    ComputedAddress(Vec<PlanExprOp>),
    ImplicitValue(Vec<u8>),
    Pieces(Vec<PieceLocation>),
    OptimizedOut,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PieceLocation {
    pub bit_offset: u32,
    pub bit_size: u32,
    pub location: Box<VariableLocation>,
}

/// Semantic location produced after DWARF expression evaluation.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ParsedLocation {
    pub location: VariableLocation,
    pub availability: Availability,
}

impl ParsedLocation {
    pub(crate) fn from_evaluation_result(result: &EvaluationResult) -> Self {
        Self {
            location: VariableLocation::from_evaluation_result(result),
            availability: Availability::from_evaluation_result(result),
        }
    }
}

impl VariableLocation {
    pub(crate) fn from_evaluation_result(result: &EvaluationResult) -> Self {
        match result {
            EvaluationResult::DirectValue(direct) => Self::from_direct_value(direct),
            EvaluationResult::MemoryLocation(location) => Self::from_location_result(location),
            EvaluationResult::Optimized => Self::OptimizedOut,
            EvaluationResult::Composite(pieces) => Self::Pieces(
                pieces
                    .iter()
                    .map(|piece| PieceLocation {
                        bit_offset: piece.bit_offset.unwrap_or(0).min(u32::MAX as u64) as u32,
                        bit_size: piece.size.saturating_mul(8).min(u32::MAX as u64) as u32,
                        location: Box::new(Self::from_evaluation_result(&piece.location)),
                    })
                    .collect(),
            ),
        }
    }

    fn from_direct_value(value: &DirectValueResult) -> Self {
        match value {
            DirectValueResult::Constant(value) => {
                Self::ComputedValue(vec![PlanExprOp::PushConstant(*value)])
            }
            DirectValueResult::AbsoluteAddress(address) => {
                Self::AbsoluteAddressValue(AddressExpr::constant(*address))
            }
            DirectValueResult::ImplicitValue(bytes) => Self::ImplicitValue(bytes.clone()),
            DirectValueResult::RegisterValue(dwarf_reg) => Self::RegisterValue {
                dwarf_reg: *dwarf_reg,
            },
            DirectValueResult::ComputedValue { steps, .. } => Self::ComputedValue(steps.clone()),
        }
    }

    fn from_location_result(location: &LocationResult) -> Self {
        match location {
            LocationResult::Address(address) => Self::Address(AddressExpr::constant(*address)),
            LocationResult::RegisterAddress {
                register, offset, ..
            } => Self::RegisterAddress {
                dwarf_reg: *register,
                offset: offset.unwrap_or(0),
            },
            LocationResult::ComputedLocation { steps } => Self::ComputedAddress(steps.clone()),
        }
    }
}

impl fmt::Display for VariableLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableLocation::Address(expr) => {
                write!(f, "[Memory] {}", location_display_for_address_expr(expr))
            }
            VariableLocation::AbsoluteAddressValue(expr) => {
                write!(f, "[DirectValue] ")?;
                if let [PlanExprOp::PushConstant(address)] = expr.steps.as_slice() {
                    DirectValueResult::AbsoluteAddress(*address as u64).fmt(f)
                } else {
                    DirectValueResult::ComputedValue {
                        steps: expr.steps.clone(),
                        result_size: MemoryAccessSize::U64,
                    }
                    .fmt(f)
                }
            }
            VariableLocation::RegisterValue { dwarf_reg } => {
                write!(f, "[DirectValue] ")?;
                DirectValueResult::RegisterValue(*dwarf_reg).fmt(f)
            }
            VariableLocation::RegisterAddress { dwarf_reg, offset } => {
                write!(f, "[Memory] ")?;
                LocationResult::RegisterAddress {
                    register: *dwarf_reg,
                    offset: Some(*offset),
                    size: None,
                }
                .fmt(f)
            }
            VariableLocation::FrameBaseRelative { offset } => {
                if *offset >= 0 {
                    write!(f, "[Memory] @[frame_base+{offset}]")
                } else {
                    write!(f, "[Memory] @[frame_base{offset}]")
                }
            }
            VariableLocation::ComputedValue(steps) => {
                write!(f, "[DirectValue] ")?;
                DirectValueResult::ComputedValue {
                    steps: steps.clone(),
                    result_size: MemoryAccessSize::U64,
                }
                .fmt(f)
            }
            VariableLocation::ComputedAddress(steps) => {
                write!(f, "[Memory] ")?;
                LocationResult::ComputedLocation {
                    steps: steps.clone(),
                }
                .fmt(f)
            }
            VariableLocation::ImplicitValue(bytes) => {
                write!(f, "[DirectValue] ")?;
                DirectValueResult::ImplicitValue(bytes.clone()).fmt(f)
            }
            VariableLocation::Pieces(pieces) => write!(f, "Composite[{} pieces]", pieces.len()),
            VariableLocation::OptimizedOut => write!(f, "<optimized out>"),
            VariableLocation::Unknown => write!(f, "<unknown>"),
        }
    }
}

fn location_display_for_address_expr(expr: &AddressExpr) -> String {
    if let [PlanExprOp::PushConstant(address)] = expr.steps.as_slice() {
        return format!("{}", LocationResult::Address(*address as u64));
    }

    format!(
        "{}",
        LocationResult::ComputedLocation {
            steps: expr.steps.clone()
        }
    )
}

/// A memory read requested by a future runtime lowering pass.
#[derive(Debug, Clone, PartialEq)]
pub struct UserMemoryRead {
    pub address: AddressExpr,
    pub size: MemoryAccessSize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{DirectValueResult, PieceResult};

    #[test]
    fn converts_register_address_location() {
        let result = EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
            register: 6,
            offset: Some(-16),
            size: None,
        });

        assert_eq!(
            VariableLocation::from_evaluation_result(&result),
            VariableLocation::RegisterAddress {
                dwarf_reg: 6,
                offset: -16
            }
        );
    }

    #[test]
    fn converts_absolute_address_value_as_rebasable_value() {
        let result = EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234));

        assert_eq!(
            VariableLocation::from_evaluation_result(&result),
            VariableLocation::AbsoluteAddressValue(AddressExpr::constant(0x1234))
        );
    }

    #[test]
    fn converts_composite_pieces() {
        let result = EvaluationResult::Composite(vec![PieceResult {
            location: EvaluationResult::DirectValue(DirectValueResult::RegisterValue(0)),
            size: 4,
            bit_offset: Some(32),
        }]);

        assert_eq!(
            VariableLocation::from_evaluation_result(&result),
            VariableLocation::Pieces(vec![PieceLocation {
                bit_offset: 32,
                bit_size: 32,
                location: Box::new(VariableLocation::RegisterValue { dwarf_reg: 0 }),
            }])
        );
    }
}

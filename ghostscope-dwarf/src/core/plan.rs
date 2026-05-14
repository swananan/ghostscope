//! Neutral semantic plans produced before runtime-specific lowering.

use crate::core::{plan_expr_steps_to_expression, Availability, MemoryAccessSize, PlanExprOp};
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
    pub(crate) fn new(location: VariableLocation) -> Self {
        let availability = location.availability();
        Self {
            location,
            availability,
        }
    }
}

impl VariableLocation {
    pub(crate) fn availability(&self) -> Availability {
        Availability::from_variable_location(self)
    }
}

impl Availability {
    pub(crate) fn from_variable_location(location: &VariableLocation) -> Self {
        match location {
            VariableLocation::OptimizedOut => Self::OptimizedOut,
            VariableLocation::Pieces(pieces) => {
                if pieces.is_empty() {
                    Self::Available
                } else if pieces
                    .iter()
                    .all(|piece| matches!(piece.location.as_ref(), VariableLocation::OptimizedOut))
                {
                    Self::OptimizedOut
                } else if pieces
                    .iter()
                    .any(|piece| matches!(piece.location.as_ref(), VariableLocation::OptimizedOut))
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

impl fmt::Display for VariableLocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableLocation::Address(expr) => {
                write!(f, "[Memory] {}", location_display_for_address_expr(expr))
            }
            VariableLocation::AbsoluteAddressValue(expr) => {
                write!(f, "[DirectValue] {}", address_value_display(expr))
            }
            VariableLocation::RegisterValue { dwarf_reg } => {
                write!(f, "[DirectValue] {}", register_display(*dwarf_reg))
            }
            VariableLocation::RegisterAddress { dwarf_reg, offset } => {
                write!(
                    f,
                    "[Memory] {}",
                    register_address_display(*dwarf_reg, *offset)
                )
            }
            VariableLocation::FrameBaseRelative { offset } => {
                if *offset >= 0 {
                    write!(f, "[Memory] @[frame_base+{offset}]")
                } else {
                    write!(f, "[Memory] @[frame_base{offset}]")
                }
            }
            VariableLocation::ComputedValue(steps) => {
                write!(f, "[DirectValue] ={}", plan_expr_steps_to_expression(steps))
            }
            VariableLocation::ComputedAddress(steps) => {
                write!(f, "[Memory] @[{}]", plan_expr_steps_to_expression(steps))
            }
            VariableLocation::ImplicitValue(bytes) => {
                write!(f, "[DirectValue] {}", implicit_value_display(bytes))
            }
            VariableLocation::Pieces(pieces) => write!(f, "Composite[{} pieces]", pieces.len()),
            VariableLocation::OptimizedOut => write!(f, "<optimized out>"),
            VariableLocation::Unknown => write!(f, "<unknown>"),
        }
    }
}

fn location_display_for_address_expr(expr: &AddressExpr) -> String {
    if let [PlanExprOp::PushConstant(address)] = expr.steps.as_slice() {
        return format!("@0x{:x}", *address as u64);
    }

    format!("@[{}]", plan_expr_steps_to_expression(&expr.steps))
}

fn address_value_display(expr: &AddressExpr) -> String {
    if let [PlanExprOp::PushConstant(address)] = expr.steps.as_slice() {
        return format!("&@0x{:x}", *address as u64);
    }

    format!("={}", plan_expr_steps_to_expression(&expr.steps))
}

fn register_display(dwarf_reg: u16) -> String {
    ghostscope_platform::register_mapping::dwarf_reg_to_name(dwarf_reg)
        .map(str::to_string)
        .unwrap_or_else(|| format!("r{dwarf_reg}"))
}

fn register_address_display(dwarf_reg: u16, offset: i64) -> String {
    let reg_name = register_display(dwarf_reg);
    if offset >= 0 {
        format!("@[{reg_name}+{offset}]")
    } else {
        format!("@[{reg_name}{offset}]")
    }
}

fn implicit_value_display(bytes: &[u8]) -> String {
    if bytes.len() > 8 {
        return format!("implicit[{} bytes]", bytes.len());
    }

    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("implicit[{hex}]")
}

/// A memory read requested by a future runtime lowering pass.
#[derive(Debug, Clone, PartialEq)]
pub struct UserMemoryRead {
    pub address: AddressExpr,
    pub size: MemoryAccessSize,
}

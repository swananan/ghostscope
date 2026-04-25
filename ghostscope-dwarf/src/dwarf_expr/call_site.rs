//! DWARF call-site expression helpers.

use crate::{
    binary::DwarfReader,
    core::ComputeStep,
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode, ExpressionEvaluator},
};
use gimli::{Operation, Reader};

pub(crate) struct ParsedCallSiteParameter {
    pub(crate) callee_register: u16,
    pub(crate) caller_value_steps: Vec<ComputeStep>,
}

pub(crate) fn target_address(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
) -> Option<u64> {
    address_attr(dwarf, unit, entry, gimli::constants::DW_AT_call_target)
        .or_else(|| target_expr_address(unit, entry))
}

pub(crate) fn parameter(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    return_pc: u64,
) -> Option<ParsedCallSiteParameter> {
    let callee_register = target_register(unit, entry)?;
    let caller_value_steps = value_steps(dwarf, unit, entry, return_pc)?;
    Some(ParsedCallSiteParameter {
        callee_register,
        caller_value_steps,
    })
}

fn target_expr_address(
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
) -> Option<u64> {
    let attr = entry.attr(gimli::constants::DW_AT_call_target)?;
    let gimli::AttributeValue::Exprloc(expr) = attr.value() else {
        return None;
    };
    let first = expr_errors::soft_optional(
        DwarfExprMode::CallSiteValue,
        crate::dwarf_expr::ops::parse_single_op(
            expr.0,
            unit.encoding(),
            "DW_AT_call_target expression",
        ),
    )?;
    match first {
        Operation::Address { address } => Some(address),
        _ => None,
    }
}

fn target_register(
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
) -> Option<u16> {
    let attr = entry.attr(gimli::constants::DW_AT_location)?;
    let gimli::AttributeValue::Exprloc(expr) = attr.value() else {
        return None;
    };
    let first = expr_errors::soft_optional(
        DwarfExprMode::CallSiteValue,
        crate::dwarf_expr::ops::parse_single_op(
            expr.0,
            unit.encoding(),
            "DW_AT_location call-site parameter expression",
        ),
    )?;
    match first {
        Operation::Register { register } => Some(register.0),
        _ => None,
    }
}

fn value_steps(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    return_pc: u64,
) -> Option<Vec<ComputeStep>> {
    let expr = [
        gimli::constants::DW_AT_call_value,
        gimli::constants::DW_AT_GNU_call_site_value,
    ]
    .into_iter()
    .find_map(|attr_name| {
        let attr = entry.attr(attr_name)?;
        match attr.value() {
            gimli::AttributeValue::Exprloc(expr) => Some(expr),
            _ => None,
        }
    })?;
    expr_errors::soft_value(
        DwarfExprMode::CallSiteValue,
        ExpressionEvaluator::parse_expression_to_steps_in_unit(
            expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
            expr.0.endian(),
            unit,
            dwarf,
            return_pc,
            None,
            None,
            None,
        ),
    )
    .or_else(|| call_value_register_fallback(expr, unit.encoding()))
}

fn call_value_register_fallback(
    expr: gimli::Expression<DwarfReader>,
    encoding: gimli::Encoding,
) -> Option<Vec<ComputeStep>> {
    let first = expr_errors::soft_optional(
        DwarfExprMode::CallSiteValue,
        crate::dwarf_expr::ops::parse_single_op(
            expr.0,
            encoding,
            "DW_AT_call_value fallback expression",
        ),
    )?;
    let Operation::EntryValue { expression: inner } = first else {
        return None;
    };
    let inner_op = expr_errors::soft_optional(
        DwarfExprMode::CallSiteValue,
        crate::dwarf_expr::ops::parse_single_op(
            inner,
            encoding,
            "DW_AT_call_value fallback entry_value inner expression",
        ),
    )?;
    match inner_op {
        Operation::Register { register } => Some(vec![ComputeStep::LoadRegister(register.0)]),
        _ => None,
    }
}

fn address_attr(
    dwarf: &gimli::Dwarf<DwarfReader>,
    unit: &gimli::Unit<DwarfReader>,
    entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    attr_name: gimli::DwAt,
) -> Option<u64> {
    let attr = entry.attr(attr_name)?;
    match attr.value() {
        gimli::AttributeValue::Addr(addr) => Some(addr),
        gimli::AttributeValue::DebugAddrIndex(index) => dwarf.address(unit, index).ok(),
        _ => None,
    }
}

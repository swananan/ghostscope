//! DWARF expression evaluator
//!
//! Converts raw DWARF location expressions into the crate's internal evaluator
//! representation before semantic planning lowers them into read plans.

use crate::binary::{DwarfEndian, DwarfReader};
use crate::core::{
    CfaResult, DirectValueResult, EvaluationResult, LocationResult, MemoryAccessSize, PieceResult,
    ParsedLocation, PlanExprOp, Result,
};
use crate::dwarf_expr::{errors as expr_errors, modes::DwarfExprMode};
use crate::index::{CfiIndex, FunctionBlocks};
use crate::semantics::{range_contains_pc, resolve_attr_with_unit_origins};
use gimli::{read::RawLocListEntry, EndianSlice, Operation, Reader};
use tracing::{debug, trace, warn};

/// DWARF expression evaluator
pub struct ExpressionEvaluator;

#[derive(Debug)]
enum ParsedOperation<R: Reader<Offset = usize>> {
    Operation(Operation<R>),
    PrecomputedSteps {
        steps: Vec<PlanExprOp>,
        forces_stack_value: bool,
    },
}

impl ExpressionEvaluator {
    const MAX_IMPLICIT_POINTER_DEPTH: usize = 8;

    /// Evaluate a variable's location from its DIE attributes
    pub fn evaluate_location(
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<ParsedLocation> {
        let result = Self::evaluate_location_result_with_depth(
            entry,
            unit,
            dwarf,
            address,
            get_cfa,
            function_context,
            cfi_index,
            0,
        )?;
        Ok(ParsedLocation::from_evaluation_result(&result))
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_location_result_with_depth(
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        // Get DW_AT_location attribute (follow origins/specification for inlined/declared vars)
        let location_attr =
            resolve_attr_with_unit_origins(entry, unit, gimli::constants::DW_AT_location)?;

        match location_attr {
            Some(gimli::AttributeValue::Exprloc(expr)) => {
                // Direct expression
                debug!("Found Exprloc, parsing DWARF expression");
                Self::parse_expression_with_context(
                    expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                    expr.0.endian(),
                    unit.encoding(),
                    Some(dwarf),
                    Some(unit),
                    address,
                    get_cfa,
                    function_context,
                    cfi_index,
                    depth,
                )
            }
            Some(gimli::AttributeValue::LocationListsRef(offset)) => {
                // Location list - variable location changes based on PC
                debug!(
                    "Found LocationListsRef at offset 0x{:x}, parsing location list",
                    offset.0
                );
                Self::parse_location_lists_with_depth(
                    unit,
                    dwarf,
                    gimli::LocationListsOffset(offset.0),
                    address,
                    get_cfa,
                    function_context,
                    cfi_index,
                    depth,
                )
            }
            Some(gimli::AttributeValue::DebugLocListsIndex(index)) => {
                let offset = dwarf.locations_offset(unit, index)?;
                debug!(
                    "Found DebugLocListsIndex {:?} -> offset 0x{:x}, parsing location list",
                    index, offset.0
                );
                Self::parse_location_lists_with_depth(
                    unit,
                    dwarf,
                    offset,
                    address,
                    get_cfa,
                    function_context,
                    cfi_index,
                    depth,
                )
            }
            Some(gimli::AttributeValue::SecOffset(offset)) => {
                // Older DWARF format location list
                debug!(
                    "Found SecOffset location list at 0x{:x}, parsing as location list",
                    offset
                );
                Self::parse_location_lists_with_depth(
                    unit,
                    dwarf,
                    gimli::LocationListsOffset(offset),
                    address,
                    get_cfa,
                    function_context,
                    cfi_index,
                    depth,
                )
            }
            None => {
                // Try DW_AT_const_value (follow origins) as a last resort
                if let Some(cv) = resolve_attr_with_unit_origins(
                    entry,
                    unit,
                    gimli::constants::DW_AT_const_value,
                )? {
                    let res = match cv {
                        gimli::AttributeValue::Udata(u) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(u as i64))
                        }
                        gimli::AttributeValue::Data1(d) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(d as i64))
                        }
                        gimli::AttributeValue::Data2(d) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(d as i64))
                        }
                        gimli::AttributeValue::Data4(d) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(d as i64))
                        }
                        gimli::AttributeValue::Data8(d) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(d as i64))
                        }
                        gimli::AttributeValue::Sdata(s) => {
                            EvaluationResult::DirectValue(DirectValueResult::Constant(s))
                        }
                        gimli::AttributeValue::Exprloc(expr) => {
                            // Some compilers may encode an implicit value via expression
                            match Self::parse_expression_with_context(
                                expr.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                expr.0.endian(),
                                unit.encoding(),
                                Some(dwarf),
                                Some(unit),
                                address,
                                get_cfa,
                                function_context,
                                cfi_index,
                                depth,
                            )? {
                                EvaluationResult::DirectValue(v) => {
                                    EvaluationResult::DirectValue(v)
                                }
                                other => other,
                            }
                        }
                        gimli::AttributeValue::Block(bytes) => match bytes.to_slice() {
                            Ok(b) => EvaluationResult::DirectValue(
                                DirectValueResult::ImplicitValue(b.to_vec()),
                            ),
                            Err(_) => EvaluationResult::Optimized,
                        },
                        other => {
                            debug!("Unhandled DW_AT_const_value form: {:?}", other);
                            EvaluationResult::Optimized
                        }
                    };
                    return Ok(res);
                }

                // No location means optimized out
                trace!("No DW_AT_location attribute (even via origins); variable optimized out");
                Ok(EvaluationResult::Optimized)
            }
            Some(other) => {
                warn!("Unexpected location attribute type: {:?}", other);
                Ok(EvaluationResult::Optimized)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn parse_expression_in_unit(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<EvaluationResult> {
        Self::parse_expression_with_context(
            expr_bytes,
            endian,
            unit.encoding(),
            Some(dwarf),
            Some(unit),
            address,
            get_cfa,
            function_context,
            cfi_index,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse_expression_to_steps_in_unit(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<PlanExprOp>> {
        let evaluation = Self::parse_expression_in_unit(
            expr_bytes,
            endian,
            unit,
            dwarf,
            address,
            get_cfa,
            function_context,
            cfi_index,
        )?;
        Self::evaluation_result_to_steps(evaluation)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse_expression_as_cfa_in_unit(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Option<CfaResult>> {
        let evaluation = Self::parse_expression_in_unit(
            expr_bytes,
            endian,
            unit,
            dwarf,
            address,
            get_cfa,
            function_context,
            cfi_index,
        )?;
        Ok(Self::evaluation_result_to_cfa(evaluation))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn parse_location_lists_as_cfa(
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Option<CfaResult>> {
        let evaluation = Self::parse_location_lists(
            unit,
            dwarf,
            offset,
            address,
            get_cfa,
            function_context,
            cfi_index,
        )?;
        Ok(Self::evaluation_result_to_cfa(evaluation))
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_expression_with_context(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        encoding: gimli::Encoding,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        if expr_bytes.is_empty() {
            return Ok(EvaluationResult::Optimized);
        }

        // Parse all expressions through unified handler
        Self::parse_full_expression(
            expr_bytes,
            endian,
            encoding,
            dwarf,
            unit,
            address,
            get_cfa,
            function_context,
            cfi_index,
            depth,
        )
    }

    fn evaluation_result_to_steps(evaluation: EvaluationResult) -> Result<Vec<PlanExprOp>> {
        match evaluation {
            EvaluationResult::DirectValue(DirectValueResult::RegisterValue(register)) => {
                Ok(vec![PlanExprOp::LoadRegister(register)])
            }
            EvaluationResult::DirectValue(DirectValueResult::Constant(value)) => {
                Ok(vec![PlanExprOp::PushConstant(value)])
            }
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(address)) => {
                Ok(vec![PlanExprOp::PushConstant(address as i64)])
            }
            EvaluationResult::DirectValue(DirectValueResult::ComputedValue { steps, .. }) => {
                Ok(steps)
            }
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                ..
            }) => Ok(Self::register_address_steps(register, offset)),
            EvaluationResult::MemoryLocation(LocationResult::Address(address)) => {
                Ok(vec![PlanExprOp::PushConstant(address as i64)])
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                Ok(steps)
            }
            EvaluationResult::DirectValue(DirectValueResult::ImplicitValue(_)) => Err(
                anyhow::anyhow!("DWARF expression lowered to implicit bytes, not PlanExprOp[]"),
            ),
            EvaluationResult::Optimized => Err(anyhow::anyhow!(
                "DWARF expression optimized out, no PlanExprOp[]"
            )),
            EvaluationResult::Composite(_) => Err(anyhow::anyhow!(
                "composite DWARF expression cannot be represented as one PlanExprOp[]"
            )),
        }
    }

    fn evaluation_result_to_cfa(evaluation: EvaluationResult) -> Option<CfaResult> {
        match evaluation {
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                ..
            }) => Some(CfaResult::RegisterPlusOffset {
                register,
                offset: offset.unwrap_or(0),
            }),
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                Some(CfaResult::Expression { steps })
            }
            EvaluationResult::MemoryLocation(LocationResult::Address(address)) => {
                Some(CfaResult::Expression {
                    steps: vec![PlanExprOp::PushConstant(address as i64)],
                })
            }
            EvaluationResult::DirectValue(DirectValueResult::Constant(value)) => {
                Some(CfaResult::Expression {
                    steps: vec![PlanExprOp::PushConstant(value)],
                })
            }
            EvaluationResult::DirectValue(DirectValueResult::RegisterValue(register)) => {
                Some(CfaResult::RegisterPlusOffset {
                    register,
                    offset: 0,
                })
            }
            EvaluationResult::DirectValue(DirectValueResult::ImplicitValue(bytes))
                if bytes.len() == 8 =>
            {
                let mut value = [0u8; 8];
                value.copy_from_slice(&bytes);
                Some(CfaResult::Expression {
                    steps: vec![PlanExprOp::PushConstant(u64::from_le_bytes(value) as i64)],
                })
            }
            _ => None,
        }
    }

    fn register_address_steps(register: u16, offset: Option<i64>) -> Vec<PlanExprOp> {
        let mut steps = vec![PlanExprOp::LoadRegister(register)];
        if let Some(offset) = offset.filter(|offset| *offset != 0) {
            steps.push(PlanExprOp::PushConstant(offset));
            steps.push(PlanExprOp::Add);
        }
        steps
    }

    fn resolve_address_index(
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        index: gimli::DebugAddrIndex<usize>,
    ) -> Result<u64> {
        let op = Operation::<DwarfReader>::AddressIndex { index };
        let Some(dwarf) = dwarf else {
            return Err(
                crate::dwarf_expr::ops::unsupported_operation_error_with_detail(
                    "DWARF expression",
                    &op,
                    format!(
                        "DW_OP_addrx requires DWARF context to resolve .debug_addr index {index:?}"
                    ),
                ),
            );
        };
        let Some(unit) = unit else {
            return Err(
                crate::dwarf_expr::ops::unsupported_operation_error_with_detail(
                    "DWARF expression",
                    &op,
                    format!(
                        "DW_OP_addrx requires unit context to resolve .debug_addr index {index:?}"
                    ),
                ),
            );
        };
        dwarf.address(unit, index).map_err(|err| {
            anyhow::anyhow!("failed to resolve DW_OP_addrx index {:?}: {}", index, err)
        })
    }

    fn has_piece_expression<R>(operations: &[ParsedOperation<R>]) -> bool
    where
        R: Reader<Offset = usize>,
    {
        operations.iter().any(|op| {
            matches!(
                op,
                ParsedOperation::Operation(Operation::Piece {
                    bit_offset: None,
                    ..
                })
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_parsed_operations<R>(
        operations: &[ParsedOperation<R>],
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        depth: usize,
    ) -> Result<EvaluationResult>
    where
        R: Reader<Offset = usize>,
    {
        if operations.is_empty() {
            return Err(anyhow::anyhow!("Empty expression"));
        }

        // Fast path for single operations - avoid compute processing.
        if operations.len() == 1 {
            if let ParsedOperation::Operation(op) = &operations[0] {
                return Self::handle_single_operation(op, dwarf, unit, address, get_cfa, depth);
            }
        }

        let mut steps = Vec::new();
        let mut has_stack_value = false;
        let mut has_link_time_address = false;

        for op in operations {
            match op {
                ParsedOperation::PrecomputedSteps {
                    steps: precomputed,
                    forces_stack_value,
                } => {
                    if *forces_stack_value {
                        has_stack_value = true;
                    }
                    steps.extend(precomputed.iter().cloned());
                }
                ParsedOperation::Operation(Operation::RegisterOffset {
                    register, offset, ..
                }) => {
                    steps.push(PlanExprOp::LoadRegister(register.0));
                    if *offset != 0 {
                        steps.push(PlanExprOp::PushConstant(*offset));
                        steps.push(PlanExprOp::Add);
                    }
                }
                ParsedOperation::Operation(Operation::Register { register }) => {
                    steps.push(PlanExprOp::LoadRegister(register.0));
                }
                ParsedOperation::Operation(Operation::FrameOffset { offset }) => {
                    let Some(get_cfa_fn) = get_cfa else {
                        return Err(anyhow::anyhow!("DW_OP_fbreg but no CFA provider available"));
                    };
                    let Some(cfa) = get_cfa_fn(address)? else {
                        return Err(anyhow::anyhow!(
                            "DW_OP_fbreg but no CFA available at address 0x{:x}",
                            address
                        ));
                    };

                    match cfa {
                        crate::core::CfaResult::RegisterPlusOffset {
                            register,
                            offset: cfa_offset,
                        } => {
                            steps.push(PlanExprOp::LoadRegister(register));
                            let total_offset = cfa_offset.saturating_add(*offset);
                            if total_offset != 0 {
                                steps.push(PlanExprOp::PushConstant(total_offset));
                                steps.push(PlanExprOp::Add);
                            }
                        }
                        crate::core::CfaResult::Expression {
                            steps: mut cfa_steps,
                        } => {
                            steps.append(&mut cfa_steps);
                            if *offset != 0 {
                                steps.push(PlanExprOp::PushConstant(*offset));
                                steps.push(PlanExprOp::Add);
                            }
                        }
                    }
                }
                ParsedOperation::Operation(Operation::PlusConstant { value }) => {
                    steps.push(PlanExprOp::PushConstant(*value as i64));
                    steps.push(PlanExprOp::Add);
                }
                ParsedOperation::Operation(Operation::Plus) => steps.push(PlanExprOp::Add),
                ParsedOperation::Operation(Operation::Minus) => steps.push(PlanExprOp::Sub),
                ParsedOperation::Operation(Operation::Mul) => steps.push(PlanExprOp::Mul),
                ParsedOperation::Operation(Operation::Div) => steps.push(PlanExprOp::Div),
                ParsedOperation::Operation(Operation::Mod) => steps.push(PlanExprOp::Mod),
                ParsedOperation::Operation(Operation::And) => steps.push(PlanExprOp::And),
                ParsedOperation::Operation(Operation::Or) => steps.push(PlanExprOp::Or),
                ParsedOperation::Operation(Operation::Xor) => steps.push(PlanExprOp::Xor),
                ParsedOperation::Operation(Operation::Shl) => steps.push(PlanExprOp::Shl),
                ParsedOperation::Operation(Operation::Shr) => steps.push(PlanExprOp::Shr),
                ParsedOperation::Operation(Operation::Shra) => steps.push(PlanExprOp::Shra),
                ParsedOperation::Operation(Operation::Not) => steps.push(PlanExprOp::Not),
                ParsedOperation::Operation(Operation::Neg) => steps.push(PlanExprOp::Neg),
                ParsedOperation::Operation(Operation::Abs) => steps.push(PlanExprOp::Abs),
                ParsedOperation::Operation(Operation::Eq) => steps.push(PlanExprOp::Eq),
                ParsedOperation::Operation(Operation::Ne) => steps.push(PlanExprOp::Ne),
                ParsedOperation::Operation(Operation::Lt) => steps.push(PlanExprOp::Lt),
                ParsedOperation::Operation(Operation::Le) => steps.push(PlanExprOp::Le),
                ParsedOperation::Operation(Operation::Gt) => steps.push(PlanExprOp::Gt),
                ParsedOperation::Operation(Operation::Ge) => steps.push(PlanExprOp::Ge),
                ParsedOperation::Operation(Operation::UnsignedConstant { value }) => {
                    steps.push(PlanExprOp::PushConstant(*value as i64));
                }
                ParsedOperation::Operation(Operation::SignedConstant { value }) => {
                    steps.push(PlanExprOp::PushConstant(*value));
                }
                ParsedOperation::Operation(Operation::Address { address }) => {
                    steps.push(PlanExprOp::PushConstant(*address as i64));
                    has_link_time_address = true;
                }
                ParsedOperation::Operation(Operation::AddressIndex { index }) => {
                    let resolved = Self::resolve_address_index(dwarf, unit, *index)?;
                    steps.push(PlanExprOp::PushConstant(resolved as i64));
                    has_link_time_address = true;
                }
                ParsedOperation::Operation(Operation::StackValue) => {
                    has_stack_value = true;
                }
                ParsedOperation::Operation(op @ Operation::Deref { size, space, .. }) => {
                    if *space {
                        return Err(crate::dwarf_expr::ops::unsupported_operation_error(
                            "DWARF expression",
                            op,
                        ));
                    }
                    let mem_size = match size {
                        1 => MemoryAccessSize::U8,
                        2 => MemoryAccessSize::U16,
                        4 => MemoryAccessSize::U32,
                        8 => MemoryAccessSize::U64,
                        _ => {
                            return Err(anyhow::anyhow!(
                                "unsupported DWARF dereference size {} in operation: {:?}",
                                size,
                                op
                            ))
                        }
                    };
                    steps.push(PlanExprOp::Dereference { size: mem_size });
                }
                ParsedOperation::Operation(Operation::Nop) => {}
                ParsedOperation::Operation(op) => {
                    return Err(crate::dwarf_expr::ops::unsupported_operation_error(
                        "DWARF expression",
                        op,
                    ));
                }
            }
        }

        if steps.is_empty() {
            return Err(anyhow::anyhow!(
                "Could not parse multi-operation expression"
            ));
        }

        if steps.len() == 1 {
            match &steps[0] {
                PlanExprOp::LoadRegister(reg) => {
                    if has_stack_value {
                        return Ok(EvaluationResult::DirectValue(
                            DirectValueResult::RegisterValue(*reg),
                        ));
                    }
                    return Ok(EvaluationResult::MemoryLocation(
                        LocationResult::RegisterAddress {
                            register: *reg,
                            offset: None,
                            size: None,
                        },
                    ));
                }
                PlanExprOp::PushConstant(val) => {
                    if has_stack_value {
                        if has_link_time_address && *val >= 0 {
                            return Ok(EvaluationResult::DirectValue(
                                DirectValueResult::AbsoluteAddress(*val as u64),
                            ));
                        }
                        return Ok(EvaluationResult::DirectValue(DirectValueResult::Constant(
                            *val,
                        )));
                    }
                    return Ok(EvaluationResult::MemoryLocation(LocationResult::Address(
                        *val as u64,
                    )));
                }
                _ => {}
            }
        } else if steps.len() == 3
            && matches!(steps[0], PlanExprOp::LoadRegister(_))
            && matches!(steps[1], PlanExprOp::PushConstant(_))
            && matches!(steps[2], PlanExprOp::Add)
        {
            if let (PlanExprOp::LoadRegister(reg), PlanExprOp::PushConstant(offset)) =
                (&steps[0], &steps[1])
            {
                if !has_stack_value {
                    return Ok(EvaluationResult::MemoryLocation(
                        LocationResult::RegisterAddress {
                            register: *reg,
                            offset: Some(*offset),
                            size: None,
                        },
                    ));
                }
            }
        }

        if has_stack_value {
            if has_link_time_address {
                if let Some(address) = Self::fold_constant_steps_to_u64(&steps) {
                    return Ok(EvaluationResult::DirectValue(
                        DirectValueResult::AbsoluteAddress(address),
                    ));
                }
            }
            Ok(EvaluationResult::DirectValue(
                DirectValueResult::ComputedValue {
                    steps,
                    result_size: MemoryAccessSize::U64,
                },
            ))
        } else {
            Ok(EvaluationResult::MemoryLocation(
                LocationResult::ComputedLocation { steps },
            ))
        }
    }

    fn fold_constant_steps_to_u64(steps: &[PlanExprOp]) -> Option<u64> {
        let mut stack = Vec::new();
        for step in steps {
            match step {
                PlanExprOp::PushConstant(value) => stack.push(*value),
                PlanExprOp::Add => {
                    let rhs = stack.pop()?;
                    let lhs = stack.pop()?;
                    stack.push(lhs.saturating_add(rhs));
                }
                _ => return None,
            }
        }

        (stack.len() == 1 && stack[0] >= 0).then_some(stack[0] as u64)
    }

    #[allow(clippy::too_many_arguments)]
    fn lower_piece_expression<R>(
        operations: &[ParsedOperation<R>],
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        depth: usize,
    ) -> Result<EvaluationResult>
    where
        R: Reader<Offset = usize>,
    {
        let mut pieces = Vec::new();
        let mut segment_start = 0usize;
        let mut composite_bit_offset = 0u64;

        for (idx, op) in operations.iter().enumerate() {
            let ParsedOperation::Operation(Operation::Piece {
                size_in_bits,
                bit_offset,
            }) = op
            else {
                continue;
            };

            if bit_offset.is_some() {
                return Err(crate::dwarf_expr::ops::unsupported_operation_error(
                    "DWARF expression",
                    match op {
                        ParsedOperation::Operation(op) => op,
                        ParsedOperation::PrecomputedSteps { .. } => unreachable!(),
                    },
                ));
            }
            if size_in_bits % 8 != 0 {
                return Err(anyhow::anyhow!(
                    "DW_OP_piece size {size_in_bits} is not byte-aligned"
                ));
            }

            let segment = &operations[segment_start..idx];
            let location = if segment.is_empty() {
                EvaluationResult::Optimized
            } else {
                Self::lower_parsed_operations(segment, dwarf, unit, address, get_cfa, depth)?
            };

            if matches!(location, EvaluationResult::Composite(_)) {
                return Err(anyhow::anyhow!(
                    "nested DW_OP_piece composite expressions are not supported"
                ));
            }

            pieces.push(PieceResult {
                location,
                size: size_in_bits / 8,
                bit_offset: Some(composite_bit_offset),
            });
            composite_bit_offset = composite_bit_offset.saturating_add(*size_in_bits);
            segment_start = idx + 1;
        }

        if segment_start < operations.len() {
            return Err(anyhow::anyhow!(
                "DW_OP_piece expression has trailing operations without a piece size"
            ));
        }

        Ok(EvaluationResult::Composite(pieces))
    }

    /// Parse a full multi-operation DWARF expression
    #[allow(clippy::too_many_arguments)]
    fn parse_full_expression(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        encoding: gimli::Encoding,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        let mut operations: Vec<ParsedOperation<_>> = Vec::new();

        // Parse all operations in the expression
        for op in expr_errors::hard(
            DwarfExprMode::Location,
            crate::dwarf_expr::ops::parse_ops(
                EndianSlice::new(expr_bytes, endian),
                encoding,
                "DWARF expression",
            ),
        )? {
            match &op {
                // Lower supported DW_OP_entry_value forms through caller-side
                // call-site metadata. This keeps optimized parameters usable
                // after their entry registers have been clobbered.
                Operation::EntryValue { expression } => {
                    match crate::dwarf_expr::entry_value::lower_location_entry_value(
                        *expression,
                        encoding,
                        crate::dwarf_expr::entry_value::LocationContext {
                            current_pc: address,
                            address_size: encoding.address_size,
                            dwarf,
                            function_context,
                            cfi_index,
                        },
                    )? {
                        crate::dwarf_expr::entry_value::LoweredEntryValue::Steps {
                            steps,
                            forces_stack_value,
                        } => {
                            operations.push(ParsedOperation::PrecomputedSteps {
                                steps,
                                forces_stack_value,
                            });
                        }
                        crate::dwarf_expr::entry_value::LoweredEntryValue::Optimized => {
                            return Ok(EvaluationResult::Optimized);
                        }
                    }
                }
                _ => operations.push(ParsedOperation::Operation(op)),
            }
        }

        if operations.is_empty() {
            return Err(anyhow::anyhow!("Empty expression"));
        }

        debug!("Parsed {} operations in expression", operations.len());

        if Self::has_piece_expression(&operations) {
            return Self::lower_piece_expression(&operations, dwarf, unit, address, get_cfa, depth);
        }

        Self::lower_parsed_operations(&operations, dwarf, unit, address, get_cfa, depth)
    }

    /// Handle single DWARF operation - fast path without compute processing
    fn handle_single_operation<R>(
        op: &Operation<R>,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        unit: Option<&gimli::Unit<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        depth: usize,
    ) -> Result<EvaluationResult>
    where
        R: gimli::Reader<Offset = usize>,
    {
        use crate::core::{CfaResult, PlanExprOp};

        match op {
            // Direct register value
            Operation::Register { register } => {
                debug!("Single DW_OP_reg{} - direct register value", register.0);
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::RegisterValue(register.0),
                ))
            }

            // Register + offset memory location
            Operation::RegisterOffset {
                register,
                offset,
                base_type: _,
            } => {
                debug!(
                    "Single DW_OP_breg{} with offset {} - memory location",
                    register.0, offset
                );
                Ok(EvaluationResult::MemoryLocation(
                    LocationResult::RegisterAddress {
                        register: register.0,
                        offset: if *offset != 0 { Some(*offset) } else { None },
                        size: None,
                    },
                ))
            }

            // Frame base + offset
            Operation::FrameOffset { offset } => {
                debug!(
                    "Single DW_OP_fbreg with offset {} - frame relative location",
                    offset
                );

                if let Some(get_cfa_fn) = get_cfa {
                    if let Ok(Some(cfa)) = get_cfa_fn(address) {
                        match cfa {
                            CfaResult::RegisterPlusOffset {
                                register,
                                offset: cfa_offset,
                            } => Ok(EvaluationResult::MemoryLocation(
                                LocationResult::RegisterAddress {
                                    register,
                                    offset: Some(cfa_offset.saturating_add(*offset)),
                                    size: None,
                                },
                            )),
                            CfaResult::Expression { mut steps } => {
                                steps.push(PlanExprOp::PushConstant(*offset));
                                steps.push(PlanExprOp::Add);
                                Ok(EvaluationResult::MemoryLocation(
                                    LocationResult::ComputedLocation { steps },
                                ))
                            }
                        }
                    } else {
                        Err(anyhow::anyhow!(
                            "DW_OP_fbreg but no CFA available at address 0x{:x}",
                            address
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!("DW_OP_fbreg but no CFA provider available"))
                }
            }

            // Direct memory address
            Operation::Address { address } => {
                debug!(
                    "Single DW_OP_addr at 0x{:x} - direct memory address",
                    address
                );
                Ok(EvaluationResult::MemoryLocation(LocationResult::Address(
                    *address,
                )))
            }
            Operation::AddressIndex { index } => {
                let resolved = Self::resolve_address_index(dwarf, unit, *index)?;
                debug!(
                    "Single DW_OP_addrx {:?} -> 0x{:x} - direct memory address",
                    index, resolved
                );
                Ok(EvaluationResult::MemoryLocation(LocationResult::Address(
                    resolved,
                )))
            }

            // Constant values
            Operation::UnsignedConstant { value } => {
                debug!("Single DW_OP_constu {} - constant value", value);
                Ok(EvaluationResult::DirectValue(DirectValueResult::Constant(
                    *value as i64,
                )))
            }
            Operation::SignedConstant { value } => {
                debug!("Single DW_OP_const {} - constant value", value);
                Ok(EvaluationResult::DirectValue(DirectValueResult::Constant(
                    *value,
                )))
            }

            // Implicit value - value is encoded in the expression
            Operation::ImplicitValue { data } => {
                let data_slice = data.to_slice()?;
                debug!(
                    "Single DW_OP_implicit_value - implicit value with {} bytes",
                    data_slice.len()
                );
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::ImplicitValue(data_slice.to_vec()),
                ))
            }
            Operation::ImplicitPointer { value, byte_offset } => {
                let Some(dwarf) = dwarf else {
                    return Err(anyhow::anyhow!(
                        "DW_OP_implicit_pointer requires DWARF context"
                    ));
                };
                Self::resolve_implicit_pointer(*value, *byte_offset, dwarf, address, get_cfa, depth)
            }

            // These operations don't make sense as single operations
            Operation::StackValue => Err(
                crate::dwarf_expr::ops::unsupported_operation_error_with_detail(
                    "single DWARF expression",
                    op,
                    "DW_OP_stack_value cannot be a standalone location expression",
                ),
            ),
            Operation::PlusConstant { .. } => Err(
                crate::dwarf_expr::ops::unsupported_operation_error_with_detail(
                    "single DWARF expression",
                    op,
                    "DW_OP_plus_uconst requires a base value",
                ),
            ),
            _ => Err(crate::dwarf_expr::ops::unsupported_operation_error(
                "single DWARF expression",
                op,
            )),
        }
    }

    fn resolve_implicit_pointer(
        value: gimli::DebugInfoOffset<usize>,
        byte_offset: i64,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        if depth >= Self::MAX_IMPLICIT_POINTER_DEPTH {
            return Err(anyhow::anyhow!(
                "DW_OP_implicit_pointer recursion depth exceeded"
            ));
        }

        let mut headers = dwarf.units();
        let mut containing_header = None;
        while let Some(header) = headers.next()? {
            if value.to_unit_offset(&header).is_some() {
                containing_header = Some(header);
                break;
            }
        }
        let header = containing_header.ok_or_else(|| {
            anyhow::anyhow!(
                "DW_OP_implicit_pointer target 0x{:x} is not inside any compilation unit",
                value.0
            )
        })?;
        let unit_offset = value.to_unit_offset(&header).ok_or_else(|| {
            anyhow::anyhow!(
                "DW_OP_implicit_pointer target 0x{:x} is outside its compilation unit",
                value.0
            )
        })?;
        let unit = dwarf
            .unit(header)
            .map_err(|e| anyhow::anyhow!("DW_OP_implicit_pointer unit parse failed: {e}"))?;
        let entry = unit
            .entry(unit_offset)
            .map_err(|e| anyhow::anyhow!("DW_OP_implicit_pointer entry parse failed: {e}"))?;
        let referenced = Self::evaluate_location_result_with_depth(
            &entry,
            &unit,
            dwarf,
            address,
            get_cfa,
            None,
            None,
            depth + 1,
        )
        .map_err(|e| anyhow::anyhow!("DW_OP_implicit_pointer target evaluation failed: {e}"))?;

        Self::addressable_location_to_pointer_value(referenced, byte_offset)
    }

    fn addressable_location_to_pointer_value(
        location: EvaluationResult,
        byte_offset: i64,
    ) -> Result<EvaluationResult> {
        use crate::core::{DirectValueResult, EvaluationResult, LocationResult, PlanExprOp};

        fn checked_add_i64(base: i64, delta: i64) -> Result<i64> {
            base.checked_add(delta)
                .ok_or_else(|| anyhow::anyhow!("implicit pointer offset overflow"))
        }

        fn checked_add_u64(base: u64, delta: i64) -> Result<u64> {
            if delta >= 0 {
                base.checked_add(delta as u64)
                    .ok_or_else(|| anyhow::anyhow!("implicit pointer offset overflow"))
            } else {
                base.checked_sub(delta.unsigned_abs())
                    .ok_or_else(|| anyhow::anyhow!("implicit pointer offset underflow"))
            }
        }

        match location {
            EvaluationResult::MemoryLocation(LocationResult::Address(addr)) => {
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::AbsoluteAddress(checked_add_u64(addr, byte_offset)?),
                ))
            }
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register,
                offset,
                ..
            }) => {
                let total_offset = checked_add_i64(offset.unwrap_or(0), byte_offset)?;
                if total_offset == 0 {
                    Ok(EvaluationResult::DirectValue(
                        DirectValueResult::RegisterValue(register),
                    ))
                } else {
                    Ok(EvaluationResult::DirectValue(
                        DirectValueResult::ComputedValue {
                            steps: vec![
                                PlanExprOp::LoadRegister(register),
                                PlanExprOp::PushConstant(total_offset),
                                PlanExprOp::Add,
                            ],
                            result_size: MemoryAccessSize::U64,
                        },
                    ))
                }
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { mut steps }) => {
                if byte_offset != 0 {
                    steps.push(PlanExprOp::PushConstant(byte_offset));
                    steps.push(PlanExprOp::Add);
                }
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::ComputedValue {
                        steps,
                        result_size: MemoryAccessSize::U64,
                    },
                ))
            }
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(addr)) => {
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::AbsoluteAddress(checked_add_u64(addr, byte_offset)?),
                ))
            }
            EvaluationResult::Optimized => Ok(EvaluationResult::Optimized),
            EvaluationResult::Composite(_) => Err(anyhow::anyhow!(
                "DW_OP_implicit_pointer target is a composite location"
            )),
            EvaluationResult::DirectValue(_) => Err(anyhow::anyhow!(
                "DW_OP_implicit_pointer target has no addressable location"
            )),
        }
    }

    /// Parse location lists from .debug_loclists or .debug_loc section
    pub fn parse_location_lists(
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<EvaluationResult> {
        Self::parse_location_lists_with_depth(
            unit,
            dwarf,
            offset,
            address,
            get_cfa,
            function_context,
            cfi_index,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn parse_location_lists_with_depth(
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        offset: gimli::LocationListsOffset<usize>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        debug!(
            "Getting location lists for offset 0x{:x} (dwarf.locations method)",
            offset.0
        );

        let mut locations = match dwarf.locations(unit, offset) {
            Ok(locations) => {
                debug!(
                    "Successfully got locations iterator for offset 0x{:x}",
                    offset.0
                );
                locations
            }
            Err(e) => {
                debug!(
                    "Failed to get location lists for offset 0x{:x}: {:?}",
                    offset.0, e
                );
                return Ok(EvaluationResult::Optimized);
            }
        };

        let mut entry_count = 0;

        // Parse location list entries
        // For now, we'll take the first valid entry as a simplification
        // In a full implementation, we'd need to track PC ranges
        loop {
            let next_result = locations.next();
            match next_result {
                Ok(Some(location_list_entry)) => {
                    entry_count += 1;
                    let start_pc = location_list_entry.range.begin;
                    let end_pc = location_list_entry.range.end;

                    debug!(
                        "Location list entry #{}: PC 0x{:x}-0x{:x} (range length: {})",
                        entry_count,
                        start_pc,
                        end_pc,
                        end_pc.saturating_sub(start_pc)
                    );

                    // Check for zero-length ranges - these are valid in DWARF (point locations)
                    if start_pc == end_pc {
                        debug!(
                            "  Zero-length address range [0x{:x}, 0x{:x}) - point location",
                            start_pc, end_pc
                        );
                    }

                    debug!(
                        "  Raw expression data length: {}",
                        location_list_entry.data.0.len()
                    );

                    // Parse the expression data for this PC range
                    // Use the actual PC range for address-specific parsing
                    let location_expr = Self::parse_expression_with_context(
                        location_list_entry
                            .data
                            .0
                            .to_slice()
                            .ok()
                            .as_deref()
                            .unwrap_or(&[]),
                        location_list_entry.data.0.endian(),
                        unit.encoding(),
                        Some(dwarf),
                        Some(unit),
                        address,
                        get_cfa,
                        function_context,
                        cfi_index,
                        depth,
                    )?;

                    debug!("  Parsed expression: {:?}", location_expr);

                    let contains_address = range_contains_pc(start_pc, end_pc, address);

                    if contains_address && !matches!(location_expr, EvaluationResult::Optimized) {
                        return Ok(location_expr);
                    }
                }
                Ok(None) => {
                    debug!(
                        "Reached end of location list entries, processed {} entries",
                        entry_count
                    );
                    break;
                }
                Err(e) => {
                    debug!(
                        "Error iterating location list at offset 0x{:x}: {:?}",
                        offset.0, e
                    );
                    break;
                }
            }
        }

        if entry_count == 0 {
            debug!(
                "No entries returned by gimli::locations, attempting raw fallback for offset 0x{:x}",
                offset.0
            );

            if let Ok(mut raw_iter) = dwarf.raw_locations(unit, offset) {
                let mut base_address = unit.low_pc;

                while let Some(raw_entry) = raw_iter.next()? {
                    match raw_entry {
                        RawLocListEntry::BaseAddress { addr } => {
                            base_address = addr;
                        }
                        RawLocListEntry::BaseAddressx { addr } => {
                            if let Ok(resolved) = dwarf.address(unit, addr) {
                                base_address = resolved;
                            }
                        }
                        RawLocListEntry::StartLength {
                            begin,
                            length,
                            data,
                        } => {
                            debug!(
                                "  Raw fallback StartLength begin=0x{:x} length={}",
                                begin, length
                            );
                            let start = begin;
                            let end = begin.wrapping_add(length);
                            let contains = range_contains_pc(start, end, address);

                            debug!(
                                "   StartLength contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression_with_context(
                                    data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                    data.0.endian(),
                                    unit.encoding(),
                                    Some(dwarf),
                                    Some(unit),
                                    address,
                                    get_cfa,
                                    function_context,
                                    cfi_index,
                                    depth,
                                )?;

                                debug!("   Raw fallback expression result: {:?}", location_expr);

                                if !matches!(location_expr, EvaluationResult::Optimized) {
                                    debug!(
                                        "Raw fallback matched StartLength entry at 0x{:x}-0x{:x}",
                                        start, end
                                    );
                                    return Ok(location_expr);
                                }
                            }
                        }
                        RawLocListEntry::StartEnd { begin, end, data } => {
                            debug!(
                                "  Raw fallback StartEnd begin=0x{:x} end=0x{:x}",
                                begin, end
                            );
                            let contains = range_contains_pc(begin, end, address);

                            debug!(
                                "   StartEnd contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression_with_context(
                                    data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                    data.0.endian(),
                                    unit.encoding(),
                                    Some(dwarf),
                                    Some(unit),
                                    address,
                                    get_cfa,
                                    function_context,
                                    cfi_index,
                                    depth,
                                )?;

                                debug!("   Raw fallback expression result: {:?}", location_expr);

                                if !matches!(location_expr, EvaluationResult::Optimized) {
                                    debug!(
                                        "Raw fallback matched StartEnd entry at 0x{:x}-0x{:x}",
                                        begin, end
                                    );
                                    return Ok(location_expr);
                                }
                            }
                        }
                        RawLocListEntry::OffsetPair { begin, end, data }
                        | RawLocListEntry::AddressOrOffsetPair { begin, end, data } => {
                            debug!(
                                "  Raw fallback OffsetPair begin=0x{:x} end=0x{:x} base=0x{:x}",
                                begin, end, base_address
                            );
                            let start = base_address.wrapping_add(begin);
                            let end_addr = base_address.wrapping_add(end);
                            let contains = range_contains_pc(start, end_addr, address);

                            debug!(
                                "   OffsetPair contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression_with_context(
                                    data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                    data.0.endian(),
                                    unit.encoding(),
                                    Some(dwarf),
                                    Some(unit),
                                    address,
                                    get_cfa,
                                    function_context,
                                    cfi_index,
                                    depth,
                                )?;

                                debug!("   Raw fallback expression result: {:?}", location_expr);

                                if !matches!(location_expr, EvaluationResult::Optimized) {
                                    debug!(
                                        "Raw fallback matched OffsetPair entry at 0x{:x}-0x{:x}",
                                        start, end_addr
                                    );
                                    return Ok(location_expr);
                                }
                            }
                        }
                        RawLocListEntry::StartxLength {
                            begin,
                            length,
                            data,
                        } => {
                            if let Ok(start) = dwarf.address(unit, begin) {
                                debug!(
                                    "  Raw fallback StartxLength begin=0x{:x} length={}",
                                    start, length
                                );
                                let end = start.wrapping_add(length);
                                let contains = range_contains_pc(start, end, address);

                                debug!(
                                    "   StartxLength contains={} (address=0x{:x})",
                                    contains, address
                                );

                                if contains {
                                    let location_expr = Self::parse_expression_with_context(
                                        data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                        data.0.endian(),
                                        unit.encoding(),
                                        Some(dwarf),
                                        Some(unit),
                                        address,
                                        get_cfa,
                                        function_context,
                                        cfi_index,
                                        depth,
                                    )?;

                                    debug!(
                                        "   Raw fallback expression result: {:?}",
                                        location_expr
                                    );

                                    if !matches!(location_expr, EvaluationResult::Optimized) {
                                        debug!(
                                            "Raw fallback matched StartxLength entry at 0x{:x}-0x{:x}",
                                            start, end
                                        );
                                        return Ok(location_expr);
                                    }
                                }
                            }
                        }
                        RawLocListEntry::StartxEndx { begin, end, data } => {
                            if let (Ok(start), Ok(end_addr)) =
                                (dwarf.address(unit, begin), dwarf.address(unit, end))
                            {
                                debug!(
                                    "  Raw fallback StartxEndx begin=0x{:x} end=0x{:x}",
                                    start, end_addr
                                );
                                let contains = range_contains_pc(start, end_addr, address);

                                debug!(
                                    "   StartxEndx contains={} (address=0x{:x})",
                                    contains, address
                                );

                                if contains {
                                    let location_expr = Self::parse_expression_with_context(
                                        data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                        data.0.endian(),
                                        unit.encoding(),
                                        Some(dwarf),
                                        Some(unit),
                                        address,
                                        get_cfa,
                                        function_context,
                                        cfi_index,
                                        depth,
                                    )?;

                                    debug!(
                                        "   Raw fallback expression result: {:?}",
                                        location_expr
                                    );

                                    if !matches!(location_expr, EvaluationResult::Optimized) {
                                        debug!(
                                            "Raw fallback matched StartxEndx entry at 0x{:x}-0x{:x}",
                                            start, end_addr
                                        );
                                        return Ok(location_expr);
                                    }
                                }
                            }
                        }
                        RawLocListEntry::DefaultLocation { data } => {
                            debug!("  Raw fallback default location entry");
                            let location_expr = Self::parse_expression_with_context(
                                data.0.to_slice().ok().as_deref().unwrap_or(&[]),
                                data.0.endian(),
                                unit.encoding(),
                                Some(dwarf),
                                Some(unit),
                                address,
                                get_cfa,
                                function_context,
                                cfi_index,
                                depth,
                            )?;

                            debug!("   Raw fallback expression result: {:?}", location_expr);

                            if !matches!(location_expr, EvaluationResult::Optimized) {
                                debug!("Raw fallback matched default location entry");
                                return Ok(location_expr);
                            }
                        }
                    }
                }
            }
        }

        // If we didn't find any valid expressions, return optimized out
        debug!(
            "No valid location expressions found in {} entries at offset 0x{:x}",
            entry_count, offset.0
        );
        Ok(EvaluationResult::Optimized)
    }
}

#[cfg(test)]
mod tests {
    use super::ExpressionEvaluator;
    use crate::core::{
        CfaResult, DirectValueResult, EvaluationResult, LocationResult, MemoryAccessSize,
        PieceResult, PlanExprOp,
    };
    use gimli::constants;
    use gimli::RunTimeEndian;

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 5,
            address_size: 8,
        }
    }

    fn encode_uleb(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
        out
    }

    fn encode_sleb(mut value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (value as u8) & 0x7f;
            value >>= 7;
            let sign_bit_set = (byte & 0x40) != 0;
            let done = (value == 0 && !sign_bit_set) || (value == -1 && sign_bit_set);
            if !done {
                byte |= 0x80;
            }
            out.push(byte);
            if done {
                break;
            }
        }
        out
    }

    fn parse_test_expr(bytes: &[u8]) -> anyhow::Result<EvaluationResult> {
        ExpressionEvaluator::parse_expression_with_context(
            bytes,
            RunTimeEndian::Little,
            test_encoding(),
            None,
            None,
            0,
            None,
            None,
            None,
            0,
        )
    }

    fn addr_expr(address: u64) -> Vec<u8> {
        let mut bytes = vec![constants::DW_OP_addr.0];
        bytes.extend(address.to_le_bytes());
        bytes
    }

    fn regx_expr(register: u64) -> Vec<u8> {
        let mut bytes = vec![constants::DW_OP_regx.0];
        bytes.extend(encode_uleb(register));
        bytes
    }

    fn bregx_expr(register: u64, offset: i64) -> Vec<u8> {
        let mut bytes = vec![constants::DW_OP_bregx.0];
        bytes.extend(encode_uleb(register));
        bytes.extend(encode_sleb(offset));
        bytes
    }

    #[test]
    fn dwarf_op_supported_coverage_matrix() {
        let cases = vec![
            (
                "DW_OP_regN",
                vec![constants::DW_OP_reg5.0],
                EvaluationResult::DirectValue(DirectValueResult::RegisterValue(5)),
            ),
            (
                "DW_OP_regx",
                regx_expr(33),
                EvaluationResult::DirectValue(DirectValueResult::RegisterValue(33)),
            ),
            (
                "DW_OP_bregN",
                {
                    let mut bytes = vec![constants::DW_OP_breg7.0];
                    bytes.extend(encode_sleb(8));
                    bytes
                },
                EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                    register: 7,
                    offset: Some(8),
                    size: None,
                }),
            ),
            (
                "DW_OP_bregx",
                bregx_expr(33, -2),
                EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                    register: 33,
                    offset: Some(-2),
                    size: None,
                }),
            ),
            (
                "DW_OP_addr",
                addr_expr(0x1234),
                EvaluationResult::MemoryLocation(LocationResult::Address(0x1234)),
            ),
            (
                "DW_OP_stack_value",
                vec![constants::DW_OP_lit1.0, constants::DW_OP_stack_value.0],
                EvaluationResult::DirectValue(DirectValueResult::Constant(1)),
            ),
            (
                "DW_OP_addr stack value",
                {
                    let mut bytes = addr_expr(0x1234);
                    bytes.push(constants::DW_OP_stack_value.0);
                    bytes
                },
                EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234)),
            ),
            (
                "arithmetic stack value subset",
                vec![
                    constants::DW_OP_lit1.0,
                    constants::DW_OP_lit2.0,
                    constants::DW_OP_plus.0,
                    constants::DW_OP_stack_value.0,
                ],
                EvaluationResult::DirectValue(DirectValueResult::ComputedValue {
                    steps: vec![
                        PlanExprOp::PushConstant(1),
                        PlanExprOp::PushConstant(2),
                        PlanExprOp::Add,
                    ],
                    result_size: MemoryAccessSize::U64,
                }),
            ),
            (
                "DW_OP_implicit_value",
                vec![constants::DW_OP_implicit_value.0, 3, 0xaa, 0xbb, 0xcc],
                EvaluationResult::DirectValue(DirectValueResult::ImplicitValue(vec![
                    0xaa, 0xbb, 0xcc,
                ])),
            ),
            (
                "DW_OP_piece split stack values",
                {
                    let mut bytes = vec![constants::DW_OP_breg5.0];
                    bytes.extend(encode_sleb(1));
                    bytes.push(constants::DW_OP_stack_value.0);
                    bytes.push(constants::DW_OP_piece.0);
                    bytes.extend(encode_uleb(4));
                    bytes.push(constants::DW_OP_breg5.0);
                    bytes.extend(encode_sleb(2));
                    bytes.push(constants::DW_OP_stack_value.0);
                    bytes.push(constants::DW_OP_piece.0);
                    bytes.extend(encode_uleb(4));
                    bytes
                },
                EvaluationResult::Composite(vec![
                    PieceResult {
                        location: EvaluationResult::DirectValue(DirectValueResult::ComputedValue {
                            steps: vec![
                                PlanExprOp::LoadRegister(5),
                                PlanExprOp::PushConstant(1),
                                PlanExprOp::Add,
                            ],
                            result_size: MemoryAccessSize::U64,
                        }),
                        size: 4,
                        bit_offset: Some(0),
                    },
                    PieceResult {
                        location: EvaluationResult::DirectValue(DirectValueResult::ComputedValue {
                            steps: vec![
                                PlanExprOp::LoadRegister(5),
                                PlanExprOp::PushConstant(2),
                                PlanExprOp::Add,
                            ],
                            result_size: MemoryAccessSize::U64,
                        }),
                        size: 4,
                        bit_offset: Some(32),
                    },
                ]),
            ),
            (
                "DW_OP_piece empty segment",
                {
                    let mut bytes = vec![constants::DW_OP_piece.0];
                    bytes.extend(encode_uleb(4));
                    bytes
                },
                EvaluationResult::Composite(vec![PieceResult {
                    location: EvaluationResult::Optimized,
                    size: 4,
                    bit_offset: Some(0),
                }]),
            ),
        ];

        for (name, bytes, expected) in cases {
            let result = parse_test_expr(&bytes).unwrap_or_else(|error| {
                panic!("{name} should parse successfully, bytes={bytes:?}: {error}")
            });
            assert_eq!(result, expected, "{name} lowered incorrectly");
        }
    }

    #[test]
    fn dwarf_op_fbreg_coverage_uses_cfa_provider() {
        let get_cfa = |_address| {
            Ok(Some(CfaResult::RegisterPlusOffset {
                register: 7,
                offset: 16,
            }))
        };
        let mut expr = vec![constants::DW_OP_fbreg.0];
        expr.extend(encode_sleb(4));

        let result = ExpressionEvaluator::parse_expression_with_context(
            &expr,
            RunTimeEndian::Little,
            test_encoding(),
            None,
            None,
            0,
            Some(&get_cfa),
            None,
            None,
            0,
        )
        .expect("DW_OP_fbreg should parse with a CFA provider");

        assert_eq!(
            result,
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register: 7,
                offset: Some(20),
                size: None,
            })
        );
    }

    #[test]
    fn dwarf_frame_base_reg_lowers_to_register_cfa() {
        let cfa = ExpressionEvaluator::evaluation_result_to_cfa(EvaluationResult::DirectValue(
            DirectValueResult::RegisterValue(6),
        ));

        assert_eq!(
            cfa,
            Some(CfaResult::RegisterPlusOffset {
                register: 6,
                offset: 0,
            })
        );
    }

    #[test]
    fn dwarf_op_unsupported_diagnostic_matrix_names_ops() {
        let cases = vec![
            (
                "DW_OP_drop",
                vec![
                    constants::DW_OP_lit1.0,
                    constants::DW_OP_drop.0,
                    constants::DW_OP_stack_value.0,
                ],
                "DW_OP_drop",
            ),
            (
                "DW_OP_bit_piece",
                {
                    let mut bytes = vec![constants::DW_OP_lit1.0, constants::DW_OP_bit_piece.0];
                    bytes.extend(encode_uleb(8));
                    bytes.extend(encode_uleb(0));
                    bytes
                },
                "DW_OP_bit_piece",
            ),
            (
                "DW_OP_addrx",
                {
                    let mut bytes = vec![constants::DW_OP_addrx.0];
                    bytes.extend(encode_uleb(0));
                    bytes
                },
                "DW_OP_addrx",
            ),
            (
                "DW_OP_bra",
                vec![
                    constants::DW_OP_lit1.0,
                    constants::DW_OP_bra.0,
                    0,
                    0,
                    constants::DW_OP_stack_value.0,
                ],
                "DW_OP_bra",
            ),
        ];

        for (name, bytes, expected_op) in cases {
            let error = match parse_test_expr(&bytes) {
                Ok(result) => panic!("{name} should be unsupported, got {result:?}"),
                Err(error) => error,
            };
            let message = error.to_string();
            assert!(
                message.contains(expected_op),
                "{name} diagnostic should mention {expected_op}, got: {message}"
            );
            assert!(
                message.contains("unsupported"),
                "{name} diagnostic should be explicit, got: {message}"
            );
            assert_eq!(
                crate::dwarf_expr::ops::unsupported_op_from_error(&error),
                Some(expected_op),
                "{name} diagnostic should carry a typed unsupported-op cause"
            );
        }
    }

    #[test]
    fn implicit_pointer_to_static_storage_preserves_absolute_address_semantics() {
        let result = ExpressionEvaluator::addressable_location_to_pointer_value(
            EvaluationResult::MemoryLocation(LocationResult::Address(0x1234)),
            0x10,
        )
        .expect("static address should convert to an implicit pointer value");

        assert_eq!(
            result,
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1244))
        );
    }

    #[test]
    fn implicit_pointer_accepts_target_absolute_address_value() {
        let result = ExpressionEvaluator::addressable_location_to_pointer_value(
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1234)),
            0x10,
        )
        .expect("static address values should convert to an implicit pointer value");

        assert_eq!(
            result,
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(0x1244))
        );
    }

    #[test]
    fn multi_op_expression_rejects_invalid_opcode_after_valid_prefix() {
        let expr_bytes = [
            constants::DW_OP_lit1.0,
            0xff,
            constants::DW_OP_stack_value.0,
        ];

        let error = ExpressionEvaluator::parse_expression_with_context(
            &expr_bytes,
            RunTimeEndian::Little,
            test_encoding(),
            None,
            None,
            0,
            None,
            None,
            None,
            0,
        )
        .expect_err("invalid opcode after a valid prefix must not return a value");

        assert!(
            error.to_string().contains("DWARF expression"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn multi_op_expression_rejects_unsupported_operation_after_valid_prefix() {
        let expr_bytes = [
            constants::DW_OP_lit1.0,
            constants::DW_OP_drop.0,
            constants::DW_OP_stack_value.0,
        ];

        let error = ExpressionEvaluator::parse_expression_with_context(
            &expr_bytes,
            RunTimeEndian::Little,
            test_encoding(),
            None,
            None,
            0,
            None,
            None,
            None,
            0,
        )
        .expect_err("unsupported operation after a valid prefix must not return a value");

        assert!(
            error.to_string().contains("unsupported"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn single_fbreg_fast_path_saturates_cfa_offset_addition() {
        let get_cfa = |_address| {
            Ok(Some(CfaResult::RegisterPlusOffset {
                register: 7,
                offset: i64::MAX - 3,
            }))
        };

        let result = ExpressionEvaluator::parse_expression_with_context(
            &[0x91, 0x0a],
            RunTimeEndian::Little,
            test_encoding(),
            None,
            None,
            0,
            Some(&get_cfa),
            None,
            None,
            0,
        )
        .expect("single DW_OP_fbreg should parse");

        assert_eq!(
            result,
            EvaluationResult::MemoryLocation(LocationResult::RegisterAddress {
                register: 7,
                offset: Some(i64::MAX),
                size: None,
            })
        );
    }

    #[test]
    fn big_endian_dw_op_addr_preserves_absolute_address() {
        let expr_bytes = [0x03, 0, 0, 0, 0, 0, 0, 0x12, 0x34];
        let result = ExpressionEvaluator::parse_expression_with_context(
            &expr_bytes,
            gimli::RunTimeEndian::Big,
            test_encoding(),
            None,
            None,
            0,
            None,
            None,
            None,
            0,
        )
        .expect("big-endian DW_OP_addr should parse");

        assert_eq!(
            result,
            EvaluationResult::MemoryLocation(LocationResult::Address(0x1234))
        );
    }
}

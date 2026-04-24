//! DWARF expression evaluator
//!
//! Converts DWARF location expressions to EvaluationResult for eBPF code generation

use crate::binary::{DwarfEndian, DwarfReader};
use crate::core::{
    ComputeStep, DirectValueResult, EntryValueCase, EvaluationResult, LocationResult,
    MemoryAccessSize, Result,
};
use crate::index::{BlockIndexBuilder, CfiIndex, FunctionBlocks};
use crate::semantics::{range_contains_pc, resolve_attr_with_unit_origins};
use gimli::{read::RawLocListEntry, EndianSlice, Expression, Operation, Reader};
use tracing::{debug, trace, warn};

/// DWARF expression evaluator
pub struct ExpressionEvaluator;

impl ExpressionEvaluator {
    const MAX_IMPLICIT_POINTER_DEPTH: usize = 8;
    const ENTRY_VALUE_LOOKUP_WARN_CASES: usize = 16;

    /// Evaluate a variable's location from its DIE attributes
    pub fn evaluate_location(
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        unit: &gimli::Unit<DwarfReader>,
        dwarf: &gimli::Dwarf<DwarfReader>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<EvaluationResult> {
        Self::evaluate_location_with_depth(
            entry,
            unit,
            dwarf,
            address,
            get_cfa,
            function_context,
            cfi_index,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_location_with_depth(
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
    ) -> Result<Vec<ComputeStep>> {
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
    fn parse_expression_with_context(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        encoding: gimli::Encoding,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
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
            address,
            get_cfa,
            function_context,
            cfi_index,
            depth,
        )
    }

    fn evaluation_result_to_steps(evaluation: EvaluationResult) -> Result<Vec<ComputeStep>> {
        match evaluation {
            EvaluationResult::DirectValue(DirectValueResult::RegisterValue(register)) => {
                Ok(vec![ComputeStep::LoadRegister(register)])
            }
            EvaluationResult::DirectValue(DirectValueResult::Constant(value)) => {
                Ok(vec![ComputeStep::PushConstant(value)])
            }
            EvaluationResult::DirectValue(DirectValueResult::AbsoluteAddress(address)) => {
                Ok(vec![ComputeStep::PushConstant(address as i64)])
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
                Ok(vec![ComputeStep::PushConstant(address as i64)])
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { steps }) => {
                Ok(steps)
            }
            EvaluationResult::DirectValue(DirectValueResult::ImplicitValue(_)) => Err(
                anyhow::anyhow!("DWARF expression lowered to implicit bytes, not ComputeStep[]"),
            ),
            EvaluationResult::Optimized => Err(anyhow::anyhow!(
                "DWARF expression optimized out, no ComputeStep[]"
            )),
            EvaluationResult::Composite(_) => Err(anyhow::anyhow!(
                "composite DWARF expression cannot be represented as one ComputeStep[]"
            )),
        }
    }

    fn register_address_steps(register: u16, offset: Option<i64>) -> Vec<ComputeStep> {
        let mut steps = vec![ComputeStep::LoadRegister(register)];
        if let Some(offset) = offset.filter(|offset| *offset != 0) {
            steps.push(ComputeStep::PushConstant(offset));
            steps.push(ComputeStep::Add);
        }
        steps
    }

    /// Parse a full multi-operation DWARF expression
    #[allow(clippy::too_many_arguments)]
    fn parse_full_expression(
        expr_bytes: &[u8],
        endian: DwarfEndian,
        encoding: gimli::Encoding,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
        depth: usize,
    ) -> Result<EvaluationResult> {
        #[derive(Debug)]
        enum ParsedOperation<R: Reader<Offset = usize>> {
            Operation(Operation<R>),
            PrecomputedSteps(Vec<ComputeStep>),
        }

        let mut expression = Expression(EndianSlice::new(expr_bytes, endian));
        let mut operations: Vec<ParsedOperation<_>> = Vec::new();
        let mut has_stack_value = false;

        // Parse all operations in the expression
        while !expression.0.is_empty() {
            let offset = expr_bytes.len() - expression.0.len();
            let op = Operation::parse(&mut expression.0, encoding).map_err(|error| {
                anyhow::anyhow!(
                    "failed to parse DWARF expression operation at byte offset {}: {}",
                    offset,
                    error
                )
            })?;
            if matches!(op, Operation::StackValue) {
                has_stack_value = true;
                debug!("Found DW_OP_stack_value - this is a computed value");
            }
            match &op {
                // Lower supported DW_OP_entry_value forms through caller-side
                // call-site metadata. This keeps optimized parameters usable
                // after their entry registers have been clobbered.
                Operation::EntryValue { expression } => {
                    let mut inner = *expression;
                    let mut inner_ops: Vec<Operation<_>> = Vec::new();
                    let inner_len = inner.len();
                    while !inner.is_empty() {
                        let offset = inner_len - inner.len();
                        let iop = Operation::parse(&mut inner, encoding).map_err(|error| {
                            anyhow::anyhow!(
                                "failed to parse DW_OP_entry_value inner expression operation at byte offset {}: {}",
                                offset,
                                error
                            )
                        })?;
                        inner_ops.push(iop);
                    }
                    if inner_ops.len() == 1 {
                        match &inner_ops[0] {
                            Operation::Register { register } => {
                                has_stack_value = true;
                                match Self::resolve_entry_value_register(
                                    address,
                                    register.0,
                                    dwarf,
                                    function_context,
                                    cfi_index,
                                ) {
                                    Ok(steps) => {
                                        operations.push(ParsedOperation::PrecomputedSteps(steps));
                                    }
                                    Err(error) => {
                                        debug!(
                                            "DW_OP_entry_value register {} unresolved at 0x{:x}: {}",
                                            register.0,
                                            address,
                                            error
                                        );
                                        return Ok(EvaluationResult::Optimized);
                                    }
                                }
                            }
                            Operation::RegisterOffset {
                                register, offset, ..
                            } => {
                                let steps = Self::resolve_entry_value_register_offset(
                                    address,
                                    register.0,
                                    *offset,
                                    encoding.address_size,
                                    dwarf,
                                    function_context,
                                    cfi_index,
                                )?;
                                operations.push(ParsedOperation::PrecomputedSteps(steps));
                            }
                            _ => {
                                debug!("Unsupported EntryValue inner op: {:?}", inner_ops[0]);
                                return Err(anyhow::anyhow!(
                                    "unsupported DW_OP_entry_value inner op: {:?}",
                                    inner_ops[0]
                                ));
                            }
                        }
                    } else {
                        debug!("Unsupported EntryValue with {} inner ops", inner_ops.len());
                        return Err(anyhow::anyhow!(
                            "unsupported DW_OP_entry_value with {} inner ops",
                            inner_ops.len()
                        ));
                    }
                }
                _ => operations.push(ParsedOperation::Operation(op)),
            }
        }

        if operations.is_empty() {
            return Err(anyhow::anyhow!("Empty expression"));
        }

        debug!("Parsed {} operations in expression", operations.len());

        // Fast path for single operations - avoid compute processing
        if operations.len() == 1 {
            if let ParsedOperation::Operation(op) = &operations[0] {
                return Self::handle_single_operation(op, dwarf, address, get_cfa, depth);
            }
        }

        // Build compute steps from operations
        if !operations.is_empty() {
            let mut steps = Vec::new();

            for op in &operations {
                match op {
                    ParsedOperation::PrecomputedSteps(precomputed) => {
                        steps.extend(precomputed.iter().cloned());
                    }
                    ParsedOperation::Operation(Operation::RegisterOffset {
                        register,
                        offset,
                        ..
                    }) => {
                        // Load register and add offset if non-zero
                        steps.push(ComputeStep::LoadRegister(register.0));
                        if *offset != 0 {
                            steps.push(ComputeStep::PushConstant(*offset));
                            steps.push(ComputeStep::Add);
                        }
                    }
                    ParsedOperation::Operation(Operation::Register { register }) => {
                        // DW_OP_reg* means the value IS in the register (direct value)
                        // We'll handle this specially below
                        steps.push(ComputeStep::LoadRegister(register.0));
                    }
                    ParsedOperation::Operation(Operation::FrameOffset { offset }) => {
                        let Some(get_cfa_fn) = get_cfa else {
                            return Err(anyhow::anyhow!(
                                "DW_OP_fbreg but no CFA provider available"
                            ));
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
                                steps.push(ComputeStep::LoadRegister(register));
                                let total_offset = cfa_offset.saturating_add(*offset);
                                if total_offset != 0 {
                                    steps.push(ComputeStep::PushConstant(total_offset));
                                    steps.push(ComputeStep::Add);
                                }
                            }
                            crate::core::CfaResult::Expression {
                                steps: mut cfa_steps,
                            } => {
                                steps.append(&mut cfa_steps);
                                if *offset != 0 {
                                    steps.push(ComputeStep::PushConstant(*offset));
                                    steps.push(ComputeStep::Add);
                                }
                            }
                        }
                    }
                    ParsedOperation::Operation(Operation::PlusConstant { value }) => {
                        steps.push(ComputeStep::PushConstant(*value as i64));
                        steps.push(ComputeStep::Add);
                    }
                    ParsedOperation::Operation(Operation::Plus) => steps.push(ComputeStep::Add),
                    ParsedOperation::Operation(Operation::Minus) => steps.push(ComputeStep::Sub),
                    ParsedOperation::Operation(Operation::Mul) => steps.push(ComputeStep::Mul),
                    ParsedOperation::Operation(Operation::Div) => steps.push(ComputeStep::Div),
                    ParsedOperation::Operation(Operation::Mod) => steps.push(ComputeStep::Mod),
                    ParsedOperation::Operation(Operation::And) => steps.push(ComputeStep::And),
                    ParsedOperation::Operation(Operation::Or) => steps.push(ComputeStep::Or),
                    ParsedOperation::Operation(Operation::Xor) => steps.push(ComputeStep::Xor),
                    ParsedOperation::Operation(Operation::Shl) => steps.push(ComputeStep::Shl),
                    ParsedOperation::Operation(Operation::Shr) => steps.push(ComputeStep::Shr),
                    ParsedOperation::Operation(Operation::Shra) => steps.push(ComputeStep::Shra),
                    ParsedOperation::Operation(Operation::Not) => steps.push(ComputeStep::Not),
                    ParsedOperation::Operation(Operation::Neg) => steps.push(ComputeStep::Neg),
                    ParsedOperation::Operation(Operation::Abs) => steps.push(ComputeStep::Abs),
                    ParsedOperation::Operation(Operation::Eq) => steps.push(ComputeStep::Eq),
                    ParsedOperation::Operation(Operation::Ne) => steps.push(ComputeStep::Ne),
                    ParsedOperation::Operation(Operation::Lt) => steps.push(ComputeStep::Lt),
                    ParsedOperation::Operation(Operation::Le) => steps.push(ComputeStep::Le),
                    ParsedOperation::Operation(Operation::Gt) => steps.push(ComputeStep::Gt),
                    ParsedOperation::Operation(Operation::Ge) => steps.push(ComputeStep::Ge),
                    ParsedOperation::Operation(Operation::UnsignedConstant { value }) => {
                        steps.push(ComputeStep::PushConstant(*value as i64));
                    }
                    ParsedOperation::Operation(Operation::SignedConstant { value }) => {
                        steps.push(ComputeStep::PushConstant(*value));
                    }
                    ParsedOperation::Operation(Operation::StackValue) => {
                        // This marks the result as a computed value, not a memory location
                        // Already handled by has_stack_value flag
                    }
                    ParsedOperation::Operation(Operation::Deref { size, space, .. }) => {
                        if *space {
                            return Err(anyhow::anyhow!(
                                "unsupported DWARF expression operation: {:?}",
                                op
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
                        steps.push(ComputeStep::Dereference { size: mem_size });
                    }
                    ParsedOperation::Operation(Operation::Nop) => {}
                    _ => {
                        return Err(anyhow::anyhow!(
                            "unsupported DWARF expression operation: {:?}",
                            op
                        ));
                    }
                }
            }

            if !steps.is_empty() {
                // Check for simple cases that don't need full computation
                if steps.len() == 1 {
                    // Single step - optimize to direct form
                    match &steps[0] {
                        ComputeStep::LoadRegister(reg) => {
                            if has_stack_value {
                                // Register value directly
                                return Ok(EvaluationResult::DirectValue(
                                    DirectValueResult::RegisterValue(*reg),
                                ));
                            } else {
                                // Register as address (no offset)
                                return Ok(EvaluationResult::MemoryLocation(
                                    LocationResult::RegisterAddress {
                                        register: *reg,
                                        offset: None,
                                        size: None,
                                    },
                                ));
                            }
                        }
                        ComputeStep::PushConstant(val) => {
                            if has_stack_value {
                                // Constant value
                                return Ok(EvaluationResult::DirectValue(
                                    DirectValueResult::Constant(*val),
                                ));
                            } else {
                                // Constant address
                                return Ok(EvaluationResult::MemoryLocation(
                                    LocationResult::Address(*val as u64),
                                ));
                            }
                        }
                        _ => {} // Other single operations need computation
                    }
                } else if steps.len() == 3 {
                    // Common pattern: LoadRegister + PushConstant + Add
                    if matches!(steps[0], ComputeStep::LoadRegister(_))
                        && matches!(steps[1], ComputeStep::PushConstant(_))
                        && matches!(steps[2], ComputeStep::Add)
                    {
                        if let (ComputeStep::LoadRegister(reg), ComputeStep::PushConstant(offset)) =
                            (&steps[0], &steps[1])
                        {
                            if !has_stack_value {
                                // Register + offset as memory location
                                return Ok(EvaluationResult::MemoryLocation(
                                    LocationResult::RegisterAddress {
                                        register: *reg,
                                        offset: Some(*offset),
                                        size: None,
                                    },
                                ));
                            }
                            // If has_stack_value, fall through to ComputedValue
                        }
                    }
                }

                // Complex expression - use computed forms
                if has_stack_value {
                    // This is a computed value
                    return Ok(EvaluationResult::DirectValue(
                        DirectValueResult::ComputedValue {
                            steps,
                            result_size: MemoryAccessSize::U64, // Default to 64-bit
                        },
                    ));
                } else {
                    // This is a computed memory location
                    return Ok(EvaluationResult::MemoryLocation(
                        LocationResult::ComputedLocation { steps },
                    ));
                }
            }
        }

        // If we couldn't parse as a complex expression, fail
        Err(anyhow::anyhow!(
            "Could not parse multi-operation expression"
        ))
    }

    /// Handle single DWARF operation - fast path without compute processing
    fn handle_single_operation<R>(
        op: &Operation<R>,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
        depth: usize,
    ) -> Result<EvaluationResult>
    where
        R: gimli::Reader<Offset = usize>,
    {
        use crate::core::{CfaResult, ComputeStep};

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
                                steps.push(ComputeStep::PushConstant(*offset));
                                steps.push(ComputeStep::Add);
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
            Operation::StackValue => Err(anyhow::anyhow!(
                "unsupported single operation: DW_OP_stack_value"
            )),
            Operation::PlusConstant { .. } => Err(anyhow::anyhow!(
                "unsupported single operation: DW_OP_plus_uconst without base"
            )),
            _ => Err(anyhow::anyhow!(
                "unsupported single operation in fast path: {:?}",
                op
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
        let referenced = Self::evaluate_location_with_depth(
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
        use crate::core::{ComputeStep, DirectValueResult, EvaluationResult, LocationResult};

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
                                ComputeStep::LoadRegister(register),
                                ComputeStep::PushConstant(total_offset),
                                ComputeStep::Add,
                            ],
                            result_size: MemoryAccessSize::U64,
                        },
                    ))
                }
            }
            EvaluationResult::MemoryLocation(LocationResult::ComputedLocation { mut steps }) => {
                if byte_offset != 0 {
                    steps.push(ComputeStep::PushConstant(byte_offset));
                    steps.push(ComputeStep::Add);
                }
                Ok(EvaluationResult::DirectValue(
                    DirectValueResult::ComputedValue {
                        steps,
                        result_size: MemoryAccessSize::U64,
                    },
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

    fn resolve_entry_value_register(
        current_pc: u64,
        register: u16,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        let function_context = function_context.ok_or_else(|| {
            anyhow::anyhow!("DW_OP_entry_value requires function call-site context")
        })?;
        Self::build_incoming_entry_value_lookup(
            current_pc,
            register,
            dwarf,
            function_context,
            cfi_index,
        )
        .or_else(|incoming_error| {
            Self::recover_entry_register_from_cfi(current_pc, register, cfi_index).map_err(
                |cfi_error| {
                    anyhow::anyhow!(
                        "failed to recover DW_OP_entry_value register {} at 0x{:x}: {}; fallback via CFI also failed: {}",
                        register,
                        current_pc,
                        incoming_error,
                        cfi_error
                    )
                },
            )
        })
    }

    fn build_incoming_entry_value_lookup(
        current_pc: u64,
        register: u16,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        function_context: &FunctionBlocks,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        let cfi_index = cfi_index.ok_or_else(|| {
            anyhow::anyhow!(
                "DW_OP_entry_value register recovery needs CFI at 0x{:x}",
                current_pc
            )
        })?;
        let recovery = cfi_index.recover_caller_frame(current_pc, &[])?;

        let mut cases_by_return_pc = std::collections::BTreeMap::<u64, Vec<ComputeStep>>::new();
        let parameters =
            Self::collect_incoming_entry_value_parameter_steps(register, dwarf, function_context);
        for (caller_return_pc, caller_value_steps) in parameters {
            let value_steps = Self::materialize_caller_value_steps(
                &caller_value_steps,
                current_pc,
                Some(cfi_index),
            )
            .map_err(|error| {
                anyhow::anyhow!(
                    "failed to materialize incoming call-site parameter for DW_OP_entry_value register {} at 0x{:x} (caller return pc 0x{:x}): {}",
                    register,
                    current_pc,
                    caller_return_pc,
                    error
                )
            })?;
            match cases_by_return_pc.entry(caller_return_pc) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(value_steps);
                }
                std::collections::btree_map::Entry::Occupied(entry) => {
                    if entry.get() != &value_steps {
                        return Err(anyhow::anyhow!(
                            "ambiguous incoming call-site parameter for DW_OP_entry_value register {} at 0x{:x} (caller return pc 0x{:x})",
                            register,
                            current_pc,
                            caller_return_pc
                        ));
                    }
                }
            }
        }

        if cases_by_return_pc.is_empty() {
            return Err(anyhow::anyhow!(
                "no call-site parameter found for DW_OP_entry_value register {} at 0x{:x}",
                register,
                current_pc
            ));
        }

        Ok(Self::build_entry_value_lookup_steps(
            recovery.caller_pc_steps,
            cases_by_return_pc,
        ))
    }

    fn collect_incoming_entry_value_parameter_steps(
        register: u16,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        function_context: &FunctionBlocks,
    ) -> Vec<(u64, Vec<ComputeStep>)> {
        let indexed_parameters: Vec<_> = function_context
            .incoming_entry_value_parameters(register)
            .into_iter()
            .map(|(caller_return_pc, parameter)| {
                (caller_return_pc, parameter.caller_value_steps.clone())
            })
            .collect();
        if !indexed_parameters.is_empty() {
            return indexed_parameters;
        }

        dwarf
            .map(|dwarf| {
                BlockIndexBuilder::new(dwarf)
                    .collect_incoming_entry_value_parameters(function_context, register)
                    .into_iter()
                    .map(|(caller_return_pc, parameter)| {
                        (caller_return_pc, parameter.caller_value_steps)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn resolve_entry_value_register_offset(
        current_pc: u64,
        register: u16,
        offset: i64,
        address_size: u8,
        dwarf: Option<&gimli::Dwarf<DwarfReader>>,
        function_context: Option<&FunctionBlocks>,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        if Self::is_stack_pointer_register(register) {
            return Self::recover_entry_stack_pointer_steps(
                current_pc,
                offset,
                address_size,
                cfi_index,
            );
        }

        match Self::resolve_entry_value_register(
            current_pc,
            register,
            dwarf,
            function_context,
            cfi_index,
        ) {
            Ok(mut steps) => {
                Self::append_constant_offset(&mut steps, offset);
                Ok(steps)
            }
            Err(entry_error) => {
                let mut steps = Self::recover_entry_register_from_cfi(
                    current_pc, register, cfi_index,
                )
                .map_err(|cfi_error| {
                    anyhow::anyhow!(
                        "failed to recover DW_OP_entry_value base register {} with offset {} at 0x{:x}: {}; fallback via CFI also failed: {}",
                        register,
                        offset,
                        current_pc,
                        entry_error,
                        cfi_error
                    )
                })?;
                Self::append_constant_offset(&mut steps, offset);
                Ok(steps)
            }
        }
    }

    fn recover_entry_register_from_cfi(
        current_pc: u64,
        register: u16,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        let cfi_index = cfi_index.ok_or_else(|| {
            anyhow::anyhow!(
                "DW_OP_entry_value register recovery needs CFI at 0x{:x}",
                current_pc
            )
        })?;
        cfi_index
            .recover_caller_register_steps(current_pc, register)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no entry register recovery rule for DWARF register {} at 0x{:x}",
                    register,
                    current_pc
                )
            })
    }

    fn recover_entry_stack_pointer_steps(
        current_pc: u64,
        offset: i64,
        address_size: u8,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        let cfi_index = cfi_index.ok_or_else(|| {
            anyhow::anyhow!(
                "DW_OP_entry_value stack-pointer recovery needs CFI at 0x{:x}",
                current_pc
            )
        })?;
        let mut steps = Self::cfa_to_steps(cfi_index.get_cfa_result(current_pc)?);
        // This assumes the common x86/x86_64 call-frame convention where the CFA
        // observed after the call is `SP_entry + address_size` because the return
        // address is stored on the stack. Targets such as AArch64 may define the
        // CFA at call entry differently when LR is not pushed, so keep this
        // adjustment centralized until entry-SP reconstruction becomes
        // target-aware.
        Self::append_constant_offset(&mut steps, offset - i64::from(address_size));
        Ok(steps)
    }

    fn cfa_to_steps(cfa: crate::core::CfaResult) -> Vec<ComputeStep> {
        match cfa {
            crate::core::CfaResult::RegisterPlusOffset { register, offset } => {
                let mut steps = vec![ComputeStep::LoadRegister(register)];
                Self::append_constant_offset(&mut steps, offset);
                steps
            }
            crate::core::CfaResult::Expression { steps } => steps,
        }
    }

    fn append_constant_offset(steps: &mut Vec<ComputeStep>, offset: i64) {
        if offset != 0 {
            steps.push(ComputeStep::PushConstant(offset));
            steps.push(ComputeStep::Add);
        }
    }

    fn is_stack_pointer_register(register: u16) -> bool {
        matches!(
            ghostscope_platform::register_mapping::dwarf_reg_to_name(register),
            Some("RSP" | "ESP" | "SP")
        )
    }

    fn build_entry_value_lookup_steps(
        caller_pc_steps: Vec<ComputeStep>,
        cases_by_return_pc: std::collections::BTreeMap<u64, Vec<ComputeStep>>,
    ) -> Vec<ComputeStep> {
        let cases: Vec<_> = cases_by_return_pc
            .into_iter()
            .map(|(caller_return_pc, value_steps)| EntryValueCase {
                caller_return_pc,
                value_steps,
            })
            .collect();
        if cases.len() > Self::ENTRY_VALUE_LOOKUP_WARN_CASES {
            warn!(
                "DW_OP_entry_value lookup generated {} caller return-pc cases; large fan-in may exceed eBPF verifier limits",
                cases.len()
            );
        }
        vec![ComputeStep::EntryValueLookup {
            caller_pc_steps,
            cases,
        }]
    }

    fn materialize_caller_value_steps(
        steps: &[ComputeStep],
        current_pc: u64,
        cfi_index: Option<&CfiIndex>,
    ) -> Result<Vec<ComputeStep>> {
        let mut materialized = Vec::new();
        for step in steps {
            match step {
                ComputeStep::LoadRegister(register) => {
                    let cfi_index = cfi_index.ok_or_else(|| {
                        anyhow::anyhow!(
                            "DW_OP_entry_value register recovery needs CFI at 0x{:x}",
                            current_pc
                        )
                    })?;
                    let recovered = cfi_index
                        .recover_caller_register_steps(current_pc, *register)?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "no caller register recovery rule for DWARF register {} at 0x{:x}; DW_OP_entry_value can only materialize caller values for registers with unwind recovery, and caller-saved argument registers are often unavailable after the call",
                                register,
                                current_pc
                            )
                        })?;
                    materialized.extend(recovered);
                }
                other => materialized.push(other.clone()),
            }
        }
        Ok(materialized)
    }
}

#[cfg(test)]
mod tests {
    use super::ExpressionEvaluator;
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{
        CfaResult, ComputeStep, DirectValueResult, EntryValueCase, EvaluationResult, LocationResult,
    };
    use crate::index::{BlockNode, CallSiteParameter, CallSiteRecord, FunctionBlocks};
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Sections, Unit,
    };
    use gimli::{Format, LittleEndian, Register, RunTimeEndian};
    use std::sync::Arc;

    fn test_encoding() -> gimli::Encoding {
        gimli::Encoding {
            format: gimli::Format::Dwarf32,
            version: 5,
            address_size: 8,
        }
    }

    fn build_scanned_incoming_entry_value_fixture(
        register: u16,
        caller_value: u64,
    ) -> gimli::Dwarf<DwarfReader> {
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version: 5,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let caller_id = unit.add(root, constants::DW_TAG_subprogram);
        let caller = unit.get_mut(caller_id);
        caller.set(
            constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x1000)),
        );
        caller.set(constants::DW_AT_high_pc, WriteAttributeValue::Udata(0x40));

        let callee_id = unit.add(root, constants::DW_TAG_subprogram);
        let callee = unit.get_mut(callee_id);
        callee.set(
            constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x1200)),
        );
        callee.set(constants::DW_AT_high_pc, WriteAttributeValue::Udata(0x10));

        let call_site_id = unit.add(caller_id, constants::DW_TAG_call_site);
        unit.get_mut(call_site_id).set(
            constants::DW_AT_call_target,
            WriteAttributeValue::Address(Address::Constant(0x1200)),
        );
        unit.get_mut(call_site_id).set(
            constants::DW_AT_call_return_pc,
            WriteAttributeValue::Address(Address::Constant(0x2018)),
        );

        let param_id = unit.add(call_site_id, constants::DW_TAG_call_site_parameter);
        let param = unit.get_mut(param_id);
        let mut location = WriteExpression::new();
        location.op_reg(Register(register));
        param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(location),
        );
        let mut value = WriteExpression::new();
        value.op_constu(caller_value);
        param.set(
            constants::DW_AT_call_value,
            WriteAttributeValue::Exprloc(value),
        );

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        dwarf.write(&mut sections).unwrap();

        let dwarf_sections: gimli::DwarfSections<Vec<u8>> = gimli::DwarfSections::load(|id| {
            Ok::<_, gimli::Error>(
                sections
                    .get(id)
                    .map(|section| section.slice().to_vec())
                    .unwrap_or_default(),
            )
        })
        .unwrap();

        dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())))
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
    fn entry_value_ignores_outgoing_call_sites_in_inline_context() {
        let mut function = FunctionBlocks {
            cu_offset: gimli::DebugInfoOffset(0),
            die_offset: gimli::UnitOffset(0),
            abs_die_offset: Some(gimli::DebugInfoOffset(0)),
            ranges: vec![(0x1000, 0x1040)],
            nodes: vec![
                BlockNode {
                    ranges: vec![],
                    entry_pc: None,
                    die_offset: Some(gimli::UnitOffset(0)),
                    variables: vec![],
                    children: vec![1],
                },
                BlockNode {
                    ranges: vec![(0x1000, 0x1040)],
                    entry_pc: Some(0x1000),
                    die_offset: Some(gimli::UnitOffset(1)),
                    variables: vec![],
                    children: vec![],
                },
            ],
            block_addr_map: std::collections::BTreeMap::new(),
            call_sites: std::collections::BTreeMap::new(),
            incoming_call_sites: std::collections::BTreeMap::new(),
        };
        function.call_sites.insert(
            0x1018,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(0),
                die_offset: gimli::UnitOffset(1),
                return_pc: 0x1018,
                call_origin: None,
                call_target: None,
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(11)],
                }],
            }],
        );
        function.call_sites.insert(
            0x1030,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(0),
                die_offset: gimli::UnitOffset(2),
                return_pc: 0x1030,
                call_origin: None,
                call_target: None,
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(22)],
                }],
            }],
        );

        let error = ExpressionEvaluator::resolve_entry_value_register(
            0x1034,
            5,
            None,
            Some(&function),
            None,
        )
        .expect_err("inline entry_value must not reuse nested outgoing call-site bindings");
        assert!(
            error
                .to_string()
                .contains("DW_OP_entry_value register recovery needs CFI"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn entry_value_ignores_outgoing_call_sites_in_non_inline_context() {
        let mut function = FunctionBlocks {
            cu_offset: gimli::DebugInfoOffset(0),
            die_offset: gimli::UnitOffset(0),
            abs_die_offset: Some(gimli::DebugInfoOffset(0)),
            ranges: vec![(0x1000, 0x1040)],
            nodes: vec![BlockNode {
                ranges: vec![],
                entry_pc: None,
                die_offset: Some(gimli::UnitOffset(0)),
                variables: vec![],
                children: vec![],
            }],
            block_addr_map: std::collections::BTreeMap::new(),
            call_sites: std::collections::BTreeMap::new(),
            incoming_call_sites: std::collections::BTreeMap::new(),
        };
        function.call_sites.insert(
            0x1030,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(0),
                die_offset: gimli::UnitOffset(2),
                return_pc: 0x1030,
                call_origin: None,
                call_target: None,
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(22)],
                }],
            }],
        );

        let error = ExpressionEvaluator::resolve_entry_value_register(
            0x1034,
            5,
            None,
            Some(&function),
            None,
        )
        .expect_err("non-inline entry_value must not reuse outgoing call-site bindings");
        assert!(
            error
                .to_string()
                .contains("DW_OP_entry_value register recovery needs CFI"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn entry_value_uses_incoming_call_site_lookup_for_non_inline_functions() {
        let mut function = FunctionBlocks {
            cu_offset: gimli::DebugInfoOffset(0),
            die_offset: gimli::UnitOffset(0),
            abs_die_offset: Some(gimli::DebugInfoOffset(0)),
            ranges: vec![(0x1200, 0x1210)],
            nodes: vec![BlockNode {
                ranges: vec![],
                entry_pc: None,
                die_offset: Some(gimli::UnitOffset(0)),
                variables: vec![],
                children: vec![],
            }],
            block_addr_map: std::collections::BTreeMap::new(),
            call_sites: std::collections::BTreeMap::new(),
            incoming_call_sites: std::collections::BTreeMap::new(),
        };
        function.incoming_call_sites.insert(
            0x2018,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(1),
                die_offset: gimli::UnitOffset(3),
                return_pc: 0x2018,
                call_origin: function.abs_die_offset,
                call_target: Some(0x1200),
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(33)],
                }],
            }],
        );
        function.incoming_call_sites.insert(
            0x2030,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(2),
                die_offset: gimli::UnitOffset(4),
                return_pc: 0x2030,
                call_origin: function.abs_die_offset,
                call_target: Some(0x1200),
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(44)],
                }],
            }],
        );

        let mut cases_by_return_pc = std::collections::BTreeMap::new();
        for (caller_return_pc, parameter) in function.incoming_entry_value_parameters(5) {
            cases_by_return_pc.insert(caller_return_pc, parameter.caller_value_steps.clone());
        }
        let steps = ExpressionEvaluator::build_entry_value_lookup_steps(
            vec![ComputeStep::PushConstant(0xdeadbeef)],
            cases_by_return_pc,
        );
        assert_eq!(
            steps,
            vec![ComputeStep::EntryValueLookup {
                caller_pc_steps: vec![ComputeStep::PushConstant(0xdeadbeef)],
                cases: vec![
                    EntryValueCase {
                        caller_return_pc: 0x2018,
                        value_steps: vec![ComputeStep::PushConstant(33)],
                    },
                    EntryValueCase {
                        caller_return_pc: 0x2030,
                        value_steps: vec![ComputeStep::PushConstant(44)],
                    },
                ],
            }]
        );
    }

    #[test]
    fn entry_value_prefers_indexed_incoming_parameters_over_dwarf_scan() {
        let mut function = FunctionBlocks {
            cu_offset: gimli::DebugInfoOffset(0),
            die_offset: gimli::UnitOffset(0),
            abs_die_offset: Some(gimli::DebugInfoOffset(0)),
            ranges: vec![(0x1200, 0x1210)],
            nodes: vec![BlockNode {
                ranges: vec![],
                entry_pc: None,
                die_offset: Some(gimli::UnitOffset(0)),
                variables: vec![],
                children: vec![],
            }],
            block_addr_map: std::collections::BTreeMap::new(),
            call_sites: std::collections::BTreeMap::new(),
            incoming_call_sites: std::collections::BTreeMap::new(),
        };
        function.incoming_call_sites.insert(
            0x2018,
            vec![CallSiteRecord {
                cu_offset: gimli::DebugInfoOffset(1),
                die_offset: gimli::UnitOffset(3),
                return_pc: 0x2018,
                call_origin: function.abs_die_offset,
                call_target: Some(0x1200),
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(33)],
                }],
            }],
        );
        let dwarf = build_scanned_incoming_entry_value_fixture(5, 99);

        let parameters = ExpressionEvaluator::collect_incoming_entry_value_parameter_steps(
            5,
            Some(&dwarf),
            &function,
        );

        assert_eq!(
            parameters,
            vec![(0x2018, vec![ComputeStep::PushConstant(33)])]
        );
    }

    #[test]
    fn entry_value_stack_pointer_offsets_use_cfa_based_entry_sp() {
        let mut entry_sp_steps =
            ExpressionEvaluator::cfa_to_steps(crate::core::CfaResult::RegisterPlusOffset {
                register: 7,
                offset: 32,
            });
        ExpressionEvaluator::append_constant_offset(&mut entry_sp_steps, 8 - 8);

        assert_eq!(
            entry_sp_steps,
            vec![
                ComputeStep::LoadRegister(7),
                ComputeStep::PushConstant(32),
                ComputeStep::Add,
            ]
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

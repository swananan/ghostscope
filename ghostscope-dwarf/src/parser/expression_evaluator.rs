//! DWARF expression evaluator
//!
//! Converts DWARF location expressions to EvaluationResult for eBPF code generation

use crate::core::{
    ComputeStep, DirectValueResult, EvaluationResult, LocationResult, MemoryAccessSize, Result,
};
use gimli::{read::RawLocListEntry, EndianSlice, Expression, LittleEndian, Operation, Reader};
use tracing::{debug, trace, warn};

/// DWARF expression evaluator
pub struct ExpressionEvaluator;

impl ExpressionEvaluator {
    /// Evaluate a variable's location from its DIE attributes
    pub fn evaluate_location(
        entry: &gimli::DebuggingInformationEntry<EndianSlice<'static, LittleEndian>>,
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<EvaluationResult> {
        // Get DW_AT_location attribute
        let location_attr = entry.attr_value(gimli::constants::DW_AT_location)?;

        match location_attr {
            Some(gimli::AttributeValue::Exprloc(expr)) => {
                // Direct expression
                debug!("Found Exprloc, parsing DWARF expression");
                Self::parse_expression(expr.0.slice(), unit.encoding(), address, get_cfa)
            }
            Some(gimli::AttributeValue::LocationListsRef(offset)) => {
                // Location list - variable location changes based on PC
                debug!(
                    "Found LocationListsRef at offset 0x{:x}, parsing location list",
                    offset.0
                );
                Self::parse_location_lists(
                    unit,
                    dwarf,
                    gimli::LocationListsOffset(offset.0),
                    address,
                    get_cfa,
                )
            }
            Some(gimli::AttributeValue::SecOffset(offset)) => {
                // Older DWARF format location list
                debug!(
                    "Found SecOffset location list at 0x{:x}, parsing as location list",
                    offset
                );
                Self::parse_location_lists(
                    unit,
                    dwarf,
                    gimli::LocationListsOffset(offset),
                    address,
                    get_cfa,
                )
            }
            None => {
                // No location means optimized out
                trace!("No DW_AT_location attribute, variable optimized out");
                Ok(EvaluationResult::Optimized)
            }
            Some(other) => {
                warn!("Unexpected location attribute type: {:?}", other);
                Ok(EvaluationResult::Optimized)
            }
        }
    }

    /// Parse a DWARF expression into an EvaluationResult
    pub fn parse_expression(
        expr_bytes: &[u8],
        encoding: gimli::Encoding,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<EvaluationResult> {
        if expr_bytes.is_empty() {
            return Ok(EvaluationResult::Optimized);
        }

        // Parse all expressions through unified handler
        Self::parse_full_expression(expr_bytes, encoding, address, get_cfa)
    }

    /// Parse a full multi-operation DWARF expression
    fn parse_full_expression(
        expr_bytes: &[u8],
        encoding: gimli::Encoding,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<EvaluationResult> {
        let mut expression = Expression(EndianSlice::new(expr_bytes, LittleEndian));
        let mut operations = Vec::new();
        let mut has_stack_value = false;

        // Parse all operations in the expression
        while let Ok(op) = Operation::parse(&mut expression.0, encoding) {
            if matches!(op, Operation::StackValue) {
                has_stack_value = true;
                debug!("Found DW_OP_stack_value - this is a computed value");
            }
            operations.push(op);
        }

        if operations.is_empty() {
            return Err(anyhow::anyhow!("Empty expression"));
        }

        debug!("Parsed {} operations in expression", operations.len());

        // Fast path for single operations - avoid compute processing
        if operations.len() == 1 {
            return Self::handle_single_operation(&operations[0], address, get_cfa);
        }

        // Build compute steps from operations
        if !operations.is_empty() {
            let mut steps = Vec::new();

            for op in &operations {
                match op {
                    Operation::RegisterOffset {
                        register, offset, ..
                    } => {
                        // Load register and add offset if non-zero
                        steps.push(ComputeStep::LoadRegister(register.0));
                        if *offset != 0 {
                            steps.push(ComputeStep::PushConstant(*offset));
                            steps.push(ComputeStep::Add);
                        }
                    }
                    Operation::Register { register } => {
                        // DW_OP_reg* means the value IS in the register (direct value)
                        // We'll handle this specially below
                        steps.push(ComputeStep::LoadRegister(register.0));
                    }
                    Operation::PlusConstant { value } => {
                        steps.push(ComputeStep::PushConstant(*value as i64));
                        steps.push(ComputeStep::Add);
                    }
                    Operation::Plus => steps.push(ComputeStep::Add),
                    Operation::Minus => steps.push(ComputeStep::Sub),
                    Operation::Mul => steps.push(ComputeStep::Mul),
                    Operation::Div => steps.push(ComputeStep::Div),
                    Operation::Mod => steps.push(ComputeStep::Mod),
                    Operation::And => steps.push(ComputeStep::And),
                    Operation::Or => steps.push(ComputeStep::Or),
                    Operation::Xor => steps.push(ComputeStep::Xor),
                    Operation::Shl => steps.push(ComputeStep::Shl),
                    Operation::Shr => steps.push(ComputeStep::Shr),
                    Operation::Shra => steps.push(ComputeStep::Shra),
                    Operation::Not => steps.push(ComputeStep::Not),
                    Operation::Neg => steps.push(ComputeStep::Neg),
                    Operation::Abs => steps.push(ComputeStep::Abs),
                    Operation::Eq => steps.push(ComputeStep::Eq),
                    Operation::Ne => steps.push(ComputeStep::Ne),
                    Operation::Lt => steps.push(ComputeStep::Lt),
                    Operation::Le => steps.push(ComputeStep::Le),
                    Operation::Gt => steps.push(ComputeStep::Gt),
                    Operation::Ge => steps.push(ComputeStep::Ge),
                    Operation::UnsignedConstant { value } => {
                        steps.push(ComputeStep::PushConstant(*value as i64));
                    }
                    Operation::SignedConstant { value } => {
                        steps.push(ComputeStep::PushConstant(*value));
                    }
                    Operation::StackValue => {
                        // This marks the result as a computed value, not a memory location
                        // Already handled by has_stack_value flag
                    }
                    Operation::Deref { size, .. } => {
                        let mem_size = match size {
                            1 => MemoryAccessSize::U8,
                            2 => MemoryAccessSize::U16,
                            4 => MemoryAccessSize::U32,
                            8 => MemoryAccessSize::U64,
                            _ => MemoryAccessSize::U64, // Default
                        };
                        steps.push(ComputeStep::Dereference { size: mem_size });
                    }
                    _ => {
                        debug!("Unhandled operation in expression: {:?}", op);
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
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
    ) -> Result<EvaluationResult>
    where
        R: gimli::Reader,
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
                                    offset: Some(cfa_offset + offset),
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
                        warn!(
                            "DW_OP_fbreg but no CFA available at address 0x{:x}",
                            address
                        );
                        Ok(EvaluationResult::Optimized)
                    }
                } else {
                    warn!("DW_OP_fbreg but no CFA provider available");
                    Ok(EvaluationResult::Optimized)
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

            // These operations don't make sense as single operations
            Operation::StackValue => {
                warn!("Single DW_OP_stack_value doesn't make sense");
                Ok(EvaluationResult::Optimized)
            }
            Operation::PlusConstant { .. } => {
                warn!("Single DW_OP_plus_uconst needs something to add to");
                Ok(EvaluationResult::Optimized)
            }
            _ => {
                debug!("Single operation {:?} not handled in fast path", op);
                Ok(EvaluationResult::Optimized)
            }
        }
    }

    /// Parse location lists from .debug_loclists or .debug_loc section
    fn parse_location_lists(
        unit: &gimli::Unit<EndianSlice<'static, LittleEndian>>,
        dwarf: &gimli::Dwarf<EndianSlice<'static, LittleEndian>>,
        offset: gimli::LocationListsOffset<usize>,
        address: u64,
        get_cfa: Option<&dyn Fn(u64) -> Result<Option<crate::core::CfaResult>>>,
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
            debug!("Location list iteration result: {:?}", next_result);

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
                    let location_expr = Self::parse_expression(
                        location_list_entry.data.0.slice(),
                        unit.encoding(),
                        address,
                        get_cfa,
                    )?;

                    debug!("  Parsed expression: {:?}", location_expr);

                    let contains_address = if start_pc == end_pc {
                        address == start_pc
                    } else {
                        address >= start_pc && address < end_pc
                    };

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
                            let contains = if length == 0 {
                                address == start
                            } else {
                                address >= start && address < end
                            };

                            debug!(
                                "   StartLength contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression(
                                    data.0.slice(),
                                    unit.encoding(),
                                    address,
                                    get_cfa,
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
                            let contains = if begin == end {
                                address == begin
                            } else {
                                address >= begin && address < end
                            };

                            debug!(
                                "   StartEnd contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression(
                                    data.0.slice(),
                                    unit.encoding(),
                                    address,
                                    get_cfa,
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
                            let contains = if start == end_addr {
                                address == start
                            } else {
                                address >= start && address < end_addr
                            };

                            debug!(
                                "   OffsetPair contains={} (address=0x{:x})",
                                contains, address
                            );

                            if contains {
                                let location_expr = Self::parse_expression(
                                    data.0.slice(),
                                    unit.encoding(),
                                    address,
                                    get_cfa,
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
                                let contains = if length == 0 {
                                    address == start
                                } else {
                                    address >= start && address < end
                                };

                                debug!(
                                    "   StartxLength contains={} (address=0x{:x})",
                                    contains, address
                                );

                                if contains {
                                    let location_expr = Self::parse_expression(
                                        data.0.slice(),
                                        unit.encoding(),
                                        address,
                                        get_cfa,
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
                                let contains = if start == end_addr {
                                    address == start
                                } else {
                                    address >= start && address < end_addr
                                };

                                debug!(
                                    "   StartxEndx contains={} (address=0x{:x})",
                                    contains, address
                                );

                                if contains {
                                    let location_expr = Self::parse_expression(
                                        data.0.slice(),
                                        unit.encoding(),
                                        address,
                                        get_cfa,
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
                            let location_expr = Self::parse_expression(
                                data.0.slice(),
                                unit.encoding(),
                                address,
                                get_cfa,
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

//! DW_OP_entry_value lowering and call-site recovery helpers.

use crate::{
    binary::DwarfReader,
    core::{ComputeStep, EntryValueCase, Result},
    dwarf_expr::{errors as expr_errors, modes::DwarfExprMode},
    index::{BlockIndexBuilder, CfiIndex, FunctionBlocks},
};
use gimli::{Operation, Reader};
use std::collections::BTreeMap;
use tracing::{debug, warn};

const ENTRY_VALUE_LOOKUP_WARN_CASES: usize = 16;

pub(crate) struct LocationContext<'a> {
    pub(crate) current_pc: u64,
    pub(crate) address_size: u8,
    pub(crate) dwarf: Option<&'a gimli::Dwarf<DwarfReader>>,
    pub(crate) function_context: Option<&'a FunctionBlocks>,
    pub(crate) cfi_index: Option<&'a CfiIndex>,
}

pub(crate) enum LoweredEntryValue {
    Steps {
        steps: Vec<ComputeStep>,
        forces_stack_value: bool,
    },
    Optimized,
}

pub(crate) fn lower_location_entry_value<R>(
    expression: R,
    encoding: gimli::Encoding,
    context: LocationContext<'_>,
) -> Result<LoweredEntryValue>
where
    R: Reader<Offset = usize>,
{
    let inner_ops = expr_errors::hard(
        DwarfExprMode::Location,
        crate::dwarf_expr::ops::parse_ops(
            expression,
            encoding,
            "DW_OP_entry_value inner expression",
        ),
    )?;
    if inner_ops.len() != 1 {
        debug!("Unsupported EntryValue with {} inner ops", inner_ops.len());
        return Err(anyhow::anyhow!(
            "unsupported DW_OP_entry_value with {} inner ops",
            inner_ops.len()
        ));
    }

    match &inner_ops[0] {
        Operation::Register { register } => {
            match resolve_register(
                context.current_pc,
                register.0,
                context.dwarf,
                context.function_context,
                context.cfi_index,
            ) {
                Ok(steps) => Ok(LoweredEntryValue::Steps {
                    steps,
                    forces_stack_value: true,
                }),
                Err(error) => {
                    debug!(
                        "DW_OP_entry_value register {} unresolved at 0x{:x}: {}",
                        register.0, context.current_pc, error
                    );
                    Ok(LoweredEntryValue::Optimized)
                }
            }
        }
        Operation::RegisterOffset {
            register, offset, ..
        } => {
            let steps = resolve_register_offset(
                context.current_pc,
                register.0,
                *offset,
                context.address_size,
                context.dwarf,
                context.function_context,
                context.cfi_index,
            )?;
            Ok(LoweredEntryValue::Steps {
                steps,
                forces_stack_value: false,
            })
        }
        _ => {
            debug!("Unsupported EntryValue inner op: {:?}", inner_ops[0]);
            Err(anyhow::anyhow!(
                "unsupported DW_OP_entry_value inner op: {:?}",
                inner_ops[0]
            ))
        }
    }
}

pub(crate) fn resolve_register(
    current_pc: u64,
    register: u16,
    dwarf: Option<&gimli::Dwarf<DwarfReader>>,
    function_context: Option<&FunctionBlocks>,
    cfi_index: Option<&CfiIndex>,
) -> Result<Vec<ComputeStep>> {
    let function_context = function_context
        .ok_or_else(|| anyhow::anyhow!("DW_OP_entry_value requires function call-site context"))?;
    build_incoming_lookup(current_pc, register, dwarf, function_context, cfi_index).or_else(
        |incoming_error| {
            recover_register_from_cfi(current_pc, register, cfi_index).map_err(|cfi_error| {
                anyhow::anyhow!(
                    "failed to recover DW_OP_entry_value register {} at 0x{:x}: {}; fallback via CFI also failed: {}",
                    register,
                    current_pc,
                    incoming_error,
                    cfi_error
                )
            })
        },
    )
}

fn build_incoming_lookup(
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

    let mut cases_by_return_pc = BTreeMap::<u64, Vec<ComputeStep>>::new();
    let parameters = collect_parameter_steps(register, dwarf, function_context);
    for (caller_return_pc, caller_value_steps) in parameters {
        let value_steps =
            materialize_caller_value_steps(&caller_value_steps, current_pc, Some(cfi_index))
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

    Ok(build_lookup_steps(
        recovery.caller_pc_steps,
        cases_by_return_pc,
    ))
}

pub(crate) fn collect_parameter_steps(
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

pub(crate) fn resolve_register_offset(
    current_pc: u64,
    register: u16,
    offset: i64,
    address_size: u8,
    dwarf: Option<&gimli::Dwarf<DwarfReader>>,
    function_context: Option<&FunctionBlocks>,
    cfi_index: Option<&CfiIndex>,
) -> Result<Vec<ComputeStep>> {
    if is_stack_pointer_register(register) {
        return recover_stack_pointer_steps(current_pc, offset, address_size, cfi_index);
    }

    match resolve_register(current_pc, register, dwarf, function_context, cfi_index) {
        Ok(mut steps) => {
            append_constant_offset(&mut steps, offset);
            Ok(steps)
        }
        Err(entry_error) => {
            let mut steps =
                recover_register_from_cfi(current_pc, register, cfi_index).map_err(|cfi_error| {
                    anyhow::anyhow!(
                        "failed to recover DW_OP_entry_value base register {} with offset {} at 0x{:x}: {}; fallback via CFI also failed: {}",
                        register,
                        offset,
                        current_pc,
                        entry_error,
                        cfi_error
                    )
                })?;
            append_constant_offset(&mut steps, offset);
            Ok(steps)
        }
    }
}

fn recover_register_from_cfi(
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

fn recover_stack_pointer_steps(
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
    let mut steps = cfa_to_steps(cfi_index.get_cfa_result(current_pc)?);
    // This assumes the common x86/x86_64 call-frame convention where the CFA
    // observed after the call is `SP_entry + address_size` because the return
    // address is stored on the stack. Targets such as AArch64 may define the
    // CFA at call entry differently when LR is not pushed, so keep this
    // adjustment centralized until entry-SP reconstruction becomes
    // target-aware.
    append_constant_offset(&mut steps, offset - i64::from(address_size));
    Ok(steps)
}

pub(crate) fn cfa_to_steps(cfa: crate::core::CfaResult) -> Vec<ComputeStep> {
    match cfa {
        crate::core::CfaResult::RegisterPlusOffset { register, offset } => {
            let mut steps = vec![ComputeStep::LoadRegister(register)];
            append_constant_offset(&mut steps, offset);
            steps
        }
        crate::core::CfaResult::Expression { steps } => steps,
    }
}

pub(crate) fn append_constant_offset(steps: &mut Vec<ComputeStep>, offset: i64) {
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

pub(crate) fn build_lookup_steps(
    caller_pc_steps: Vec<ComputeStep>,
    cases_by_return_pc: BTreeMap<u64, Vec<ComputeStep>>,
) -> Vec<ComputeStep> {
    let cases: Vec<_> = cases_by_return_pc
        .into_iter()
        .map(|(caller_return_pc, value_steps)| EntryValueCase {
            caller_return_pc,
            value_steps,
        })
        .collect();
    if cases.len() > ENTRY_VALUE_LOOKUP_WARN_CASES {
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

#[cfg(test)]
mod tests {
    use super::{
        append_constant_offset, build_lookup_steps, cfa_to_steps, collect_parameter_steps,
        resolve_register,
    };
    use crate::binary::{dwarf_reader_from_arc, DwarfReader};
    use crate::core::{ComputeStep, EntryValueCase};
    use crate::index::{BlockNode, CallSiteParameter, CallSiteRecord, FunctionBlocks};
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Sections, Unit,
    };
    use gimli::{Format, LittleEndian, Register};
    use std::sync::Arc;

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
    fn ignores_outgoing_call_sites_in_inline_context() {
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

        let error = resolve_register(0x1034, 5, None, Some(&function), None)
            .expect_err("inline entry_value must not reuse nested outgoing call-site bindings");
        assert!(
            error
                .to_string()
                .contains("DW_OP_entry_value register recovery needs CFI"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn ignores_outgoing_call_sites_in_non_inline_context() {
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

        let error = resolve_register(0x1034, 5, None, Some(&function), None)
            .expect_err("non-inline entry_value must not reuse outgoing call-site bindings");
        assert!(
            error
                .to_string()
                .contains("DW_OP_entry_value register recovery needs CFI"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn uses_incoming_call_site_lookup_for_non_inline_functions() {
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
        let steps = build_lookup_steps(
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
    fn prefers_indexed_incoming_parameters_over_dwarf_scan() {
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

        let parameters = collect_parameter_steps(5, Some(&dwarf), &function);

        assert_eq!(
            parameters,
            vec![(0x2018, vec![ComputeStep::PushConstant(33)])]
        );
    }

    #[test]
    fn stack_pointer_offsets_use_cfa_based_entry_sp() {
        let mut entry_sp_steps = cfa_to_steps(crate::core::CfaResult::RegisterPlusOffset {
            register: 7,
            offset: 32,
        });
        append_constant_offset(&mut entry_sp_steps, 8 - 8);

        assert_eq!(
            entry_sp_steps,
            vec![
                ComputeStep::LoadRegister(7),
                ComputeStep::PushConstant(32),
                ComputeStep::Add,
            ]
        );
    }
}

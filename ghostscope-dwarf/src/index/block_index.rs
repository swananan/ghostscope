//! Per-function block/variable index (blockvector-like)
//!
//! This module builds a compact block-level index for each function:
//! - Captures lexical blocks and inlined subroutines with their PC ranges
//! - Associates variables and parameters with the block scopes
//! - Captures caller-side call-site metadata for future entry_value recovery
//! - Provides fast lookup of in-scope variables at a given PC

use crate::{
    binary::DwarfReader,
    core::ComputeStep,
    parser::{ExpressionEvaluator, RangeExtractor},
    semantics::{ranges_contain_pc, resolve_origin_entry},
};
use gimli::Reader;
use std::collections::BTreeMap;

/// Reference to a variable DIE within a unit (minimal info)
#[derive(Debug, Clone)]
pub struct VarRef {
    pub cu_offset: gimli::DebugInfoOffset,
    pub die_offset: gimli::UnitOffset,
}

/// A caller-side call-site parameter value binding.
#[derive(Debug, Clone, PartialEq)]
pub struct CallSiteParameter {
    /// Callee entry register described by DW_AT_location.
    pub callee_register: u16,
    /// Caller-side DW_AT_call_value lowered directly into ComputeStep[].
    pub caller_value_steps: Vec<ComputeStep>,
}

/// A call-site record keyed by DW_AT_call_return_pc.
#[derive(Debug, Clone, PartialEq)]
pub struct CallSiteRecord {
    /// DIE offset for the call-site itself.
    pub die_offset: gimli::UnitOffset,
    /// Return PC immediately after the call instruction.
    pub return_pc: u64,
    /// Callee parameter bindings available at this call site.
    pub parameters: Vec<CallSiteParameter>,
}

/// A lexical block (or inlined_subroutine) node
#[derive(Debug, Clone)]
pub struct BlockNode {
    /// Address ranges for the block
    pub ranges: Vec<(u64, u64)>,
    /// Optional entry_pc for call sites/inlined locations
    pub entry_pc: Option<u64>,
    /// DIE offset for this block (lexical_block/inlined_subroutine)
    pub die_offset: Option<gimli::UnitOffset>,
    /// Variables declared directly in this block
    pub variables: Vec<VarRef>,
    /// Children blocks indices
    pub children: Vec<usize>,
}

impl BlockNode {
    fn new() -> Self {
        Self {
            ranges: Vec::new(),
            entry_pc: None,
            die_offset: None,
            variables: Vec::new(),
            children: Vec::new(),
        }
    }

    #[inline]
    fn contains_pc(&self, pc: u64) -> bool {
        if let Some(epc) = self.entry_pc {
            if pc == epc {
                return true;
            }
        }
        ranges_contain_pc(&self.ranges, pc)
    }
}

/// Block vector for a single function (root is the function scope)
#[derive(Debug, Clone)]
pub struct FunctionBlocks {
    pub cu_offset: gimli::DebugInfoOffset,
    pub die_offset: gimli::UnitOffset,
    /// Function ranges
    pub ranges: Vec<(u64, u64)>,
    /// Root node is index 0
    pub nodes: Vec<BlockNode>,
    /// Fast map: block start addr -> node index (sparse)
    pub block_addr_map: BTreeMap<u64, usize>,
    /// Caller-side call-site records keyed by DW_AT_call_return_pc.
    pub call_sites: BTreeMap<u64, Vec<CallSiteRecord>>,
}

impl FunctionBlocks {
    fn new(cu_offset: gimli::DebugInfoOffset, die_offset: gimli::UnitOffset) -> Self {
        let mut root = BlockNode::new();
        root.die_offset = Some(die_offset);
        let nodes = vec![root]; // root at 0
        Self {
            cu_offset,
            die_offset,
            ranges: Vec::new(),
            nodes,
            block_addr_map: BTreeMap::new(),
            call_sites: BTreeMap::new(),
        }
    }

    #[inline]
    fn function_contains_pc(&self, pc: u64) -> bool {
        ranges_contain_pc(&self.ranges, pc)
    }

    /// Return node indices from root to the innermost block containing PC
    pub fn block_path_for_pc(&self, pc: u64) -> Vec<usize> {
        let mut path = vec![0usize];
        if self.nodes[0].children.is_empty() {
            return path;
        }

        let mut stack = vec![(0usize, 0usize)]; // (node, child_iter_index)
        let mut best_path = path.clone();
        while let Some((node_idx, mut child_idx)) = stack.pop() {
            // Try children depth-first
            while child_idx < self.nodes[node_idx].children.len() {
                let child = self.nodes[node_idx].children[child_idx];
                child_idx += 1;
                // Push back current with advanced iterator
                stack.push((node_idx, child_idx));
                // Descend into child
                if self.nodes[child].contains_pc(pc) {
                    // Extend path
                    let mut cur = path.clone();
                    cur.push(child);
                    path = cur.clone();
                    best_path = path.clone();
                    // Descend further from this child
                    stack.push((child, 0));
                    break;
                }
            }
        }
        best_path
    }

    /// Enumerate all VarRefs visible at PC (root + blocks on path)
    pub fn variables_at_pc(&self, pc: u64) -> Vec<VarRef> {
        if !self.function_contains_pc(pc) {
            return Vec::new();
        }
        let path = self.block_path_for_pc(pc);
        let mut out = Vec::new();
        for idx in path {
            out.extend(self.nodes[idx].variables.iter().cloned());
        }
        out
    }

    /// Find the nearest caller-side call-site parameter binding whose return_pc
    /// is at or before `pc` and whose callee entry register matches `register`.
    pub fn entry_value_parameter_for_pc(
        &self,
        pc: u64,
        register: u16,
    ) -> Option<&CallSiteParameter> {
        for (_, records) in self.call_sites.range(..=pc).rev() {
            for record in records.iter().rev() {
                if let Some(parameter) = record
                    .parameters
                    .iter()
                    .find(|parameter| parameter.callee_register == register)
                {
                    return Some(parameter);
                }
            }
        }
        None
    }
}

/// Global per-module block index
#[derive(Debug, Default)]
pub struct BlockIndex {
    pub functions: Vec<FunctionBlocks>,
    /// Map: function start addr -> function index
    pub func_addr_map: BTreeMap<u64, usize>,
}

impl BlockIndex {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find a function containing PC via start-addr map and range verification
    pub fn find_function_by_pc(&self, pc: u64) -> Option<&FunctionBlocks> {
        let mut cand: Option<&FunctionBlocks> = None;
        for (_, &fi) in self.func_addr_map.range(..=pc).rev() {
            let f = &self.functions[fi];
            if f.function_contains_pc(pc) {
                cand = Some(f);
                break;
            }
        }
        cand
    }

    /// Add built functions and update address map
    pub fn add_functions(&mut self, mut list: Vec<FunctionBlocks>) {
        for fb in list.drain(..) {
            let idx = self.functions.len();
            for (lo, _) in &fb.ranges {
                self.func_addr_map.insert(*lo, idx);
            }
            self.functions.push(fb);
        }
    }
}

/// Builder for block index using DWARF data
pub struct BlockIndexBuilder<'a> {
    dwarf: &'a gimli::Dwarf<DwarfReader>,
}

impl<'a> BlockIndexBuilder<'a> {
    pub fn new(dwarf: &'a gimli::Dwarf<DwarfReader>) -> Self {
        Self { dwarf }
    }

    // build(): removed to avoid dead_code warnings; use build_for_unit/build_for_function instead.

    /// Build functions for a single CU offset
    pub fn build_for_unit(&self, cu_offset: gimli::DebugInfoOffset) -> Option<Vec<FunctionBlocks>> {
        let header = self.dwarf.unit_header(cu_offset).ok()?;
        let unit = self.dwarf.unit(header).ok()?;
        let mut entries = unit.entries();
        let mut out: Vec<FunctionBlocks> = Vec::new();
        while let Ok(Some(entry)) = entries.next_dfs() {
            if entry.tag() == gimli::constants::DW_TAG_subprogram {
                let mut fb = FunctionBlocks::new(cu_offset, entry.offset());
                if let Ok(ranges) = RangeExtractor::extract_all_ranges(entry, &unit, self.dwarf) {
                    fb.ranges = ranges;
                }
                self.build_blocks_for_function(&unit, entry, &mut fb);
                for (idx, node) in fb.nodes.iter().enumerate() {
                    for (lo, _) in &node.ranges {
                        fb.block_addr_map.insert(*lo, idx);
                    }
                    if let Some(epc) = node.entry_pc {
                        fb.block_addr_map.insert(epc, idx);
                    }
                }
                out.push(fb);
            }
        }
        Some(out)
    }

    /// Build block index for a single subprogram DIE in a CU
    pub fn build_for_function(
        &self,
        cu_offset: gimli::DebugInfoOffset,
        die_offset: gimli::UnitOffset,
    ) -> Option<FunctionBlocks> {
        let header = self.dwarf.unit_header(cu_offset).ok()?;
        let unit = self.dwarf.unit(header).ok()?;
        let entry = unit.entry(die_offset).ok()?;
        if entry.tag() != gimli::constants::DW_TAG_subprogram {
            return None;
        }
        let mut fb = FunctionBlocks::new(cu_offset, die_offset);
        if let Ok(ranges) = RangeExtractor::extract_all_ranges(&entry, &unit, self.dwarf) {
            fb.ranges = ranges;
        }
        self.build_blocks_for_function(&unit, &entry, &mut fb);
        for (idx, node) in fb.nodes.iter().enumerate() {
            for (lo, _) in &node.ranges {
                fb.block_addr_map.insert(*lo, idx);
            }
            if let Some(epc) = node.entry_pc {
                fb.block_addr_map.insert(epc, idx);
            }
        }
        Some(fb)
    }

    fn build_blocks_for_function(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        func_entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        fb: &mut FunctionBlocks,
    ) {
        // DFS but only within this function's subtree
        if let Ok(mut tree) = unit.entries_tree(Some(func_entry.offset())) {
            if let Ok(root) = tree.root() {
                self.walk_children(unit, root, 0, fb);
            }
        }
    }

    fn walk_children(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        node: gimli::EntriesTreeNode<DwarfReader>,
        parent_idx: usize,
        fb: &mut FunctionBlocks,
    ) {
        let mut children = node.children();
        while let Ok(Some(child)) = children.next() {
            let e = child.entry();
            match e.tag() {
                gimli::constants::DW_TAG_formal_parameter | gimli::constants::DW_TAG_variable => {
                    // Only record DIE offsets; evaluation happens on demand
                    let v = VarRef {
                        cu_offset: match unit.header.debug_info_offset() {
                            Some(off) => off,
                            _ => continue,
                        },
                        die_offset: e.offset(),
                    };
                    fb.nodes[parent_idx].variables.push(v);
                }
                gimli::constants::DW_TAG_lexical_block
                | gimli::constants::DW_TAG_inlined_subroutine => {
                    let mut bn = BlockNode::new();
                    if let Ok(ranges) = RangeExtractor::extract_all_ranges(e, unit, self.dwarf) {
                        bn.ranges = ranges;
                    }
                    bn.entry_pc =
                        self.resolve_address_attr(unit, e, gimli::constants::DW_AT_entry_pc);
                    // Record this block's DIE offset for later attribute lookups (e.g., frame base)
                    bn.die_offset = Some(e.offset());
                    let new_idx = fb.nodes.len();
                    fb.nodes.push(bn);
                    fb.nodes[parent_idx].children.push(new_idx);

                    // If this is an inlined subroutine, import origin parameters ONLY if this inline node
                    // does not already have formal_parameter children (some compilers emit them directly).
                    if e.tag() == gimli::constants::DW_TAG_inlined_subroutine {
                        // Peek direct children of this inline node to detect existing formal_parameter DIEs
                        let mut has_inline_params = false;
                        if let Ok(mut it) = unit.entries_at_offset(e.offset()) {
                            // skip self
                            let _ = it.next_entry();
                            while let Ok(Some(ce)) = it.next_dfs() {
                                if ce.depth() <= 0 {
                                    break;
                                }
                                if ce.depth() > 1 {
                                    continue;
                                }
                                if ce.tag() == gimli::constants::DW_TAG_formal_parameter {
                                    has_inline_params = true;
                                    break;
                                }
                            }
                        }
                        if !has_inline_params {
                            if let Some(attr) = e.attr(gimli::constants::DW_AT_abstract_origin) {
                                if let Ok(Some((_origin_abs, origin_unit, origin_entry))) =
                                    resolve_origin_entry(self.dwarf, unit, attr.value())
                                {
                                    if let Ok(mut iter) =
                                        origin_unit.entries_at_offset(origin_entry.offset())
                                    {
                                        // Skip the origin DIE itself
                                        let _ = iter.next_entry();
                                        while let Ok(Some(ce)) = iter.next_dfs() {
                                            // Only consider direct children of the origin DIE
                                            if ce.depth() <= 0 {
                                                break;
                                            }
                                            if ce.depth() > 1 {
                                                continue;
                                            }
                                            if ce.tag() == gimli::constants::DW_TAG_formal_parameter
                                            {
                                                let v = VarRef {
                                                    cu_offset: match origin_unit
                                                        .header
                                                        .debug_info_offset()
                                                    {
                                                        Some(off) => off,
                                                        _ => continue,
                                                    },
                                                    die_offset: ce.offset(),
                                                };
                                                if let Some(node) = fb.nodes.get_mut(new_idx) {
                                                    node.variables.push(v);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    // Recurse into this block
                    self.walk_children(unit, child, new_idx, fb);
                }
                gimli::constants::DW_TAG_call_site | gimli::constants::DW_TAG_GNU_call_site => {
                    self.record_call_site(unit, child, fb);
                }
                // Skip nested subprograms
                gimli::constants::DW_TAG_subprogram => {}
                _ => {}
            }
        }
    }

    fn record_call_site(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        node: gimli::EntriesTreeNode<DwarfReader>,
        fb: &mut FunctionBlocks,
    ) {
        let entry = node.entry();
        let Some(return_pc) =
            self.resolve_address_attr(unit, entry, gimli::constants::DW_AT_call_return_pc)
        else {
            return;
        };

        let mut record = CallSiteRecord {
            die_offset: entry.offset(),
            return_pc,
            parameters: Vec::new(),
        };

        let mut children = node.children();
        while let Ok(Some(child)) = children.next() {
            let child_entry = child.entry();
            if matches!(
                child_entry.tag(),
                gimli::constants::DW_TAG_call_site_parameter
                    | gimli::constants::DW_TAG_GNU_call_site_parameter
            ) {
                if let Some(parameter) =
                    self.parse_call_site_parameter(unit, child_entry, return_pc)
                {
                    record.parameters.push(parameter);
                }
            }
        }

        fb.call_sites.entry(return_pc).or_default().push(record);
    }

    fn parse_call_site_parameter(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        return_pc: u64,
    ) -> Option<CallSiteParameter> {
        let callee_register = Self::parse_call_site_target_register(unit, entry)?;
        let caller_value_steps = self.parse_call_site_value_steps(unit, entry, return_pc)?;
        Some(CallSiteParameter {
            callee_register,
            caller_value_steps,
        })
    }

    fn parse_call_site_target_register(
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
    ) -> Option<u16> {
        let attr = entry.attr(gimli::constants::DW_AT_location)?;
        let gimli::AttributeValue::Exprloc(expr) = attr.value() else {
            return None;
        };
        let expr_bytes = expr.0.to_slice().ok()?;
        let mut expression =
            gimli::Expression(gimli::EndianSlice::new(&expr_bytes, gimli::LittleEndian));
        let first = gimli::Operation::parse(&mut expression.0, unit.encoding()).ok()?;
        if !expression.0.is_empty() {
            return None;
        }
        match first {
            gimli::Operation::Register { register } => Some(register.0),
            _ => None,
        }
    }

    fn parse_call_site_value_steps(
        &self,
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
        let expr_bytes = expr.0.to_slice().ok()?;
        ExpressionEvaluator::parse_expression_to_steps_in_unit(
            &expr_bytes,
            unit,
            self.dwarf,
            return_pc,
            None,
            None,
            None,
        )
        .ok()
        .or_else(|| Self::lower_entry_value_call_site_register(unit, &expr_bytes))
    }

    fn lower_entry_value_call_site_register(
        unit: &gimli::Unit<DwarfReader>,
        expr_bytes: &[u8],
    ) -> Option<Vec<ComputeStep>> {
        let mut expression =
            gimli::Expression(gimli::EndianSlice::new(expr_bytes, gimli::LittleEndian));
        let first = gimli::Operation::parse(&mut expression.0, unit.encoding()).ok()?;
        if !expression.0.is_empty() {
            return None;
        }
        let gimli::Operation::EntryValue { expression: inner } = first else {
            return None;
        };
        let mut inner = inner;
        let inner_op = gimli::Operation::parse(&mut inner, unit.encoding()).ok()?;
        if !inner.is_empty() {
            return None;
        }
        match inner_op {
            gimli::Operation::Register { register } => {
                Some(vec![ComputeStep::LoadRegister(register.0)])
            }
            _ => None,
        }
    }

    fn resolve_address_attr(
        &self,
        unit: &gimli::Unit<DwarfReader>,
        entry: &gimli::DebuggingInformationEntry<DwarfReader>,
        attr_name: gimli::DwAt,
    ) -> Option<u64> {
        let attr = entry.attr(attr_name)?;
        match attr.value() {
            gimli::AttributeValue::Addr(addr) => Some(addr),
            gimli::AttributeValue::DebugAddrIndex(index) => self.dwarf.address(unit, index).ok(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binary::dwarf_reader_from_arc;
    use gimli::constants;
    use gimli::write::{
        Address, AttributeValue as WriteAttributeValue, Dwarf as WriteDwarf, EndianVec,
        Expression as WriteExpression, LineProgram, Sections, Unit,
    };
    use gimli::{Format, LittleEndian, Register};
    use std::sync::Arc;

    fn build_call_site_fixture(
        call_site_tag: gimli::DwTag,
        parameter_tag: gimli::DwTag,
        value_attr: gimli::DwAt,
    ) -> (gimli::Dwarf<DwarfReader>, gimli::DebugInfoOffset) {
        let version = if call_site_tag == constants::DW_TAG_call_site {
            5
        } else {
            4
        };
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let subprogram_id = unit.add(root, constants::DW_TAG_subprogram);
        let subprogram = unit.get_mut(subprogram_id);
        subprogram.set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"call_site_fixture".to_vec()),
        );
        subprogram.set(
            constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x1000)),
        );
        subprogram.set(constants::DW_AT_high_pc, WriteAttributeValue::Udata(0x40));

        let inline_id = unit.add(subprogram_id, constants::DW_TAG_inlined_subroutine);
        let inline_entry = unit.get_mut(inline_id);
        inline_entry.set(
            constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x1010)),
        );
        inline_entry.set(constants::DW_AT_high_pc, WriteAttributeValue::Udata(0x10));
        inline_entry.set(
            constants::DW_AT_entry_pc,
            WriteAttributeValue::Address(Address::Constant(0x1010)),
        );

        let call_site_id = unit.add(inline_id, call_site_tag);
        unit.get_mut(call_site_id).set(
            constants::DW_AT_call_return_pc,
            WriteAttributeValue::Address(Address::Constant(0x1018)),
        );

        let first_param_id = unit.add(call_site_id, parameter_tag);
        let first_param = unit.get_mut(first_param_id);
        let mut first_location = WriteExpression::new();
        first_location.op_reg(Register(5));
        first_param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(first_location),
        );
        let mut first_value = WriteExpression::new();
        first_value.op_breg(Register(3), -1);
        first_param.set(value_attr, WriteAttributeValue::Exprloc(first_value));

        let second_param_id = unit.add(call_site_id, parameter_tag);
        let second_param = unit.get_mut(second_param_id);
        let mut second_location = WriteExpression::new();
        second_location.op_reg(Register(4));
        second_param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(second_location),
        );
        let mut second_value = WriteExpression::new();
        second_value.op_constu(42);
        second_param.set(value_attr, WriteAttributeValue::Exprloc(second_value));

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

        let read_dwarf = dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));
        let mut units = read_dwarf.units();
        let header = units.next().unwrap().unwrap();
        let cu_offset = header.debug_info_offset().unwrap();
        (read_dwarf, cu_offset)
    }

    #[test]
    fn build_for_unit_indexes_standard_call_site_values() {
        let (dwarf, cu_offset) = build_call_site_fixture(
            constants::DW_TAG_call_site,
            constants::DW_TAG_call_site_parameter,
            constants::DW_AT_call_value,
        );
        let builder = BlockIndexBuilder::new(&dwarf);
        let functions = builder
            .build_for_unit(cu_offset)
            .expect("fixture CU should build");
        let function = functions
            .first()
            .expect("fixture should contain one function");

        let records = function
            .call_sites
            .get(&0x1018)
            .map(Vec::as_slice)
            .expect("call-site return_pc should be indexed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].return_pc, 0x1018);
        assert_eq!(records[0].parameters.len(), 2);
        assert_eq!(records[0].parameters[0].callee_register, 5);
        assert_eq!(
            records[0].parameters[0].caller_value_steps,
            vec![
                ComputeStep::LoadRegister(3),
                ComputeStep::PushConstant(-1),
                ComputeStep::Add,
            ]
        );
        assert_eq!(records[0].parameters[1].callee_register, 4);
        assert_eq!(
            records[0].parameters[1].caller_value_steps,
            vec![ComputeStep::PushConstant(42)]
        );
    }

    #[test]
    fn build_for_unit_indexes_gnu_call_site_values() {
        let (dwarf, cu_offset) = build_call_site_fixture(
            constants::DW_TAG_GNU_call_site,
            constants::DW_TAG_GNU_call_site_parameter,
            constants::DW_AT_GNU_call_site_value,
        );
        let builder = BlockIndexBuilder::new(&dwarf);
        let functions = builder
            .build_for_unit(cu_offset)
            .expect("fixture CU should build");
        let function = functions
            .first()
            .expect("fixture should contain one function");

        let records = function
            .call_sites
            .get(&0x1018)
            .map(Vec::as_slice)
            .expect("GNU call-site return_pc should be indexed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].parameters.len(), 2);
        assert_eq!(records[0].parameters[0].callee_register, 5);
        assert_eq!(
            records[0].parameters[0].caller_value_steps,
            vec![
                ComputeStep::LoadRegister(3),
                ComputeStep::PushConstant(-1),
                ComputeStep::Add,
            ]
        );
    }

    #[test]
    fn build_for_unit_indexes_entry_value_call_site_values_as_caller_register_loads() {
        let version = 5;
        let encoding = gimli::Encoding {
            format: Format::Dwarf32,
            version,
            address_size: 8,
        };

        let mut dwarf = WriteDwarf::new();
        let unit_id = dwarf.units.add(Unit::new(encoding, LineProgram::none()));
        let unit = dwarf.units.get_mut(unit_id);
        let root = unit.root();

        let subprogram_id = unit.add(root, constants::DW_TAG_subprogram);
        let subprogram = unit.get_mut(subprogram_id);
        subprogram.set(
            constants::DW_AT_name,
            WriteAttributeValue::String(b"entry_value_call_site_fixture".to_vec()),
        );
        subprogram.set(
            constants::DW_AT_low_pc,
            WriteAttributeValue::Address(Address::Constant(0x1000)),
        );
        subprogram.set(constants::DW_AT_high_pc, WriteAttributeValue::Udata(0x40));

        let call_site_id = unit.add(subprogram_id, constants::DW_TAG_call_site);
        unit.get_mut(call_site_id).set(
            constants::DW_AT_call_return_pc,
            WriteAttributeValue::Address(Address::Constant(0x1018)),
        );

        let param_id = unit.add(call_site_id, constants::DW_TAG_call_site_parameter);
        let param = unit.get_mut(param_id);
        let mut location = WriteExpression::new();
        location.op_reg(Register(4));
        param.set(
            constants::DW_AT_location,
            WriteAttributeValue::Exprloc(location),
        );
        let mut inner = WriteExpression::new();
        inner.op_reg(Register(4));
        let mut value = WriteExpression::new();
        value.op_entry_value(inner);
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

        let read_dwarf = dwarf_sections
            .borrow(|section| dwarf_reader_from_arc(Arc::<[u8]>::from(section.as_slice())));
        let mut units = read_dwarf.units();
        let header = units.next().unwrap().unwrap();
        let cu_offset = header.debug_info_offset().unwrap();

        let builder = BlockIndexBuilder::new(&read_dwarf);
        let functions = builder
            .build_for_unit(cu_offset)
            .expect("fixture CU should build");
        let function = functions
            .first()
            .expect("fixture should contain one function");

        let records = function
            .call_sites
            .get(&0x1018)
            .map(Vec::as_slice)
            .expect("call-site return_pc should be indexed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].parameters.len(), 1);
        assert_eq!(records[0].parameters[0].callee_register, 4);
        assert_eq!(
            records[0].parameters[0].caller_value_steps,
            vec![ComputeStep::LoadRegister(4)]
        );
    }

    #[test]
    fn entry_value_parameter_lookup_uses_nearest_prior_return_pc() {
        let mut function = FunctionBlocks::new(gimli::DebugInfoOffset(0), gimli::UnitOffset(0));
        function.call_sites.insert(
            0x1018,
            vec![CallSiteRecord {
                die_offset: gimli::UnitOffset(1),
                return_pc: 0x1018,
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(11)],
                }],
            }],
        );
        function.call_sites.insert(
            0x1030,
            vec![CallSiteRecord {
                die_offset: gimli::UnitOffset(2),
                return_pc: 0x1030,
                parameters: vec![CallSiteParameter {
                    callee_register: 5,
                    caller_value_steps: vec![ComputeStep::PushConstant(22)],
                }],
            }],
        );

        let parameter = function
            .entry_value_parameter_for_pc(0x1034, 5)
            .expect("nearest call-site parameter should be found");
        assert_eq!(
            parameter.caller_value_steps,
            vec![ComputeStep::PushConstant(22)]
        );

        let earlier = function
            .entry_value_parameter_for_pc(0x1019, 5)
            .expect("earlier call-site parameter should be found");
        assert_eq!(
            earlier.caller_value_steps,
            vec![ComputeStep::PushConstant(11)]
        );

        assert!(
            function.entry_value_parameter_for_pc(0x1017, 5).is_none(),
            "call sites after the current PC must not match"
        );
    }
}

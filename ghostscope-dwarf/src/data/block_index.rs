//! Per-function block/variable index (blockvector-like)
//!
//! This module builds a compact block-level index for each function:
//! - Captures lexical blocks and inlined subroutines with their PC ranges
//! - Associates variables and parameters with the block scopes
//! - Provides fast lookup of in-scope variables at a given PC

use crate::parser::RangeExtractor;
use gimli::{EndianArcSlice, LittleEndian};
use std::collections::BTreeMap;

/// Reference to a variable DIE within a unit (minimal info)
#[derive(Debug, Clone)]
pub struct VarRef {
    pub cu_offset: gimli::DebugInfoOffset,
    pub die_offset: gimli::UnitOffset,
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
        for (lo, hi) in &self.ranges {
            if if lo == hi {
                pc == *lo
            } else {
                pc >= *lo && pc < *hi
            } {
                return true;
            }
        }
        false
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
        }
    }

    #[inline]
    fn function_contains_pc(&self, pc: u64) -> bool {
        for (lo, hi) in &self.ranges {
            if if lo == hi {
                pc == *lo
            } else {
                pc >= *lo && pc < *hi
            } {
                return true;
            }
        }
        false
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
    dwarf: &'a gimli::Dwarf<EndianArcSlice<LittleEndian>>,
}

impl<'a> BlockIndexBuilder<'a> {
    pub fn new(dwarf: &'a gimli::Dwarf<EndianArcSlice<LittleEndian>>) -> Self {
        Self { dwarf }
    }

    // build(): removed to avoid dead_code warnings; use build_for_unit/build_for_function instead.

    /// Build functions for a single CU offset
    pub fn build_for_unit(&self, cu_offset: gimli::DebugInfoOffset) -> Option<Vec<FunctionBlocks>> {
        let header = self.dwarf.debug_info.header_from_offset(cu_offset).ok()?;
        let unit = self.dwarf.unit(header).ok()?;
        let mut entries = unit.entries();
        let mut out: Vec<FunctionBlocks> = Vec::new();
        while let Ok(Some((_depth, entry))) = entries.next_dfs() {
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
        let header = self.dwarf.debug_info.header_from_offset(cu_offset).ok()?;
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
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        func_entry: &gimli::DebuggingInformationEntry<EndianArcSlice<LittleEndian>>,
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
        unit: &gimli::Unit<EndianArcSlice<LittleEndian>>,
        node: gimli::EntriesTreeNode<EndianArcSlice<LittleEndian>>,
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
                        cu_offset: match unit.header.offset() {
                            gimli::UnitSectionOffset::DebugInfoOffset(off) => off,
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
                    if let Ok(Some(a)) = e.attr(gimli::constants::DW_AT_entry_pc) {
                        if let gimli::AttributeValue::Addr(addr) = a.value() {
                            bn.entry_pc = Some(addr);
                        }
                    }
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
                            while let Ok(Some((depth, ce))) = it.next_dfs() {
                                if depth == 0 {
                                    break;
                                }
                                if depth > 1 {
                                    continue;
                                }
                                if ce.tag() == gimli::constants::DW_TAG_formal_parameter {
                                    has_inline_params = true;
                                    break;
                                }
                            }
                        }
                        if !has_inline_params {
                            if let Ok(Some(attr)) = e.attr(gimli::constants::DW_AT_abstract_origin)
                            {
                                if let gimli::AttributeValue::UnitRef(origin_off) = attr.value() {
                                    if let Ok(mut iter) = unit.entries_at_offset(origin_off) {
                                        // Skip the origin DIE itself
                                        let _ = iter.next_entry();
                                        while let Ok(Some((depth, ce))) = iter.next_dfs() {
                                            // Only consider direct children of the origin DIE
                                            if depth == 0 {
                                                break;
                                            }
                                            if depth > 1 {
                                                continue;
                                            }
                                            if ce.tag() == gimli::constants::DW_TAG_formal_parameter
                                            {
                                                let v = VarRef {
                                                    cu_offset: match unit.header.offset() {
                                                        gimli::UnitSectionOffset::DebugInfoOffset(off) => off,
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
                // Skip nested subprograms
                gimli::constants::DW_TAG_subprogram => {}
                _ => {}
            }
        }
    }
}

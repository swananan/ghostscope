//! PC-centered semantic context types.

use crate::core::{CuId, DieRef, FunctionId, InlineContextId, ModuleId, ScopeId};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcContext {
    pub module: ModuleId,
    /// Runtime PC in the target process address space.
    pub pc: u64,
    /// Module-normalized PC used for DWARF and object-file queries.
    pub normalized_pc: u64,
    pub cu: Option<CuId>,
    pub function: Option<FunctionId>,
    /// Best-effort display name until stable function DIE ids are wired in.
    pub function_name: Option<String>,
    pub lexical_scopes: Vec<ScopeId>,
    pub inline_chain: Vec<InlineFrame>,
    /// Best-effort inline classification until inline DIE chains are exposed.
    pub is_inline: Option<bool>,
    pub line: Option<PcLineInfo>,
    pub address_space: AddressSpaceInfo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionParameter {
    pub name: String,
    pub type_name: String,
    pub is_artificial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineFrame {
    pub context: Option<InlineContextId>,
    pub call_site: Option<PcLineInfo>,
    pub abstract_origin: Option<DieRef>,
    pub concrete_die: DieRef,
    pub function_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcLineInfo {
    pub file_path: String,
    pub line_number: u32,
    pub column: Option<u32>,
    pub address: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpaceInfo {
    pub module_path: Option<PathBuf>,
    pub runtime_base: Option<u64>,
    pub link_base: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcRange {
    pub start: u64,
    pub end: u64,
}

impl PcRange {
    pub fn contains(&self, pc: u64) -> bool {
        if self.start == self.end {
            pc == self.start
        } else {
            pc >= self.start && pc < self.end
        }
    }
}

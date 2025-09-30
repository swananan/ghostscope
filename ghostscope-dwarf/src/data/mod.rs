//! Data structures for DWARF analysis results

pub(crate) mod block_index;
pub(crate) mod cfi_index;
pub(crate) mod lightweight_file_index;
pub(crate) mod lightweight_index;
pub(crate) mod line_mapping;
pub(crate) mod on_demand_resolver;
pub(crate) mod path;
pub(crate) mod type_index;

// Re-export only what's needed externally
pub use crate::parser::VariableWithEvaluation;

// Internal re-exports for crate use
pub(crate) use block_index::*;
pub(crate) use cfi_index::*;
pub(crate) use lightweight_file_index::*;
pub(crate) use lightweight_index::*;
pub(crate) use line_mapping::*;
pub(crate) use on_demand_resolver::OnDemandResolver;
pub(crate) use path::{directory_from_index, resolve_file_path};
pub(crate) use type_index::*;

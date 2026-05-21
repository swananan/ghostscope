pub(crate) mod block_index;
pub(crate) mod cfi_index;
pub(crate) mod lightweight_file_index;
pub(crate) mod lightweight_index;
pub(crate) mod line_mapping;
pub(crate) mod path;
pub(crate) mod type_index;

pub(crate) use block_index::{BlockIndex, BlockIndexBuilder, FunctionBlocks, VarRef};
#[cfg(test)]
pub(crate) use block_index::{BlockNode, CallSiteParameter, CallSiteRecord};
pub(crate) use cfi_index::CfiIndex;
pub(crate) use lightweight_file_index::{LightweightFileIndex, ScopedFileIndexManager};
pub(crate) use lightweight_index::{LightweightIndex, LightweightIndexShard};
pub(crate) use line_mapping::LineMappingTable;
pub(crate) use path::{directory_from_index, resolve_file_path};
pub(crate) use type_index::TypeNameIndex;

//! Semantic value presentations carried alongside physical DWARF types.

use serde::{Deserialize, Serialize};

/// Number of bytes used to encode the original length of an indirect byte
/// sequence before its captured payload.
pub const INDIRECT_BYTES_LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<u64>();

/// User-space presentation selected for a captured value.
///
/// `Dwarf` preserves the existing physical-layout formatter. Other variants
/// define both the capture payload contract and its semantic rendering.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValuePresentation {
    #[default]
    Dwarf,
    /// A UTF-8 string encoded as an original-length `u64` followed by captured
    /// bytes. The byte payload may be shorter than the original length.
    Utf8String,
}

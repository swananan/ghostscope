//! Semantic value presentations carried alongside physical DWARF types.

use crate::TypeInfo;
use serde::{Deserialize, Serialize};

/// Number of bytes used to encode the original length of an indirect byte
/// sequence before its captured payload.
pub const INDIRECT_BYTES_LENGTH_PREFIX_SIZE: usize = std::mem::size_of::<u64>();

/// Number of bytes used by an indirect sequence header. The first `u64` is
/// the original element count and the second is the captured element count.
pub const INDIRECT_SEQUENCE_HEADER_SIZE: usize = std::mem::size_of::<u64>() * 2;

/// Offset of the captured element count in an indirect sequence header.
pub const INDIRECT_SEQUENCE_CAPTURED_COUNT_OFFSET: usize = std::mem::size_of::<u64>();

/// User-space presentation selected for a captured value.
///
/// `Dwarf` preserves the existing physical-layout formatter. Other variants
/// define both the capture payload contract and its semantic rendering.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub enum ValuePresentation {
    #[default]
    Dwarf,
    /// A UTF-8 string encoded as an original-length `u64` followed by captured
    /// bytes. The byte payload may be shorter than the original length.
    Utf8String,
    /// A contiguous sequence encoded as original and captured element counts,
    /// followed by complete element bytes. The element type and stride come
    /// from DWARF rather than a source-language ABI assumption.
    Sequence {
        element_type: Box<TypeInfo>,
        element_stride: u64,
    },
    /// An arbitrary byte string using the same length-prefixed payload as
    /// `Utf8String`. Invalid UTF-8 bytes are rendered with `\xNN` escapes.
    ByteString,
}

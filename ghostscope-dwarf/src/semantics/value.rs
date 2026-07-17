//! Semantic capture plans for values whose source-language meaning is not
//! represented by their physical DWARF aggregate alone.

use super::TypeProjection;
use ghostscope_protocol::ValuePresentation;

/// A language-selected presentation and the physical reads needed to produce
/// its protocol payload.
#[derive(Debug, Clone, PartialEq)]
pub struct ValueReadPlan {
    pub presentation: ValuePresentation,
    pub capture: ValueCapturePlan,
}

/// Runtime source of a ring sequence's logical element count.
#[derive(Debug, Clone, PartialEq)]
pub enum RingSequenceLength {
    /// Read the element count directly from this member.
    Explicit(TypeProjection),
    /// Compute the wrapped distance from the start index to this end index.
    End(TypeProjection),
}

/// Physical capture strategy used by a semantic value adapter.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueCapturePlan {
    /// Read an embedded value at a DWARF-derived member projection and present
    /// it using the projected type rather than the physical wrapper type.
    ProjectedValue { value: TypeProjection },
    /// Read a pointer and length from an aggregate, then capture a bounded byte
    /// sequence from the pointer.
    IndirectBytes {
        data: TypeProjection,
        length: TypeProjection,
    },
    /// Read a pointer and logical element count from an aggregate, then capture
    /// a bounded number of complete, contiguous elements.
    IndirectSequence {
        data: TypeProjection,
        length: TypeProjection,
        element_stride: u64,
    },
    /// Read a ring-buffer descriptor, then normalize up to two physical
    /// segments into one logical sequence payload.
    IndirectRingSequence {
        data: TypeProjection,
        start: TypeProjection,
        length: Box<RingSequenceLength>,
        capacity: TypeProjection,
        element_stride: u64,
    },
}

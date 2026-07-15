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

/// Physical capture strategy used by a semantic value adapter.
#[derive(Debug, Clone, PartialEq)]
pub enum ValueCapturePlan {
    /// Read a pointer and length from an aggregate, then capture a bounded byte
    /// sequence from the pointer.
    IndirectBytes {
        data: TypeProjection,
        length: TypeProjection,
    },
}

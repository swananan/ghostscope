//! Core module - handles session management and core data structures

pub mod session;

// Re-export main types for convenience
pub use session::{
    BacktraceRuntimeModuleRequest, BacktraceRuntimeRefreshOutcome, BacktraceRuntimeRefreshSchedule,
    GhostSession,
};

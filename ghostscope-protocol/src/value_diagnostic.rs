//! Static explanations of value display limits, independent of logging.
//! They do not assert that a probe ran or a conditional branch was active.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueDiagnosticReason {
    LayoutUnsupported,
    ReadPlanUnsupported,
    DepthLimit,
    RecursiveType,
    CaptureBudget,
}

impl ValueDiagnosticReason {
    pub fn code(self) -> &'static str {
        match self {
            Self::LayoutUnsupported => "layout-unsupported",
            Self::ReadPlanUnsupported => "read-plan-unsupported",
            Self::DepthLimit => "depth-limit",
            Self::RecursiveType => "recursive-type",
            Self::CaptureBudget => "capture-budget",
        }
    }

    pub fn summary(self) -> &'static str {
        match self {
            Self::LayoutUnsupported => {
                "contents unavailable: unsupported memory layout; showing internal fields"
            }
            Self::ReadPlanUnsupported => {
                "contents unavailable: unsupported debug information; showing internal fields"
            }
            Self::DepthLimit => "nested contents not expanded: depth limit",
            Self::RecursiveType => "nested contents not expanded: recursive type",
            Self::CaptureBudget => "nested contents not expanded: capture budget",
        }
    }

    pub fn short_label(self) -> &'static str {
        match self {
            Self::LayoutUnsupported => "layout unsupported",
            Self::ReadPlanUnsupported => "read plan unsupported",
            Self::DepthLimit => "depth limit",
            Self::RecursiveType => "recursive type",
            Self::CaptureBudget => "capture budget",
        }
    }

    pub fn marker(self) -> &'static str {
        match self {
            Self::LayoutUnsupported => "<internal fields: layout unsupported>",
            Self::ReadPlanUnsupported => "<internal fields: read plan unsupported>",
            Self::DepthLimit => "<not expanded: depth limit>",
            Self::RecursiveType => "<not expanded: recursive type>",
            Self::CaptureBudget => "<not expanded: capture budget>",
        }
    }
}

/// Paths are relative to the printed expression. `[]` describes elements;
/// variant-qualified paths describe a possible branch, not a runtime failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValueDiagnostic {
    pub path: String,
    pub type_name: String,
    pub reason: ValueDiagnosticReason,
    pub detail: String,
}

impl ValueDiagnostic {
    pub fn prefixed(mut self, path: &str) -> Self {
        self.path.insert_str(0, path);
        self
    }

    pub fn message(&self, expression: &str) -> String {
        format!(
            "{}{}: {} [{}]\n  Type: {}\n  Detail: {}\n  Help: docs/value-diagnostics.md#{} (offline: ghostscope --value-diagnostics-help)",
            expression,
            self.path,
            self.reason.summary(),
            self.reason.code(),
            self.type_name,
            self.detail,
            self.reason.code(),
        )
    }
}

/// One expression/type pair in a compiled trace. Type indices distinguish
/// semantic printing from explicit memory formats of the same expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceValueDiagnostic {
    pub variable_index: u16,
    pub type_index: u16,
    pub diagnostic: ValueDiagnostic,
}

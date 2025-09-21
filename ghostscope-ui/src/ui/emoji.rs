/// Emoji configuration and management for the UI
use crate::ui::strings::UIStrings;

/// Global emoji configuration
#[derive(Debug, Clone)]
pub struct EmojiConfig {
    pub enabled: bool,
}

impl Default for EmojiConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl EmojiConfig {
    /// Create a new emoji configuration
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// Get the appropriate prefix based on emoji configuration
    pub fn get_status_prefix(&self, status: StatusType) -> &'static str {
        if self.enabled {
            match status {
                StatusType::Success => UIStrings::SUCCESS_PREFIX,
                StatusType::Error => UIStrings::ERROR_PREFIX,
                StatusType::Warning => UIStrings::WARNING_PREFIX,
                StatusType::Info => UIStrings::INFO_PREFIX,
                StatusType::Progress => UIStrings::PROGRESS_PREFIX,
            }
        } else {
            match status {
                StatusType::Success => UIStrings::SUCCESS_PREFIX_ASCII,
                StatusType::Error => UIStrings::ERROR_PREFIX_ASCII,
                StatusType::Warning => UIStrings::WARNING_PREFIX_ASCII,
                StatusType::Info => UIStrings::INFO_PREFIX_ASCII,
                StatusType::Progress => UIStrings::PROGRESS_PREFIX_ASCII,
            }
        }
    }

    /// Get script status emoji or ASCII equivalent
    pub fn get_script_status(&self, status: ScriptStatus) -> &'static str {
        if self.enabled {
            match status {
                ScriptStatus::Success => UIStrings::SCRIPT_SUCCESS_EMOJI,
                ScriptStatus::Error => UIStrings::SCRIPT_ERROR_EMOJI,
                ScriptStatus::Partial => UIStrings::SCRIPT_PARTIAL_EMOJI,
                ScriptStatus::Compiling => UIStrings::SCRIPT_COMPILING_EMOJI,
            }
        } else {
            match status {
                ScriptStatus::Success => "[SUCCESS]",
                ScriptStatus::Error => "[ERROR]",
                ScriptStatus::Partial => "[PARTIAL]",
                ScriptStatus::Compiling => "[COMPILING]",
            }
        }
    }

    /// Get trace element emoji or ASCII equivalent
    pub fn get_trace_element(&self, element: TraceElement) -> &'static str {
        if self.enabled {
            match element {
                TraceElement::Target => UIStrings::TARGET_EMOJI,
                TraceElement::Binary => UIStrings::BINARY_EMOJI,
                TraceElement::Address => UIStrings::ADDRESS_EMOJI,
                TraceElement::Line => UIStrings::LINE_EMOJI,
                TraceElement::File => UIStrings::FILE_EMOJI,
                TraceElement::Function => UIStrings::FUNCTION_EMOJI,
                TraceElement::Variable => UIStrings::VARIABLE_EMOJI,
                TraceElement::Probe => UIStrings::PROBE_EMOJI,
            }
        } else {
            match element {
                TraceElement::Target => "Target:",
                TraceElement::Binary => "Binary:",
                TraceElement::Address => "Address:",
                TraceElement::Line => "Line:",
                TraceElement::File => "File:",
                TraceElement::Function => "Function:",
                TraceElement::Variable => "Variable:",
                TraceElement::Probe => "Probe:",
            }
        }
    }

    /// Get trace status emoji or ASCII equivalent
    pub fn get_trace_status(&self, status: TraceStatusType) -> &'static str {
        if self.enabled {
            match status {
                TraceStatusType::Active => UIStrings::ACTIVE_EMOJI,
                TraceStatusType::Disabled => UIStrings::DISABLED_EMOJI,
                TraceStatusType::Failed => UIStrings::FAILED_EMOJI,
                TraceStatusType::Skipped => UIStrings::SKIPPED_EMOJI,
            }
        } else {
            match status {
                TraceStatusType::Active => "[ACTIVE]",
                TraceStatusType::Disabled => "[DISABLED]",
                TraceStatusType::Failed => "[FAILED]",
                TraceStatusType::Skipped => "[SKIPPED]",
            }
        }
    }
}

/// Status types for general UI messages
#[derive(Debug, Clone, Copy)]
pub enum StatusType {
    Success,
    Error,
    Warning,
    Info,
    Progress,
}

/// Script compilation/execution status
#[derive(Debug, Clone, Copy)]
pub enum ScriptStatus {
    Success,
    Error,
    Partial,
    Compiling,
}

/// Trace element types
#[derive(Debug, Clone, Copy)]
pub enum TraceElement {
    Target,
    Binary,
    Address,
    Line,
    File,
    Function,
    Variable,
    Probe,
}

/// Trace status types
#[derive(Debug, Clone, Copy)]
pub enum TraceStatusType {
    Active,
    Disabled,
    Failed,
    Skipped,
}

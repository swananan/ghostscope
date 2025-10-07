/// Centralized UI strings for internationalization support
pub struct UIStrings;

impl UIStrings {
    // Panel titles
    pub const SOURCE_PANEL_TITLE: &'static str = "Source Code";
    pub const EBPF_PANEL_TITLE: &'static str = "eBPF Output";
    pub const COMMAND_PANEL_TITLE: &'static str = "Interactive Command";

    // Mode indicators
    pub const INPUT_MODE: &'static str = "INPUT";
    pub const COMMAND_MODE: &'static str = "COMMAND";
    pub const SCRIPT_MODE: &'static str = "SCRIPT";

    // Prompts
    pub const GHOSTSCOPE_PROMPT: &'static str = "(ghostscope) ";
    pub const SEARCH_PROMPT: &'static str = "Search: ";
    pub const FILE_SEARCH_PROMPT: &'static str = "File: ";

    // Status messages
    pub const LOADING: &'static str = "Loading...";
    pub const COMPILING: &'static str = "Compiling and loading script...";
    pub const SCRIPT_CANCELLED: &'static str = "Script input cancelled";
    pub const UNKNOWN_COMMAND: &'static str = "Unknown command";

    // Help text
    pub const HELP_TEXT: &'static str = r#"Available commands:
  help     - Show this help message
  trace    - Start tracing a function (enters script mode)
  attach   - Attach to a process by PID
  detach   - Detach from current process
  quit     - Exit ghostscope
  exit     - Exit ghostscope"#;

    // File info headers
    pub const SOURCE_FILES_HEADER: &'static str = "Source Files by Module";
    pub const NO_SOURCE_FILES: &'static str = "No source files found.";
    pub const SHARED_LIBRARIES_HEADER: &'static str = "Shared Libraries";
    pub const NO_SHARED_LIBRARIES: &'static str = "No shared libraries found.";

    // Table headers
    pub const SHARED_LIB_TABLE_HEADER: &'static str =
        "From                To                  Syms Read   Debug Read   Shared Object Library";

    // Warnings
    pub const NO_DEBUG_INFO_WARNING: &'static str = "has no DWARF debug information";

    // Script display
    pub const SCRIPT_TARGET_PREFIX: &'static str = "Script for target: ";
    pub const SCRIPT_SEPARATOR: &'static str = "─";

    // Trace status
    pub const TRACE_STATUS_HEADER: &'static str = "Trace Status";
    pub const NO_TRACES_FOUND: &'static str = "No traces found.";
    pub const TRACE_DETAILS_HEADER: &'static str = "Trace Details:";

    // Error prefixes (keeping ASCII for better compatibility)
    pub const ERROR_PREFIX: &'static str = "✗";
    pub const SUCCESS_PREFIX: &'static str = "✅";
    pub const WARNING_PREFIX: &'static str = "⚠️";
    pub const INFO_PREFIX: &'static str = "ℹ️";
    pub const PROGRESS_PREFIX: &'static str = "⏳";

    // ASCII alternatives for better compatibility
    pub const ERROR_PREFIX_ASCII: &'static str = "[ERROR]";
    pub const SUCCESS_PREFIX_ASCII: &'static str = "[OK]";
    pub const WARNING_PREFIX_ASCII: &'static str = "[WARN]";
    pub const INFO_PREFIX_ASCII: &'static str = "[INFO]";
    pub const PROGRESS_PREFIX_ASCII: &'static str = "[...]";

    // Enhanced emoji support for trace operations
    pub const SCRIPT_SUCCESS_EMOJI: &'static str = "✅";
    pub const SCRIPT_ERROR_EMOJI: &'static str = "❌";
    pub const SCRIPT_PARTIAL_EMOJI: &'static str = "⚠️";
    pub const SCRIPT_COMPILING_EMOJI: &'static str = "🔄";
    pub const TARGET_EMOJI: &'static str = "🎯";
    pub const BINARY_EMOJI: &'static str = "📦";
    pub const ADDRESS_EMOJI: &'static str = "📍";
    pub const LINE_EMOJI: &'static str = "📝";
    pub const FILE_EMOJI: &'static str = "📄";
    pub const FUNCTION_EMOJI: &'static str = "🔧";
    pub const VARIABLE_EMOJI: &'static str = "💾";
    pub const PROBE_EMOJI: &'static str = "🔗";
    pub const DISABLED_EMOJI: &'static str = "⏸️";
    pub const SKIPPED_EMOJI: &'static str = "⏭️";
    pub const ACTIVE_EMOJI: &'static str = "🟢";
    pub const FAILED_EMOJI: &'static str = "🔴";
}

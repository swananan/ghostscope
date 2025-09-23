/// Central Action enum for TEA architecture
/// All possible actions/messages that can modify application state
#[derive(Debug, Clone)]
pub enum Action {
    // Global actions
    Quit,
    Resize(u16, u16),

    // Panel focus actions
    FocusNext,
    FocusPrevious,
    FocusPanel(PanelType),
    ToggleFullscreen,
    SwitchLayout,

    // Window navigation
    EnterWindowNavMode,
    ExitWindowNavMode,
    WindowNavMove(WindowDirection),

    // Input actions
    InsertChar(char),
    DeleteChar,
    MoveCursor(CursorDirection),
    DeleteWord,
    DeletePreviousWord,
    DeleteToEnd,
    DeleteToBeginning,
    MoveToBeginning,
    MoveToEnd,

    // Command actions
    SubmitCommand,
    SubmitCommandWithText {
        command: String,
    }, // For history search mode
    HistoryUp,
    HistoryDown,
    HistoryPrevious, // Ctrl+p - go to previous command
    HistoryNext,     // Ctrl+n - go to next command
    EnterCommandMode,
    ExitCommandMode, // Exit command mode and return to previous mode
    EnterInputMode,

    // Command mode navigation actions
    CommandCursorUp,
    CommandCursorDown,
    CommandCursorLeft,
    CommandCursorRight,
    CommandHalfPageUp,   // Ctrl+U in command mode
    CommandHalfPageDown, // Ctrl+D in command mode

    // Script editing actions
    EnterScriptMode(String),
    ExitScriptMode,
    SubmitScript,
    CancelScript,
    InsertNewline,
    InsertTab,

    // Response handling
    AddResponse {
        content: String,
        response_type: ResponseType,
    },
    AddStyledWelcomeMessage {
        styled_lines: Vec<ratatui::text::Line<'static>>,
        response_type: ResponseType,
    },
    CommandCompleted,
    CommandFailed(String),

    // Runtime communication
    SendRuntimeCommand(RuntimeCommand),
    HandleRuntimeStatus(RuntimeStatus),
    HandleTraceEvent(ghostscope_protocol::TraceEventData),

    // Source panel actions
    LoadSource {
        path: String,
        line: Option<usize>,
    },
    EnterFileSearch,
    ExitFileSearch,
    EnterTextSearch,
    ExitTextSearch,
    NavigateSource(SourceNavigation),
    SourceSearchInput(char),
    SourceSearchBackspace,
    SourceSearchConfirm,
    SourceFileSearchInput(char),
    SourceFileSearchBackspace,
    SourceFileSearchConfirm,
    SourceNumberInput(char),
    SourceGoToLine,
    SourceGoToBottom,

    // eBPF panel actions
    NavigateEbpf(EbpfNavigation),

    // Internal actions
    NoOp, // No operation - used to prevent event fallback without side effects
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PanelType {
    Source,
    EbpfInfo,
    InteractiveCommand,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CursorDirection {
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WindowDirection {
    Left,  // h
    Right, // l
    Up,    // k
    Down,  // j
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SourceNavigation {
    Up,
    Down,
    Left,
    Right,
    PageUp,
    PageDown,
    HalfPageUp,   // Ctrl+U - up 10 lines
    HalfPageDown, // Ctrl+D - down 10 lines
    WordForward,  // w - next word
    WordBackward, // b - previous word
    LineStart,    // ^ - first non-whitespace character
    LineEnd,      // $ - end of line
    GoToLine(usize),
    NextMatch,
    PrevMatch,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EbpfNavigation {
    Up,
    Down,
    PageUp,
    PageDown,
    GoToLine(usize),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseType {
    Success,
    Error,
    Warning,
    Info,
    Progress,
    ScriptDisplay,
}

// Import from events.rs
pub use crate::events::{RuntimeCommand, RuntimeStatus};

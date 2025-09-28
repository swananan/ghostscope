use crate::action::ResponseType;
use ghostscope_protocol::ParsedTraceEvent;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Cached trace event with pre-formatted timestamp
#[derive(Debug, Clone)]
pub struct CachedTraceEvent {
    pub event: ParsedTraceEvent,
    pub formatted_timestamp: String,
}

/// Source panel state
#[derive(Debug, Clone)]
pub struct SourcePanelState {
    pub content: Vec<String>,
    pub current_line: Option<usize>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub scroll_offset: usize,
    pub horizontal_scroll_offset: usize,
    pub file_path: Option<String>,
    pub language: String,
    pub area_height: u16,
    pub area_width: u16,

    // Search state
    pub search_query: String,
    pub search_matches: Vec<(usize, usize, usize)>, // (line_idx, start, end)
    pub current_match: Option<usize>,
    pub is_searching: bool,

    // File search state
    pub file_search_query: String,
    pub file_search_cursor_pos: usize, // Cursor position in the search query
    pub file_search_results: Vec<String>,
    pub file_search_filtered_indices: Vec<usize>,
    pub file_search_selected: usize,
    pub file_search_scroll: usize,
    pub file_search_message: Option<String>,
    pub is_file_searching: bool,

    // Navigation state
    pub number_buffer: String,
    pub expecting_g: bool,
    pub g_pressed: bool,

    // Mode state
    pub mode: SourcePanelMode,

    // Traced lines tracking
    pub traced_lines: HashSet<usize>, // Line numbers with active traces (1-based)
    pub disabled_lines: HashSet<usize>, // Line numbers with disabled traces (1-based)
    pub pending_trace_line: Option<usize>, // Line waiting for trace confirmation (1-based)
    // Map from trace_id to (file_path, line_number) for managing trace status
    pub trace_locations: HashMap<u32, (String, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourcePanelMode {
    Normal,
    TextSearch,
    FileSearch,
}

impl SourcePanelState {
    pub fn new() -> Self {
        Self {
            content: vec!["// No source code loaded".to_string()],
            current_line: None,
            cursor_line: 0,
            cursor_col: 0,
            scroll_offset: 0,
            horizontal_scroll_offset: 0,
            file_path: None,
            language: "c".to_string(),
            area_height: 10,
            area_width: 80,
            search_query: String::new(),
            search_matches: Vec::new(),
            current_match: None,
            is_searching: false,
            file_search_query: String::new(),
            file_search_cursor_pos: 0,
            file_search_results: Vec::new(),
            file_search_filtered_indices: Vec::new(),
            file_search_selected: 0,
            file_search_scroll: 0,
            file_search_message: None,
            is_file_searching: false,
            number_buffer: String::new(),
            expecting_g: false,
            g_pressed: false,
            mode: SourcePanelMode::Normal,
            traced_lines: HashSet::new(),
            disabled_lines: HashSet::new(),
            pending_trace_line: None,
            trace_locations: HashMap::new(),
        }
    }
}

impl Default for SourcePanelState {
    fn default() -> Self {
        Self::new()
    }
}

/// eBPF panel state
#[derive(Debug)]
pub struct EbpfPanelState {
    pub trace_events: VecDeque<CachedTraceEvent>,
    pub scroll_offset: usize,
    pub max_messages: usize,
    pub auto_scroll: bool,
    pub cursor_trace_index: usize, // Index of the selected trace (not line)
    pub show_cursor: bool,         // Whether to show cursor highlighting
    pub display_mode: DisplayMode, // Current display mode
    pub next_message_id: u64,      // Simple counter for message numbering
    // Numeric jump input for N+G
    pub numeric_prefix: Option<String>,
    pub g_pressed: bool, // whether first 'g' was pressed (for 'gg')
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DisplayMode {
    AutoRefresh, // Default mode: always show latest trace, auto-scroll
    Scroll,      // Manual mode: show cursor, manual navigation
}

impl EbpfPanelState {
    pub fn new() -> Self {
        Self {
            trace_events: VecDeque::new(),
            scroll_offset: 0,
            max_messages: 2000, // TODO: Make this configurable in the future
            auto_scroll: true,
            cursor_trace_index: 0,
            show_cursor: false,
            display_mode: DisplayMode::AutoRefresh,
            next_message_id: 1,
            numeric_prefix: None,
            g_pressed: false,
        }
    }

    pub fn add_trace_event(&mut self, trace_event: ParsedTraceEvent) {
        // Format timestamp once when adding the event
        let formatted_timestamp = crate::utils::format_timestamp_ns(trace_event.timestamp);
        let cached_event = CachedTraceEvent {
            event: trace_event,
            formatted_timestamp,
        };

        self.trace_events.push_back(cached_event);
        if self.trace_events.len() > self.max_messages {
            self.trace_events.pop_front();
        }

        // Only auto-scroll in auto-refresh mode
        if self.display_mode == DisplayMode::AutoRefresh {
            self.scroll_to_bottom();
        }
    }

    pub fn scroll_up(&mut self) {
        if self.scroll_offset > 0 {
            self.scroll_offset -= 1;
            self.auto_scroll = false;
        }
    }

    pub fn scroll_down(&mut self) {
        let total_lines = self.trace_events.len();
        if self.scroll_offset + 1 < total_lines {
            self.scroll_offset += 1;
        } else {
            self.auto_scroll = true;
        }
    }

    pub fn scroll_to_bottom(&mut self) {
        // For now, just set scroll offset to 0 to show all messages
        self.scroll_offset = 0;
        self.auto_scroll = true;
        self.show_cursor = false;
    }

    pub fn move_cursor_up(&mut self) {
        self.enter_scroll_mode();
        if self.cursor_trace_index > 0 {
            self.cursor_trace_index -= 1;
        }
    }

    pub fn move_cursor_down(&mut self) {
        self.enter_scroll_mode();
        if self.cursor_trace_index + 1 < self.trace_events.len() {
            self.cursor_trace_index += 1;
        }
    }

    pub fn move_cursor_up_10(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = self.cursor_trace_index.saturating_sub(10);
    }

    pub fn move_cursor_down_10(&mut self) {
        self.enter_scroll_mode();
        let max_index = self.trace_events.len().saturating_sub(1);
        self.cursor_trace_index = (self.cursor_trace_index + 10).min(max_index);
    }

    // Jump to first trace (gg)
    pub fn jump_to_first(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = 0;
    }

    // Jump to last trace (G without prefix)
    pub fn jump_to_last(&mut self) {
        self.enter_scroll_mode();
        self.cursor_trace_index = self.trace_events.len().saturating_sub(1);
    }

    // Start or append numeric prefix for N G
    pub fn push_numeric_digit(&mut self, ch: char) {
        if ch.is_ascii_digit() {
            self.enter_scroll_mode();
            let s = self.numeric_prefix.get_or_insert_with(String::new);
            if s.len() < 9 {
                s.push(ch);
            }
            // typing number cancels pending 'g'
            self.g_pressed = false;
        }
    }

    // Confirm 'G' action: if numeric prefix present, jump to that message number; else jump to last
    pub fn confirm_goto(&mut self) {
        if let Some(s) = self.numeric_prefix.take() {
            if let Ok(num) = s.parse::<u64>() {
                self.jump_to_message_number(num);
                return;
            }
        }
        self.jump_to_last();
    }

    // Jump to specific message number (1-based). Clamp to [first,last]
    pub fn jump_to_message_number(&mut self, message_number: u64) {
        self.enter_scroll_mode();
        if self.trace_events.is_empty() {
            self.cursor_trace_index = 0;
            return;
        }

        // Message numbers are 1-based sequential (1, 2, 3, ...)
        // Convert to 0-based index
        if message_number == 0 {
            self.cursor_trace_index = 0;
            return;
        }

        let target_index = (message_number - 1) as usize;
        self.cursor_trace_index = target_index.min(self.trace_events.len().saturating_sub(1));
    }

    // Exit to auto-refresh (ESC)
    pub fn exit_to_auto_refresh(&mut self) {
        self.numeric_prefix = None;
        self.g_pressed = false;
        self.hide_cursor();
        self.scroll_to_bottom();
    }

    // Handle 'g' key (support 'gg')
    pub fn handle_g_key(&mut self) {
        self.enter_scroll_mode();
        if self.g_pressed {
            self.g_pressed = false;
            self.jump_to_first();
        } else {
            self.g_pressed = true;
        }
    }

    /// Enter scroll mode and set cursor to the last trace
    fn enter_scroll_mode(&mut self) {
        if self.display_mode != DisplayMode::Scroll {
            self.display_mode = DisplayMode::Scroll;
            self.show_cursor = true;
            self.auto_scroll = false;
            // Set cursor to the last trace when entering scroll mode
            self.cursor_trace_index = self.trace_events.len().saturating_sub(1);
        }
    }

    pub fn hide_cursor(&mut self) {
        self.display_mode = DisplayMode::AutoRefresh;
        self.show_cursor = false;
        self.auto_scroll = true;
    }
}

impl Default for EbpfPanelState {
    fn default() -> Self {
        Self::new()
    }
}

/// Command panel state
#[derive(Debug)]
pub struct CommandPanelState {
    // Input state
    pub input_text: String,
    pub cursor_position: usize,

    // Mode and interaction state
    pub mode: InteractionMode,
    pub input_state: InputState,

    // History
    pub command_history: Vec<CommandHistoryItem>,
    pub history_index: Option<usize>,
    pub unsent_input_backup: Option<String>,

    // Script editing
    pub script_cache: Option<ScriptCache>,

    // Command mode navigation - cursor in unified line view
    pub command_cursor_line: usize,
    pub command_cursor_column: usize,
    pub cached_panel_width: u16, // Cached panel width for text wrapping calculations

    // File completion cache
    pub file_completion_cache:
        Option<crate::components::command_panel::file_completion::FileCompletionCache>,

    // Saved cursor states for mode switching
    pub saved_input_cursor: usize, // Input mode cursor position
    pub saved_script_cursor: Option<(usize, usize)>, // Script mode (line, col)
    pub previous_mode: Option<InteractionMode>, // Track mode for 'i' key return

    // Display
    pub static_lines: Vec<StaticTextLine>,
    pub scroll_offset: usize,
    pub styled_buffer: Option<Vec<ratatui::text::Line<'static>>>,
    pub styled_at_history_index: Option<usize>,

    // Vim-like escape sequence
    pub jk_escape_state: JkEscapeState,
    pub jk_timer: Option<Instant>,

    // Configuration
    pub max_history_items: usize,

    // New history management
    pub command_history_manager: crate::components::command_panel::CommandHistory,
    pub history_search: crate::components::command_panel::HistorySearchState,
    pub auto_suggestion: crate::components::command_panel::AutoSuggestionState,

    // Batch loading state for source command
    pub batch_loading: Option<BatchLoadingState>,
}

/// State for tracking batch trace loading (e.g., from source command)
#[derive(Debug, Clone)]
pub struct BatchLoadingState {
    pub filename: String,
    pub total_count: usize,
    pub completed_count: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub disabled_count: usize, // TODO: Currently not used - disabled traces are ignored during loading
    pub details: Vec<crate::events::TraceLoadDetail>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InteractionMode {
    Input,        // Normal input mode
    Command,      // Command mode (previously VimCommand)
    ScriptEditor, // Multi-line script editing mode
}

#[derive(Debug, Clone, PartialEq)]
pub enum JkEscapeState {
    None, // No escape sequence in progress
    J,    // 'j' was pressed, waiting for 'k'
}

#[derive(Debug, Clone, PartialEq)]
pub enum InputState {
    Ready, // Normal input state, shows (ghostscope)
    WaitingResponse {
        // Waiting for response, completely hide input
        command: String,
        sent_time: Instant,
        command_type: CommandType,
    },
    ScriptEditor, // Script editing mode
}

#[derive(Debug, Clone, PartialEq)]
pub enum CommandType {
    Script,
    Enable { trace_id: u32 },
    Disable { trace_id: u32 },
    Delete { trace_id: u32 },
    EnableAll,
    DisableAll,
    DeleteAll,
    InfoFunction { target: String },
    InfoLine { target: String },
    InfoAddress { target: String },
    InfoTrace { trace_id: Option<u32> },
    InfoTraceAll,
    InfoSource,
    InfoShare,
    SaveTraces,
    LoadTraces,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScriptStatus {
    Draft,     // Script is being edited
    Submitted, // Script was submitted successfully
    Error,     // Script had errors
}

#[derive(Debug, Clone)]
pub struct SavedScript {
    pub content: String,    // Script content
    pub cursor_line: usize, // Saved cursor line
    pub cursor_col: usize,  // Saved cursor column
}

#[derive(Debug, Clone)]
pub struct ScriptCache {
    pub target: String,           // Trace target (function name or file:line)
    pub original_command: String, // Original trace command (e.g., "trace main")
    pub lines: Vec<String>,       // Script lines
    pub cursor_line: usize,       // Current cursor line (0-based)
    pub cursor_col: usize,        // Current cursor column (0-based)
    pub status: ScriptStatus,     // Current script status
    pub saved_scripts: HashMap<String, SavedScript>, // target -> complete script cache
}

#[derive(Debug, Clone)]
pub struct CommandHistoryItem {
    pub command: String,
    pub response: Option<String>,
    pub timestamp: std::time::Instant,
    pub prompt: String,
    pub response_type: Option<ResponseType>,
}

#[derive(Debug, Clone)]
pub struct StaticTextLine {
    pub content: String,
    pub line_type: LineType,
    pub history_index: Option<usize>,
    pub response_type: Option<ResponseType>,
    /// Optional pre-styled content (takes precedence over content if present)
    pub styled_content: Option<ratatui::text::Line<'static>>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LineType {
    Command,
    Response,
    CurrentInput,
    Welcome,
}

impl CommandPanelState {
    pub fn new() -> Self {
        Self::new_with_config(&crate::model::ui_state::HistoryConfig::default())
    }

    pub fn new_with_config(history_config: &crate::model::ui_state::HistoryConfig) -> Self {
        Self {
            input_text: String::new(),
            cursor_position: 0,
            mode: InteractionMode::Input,
            input_state: InputState::Ready,
            command_history: Vec::new(),
            history_index: None,
            unsent_input_backup: None,
            script_cache: None,
            command_cursor_line: 0,
            command_cursor_column: 0,
            cached_panel_width: 80, // Default width
            file_completion_cache: None,
            saved_input_cursor: 0,
            saved_script_cursor: None,
            previous_mode: None,
            static_lines: Vec::new(),
            scroll_offset: 0,
            styled_buffer: None,
            styled_at_history_index: None,
            jk_escape_state: JkEscapeState::None,
            jk_timer: None,
            max_history_items: history_config.max_entries,

            // New history management
            command_history_manager:
                crate::components::command_panel::CommandHistory::new_with_config(history_config),
            history_search: crate::components::command_panel::HistorySearchState::new(),
            auto_suggestion: crate::components::command_panel::AutoSuggestionState::new(),
            batch_loading: None,
        }
    }

    /// Update cached panel width for text wrapping calculations
    pub fn update_panel_width(&mut self, width: u16) {
        self.cached_panel_width = width;
    }

    /// Clean up file completion cache if unused for too long
    pub fn cleanup_file_completion_cache(&mut self) {
        if let Some(cache) = &self.file_completion_cache {
            if cache.should_cleanup() {
                tracing::debug!("Cleaning up unused file completion cache");
                self.file_completion_cache = None;
            }
        }
    }

    /// Enter command mode from current mode, saving cursor state
    pub fn enter_command_mode(&mut self, panel_width: u16) {
        self.cached_panel_width = panel_width;
        self.previous_mode = Some(self.mode);

        match self.mode {
            InteractionMode::Input => {
                self.saved_input_cursor = self.cursor_position;
                // Set command cursor to the current input line (last line)
                // Use wrapped lines to handle text that exceeds panel width
                let wrapped_lines = self.get_command_mode_wrapped_lines(panel_width);

                self.command_cursor_line = wrapped_lines.len().saturating_sub(1);
                // Calculate column position including prompt prefix
                let prompt = crate::ui::strings::UIStrings::GHOSTSCOPE_PROMPT;
                self.command_cursor_column = prompt.chars().count() + self.cursor_position;
            }
            InteractionMode::ScriptEditor => {
                if let Some(ref script_cache) = self.script_cache {
                    self.saved_script_cursor =
                        Some((script_cache.cursor_line, script_cache.cursor_col));
                    // Calculate which line in the unified view corresponds to current script cursor
                    let lines = self.get_command_mode_lines();
                    let script_start_line = self.get_script_start_line();
                    // Add 3 for header lines (target, separator, prompt)
                    self.command_cursor_line = (script_start_line + 3 + script_cache.cursor_line)
                        .min(lines.len().saturating_sub(1));
                    self.command_cursor_column = script_cache.cursor_col;
                }
            }
            InteractionMode::Command => {
                // Already in command mode, no change needed
                return;
            }
        }

        self.mode = InteractionMode::Command;
    }

    /// Exit command mode and return to previous mode, restoring cursor state
    pub fn exit_command_mode(&mut self) {
        if let Some(previous_mode) = self.previous_mode {
            match previous_mode {
                InteractionMode::Input => {
                    self.cursor_position = self.saved_input_cursor;
                    self.mode = InteractionMode::Input;
                }
                InteractionMode::ScriptEditor => {
                    if let Some((line, col)) = self.saved_script_cursor {
                        if let Some(ref mut script_cache) = self.script_cache {
                            script_cache.cursor_line = line;
                            script_cache.cursor_col = col;
                        }
                    }
                    self.mode = InteractionMode::ScriptEditor;
                }
                InteractionMode::Command => {
                    // This shouldn't happen, but handle gracefully
                    self.mode = InteractionMode::Input;
                }
            }
            self.previous_mode = None;
        } else {
            // Fallback to input mode if no previous mode
            self.mode = InteractionMode::Input;
        }
    }

    /// Get total number of lines in unified view (for command mode navigation)
    pub fn get_total_lines(&self) -> usize {
        // Use wrapped lines to get accurate line count that considers text wrapping
        let wrapped_lines = self.get_command_mode_wrapped_lines(self.cached_panel_width);
        wrapped_lines.len()
    }

    /// Get script start line offset in unified view
    fn get_script_start_line(&self) -> usize {
        let mut offset = 0;

        // Count history lines
        for item in &self.command_history {
            offset += 1; // Command line
            if let Some(ref response) = item.response {
                offset += response.lines().count();
            }
        }

        offset += 3; // Header + separator + prompt
        offset
    }

    /// Get all lines for command mode (unified view)
    pub fn get_command_mode_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();

        // First, add static lines (including welcome messages)
        for static_line in &self.static_lines {
            lines.push(static_line.content.clone());
        }

        // Then add history lines
        for item in &self.command_history {
            lines.push(format!("(ghostscope) {}", item.command));
            if let Some(ref response) = item.response {
                for response_line in response.lines() {
                    lines.push(response_line.to_string());
                }
            }
        }

        // Add current content based on mode
        // In command mode, show content based on previous_mode
        let display_mode = if self.mode == InteractionMode::Command {
            self.previous_mode.unwrap_or(InteractionMode::Input)
        } else {
            self.mode
        };

        match display_mode {
            InteractionMode::Input => {
                if matches!(self.input_state, InputState::Ready) {
                    lines.push(format!("(ghostscope) {}", self.input_text));
                }
            }
            InteractionMode::ScriptEditor => {
                if let Some(ref script_cache) = self.script_cache {
                    lines.push(format!(
                        "🔨 Entering script mode for target: {}",
                        script_cache.target
                    ));
                    lines.push("─".repeat(50));
                    lines.push("Script Editor (Ctrl+s to submit, Esc to cancel):".to_string());

                    for (idx, line) in script_cache.lines.iter().enumerate() {
                        lines.push(format!("{:3} │ {}", idx + 1, line));
                    }
                }
            }
            InteractionMode::Command => {
                // This shouldn't happen in normal flow, but handle gracefully
                if matches!(self.input_state, InputState::Ready) {
                    lines.push(format!("(ghostscope) {}", self.input_text));
                }
            }
        }

        lines
    }

    /// Get wrapped lines for command mode navigation (considering text wrapping)
    pub fn get_command_mode_wrapped_lines(&self, available_width: u16) -> Vec<String> {
        let logical_lines = self.get_command_mode_lines();
        let mut wrapped_lines = Vec::new();

        for logical_line in logical_lines {
            let wrapped = self.wrap_text_unicode(&logical_line, available_width);
            wrapped_lines.extend(wrapped);
        }

        // Add current input if not already included (for navigation)
        if matches!(self.previous_mode, Some(InteractionMode::Input)) {
            let current_input_line = format!("(ghostscope) {}", self.input_text);

            // Check if it's already included
            let should_add = if wrapped_lines.is_empty() {
                true
            } else {
                !wrapped_lines.iter().any(|line| line == &current_input_line)
            };

            if should_add {
                let wrapped = self.wrap_text_unicode(&current_input_line, available_width);
                wrapped_lines.extend(wrapped);
            }
        }

        wrapped_lines
    }

    /// Wrap text considering Unicode character widths
    fn wrap_text_unicode(&self, text: &str, width: u16) -> Vec<String> {
        use unicode_width::UnicodeWidthChar;

        if width <= 2 {
            return vec![text.to_string()];
        }

        let max_width = width as usize;
        let mut lines = Vec::new();

        for line in text.lines() {
            // Calculate the actual display width using Unicode width
            let line_width: usize = line
                .chars()
                .map(|c| UnicodeWidthChar::width(c).unwrap_or(0))
                .sum();

            if line_width <= max_width {
                lines.push(line.to_string());
            } else {
                // Need to wrap this line
                let mut current_line = String::new();
                let mut current_width = 0;

                for ch in line.chars() {
                    let char_width = UnicodeWidthChar::width(ch).unwrap_or(0);

                    if current_width + char_width > max_width && !current_line.is_empty() {
                        // Start a new line
                        lines.push(current_line);
                        current_line = ch.to_string();
                        current_width = char_width;
                    } else {
                        current_line.push(ch);
                        current_width += char_width;
                    }
                }

                if !current_line.is_empty() {
                    lines.push(current_line);
                }
            }
        }

        if lines.is_empty() {
            lines.push(String::new());
        }

        lines
    }

    /// Move command cursor up
    pub fn move_command_cursor_up(&mut self) {
        if self.command_cursor_line > 0 {
            self.command_cursor_line -= 1;
            // Adjust column to fit new line - use wrapped lines for accurate navigation
            let lines = self.get_command_mode_wrapped_lines(self.cached_panel_width);
            if self.command_cursor_line < lines.len() {
                let line_len = lines[self.command_cursor_line].chars().count();
                self.command_cursor_column = self.command_cursor_column.min(line_len);
            }
        }
    }

    /// Move command cursor down
    pub fn move_command_cursor_down(&mut self) {
        // Use wrapped lines for accurate navigation
        let lines = self.get_command_mode_wrapped_lines(self.cached_panel_width);
        if self.command_cursor_line + 1 < lines.len() {
            self.command_cursor_line += 1;
            // Adjust column to fit new line
            if self.command_cursor_line < lines.len() {
                let line_len = lines[self.command_cursor_line].chars().count();
                self.command_cursor_column = self.command_cursor_column.min(line_len);
            }
        }
    }

    /// Move command cursor left (supports line wrapping and Unicode)
    pub fn move_command_cursor_left(&mut self) {
        if self.command_cursor_column > 0 {
            // Move left within current line
            self.command_cursor_column -= 1;
        } else if self.command_cursor_line > 0 {
            // At beginning of line, wrap to end of previous line
            self.command_cursor_line -= 1;
            let lines = self.get_command_mode_wrapped_lines(self.cached_panel_width);
            if self.command_cursor_line < lines.len() {
                // Use Unicode-aware character counting
                self.command_cursor_column = lines[self.command_cursor_line].chars().count();
            }
        }
    }

    /// Move command cursor right (supports line wrapping and Unicode)
    pub fn move_command_cursor_right(&mut self) {
        let lines = self.get_command_mode_wrapped_lines(self.cached_panel_width);
        if self.command_cursor_line < lines.len() {
            // Use Unicode-aware character counting
            let line_len = lines[self.command_cursor_line].chars().count();
            if self.command_cursor_column < line_len {
                // Move right within current line
                self.command_cursor_column += 1;
            } else if self.command_cursor_line + 1 < lines.len() {
                // At end of line, wrap to beginning of next line
                self.command_cursor_line += 1;
                self.command_cursor_column = 0;
            }
        }
    }

    /// Navigate to previous command in history (Ctrl+p)
    pub fn history_previous(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        match self.history_index {
            None => {
                // Currently at input line, save current input and go to most recent command
                self.unsent_input_backup = Some(self.input_text.clone());
                self.history_index = Some(self.command_history.len() - 1);
                self.input_text = self.command_history[self.command_history.len() - 1]
                    .command
                    .clone();
                self.cursor_position = self.input_text.len();
            }
            Some(current_idx) => {
                if current_idx > 0 {
                    // Go to previous command
                    self.history_index = Some(current_idx - 1);
                    self.input_text = self.command_history[current_idx - 1].command.clone();
                    self.cursor_position = self.input_text.len();
                }
                // If already at first command (index 0), do nothing
            }
        }
    }

    /// Navigate to next command in history (Ctrl+n)
    pub fn history_next(&mut self) {
        if self.command_history.is_empty() {
            return;
        }

        match self.history_index {
            None => {
                // Already at current input line, do nothing
            }
            Some(current_idx) => {
                if current_idx + 1 < self.command_history.len() {
                    // Go to next command
                    self.history_index = Some(current_idx + 1);
                    self.input_text = self.command_history[current_idx + 1].command.clone();
                    self.cursor_position = self.input_text.len();
                } else {
                    // At last command, go back to current input
                    self.history_index = None;
                    if let Some(backup) = self.unsent_input_backup.take() {
                        self.input_text = backup;
                    } else {
                        self.input_text.clear();
                    }
                    self.cursor_position = self.input_text.len();
                }
            }
        }
    }

    /// Move command cursor up by half a page (fast scroll)
    pub fn move_command_half_page_up(&mut self) {
        let jump_size = 10; // Half page size
        if self.command_cursor_line >= jump_size {
            self.command_cursor_line -= jump_size;
        } else {
            self.command_cursor_line = 0;
        }

        // Adjust column to fit new line
        let lines = self.get_command_mode_lines();
        if self.command_cursor_line < lines.len() {
            let line_len = lines[self.command_cursor_line].chars().count();
            self.command_cursor_column = self.command_cursor_column.min(line_len);
        }
    }

    /// Move command cursor down by half a page (fast scroll)
    pub fn move_command_half_page_down(&mut self) {
        let jump_size = 10; // Half page size
        let total_lines = self.get_total_lines();

        if self.command_cursor_line + jump_size < total_lines {
            self.command_cursor_line += jump_size;
        } else {
            self.command_cursor_line = total_lines.saturating_sub(1);
        }

        // Adjust column to fit new line
        let lines = self.get_command_mode_lines();
        if self.command_cursor_line < lines.len() {
            let line_len = lines[self.command_cursor_line].chars().count();
            self.command_cursor_column = self.command_cursor_column.min(line_len);
        }
    }

    // === History Management Methods ===

    /// Update auto suggestion based on current input
    pub fn update_auto_suggestion(&mut self) {
        tracing::debug!("update_auto_suggestion: input_text='{}'", self.input_text);

        self.auto_suggestion
            .update(&self.input_text, &self.command_history_manager);

        if let Some(suggestion) = self.auto_suggestion.get_full_suggestion() {
            tracing::debug!("update_auto_suggestion: found suggestion='{}'", suggestion);
        } else {
            tracing::debug!("update_auto_suggestion: no suggestion found");
        }
    }

    /// Accept the current auto suggestion
    /// This treats the suggestion as a new command entry, clearing all related state
    pub fn accept_auto_suggestion(&mut self) {
        if let Some(suggestion) = self.auto_suggestion.get_full_suggestion() {
            tracing::debug!(
                "accept_auto_suggestion: before - input_text='{}', cursor_position={}",
                self.input_text,
                self.cursor_position
            );
            tracing::debug!(
                "accept_auto_suggestion: accepting suggestion='{}'",
                suggestion
            );

            self.input_text = suggestion.to_string();
            self.cursor_position = self.input_text.len();
            self.auto_suggestion.clear();

            // Clear any search state - this is a new command entry
            self.history_search.clear();

            tracing::debug!(
                "accept_auto_suggestion: after - input_text='{}', cursor_position={}",
                self.input_text,
                self.cursor_position
            );
        } else {
            tracing::debug!("accept_auto_suggestion: no suggestion available");
        }
    }

    /// Start history search mode
    pub fn start_history_search(&mut self) {
        tracing::debug!(
            "start_history_search: command_history.len()={}",
            self.command_history.len()
        );
        self.history_search.start_search();
        // Clear current input when starting search
        self.input_text.clear();
        self.cursor_position = 0;
        tracing::debug!(
            "start_history_search: after clear - command_history.len()={}",
            self.command_history.len()
        );
    }

    /// Update history search query and find matches
    pub fn update_history_search(&mut self, query: String) {
        self.history_search
            .update_query(query, &self.command_history_manager);
        // Don't modify input_text here - keep it as the actual user input (search query)
        // The renderer will decide what to display based on search state
    }

    /// Move to next history search match
    pub fn next_history_match(&mut self) {
        // Just update the match, don't modify input_text
        // The renderer will display the matched command
        self.history_search
            .next_match(&self.command_history_manager);
    }

    /// Exit history search mode
    pub fn exit_history_search(&mut self) {
        self.history_search.clear();
        self.auto_suggestion.clear();
    }

    /// Exit history search mode and set the selected command as new input
    pub fn exit_history_search_with_selection(&mut self, selected_command: &str) {
        self.input_text = selected_command.to_string();
        self.cursor_position = self.input_text.len();
        self.history_search.clear();
        self.auto_suggestion.clear();
    }

    /// Add command to history when executed
    pub fn add_command_to_history(&mut self, command: &str) {
        self.command_history_manager.add_command(command);
    }

    /// Check if currently in history search mode
    pub fn is_in_history_search(&self) -> bool {
        self.history_search.is_active
    }

    /// Get current history search query
    pub fn get_history_search_query(&self) -> &str {
        &self.history_search.query
    }

    // Removed old add_welcome_lines - now using add_styled_welcome_lines

    /// Add styled welcome message lines directly (new simplified approach)
    pub fn add_styled_welcome_lines(
        &mut self,
        styled_lines: Vec<ratatui::text::Line<'static>>,
        response_type: ResponseType,
    ) {
        // Clear existing welcome messages to prevent duplicates
        self.static_lines
            .retain(|line| !matches!(line.line_type, LineType::Welcome));

        for styled_line in styled_lines {
            // Extract plain text for content field (for compatibility)
            let content: String = styled_line
                .spans
                .iter()
                .map(|span| span.content.as_ref())
                .collect();

            self.static_lines.push(StaticTextLine {
                content,
                line_type: LineType::Welcome,
                history_index: None,
                response_type: Some(response_type),
                styled_content: Some(styled_line),
            });
        }
        // Clear any cached styled buffer since we've added new content
        self.styled_buffer = None;
        self.styled_at_history_index = None;
    }

    /// Get auto suggestion text for rendering
    pub fn get_suggestion_text(&self) -> Option<&str> {
        self.auto_suggestion.get_suggestion_text()
    }

    /// Get the text that should be displayed in the input line
    /// In normal mode, this is just the input text (auto-suggestions are handled separately)
    /// In history search mode, this is the matched command
    pub fn get_display_text(&self) -> &str {
        if self.is_in_history_search() {
            // In history search mode, display the matched command if available
            if let Some(matched_command) = self
                .history_search
                .current_match(&self.command_history_manager)
            {
                return matched_command;
            }
        }
        // In normal mode, always display just the actual input text
        // Auto-suggestions are displayed separately in the renderer
        &self.input_text
    }

    /// Get the position where cursor should be displayed
    /// This is always based on the actual input text, not auto-suggestions
    pub fn get_display_cursor_position(&self) -> usize {
        let result = if self.is_in_history_search() {
            // In history search mode, cursor should be at the end of the search query
            self.history_search.query.len()
        } else {
            // Normal mode, use actual cursor position in the input text
            self.cursor_position
        };

        tracing::debug!("get_display_cursor_position: is_in_history_search={}, input_text='{}', cursor_position={}, result={}",
            self.is_in_history_search(), self.input_text, self.cursor_position, result);
        result
    }
}

impl Default for CommandPanelState {
    fn default() -> Self {
        Self::new()
    }
}

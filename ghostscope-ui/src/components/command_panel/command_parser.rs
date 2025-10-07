use crate::action::{Action, ResponseType, RuntimeCommand};
use crate::model::panel_state::{CommandPanelState, CommandType, InputState};
use crate::ui::strings::UIStrings;
use ratatui::style::Modifier;
use std::time::Instant;

/// Handles command parsing and built-in command execution
pub struct CommandParser;

impl CommandParser {
    /// Parse and handle a command, returning appropriate actions
    pub fn parse_command(state: &mut CommandPanelState, command: &str) -> Vec<Action> {
        let cmd = command.trim();

        // Handle built-in help commands with styled responses
        if cmd == "help" {
            let plain = Self::format_help_message();
            let styled = Self::format_help_message_styled();
            return vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Info,
            }];
        }
        if cmd == "help srcpath" {
            let plain = Self::format_srcpath_help();
            let styled = Self::format_srcpath_help_styled();
            return vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Info,
            }];
        }

        // Handle sync commands (enable/disable/delete)
        if let Some(actions) = Self::parse_sync_command(state, cmd) {
            return actions;
        }

        // Handle trace command (support both full command and abbreviation)
        if cmd.starts_with("trace ") {
            return vec![Action::EnterScriptMode(cmd.to_string())];
        }
        if cmd.starts_with("t ") {
            // Convert "t target" to "trace target" for consistent handling
            let target = cmd.strip_prefix("t ").unwrap();
            let full_command = format!("trace {target}");
            return vec![Action::EnterScriptMode(full_command)];
        }

        // Handle shortcut commands
        if let Some(actions) = Self::parse_shortcut_command(state, cmd) {
            return actions;
        }

        // Handle info commands
        if let Some(actions) = Self::parse_info_command(state, cmd) {
            return actions;
        }

        // Handle save commands (traces, output, session)
        if let Some(actions) = Self::parse_save_command(state, cmd) {
            return actions;
        }

        // Handle stop command (stop realtime logging)
        if let Some(actions) = Self::parse_stop_command(cmd) {
            return actions;
        }

        // Handle source command
        if let Some(actions) = Self::parse_source_command(state, cmd) {
            return actions;
        }

        // Handle srcpath command
        if let Some(actions) = Self::parse_srcpath_command(state, cmd) {
            return actions;
        }

        // Handle quit/exit commands
        if cmd == "quit" || cmd == "exit" {
            return vec![Action::Quit];
        }

        // Handle clear command
        if cmd == "clear" {
            // Clear command history
            state.command_history.clear();
            let plain = "✅ Command history cleared.".to_string();
            let styled = vec![
                crate::components::command_panel::style_builder::StyledLineBuilder::new()
                    .styled(
                        plain.clone(),
                        crate::components::command_panel::style_builder::StylePresets::SUCCESS,
                    )
                    .build(),
            ];
            return vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Info,
            }];
        }

        // Unknown command
        {
            let plain = format!("{} {}", UIStrings::ERROR_PREFIX, UIStrings::UNKNOWN_COMMAND);
            let styled =
                crate::components::command_panel::ResponseFormatter::style_generic_message_lines(
                    &plain,
                );
            vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]
        }
    }

    /// Format detailed srcpath help message
    fn format_srcpath_help() -> String {
        [
            "📘 Source Path Command - Detailed Help",
            "",
            "The 'srcpath' command helps resolve source files when DWARF debug info contains",
            "compilation-time paths that differ from runtime paths (e.g., compiled on CI server).",
            "",
            "Commands:",
            "  srcpath                      - Show current path mappings and search directories",
            "  srcpath map <from> <to>      - Map DWARF compilation directory to local path (⭐ Recommended)",
            "  srcpath add <dir>            - Add search directory (fallback, non-recursive)",
            "  srcpath remove <path>        - Remove a mapping or search directory",
            "  srcpath clear                - Clear all runtime rules (keep config file rules)",
            "  srcpath reset                - Reset to config file rules only",
            "",
            "Resolution Strategy:",
            "  1. Try exact path from DWARF",
            "  2. Apply path substitutions (runtime rules first, then config file)",
            "  3. Search by filename in additional directories (root only, non-recursive)",
            "",
            "⭐ Recommended Usage:",
            "  Use 'srcpath map' to map DWARF compilation directory:",
            "    srcpath map /home/build/nginx-1.27.1 /home/user/nginx-1.27.1",
            "  This maps ALL relative paths automatically.",
            "",
            "Examples:",
            "  srcpath map /build/project /home/user/project    # Map compilation directory",
            "  srcpath add /usr/local/include                    # Add search directory (fallback)",
            "  srcpath remove /build/project                     # Remove a rule",
            "",
            "Configuration:",
            "  Rules can be persisted in config.toml under [source] section.",
            "  Runtime rules (via commands) take priority over config file rules.",
            "",
            "💡 Tip: Check file loading errors for 'DWARF Directory', then map it directly.",
            "   Type 'help srcpath' for more details.",
        ]
        .join("\n")
    }

    /// Format comprehensive help message
    fn format_help_message() -> String {
        format!(
            "📘 Ghostscope Commands:\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}",
            Self::format_tracing_commands(),
            Self::format_info_commands(),
            Self::format_srcpath_commands(),
            Self::format_control_commands(),
            Self::format_navigation_commands(),
            Self::format_general_commands()
        )
    }

    /// Styled comprehensive help message
    fn format_help_message_styled() -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::StyledLineBuilder;
        use ratatui::text::Line;

        let mut lines = Vec::new();
        // Title
        lines.push(
            StyledLineBuilder::new()
                .title("📘 Ghostscope Commands:")
                .build(),
        );
        lines.push(Line::from(""));

        // Sections
        lines.extend(Self::format_section_styled(&Self::format_tracing_commands()));
        lines.push(Line::from(""));
        lines.extend(Self::format_section_styled(&Self::format_info_commands()));
        lines.push(Line::from(""));
        lines.extend(Self::format_section_styled(&Self::format_srcpath_commands()));
        lines.push(Line::from(""));
        lines.extend(Self::format_section_styled(&Self::format_control_commands()));
        lines.push(Line::from(""));
        lines.extend(Self::format_section_styled(
            &Self::format_navigation_commands(),
        ));
        lines.push(Line::from(""));
        lines.extend(Self::format_section_styled(&Self::format_general_commands()));
        lines
    }

    /// Helper: format a single help section's text into styled lines
    fn format_section_styled(section_text: &str) -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        let mut out = Vec::new();
        for raw in section_text.lines() {
            if raw.is_empty() {
                out.push(ratatui::text::Line::from(""));
                continue;
            }
            if matches!(
                raw.chars().next(),
                Some('📊' | '🔍' | '🗂' | '⚙' | '🧭' | '🔧')
            ) {
                out.push(
                    StyledLineBuilder::new()
                        .styled(raw, StylePresets::SECTION)
                        .build(),
                );
                continue;
            }
            if raw.starts_with("  ") {
                out.push(Self::build_help_command_line(raw));
                continue;
            }
            if raw.contains("💡") {
                out.push(
                    StyledLineBuilder::new()
                        .styled(raw, StylePresets::TIP)
                        .build(),
                );
                continue;
            }
            out.push(StyledLineBuilder::new().value(raw).build());
        }
        out
    }

    /// Styled srcpath detailed help
    fn format_srcpath_help_styled() -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        use ratatui::text::Line;

        let mut lines = Vec::new();
        lines.push(
            StyledLineBuilder::new()
                .title("📘 Source Path Command - Detailed Help")
                .build(),
        );
        lines.push(Line::from(""));

        for raw in Self::format_srcpath_help().lines() {
            if raw.is_empty() {
                lines.push(Line::from(""));
                continue;
            }
            if raw.starts_with("📘") {
                continue; // already handled as title
            }
            if matches!(
                raw,
                "Commands:"
                    | "Resolution Strategy:"
                    | "⭐ Recommended Usage:"
                    | "Examples:"
                    | "Configuration:"
            ) {
                lines.push(
                    StyledLineBuilder::new()
                        .styled(raw, StylePresets::SECTION)
                        .build(),
                );
                continue;
            }
            if raw.starts_with("  ") {
                lines.push(Self::build_help_command_line(raw));
                continue;
            }
            if raw.contains("💡") {
                lines.push(
                    StyledLineBuilder::new()
                        .styled(raw, StylePresets::TIP)
                        .build(),
                );
                continue;
            }
            lines.push(StyledLineBuilder::new().value(raw).build());
        }

        lines
    }

    /// Styled info help (info commands usage)
    fn format_info_help_styled() -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        let mut lines = Vec::new();
        for raw in Self::format_info_help().lines() {
            if raw.is_empty() {
                lines.push(ratatui::text::Line::from(""));
                continue;
            }
            if raw.starts_with("🔍 Info") {
                lines.push(StyledLineBuilder::new().title(raw).build());
                continue;
            }
            if raw.starts_with("  ") {
                lines.push(Self::build_help_command_line(raw));
                continue;
            }
            if raw.contains("💡") {
                lines.push(
                    StyledLineBuilder::new()
                        .styled(raw, StylePresets::TIP)
                        .build(),
                );
                continue;
            }
            lines.push(StyledLineBuilder::new().value(raw).build());
        }
        lines
    }

    /// Helper: convert a single help command line into styled spans
    fn build_help_command_line(line: &str) -> ratatui::text::Line<'static> {
        use ratatui::{
            style::{Color, Style},
            text::{Line, Span},
        };

        // Preserve leading spaces
        let mut spans: Vec<Span<'static>> = Vec::new();
        let trimmed = line.trim_start();
        let leading = line.len() - trimmed.len();
        if leading > 0 {
            spans.push(Span::raw(" ".repeat(leading)));
        }

        // Split into command part and description
        let (cmd_part, desc_part) = match trimmed.find(" - ") {
            Some(pos) => (&trimmed[..pos], Some(&trimmed[pos..])),
            None => (trimmed, None),
        };

        // Walk cmd_part and style parameters in <...> as Yellow, others as White+Bold
        let mut current = String::new();
        let mut in_param = false;
        for ch in cmd_part.chars() {
            match ch {
                '<' => {
                    if !current.is_empty() {
                        spans.push(Span::styled(
                            current.clone(),
                            Style::default()
                                .fg(Color::White)
                                .add_modifier(Modifier::BOLD),
                        ));
                        current.clear();
                    }
                    in_param = true;
                    current.push('<');
                }
                '>' => {
                    current.push('>');
                    spans.push(Span::styled(
                        current.clone(),
                        Style::default().fg(Color::Yellow),
                    ));
                    current.clear();
                    in_param = false;
                }
                _ => current.push(ch),
            }
        }
        if !current.is_empty() {
            if in_param {
                spans.push(Span::styled(current, Style::default().fg(Color::Yellow)));
            } else {
                spans.push(Span::styled(
                    current,
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ));
            }
        }

        // Description part in dark gray
        if let Some(desc) = desc_part {
            spans.push(Span::styled(
                desc.to_string(),
                Style::default().fg(Color::DarkGray),
            ));
        }

        Line::from(spans)
    }

    /// Styled 'Usage: ...' helper: highlights 'Usage:' and parameters in <...>
    fn styled_usage(usage: &str) -> Vec<ratatui::text::Line<'static>> {
        use ratatui::{
            style::{Color, Style},
            text::{Line, Span},
        };

        let mut spans: Vec<Span<'static>> = Vec::new();
        let trimmed = usage.trim_start();
        // Preserve indent if any
        let leading = usage.len() - trimmed.len();
        if leading > 0 {
            spans.push(Span::raw(" ".repeat(leading)));
        }

        let prefix = "Usage:";
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            spans.push(Span::styled(
                prefix.to_string(),
                Style::default().fg(Color::Cyan),
            ));
            spans.push(Span::raw(" "));
            // Highlight parameters between <...>
            let mut current = String::new();
            let mut in_param = false;
            for ch in rest.chars() {
                match ch {
                    '<' => {
                        if !current.is_empty() {
                            spans.push(Span::styled(
                                current.clone(),
                                Style::default().fg(Color::White),
                            ));
                            current.clear();
                        }
                        in_param = true;
                        current.push('<');
                    }
                    '>' => {
                        current.push('>');
                        spans.push(Span::styled(
                            current.clone(),
                            Style::default().fg(Color::Yellow),
                        ));
                        current.clear();
                        in_param = false;
                    }
                    _ => current.push(ch),
                }
            }
            if !current.is_empty() {
                let style = if in_param {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::White)
                };
                spans.push(Span::styled(current, style));
            }
        } else {
            // No prefix, color whole line white
            spans.push(Span::styled(
                trimmed.to_string(),
                Style::default().fg(Color::White),
            ));
        }

        vec![Line::from(spans)]
    }

    /// Format tracing command section
    fn format_tracing_commands() -> String {
        [
            "📊 Tracing Commands:",
            "  trace <target>             - Start tracing a function/location (t)",
            "  enable <id|all>            - Enable specific trace or all traces (en)",
            "  disable <id|all>           - Disable specific trace or all traces (dis)",
            "  delete <id|all>            - Delete specific trace or all traces (del)",
            "  save traces [file]         - Save all traces to file (s t)",
            "  save traces enabled [file] - Save only enabled traces",
            "  save traces disabled [file]- Save only disabled traces",
            "  save output [file]         - Start realtime eBPF output logging (s o)",
            "  save session [file]        - Start realtime session logging (s s)",
            "  stop output                - Stop realtime eBPF output logging",
            "  stop session               - Stop realtime session logging",
            "  source <file>              - Load traces from file (s)",
        ]
        .join("\n")
    }

    /// Format info command section
    fn format_info_commands() -> String {
        [
            "🔍 Information Commands:",
            "  info                 - Show available info commands",
            "  info file            - Show executable file info and sections (i f, i file)",
            "  info trace [id]      - Show trace status (i t [id])",
            "  info source          - Show all source files (i s)",
            "  info share           - Show loaded shared libraries (i sh)",
            "  info function <name> [verbose|v] - Show debug info for function (i f <name> [v])",
            "  info line <file:line> [verbose|v] - Show debug info for line (i l <file:line> [v])",
            "  info address <addr> [verbose|v]   - Show debug info for address (i a <addr> [v]) [TODO]",
        ]
        .join("\n")
    }

    /// Format source path command section
    fn format_srcpath_commands() -> String {
        [
            "🗂️  Source Path Commands:",
            "  srcpath                      - Show current path mappings and search directories",
            "  srcpath map <from> <to>      - Map DWARF compilation directory (⭐ Recommended)",
            "  srcpath add <dir>            - Add search directory (fallback, non-recursive)",
            "  srcpath remove <path>        - Remove a mapping or search directory",
            "  srcpath clear                - Clear all runtime rules",
            "  srcpath reset                - Reset to config file rules",
            "",
            "  💡 Tip: Use 'help srcpath' for detailed usage and best practices",
        ]
        .join("\n")
    }

    /// Format control command section
    fn format_control_commands() -> String {
        [
            "⚙️  Control Commands:",
            "  clear                - Clear command history",
            "  quit, exit           - Exit ghostscope",
        ]
        .join("\n")
    }

    /// Format navigation command section
    fn format_navigation_commands() -> String {
        [
            "🧭 Navigation & Input:",
            "Input Mode:",
            "  Tab                  - Command completion",
            "  Right/Ctrl+E         - Accept auto-suggestion",
            "  Ctrl+P/N             - Navigate command history",
            "  Ctrl+A/E             - Move to beginning/end of line (emacs)",
            "  Ctrl+B/F             - Move cursor left/right (emacs)",
            "  Ctrl+H               - Delete previous character (emacs)",
            "  Ctrl+W               - Delete previous word (emacs)",
            "",
            "Command Mode (vim-style):",
            "  jk/Escape            - Enter command mode",
            "  hjkl                 - Navigate (left/down/up/right)",
            "  i                    - Return to input mode",
        ]
        .join("\n")
    }

    /// Format general command section
    fn format_general_commands() -> String {
        [
            "🔧 General:",
            "  help                 - Show this help message",
            "",
            "💡 Input: Tab=completion, Right/Ctrl+E=auto-suggest, emacs keys | Command: jk/Esc enter, i exit, hjkl move",
        ]
        .join("\n")
    }

    /// Get command completion for the given input
    pub fn get_command_completion(input: &str) -> Option<String> {
        let input = input.trim();

        // Check if we're completing the verbose parameter for info commands
        // e.g., "info function main v<Tab>" -> "info function main verbose"
        if let Some(verbose_completion) = Self::complete_verbose_parameter(input) {
            return Some(verbose_completion);
        }

        // All available commands (full commands + abbreviations)
        let commands = [
            // Primary commands
            "trace",
            "enable",
            "disable",
            "delete",
            "save",
            "source",
            "info",
            "help",
            "clear",
            "quit",
            "exit",
            "srcpath",
            // Abbreviations
            "t",
            "en",
            "dis",
            "del",
            // Save subcommands
            "save traces",
            "save traces enabled",
            "save traces disabled",
            "save output",
            "save session",
            // Stop subcommands
            "stop output",
            "stop session",
            // Info subcommands
            "info file",
            "info trace",
            "info source",
            "info share",
            "info function",
            "info line",
            "info address",
            // Source path subcommands
            "srcpath",
            "srcpath add",
            "srcpath map",
            "srcpath remove",
            "srcpath clear",
            "srcpath reset",
            // Shortcut commands
            "i",
            "i file",
            "i s",
            "i sh",
            "i t",
            "i f",
            "i l",
            "i a",
            "s t", // "s" alone is ambiguous (save/source), so we only support specific "s" shortcuts
            "s o", // save output
            "s s", // save session
        ];

        // Find commands that start with the input
        let matches: Vec<&str> = commands
            .iter()
            .filter(|cmd| cmd.starts_with(input) && cmd.len() > input.len())
            .cloned()
            .collect();

        match matches.len() {
            0 => None, // No matches
            1 => {
                // Single match - return the completion part
                let full_command = matches[0];
                Some(full_command[input.len()..].to_string())
            }
            _ => {
                // Multiple matches - find common prefix
                Self::find_common_prefix(&matches, input.len())
            }
        }
    }

    /// Complete the verbose parameter for info commands
    /// Returns the completion suffix if input matches an info command pattern with partial verbose
    fn complete_verbose_parameter(input: &str) -> Option<String> {
        // Split input into words
        let parts: Vec<&str> = input.split_whitespace().collect();

        // Need at least 3 parts: command + subcommand + target [+ partial_verbose]
        if parts.len() < 3 {
            return None;
        }

        // Check if this is an info command
        let is_info_cmd = matches!(
            (parts[0], parts.get(1)),
            ("info", Some(&"function"))
                | ("info", Some(&"line"))
                | ("info", Some(&"address"))
                | ("i", Some(&"f"))
                | ("i", Some(&"l"))
                | ("i", Some(&"a"))
        );

        if !is_info_cmd {
            return None;
        }

        // Check if last part could be start of "verbose"
        let last_part = parts.last()?;

        // If it already says "verbose" or "v", no completion needed
        if *last_part == "verbose" || *last_part == "v" {
            return None;
        }

        // Check if last part is a prefix of "verbose" or is "v"
        if "verbose".starts_with(last_part) && last_part.len() < "verbose".len() {
            // Calculate how much of "verbose" remains to be completed
            let remaining = &"verbose"[last_part.len()..];
            return Some(remaining.to_string());
        }

        None
    }

    /// Find the longest common prefix among multiple command matches
    fn find_common_prefix(matches: &[&str], input_len: usize) -> Option<String> {
        if matches.is_empty() {
            return None;
        }

        let first = &matches[0][input_len..];
        let mut common_len = first.len();

        for &cmd in &matches[1..] {
            let suffix = &cmd[input_len..];
            common_len = first
                .chars()
                .zip(suffix.chars())
                .take_while(|(a, b)| a == b)
                .count()
                .min(common_len);
        }

        if common_len > 0 {
            let common_prefix = &first[..common_len];
            // Don't complete with just whitespace
            if common_prefix.trim().is_empty() {
                None
            } else {
                Some(common_prefix.to_string())
            }
        } else {
            None
        }
    }

    /// Parse synchronous commands (enable/disable/delete)
    fn parse_sync_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        // Support both full command and abbreviation for disable
        if command.starts_with("disable ") {
            let target = command.strip_prefix("disable ").unwrap().trim();
            return Some(Self::parse_disable_command(state, target));
        }
        if command.starts_with("dis ") {
            let target = command.strip_prefix("dis ").unwrap().trim();
            return Some(Self::parse_disable_command(state, target));
        }

        // Support both full command and abbreviation for enable
        if command.starts_with("enable ") {
            let target = command.strip_prefix("enable ").unwrap().trim();
            return Some(Self::parse_enable_command(state, target));
        }
        if command.starts_with("en ") {
            let target = command.strip_prefix("en ").unwrap().trim();
            return Some(Self::parse_enable_command(state, target));
        }

        // Support both full command and abbreviation for delete
        if command.starts_with("delete ") {
            let target = command.strip_prefix("delete ").unwrap().trim();
            return Some(Self::parse_delete_command(state, target));
        }
        if command.starts_with("del ") {
            let target = command.strip_prefix("del ").unwrap().trim();
            return Some(Self::parse_delete_command(state, target));
        }

        None
    }

    /// Parse disable command
    fn parse_disable_command(state: &mut CommandPanelState, target: &str) -> Vec<Action> {
        if target == "all" {
            state.input_state = InputState::WaitingResponse {
                command: format!("disable {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::DisableAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DisableAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("disable {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::Disable { trace_id },
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DisableTrace(
                trace_id,
            ))]
        } else {
            let plain = "Usage: disable <trace_id|all>".to_string();
            let styled = Self::styled_usage(&plain);
            vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]
        }
    }

    /// Parse enable command
    fn parse_enable_command(state: &mut CommandPanelState, target: &str) -> Vec<Action> {
        if target == "all" {
            state.input_state = InputState::WaitingResponse {
                command: format!("enable {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::EnableAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::EnableAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("enable {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::Enable { trace_id },
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::EnableTrace(
                trace_id,
            ))]
        } else {
            let plain = "Usage: enable <trace_id|all>".to_string();
            let styled = Self::styled_usage(&plain);
            vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]
        }
    }

    /// Parse delete command
    fn parse_delete_command(state: &mut CommandPanelState, target: &str) -> Vec<Action> {
        if target == "all" {
            state.input_state = InputState::WaitingResponse {
                command: format!("delete {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::DeleteAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DeleteAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("delete {target}"),
                sent_time: Instant::now(),
                command_type: CommandType::Delete { trace_id },
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DeleteTrace(
                trace_id,
            ))]
        } else {
            let plain = "Usage: delete <trace_id|all>".to_string();
            let styled = Self::styled_usage(&plain);
            vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]
        }
    }

    /// Parse info commands
    fn parse_info_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        if command == "info" {
            return Some(vec![Action::AddResponseWithStyle {
                content: Self::format_info_help(),
                styled_lines: Some(Self::format_info_help_styled()),
                response_type: ResponseType::Info,
            }]);
        }

        if command == "info file" {
            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoFile,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoFile)]);
        }

        if command == "info source" {
            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoSource,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoSource)]);
        }

        if command == "info share" {
            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoShare,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoShare)]);
        }

        if command == "info trace" {
            return Some(Self::parse_info_trace_command(state, None));
        }

        if command.starts_with("info trace ") {
            let id_str = command.strip_prefix("info trace ").unwrap().trim();
            if let Ok(trace_id) = id_str.parse::<u32>() {
                return Some(Self::parse_info_trace_command(state, Some(trace_id)));
            } else {
                let plain = "Usage: info trace [trace_id]".to_string();
                let styled = Self::styled_usage(&plain);
                return Some(vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle info function command
        if command.starts_with("info function ") || command.starts_with("i f ") {
            let args = if command.starts_with("info function ") {
                command.strip_prefix("info function ").unwrap()
            } else {
                command.strip_prefix("i f ").unwrap()
            };

            let parts: Vec<&str> = args.split_whitespace().collect();
            if parts.is_empty() {
                let plain = "Usage: info function <function_name> [verbose|v]".to_string();
                let styled = Self::styled_usage(&plain);
                return Some(vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Error,
                }]);
            }

            let target = parts[0].to_string();
            let verbose = parts.len() > 1 && (parts[1] == "verbose" || parts[1] == "v");

            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoFunction {
                    target: target.clone(),
                    verbose,
                },
            };
            return Some(vec![Action::SendRuntimeCommand(
                RuntimeCommand::InfoFunction { target, verbose },
            )]);
        }

        // Handle info line command
        if command.starts_with("info line ") || command.starts_with("i l ") {
            let args = if command.starts_with("info line ") {
                command.strip_prefix("info line ").unwrap()
            } else {
                command.strip_prefix("i l ").unwrap()
            };

            let parts: Vec<&str> = args.split_whitespace().collect();
            if parts.is_empty() {
                let plain = "Usage: info line <file:line> [verbose|v]".to_string();
                let styled = Self::styled_usage(&plain);
                return Some(vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Error,
                }]);
            }

            let target = parts[0].to_string();
            let verbose = parts.len() > 1 && (parts[1] == "verbose" || parts[1] == "v");

            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoLine {
                    target: target.clone(),
                    verbose,
                },
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoLine {
                target,
                verbose,
            })]);
        }

        // Handle info address command (TODO)
        if command.starts_with("info address ") || command.starts_with("i a ") {
            let plain = "TODO: info address command not implemented yet".to_string();
            let styled = vec![
                crate::components::command_panel::style_builder::StyledLineBuilder::new()
                    .styled(
                        plain.clone(),
                        crate::components::command_panel::style_builder::StylePresets::WARNING,
                    )
                    .build(),
            ];
            return Some(vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Warning,
            }]);
        }

        None
    }

    /// Parse all save commands (traces, output, session)
    fn parse_save_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        let parts: Vec<&str> = command.split_whitespace().collect();

        if parts.is_empty() || parts[0] != "save" {
            return None;
        }

        if parts.len() < 2 {
            let plain = "Usage: save <traces|output|session> [filename]".to_string();
            let styled = Self::styled_usage(&plain);
            return Some(vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]);
        }

        match parts[1] {
            "traces" => Self::parse_save_traces_command(state, command),
            "output" => Self::parse_save_output_command(state, command),
            "session" => Self::parse_save_session_command(state, command),
            _ => {
                Some(vec![{
                    let plain = format!(
                    "Unknown save target: '{}'. Use 'save traces', 'save output', or 'save session'",
                    parts[1]
                );
                    let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(plain.clone(), crate::components::command_panel::style_builder::StylePresets::ERROR)
                        .build(),
                ];
                    Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: ResponseType::Error,
                    }
                }])
            }
        }
    }

    /// Parse save traces command
    fn parse_save_traces_command(
        state: &mut CommandPanelState,
        command: &str,
    ) -> Option<Vec<Action>> {
        use crate::components::command_panel::trace_persistence::CommandParser as TraceCmdParser;

        // Use the CommandParser trait to parse the command
        if let Some((filename, filter)) = command.parse_save_traces_command() {
            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::SaveTraces,
            };

            return Some(vec![Action::SendRuntimeCommand(
                RuntimeCommand::SaveTraces { filename, filter },
            )]);
        }

        None
    }

    /// Parse save output command (handled directly in UI)
    fn parse_save_output_command(
        _state: &mut CommandPanelState,
        command: &str,
    ) -> Option<Vec<Action>> {
        let parts: Vec<&str> = command.split_whitespace().collect();

        // save output [filename]
        let filename = if parts.len() > 2 {
            Some(parts[2..].join(" "))
        } else {
            None
        };

        Some(vec![Action::SaveEbpfOutput { filename }])
    }

    /// Parse save session command (handled directly in UI)
    fn parse_save_session_command(
        _state: &mut CommandPanelState,
        command: &str,
    ) -> Option<Vec<Action>> {
        let parts: Vec<&str> = command.split_whitespace().collect();

        // save session [filename]
        let filename = if parts.len() > 2 {
            Some(parts[2..].join(" "))
        } else {
            None
        };

        Some(vec![Action::SaveCommandSession { filename }])
    }

    /// Parse stop command to stop realtime logging
    fn parse_stop_command(command: &str) -> Option<Vec<Action>> {
        let parts: Vec<&str> = command.split_whitespace().collect();

        if parts.is_empty() || parts[0] != "stop" {
            return None;
        }

        if parts.len() < 2 {
            let plain = "Usage: stop <output|session>".to_string();
            let styled = Self::styled_usage(&plain);
            return Some(vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]);
        }

        match parts[1] {
            "output" => Some(vec![Action::StopSaveOutput]),
            "session" => Some(vec![Action::StopSaveSession]),
            _ => {
                let plain = format!(
                    "Unknown stop target: '{}'. Use 'stop output' or 'stop session'",
                    parts[1]
                );
                let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(
                            plain.clone(),
                            crate::components::command_panel::style_builder::StylePresets::ERROR,
                        )
                        .build(),
                ];
                Some(vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Error,
                }])
            }
        }
    }

    /// Parse source command to load traces from file
    fn parse_source_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        use crate::components::command_panel::trace_persistence::TracePersistence;

        // Parse "source <filename>" or "s <filename>"
        let filename = if command.starts_with("source ") {
            command.strip_prefix("source ").unwrap().trim()
        } else if command.starts_with("s ")
            && !command.starts_with("s t")
            && !command.starts_with("save")
        {
            // Handle "s <filename>" but not "s t" (save traces) or "save"
            command.strip_prefix("s ").unwrap().trim()
        } else {
            return None;
        };

        if filename.is_empty() {
            let plain = "Usage: source <filename>".to_string();
            let styled = Self::styled_usage(&plain);
            return Some(vec![Action::AddResponseWithStyle {
                content: plain,
                styled_lines: Some(styled),
                response_type: ResponseType::Error,
            }]);
        }

        // Try to load and parse the file
        match TracePersistence::load_traces_from_file(filename) {
            Ok(traces) => {
                if traces.is_empty() {
                    let plain = format!("No traces found in {filename}");
                    let styled = vec![
                        crate::components::command_panel::style_builder::StyledLineBuilder::new()
                            .styled(plain.clone(), crate::components::command_panel::style_builder::StylePresets::WARNING)
                            .build(),
                    ];
                    return Some(vec![Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: ResponseType::Warning,
                    }]);
                }

                // Initialize batch loading state
                state.batch_loading = Some(crate::model::panel_state::BatchLoadingState {
                    filename: filename.to_string(),
                    total_count: traces.len(),
                    completed_count: 0,
                    success_count: 0,
                    failed_count: 0,
                    disabled_count: 0,
                    details: Vec::new(),
                });

                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::LoadTraces,
                };

                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::LoadTraces {
                        filename: filename.to_string(),
                        traces,
                    },
                )])
            }
            Err(e) => {
                Some(vec![{
                    let plain = format!("✗ Failed to load {filename}: {e}");
                    let styled = vec![
                    crate::components::command_panel::style_builder::StyledLineBuilder::new()
                        .styled(plain.clone(), crate::components::command_panel::style_builder::StylePresets::ERROR)
                        .build(),
                ];
                    Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: ResponseType::Error,
                    }
                }])
            }
        }
    }

    /// Parse srcpath command for source path configuration
    fn parse_srcpath_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        if !command.starts_with("srcpath") {
            return None;
        }

        let parts: Vec<&str> = command.split_whitespace().collect();

        if parts.len() == 1 {
            // srcpath - show current configuration
            state.input_state = InputState::WaitingResponse {
                command: command.to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::SrcPath,
            };
            return Some(vec![Action::SendRuntimeCommand(
                RuntimeCommand::SrcPathList,
            )]);
        }

        match parts.get(1) {
            Some(&"add") if parts.len() == 3 => {
                // srcpath add /path
                let dir = parts[2].to_string();
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::SrcPathAdd,
                };
                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::SrcPathAddDir { dir },
                )])
            }
            Some(&"map") if parts.len() == 4 => {
                // srcpath map /old /new
                let from = parts[2].to_string();
                let to = parts[3].to_string();
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::SrcPathMap,
                };
                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::SrcPathAddMap { from, to },
                )])
            }
            Some(&"remove") if parts.len() == 3 => {
                // srcpath remove /path
                let pattern = parts[2].to_string();
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::SrcPathRemove,
                };
                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::SrcPathRemove { pattern },
                )])
            }
            Some(&"clear") if parts.len() == 2 => {
                // srcpath clear
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::SrcPathClear,
                };
                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::SrcPathClear,
                )])
            }
            Some(&"reset") if parts.len() == 2 => {
                // srcpath reset
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::SrcPathReset,
                };
                Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::SrcPathReset,
                )])
            }
            _ => {
                Some(vec![{
                    let plain = "Usage: srcpath [add <dir> | map <from> <to> | remove <path> | clear | reset]".to_string();
                    let styled = Self::styled_usage(&plain);
                    Action::AddResponseWithStyle {
                        content: plain,
                        styled_lines: Some(styled),
                        response_type: ResponseType::Error,
                    }
                }])
            }
        }
    }

    /// Parse shortcut commands (i s, i f, i l, i t, s t, s o, s s, etc.)
    fn parse_shortcut_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        // Handle "s t" -> "save traces"
        if command == "s t" {
            return Self::parse_save_traces_command(state, "save traces");
        }

        // Handle "s t <filename>" -> "save traces <filename>"
        if command.starts_with("s t ") {
            let rest = command.strip_prefix("s t ").unwrap();
            let full_command = format!("save traces {rest}");
            return Self::parse_save_traces_command(state, &full_command);
        }

        // Handle "s o" -> "save output"
        if command == "s o" {
            return Self::parse_save_output_command(state, "save output");
        }

        // Handle "s o <filename>" -> "save output <filename>"
        if command.starts_with("s o ") {
            let rest = command.strip_prefix("s o ").unwrap();
            let full_command = format!("save output {rest}");
            return Self::parse_save_output_command(state, &full_command);
        }

        // Handle "s s" -> "save session"
        if command == "s s" {
            return Self::parse_save_session_command(state, "save session");
        }

        // Handle "s s <filename>" -> "save session <filename>"
        if command.starts_with("s s ") {
            let rest = command.strip_prefix("s s ").unwrap();
            let full_command = format!("save session {rest}");
            return Self::parse_save_session_command(state, &full_command);
        }

        // Handle "s <filename>" -> "source <filename>" (but not "s t", "s o", "s s")
        if command.starts_with("s ")
            && !command.starts_with("s t")
            && !command.starts_with("s o")
            && !command.starts_with("s s")
        {
            return Self::parse_source_command(state, command);
        }

        // Handle "i s" -> "info source"
        if command == "i s" {
            state.input_state = InputState::WaitingResponse {
                command: "info source".to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoSource,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoSource)]);
        }

        // Handle "i sh" -> "info share"
        if command == "i sh" {
            state.input_state = InputState::WaitingResponse {
                command: "info share".to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoShare,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoShare)]);
        }

        // Handle "i file" or "i f" (no args) -> "info file"
        if command == "i file" || command == "i f" {
            state.input_state = InputState::WaitingResponse {
                command: "info file".to_string(),
                sent_time: Instant::now(),
                command_type: CommandType::InfoFile,
            };
            return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoFile)]);
        }

        // Handle "i t" -> "info trace"
        if command == "i t" {
            return Some(Self::parse_info_trace_command(state, None));
        }

        // Handle "i t <id>" -> "info trace <id>"
        if command.starts_with("i t ") {
            let id_str = command.strip_prefix("i t ").unwrap().trim();
            if let Ok(trace_id) = id_str.parse::<u32>() {
                return Some(Self::parse_info_trace_command(state, Some(trace_id)));
            } else {
                let plain = "Usage: i t [trace_id]".to_string();
                let styled = Self::styled_usage(&plain);
                return Some(vec![Action::AddResponseWithStyle {
                    content: plain,
                    styled_lines: Some(styled),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        None
    }

    /// Parse info trace command
    fn parse_info_trace_command(
        state: &mut CommandPanelState,
        trace_id: Option<u32>,
    ) -> Vec<Action> {
        state.input_state = InputState::WaitingResponse {
            command: if let Some(id) = trace_id {
                format!("info trace {id}")
            } else {
                "info trace".to_string()
            },
            sent_time: Instant::now(),
            command_type: CommandType::InfoTrace { trace_id },
        };

        if trace_id.is_some() {
            vec![Action::SendRuntimeCommand(RuntimeCommand::InfoTrace {
                trace_id,
            })]
        } else {
            vec![Action::SendRuntimeCommand(RuntimeCommand::InfoTraceAll)]
        }
    }

    /// Format general info help message
    fn format_info_help() -> String {
        [
            "🔍 Info Commands Usage:",
            "",
            "  info                  - Show this help message",
            "  info file             - Show executable file info and sections (i f, i file)",
            "  info trace [id]       - Show trace status (i t [id])",
            "  info source           - Show all source files by module (i s)",
            "  info share            - Show loaded shared libraries (i sh)",
            "  info function <name>  - Show debug info for function (i f <name>)",
            "  info line <file:line> - Show debug info for source line (i l <file:line>)",
            "  info address <addr>   - Show debug info for address (i a <addr>) [TODO]",
            "",
            "💡 Shortcuts:",
            "  i f / i file          - Same as 'info file'",
            "  i s                   - Same as 'info source'",
            "  i sh                  - Same as 'info share'",
            "  i t [id]              - Same as 'info trace [id]'",
            "  i f <name>            - Same as 'info function <name>'",
            "  i l <file:line>       - Same as 'info line <file:line>'",
            "  i a <addr>            - Same as 'info address <addr>' [TODO]",
            "",
            "Examples:",
            "  info file             - Show executable file information",
            "  info trace            - Show all traces",
            "  i t 1                 - Show specific trace info",
            "  i f main              - Show debug info for 'main' function",
            "  i l file.c:42         - Show debug info for source line",
            "",
            "💡 Use 'help' for complete command reference.",
        ]
        .join("\n")
    }

    /// Check if input should show prompt
    pub fn should_show_input_prompt(state: &CommandPanelState) -> bool {
        matches!(state.input_state, InputState::Ready)
    }

    /// Get current prompt string
    pub fn get_prompt(state: &CommandPanelState) -> String {
        if !Self::should_show_input_prompt(state) {
            return String::new();
        }

        match state.mode {
            crate::model::panel_state::InteractionMode::Input => {
                UIStrings::GHOSTSCOPE_PROMPT.to_string()
            }
            crate::model::panel_state::InteractionMode::Command => {
                UIStrings::GHOSTSCOPE_PROMPT.to_string()
            }
            crate::model::panel_state::InteractionMode::ScriptEditor => {
                UIStrings::GHOSTSCOPE_PROMPT.to_string()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_completion_exact_match() {
        // Test exact single match
        assert_eq!(
            CommandParser::get_command_completion("tr"),
            Some("ace".to_string())
        );
        assert_eq!(
            CommandParser::get_command_completion("hel"),
            Some("p".to_string())
        );
        assert_eq!(
            CommandParser::get_command_completion("clea"),
            Some("r".to_string())
        );
    }

    #[test]
    fn test_command_completion_multiple_matches() {
        // Test multiple matches - should return None when no common prefix exists
        assert_eq!(CommandParser::get_command_completion("d"), None); // "delete", "disable", "dis", "del" have no common prefix
        assert_eq!(CommandParser::get_command_completion("e"), None); // "enable", "exit" have no common prefix beyond "e"

        // Test with actual matches
        assert_eq!(
            CommandParser::get_command_completion("de"),
            Some("l".to_string())
        ); // "del" and "delete" -> common prefix "del"
        assert_eq!(CommandParser::get_command_completion("info "), None); // Multiple info subcommands, whitespace prefix filtered out
    }

    #[test]
    fn test_command_completion_no_match() {
        // Test no matches
        assert_eq!(CommandParser::get_command_completion("xyz"), None);
        assert_eq!(CommandParser::get_command_completion("unknown"), None);
    }

    #[test]
    fn test_command_completion_exact_command() {
        // Test already complete commands
        assert_eq!(CommandParser::get_command_completion("trace"), None);
        assert_eq!(CommandParser::get_command_completion("help"), None);
    }

    #[test]
    fn test_command_completion_abbreviations() {
        // Test abbreviations work
        assert_eq!(
            CommandParser::get_command_completion("en"),
            Some("able".to_string())
        ); // "en" -> "enable"
        assert_eq!(
            CommandParser::get_command_completion("di"),
            Some("s".to_string())
        ); // "di" -> "dis" (common prefix of "disable")
    }
}

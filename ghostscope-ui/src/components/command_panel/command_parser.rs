use crate::action::{Action, ResponseType, RuntimeCommand};
use crate::model::panel_state::{CommandPanelState, CommandType, InputState};
use crate::ui::strings::UIStrings;
use std::time::Instant;

/// Handles command parsing and built-in command execution
pub struct CommandParser;

impl CommandParser {
    /// Parse and handle a command, returning appropriate actions
    pub fn parse_command(state: &mut CommandPanelState, command: &str) -> Vec<Action> {
        let cmd = command.trim();

        // Handle built-in commands first
        if let Some(response) = Self::handle_builtin_command(cmd) {
            return vec![Action::AddResponse {
                content: response,
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

        // Handle quit/exit commands
        if cmd == "quit" || cmd == "exit" {
            return vec![Action::Quit];
        }

        // Handle clear command
        if cmd == "clear" {
            // Clear command history
            state.command_history.clear();
            return vec![Action::AddResponse {
                content: "Command history cleared.".to_string(),
                response_type: ResponseType::Info,
            }];
        }

        // Unknown command
        vec![Action::AddResponse {
            content: format!("{} {}", UIStrings::ERROR_PREFIX, UIStrings::UNKNOWN_COMMAND),
            response_type: ResponseType::Error,
        }]
    }

    /// Handle built-in commands that don't require runtime communication
    fn handle_builtin_command(command: &str) -> Option<String> {
        match command {
            "help" => Some(Self::format_help_message()),
            _ => None,
        }
    }

    /// Format comprehensive help message
    fn format_help_message() -> String {
        format!(
            "📘 Ghostscope Commands:\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}",
            Self::format_tracing_commands(),
            Self::format_info_commands(),
            Self::format_control_commands(),
            Self::format_navigation_commands(),
            Self::format_general_commands()
        )
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
            "  info trace [id]      - Show trace status (i t [id])",
            "  info source          - Show all source files (i s)",
            "  info share           - Show loaded shared libraries (i sh)",
            "  info function <name> - Show debug info for function (i f <name>)",
            "  info line <file:line>- Show debug info for source line (i l <file:line>)",
            "  info address <addr>  - Show debug info for address (i a <addr>) [TODO]",
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
            "info trace",
            "info source",
            "info share",
            "info function",
            "info line",
            "info address",
            // Shortcut commands
            "i",
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
            vec![Action::AddResponse {
                content: "Usage: disable <trace_id|all>".to_string(),
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
            vec![Action::AddResponse {
                content: "Usage: enable <trace_id|all>".to_string(),
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
            vec![Action::AddResponse {
                content: "Usage: delete <trace_id|all>".to_string(),
                response_type: ResponseType::Error,
            }]
        }
    }

    /// Parse info commands
    fn parse_info_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        if command == "info" {
            return Some(vec![Action::AddResponse {
                content: Self::format_info_help(),
                response_type: ResponseType::Info,
            }]);
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
                return Some(vec![Action::AddResponse {
                    content: "Usage: info trace [trace_id]".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle info function command
        if command.starts_with("info function ") {
            let target = command
                .strip_prefix("info function ")
                .unwrap()
                .trim()
                .to_string();
            if !target.is_empty() {
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::InfoFunction {
                        target: target.clone(),
                    },
                };
                return Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::InfoFunction { target },
                )]);
            } else {
                return Some(vec![Action::AddResponse {
                    content: "Usage: info function <function_name>".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle info line command
        if command.starts_with("info line ") {
            let target = command
                .strip_prefix("info line ")
                .unwrap()
                .trim()
                .to_string();
            if !target.is_empty() {
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::InfoLine {
                        target: target.clone(),
                    },
                };
                return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoLine {
                    target,
                })]);
            } else {
                return Some(vec![Action::AddResponse {
                    content: "Usage: info line <file:line>".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle info address command (TODO)
        if command.starts_with("info address ") {
            return Some(vec![Action::AddResponse {
                content: "TODO: info address command not implemented yet".to_string(),
                response_type: ResponseType::Error,
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
            return Some(vec![Action::AddResponse {
                content: "Usage: save <traces|output|session> [filename]".to_string(),
                response_type: ResponseType::Error,
            }]);
        }

        match parts[1] {
            "traces" => Self::parse_save_traces_command(state, command),
            "output" => Self::parse_save_output_command(state, command),
            "session" => Self::parse_save_session_command(state, command),
            _ => Some(vec![Action::AddResponse {
                content: format!(
                    "Unknown save target: '{}'. Use 'save traces', 'save output', or 'save session'",
                    parts[1]
                ),
                response_type: ResponseType::Error,
            }]),
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
            return Some(vec![Action::AddResponse {
                content: "Usage: stop <output|session>".to_string(),
                response_type: ResponseType::Error,
            }]);
        }

        match parts[1] {
            "output" => Some(vec![Action::StopSaveOutput]),
            "session" => Some(vec![Action::StopSaveSession]),
            _ => Some(vec![Action::AddResponse {
                content: format!(
                    "Unknown stop target: '{}'. Use 'stop output' or 'stop session'",
                    parts[1]
                ),
                response_type: ResponseType::Error,
            }]),
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
            return Some(vec![Action::AddResponse {
                content: "Usage: source <filename>".to_string(),
                response_type: ResponseType::Error,
            }]);
        }

        // Try to load and parse the file
        match TracePersistence::load_traces_from_file(filename) {
            Ok(traces) => {
                if traces.is_empty() {
                    return Some(vec![Action::AddResponse {
                        content: format!("No traces found in {filename}"),
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
            Err(e) => Some(vec![Action::AddResponse {
                content: format!("Failed to load {filename}: {e}"),
                response_type: ResponseType::Error,
            }]),
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
                return Some(vec![Action::AddResponse {
                    content: "Usage: i t [trace_id]".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle "i f <name>" -> "info function <name>"
        if command.starts_with("i f ") {
            let target = command.strip_prefix("i f ").unwrap().trim().to_string();
            if !target.is_empty() {
                state.input_state = InputState::WaitingResponse {
                    command: format!("info function {target}"),
                    sent_time: Instant::now(),
                    command_type: CommandType::InfoFunction {
                        target: target.clone(),
                    },
                };
                return Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::InfoFunction { target },
                )]);
            } else {
                return Some(vec![Action::AddResponse {
                    content: "Usage: i f <function_name>".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle "i l <target>" -> "info line <target>"
        if command.starts_with("i l ") {
            let target = command.strip_prefix("i l ").unwrap().trim().to_string();
            if !target.is_empty() {
                state.input_state = InputState::WaitingResponse {
                    command: format!("info line {target}"),
                    sent_time: Instant::now(),
                    command_type: CommandType::InfoLine {
                        target: target.clone(),
                    },
                };
                return Some(vec![Action::SendRuntimeCommand(RuntimeCommand::InfoLine {
                    target,
                })]);
            } else {
                return Some(vec![Action::AddResponse {
                    content: "Usage: i l <file:line>".to_string(),
                    response_type: ResponseType::Error,
                }]);
            }
        }

        // Handle "i a <target>" -> "info address <target>" (TODO)
        if command.starts_with("i a ") {
            return Some(vec![Action::AddResponse {
                content: "TODO: i a (info address) command not implemented yet".to_string(),
                response_type: ResponseType::Error,
            }]);
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
            "  info trace [id]       - Show trace status (i t [id])",
            "  info source           - Show all source files by module (i s)",
            "  info share            - Show loaded shared libraries (i sh)",
            "  info function <name>  - Show debug info for function (i f <name>)",
            "  info line <file:line> - Show debug info for source line (i l <file:line>)",
            "  info address <addr>   - Show debug info for address (i a <addr>) [TODO]",
            "",
            "💡 Shortcuts:",
            "  i s                   - Same as 'info source'",
            "  i sh                  - Same as 'info share'",
            "  i t [id]              - Same as 'info trace [id]'",
            "  i f <name>            - Same as 'info function <name>'",
            "  i l <file:line>       - Same as 'info line <file:line>'",
            "  i a <addr>            - Same as 'info address <addr>' [TODO]",
            "",
            "Examples:",
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

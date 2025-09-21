use crate::action::{Action, ResponseType, RuntimeCommand};
use crate::model::panel_state::{CommandPanelState, CommandType, InputState};
use crate::ui::strings::UIStrings;
use crate::ui::symbols::UISymbols;
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

        // Handle trace command
        if cmd.starts_with("trace ") {
            return vec![Action::EnterScriptMode(cmd.to_string())];
        }

        // Handle info commands
        if let Some(actions) = Self::parse_info_command(state, cmd) {
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
            "  trace <target>       - Start tracing a function/location",
            "  enable <id|all>      - Enable specific trace or all traces",
            "  disable <id|all>     - Disable specific trace or all traces",
            "  delete <id|all>      - Delete specific trace or all traces",
        ]
        .join("\n")
    }

    /// Format info command section
    fn format_info_commands() -> String {
        [
            "🔍 Information Commands:",
            "  info                 - Show available info commands",
            "  info trace [id]      - Show trace status (specific or all)",
            "  info source          - Show all source files",
            "  info share           - Show loaded shared libraries",
            "  info <target>        - Show debug info for function/file:line",
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
            "🧭 Navigation:",
            "  jk                   - Switch to command mode (vim-like)",
            "  Ctrl+P/N             - Navigate command history",
            "  Ctrl+A/E             - Move to beginning/end of line (emacs)",
            "  Ctrl+B/F             - Move cursor left/right (emacs)",
            "  Ctrl+H               - Delete previous character (emacs)",
            "  Ctrl+W               - Delete previous word (emacs)",
            "  Escape               - Return to input mode",
        ]
        .join("\n")
    }

    /// Format general command section
    fn format_general_commands() -> String {
        [
            "🔧 General:",
            "  help                 - Show this help message",
            "",
            "💡 Tip: Use tab completion and 'jk' for vim-like navigation.",
        ]
        .join("\n")
    }

    /// Parse synchronous commands (enable/disable/delete)
    fn parse_sync_command(state: &mut CommandPanelState, command: &str) -> Option<Vec<Action>> {
        if command.starts_with("disable ") {
            let target = command.strip_prefix("disable ").unwrap().trim();
            return Some(Self::parse_disable_command(state, target));
        }

        if command.starts_with("enable ") {
            let target = command.strip_prefix("enable ").unwrap().trim();
            return Some(Self::parse_enable_command(state, target));
        }

        if command.starts_with("delete ") {
            let target = command.strip_prefix("delete ").unwrap().trim();
            return Some(Self::parse_delete_command(state, target));
        }

        None
    }

    /// Parse disable command
    fn parse_disable_command(state: &mut CommandPanelState, target: &str) -> Vec<Action> {
        if target == "all" {
            state.input_state = InputState::WaitingResponse {
                command: format!("disable {}", target),
                sent_time: Instant::now(),
                command_type: CommandType::DisableAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DisableAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("disable {}", target),
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
                command: format!("enable {}", target),
                sent_time: Instant::now(),
                command_type: CommandType::EnableAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::EnableAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("enable {}", target),
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
                command: format!("delete {}", target),
                sent_time: Instant::now(),
                command_type: CommandType::DeleteAll,
            };
            vec![Action::SendRuntimeCommand(RuntimeCommand::DeleteAllTraces)]
        } else if let Ok(trace_id) = target.parse::<u32>() {
            state.input_state = InputState::WaitingResponse {
                command: format!("delete {}", target),
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

        if command.starts_with("info ")
            && !command.starts_with("info trace")
            && !command.starts_with("info source")
            && !command.starts_with("info share")
        {
            let target = command.strip_prefix("info ").unwrap().trim().to_string();
            if !target.is_empty() {
                state.input_state = InputState::WaitingResponse {
                    command: command.to_string(),
                    sent_time: Instant::now(),
                    command_type: CommandType::Info {
                        target: target.clone(),
                    },
                };
                return Some(vec![Action::SendRuntimeCommand(
                    RuntimeCommand::InfoTarget { target },
                )]);
            } else {
                return Some(vec![Action::AddResponse {
                    content: "Usage: info <target>".to_string(),
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
                format!("info trace {}", id)
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
            "  info                 - Show this help message",
            "  info trace [id]      - Show trace status (specific or all)",
            "  info source          - Show all source files by module",
            "  info share           - Show loaded shared libraries",
            "  info <target>        - Show debug info for function/file:line",
            "",
            "Examples:",
            "  info trace           - Show all traces",
            "  info trace 1         - Show specific trace info",
            "  info main            - Show debug info for 'main' function",
            "  info file.c:42       - Show debug info for source line",
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

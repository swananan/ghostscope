use ghostscope_ui::action::{Action, ResponseType};
use ghostscope_ui::components::command_panel::CommandParser;
use ghostscope_ui::model::panel_state::CommandPanelState;

#[cfg(test)]
mod save_command_tests {
    use super::*;

    /// Test that save output command returns proper action
    #[test]
    fn test_save_output_command_parsing() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "save output test.log");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveEbpfOutput {
                filename: Some(ref f)
            } if f == "test.log"
        ));
    }

    /// Test save output without filename
    #[test]
    fn test_save_output_no_filename() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "save output");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveEbpfOutput { filename: None }
        ));
    }

    /// Test save session command parsing
    #[test]
    fn test_save_session_command_parsing() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "save session debug.log");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveCommandSession {
                filename: Some(ref f)
            } if f == "debug.log"
        ));
    }

    /// Test save session without filename
    #[test]
    fn test_save_session_no_filename() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "save session");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveCommandSession { filename: None }
        ));
    }

    /// Test stop output command
    #[test]
    fn test_stop_output_command() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "stop output");

        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::StopSaveOutput));
    }

    /// Test stop session command
    #[test]
    fn test_stop_session_command() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "stop session");

        assert_eq!(actions.len(), 1);
        assert!(matches!(actions[0], Action::StopSaveSession));
    }

    /// Test save command shorthand: s o
    #[test]
    fn test_save_output_shorthand() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "s o test.log");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveEbpfOutput {
                filename: Some(ref f)
            } if f == "test.log"
        ));
    }

    /// Test save session shorthand: s s
    #[test]
    fn test_save_session_shorthand() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "s s debug.log");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveCommandSession {
                filename: Some(ref f)
            } if f == "debug.log"
        ));
    }

    /// Test invalid stop command
    #[test]
    fn test_stop_invalid_target() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "stop invalid");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::AddResponseWithStyle {
                response_type: ResponseType::Error,
                ..
            }
        ));
    }

    /// Test stop command without target
    #[test]
    fn test_stop_no_target() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "stop");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::AddResponseWithStyle {
                response_type: ResponseType::Error,
                ..
            }
        ));
    }

    /// Test save with multi-word filename
    #[test]
    fn test_save_output_multi_word_filename() {
        let mut state = CommandPanelState::new();
        let actions = CommandParser::parse_command(&mut state, "save output my debug log.txt");

        assert_eq!(actions.len(), 1);
        assert!(matches!(
            actions[0],
            Action::SaveEbpfOutput {
                filename: Some(ref f)
            } if f == "my debug log.txt"
        ));
    }
}

#[cfg(test)]
mod command_response_tests {
    use super::*;
    use ghostscope_ui::components::command_panel::OptimizedInputHandler;
    use ghostscope_ui::model::panel_state::InteractionMode;

    /// Test that command submission creates history item that can receive response
    #[test]
    fn test_command_creates_history_entry() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "save output test.log".to_string(),
            ..Default::default()
        };

        let mut handler = OptimizedInputHandler::new();
        let _actions = handler.handle_submit(&mut state);

        // Verify command was added to history
        assert_eq!(state.command_history.len(), 1);
        assert_eq!(state.command_history[0].command, "save output test.log");
        assert!(state.command_history[0].response.is_none());
    }

    /// Test that response can be added to last command
    #[test]
    fn test_response_added_to_command() {
        use ghostscope_ui::components::command_panel::ResponseFormatter;

        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "save output test.log".to_string(),
            ..Default::default()
        };

        let mut handler = OptimizedInputHandler::new();
        let _actions = handler.handle_submit(&mut state);

        // Add response
        ResponseFormatter::add_response_with_style(
            &mut state,
            "✓ Realtime eBPF output logging started: /tmp/test.log".to_string(),
            None,
            ResponseType::Success,
        );

        // Verify response was added
        assert_eq!(state.command_history.len(), 1);
        assert!(state.command_history[0].response.is_some());
        assert_eq!(
            state.command_history[0].response.as_ref().unwrap(),
            "✓ Realtime eBPF output logging started: /tmp/test.log"
        );
        assert_eq!(
            state.command_history[0].response_type,
            Some(ResponseType::Success)
        );
    }

    /// Test multiple commands each get their own response
    #[test]
    fn test_multiple_commands_with_responses() {
        use ghostscope_ui::components::command_panel::ResponseFormatter;

        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            ..Default::default()
        };

        let mut handler = OptimizedInputHandler::new();

        // First command
        state.input_text = "save output test1.log".to_string();
        let _actions = handler.handle_submit(&mut state);
        ResponseFormatter::add_response_with_style(
            &mut state,
            "✓ Started logging to test1.log".to_string(),
            None,
            ResponseType::Success,
        );

        // Second command
        state.input_text = "save session test2.log".to_string();
        let _actions = handler.handle_submit(&mut state);
        ResponseFormatter::add_response_with_style(
            &mut state,
            "✓ Started logging to test2.log".to_string(),
            None,
            ResponseType::Success,
        );

        // Verify both commands have responses
        assert_eq!(state.command_history.len(), 2);

        assert_eq!(state.command_history[0].command, "save output test1.log");
        assert_eq!(
            state.command_history[0].response.as_ref().unwrap(),
            "✓ Started logging to test1.log"
        );

        assert_eq!(state.command_history[1].command, "save session test2.log");
        assert_eq!(
            state.command_history[1].response.as_ref().unwrap(),
            "✓ Started logging to test2.log"
        );
    }

    /// Test error response handling
    #[test]
    fn test_error_response() {
        use ghostscope_ui::components::command_panel::ResponseFormatter;

        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "save output /invalid/path/test.log".to_string(),
            ..Default::default()
        };

        let mut handler = OptimizedInputHandler::new();
        let _actions = handler.handle_submit(&mut state);

        // Add error response
        ResponseFormatter::add_response_with_style(
            &mut state,
            "✗ Failed to start output logging: Directory does not exist".to_string(),
            None,
            ResponseType::Error,
        );

        // Verify error response was added
        assert_eq!(state.command_history.len(), 1);
        assert!(state.command_history[0].response.is_some());
        assert!(state.command_history[0]
            .response
            .as_ref()
            .unwrap()
            .contains("Failed"));
        assert_eq!(
            state.command_history[0].response_type,
            Some(ResponseType::Error)
        );
    }
}

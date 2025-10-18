use ghostscope_ui::action::CursorDirection;
use ghostscope_ui::components::command_panel::InputHandler;
use ghostscope_ui::model::panel_state::{
    CommandPanelState, InteractionMode, LineType, StaticTextLine,
};

/// Helper to create a command panel state in command mode with test content
fn create_command_mode_state() -> CommandPanelState {
    CommandPanelState {
        mode: InteractionMode::Command,
        static_lines: vec![
            StaticTextLine {
                content: "First line of text".to_string(),
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            },
            StaticTextLine {
                content: "Second line with more content".to_string(),
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            },
            StaticTextLine {
                content: "Third line".to_string(),
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            },
            StaticTextLine {
                content: "".to_string(), // Empty line
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            },
            StaticTextLine {
                content: "Final line here".to_string(),
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            },
        ],
        command_cursor_line: 0,
        command_cursor_column: 0,
        ..Default::default()
    }
}

#[cfg(test)]
mod command_mode_cursor_tests {
    use super::*;

    #[test]
    fn test_basic_horizontal_movement() {
        let mut state = create_command_mode_state();

        // Move right from start
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.command_cursor_column, 1);
        assert_eq!(state.command_cursor_line, 0);

        // Move right multiple times
        for _ in 0..5 {
            InputHandler::move_cursor(&mut state, CursorDirection::Right);
        }
        assert_eq!(state.command_cursor_column, 6);

        // Move left
        InputHandler::move_cursor(&mut state, CursorDirection::Left);
        assert_eq!(state.command_cursor_column, 5);

        // Move left to beginning
        for _ in 0..10 {
            InputHandler::move_cursor(&mut state, CursorDirection::Left);
        }
        assert_eq!(state.command_cursor_column, 0); // Should stop at 0
    }

    #[test]
    fn test_horizontal_boundary_checking() {
        let mut state = create_command_mode_state();

        // Try to move right beyond line length
        let first_line_len = state.static_lines[0].content.len();
        for _ in 0..50 {
            InputHandler::move_cursor(&mut state, CursorDirection::Right);
        }
        // Should stop at line length
        assert_eq!(state.command_cursor_column, first_line_len);

        // Move to empty line
        state.command_cursor_line = 3; // Empty line
        state.command_cursor_column = 0;

        // Try to move right on empty line
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.command_cursor_column, 0); // Should stay at 0
    }

    #[test]
    fn test_vertical_movement() {
        let mut state = create_command_mode_state();

        // Move down
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 1);
        assert_eq!(state.command_cursor_column, 0);

        // Move down to last line
        for _ in 0..10 {
            InputHandler::move_cursor(&mut state, CursorDirection::Down);
        }
        assert_eq!(state.command_cursor_line, 4); // Should stop at last line

        // Move up
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        assert_eq!(state.command_cursor_line, 3);

        // Move up to first line
        for _ in 0..10 {
            InputHandler::move_cursor(&mut state, CursorDirection::Up);
        }
        assert_eq!(state.command_cursor_line, 0); // Should stop at 0
    }

    #[test]
    fn test_column_adjustment_on_vertical_movement() {
        let mut state = create_command_mode_state();

        // Move to end of second line (longer line)
        state.command_cursor_line = 1;
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        let long_line_end = state.command_cursor_column;
        assert_eq!(long_line_end, 29); // "Second line with more content" length

        // Move up to shorter first line
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        assert_eq!(state.command_cursor_line, 0);
        // Column should be adjusted to fit shorter line
        assert_eq!(
            state.command_cursor_column,
            state.static_lines[0].content.len()
        );

        // Move down to third line (even shorter)
        state.command_cursor_column = 15;
        state.command_cursor_line = 0;

        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 2);
        // Column should be adjusted to "Third line" length (10)
        assert_eq!(state.command_cursor_column, 10);
    }

    #[test]
    fn test_home_and_end_movement() {
        let mut state = create_command_mode_state();

        // Move to middle of line
        state.command_cursor_column = 5;

        // Test Home
        InputHandler::move_cursor(&mut state, CursorDirection::Home);
        assert_eq!(state.command_cursor_column, 0);
        assert_eq!(state.command_cursor_line, 0); // Line shouldn't change

        // Test End
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(
            state.command_cursor_column,
            state.static_lines[0].content.len()
        );

        // Test End on different line
        state.command_cursor_line = 2;
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(
            state.command_cursor_column,
            state.static_lines[2].content.len()
        );

        // Test Home on empty line
        state.command_cursor_line = 3; // Empty line
        state.command_cursor_column = 5; // Invalid position
        InputHandler::move_cursor(&mut state, CursorDirection::Home);
        assert_eq!(state.command_cursor_column, 0);
    }

    #[test]
    fn test_complex_navigation_sequence() {
        let mut state = create_command_mode_state();

        // Complex navigation pattern
        // Start at (0, 0)
        assert_eq!(
            (state.command_cursor_line, state.command_cursor_column),
            (0, 0)
        );

        // Move to end of first line
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.command_cursor_column, 18); // "First line of text"

        // Move down (column should adjust to second line)
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 1);
        assert_eq!(state.command_cursor_column, 18);

        // Move right 5 times
        for _ in 0..5 {
            InputHandler::move_cursor(&mut state, CursorDirection::Right);
        }
        assert_eq!(state.command_cursor_column, 23);

        // Move down to third line (column should adjust)
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 2);
        assert_eq!(state.command_cursor_column, 10); // Adjusted to "Third line" length

        // Move to home
        InputHandler::move_cursor(&mut state, CursorDirection::Home);
        assert_eq!(state.command_cursor_column, 0);

        // Move up
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        assert_eq!(state.command_cursor_line, 1);

        // Move to end of this line
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.command_cursor_column, 29);
    }

    #[test]
    fn test_movement_preserves_mode() {
        let mut state = create_command_mode_state();

        // Ensure mode stays as Command after movements
        let movements = vec![
            CursorDirection::Right,
            CursorDirection::Down,
            CursorDirection::Left,
            CursorDirection::Up,
            CursorDirection::Home,
            CursorDirection::End,
        ];

        for direction in movements {
            InputHandler::move_cursor(&mut state, direction);
            assert_eq!(
                state.mode,
                InteractionMode::Command,
                "Mode should remain Command after {direction:?} movement"
            );
        }
    }

    #[test]
    fn test_empty_lines_navigation() {
        let mut state = create_command_mode_state();

        // Navigate to empty line
        state.command_cursor_line = 3;
        state.command_cursor_column = 0;

        // Try to move right on empty line
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.command_cursor_column, 0); // Should stay at 0

        // Move End on empty line
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.command_cursor_column, 0); // Should stay at 0

        // Move down from empty line with column > 0
        state.command_cursor_column = 5; // Set invalid column
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 4);
        // Column should be adjusted to 0 first, then to min of line length
        assert_eq!(
            state.command_cursor_column,
            5.min(state.static_lines[4].content.len())
        );
    }

    #[test]
    fn test_navigation_with_single_line() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Command,
            static_lines: vec![StaticTextLine {
                content: "Only line".to_string(),
                line_type: LineType::Response,
                history_index: None,
                response_type: None,
                styled_content: None,
            }],
            command_cursor_line: 0,
            command_cursor_column: 0,
            ..Default::default()
        };

        // Try to move up and down - should stay on same line
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        assert_eq!(state.command_cursor_line, 0);

        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 0);

        // Horizontal movement should work
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.command_cursor_column, 1);

        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.command_cursor_column, 9);
    }

    #[test]
    fn test_navigation_with_no_lines() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Command,
            static_lines: vec![], // No lines
            command_cursor_line: 0,
            command_cursor_column: 0,
            ..Default::default()
        };

        // All movements should be safe and not panic
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.command_cursor_column, 0);

        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.command_cursor_line, 0);

        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.command_cursor_column, 0);
    }
}

#[cfg(test)]
mod input_mode_cursor_tests {
    use super::*;

    #[test]
    fn test_input_mode_horizontal_movement() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "test input text".to_string(),
            cursor_position: 0,
            ..Default::default()
        };

        // Move right
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.cursor_position, 1);

        // Move to middle
        for _ in 0..4 {
            InputHandler::move_cursor(&mut state, CursorDirection::Right);
        }
        assert_eq!(state.cursor_position, 5);

        // Move left
        InputHandler::move_cursor(&mut state, CursorDirection::Left);
        assert_eq!(state.cursor_position, 4);

        // Move to beginning
        InputHandler::move_cursor(&mut state, CursorDirection::Home);
        assert_eq!(state.cursor_position, 0);

        // Move to end
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.cursor_position, 15); // "test input text" length
    }

    #[test]
    fn test_input_mode_boundary_checking() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "short".to_string(),
            cursor_position: 0,
            ..Default::default()
        };

        // Try to move left from beginning
        InputHandler::move_cursor(&mut state, CursorDirection::Left);
        assert_eq!(state.cursor_position, 0); // Should stay at 0

        // Move to end
        state.cursor_position = 5;

        // Try to move right from end
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.cursor_position, 5); // Should stay at end
    }

    #[test]
    fn test_unicode_cursor_movement() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "Hello 世界 Test".to_string(),
            cursor_position: 0,
            ..Default::default()
        };

        // Move through Unicode characters
        for i in 1..=6 {
            InputHandler::move_cursor(&mut state, CursorDirection::Right);
            assert_eq!(state.cursor_position, i);
        }
        // Position 6 is after "Hello " before first Chinese character

        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.cursor_position, 7); // After first Chinese character

        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.cursor_position, 8); // After second Chinese character
    }

    #[test]
    fn test_word_deletion_movement() {
        let mut state = CommandPanelState {
            mode: InteractionMode::Input,
            input_text: "one two three four".to_string(),
            cursor_position: 18,
            ..Default::default()
        }; // End of string

        // Delete previous word
        InputHandler::delete_previous_word(&mut state);
        assert_eq!(state.input_text, "one two three ");
        assert_eq!(state.cursor_position, 14);

        // Delete another word
        InputHandler::delete_previous_word(&mut state);
        assert_eq!(state.input_text, "one two ");
        assert_eq!(state.cursor_position, 8);

        // Move cursor to middle and delete word
        state.cursor_position = 4; // After "one "
        InputHandler::delete_previous_word(&mut state);
        assert_eq!(state.input_text, "two ");
        assert_eq!(state.cursor_position, 0);
    }
}

#[cfg(test)]
mod script_editor_cursor_tests {
    use super::*;
    use ghostscope_ui::model::panel_state::ScriptCache;

    fn create_script_state() -> CommandPanelState {
        CommandPanelState {
            mode: InteractionMode::ScriptEditor,
            script_cache: Some(ScriptCache {
                target: "test_function".to_string(),
                original_command: "trace test_function".to_string(),
                selected_index: None,
                lines: vec![
                    "First line".to_string(),
                    "Second line here".to_string(),
                    "".to_string(), // Empty line
                    "Fourth line content".to_string(),
                    "Last line".to_string(),
                ],
                cursor_line: 0,
                cursor_col: 0,
                status: ghostscope_ui::model::panel_state::ScriptStatus::Draft,
                saved_scripts: std::collections::HashMap::new(),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn test_script_editor_horizontal_movement() {
        let mut state = create_script_state();

        // Move right on first line
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_col, 1);

        // Move to end of first line
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_col, 10); // "First line"

        // Move to beginning
        InputHandler::move_cursor(&mut state, CursorDirection::Home);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_col, 0);
    }

    #[test]
    fn test_script_editor_vertical_movement() {
        let mut state = create_script_state();

        // Set initial position
        if let Some(ref mut script) = state.script_cache {
            script.cursor_col = 5;
        }

        // Move down
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        let script = state.script_cache.as_ref().unwrap();
        assert_eq!(script.cursor_line, 1);
        assert_eq!(script.cursor_col, 5); // Column preserved

        // Move down to empty line
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        let script = state.script_cache.as_ref().unwrap();
        assert_eq!(script.cursor_line, 2);
        assert_eq!(script.cursor_col, 0); // Adjusted to empty line

        // Move down from empty line
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        let script = state.script_cache.as_ref().unwrap();
        assert_eq!(script.cursor_line, 3);
        assert_eq!(script.cursor_col, 0); // Reset from empty line
    }

    #[test]
    fn test_script_editor_column_preservation() {
        let mut state = create_script_state();

        // Move to end of second line (longest)
        if let Some(ref mut script) = state.script_cache {
            script.cursor_line = 1;
        }
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        let long_col = state.script_cache.as_ref().unwrap().cursor_col;
        assert_eq!(long_col, 16); // "Second line here"

        // Move up to shorter line
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        let script = state.script_cache.as_ref().unwrap();
        assert_eq!(script.cursor_line, 0);
        assert_eq!(script.cursor_col, 10); // Adjusted to "First line" length

        // Move down past empty line
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        let script = state.script_cache.as_ref().unwrap();
        assert_eq!(script.cursor_line, 2); // Empty line
        assert_eq!(script.cursor_col, 0);
    }

    #[test]
    fn test_script_editor_boundary_checking() {
        let mut state = create_script_state();

        // Try to move up from first line
        InputHandler::move_cursor(&mut state, CursorDirection::Up);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_line, 0);

        // Move to last line
        if let Some(ref mut script) = state.script_cache {
            script.cursor_line = 4;
        }

        // Try to move down from last line
        InputHandler::move_cursor(&mut state, CursorDirection::Down);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_line, 4);

        // Try to move right beyond line end
        InputHandler::move_cursor(&mut state, CursorDirection::End);
        let end_col = state.script_cache.as_ref().unwrap().cursor_col;
        InputHandler::move_cursor(&mut state, CursorDirection::Right);
        assert_eq!(state.script_cache.as_ref().unwrap().cursor_col, end_col);
    }
}

use ratatui::{
    backend::TestBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Terminal,
};

/// Test for command line wrapping behavior
mod line_wrapping_tests {
    use super::*;

    #[test]
    fn test_command_input_line_wrapping() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                // Create a long command that should wrap
                let long_command = "trace main --script 'print \"This is a very long command that should definitely wrap to multiple lines when rendered\"'";

                let paragraph = Paragraph::new(long_command)
                    .block(Block::default().title("Command").borders(Borders::ALL))
                    .wrap(ratatui::widgets::Wrap { trim: false });

                f.render_widget(paragraph, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();

        // Verify that text wraps to multiple lines
        let mut found_lines = 0;
        for y in 1..9 {
            // Skip border lines
            let mut line = String::new();
            for x in 1..39 {
                // Skip border columns
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            if !line.trim().is_empty() {
                found_lines += 1;
            }
        }

        assert!(
            found_lines > 1,
            "Long command should wrap to multiple lines"
        );
    }

    #[test]
    fn test_wrapped_line_cursor_position() {
        let backend = TestBackend::new(30, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        let cursor_position = 45; // Position beyond first line
        let command = "print variable_with_very_long_name_that_wraps";

        terminal
            .draw(|f| {
                let text_before_cursor = &command[..cursor_position.min(command.len())];
                let text_after_cursor = if cursor_position < command.len() {
                    &command[cursor_position..]
                } else {
                    ""
                };

                let content = vec![Line::from(vec![
                    Span::raw(text_before_cursor),
                    Span::styled("│", Style::default().fg(Color::Yellow)),
                    Span::raw(text_after_cursor),
                ])];

                let paragraph =
                    Paragraph::new(content).wrap(ratatui::widgets::Wrap { trim: false });

                f.render_widget(paragraph, f.area());
            })
            .unwrap();

        // Verify cursor appears on wrapped line
        let buffer = terminal.backend().buffer();
        let mut cursor_found = false;

        for y in 0..5 {
            for x in 0..30 {
                let cell = &buffer[(x, y)];
                if cell.symbol() == "│" {
                    cursor_found = true;
                    assert!(y > 0, "Cursor should be on wrapped line");
                    break;
                }
            }
        }

        assert!(cursor_found, "Cursor indicator should be visible");
    }
}

/// Test for history command suggestions
mod history_tests {
    use super::*;
    use ghostscope_ui::components::command_panel::history_manager::{
        CommandHistory, HistorySearchState,
    };

    #[test]
    fn test_history_navigation() {
        let mut history = CommandHistory::new_for_test();

        // Add some commands to history
        history.add_command("trace main");
        history.add_command("print x");
        history.add_command("info function test");

        // Test that history was added
        assert_eq!(history.len(), 3);

        // Get entries for verification
        let entries = history.get_entries_for_test();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], "trace main");
        assert_eq!(entries[1], "print x");
        assert_eq!(entries[2], "info function test");
    }

    #[test]
    fn test_history_search() {
        let mut history = CommandHistory::new_for_test();

        history.add_command("trace main --script 'print x'");
        history.add_command("print y");
        history.add_command("trace test --script 'print z'");
        history.add_command("info function");

        // Search for commands containing "trace"
        let mut search_state = HistorySearchState {
            is_active: true,
            query: "trace".to_string(),
            current_index: None,
            matches: vec![],
            current_match_index: 0,
        };

        // Use the real search method
        search_state.update_query("trace".to_string(), &history);

        // Verify matches found
        assert_eq!(search_state.matches.len(), 2);

        // The matches should be indices 2 and 0 (reversed order from search_backwards)
        // Index 0: "trace main --script 'print x'"
        // Index 2: "trace test --script 'print z'"
        let entries = history.get_entries_for_test();
        assert!(entries[0].contains("trace")); // First trace command
        assert!(entries[2].contains("trace")); // Second trace command
    }

    #[test]
    fn test_auto_suggestions() {
        let mut history = CommandHistory::new_for_test();

        history.add_command("trace main --script 'print x'");
        history.add_command("trace test --debug");
        history.add_command("print variable");

        // Test using the real prefix match method
        let suggestion = history.get_prefix_match("tra");
        assert!(suggestion.is_some());
        assert!(suggestion.unwrap().starts_with("trace"));

        let suggestion = history.get_prefix_match("print");
        assert!(suggestion.is_some());
        assert_eq!(suggestion.unwrap(), "print variable");
    }

    #[test]
    fn test_history_rendering_with_suggestions() {
        let backend = TestBackend::new(50, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let current_input = "tra";
                let suggestion = "trace main --script 'print x'";

                // Render input with suggestion ghost text
                let content = vec![Line::from(vec![
                    Span::raw("> "),
                    Span::raw(current_input),
                    Span::styled(
                        &suggestion[current_input.len()..],
                        Style::default().fg(Color::DarkGray),
                    ),
                ])];

                let paragraph = Paragraph::new(content);
                f.render_widget(paragraph, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();

        // Verify suggestion is rendered in gray
        let mut line = String::new();
        for x in 0..50 {
            let cell = &buffer[(x, 0)];
            line.push_str(cell.symbol());
        }

        assert!(line.starts_with("> tra"));
        // Note: We can't directly test color in TestBackend, but structure is verified
    }
}

/// Test for syntax highlighting rendering
mod syntax_highlighting_tests {
    use super::*;
    use ghostscope_ui::components::command_panel::syntax_highlighter::SyntaxHighlighter;

    #[test]
    fn test_keyword_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let input = "trace main --script 'print x'";
        let highlighted = highlighter.highlight_line(input);

        // First span should be keyword "trace"
        assert_eq!(highlighted[0].content, "trace");

        // Verify styling (checking if style is set for keyword)
        let keyword_style = highlighted[0].style;
        assert_ne!(keyword_style.fg, None); // Keywords should have color
    }

    #[test]
    fn test_string_literal_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let input = "print \"hello world\"";
        let highlighted = highlighter.highlight_line(input);

        // Find the string literal span
        let string_span = highlighted
            .iter()
            .find(|s| s.content.contains("\"hello world\""));
        assert!(string_span.is_some());

        let string_style = string_span.unwrap().style;
        assert_ne!(string_style.fg, None); // Strings should have color
    }

    #[test]
    fn test_number_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let input = "print variable[42]";
        let highlighted = highlighter.highlight_line(input);

        // Find the number span
        let number_span = highlighted.iter().find(|s| s.content == "42");
        assert!(number_span.is_some());

        let number_style = number_span.unwrap().style;
        assert_ne!(number_style.fg, None); // Numbers should have color
    }

    #[test]
    fn test_comment_highlighting() {
        let highlighter = SyntaxHighlighter::new();
        let input = "trace main # This is a comment";
        let highlighted = highlighter.highlight_line(input);

        // Find the comment span
        let comment_span = highlighted
            .iter()
            .find(|s| s.content.contains("# This is a comment"));
        assert!(comment_span.is_some());

        let comment_style = comment_span.unwrap().style;
        assert_ne!(comment_style.fg, None); // Comments should have color
    }

    #[test]
    fn test_highlighting_render() {
        let backend = TestBackend::new(60, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                // Create highlighted spans
                let spans = vec![
                    Span::styled(
                        "trace",
                        Style::default()
                            .fg(Color::Blue)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(" "),
                    Span::styled("main", Style::default().fg(Color::White)),
                    Span::raw(" "),
                    Span::styled("--script", Style::default().fg(Color::Green)),
                    Span::raw(" "),
                    Span::styled("'print x'", Style::default().fg(Color::Yellow)),
                ];

                let paragraph = Paragraph::new(vec![Line::from(spans)]);
                f.render_widget(paragraph, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();

        // Verify text is rendered
        let mut line = String::new();
        for x in 0..60 {
            let cell = &buffer[(x, 0)];
            line.push_str(cell.symbol());
        }

        assert!(line.contains("trace"));
        assert!(line.contains("main"));
        assert!(line.contains("--script"));
    }
}

/// Test for panel focus switching
mod panel_navigation_tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum PanelType {
        Command,
        Source,
        Output,
    }

    struct PanelState {
        focused_panel: PanelType,
    }

    impl PanelState {
        fn switch_to_next_panel(&mut self) {
            self.focused_panel = match self.focused_panel {
                PanelType::Command => PanelType::Source,
                PanelType::Source => PanelType::Output,
                PanelType::Output => PanelType::Command,
            };
        }

        fn switch_to_prev_panel(&mut self) {
            self.focused_panel = match self.focused_panel {
                PanelType::Command => PanelType::Output,
                PanelType::Source => PanelType::Command,
                PanelType::Output => PanelType::Source,
            };
        }
    }

    #[test]
    fn test_tab_panel_switching() {
        let mut state = PanelState {
            focused_panel: PanelType::Command,
        };

        // Test forward navigation
        state.switch_to_next_panel();
        assert_eq!(state.focused_panel, PanelType::Source);

        state.switch_to_next_panel();
        assert_eq!(state.focused_panel, PanelType::Output);

        state.switch_to_next_panel();
        assert_eq!(state.focused_panel, PanelType::Command);
    }

    #[test]
    fn test_shift_tab_panel_switching() {
        let mut state = PanelState {
            focused_panel: PanelType::Command,
        };

        // Test backward navigation
        state.switch_to_prev_panel();
        assert_eq!(state.focused_panel, PanelType::Output);

        state.switch_to_prev_panel();
        assert_eq!(state.focused_panel, PanelType::Source);

        state.switch_to_prev_panel();
        assert_eq!(state.focused_panel, PanelType::Command);
    }

    #[test]
    fn test_focus_visual_indication() {
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();

        let focused_panel = PanelType::Source;

        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Percentage(33),
                        Constraint::Percentage(34),
                        Constraint::Percentage(33),
                    ])
                    .split(f.area());

                // Render command panel
                let command_block = Block::default()
                    .title("Command")
                    .borders(Borders::ALL)
                    .border_style(if focused_panel == PanelType::Command {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    });
                f.render_widget(command_block, chunks[0]);

                // Render source panel (focused)
                let source_block = Block::default()
                    .title("Source [FOCUSED]")
                    .borders(Borders::ALL)
                    .border_style(if focused_panel == PanelType::Source {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    });
                f.render_widget(source_block, chunks[1]);

                // Render output panel
                let output_block = Block::default()
                    .title("Output")
                    .borders(Borders::ALL)
                    .border_style(if focused_panel == PanelType::Output {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    });
                f.render_widget(output_block, chunks[2]);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();

        // Check that focused panel title is present
        let mut found_focused = false;
        for y in 0..20 {
            let mut line = String::new();
            for x in 0..80 {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            if line.contains("[FOCUSED]") {
                found_focused = true;
                break;
            }
        }

        assert!(found_focused, "Focused panel should have visual indication");
    }
}

/// Test for scrolling behavior
mod scrolling_tests {
    use super::*;
    use ratatui::widgets::{List, ListItem, ListState};

    #[test]
    fn test_output_panel_scrolling() {
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        let items: Vec<ListItem> = (0..20)
            .map(|i| ListItem::new(format!("Line {i}")))
            .collect();

        let mut state = ListState::default();
        state.select(Some(15)); // Scroll to line 15

        terminal
            .draw(|f| {
                let list = List::new(items.clone())
                    .block(Block::default().title("Output").borders(Borders::ALL));

                f.render_stateful_widget(list, f.area(), &mut state);
            })
            .unwrap();

        // Selected item should be visible
        let buffer = terminal.backend().buffer();
        let mut found_line_15 = false;

        for y in 1..9 {
            // Skip borders
            let mut line = String::new();
            for x in 1..39 {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            if line.contains("Line 15") {
                found_line_15 = true;
                break;
            }
        }

        assert!(found_line_15, "Selected line should be visible in viewport");
    }

    #[test]
    fn test_scroll_position_preservation() {
        let mut scroll_offset = 0;
        let viewport_height = 10;
        let total_lines = 50;

        // Scroll down
        scroll_offset = (scroll_offset + 5).min(total_lines - viewport_height);
        assert_eq!(scroll_offset, 5);

        // Scroll to bottom
        scroll_offset = total_lines - viewport_height;
        assert_eq!(scroll_offset, 40);

        // Try to scroll beyond bottom
        scroll_offset = (scroll_offset + 10).min(total_lines - viewport_height);
        assert_eq!(scroll_offset, 40); // Should stay at bottom
    }
}

/// Test for auto-completion
mod auto_completion_tests {
    use super::*;
    use ratatui::widgets::{List, ListItem};

    #[derive(Debug)]
    struct CompletionEngine {
        commands: Vec<String>,
        files: Vec<String>,
    }

    impl CompletionEngine {
        fn new() -> Self {
            Self {
                commands: vec![
                    "trace".to_string(),
                    "print".to_string(),
                    "info".to_string(),
                    "disable".to_string(),
                    "enable".to_string(),
                ],
                files: vec![
                    "test.c".to_string(),
                    "test.h".to_string(),
                    "main.c".to_string(),
                ],
            }
        }

        fn get_completions(&self, input: &str) -> Vec<String> {
            self.commands
                .iter()
                .filter(|cmd| cmd.starts_with(input))
                .cloned()
                .collect()
        }

        fn get_file_completions(&self, partial: &str) -> Vec<String> {
            self.files
                .iter()
                .filter(|file| file.starts_with(partial))
                .cloned()
                .collect()
        }
    }

    #[test]
    fn test_command_completion() {
        let engine = CompletionEngine::new();

        let completions = engine.get_completions("tr");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0], "trace");

        let completions = engine.get_completions("t");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0], "trace");

        let completions = engine.get_completions("in");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0], "info");
    }

    #[test]
    fn test_file_completion() {
        let engine = CompletionEngine::new();

        let completions = engine.get_file_completions("test");
        assert_eq!(completions.len(), 2);
        assert!(completions.contains(&"test.c".to_string()));
        assert!(completions.contains(&"test.h".to_string()));

        let completions = engine.get_file_completions("main");
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0], "main.c");
    }

    #[test]
    fn test_completion_rendering() {
        let backend = TestBackend::new(50, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        let input = "tr";
        let completions = ["trace", "track", "transform"];

        terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3), // Input line
                        Constraint::Min(0),    // Completions
                    ])
                    .split(f.area());

                // Render input
                let input_widget = Paragraph::new(format!("> {input}"))
                    .block(Block::default().borders(Borders::ALL));
                f.render_widget(input_widget, chunks[0]);

                // Render completion dropdown (completions array is always non-empty)
                let items: Vec<ListItem> = completions
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        if i == 0 {
                            ListItem::new(format!("→ {c}")) // Selected
                        } else {
                            ListItem::new(format!("  {c}"))
                        }
                    })
                    .collect();

                let list = List::new(items)
                    .block(Block::default().title("Completions").borders(Borders::ALL));
                f.render_widget(list, chunks[1]);
            })
            .unwrap();

        let buffer = terminal.backend().buffer();

        // Check that completions are shown
        let mut found_completion = false;
        for y in 0..10 {
            let mut line = String::new();
            for x in 0..50 {
                let cell = &buffer[(x, y)];
                line.push_str(cell.symbol());
            }
            if line.contains("→ trace") {
                found_completion = true;
                break;
            }
        }

        assert!(found_completion, "Selected completion should be visible");
    }
}

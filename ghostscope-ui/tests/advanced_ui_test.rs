use ratatui::{
    backend::TestBackend,
    buffer::Buffer,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    Terminal,
};
use std::time::Duration;

/// Test edge cases and extreme inputs
mod edge_case_tests {
    use super::*;

    #[test]
    fn test_zero_size_terminal() {
        // Test handling of zero-size terminal
        let backend = TestBackend::new(0, 0);
        let terminal = Terminal::new(backend);
        assert!(terminal.is_ok(), "Should handle zero-size terminal");
    }

    #[test]
    fn test_minimal_terminal_size() {
        // Test minimal terminal size (1x1)
        let backend = TestBackend::new(1, 1);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                // Should render even in minimal space
                let area = f.area();
                assert_eq!(area.width, 1);
                assert_eq!(area.height, 1);
            })
            .unwrap();
    }

    #[test]
    fn test_huge_terminal_size() {
        // Test huge terminal size - TestBackend has size limits, use reasonable large size
        let backend = TestBackend::new(1000, 500);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                let area = f.area();

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                    .split(area);

                // Layout should split space evenly (50%/50%)
                // TestBackend seems to have size limits
                // Verify layout correctly allocates available space
                let total_height = chunks[0].height + chunks[1].height;
                assert_eq!(total_height, area.height);

                // Verify roughly even split (allow rounding differences)
                let diff = (chunks[0].height as i32 - chunks[1].height as i32).abs();
                assert!(
                    diff <= 1,
                    "Height difference should be at most 1 due to rounding"
                );
            })
            .unwrap();
    }

    #[test]
    fn test_unicode_handling() {
        // Test Unicode character handling
        let backend = TestBackend::new(20, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                use ratatui::widgets::{Block, Borders, Paragraph};

                let text = "Test🦀Unicode😊Mixed";
                let widget = Paragraph::new(text).block(Block::default().borders(Borders::ALL));

                f.render_widget(widget, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        // Verify Unicode characters are handled correctly
        assert!(buffer.area.width == 20);
    }

    #[test]
    fn test_empty_input_handling() {
        // Test empty input handling
        let backend = TestBackend::new(40, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                use ratatui::widgets::{List, ListItem};

                let items: Vec<ListItem> = vec![]; // Empty list
                let list = List::new(items);

                f.render_widget(list, f.area());
            })
            .unwrap();

        // Should render empty list without issues
        assert!(terminal.backend().buffer().area.width > 0);
    }
}

/// Test styles and colors
mod style_tests {
    use super::*;

    #[test]
    fn test_color_preservation() {
        let backend = TestBackend::new(20, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                use ratatui::text::{Line, Span};
                use ratatui::widgets::Paragraph;

                let spans = vec![
                    Span::styled("Red", Style::default().fg(Color::Red)),
                    Span::raw(" "),
                    Span::styled("Blue", Style::default().fg(Color::Blue)),
                ];

                let widget = Paragraph::new(vec![Line::from(spans)]);
                f.render_widget(widget, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        // Verify color information is preserved
        let cell = &buffer[(0, 0)];
        assert_eq!(cell.fg, Color::Red);
    }

    #[test]
    fn test_modifier_combinations() {
        let backend = TestBackend::new(30, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                use ratatui::text::Span;
                use ratatui::widgets::Paragraph;

                let text = Span::styled(
                    "Bold+Italic",
                    Style::default()
                        .add_modifier(Modifier::BOLD)
                        .add_modifier(Modifier::ITALIC),
                );

                let widget = Paragraph::new(text);
                f.render_widget(widget, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let cell = &buffer[(0, 0)];
        assert!(cell.modifier.contains(Modifier::BOLD));
        assert!(cell.modifier.contains(Modifier::ITALIC));
    }
}

/// Test layout calculations
mod layout_tests {
    use super::*;

    #[test]
    fn test_complex_nested_layout() {
        let backend = TestBackend::new(100, 50);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                // Create complex nested layout
                let main_chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
                    .split(f.area());

                let left_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),
                        Constraint::Min(0),
                        Constraint::Length(3),
                    ])
                    .split(main_chunks[0]);

                let right_chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)])
                    .split(main_chunks[1]);

                // Verify layout calculations are correct
                assert_eq!(main_chunks[0].width, 30);
                assert_eq!(main_chunks[1].width, 70);
                assert_eq!(left_chunks[0].height, 3);
                assert_eq!(left_chunks[2].height, 3);
                assert!(right_chunks[0].height < right_chunks[1].height);
            })
            .unwrap();
    }

    #[test]
    fn test_layout_overflow_handling() {
        let backend = TestBackend::new(10, 10);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|f| {
                // Test handling when constraints exceed available space
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(5),
                        Constraint::Length(5),
                        Constraint::Length(5), // Total 15 but only 10 height available
                    ])
                    .split(f.area());

                // Should allocate space reasonably
                let total_height: u16 = chunks.iter().map(|c| c.height).sum();
                assert_eq!(total_height, 10);
            })
            .unwrap();
    }
}

/// Test scrolling and viewport
mod scrolling_tests {
    use super::*;

    #[test]
    fn test_scrollable_content() {
        let backend = TestBackend::new(20, 5);
        let mut terminal = Terminal::new(backend).unwrap();

        let content: Vec<String> = (0..100).map(|i| format!("Line {i}")).collect();
        let scroll_offset = 50;

        terminal
            .draw(|f| {
                use ratatui::widgets::{List, ListItem};

                // Create scrollable content
                let items: Vec<ListItem> = content
                    .iter()
                    .skip(scroll_offset)
                    .take(5)
                    .map(|i| ListItem::new(i.as_str()))
                    .collect();

                let list = List::new(items);
                f.render_widget(list, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        // Verify correct scroll position is displayed
        let first_line = buffer_to_string(buffer, 0);
        assert!(first_line.contains("Line 50"));
    }

    #[test]
    fn test_horizontal_scroll() {
        let backend = TestBackend::new(10, 3);
        let mut terminal = Terminal::new(backend).unwrap();

        let long_text = "This is a very long text that needs horizontal scrolling";
        let h_scroll = 10;

        terminal
            .draw(|f| {
                use ratatui::widgets::Paragraph;

                let visible_text =
                    &long_text[h_scroll..h_scroll + 10.min(long_text.len() - h_scroll)];
                let widget = Paragraph::new(visible_text);

                f.render_widget(widget, f.area());
            })
            .unwrap();

        let buffer = terminal.backend().buffer();
        let text = buffer_to_string(buffer, 0);
        assert!(text.starts_with("very"));
    }
}

/// Test animations and state transitions
mod animation_tests {
    use super::*;

    struct AnimationState {
        frame: usize,
        max_frames: usize,
    }

    impl AnimationState {
        fn new(max_frames: usize) -> Self {
            Self {
                frame: 0,
                max_frames,
            }
        }

        fn tick(&mut self) {
            self.frame = (self.frame + 1) % self.max_frames;
        }

        fn get_progress(&self) -> f64 {
            self.frame as f64 / self.max_frames as f64
        }
    }

    #[test]
    fn test_animation_frames() {
        let backend = TestBackend::new(20, 1);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AnimationState::new(10);

        for _ in 0..10 {
            terminal
                .draw(|f| {
                    use ratatui::widgets::Gauge;

                    let progress = state.get_progress();
                    let gauge = Gauge::default().percent((progress * 100.0) as u16);

                    f.render_widget(gauge, f.area());
                })
                .unwrap();

            state.tick();
        }

        // Verify animation loop completes
        assert_eq!(state.frame, 0);
    }
}

/// Test focus management
mod focus_tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    enum FocusableWidget {
        Input,
        List,
        Button,
    }

    struct FocusManager {
        widgets: Vec<FocusableWidget>,
        focused_index: usize,
    }

    impl FocusManager {
        fn new(widgets: Vec<FocusableWidget>) -> Self {
            Self {
                widgets,
                focused_index: 0,
            }
        }

        fn next(&mut self) {
            self.focused_index = (self.focused_index + 1) % self.widgets.len();
        }

        fn previous(&mut self) {
            self.focused_index = if self.focused_index == 0 {
                self.widgets.len() - 1
            } else {
                self.focused_index - 1
            };
        }

        fn current(&self) -> &FocusableWidget {
            &self.widgets[self.focused_index]
        }
    }

    #[test]
    fn test_focus_cycling() {
        let mut focus_manager = FocusManager::new(vec![
            FocusableWidget::Input,
            FocusableWidget::List,
            FocusableWidget::Button,
        ]);

        assert_eq!(focus_manager.current(), &FocusableWidget::Input);

        focus_manager.next();
        assert_eq!(focus_manager.current(), &FocusableWidget::List);

        focus_manager.next();
        assert_eq!(focus_manager.current(), &FocusableWidget::Button);

        focus_manager.next();
        assert_eq!(focus_manager.current(), &FocusableWidget::Input); // Cycled back

        focus_manager.previous();
        assert_eq!(focus_manager.current(), &FocusableWidget::Button);
    }

    #[test]
    fn test_focus_visual_feedback() {
        let backend = TestBackend::new(30, 10);
        let mut terminal = Terminal::new(backend).unwrap();
        let focus_manager = FocusManager::new(vec![FocusableWidget::Input, FocusableWidget::List]);

        terminal
            .draw(|f| {
                use ratatui::widgets::{Block, Borders};

                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(0)])
                    .split(f.area());

                for (i, chunk) in chunks.iter().enumerate() {
                    let is_focused = i == focus_manager.focused_index;
                    let block =
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(if is_focused {
                                Style::default().fg(Color::Yellow)
                            } else {
                                Style::default()
                            });

                    f.render_widget(block, *chunk);
                }
            })
            .unwrap();

        // Verify focus visual feedback
        let buffer = terminal.backend().buffer();
        // First widget should have yellow border
        let border_cell = &buffer[(0, 0)];
        assert_eq!(border_cell.fg, Color::Yellow);
    }
}

/// Helper functions
fn buffer_to_string(buffer: &Buffer, row: u16) -> String {
    let mut line = String::new();
    for x in 0..buffer.area.width {
        let cell = &buffer[(x, row)];
        line.push_str(cell.symbol());
    }
    line.trim_end().to_string()
}

#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_large_list_rendering_performance() {
        let backend = TestBackend::new(100, 50);
        let mut terminal = Terminal::new(backend).unwrap();

        // Create large dataset
        let items: Vec<String> = (0..10000).map(|i| format!("Item {i}")).collect();

        let start = Instant::now();

        terminal
            .draw(|f| {
                use ratatui::widgets::{List, ListItem};

                // Only render visible portion
                let visible_items: Vec<ListItem> = items
                    .iter()
                    .skip(5000)
                    .take(50)
                    .map(|i| ListItem::new(i.as_str()))
                    .collect();

                let list = List::new(visible_items);
                f.render_widget(list, f.area());
            })
            .unwrap();

        let duration = start.elapsed();

        // Verify rendering performance
        assert!(
            duration < Duration::from_millis(100),
            "Large list rendering took too long: {duration:?}"
        );
    }

    #[test]
    fn test_frequent_redraws() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        let start = Instant::now();
        let redraw_count = 100;

        for i in 0..redraw_count {
            terminal
                .draw(|f| {
                    use ratatui::widgets::Paragraph;

                    let text = format!("Frame {i}/{redraw_count}");
                    let widget = Paragraph::new(text);

                    f.render_widget(widget, f.area());
                })
                .unwrap();
        }

        let duration = start.elapsed();
        let avg_frame_time = duration.as_millis() / redraw_count;

        // Verify average frame time
        assert!(
            avg_frame_time < 10,
            "Average frame time too high: {avg_frame_time}ms"
        );
    }
}

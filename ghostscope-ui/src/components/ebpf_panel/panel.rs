use crate::action::Action;
use crate::model::panel_state::EbpfPanelState;
use crossterm::event::{KeyCode, KeyModifiers};
use ratatui::crossterm::event::KeyEvent;

/// Handles input events for the eBPF panel
#[derive(Debug)]
pub struct EbpfPanelHandler;

impl EbpfPanelHandler {
    pub fn new() -> Self {
        Self
    }

    /// Handle key events for the eBPF panel
    pub fn handle_key_event(&mut self, state: &mut EbpfPanelState, key: KeyEvent) -> Vec<Action> {
        let actions = Vec::new();

        // Expanded view key handling
        if state.is_expanded() {
            let half = state.last_inner_height.max(1) / 2;
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => state.scroll_expanded_up(1),
                KeyCode::Down | KeyCode::Char('j') => state.scroll_expanded_down(1, usize::MAX),
                KeyCode::PageUp => state.scroll_expanded_up(state.last_inner_height.max(1)),
                KeyCode::PageDown => {
                    state.scroll_expanded_down(state.last_inner_height.max(1), usize::MAX)
                }
                KeyCode::Enter => {} // no-op
                KeyCode::Esc => {
                    state.close_expanded();
                }
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    state.close_expanded();
                }
                _ => {
                    // ignore other keys in expanded view
                }
            }

            if key.modifiers.contains(KeyModifiers::CONTROL) {
                match key.code {
                    KeyCode::Char('d') => state.scroll_expanded_down(half.max(1), usize::MAX),
                    KeyCode::Char('u') => state.scroll_expanded_up(half.max(1)),
                    _ => {}
                }
            }

            return actions; // Expanded view handled exclusively
        } else {
            // List view key handling (existing behavior)
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    state.move_cursor_up();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    state.move_cursor_down();
                }
                KeyCode::Char('g') => {
                    state.handle_g_key();
                }
                KeyCode::Char('G') => {
                    state.confirm_goto();
                }
                KeyCode::Char(d) if d.is_ascii_digit() => {
                    state.push_numeric_digit(d);
                }
                KeyCode::Enter => {
                    state.open_expanded_current();
                }
                KeyCode::Esc => {
                    state.exit_to_auto_refresh();
                }
                _ => {}
            }

            if key.modifiers.contains(KeyModifiers::CONTROL) {
                match key.code {
                    KeyCode::Char('d') => {
                        state.move_cursor_down_10();
                    }
                    KeyCode::Char('u') => {
                        state.move_cursor_up_10();
                    }
                    _ => {}
                }
            }
        }

        actions
    }
}

impl Default for EbpfPanelHandler {
    fn default() -> Self {
        Self::new()
    }
}

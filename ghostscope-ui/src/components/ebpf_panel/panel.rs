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
            KeyCode::Esc => {
                state.exit_to_auto_refresh();
            }
            _ => {}
        }

        // Handle Ctrl+key combinations for eBPF panel
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

        actions
    }
}

impl Default for EbpfPanelHandler {
    fn default() -> Self {
        Self::new()
    }
}

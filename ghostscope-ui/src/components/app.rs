mod actions;
mod event_loop;
mod logging;
mod render;
mod runtime_status;

use crate::events::EventRegistry;
use crate::model::ui_state::LayoutMode;
use crate::model::AppState;
use anyhow::Result;
use crossterm::{
    event::EnableBracketedPaste,
    execute,
    terminal::{enable_raw_mode, EnterAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

/// Modern TUI application using TEA architecture
pub struct App {
    terminal: Terminal<CrosstermBackend<io::Stdout>>,
    state: AppState,
    should_quit: bool,
}

impl App {
    /// Create a new application instance
    pub async fn new(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Enable bracketed paste to detect paste events (does not affect mouse selection copy)
        execute!(stdout, EnableBracketedPaste)?;
        // Mouse capture disabled to allow standard copy/paste functionality
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let mut state = AppState::new(event_registry, layout_mode);

        // Request initial source code on startup if source panel is enabled
        if state.ui.config.show_source_panel {
            if let Err(e) = state
                .event_registry
                .command_sender
                .send(crate::events::RuntimeCommand::RequestSourceCode)
            {
                tracing::warn!("Failed to send initial source code request: {}", e);
            } else {
                // Move to connecting state since we've sent the request
                state.set_loading_state(
                    crate::components::loading::LoadingState::ConnectingToRuntime,
                );
            }
        }

        Ok(Self {
            terminal,
            state,
            should_quit: false,
        })
    }

    /// Create a new application instance with full UI configuration
    pub async fn new_with_config(
        event_registry: EventRegistry,
        ui_config: crate::model::ui_state::UiConfig,
    ) -> Result<Self> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        // Enable bracketed paste to detect paste events (does not affect mouse selection copy)
        execute!(stdout, EnableBracketedPaste)?;
        // Mouse capture disabled to allow standard copy/paste functionality
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;

        let mut state = AppState::new_with_config(event_registry, ui_config);

        // Request initial source code on startup if source panel is enabled
        if state.ui.config.show_source_panel {
            if let Err(e) = state
                .event_registry
                .command_sender
                .send(crate::events::RuntimeCommand::RequestSourceCode)
            {
                tracing::warn!("Failed to send initial source code request: {}", e);
            } else {
                // Move to connecting state since we've sent the request
                state.set_loading_state(
                    crate::components::loading::LoadingState::ConnectingToRuntime,
                );
            }
        }

        Ok(Self {
            terminal,
            state,
            should_quit: false,
        })
    }
}

pub mod events;
mod panels;
mod syntax_highlight;
pub mod trace;
mod tui_app;

pub use events::{EventRegistry, RuntimeChannels, RuntimeCommand, RuntimeStatus, TuiEvent};
pub use tui_app::{LayoutMode, TuiApp};

use anyhow::Result;
use tokio::sync::mpsc;

/// Main entry point for TUI mode
pub async fn run_tui_mode(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<()> {
    let mut tui_app = TuiApp::new(event_registry, layout_mode).await?;
    tui_app.run().await
}

pub fn hello() -> String {
    format!("UI: {}", ghostscope_frontend::hello())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "UI: Frontend: Hello from ghostscope-compiler!");
    }
}

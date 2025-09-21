// Core modules
pub mod action;
pub mod components;
pub mod events;
pub mod handlers;
pub mod model;
pub mod ui;
pub mod utils;

// Public exports
pub use action::Action;
pub use components::App;
pub use events::{EventRegistry, RuntimeChannels, RuntimeCommand, RuntimeStatus, TuiEvent};
pub use model::ui_state::LayoutMode;

use anyhow::Result;

pub async fn run_tui_mode(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<()> {
    let mut app = App::new(event_registry, layout_mode).await?;
    app.run().await
}

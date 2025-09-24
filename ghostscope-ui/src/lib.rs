// Core modules
pub mod action;
pub mod components;
pub mod events;
pub mod handlers;
pub mod model;
pub mod ui;
pub mod utils;

// Public exports
pub use action::{Action, PanelType};
pub use components::App;
pub use events::{EventRegistry, RuntimeChannels, RuntimeCommand, RuntimeStatus, TuiEvent};
pub use model::ui_state::{HistoryConfig, LayoutMode, UiConfig};

use anyhow::Result;

pub async fn run_tui_mode(event_registry: EventRegistry, layout_mode: LayoutMode) -> Result<()> {
    let ui_config = UiConfig {
        layout_mode,
        panel_ratios: [4, 3, 3], // Default ratios for backward compatibility
        default_focus: crate::action::PanelType::InteractiveCommand,
        history: HistoryConfig::default(),
    };
    run_tui_mode_with_config(event_registry, ui_config).await
}

pub async fn run_tui_mode_with_config(
    event_registry: EventRegistry,
    ui_config: UiConfig,
) -> Result<()> {
    let mut app = App::new_with_config(event_registry, ui_config).await?;
    app.run().await
}

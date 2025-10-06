use crate::components::command_panel::{OptimizedInputHandler, OptimizedRenderer};
use crate::components::ebpf_panel::{EbpfPanelHandler, EbpfPanelRenderer};
use crate::components::loading::{LoadingState, LoadingUI};
use crate::events::EventRegistry;
use crate::model::ui_state::LayoutMode;
use crate::model::{CommandPanelState, EbpfPanelState, SourcePanelState, UIState};
use crate::ui::EmojiConfig;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;

/// Realtime logging state for command session
#[derive(Debug)]
pub struct RealtimeSessionLogger {
    pub enabled: bool,
    pub file_path: Option<PathBuf>,
    pub writer: Option<BufWriter<File>>,
}

impl Default for RealtimeSessionLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeSessionLogger {
    pub fn new() -> Self {
        Self {
            enabled: false,
            file_path: None,
            writer: None,
        }
    }

    /// Start realtime logging to a file
    pub fn start(&mut self, file_path: PathBuf) -> anyhow::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        self.file_path = Some(file_path);
        self.writer = Some(BufWriter::new(file));
        self.enabled = true;
        Ok(())
    }

    /// Stop realtime logging and flush
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush()?;
        }
        self.enabled = false;
        self.file_path = None;
        Ok(())
    }

    /// Write a line to the log file
    pub fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        if let Some(writer) = &mut self.writer {
            writeln!(writer, "{line}")?;
            writer.flush()?; // Flush immediately for realtime logging
        }
        Ok(())
    }
}

/// Realtime logging state for eBPF output
#[derive(Debug)]
pub struct RealtimeOutputLogger {
    pub enabled: bool,
    pub file_path: Option<PathBuf>,
    pub writer: Option<BufWriter<File>>,
}

impl Default for RealtimeOutputLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl RealtimeOutputLogger {
    pub fn new() -> Self {
        Self {
            enabled: false,
            file_path: None,
            writer: None,
        }
    }

    /// Start realtime logging to a file
    pub fn start(&mut self, file_path: PathBuf) -> anyhow::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;

        self.file_path = Some(file_path);
        self.writer = Some(BufWriter::new(file));
        self.enabled = true;
        Ok(())
    }

    /// Stop realtime logging and flush
    pub fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut writer) = self.writer.take() {
            writer.flush()?;
        }
        self.enabled = false;
        self.file_path = None;
        Ok(())
    }

    /// Write a line to the log file
    pub fn write_line(&mut self, line: &str) -> anyhow::Result<()> {
        if let Some(writer) = &mut self.writer {
            writeln!(writer, "{line}")?;
            writer.flush()?; // Flush immediately for realtime logging
        }
        Ok(())
    }
}

/// Root application state following TEA Model pattern
#[derive(Debug)]
pub struct AppState {
    pub should_quit: bool,

    // Loading state
    pub loading_state: LoadingState,
    pub loading_ui: LoadingUI,

    // Panel states
    pub source_panel: SourcePanelState,
    pub ebpf_panel: EbpfPanelState,
    pub command_panel: CommandPanelState,

    // Optimized command panel components
    pub command_renderer: OptimizedRenderer,
    pub command_input_handler: OptimizedInputHandler,

    // eBPF panel components
    pub ebpf_panel_handler: EbpfPanelHandler,
    pub ebpf_panel_renderer: EbpfPanelRenderer,

    // UI state
    pub ui: UIState,

    // Panel dimensions cache (updated during render)
    pub command_panel_width: u16,

    // Event communication
    pub event_registry: EventRegistry,

    // Special routing flags
    pub route_file_info_to_file_search: bool,

    // Process information
    pub target_pid: Option<u32>,

    // UI configuration
    pub emoji_config: EmojiConfig,

    // Ctrl+C tracking for double-press quit (true if last key was Ctrl+C)
    pub expecting_second_ctrl_c: bool,

    // Realtime logging for save commands
    pub realtime_session_logger: RealtimeSessionLogger,
    pub realtime_output_logger: RealtimeOutputLogger,
}

impl AppState {
    pub fn new(event_registry: EventRegistry, layout_mode: LayoutMode) -> Self {
        Self {
            should_quit: false,
            loading_state: LoadingState::Initializing, // Start with loading, wait for runtime response
            loading_ui: LoadingUI::new(),
            source_panel: SourcePanelState::new(),
            ebpf_panel: EbpfPanelState::new(),
            command_panel: CommandPanelState::new(),
            command_renderer: OptimizedRenderer::new(),
            command_input_handler: OptimizedInputHandler::new(),
            ebpf_panel_handler: EbpfPanelHandler::new(),
            ebpf_panel_renderer: EbpfPanelRenderer::new(),
            ui: UIState::new_with_layout_mode(layout_mode),
            command_panel_width: 80, // Default width, will be updated during render
            event_registry,
            route_file_info_to_file_search: false,
            target_pid: None,
            emoji_config: EmojiConfig::default(),
            expecting_second_ctrl_c: false,
            realtime_session_logger: RealtimeSessionLogger::new(),
            realtime_output_logger: RealtimeOutputLogger::new(),
        }
    }

    pub fn new_with_config(
        event_registry: EventRegistry,
        ui_config: crate::model::ui_state::UiConfig,
    ) -> Self {
        Self {
            should_quit: false,
            loading_state: LoadingState::Initializing, // Start with loading, wait for runtime response
            loading_ui: LoadingUI::new(),
            source_panel: SourcePanelState::new(),
            ebpf_panel: EbpfPanelState::new_with_max_messages(ui_config.ebpf_max_messages),
            command_panel: CommandPanelState::new_with_config(&ui_config.history),
            command_renderer: OptimizedRenderer::new(),
            command_input_handler: OptimizedInputHandler::new(),
            ebpf_panel_handler: EbpfPanelHandler::new(),
            ebpf_panel_renderer: EbpfPanelRenderer::new(),
            ui: UIState::new(ui_config),
            command_panel_width: 80, // Default width, will be updated during render
            event_registry,
            route_file_info_to_file_search: false,
            target_pid: None,
            emoji_config: EmojiConfig::default(),
            expecting_second_ctrl_c: false,
            realtime_session_logger: RealtimeSessionLogger::new(),
            realtime_output_logger: RealtimeOutputLogger::new(),
        }
    }

    /// Check if application is still in loading phase
    pub fn is_loading(&self) -> bool {
        !self.loading_state.is_ready() && !self.loading_state.is_failed()
    }

    /// Update loading state
    pub fn set_loading_state(&mut self, state: LoadingState) {
        tracing::debug!(
            "Loading state change: {:?} -> {:?}",
            self.loading_state,
            state
        );
        self.loading_state = state;
    }
}

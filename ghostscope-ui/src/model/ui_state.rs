use crate::action::PanelType;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LayoutMode {
    Horizontal,
    Vertical,
}

/// Command history configuration
#[derive(Debug, Clone)]
pub struct HistoryConfig {
    /// Enable/disable command history file functionality
    pub enabled: bool,
    /// Maximum number of history entries to keep
    pub max_entries: usize,
}

impl Default for HistoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_entries: 5000,
        }
    }
}

/// UI configuration passed from the main crate
#[derive(Debug, Clone)]
pub struct UiConfig {
    pub layout_mode: LayoutMode,
    pub panel_ratios: [u16; 3], // [Source, EbpfInfo, InteractiveCommand]
    pub show_source_panel: bool,
    pub two_panel_ratios: [u16; 2], // [EbpfInfo, InteractiveCommand] when source hidden
    pub default_focus: crate::action::PanelType,
    pub history: HistoryConfig,
    pub ebpf_max_messages: usize,
}

/// UI-specific state management
#[derive(Debug)]
pub struct UIState {
    pub layout: LayoutState,
    pub focus: FocusState,
    pub config: UiConfig,
}

impl UIState {
    pub fn new(ui_config: UiConfig) -> Self {
        // If source panel is hidden but default focus is Source, fallback to InteractiveCommand
        let effective_default = if !ui_config.show_source_panel
            && matches!(ui_config.default_focus, PanelType::Source)
        {
            PanelType::InteractiveCommand
        } else {
            ui_config.default_focus
        };

        Self {
            layout: LayoutState::new(ui_config.layout_mode),
            focus: FocusState::new_with_default(effective_default),
            config: ui_config,
        }
    }

    // Backward compatibility method
    pub fn new_with_layout_mode(layout_mode: LayoutMode) -> Self {
        Self::new(UiConfig {
            layout_mode,
            panel_ratios: [4, 3, 3], // Default ratios
            show_source_panel: true,
            two_panel_ratios: [3, 3],
            default_focus: crate::action::PanelType::InteractiveCommand,
            history: HistoryConfig::default(),
            ebpf_max_messages: 2000, // Default value
        })
    }
}

#[derive(Debug)]
pub struct LayoutState {
    pub mode: LayoutMode,
    pub is_fullscreen: bool,
}

impl LayoutState {
    pub fn new(mode: LayoutMode) -> Self {
        Self {
            mode,
            is_fullscreen: false,
        }
    }

    pub fn toggle_fullscreen(&mut self) {
        self.is_fullscreen = !self.is_fullscreen;
    }

    pub fn switch_mode(&mut self) {
        self.mode = match self.mode {
            LayoutMode::Horizontal => LayoutMode::Vertical,
            LayoutMode::Vertical => LayoutMode::Horizontal,
        };
    }
}

#[derive(Debug)]
pub struct FocusState {
    pub current_panel: PanelType,
    pub expecting_window_nav: bool,
}

impl FocusState {
    pub fn new() -> Self {
        Self {
            current_panel: PanelType::InteractiveCommand,
            expecting_window_nav: false,
        }
    }

    pub fn new_with_default(default_panel: PanelType) -> Self {
        Self {
            current_panel: default_panel,
            expecting_window_nav: false,
        }
    }

    pub fn cycle_next(&mut self, source_enabled: bool) {
        self.current_panel = match (self.current_panel, source_enabled) {
            (PanelType::Source, _) => PanelType::EbpfInfo,
            (PanelType::EbpfInfo, _) => PanelType::InteractiveCommand,
            (PanelType::InteractiveCommand, true) => PanelType::Source,
            (PanelType::InteractiveCommand, false) => PanelType::EbpfInfo,
        };
    }

    pub fn cycle_previous(&mut self, source_enabled: bool) {
        self.current_panel = match (self.current_panel, source_enabled) {
            (PanelType::Source, _) => PanelType::InteractiveCommand,
            (PanelType::EbpfInfo, true) => PanelType::Source,
            (PanelType::EbpfInfo, false) => PanelType::InteractiveCommand,
            (PanelType::InteractiveCommand, _) => PanelType::EbpfInfo,
        };
    }

    pub fn set_panel(&mut self, panel: PanelType) {
        self.current_panel = panel;
    }

    pub fn is_focused(&self, panel: PanelType) -> bool {
        self.current_panel == panel
    }

    pub fn move_focus_in_direction(
        &mut self,
        direction: crate::action::WindowDirection,
        layout_mode: LayoutMode,
        source_enabled: bool,
    ) {
        use crate::action::WindowDirection;

        match layout_mode {
            LayoutMode::Horizontal => {
                match direction {
                    WindowDirection::Left => {
                        // Left motion
                        self.current_panel = match (self.current_panel, source_enabled) {
                            (PanelType::InteractiveCommand, _) => PanelType::EbpfInfo,
                            (PanelType::EbpfInfo, true) => PanelType::Source,
                            (PanelType::EbpfInfo, false) => PanelType::InteractiveCommand,
                            (PanelType::Source, _) => PanelType::InteractiveCommand, // Wrap to rightmost
                        };
                    }
                    WindowDirection::Right => {
                        // Right motion
                        self.current_panel = match (self.current_panel, source_enabled) {
                            (PanelType::Source, _) => PanelType::EbpfInfo,
                            (PanelType::EbpfInfo, _) => PanelType::InteractiveCommand,
                            (PanelType::InteractiveCommand, true) => PanelType::Source, // Wrap to leftmost
                            (PanelType::InteractiveCommand, false) => PanelType::EbpfInfo,
                        };
                    }
                    _ => {} // Up/Down not relevant in horizontal layout
                }
            }
            LayoutMode::Vertical => {
                match direction {
                    WindowDirection::Up => {
                        self.current_panel = match (self.current_panel, source_enabled) {
                            (PanelType::InteractiveCommand, _) => PanelType::EbpfInfo,
                            (PanelType::EbpfInfo, true) => PanelType::Source,
                            (PanelType::EbpfInfo, false) => PanelType::InteractiveCommand,
                            (PanelType::Source, _) => PanelType::InteractiveCommand, // Wrap to bottom
                        };
                    }
                    WindowDirection::Down => {
                        self.current_panel = match (self.current_panel, source_enabled) {
                            (PanelType::Source, _) => PanelType::EbpfInfo,
                            (PanelType::EbpfInfo, _) => PanelType::InteractiveCommand,
                            (PanelType::InteractiveCommand, true) => PanelType::Source, // Wrap to top
                            (PanelType::InteractiveCommand, false) => PanelType::EbpfInfo,
                        };
                    }
                    _ => {} // Left/Right not relevant in vertical layout
                }
            }
        }
    }
}

impl Default for FocusState {
    fn default() -> Self {
        Self::new()
    }
}

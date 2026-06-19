use super::App;
use crate::action::PanelType;
use crate::components::loading::{LoadingState, LoadingUI};
use crate::model::ui_state::LayoutMode;
use crate::model::AppState;
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    widgets::{Block, BorderType, Borders},
    Frame,
};

impl App {
    pub(super) fn draw_ui(f: &mut Frame, state: &mut AppState) {
        let size = f.area();

        // Show loading screen if still loading
        if state.is_loading() {
            // Use enhanced DWARF loading UI if we're loading symbols
            if matches!(state.loading_state, LoadingState::LoadingSymbols { .. }) {
                LoadingUI::render_dwarf_loading(
                    f,
                    &mut state.loading_ui,
                    &state.loading_state,
                    state.target_pid,
                );
            } else {
                // Use simple loading UI for other states
                LoadingUI::render_simple(
                    f,
                    &mut state.loading_ui,
                    state.loading_state.message(),
                    state.loading_state.progress(),
                );
            }
            return;
        }

        if state.ui.layout.is_fullscreen {
            // In fullscreen mode, give the focused panel the entire screen
            match state.ui.focus.current_panel {
                PanelType::Source => {
                    if state.ui.config.show_source_panel {
                        Self::draw_source_panel(f, size, state);
                    } else {
                        // Source hidden: fallback to command panel fullscreen
                        Self::draw_command_panel(f, size, state);
                    }
                }
                PanelType::EbpfInfo => {
                    Self::draw_ebpf_panel(f, size, state);
                }
                PanelType::InteractiveCommand => {
                    Self::draw_command_panel(f, size, state);
                }
            }
        } else {
            // Normal multi-panel layout
            if state.ui.config.show_source_panel {
                // 3-panel layout
                let ratios = &state.ui.config.panel_ratios;
                let total_ratio: u32 = ratios.iter().map(|&x| x as u32).sum();

                let chunks = match state.ui.layout.mode {
                    LayoutMode::Horizontal => {
                        Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [
                                    Constraint::Ratio(ratios[0] as u32, total_ratio), // Source code panel
                                    Constraint::Ratio(ratios[1] as u32, total_ratio), // eBPF info panel
                                    Constraint::Ratio(ratios[2] as u32, total_ratio), // Command panel
                                ]
                                .as_ref(),
                            )
                            .split(size)
                    }
                    LayoutMode::Vertical => {
                        Layout::default()
                            .direction(Direction::Vertical)
                            .constraints(
                                [
                                    Constraint::Ratio(ratios[0] as u32, total_ratio), // Source code panel
                                    Constraint::Ratio(ratios[1] as u32, total_ratio), // eBPF info panel
                                    Constraint::Ratio(ratios[2] as u32, total_ratio), // Command panel
                                ]
                                .as_ref(),
                            )
                            .split(size)
                    }
                };

                // Draw panels in proper layout
                Self::draw_source_panel(f, chunks[0], state);
                Self::draw_ebpf_panel(f, chunks[1], state);
                Self::draw_command_panel(f, chunks[2], state);
            } else {
                // 2-panel layout: [EbpfInfo, InteractiveCommand]
                let ratios2 = state.ui.config.two_panel_ratios;
                let total2: u32 = (ratios2[0] as u32) + (ratios2[1] as u32);

                let chunks = match state.ui.layout.mode {
                    LayoutMode::Horizontal => {
                        Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [
                                    Constraint::Ratio(ratios2[0] as u32, total2), // eBPF info panel
                                    Constraint::Ratio(ratios2[1] as u32, total2), // Command panel
                                ]
                                .as_ref(),
                            )
                            .split(size)
                    }
                    LayoutMode::Vertical => {
                        Layout::default()
                            .direction(Direction::Vertical)
                            .constraints(
                                [
                                    Constraint::Ratio(ratios2[0] as u32, total2), // eBPF info panel
                                    Constraint::Ratio(ratios2[1] as u32, total2), // Command panel
                                ]
                                .as_ref(),
                            )
                            .split(size)
                    }
                };

                Self::draw_ebpf_panel(f, chunks[0], state);
                Self::draw_command_panel(f, chunks[1], state);
            }
        }
    }

    /// Draw source panel
    fn draw_source_panel(f: &mut Frame, area: Rect, state: &AppState) {
        let is_focused = state.ui.focus.is_focused(PanelType::Source);
        // Create a mutable copy for rendering (area update)
        let mut source_state = state.source_panel.clone();

        // Get cache reference (create empty cache if None)
        let empty_cache = crate::components::command_panel::FileCompletionCache::default();
        let cache = state
            .command_panel
            .file_completion_cache
            .as_ref()
            .unwrap_or(&empty_cache);

        crate::components::source_panel::SourceRenderer::render(
            f,
            area,
            &mut source_state,
            cache,
            is_focused,
        );
    }

    /// Draw eBPF panel
    fn draw_ebpf_panel(f: &mut Frame, area: Rect, state: &mut AppState) {
        let is_focused = state.ui.focus.is_focused(PanelType::EbpfInfo);
        state
            .ebpf_panel_renderer
            .render(&mut state.ebpf_panel, f, area, is_focused);
    }

    /// Draw command panel
    fn draw_command_panel(f: &mut Frame, area: Rect, state: &mut AppState) {
        // Cache panel width for navigation calculations
        let old_width = state.command_panel.cached_panel_width;
        state.command_panel_width = area.width.saturating_sub(2); // Subtract borders

        // Remap command cursor from old wraps to new wraps (before updating cached width)
        state
            .command_panel
            .remap_command_cursor_on_width_change(old_width, state.command_panel_width);

        // Update cached width afterward to keep state consistent
        state
            .command_panel
            .update_panel_width(state.command_panel_width);

        let is_focused = state.ui.focus.is_focused(PanelType::InteractiveCommand);
        let border_style = if is_focused {
            crate::ui::themes::UIThemes::panel_focused()
        } else {
            crate::ui::themes::UIThemes::panel_unfocused()
        };

        let block = Block::default()
            .title(crate::ui::strings::UIStrings::COMMAND_PANEL_TITLE)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(border_style);

        f.render_widget(block, area);

        // Use optimized renderer for command panel content
        state
            .command_renderer
            .render(f, area, &state.command_panel, is_focused);
    }
}

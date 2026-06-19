/// Source path information for display (shared between UI and runtime)
#[derive(Debug, Clone)]
pub struct SourcePathInfo {
    pub substitutions: Vec<PathSubstitution>,
    pub search_dirs: Vec<String>,
    pub runtime_substitution_count: usize,
    pub runtime_search_dir_count: usize,
    pub config_substitution_count: usize,
    pub config_search_dir_count: usize,
}

impl SourcePathInfo {
    /// Format for display in command panel
    pub fn format_for_display(&self) -> String {
        let mut output = String::new();

        output.push_str("🗂️  Source Path Configuration:\n\n");

        // Path substitutions
        if self.substitutions.is_empty() {
            output.push_str("Path Substitutions: (none)\n");
        } else {
            output.push_str(&format!(
                "Path Substitutions ({}):\n",
                self.substitutions.len()
            ));
            for (i, sub) in self.substitutions.iter().enumerate() {
                let marker = if i < self.runtime_substitution_count {
                    "[runtime]"
                } else {
                    "[config] "
                };
                output.push_str(&format!("  {} {} -> {}\n", marker, sub.from, sub.to));
            }
        }

        output.push('\n');

        // Search directories
        if self.search_dirs.is_empty() {
            output.push_str("Search Directories: (none)\n");
        } else {
            output.push_str(&format!(
                "Search Directories ({}):\n",
                self.search_dirs.len()
            ));
            for (i, dir) in self.search_dirs.iter().enumerate() {
                let marker = if i < self.runtime_search_dir_count {
                    "[runtime]"
                } else {
                    "[config] "
                };
                output.push_str(&format!("  {marker} {dir}\n"));
            }
        }

        output.push_str("\n💡 Runtime rules take precedence over config file rules.\n");
        output.push_str(
            "💡 Use 'srcpath clear' to remove runtime rules, 'srcpath reset' to reset to config.\n",
        );

        output
    }

    /// Styled version for display
    pub fn format_for_display_styled(&self) -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};
        use ratatui::text::Line;

        let mut lines = Vec::new();

        // Title
        lines.push(
            StyledLineBuilder::new()
                .title("🗂️  Source Path Configuration:")
                .build(),
        );
        lines.push(Line::from(""));

        // Path substitutions
        if self.substitutions.is_empty() {
            lines.push(
                StyledLineBuilder::new()
                    .key("Path Substitutions:")
                    .text(" (none)")
                    .build(),
            );
        } else {
            lines.push(
                StyledLineBuilder::new()
                    .key(format!(
                        "Path Substitutions ({}):",
                        self.substitutions.len()
                    ))
                    .build(),
            );
            for (i, sub) in self.substitutions.iter().enumerate() {
                let marker = if i < self.runtime_substitution_count {
                    "[runtime]"
                } else {
                    "[config] "
                };
                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .styled(marker, StylePresets::MARKER)
                        .text(" ")
                        .value(&sub.from)
                        .styled(" -> ", StylePresets::TREE)
                        .styled(&sub.to, StylePresets::KEY)
                        .build(),
                );
            }
        }

        lines.push(Line::from(""));

        // Search directories
        if self.search_dirs.is_empty() {
            lines.push(
                StyledLineBuilder::new()
                    .key("Search Directories:")
                    .text(" (none)")
                    .build(),
            );
        } else {
            lines.push(
                StyledLineBuilder::new()
                    .key(format!("Search Directories ({}):", self.search_dirs.len()))
                    .build(),
            );
            for (i, dir) in self.search_dirs.iter().enumerate() {
                let marker = if i < self.runtime_search_dir_count {
                    "[runtime]"
                } else {
                    "[config] "
                };
                lines.push(
                    StyledLineBuilder::new()
                        .text("  ")
                        .styled(marker, StylePresets::MARKER)
                        .text(" ")
                        .value(dir)
                        .build(),
                );
            }
        }

        lines.push(Line::from(""));
        lines.push(
            StyledLineBuilder::new()
                .styled(
                    "💡 Runtime rules take precedence over config file rules.",
                    StylePresets::TIP,
                )
                .build(),
        );
        lines.push(
            StyledLineBuilder::new()
                .styled(
                    "💡 Use 'srcpath clear' to remove runtime rules, 'srcpath reset' to reset to config.",
                    StylePresets::TIP,
                )
                .build(),
        );

        lines
    }
}

/// Path substitution rule (shared definition)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathSubstitution {
    pub from: String,
    pub to: String,
}

/// Source code information for display in TUI
#[derive(Debug, Clone)]
pub struct SourceCodeInfo {
    pub file_path: String,
    pub current_line: Option<usize>,
}

/// Debug information for a target (function or source location)
#[derive(Debug, Clone)]
pub struct TargetDebugInfo {
    pub target: String,
    pub target_type: TargetType,
    pub file_path: Option<String>,
    pub line_number: Option<u32>,
    pub function_name: Option<String>,
    pub modules: Vec<ModuleDebugInfo>, // Grouped by module/binary
}

impl TargetDebugInfo {
    /// Format target debug info with tree-style layout for display
    pub fn format_for_display(&self, verbose: bool) -> String {
        let mut result = String::new();

        // Calculate statistics
        let module_count = self.modules.len();
        let total_addresses: usize = self
            .modules
            .iter()
            .map(|module| module.address_mappings.len())
            .sum();

        // Header by target type
        let header_prefix = match self.target_type {
            TargetType::Function => "🔧 Function Debug Info",
            TargetType::SourceLocation => "📄 Line Debug Info",
            TargetType::Address => "📍 Address Debug Info",
        };
        result.push_str(&format!(
            "{header_prefix}: {} ({} modules, {} traceable addresses)\n\n",
            self.target, module_count, total_addresses
        ));

        // Format modules with tree structure - modules will show their own paths and source info
        for (module_idx, module) in self.modules.iter().enumerate() {
            let is_last_module = module_idx == self.modules.len() - 1;
            result.push_str(&module.format_for_display(
                is_last_module,
                &self.file_path,
                self.line_number,
                verbose,
            ));
        }

        // Suggestions for address targets
        if let TargetType::Address = self.target_type {
            // Try to pick the first address for an example
            let example_addr = self
                .modules
                .iter()
                .flat_map(|m| m.address_mappings.iter())
                .map(|m| m.address)
                .next();
            if let Some(addr) = example_addr {
                result.push_str("\n💡 Tips:\n");
                result.push_str(&format!(
                    "  - In '-t <module>' mode: use `trace 0x{addr:x} {{ ... }}` (defaults to that module)\n"
                ));
                result.push_str(&format!(
                    "  - In '-p <pid>' mode: default module is the main executable; for library addresses, start GhostScope with '-t <that .so>' then use `trace 0x{addr:x} {{ ... }}`\n"
                ));
            }
        }

        result
    }

    /// Styled version for display (pre-styled lines for UI rendering)
    pub fn format_for_display_styled(&self, verbose: bool) -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::StyledLineBuilder;
        use ratatui::text::Line;

        let mut lines = Vec::new();

        // Title line by type
        let total_addresses: usize = self.modules.iter().map(|m| m.address_mappings.len()).sum();
        let header_prefix = match self.target_type {
            TargetType::Function => "🔧 Function Debug Info",
            TargetType::SourceLocation => "📄 Line Debug Info",
            TargetType::Address => "📍 Address Debug Info",
        };
        lines.push(
            StyledLineBuilder::new()
                .title(format!(
                    "{header_prefix}: {} ({} modules, {} addresses)",
                    self.target,
                    self.modules.len(),
                    total_addresses
                ))
                .build(),
        );
        lines.push(Line::from(""));

        for (idx, module) in self.modules.iter().enumerate() {
            let is_last = idx + 1 == self.modules.len();
            lines.extend(module.format_for_display_styled(
                is_last,
                &self.file_path,
                self.line_number,
                verbose,
            ));
        }

        // Suggestions for address targets
        if let TargetType::Address = self.target_type {
            // Example address from first mapping
            if let Some(addr) = self
                .modules
                .iter()
                .flat_map(|m| m.address_mappings.iter())
                .map(|m| m.address)
                .next()
            {
                lines.push(Line::from(""));
                lines.push(
                    StyledLineBuilder::new()
                        .styled(
                            "💡 Tips:",
                            crate::components::command_panel::style_builder::StylePresets::SECTION,
                        )
                        .build(),
                );
                lines.push(
                    StyledLineBuilder::new()
                        .text("  - In '-t <module>' mode: use ")
                        .value(format!("trace 0x{addr:x} {{ ... }}"))
                        .text(" (defaults to that module)")
                        .build(),
                );
                lines.push(
                    StyledLineBuilder::new()
                        .text("  - In '-p <pid>' mode: default module is main executable; for library addresses, start with '-t <that .so>' then use ")
                        .value(format!("trace 0x{addr:x} {{ ... }}"))
                        .build(),
                );
            }
        }

        lines
    }
}

/// Debug information for a module (binary) containing one or more addresses
#[derive(Debug, Clone)]
pub struct ModuleDebugInfo {
    pub binary_path: String,
    pub address_mappings: Vec<AddressMapping>,
}

impl ModuleDebugInfo {
    /// Format module info with tree-style layout for display
    pub fn format_for_display(
        &self,
        is_last_module: bool,
        source_file: &Option<String>,
        source_line: Option<u32>,
        verbose: bool,
    ) -> String {
        let mut result = String::new();

        // Module header with full path and source info
        result.push_str(&format!("📦 {}", &self.binary_path));

        // Add source information if available
        if let Some(ref file) = source_file {
            if let Some(line) = source_line {
                result.push_str(&format!(" @ {file}:{line}\n"));
            } else {
                result.push_str(&format!(" @ {file}\n"));
            }
        } else {
            result.push('\n');
        }

        for (addr_idx, mapping) in self.address_mappings.iter().enumerate() {
            let is_last_addr = addr_idx == self.address_mappings.len() - 1;
            let addr_prefix = match (is_last_module, is_last_addr) {
                (true, true) => "   └─",
                (true, false) => "   ├─",
                (false, true) => "│  └─",
                (false, false) => "│  ├─",
            };

            // Enhanced PC address display with optional index + classification/source
            let mut pc_description = if let Some(i) = mapping.index {
                format!("[{}] 🎯 0x{:x}", i, mapping.address)
            } else {
                format!("🎯 0x{:x}", mapping.address)
            };
            if let Some(is_inline) = mapping.is_inline {
                pc_description
                    .push_str(&format!(" — {}", if is_inline { "inline" } else { "call" }));
            }
            if let (Some(ref file), Some(line)) = (&mapping.source_file, mapping.source_line) {
                pc_description.push_str(&format!(" @ {file}:{line}"));
            }

            result.push_str(&format!("{addr_prefix} {pc_description}\n"));

            // Format parameters
            if !mapping.parameters.is_empty() {
                let param_prefix = match (is_last_module, is_last_addr) {
                    (true, true) => "      ├─",
                    (true, false) => "   │  ├─",
                    (false, true) => "│     ├─",
                    (false, false) => "│  │  ├─",
                };

                result.push_str(&format!("{param_prefix} 📥 Parameters\n"));

                for (param_idx, param) in mapping.parameters.iter().enumerate() {
                    let is_last_param =
                        param_idx == mapping.parameters.len() - 1 && mapping.variables.is_empty();
                    let item_prefix = match (is_last_module, is_last_addr, is_last_param) {
                        (true, true, true) => "      │  └─",
                        (true, true, false) => "      │  ├─",
                        (true, false, true) => "   │  │  └─",
                        (true, false, false) => "   │  │  ├─",
                        (false, true, true) => "│     │  └─",
                        (false, true, false) => "│     │  ├─",
                        (false, false, true) => "│  │  │  └─",
                        (false, false, false) => "│  │  │  ├─",
                    };

                    let param_line = Self::format_variable_line(param, verbose);

                    result.push_str(&Self::wrap_long_line(
                        &format!("{item_prefix} {param_line}"),
                        80,
                        item_prefix,
                    ));
                }
            }

            // Format variables
            if !mapping.variables.is_empty() {
                let var_prefix = match (is_last_module, is_last_addr) {
                    (true, true) => "      └─",
                    (true, false) => "   │  └─",
                    (false, true) => "│     └─",
                    (false, false) => "│  │  └─",
                };

                result.push_str(&format!("{var_prefix} 📦 Variables\n"));

                for (var_idx, var) in mapping.variables.iter().enumerate() {
                    let is_last_var = var_idx == mapping.variables.len() - 1;
                    let item_prefix = match (is_last_module, is_last_addr, is_last_var) {
                        (true, true, true) => "         └─",
                        (true, true, false) => "         ├─",
                        (true, false, true) => "   │     └─",
                        (true, false, false) => "   │     ├─",
                        (false, true, true) => "│        └─",
                        (false, true, false) => "│        ├─",
                        (false, false, true) => "│  │     └─",
                        (false, false, false) => "│  │     ├─",
                    };

                    let var_line = Self::format_variable_line(var, verbose);

                    result.push_str(&Self::wrap_long_line(
                        &format!("{item_prefix} {var_line}"),
                        80,
                        item_prefix,
                    ));
                }
            }
        }

        result
    }

    /// Overload helper: build from VariableDebugInfo
    pub fn format_variable_line(var: &VariableDebugInfo, verbose: bool) -> String {
        // Use enhanced DWARF type display (includes type name and size)
        let type_display = var
            .type_pretty
            .as_ref()
            .filter(|pretty| !pretty.is_empty())
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let name = &var.name;
        if !verbose || var.location_description.is_empty() || var.location_description == "None" {
            format!("{name} ({type_display})")
        } else {
            let location = &var.location_description;
            format!("{name} ({type_display}) = {location}")
        }
    }

    /// Wrap long lines with proper indentation
    fn wrap_long_line(text: &str, max_width: usize, indent: &str) -> String {
        if text.len() <= max_width {
            format!("{text}\n")
        } else {
            let mut result = String::new();
            let mut current_line = text.to_string();

            while current_line.len() > max_width {
                let break_point = current_line
                    .rfind(' ')
                    .unwrap_or(max_width.saturating_sub(10));
                let (first_part, rest) = current_line.split_at(break_point);
                result.push_str(&format!("{first_part}\n"));

                // Create continuation line with proper indentation
                let continuation_indent =
                    format!("{}   ", indent.replace("├─", "│ ").replace("└─", "  "));
                let trimmed_rest = rest.trim();
                current_line = format!("{continuation_indent}{trimmed_rest}");
            }

            if !current_line.trim().is_empty() {
                result.push_str(&format!("{current_line}\n"));
            }

            result
        }
    }
}

impl ModuleDebugInfo {
    /// Styled module info lines
    pub fn format_for_display_styled(
        &self,
        is_last_module: bool,
        source_file: &Option<String>,
        source_line: Option<u32>,
        verbose: bool,
    ) -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};

        let mut lines = Vec::new();

        let mut builder = StyledLineBuilder::new()
            .styled("📦 ", StylePresets::SECTION)
            .styled(&self.binary_path, StylePresets::SECTION);

        if let Some(ref file) = source_file {
            builder = builder.text(" @ ").styled(
                if let Some(line) = source_line {
                    format!("{file}:{line}")
                } else {
                    file.clone()
                },
                StylePresets::LOCATION,
            );
        }

        lines.push(builder.build());

        for (addr_idx, mapping) in self.address_mappings.iter().enumerate() {
            let is_last_addr = addr_idx + 1 == self.address_mappings.len();
            lines.extend(mapping.format_for_display_styled(is_last_module, is_last_addr, verbose));
        }

        lines
    }
}

/// Debug information for a specific address within a module
#[derive(Debug, Clone)]
pub struct AddressMapping {
    pub address: u64,
    pub binary_path: String, // Full binary path for this address
    pub function_name: Option<String>,
    pub variables: Vec<VariableDebugInfo>,
    pub parameters: Vec<VariableDebugInfo>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
    pub is_inline: Option<bool>,
    pub index: Option<usize>, // 1-based global index for selection
}

impl AddressMapping {
    /// Styled address mapping lines with tree prefixes
    pub fn format_for_display_styled(
        &self,
        is_last_module: bool,
        is_last_addr: bool,
        verbose: bool,
    ) -> Vec<ratatui::text::Line<'static>> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};

        let mut lines = Vec::new();

        let prefix = match (is_last_module, is_last_addr) {
            (true, true) => "   └─",
            (true, false) => "   ├─",
            (false, true) => "│  └─",
            (false, false) => "│  ├─",
        };

        // Header line with index + address + optional classification and source location
        let mut header = StyledLineBuilder::new().styled(prefix, StylePresets::TREE);
        if let Some(i) = self.index {
            header = header
                .text(" ")
                .styled(format!("[{i}]"), StylePresets::ADDRESS);
        }
        header = header.text(" 🎯 ").address(self.address);

        if let Some(is_inline) = self.is_inline {
            header = header
                .text(" ")
                .key("—")
                .text(" ")
                .styled(if is_inline { "inline" } else { "call" }, StylePresets::KEY);
        }
        if let (Some(ref file), Some(line)) = (&self.source_file, self.source_line) {
            header = header
                .text(" ")
                .key("@")
                .text(" ")
                .value(format!("{file}:{line}"));
        }

        lines.push(header.build());

        if !self.parameters.is_empty() {
            let param_prefix = match (is_last_module, is_last_addr) {
                (true, true) => "      ├─",
                (true, false) => "   │  ├─",
                (false, true) => "│     ├─",
                (false, false) => "│  │  ├─",
            };

            lines.push(
                StyledLineBuilder::new()
                    .styled(param_prefix, StylePresets::TREE)
                    .styled(" 📥 Parameters", StylePresets::SECTION)
                    .build(),
            );

            for (param_idx, param) in self.parameters.iter().enumerate() {
                let is_last_param =
                    param_idx + 1 == self.parameters.len() && self.variables.is_empty();
                let item_prefix = match (is_last_module, is_last_addr, is_last_param) {
                    (true, true, true) => "      │  └─",
                    (true, true, false) => "      │  ├─",
                    (true, false, true) => "   │  │  └─",
                    (true, false, false) => "   │  │  ├─",
                    (false, true, true) => "│     │  └─",
                    (false, true, false) => "│     │  ├─",
                    (false, false, true) => "│  │  │  └─",
                    (false, false, false) => "│  │  │  ├─",
                };

                lines.push(Self::format_variable_styled(item_prefix, param, verbose));
            }
        }

        if !self.variables.is_empty() {
            let var_prefix = match (is_last_module, is_last_addr) {
                (true, true) => "      └─",
                (true, false) => "   │  └─",
                (false, true) => "│     └─",
                (false, false) => "│  │  └─",
            };

            lines.push(
                StyledLineBuilder::new()
                    .styled(var_prefix, StylePresets::TREE)
                    .styled(" 📦 Variables", StylePresets::SECTION)
                    .build(),
            );

            for (var_idx, var) in self.variables.iter().enumerate() {
                let is_last_var = var_idx + 1 == self.variables.len();
                let item_prefix = match (is_last_module, is_last_addr, is_last_var) {
                    (true, true, true) => "         └─",
                    (true, true, false) => "         ├─",
                    (true, false, true) => "   │     └─",
                    (true, false, false) => "   │     ├─",
                    (false, true, true) => "│        └─",
                    (false, true, false) => "│        ├─",
                    (false, false, true) => "│  │     └─",
                    (false, false, false) => "│  │     ├─",
                };

                lines.push(Self::format_variable_styled(item_prefix, var, verbose));
            }
        }

        lines
    }

    fn format_variable_styled(
        indent_prefix: &str,
        var: &VariableDebugInfo,
        verbose: bool,
    ) -> ratatui::text::Line<'static> {
        use crate::components::command_panel::style_builder::{StylePresets, StyledLineBuilder};

        let type_display = var
            .type_pretty
            .as_ref()
            .filter(|s| !s.is_empty())
            .map(|s| s.as_str())
            .unwrap_or("unknown");

        let mut builder = StyledLineBuilder::new()
            .styled(indent_prefix, StylePresets::TREE)
            .text(" ")
            .value(&var.name)
            .key(": ")
            .styled(type_display, StylePresets::TYPE);

        if let Some(size) = var.size {
            builder = builder.text(" ").text(format!("({size} bytes)"));
        }

        if verbose && !var.location_description.is_empty() && var.location_description != "None" {
            builder = builder
                .text(" ")
                .key("@")
                .text(" ")
                .styled(&var.location_description, StylePresets::LOCATION);
        }

        builder.build()
    }
}

/// Type of target being inspected
#[derive(Debug, Clone)]
pub enum TargetType {
    Function,
    SourceLocation,
    Address,
}

/// Variable debug information
#[derive(Debug, Clone)]
pub struct VariableDebugInfo {
    pub name: String,
    pub type_name: String,
    pub type_pretty: Option<String>,
    pub location_description: String,
    pub size: Option<u64>,
    pub scope_start: Option<u64>,
    pub scope_end: Option<u64>,
}

/// Source file information
#[derive(Debug, Clone)]
pub struct SourceFileInfo {
    pub path: String,
    pub directory: String,
}

/// Group of source files for a specific module
#[derive(Debug, Clone)]
pub struct SourceFileGroup {
    pub module_path: String,
    pub files: Vec<SourceFileInfo>,
}

/// Shared library information (similar to GDB's "info share" output)
#[derive(Debug, Clone)]
pub struct SharedLibraryInfo {
    pub from_address: u64,               // Starting address in memory
    pub to_address: u64,                 // Ending address in memory
    pub symbols_read: bool,              // Whether symbols were successfully read
    pub debug_info_available: bool,      // Whether debug information is available
    pub library_path: String,            // Full path to the library file
    pub size: u64,                       // Size of the library in memory
    pub debug_file_path: Option<String>, // Path to separate debug file (if via .gnu_debuglink)
}

/// Section information for executable files
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub start_address: u64, // Starting address of the section
    pub end_address: u64,   // Ending address of the section
    pub size: u64,          // Size of the section in bytes
}

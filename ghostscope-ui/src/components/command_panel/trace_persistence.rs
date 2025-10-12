//! Trace persistence module for saving and loading trace configurations
//!
//! This module provides functionality to save active traces to script files
//! and load them back, preserving their state (enabled/disabled) and full
//! script content.

use chrono::Local;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::events::{TraceDefinition, TraceStatus};

/// Represents a single trace configuration for persistence
#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub id: u32,
    pub target: String,      // Function name or file:line
    pub script: String,      // Full script content
    pub status: TraceStatus, // Active, Disabled, or Failed
    pub binary_path: String, // Associated binary
}

/// Filter options for saving traces
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SaveFilter {
    All,      // Save all traces
    Enabled,  // Save only enabled traces
    Disabled, // Save only disabled traces
}

/// Result of a save operation
#[derive(Debug)]
pub struct SaveResult {
    pub filename: PathBuf,
    pub saved_count: usize,
    pub total_count: usize,
}

/// Result of a load operation
#[derive(Debug)]
pub struct LoadResult {
    pub filename: PathBuf,
    pub loaded_count: usize,
    pub enabled_count: usize,
    pub disabled_count: usize,
}

/// Main trace persistence handler
pub struct TracePersistence {
    /// Current trace configurations indexed by ID
    traces: HashMap<u32, TraceConfig>,
    /// Binary path for the current session
    binary_path: Option<String>,
    /// Process ID for the current session
    pid: Option<u32>,
}

impl Default for TracePersistence {
    fn default() -> Self {
        Self::new()
    }
}

impl TracePersistence {
    /// Create a new trace persistence handler
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            binary_path: None,
            pid: None,
        }
    }

    /// Update binary path for the session
    pub fn set_binary_path(&mut self, path: String) {
        self.binary_path = Some(path);
    }

    /// Update process ID for the session
    pub fn set_pid(&mut self, pid: u32) {
        self.pid = Some(pid);
    }

    /// Add or update a trace configuration
    pub fn add_trace(&mut self, config: TraceConfig) {
        self.traces.insert(config.id, config);
    }

    /// Remove a trace configuration
    pub fn remove_trace(&mut self, id: u32) -> Option<TraceConfig> {
        self.traces.remove(&id)
    }

    /// Update trace status
    pub fn update_trace_status(&mut self, id: u32, status: TraceStatus) {
        if let Some(trace) = self.traces.get_mut(&id) {
            trace.status = status;
        }
    }

    /// Get all traces matching the filter
    pub fn get_filtered_traces(&self, filter: SaveFilter) -> Vec<&TraceConfig> {
        self.traces
            .values()
            .filter(|t| match filter {
                SaveFilter::All => true,
                SaveFilter::Enabled => matches!(t.status, TraceStatus::Active),
                SaveFilter::Disabled => matches!(t.status, TraceStatus::Disabled),
            })
            .collect()
    }

    /// Save traces to a file
    pub fn save_traces(
        &self,
        filename: Option<&str>,
        filter: SaveFilter,
    ) -> io::Result<SaveResult> {
        // Use provided filename or generate default
        let path = if let Some(name) = filename {
            // Use filename exactly as provided - no extension added
            PathBuf::from(name)
        } else {
            // Generate default filename with .gs extension
            self.generate_default_filename()
        };

        // Get traces to save
        let traces = self.get_filtered_traces(filter);
        if traces.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No traces to save",
            ));
        }

        // Generate file content
        let content = self.generate_save_content(&traces, filter);

        // Write to file
        fs::write(&path, content)?;

        Ok(SaveResult {
            filename: path,
            saved_count: traces.len(),
            total_count: self.traces.len(),
        })
    }

    /// Generate default filename with timestamp
    fn generate_default_filename(&self) -> PathBuf {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S");
        let binary_name = self
            .binary_path
            .as_ref()
            .and_then(|p| Path::new(p).file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("program");

        PathBuf::from(format!("traces_{binary_name}_{timestamp}.gs"))
    }

    /// Generate the content for the save file
    fn generate_save_content(&self, traces: &[&TraceConfig], filter: SaveFilter) -> String {
        let mut content = String::new();

        // Write header
        content.push_str(&self.generate_header(traces.len(), filter));
        content.push('\n');

        // Write each trace
        for (idx, trace) in traces.iter().enumerate() {
            if idx > 0 {
                content.push('\n');
            }
            content.push_str(&self.generate_trace_section(trace));
        }

        content
    }

    /// Generate file header with metadata
    fn generate_header(&self, trace_count: usize, filter: SaveFilter) -> String {
        let mut header = String::new();

        // File identification
        header.push_str("// GhostScope Trace Save File v1.0\n");

        // Timestamp
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        header.push_str(&format!("// Generated: {timestamp}\n"));

        // Binary information
        if let Some(ref binary) = self.binary_path {
            header.push_str(&format!("// Binary: {binary}\n"));
        }

        // PID information (if available)
        if let Some(pid) = self.pid {
            header.push_str(&format!("// PID: {pid}\n"));
        }

        // Filter information
        let filter_desc = match filter {
            SaveFilter::All => "all",
            SaveFilter::Enabled => "enabled only",
            SaveFilter::Disabled => "disabled only",
        };
        header.push_str(&format!("// Filter: {filter_desc}\n"));

        // Trace count summary
        let enabled_count = self
            .traces
            .values()
            .filter(|t| matches!(t.status, TraceStatus::Active))
            .count();
        let disabled_count = self
            .traces
            .values()
            .filter(|t| matches!(t.status, TraceStatus::Disabled))
            .count();

        header.push_str(&format!(
            "// Traces: {trace_count} total ({enabled_count} enabled, {disabled_count} disabled)\n"
        ));

        header
    }

    /// Generate a single trace section
    fn generate_trace_section(&self, trace: &TraceConfig) -> String {
        let mut section = String::new();

        // Section separator
        section.push_str("// ========================================\n");

        // Trace metadata
        let status_str = match trace.status {
            TraceStatus::Active => "ENABLED",
            TraceStatus::Disabled => "DISABLED",
            TraceStatus::Failed => "FAILED",
        };

        section.push_str(&format!(
            "// Trace {}: {} [{}]\n",
            trace.id, trace.target, status_str
        ));
        section.push_str(&format!("// Target: {}\n", trace.target));
        section.push_str(&format!("// Status: {}\n", trace.status));
        section.push_str("// ========================================\n");

        // Add disabled marker if needed
        if matches!(trace.status, TraceStatus::Disabled) {
            section.push_str("//@disabled\n");
        }

        // Trace command and script
        section.push_str(&format!("trace {} {{\n", trace.target));

        // Indent script content
        for line in trace.script.lines() {
            section.push_str("    ");
            section.push_str(line);
            section.push('\n');
        }

        section.push_str("}\n");

        section
    }

    /// Parse a saved trace file for loading
    pub fn parse_trace_file(content: &str) -> io::Result<Vec<TraceDefinition>> {
        let mut traces = Vec::new();
        let mut current_target: Option<String> = None;
        let mut in_script = false;
        let mut script_lines = Vec::new();
        let mut pending_disabled = false;
        // Track nested braces so inner blocks (e.g., if { ... }) don't terminate the trace section
        let mut brace_depth: usize = 0;

        for line in content.lines() {
            let trimmed = line.trim();

            // Check for disabled marker
            if trimmed == "//@disabled" {
                pending_disabled = true;
                continue;
            }

            // Check for trace command start
            if trimmed.starts_with("trace ") && trimmed.ends_with(" {") {
                // Extract target from trace command
                let target = trimmed
                    .strip_prefix("trace ")
                    .and_then(|s| s.strip_suffix(" {"))
                    .unwrap_or("")
                    .to_string();

                current_target = Some(target);
                in_script = true;
                script_lines.clear();
                // Opening brace for the trace section
                brace_depth = 1;
                continue;
            }

            // Check for script end: only close when this '}' matches the outer trace block
            if in_script && trimmed == "}" && brace_depth == 1 {
                if let Some(target) = current_target.take() {
                    let script = script_lines.join("\n");
                    traces.push(TraceDefinition {
                        target,
                        script,
                        enabled: !pending_disabled,
                    });
                    pending_disabled = false;
                }
                in_script = false;
                brace_depth = 0;
                continue;
            }

            // Collect script lines
            if in_script {
                // Remove leading indentation (4 spaces)
                let script_line = if let Some(stripped) = line.strip_prefix("    ") {
                    stripped
                } else {
                    line
                };
                script_lines.push(script_line.to_string());

                // Update brace depth based on current line content so nested '}' are preserved
                // Note: naïve count, acceptable because braces rarely appear in string literals in our scripts
                let opens = script_line.chars().filter(|&c| c == '{').count();
                let closes = script_line.chars().filter(|&c| c == '}').count();
                // Saturating arithmetic to avoid underflow on malformed input
                brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);
            }
        }

        Ok(traces)
    }

    /// Load traces from a file
    pub fn load_traces_from_file(filename: &str) -> io::Result<Vec<TraceDefinition>> {
        let content = fs::read_to_string(filename)?;
        Self::parse_trace_file(&content)
    }
}

/// Extension trait for command parsing
pub trait CommandParser {
    fn parse_save_traces_command(&self) -> Option<(Option<String>, SaveFilter)>;
}

impl CommandParser for str {
    fn parse_save_traces_command(&self) -> Option<(Option<String>, SaveFilter)> {
        let parts: Vec<&str> = self.split_whitespace().collect();

        if parts.len() < 2 || parts[0] != "save" || parts[1] != "traces" {
            return None;
        }

        match parts.len() {
            2 => {
                // save traces
                Some((None, SaveFilter::All))
            }
            3 => {
                // save traces <filename> or save traces enabled/disabled
                match parts[2] {
                    "enabled" => Some((None, SaveFilter::Enabled)),
                    "disabled" => Some((None, SaveFilter::Disabled)),
                    filename => Some((Some(filename.to_string()), SaveFilter::All)),
                }
            }
            4 => {
                // save traces enabled/disabled <filename>
                let filter = match parts[2] {
                    "enabled" => SaveFilter::Enabled,
                    "disabled" => SaveFilter::Disabled,
                    _ => return None,
                };
                Some((Some(parts[3].to_string()), filter))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_save_command() {
        // Basic save
        let (file, filter) = "save traces".parse_save_traces_command().unwrap();
        assert_eq!(file, None);
        assert_eq!(filter, SaveFilter::All);

        // Save with filename
        let (file, filter) = "save traces session.gs"
            .parse_save_traces_command()
            .unwrap();
        assert_eq!(file, Some("session.gs".to_string()));
        assert_eq!(filter, SaveFilter::All);

        // Save enabled only
        let (file, filter) = "save traces enabled".parse_save_traces_command().unwrap();
        assert_eq!(file, None);
        assert_eq!(filter, SaveFilter::Enabled);

        // Save disabled with filename
        let (file, filter) = "save traces disabled debug.gs"
            .parse_save_traces_command()
            .unwrap();
        assert_eq!(file, Some("debug.gs".to_string()));
        assert_eq!(filter, SaveFilter::Disabled);
    }

    #[test]
    fn test_parse_trace_file() {
        let content = r#"// Header
//@disabled
trace main {
    print "hello";
    print "world";
}

trace foo {
    print "foo";
}"#;

        let traces = TracePersistence::parse_trace_file(content).unwrap();
        assert_eq!(traces.len(), 2);

        assert_eq!(traces[0].target, "main");
        assert!(!traces[0].enabled); // disabled trace
        assert_eq!(traces[0].script, "print \"hello\";\nprint \"world\";");

        assert_eq!(traces[1].target, "foo");
        assert!(traces[1].enabled); // enabled trace
        assert_eq!(traces[1].script, "print \"foo\";");
    }
}

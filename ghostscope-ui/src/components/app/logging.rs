use super::App;

impl App {
    fn validate_and_resolve_path(filename: &str) -> anyhow::Result<std::path::PathBuf> {
        use std::path::{Path, PathBuf};

        // Check for path traversal attempts
        if filename.contains("..") {
            return Err(anyhow::anyhow!(
                "Path traversal not allowed (contains '..')"
            ));
        }

        // Resolve to absolute path
        let file_path = if Path::new(filename).is_relative() {
            let current_dir = std::env::current_dir()?;
            current_dir.join(filename)
        } else {
            PathBuf::from(filename)
        };

        // Canonicalize and verify the path stays within allowed directory
        // For relative paths, ensure they resolve within current directory
        if Path::new(filename).is_relative() {
            let current_dir = std::env::current_dir()?;
            let canonical_current = current_dir
                .canonicalize()
                .unwrap_or_else(|_| current_dir.clone());

            // Check parent directory exists before canonicalizing
            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    return Err(anyhow::anyhow!(
                        "Directory does not exist: {}",
                        parent.display()
                    ));
                }

                // Verify resolved path is within current directory
                let canonical_parent = parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf());
                if !canonical_parent.starts_with(&canonical_current) {
                    return Err(anyhow::anyhow!("Cannot save outside current directory"));
                }
            }
        }

        Ok(file_path)
    }

    /// Start realtime eBPF output logging
    pub(super) fn start_realtime_output_logging(
        &mut self,
        filename: Option<String>,
    ) -> anyhow::Result<std::path::PathBuf> {
        use chrono::Local;

        // Check if already logging
        if self.state.realtime_output_logger.enabled {
            return Err(anyhow::anyhow!(
                "Realtime output logging already active to: {}",
                self.state
                    .realtime_output_logger
                    .file_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        // Generate filename if not provided
        let filename = filename.unwrap_or_else(|| {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            format!("ebpf_output_{timestamp}.log")
        });

        // Validate and resolve path
        let file_path = Self::validate_and_resolve_path(&filename)?;

        // Determine if this is a new file
        let is_new_file = !file_path.exists();

        // Start the logger
        self.state.realtime_output_logger.start(file_path.clone())?;

        // Write header if this is a new file
        if is_new_file {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state
                .realtime_output_logger
                .write_line("# GhostScope eBPF Output Log (Realtime)")?;
            self.state
                .realtime_output_logger
                .write_line(&format!("# Session: {timestamp}"))?;
            self.state
                .realtime_output_logger
                .write_line("# ========================================")?;
            self.state.realtime_output_logger.write_line("")?;
        } else {
            // Add separator for continuation
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state.realtime_output_logger.write_line("")?;
            self.state
                .realtime_output_logger
                .write_line("# ----------------------------------------")?;
            self.state
                .realtime_output_logger
                .write_line(&format!("# Resumed: {timestamp}"))?;
            self.state
                .realtime_output_logger
                .write_line("# ----------------------------------------")?;
            self.state.realtime_output_logger.write_line("")?;
        }

        Ok(file_path)
    }

    /// Write an eBPF event to the output log (realtime)
    pub(super) fn write_ebpf_event_to_output_log(
        &mut self,
        event: &crate::events::UiTraceEvent,
    ) -> anyhow::Result<()> {
        if self.state.realtime_output_logger.enabled {
            // Format timestamp
            let secs = event.timestamp / 1_000_000_000;
            let nanos = event.timestamp % 1_000_000_000;
            let formatted_ts = format!(
                "{:02}:{:02}:{:02}.{:06}",
                (secs / 3600) % 24,
                (secs / 60) % 60,
                secs % 60,
                nanos / 1000
            );

            // Format output from instructions
            let formatted_output = event.to_formatted_output();
            let message = formatted_output.join(" ");

            // Write: [timestamp] [PID xxxx/TID yyyy] Trace #id: message
            self.state.realtime_output_logger.write_line(&format!(
                "[{}] [PID {}/TID {}] Trace #{}: {}",
                formatted_ts, event.pid, event.tid, event.trace_id, message
            ))?;
        }
        Ok(())
    }

    /// Write a command to the session log (realtime)
    pub(super) fn write_command_to_session_log(&mut self, command: &str) -> anyhow::Result<()> {
        if self.state.realtime_session_logger.enabled {
            self.state.realtime_session_logger.write_line("")?;
            self.state
                .realtime_session_logger
                .write_line(&format!(">>> {command}"))?;
        }
        Ok(())
    }

    /// Write a response to the session log (realtime)
    pub(super) fn write_response_to_session_log(&mut self, response: &str) -> anyhow::Result<()> {
        if self.state.realtime_session_logger.enabled {
            for line in response.lines() {
                self.state
                    .realtime_session_logger
                    .write_line(&format!("    {line}"))?;
            }
        }
        Ok(())
    }

    /// Start realtime command session logging
    pub(super) fn start_realtime_session_logging(
        &mut self,
        filename: Option<String>,
    ) -> anyhow::Result<std::path::PathBuf> {
        use chrono::Local;

        // Check if already logging
        if self.state.realtime_session_logger.enabled {
            return Err(anyhow::anyhow!(
                "Realtime session logging already active to: {}",
                self.state
                    .realtime_session_logger
                    .file_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }

        // Generate filename if not provided
        let filename = filename.unwrap_or_else(|| {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            format!("command_session_{timestamp}.log")
        });

        // Validate and resolve path
        let file_path = Self::validate_and_resolve_path(&filename)?;

        // Determine if this is a new file
        let is_new_file = !file_path.exists();

        // Start the logger
        self.state
            .realtime_session_logger
            .start(file_path.clone())?;

        // Write header if this is a new file
        if is_new_file {
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state
                .realtime_session_logger
                .write_line("# GhostScope Command Session Log (Realtime)")?;
            self.state
                .realtime_session_logger
                .write_line(&format!("# Session: {timestamp}"))?;
            self.state
                .realtime_session_logger
                .write_line("# ========================================")?;
            self.state.realtime_session_logger.write_line("")?;

            // Write static lines (welcome messages)
            for static_line in &self.state.command_panel.static_lines {
                self.state
                    .realtime_session_logger
                    .write_line(&static_line.content)?;
            }
            self.state.realtime_session_logger.write_line("")?;
        } else {
            // Add separator for continuation
            let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
            self.state.realtime_session_logger.write_line("")?;
            self.state
                .realtime_session_logger
                .write_line("# ----------------------------------------")?;
            self.state
                .realtime_session_logger
                .write_line(&format!("# Resumed: {timestamp}"))?;
            self.state
                .realtime_session_logger
                .write_line("# ----------------------------------------")?;
            self.state.realtime_session_logger.write_line("")?;
        }

        Ok(file_path)
    }
}

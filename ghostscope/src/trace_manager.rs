use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use ghostscope_ui::events::TraceStatus;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// Individual trace instance with single PC value
#[derive(Debug)]
pub struct TraceInstance {
    pub trace_id: u32,
    pub target: String, // Target identifier for grouping (e.g., "test_program:L15")
    pub script_content: String, // Original script content
    pub binary_path: String, // Binary being traced
    pub target_display: String, // Display name for UI (e.g., "main", "file.c:15")
    pub pc: u64,        // Program counter value for this trace (file offset for uprobe)
    pub target_pid: Option<u32>, // Target PID if specified
    pub is_enabled: bool, // Whether the uprobe is currently enabled
    pub loader: Option<GhostScopeLoader>, // eBPF loader for this trace
    pub ebpf_function_name: String, // eBPF function name for uprobe attachment
}

impl TraceInstance {
    pub fn new(
        trace_id: u32,
        target: String,
        script_content: String,
        pc: u64,
        binary_path: String,
        target_display: String,
        target_pid: Option<u32>,
        loader: Option<GhostScopeLoader>,
        ebpf_function_name: String,
    ) -> Self {
        Self {
            trace_id,
            target,
            script_content,
            pc,
            binary_path,
            target_display,
            target_pid,
            is_enabled: false,
            loader,
            ebpf_function_name,
        }
    }

    /// Get trace status as enum
    pub fn status(&self) -> TraceStatus {
        if self.is_enabled {
            TraceStatus::Active
        } else {
            TraceStatus::Disabled
        }
    }

    /// Get script preview (first meaningful line)
    pub fn script_preview(&self) -> Option<String> {
        for line in self.script_content.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('{') && !trimmed.starts_with('}') {
                return Some(trimmed.to_string());
            }
        }
        None
    }

    /// Enable this trace instance
    pub fn enable(&mut self) -> Result<()> {
        if self.is_enabled {
            info!("Trace {} is already enabled", self.trace_id);
            return Ok(());
        }

        info!(
            "Enabling trace {} for target '{}' at PC 0x{:x} in binary '{}'",
            self.trace_id, self.target_display, self.pc, self.binary_path
        );

        // Attach uprobe using the loader
        if let Some(ref mut loader) = self.loader {
            if loader.is_uprobe_attached() {
                warn!("Uprobe already attached for trace {}", self.trace_id);
                self.is_enabled = true;
                return Ok(());
            } else if loader.get_attachment_info().is_some() {
                info!(
                    "Re-attaching uprobe for trace {} (program already loaded)",
                    self.trace_id
                );
                match loader.reattach_uprobe() {
                    Ok(_) => {
                        info!(
                            "✓ Successfully re-attached uprobe for trace {}",
                            self.trace_id
                        );
                        self.is_enabled = true;
                        return Ok(());
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to re-attach uprobe for trace {}: {}",
                            self.trace_id, e
                        );
                        return Err(anyhow::anyhow!("Failed to re-attach uprobe: {}", e));
                    }
                }
            } else {
                info!(
                    "Attaching uprobe for trace {} at offset 0x{:x} using program '{}'",
                    self.trace_id, self.pc, self.ebpf_function_name
                );
                match loader.attach_uprobe(
                    &self.binary_path,
                    &self.ebpf_function_name,
                    Some(self.pc),
                    self.target_pid.map(|pid| pid as i32),
                ) {
                    Ok(_) => {
                        info!(
                            "✓ Successfully attached uprobe for trace {} at 0x{:x}",
                            self.trace_id, self.pc
                        );
                        self.is_enabled = true;
                        Ok(())
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to attach uprobe for trace {} at 0x{:x}: {}",
                            self.trace_id, self.pc, e
                        );
                        Err(anyhow::anyhow!("Failed to attach uprobe: {}", e))
                    }
                }
            }
        } else {
            error!("No eBPF loader available for trace {}", self.trace_id);
            Err(anyhow::anyhow!("No eBPF loader available"))
        }
    }

    /// Disable this trace instance
    pub fn disable(&mut self) -> Result<()> {
        if !self.is_enabled {
            info!("Trace {} is already disabled", self.trace_id);
            return Ok(());
        }

        info!("Disabling trace {} at PC 0x{:x}", self.trace_id, self.pc);

        // Detach uprobe using the loader
        if let Some(ref mut loader) = self.loader {
            if loader.is_uprobe_attached() {
                info!("Detaching uprobe for trace {}", self.trace_id);
                match loader.detach_uprobe() {
                    Ok(_) => {
                        info!("✓ Successfully detached uprobe for trace {}", self.trace_id);
                        self.is_enabled = false;
                        Ok(())
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to detach uprobe for trace {}: {}",
                            self.trace_id, e
                        );
                        Err(anyhow::anyhow!("Failed to detach uprobe: {}", e))
                    }
                }
            } else {
                warn!(
                    "Uprobe not attached for trace {}, marking as disabled",
                    self.trace_id
                );
                self.is_enabled = false;
                Ok(())
            }
        } else {
            error!("No eBPF loader available for trace {}", self.trace_id);
            Err(anyhow::anyhow!("No eBPF loader available"))
        }
    }

    /// Wait for events asynchronously from this trace instance
    pub async fn wait_for_events_async(&mut self) -> Result<Vec<ghostscope_protocol::EventData>> {
        if !self.is_enabled {
            return Ok(Vec::new());
        }

        // Wait for events using the loader
        if let Some(ref mut loader) = self.loader {
            match loader.wait_for_events_async().await {
                Ok(events) => Ok(events),
                Err(e) => {
                    warn!(
                        "Error waiting for events from trace {}: {}",
                        self.trace_id, e
                    );
                    Err(e.into())
                }
            }
        } else {
            error!("No eBPF loader available for trace {}", self.trace_id);
            Err(anyhow::anyhow!("No eBPF loader available"))
        }
    }
}

#[derive(Debug, Clone)]
pub struct TraceSnapshot {
    pub trace_id: u32,
    pub target: String,
    pub script_content: String,
    pub binary_path: String,
    pub target_display: String,
    pub target_pid: Option<u32>,
    pub is_enabled: bool,
    pub pc: u64,
    pub ebpf_function_name: String,
}

/// Summary statistics for all traces
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub total: usize,
    pub active: usize,
    pub disabled: usize,
}

impl TraceSummary {
    pub fn new() -> Self {
        Self {
            total: 0,
            active: 0,
            disabled: 0,
        }
    }

    pub fn format(&self) -> String {
        format!(
            "Total: {} | Active: {} | Disabled: {}",
            self.total, self.active, self.disabled
        )
    }
}

/// Formatted trace information for display
#[derive(Debug, Clone)]
pub struct FormattedTraceInfo {
    pub trace_id: u32,
    pub target_display: String,
    pub binary_path: String,
    pub status: TraceStatus,
    pub duration: String,
    pub script_preview: Option<String>,
    pub pc: u64,
    pub error_message: Option<String>,
}

impl FormattedTraceInfo {
    pub fn format_line(&self) -> String {
        // Extract binary name from path for cleaner display
        let binary_name = std::path::Path::new(&self.binary_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(&self.binary_path);

        let mut line = format!(
            "{} [{}] {}@{}+0x{:x} - {} ({})",
            self.status.to_emoji(),
            self.trace_id,
            self.target_display,
            binary_name,
            self.pc,
            self.status.to_string(),
            self.duration
        );

        if let Some(ref error) = self.error_message {
            line.push_str(&format!(" - Error: {}", error));
        }

        line
    }
}

/// Manager for all active trace instances
#[derive(Debug)]
pub struct TraceManager {
    traces: HashMap<u32, TraceInstance>,
    next_trace_id: u32,
    target_to_trace_id: HashMap<String, u32>, // Map target name to trace_id
    no_trace_wait_notify: Notify,             // Notify when first trace is successfully enabled
    // Track creation timestamps for duration calculation
    trace_created_times: HashMap<u32, u64>,
}

impl TraceManager {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            next_trace_id: 0,
            target_to_trace_id: HashMap::new(),
            no_trace_wait_notify: Notify::new(),
            trace_created_times: HashMap::new(),
        }
    }

    /// Add a new trace instance
    pub fn add_trace(
        &mut self,
        target: String,
        script_content: String,
        pc: u64,
        binary_path: String,
        target_display: String,
        target_pid: Option<u32>,
        loader: Option<GhostScopeLoader>,
        ebpf_function_name: String,
    ) -> u32 {
        let trace_id = self.next_trace_id;
        self.next_trace_id += 1;

        // Record creation time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.trace_created_times.insert(trace_id, now);

        // Create unique target key by combining target with trace_id
        // This allows multiple traces for the same target (e.g., same function/line)
        let unique_target = format!("{}#{}", target, trace_id);

        let trace_instance = TraceInstance::new(
            trace_id,
            target.clone(), // Keep original target for grouping
            script_content,
            pc,
            binary_path,
            target_display,
            target_pid,
            loader,
            ebpf_function_name,
        );

        self.traces.insert(trace_id, trace_instance);
        self.target_to_trace_id.insert(unique_target, trace_id);

        debug!(
            "Added trace {} to manager with target '{}'",
            trace_id, target
        );
        trace_id
    }

    /// Enable a trace by ID (duplicate of enable_trace method - keeping for compatibility)
    pub fn activate_trace(&mut self, trace_id: u32) -> Result<()> {
        self.enable_trace(trace_id)
    }

    /// Remove a trace by ID (legacy method, use delete_trace for complete cleanup)
    pub fn remove_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(mut trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping using the correct unique target key
            let unique_target = format!("{}#{}", trace.target, trace_id);
            self.target_to_trace_id.remove(&unique_target);
            // Remove creation time
            self.trace_created_times.remove(&trace_id);

            // Disable all mounts if still active
            trace.disable()?;

            debug!("Removed trace {} from manager", trace_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Completely delete a trace by ID, destroying all associated resources
    pub fn delete_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping using the correct unique target key
            let unique_target = format!("{}#{}", trace.target, trace_id);
            self.target_to_trace_id.remove(&unique_target);
            // Remove creation time
            self.trace_created_times.remove(&trace_id);

            info!("Deleting trace {} and all associated resources", trace_id);

            // Destroy eBPF loader and all associated resources
            if let Some(mut loader) = trace.loader {
                let _ = loader.destroy();
                info!("Destroyed eBPF loader for trace {}", trace_id);
            }

            info!("Trace {} deleted successfully", trace_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Delete all traces, destroying all associated resources
    pub fn delete_all_traces(&mut self) -> Result<usize> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        let count = trace_ids.len();

        info!("Deleting all {} traces and their resources", count);

        for trace_id in trace_ids {
            if let Err(e) = self.delete_trace(trace_id) {
                warn!("Failed to delete trace {}: {}", trace_id, e);
            }
        }

        info!("Deleted all traces successfully");
        Ok(count)
    }

    /// Get trace by ID
    pub fn get_trace(&self, trace_id: u32) -> Option<&TraceInstance> {
        self.traces.get(&trace_id)
    }

    /// Get mutable trace by ID
    pub fn get_trace_mut(&mut self, trace_id: u32) -> Option<&mut TraceInstance> {
        self.traces.get_mut(&trace_id)
    }

    /// Get trace by target name
    pub fn get_trace_by_target(&self, target: &str) -> Option<&TraceInstance> {
        self.target_to_trace_id
            .get(target)
            .and_then(|&trace_id| self.traces.get(&trace_id))
    }

    /// Get all active trace IDs
    pub fn get_active_trace_ids(&self) -> Vec<u32> {
        self.traces
            .iter()
            .filter_map(|(&id, trace)| if trace.is_enabled { Some(id) } else { None })
            .collect()
    }

    /// Get all trace IDs
    pub fn get_all_trace_ids(&self) -> Vec<u32> {
        self.traces.keys().cloned().collect()
    }

    /// Get PC value for a trace
    pub fn get_trace_pc(&self, trace_id: u32) -> Option<u64> {
        self.traces.get(&trace_id).map(|t| t.pc)
    }

    /// Wait for events asynchronously from all active traces
    pub async fn wait_for_all_events_async(&mut self) -> Vec<ghostscope_protocol::EventData> {
        let mut all_events = Vec::new();

        // Create futures for all enabled traces
        let futures: Vec<_> = self
            .traces
            .iter_mut()
            .filter_map(|(&trace_id, trace)| {
                if trace.is_enabled {
                    Some(Box::pin(async move {
                        (trace_id, trace.wait_for_events_async().await)
                    }))
                } else {
                    None
                }
            })
            .collect();

        if !futures.is_empty() {
            // Use select_all to wait for any trace to have events
            match futures::future::select_all(futures).await {
                ((_trace_id, Ok(events)), _index, _remaining_futures) => {
                    for event in events {
                        all_events.push(event);
                    }
                }
                ((_trace_id, Err(e)), _index, _remaining_futures) => {
                    warn!("Error waiting for events from trace: {}", e);
                }
            }
        } else {
            // No active traces, wait for the first trace to be successfully enabled
            self.no_trace_wait_notify.notified().await;
        }

        all_events
    }

    /// Get trace count
    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }

    /// Get active trace count
    pub fn active_trace_count(&self) -> usize {
        self.traces.values().filter(|t| t.is_enabled).count()
    }

    /// Enable a specific trace by ID
    pub fn enable_trace(&mut self, trace_id: u32) -> Result<()> {
        // Check if this is the first trace being enabled (from 0 to 1)
        let was_no_active_traces = self.active_trace_count() == 0;

        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.enable()?;

            // If this was the first trace being enabled, notify waiters
            if was_no_active_traces && self.active_trace_count() == 1 {
                self.no_trace_wait_notify.notify_waiters();
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Disable a specific trace by ID
    pub fn disable_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.disable()
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Enable all traces
    pub fn enable_all_traces(&mut self) -> Result<()> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        for trace_id in trace_ids {
            if let Err(e) = self.enable_trace(trace_id) {
                warn!("Failed to enable trace {}: {}", trace_id, e);
            }
        }
        Ok(())
    }

    /// Disable all traces  
    pub fn disable_all_traces(&mut self) -> Result<()> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        for trace_id in trace_ids {
            if let Err(e) = self.disable_trace(trace_id) {
                warn!("Failed to disable trace {}: {}", trace_id, e);
            }
        }
        Ok(())
    }

    pub fn get_trace_snapshot(&self, trace_id: u32) -> Option<TraceSnapshot> {
        self.traces.get(&trace_id).map(|t| TraceSnapshot {
            trace_id: t.trace_id,
            target: t.target.clone(),
            script_content: t.script_content.clone(),
            binary_path: t.binary_path.clone(),
            target_display: t.target_display.clone(),
            target_pid: t.target_pid,
            is_enabled: t.is_enabled,
            pc: t.pc,
            ebpf_function_name: t.ebpf_function_name.clone(),
        })
    }

    /// Get summary statistics for all traces
    pub fn get_summary(&self) -> TraceSummary {
        let mut summary = TraceSummary::new();
        summary.total = self.traces.len();

        for trace in self.traces.values() {
            if trace.is_enabled {
                summary.active += 1;
            } else {
                summary.disabled += 1;
            }
        }

        summary
    }

    /// Format duration since creation
    fn format_duration(&self, trace_id: u32) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(&created_time) = self.trace_created_times.get(&trace_id) {
            let duration = now.saturating_sub(created_time);
            if duration < 60 {
                format!("{}s", duration)
            } else if duration < 3600 {
                format!("{}m{}s", duration / 60, duration % 60)
            } else {
                format!("{}h{}m", duration / 3600, (duration % 3600) / 60)
            }
        } else {
            "unknown".to_string()
        }
    }

    /// Get emoji for status
    fn status_emoji(is_enabled: bool) -> &'static str {
        if is_enabled {
            "✅"
        } else {
            "⏸️"
        }
    }

    /// Get formatted trace information for display
    pub fn get_formatted_trace_info(&self, trace_id: u32) -> Option<FormattedTraceInfo> {
        self.traces.get(&trace_id).map(|trace| {
            FormattedTraceInfo {
                trace_id,
                target_display: trace.target_display.clone(),
                binary_path: trace.binary_path.clone(),
                status: trace.status(),
                duration: self.format_duration(trace_id),
                script_preview: trace.script_preview(),
                pc: trace.pc,
                error_message: None, // Currently not tracking errors in TraceManager
            }
        })
    }

    /// Get all formatted trace information
    pub fn get_all_formatted_traces(&self) -> Vec<FormattedTraceInfo> {
        let mut traces: Vec<_> = self
            .traces
            .keys()
            .filter_map(|&id| self.get_formatted_trace_info(id))
            .collect();

        traces.sort_by_key(|t| t.trace_id);
        traces
    }

    /// Format complete trace status information as string
    pub fn format_all_traces_info(&self) -> String {
        let summary = self.get_summary();
        let mut output = format!("Trace Status: {}\n", summary.format());

        if summary.total > 0 {
            output.push_str("\nTrace Details:\n");
            let traces = self.get_all_formatted_traces();
            for trace in traces {
                output.push_str(&format!("  {}\n", trace.format_line()));
                // Add PC information
                output.push_str(&format!("    PC: 0x{:x}\n", trace.pc));
            }
        } else {
            output.push_str("No traces currently loaded.");
        }

        output
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

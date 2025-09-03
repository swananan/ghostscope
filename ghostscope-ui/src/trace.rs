use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::warn;

/// Trace status enum
#[derive(Debug, Clone, PartialEq)]
pub enum TraceStatus {
    Loading,  // Script is being compiled
    Active,   // Script is loaded and active (uprobe attached)
    Disabled, // Script is loaded but disabled (uprobe detached)
    Failed,   // Script failed to load
    Stopped,  // Script was stopped
}

/// Individual trace information
#[derive(Debug, Clone)]
pub struct TraceInfo {
    pub id: u32,                       // Sequential ID starting from 0
    pub target: String,                // Function or location being traced
    pub script_content: String,        // The actual script content
    pub status: TraceStatus,           // Current status
    pub created_time: u64,             // Unix timestamp when created
    pub last_updated: u64,             // Unix timestamp when last updated
    pub error_message: Option<String>, // Error message if failed
}

impl TraceInfo {
    pub fn new(id: u32, target: String, script_content: String) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            id,
            target,
            script_content,
            status: TraceStatus::Loading,
            created_time: now,
            last_updated: now,
            error_message: None,
        }
    }

    pub fn update_status(&mut self, status: TraceStatus, error_message: Option<String>) {
        self.status = status;
        self.error_message = error_message;
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    pub fn format_duration(&self, timestamp: u64) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let duration = now.saturating_sub(timestamp);
        if duration < 60 {
            format!("{}s", duration)
        } else if duration < 3600 {
            format!("{}m{}s", duration / 60, duration % 60)
        } else {
            format!("{}h{}m", duration / 3600, (duration % 3600) / 60)
        }
    }
}

/// Trace manager to handle all trace operations
#[derive(Debug)]
pub struct TraceManager {
    traces: HashMap<u32, TraceInfo>,
    next_id: u32,
}

impl TraceManager {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            next_id: 0,
        }
    }

    /// Add a new trace (when script compilation starts)
    pub fn add_trace(&mut self, target: String, script_content: String) -> u32 {
        let trace_id = self.next_id;
        self.next_id += 1;

        let trace_info = TraceInfo::new(trace_id, target.clone(), script_content);

        self.traces.insert(trace_id, trace_info);

        trace_id
    }

    /// Update trace status (when compilation completes or fails)
    pub fn update_trace_status(
        &mut self,
        trace_id: u32,
        status: TraceStatus,
        error_message: Option<String>,
    ) {
        if let Some(trace_info) = self.traces.get_mut(&trace_id) {
            trace_info.update_status(status, error_message);
        } else {
            warn!("Can not update script state with trace id {}", trace_id);
        }
    }

    /// Get trace info by ID
    pub fn get_trace(&self, id: u32) -> Option<&TraceInfo> {
        self.traces.get(&id)
    }

    /// Get all traces
    pub fn get_all_traces(&self) -> Vec<&TraceInfo> {
        let mut traces: Vec<_> = self.traces.values().collect();
        traces.sort_by_key(|t| t.id);
        traces
    }

    /// Get traces by status
    pub fn get_traces_by_status(&self, status: TraceStatus) -> Vec<&TraceInfo> {
        let mut traces: Vec<_> = self
            .traces
            .values()
            .filter(|t| t.status == status)
            .collect();
        traces.sort_by_key(|t| t.id);
        traces
    }

    /// Remove trace by ID
    pub fn remove_trace(&mut self, id: u32) -> Option<TraceInfo> {
        if let Some(trace_info) = self.traces.remove(&id) {
            Some(trace_info)
        } else {
            None
        }
    }

    pub fn remove_latest_trace(&mut self) {
        if self.traces.is_empty() {
            return;
        }

        self.next_id = self.next_id - 1;
        self.remove_trace(self.next_id);
    }

    /// Clear all traces
    pub fn clear_all_traces(&mut self) {
        self.traces.clear();
        // Reset ID counter to 0 since all traces are deleted
        self.next_id = 0;
    }

    /// Get summary statistics
    pub fn get_summary(&self) -> TraceSummary {
        let mut active = 0;
        let mut loading = 0;
        let mut failed = 0;
        let mut stopped = 0;

        for trace in self.traces.values() {
            match trace.status {
                TraceStatus::Active => active += 1,
                TraceStatus::Loading => loading += 1,
                TraceStatus::Disabled => stopped += 1, // Group disabled with stopped
                TraceStatus::Failed => failed += 1,
                TraceStatus::Stopped => stopped += 1,
            }
        }

        TraceSummary {
            total: self.traces.len(),
            active,
            loading,
            failed,
            stopped,
        }
    }

    /// Format trace info for display
    pub fn format_trace_info(&self, trace: &TraceInfo) -> String {
        let status_symbol = match trace.status {
            TraceStatus::Active => "✅",
            TraceStatus::Loading => "⏳",
            TraceStatus::Disabled => "⏸️", // Pause symbol for disabled
            TraceStatus::Failed => "❌",
            TraceStatus::Stopped => "⏹️",
        };

        let duration = trace.format_duration(trace.created_time);
        let mut info = format!(
            "{} [{}] {} - {} ({})",
            status_symbol,
            trace.id,
            trace.target,
            match trace.status {
                TraceStatus::Active => "Active",
                TraceStatus::Loading => "Loading",
                TraceStatus::Disabled => "Disabled",
                TraceStatus::Failed => "Failed",
                TraceStatus::Stopped => "Stopped",
            },
            duration
        );

        if let Some(ref error) = trace.error_message {
            info.push_str(&format!(" - Error: {}", error));
        }

        info
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of trace statistics
#[derive(Debug, Clone)]
pub struct TraceSummary {
    pub total: usize,
    pub active: usize,
    pub loading: usize,
    pub failed: usize,
    pub stopped: usize,
}

impl TraceSummary {
    pub fn format(&self) -> String {
        format!(
            "Total: {} | Active: {} | Loading: {} | Failed: {} | Stopped: {}",
            self.total, self.active, self.loading, self.failed, self.stopped
        )
    }
}

use anyhow::Result;
use futures::future;
use ghostscope_loader::GhostScopeLoader;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Individual trace instance with associated eBPF loader
#[derive(Debug)]
pub struct TraceInstance {
    pub trace_id: u32,
    pub target: String, // Target identifier for grouping (e.g., "test_program:L15")
    pub script_content: String, // Original script content
    pub loader: GhostScopeLoader, // eBPF loader for this specific trace
    pub binary_path: String, // Binary being traced
    pub target_display: String, // Display name for UI (e.g., "main", "file.c:15")
    pub uprobe_offset: Option<u64>, // Uprobe offset (required for attachment)
    pub target_pid: Option<u32>, // Target PID if specified
    pub is_enabled: bool, // Whether the uprobe is currently enabled
}

impl TraceInstance {
    pub fn new(
        trace_id: u32,
        target: String,
        script_content: String,
        loader: GhostScopeLoader,
        binary_path: String,
        target_display: String,
        uprobe_offset: Option<u64>,
        target_pid: Option<u32>,
    ) -> Self {
        Self {
            trace_id,
            target,
            script_content,
            loader,
            binary_path,
            target_display,
            uprobe_offset,
            target_pid,
            is_enabled: false,
        }
    }

    /// Enable this trace instance (attach uprobe)
    pub async fn enable(&mut self) -> Result<()> {
        if self.is_enabled {
            info!("Trace {} is already enabled", self.trace_id);
            return Ok(());
        }

        info!(
            "Enabling trace {} for target '{}' in binary '{}'",
            self.trace_id, self.target_display, self.binary_path
        );

        // If the loader already has attachment parameters stored (from previous attach),
        // use reattach_uprobe instead of attach_uprobe to avoid reloading the program
        if self.loader.is_uprobe_attached() {
            // This should not happen since we checked is_enabled above
            warn!("Uprobe is already attached for trace {}", self.trace_id);
            return Ok(());
        } else if self.loader.get_attachment_info().is_some() {
            // Attachment parameters exist, this means the program was loaded before
            // Use reattach_uprobe to avoid reloading the program
            info!(
                "Using reattach_uprobe for trace {} (program already loaded)",
                self.trace_id
            );
            self.loader.reattach_uprobe()?;
        } else {
            // First time attachment, use attach_uprobe
            info!(
                "Using attach_uprobe for trace {} (first time)",
                self.trace_id
            );
            self.loader.attach_uprobe(
                &self.binary_path,
                &self.target_display, // Used only for logging; actual attachment uses uprobe_offset
                self.uprobe_offset,
                self.target_pid.map(|pid| pid as i32),
            )?;
        }

        self.is_enabled = true;
        info!("Trace {} enabled successfully", self.trace_id);
        Ok(())
    }

    /// Disable this trace instance (detach uprobe but keep eBPF resources)
    pub async fn disable(&mut self) -> Result<()> {
        if !self.is_enabled {
            info!("Trace {} is already disabled", self.trace_id);
            return Ok(());
        }

        info!("Disabling trace {}", self.trace_id);
        // Detach the uprobe while keeping eBPF resources
        self.loader.detach_uprobe()?;
        self.is_enabled = false;
        info!("Trace {} disabled successfully", self.trace_id);
        Ok(())
    }

    /// Wait for events asynchronously from this trace instance
    pub async fn wait_for_events_async(&mut self) -> Result<Vec<ghostscope_protocol::EventData>> {
        if !self.is_enabled {
            return Ok(Vec::new());
        }

        match self.loader.wait_for_events_async().await {
            Ok(events) => {
                // Return EventData directly, no need to convert to strings
                Ok(events)
            }
            Err(e) => {
                warn!(
                    "Error waiting for events from trace {}: {}",
                    self.trace_id, e
                );
                Err(e.into())
            }
        }
    }
}

/// Manager for all active trace instances
#[derive(Debug)]
pub struct TraceManager {
    traces: HashMap<u32, TraceInstance>,
    next_trace_id: u32,
    target_to_trace_id: HashMap<String, u32>, // Map target name to trace_id
}

impl TraceManager {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            next_trace_id: 0,
            target_to_trace_id: HashMap::new(),
        }
    }

    /// Add a new trace instance
    pub fn add_trace(
        &mut self,
        target: String,
        script_content: String,
        loader: GhostScopeLoader,
        binary_path: String,
        target_display: String,
        uprobe_offset: Option<u64>,
        target_pid: Option<u32>,
    ) -> u32 {
        let trace_id = self.next_trace_id;
        self.next_trace_id += 1;

        // Create unique target key by combining target with trace_id
        // This allows multiple traces for the same target (e.g., same function/line)
        let unique_target = format!("{}#{}", target, trace_id);

        let trace_instance = TraceInstance::new(
            trace_id,
            target.clone(), // Keep original target for grouping
            script_content,
            loader,
            binary_path,
            target_display,
            uprobe_offset,
            target_pid,
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
    pub async fn activate_trace(&mut self, trace_id: u32) -> Result<()> {
        self.enable_trace(trace_id).await
    }

    /// Disable a trace by ID (duplicate of disable_trace method - keeping for compatibility)
    pub async fn deactivate_trace(&mut self, trace_id: u32) -> Result<()> {
        self.disable_trace(trace_id).await
    }

    /// Remove a trace by ID (legacy method, use delete_trace for complete cleanup)
    pub async fn remove_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(mut trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping
            self.target_to_trace_id.remove(&trace.target);

            // Disable if still active
            trace.disable().await?;

            debug!("Removed trace {} from manager", trace_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Completely delete a trace by ID, destroying all associated resources
    pub async fn delete_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(mut trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping
            self.target_to_trace_id.remove(&trace.target);

            info!("Deleting trace {} and all associated resources", trace_id);

            // Completely destroy the loader and all eBPF resources
            trace.loader.destroy()?;

            info!("Trace {} deleted successfully", trace_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Delete all traces, destroying all associated resources
    pub async fn delete_all_traces(&mut self) -> Result<usize> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        let count = trace_ids.len();

        info!("Deleting all {} traces and their resources", count);

        for trace_id in trace_ids {
            if let Err(e) = self.delete_trace(trace_id).await {
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
                ((trace_id, Ok(events)), _index, _remaining_futures) => {
                    for event in events {
                        all_events.push(event);
                    }
                }
                ((trace_id, Err(e)), _index, _remaining_futures) => {
                    warn!("Error waiting for events from trace {}: {}", trace_id, e);
                }
            }
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
    pub async fn enable_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.enable().await
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Disable a specific trace by ID
    pub async fn disable_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.disable().await
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Enable all traces
    pub async fn enable_all_traces(&mut self) -> Result<()> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        for trace_id in trace_ids {
            if let Err(e) = self.enable_trace(trace_id).await {
                warn!("Failed to enable trace {}: {}", trace_id, e);
            }
        }
        Ok(())
    }

    /// Disable all traces  
    pub async fn disable_all_traces(&mut self) -> Result<()> {
        let trace_ids: Vec<u32> = self.traces.keys().cloned().collect();
        for trace_id in trace_ids {
            if let Err(e) = self.disable_trace(trace_id).await {
                warn!("Failed to disable trace {}: {}", trace_id, e);
            }
        }
        Ok(())
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

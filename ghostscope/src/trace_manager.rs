use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use std::collections::HashMap;
use tracing::{debug, info, warn};

/// Individual trace instance with associated eBPF loader
#[derive(Debug)]
pub struct TraceInstance {
    pub trace_id: u32,
    pub target: String,             // Function name or target identifier
    pub script_content: String,     // Original script content
    pub loader: GhostScopeLoader,   // eBPF loader for this specific trace
    pub binary_path: String,        // Binary being traced
    pub function_name: String,      // Specific function being traced
    pub uprobe_offset: Option<u64>, // Uprobe offset if calculated
    pub target_pid: Option<u32>,    // Target PID if specified
    pub is_active: bool,            // Whether the trace is currently active
}

impl TraceInstance {
    pub fn new(
        trace_id: u32,
        target: String,
        script_content: String,
        loader: GhostScopeLoader,
        binary_path: String,
        function_name: String,
        uprobe_offset: Option<u64>,
        target_pid: Option<u32>,
    ) -> Self {
        Self {
            trace_id,
            target,
            script_content,
            loader,
            binary_path,
            function_name,
            uprobe_offset,
            target_pid,
            is_active: false,
        }
    }

    /// Activate this trace instance (attach uprobe)
    pub async fn activate(&mut self) -> Result<()> {
        info!(
            "Activating trace {} for function '{}' in binary '{}'",
            self.trace_id, self.function_name, self.binary_path
        );

        self.loader.attach_uprobe(
            &self.binary_path,
            &self.function_name,
            self.uprobe_offset,
            self.target_pid.map(|pid| pid as i32),
        )?;

        self.is_active = true;
        info!("Trace {} activated successfully", self.trace_id);
        Ok(())
    }

    /// Deactivate this trace instance
    pub async fn deactivate(&mut self) -> Result<()> {
        if self.is_active {
            info!("Deactivating trace {}", self.trace_id);
            // Note: GhostScopeLoader doesn't have explicit detach yet,
            // so we just mark as inactive for now
            self.is_active = false;
        }
        Ok(())
    }

    /// Poll events from this trace instance
    pub fn poll_events(&mut self) -> Result<Option<Vec<String>>> {
        if !self.is_active {
            return Ok(None);
        }

        match self.loader.poll_events() {
            Ok(Some(events)) => {
                // Add trace_id context to each event
                let traced_events = events
                    .into_iter()
                    .map(|event| format!("[Trace {}] {}", self.trace_id, event))
                    .collect();
                Ok(Some(traced_events))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                warn!("Error polling events from trace {}: {}", self.trace_id, e);
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
        function_name: String,
        uprobe_offset: Option<u64>,
        target_pid: Option<u32>,
    ) -> u32 {
        let trace_id = self.next_trace_id;
        self.next_trace_id += 1;

        // Remove any existing trace for this target
        if let Some(old_trace_id) = self.target_to_trace_id.remove(&target) {
            if let Some(mut old_trace) = self.traces.remove(&old_trace_id) {
                // Deactivate the old trace
                tokio::spawn(async move {
                    if let Err(e) = old_trace.deactivate().await {
                        warn!("Failed to deactivate old trace {}: {}", old_trace_id, e);
                    }
                });
            }
        }

        let trace_instance = TraceInstance::new(
            trace_id,
            target.clone(),
            script_content,
            loader,
            binary_path,
            function_name,
            uprobe_offset,
            target_pid,
        );

        self.traces.insert(trace_id, trace_instance);
        self.target_to_trace_id.insert(target, trace_id);

        debug!("Added trace {} to manager", trace_id);
        trace_id
    }

    /// Activate a trace by ID
    pub async fn activate_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.activate().await
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Deactivate a trace by ID
    pub async fn deactivate_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.deactivate().await
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Remove a trace by ID
    pub async fn remove_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(mut trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping
            self.target_to_trace_id.remove(&trace.target);

            // Deactivate if still active
            trace.deactivate().await?;

            debug!("Removed trace {} from manager", trace_id);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
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
            .filter_map(|(&id, trace)| if trace.is_active { Some(id) } else { None })
            .collect()
    }

    /// Get all trace IDs
    pub fn get_all_trace_ids(&self) -> Vec<u32> {
        self.traces.keys().cloned().collect()
    }

    /// Poll events from all active traces
    pub fn poll_all_events(&mut self) -> Vec<(u32, String)> {
        let mut all_events = Vec::new();

        for (&trace_id, trace) in self.traces.iter_mut() {
            if trace.is_active {
                match trace.poll_events() {
                    Ok(Some(events)) => {
                        for event in events {
                            all_events.push((trace_id, event));
                        }
                    }
                    Ok(None) => {
                        // No events from this trace
                    }
                    Err(e) => {
                        warn!("Error polling events from trace {}: {}", trace_id, e);
                    }
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
        self.traces.values().filter(|t| t.is_active).count()
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

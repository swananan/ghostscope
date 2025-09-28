use crate::tracing::instance::TraceInstance;
use crate::tracing::snapshot::{TraceSnapshot, TraceSummary};
use anyhow::Result;
use futures::future::{select_all, BoxFuture};
use futures::FutureExt;
use ghostscope_loader::GhostScopeLoader;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

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
            next_trace_id: ghostscope_protocol::consts::DEFAULT_TRACE_ID as u32,
            target_to_trace_id: HashMap::new(),
            no_trace_wait_notify: Notify::new(),
            trace_created_times: HashMap::new(),
        }
    }

    /// Get the current next trace ID without reserving it
    /// This is used for script compilation to know the starting trace ID
    pub fn get_next_trace_id(&self) -> u32 {
        self.next_trace_id
    }

    /// Add a new trace instance with a pre-allocated trace ID
    #[allow(clippy::too_many_arguments)]
    pub fn add_trace_with_id(
        &mut self,
        trace_id: u32,
        target: String,
        script_content: String,
        pc: u64,
        binary_path: String,
        target_display: String,
        target_pid: Option<u32>,
        loader: Option<GhostScopeLoader>,
        ebpf_function_name: String,
    ) -> u32 {
        // Use the provided trace_id and ensure next_trace_id is updated to maintain proper ordering
        // This prevents ID conflicts and ensures IDs only increment
        if trace_id >= self.next_trace_id {
            self.next_trace_id = trace_id + 1;
        }

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
            "Added trace {} to manager with target '{}', next_trace_id updated to {}",
            trace_id, target, self.next_trace_id
        );
        trace_id
    }

    /// Completely delete a trace by ID, destroying all associated resources
    pub fn delete_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping using the correct unique target key
            let unique_target = format!("{}#{}", trace.target, trace_id);
            self.target_to_trace_id.remove(&unique_target);
            // Remove creation time
            self.trace_created_times.remove(&trace_id);

            info!("Deleted trace {} with target '{}'", trace_id, trace.target);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {} not found", trace_id))
        }
    }

    /// Delete all traces
    pub fn delete_all_traces(&mut self) -> Result<usize> {
        let count = self.traces.len();
        self.traces.clear();
        self.target_to_trace_id.clear();
        self.trace_created_times.clear();
        info!("Deleted all {} traces", count);
        Ok(count)
    }

    /// Get count of active (enabled) traces
    pub fn active_trace_count(&self) -> usize {
        self.traces.values().filter(|t| t.is_enabled).count()
    }

    /// Get all trace IDs
    pub fn get_all_trace_ids(&self) -> Vec<u32> {
        self.traces.keys().cloned().collect()
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

    /// Get a snapshot of a specific trace
    pub fn get_trace_snapshot(&self, trace_id: u32) -> Option<TraceSnapshot> {
        self.traces.get(&trace_id).map(|trace| TraceSnapshot {
            trace_id: trace.trace_id,
            target: trace.target.clone(),
            script_content: trace.script_content.clone(),
            binary_path: trace.binary_path.clone(),
            target_display: trace.target_display.clone(),
            target_pid: trace.target_pid,
            is_enabled: trace.is_enabled,
            pc: trace.pc,
            ebpf_function_name: trace.ebpf_function_name.clone(),
        })
    }

    /// Get summary of all traces
    pub fn get_summary(&self) -> TraceSummary {
        let total = self.traces.len();
        let active = self.active_trace_count();
        let disabled = total - active;

        TraceSummary {
            total,
            active,
            disabled,
        }
    }

    /// Wait for the first trace to be enabled (for TUI mode to avoid busy waiting)
    pub async fn wait_for_first_trace(&self) {
        self.no_trace_wait_notify.notified().await;
    }

    /// Wait for events from all active traces using futures::select_all
    pub async fn wait_for_all_events_async(
        &mut self,
    ) -> Vec<ghostscope_protocol::ParsedTraceEvent> {
        loop {
            let futures: Vec<
                BoxFuture<
                    '_,
                    (
                        u32,
                        anyhow::Result<Vec<ghostscope_protocol::ParsedTraceEvent>>,
                    ),
                >,
            > = self
                .traces
                .iter_mut()
                .filter_map(|(&trace_id, trace)| {
                    if trace.is_enabled {
                        Some(async move { (trace_id, trace.wait_for_events_async().await) }.boxed())
                    } else {
                        None
                    }
                })
                .collect();

            if futures.is_empty() {
                drop(futures);
                self.wait_for_first_trace().await;
                continue;
            }

            let ((trace_id, result), _index, remaining) = select_all(futures).await;

            let mut aggregated_events = Vec::new();

            match result {
                Ok(events) => {
                    aggregated_events.extend(events);
                }
                Err(e) => {
                    warn!("Error waiting for events from trace {}: {}", trace_id, e);
                }
            }

            for future in remaining {
                if let Some((trace_id, result)) = future.now_or_never() {
                    match result {
                        Ok(events) => {
                            aggregated_events.extend(events);
                        }
                        Err(e) => {
                            warn!("Error waiting for events from trace {}: {}", trace_id, e);
                        }
                    }
                }
            }

            if !aggregated_events.is_empty() {
                return aggregated_events;
            }
            // No events received after draining ready traces, continue looping.
        }
    }

    /// Get all traces for save/export operations
    pub fn get_all_traces(&self) -> Vec<&TraceInstance> {
        self.traces.values().collect()
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

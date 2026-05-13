use crate::trace::instance::{TraceInstance, TraceInstanceArgs, TracePidContext};
use crate::trace::snapshot::{TraceSnapshot, TraceSummary};
use anyhow::Result;
use futures::future::{select_all, BoxFuture};
use futures::FutureExt;
use ghostscope_loader::{EventLossStats, GhostScopeLoader};
use ghostscope_protocol::ParsedTraceEvent;
use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

const MAX_AGGREGATED_EVENTS_PER_WAIT: usize = 1024;

/// Manager for all active trace instances
#[derive(Debug)]
pub struct TraceManager {
    traces: HashMap<u32, TraceInstance>,
    next_trace_id: u32,
    target_to_trace_id: HashMap<String, u32>, // Map target name to trace_id
    no_trace_wait_notify: Notify,             // Notify when first trace is successfully enabled
    // Track creation timestamps for duration calculation
    trace_created_times: HashMap<u32, u64>,
    pending_events: VecDeque<ParsedTraceEvent>,
    last_reported_event_loss: HashMap<u32, EventLossStats>,
}

/// Parameters for adding a new trace with a pre-allocated ID
#[derive(Debug)]
pub struct AddTraceParams {
    pub trace_id: u32,
    pub target: String,
    pub script_content: String,
    pub pc: u64,
    pub binary_path: String,
    pub target_display: String,
    pub pid_context: TracePidContext,
    pub loader: Option<GhostScopeLoader>,
    pub ebpf_function_name: String,
    pub address_global_index: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventLossReport {
    pub trace_id: u32,
    pub target_display: String,
    pub lost_since_last: u64,
    pub lost_total: u64,
}

impl TraceManager {
    pub fn new() -> Self {
        Self {
            traces: HashMap::new(),
            next_trace_id: ghostscope_protocol::consts::DEFAULT_TRACE_ID as u32,
            target_to_trace_id: HashMap::new(),
            no_trace_wait_notify: Notify::new(),
            trace_created_times: HashMap::new(),
            pending_events: VecDeque::new(),
            last_reported_event_loss: HashMap::new(),
        }
    }

    /// Get the current next trace ID without reserving it
    /// This is used for script compilation to know the starting trace ID
    pub fn get_next_trace_id(&self) -> u32 {
        self.next_trace_id
    }

    /// Add a new trace instance with a pre-allocated trace ID
    pub fn add_trace_with_id(&mut self, params: AddTraceParams) -> u32 {
        // Use the provided trace_id and ensure next_trace_id is updated to maintain proper ordering
        // This prevents ID conflicts and ensures IDs only increment
        if params.trace_id >= self.next_trace_id {
            self.next_trace_id = params.trace_id + 1;
        }

        // Record creation time
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.trace_created_times.insert(params.trace_id, now);

        // Create unique target key by combining target with trace_id
        // This allows multiple traces for the same target (e.g., same function/line)
        let unique_target = format!("{}#{}", params.target, params.trace_id);

        let trace_instance = TraceInstance::new(TraceInstanceArgs {
            trace_id: params.trace_id,
            target: params.target.clone(),
            script_content: params.script_content,
            pc: params.pc,
            binary_path: params.binary_path,
            target_display: params.target_display,
            pid_context: params.pid_context,
            loader: params.loader,
            ebpf_function_name: params.ebpf_function_name,
            address_global_index: params.address_global_index,
        });

        self.traces.insert(params.trace_id, trace_instance);
        self.target_to_trace_id
            .insert(unique_target, params.trace_id);

        debug!(
            "Added trace {} to manager with target '{}', next_trace_id updated to {}",
            params.trace_id, params.target, self.next_trace_id
        );
        params.trace_id
    }

    /// Completely delete a trace by ID, destroying all associated resources
    pub fn delete_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping using the correct unique target key
            let unique_target = format!("{}#{}", trace.target, trace_id);
            self.target_to_trace_id.remove(&unique_target);
            // Remove creation time
            self.trace_created_times.remove(&trace_id);
            self.pending_events
                .retain(|event| event.trace_id != trace_id as u64);
            self.last_reported_event_loss.remove(&trace_id);

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
        self.pending_events.clear();
        self.last_reported_event_loss.clear();
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
            pid_context: trace.pid_context,
            is_enabled: trace.is_enabled,
            pc: trace.pc,
            ebpf_function_name: trace.ebpf_function_name.clone(),
            address_global_index: trace.address_global_index,
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

    pub fn collect_event_loss_reports(&mut self) -> Vec<EventLossReport> {
        let mut reports = Vec::new();

        for (&trace_id, trace) in self.traces.iter() {
            let stats = match trace.read_event_loss_stats() {
                Ok(Some(stats)) => stats,
                Ok(None) => continue,
                Err(err) => {
                    warn!(
                        "Failed to read eBPF event loss counters for trace {}: {}",
                        trace_id, err
                    );
                    continue;
                }
            };

            let previous = self
                .last_reported_event_loss
                .get(&trace_id)
                .copied()
                .unwrap_or_default();
            let delta = stats.saturating_sub(previous);
            if delta.is_empty() {
                continue;
            }

            self.last_reported_event_loss.insert(trace_id, stats);
            reports.push(EventLossReport {
                trace_id,
                target_display: trace.target_display.clone(),
                lost_since_last: delta.output_failures,
                lost_total: stats.output_failures,
            });
        }

        reports
    }

    /// Wait for the first trace to be enabled (for TUI mode to avoid busy waiting)
    pub async fn wait_for_first_trace(&self) {
        self.no_trace_wait_notify.notified().await;
    }

    /// Wait for events from all active traces using futures::select_all
    pub async fn wait_for_all_events_async(&mut self) -> anyhow::Result<Vec<ParsedTraceEvent>> {
        loop {
            if let Some(events) = self.take_pending_events() {
                return Ok(events);
            }

            let futures: Vec<BoxFuture<'_, (u32, anyhow::Result<Vec<ParsedTraceEvent>>)>> = self
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
            let mut deferred_by_batch_limit = 0usize;

            match result {
                Ok(events) => {
                    deferred_by_batch_limit += append_with_limit(
                        &mut aggregated_events,
                        events,
                        &mut self.pending_events,
                        MAX_AGGREGATED_EVENTS_PER_WAIT,
                    );
                }
                Err(e) => {
                    // Fatal errors should be propagated to the caller
                    error!(
                        "Fatal error waiting for events from trace {}: {}",
                        trace_id, e
                    );
                    return Err(e);
                }
            }

            for future in remaining {
                if aggregated_events.len() >= MAX_AGGREGATED_EVENTS_PER_WAIT {
                    break;
                }
                if let Some((trace_id, result)) = future.now_or_never() {
                    match result {
                        Ok(events) => {
                            deferred_by_batch_limit += append_with_limit(
                                &mut aggregated_events,
                                events,
                                &mut self.pending_events,
                                MAX_AGGREGATED_EVENTS_PER_WAIT,
                            );
                        }
                        Err(e) => {
                            // Fatal errors should be propagated to the caller
                            error!(
                                "Fatal error waiting for events from trace {}: {}",
                                trace_id, e
                            );
                            return Err(e);
                        }
                    }
                }
            }

            if !aggregated_events.is_empty() {
                if deferred_by_batch_limit > 0 {
                    debug!(
                        "Trace manager batch limit reached ({} events returned, {} parsed events deferred)",
                        aggregated_events.len(),
                        deferred_by_batch_limit
                    );
                }
                return Ok(aggregated_events);
            }
            // No events received after draining ready traces, continue looping.
        }
    }

    fn take_pending_events(&mut self) -> Option<Vec<ParsedTraceEvent>> {
        if self.pending_events.is_empty() {
            return None;
        }

        let take_count = self
            .pending_events
            .len()
            .min(MAX_AGGREGATED_EVENTS_PER_WAIT);
        let mut events = Vec::with_capacity(take_count);
        for _ in 0..take_count {
            if let Some(event) = self.pending_events.pop_front() {
                events.push(event);
            }
        }
        Some(events)
    }
}

fn append_with_limit<T>(
    dst: &mut Vec<T>,
    mut src: Vec<T>,
    pending: &mut VecDeque<T>,
    limit: usize,
) -> usize {
    if dst.len() >= limit {
        let deferred = src.len();
        pending.extend(src);
        return deferred;
    }

    let remaining = limit - dst.len();
    if src.len() <= remaining {
        dst.extend(src);
        0
    } else {
        let deferred_events = src.split_off(remaining);
        let deferred = deferred_events.len();
        dst.extend(src);
        pending.extend(deferred_events);
        deferred
    }
}

impl Default for TraceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{append_with_limit, TraceManager, MAX_AGGREGATED_EVENTS_PER_WAIT};
    use ghostscope_protocol::ParsedTraceEvent;
    use std::collections::VecDeque;

    fn event(trace_id: u64) -> ParsedTraceEvent {
        ParsedTraceEvent {
            trace_id,
            timestamp: 0,
            pid: 0,
            tid: 0,
            instructions: Vec::new(),
        }
    }

    #[test]
    fn append_with_limit_preserves_capacity_under_limit() {
        let mut dst = vec![1, 2];
        let mut pending = VecDeque::new();
        let deferred = append_with_limit(&mut dst, vec![3, 4], &mut pending, 5);

        assert_eq!(deferred, 0);
        assert_eq!(dst, vec![1, 2, 3, 4]);
        assert!(pending.is_empty());
    }

    #[test]
    fn append_with_limit_defers_overflow_items() {
        let mut dst = vec![1, 2];
        let mut pending = VecDeque::new();
        let deferred = append_with_limit(&mut dst, vec![3, 4, 5], &mut pending, 4);

        assert_eq!(deferred, 1);
        assert_eq!(dst, vec![1, 2, 3, 4]);
        assert_eq!(pending.into_iter().collect::<Vec<_>>(), vec![5]);
    }

    #[test]
    fn append_with_limit_defers_all_items_when_full() {
        let mut dst = vec![1, 2];
        let mut pending = VecDeque::new();
        let deferred = append_with_limit(&mut dst, vec![3, 4], &mut pending, 2);

        assert_eq!(deferred, 2);
        assert_eq!(dst, vec![1, 2]);
        assert_eq!(pending.into_iter().collect::<Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn pending_events_are_returned_before_polling_traces() {
        let mut manager = TraceManager::new();
        for i in 0..(MAX_AGGREGATED_EVENTS_PER_WAIT + 1) {
            manager.pending_events.push_back(event(i as u64));
        }

        let first = manager.take_pending_events().unwrap();
        assert_eq!(first.len(), MAX_AGGREGATED_EVENTS_PER_WAIT);
        assert_eq!(first.first().map(|event| event.trace_id), Some(0));
        assert_eq!(
            first.last().map(|event| event.trace_id),
            Some((MAX_AGGREGATED_EVENTS_PER_WAIT - 1) as u64)
        );

        let second = manager.take_pending_events().unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(
            second.first().map(|event| event.trace_id),
            Some(MAX_AGGREGATED_EVENTS_PER_WAIT as u64)
        );
        assert!(manager.take_pending_events().is_none());
    }
}

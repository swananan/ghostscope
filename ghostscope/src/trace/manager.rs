use crate::trace::actor::{
    spawn_trace_actor, TraceActorConfig, TraceActorEvent, TraceActorFatal,
    TRACE_EVENT_CHANNEL_CAPACITY,
};
use crate::trace::instance::{TraceInstance, TraceInstanceArgs, TracePidContext};
use crate::trace::snapshot::{TraceSnapshot, TraceSummary};
use anyhow::Result;
use ghostscope_loader::{BacktraceUnwindRowsAppendStats, EventLossStats, GhostScopeLoader};
use ghostscope_protocol::BacktraceUnwindRow;
use ghostscope_protocol::ParsedTraceEvent;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const MAX_AGGREGATED_EVENTS_PER_WAIT: usize = 1024;

/// Manager for all active trace instances
#[derive(Debug)]
pub struct TraceManager {
    traces: HashMap<u32, TraceInstance>,
    next_trace_id: u32,
    target_to_trace_id: HashMap<String, u32>, // Map target name to trace_id
    // Track creation timestamps for duration calculation
    trace_created_times: HashMap<u32, u64>,
    event_sender: mpsc::Sender<TraceActorEvent>,
    event_receiver: mpsc::Receiver<TraceActorEvent>,
    fatal_sender: mpsc::UnboundedSender<TraceActorFatal>,
    fatal_receiver: mpsc::UnboundedReceiver<TraceActorFatal>,
    pending_events: VecDeque<ParsedTraceEvent>,
    pending_error: Option<anyhow::Error>,
    minimum_event_generations: HashMap<u32, u64>,
    last_reported_event_loss: HashMap<u32, EventLossStats>,
    last_reported_delivery_loss: HashMap<u32, u64>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDeliveryLossReport {
    pub trace_id: u32,
    pub target_display: String,
    pub dropped_since_last: u64,
    pub dropped_total: u64,
}

#[derive(Debug, Default)]
pub struct TraceLossReports {
    pub kernel: Vec<EventLossReport>,
    pub delivery: Vec<EventDeliveryLossReport>,
}

impl TraceManager {
    pub fn new() -> Self {
        let (event_sender, event_receiver) = mpsc::channel(TRACE_EVENT_CHANNEL_CAPACITY);
        let (fatal_sender, fatal_receiver) = mpsc::unbounded_channel();
        Self {
            traces: HashMap::new(),
            next_trace_id: ghostscope_protocol::consts::DEFAULT_TRACE_ID as u32,
            target_to_trace_id: HashMap::new(),
            trace_created_times: HashMap::new(),
            event_sender,
            event_receiver,
            fatal_sender,
            fatal_receiver,
            pending_events: VecDeque::new(),
            pending_error: None,
            minimum_event_generations: HashMap::new(),
            last_reported_event_loss: HashMap::new(),
            last_reported_delivery_loss: HashMap::new(),
        }
    }

    /// Get the current next trace ID without reserving it
    /// This is used for script compilation to know the starting trace ID
    pub fn get_next_trace_id(&self) -> u32 {
        self.next_trace_id
    }

    pub fn event_channel_capacity(&self) -> usize {
        TRACE_EVENT_CHANNEL_CAPACITY
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
        self.minimum_event_generations.insert(params.trace_id, 0);

        // Create unique target key by combining target with trace_id
        // This allows multiple traces for the same target (e.g., same function/line)
        let unique_target = format!("{}#{}", params.target, params.trace_id);

        let actor = params.loader.map(|loader| {
            spawn_trace_actor(
                loader,
                TraceActorConfig {
                    trace_id: params.trace_id,
                    target_display: params.target_display.clone(),
                    pc: params.pc,
                    binary_path: params.binary_path.clone(),
                    pid_context: params.pid_context,
                    ebpf_function_name: params.ebpf_function_name.clone(),
                },
                self.event_sender.clone(),
                self.fatal_sender.clone(),
            )
        });

        let trace_instance = TraceInstance::new(TraceInstanceArgs {
            trace_id: params.trace_id,
            target: params.target.clone(),
            script_content: params.script_content,
            pc: params.pc,
            binary_path: params.binary_path,
            target_display: params.target_display,
            pid_context: params.pid_context,
            actor,
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
    pub async fn delete_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get(&trace_id) {
            trace.delete().await?;
        }

        if let Some(trace) = self.traces.remove(&trace_id) {
            // Remove from target mapping using the correct unique target key
            let unique_target = format!("{}#{}", trace.target, trace_id);
            self.target_to_trace_id.remove(&unique_target);
            // Remove creation time
            self.trace_created_times.remove(&trace_id);
            self.pending_events
                .retain(|event| event.trace_id != trace_id as u64);
            self.minimum_event_generations.remove(&trace_id);
            self.last_reported_event_loss.remove(&trace_id);
            self.last_reported_delivery_loss.remove(&trace_id);

            info!("Deleted trace {} with target '{}'", trace_id, trace.target);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {trace_id} not found"))
        }
    }

    /// Delete all traces
    pub async fn delete_all_traces(&mut self) -> Result<usize> {
        let count = self.traces.len();
        let trace_ids = self.get_all_trace_ids();
        for trace_id in trace_ids {
            self.delete_trace(trace_id).await?;
        }
        self.pending_events.clear();
        self.pending_error = None;
        self.minimum_event_generations.clear();
        self.last_reported_event_loss.clear();
        self.last_reported_delivery_loss.clear();
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
    pub async fn enable_trace(&mut self, trace_id: u32) -> Result<()> {
        // Check if this is the first trace being enabled (from 0 to 1)
        let was_no_active_traces = self.active_trace_count() == 0;

        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.enable().await?;

            if was_no_active_traces {
                debug!(trace_id, "First trace actor enabled");
            }

            Ok(())
        } else {
            Err(anyhow::anyhow!("Trace {trace_id} not found"))
        }
    }

    /// Disable a specific trace by ID
    pub async fn disable_trace(&mut self, trace_id: u32) -> Result<()> {
        if let Some(trace) = self.traces.get_mut(&trace_id) {
            trace.disable().await
        } else {
            Err(anyhow::anyhow!("Trace {trace_id} not found"))
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

    pub async fn collect_event_loss_reports(&mut self) -> TraceLossReports {
        let mut reports = TraceLossReports::default();

        for (&trace_id, trace) in self.traces.iter() {
            let stats = match trace.read_loss_stats().await {
                Ok(stats) => stats,
                Err(err) => {
                    warn!(
                        "Failed to read event loss counters for trace {}: {}",
                        trace_id, err
                    );
                    continue;
                }
            };

            if let Some(kernel_stats) = stats.kernel {
                let previous = self
                    .last_reported_event_loss
                    .get(&trace_id)
                    .copied()
                    .unwrap_or_default();
                let delta = kernel_stats.saturating_sub(previous);
                if !delta.is_empty() {
                    self.last_reported_event_loss.insert(trace_id, kernel_stats);
                    reports.kernel.push(EventLossReport {
                        trace_id,
                        target_display: trace.target_display.clone(),
                        lost_since_last: delta.output_failures,
                        lost_total: kernel_stats.output_failures,
                    });
                }
            }

            let previous_delivery = self
                .last_reported_delivery_loss
                .get(&trace_id)
                .copied()
                .unwrap_or_default();
            let delivery_delta = stats.delivery_dropped.saturating_sub(previous_delivery);
            if delivery_delta > 0 {
                self.last_reported_delivery_loss
                    .insert(trace_id, stats.delivery_dropped);
                reports.delivery.push(EventDeliveryLossReport {
                    trace_id,
                    target_display: trace.target_display.clone(),
                    dropped_since_last: delivery_delta,
                    dropped_total: stats.delivery_dropped,
                });
            }
        }

        reports
    }

    pub async fn append_backtrace_unwind_rows_for_modules(
        &mut self,
        modules: &[(u64, Vec<BacktraceUnwindRow>)],
    ) -> BacktraceUnwindRowsAppendStats {
        let mut total = BacktraceUnwindRowsAppendStats::default();
        if modules.is_empty() {
            return total;
        }

        let modules = Arc::new(modules.to_vec());
        let trace_ids = self.get_all_trace_ids();
        for trace_id in trace_ids {
            let update = {
                let Some(trace) = self.traces.get(&trace_id) else {
                    continue;
                };
                trace.append_backtrace_rows(Arc::clone(&modules)).await
            };
            match update {
                Ok(update) => {
                    let stats = update.stats;
                    if stats.modules > 0 {
                        self.require_event_generation(trace_id, update.event_generation);
                        debug!(
                            trace_id,
                            modules = stats.modules,
                            rows = stats.rows,
                            "Appended runtime DWARF bt unwind rows to trace"
                        );
                        total.modules += stats.modules;
                        total.rows += stats.rows;
                    }
                }
                Err(err) => {
                    warn!(
                        trace_id,
                        "Failed to append runtime DWARF bt unwind rows: {}", err
                    );
                }
            }
        }

        total
    }

    fn require_event_generation(&mut self, trace_id: u32, generation: u64) {
        let minimum = self.minimum_event_generations.entry(trace_id).or_default();
        if generation <= *minimum {
            return;
        }

        *minimum = generation;
        // Events deferred by the aggregation limit were necessarily captured
        // before the actor acknowledged the update. Remove them here so they do
        // not hide events captured with the newly installed unwind tables.
        self.pending_events
            .retain(|event| event.trace_id != trace_id as u64);
    }

    /// Wait for events emitted by the independent trace actors.
    pub async fn wait_for_all_events_async(&mut self) -> anyhow::Result<Vec<ParsedTraceEvent>> {
        if let Some(events) = self.take_pending_events() {
            return Ok(events);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }

        let mut aggregated_events = Vec::new();
        let mut deferred_by_batch_limit = 0usize;
        let first = loop {
            let event = tokio::select! {
                biased;
                event = self.event_receiver.recv() => Some(event
                    .ok_or_else(|| anyhow::anyhow!("trace actor event channel closed"))?),
                fatal = self.fatal_receiver.recv() => {
                    let fatal = fatal
                        .ok_or_else(|| anyhow::anyhow!("trace actor fatal channel closed"))?;
                    if self.traces.contains_key(&fatal.trace_id) {
                        return Err(actor_fatal_error(fatal));
                    }
                    debug!(
                        trace_id = fatal.trace_id,
                        "Ignoring fatal notification from deleted trace actor"
                    );
                    None
                }
            };
            if let Some(event) = event {
                break event;
            }
        };
        self.append_actor_event(first, &mut aggregated_events, &mut deferred_by_batch_limit);

        while aggregated_events.len() < MAX_AGGREGATED_EVENTS_PER_WAIT {
            match self.event_receiver.try_recv() {
                Ok(event) => {
                    self.append_actor_event(
                        event,
                        &mut aggregated_events,
                        &mut deferred_by_batch_limit,
                    );
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    if aggregated_events.is_empty() {
                        return Err(anyhow::anyhow!("trace actor event channel closed"));
                    }
                    break;
                }
            }
        }

        if let Ok(fatal) = self.fatal_receiver.try_recv() {
            if self.traces.contains_key(&fatal.trace_id) {
                let error = actor_fatal_error(fatal);
                if aggregated_events.is_empty() {
                    return Err(error);
                }
                self.pending_error = Some(error);
            } else {
                debug!(
                    trace_id = fatal.trace_id,
                    "Ignoring fatal notification from deleted trace actor"
                );
            }
        }

        if deferred_by_batch_limit > 0 {
            debug!(
                "Trace manager batch limit reached ({} events returned, {} parsed events deferred)",
                aggregated_events.len(),
                deferred_by_batch_limit
            );
        }
        Ok(aggregated_events)
    }

    fn append_actor_event(
        &mut self,
        event: TraceActorEvent,
        aggregated_events: &mut Vec<ParsedTraceEvent>,
        deferred_by_batch_limit: &mut usize,
    ) {
        match event {
            TraceActorEvent::Events {
                trace_id,
                generation,
                events,
            } => {
                // Delete waits for the actor to tear down its loader, but batches
                // sent before that acknowledgement may still be queued.
                if !self.traces.contains_key(&trace_id) {
                    return;
                }
                if generation
                    < self
                        .minimum_event_generations
                        .get(&trace_id)
                        .copied()
                        .unwrap_or_default()
                {
                    return;
                }
                *deferred_by_batch_limit += append_with_limit(
                    aggregated_events,
                    events,
                    &mut self.pending_events,
                    MAX_AGGREGATED_EVENTS_PER_WAIT,
                );
            }
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

fn actor_fatal_error(fatal: TraceActorFatal) -> anyhow::Error {
    error!(
        trace_id = fatal.trace_id,
        "Fatal error waiting for trace events: {}", fatal.error
    );
    anyhow::anyhow!(
        "Fatal error waiting for events from trace {}: {}",
        fatal.trace_id,
        fatal.error
    )
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
    use super::{append_with_limit, AddTraceParams, TraceManager, MAX_AGGREGATED_EVENTS_PER_WAIT};
    use crate::trace::actor::{TraceActorEvent, TraceActorFatal};
    use crate::trace::instance::TracePidContext;
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

    fn add_test_trace(manager: &mut TraceManager, trace_id: u32) {
        manager.add_trace_with_id(AddTraceParams {
            trace_id,
            target: format!("target-{trace_id}"),
            script_content: String::new(),
            pc: 0,
            binary_path: String::new(),
            target_display: format!("trace-{trace_id}"),
            pid_context: TracePidContext::default(),
            loader: None,
            ebpf_function_name: String::new(),
            address_global_index: None,
        });
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

    #[tokio::test]
    async fn actor_batches_are_aggregated_from_the_shared_queue() {
        let mut manager = TraceManager::new();
        add_test_trace(&mut manager, 7);
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 0,
                events: vec![event(7), event(7)],
            })
            .await
            .unwrap();
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 0,
                events: vec![event(7)],
            })
            .await
            .unwrap();

        let events = manager.wait_for_all_events_async().await.unwrap();
        assert_eq!(events.len(), 3);
        assert!(events.iter().all(|event| event.trace_id == 7));
    }

    #[tokio::test]
    async fn queued_events_for_a_deleted_trace_are_ignored() {
        let mut manager = TraceManager::new();
        add_test_trace(&mut manager, 7);
        add_test_trace(&mut manager, 8);
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 0,
                events: vec![event(7)],
            })
            .await
            .unwrap();
        manager.delete_trace(7).await.unwrap();
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 8,
                generation: 0,
                events: vec![event(8)],
            })
            .await
            .unwrap();

        let events = manager.wait_for_all_events_async().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].trace_id, 8);
    }

    #[tokio::test]
    async fn stale_event_generations_and_pending_events_are_ignored_after_update() {
        let mut manager = TraceManager::new();
        add_test_trace(&mut manager, 7);
        add_test_trace(&mut manager, 8);
        manager.pending_events.push_back(event(7));
        manager.pending_events.push_back(event(8));
        manager.require_event_generation(7, 1);

        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 0,
                events: vec![event(7)],
            })
            .await
            .unwrap();
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 1,
                events: vec![event(7)],
            })
            .await
            .unwrap();

        let pending = manager.take_pending_events().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].trace_id, 8);

        let events = manager.wait_for_all_events_async().await.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].trace_id, 7);
    }

    #[tokio::test]
    async fn fatal_actor_error_is_deferred_until_queued_events_are_returned() {
        let mut manager = TraceManager::new();
        add_test_trace(&mut manager, 7);
        manager
            .event_sender
            .send(TraceActorEvent::Events {
                trace_id: 7,
                generation: 0,
                events: vec![event(7)],
            })
            .await
            .unwrap();
        manager
            .fatal_sender
            .send(TraceActorFatal {
                trace_id: 7,
                error: "reader failed".to_string(),
            })
            .unwrap();

        let events = manager.wait_for_all_events_async().await.unwrap();
        assert_eq!(events.len(), 1);

        let error = manager.wait_for_all_events_async().await.unwrap_err();
        assert!(error.to_string().contains("reader failed"));
    }
}

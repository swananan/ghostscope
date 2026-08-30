use super::instance::TracePidContext;
use anyhow::Result;
use ghostscope_loader::{BacktraceUnwindRowsAppendStats, EventLossStats, GhostScopeLoader};
use ghostscope_protocol::{BacktraceUnwindRow, ParsedTraceEvent};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

// Each slot contains one bounded loader batch (currently at most 128 events).
pub(super) const TRACE_EVENT_CHANNEL_CAPACITY: usize = 64;
const TRACE_COMMAND_CHANNEL_CAPACITY: usize = 8;

#[derive(Debug)]
pub(super) enum TraceActorEvent {
    Events {
        trace_id: u32,
        generation: u64,
        events: Vec<ParsedTraceEvent>,
    },
}

#[derive(Debug)]
pub(super) struct TraceActorFatal {
    pub trace_id: u32,
    pub error: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TraceActorLossStats {
    pub kernel: Option<EventLossStats>,
    pub delivery_dropped: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct TraceActorBacktraceUpdate {
    pub stats: BacktraceUnwindRowsAppendStats,
    pub event_generation: u64,
}

#[derive(Debug)]
pub(super) struct TraceActorConfig {
    pub trace_id: u32,
    pub target_display: String,
    pub pc: u64,
    pub binary_path: String,
    pub pid_context: TracePidContext,
    pub ebpf_function_name: String,
}

enum TraceCommand {
    Enable(oneshot::Sender<Result<()>>),
    Disable(oneshot::Sender<Result<u64>>),
    ReadLossStats(oneshot::Sender<Result<TraceActorLossStats>>),
    AppendBacktraceRows {
        modules: Arc<Vec<(u64, Vec<BacktraceUnwindRow>)>>,
        response: oneshot::Sender<Result<TraceActorBacktraceUpdate>>,
    },
    Delete(oneshot::Sender<Result<()>>),
}

enum CommandOutcome {
    Continue,
    Delete {
        response: oneshot::Sender<Result<()>>,
        result: Result<()>,
    },
}

#[derive(Clone, Debug)]
pub(super) struct TraceActorHandle {
    command_sender: mpsc::Sender<TraceCommand>,
}

impl TraceActorHandle {
    pub async fn enable(&self) -> Result<()> {
        self.request(TraceCommand::Enable).await
    }

    pub async fn disable(&self) -> Result<u64> {
        self.request(TraceCommand::Disable).await
    }

    pub async fn read_loss_stats(&self) -> Result<TraceActorLossStats> {
        self.request(TraceCommand::ReadLossStats).await
    }

    pub async fn append_backtrace_rows(
        &self,
        modules: Arc<Vec<(u64, Vec<BacktraceUnwindRow>)>>,
    ) -> Result<TraceActorBacktraceUpdate> {
        let (response, receiver) = oneshot::channel();
        self.command_sender
            .send(TraceCommand::AppendBacktraceRows { modules, response })
            .await
            .map_err(|_| anyhow::anyhow!("trace actor command channel closed"))?;
        receiver
            .await
            .map_err(|_| anyhow::anyhow!("trace actor stopped before replying"))?
    }

    pub async fn delete(&self) -> Result<()> {
        let (response, receiver) = oneshot::channel();
        // A closed command channel means the actor already exited and dropped
        // its loader (for example after a fatal parser error), so deletion is
        // already complete from the manager's perspective.
        if self
            .command_sender
            .send(TraceCommand::Delete(response))
            .await
            .is_err()
        {
            return Ok(());
        }
        match receiver.await {
            Ok(result) => result,
            Err(_) => Ok(()),
        }
    }

    async fn request<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T>>) -> TraceCommand,
    ) -> Result<T> {
        let (response, receiver) = oneshot::channel();
        self.command_sender
            .send(build(response))
            .await
            .map_err(|_| anyhow::anyhow!("trace actor command channel closed"))?;
        receiver
            .await
            .map_err(|_| anyhow::anyhow!("trace actor stopped before replying"))?
    }
}

pub(super) fn spawn_trace_actor(
    mut loader: GhostScopeLoader,
    config: TraceActorConfig,
    event_sender: mpsc::Sender<TraceActorEvent>,
    fatal_sender: mpsc::UnboundedSender<TraceActorFatal>,
) -> TraceActorHandle {
    let (command_sender, mut command_receiver) = mpsc::channel(TRACE_COMMAND_CHANNEL_CAPACITY);
    let handle = TraceActorHandle { command_sender };

    tokio::spawn(async move {
        let mut is_enabled = false;
        let mut delivery_dropped = 0u64;
        let mut event_generation = 0u64;

        loop {
            if !is_enabled {
                let Some(command) = command_receiver.recv().await else {
                    destroy_loader(&mut loader, config.trace_id);
                    break;
                };
                if let CommandOutcome::Delete { response, result } = handle_command(
                    command,
                    &mut loader,
                    &config,
                    &mut is_enabled,
                    delivery_dropped,
                    &mut event_generation,
                ) {
                    // Drop the complete loader before acknowledging deletion.
                    // EventMap drops its readiness registrations before their
                    // borrowed fds, then Ebpf drops the remaining program/map fds.
                    drop(loader);
                    let _ = response.send(result);
                    break;
                }
                continue;
            }

            // When a command wins, select! cancels and drops the pending read
            // future before entering the command branch. Any readiness guard is
            // therefore gone before Delete can destroy the registered source.
            tokio::select! {
                biased;

                command = command_receiver.recv() => {
                    let Some(command) = command else {
                        destroy_loader(&mut loader, config.trace_id);
                        break;
                    };
                    if let CommandOutcome::Delete { response, result } = handle_command(
                        command,
                        &mut loader,
                        &config,
                        &mut is_enabled,
                        delivery_dropped,
                        &mut event_generation,
                    ) {
                        drop(loader);
                        let _ = response.send(result);
                        break;
                    }
                }

                result = loader.wait_for_events_async() => {
                    match result {
                        Ok(events) if events.is_empty() => {}
                        Ok(events) => {
                            let event_count = events.len() as u64;
                            match event_sender.try_send(TraceActorEvent::Events {
                                trace_id: config.trace_id,
                                generation: event_generation,
                                events,
                            }) {
                                Ok(()) => {}
                                Err(mpsc::error::TrySendError::Full(_)) => {
                                    delivery_dropped = delivery_dropped.saturating_add(event_count);
                                }
                                Err(mpsc::error::TrySendError::Closed(_)) => {
                                    destroy_loader(&mut loader, config.trace_id);
                                    break;
                                }
                            }
                        }
                        Err(err) => {
                            let error = err.to_string();
                            error!(
                                trace_id = config.trace_id,
                                "Fatal error reading trace events: {error}"
                            );
                            // Fatal notifications use a separate unbounded control
                            // path (at most one per actor), so a saturated bounded
                            // event queue cannot hide failure or delay teardown.
                            let _ = fatal_sender.send(TraceActorFatal {
                                trace_id: config.trace_id,
                                error,
                            });
                            destroy_loader(&mut loader, config.trace_id);
                            break;
                        }
                    }
                    // A hot trace should not monopolize a runtime worker even when
                    // its fd remains continuously readable.
                    tokio::task::yield_now().await;
                }
            }
        }
    });

    handle
}

fn handle_command(
    command: TraceCommand,
    loader: &mut GhostScopeLoader,
    config: &TraceActorConfig,
    is_enabled: &mut bool,
    delivery_dropped: u64,
    event_generation: &mut u64,
) -> CommandOutcome {
    match command {
        TraceCommand::Enable(response) => {
            let result = enable_loader(loader, config, *is_enabled);
            if result.is_ok() {
                *is_enabled = true;
            }
            let _ = response.send(result);
            CommandOutcome::Continue
        }
        TraceCommand::Disable(response) => {
            let result = disable_loader(loader, config, *is_enabled).map(|()| {
                *is_enabled = false;
                advance_event_generation(event_generation)
            });
            let _ = response.send(result);
            CommandOutcome::Continue
        }
        TraceCommand::ReadLossStats(response) => {
            let result = loader
                .read_event_loss_stats()
                .map(|kernel| TraceActorLossStats {
                    kernel,
                    delivery_dropped,
                })
                .map_err(Into::into);
            let _ = response.send(result);
            CommandOutcome::Continue
        }
        TraceCommand::AppendBacktraceRows { modules, response } => {
            let result = loader
                .append_backtrace_unwind_rows_for_modules(modules.as_slice())
                .map(|stats| {
                    // Shared pinned unwind maps may have been populated by a
                    // different actor, in which case this loader reports zero
                    // inserted modules but its queued batches are still stale.
                    let event_generation = advance_event_generation(event_generation);
                    TraceActorBacktraceUpdate {
                        stats,
                        event_generation,
                    }
                })
                .map_err(Into::into);
            let _ = response.send(result);
            CommandOutcome::Continue
        }
        TraceCommand::Delete(response) => {
            // destroy() explicitly clears EventMap. The caller then drops the
            // rest of the loader before acknowledging the command.
            let result = loader.destroy().map_err(Into::into);
            CommandOutcome::Delete { response, result }
        }
    }
}

fn advance_event_generation(event_generation: &mut u64) -> u64 {
    *event_generation = event_generation.saturating_add(1);
    *event_generation
}

fn enable_loader(
    loader: &mut GhostScopeLoader,
    config: &TraceActorConfig,
    is_enabled: bool,
) -> Result<()> {
    if is_enabled {
        info!("Trace {} is already enabled", config.trace_id);
        return Ok(());
    }

    if loader.is_uprobe_attached() {
        return Ok(());
    }

    info!(
        "Enabling trace {} for target '{}' at PC 0x{:x} in binary '{}'",
        config.trace_id, config.target_display, config.pc, config.binary_path
    );
    if loader.get_attachment_info().is_some() {
        loader
            .reattach_uprobe()
            .map_err(|err| anyhow::anyhow!("Failed to re-attach uprobe: {err}"))?;
    } else {
        loader
            .attach_uprobe(
                &config.binary_path,
                &config.ebpf_function_name,
                Some(config.pc),
                config.pid_context.attach_pid.map(|pid| pid as i32),
            )
            .map_err(|err| anyhow::anyhow!("Failed to attach uprobe: {err}"))?;
    }

    info!("Successfully enabled trace {}", config.trace_id);
    Ok(())
}

fn disable_loader(
    loader: &mut GhostScopeLoader,
    config: &TraceActorConfig,
    is_enabled: bool,
) -> Result<()> {
    if !is_enabled {
        info!("Trace {} is already disabled", config.trace_id);
        return Ok(());
    }

    info!(
        "Disabling trace {} for target '{}' at PC 0x{:x}",
        config.trace_id, config.target_display, config.pc
    );
    loader
        .detach_uprobe()
        .map_err(|err| anyhow::anyhow!("Failed to detach uprobe: {err}"))?;
    info!("Successfully disabled trace {}", config.trace_id);
    Ok(())
}

fn destroy_loader(loader: &mut GhostScopeLoader, trace_id: u32) {
    if let Err(err) = loader.destroy() {
        warn!(trace_id, "Failed to destroy trace loader: {err}");
    }
}

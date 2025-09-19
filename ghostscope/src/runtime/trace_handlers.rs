use crate::core::GhostSession;
use ghostscope_ui::{events::*, RuntimeChannels, RuntimeStatus};
use tracing::{error, info, warn};

/// Handle DisableTrace command
pub async fn handle_disable_trace(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    trace_id: u32,
) {
    if let Some(ref mut session) = session {
        match session.trace_manager.disable_trace(trace_id) {
            Ok(_) => {
                info!("✓ Disabled trace {}", trace_id);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceDisabled { trace_id });
            }
            Err(e) => {
                error!("❌ Failed to disable trace {}: {}", trace_id, e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceDisableFailed {
                        trace_id,
                        error: format!("Failed to disable trace: {}", e),
                    });
            }
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceDisableFailed {
                trace_id,
                error: "No debug session available".to_string(),
            });
    }
}

/// Handle EnableTrace command
pub async fn handle_enable_trace(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    trace_id: u32,
) {
    if let Some(ref mut session) = session {
        match session.trace_manager.enable_trace(trace_id) {
            Ok(_) => {
                info!("✓ Enabled trace {}", trace_id);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceEnabled { trace_id });
            }
            Err(e) => {
                error!("❌ Failed to enable trace {}: {}", trace_id, e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceEnableFailed {
                        trace_id,
                        error: format!("Failed to enable trace: {}", e),
                    });
            }
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceEnableFailed {
                trace_id,
                error: "No debug session available".to_string(),
            });
    }
}

/// Handle DisableAllTraces command
pub async fn handle_disable_all_traces(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref mut session) = session {
        let trace_count = session.trace_manager.get_all_trace_ids().len();
        match session.trace_manager.disable_all_traces() {
            Ok(_) => {
                info!("✓ Disabled all traces (count: {})", trace_count);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::AllTracesDisabled { count: trace_count });
            }
            Err(e) => {
                error!("❌ Failed to disable all traces: {}", e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::Error(format!(
                        "Failed to disable all traces: {}",
                        e
                    )));
            }
        }
    } else {
        let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(
            "No debug session available".to_string(),
        ));
    }
}

/// Handle EnableAllTraces command
pub async fn handle_enable_all_traces(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref mut session) = session {
        let trace_count = session.trace_manager.get_all_trace_ids().len();
        match session.trace_manager.enable_all_traces() {
            Ok(_) => {
                info!("✓ Enabled all traces (count: {})", trace_count);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::AllTracesEnabled { count: trace_count });
            }
            Err(e) => {
                error!("❌ Failed to enable all traces: {}", e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::Error(format!(
                        "Failed to enable all traces: {}",
                        e
                    )));
            }
        }
    } else {
        let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(
            "No debug session available".to_string(),
        ));
    }
}

/// Handle DeleteTrace command
pub async fn handle_delete_trace(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
    trace_id: u32,
) {
    if let Some(ref mut session) = session {
        match session.trace_manager.delete_trace(trace_id) {
            Ok(_) => {
                info!("✓ Deleted trace {}", trace_id);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceDeleted { trace_id });
            }
            Err(e) => {
                error!("❌ Failed to delete trace {}: {}", trace_id, e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::TraceDeleteFailed {
                        trace_id,
                        error: format!("Failed to delete trace: {}", e),
                    });
            }
        }
    } else {
        let _ = runtime_channels
            .status_sender
            .send(RuntimeStatus::TraceDeleteFailed {
                trace_id,
                error: "No debug session available".to_string(),
            });
    }
}

/// Handle DeleteAllTraces command
pub async fn handle_delete_all_traces(
    session: &mut Option<GhostSession>,
    runtime_channels: &mut RuntimeChannels,
) {
    if let Some(ref mut session) = session {
        match session.trace_manager.delete_all_traces() {
            Ok(count) => {
                info!("✓ Deleted all traces (count: {})", count);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::AllTracesDeleted { count });
            }
            Err(e) => {
                error!("❌ Failed to delete all traces: {}", e);
                let _ = runtime_channels
                    .status_sender
                    .send(RuntimeStatus::Error(format!(
                        "Failed to delete all traces: {}",
                        e
                    )));
            }
        }
    } else {
        let _ = runtime_channels.status_sender.send(RuntimeStatus::Error(
            "No debug session available".to_string(),
        ));
    }
}

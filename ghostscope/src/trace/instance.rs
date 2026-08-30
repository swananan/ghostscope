use super::actor::{TraceActorBacktraceUpdate, TraceActorHandle, TraceActorLossStats};
use anyhow::Result;
use ghostscope_protocol::BacktraceUnwindRow;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TracePidContext {
    /// PID used for uprobe attach restrictions in GhostScope's current userspace view.
    pub attach_pid: Option<u32>,
    /// Host-view PID kept for logs and UI display.
    pub host_pid: Option<u32>,
    /// PID used for userspace `/proc` access and user-facing display.
    pub proc_pid: Option<u32>,
}

impl TracePidContext {
    pub fn display_pid(self) -> Option<u32> {
        self.proc_pid.or(self.attach_pid)
    }
}

/// Individual trace instance with single PC value
#[derive(Debug)]
pub(super) struct TraceInstance {
    pub trace_id: u32,
    pub target: String, // Target identifier for grouping (e.g., "test_program:L15")
    pub script_content: String, // Original script content
    pub binary_path: String, // Binary being traced
    pub target_display: String, // Display name for UI (e.g., "main", "file.c:15")
    pub pc: u64,        // Program counter value for this trace (file offset for uprobe)
    pub pid_context: TracePidContext,
    pub is_enabled: bool, // Whether the uprobe is currently enabled
    pub(super) actor: Option<TraceActorHandle>, // Owns the eBPF loader for this trace
    pub ebpf_function_name: String, // eBPF function name for uprobe attachment
    pub address_global_index: Option<usize>, // Global 1-based index of the resolved address
}

pub(super) struct TraceInstanceArgs {
    pub trace_id: u32,
    pub target: String,
    pub script_content: String,
    pub pc: u64,
    pub binary_path: String,
    pub target_display: String,
    pub pid_context: TracePidContext,
    pub(super) actor: Option<TraceActorHandle>,
    pub ebpf_function_name: String,
    pub address_global_index: Option<usize>,
}

impl TraceInstance {
    pub(super) fn new(args: TraceInstanceArgs) -> Self {
        Self {
            trace_id: args.trace_id,
            target: args.target,
            script_content: args.script_content,
            pc: args.pc,
            binary_path: args.binary_path,
            target_display: args.target_display,
            pid_context: args.pid_context,
            is_enabled: false,
            actor: args.actor,
            ebpf_function_name: args.ebpf_function_name,
            address_global_index: args.address_global_index,
        }
    }

    /// Enable this trace instance
    pub(super) async fn enable(&mut self) -> Result<()> {
        if self.is_enabled {
            info!("Trace {} is already enabled", self.trace_id);
            Ok(())
        } else if let Some(actor) = &self.actor {
            actor.enable().await?;
            self.is_enabled = true;
            Ok(())
        } else {
            Err(anyhow::anyhow!("No trace actor available"))
        }
    }

    /// Disable this trace instance
    pub(super) async fn disable(&mut self) -> Result<Option<u64>> {
        if !self.is_enabled {
            info!("Trace {} is already disabled", self.trace_id);
            return Ok(None);
        }

        info!(
            "Disabling trace {} for target '{}' at PC 0x{:x}",
            self.trace_id, self.target_display, self.pc
        );

        if let Some(actor) = &self.actor {
            let event_generation = actor.disable().await?;
            self.is_enabled = false;
            Ok(Some(event_generation))
        } else {
            warn!(
                "No trace actor available for trace {}, marking as disabled",
                self.trace_id
            );
            self.is_enabled = false;
            Ok(None)
        }
    }

    pub(super) async fn read_loss_stats(&self) -> Result<TraceActorLossStats> {
        if let Some(actor) = &self.actor {
            actor.read_loss_stats().await
        } else {
            Ok(TraceActorLossStats::default())
        }
    }

    pub(super) async fn append_backtrace_rows(
        &self,
        modules: Arc<Vec<(u64, Vec<BacktraceUnwindRow>)>>,
    ) -> Result<TraceActorBacktraceUpdate> {
        if let Some(actor) = &self.actor {
            actor.append_backtrace_rows(modules).await
        } else {
            Ok(Default::default())
        }
    }

    pub(super) async fn delete(&self) -> Result<()> {
        if let Some(actor) = &self.actor {
            actor.delete().await
        } else {
            Ok(())
        }
    }
}

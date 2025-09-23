use anyhow::Result;
use ghostscope_loader::GhostScopeLoader;
use ghostscope_ui::events::TraceStatus;
use tracing::{error, info, warn};

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
                            "✓ Successfully attached uprobe for trace {} at offset 0x{:x}",
                            self.trace_id, self.pc
                        );
                        self.is_enabled = true;
                        return Ok(());
                    }
                    Err(e) => {
                        error!(
                            "❌ Failed to attach uprobe for trace {}: {}",
                            self.trace_id, e
                        );
                        return Err(anyhow::anyhow!("Failed to attach uprobe: {}", e));
                    }
                }
            }
        } else {
            error!("No eBPF loader available for trace {}", self.trace_id);
            return Err(anyhow::anyhow!("No eBPF loader available"));
        }
    }

    /// Disable this trace instance
    pub fn disable(&mut self) -> Result<()> {
        if !self.is_enabled {
            info!("Trace {} is already disabled", self.trace_id);
            return Ok(());
        }

        info!(
            "Disabling trace {} for target '{}' at PC 0x{:x}",
            self.trace_id, self.target_display, self.pc
        );

        // Detach uprobe using the loader
        if let Some(ref mut loader) = self.loader {
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
                "No eBPF loader available for trace {}, marking as disabled",
                self.trace_id
            );
            self.is_enabled = false;
            Ok(())
        }
    }

    /// Wait for events asynchronously from this trace instance
    pub async fn wait_for_events_async(&mut self) -> Result<Vec<ghostscope_protocol::TraceEventData>> {
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

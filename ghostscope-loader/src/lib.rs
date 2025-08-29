use aya::{
    maps::RingBuf,
    programs::{uprobe::UProbeAttachLocation, ProgramError, UProbe},
    Ebpf, EbpfLoader, VerifierLogLevel,
};
use ghostscope_protocol::{consts, MessageParser, MessageType, TypeEncoding, VariableDataMessage};
use std::convert::TryInto;
use tracing::{debug, error, info, warn};

pub fn hello() -> String {
    format!("Loader: {}", ghostscope_compiler::hello())
}

#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("Aya error: {0}")]
    Aya(#[from] aya::EbpfError),

    #[error("Program error: {0}")]
    Program(#[from] aya::programs::ProgramError),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Loader error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, LoaderError>;

pub struct GhostScopeLoader {
    bpf: Ebpf,
    ringbuf: Option<RingBuf<aya::maps::MapData>>,
}

impl std::fmt::Debug for GhostScopeLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhostScopeLoader")
            .field("bpf", &"<eBPF object>")
            .field("ringbuf", &self.ringbuf.is_some())
            .finish()
    }
}

impl GhostScopeLoader {
    /// Create a new loader instance from eBPF bytecode
    pub fn new(bytecode: &[u8]) -> Result<Self> {
        info!(
            "Loading eBPF program from bytecode ({} bytes)",
            bytecode.len()
        );

        // Load BPF program from bytecode with high verifier log level for debugging
        match EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
            .load(bytecode)
        {
            Ok(bpf) => {
                info!("Successfully loaded eBPF program");
                Ok(Self { bpf, ringbuf: None })
            }
            Err(e) => {
                error!("Failed to load BPF program: {:?}", e);
                // Try to provide more specific error information
                match &e {
                    aya::EbpfError::ParseError(parse_err) => {
                        error!("Parse error details: {:?}", parse_err);
                    }
                    aya::EbpfError::BtfError(btf_err) => {
                        error!("BTF error details: {:?}", btf_err);
                    }
                    _ => {
                        error!("Other BPF error: {:?}", e);
                    }
                }
                Err(LoaderError::Aya(e))
            }
        }
    }

    /// Attach to a uprobe at the specified function offset
    pub fn attach_uprobe(
        &mut self,
        target_binary: &str,
        function_name: &str,
        offset: Option<u64>,
        pid: Option<i32>,
    ) -> Result<()> {
        self.attach_uprobe_with_program_name(target_binary, function_name, offset, pid, None)
    }

    /// Attach to a uprobe with a specific eBPF program name
    pub fn attach_uprobe_with_program_name(
        &mut self,
        target_binary: &str,
        function_name: &str,
        offset: Option<u64>,
        pid: Option<i32>,
        program_name: Option<&str>,
    ) -> Result<()> {
        info!("attach_uprobe called with offset: {:?}", offset);
        if let Some(offset) = offset {
            info!(
                "Using offset-based attachment: {} at 0x{:x} ({}) (pid: {:?})",
                target_binary, offset, function_name, pid
            );
        } else {
            info!(
                "Using function name-based attachment: {}:{} (pid: {:?})",
                target_binary, function_name, pid
            );
        }

        // Collect all available program names first to avoid borrowing conflicts
        let available_programs: Vec<String> = self
            .bpf
            .programs()
            .map(|(name, _)| name.to_string())
            .collect();

        // Debug: Print all available programs
        info!("Available programs:");
        for name in &available_programs {
            info!("  - {}", name);
        }

        // Get the program from the BPF object
        let program_name: String = if let Some(name) = program_name {
            // Use the specified program name
            info!("Using specified program name: {}", name);
            if available_programs.contains(&name.to_string()) {
                name.to_string()
            } else {
                return Err(LoaderError::Generic(format!(
                    "Specified program '{}' not found in eBPF object",
                    name
                )));
            }
        } else {
            // Try different program names: section name first, then function name, then any program
            let program_names = ["uprobe", "main"];
            let mut found_program_name: Option<String> = None;

            for name in &program_names {
                info!("Checking if program exists: {}", name);
                if available_programs.contains(&name.to_string()) {
                    info!("Found program: {}", name);
                    found_program_name = Some(name.to_string());
                    break;
                }
            }

            // If no standard names found, use the first available program
            if found_program_name.is_none() {
                if let Some(first_name) = available_programs.first() {
                    info!(
                        "No standard program names found, using first available: {}",
                        first_name
                    );
                    found_program_name = Some(first_name.clone());
                }
            }

            found_program_name
                .ok_or_else(|| LoaderError::Generic("No suitable program found".to_string()))?
        };

        info!("Attempting to load program: {}", program_name);

        let program_ref = self
            .bpf
            .program_mut(&program_name)
            .ok_or_else(|| LoaderError::Generic(format!("Program '{}' not found", program_name)))?;

        info!("Found program, attempting to convert to UProbe");
        info!("Program type: {:?}", program_ref.prog_type());

        // Check what type of program this actually is
        match program_ref {
            aya::programs::Program::UProbe(_) => {
                info!("Program is correctly recognized as UProbe");
            }
            aya::programs::Program::KProbe(_) => {
                error!("Program is incorrectly recognized as KProbe, should be UProbe");
            }
            ref _other => {
                error!("Program is unexpected type (not UProbe or KProbe)");
            }
        }

        let program: &mut UProbe = program_ref.try_into().map_err(|e| {
            LoaderError::Generic(format!(
                "Program '{}' is not a UProbe: {:?}",
                program_name, e
            ))
        })?;

        // Load the program
        info!("About to load eBPF program");
        program.load()?;
        info!("Program loaded successfully");

        // Attach the uprobe using aya API
        // If we have an offset, use it; otherwise fall back to function name
        let attach_result = if let Some(offset) = offset {
            // Use absolute offset-based attachment
            program.attach(
                UProbeAttachLocation::AbsoluteOffset(offset),
                target_binary,
                pid,
                None,
            )
        } else {
            // Use function name-based attachment
            program.attach(function_name, target_binary, pid, None)
        };

        match attach_result {
            Ok(_) => {
                if let Some(offset) = offset {
                    info!(
                        "Uprobe attached successfully to {} at offset 0x{:x}",
                        target_binary, offset
                    );
                } else {
                    info!(
                        "Uprobe attached successfully to {}:{}",
                        target_binary, function_name
                    );
                }
            }
            Err(e) => {
                if let Some(offset) = offset {
                    error!(
                        "Failed to attach uprobe to {} at offset 0x{:x}: {}",
                        target_binary, offset, e
                    );
                    error!("Detailed error: {:#?}", e);
                } else {
                    error!(
                        "Failed to attach uprobe to {}:{}: {}",
                        target_binary, function_name, e
                    );
                    error!("Detailed error: {:#?}", e);
                }

                // Try to provide more helpful error information
                if let ProgramError::SyscallError(syscall_error) = &e {
                    error!(
                        "Syscall '{}' failed: {}",
                        syscall_error.call, syscall_error.io_error
                    );
                    if let Some(13) = syscall_error.io_error.raw_os_error() {
                        error!("Permission denied - make sure to run with sudo");
                    }
                }

                return Err(LoaderError::Program(e));
            }
        }

        // Initialize ringbuf after successful attachment
        // Use the same map name as generated in our codegen (ringbuf)
        let ringbuf: RingBuf<_> = self
            .bpf
            .take_map("ringbuf")
            .ok_or_else(|| LoaderError::MapNotFound("ringbuf".to_string()))?
            .try_into()
            .map_err(|e| LoaderError::Generic(format!("Failed to convert ringbuf map: {}", e)))?;

        self.ringbuf = Some(ringbuf);
        info!("Ringbuf map initialized");

        Ok(())
    }

    /// Poll for new events (non-blocking)
    /// Returns Some(events) if there are events, None if no events available
    pub fn poll_events(&mut self) -> Result<Option<Vec<EventData>>> {
        let ringbuf = self.ringbuf.as_mut().ok_or_else(|| {
            LoaderError::Generic("Ringbuf not initialized. Call attach_uprobe first.".to_string())
        })?;

        let mut events = Vec::new();

        // Read all available events without blocking
        while let Some(item) = ringbuf.next() {
            // Parse event directly here to avoid borrowing issues
            if let Some(event) = Self::parse_event_static(&item) {
                events.push(event);
            }
        }

        if events.is_empty() {
            Ok(None)
        } else {
            Ok(Some(events))
        }
    }

    /// Parse event data using GhostScope Protocol format
    fn parse_event_static(data: &[u8]) -> Option<EventData> {
        debug!("Processing protocol message: {} bytes", data.len());

        // Check minimum message size
        if data.len() < 8 {
            debug!("Message too short for header: {} bytes", data.len());
            return None;
        }

        // Parse message header
        let header = match MessageParser::parse_header(data) {
            Ok(header) => header,
            Err(e) => {
                debug!("Failed to parse header: {}", e);
                return None;
            }
        };

        // Verify magic number
        if header.magic != consts::MAGIC {
            let magic = header.magic; // Copy field to avoid packed reference
            debug!(
                "Invalid magic number: 0x{:08x}, expected 0x{:08x}",
                magic,
                consts::MAGIC
            );
            return None;
        }

        // Handle different message types
        match header.msg_type {
            t if t == MessageType::VariableData as u8 => Self::parse_variable_data_message(data),
            t if t == MessageType::Error as u8 => {
                warn!("Received error message from eBPF");
                None
            }
            t if t == MessageType::Heartbeat as u8 => {
                debug!("Received heartbeat message");
                None
            }
            t if t == MessageType::Log as u8 => {
                Self::handle_log_message(data);
                None
            }
            t if t == MessageType::ExecutionFailure as u8 => {
                Self::handle_execution_failure_message(data);
                None
            }
            _ => {
                debug!("Unknown message type: {}", header.msg_type);
                None
            }
        }
    }

    /// Parse variable data message
    fn parse_variable_data_message(data: &[u8]) -> Option<EventData> {
        match MessageParser::parse_variable_message(data) {
            Ok((msg_body, variables)) => {
                let trace_id = msg_body.trace_id; // Copy field to avoid packed reference
                info!(
                    "Parsed variable message: {} variables from trace_id {}",
                    variables.len(),
                    trace_id
                );

                let mut variable_infos = Vec::new();
                for (name, type_encoding, raw_data) in variables {
                    let formatted_value =
                        MessageParser::format_variable_value(type_encoding, &raw_data)
                            .unwrap_or_else(|e| format!("<format error: {}>", e));

                    info!(
                        "Variable: {} ({:?}) = {}",
                        name, type_encoding, formatted_value
                    );

                    variable_infos.push(VariableInfo {
                        name,
                        type_encoding,
                        raw_data,
                        formatted_value,
                    });
                }

                Some(EventData {
                    trace_id: msg_body.trace_id,
                    timestamp: msg_body.timestamp,
                    pid: msg_body.pid,
                    tid: msg_body.tid,
                    variables: variable_infos,
                })
            }
            Err(e) => {
                error!("Failed to parse variable data message: {}", e);
                None
            }
        }
    }

    /// Parse event data into structured format (instance method for compatibility)
    fn parse_event(&self, data: &[u8]) -> Option<EventData> {
        Self::parse_event_static(data)
    }

    // Helper functions removed - now using protocol parser

    /// Get information about loaded maps
    pub fn get_map_info(&self) -> Vec<String> {
        self.bpf
            .maps()
            .map(|(name, _map)| format!("Map: {}", name))
            .collect()
    }

    /// Get information about loaded programs  
    pub fn get_program_info(&self) -> Vec<String> {
        self.bpf
            .programs()
            .map(|(name, _prog)| format!("Program: {}", name))
            .collect()
    }

    /// Handle log message from eBPF
    fn handle_log_message(data: &[u8]) {
        match MessageParser::parse_log_message(data) {
            Ok((log_msg, message)) => {
                // Copy fields from packed struct to avoid packed reference issues
                let trace_id = log_msg.trace_id;
                let timestamp = log_msg.timestamp;
                let pid = log_msg.pid;
                let tid = log_msg.tid;
                let log_level = log_msg.log_level;

                let level_str = match log_level {
                    0 => "DEBUG",
                    1 => "INFO",
                    2 => "WARN",
                    3 => "ERROR",
                    _ => "UNKNOWN",
                };

                // Convert nanosecond timestamp to readable format
                let readable_ts = Self::format_timestamp_ns(timestamp);

                info!(
                    "[eBPF-{}] trace_id:{} pid:{} tid:{} {} - {}",
                    level_str, trace_id, pid, tid, readable_ts, message
                );
            }
            Err(e) => {
                warn!("Failed to parse log message: {}", e);
            }
        }
    }

    /// Handle execution failure message from eBPF
    fn handle_execution_failure_message(data: &[u8]) {
        match MessageParser::parse_execution_failure_message(data) {
            Ok((failure_msg, message)) => {
                // Copy fields from packed struct to avoid packed reference issues
                let trace_id = failure_msg.trace_id;
                let timestamp = failure_msg.timestamp;
                let pid = failure_msg.pid;
                let tid = failure_msg.tid;
                let function_id = failure_msg.function_id;
                let error_code = failure_msg.error_code;

                // Convert nanosecond timestamp to readable format
                let readable_ts = Self::format_timestamp_ns(timestamp);

                error!(
                    "[eBPF-FAILURE] trace_id:{} pid:{} tid:{} {} func_id:{} error_code:{} - {}",
                    trace_id, pid, tid, readable_ts, function_id, error_code, message
                );
            }
            Err(e) => {
                warn!("Failed to parse execution failure message: {}", e);
            }
        }
    }

    /// Format nanosecond timestamp to readable string
    /// eBPF uses bpf_ktime_get_ns() which returns nanoseconds since system boot
    fn format_timestamp_ns(ns_timestamp: u64) -> String {
        use std::time::{Duration, SystemTime, UNIX_EPOCH};

        // Get current system time and boot time
        let now = SystemTime::now();
        let uptime = Self::get_system_uptime_ns();

        if let (Ok(now_since_epoch), Some(boot_ns)) = (now.duration_since(UNIX_EPOCH), uptime) {
            // Calculate when the system booted
            let boot_time_ns = now_since_epoch.as_nanos() as u64 - boot_ns;

            // Add eBPF timestamp to boot time to get actual time
            let actual_time_ns = boot_time_ns + ns_timestamp;
            let actual_time_secs = actual_time_ns / 1_000_000_000;
            let actual_time_nanos = actual_time_ns % 1_000_000_000;

            // Convert to chrono DateTime with local timezone
            if let Some(utc_datetime) =
                chrono::DateTime::from_timestamp(actual_time_secs as i64, actual_time_nanos as u32)
            {
                let local_datetime: chrono::DateTime<chrono::Local> = utc_datetime.into();
                return format!(
                    "{}.{:03}",
                    local_datetime.format("%Y-%m-%d %H:%M:%S"),
                    actual_time_nanos / 1_000_000
                );
            }
        }

        // Fallback to boot time offset if conversion fails
        let ms = ns_timestamp / 1_000_000;
        let seconds = ms / 1000;
        let ms_remainder = ms % 1000;
        format!("boot+{}.{:03}s", seconds, ms_remainder)
    }

    /// Get system uptime in nanoseconds
    fn get_system_uptime_ns() -> Option<u64> {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|content| {
                let uptime_secs: f64 = content.split_whitespace().next()?.parse().ok()?;
                Some((uptime_secs * 1_000_000_000.0) as u64)
            })
    }
}

/// Structured event data from eBPF program using GhostScope Protocol
#[derive(Debug, Clone)]
pub struct EventData {
    pub trace_id: u64,
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub variables: Vec<VariableInfo>,
}

/// Variable information extracted from protocol message
#[derive(Debug, Clone)]
pub struct VariableInfo {
    pub name: String,
    pub type_encoding: TypeEncoding,
    pub raw_data: Vec<u8>,
    pub formatted_value: String,
}

impl std::fmt::Display for EventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let readable_ts = GhostScopeLoader::format_timestamp_ns(self.timestamp);
        writeln!(
            f,
            "Event [trace_id: {}, pid: {}, tid: {}, timestamp: {}]:",
            self.trace_id, self.pid, self.tid, readable_ts
        )?;
        for var in &self.variables {
            writeln!(
                f,
                "  {} ({}): {}",
                var.name,
                format!("{:?}", var.type_encoding),
                var.formatted_value
            )?;
        }
        Ok(())
    }
}

impl std::fmt::Display for VariableInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} = {}", self.name, self.formatted_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello() {
        assert_eq!(hello(), "Loader: Hello from ghostscope-compiler!");
    }
}

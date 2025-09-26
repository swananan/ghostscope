use aya::{
    maps::RingBuf,
    programs::{
        uprobe::{UProbeAttachLocation, UProbeLinkId},
        ProgramError, UProbe,
    },
    Ebpf, EbpfLoader, VerifierLogLevel,
};
use ghostscope_protocol::{ParsedTraceEvent, StreamingTraceParser, StringTable};
use std::convert::TryInto;
use std::os::unix::io::AsRawFd;
use tokio::io::unix::AsyncFd;
use tracing::{error, info, warn};

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
    uprobe_link: Option<UProbeLinkId>,
    // Store attachment parameters for re-enabling
    attachment_params: Option<UprobeAttachmentParams>,
    // Streaming parser for trace events
    parser: StreamingTraceParser,
    // String table for parsing trace events
    string_table: Option<StringTable>,
}

#[derive(Debug, Clone)]
struct UprobeAttachmentParams {
    target_binary: String,
    function_name: String,
    offset: Option<u64>,
    pid: Option<i32>,
    program_name: String,
}

impl std::fmt::Debug for GhostScopeLoader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GhostScopeLoader")
            .field("bpf", &"<eBPF object>")
            .field("ringbuf", &self.ringbuf.is_some())
            .field("uprobe_attached", &self.uprobe_link.is_some())
            .field("attachment_params", &self.attachment_params.is_some())
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
                Ok(Self {
                    bpf,
                    ringbuf: None,
                    uprobe_link: None,
                    attachment_params: None,
                    parser: StreamingTraceParser::new(),
                    string_table: None,
                })
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
                    "Specified program '{name}' not found in eBPF object"
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
            .ok_or_else(|| LoaderError::Generic(format!("Program '{program_name}' not found")))?;

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
            LoaderError::Generic(format!("Program '{program_name}' is not a UProbe: {e:?}"))
        })?;

        // Load the program
        info!("About to load eBPF program");
        match program.load() {
            Ok(()) => {
                info!("Program loaded successfully");
            }
            Err(e) => {
                error!("eBPF program load failed: {}", e);
                error!("This typically indicates eBPF verifier rejection");

                // Check for specific verifier errors
                if let ProgramError::SyscallError(syscall_error) = &e {
                    error!(
                        "Syscall '{}' failed: {}",
                        syscall_error.call, syscall_error.io_error
                    );

                    // Check for common error codes
                    if let Some(errno) = syscall_error.io_error.raw_os_error() {
                        match errno {
                            22 => error!(
                                "EINVAL (22): Invalid argument - likely eBPF verifier rejection"
                            ),
                            7 => error!("E2BIG (7): Program too large"),
                            13 => error!("EACCES (13): Permission denied"),
                            95 => error!("EOPNOTSUPP (95): Operation not supported"),
                            _ => error!("Unknown errno: {}", errno),
                        }
                    }
                }

                // Log additional debugging info
                error!("Program name: {}", program_name);
                error!("Program type: {:?}", program_ref.prog_type());

                return Err(LoaderError::Program(e));
            }
        }

        // Attach the uprobe using aya API
        // If we have an offset, use it; otherwise fall back to function name
        let attach_result = if let Some(offset) = offset {
            // Use absolute offset-based attachment
            program.attach(
                UProbeAttachLocation::AbsoluteOffset(offset),
                target_binary,
                None,
                None,
            )
        } else {
            // Use function name-based attachment
            program.attach(function_name, target_binary, None, None)
        };

        match attach_result {
            Ok(link) => {
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

                // Store the link handle and attachment parameters for later use
                self.uprobe_link = Some(link);
                self.attachment_params = Some(UprobeAttachmentParams {
                    target_binary: target_binary.to_string(),
                    function_name: function_name.to_string(),
                    offset,
                    pid,
                    program_name,
                });
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
            .map_err(|e| LoaderError::Generic(format!("Failed to convert ringbuf map: {e}")))?;

        self.ringbuf = Some(ringbuf);
        info!("Ringbuf map initialized");

        Ok(())
    }

    /// Detach the uprobe (disable tracing) while keeping eBPF resources loaded
    /// This allows the trace to be quickly re-enabled later
    pub fn detach_uprobe(&mut self) -> Result<()> {
        if let Some(link_id) = self.uprobe_link.take() {
            if let Some(params) = &self.attachment_params {
                info!("Detaching uprobe...");

                // Get the program to detach the link
                let program_ref = self.bpf.program_mut(&params.program_name).ok_or_else(|| {
                    let program_name = &params.program_name;
                    LoaderError::Generic(format!("Program '{program_name}' not found"))
                })?;

                let program: &mut UProbe = program_ref.try_into().map_err(|e| {
                    let program_name = &params.program_name;
                    LoaderError::Generic(format!("Program '{program_name}' is not a UProbe: {e:?}"))
                })?;

                // Detach the uprobe using the link ID
                program.detach(link_id).map_err(LoaderError::Program)?;

                info!("Uprobe detached successfully");
                Ok(())
            } else {
                error!("No attachment parameters stored");
                Err(LoaderError::Generic(
                    "No attachment parameters stored".to_string(),
                ))
            }
        } else {
            warn!("No uprobe attached, nothing to detach");
            Ok(())
        }
    }

    /// Reattach the uprobe (re-enable tracing) using previously stored parameters
    /// This requires that attach_uprobe was called previously to store the parameters
    pub fn reattach_uprobe(&mut self) -> Result<()> {
        if self.uprobe_link.is_some() {
            info!("Uprobe already attached");
            return Ok(());
        }

        let params = self
            .attachment_params
            .as_ref()
            .ok_or_else(|| {
                LoaderError::Generic(
                    "No attachment parameters stored. Call attach_uprobe first.".to_string(),
                )
            })?
            .clone();

        info!("Reattaching uprobe with stored parameters...");

        // Get the program directly (it's already loaded)
        let program_ref = self.bpf.program_mut(&params.program_name).ok_or_else(|| {
            LoaderError::Generic(format!("Program '{}' not found", params.program_name))
        })?;

        let program: &mut UProbe = program_ref.try_into().map_err(|e| {
            LoaderError::Generic(format!(
                "Program '{}' is not a UProbe: {:?}",
                params.program_name, e
            ))
        })?;

        // Attach the uprobe directly (don't load - it's already loaded)
        let attach_result = if let Some(offset) = params.offset {
            program.attach(
                UProbeAttachLocation::AbsoluteOffset(offset),
                &params.target_binary,
                None,
                None,
            )
        } else {
            program.attach(
                params.function_name.as_str(),
                &params.target_binary,
                None,
                None,
            )
        };

        match attach_result {
            Ok(link) => {
                if let Some(offset) = params.offset {
                    info!(
                        "Uprobe reattached successfully to {} at offset 0x{:x}",
                        params.target_binary, offset
                    );
                } else {
                    info!(
                        "Uprobe reattached successfully to {}:{}",
                        params.target_binary, params.function_name
                    );
                }

                // Store the new link handle
                self.uprobe_link = Some(link);
                Ok(())
            }
            Err(e) => {
                error!("Failed to reattach uprobe: {:?}", e);
                Err(LoaderError::Program(e))
            }
        }
    }

    /// Check if the uprobe is currently attached
    pub fn is_uprobe_attached(&self) -> bool {
        self.uprobe_link.is_some()
    }

    /// Completely destroy this loader and all associated resources
    /// This detaches any attached uprobes and clears all eBPF resources
    /// After calling this, the loader cannot be reused
    pub fn destroy(&mut self) -> Result<()> {
        info!("Destroying GhostScopeLoader and all associated resources");

        // First detach uprobe if attached
        if self.uprobe_link.is_some() {
            if let Err(e) = self.detach_uprobe() {
                warn!("Failed to detach uprobe during destroy: {}", e);
                // Continue with destruction even if detach fails
            }
        }

        // Clear attachment parameters
        self.attachment_params = None;

        // Clear ringbuf reference (this doesn't destroy the actual eBPF map,
        // but removes our handle to it)
        self.ringbuf = None;

        // Note: The eBPF programs and maps will be automatically cleaned up
        // when the `bpf` field is dropped (when this struct is dropped)

        info!("GhostScopeLoader destroyed successfully");
        Ok(())
    }

    /// Get current attachment status information
    pub fn get_attachment_info(&self) -> Option<String> {
        if let Some(params) = &self.attachment_params {
            if let Some(offset) = params.offset {
                Some(format!(
                    "{}:{} (offset: 0x{:x}, pid: {:?}) - {}",
                    params.target_binary,
                    params.function_name,
                    offset,
                    params.pid,
                    if self.is_uprobe_attached() {
                        "attached"
                    } else {
                        "detached"
                    }
                ))
            } else {
                Some(format!(
                    "{}:{} (pid: {:?}) - {}",
                    params.target_binary,
                    params.function_name,
                    params.pid,
                    if self.is_uprobe_attached() {
                        "attached"
                    } else {
                        "detached"
                    }
                ))
            }
        } else {
            None
        }
    }

    /// Wait for events asynchronously using AsyncFd
    pub async fn wait_for_events_async(&mut self) -> Result<Vec<ParsedTraceEvent>> {
        let ringbuf = self.ringbuf.as_mut().ok_or_else(|| {
            LoaderError::Generic("Ringbuf not initialized. Call attach_uprobe first.".to_string())
        })?;

        // Create AsyncFd from the ringbuf's file descriptor
        let async_fd = AsyncFd::new(ringbuf.as_raw_fd())
            .map_err(|e| LoaderError::Generic(format!("Failed to create AsyncFd: {e}")))?;

        // Wait for the file descriptor to become readable (events available)
        let _guard = async_fd
            .readable()
            .await
            .map_err(|e| LoaderError::Generic(format!("AsyncFd error: {e}")))?;

        // Read all available events using streaming parser
        let mut events = Vec::new();

        // Check if we have a string table for parsing
        if let Some(string_table) = &self.string_table {
            while let Some(item) = ringbuf.next() {
                // Process segment with string table
                match self.parser.process_segment(&item, string_table) {
                    Ok(Some(parsed_event)) => {
                        // Directly use ParsedTraceEvent
                        events.push(parsed_event);
                    }
                    Ok(None) => {
                        // Segment processed but no complete event yet
                    }
                    Err(e) => {
                        warn!("Failed to parse trace event segment: {}", e);
                    }
                }
            }
        } else {
            return Err(LoaderError::Generic(
                "No string table available - cannot parse trace events".to_string(),
            ));
        }

        Ok(events)
    }

    /// Drain all currently available events without blocking
    pub fn drain_available_events(&mut self) -> Result<Vec<ParsedTraceEvent>> {
        let Some(ringbuf) = self.ringbuf.as_mut() else {
            return Ok(Vec::new());
        };

        let Some(string_table) = self.string_table.as_ref() else {
            return Err(LoaderError::Generic(
                "No string table available - cannot parse trace events".to_string(),
            ));
        };

        let mut events = Vec::new();

        while let Some(item) = ringbuf.next() {
            match self.parser.process_segment(&item, string_table) {
                Ok(Some(parsed_event)) => events.push(parsed_event),
                Ok(None) => {}
                Err(e) => {
                    warn!("Failed to parse trace event segment: {}", e);
                }
            }
        }

        Ok(events)
    }

    /// Set the string table for parsing trace events
    pub fn set_string_table(&mut self, string_table: StringTable) {
        info!("Setting string table for trace event parsing");
        self.string_table = Some(string_table);
    }

    // Helper functions removed - now using protocol parser

    /// Get information about loaded maps
    pub fn get_map_info(&self) -> Vec<String> {
        self.bpf
            .maps()
            .map(|(name, _map)| format!("Map: {name}"))
            .collect()
    }

    /// Get information about loaded programs
    pub fn get_program_info(&self) -> Vec<String> {
        self.bpf
            .programs()
            .map(|(name, _prog)| format!("Program: {name}"))
            .collect()
    }
}

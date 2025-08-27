use aya::{Ebpf, EbpfLoader, VerifierLogLevel, programs::{UProbe, uprobe::UProbeAttachLocation, ProgramError}, maps::RingBuf};
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
        info!("Loading eBPF program from bytecode ({} bytes)", bytecode.len());
        
        // Load BPF program from bytecode with high verifier log level for debugging
        match EbpfLoader::new()
            .verifier_log_level(VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS)
            .load(bytecode) {
            Ok(bpf) => {
                info!("Successfully loaded eBPF program");
                Ok(Self { 
                    bpf,
                    ringbuf: None,
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
    pub fn attach_uprobe(&mut self, target_binary: &str, function_name: &str, offset: Option<u64>, pid: Option<i32>) -> Result<()> {
        self.attach_uprobe_with_program_name(target_binary, function_name, offset, pid, None)
    }
    
    /// Attach to a uprobe with a specific eBPF program name
    pub fn attach_uprobe_with_program_name(&mut self, target_binary: &str, function_name: &str, offset: Option<u64>, pid: Option<i32>, program_name: Option<&str>) -> Result<()> {
        info!("attach_uprobe called with offset: {:?}", offset);
        if let Some(offset) = offset {
            info!("Using offset-based attachment: {} at 0x{:x} ({}) (pid: {:?})", target_binary, offset, function_name, pid);
        } else {
            info!("Using function name-based attachment: {}:{} (pid: {:?})", target_binary, function_name, pid);
        }
        
        // Collect all available program names first to avoid borrowing conflicts
        let available_programs: Vec<String> = self.bpf.programs().map(|(name, _)| name.to_string()).collect();
        
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
                return Err(LoaderError::Generic(format!("Specified program '{}' not found in eBPF object", name)));
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
                    info!("No standard program names found, using first available: {}", first_name);
                    found_program_name = Some(first_name.clone());
                }
            }
            
            found_program_name
                .ok_or_else(|| LoaderError::Generic("No suitable program found".to_string()))?
        };
            
        info!("Attempting to load program: {}", program_name);
        
        let program_ref = self.bpf
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
        
        let program: &mut UProbe = program_ref
            .try_into()
            .map_err(|e| LoaderError::Generic(format!("Program '{}' is not a UProbe: {:?}", program_name, e)))?;

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
                None
            )
        } else {
            // Use function name-based attachment  
            program.attach(function_name, target_binary, pid, None)
        };
        
        match attach_result {
            Ok(_) => {
                if let Some(offset) = offset {
                    info!("Uprobe attached successfully to {} at offset 0x{:x}", target_binary, offset);
                } else {
                    info!("Uprobe attached successfully to {}:{}", target_binary, function_name);
                }
            }
            Err(e) => {
                if let Some(offset) = offset {
                    error!("Failed to attach uprobe to {} at offset 0x{:x}: {}", target_binary, offset, e);
                    error!("Detailed error: {:#?}", e);
                } else {
                    error!("Failed to attach uprobe to {}:{}: {}", target_binary, function_name, e);
                    error!("Detailed error: {:#?}", e);
                }
                
                // Try to provide more helpful error information
                if let ProgramError::SyscallError(syscall_error) = &e {
                    error!("Syscall '{}' failed: {}", syscall_error.call, syscall_error.io_error);
                    if let Some(13) = syscall_error.io_error.raw_os_error() {
                        error!("Permission denied - make sure to run with sudo");
                    }
                }
                
                return Err(LoaderError::Program(e));
            }
        }

        // Initialize ringbuf after successful attachment
        // Use the same map name as generated in our codegen (ringbuf)
        let ringbuf: RingBuf<_> = self.bpf
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
        let ringbuf = self.ringbuf.as_mut()
            .ok_or_else(|| LoaderError::Generic("Ringbuf not initialized. Call attach_uprobe first.".to_string()))?;

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

    /// Parse event data into structured format (static version)
    fn parse_event_static(data: &[u8]) -> Option<EventData> {
        debug!("Processing event: {} bytes", data.len());
        
        match data.len() {
            8 => {
                // Try to parse as integer first, then float
                if let Some(int_val) = Self::try_parse_as_integer(data) {
                    Some(EventData::Integer(int_val))
                } else if let Some(float_val) = Self::try_parse_as_float(data) {
                    Some(EventData::Float(float_val))
                } else {
                    Some(EventData::Raw(data.to_vec()))
                }
            }
            len if len <= 64 => {
                // Try to parse as string
                if let Some(string_val) = Self::try_parse_as_string(data) {
                    Some(EventData::String(string_val))
                } else {
                    Some(EventData::Raw(data.to_vec()))
                }
            }
            _ => {
                Some(EventData::Raw(data.to_vec()))
            }
        }
    }

    /// Parse event data into structured format (instance method for compatibility)
    fn parse_event(&self, data: &[u8]) -> Option<EventData> {
        Self::parse_event_static(data)
    }

    fn try_parse_as_integer(data: &[u8]) -> Option<i64> {
        if data.len() == 8 {
            let bytes: [u8; 8] = data.try_into().ok()?;
            Some(i64::from_le_bytes(bytes))
        } else {
            None
        }
    }

    fn try_parse_as_float(data: &[u8]) -> Option<f64> {
        if data.len() == 8 {
            let bytes: [u8; 8] = data.try_into().ok()?;
            Some(f64::from_le_bytes(bytes))
        } else {
            None
        }
    }

    fn try_parse_as_string(data: &[u8]) -> Option<String> {
        // Try to parse as null-terminated string
        let null_pos = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let string_bytes = &data[..null_pos];
        
        std::str::from_utf8(string_bytes)
            .ok()
            .map(|s| s.to_string())
    }

    /// Get information about loaded maps
    pub fn get_map_info(&self) -> Vec<String> {
        self.bpf.maps()
            .map(|(name, _map)| format!("Map: {}", name))
            .collect()
    }

    /// Get information about loaded programs  
    pub fn get_program_info(&self) -> Vec<String> {
        self.bpf.programs()
            .map(|(name, _prog)| format!("Program: {}", name))
            .collect()
    }
}

/// Structured event data from eBPF program
#[derive(Debug, Clone)]
pub enum EventData {
    Integer(i64),
    Float(f64),
    String(String),
    Raw(Vec<u8>),
}

impl std::fmt::Display for EventData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventData::Integer(val) => write!(f, "{}", val),
            EventData::Float(val) => write!(f, "{}", val),
            EventData::String(val) => write!(f, "\"{}\"", val),
            EventData::Raw(data) => write!(f, "Raw({} bytes): {:?}", data.len(), data),
        }
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

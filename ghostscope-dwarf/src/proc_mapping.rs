//! Process memory mapping parser for module discovery
//!
//! Extracted from ghostscope-binary/src/process.rs

use crate::{DwarfError, Result};
use std::fs;
use std::path::PathBuf;

/// Memory mapping information from /proc/PID/maps
#[derive(Debug, Clone)]
pub struct MemoryMapping {
    pub start_addr: u64,
    pub end_addr: u64,
    pub permissions: String, // r-xp, rw-p etc.
    pub device: String,      // major:minor device
    pub inode: u64,
    pub pathname: Option<String>, // Binary file path
}

/// Module mapping information from proc maps analysis
#[derive(Debug, Clone)]
pub struct ModuleMapping {
    pub path: PathBuf,
    pub loaded_address: Option<u64>, // Loaded address in process (None for exec path mode)
    pub size: u64,
}

/// Process memory mapping parser
pub struct ProcMappingParser;

impl ProcMappingParser {
    /// Discover all modules for a given PID
    pub fn discover_modules(pid: u32) -> Result<Vec<ModuleMapping>> {
        tracing::info!("Discovering modules for PID {}", pid);

        let mappings = Self::parse_proc_maps(pid)?;
        tracing::info!("Found {} memory mappings", mappings.len());

        let mut module_mappings = Vec::new();
        let mut processed_paths = std::collections::HashSet::new();
        let mut processed_device_keys = std::collections::HashSet::new();

        // Process executable mappings to find modules
        for mapping in &mappings {
            if let Some(path) = &mapping.pathname {
                // Only process executable mappings and avoid duplicates
                if mapping.permissions.contains('x')
                    && processed_device_keys.insert((mapping.device.clone(), mapping.inode))
                    && processed_paths.insert(path.clone())
                {
                    match Self::try_create_module(path, mapping) {
                        Ok(module_mapping) => {
                            tracing::debug!(
                                "Discovered module: {} at 0x{:x}",
                                path,
                                mapping.start_addr
                            );
                            module_mappings.push(module_mapping);
                        }
                        Err(e) => {
                            tracing::debug!("Skipping module {}: {}", path, e);
                        }
                    }
                }
            }
        }

        tracing::info!("Successfully discovered {} modules", module_mappings.len());
        Ok(module_mappings)
    }

    /// Parse /proc/PID/maps file
    fn parse_proc_maps(pid: u32) -> Result<Vec<MemoryMapping>> {
        let maps_path = format!("/proc/{pid}/maps");
        tracing::debug!("Reading memory mappings from: {}", maps_path);

        let content =
            fs::read_to_string(&maps_path).map_err(|_e| DwarfError::ProcessNotFound { pid })?;

        let mut mappings = Vec::new();

        for line in content.lines() {
            if let Some(mapping) = Self::parse_maps_line(line) {
                mappings.push(mapping);
            }
        }

        Ok(mappings)
    }

    /// Parse single line from /proc/PID/maps
    /// Format: address perms offset dev inode pathname
    /// Example: 7f8b8c000000-7f8b8c028000 r--p 00000000 08:01 2097153 /lib64/ld-linux-x86-64.so.2
    fn parse_maps_line(line: &str) -> Option<MemoryMapping> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        // Parse address range
        let addr_parts: Vec<&str> = parts[0].split('-').collect();
        if addr_parts.len() != 2 {
            return None;
        }

        let start_addr = u64::from_str_radix(addr_parts[0], 16).ok()?;
        let end_addr = u64::from_str_radix(addr_parts[1], 16).ok()?;

        // Parse other fields
        let permissions = parts[1].to_string();
        let _ = u64::from_str_radix(parts[2], 16).ok()?;
        let device = parts[3].to_string();
        let inode = parts[4].parse().ok()?;

        // Pathname is optional (might be empty for anonymous mappings)
        let pathname = if parts.len() > 5 {
            let path_str = parts[5];
            // Filter out special entries like [stack], [vdso], etc.
            if path_str.starts_with('[') && path_str.ends_with(']') {
                None
            } else {
                Some(path_str.to_string())
            }
        } else {
            None
        };

        Some(MemoryMapping {
            start_addr,
            end_addr,
            permissions,
            device,
            inode,
            pathname,
        })
    }

    /// Try to create a module from a memory mapping
    fn try_create_module(path: &str, mapping: &MemoryMapping) -> Result<ModuleMapping> {
        tracing::debug!("Trying to create module from: {}", path);

        // Check if file exists and is accessible
        let path_buf = PathBuf::from(path);
        if !path_buf.exists() {
            return Err(DwarfError::ModuleNotFound { path: path_buf }.into());
        }

        // Determine if this is the main executable or a dynamic library
        let module_mapping = ModuleMapping {
            path: path_buf,
            loaded_address: Some(mapping.start_addr),
            size: mapping.end_addr - mapping.start_addr,
        };

        tracing::debug!(
            "Successfully created module: {} (size: {} bytes)",
            path,
            module_mapping.size
        );
        Ok(module_mapping)
    }
}

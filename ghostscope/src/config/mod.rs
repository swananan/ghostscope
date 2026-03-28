//! Configuration management for GhostScope
//!
//! This module handles both command line arguments and configuration file loading.
//! Configuration priority (highest to lowest):
//! 1. Command line arguments
//! 2. --config specified file
//! 3. ~/.ghostscope/config.toml
//! 4. ./ghostscope.toml

pub mod args;
pub mod merged;
pub mod runtime_env;
pub mod settings;

pub use crate::pid::{resolve_pid_info, ResolvedPidInfo};
pub use args::{Args, BpffsCommand, BpffsPruneArgs, LayoutMode, ParsedArgs, ParsedCommand};
pub use merged::MergedConfig;
pub use runtime_env::{detect_runtime_environment, RuntimeEnvironmentInfo};
pub use settings::{Config, LogLevel, PanelType};

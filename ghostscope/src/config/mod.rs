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

pub use args::{
    Args, BpffsCommand, BpffsPruneArgs, LayoutMode, ParsedArgs, ParsedCommand, ScriptOutputMode,
    ScriptTimestampFormat,
};
pub use ghostscope_process::{resolve_input_pid, PidViews};
pub use merged::MergedConfig;
pub use runtime_env::{detect_runtime_environment, RuntimeEnvironmentInfo};
pub use settings::{CliColorMode, Config, LogLevel, PanelType};

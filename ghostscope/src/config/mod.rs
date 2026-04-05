//! Configuration management for GhostScope
//!
//! This module handles both command line arguments and configuration file loading.
//! Configuration priority (highest to lowest):
//! 1. Command line arguments
//! 2. --config specified file
//! 3. ~/.ghostscope/config.toml
//! 4. ./ghostscope.toml

pub mod args;
pub mod runtime;
pub mod settings;
pub mod user;

pub use args::{
    Args, BpffsCommand, BpffsPruneArgs, LayoutMode, ParsedArgs, ParsedCommand, ScriptOutputMode,
    ScriptTimestampFormat,
};
pub use ghostscope_process::PidViews;
pub use runtime::ResolvedConfig;
pub use settings::{CliColorMode, Config, LogLevel, PanelType};
pub use user::UserConfig;

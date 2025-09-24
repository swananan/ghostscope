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
pub mod settings;

pub use args::{Args, LayoutMode, ParsedArgs};
pub use merged::{CompilerConfiguration, DwarfConfiguration, MergedConfig};
pub use settings::{Config, LogLevel, PanelType, UiConfigToml};

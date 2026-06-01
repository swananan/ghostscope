use crate::config::CliColorMode;
use std::fmt::Display;
use std::io::{self, IsTerminal};

#[derive(Debug, Clone, Copy)]
pub struct CliColors {
    enabled: bool,
}

impl CliColors {
    pub fn for_stdout(mode: CliColorMode) -> Self {
        Self::new(mode.use_ansi(io::stdout().is_terminal()))
    }

    pub fn for_stderr(mode: CliColorMode) -> Self {
        Self::new(mode.use_ansi(io::stderr().is_terminal()))
    }

    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn dim<T: Display>(&self, value: T) -> String {
        self.wrap("2", value)
    }

    pub fn bold<T: Display>(&self, value: T) -> String {
        self.wrap("1", value)
    }

    pub fn cyan<T: Display>(&self, value: T) -> String {
        self.wrap("36", value)
    }

    pub fn blue<T: Display>(&self, value: T) -> String {
        self.wrap("34", value)
    }

    pub fn green<T: Display>(&self, value: T) -> String {
        self.wrap("32", value)
    }

    pub fn yellow<T: Display>(&self, value: T) -> String {
        self.wrap("33", value)
    }

    pub fn magenta<T: Display>(&self, value: T) -> String {
        self.wrap("35", value)
    }

    pub fn red<T: Display>(&self, value: T) -> String {
        self.wrap("31", value)
    }

    fn wrap<T: Display>(&self, code: &str, value: T) -> String {
        if self.enabled {
            format!("\x1b[{code}m{value}\x1b[0m")
        } else {
            value.to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CliColors;

    #[test]
    fn colors_can_be_disabled() {
        let colors = CliColors::new(false);
        assert_eq!(colors.green("ready"), "ready");
    }

    #[test]
    fn colors_emit_ansi_when_enabled() {
        let colors = CliColors::new(true);
        assert_eq!(colors.green("ready"), "\u{1b}[32mready\u{1b}[0m");
    }
}

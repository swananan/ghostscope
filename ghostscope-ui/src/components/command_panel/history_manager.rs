use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct CommandHistory {
    entries: Vec<String>,
    file_path: PathBuf,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct HistorySearchState {
    pub is_active: bool,
    pub query: String,
    pub current_index: Option<usize>,
    pub matches: Vec<usize>,
    pub current_match_index: usize,
}

#[derive(Debug, Clone)]
pub struct AutoSuggestionState {
    pub suggestion: Option<String>,
    pub start_position: usize,
}

impl CommandHistory {
    pub fn new() -> Self {
        Self::new_with_config(&crate::model::ui_state::HistoryConfig::default())
    }

    pub fn new_with_config(config: &crate::model::ui_state::HistoryConfig) -> Self {
        let file_path = if config.enabled {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".ghostscope_history")
        } else {
            // Use empty path when disabled - won't save to file
            PathBuf::new()
        };

        let mut history = Self {
            entries: Vec::new(),
            file_path,
            max_entries: config.max_entries,
        };

        if config.enabled {
            history.load_from_file();
        }
        history
    }

    pub fn load_from_file(&mut self) {
        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);
            let mut entries = Vec::new();

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if !line.trim().is_empty() {
                            entries.push(line);
                        }
                    }
                    Err(_) => continue,
                }
            }

            self.entries = entries;
        }
    }

    pub fn save_to_file(&self) {
        // Don't save if path is empty (history disabled)
        if self.file_path.as_os_str().is_empty() {
            return;
        }

        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.file_path)
        {
            for entry in &self.entries {
                let _ = writeln!(file, "{entry}");
            }
        }
    }

    pub fn add_command(&mut self, command: &str) {
        let cmd = command.trim().to_string();
        if cmd.is_empty() {
            return;
        }

        if let Some(last) = self.entries.last() {
            if last == &cmd {
                return;
            }
        }

        self.entries.push(cmd);

        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }

        self.save_to_file();
    }

    pub fn search_backwards(&self, query: &str, start_from: Option<usize>) -> Vec<usize> {
        if query.is_empty() {
            return Vec::new();
        }

        let start_index = start_from.unwrap_or(self.entries.len());
        let mut matches = Vec::new();

        for i in (0..start_index.min(self.entries.len())).rev() {
            if self.entries[i].contains(query) {
                matches.push(i);
            }
        }

        matches
    }

    pub fn get_prefix_match(&self, prefix: &str) -> Option<&str> {
        if prefix.is_empty() {
            return None;
        }

        self.entries
            .iter()
            .rev()
            .find(|entry| entry.starts_with(prefix) && entry.as_str() != prefix)
            .map(|entry| entry.as_str())
    }

    pub fn get_entry(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(|s| s.as_str())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl HistorySearchState {
    pub fn new() -> Self {
        Self {
            is_active: false,
            query: String::new(),
            current_index: None,
            matches: Vec::new(),
            current_match_index: 0,
        }
    }

    pub fn start_search(&mut self) {
        self.is_active = true;
        self.query.clear();
        self.current_index = None;
        self.matches.clear();
        self.current_match_index = 0;
    }

    pub fn update_query(&mut self, query: String, history: &CommandHistory) {
        self.query = query;
        self.matches = history.search_backwards(&self.query, None);
        self.current_match_index = 0;
        self.current_index = self.matches.first().copied();
    }

    pub fn next_match<'a>(&mut self, history: &'a CommandHistory) -> Option<&'a str> {
        if self.matches.is_empty() {
            return None;
        }

        self.current_match_index = (self.current_match_index + 1) % self.matches.len();
        self.current_index = Some(self.matches[self.current_match_index]);

        if let Some(index) = self.current_index {
            history.get_entry(index)
        } else {
            None
        }
    }

    pub fn current_match<'a>(&self, history: &'a CommandHistory) -> Option<&'a str> {
        if let Some(index) = self.current_index {
            history.get_entry(index)
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.is_active = false;
        self.query.clear();
        self.current_index = None;
        self.matches.clear();
        self.current_match_index = 0;
    }
}

impl AutoSuggestionState {
    pub fn new() -> Self {
        Self {
            suggestion: None,
            start_position: 0,
        }
    }

    pub fn update(&mut self, input: &str, history: &CommandHistory) {
        if input.is_empty() {
            self.clear();
            return;
        }

        // First check static commands
        if let Some(static_match) = Self::get_static_command_match(input) {
            if static_match != input {
                self.suggestion = Some(static_match);
                self.start_position = input.len();
                return;
            }
        }

        // Then check history
        if let Some(matched_command) = history.get_prefix_match(input) {
            if matched_command != input {
                self.suggestion = Some(matched_command.to_string());
                self.start_position = input.len();
            } else {
                self.clear();
            }
        } else {
            self.clear();
        }
    }

    fn get_static_command_match(prefix: &str) -> Option<String> {
        // Built-in commands for auto-completion
        const COMMANDS: &[&str] = &[
            "save traces",
            "save traces enabled",
            "save traces disabled",
            "source",
            "info trace",
            "info source",
            "info share",
            "info share all",
            "info function",
            "info line",
            "info address",
            "trace",
            "enable",
            "disable",
            "delete",
            "delete all",
            "disable all",
            "enable all",
            "quit",
            "exit",
            "clear",
            "help",
        ];

        COMMANDS
            .iter()
            .find(|cmd| cmd.starts_with(prefix) && **cmd != prefix)
            .map(|cmd| cmd.to_string())
    }

    pub fn get_suggestion_text(&self) -> Option<&str> {
        if let Some(ref suggestion) = self.suggestion {
            if suggestion.len() > self.start_position {
                return Some(&suggestion[self.start_position..]);
            }
        }
        None
    }

    pub fn get_full_suggestion(&self) -> Option<&str> {
        self.suggestion.as_deref()
    }

    pub fn clear(&mut self) {
        self.suggestion = None;
        self.start_position = 0;
    }
}

// Test helper methods - available in tests
impl CommandHistory {
    /// Create a new history without loading from file (for testing)
    #[doc(hidden)]
    pub fn new_for_test() -> Self {
        Self {
            entries: Vec::new(),
            file_path: PathBuf::new(), // Empty path prevents file operations
            max_entries: 1000,
        }
    }

    /// Get all entries for testing (only available in test builds)
    #[doc(hidden)]
    pub fn get_entries_for_test(&self) -> Vec<String> {
        self.entries.clone()
    }

    /// Get entry at specific index for testing
    #[doc(hidden)]
    pub fn get_at(&self, index: usize) -> Option<String> {
        self.entries.get(index).cloned()
    }

    /// Get entries in reverse order (as they would appear when navigating)
    #[doc(hidden)]
    pub fn get_entries_reversed(&self) -> Vec<String> {
        self.entries.iter().rev().cloned().collect()
    }
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HistorySearchState {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for AutoSuggestionState {
    fn default() -> Self {
        Self::new()
    }
}

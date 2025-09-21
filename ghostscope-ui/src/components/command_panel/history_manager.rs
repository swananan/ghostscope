use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// 命令历史管理器
#[derive(Debug, Clone)]
pub struct CommandHistory {
    entries: Vec<String>,
    file_path: PathBuf,
    max_entries: usize,
}

/// 历史搜索状态
#[derive(Debug, Clone)]
pub struct HistorySearchState {
    pub is_active: bool,
    pub query: String,
    pub current_index: Option<usize>,
    pub matches: Vec<usize>, // 匹配的历史条目索引
    pub current_match_index: usize,
}

/// 自动提示状态
#[derive(Debug, Clone)]
pub struct AutoSuggestionState {
    pub suggestion: Option<String>,
    pub start_position: usize,
}

impl CommandHistory {
    pub fn new() -> Self {
        let file_path = std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(".ghostscope_history");

        let mut history = Self {
            entries: Vec::new(),
            file_path,
            max_entries: 1000, // 类似 bash HISTSIZE
        };

        history.load_from_file();
        history
    }

    /// 从文件加载历史记录
    pub fn load_from_file(&mut self) {
        if let Ok(file) = File::open(&self.file_path) {
            let reader = BufReader::new(file);
            self.entries = reader
                .lines()
                .filter_map(|line| line.ok())
                .filter(|line| !line.trim().is_empty())
                .collect();
        }
    }

    /// 保存历史记录到文件
    pub fn save_to_file(&self) {
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.file_path)
        {
            for entry in &self.entries {
                let _ = writeln!(file, "{}", entry);
            }
        }
    }

    /// 添加新命令到历史记录
    pub fn add_command(&mut self, command: &str) {
        let cmd = command.trim().to_string();
        if cmd.is_empty() {
            return;
        }

        // 避免重复添加相同命令
        if let Some(last) = self.entries.last() {
            if last == &cmd {
                return;
            }
        }

        self.entries.push(cmd);

        // 限制历史记录数量
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }

        self.save_to_file();
    }

    /// 反向搜索匹配的命令
    pub fn search_backwards(&self, query: &str, start_from: Option<usize>) -> Vec<usize> {
        if query.is_empty() {
            return Vec::new();
        }

        let start_index = start_from.unwrap_or(self.entries.len());
        let mut matches = Vec::new();

        // 从指定位置向前搜索
        for i in (0..start_index.min(self.entries.len())).rev() {
            if self.entries[i].contains(query) {
                matches.push(i);
            }
        }

        matches
    }

    /// 获取前缀匹配的命令
    pub fn get_prefix_match(&self, prefix: &str) -> Option<&str> {
        if prefix.is_empty() {
            return None;
        }

        // 从最新的命令开始向前查找
        for entry in self.entries.iter().rev() {
            if entry.starts_with(prefix) && entry != prefix {
                return Some(entry);
            }
        }

        None
    }

    /// 获取指定索引的条目
    pub fn get_entry(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(|s| s.as_str())
    }

    /// 获取历史记录数量
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// 检查是否为空
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

    /// 开始历史搜索
    pub fn start_search(&mut self) {
        self.is_active = true;
        self.query.clear();
        self.current_index = None;
        self.matches.clear();
        self.current_match_index = 0;
    }

    /// 更新搜索查询
    pub fn update_query(&mut self, query: String, history: &CommandHistory) {
        self.query = query;
        self.matches = history.search_backwards(&self.query, None);
        self.current_match_index = 0;
        self.current_index = self.matches.first().copied();
    }

    /// 移动到下一个匹配项
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

    /// 获取当前匹配项
    pub fn current_match<'a>(&self, history: &'a CommandHistory) -> Option<&'a str> {
        if let Some(index) = self.current_index {
            history.get_entry(index)
        } else {
            None
        }
    }

    /// 清除搜索状态
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

    /// 更新自动提示
    pub fn update(&mut self, input: &str, history: &CommandHistory) {
        if input.is_empty() {
            self.clear();
            return;
        }

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

    /// 获取建议的文本部分
    pub fn get_suggestion_text(&self) -> Option<&str> {
        if let Some(ref suggestion) = self.suggestion {
            if suggestion.len() > self.start_position {
                return Some(&suggestion[self.start_position..]);
            }
        }
        None
    }

    /// 获取完整的建议命令
    pub fn get_full_suggestion(&self) -> Option<&str> {
        self.suggestion.as_deref()
    }

    /// 清除自动提示
    pub fn clear(&mut self) {
        self.suggestion = None;
        self.start_position = 0;
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

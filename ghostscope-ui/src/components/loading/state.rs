use std::time::Instant;

/// Loading states for different initialization phases
#[derive(Debug, Clone, PartialEq)]
pub enum LoadingState {
    /// Application is starting up
    Initializing,
    /// Waiting for runtime to connect
    ConnectingToRuntime,
    /// Waiting for DWARF symbols to load
    LoadingSymbols { progress: Option<f64> },
    /// Waiting for source code information
    LoadingSourceCode,
    /// Loading completed, application ready
    Ready,
    /// Loading failed with error
    Failed(String),
}

impl LoadingState {
    /// Get display message for current loading state
    pub fn message(&self) -> &str {
        match self {
            LoadingState::Initializing => "Initializing application...",
            LoadingState::ConnectingToRuntime => "Connecting to runtime...",
            LoadingState::LoadingSymbols { .. } => "Loading debug information...",
            LoadingState::LoadingSourceCode => "Loading source code information...",
            LoadingState::Ready => "Ready",
            LoadingState::Failed(error) => error,
        }
    }

    /// Get progress value (0.0 to 1.0) if available
    pub fn progress(&self) -> Option<f64> {
        match self {
            LoadingState::LoadingSymbols { progress } => *progress,
            LoadingState::Ready => Some(1.0),
            _ => None,
        }
    }

    /// Check if loading is complete
    pub fn is_ready(&self) -> bool {
        matches!(self, LoadingState::Ready)
    }

    /// Check if loading failed
    pub fn is_failed(&self) -> bool {
        matches!(self, LoadingState::Failed(_))
    }
}

/// Module loading status for individual modules
#[derive(Debug, Clone)]
pub struct ModuleLoadStatus {
    pub path: String,
    pub state: ModuleState,
    pub stats: Option<ModuleStats>,
    pub start_time: Option<Instant>,
    pub load_time: Option<f64>, // seconds
}

#[derive(Debug, Clone)]
pub enum ModuleState {
    Queued,
    Loading,
    Completed,
    Failed(String),
}

#[derive(Debug, Clone)]
pub struct ModuleStats {
    pub functions: usize,
    pub variables: usize,
    pub types: usize,
}

impl ModuleLoadStatus {
    pub fn new(path: String) -> Self {
        Self {
            path,
            state: ModuleState::Queued,
            stats: None,
            start_time: None,
            load_time: None,
        }
    }

    pub fn start_loading(&mut self) {
        self.state = ModuleState::Loading;
        self.start_time = Some(Instant::now());
    }

    pub fn complete(&mut self, stats: ModuleStats) {
        if let Some(start_time) = self.start_time {
            self.load_time = Some(start_time.elapsed().as_secs_f64());
        }
        self.state = ModuleState::Completed;
        self.stats = Some(stats);
    }

    pub fn fail(&mut self, error: String) {
        if let Some(start_time) = self.start_time {
            self.load_time = Some(start_time.elapsed().as_secs_f64());
        }
        self.state = ModuleState::Failed(error);
    }
}

/// Overall loading progress tracking
#[derive(Debug, Clone)]
pub struct LoadingProgress {
    pub start_time: Instant,
    pub modules: Vec<ModuleLoadStatus>,
    pub completed_count: usize,
    pub failed_count: usize,
    pub current_loading: Option<String>,
}

impl LoadingProgress {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            modules: Vec::new(),
            completed_count: 0,
            failed_count: 0,
            current_loading: None,
        }
    }

    pub fn add_module(&mut self, path: String) {
        self.modules.push(ModuleLoadStatus::new(path));
    }

    pub fn start_module_loading(&mut self, path: &str) {
        if let Some(module) = self.modules.iter_mut().find(|m| m.path == path) {
            module.start_loading();
            self.current_loading = Some(path.to_string());
        }
    }

    pub fn complete_module(&mut self, path: &str, stats: ModuleStats) {
        if let Some(module) = self.modules.iter_mut().find(|m| m.path == path) {
            module.complete(stats);
            self.completed_count += 1;
            if self.current_loading.as_deref() == Some(path) {
                self.current_loading = None;
            }
        }
    }

    pub fn fail_module(&mut self, path: &str, error: String) {
        if let Some(module) = self.modules.iter_mut().find(|m| m.path == path) {
            module.fail(error);
            self.failed_count += 1;
            if self.current_loading.as_deref() == Some(path) {
                self.current_loading = None;
            }
        }
    }

    pub fn total_modules(&self) -> usize {
        self.modules.len()
    }

    pub fn progress_ratio(&self) -> f64 {
        if self.modules.is_empty() {
            0.0
        } else {
            (self.completed_count + self.failed_count) as f64 / self.modules.len() as f64
        }
    }

    pub fn elapsed_time(&self) -> f64 {
        self.start_time.elapsed().as_secs_f64()
    }

    pub fn recently_completed(&self, limit: usize) -> Vec<&ModuleLoadStatus> {
        self.modules
            .iter()
            .filter(|m| matches!(m.state, ModuleState::Completed))
            .rev()
            .take(limit)
            .collect()
    }

    pub fn recently_failed(&self, limit: usize) -> Vec<&ModuleLoadStatus> {
        self.modules
            .iter()
            .filter(|m| matches!(m.state, ModuleState::Failed(_)))
            .rev()
            .take(limit)
            .collect()
    }

    pub fn recently_finished(&self, limit: usize) -> Vec<&ModuleLoadStatus> {
        self.modules
            .iter()
            .filter(|m| matches!(m.state, ModuleState::Completed | ModuleState::Failed(_)))
            .rev()
            .take(limit)
            .collect()
    }

    pub fn total_stats(&self) -> ModuleStats {
        let mut total = ModuleStats {
            functions: 0,
            variables: 0,
            types: 0,
        };

        for module in &self.modules {
            if let Some(stats) = &module.stats {
                total.functions += stats.functions;
                total.variables += stats.variables;
                total.types += stats.types;
            }
        }

        total
    }

    pub fn is_complete(&self) -> bool {
        !self.modules.is_empty() && (self.completed_count + self.failed_count) == self.modules.len()
    }
}

impl Default for LoadingProgress {
    fn default() -> Self {
        Self::new()
    }
}

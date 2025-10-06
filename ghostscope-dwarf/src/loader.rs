//! Module loading with Builder pattern and parallel support

use crate::{
    analyzer::{ModuleLoadingEvent, ModuleLoadingStats},
    core::Result,
    module::ModuleData,
    proc_mapping::ModuleMapping,
};
use std::sync::Arc;
use tokio::task;

/// Configuration for module loading (parallel only)
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// Maximum number of concurrent module loads
    pub max_module_concurrency: usize,
    /// Debug file search paths (for .gnu_debuglink)
    pub debug_search_paths: Vec<String>,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
            debug_search_paths: Vec::new(),
        }
    }
}

impl LoadConfig {
    /// Fast loading with maximum concurrency
    pub fn fast() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
            debug_search_paths: Vec::new(),
        }
    }
}

/// Builder for loading modules with flexible parallelism options
pub struct ModuleLoader {
    mappings: Vec<ModuleMapping>,
    config: LoadConfig,
}

impl ModuleLoader {
    /// Create a new loader with given module mappings
    pub fn new(mappings: Vec<ModuleMapping>) -> Self {
        Self {
            mappings,
            config: LoadConfig::default(),
        }
    }

    /// Use predefined parallel configuration
    pub fn parallel(mut self) -> Self {
        self.config = LoadConfig::fast();
        self
    }

    /// Set debug search paths for .gnu_debuglink files
    pub fn with_debug_search_paths(mut self, paths: Vec<String>) -> Self {
        self.config.debug_search_paths = paths;
        self
    }

    /// Load with progress callback - always parallel
    pub async fn load_with_progress<F>(self, progress_callback: F) -> Result<Vec<ModuleData>>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        self.load_modules_parallel_with_progress(progress_callback)
            .await
    }

    /// Add progress callback (method chaining convenience)
    pub fn with_progress_callback<F>(self, progress_callback: F) -> ModuleLoaderWithCallback<F>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        ModuleLoaderWithCallback {
            loader: self,
            callback: progress_callback,
        }
    }

    /// Load modules in parallel with progress tracking
    async fn load_modules_parallel_with_progress<F>(
        self,
        progress_callback: F,
    ) -> Result<Vec<ModuleData>>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        // Use semaphore to limit concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_module_concurrency,
        ));

        let total_modules = self.mappings.len();
        let progress_callback = Arc::new(progress_callback);
        let debug_search_paths = Arc::new(self.config.debug_search_paths.clone());

        let tasks: Vec<_> = self
            .mappings
            .into_iter()
            .enumerate()
            .map(|(index, mapping)| {
                let semaphore = semaphore.clone();
                let progress_callback = progress_callback.clone();
                let debug_search_paths = debug_search_paths.clone();

                task::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();

                    let module_path = mapping.path.to_string_lossy().to_string();

                    // Notify loading started
                    progress_callback(ModuleLoadingEvent::LoadingStarted {
                        module_path: module_path.clone(),
                        current: index + 1,
                        total: total_modules,
                    });

                    let start_time = std::time::Instant::now();

                    let result = ModuleData::load_parallel(mapping, &debug_search_paths).await;

                    let load_time_ms = start_time.elapsed().as_millis() as u64;

                    match result {
                        Ok(module) => {
                            // Extract stats for progress reporting
                            let (functions, variables, types) =
                                module.get_lightweight_index().get_stats();
                            let stats = ModuleLoadingStats {
                                functions,
                                variables,
                                types,
                                load_time_ms,
                            };

                            progress_callback(ModuleLoadingEvent::LoadingCompleted {
                                module_path,
                                stats,
                                current: index + 1,
                                total: total_modules,
                            });

                            Ok(module)
                        }
                        Err(e) => {
                            progress_callback(ModuleLoadingEvent::LoadingFailed {
                                module_path,
                                error: e.to_string(),
                                current: index + 1,
                                total: total_modules,
                            });
                            Err(e)
                        }
                    }
                })
            })
            .collect();

        let results = futures::future::try_join_all(tasks).await?;
        let modules: Result<Vec<_>> = results.into_iter().collect();
        modules
    }
}

/// ModuleLoader with attached progress callback (for method chaining)
pub struct ModuleLoaderWithCallback<F>
where
    F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
{
    loader: ModuleLoader,
    callback: F,
}

impl<F> ModuleLoaderWithCallback<F>
where
    F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
{
    /// Load modules with attached progress callback
    pub async fn load(self) -> Result<Vec<ModuleData>> {
        self.loader.load_with_progress(self.callback).await
    }
}

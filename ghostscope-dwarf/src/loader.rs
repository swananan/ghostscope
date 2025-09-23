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
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
        }
    }
}

impl LoadConfig {
    /// Fast loading with maximum concurrency
    pub fn fast() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
        }
    }

    /// Conservative loading with limited concurrency
    pub fn conservative(concurrency: usize) -> Self {
        Self {
            max_module_concurrency: concurrency.max(1),
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

    /// Set maximum concurrency for module loading
    pub fn max_concurrency(mut self, limit: usize) -> Self {
        self.config.max_module_concurrency = limit;
        self
    }

    /// Use predefined parallel configuration
    pub fn parallel(mut self) -> Self {
        self.config = LoadConfig::fast();
        self
    }

    /// Load modules synchronously (blocking) - now always uses parallel loading
    pub fn load_sync(self) -> Result<Vec<ModuleData>> {
        // Always use async runtime for parallel loading
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(self.load_async())
    }

    /// Load modules asynchronously - always parallel
    pub async fn load_async(self) -> Result<Vec<ModuleData>> {
        self.load_modules_parallel().await
    }

    /// Unified load method - automatically chooses sync/async based on configuration
    pub async fn load(self) -> Result<Vec<ModuleData>> {
        self.load_async().await
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

    /// Load modules in parallel
    async fn load_modules_parallel(self) -> Result<Vec<ModuleData>> {
        // Use semaphore to limit concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_module_concurrency,
        ));

        let tasks: Vec<_> = self
            .mappings
            .into_iter()
            .map(|mapping| {
                let semaphore = Arc::clone(&semaphore);

                task::spawn(async move {
                    let _permit = semaphore.acquire().await?;

                    ModuleData::load_parallel(mapping).await
                })
            })
            .collect();

        let results = futures::future::try_join_all(tasks).await?;
        results.into_iter().collect::<Result<Vec<_>>>()
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

        let tasks: Vec<_> = self
            .mappings
            .into_iter()
            .enumerate()
            .map(|(index, mapping)| {
                let semaphore = semaphore.clone();
                let progress_callback = progress_callback.clone();

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

                    let result = ModuleData::load_parallel(mapping).await;

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

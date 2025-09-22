//! Module loading with Builder pattern and parallel support

use crate::{
    analyzer::{ModuleLoadingEvent, ModuleLoadingStats},
    core::Result,
    module::ModuleData,
    proc_mapping::ModuleMapping,
};
use std::sync::Arc;
use tokio::task;

/// Configuration for module loading
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// Whether to load multiple modules in parallel
    pub parallel_modules: bool,
    /// Whether to parse sections (debug_line, debug_info, CFI) in parallel within each module
    pub parallel_sections: bool,
    /// Maximum number of concurrent module loads
    pub max_module_concurrency: usize,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            parallel_modules: true,
            parallel_sections: true,
            max_module_concurrency: num_cpus::get(),
        }
    }
}

impl LoadConfig {
    /// Fast loading with full parallelism
    pub fn fast() -> Self {
        Self {
            parallel_modules: true,
            parallel_sections: true,
            max_module_concurrency: num_cpus::get(),
        }
    }

    /// Conservative loading (sequential)
    pub fn sequential() -> Self {
        Self {
            parallel_modules: false,
            parallel_sections: false,
            max_module_concurrency: 1,
        }
    }

    /// Parallel modules but sequential sections
    pub fn parallel_modules_only() -> Self {
        Self {
            parallel_modules: true,
            parallel_sections: false,
            max_module_concurrency: num_cpus::get(),
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

    /// Enable/disable parallel loading of multiple modules
    pub fn parallel_modules(mut self, enable: bool) -> Self {
        self.config.parallel_modules = enable;
        self
    }

    /// Enable/disable parallel parsing of sections within each module
    pub fn parallel_sections(mut self, enable: bool) -> Self {
        self.config.parallel_sections = enable;
        self
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

    /// Use predefined sequential configuration
    pub fn sequential(mut self) -> Self {
        self.config = LoadConfig::sequential();
        self
    }

    /// Load modules synchronously (blocking)
    pub fn load_sync(self) -> Result<Vec<ModuleData>> {
        if self.config.parallel_modules || self.config.parallel_sections {
            // Use async runtime for parallel loading
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(self.load_async())
        } else {
            // Pure synchronous loading
            self.load_sequential_sync()
        }
    }

    /// Load modules asynchronously
    pub async fn load_async(self) -> Result<Vec<ModuleData>> {
        if self.config.parallel_modules {
            self.load_modules_parallel().await
        } else {
            self.load_modules_sequential().await
        }
    }

    /// Unified load method - automatically chooses sync/async based on configuration
    pub async fn load(self) -> Result<Vec<ModuleData>> {
        self.load_async().await
    }

    /// Load with progress callback
    pub async fn load_with_progress<F>(self, progress_callback: F) -> Result<Vec<ModuleData>>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        if self.config.parallel_modules {
            self.load_modules_parallel_with_progress(progress_callback)
                .await
        } else {
            self.load_modules_sequential_with_progress(progress_callback)
                .await
        }
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

    /// Sequential synchronous loading (no async runtime needed)
    fn load_sequential_sync(self) -> Result<Vec<ModuleData>> {
        let mut modules = Vec::with_capacity(self.mappings.len());

        for mapping in self.mappings {
            let module = if self.config.parallel_sections {
                // This shouldn't happen with sequential config, but handle it
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(ModuleData::load_parallel(mapping))?
            } else {
                ModuleData::load_sequential(mapping)?
            };
            modules.push(module);
        }

        Ok(modules)
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
                let parallel_sections = self.config.parallel_sections;

                task::spawn(async move {
                    let _permit = semaphore.acquire().await?;

                    if parallel_sections {
                        ModuleData::load_parallel(mapping).await
                    } else {
                        // Run sync version in blocking task
                        task::spawn_blocking(move || ModuleData::load_sequential(mapping)).await?
                    }
                })
            })
            .collect();

        let results = futures::future::try_join_all(tasks).await?;
        results.into_iter().collect::<Result<Vec<_>>>()
    }

    /// Load modules sequentially (but potentially with parallel sections)
    async fn load_modules_sequential(self) -> Result<Vec<ModuleData>> {
        let mut modules = Vec::with_capacity(self.mappings.len());

        for mapping in self.mappings {
            let module = if self.config.parallel_sections {
                ModuleData::load_parallel(mapping).await?
            } else {
                task::spawn_blocking(move || ModuleData::load_sequential(mapping)).await??
            };
            modules.push(module);
        }

        Ok(modules)
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
                let parallel_sections = self.config.parallel_sections;

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

                    let result = if parallel_sections {
                        ModuleData::load_parallel(mapping).await
                    } else {
                        task::spawn_blocking(move || ModuleData::load_sequential(mapping)).await?
                    };

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

    /// Load modules sequentially with progress tracking
    async fn load_modules_sequential_with_progress<F>(
        self,
        progress_callback: F,
    ) -> Result<Vec<ModuleData>>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        let mut modules = Vec::with_capacity(self.mappings.len());
        let total_modules = self.mappings.len();

        for (index, mapping) in self.mappings.into_iter().enumerate() {
            let module_path = mapping.path.to_string_lossy().to_string();

            // Notify loading started
            progress_callback(ModuleLoadingEvent::LoadingStarted {
                module_path: module_path.clone(),
                current: index + 1,
                total: total_modules,
            });

            let start_time = std::time::Instant::now();

            let result = if self.config.parallel_sections {
                ModuleData::load_parallel(mapping).await
            } else {
                task::spawn_blocking(move || ModuleData::load_sequential(mapping)).await?
            };

            let load_time_ms = start_time.elapsed().as_millis() as u64;

            match result {
                Ok(module) => {
                    // Extract stats for progress reporting
                    let (functions, variables, types) = module.get_lightweight_index().get_stats();
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

                    modules.push(module);
                }
                Err(e) => {
                    progress_callback(ModuleLoadingEvent::LoadingFailed {
                        module_path,
                        error: e.to_string(),
                        current: index + 1,
                        total: total_modules,
                    });
                    return Err(e);
                }
            }
        }

        Ok(modules)
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

//! Module loading with Builder pattern and parallel support

use crate::{core::Result, module::ModuleData, proc_mapping::ModuleMapping};
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
}

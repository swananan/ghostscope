//! Module loading with Builder pattern and parallel support

use crate::{
    analyzer::{ModuleLoadingEvent, ModuleLoadingStats},
    core::{mapping::ModuleMapping, Result},
    objfile::LoadedObjfile,
};
use ghostscope_debuginfod::DebuginfodClient;
use std::ffi::OsStr;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tokio::task;

/// A user-provided debug file bound to one loaded module.
#[derive(Debug, Clone)]
pub struct ExplicitDebugFile {
    pub target_module: PathBuf,
    pub debug_file: PathBuf,
}

impl ExplicitDebugFile {
    pub fn new(target_module: PathBuf, debug_file: PathBuf) -> Self {
        Self {
            target_module,
            debug_file,
        }
    }

    fn matches_module(&self, module_path: &Path) -> bool {
        paths_equivalent(module_path, &self.target_module)
    }
}

/// Configuration for module loading (parallel only)
#[derive(Debug, Clone)]
pub struct LoadConfig {
    /// Maximum number of concurrent module loads
    pub max_module_concurrency: usize,
    /// Debug file search paths (for .gnu_debuglink)
    pub debug_search_paths: Vec<String>,
    /// Allow non-strict debug file matching (CRC/Build-ID)
    pub allow_loose_debug_match: bool,
    /// Optional user-provided debug file for one target module.
    pub explicit_debug_file: Option<ExplicitDebugFile>,
    /// Optional debuginfod client for build-id based debug file lookup.
    pub debuginfod_client: Option<Arc<DebuginfodClient>>,
}

impl Default for LoadConfig {
    fn default() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
            debug_search_paths: Vec::new(),
            allow_loose_debug_match: false,
            explicit_debug_file: None,
            debuginfod_client: None,
        }
    }
}

impl LoadConfig {
    /// Fast loading with maximum concurrency
    pub fn fast() -> Self {
        Self {
            max_module_concurrency: num_cpus::get(),
            debug_search_paths: Vec::new(),
            allow_loose_debug_match: false,
            explicit_debug_file: None,
            debuginfod_client: None,
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

    /// Set loose debug match policy (CRC/Build-ID mismatches allowed)
    pub fn with_loose_debug_match(mut self, allow: bool) -> Self {
        self.config.allow_loose_debug_match = allow;
        self
    }

    /// Set a user-provided debug file for one target module.
    pub fn with_explicit_debug_file(mut self, debug_file: Option<ExplicitDebugFile>) -> Self {
        self.config.explicit_debug_file = debug_file;
        self
    }

    /// Set optional debuginfod client for build-id based debug file fallback.
    pub fn with_debuginfod_client(mut self, client: Option<Arc<DebuginfodClient>>) -> Self {
        self.config.debuginfod_client = client;
        self
    }

    /// Load with progress callback - always parallel
    pub async fn load_with_progress<F>(self, progress_callback: F) -> Result<Vec<LoadedObjfile>>
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
    ) -> Result<Vec<LoadedObjfile>>
    where
        F: Fn(ModuleLoadingEvent) + Send + Sync + 'static,
    {
        // Use semaphore to limit concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(
            self.config.max_module_concurrency,
        ));

        let total_modules = self.mappings.len();
        if let Some(explicit) = self.config.explicit_debug_file.as_ref() {
            validate_explicit_debug_file_target(&self.mappings, explicit)?;
        }
        let progress_callback = Arc::new(progress_callback);
        let debug_search_paths = Arc::new(self.config.debug_search_paths.clone());
        let allow_loose = self.config.allow_loose_debug_match;
        let explicit_debug_file = self.config.explicit_debug_file.clone();
        let debuginfod_client = self.config.debuginfod_client.clone();

        let tasks: Vec<_> = self
            .mappings
            .into_iter()
            .enumerate()
            .map(|(index, mapping)| {
                let semaphore = semaphore.clone();
                let progress_callback = progress_callback.clone();
                let debug_search_paths = debug_search_paths.clone();
                let debuginfod_client = debuginfod_client.clone();
                let explicit_debug_file_for_module =
                    explicit_debug_file.as_ref().and_then(|explicit| {
                        explicit
                            .matches_module(&mapping.path)
                            .then(|| explicit.debug_file.clone())
                    });

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

                    let result = LoadedObjfile::load_parallel(
                        mapping,
                        &debug_search_paths,
                        allow_loose,
                        explicit_debug_file_for_module,
                        debuginfod_client,
                    )
                    .await;

                    let load_time_ms = start_time.elapsed().as_millis() as u64;

                    match result {
                        Ok(module) => {
                            // Extract stats for progress reporting
                            let (functions, variables, types) = module.get_index_stats();
                            let (parse_time_ms, index_time_ms, module_total_time_ms) =
                                module.get_load_timing_ms();
                            let stats = ModuleLoadingStats {
                                functions,
                                variables,
                                types,
                                debug_info_source: module.get_debug_info_source().clone(),
                                dwarf_index_status: module.dwarf_index_status().clone(),
                                load_time_ms,
                                parse_time_ms,
                                index_time_ms,
                                module_total_time_ms,
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

fn validate_explicit_debug_file_target(
    mappings: &[ModuleMapping],
    explicit: &ExplicitDebugFile,
) -> Result<()> {
    let matches: Vec<&ModuleMapping> = mappings
        .iter()
        .filter(|mapping| explicit.matches_module(&mapping.path))
        .collect();

    match matches.len() {
        1 => Ok(()),
        0 => {
            let sample = mappings
                .iter()
                .take(8)
                .map(|mapping| mapping.path.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  - ");
            Err(anyhow::anyhow!(
                "Explicit debug file {} was provided for target module {}, but that module was not loaded. Loaded modules include:\n  - {}",
                explicit.debug_file.display(),
                explicit.target_module.display(),
                sample
            ))
        }
        _ => {
            let sample = matches
                .iter()
                .take(8)
                .map(|mapping| mapping.path.display().to_string())
                .collect::<Vec<_>>()
                .join("\n  - ");
            Err(anyhow::anyhow!(
                "Explicit debug file {} target {} matched multiple loaded modules:\n  - {}",
                explicit.debug_file.display(),
                explicit.target_module.display(),
                sample
            ))
        }
    }
}

fn paths_equivalent(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }

    if proc_root_paths_equivalent(left, right) {
        return true;
    }

    if let (Ok(left), Ok(right)) = (left.canonicalize(), right.canonicalize()) {
        if left == right {
            return true;
        }
    }

    match (std::fs::metadata(left), std::fs::metadata(right)) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

fn proc_root_paths_equivalent(left: &Path, right: &Path) -> bool {
    match (strip_proc_root_prefix(left), strip_proc_root_prefix(right)) {
        (Some(left), Some(right)) => left == right,
        (Some(left), None) => left.as_path() == right,
        (None, Some(right)) => left == right.as_path(),
        (None, None) => false,
    }
}

fn strip_proc_root_prefix(path: &Path) -> Option<PathBuf> {
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("proc")
    ) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(pid)) if pid.to_string_lossy().parse::<u32>().is_ok()
    ) {
        return None;
    }
    if !matches!(
        components.next(),
        Some(Component::Normal(component)) if component == OsStr::new("root")
    ) {
        return None;
    }

    let remaining = components.as_path();
    let mut stripped = PathBuf::from("/");
    if !remaining.as_os_str().is_empty() {
        stripped.push(remaining);
    }
    Some(stripped)
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
    pub async fn load(self) -> Result<Vec<LoadedObjfile>> {
        self.loader.load_with_progress(self.callback).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_debug_file_matches_proc_root_rewritten_target_path() {
        let mapping = ModuleMapping::from_path(PathBuf::from("/proc/123/root/usr/bin/app"));
        let explicit = ExplicitDebugFile::new(
            PathBuf::from("/usr/bin/app"),
            PathBuf::from("/tmp/app.debug"),
        );

        assert!(explicit.matches_module(&mapping.path));
        assert!(validate_explicit_debug_file_target(&[mapping], &explicit).is_ok());
    }

    #[test]
    fn explicit_debug_file_rejects_unmatched_proc_root_target_path() {
        let mapping = ModuleMapping::from_path(PathBuf::from("/proc/123/root/usr/bin/other"));
        let explicit = ExplicitDebugFile::new(
            PathBuf::from("/usr/bin/app"),
            PathBuf::from("/tmp/app.debug"),
        );

        let error = validate_explicit_debug_file_target(&[mapping], &explicit)
            .expect_err("unmatched explicit debug file should be rejected")
            .to_string();

        assert!(error.contains("/usr/bin/app"));
    }

    #[test]
    fn proc_root_paths_equivalent_normalizes_either_side() {
        assert!(proc_root_paths_equivalent(
            Path::new("/proc/123/root/usr/bin/app"),
            Path::new("/usr/bin/app")
        ));
        assert!(proc_root_paths_equivalent(
            Path::new("/usr/lib/libfoo.so"),
            Path::new("/proc/456/root/usr/lib/libfoo.so")
        ));
        assert!(!proc_root_paths_equivalent(
            Path::new("/proc/123/root/usr/bin/app"),
            Path::new("/usr/bin/other")
        ));
    }
}

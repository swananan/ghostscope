use crate::{config::UserConfig, core::session::build_debuginfod_client};
use anyhow::{Context, Result};
use ghostscope_dwarf::{AnalysisCache, DwarfAnalyzer, DwarfLoadOptions, ExplicitDebugFile};
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

pub async fn prepare_analysis_cache(config: &UserConfig) -> Result<()> {
    config.validate_prepare()?;

    let target = PathBuf::from(
        config
            .target_path
            .as_deref()
            .context("--prepare requires --target <PATH>")?,
    );
    let cache_dir = config
        .dwarf_analysis_cache_dir
        .clone()
        .context("Analysis cache is disabled")?;
    let options = DwarfLoadOptions {
        debug_search_paths: config.dwarf_search_paths.clone(),
        allow_loose_debug_match: config.dwarf_allow_loose_debug_match,
        explicit_debug_file: config
            .debug_file
            .clone()
            .map(|debug_file| ExplicitDebugFile::new(target.clone(), debug_file)),
        debuginfod_client: build_debuginfod_client(&config.dwarf_debuginfod)?,
        analysis_cache: Some(AnalysisCache::new(&cache_dir)),
    };

    let cache_hit = Arc::new(AtomicBool::new(false));
    let cache_hit_for_progress = Arc::clone(&cache_hit);
    let analyzer =
        DwarfAnalyzer::from_exec_path_with_options_and_progress(&target, options, move |event| {
            if let ghostscope_dwarf::ModuleLoadingEvent::LoadingCompleted { stats, .. } = event {
                cache_hit_for_progress
                    .store(stats.analysis_cache_status.is_hit(), Ordering::Relaxed);
            }
        })
        .await?;
    let stats = analyzer.get_module_stats();
    let action = if cache_hit.load(Ordering::Relaxed) {
        "Reused"
    } else {
        "Prepared"
    };
    println!(
        "{} analysis cache for {} ({} symbols) at {}",
        action,
        target.display(),
        stats.total_symbols,
        cache_dir.display()
    );
    Ok(())
}

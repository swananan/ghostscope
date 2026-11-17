//! Rootless warm benchmark of loading, startup statistics and a function/source query.
use anyhow::{ensure, Context, Result};
use ghostscope_dwarf::{AnalysisCache, DwarfAnalyzer, DwarfLoadOptions, ModuleLoadingEvent};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

async fn load(
    target: &Path,
    cache: Option<AnalysisCache>,
    expect_hit: bool,
) -> Result<(Duration, String)> {
    let hit = Arc::new(AtomicBool::new(false));
    let report_hit = Arc::clone(&hit);
    let started = Instant::now();
    let analyzer = DwarfAnalyzer::from_exec_path_with_options_and_progress(
        target,
        DwarfLoadOptions {
            analysis_cache: cache,
            ..Default::default()
        },
        move |event| {
            if let ModuleLoadingEvent::LoadingCompleted { stats, .. } = event {
                report_hit.store(stats.analysis_cache_status.is_hit(), Ordering::Relaxed);
            }
        },
    )
    .await?;
    let total_symbols = analyzer.get_module_stats().total_symbols;
    let addresses = analyzer.lookup_function_addresses("main");
    ensure!(
        !addresses.is_empty(),
        "benchmark target needs a main function"
    );
    let locations = addresses
        .iter()
        .map(|address| analyzer.lookup_source_location(address))
        .collect::<Vec<_>>();
    ensure!(
        locations.iter().any(Option::is_some),
        "benchmark target needs source-line information for main"
    );
    let elapsed = started.elapsed();
    ensure!(
        hit.load(Ordering::Relaxed) == expect_hit,
        "unexpected cache hit state"
    );
    Ok((
        elapsed,
        format!("{total_symbols} {addresses:?} {locations:?}"),
    ))
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let target = args
        .next()
        .context("usage: analysis_cache_bench TARGET [PAIRS]")?;
    let target = Path::new(&target);
    let pairs: usize = args
        .next()
        .map(|value| value.to_string_lossy().parse())
        .transpose()?
        .unwrap_or(7);
    ensure!(pairs > 0, "PAIRS must be positive");
    let directory = tempfile::tempdir()?;
    let cache_dir = directory.path().join("cache");
    let (_, expected) = load(target, Some(AnalysisCache::new(&cache_dir)), false).await?;
    ensure!(
        cache_dir.exists(),
        "native index available; target does not need a full-scan cache"
    );
    let mut raw = Vec::new();
    let mut cached = Vec::new();
    for pair in 0..=pairs {
        let order = if pair % 2 == 0 {
            [false, true]
        } else {
            [true, false]
        };
        for hit in order {
            let (duration, result) = load(
                target,
                hit.then(|| AnalysisCache::read_only(&cache_dir)),
                hit,
            )
            .await?;
            ensure!(
                result == expected,
                "cached/raw symbol or source result differs"
            );
            if pair > 0 {
                println!(
                    "pair={pair} cached={hit} ms={:.3}",
                    duration.as_secs_f64() * 1000.0
                );
                if hit {
                    cached.push(duration);
                } else {
                    raw.push(duration);
                }
            }
        }
    }
    raw.sort();
    cached.sort();
    fn median(samples: &[Duration]) -> f64 {
        let middle = samples.len() / 2;
        (samples[middle].as_secs_f64() + samples[(samples.len() - 1) / 2].as_secs_f64()) * 500.0
    }
    let mut bytes = 0;
    for version in std::fs::read_dir(&cache_dir)? {
        let version = version?;
        if !version.file_type()?.is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(version.path())? {
            bytes += entry?.metadata()?.len();
        }
    }
    println!(
        "target_bytes={} cache_bytes={bytes} raw_median_ms={:.3} cached_median_ms={:.3}",
        std::fs::metadata(target)?.len(),
        median(&raw),
        median(&cached)
    );
    Ok(())
}

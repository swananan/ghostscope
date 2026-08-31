//! Kernel-buffer backlog coverage for trace lifecycle generations.

mod common;

use anyhow::Context as _;
use common::{init, targets::TargetHandle, FIXTURES};
use ghostscope_compiler::{CompileOptions, EventMapType};
use ghostscope_dwarf::DwarfAnalyzer;
use ghostscope_loader::GhostScopeLoader;
use ghostscope_process::pinned_bpf_maps::{
    cleanup_current_pinned_maps, ensure_pinned_pid_aliases_exists,
    ensure_pinned_proc_module_ranges_exist, ensure_pinned_proc_offsets_exists,
};
use scopeguard::guard;
use serial_test::serial;
use std::path::Path;
use std::time::Duration;

const BACKLOG_FILL_TIME: Duration = Duration::from_secs(1);
const EVENT_READ_TIMEOUT: Duration = Duration::from_secs(3);
const GENERATION_TRANSITION_TIMEOUT: Duration = Duration::from_secs(5);
// PerfEventArray drains at most 64 records from one CPU per loader call.
const MIN_PROVEN_BACKLOG_BATCH: usize = 64;

fn container_topology_requested() -> bool {
    std::env::var_os("E2E_RUN_CONTAINER_TOPOLOGY").is_some()
}

fn prepare_pinned_maps() -> anyhow::Result<()> {
    const MAX_ENTRIES: u32 = 4096;
    ensure_pinned_proc_offsets_exists(MAX_ENTRIES)?;
    ensure_pinned_pid_aliases_exists(MAX_ENTRIES)?;
    ensure_pinned_proc_module_ranges_exist(MAX_ENTRIES)?;
    Ok(())
}

async fn read_events(
    loader: &mut GhostScopeLoader,
) -> anyhow::Result<Vec<ghostscope_protocol::ParsedTraceEvent>> {
    tokio::time::timeout(EVENT_READ_TIMEOUT, loader.wait_for_events_async())
        .await
        .context("timed out waiting for kernel-buffered trace events")?
        .map_err(Into::into)
}

async fn observe_generation_transition(
    loader: &mut GhostScopeLoader,
    minimum_new_generation: u64,
) -> anyhow::Result<(usize, usize)> {
    let deadline = tokio::time::Instant::now() + GENERATION_TRANSITION_TIMEOUT;
    let mut stale = 0usize;
    let mut current = 0usize;

    while tokio::time::Instant::now() < deadline && (stale == 0 || current == 0) {
        for event in read_events(loader).await? {
            if event.generation < minimum_new_generation {
                stale += 1;
            } else {
                current += 1;
            }
        }
    }

    Ok((stale, current))
}

fn backend_name(backend: EventMapType) -> &'static str {
    match backend {
        EventMapType::RingBuf => "RingBuf",
        EventMapType::PerfEventArray => "PerfEventArray",
    }
}

async fn run_backend(
    analyzer: &DwarfAnalyzer,
    binary_path: &Path,
    target: &TargetHandle,
    backend: EventMapType,
) -> anyhow::Result<()> {
    let binary_path_str = binary_path
        .to_str()
        .context("backtrace fixture path is not valid UTF-8")?;
    let compile_options = CompileOptions {
        binary_path_hint: Some(binary_path.to_string_lossy().into_owned()),
        event_map_type: backend,
        ..CompileOptions::default()
    };
    let result = ghostscope_compiler::compile_script(
        r#"trace hot_bt_probe { print "GENERATION_BACKLOG"; }"#,
        analyzer,
        Some(target.host_pid()),
        Some(1),
        &compile_options,
    )?;
    anyhow::ensure!(
        result.uprobe_configs.len() == 1,
        "{} compilation produced {} uprobes and {} failed targets",
        backend_name(backend),
        result.uprobe_configs.len(),
        result.failed_targets.len()
    );
    let config = &result.uprobe_configs[0];
    let offset = config
        .uprobe_offset
        .context("compiled hot_bt_probe has no uprobe offset")?;
    let function_name = config.function_name.as_deref().unwrap_or("hot_bt_probe");

    let mut loader = GhostScopeLoader::new(&config.ebpf_bytecode)?;
    loader.set_perf_page_count(64);
    loader.set_trace_context(config.trace_context.clone());
    loader.attach_uprobe_with_program_name(
        binary_path_str,
        function_name,
        Some(offset),
        Some(target.host_pid() as i32),
        Some(&config.ebpf_function_name),
    )?;

    let test_result = async {
        // CFI-style barrier: update generation while the probe remains attached.
        // Records already waiting in the kernel must keep generation zero.
        tokio::time::sleep(BACKLOG_FILL_TIME).await;
        loader.set_event_generation(1)?;
        let (stale, current) = observe_generation_transition(&mut loader, 1).await?;
        anyhow::ensure!(
            stale > 0 && current > 0,
            "{} CFI-style transition did not expose both buffered old and new events: stale={stale}, current={current}",
            backend_name(backend)
        );

        // Disable-style barrier: prove a substantial backlog exists, then
        // detach, advance, reattach, and read the remaining old records.
        tokio::time::sleep(BACKLOG_FILL_TIME).await;
        loader.detach_uprobe()?;
        let proof_batch = read_events(&mut loader).await?;
        anyhow::ensure!(
            proof_batch.len() >= MIN_PROVEN_BACKLOG_BATCH,
            "{} did not build the expected real kernel backlog: read {} events",
            backend_name(backend),
            proof_batch.len()
        );
        anyhow::ensure!(
            proof_batch.iter().all(|event| event.generation < 2)
                && proof_batch.iter().any(|event| event.generation == 1),
            "{} backlog before Disable did not contain generation-one events",
            backend_name(backend)
        );

        loader.set_event_generation(2)?;
        loader.reattach_uprobe()?;
        let (stale, current) = observe_generation_transition(&mut loader, 2).await?;
        anyhow::ensure!(
            stale > 0 && current > 0,
            "{} Disable-style transition did not expose both buffered old and new events: stale={stale}, current={current}",
            backend_name(backend)
        );

        Ok(())
    }
    .await;

    let destroy_result = loader.destroy();
    destroy_result?;
    test_result
}

#[tokio::test]
#[serial(event_generation_backlog)]
async fn test_kernel_backlogs_keep_source_generation_for_ringbuf_and_perf() -> anyhow::Result<()> {
    init();
    // This low-level loader test intentionally exercises host kernel buffers.
    // Container topology behavior is covered by the CLI-oriented suites.
    if container_topology_requested() {
        return Ok(());
    }

    cleanup_current_pinned_maps()?;
    let _cleanup = guard((), |_| {
        let _ = cleanup_current_pinned_maps();
    });
    prepare_pinned_maps()?;

    let binary_path = FIXTURES.get_test_binary("backtrace_hot_program")?;
    let binary_dir = binary_path
        .parent()
        .context("backtrace fixture has no parent directory")?;
    let analyzer = DwarfAnalyzer::from_exec_path(&binary_path).await?;
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .current_dir(binary_dir)
        .spawn()
        .await?;

    let test_result = async {
        run_backend(&analyzer, &binary_path, &target, EventMapType::RingBuf).await?;
        run_backend(
            &analyzer,
            &binary_path,
            &target,
            EventMapType::PerfEventArray,
        )
        .await
    }
    .await;

    target.terminate().await?;
    test_result
}

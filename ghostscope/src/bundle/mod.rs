//! Offline compilation and a DWARF-free, LLVM-free attach path.
mod artifact;

use anyhow::{ensure, Context, Result};
use clap::Parser;
use ghostscope_compiler::script::Statement;
use ghostscope_loader::KernelCapabilities;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Instant;

use crate::config::args::{PrepareArgs, RunBundleArgs};
use crate::config::{Args, Config, ResolvedConfig, UserConfig};
use crate::core::GhostSession;
use artifact::{fingerprint, open_regular_file, Bundle};

// This is a compilation profile, not a probe of the preparing machine's kernel.
// Runtime must explicitly verify it before loading any saved bytecode.
fn compilation_profile(user: &UserConfig) -> KernelCapabilities {
    KernelCapabilities {
        supports_uprobe_multi: true,
        supports_ringbuf: !user.ebpf_config.force_perf_event_array,
        supports_perf_event_array: true,
        supports_ns_current_pid_tgid_helper: false,
        supports_sleepable_uprobe: user.ebpf_config.sleepable_uprobe,
        supports_sleepable_tail_calls: false,
    }
}

fn reject_backtrace(statements: &[Statement]) -> Result<()> {
    for statement in statements {
        match statement {
            Statement::Backtrace(_) => anyhow::bail!("prepare does not support bt/backtrace yet"),
            Statement::TracePoint { body, .. } | Statement::Block(body) => reject_backtrace(body)?,
            Statement::If {
                then_body,
                else_body,
                ..
            } => {
                reject_backtrace(then_body)?;
                if let Some(body) = else_body {
                    reject_backtrace(std::slice::from_ref(body))?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) async fn prepare(args: PrepareArgs) -> Result<()> {
    let started = Instant::now();
    ensure!(
        !args.output.try_exists()?,
        "output already exists: {}",
        args.output.display()
    );
    let mut trace_args = Args::try_parse_from(["ghostscope"])?;
    trace_args.target = Some(args.target);
    trace_args.script = args.script;
    trace_args.script_file = args.script_file;
    trace_args.debug_file = args.debug_file;
    trace_args.config = args.config.clone();
    let parsed = trace_args.into_parsed()?;
    let mut user = UserConfig::new_with_explicit_config(parsed, args.config)?;
    user.dry_run = true;
    user.tui_mode = false;
    user.dwarf_backtrace_runtime_modules = false;
    user.validate_with_pid_state(false)?;
    ensure!(
        !user.ebpf_config.sleepable_uprobe || !user.ebpf_config.force_perf_event_array,
        "sleepable uprobes require RingBuf output"
    );
    let script = match (&user.script, &user.script_file) {
        (Some(script), _) => script.clone(),
        (_, Some(file)) => std::fs::read_to_string(file).context("cannot read trace script")?,
        _ => anyhow::bail!("prepare requires --script or --script-file"),
    };
    reject_backtrace(&ghostscope_compiler::script::parser::parse(&script)?.statements)?;
    let target = std::fs::canonicalize(user.target_path.as_ref().context("prepare requires -t")?)?;
    let target = ghostscope_process::module_probe::module_path_str(&target)?.to_owned();
    user.target_path = Some(target.clone());
    let mut target_file = open_regular_file(Path::new(&target))?;
    let target_sha256 = fingerprint(&mut target_file)?;
    let module_cookie = ghostscope_compiler::module_cookie_for_path(&target);
    let profile = compilation_profile(&user);
    let config = ResolvedConfig {
        user,
        runtime: Default::default(),
        kernel_capabilities: profile,
    };
    let mut session = GhostSession::new_with_config(&config);
    session.load_binary_parallel().await?;
    let options = config.get_compile_options(false, false, false, Some(target.clone()));
    let compiled = crate::script::compile_script_for_cli(&script, &mut session, &options)?;
    ensure!(
        target_sha256 == fingerprint(&mut open_regular_file(Path::new(&target))?)?,
        "target changed during preparation"
    );
    let bundle = Bundle::from_compilation(
        target,
        target_sha256,
        module_cookie,
        script,
        config.ebpf_config.clone(),
        config.value_adapter_config,
        compiled,
    )?;
    bundle.write(&args.output)?;
    eprintln!(
        "Prepared {} probe(s) in {:.1} ms: {} (no BPF programs loaded)",
        bundle.probes.len(),
        started.elapsed().as_secs_f64() * 1000.0,
        args.output.display()
    );
    Ok(())
}

pub(crate) async fn run(args: RunBundleArgs) -> Result<()> {
    let started = Instant::now();
    let bundle = Bundle::read(&args.bundle)?;
    let mut trace_args = Args::try_parse_from(["ghostscope"])?;
    trace_args.target = Some(args.target.unwrap_or_else(|| bundle.target.clone()));
    trace_args.pid = Some(args.pid);
    trace_args.script = Some(bundle.script.clone());
    trace_args.script_output = Some(args.script_output);
    trace_args.no_status = args.no_status;
    trace_args.emit_ready_marker = args.emit_ready_marker;
    let mut user = UserConfig::new(trace_args.into_parsed()?, Config::default());
    user.ebpf_config = bundle.ebpf.clone();
    user.value_adapter_config = bundle.value_adapter;
    user.dwarf_backtrace_runtime_modules = false;
    user.should_save_llvm_ir = false;
    user.should_save_ebpf = false;
    user.should_save_ast = false;
    let target = user.target_path.clone().context("bundle has no target")?;
    let mut target_file =
        open_regular_file(Path::new(&target)).context("cannot open bundle target")?;
    ensure!(
        fingerprint(&mut target_file)? == bundle.target_sha256,
        "bundle target identity mismatch (SHA-256); prepare it again for this binary"
    );
    ensure!(
        ghostscope_compiler::module_cookie_for_path(&target) == bundle.module_cookie,
        "bundle module cookie mismatch; targets without a build ID must retain their file identity"
    );
    let start_time = process_start_time(args.pid)?;
    ensure_target_is_mapped(args.pid, &target_file)?;

    crate::util::ensure_privileges();
    let caps = if user.ebpf_config.sleepable_uprobe {
        KernelCapabilities::detect_for_startup_with_sleepable_uprobe(
            user.ebpf_config.force_perf_event_array,
        )?
    } else {
        KernelCapabilities::detect_for_startup(user.ebpf_config.force_perf_event_array)?
    };
    ensure!(caps.supports_uprobe_multi, "run-bundle requires process-scoped multi-uprobe support; no recompilation fallback is performed");
    ensure!(
        if user.ebpf_config.force_perf_event_array {
            caps.supports_perf_event_array
        } else {
            caps.supports_ringbuf
        },
        "kernel does not support the bundle event transport; prepare a compatible bundle"
    );
    let config = ResolvedConfig::resolve(user, &caps)?;
    ensure!(!config.runtime.runtime_env.is_container_likely()
        && config.runtime.pid_views.as_ref().is_some_and(|views| views.is_initial_pid_namespace()),
        "run-bundle currently supports host processes only; container PID namespaces require runtime binding support");
    let _cleanup = crate::util::PinnedMapsCleanupGuard::new();
    // No load_binary* call: the process manager only reads ELF mappings/offsets.
    let mut session = GhostSession::new_with_config(&config);
    let mut options = config.get_compile_options(false, false, false, Some(target.clone()));
    options.pid_filter_spec = None;
    options.special_pid_ns = None;
    options.proc_offsets_pid_ns = None;
    options.input_pid = None;
    let script = bundle.script.clone();
    let compilation = bundle.into_compilation(&target, args.pid);
    crate::script::report_value_diagnostics(&compilation);
    // Attach through the retained descriptor, so a pathname replacement cannot
    // substitute another inode after the fingerprint/mapping checks.
    let attach_target = format!("/proc/self/fd/{}", target_file.as_raw_fd());
    crate::script::load_compiled_script_for_cli(
        &script,
        compilation,
        &mut session,
        &options,
        Some(&attach_target),
    )
    .await?;
    ensure!(
        process_start_time(args.pid)? == start_time,
        "target process changed during bundle attachment"
    );
    ensure_target_is_mapped(args.pid, &target_file)?;
    if config.script_status {
        eprintln!(
            "Bundle attached in {:.1} ms (DWARF parsing and LLVM codegen skipped)",
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    crate::cli::script_runtime::monitor_cli_session(session, &config).await
}

fn process_start_time(pid: u32) -> Result<String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    stat.rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(19))
        .map(str::to_owned)
        .context("invalid process stat start time")
}

fn ensure_target_is_mapped(pid: u32, file: &File) -> Result<()> {
    let meta = file.metadata()?;
    let dev = meta.dev();
    ensure!(
        ghostscope_process::proc_maps::read_proc_maps(pid)?
            .iter()
            .any(|entry| {
                entry.inode == meta.ino()
                    && entry.dev_major == u64::from(libc::major(dev))
                    && entry.dev_minor == u64::from(libc::minor(dev))
                    && entry.perms.contains('x')
            }),
        "bundle target is not mapped as executable code in PID {pid}"
    );
    Ok(())
}

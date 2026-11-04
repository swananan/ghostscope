//! Prepared bundles have an unprivileged producer and a DWARF-free consumer.
mod common;

use anyhow::{ensure, Context, Result};
use common::sandbox::SandboxHandle;
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

const SCRIPT: &str = r#"trace bundle_probe { print "BUNDLE value={} global={} pid={} tid={}", value, bundle_global, $pid, $tid; }"#;

struct Fixture {
    directory: tempfile::TempDir,
    binary: PathBuf,
    debug: PathBuf,
    config: PathBuf,
    ghostscope: PathBuf,
    diagnostics: bool,
}

impl Fixture {
    fn new(perf: bool) -> Result<Self> {
        let directory = tempfile::tempdir_in("/tmp")?;
        // Root-run e2e deliberately prepares as nobody, without BPF capabilities.
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o777))?;
        let source = directory.path().join("target.c");
        let binary = directory.path().join("target");
        let debug = directory.path().join("target.debug");
        fs::write(
            &source,
            r#"
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
volatile int bundle_global = 73;
__attribute__((noinline)) void bundle_probe(int value) {
    asm volatile("" : : "r"(value) : "memory");
}
void *worker(void *arg) {
    int value = *(int *)arg;
    for (;;) { bundle_probe(value); usleep(10000); }
    return 0;
}
int main(int argc, char **argv) {
    int value = argc > 1 ? atoi(argv[1]) : 42;
    int worker_value = value + 1;
    pthread_t thread;
    pthread_create(&thread, 0, worker, &worker_value);
    worker(&value);
    return 0;
}
"#,
        )?;
        successful(
            Command::new("cc")
                .args(["-g", "-O0", "-pthread", "-Wl,--build-id"])
                .arg(&source)
                .arg("-o")
                .arg(&binary)
                .output()?,
        )?;
        successful(
            Command::new("objcopy")
                .arg("--only-keep-debug")
                .arg(&binary)
                .arg(&debug)
                .output()?,
        )?;
        successful(
            Command::new("strip")
                .arg("--strip-debug")
                .arg(&binary)
                .output()?,
        )?;
        successful(
            Command::new("objcopy")
                .arg("--add-gnu-debuglink=target.debug")
                .arg(&binary)
                .current_dir(directory.path())
                .output()?,
        )?;
        let config = directory.path().join("config.toml");
        fs::write(&config, format!("[general]\nenable_logging = false\n[ebpf]\nforce_perf_event_array = {perf}\n[dwarf.debuginfod]\nenabled = \"off\"\n"))?;
        let (binary_command, args) = SandboxHandle::host().ghostscope_command()?;
        ensure!(args.is_empty(), "expected a direct host executable");
        let ghostscope = directory.path().join("ghostscope");
        fs::copy(PathBuf::from(binary_command), &ghostscope)?;
        fs::set_permissions(&ghostscope, fs::Permissions::from_mode(0o755))?;
        Ok(Self {
            directory,
            binary,
            debug,
            config,
            ghostscope,
            diagnostics: false,
        })
    }

    fn script(&self) -> String {
        if self.diagnostics {
            SCRIPT.replace("$pid, $tid;", "$pid, $tid; print bundle_large;")
        } else {
            SCRIPT.to_owned()
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.ghostscope);
        command.current_dir(self.directory.path());
        command
    }

    fn prepare(&self, script: &str, bundle: &Path) -> Result<Output> {
        let mut command = self.command();
        command
            .arg("prepare")
            .arg("-t")
            .arg(&self.binary)
            .arg("--script")
            .arg(script)
            .arg("--config")
            .arg(&self.config)
            .arg("-o")
            .arg(bundle);
        // SAFETY: geteuid has no arguments or memory effects.
        if unsafe { libc::geteuid() } == 0 {
            command.gid(65534).uid(65534);
        }
        command
            .output()
            .context("could not execute unprivileged prepare")
    }
}

fn successful(output: Output) -> Result<String> {
    ensure!(
        output.status.success(),
        "command failed: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn capture(fixture: &Fixture, pid: u32, bundle: Option<&Path>) -> Result<(String, Duration)> {
    let out_path = fixture.directory.path().join("stdout");
    let err_path = fixture.directory.path().join("stderr");
    let mut command = fixture.command();
    if let Some(bundle) = bundle {
        command.arg("run-bundle").arg(bundle);
    } else {
        command
            .arg("-t")
            .arg(&fixture.binary)
            .arg("--script")
            .arg(fixture.script())
            .arg("--config")
            .arg(&fixture.config)
            .args([
                "--no-log",
                "--no-save-llvm-ir",
                "--no-save-ebpf",
                "--no-save-ast",
            ]);
    }
    command
        .args([
            "-p",
            &pid.to_string(),
            "--no-status",
            "--script-output",
            if fs::read_to_string(&fixture.config)?.contains("force_perf_event_array = true") {
                "plain"
            } else {
                "pretty"
            },
            "--emit-ready-marker",
            "BUNDLE_READY",
        ])
        .stdout(Stdio::from(File::create(&out_path)?))
        .stderr(Stdio::from(File::create(&err_path)?));
    let started = Instant::now();
    let mut child = ChildGuard(command.spawn()?);
    let mut ready_after = None;
    let deadline = started + Duration::from_secs(60);
    let output = loop {
        let output = fs::read_to_string(&out_path)?;
        if output.contains("BUNDLE_READY") && ready_after.is_none() {
            ready_after = Some(started.elapsed());
        }
        if ready_after.is_some()
            && output.contains("value=42 global=73")
            && output.contains("value=43 global=73")
        {
            break output;
        }
        if let Some(status) = child.0.try_wait()? {
            anyhow::bail!(
                "tracer exited {status}: {output}\n{}",
                fs::read_to_string(&err_path)?
            );
        }
        ensure!(
            Instant::now() < deadline,
            "timed out: {output}\n{}",
            fs::read_to_string(&err_path)?
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    common::termination::send_sigterm(child.0.id(), "bundle tracer")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait()? {
            ensure!(
                status.success(),
                "tracer failed shutdown: {}",
                fs::read_to_string(&err_path)?
            );
            break;
        }
        ensure!(Instant::now() < deadline, "tracer failed to shut down");
        std::thread::sleep(Duration::from_millis(10));
    }
    let stderr = fs::read_to_string(&err_path)?;
    ensure!(
        !fixture.diagnostics
            || stderr
                .lines()
                .filter(|line| line.contains("Display note")
                    && line.contains("bundle_large")
                    && line.contains("capture-budget"))
                .count()
                == 1,
        "expected exactly one static display diagnostic: {stderr}"
    );
    ensure!(
        !output.contains("Display note"),
        "diagnostics leaked into stdout: {output}"
    );
    for line in output.lines().filter(|line| line.contains("BUNDLE value=")) {
        ensure!(line.contains(&format!(" pid={pid} ")), "wrong PID: {line}");
        ensure!(
            !line.contains("value=99") && !line.contains("value=100"),
            "unrelated process was traced: {line}"
        );
    }
    Ok((output, ready_after.context("missing ready marker")?))
}

fn host_topology() -> Result<bool> {
    Ok(SandboxHandle::default_ghostscope()?.is_host_backend()
        && SandboxHandle::default_target()?.is_host_backend())
}

#[test]
fn test_prepared_bundle_unprivileged_roundtrip_without_debug_info() -> Result<()> {
    common::init();
    if !host_topology()? {
        eprintln!("prepared bundle MVP is host-only; skipping positive cases outside host->host");
        return Ok(());
    }
    for perf in [false, true] {
        let fixture = Fixture::new(perf)?;
        let bundle = fixture.directory.path().join("trace.gsb");
        successful(fixture.prepare(SCRIPT, &bundle)?)?;
        let target = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
        let unrelated = ChildGuard(Command::new(&fixture.binary).arg("99").spawn()?);
        if !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi
        {
            // Older supported GhostScope kernels cannot run this bundle profile.
            // Still exercise offline preparation and the explicit refusal path.
            let output = fixture
                .command()
                .arg("run-bundle")
                .arg(&bundle)
                .arg("-p")
                .arg(target.0.id().to_string())
                .output()?;
            ensure!(
                !output.status.success(),
                "unsupported kernel accepted a bundle"
            );
            ensure!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("requires process-scoped multi-uprobe"),
                "unexpected capability error: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            writeln!(std::io::stderr(), "prepared bundle: verified unsupported-kernel rejection; positive attach coverage requires process-scoped multi-uprobes")?;
            continue;
        }
        let mut normal_times = Vec::new();
        for _ in 0..3 {
            normal_times.push(capture(&fixture, target.0.id(), None)?.1);
        }
        // The compiled producer needs this file. The prepared consumer must not.
        fs::remove_file(&fixture.debug)?;
        let mut bundle_times = Vec::new();
        for _ in 0..3 {
            bundle_times.push(capture(&fixture, target.0.id(), Some(&bundle))?.1);
        }
        drop(target);
        let second = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
        capture(&fixture, second.0.id(), Some(&bundle))?;
        drop(unrelated);
        normal_times.sort();
        bundle_times.sort();
        // Direct stderr keeps benchmark evidence visible even without --nocapture.
        writeln!(std::io::stderr(), "prepared bundle perf={perf}: median of 3 normal ready={}ms, bundle ready={}ms (small split-DWARF C fixture)", normal_times[1].as_millis(), bundle_times[1].as_millis())?;
    }
    Ok(())
}

#[test]
fn test_prepared_bundle_rejects_backtrace_mismatch_and_overwrite() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    let fixture = Fixture::new(false)?;
    let bundle = fixture.directory.path().join("trace.gsb");
    let rejected = fixture.prepare("trace bundle_probe { if true { bt; } }", &bundle)?;
    ensure!(!rejected.status.success(), "backtrace was accepted");
    ensure!(
        String::from_utf8_lossy(&rejected.stderr).contains("does not support bt/backtrace"),
        "unexpected failure: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    ensure!(!bundle.exists(), "failed preparation published a bundle");
    successful(fixture.prepare(SCRIPT, &bundle)?)?;
    let original = fs::read(&bundle)?;
    ensure!(
        !fixture.prepare(SCRIPT, &bundle)?.status.success(),
        "existing bundle was overwritten"
    );
    ensure!(fs::read(&bundle)? == original, "existing bundle changed");

    let target = ChildGuard(Command::new(&fixture.binary).arg("42").spawn()?);
    for (field, value, expected) in [
        ("format_version", serde_json::json!(999), "format version"),
        (
            "architecture",
            serde_json::json!("unsupported"),
            "architecture mismatch",
        ),
        (
            "ghostscope_version",
            serde_json::json!("0.0.0"),
            "version mismatch",
        ),
        (
            "target_sha256",
            serde_json::json!(vec![0; 32]),
            "identity mismatch",
        ),
    ] {
        let mut contents: serde_json::Value = serde_json::from_slice(&original)?;
        contents[field] = value;
        let path = fixture.directory.path().join("bad.gsb");
        fs::write(&path, serde_json::to_vec(&contents)?)?;
        let output = fixture
            .command()
            .arg("run-bundle")
            .arg(path)
            .arg("-p")
            .arg(target.0.id().to_string())
            .output()?;
        ensure!(!output.status.success(), "invalid {field} accepted");
        ensure!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "unexpected {field} error: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = fixture
        .command()
        .arg("run-bundle")
        .arg(&bundle)
        .arg("-p")
        .arg(std::process::id().to_string())
        .output()?;
    ensure!(!output.status.success(), "unmapped target accepted");
    ensure!(
        String::from_utf8_lossy(&output.stderr).contains("not mapped"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn test_prepared_bundle_replays_static_diagnostics() -> Result<()> {
    common::init();
    if !host_topology()? {
        return Ok(());
    }
    if !ghostscope_loader::KernelCapabilities::detect_for_startup(false)?.supports_uprobe_multi {
        eprintln!("static bundle diagnostics test requires process-scoped multi-uprobes");
        return Ok(());
    }
    for perf in [false, true] {
        let mut fixture = Fixture::new(perf)?;
        fixture.diagnostics = true;
        let source = fixture.directory.path().join("diagnostics.rs");
        fs::write(
            &source,
            r#"
use std::cell::Cell;
#[no_mangle] pub static mut bundle_global: i32 = 73;
#[no_mangle] pub static mut bundle_large: Cell<String> = Cell::new(String::new());
#[inline(never)] #[no_mangle] pub fn bundle_probe(value: i32) { std::hint::black_box(value); std::hint::black_box(unsafe { bundle_global }); }
fn worker(value: i32) { loop { bundle_probe(value); std::thread::sleep(std::time::Duration::from_millis(10)); } }
fn main() {
    unsafe { bundle_large = Cell::new(String::from("cell value")); }
    std::thread::spawn(|| worker(43));
    worker(42);
}
"#,
        )?;
        successful(
            Command::new("rustc")
                .args(["-g", "--edition=2021"])
                .arg(&source)
                .arg("-o")
                .arg(&fixture.binary)
                .output()?,
        )?;
        let config =
            fs::read_to_string(&fixture.config)?.replace("[ebpf]", "[ebpf]\nmem_dump_cap = 24");
        fs::write(&fixture.config, config)?;
        let bundle = fixture.directory.path().join("diagnostics.gsb");
        let preparation = successful(fixture.prepare(&fixture.script(), &bundle)?)?;
        ensure!(
            preparation.contains("capture-budget"),
            "fixture produced no static diagnostic: {preparation}"
        );
        let target = ChildGuard(Command::new(&fixture.binary).spawn()?);
        capture(&fixture, target.0.id(), None)?;
        capture(&fixture, target.0.id(), Some(&bundle))?;
    }
    Ok(())
}

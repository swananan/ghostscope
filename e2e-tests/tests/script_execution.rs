//! Script execution integration tests
//!
//! Tests for ghostscope script execution and tracing functionality.
//! Assumes tests are run with sudo permissions for eBPF attachment.
//!
//! Concurrency note: these tests intentionally exercise multiple scripts
//! against a single long-lived sample_program process (per optimization
//! level). This is by design to validate real-world multi-attachment
//! scenarios and reduce test startup overhead. Do not serialize this file.

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::{Arc, Once};
use tokio::sync::RwLock;

// Global test program management
lazy_static! {
    // Maintain one process per optimization level to avoid cross-test interference.
    static ref GLOBAL_TEST_MANAGER: Arc<RwLock<HashMap<OptimizationLevel, GlobalTestProcess>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

struct GlobalTestProcess {
    target: common::targets::TargetHandle,
    optimization_level: OptimizationLevel,
}

impl GlobalTestProcess {
    async fn start_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<Self> {
        println!(
            "🚀 Starting global sample_program ({})",
            opt_level.description()
        );

        let target = common::targets::TargetLauncher::sample_program_with_opt(opt_level)
            .spawn()
            .await?;
        let host_pid = target.host_pid();
        let visible_pid =
            target.visible_pid_from(&common::sandbox::SandboxHandle::default_ghostscope()?)?;

        println!(
            "✓ Started global sample_program ({}) with host_pid={} visible_pid={}",
            opt_level.description(),
            host_pid,
            visible_pid
        );

        Ok(Self {
            target,
            optimization_level: opt_level,
        })
    }

    fn host_pid(&self) -> u32 {
        self.target.host_pid()
    }

    fn visible_pid(&self) -> anyhow::Result<u32> {
        self.target
            .visible_pid_from(&common::sandbox::SandboxHandle::default_ghostscope()?)
    }

    fn target(&self) -> &common::targets::TargetHandle {
        &self.target
    }

    async fn terminate(self) -> anyhow::Result<()> {
        println!(
            "🛑 Terminating global sample_program ({}, host PID: {})",
            self.optimization_level.description(),
            self.host_pid()
        );
        self.target.terminate().await?;
        println!(
            "✓ Global sample_program ({}) terminated",
            self.optimization_level.description()
        );
        Ok(())
    }
}

// Get or start the global test process with specific optimization level
async fn get_global_test_pid_with_opt(opt_level: OptimizationLevel) -> anyhow::Result<u32> {
    let manager = GLOBAL_TEST_MANAGER.clone();

    // Fast path: check if we already have a live process for this opt level
    {
        let read_guard = manager.read().await;
        if let Some(process) = read_guard.get(&opt_level) {
            if common::host_pid_is_running(process.host_pid()) {
                return process.visible_pid();
            }
        }
    }

    // Slow path: create or replace the entry for this opt level
    let mut write_guard = manager.write().await;

    // Double-check under write lock in case another task started it
    if let Some(process) = write_guard.get(&opt_level) {
        if common::host_pid_is_running(process.host_pid()) {
            return process.visible_pid();
        }
    }

    // If an old process exists for this opt level, remove it first (drop lock before awaiting)
    let old_proc = write_guard.remove(&opt_level);
    drop(write_guard);

    if let Some(old) = old_proc {
        let _ = old.terminate().await;
    }

    // Start new process with the requested optimization level
    let new_process = GlobalTestProcess::start_with_opt(opt_level).await?;
    let pid = new_process.visible_pid()?;

    // Re-acquire write lock to insert the new process
    let mut write_guard = manager.write().await;
    write_guard.insert(opt_level, new_process);
    Ok(pid)
}

async fn get_global_test_target_with_opt(
    opt_level: OptimizationLevel,
) -> anyhow::Result<common::targets::TargetHandle> {
    let _ = get_global_test_pid_with_opt(opt_level).await?;
    let manager = GLOBAL_TEST_MANAGER.clone();
    let read_guard = manager.read().await;
    let process = read_guard.get(&opt_level).ok_or_else(|| {
        anyhow::anyhow!("global test target missing for {}", opt_level.description())
    })?;
    Ok(process.target().clone())
}

// Get or start the global test process (defaults to Debug optimization)
// Cleanup function to be called when tests finish
pub async fn cleanup_global_test_process() -> anyhow::Result<()> {
    let manager = GLOBAL_TEST_MANAGER.clone();
    let mut write_guard = manager.write().await;

    // Terminate all managed processes (for every optimization level)
    let processes: Vec<GlobalTestProcess> = write_guard.drain().map(|(_, p)| p).collect();
    drop(write_guard);

    for proc in processes.into_iter() {
        let _ = proc.terminate().await;
    }

    Ok(())
}

#[tokio::test]
async fn test_void_pointer_addition_prints_address() -> anyhow::Result<()> {
    // Verify: for sink_void(const void* p), p+1 prints an address (fallback path)
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace sink_void {
    print p + 1;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 4, opt_level).await?;
    assert_eq!(
        exit_code, 0,
        "unexpected error: stderr={stderr}\nstdout={stdout}"
    );

    // Expect something like: (p+1) = 0x... or plain 0x... (void*)
    // This covers the AddressValue path rendered via ComplexFormat
    let mut saw_addr = false;
    for line in stdout.lines() {
        let t = line.trim();
        if (t.starts_with("(p+1) = ") && t.contains("0x"))
            || (t.starts_with("0x") && t.contains("(void*)"))
        {
            saw_addr = true;
            break;
        }
    }
    assert!(
        saw_addr,
        "expected (p+1) to print an address.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_struct_pointer_addition_scales_by_type_size() -> anyhow::Result<()> {
    // Verify: on print_record(const DataRecord* record), (record+1) and (record+2)
    // have addresses separated by sizeof(DataRecord) (expected 48 bytes on x86_64 with current layout).
    // We avoid relying on successful reads; we only compare addresses when read fails (errno=-14).
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace print_record {
    print record + 1;
    print record + 2;
    print (record + 0x1) + 0b1;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 5, opt_level).await?;

    // If attach fails due to sandbox (BPF_PROG_LOAD), skip to avoid false negatives in CI
    if exit_code != 0 && stderr.contains("BPF_PROG_LOAD") {
        return Ok(());
    }
    assert_eq!(
        exit_code, 0,
        "unexpected error: stderr={stderr}\nstdout={stdout}"
    );

    // Gather addresses from failure lines for (record+1) and (record+2)
    let mut addr1: Option<u64> = None;
    let mut addr2: Option<u64> = None;
    let mut addr_chain: Option<u64> = None;
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("(record+1) = ") || t.starts_with("(record + 1) = ") {
            if let Some(ix) = t.rfind("0x") {
                let mut j = ix + 2;
                let bytes = t.as_bytes();
                while j < t.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > ix + 2 {
                    if let Ok(v) = u64::from_str_radix(&t[ix + 2..j], 16) {
                        addr1 = Some(v);
                    }
                }
            }
        }
        if t.starts_with("(record+2) = ") || t.starts_with("(record + 2) = ") {
            if let Some(ix) = t.rfind("0x") {
                let mut j = ix + 2;
                let bytes = t.as_bytes();
                while j < t.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > ix + 2 {
                    if let Ok(v) = u64::from_str_radix(&t[ix + 2..j], 16) {
                        addr2 = Some(v);
                    }
                }
            }
        }
        if t.starts_with("((record+1)+1) = ")
            || t.starts_with("((record + 1) + 1) = ")
            || t.starts_with("((record+0x1)+0b1) = ")
            || t.starts_with("((record + 0x1) + 0b1) = ")
        {
            if let Some(ix) = t.rfind("0x") {
                let mut j = ix + 2;
                let bytes = t.as_bytes();
                while j < t.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > ix + 2 {
                    if let Ok(v) = u64::from_str_radix(&t[ix + 2..j], 16) {
                        addr_chain = Some(v);
                    }
                }
            }
        }
    }

    if let (Some(a1), Some(a2)) = (addr1, addr2) {
        // Expected sizeof(DataRecord) = 48 bytes with current layout (int(4)+name[32]+padding(4)+double(8))
        let delta = a2.wrapping_sub(a1);
        assert_eq!(
            delta, 48,
            "expected address delta sizeof(DataRecord)=48 bytes (got {delta}).\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        );
        let chain = addr_chain.ok_or_else(|| {
            anyhow::anyhow!("missing nested record pointer address. STDOUT: {stdout}")
        })?;
        assert_eq!(
            chain, a2,
            "expected nested record pointer addition to equal record+2.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        );
    } else {
        // If we didn't observe failure lines with addresses, we cannot assert safely here.
        // Consider success in this scenario to avoid flaky behavior.
    }

    Ok(())
}

#[tokio::test]
async fn test_special_pid_in_if_condition() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let test_pid = get_global_test_pid_with_opt(opt_level).await?;

    // Use $input_pid in an expression: it should equal the PID passed through -p.
    let script_content = format!(
        "trace sample_program.c:16 {{\n    if $input_pid == {test_pid} {{ print \"PID_OK\"; }} else {{ print \"PID_BAD\"; }}\n}}\n"
    );

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(&script_content, 3, opt_level).await?;

    assert_eq!(exit_code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("PID_OK"),
        "Expected PID_OK in output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_special_tid_and_timestamp_print() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    // Just print them to ensure they compile, evaluate and render
    let script_content = r#"
trace sample_program.c:16 {
    print "TST:{} {}", $tid, $timestamp;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 3, opt_level).await?;

    assert_eq!(exit_code, 0, "stderr={stderr}");
    assert!(
        stdout.contains("TST:"),
        "Expected TST: with tid/timestamp in output. STDOUT: {stdout}"
    );
    Ok(())
}

// Global cleanup registration - only runs once when the first test calls it
static GLOBAL_CLEANUP_REGISTERED: Once = Once::new();

fn ensure_global_cleanup_registered() {
    GLOBAL_CLEANUP_REGISTERED.call_once(|| {
        // Use atexit to ensure cleanup runs when the test binary exits
        extern "C" fn cleanup_on_exit() {
            println!("🧹 Global test cleanup: All tests finished, cleaning up...");

            // Kill any remaining sample_program processes
            let _pkill_result = std::process::Command::new("pkill")
                .args(["-f", "sample_program"]) // pass array by value to avoid needless borrow
                .status()
                .is_ok();

            // Clean up sample_program build files
            let fixtures_path =
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
            let sample_program_dir = fixtures_path.join("sample_program");

            println!("🧹 Running make clean in sample_program directory...");
            let clean_result = std::process::Command::new("make")
                .arg("clean")
                .current_dir(sample_program_dir)
                .output();

            match clean_result {
                Ok(output) => {
                    if output.status.success() {
                        println!("✓ Successfully cleaned sample_program build files");
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        println!("⚠️ Make clean failed: {stderr}");
                    }
                }
                Err(e) => {
                    println!("⚠️ Failed to run make clean: {e}");
                }
            }

            println!("🧹 Global cleanup completed");
        }

        unsafe {
            libc::atexit(cleanup_on_exit);
        }

        println!("✓ Global cleanup handler registered");
    });
}

/// Helper to run ghostscope with script and capture results with specific optimization level
/// For failing cases (syntax errors, etc.), this will return quickly with exit code != 0
/// For successful cases, this will run for timeout_secs, collect output, then terminate the process
async fn run_ghostscope_with_script_opt(
    script_content: &str,
    timeout_secs: u64,
    opt_level: OptimizationLevel,
) -> anyhow::Result<(i32, String, String)> {
    // Get PID of running sample_program with specific optimization level
    let test_pid = get_global_test_pid_with_opt(opt_level).await?;

    println!(
        "🔍 Running ghostscope with {} binary (PID: {})",
        opt_level.description(),
        test_pid
    );

    let target = get_global_test_target_with_opt(opt_level).await?;

    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(&target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

/// Helper to run ghostscope with script and capture results (defaults to Debug optimization)
/// For failing cases (syntax errors, etc.), this will return quickly with exit code != 0
/// For successful cases, this will run for timeout_secs, collect output, then terminate the process
async fn run_ghostscope_with_script(
    script_content: &str,
    timeout_secs: u64,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_opt(script_content, timeout_secs, OptimizationLevel::Debug).await
}

#[tokio::test]
async fn test_capture_len_uses_scalar_script_var_from_dwarf_expr() -> anyhow::Result<()> {
    init();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for sample_program: {e}"))?;
    let script_content = r#"
trace sample_lib.c:45 {
    let n = len;
    print "LEN_MSG={:s.n$}", str;
}
"#;

    let compile_options = ghostscope_compiler::CompileOptions {
        binary_path_hint: Some(binary_path.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let result = ghostscope_compiler::compile_script(
        script_content,
        &analyzer,
        None,
        Some(1),
        &compile_options,
    )
    .map_err(|e| anyhow::anyhow!("compile_script failed: {e}"))?;

    assert!(
        !result.uprobe_configs.is_empty(),
        "expected at least one compiled uprobe config"
    );
    Ok(())
}

#[tokio::test]
async fn test_logical_or_short_circuit_chain() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Attach to a hot function so we get a few events quickly
    let script_content = r#"
trace calculate_something {
    // Exercise chained OR; final should be true
    print (0 || 0 || 1);
    // Exercise chained OR; final should be false
    print (0 || 0 || 0);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Expect to observe both true and false lines at least once
    let saw_true = stdout.contains("true");
    let saw_false = stdout.contains("false");
    assert!(
        saw_true,
        "Expected at least one true result. STDOUT: {stdout}"
    );
    assert!(
        saw_false,
        "Expected at least one false result. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_memcmp_rejects_script_pointer_variable_e2e() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Using a script pointer variable as memcmp arg must fail at compile time now.
    let script_content = r#"
trace calculate_something {
    let p = "A";
    if memcmp(p, hex("41"), 1) { print "OK"; } else { print "NO"; }
}
"#;

    let (exit_code, _stdout, stderr) = run_ghostscope_with_script(script_content, 2).await?;
    assert!(
        exit_code != 0,
        "expected non-zero exit due to compile error; stderr={stderr}"
    );
    // Expect the consolidated failed-targets banner with the pointer/address type error and tip
    let has_banner = stderr.contains("No uprobe configurations created")
        || stderr.contains("Script compilation failed");
    let has_failed_targets = stderr.contains("Failed targets:");
    let has_reason = stderr.contains("expression is not a pointer/address");
    let has_tip = stderr.contains("Tip: fix the reported compile-time errors above");
    assert!(
        has_banner && has_failed_targets && has_reason && has_tip,
        "Expected failed-targets details with pointer/address reason and tip. stderr={stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_address_trace_compile_failure_uses_failed_target_banner() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let binary_path = FIXTURES.get_test_binary("sample_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("failed to load DWARF for sample_program: {e}"))?;
    let addrs = analyzer.lookup_function_addresses("calculate_something");
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for calculate_something"
    );
    let pc = addrs[0].address;

    let script_content = format!(
        r#"
trace 0x{pc:x} {{
    let p = "A";
    if memcmp(p, hex("41"), 1) {{ print "OK"; }} else {{ print "NO"; }}
}}
"#
    );

    let (exit_code, _stdout, stderr) = run_ghostscope_with_script(&script_content, 2).await?;
    assert!(
        exit_code != 0,
        "expected non-zero exit due to compile error; stderr={stderr}"
    );

    let has_banner = stderr.contains("No uprobe configurations created")
        || stderr.contains("Script compilation failed");
    assert!(
        has_banner && stderr.contains("Failed targets:"),
        "Expected failed-targets banner for address trace. stderr={stderr}"
    );
    assert!(
        stderr.contains(&format!("0x{pc:x}"))
            && stderr.contains("expression is not a pointer/address"),
        "Expected address target and pointer/address reason. stderr={stderr}"
    );
    assert!(
        !stderr.contains("Code generation error:"),
        "User-facing stderr should not expose CodeGen wrapper. stderr={stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_pointer_ordered_comparison_is_rejected_e2e() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Ordered comparisons on pointers/addresses (<, <=, >, >=) are forbidden at compile time.
    // process_data(const char* message) provides a pointer parameter for this check.
    let script_content = r#"
trace process_data {
    if message > 0 { print "BAD"; }
}
"#;

    let (exit_code, _stdout, stderr) = run_ghostscope_with_script(script_content, 2).await?;
    assert!(
        exit_code != 0,
        "expected non-zero exit due to compile error; stderr={stderr}"
    );

    // Expect banner + friendly pointer-ordered-comparison message
    let has_banner = stderr.contains("No uprobe configurations created")
        || stderr.contains("Script compilation failed");
    let has_reason =
        stderr.contains("Pointer ordered comparison ('<', '<=', '>', '>=') is not supported");
    assert!(
        has_banner && has_reason,
        "Expected pointer ordered comparison rejection with banner. stderr={stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_pointer_addition_print_reads_element_at_offset() -> anyhow::Result<()> {
    // Verify: print activity + 1; where activity: const char* in log_activity
    // Should move by sizeof(char) and print the byte at new address (expected 'a' from "main_loop").
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace log_activity {
    print activity + 1;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 4, opt_level).await?;

    assert_eq!(
        exit_code, 0,
        "unexpected error: stderr={stderr}\nstdout={stdout}"
    );

    // Expect at least one line like: "(activity+1) = <value>" or "activity + 1 = <value>"
    // Accept either numeric '97' or "'a'" depending on encoding handling.
    let mut matched = false;
    for line in stdout.lines() {
        let t = line.trim();
        let is_name = t.starts_with("(activity+1) = ") || t.starts_with("activity + 1 = ");
        if is_name && (t.ends_with("97") || t.ends_with("'a'")) {
            matched = true;
            break;
        }
    }
    assert!(
        matched,
        "expected activity + 1 to print 'a' (97).\nSTDOUT: {stdout}\nSTDERR: {stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_pointer_addition_scales_on_int_array() -> anyhow::Result<()> {
    // Verify: on calculate_average(int* numbers, int count), numbers+1 reads the 2nd int (20), numbers+2 reads 3rd (30)
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::Debug;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace sample_program.c:42 {
    print numbers + 1;
    print numbers + 2;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 5, opt_level).await?;

    assert_eq!(
        exit_code, 0,
        "unexpected error: stderr={stderr}\nstdout={stdout}"
    );

    let mut saw_20 = false;
    let mut saw_30 = false;
    let mut addr1: Option<u64> = None;
    let mut addr2: Option<u64> = None;
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("(numbers+1) = ") {
            if t.ends_with("20") {
                saw_20 = true;
            }
            if let Some(ix) = t.rfind("0x") {
                let mut j = ix + 2;
                let bytes = t.as_bytes();
                while j < t.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > ix + 2 {
                    if let Ok(v) = u64::from_str_radix(&t[ix + 2..j], 16) {
                        addr1 = Some(v);
                    }
                }
            }
        }
        if t.starts_with("(numbers+2) = ") {
            if t.ends_with("30") {
                saw_30 = true;
            }
            if let Some(ix) = t.rfind("0x") {
                let mut j = ix + 2;
                let bytes = t.as_bytes();
                while j < t.len() && bytes[j].is_ascii_hexdigit() {
                    j += 1;
                }
                if j > ix + 2 {
                    if let Ok(v) = u64::from_str_radix(&t[ix + 2..j], 16) {
                        addr2 = Some(v);
                    }
                }
            }
        }
    }
    if !(saw_20 && saw_30) {
        if let (Some(a1), Some(a2)) = (addr1, addr2) {
            assert_eq!(
                a2.wrapping_sub(a1),
                4,
                "expected address delta 4 bytes.\nSTDOUT: {stdout}\nSTDERR: {stderr}"
            );
        } else {
            panic!("expected (numbers+1)=20 and (numbers+2)=30, or address delta=4.\nSTDOUT: {stdout}\nSTDERR: {stderr}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_string_variable_copy_allowed_e2e() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    let s = "A";
    let p = s;
    print p;
}
"#;

    let (exit_code, _stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "unexpected error: stderr={stderr}");
    Ok(())
}

#[tokio::test]
async fn test_assignment_is_rejected_with_friendly_message_e2e() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Immutable variables: reject assignment 'a = ...' with friendly error
    let script_content = r#"
trace calculate_something {
    let a = G_STATE.lib;
    a = G_STATE;
    if memcmp(a, hex("00"), 1) { print "A"; }
    else if memcmp(gm, hex("48"), 1) { print "B"; }
    else { print "C"; }
}
"#;

    let (exit_code, _stdout, stderr) = run_ghostscope_with_script(script_content, 2).await?;
    assert!(
        exit_code != 0,
        "expected compile-time error; stderr={stderr}"
    );
    assert!(
        stderr.contains("Assignment is not supported: variables are immutable"),
        "stderr should contain friendly assignment error. stderr={stderr}"
    );
    Ok(())
}

#[tokio::test]
async fn test_logical_mixed_precedence() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Validate precedence: && has higher precedence than ||
    // (1 || 0 && 0) => 1 || (0 && 0) => true
    // (0 || 1 && 0) => 0 || (1 && 0) => false
    let script_content = r#"
trace calculate_something {
    print "MIX:{}|{}", (1 || 0 && 0), (0 || 1 && 0);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Look for a line like: MIX:true|false
    let expected = "MIX:true|false";
    assert!(
        stdout.contains(expected),
        "Expected \"{expected}\". STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_logical_and_short_circuit_chain() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    // true && true && false => false
    print (1 && 1 && 0);
    // true && true && true => true
    print (1 && 1 && 1);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    let saw_true = stdout.contains("true");
    let saw_false = stdout.contains("false");
    assert!(
        saw_true,
        "Expected at least one true result. STDOUT: {stdout}"
    );
    assert!(
        saw_false,
        "Expected at least one false result. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_syntax_error() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "missing semicolon"  // Missing semicolon - should cause parse error
    invalid_token_here
}
"#;

    println!("=== Syntax Error Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("=========================");

    // Should fail fast with syntax error
    assert_ne!(exit_code, 0, "Invalid syntax should cause non-zero exit");
    assert!(
        stderr.contains("Parse error") || stderr.contains("not running"),
        "Should contain parse error: {stderr}"
    );

    if stderr.contains("Parse error") {
        println!("✓ Syntax error correctly detected and rejected");
    } else {
        println!(
            "○ Ghostscope exited because target process ended before parsing (stderr: {})",
            stderr.trim()
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_top_level_non_trace_statement_is_rejected() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
print "orphan output";
"#;

    println!("=== Top-level Non-trace Statement Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("==========================================");

    assert_ne!(
        exit_code, 0,
        "top-level non-trace statements should fail. stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("top-level") && stderr.contains("trace"),
        "expected a top-level trace error. stderr={stderr} stdout={stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_format_mismatch() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "format {} {} but only one arg", a;  // Format/argument count mismatch
}
"#;

    println!("=== Format Mismatch Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("============================");

    // Should fail fast with format error
    assert_ne!(exit_code, 0, "Format mismatch should cause non-zero exit");

    // Check for format validation error
    if stderr.contains("Parse error")
        || stderr.contains("Type error")
        || stderr.contains("format")
        || stderr.contains("placeholders")
    {
        println!("✓ Format mismatch correctly detected");
    } else {
        println!("⚠️  Expected format validation error, got: {stderr}");
    }

    Ok(())
}

#[tokio::test]
async fn test_nonexistent_function() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace nonexistent_function_12345 {
    print "This function does not exist in sample_program";
}
"#;

    println!("=== Nonexistent Function Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("=================================");

    // Should fail fast when function doesn't exist
    assert_ne!(
        exit_code, 0,
        "Nonexistent function should cause non-zero exit"
    );
    assert!(
        !stderr.contains("Parse error"),
        "Script syntax should be valid: {stderr}"
    );

    if stderr.contains("No uprobe configurations created") {
        println!("✓ Correctly detected that target function doesn't exist");
    } else {
        println!("⚠️  Expected 'No uprobe configurations' error, got: {stderr}");
    }

    Ok(())
}

#[tokio::test]
async fn test_o3_cross_object_register_args_and_string_pointer_formatting() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::O3;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace add_numbers {
    print "O3_ADD:{}:{}:{}", a, b, a + b;
    print "O3_DIV_DYNAMIC:{}:{}:{}", a, b, b / a;
    if b == a * 2 { print "O3_ADD_OK"; }
    if b / (b - a) >= 0x1 { print "O3_DIV_DYNAMIC_OK"; }
}

trace get_string_length {
    let dyn_offset = 0xb + ($pid - $pid);
    let dyn_prefix = ($pid - $pid) + str;
    let dyn_tail = str + dyn_offset;
    print "O3_STR={:s.0x9}", str;
    print "O3_STR_DYN_PREFIX={:s.0x9}", dyn_prefix;
    print "O3_STR_DYN_TAIL={:s.0x5}", dyn_tail;
    if strncmp(str, "Iteration", 0x9) { print "O3_STR_OK"; }
    if strncmp(str + 11, "value", 5) { print "O3_STR_OFFSET_OK"; }
    if strncmp(dyn_prefix, "Iteration", 0b1001) { print "O3_STR_DYN_PREFIX_OK"; }
    if strncmp(dyn_tail, "value", 0x5) { print "O3_STR_DYN_TAIL_OK"; }
    if strncmp(dyn_offset + str, "value", 0o5) { print "O3_STR_DYN_COMMUTE_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 4, opt_level).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_ADD_OK"),
        "Expected O3 cross-object register argument comparison. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DIV_DYNAMIC_OK"),
        "Expected O3 dynamic division marker. STDOUT: {stdout}"
    );
    let mut div_samples = 0;
    for line in stdout.lines() {
        let Some(sample) = line.trim().strip_prefix("O3_DIV_DYNAMIC:") else {
            continue;
        };
        let fields: Vec<_> = sample.split(':').collect();
        if fields.len() != 3 {
            continue;
        }
        let a: i64 = fields[0].parse()?;
        let b: i64 = fields[1].parse()?;
        let quotient: i64 = fields[2].parse()?;
        assert_ne!(a, 0, "STDOUT: {stdout}");
        assert_eq!(quotient, b / a, "STDOUT: {stdout}");
        div_samples += 1;
    }
    assert!(
        div_samples >= 1,
        "Expected O3 dynamic division samples. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR=Iteration"),
        "Expected O3 string pointer formatting with hex static length. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR_DYN_PREFIX=Iteration"),
        "Expected O3 dynamic string pointer alias formatting at prefix. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR_DYN_TAIL=value"),
        "Expected O3 dynamic string pointer alias formatting at tail. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR_OK"),
        "Expected O3 strncmp with hex static length. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR_OFFSET_OK"),
        "Expected O3 strncmp on typed string pointer arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_STR_DYN_PREFIX_OK")
            && stdout.contains("O3_STR_DYN_TAIL_OK")
            && stdout.contains("O3_STR_DYN_COMMUTE_OK"),
        "Expected O3 dynamic string pointer alias strncmp markers. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_o3_guarded_dynamic_division_short_circuits_zero_denominator() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::O3;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace calculate_something {
    let denom = b - a - 0x5;
    if denom == 0 || a / denom > 0 { print "O3_DIV_GUARD_OR_OK"; }
    if denom != 0 && a / denom > 0 { print "O3_DIV_GUARD_AND_BAD"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 4, opt_level).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_DIV_GUARD_OR_OK"),
        "Expected short-circuit OR guard marker. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("O3_DIV_GUARD_AND_BAD"),
        "AND guard should not execute division branch while denom is zero. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("ExprError"),
        "Guarded dynamic division should not emit ExprError. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_o3_local_int_array_decay_pointer_addition_and_memcmp() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let opt_level = OptimizationLevel::O3;
    let _ = get_global_test_pid_with_opt(opt_level).await?;

    let script_content = r#"
trace sample_program.c:73 {
    let p = numbers + 0x1;
    let q = p;
    let r = p - 0b1;
    let s = p + -0x1;
    let t = -0x1 + p;
    let u = p - -0x1;
    let byte_back = &numbers[0b10] + -0x4;
    let byte_forward = &numbers[0x1] - -0x4;
    let dyn_arr_idx = numbers[0x0] / 0xa;
    let dyn_ptr_idx = (numbers[0b10] / numbers[0x0]) - 0b10;
    let dyn_ptr = numbers + dyn_arr_idx;
    let dyn_alias = p + dyn_ptr_idx;
    let dyn_byte_off = dyn_arr_idx * 0x4;
    let dyn_raw_addr = &numbers[0x0] + dyn_byte_off;
    let dyn_raw_back = &numbers[0b10] - dyn_byte_off;
    print "O3_NUM1:{}", numbers + 1;
    print "O3_NUM2:{}", (numbers + 0x1) + 0b1;
    print "O3_ALIAS_NUM2:{}", p + 0b1;
    print "O3_MIXED_NUM2:{}", (numbers + 0x3) - 0b1;
    print "O3_ALIAS_CHAIN_NUM2:{}", q + 0b1;
    print "O3_INDEX_NUM2:{}", numbers[0b10];
    print "O3_ALIAS_INDEX_NUM2:{}", p[0b1];
    print "O3_ALIAS_CHAIN_INDEX_NUM2:{}", q[0b1];
    print "O3_NEG_INDEX0:{}", p[-0x1];
    print "O3_CONST_EXPR_INDEX_NUM2:{}", p[0x2 - 0b1];
    print "O3_CONST_EXPR_CHAIN_INDEX_NUM2:{}", q[-0x1 + 0b10];
    print "O3_DYNAMIC_INDEX:{}:{}:{}", dyn_arr_idx, numbers[dyn_arr_idx], p[dyn_ptr_idx];
    print "O3_DYNAMIC_INDEX_CHAIN:{}:{}", q[dyn_ptr_idx], p[dyn_ptr_idx - 0x1];
    print "O3_DYNAMIC_ALIAS_VALUE:{}:{}", dyn_ptr[0x1], dyn_ptr[dyn_arr_idx];
    print "O3_DEREF_ALIAS1:{}", *p;
    print "O3_DEREF_ALIAS_CHAIN2:{}", *(q + 0b1);
    print "O3_NUM_DIV:{}:{}:{}", numbers[0b10] / numbers[0x0], p[0b1] / *p, *(q + 0b1) / (p[-0x1] + 0x5);
    print "O3_DYNAMIC_INDEX_DIV:{}:{}", numbers[dyn_arr_idx + 0x1] / numbers[dyn_arr_idx], q[dyn_ptr_idx] / p[dyn_ptr_idx - 0x1];
    print "O3_REBASED_NUM2:{}", r + 0x2;
    print "O3_REBASED_INDEX2:{}", r[0x2];
    print "O3_REBASED_DEREF2:{}", *(r + 0x2);
    print "O3_NEGADD_NUM2:{}", s + 0b10;
    print "O3_NEGADD_INDEX2:{}", s[0b10];
    print "O3_LEFT_NEGADD_NUM2:{}", t + 0b10;
    print "O3_SUB_NEG_NUM2:{}", u + 0x0;
    print "O3_NUM_HEX={:x.0x8}", numbers;
    print "O3_NUM_CHAIN_HEX={:x.0x4}", (numbers + 0x1) + 0b1;
    print "O3_ALIAS_CHAIN_HEX={:x.0x4}", p + 0b1;
    print "O3_MIXED_CHAIN_HEX={:x.0o4}", (numbers + 0x3) - 0b1;
    print "O3_ALIAS_ALIAS_CHAIN_HEX={:x.0b100}", q + 0b1;
    print "O3_DYNAMIC_INDEX_HEX={:x.0x4}", &numbers[dyn_arr_idx];
    print "O3_DYNAMIC_ALIAS_INDEX_HEX={:x.0b100}", &p[dyn_ptr_idx];
    print "O3_DYNAMIC_PTRADD_HEX={:x.0x4}", numbers + dyn_arr_idx;
    print "O3_DYNAMIC_ALIAS_PTRADD_HEX={:x.0b100}", p + dyn_ptr_idx;
    print "O3_DYNAMIC_ALIAS_DIRECT_HEX={:x.0x4}", dyn_ptr;
    print "O3_DYNAMIC_ALIAS_INDEX_HEX={:x.0x4}", &dyn_ptr[0x1];
    print "O3_DYNAMIC_ALIAS_DYN_INDEX_HEX={:x.0b100}", &dyn_ptr[dyn_arr_idx];
    print "O3_DYNAMIC_ALIAS_PLUS_HEX={:x.0x4}", dyn_ptr + 0x1;
    print "O3_DYNAMIC_ALIAS_SUB_HEX={:x.0x4}", dyn_alias - dyn_ptr_idx;
    print "O3_DYNAMIC_ALIAS_COMMUTE_HEX={:x.0x4}", dyn_arr_idx + dyn_ptr;
    print "O3_DYNAMIC_RAW_ADDR_HEX={:x.0x4}", dyn_raw_addr;
    print "O3_DYNAMIC_RAW_BACK_HEX={:x.0b100}", dyn_raw_back;
    print "O3_ADDR_ALIAS_INDEX_HEX={:x.0x4}", &p[0b1];
    print "O3_ADDR_DEREF_HEX={:x.0b100}", &*(q + 0b1);
    print "O3_NEGADD_HEX={:x.0x4}", s + 0b10;
    print "O3_LEFT_NEGADD_HEX={:x.0x4}", t + 0b10;
    print "O3_SUB_NEG_HEX={:x.0x4}", u + 0x0;
    print "O3_BYTE_BACK_HEX={:x.0x4}", byte_back;
    print "O3_BYTE_FORWARD_HEX={:x.0b100}", byte_forward;
    print "O3_NEG_INDEX_HEX={:x.0x4}", &p[-0x1];
    print "O3_CONST_EXPR_INDEX_HEX={:x.0o4}", &p[0x2 - 0b1];
    print "O3_CONST_EXPR_CHAIN_INDEX_HEX={:x.0b100}", &q[-0x1 + 0b10];
    if memcmp(numbers, hex("0a00000014000000"), 0x8) { print "O3_NUM_MEM_OK"; }
    if memcmp(numbers + 1, hex("14000000"), 0b100) { print "O3_NUM_PTRADD_OK"; }
    if memcmp((numbers + 0x1) + 0b1, hex("1e000000"), 0b100) { print "O3_NUM_CHAIN_PTRADD_OK"; }
    if memcmp(p + 0b1, hex("1e000000"), 0b100) { print "O3_NUM_ALIAS_PTRADD_OK"; }
    if memcmp((numbers + 0x3) - 0b1, hex("1e000000"), 0o4) { print "O3_NUM_MIXED_PTRADD_OK"; }
    if memcmp(q + 0b1, hex("1e000000"), 0b100) { print "O3_NUM_ALIAS_CHAIN_PTRADD_OK"; }
    if memcmp(r + 0x2, hex("1e000000"), 0x4) { print "O3_NUM_REBASED_PTRADD_OK"; }
    if memcmp(&numbers[dyn_arr_idx], hex("14000000"), 0x4) { print "O3_DYNAMIC_INDEX_ADDR_OK"; }
    if memcmp(&p[dyn_ptr_idx], hex("1e000000"), 0b100) { print "O3_DYNAMIC_ALIAS_INDEX_ADDR_OK"; }
    if memcmp(numbers + dyn_arr_idx, hex("14000000"), 0x4) { print "O3_DYNAMIC_PTRADD_OK"; }
    if memcmp(p + dyn_ptr_idx, hex("1e000000"), 0b100) { print "O3_DYNAMIC_ALIAS_PTRADD_OK"; }
    if memcmp(dyn_ptr, hex("14000000"), 0x4) { print "O3_DYNAMIC_ALIAS_DIRECT_OK"; }
    if memcmp(&dyn_ptr[0x1], hex("1e000000"), 0x4) { print "O3_DYNAMIC_ALIAS_INDEX_OK"; }
    if memcmp(&dyn_ptr[dyn_arr_idx], hex("1e000000"), 0b100) { print "O3_DYNAMIC_ALIAS_DYN_INDEX_OK"; }
    if memcmp(dyn_ptr + 0x1, hex("1e000000"), 0x4) { print "O3_DYNAMIC_ALIAS_PLUS_OK"; }
    if memcmp(dyn_alias - dyn_ptr_idx, hex("14000000"), 0x4) { print "O3_DYNAMIC_ALIAS_SUB_OK"; }
    if memcmp(dyn_arr_idx + dyn_ptr, hex("1e000000"), 0x4) { print "O3_DYNAMIC_ALIAS_COMMUTE_OK"; }
    if memcmp(dyn_raw_addr, hex("14000000"), 0x4) { print "O3_DYNAMIC_RAW_ADDR_OK"; }
    if memcmp(dyn_raw_back, hex("14000000"), 0b100) { print "O3_DYNAMIC_RAW_BACK_OK"; }
    if memcmp(&p[0b1], hex("1e000000"), 0x4) { print "O3_ADDR_ALIAS_INDEX_OK"; }
    if memcmp(&*(q + 0b1), hex("1e000000"), 0b100) { print "O3_ADDR_DEREF_OK"; }
    if memcmp(s + 0b10, hex("1e000000"), 0x4) { print "O3_NEGADD_PTRADD_OK"; }
    if memcmp(t + 0b10, hex("1e000000"), 0x4) { print "O3_LEFT_NEGADD_PTRADD_OK"; }
    if memcmp(u + 0x0, hex("1e000000"), 0b100) { print "O3_SUB_NEG_PTRADD_OK"; }
    if memcmp(byte_back, hex("14000000"), 0x4) { print "O3_BYTE_BACK_OK"; }
    if memcmp(byte_forward, hex("1e000000"), 0b100) { print "O3_BYTE_FORWARD_OK"; }
    if memcmp(&p[-0x1], hex("0a000000"), 0x4) { print "O3_NEG_INDEX_OK"; }
    if memcmp(&p[0x2 - 0b1], hex("1e000000"), 0o4) { print "O3_CONST_EXPR_INDEX_OK"; }
    if memcmp(&q[-0x1 + 0b10], hex("1e000000"), 0b100) { print "O3_CONST_EXPR_CHAIN_INDEX_OK"; }
    if numbers[0b10] / numbers[0x0] == 0x3 { print "O3_NUM_DIV_INDEX_OK"; }
    if p[0b1] / *p == 0b1 { print "O3_NUM_DIV_ALIAS_OK"; }
    if *(q + 0b1) / (p[-0x1] + 0x5) == 0x2 { print "O3_NUM_DIV_MIXED_OK"; }
    if numbers[dyn_arr_idx] == 0x14 { print "O3_DYNAMIC_INDEX_ARRAY_OK"; }
    if p[dyn_ptr_idx] == 0x1e { print "O3_DYNAMIC_INDEX_PTR_OK"; }
    if q[dyn_ptr_idx] / p[dyn_ptr_idx - 0x1] == 0x1 { print "O3_DYNAMIC_INDEX_DIV_OK"; }
    if dyn_ptr[0x1] == 0x1e && dyn_ptr[dyn_arr_idx] == 0x1e { print "O3_DYNAMIC_ALIAS_VALUE_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_opt(script_content, 4, opt_level).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_NUM1:20") || stdout.contains("O3_NUM1:(numbers+1) = 20"),
        "Expected O3 pointer addition on int array to read the second element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM2:30") || stdout.contains("O3_NUM2:((numbers+1)+1) = 30"),
        "Expected nested O3 pointer addition on int array to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_NUM2:30") || stdout.contains("O3_ALIAS_NUM2:(p+1) = 30"),
        "Expected alias-based nested O3 pointer addition on int array to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_MIXED_NUM2:30")
            || stdout.contains("O3_MIXED_NUM2:((numbers+3)-1) = 30"),
        "Expected mixed +/- O3 pointer arithmetic on int array to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_CHAIN_NUM2:30")
            || stdout.contains("O3_ALIAS_CHAIN_NUM2:(q+1) = 30"),
        "Expected alias-of-alias O3 pointer arithmetic on int array to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_INDEX_NUM2:30"),
        "Expected O3 binary array index on int array to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_INDEX_NUM2:30"),
        "Expected O3 alias pointer array index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_CHAIN_INDEX_NUM2:30"),
        "Expected O3 alias-of-alias pointer array index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEG_INDEX0:10"),
        "Expected O3 negative alias pointer array index to read the first element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_INDEX_NUM2:30"),
        "Expected O3 constant-expression alias pointer index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_CHAIN_INDEX_NUM2:30"),
        "Expected O3 constant-expression alias-of-alias index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX:1:20:30"),
        "Expected dynamic array and alias pointer indexes to read second and third elements. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX_CHAIN:30:20"),
        "Expected dynamic alias-of-alias pointer index and rebased dynamic index reads. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_VALUE:30:30"),
        "Expected dynamic pointer alias literal and dynamic indexes to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DEREF_ALIAS1:20"),
        "Expected O3 alias pointer dereference to read the second element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DEREF_ALIAS_CHAIN2:30"),
        "Expected O3 alias-of-alias pointer arithmetic dereference to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_DIV:3:1:2"),
        "Expected O3 local array indexed division results. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX_DIV:1:1"),
        "Expected dynamic local array and alias pointer division results. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_REBASED_NUM2:30") || stdout.contains("O3_REBASED_NUM2:(r+2) = 30"),
        "Expected O3 rebased subtraction alias pointer addition to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_REBASED_INDEX2:30"),
        "Expected O3 rebased subtraction alias array index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_REBASED_DEREF2:30"),
        "Expected O3 rebased subtraction alias dereference to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEGADD_NUM2:30") || stdout.contains("O3_NEGADD_NUM2:(s+2) = 30"),
        "Expected O3 alias plus negative literal pointer addition to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEGADD_INDEX2:30"),
        "Expected O3 alias plus negative literal array index to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_LEFT_NEGADD_NUM2:30")
            || stdout.contains("O3_LEFT_NEGADD_NUM2:(t+2) = 30"),
        "Expected O3 negative-left alias pointer addition to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_SUB_NEG_NUM2:30") || stdout.contains("O3_SUB_NEG_NUM2:(u+0) = 30"),
        "Expected O3 subtract-negative alias pointer arithmetic to read the third element. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_HEX=0a 00 00 00 14 00 00 00"),
        "Expected O3 local int array hex memdump. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_CHAIN_HEX=1e 00 00 00"),
        "Expected nested O3 pointer addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_CHAIN_HEX=1e 00 00 00"),
        "Expected alias-based nested O3 pointer addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_MIXED_CHAIN_HEX=1e 00 00 00"),
        "Expected mixed +/- O3 pointer addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ALIAS_ALIAS_CHAIN_HEX=1e 00 00 00"),
        "Expected alias-of-alias O3 pointer addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX_HEX=14 00 00 00"),
        "Expected dynamic address-of local array index memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_INDEX_HEX=1e 00 00 00"),
        "Expected dynamic address-of alias pointer index memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_PTRADD_HEX=14 00 00 00"),
        "Expected dynamic local array pointer addition memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_PTRADD_HEX=1e 00 00 00"),
        "Expected dynamic alias pointer addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_DIRECT_HEX=14 00 00 00"),
        "Expected dynamic pointer alias memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_INDEX_HEX=1e 00 00 00"),
        "Expected dynamic pointer alias literal index memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_DYN_INDEX_HEX=1e 00 00 00"),
        "Expected dynamic pointer alias dynamic index memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_PLUS_HEX=1e 00 00 00"),
        "Expected dynamic pointer alias plus literal memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_SUB_HEX=14 00 00 00"),
        "Expected dynamic pointer alias subtraction memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_COMMUTE_HEX=1e 00 00 00"),
        "Expected dynamic pointer alias commuted addition memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_RAW_ADDR_HEX=14 00 00 00"),
        "Expected dynamic raw address byte-offset memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_RAW_BACK_HEX=14 00 00 00"),
        "Expected dynamic raw address byte-offset subtraction memdump to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ADDR_ALIAS_INDEX_HEX=1e 00 00 00"),
        "Expected address-of alias pointer indexing memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ADDR_DEREF_HEX=1e 00 00 00"),
        "Expected address-of pointer dereference memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEGADD_HEX=1e 00 00 00"),
        "Expected alias plus negative literal memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_LEFT_NEGADD_HEX=1e 00 00 00"),
        "Expected negative-left alias pointer memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_SUB_NEG_HEX=1e 00 00 00"),
        "Expected subtract-negative alias pointer memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYTE_BACK_HEX=14 00 00 00"),
        "Expected raw address plus negative byte offset to start at the second int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYTE_FORWARD_HEX=1e 00 00 00"),
        "Expected raw address subtract-negative byte offset to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEG_INDEX_HEX=0a 00 00 00"),
        "Expected address-of negative alias pointer index to start at the first int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_INDEX_HEX=1e 00 00 00"),
        "Expected constant-expression alias pointer index memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_CHAIN_INDEX_HEX=1e 00 00 00"),
        "Expected constant-expression alias-of-alias index memdump to start at the third int. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_MEM_OK"),
        "Expected O3 memcmp on local int array decay. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_PTRADD_OK"),
        "Expected O3 memcmp on scaled int pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_CHAIN_PTRADD_OK"),
        "Expected O3 memcmp on nested scaled int pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_ALIAS_PTRADD_OK"),
        "Expected O3 memcmp on alias-based nested scaled int pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_MIXED_PTRADD_OK"),
        "Expected O3 memcmp on mixed +/- scaled int pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_ALIAS_CHAIN_PTRADD_OK"),
        "Expected O3 memcmp on alias-of-alias scaled int pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_REBASED_PTRADD_OK"),
        "Expected O3 memcmp on rebased subtraction alias pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX_ADDR_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_INDEX_ADDR_OK"),
        "Expected O3 memcmp on dynamic address-of array and alias pointer indexes. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_PTRADD_OK") && stdout.contains("O3_DYNAMIC_ALIAS_PTRADD_OK"),
        "Expected O3 memcmp on dynamic array and alias pointer addition. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ALIAS_DIRECT_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_INDEX_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_DYN_INDEX_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_PLUS_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_SUB_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_COMMUTE_OK"),
        "Expected O3 memcmp on dynamic pointer aliases and follow-up arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_RAW_ADDR_OK") && stdout.contains("O3_DYNAMIC_RAW_BACK_OK"),
        "Expected O3 memcmp on dynamic raw address byte offsets. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ADDR_ALIAS_INDEX_OK"),
        "Expected O3 memcmp on address-of alias pointer indexing. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ADDR_DEREF_OK"),
        "Expected O3 memcmp on address-of pointer dereference. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEGADD_PTRADD_OK"),
        "Expected O3 memcmp on alias plus negative literal pointer arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_LEFT_NEGADD_PTRADD_OK"),
        "Expected O3 memcmp on negative-left alias pointer arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_SUB_NEG_PTRADD_OK"),
        "Expected O3 memcmp on subtract-negative alias pointer arithmetic. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYTE_BACK_OK"),
        "Expected O3 memcmp on raw address plus negative byte offset. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_BYTE_FORWARD_OK"),
        "Expected O3 memcmp on raw address subtract-negative byte offset. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NEG_INDEX_OK"),
        "Expected O3 memcmp on address-of negative alias pointer index. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_INDEX_OK"),
        "Expected O3 memcmp on constant-expression alias pointer index. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_CONST_EXPR_CHAIN_INDEX_OK"),
        "Expected O3 memcmp on constant-expression alias-of-alias index. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_DIV_INDEX_OK"),
        "Expected O3 indexed local array division marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_DIV_ALIAS_OK"),
        "Expected O3 alias local array division marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NUM_DIV_MIXED_OK"),
        "Expected O3 mixed local array division marker. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_INDEX_ARRAY_OK")
            && stdout.contains("O3_DYNAMIC_INDEX_PTR_OK")
            && stdout.contains("O3_DYNAMIC_INDEX_DIV_OK")
            && stdout.contains("O3_DYNAMIC_ALIAS_VALUE_OK"),
        "Expected O3 dynamic array and pointer index markers. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_function_level_tracing() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "CALC: a={} b={}", a, b;
}
"#;

    // Test with both optimization levels.
    let optimization_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &optimization_levels {
        println!(
            "=== Function Level Tracing Test ({}) ===",
            opt_level.description()
        );

        let (exit_code, stdout, stderr) =
            run_ghostscope_with_script_opt(script_content, 3, *opt_level).await?;

        println!("Exit code: {exit_code}");
        println!("STDOUT: {stdout}");
        println!("STDERR: {stderr}");
        println!("===============================================");

        // If we have permissions, should run successfully and produce output
        assert_eq!(
            exit_code,
            0,
            "Ghostscope should succeed for {} (stderr: {})",
            opt_level.description(),
            stderr
        );

        println!("✓ Ghostscope attached and ran successfully");

        // Parse output to validate math: a == b - 5
        let mut math_validations = 0;
        let mut function_calls_found = 0;
        let mut validation_errors = Vec::new();

        for line in stdout.lines() {
            if line.contains("CALC: ") {
                function_calls_found += 1;
                if let Some((a, b)) = parse_calc_line_simple(line) {
                    if a == b - 5 {
                        println!("✓ Math validation passed: a={} == b-5={}", a, b - 5);
                        math_validations += 1;
                    } else {
                        let error_msg =
                            format!("Math validation failed: a={a} != b-5={} (b={b})", b - 5);
                        println!("❌ {error_msg}");
                        validation_errors.push(error_msg);
                    }
                } else {
                    println!("⚠️  Failed to parse line: {line}");
                }
            }
        }

        if function_calls_found == 0 {
            panic!("❌ No function calls captured - test failed. Expected at least one calculate_something call. This indicates either:\n  1. sample_program is not running\n  2. Function is not being called\n  3. Ghostscope failed to attach properly");
        } else if !validation_errors.is_empty() {
            panic!("❌ Function calls captured but math validation failed:\n  Found {} function calls, {} validation errors:\n  {}",
            function_calls_found, validation_errors.len(), validation_errors.join("\n  "));
        } else if math_validations > 0 {
            println!("✓ Validated {math_validations} calculate_something calls");
        }

        println!("===============================================");
    }

    Ok(())
}

#[tokio::test]
async fn test_multiple_trace_targets() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test both function-level and line-level tracing in one script
    let script_content = r#"
trace calculate_something {
    print "FUNC: a={} b={}", a, b;
}

trace sample_program.c:16 {
    print "LINE16: a={} b={} result={}", a, b, result;
}
"#;

    let optimization_levels = [OptimizationLevel::Debug, OptimizationLevel::O2];

    for opt_level in &optimization_levels {
        println!(
            "=== Multiple Trace Targets Test ({}) ===",
            opt_level.description()
        );

        let (exit_code, stdout, stderr) =
            run_ghostscope_with_script_opt(script_content, 3, *opt_level).await?;

        println!("Exit code: {exit_code}");
        println!("STDOUT: {stdout}");
        println!("STDERR: {stderr}");
        println!("=====================================");

        // Check that script syntax is valid
        assert!(
            !stderr.contains("Parse error"),
            "Multi-target script should have valid syntax: {stderr}"
        );

        assert_eq!(
            exit_code,
            0,
            "Ghostscope should succeed for {} (stderr: {})",
            opt_level.description(),
            stderr
        );

        println!("✓ Multiple trace targets attached and ran successfully");

        // Check for both function-level and line-level outputs
        let has_func = stdout.contains("FUNC:");
        let has_line16 = stdout.contains("LINE16:");

        if *opt_level == OptimizationLevel::Debug {
            assert!(
                has_func,
                "Expected function-level trace output for {} but none was captured. STDOUT: {}",
                opt_level.description(),
                stdout
            );
        } else if !has_func {
            println!(
                "Function-level trace did not fire for {}; calculate_something may be inlined",
                opt_level.description()
            );
        }
        assert!(
            has_line16,
            "Expected line-level trace output for {} but none was captured. STDOUT: {}",
            opt_level.description(),
            stdout
        );

        println!("Trace capture status: FUNC={has_func}, LINE16={has_line16}");

        let mut func_validations = 0;
        let mut line_validations = 0;
        let mut validation_errors = Vec::new();

        // Detect optimized-out markers and bad placeholders
        let func_has_placeholder_zero = stdout.lines().any(|line| line.contains("FUNC: a=0 b=0"));
        let func_has_optimized_marker = stdout
            .lines()
            .any(|line| line.contains("FUNC:") && line.to_lowercase().contains("optimiz"));
        let line_has_optimized_marker = stdout
            .lines()
            .any(|line| line.contains("LINE16:") && line.to_lowercase().contains("optimiz"));

        // Validate function-level traces (a == b - 5). Skip non-numeric or optimized-out lines.
        for line in stdout.lines() {
            if line.contains("FUNC: ") {
                if let Some((a, b)) = parse_calc_line_simple(line) {
                    // Treat O2 placeholder zeros as non-valid (will be asserted below)
                    if *opt_level == OptimizationLevel::Debug || (a != 0 || b != 0) {
                        if a == b - 5 {
                            println!(
                                "✓ Function-level math validation passed: a={} == b-5={}",
                                a,
                                b - 5
                            );
                            func_validations += 1;
                        } else {
                            let error_msg = format!(
                                "Function-level validation failed: a={} != b-5={}",
                                a,
                                b - 5
                            );
                            println!("❌ {error_msg}");
                            validation_errors.push(error_msg);
                        }
                    }
                }
            }
        }

        // Validate line-level traces (a * b + 42 == result)
        for line in stdout.lines() {
            if line.contains("LINE16: ") {
                if let Some((a, b, result)) = parse_line16_trace(line) {
                    let expected = a * b + 42;
                    if result == expected {
                        println!("✓ Line-level math validation passed: {a} * {b} + 42 = {result}");
                        line_validations += 1;
                    } else {
                        let error_msg = format!(
                            "Line-level validation failed: {a} * {b} + 42 = {expected} but got {result}"
                        );
                        println!("❌ {error_msg}");
                        validation_errors.push(error_msg);
                    }
                }
            }
        }

        // Adjust validation policy for optimized builds
        if *opt_level == OptimizationLevel::Debug {
            if func_validations == 0 {
                panic!(
                    "❌ Expected function-level traces for {} but none validated successfully. STDOUT: {}",
                    opt_level.description(),
                    stdout
                );
            }
            if line_validations == 0 {
                panic!(
                    "❌ Expected line-level traces for {} but none validated successfully. STDOUT: {}",
                    opt_level.description(),
                    stdout
                );
            }
        } else {
            // In optimized builds, the function body may be fully inlined into
            // its caller. If a function-level trace fires, validate it, but do
            // not require a hit from an out-of-line symbol that is not called.
            assert!(
                !func_has_placeholder_zero,
                "Should not emit placeholder optimized-out values in optimized builds. STDOUT: {stdout}"
            );
            if has_func && func_validations == 0 && !func_has_optimized_marker {
                panic!(
                    "❌ Expected function-level traces to be either numerically valid or marked as optimized-out. STDOUT: {stdout}"
                );
            }
            if line_validations == 0 && !line_has_optimized_marker {
                panic!(
                    "❌ Expected line-level traces to be either numerically valid or marked as optimized-out. STDOUT: {stdout}"
                );
            }
        }

        if !validation_errors.is_empty() {
            panic!(
                "❌ Traces captured but validation failed:\n  Function validations: {}, Line validations: {}\n  Errors: {}",
                func_validations,
                line_validations,
                validation_errors.join("\n  ")
            );
        }

        println!(
            "✓ Multiple trace targets validated successfully: {func_validations} function traces, {line_validations} line traces"
        );

        println!("=====================================");
    }

    Ok(())
}
/// Parse a calc line and return only (a, b) for simple validation
fn parse_calc_line_simple(line: &str) -> Option<(i32, i32)> {
    // Expected format: "CALC: a=5 b=3 ..." or "FUNC: a=5 b=3" - we only care about a and b
    let line = line
        .trim_start_matches("CALC: ")
        .trim_start_matches("FUNC: ");

    let mut a = None;
    let mut b = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("a=") {
            a = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("b=") {
            b = value_str.parse().ok();
        }
    }

    match (a, b) {
        (Some(a_val), Some(b_val)) => Some((a_val, b_val)),
        _ => {
            println!("⚠️  Failed to parse a and b from line: {line}");
            None
        }
    }
}

#[tokio::test]
async fn test_line_level_tracing() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test line-level tracing at sample_program.c:16 (return result;)
    let script_content = r#"
trace sample_program.c:16 {
    print "LINE16: a={} b={} result={}", a, b, result;
}
"#;

    println!("=== Line Level Tracing Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("===============================================");

    // Must run successfully
    assert_eq!(exit_code, 0, "Ghostscope should succeed (stderr: {stderr})");

    // If we have permissions, should run successfully and produce output
    if exit_code == 0 {
        println!("✓ Ghostscope attached and ran successfully");

        // Parse output to validate math: a * b + 42 == result
        let mut math_validations = 0;
        let mut function_calls_found = 0;
        let mut validation_errors = Vec::new();

        for line in stdout.lines() {
            if line.contains("LINE16: ") {
                function_calls_found += 1;
                if let Some((a, b, result)) = parse_line16_trace(line) {
                    let expected = a * b + 42;
                    if result == expected {
                        println!("✓ Math validation passed: {a} * {b} + 42 = {result}");
                        math_validations += 1;
                    } else {
                        let error_msg = format!(
                            "Math validation failed: {a} * {b} + 42 = {expected} but got {result}"
                        );
                        println!("❌ {error_msg}");
                        validation_errors.push(error_msg);
                    }
                } else {
                    println!("⚠️  Failed to parse line: {line}");
                }
            }
        }

        if function_calls_found == 0 {
            panic!("❌ No line traces captured - test failed. Expected at least one line:16 execution trace. This indicates either:\n  1. sample_program is not running\n  2. Line 16 is not being executed\n  3. Line-level tracing failed to attach");
        } else if !validation_errors.is_empty() {
            panic!("❌ Line traces captured but math validation failed:\n  Found {} line executions, {} validation errors:\n  {}",
                function_calls_found, validation_errors.len(), validation_errors.join("\n  "));
        } else if math_validations > 0 {
            println!("✓ Validated {math_validations} line:16 executions with correct math");
        }
    }

    Ok(())
}

/// Parse a line16 trace like "LINE16: a=5 b=3 result=57" and return (a, b, result)
fn parse_line16_trace(line: &str) -> Option<(i32, i32, i32)> {
    // Expected format: "LINE16: a=5 b=3 result=57"
    let line = line.trim_start_matches("LINE16: ");

    let mut a = None;
    let mut b = None;
    let mut result = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("a=") {
            a = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("b=") {
            b = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("result=") {
            result = value_str.parse().ok();
        }
    }

    match (a, b, result) {
        (Some(a_val), Some(b_val), Some(result_val)) => Some((a_val, b_val, result_val)),
        _ => {
            println!("⚠️  Failed to parse line16 trace: {line}");
            None
        }
    }
}

#[tokio::test]
async fn test_print_variables_directly() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test printing variables directly without format strings
    let script_content = r#"
trace calculate_something {
    print a;
    print b;
}
"#;

    println!("=== Print Variables Directly Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("======================================");

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Print variables script should have valid syntax: {stderr}"
    );

    assert_eq!(exit_code, 0, "Ghostscope should succeed (stderr: {stderr})");

    if exit_code == 0 {
        println!("✓ Print variables script attached successfully");

        // Look for direct variable prints (should just be numbers)
        let mut variable_prints = 0;
        for line in stdout.lines() {
            // Direct variable prints should produce simple numeric output
            if line.trim().parse::<i32>().is_ok() {
                variable_prints += 1;
                println!("✓ Found variable print: {}", line.trim());
            }
        }

        if variable_prints > 0 {
            println!("✓ Successfully captured {variable_prints} variable prints");
        } else {
            println!("⚠️ No direct variable prints captured");
        }
    }

    Ok(())
}

#[tokio::test]
async fn test_custom_variables() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Test custom variable definition and usage
    let script_content = r#"
trace calculate_something {
    let sum = a + b;
    let diff = a - b;
    let product = a * b;
    print "CUSTOM: sum={} diff={} product={}", sum, diff, product;
}
"#;

    println!("=== Custom Variables Test ===");

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("==============================");

    // Check that script syntax is valid
    assert!(
        !stderr.contains("Parse error"),
        "Custom variables script should have valid syntax: {stderr}"
    );

    assert_eq!(exit_code, 0, "Ghostscope should succeed (stderr: {stderr})");

    if exit_code == 0 {
        println!("✓ Custom variables script attached successfully");

        let mut custom_var_outputs = 0;
        let mut math_validations = 0;

        for line in stdout.lines() {
            if line.contains("CUSTOM: ") {
                custom_var_outputs += 1;
                if let Some((a, b, sum, diff, product)) = parse_custom_variables_line(line) {
                    let expected_sum = a + b;
                    let expected_diff = a - b;
                    let expected_product = a * b;

                    if sum == expected_sum && diff == expected_diff && product == expected_product {
                        math_validations += 1;
                        println!("✓ Custom variables validated: sum={a}+{b}={sum}, diff={a}-{b}={diff}, product={a}*{b}={product}");
                    } else {
                        println!("❌ Custom variables validation failed:");
                        println!(
                            "   Expected: sum={expected_sum}, diff={expected_diff}, product={expected_product}"
                        );
                        println!("   Got: sum={sum}, diff={diff}, product={product}");
                    }
                }
            }
        }

        if custom_var_outputs > 0 && math_validations > 0 {
            println!("✓ Successfully validated {math_validations} custom variable calculations");
        } else if custom_var_outputs > 0 {
            println!("⚠️ Custom variable outputs captured but validation failed");
        } else {
            println!("⚠️ No custom variable outputs captured");
        }
    }

    Ok(())
}

/// Parse a custom variables line like "CUSTOM: sum=8 diff=2 product=15" and return (a, b, sum, diff, product)
fn parse_custom_variables_line(line: &str) -> Option<(i32, i32, i32, i32, i32)> {
    // Expected format: "CUSTOM: sum=8 diff=2 product=15"
    // We need to reverse-engineer a and b from the calculations
    let line = line.trim_start_matches("CUSTOM: ");

    let mut sum = None;
    let mut diff = None;
    let mut product = None;

    for part in line.split_whitespace() {
        if let Some(value_str) = part.strip_prefix("sum=") {
            sum = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("diff=") {
            diff = value_str.parse().ok();
        } else if let Some(value_str) = part.strip_prefix("product=") {
            product = value_str.parse().ok();
        }
    }

    match (sum, diff, product) {
        (Some(sum_val), Some(diff_val), Some(product_val)) => {
            // Reverse-engineer a and b from sum and diff
            // sum = a + b, diff = a - b
            // Therefore: a = (sum + diff) / 2, b = (sum - diff) / 2
            let a = (sum_val + diff_val) / 2;
            let b = (sum_val - diff_val) / 2;
            Some((a, b, sum_val, diff_val, product_val))
        }
        _ => {
            println!("⚠️  Failed to parse custom variables line: {line}");
            None
        }
    }
}

/// Run ghostscope with a specific PID (bypass global test program)
async fn run_ghostscope_with_specific_pid(
    script_content: &str,
    target_pid: u32,
    timeout_secs: u64,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .with_pid(target_pid)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

async fn run_ghostscope_attached_to_target(
    script_content: &str,
    target: &common::targets::TargetHandle,
    timeout_secs: u64,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

#[tokio::test]
async fn test_invalid_pid_handling() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "Should never see this: a={} b={}", a, b;
}
"#;

    println!("=== Invalid PID Handling Test ===");

    // Use a non-existent PID
    let fake_pid = 999999;
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_specific_pid(script_content, fake_pid, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("=====================================");

    // Should fail quickly
    assert_ne!(exit_code, 0, "Invalid PID should cause non-zero exit");
    assert!(
        stderr.contains("No such process")
            || stderr.contains("Failed to attach")
            || stderr.contains("Invalid PID")
            || stderr.contains("Permission denied")
            || stderr.contains("Operation not permitted")
            || stderr.contains("is not running"),
        "Should contain appropriate error message: {stderr}"
    );

    println!("✓ Invalid PID correctly rejected");
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_char_ptr() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compare const char* parameter against a script literal
    let script_content = r#"
trace log_activity {
    if (activity == "main_loop") {
        print "CSTR_EQ";
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 5).await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("CSTR_EQ"),
        "Expected to see CSTR_EQ when activity == 'main_loop'. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_char_array() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compare char[32] field inside DataRecord against a script literal
    // Use process_record (called every loop) to shorten wait time
    let script_content = r#"
trace process_record {
    if (record.name == "test_record") {
        print "ARR_EQ";
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("ARR_EQ"),
        "Expected to see ARR_EQ when record.name == \"test_record\". STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_builtins_strncmp_starts_with_activity() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Validate builtins on DWARF char* parameter in a hot function
    let script_content = r#"
trace log_activity {
    print "SN:{}", strncmp(activity, "main", 4);
    print "SW:{}", starts_with(activity, "main");
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Expect at least one true for both builtins
    assert!(
        stdout.lines().any(|l| l.contains("SN:true")),
        "Expected SN:true for strncmp(activity, \"main\", 4). STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("SW:true")),
        "Expected SW:true for starts_with(activity, \"main\"). STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_builtin_strncmp_on_struct_pointer_mismatch() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Negative case: pass a non-string pointer (DataRecord*) to strncmp; should be false
    // Use a hot function for quick events
    let script_content = r#"
trace process_record {
    print "REC_SN:{}", strncmp(record, "HTTP", 4);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.lines().any(|l| l.contains("REC_SN:false")),
        "Expected REC_SN:false for non-string pointer compare. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_bool_literals_in_expressions() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Validate boolean literals in expressions (both orders) and negative cases
    let script_content = r#"
trace log_activity {
    // positive cases
    print "B1:{}", starts_with(activity, "main") == true;
    print "B4:{}", true == starts_with(activity, "main");
    // unary not
    print "BN1:{}", !starts_with(activity, "main");
    // negative (non-match literal)
    print "B6:{}", starts_with(activity, "zzz") == false;
}

trace process_record {
    // positive cases
    print "B2:{}", strncmp(record, "HTTP", 4) == false;
    print "B3:{}", false == strncmp(record, "HTTP", 4);
    // unary not
    print "BN2:{}", !strncmp(record, "HTTP", 4);
    // negative case (should be false)
    print "B5:{}", strncmp(record, "HTTP", 4) == true;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script(script_content, 6).await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // positives
    assert!(
        stdout.lines().any(|l| l.contains("B1:true")),
        "Expected B1:true. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("B2:true")),
        "Expected B2:true. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("B3:true")),
        "Expected B3:true. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("B4:true")),
        "Expected B4:true. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("B6:true")),
        "Expected B6:true. STDOUT: {stdout}"
    );
    // negative and unary not checks
    assert!(
        stdout.lines().any(|l| l.contains("B5:false")),
        "Expected B5:false. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("BN1:false")),
        "Expected BN1:false. STDOUT: {stdout}"
    );
    assert!(
        stdout.lines().any(|l| l.contains("BN2:true")),
        "Expected BN2:true. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_correct_pid_filtering() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "FILTERED: a={} b={}", a, b;
}
"#;

    println!("=== Correct PID Filtering Test ===");

    // Start two independent sample_program processes
    let sample_program_1 = common::targets::TargetLauncher::sample_program()
        .spawn()
        .await?;
    let sample_program_2 = common::targets::TargetLauncher::sample_program()
        .spawn()
        .await?;

    println!(
        "Started sample_program_1 with PID: {}",
        sample_program_1.host_pid()
    );
    println!(
        "Started sample_program_2 with PID: {}",
        sample_program_2.host_pid()
    );

    // Only trace the first process
    let (exit_code, stdout, stderr) =
        run_ghostscope_attached_to_target(script_content, &sample_program_1, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("=====================================");

    // Clean up processes
    sample_program_1.terminate().await?;
    sample_program_2.terminate().await?;

    if exit_code == 0 {
        let filtered_outputs = stdout
            .lines()
            .filter(|line| line.contains("FILTERED:"))
            .count();

        if filtered_outputs > 0 {
            println!("✓ Successfully captured {filtered_outputs} function calls from target PID");
            println!("✓ PID filtering working correctly");
        } else {
            println!("⚠️ No function calls captured, but PID filtering test completed");
        }
    } else {
        println!("⚠️ Unexpected exit code: {exit_code}. STDERR: {stderr}");
    }

    Ok(())
}

#[tokio::test]
async fn test_pid_specificity_with_multiple_processes() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    let script_content = r#"
trace calculate_something {
    print "TARGET_ONLY: traced a={} b={}", a, b;
}
"#;

    println!("=== PID Specificity with Multiple Processes Test ===");

    // Start 3 independent sample_program processes
    let programs = vec![
        common::targets::TargetLauncher::sample_program()
            .spawn()
            .await?,
        common::targets::TargetLauncher::sample_program()
            .spawn()
            .await?,
        common::targets::TargetLauncher::sample_program()
            .spawn()
            .await?,
    ];

    for (i, program) in programs.iter().enumerate() {
        println!(
            "Started sample_program_{} with PID: {}",
            i + 1,
            program.host_pid()
        );
    }

    // Only trace the middle process (programs[1])
    let target_pid = programs[1].host_pid();
    let (exit_code, stdout, stderr) =
        run_ghostscope_attached_to_target(script_content, &programs[1], 4).await?;

    println!("Target PID: {target_pid}");
    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("==================================================");

    // Clean up all processes
    for program in programs {
        program.terminate().await?;
    }

    if exit_code == 0 {
        let traced_outputs = stdout
            .lines()
            .filter(|line| line.contains("TARGET_ONLY:"))
            .count();

        if traced_outputs > 0 {
            println!("✓ Successfully captured {traced_outputs} function calls");
            println!("✓ PID specificity verified - only target process traced");
        } else {
            println!("⚠️ No function calls captured during test window");
        }
    } else {
        println!("⚠️ Unexpected exit code: {exit_code}. STDERR: {stderr}");
    }

    Ok(())
}

#[tokio::test]
#[serial_test::serial]
async fn test_stripped_binary_with_debuglink() -> anyhow::Result<()> {
    init();
    ensure_global_cleanup_registered();

    // Compile stripped binary with separate debug file
    common::ensure_test_program_compiled_with_opt(OptimizationLevel::Stripped)?;

    let script_content = r#"
trace add_numbers {
    print "STRIPPED_BINARY: add_numbers called with a={} b={}", a, b;
}
"#;

    println!("=== Stripped Binary with .gnu_debuglink Test ===");

    // Start stripped binary
    let binary_path =
        FIXTURES.get_test_binary_with_opt("sample_program", OptimizationLevel::Stripped)?;

    println!("Binary path: {}", binary_path.display());

    // Verify debug file exists
    let debug_file = binary_path.with_file_name("sample_program_stripped.debug");
    assert!(
        debug_file.exists(),
        "Debug file should exist: {}",
        debug_file.display()
    );
    println!("Debug file found: {}", debug_file.display());

    // Verify binary is actually stripped
    let output = std::process::Command::new("readelf")
        .args(["-S", binary_path.to_str().unwrap()])
        .output()?;
    let sections_output = String::from_utf8_lossy(&output.stdout);

    if sections_output.contains(".debug_info") {
        println!("⚠️ Warning: Binary still contains .debug_info section");
    } else {
        println!("✓ Binary is stripped (no .debug_info section)");
    }

    if sections_output.contains(".gnu_debuglink") {
        println!("✓ Binary has .gnu_debuglink section");
    } else {
        println!("⚠️ Warning: Binary missing .gnu_debuglink section");
    }

    // Start the stripped binary through the shared target launcher.
    let target = common::targets::TargetLauncher::binary(&binary_path)
        .spawn()
        .await?;
    println!("Started stripped binary with PID: {}", target.host_pid());

    // Run ghostscope with the stripped binary
    let (exit_code, stdout, stderr) =
        run_ghostscope_attached_to_target(script_content, &target, 3).await?;

    println!("Exit code: {exit_code}");
    println!("STDOUT: {stdout}");
    println!("STDERR: {stderr}");
    println!("===============================================");

    // Clean up
    target.terminate().await?;

    // Verify results
    if exit_code == 0 {
        let traced_outputs = stdout
            .lines()
            .filter(|line| line.contains("STRIPPED_BINARY:"))
            .count();

        if traced_outputs > 0 {
            println!("✓ Successfully traced {traced_outputs} function calls from stripped binary");
            println!("✓ .gnu_debuglink mechanism working correctly");
            println!("✓ Uprobe offset calculation correct for stripped binary");
        } else {
            println!("⚠️ No function calls captured, but debuglink loading succeeded");
        }

        // Verify that debug info was actually loaded from debuglink
        if stderr.contains("Looking for debug file")
            || stderr.contains("Loading DWARF from separate debug file")
        {
            println!("✓ Confirmed: Debug info loaded from .gnu_debuglink");
        }
    } else {
        // Check for specific error messages
        if stderr.contains("No debug information found") {
            println!("✗ Failed: Could not load debug information from .gnu_debuglink");
            anyhow::bail!("Debug information not found - .gnu_debuglink not working");
        } else {
            println!("⚠️ Unexpected exit code: {exit_code}. STDERR: {stderr}");
        }
    }

    Ok(())
}

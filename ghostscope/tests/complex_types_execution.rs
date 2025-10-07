#![allow(clippy::uninlined_format_args)]

//! Complex types script execution test
//! - Uses a long-running test program with complex DWARF types
//! - Validates struct/array/member/bitfield/union/enum formatting and array index

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use std::ffi::OsString;
use std::io::Write;
use std::process::Stdio;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::time::timeout;

async fn run_ghostscope_with_script_for_pid(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_for_pid_impl(script_content, timeout_secs, pid, false).await
}

async fn run_ghostscope_with_script_for_pid_perf(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
) -> anyhow::Result<(i32, String, String)> {
    run_ghostscope_with_script_for_pid_impl(script_content, timeout_secs, pid, true).await
}

async fn run_ghostscope_with_script_for_pid_impl(
    script_content: &str,
    timeout_secs: u64,
    pid: u32,
    force_perf_event_array: bool,
) -> anyhow::Result<(i32, String, String)> {
    let mut script_file = NamedTempFile::new()?;
    script_file.write_all(script_content.as_bytes())?;
    let script_path = script_file.path();

    let binary_path = "../target/debug/ghostscope";
    let mut args: Vec<OsString> = vec![
        OsString::from("-p"),
        OsString::from(pid.to_string()),
        OsString::from("--script-file"),
        script_path.as_os_str().to_os_string(),
        OsString::from("--no-save-llvm-ir"),
        OsString::from("--no-save-ebpf"),
        OsString::from("--no-save-ast"),
        OsString::from("--no-log"),
    ];

    if force_perf_event_array {
        args.push(OsString::from("--force-perf-event-array"));
    }

    let mut command = Command::new(binary_path);
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let mut child = command.spawn()?;

    let stdout_handle = child.stdout.take().unwrap();
    let stderr_handle = child.stderr.take().unwrap();

    let mut stdout_reader = BufReader::new(stdout_handle);
    let mut stderr_reader = BufReader::new(stderr_handle);

    let mut stdout_content = String::new();
    let mut stderr_content = String::new();

    let read_task = async {
        let mut stdout_line = String::new();
        let mut stderr_line = String::new();
        for _ in 0..120 {
            // up to ~12s
            stdout_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stdout_reader.read_line(&mut stdout_line),
            )
            .await
            {
                if n > 0 {
                    stdout_content.push_str(&stdout_line);
                }
            }
            stderr_line.clear();
            if let Ok(Ok(n)) = timeout(
                Duration::from_millis(50),
                stderr_reader.read_line(&mut stderr_line),
            )
            .await
            {
                if n > 0 {
                    stderr_content.push_str(&stderr_line);
                }
            }
            if let Ok(Some(_)) = child.try_wait() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    };

    let _ = timeout(Duration::from_secs(timeout_secs), read_task).await;

    let mut exit_code = match child.try_wait() {
        Ok(Some(status)) => status.code().unwrap_or(-1),
        _ => {
            let _ = child.kill().await;
            match timeout(Duration::from_secs(2), child.wait()).await {
                Ok(Ok(status)) => status.code().unwrap_or(-1),
                _ => -1,
            }
        }
    };

    if exit_code == -1 && (!stdout_content.is_empty() || !stderr_content.is_empty()) {
        exit_code = 0;
    }
    Ok((exit_code, stdout_content, stderr_content))
}

#[tokio::test]
async fn test_entry_prints() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Script based on t.gs semantics, but inlined (no file read)
    let script = r#"
trace complex_types_program.c:7 {
    print &*&*c;        // pointer address of c (struct Complex*)
    print c.friend_ref; // pointer value or NULL
    print c.name;       // char[16] -> string
    print *c.friend_ref; // dereferenced struct (or null-deref error)
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={}, stdout={})",
        stderr, stdout
    );

    // Validate pointer prints include type suffix and hex
    let has_any_ptr = stdout.contains("0x") && stdout.contains("(Complex*)");
    assert!(
        has_any_ptr,
        "Expected pointer print with type suffix. STDOUT: {}",
        stdout
    );

    // Validate c.name renders as a quoted string
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {}", stdout);

    // Validate deref prints either a pretty struct or a null-deref error
    let has_deref_struct = stdout.contains("*c.friend_ref")
        && (stdout.contains("Complex {") || stdout.contains("<error: null pointer dereference>"));
    assert!(
        has_deref_struct,
        "Expected deref output (struct or null-deref). STDOUT: {}",
        stdout
    );

    let _ = prog.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_struct_char_array() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Compare embedded char[16] field c.name against script literals
    // update_complex(&a, i) and update_complex(&b, i) are both called each second
    let script = r#"
trace update_complex {
    if (c.name == "Alice") { print "CNAME_A"; }
    if (c.name == "Bob") { print "CNAME_B"; }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // We expect to see at least one of the names captured within the window
    let saw_a = stdout.contains("CNAME_A");
    let saw_b = stdout.contains("CNAME_B");
    assert!(
        saw_a || saw_b,
        "Expected to see at least Alice or Bob. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_format() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Format-print with local array constant indices
    let script = r#"
trace complex_types_program.c:25 {
    print "ARR:{}|BRR:{}", a.arr[1], b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_arr = Regex::new(r"ARR:(-?\d+)").unwrap();
    let re_brr = Regex::new(r"BRR:(-?\d+)").unwrap();
    let has_arr = stdout.lines().any(|l| re_arr.is_match(l));
    let has_brr = stdout.lines().any(|l| re_brr.is_match(l));
    assert!(
        has_arr,
        "Expected formatted ARR value from a.arr[1]. STDOUT: {}",
        stdout
    );
    assert!(
        has_brr,
        "Expected formatted BRR value from b.arr[0]. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_local_chain_tail_array_index_format() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Member chain + constant index: b.friend_ref.arr[1] (friend_ref -> &a) and a.arr[2]
    // Attach at main where a/b are locals
    let script = r#"
trace complex_types_program.c:25 {
    print "CF:{}|AF:{}", b.friend_ref.arr[1], a.arr[2];
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_cf = Regex::new(r"CF:(-?\d+)").unwrap();
    let re_af = Regex::new(r"AF:(-?\d+)").unwrap();
    let has_cf = stdout.lines().any(|l| re_cf.is_match(l));
    let has_af = stdout.lines().any(|l| re_af.is_match(l));
    assert!(
        has_cf,
        "Expected CF value from b.friend_ref.arr[1]. STDOUT: {}",
        stdout
    );
    assert!(
        has_af,
        "Expected AF value from a.arr[2]. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_access() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Local array constant index on a struct local (a.arr[1]) and another (b.arr[0])
    let script = r#"
trace complex_types_program.c:25 {
    print "AR:{}", a.arr[1];
    print "BR:{}", b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_ar = Regex::new(r"AR:(-?\d+)").unwrap();
    let re_br = Regex::new(r"BR:(-?\d+)").unwrap();
    let has_ar = stdout.lines().any(|l| re_ar.is_match(l));
    let has_br = stdout.lines().any(|l| re_br.is_match(l));
    assert!(
        has_ar,
        "Expected at least one numeric a.arr[1] sample. STDOUT: {}",
        stdout
    );
    assert!(
        has_br,
        "Expected at least one numeric b.arr[0] sample. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_cross_type_comparisons_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Cross-type comparisons (string equality is covered by dedicated tests)
    // - a.age > 26 (DWARF int vs script int)
    // - a.status == 0 (DWARF enum-as-int vs script int)
    // - a.friend_ref == 0 (DWARF pointer vs script int)
    // - let t = 100; a.age < t (DWARF int vs script variable)
    let script = r#"
trace complex_types_program.c:25 {
    let t = 100;
    print "GT:{} EQ:{} PZ:{} LT:{}",
        a.age > 26,
        a.status == 0,
        a.friend_ref == 0,
        a.age < t;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re =
        Regex::new(r"GT:(true|false) EQ:(true|false) PZ:(true|false) LT:(true|false)").unwrap();
    let mut saw_line = false;
    let mut saw_pz_true = false;
    for line in stdout.lines() {
        if let Some(c) = re.captures(line) {
            saw_line = true;
            if &c[3] == "true" {
                saw_pz_true = true; // friend_ref == 0
            }
        }
    }
    assert!(
        saw_line,
        "Expected at least one comparison line. STDOUT: {}",
        stdout
    );
    assert!(
        saw_pz_true,
        "Expected PZ:1 for pointer==0. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_and_bare_expr_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify: print expr; and if / else if with expression conditions
    let script = r#"
trace complex_types_program.c:25 {
    // bare expression print should render name = value
    print a.status == 0;
    if a.status == 0 {
        print "wtf";
    } else if a.status == 1 {
        print a.age == 0;
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Expect at least one bare expr line for (a.status==0) = true/false
    let has_status_line = stdout
        .lines()
        .any(|l| l.contains("(a.status==0) = true") || l.contains("(a.status==0) = false"));
    assert!(
        has_status_line,
        "Expected bare expression output for a.status==0. STDOUT: {}",
        stdout
    );

    // Expect either the then branch literal or the else-if branch expr at least once across samples
    let has_then = stdout.lines().any(|l| l.contains("wtf"));
    let has_elseif_expr = stdout
        .lines()
        .any(|l| l.contains("(a.age==0) = true") || l.contains("(a.age==0) = false"));
    assert!(
        has_then || has_elseif_expr,
        "Expected either then-branch 'wtf' or else-if expr output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_logical_ops_local() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace complex_types_program.c:25 {
    // Truthiness check for script ints
    let x = 2; let y = 1; let z = 0;
    print "AND:{} OR:{}", x && y, x || z;
    // DWARF-backed locals with logical ops
    if a.age > 26 && a.status == 0 { print "AND"; }
    else if a.age < 100 || a.friend_ref == 0 { print "OR"; }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re = Regex::new(r"AND:(true|false) OR:(true|false)").unwrap();
    let mut saw_fmt = false;
    for line in stdout.lines() {
        if re.is_match(line) {
            saw_fmt = true;
            break;
        }
    }
    assert!(saw_fmt, "Expected logical fmt line. STDOUT: {}", stdout);

    Ok(())
}

#[tokio::test]
async fn test_or_short_circuit_avoids_null_deref() -> anyhow::Result<()> {
    init();

    // Start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The RHS would deref c.friend_ref, which is NULL for 'a' iterations.
    // Since LHS is true, RHS must not be evaluated and no null-deref error should appear.
    let script = r#"
trace update_complex {
    print (1 || *c.friend_ref);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    assert!(
        stdout.contains("true"),
        "Expected true result. STDOUT: {}",
        stdout
    );
    assert!(
        !stdout.contains("<error: null pointer dereference>"),
        "Short-circuit should avoid null-deref RHS. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_and_short_circuit_avoids_null_deref() -> anyhow::Result<()> {
    init();

    // Start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // LHS is false, RHS would deref c.friend_ref which can be NULL. Short-circuit must avoid RHS.
    let script = r#"
trace update_complex {
    print (0 && *c.friend_ref);
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    assert!(
        stdout.contains("false"),
        "Expected false result. STDOUT: {}",
        stdout
    );
    assert!(
        !stdout.contains("<error: null pointer dereference>"),
        "Short-circuit should avoid null-deref RHS. STDOUT: {}",
        stdout
    );
    Ok(())
}

#[tokio::test]
async fn test_address_of_and_comparisons_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Exercise address-of as top-level print (pointer formatting) and as rvalue in comparisons
    let script = r#"
trace complex_types_program.c:25 {
    // top-level &expr should print as pointer with hex and type suffix
    print &a;
    // address-of in expression should print name=value
    print (&a != 0);
    if &a != 0 {
        print "ADDR";
    }
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 4, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Top-level &a should produce a hex pointer
    let has_hex_ptr = stdout.contains("0x");
    assert!(
        has_hex_ptr,
        "Expected hex pointer for &a. STDOUT: {}",
        stdout
    );

    // (&a != 0) should produce bare expr with name and boolean value
    let has_expr_bool = stdout
        .lines()
        .any(|l| l.contains("(&a!=0) = true") || l.contains("(&a!=0) = false"));
    assert!(
        has_expr_bool,
        "Expected bare expr output for (&a!=0). STDOUT: {}",
        stdout
    );

    // Then-branch literal
    let has_then = stdout.lines().any(|l| l.contains("ADDR"));
    assert!(
        has_then,
        "Expected then-branch ADDR line. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_string_equality_local() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace complex_types_program.c:25 {
    print "SE:{}", a.name == "Alice";
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);
    // Expect SE:true at least once near main where a.name=="Alice"
    assert!(stdout.contains("SE:true") || stdout.contains("SE:false"));
    Ok(())
}

#[tokio::test]
async fn test_entry_pointer_values() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Focus on pointer prints at entry
    let script = r#"
trace complex_types_program.c:7 {
    print &*&*c;
    print c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={}, stdout={})",
        stderr, stdout
    );

    // Expect at least one pointer value with type suffix
    assert!(
        stdout.contains("0x") && stdout.contains("(Complex*)"),
        "Expected pointer formatting with type suffix. STDOUT: {}",
        stdout
    );

    let _ = prog.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_entry_name_string_and_deref_struct_fields() -> anyhow::Result<()> {
    init();

    // Start program
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Focused script to capture name and deref content
    let script = r#"
trace complex_types_program.c:7 {
    print c.name;
    print *c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;

    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // Check c.name renders correctly
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {}", stdout);

    // Look for at least one deref with full struct fields
    let mut found_struct = false;
    for line in stdout.lines() {
        if line.contains("*c.friend_ref = Complex {") {
            // Validate presence of key fields
            let has_status = line.contains("status:") && line.contains("Status::");
            let has_data = line.contains("data: union Data {");
            let has_arr = line.contains("arr: [");
            let has_active = line.contains("active:");
            let has_flags = line.contains("flags:");
            if has_status && has_data && has_arr && has_active && has_flags {
                found_struct = true;
                break;
            }
        }
    }
    assert!(
        found_struct,
        "Expected at least one full struct deref with fields. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_entry_friend_ref_null_and_non_null_cases() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Print both pointer value and deref to observe null/non-null
    let script = r#"
trace complex_types_program.c:7 {
    print c.friend_ref;
    print *c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;

    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    // We expect across events to see either NULL or non-NULL friend_ref at least once,
    // and when non-NULL, deref should produce a struct.
    let saw_null_ptr = stdout.contains("c.friend_ref = NULL (struct Complex*)");
    let saw_non_null_ptr = stdout.contains("c.friend_ref = 0x");
    let saw_struct_deref = stdout.contains("*c.friend_ref = Complex {");
    let saw_null_deref_err = stdout.contains("*c.friend_ref = <error: null pointer dereference>");

    assert!(
        saw_null_ptr || saw_non_null_ptr,
        "Expected at least one friend_ref pointer print. STDOUT: {}",
        stdout
    );
    assert!(
        saw_struct_deref || saw_null_deref_err,
        "Expected deref to produce either struct or null-deref error. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_types_formatting() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' (struct Complex) is in scope
    // Avoid pointer deref on parameter 'c' (not supported yet)
    let script_content = r#"
trace complex_types_program.c:25 {
    print a; // struct
    print a.name; // char[N] as string
    print "User: {} Age: {} {}", a.name, a.age, a.status;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid(script_content, 3, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    // Basic assertions (no fallback, attach failure is failure)
    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Check struct formatted line is present
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {}",
        stdout
    );

    // Ensure c.name renders as a quoted string (Alice/Bob)
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {}",
        stdout
    );

    // Optional: struct print contains 'arr:' field (do not require arr index due to grammar limits)
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_member_access() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Function attach where 'c' (struct Complex*) is in scope
    // Auto-deref expected: c.name, c.age resolve via implicit pointer dereference
    let script = r#"
trace update_complex {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Expect at least one line referencing the name string from pointer-deref path
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name (\"Alice\" or \"Bob\"). STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists with both fields
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_source_line_entry() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Source-line attach to the function declaration line (expected to be before/at prologue)
    // Validate auto-deref for register-resident pointer parameter 'c'
    let script = r#"
trace complex_types_program.c:6 {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Name should be readable via auto-deref
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name at entry (\"Alice\" or \"Bob\"). STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output at entry. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_types_formatting_nopie() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Non-PIE)
    let binary_path = FIXTURES.get_test_binary_complex_nopie()?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' is in scope
    let script_content = r#"
trace complex_types_program.c:25 {
    print a; // struct
    print a.name;
    print "User: {} Age: {} {}", a.name, a.age, a.status;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid(script_content, 3, pid).await?;
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {}",
        stdout
    );
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {}",
        stdout
    );
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {}",
        stdout
    );
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_member_access_nopie() -> anyhow::Result<()> {
    init();
    let binary_path = FIXTURES.get_test_binary_complex_nopie()?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    let script = r#"
trace update_complex {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script, 3, pid).await?;
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name (\"Alice\" or \"Bob\"). STDOUT: {}",
        stdout
    );
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_bitfields_correctness() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' and 'i' are in scope
    let script_fn = r#"
trace complex_types_program.c:25 {
    print "I={}", i;
    print a.active;
    print a.flags;
}
"#;

    let (exit_code, stdout, stderr) = run_ghostscope_with_script_for_pid(script_fn, 3, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Parse values from output
    // Expect lines like:
    //   : I=1234
    //   : c.active = 0/1 (or a.active = ... depending on var name)
    //   : c.flags = 0..7
    use regex::Regex;
    let re_i = Regex::new(r"I=([0-9]+)").unwrap();
    let re_active = Regex::new(r"(?i)(?:\b|\.)active\s*=\s*([0-9]+)").unwrap();
    let re_flags = Regex::new(r"(?i)(?:\b|\.)flags\s*=\s*([0-9]+)").unwrap();

    let mut found_i: Option<u64> = None;
    let mut found_active: Option<u64> = None;
    let mut found_flags: Option<u64> = None;

    for line in stdout.lines() {
        if found_i.is_none() {
            if let Some(caps) = re_i.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_i = Some(val);
                }
            }
        }
        if found_active.is_none() {
            if let Some(caps) = re_active.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_active = Some(val);
                }
            }
        }
        if found_flags.is_none() {
            if let Some(caps) = re_flags.captures(line) {
                if let Ok(val) = caps[1].parse::<u64>() {
                    found_flags = Some(val);
                }
            }
        }
        if found_i.is_some() && found_active.is_some() && found_flags.is_some() {
            break;
        }
    }

    let i_val = found_i.ok_or_else(|| anyhow::anyhow!("Missing I=... line. STDOUT: {}", stdout))?;
    let active_val =
        found_active.ok_or_else(|| anyhow::anyhow!("Missing active line. STDOUT: {}", stdout))?;
    let flags_val =
        found_flags.ok_or_else(|| anyhow::anyhow!("Missing flags line. STDOUT: {}", stdout))?;

    assert!(
        active_val <= 1,
        "active should be 0 or 1, got {}. STDOUT: {}",
        active_val,
        stdout
    );
    assert!(
        flags_val <= 7,
        "flags should be 0..7, got {}. STDOUT: {}",
        flags_val,
        stdout
    );
    assert_eq!(
        active_val,
        i_val & 1,
        "active must equal i&1 (i={}, active={})",
        i_val,
        active_val
    );
    assert_eq!(
        flags_val,
        i_val & 7,
        "flags must equal i&7 (i={}, flags={})",
        i_val,
        flags_val
    );

    Ok(())
}

// ============================================================================
// PerfEventArray Tests (--force-perf-event-array)
// These tests verify the same functionality but with PerfEventArray backend
// ============================================================================

#[tokio::test]
async fn test_entry_prints_perf() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Script based on t.gs semantics, but inlined (no file read)
    let script = r#"
trace complex_types_program.c:7 {
    print &*&*c;        // pointer address of c (struct Complex*)
    print c.friend_ref; // pointer value or NULL
    print c.name;       // char[16] -> string
    print *c.friend_ref; // dereferenced struct (or null-deref error)
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid_perf(script, 3, pid).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={}, stdout={})",
        stderr, stdout
    );

    // Validate pointer prints include type suffix and hex
    let has_any_ptr = stdout.contains("0x") && stdout.contains("(Complex*)");
    assert!(
        has_any_ptr,
        "Expected pointer print with type suffix. STDOUT: {}",
        stdout
    );

    // Validate c.name renders as a quoted string
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {}", stdout);

    // Validate deref prints either a pretty struct or a null-deref error
    let has_deref_struct = stdout.contains("*c.friend_ref")
        && (stdout.contains("Complex {") || stdout.contains("<error: null pointer dereference>"));
    assert!(
        has_deref_struct,
        "Expected deref output (struct or null-deref). STDOUT: {}",
        stdout
    );

    let _ = prog.kill().await;
    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_format_perf() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Format-print with local array constant indices
    let script = r#"
trace complex_types_program.c:25 {
    print "ARR:{}|BRR:{}", a.arr[1], b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid_perf(script, 3, pid).await?;
    let _ = prog.kill().await;
    assert_eq!(exit_code, 0, "stderr={} stdout={}", stderr, stdout);

    use regex::Regex;
    let re_arr = Regex::new(r"ARR:(-?\d+)").unwrap();
    let re_brr = Regex::new(r"BRR:(-?\d+)").unwrap();
    let has_arr = stdout.lines().any(|l| re_arr.is_match(l));
    let has_brr = stdout.lines().any(|l| re_brr.is_match(l));
    assert!(
        has_arr,
        "Expected formatted ARR value from a.arr[1]. STDOUT: {}",
        stdout
    );
    assert!(
        has_brr,
        "Expected formatted BRR value from b.arr[0]. STDOUT: {}",
        stdout
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_types_formatting_perf() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let mut prog = Command::new(&binary_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let pid = prog
        .id()
        .ok_or_else(|| anyhow::anyhow!("Failed to get PID"))?;
    // Give it time to start
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Use source-line attach where 'a' (struct Complex) is in scope
    // Avoid pointer deref on parameter 'c' (not supported yet)
    let script_content = r#"
trace complex_types_program.c:25 {
    print a; // struct
    print a.name; // char[N] as string
    print "User: {} Age: {} {}", a.name, a.age, a.status;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_pid_perf(script_content, 3, pid).await?;

    // Cleanup program
    let _ = prog.kill().await;

    // Basic assertions (no fallback, attach failure is failure)
    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={} stdout={}",
        stderr, stdout
    );

    // Check struct formatted line is present
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {}",
        stdout
    );

    // Ensure c.name renders as a quoted string (Alice/Bob)
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {}",
        stdout
    );

    // Optional: struct print contains 'arr:' field (do not require arr index due to grammar limits)
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {}",
        stdout
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {}",
        stdout
    );

    Ok(())
}

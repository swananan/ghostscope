//! Complex types script execution test
//! - Uses a long-running test program with complex DWARF types
//! - Validates struct/array/member/bitfield/union/enum formatting and array index

mod common;

use common::{init, OptimizationLevel, FIXTURES};
use std::path::Path;
use std::time::Duration;

async fn run_ghostscope_with_script_for_target(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

async fn run_ghostscope_with_script_for_target_perf(
    script_content: &str,
    timeout_secs: u64,
    target: &common::targets::TargetHandle,
) -> anyhow::Result<(i32, String, String)> {
    common::runner::GhostscopeRunner::new()
        .with_script(script_content)
        .attach_to(target)
        .timeout_secs(timeout_secs)
        .force_perf_event_array(true)
        .enable_sysmon_for_target(false)
        .run()
        .await
}

async fn spawn_complex_types_binary(
    binary_path: &Path,
) -> anyhow::Result<common::targets::TargetHandle> {
    let target = common::targets::TargetLauncher::binary(binary_path)
        .spawn()
        .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    Ok(target)
}

#[tokio::test]
async fn test_memcmp_int_array_decay_to_pointer() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Use DWARF int arr[8] directly as a pointer via decay semantics
    let script = r#"
trace update_complex {
    if memcmp(c.arr, c.arr, 16) { print "ARR_EQ"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 2, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("ARR_EQ"),
        "Expected ARR_EQ. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_cast_pointer_members_array_and_scalar() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace complex_types_program.c:15 {
    let idx = i - (i / 8) * 8;
    print cast(c, "struct Complex");
    print *cast(c, "struct Complex *");
    print "CAST_PTR I={} AGE={} DATA={} ARR={} U8={}",
        i,
        cast(c, "struct Complex *").age,
        cast(c, "struct Complex *").data.i,
        cast(c, "struct Complex *").arr[idx],
        cast(i, "u8");
    if (*cast(c, "struct Complex *")).data.i == i { print "CAST_DEREF_OK"; }
    if cast(c, "struct Complex *").data.i == i { print "CAST_DATA_OK"; }
    if cast(c, "struct Complex *").arr[idx] == i * 2 { print "CAST_ARR_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("arr: [") && stdout.contains("friend_ref:"),
        "Expected aggregate cast to render struct fields. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CAST_DATA_OK"),
        "Expected pointer cast member access to match i. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CAST_DEREF_OK"),
        "Expected pointer deref cast member access to match i. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CAST_ARR_OK"),
        "Expected pointer cast array access to scale by element size. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CAST_PTR I=") && stdout.contains(" U8="),
        "Expected formatted scalar cast output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_o3_pointer_members_after_volatile_path() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::O3)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace complex_types_program.c:15 {
    print "O3_COMPLEX I={} AGE={} DATA={} ACTIVE={} FLAGS={}", i, c.age, c.data.i, c.active, c.flags;
    print "O3_COMPLEX_ARITH AGE1={} DATA2={} FLAGS1={}", c.age - 0x1, c.data.i + 0b10, c.flags + -0x1;
    print "O3_COMPLEX_DIV AGE={} DATA={} FLAGS={}", c.age / 0x3, c.data.i / 0x2, c.flags / 0x2;
    print "O3_FRIEND_MEMBERS AGE={} DATA={} FLAGS={}", c.friend_ref.age, c.friend_ref.data.i, c.friend_ref.flags;
    print "O3_FRIEND_DIV AGE={} DATA={} FLAGS={}", c.friend_ref.age / 0x5, c.friend_ref.data.i / (i + 0x1), c.friend_ref.flags / -0x2;
    let dyn_idx = i - (i / 0x8) * 0x8;
    let dyn_zero = i - i;
    let c_dyn = c + dyn_zero;
    print "O3_DYNAMIC_ARR IDX={} VAL={}", dyn_idx, c.arr[dyn_idx];
    print "O3_DYNAMIC_ARR_DIV:{}", c.arr[dyn_idx] / 0x2;
    print "O3_DYNAMIC_ARR_PTR={:p}", &c.arr[dyn_idx];
    print "O3_DYNAMIC_ARR_ADDR_DEFAULT:{}", &c.arr[dyn_idx];
    print "O3_C_DYN AGE={} DATA={} FLAGS={} ARR={}", c_dyn.age, c_dyn.data.i, c_dyn.flags, c_dyn.arr[dyn_idx];
    print "O3_C_DYN_ARR_PTR={:p}", &c_dyn.arr[dyn_idx];
    print "O3_C_DYN_FRIEND DATA={} FLAGS={}", c_dyn.friend_ref.data.i, c_dyn.friend_ref.flags;
    print "O3_FRIEND_DYNAMIC_ARR IDX={} VAL={}", dyn_idx, c.friend_ref.arr[dyn_idx];
    print "O3_FRIEND_DYNAMIC_ARR_PTR={:p}", &c.friend_ref.arr[dyn_idx];
    print "O3_FRIEND_DYNAMIC_ARR_HEX={:x.0x4}", &c.friend_ref.arr[dyn_idx];
    print "O3_NAME={:s.5}", &c.name[0];
    print "O3_FRIEND={:p}", c.friend_ref;
    if c.flags < 0 { print "O3_FLAGS_NEG"; }
    if c.flags == -0x4 { print "O3_FLAGS_EQ_NEG4"; }
    if c.flags / 0x2 == -0x2 { print "O3_FLAGS_DIV_NEG2"; }
    if c.data.i / 0x2 >= 0 { print "O3_DATA_DIV_NONNEG"; }
    if c.friend_ref.data.i == i { print "O3_FRIEND_DATA_EQ_I"; }
    if c.friend_ref.flags / -0x2 >= -0x1 { print "O3_FRIEND_FLAGS_DIV_RANGE"; }
    if c.arr[dyn_idx] / 0x2 == i { print "O3_DYNAMIC_ARR_DIV_OK"; }
    if c_dyn.data.i == i { print "O3_C_DYN_DATA_EQ_I"; }
    if c_dyn.arr[dyn_idx] / 0x2 == i { print "O3_C_DYN_ARR_OK"; }
    if c_dyn.friend_ref.data.i == i { print "O3_C_DYN_FRIEND_DATA_EQ_I"; }
    if c.friend_ref.arr[dyn_idx] / 0x2 == i { print "O3_FRIEND_DYNAMIC_ARR_OK"; }
    if memcmp(&c.friend_ref.arr[dyn_idx], &c.arr[dyn_idx], 0x4) { print "O3_FRIEND_DYNAMIC_ARR_MEM_OK"; }
    if c.active == 1 { print "O3_ACTIVE_ONE"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re = Regex::new(
        r"O3_COMPLEX I=([0-9]+)\s+AGE=([0-9]+)\s+DATA=(-?[0-9]+)\s+ACTIVE=([0-9]+)\s+FLAGS=(-?[0-9]+)",
    )
    .unwrap();
    let samples: Vec<(u64, u64, i64, u64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<u64>().ok()?,
                caps.get(2)?.as_str().parse::<u64>().ok()?,
                caps.get(3)?.as_str().parse::<i64>().ok()?,
                caps.get(4)?.as_str().parse::<u64>().ok()?,
                caps.get(5)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !samples.is_empty(),
        "Missing O3 complex member samples. STDOUT: {stdout}"
    );

    let saw_consistent_sample =
        samples
            .iter()
            .any(|&(i_val, _age_val, data_val, active_val, flags_val)| {
                let raw3 = (i_val & 7) as i64;
                let expected_flags = if raw3 >= 4 { raw3 - 8 } else { raw3 };
                data_val == i_val as i64 && active_val == (i_val & 1) && flags_val == expected_flags
            });
    assert!(
        saw_consistent_sample,
        "Expected a consistent O3 bitfield/data sample. Samples={samples:?} STDOUT: {stdout}"
    );
    let arith_re =
        Regex::new(r"O3_COMPLEX_ARITH AGE1=(-?[0-9]+)\s+DATA2=(-?[0-9]+)\s+FLAGS1=(-?[0-9]+)")
            .unwrap();
    let arith_samples: Vec<(i64, i64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = arith_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<i64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
                caps.get(3)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !arith_samples.is_empty(),
        "Missing O3 complex arithmetic samples. STDOUT: {stdout}"
    );
    let saw_consistent_arithmetic = samples.iter().zip(arith_samples.iter()).any(
        |(
            &(_i_val, age_val, data_val, _active_val, flags_val),
            &(age_minus, data_plus, flags_minus),
        )| {
            age_minus == age_val as i64 - 1
                && data_plus == data_val + 2
                && flags_minus == flags_val - 1
        },
    );
    assert!(
        saw_consistent_arithmetic,
        "Expected O3 member arithmetic to match printed member values. Samples={samples:?} Arith={arith_samples:?} STDOUT: {stdout}"
    );
    let div_re =
        Regex::new(r"O3_COMPLEX_DIV AGE=(-?[0-9]+)\s+DATA=(-?[0-9]+)\s+FLAGS=(-?[0-9]+)").unwrap();
    let div_samples: Vec<(i64, i64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = div_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<i64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
                caps.get(3)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !div_samples.is_empty(),
        "Missing O3 complex division samples. STDOUT: {stdout}"
    );
    let saw_consistent_division = samples.iter().zip(div_samples.iter()).any(
        |(
            &(_i_val, age_val, data_val, _active_val, flags_val),
            &(age_div, data_div, flags_div),
        )| {
            age_div == age_val as i64 / 3 && data_div == data_val / 2 && flags_div == flags_val / 2
        },
    );
    assert!(
        saw_consistent_division,
        "Expected O3 member and bitfield division to match printed member values. Samples={samples:?} Div={div_samples:?} STDOUT: {stdout}"
    );
    let friend_re =
        Regex::new(r"O3_FRIEND_MEMBERS AGE=([0-9]+)\s+DATA=(-?[0-9]+)\s+FLAGS=(-?[0-9]+)").unwrap();
    let friend_samples: Vec<(u64, i64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = friend_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<u64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
                caps.get(3)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !friend_samples.is_empty(),
        "Missing O3 friend member samples. STDOUT: {stdout}"
    );
    let saw_consistent_friend = samples.iter().zip(friend_samples.iter()).any(
        |(
            &(i_val, _age_val, _data_val, _active_val, _flags_val),
            &(_friend_age, friend_data, friend_flags),
        )| {
            let raw3 = (i_val & 7) as i64;
            let expected_flags = if raw3 >= 4 { raw3 - 8 } else { raw3 };
            friend_data == i_val as i64 && friend_flags == expected_flags
        },
    );
    assert!(
        saw_consistent_friend,
        "Expected O3 friend member chain to match loop state. Samples={samples:?} Friend={friend_samples:?} STDOUT: {stdout}"
    );
    let friend_div_re =
        Regex::new(r"O3_FRIEND_DIV AGE=(-?[0-9]+)\s+DATA=(-?[0-9]+)\s+FLAGS=(-?[0-9]+)").unwrap();
    let friend_div_samples: Vec<(i64, i64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = friend_div_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<i64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
                caps.get(3)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !friend_div_samples.is_empty(),
        "Missing O3 friend division samples. STDOUT: {stdout}"
    );
    let saw_consistent_friend_division = samples
        .iter()
        .zip(friend_samples.iter())
        .zip(friend_div_samples.iter())
        .any(
            |(
                (
                    &(i_val, _age_val, _data_val, _active_val, _flags_val),
                    &(friend_age, friend_data, friend_flags),
                ),
                &(friend_age_div, friend_data_div, friend_flags_div),
            )| {
                friend_age_div == friend_age as i64 / 5
                    && friend_data_div == friend_data / (i_val as i64 + 1)
                    && friend_flags_div == friend_flags / -2
            },
        );
    assert!(
        saw_consistent_friend_division,
        "Expected O3 friend member division to match printed friend values. Samples={samples:?} Friend={friend_samples:?} FriendDiv={friend_div_samples:?} STDOUT: {stdout}"
    );
    let dynamic_arr_re = Regex::new(r"O3_DYNAMIC_ARR IDX=([0-9]+)\s+VAL=(-?[0-9]+)").unwrap();
    let dynamic_arr_samples: Vec<(u64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = dynamic_arr_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<u64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !dynamic_arr_samples.is_empty(),
        "Missing O3 dynamic array-index samples. STDOUT: {stdout}"
    );
    let dynamic_arr_div_re = Regex::new(r"O3_DYNAMIC_ARR_DIV:([0-9-]+)").unwrap();
    let dynamic_arr_div_samples: Vec<i64> = dynamic_arr_div_re
        .captures_iter(&stdout)
        .map(|caps| caps[1].parse::<i64>())
        .collect::<Result<Vec<_>, _>>()?;
    anyhow::ensure!(
        !dynamic_arr_div_samples.is_empty(),
        "Missing O3 dynamic array-index division samples. STDOUT: {stdout}"
    );
    let saw_consistent_dynamic_arr = samples
        .iter()
        .zip(dynamic_arr_samples.iter())
        .zip(dynamic_arr_div_samples.iter())
        .any(
            |(
                (&(i_val, _age_val, _data_val, _active_val, _flags_val), &(idx, arr_val)),
                &arr_div,
            )| {
                idx == (i_val & 7) && arr_val == (i_val as i64) * 2 && arr_div == i_val as i64
            },
        );
    assert!(
        saw_consistent_dynamic_arr,
        "Expected O3 dynamic array index to match loop state. Samples={samples:?} DynamicArr={dynamic_arr_samples:?} DynamicArrDiv={dynamic_arr_div_samples:?} STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_DYNAMIC_ARR_PTR=0x")
            && stdout.contains("O3_DYNAMIC_ARR_ADDR_DEFAULT:0x")
            && stdout.contains("O3_C_DYN_ARR_PTR=0x"),
        "Expected O3 dynamic member-array address prints. STDOUT: {stdout}"
    );
    let friend_dynamic_arr_re =
        Regex::new(r"O3_FRIEND_DYNAMIC_ARR IDX=([0-9]+)\s+VAL=(-?[0-9]+)").unwrap();
    let friend_dynamic_arr_samples: Vec<(u64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = friend_dynamic_arr_re.captures(line)?;
            Some((
                caps.get(1)?.as_str().parse::<u64>().ok()?,
                caps.get(2)?.as_str().parse::<i64>().ok()?,
            ))
        })
        .collect();
    anyhow::ensure!(
        !friend_dynamic_arr_samples.is_empty(),
        "Missing O3 nested friend dynamic array-index samples. STDOUT: {stdout}"
    );
    let saw_consistent_friend_dynamic_arr =
        samples.iter().zip(friend_dynamic_arr_samples.iter()).any(
            |(&(i_val, _age_val, _data_val, _active_val, _flags_val), &(idx, arr_val))| {
                idx == (i_val & 7) && arr_val == (i_val as i64) * 2
            },
        );
    assert!(
        saw_consistent_friend_dynamic_arr,
        "Expected O3 nested friend dynamic array index to match loop state. Samples={samples:?} FriendDynamicArr={friend_dynamic_arr_samples:?} STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_FRIEND_DYNAMIC_ARR_PTR=0x")
            && stdout.contains("O3_FRIEND_DYNAMIC_ARR_HEX="),
        "Expected O3 nested friend dynamic member-array address formats. STDOUT: {stdout}"
    );
    for marker in [
        "O3_FLAGS_NEG",
        "O3_FLAGS_EQ_NEG4",
        "O3_FLAGS_DIV_NEG2",
        "O3_DATA_DIV_NONNEG",
        "O3_FRIEND_DATA_EQ_I",
        "O3_FRIEND_FLAGS_DIV_RANGE",
        "O3_DYNAMIC_ARR_DIV_OK",
        "O3_C_DYN_DATA_EQ_I",
        "O3_C_DYN_ARR_OK",
        "O3_C_DYN_FRIEND_DATA_EQ_I",
        "O3_FRIEND_DYNAMIC_ARR_OK",
        "O3_FRIEND_DYNAMIC_ARR_MEM_OK",
        "O3_ACTIVE_ONE",
    ] {
        assert!(
            stdout.contains(marker),
            "Expected O3 bitfield comparison marker {marker}. STDOUT: {stdout}"
        );
    }
    assert!(
        stdout.contains("O3_NAME=Alice") || stdout.contains("O3_NAME=Bob"),
        "Expected optimized char array name formatting. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_FRIEND=0x"),
        "Expected optimized friend_ref pointer formatting. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_o3_memcmp_array_decay_and_base_lengths() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::O3)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace complex_types_program.c:15 {
    if memcmp(&c.name[0], &c.name[0], 0x3) { print "O3_NAME_SELF_EQ"; }
    if memcmp(c.arr, c.arr, 0b100) { print "O3_ARR_SELF_EQ"; }
    let n = 3;
    print "O3_NAME_HEX={:x.0x3}", &c.name[0];
    print "O3_NAME_ASCII={:s.n$}", &c.name[0];
    print "O3_ARR_HEX={:x.0x8}", c.arr;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("O3_NAME_SELF_EQ"),
        "Expected optimized self memcmp for c.name. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_ARR_SELF_EQ"),
        "Expected optimized array-decay memcmp for c.arr. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NAME_HEX=41 6c 69") || stdout.contains("O3_NAME_HEX=42 6f 62"),
        "Expected optimized base-prefixed hex name bytes. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("O3_NAME_ASCII=Ali") || stdout.contains("O3_NAME_ASCII=Bob"),
        "Expected optimized named-length ASCII formatting. STDOUT: {stdout}"
    );

    use regex::Regex;
    let re_arr_hex = Regex::new(r"O3_ARR_HEX=(?:[0-9a-f]{2}\s+){7}[0-9a-f]{2}").unwrap();
    assert!(
        stdout.lines().any(|line| re_arr_hex.is_match(line)),
        "Expected optimized array raw hex bytes. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_entry_prints() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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
        run_ghostscope_with_script_for_target(script, 3, &target).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={stderr}, stdout={stdout})"
    );

    // Validate pointer prints include type suffix and hex
    let has_any_ptr = stdout.contains("0x") && stdout.contains("(Complex*)");
    assert!(
        has_any_ptr,
        "Expected pointer print with type suffix. STDOUT: {stdout}"
    );

    // Validate c.name renders as a quoted string
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {stdout}");

    // Validate deref prints either a pretty struct or a null-deref error
    let has_deref_struct = stdout.contains("*c.friend_ref")
        && (stdout.contains("Complex {") || stdout.contains("<error: null pointer dereference>"));
    assert!(
        has_deref_struct,
        "Expected deref output (struct or null-deref). STDOUT: {stdout}"
    );

    target.terminate().await?;
    Ok(())
}

#[tokio::test]
async fn test_memcmp_struct_name_equal_and_diff() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Compare embedded char[16] field name: &c.name[0] vs itself / offset 1
    let script = r#"
trace update_complex {
    if memcmp(&c.name[0], &c.name[0], 5) { print "CNAME_EQ"; }
    if !memcmp(&c.name[0], &c.name[1], 5) { print "CNAME_NE"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("CNAME_EQ"),
        "Expected CNAME_EQ. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("CNAME_NE"),
        "Expected CNAME_NE. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_memcmp_dynamic_and_zero_negative_on_name() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace update_complex {
    // len=0 -> true
    if memcmp(&c.name[0], &c.name[1], 0) { print "Z0"; }
    // dynamic len from script var
    let n = 8;
    if memcmp(&c.name[0], &c.name[0], n) { print "DYN_OK"; }
    // negative clamps to 0 -> true
    let k = -3;
    if memcmp(&c.name[0], &c.name[1], k) { print "NEG_OK"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(stdout.contains("Z0"), "Expected Z0. STDOUT: {stdout}");
    assert!(
        stdout.contains("DYN_OK"),
        "Expected DYN_OK. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("NEG_OK"),
        "Expected NEG_OK. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_string_comparison_struct_char_array() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Compare embedded char[16] field c.name against script literals
    // update_complex(&a, i) and update_complex(&b, i) are both called each second
    let script = r#"
trace update_complex {
    if (c.name == "Alice") { print "CNAME_A"; }
    if (c.name == "Bob") { print "CNAME_B"; }
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // We expect to see at least one of the names captured within the window
    let saw_a = stdout.contains("CNAME_A");
    let saw_b = stdout.contains("CNAME_B");
    assert!(
        saw_a || saw_b,
        "Expected to see at least Alice or Bob. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_format() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Format-print with local array constant indices
    let script = r#"
trace complex_types_program.c:25 {
    print "ARR:{}|BRR:{}", a.arr[1], b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re_arr = Regex::new(r"ARR:(-?\d+)").unwrap();
    let re_brr = Regex::new(r"BRR:(-?\d+)").unwrap();
    let has_arr = stdout.lines().any(|l| re_arr.is_match(l));
    let has_brr = stdout.lines().any(|l| re_brr.is_match(l));
    assert!(
        has_arr,
        "Expected formatted ARR value from a.arr[1]. STDOUT: {stdout}"
    );
    assert!(
        has_brr,
        "Expected formatted BRR value from b.arr[0]. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_local_chain_tail_array_index_format() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Member chain + constant index: b.friend_ref.arr[1] (friend_ref -> &a) and a.arr[2]
    // Attach at main where a/b are locals
    let script = r#"
trace complex_types_program.c:25 {
    print "CF:{}|AF:{}", b.friend_ref.arr[1], a.arr[2];
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re_cf = Regex::new(r"CF:(-?\d+)").unwrap();
    let re_af = Regex::new(r"AF:(-?\d+)").unwrap();
    let has_cf = stdout.lines().any(|l| re_cf.is_match(l));
    let has_af = stdout.lines().any(|l| re_af.is_match(l));
    assert!(
        has_cf,
        "Expected CF value from b.friend_ref.arr[1]. STDOUT: {stdout}"
    );
    assert!(has_af, "Expected AF value from a.arr[2]. STDOUT: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_access() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Local array constant index on a struct local (a.arr[1]) and another (b.arr[0])
    let script = r#"
trace complex_types_program.c:25 {
    print "AR:{}", a.arr[1];
    print "BR:{}", b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re_ar = Regex::new(r"AR:(-?\d+)").unwrap();
    let re_br = Regex::new(r"BR:(-?\d+)").unwrap();
    let has_ar = stdout.lines().any(|l| re_ar.is_match(l));
    let has_br = stdout.lines().any(|l| re_br.is_match(l));
    assert!(
        has_ar,
        "Expected at least one numeric a.arr[1] sample. STDOUT: {stdout}"
    );
    assert!(
        has_br,
        "Expected at least one numeric b.arr[0] sample. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_cross_type_comparisons_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

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
        "Expected at least one comparison line. STDOUT: {stdout}"
    );
    assert!(
        saw_pz_true,
        "Expected PZ:1 for pointer==0. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_special_vars_pid_tid_timestamp_complex() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;
    let host_pid = target.host_pid();
    let input_pid =
        target.visible_pid_from(&common::sandbox::SandboxHandle::default_ghostscope()?)?;

    let script = format!(
        "trace complex_types_program.c:25 {{\n    print \"PID={} HOST_PID={} INPUT_PID={} TID={} TS={}\", $pid, $host_pid, $input_pid, $tid, $timestamp;\n    if $host_pid == {} {{ print \"HOST_PID_OK\"; }}\n    if $input_pid == {} {{ print \"INPUT_PID_OK\"; }}\n}}\n",
        "{}", "{}", "{}", "{}", "{}", host_pid, input_pid
    );

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.contains("HOST_PID_OK"),
        "Expected HOST_PID_OK. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("INPUT_PID_OK"),
        "Expected INPUT_PID_OK. STDOUT: {stdout}"
    );
    assert!(
        stdout.contains("PID=") || stdout.contains("PID:"),
        "Expected PID field in output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_and_bare_expr_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Expect at least one bare expr line for (a.status==0) = true/false
    let has_status_line = stdout
        .lines()
        .any(|l| l.contains("(a.status==0) = true") || l.contains("(a.status==0) = false"));
    assert!(
        has_status_line,
        "Expected bare expression output for a.status==0. STDOUT: {stdout}"
    );

    // Expect either the then branch literal or the else-if branch expr at least once across samples
    let has_then = stdout.lines().any(|l| l.contains("wtf"));
    let has_elseif_expr = stdout
        .lines()
        .any(|l| l.contains("(a.age==0) = true") || l.contains("(a.age==0) = false"));
    assert!(
        has_then || has_elseif_expr,
        "Expected either then-branch 'wtf' or else-if expr output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_if_else_if_logical_ops_local() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re = Regex::new(r"AND:(true|false) OR:(true|false)").unwrap();
    let mut saw_fmt = false;
    for line in stdout.lines() {
        if re.is_match(line) {
            saw_fmt = true;
            break;
        }
    }
    assert!(saw_fmt, "Expected logical fmt line. STDOUT: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_or_short_circuit_avoids_null_deref() -> anyhow::Result<()> {
    init();

    // Start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // The RHS would deref c.friend_ref, which is NULL for 'a' iterations.
    // Since LHS is true, RHS must not be evaluated and no null-deref error should appear.
    let script = r#"
trace update_complex {
    print (1 || *c.friend_ref);
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("true"),
        "Expected true result. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("<error: null pointer dereference>"),
        "Short-circuit should avoid null-deref RHS. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_and_short_circuit_avoids_null_deref() -> anyhow::Result<()> {
    init();

    // Start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // LHS is false, RHS would deref c.friend_ref which can be NULL. Short-circuit must avoid RHS.
    let script = r#"
trace update_complex {
    print (0 && *c.friend_ref);
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    assert!(
        stdout.contains("false"),
        "Expected false result. STDOUT: {stdout}"
    );
    assert!(
        !stdout.contains("<error: null pointer dereference>"),
        "Short-circuit should avoid null-deref RHS. STDOUT: {stdout}"
    );
    Ok(())
}

#[tokio::test]
async fn test_address_of_and_comparisons_local() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 4, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Top-level &a should produce a hex pointer
    let has_hex_ptr = stdout.contains("0x");
    assert!(has_hex_ptr, "Expected hex pointer for &a. STDOUT: {stdout}");

    // (&a != 0) should produce bare expr with name and boolean value
    let has_expr_bool = stdout
        .lines()
        .any(|l| l.contains("(&a!=0) = true") || l.contains("(&a!=0) = false"));
    assert!(
        has_expr_bool,
        "Expected bare expr output for (&a!=0). STDOUT: {stdout}"
    );

    // Then-branch literal
    let has_then = stdout.lines().any(|l| l.contains("ADDR"));
    assert!(has_then, "Expected then-branch ADDR line. STDOUT: {stdout}");

    Ok(())
}

#[tokio::test]
async fn test_string_equality_local() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace complex_types_program.c:25 {
    print "SE:{}", a.name == "Alice";
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
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
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Focus on pointer prints at entry
    let script = r#"
trace complex_types_program.c:7 {
    print &*&*c;
    print c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={stderr}, stdout={stdout})"
    );

    // Expect at least one pointer value with type suffix
    assert!(
        stdout.contains("0x") && stdout.contains("(Complex*)"),
        "Expected pointer formatting with type suffix. STDOUT: {stdout}"
    );

    target.terminate().await?;
    Ok(())
}

#[tokio::test]
async fn test_entry_name_string_and_deref_struct_fields() -> anyhow::Result<()> {
    init();

    // Start program
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Focused script to capture name and deref content
    let script = r#"
trace complex_types_program.c:7 {
    print c.name;
    print *c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;

    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // Check c.name renders correctly
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {stdout}");

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
        "Expected at least one full struct deref with fields. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_entry_friend_ref_null_and_non_null_cases() -> anyhow::Result<()> {
    init();

    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Print both pointer value and deref to observe null/non-null
    let script = r#"
trace complex_types_program.c:7 {
    print c.friend_ref;
    print *c.friend_ref;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;

    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    // We expect across events to see either NULL or non-NULL friend_ref at least once,
    // and when non-NULL, deref should produce a struct.
    let saw_null_ptr = stdout.contains("c.friend_ref = NULL (struct Complex*)");
    let saw_non_null_ptr = stdout.contains("c.friend_ref = 0x");
    let saw_struct_deref = stdout.contains("*c.friend_ref = Complex {");
    let saw_null_deref_err = stdout.contains("*c.friend_ref = <error: null pointer dereference>");

    assert!(
        saw_null_ptr || saw_non_null_ptr,
        "Expected at least one friend_ref pointer print. STDOUT: {stdout}"
    );
    assert!(
        saw_struct_deref || saw_null_deref_err,
        "Expected deref to produce either struct or null-deref error. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_trace_by_address_nopie_complex_types() -> anyhow::Result<()> {
    // End-to-end on Non-PIE binary: resolve DWARF PC for a known source line and attach by 0xADDR
    init();

    // 1) Build and start Non-PIE binary (ET_EXEC)
    let binary_path = FIXTURES.get_test_binary_complex_nopie()?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // 2) Resolve a module-relative address (DWARF PC) for a stable line in update_complex
    //    Choose 'c->age += 1;' which is consistently present near the top of the function.
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to load DWARF for Non-PIE test binary: {e}"))?;
    let addrs = analyzer.lookup_addresses_by_source_line("complex_types_program.c", 8);
    anyhow::ensure!(
        !addrs.is_empty(),
        "No DWARF addresses found for complex_types_program.c:8"
    );
    let pc = addrs[0].address;

    // 3) Build a script that attaches by address and prints a marker
    let script = format!("trace 0x{pc:x} {{\n    print \"NP_ADDR_OK\";\n}}\n");

    // 4) Run ghostscope in PID mode (-p). Default module resolves to the main executable.
    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(&script, 2, &target).await?;
    target.terminate().await?;

    // 5) Validate: we should see the marker at least once
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");
    assert!(
        stdout.lines().any(|l| l.contains("NP_ADDR_OK")),
        "Expected NP_ADDR_OK in output. STDOUT: {stdout}"
    );

    Ok(())
}
#[tokio::test]
async fn test_complex_types_formatting() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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
        run_ghostscope_with_script_for_target(script_content, 3, &target).await?;

    // Cleanup program
    target.terminate().await?;

    // Basic assertions (no fallback, attach failure is failure)
    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );

    // Check struct formatted line is present
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {stdout}"
    );

    // Ensure c.name renders as a quoted string (Alice/Bob)
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {stdout}"
    );

    // Optional: struct print contains 'arr:' field (do not require arr index due to grammar limits)
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {stdout}"
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_member_access() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Function attach where 'c' (struct Complex*) is in scope
    // Auto-deref expected: c.name, c.age resolve via implicit pointer dereference
    let script = r#"
trace update_complex {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;

    // Cleanup program
    target.terminate().await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );

    // Expect at least one line referencing the name string from pointer-deref path
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name (\"Alice\" or \"Bob\"). STDOUT: {stdout}"
    );

    // Ensure formatted print line exists with both fields
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_source_line_entry() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Source-line attach to the function declaration line (expected to be before/at prologue)
    // Validate auto-deref for register-resident pointer parameter 'c'
    let script = r#"
trace complex_types_program.c:6 {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;

    // Cleanup program
    target.terminate().await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );

    // Name should be readable via auto-deref
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name at entry (\"Alice\" or \"Bob\"). STDOUT: {stdout}"
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output at entry. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_types_formatting_nopie() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Non-PIE)
    let binary_path = FIXTURES.get_test_binary_complex_nopie()?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Use source-line attach where 'a' is in scope
    let script_content = r#"
trace complex_types_program.c:25 {
    print a; // struct
    print a.name;
    print "User: {} Age: {} {}", a.name, a.age, a.status;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script_content, 3, &target).await?;
    target.terminate().await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {stdout}"
    );
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {stdout}"
    );
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {stdout}"
    );
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_pointer_auto_deref_member_access_nopie() -> anyhow::Result<()> {
    init();
    let binary_path = FIXTURES.get_test_binary_complex_nopie()?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    let script = r#"
trace update_complex {
    print c.name;
    print "U:{} A:{}", c.name, c.age;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script, 3, &target).await?;
    target.terminate().await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name,
        "Expected dereferenced name (\"Alice\" or \"Bob\"). STDOUT: {stdout}"
    );
    let has_formatted = stdout.contains("U:") && stdout.contains("A:");
    assert!(
        has_formatted,
        "Expected formatted pointer-deref output. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_bitfields_correctness() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Use source-line attach on the executed line inside the friend_ref branch.
    // Attaching to the `if` condition line can observe multiple line-table rows
    // around the branch decision, which has been flaky in child-container e2e.
    // Line 15 still runs in the same frame after the bitfield writes, but only
    // on the stable, post-branch path for `b`.
    let script_fn = r#"
trace complex_types_program.c:15 {
    print "I={} ACTIVE={} FLAGS={}", i, c.active, c.flags;
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target(script_fn, 3, &target).await?;

    // Cleanup program
    target.terminate().await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );

    // Parse values from a single formatted line to avoid cross-event line pairing.
    // Expected line shape:
    //   : I=1234 ACTIVE=0 FLAGS=4
    use regex::Regex;
    let re_triplet = Regex::new(r"I=([0-9]+)\s+ACTIVE=([0-9]+)\s+FLAGS=(-?[0-9]+)").unwrap();
    let triplets: Vec<(u64, u64, i64)> = stdout
        .lines()
        .filter_map(|line| {
            let caps = re_triplet.captures(line)?;
            let i = caps.get(1)?.as_str().parse::<u64>().ok()?;
            let active = caps.get(2)?.as_str().parse::<u64>().ok()?;
            let flags = caps.get(3)?.as_str().parse::<i64>().ok()?;
            Some((i, active, flags))
        })
        .collect();
    anyhow::ensure!(
        !triplets.is_empty(),
        "Missing I/ACTIVE/FLAGS triplet. STDOUT: {stdout}"
    );

    for &(_, active_val, flags_val) in &triplets {
        assert!(
            active_val <= 1,
            "active should be 0 or 1, got {active_val}. STDOUT: {stdout}"
        );
        assert!(
            (-4..=3).contains(&flags_val),
            "flags should be in signed 3-bit range [-4,3], got {flags_val}. STDOUT: {stdout}"
        );
    }

    let saw_consistent_sample = triplets.iter().any(|&(i_val, active_val, flags_val)| {
        let raw3 = (i_val & 7) as i64;
        let expected_flags = if raw3 >= 4 { raw3 - 8 } else { raw3 };
        active_val == (i_val & 1) && flags_val == expected_flags
    });
    assert!(
        saw_consistent_sample,
        "Expected at least one consistent bitfield sample. Samples={triplets:?} STDOUT: {stdout}"
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
    let target = spawn_complex_types_binary(&binary_path).await?;

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
        run_ghostscope_with_script_for_target_perf(script, 3, &target).await?;

    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully (stderr={stderr}, stdout={stdout})"
    );

    // Validate pointer prints include type suffix and hex
    let has_any_ptr = stdout.contains("0x") && stdout.contains("(Complex*)");
    assert!(
        has_any_ptr,
        "Expected pointer print with type suffix. STDOUT: {stdout}"
    );

    // Validate c.name renders as a quoted string
    let has_name = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(has_name, "Expected c.name string. STDOUT: {stdout}");

    // Validate deref prints either a pretty struct or a null-deref error
    let has_deref_struct = stdout.contains("*c.friend_ref")
        && (stdout.contains("Complex {") || stdout.contains("<error: null pointer dereference>"));
    assert!(
        has_deref_struct,
        "Expected deref output (struct or null-deref). STDOUT: {stdout}"
    );

    target.terminate().await?;
    Ok(())
}

#[tokio::test]
async fn test_local_array_constant_index_format_perf() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

    // Format-print with local array constant indices
    let script = r#"
trace complex_types_program.c:25 {
    print "ARR:{}|BRR:{}", a.arr[1], b.arr[0];
}
"#;

    let (exit_code, stdout, stderr) =
        run_ghostscope_with_script_for_target_perf(script, 3, &target).await?;
    target.terminate().await?;
    assert_eq!(exit_code, 0, "stderr={stderr} stdout={stdout}");

    use regex::Regex;
    let re_arr = Regex::new(r"ARR:(-?\d+)").unwrap();
    let re_brr = Regex::new(r"BRR:(-?\d+)").unwrap();
    let has_arr = stdout.lines().any(|l| re_arr.is_match(l));
    let has_brr = stdout.lines().any(|l| re_brr.is_match(l));
    assert!(
        has_arr,
        "Expected formatted ARR value from a.arr[1]. STDOUT: {stdout}"
    );
    assert!(
        has_brr,
        "Expected formatted BRR value from b.arr[0]. STDOUT: {stdout}"
    );

    Ok(())
}

#[tokio::test]
async fn test_complex_types_formatting_perf() -> anyhow::Result<()> {
    init();

    // Build and start complex_types_program (Debug)
    let binary_path =
        FIXTURES.get_test_binary_with_opt("complex_types_program", OptimizationLevel::Debug)?;
    let target = spawn_complex_types_binary(&binary_path).await?;

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
        run_ghostscope_with_script_for_target_perf(script_content, 3, &target).await?;

    // Cleanup program
    target.terminate().await?;

    // Basic assertions (no fallback, attach failure is failure)
    assert_eq!(
        exit_code, 0,
        "ghostscope should run successfully. stderr={stderr} stdout={stdout}"
    );

    // Check struct formatted line is present
    let has_struct =
        stdout.contains("Complex {") && stdout.contains("name:") && stdout.contains("age:");
    assert!(
        has_struct,
        "Expected struct output with fields. STDOUT: {stdout}"
    );

    // Ensure c.name renders as a quoted string (Alice/Bob)
    let has_name_str = stdout.contains("\"Alice\"") || stdout.contains("\"Bob\"");
    assert!(
        has_name_str,
        "Expected name string output. STDOUT: {stdout}"
    );

    // Optional: struct print contains 'arr:' field (do not require arr index due to grammar limits)
    let has_arr_field = stdout.contains("arr:");
    assert!(
        has_arr_field,
        "Expected struct output contains arr field. STDOUT: {stdout}"
    );

    // Ensure formatted print line exists
    let has_formatted = stdout.contains("User:") && stdout.contains("Age:");
    assert!(
        has_formatted,
        "Expected formatted print output. STDOUT: {stdout}"
    );

    Ok(())
}

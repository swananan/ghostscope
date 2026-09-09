//! User-facing value diagnostic contracts, exercised through the real CLI.
//! Assert reasons, retained values, streams, and exit status. Do not snapshot
//! timestamps, ASLR addresses, decoration, or entire explanatory paragraphs.

mod common;

use std::path::{Path, PathBuf};

use common::{
    init,
    runner::GhostscopeRunner,
    rust_toolchain::{
        compile_standalone_fixture_with_codegen_options, fixture_tempdir, rustc_for_toolchain,
    },
    targets::{TargetHandle, TargetLauncher},
    FIXTURES,
};

const TOOLCHAIN: &str = "1.88.0";
const VALUES: &str = "rust_value_diagnostics_program/main.rs";
const FALLBACK: &str = "rust_adapter_rejection_program/sized/alloc.rs";
const UNSIZED: &str = "rust_adapter_rejection_program/alloc.rs";
const OFFLINE_HELP: &str = "ghostscope --value-diagnostics-help";

#[derive(Debug)]
struct CliOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

impl From<(i32, String, String)> for CliOutput {
    fn from((code, stdout, stderr): (i32, String, String)) -> Self {
        Self {
            code,
            stdout,
            stderr,
        }
    }
}

impl CliOutput {
    fn success(&self) {
        assert_eq!(self.code, 0, "{self:#?}");
        assert!(!self.stdout.contains("Display note"), "{self:#?}");
        for unexpected in ["<INVALID_", "<MISSING_ARG>", "ExprError"] {
            assert!(!self.stdout.contains(unexpected), "{self:#?}");
        }
    }

    fn compile_failure(&self, reason: &str) {
        assert_ne!(self.code, 0, "{self:#?}");
        assert!(self.stderr.contains("Failed targets:"), "{self:#?}");
        assert!(self.stderr.contains(reason), "{self:#?}");
        assert!(
            self.stdout.trim().is_empty(),
            "failed compilation emitted events: {self:#?}"
        );
        assert!(
            !self.stderr.contains("check your script syntax"),
            "misleading generic advice: {self:#?}"
        );
    }

    fn events(&self, tag: &str) -> Vec<&str> {
        let values = self
            .stdout
            .lines()
            .filter_map(|line| line.split_once(tag).map(|(_, value)| value))
            .collect::<Vec<_>>();
        assert!(!values.is_empty(), "missing {tag}: {self:#?}");
        assert!(
            !self.stderr.contains(tag),
            "event leaked to stderr: {self:#?}"
        );
        values
    }

    fn note(&self, path: &str, reason: &str) {
        assert!(
            self.stderr
                .lines()
                .any(|line| line.contains(&format!(": {path}"))
                    && line.contains(&format!("[{reason}]"))),
            "missing note for {path} [{reason}]: {self:#?}"
        );
        for expected in [
            "Type:",
            "Detail:",
            OFFLINE_HELP,
            &format!("docs/value-diagnostics.md#{reason}"),
        ] {
            assert!(
                self.stderr.contains(expected),
                "missing {expected}: {self:#?}"
            );
        }
    }
}

fn quiet_runner(script: &str, config: &str) -> GhostscopeRunner {
    GhostscopeRunner::new()
        .with_script(script)
        .with_config_content(config)
        .with_cli_args(["--no-log", "--no-status"])
        .timeout_secs(4)
        .enable_sysmon_for_target(false)
}

fn compile_fixture(source: &str, directory: &Path) -> anyhow::Result<PathBuf> {
    compile_fixture_with_options(source, directory, &["opt-level=0"])
}

fn compile_fixture_with_options(
    source: &str,
    directory: &Path,
    codegen_options: &[&str],
) -> anyhow::Result<PathBuf> {
    let rustc = rustc_for_toolchain(TOOLCHAIN)
        .ok_or_else(|| anyhow::anyhow!("required Rust toolchain {TOOLCHAIN} is not installed"))?;
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(source);
    let binary = directory.join("value_diagnostics_program");
    compile_standalone_fixture_with_codegen_options(
        &rustc,
        TOOLCHAIN,
        &source,
        &binary,
        codegen_options,
    )?;
    Ok(binary)
}

async fn capture(target: &TargetHandle, runner: GhostscopeRunner) -> anyhow::Result<CliOutput> {
    Ok(runner.attach_to(target).run().await?.into())
}

async fn run_fixture(source: &str, runner: GhostscopeRunner) -> anyhow::Result<CliOutput> {
    let directory = fixture_tempdir()?;
    let binary = compile_fixture(source, directory.path())?;
    let target = TargetLauncher::binary(&binary)
        .current_dir(directory.path())
        .spawn()
        .await?;
    let result = capture(&target, runner).await;
    target.terminate().await?;
    result
}

#[tokio::test]
async fn test_value_diagnostics_layout_fallback_is_visible_without_logging() -> anyhow::Result<()> {
    init();
    for mode in ["plain", "pretty"] {
        let output = run_fixture(
            FALLBACK,
            quiet_runner(
                r#"
trace observe_adapter_rejection {
    print "FALLBACK:{}", G_REJECTED_STRING;
    print "AGAIN:{}", G_REJECTED_STRING;
    print "PLAIN:{}", G_PLAIN;
}"#,
                "[value_adapters]\nmax_nesting_depth = 1\n",
            )
            .with_cli_args(["--script-output", mode]),
        )
        .await?;
        output.success();
        for tag in ["FALLBACK:", "AGAIN:"] {
            for value in output.events(tag) {
                assert!(
                    value.contains("raw: 42")
                        && value.contains("<internal fields: layout unsupported>"),
                    "{value}"
                );
                assert!(!value.contains("<unreadable:"), "{value}");
            }
        }
        for value in output.events("PLAIN:") {
            assert!(value.contains("number: 99"), "{value}");
            assert!(
                !value.contains("<internal fields:") && !value.contains("display limits"),
                "{value}"
            );
        }
        output.note("G_REJECTED_STRING", "layout-unsupported");
        assert_eq!(
            output
                .stderr
                .matches("Help: docs/value-diagnostics.md#layout-unsupported")
                .count(),
            1,
            "{output:#?}"
        );
        assert!(
            output
                .stderr
                .contains("expected `vec.buf[.inner].ptr` and `vec.len`"),
            "{output:#?}"
        );
        assert!(!output.stderr.contains("G_PLAIN"), "{output:#?}");
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_failed_fallback_is_a_compile_error() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        UNSIZED,
        quiet_runner(
            r#"trace observe_adapter_rejection { print "SHOULD_NOT_LOAD:{}", G_REJECTED_STRING; }"#,
            "",
        ),
    )
    .await?;
    output.compile_failure("Variable 'G_REJECTED_STRING' has no concrete DWARF size");
    for expected in [
        "ordinary DWARF fallback also failed",
        "adapter: String",
        "type: alloc::string::String",
        "rejected at: layout-validation",
        "expected `vec.buf[.inner].ptr` and `vec.len`",
        "target rustc: 1.88.0",
        "target DWARF:",
        "producer:",
        "docs/value-diagnostics.md#layout-unsupported",
        OFFLINE_HELP,
    ] {
        assert!(
            output.stderr.contains(expected),
            "missing {expected}: {output:#?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_read_plan_fallback_has_a_distinct_reason() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        FALLBACK,
        quiet_runner(
            r#"trace observe_adapter_rejection { print "PLAN:{}", G_NO_ELEMENT_TYPE; }"#,
            "",
        ),
    )
    .await?;
    output.success();
    output.note("G_NO_ELEMENT_TYPE", "read-plan-unsupported");
    for value in output.events("PLAN:") {
        assert!(
            value.contains("len: 7") && value.contains("<internal fields: read plan unsupported>"),
            "{value}"
        );
        assert!(
            !value.contains("layout unsupported") && !value.contains("<unreadable:"),
            "{value}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_read_failure_preserves_errno_and_siblings() -> anyhow::Result<()> {
    init();
    let read_error =
        regex::Regex::new(r"<unreadable: memory read failed; errno=-[0-9]+; address=0x1>")?;
    for perf in [false, true] {
        let output = run_fixture(
            FALLBACK,
            quiet_runner(
                r#"
trace observe_adapter_rejection {
    print "READ:{}", G_UNREADABLE;
    print "MIXED:{}", G_MIXED;
    print "DUMP:{:x.8}", cast(1, "u64 *");
    print "NULL:{}", *G_NULL;
    print "HEALTHY:{}", G_PLAIN;
}"#,
                "",
            )
            .force_perf_event_array(perf),
        )
        .await?;
        output.success();
        for tag in ["READ:", "MIXED:", "DUMP:"] {
            for value in output.events(tag) {
                assert!(read_error.is_match(value), "{value}");
                assert!(
                    !value.contains("<unavailable:")
                        && !value.contains("<internal fields:")
                        && !value.contains("<truncated:"),
                    "{value}"
                );
                if tag == "MIXED:" {
                    assert!(
                        value.contains("good: 73") && value.contains("bad:"),
                        "{value}"
                    );
                }
            }
        }
        for value in output.events("NULL:") {
            assert!(
                value.contains("<error: null pointer dereference>"),
                "{value}"
            );
            assert!(!value.contains("memory read failed"), "{value}");
        }
        assert!(
            output
                .events("HEALTHY:")
                .iter()
                .all(|value| value.contains("number: 99")),
            "{output:#?}"
        );
        assert!(!output.stderr.contains("Display note"), "{output:#?}");
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_optimized_out_print_and_expression_are_distinct(
) -> anyhow::Result<()> {
    init();
    // The existing compiler-specific fixture pins this source line and checks
    // its DWARF. Fail if the intended unavailable location stops being emitted.
    const LINE: u32 = 20;
    let binary = FIXTURES.get_test_binary("inline_call_value_program")?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let locations = analyzer.query_source_line_best_effort("inline_call_value_program.c", LINE)?;
    assert!(
        locations.iter().any(
            |location| location
                .variables
                .iter()
                .any(|variable| variable.name == "local_x"
                    && matches!(
                        variable.location,
                        ghostscope_dwarf::VariableLocation::OptimizedOut
                    ))
        ),
        "{locations:?}"
    );
    for (body, unavailable) in [
        (
            r#"print "OPT:{}", local_x; print "LIVE:{}", original_x;"#,
            true,
        ),
        (r#"if local_x == 0 { print "SHOULD_NOT_LOAD"; }"#, false),
    ] {
        let target = TargetLauncher::binary(&binary).spawn().await?;
        let script = format!("trace inline_call_value_program.c:{LINE} {{ {body} }}");
        let result = capture(&target, quiet_runner(&script, "")).await;
        target.terminate().await?;
        let output = result?;
        if unavailable {
            output.success();
            assert!(
                output
                    .events("OPT:")
                    .iter()
                    .all(|value| value.contains("<unavailable: optimized out>")),
                "{output:#?}"
            );
            assert!(
                output
                    .events("LIVE:")
                    .iter()
                    .all(|value| value.trim().parse::<i64>().is_ok()),
                "{output:#?}"
            );
            assert!(
                !output.stdout.contains("<unreadable:")
                    && !output.stdout.contains("<internal fields:"),
                "{output:#?}"
            );
        } else {
            output.compile_failure("optimized out at the selected probe PC");
            assert!(output.stderr.contains("local_x"), "{output:#?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_byte_limit_preserves_prefix_and_empty_value() -> anyhow::Result<()>
{
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"trace observe_diagnostics { print "BYTES:{}", G_TEXT; print "EMPTY:{}", G_EMPTY; }"#,
            "[ebpf]\nmem_dump_cap = 3\n",
        ),
    )
    .await?;
    output.success();
    assert!(
        output
            .events("BYTES:")
            .iter()
            .all(|value| *value == r#""alp" <truncated: byte limit>"#),
        "{output:#?}"
    );
    assert!(
        output
            .events("EMPTY:")
            .iter()
            .all(|value| *value == r#""""#),
        "{output:#?}"
    );
    assert!(
        !output.stdout.contains("<unreadable:") && !output.stderr.contains("Display note"),
        "{output:#?}"
    );
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_element_limit_preserves_prefix() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"trace observe_diagnostics { print "ELEMENTS:{}", G_ITEMS; }"#,
            "[value_adapters]\nmax_sequence_elements = 2\n",
        ),
    )
    .await?;
    output.success();
    for value in output.events("ELEMENTS:") {
        assert_eq!(value, r#"["alpha", "beta"] <truncated: element limit>"#);
        assert!(!value.contains("omega"), "{value}");
    }
    assert!(!output.stderr.contains("Display note"), "{output:#?}");
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_depth_limit_and_inactive_variant_are_static() -> anyhow::Result<()>
{
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"
trace observe_diagnostics {
    print "DEPTH:{}", G_NESTED;
    print "AGAIN_DEPTH:{}", G_NESTED;
    print "INACTIVE_VALUE:{}", G_INACTIVE;
}"#,
            "[value_adapters]\nmax_nesting_depth = 1\n",
        ),
    )
    .await?;
    output.success();
    output.note("G_NESTED[][]", "depth-limit");
    output.note("G_INACTIVE::Limited.__0.value", "depth-limit");
    assert_eq!(
        output
            .stderr
            .lines()
            .filter(|line| line.contains("G_NESTED[][]") && line.contains("[depth-limit]"))
            .count(),
        1,
        "{output:#?}"
    );
    for tag in ["DEPTH:", "INACTIVE_VALUE:"] {
        for value in output.events(tag) {
            assert!(
                value.contains("<nested display limits: depth limit; see trace details>"),
                "{value}"
            );
            assert!(
                !value.contains("<unreadable:") && !value.contains("<not expanded:"),
                "{value}"
            );
            if tag == "INACTIVE_VALUE:" {
                assert!(
                    value.contains("Empty")
                        && !value.contains("Limited(")
                        && !value.contains("<truncated:"),
                    "{value}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_notes_preserve_ordinary_reads() -> anyhow::Result<()> {
    init();
    let directory = fixture_tempdir()?;
    let binary = compile_fixture(VALUES, directory.path())?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let (_, read_plan) = analyzer
        .plan_global_access_read_plan(
            &binary,
            "G_WRAPPED",
            &ghostscope_dwarf::VariableAccessPath::default(),
        )?
        .expect("wrapped global read plan");
    let resolved = analyzer
        .resolved_type_for_plan(&read_plan)?
        .expect("wrapped global type");
    let options = ghostscope_dwarf::ValueReadPlanOptions {
        max_nesting_depth: 1,
    };
    let resolution =
        analyzer.resolve_value_read_plan_with_options(&resolved, Some(&binary), options)?;
    assert!(
        resolution.plan.is_none(),
        "notes must not select a semantic capture: {resolution:?}"
    );
    assert!(resolution
        .diagnostics
        .iter()
        .any(|note| note.reason == ghostscope_protocol::ValueDiagnosticReason::DepthLimit));
    assert!(analyzer
        .value_read_plan_with_options(&resolved, Some(&binary), options)?
        .is_none());

    let target = TargetLauncher::binary(&binary)
        .current_dir(directory.path())
        .spawn()
        .await?;
    let result = capture(
        &target,
        quiet_runner(
            r#"
trace observe_diagnostics {
    print "ROOT_VALUE:{}", G_WRAPPED;
    print "GOOD_VALUE:{}", *G_GOOD_WRAPPED;
    print "NULL_VALUE:{}", *G_NULL_WRAPPED;
    print "BAD_VALUE:{}", *G_BAD_WRAPPED;
}"#,
            "[value_adapters]\nmax_nesting_depth = 1\n",
        ),
    )
    .await;
    target.terminate().await?;
    let output = result?;
    output.success();
    for expression in [
        "G_WRAPPED",
        "*G_GOOD_WRAPPED",
        "*G_NULL_WRAPPED",
        "*G_BAD_WRAPPED",
    ] {
        output.note(expression, "depth-limit");
    }
    for tag in ["ROOT_VALUE:", "GOOD_VALUE:"] {
        for value in output.events(tag) {
            assert!(
                value.contains("91")
                    && value.contains("<nested display limits: depth limit; see trace details>"),
                "{value}"
            );
            assert!(
                !value.contains("<unreadable:") && !value.contains("<error:"),
                "{value}"
            );
        }
    }
    for value in output.events("NULL_VALUE:") {
        assert!(
            value.contains("<error: null pointer dereference>"),
            "{value}"
        );
        assert!(
            !value.contains("memory read failed") && !value.contains("depth limit"),
            "{value}"
        );
    }
    for value in output.events("BAD_VALUE:") {
        assert!(
            value.contains("<unreadable: memory read failed; errno=")
                && value.contains("address=0x1>"),
            "{value}"
        );
        assert!(
            !value.contains("null pointer") && !value.contains("depth limit"),
            "{value}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_register_arguments_retain_static_notes() -> anyhow::Result<()> {
    init();
    let directory = fixture_tempdir()?;
    let binary = compile_fixture_with_options(
        "rust_value_diagnostics_program/register.rs",
        directory.path(),
        &["opt-level=2"],
    )?;
    let analyzer = ghostscope_dwarf::DwarfAnalyzer::from_exec_path(&binary).await?;
    let mut found_register = false;
    for address in analyzer.lookup_function_addresses("observe_register") {
        let context = analyzer.resolve_pc(&address)?;
        if let Some(plan) = analyzer.plan_variable_by_name(&context, "value")? {
            let materialized =
                plan.materialization_plan(&ghostscope_dwarf::RuntimeCapabilities::default());
            if matches!(
                materialized.materialization,
                ghostscope_dwarf::VariableMaterialization::DirectValue {
                    value: ghostscope_dwarf::PlannedValue::RegisterValue { .. }
                }
            ) {
                found_register = true;
            }
        }
    }
    assert!(
        found_register,
        "fixture must retain a register-backed parameter at the probe PC"
    );
    let target = TargetLauncher::binary(&binary)
        .current_dir(directory.path())
        .spawn()
        .await?;
    let result = capture(
        &target,
        quiet_runner(
            r#"
trace observe_register {
    print "REGISTER_VALUE:{}", value;
    print "MEMORY_VALUE:{}", G_REGISTER_PEER;
}"#,
            "[value_adapters]\nmax_nesting_depth = 1\n",
        ),
    )
    .await;
    target.terminate().await?;
    let output = result?;
    output.success();
    output.note("value", "depth-limit");
    output.note("G_REGISTER_PEER", "depth-limit");
    for (tag, expected) in [("REGISTER_VALUE:", "41"), ("MEMORY_VALUE:", "73")] {
        for value in output.events(tag) {
            assert!(
                value.contains(expected)
                    && value.contains("<nested display limits: depth limit; see trace details>"),
                "{value}"
            );
            assert!(
                !value.contains("<unreadable:") && !value.contains("<unavailable:"),
                "{value}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_capture_budget_retains_root_fields() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"trace observe_diagnostics { print "BUDGET:{}", G_CELL; }"#,
            "[ebpf]\nmem_dump_cap = 24\n",
        ),
    )
    .await?;
    output.success();
    output.note("G_CELL", "capture-budget");
    for value in output.events("BUDGET:") {
        assert!(
            value.contains("<not expanded: capture budget>") && value.contains("len: 10"),
            "{value}"
        );
        assert!(
            !value.contains("<unreadable:") && !value.contains("<truncated:"),
            "{value}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_recursive_type_keeps_finite_tree_readable() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"trace observe_diagnostics { print "TREE:{}", G_TREE; }"#,
            r#"
[ebpf]
mem_dump_cap = 4096
[value_adapters]
max_nesting_depth = 8
max_sequence_elements = 1
"#,
        ),
    )
    .await?;
    output.success();
    output.note("G_TREE.children[]", "recursive-type");
    for value in output.events("TREE:") {
        assert!(
            value.contains(r#"label: "root""#)
                && value.contains("<nested display limits: recursive type; see trace details>"),
            "{value}"
        );
        assert!(
            !value.contains("<unreadable:") && !value.contains("depth limit"),
            "{value}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_event_limit_does_not_claim_a_read_failure() -> anyhow::Result<()> {
    init();
    let output = run_fixture(
        VALUES,
        quiet_runner(
            r#"trace observe_diagnostics { print "EVENT:{}:{}", G_CELL, G_CELL; }"#,
            "[ebpf]\nmem_dump_cap = 1024\nmax_trace_event_size = 256\n",
        ),
    )
    .await?;
    output.success();
    for value in output.events("EVENT:") {
        assert_eq!(
            value,
            "<truncated: capture limit>:<truncated: capture limit>"
        );
    }
    assert!(!output.stderr.contains("Display note"), "{output:#?}");
    Ok(())
}

#[tokio::test]
async fn test_value_diagnostics_offline_help_explains_public_reasons() -> anyhow::Result<()> {
    init();
    // The invalid configuration and PID must never reach runtime setup.
    let output: CliOutput = quiet_runner("invalid script", "[invalid TOML")
        .with_pid(u32::MAX)
        .with_cli_args(["--value-diagnostics-help"])
        .run()
        .await?
        .into();
    assert_eq!(output.code, 0, "{output:#?}");
    assert!(output.stderr.is_empty(), "{output:#?}");
    assert_eq!(
        output.stdout,
        include_str!("../../docs/value-diagnostics.md")
    );
    let chinese = include_str!("../../docs/zh/value-diagnostics.md");
    for reason in [
        "optimized-out",
        "memory-read-failed",
        "layout-unsupported",
        "read-plan-unsupported",
        "byte-limit",
        "element-limit",
        "capture-limit",
        "depth-limit",
        "recursive-type",
        "capture-budget",
    ] {
        for guide in [output.stdout.as_str(), chinese] {
            assert!(
                guide.lines().any(|line| line == format!("## {reason}")),
                "missing documented reason {reason}"
            );
        }
    }
    assert!(
        output.stdout.contains("--sleepable-uprobe")
            && output.stdout.contains("sleepable_uprobe = true")
    );
    Ok(())
}

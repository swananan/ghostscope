use ghostscope_ui::components::command_panel::script_editor::ScriptEditor;
use ghostscope_ui::events::{ExecutionStatus, ScriptCompilationDetails, ScriptExecutionResult};
use ghostscope_ui::ui::emoji::EmojiConfig;

#[test]
fn test_trace_results_success_color() {
    // Test that successful count is shown in green
    let emoji_config = EmojiConfig::new(true);

    let compilation_details = ScriptCompilationDetails {
        total_count: 1,
        success_count: 1,
        failed_count: 0,
        results: vec![ScriptExecutionResult {
            target_name: "test.c:10".to_string(),
            binary_path: "/path/to/binary".to_string(),
            pc_address: 0x1000,
            status: ExecutionStatus::Success,
            source_file: None,
            source_line: None,
            is_inline: None,
            value_diagnostics: Vec::new(),
        }],
        trace_ids: vec![0],
    };

    let result = ScriptEditor::format_compilation_results(
        &compilation_details,
        Some("trace test.c:10"),
        &emoji_config,
    );

    // Check that the result contains green ANSI code for "1 successful"
    assert!(
        result.contains("\x1b[32m1 successful\x1b[0m"),
        "Expected green color for successful count, got: {result}"
    );

    // Check that "0 failed" does not have red color
    assert!(
        !result.contains("\x1b[31m0 failed\x1b[0m"),
        "Should not have red color for 0 failed, got: {result}"
    );

    // "0 failed" should appear without color codes
    assert!(
        result.contains("0 failed"),
        "Expected '0 failed' without color, got: {result}"
    );
}

#[test]
fn test_trace_results_failed_color() {
    // Test that failed count is shown in red
    let emoji_config = EmojiConfig::new(true);

    let compilation_details = ScriptCompilationDetails {
        total_count: 1,
        success_count: 0,
        failed_count: 1,
        results: vec![ScriptExecutionResult {
            target_name: "test.c:10".to_string(),
            binary_path: "/path/to/binary".to_string(),
            pc_address: 0x0,
            status: ExecutionStatus::Failed("Error".to_string()),
            source_file: None,
            source_line: None,
            is_inline: None,
            value_diagnostics: Vec::new(),
        }],
        trace_ids: vec![],
    };

    let result = ScriptEditor::format_compilation_results(
        &compilation_details,
        Some("trace test.c:10"),
        &emoji_config,
    );

    // Check that the result contains red ANSI code for "1 failed"
    assert!(
        result.contains("\x1b[31m1 failed\x1b[0m"),
        "Expected red color for failed count, got: {result}"
    );

    // Check that "0 successful" does not have green color
    assert!(
        !result.contains("\x1b[32m0 successful\x1b[0m"),
        "Should not have green color for 0 successful, got: {result}"
    );

    // "0 successful" should appear without color codes
    assert!(
        result.contains("0 successful"),
        "Expected '0 successful' without color, got: {result}"
    );
}

#[test]
fn test_trace_results_mixed_colors() {
    // Test that both success and failed counts have their respective colors
    let emoji_config = EmojiConfig::new(true);

    let compilation_details = ScriptCompilationDetails {
        total_count: 3,
        success_count: 2,
        failed_count: 1,
        results: vec![
            ScriptExecutionResult {
                target_name: "test.c:10".to_string(),
                binary_path: "/path/to/binary".to_string(),
                pc_address: 0x1000,
                status: ExecutionStatus::Success,
                source_file: None,
                source_line: None,
                is_inline: None,
                value_diagnostics: Vec::new(),
            },
            ScriptExecutionResult {
                target_name: "test.c:20".to_string(),
                binary_path: "/path/to/binary".to_string(),
                pc_address: 0x2000,
                status: ExecutionStatus::Success,
                source_file: None,
                source_line: None,
                is_inline: None,
                value_diagnostics: Vec::new(),
            },
            ScriptExecutionResult {
                target_name: "test.c:30".to_string(),
                binary_path: "/path/to/binary".to_string(),
                pc_address: 0x0,
                status: ExecutionStatus::Failed("Error".to_string()),
                source_file: None,
                source_line: None,
                is_inline: None,
                value_diagnostics: Vec::new(),
            },
        ],
        trace_ids: vec![0, 1],
    };

    let result = ScriptEditor::format_compilation_results(
        &compilation_details,
        Some("trace multiple"),
        &emoji_config,
    );

    // Check that successful count has green color
    assert!(
        result.contains("\x1b[32m2 successful\x1b[0m"),
        "Expected green color for 2 successful, got: {result}"
    );

    // Check that failed count has red color
    assert!(
        result.contains("\x1b[31m1 failed\x1b[0m"),
        "Expected red color for 1 failed, got: {result}"
    );
}

#[test]
fn test_trace_results_preserve_multiline_failure_diagnostics() {
    let emoji_config = EmojiConfig::new(false);
    let error = concat!(
        "Variable 'value' has no concrete DWARF size\n\n",
        "Rust value adapter diagnostic:\n",
        "  adapter: String\n",
        "  rejected at: layout-validation",
    );
    let compilation_details = ScriptCompilationDetails {
        total_count: 1,
        success_count: 0,
        failed_count: 1,
        results: vec![ScriptExecutionResult {
            target_name: "observe_value".to_string(),
            binary_path: "/path/to/binary".to_string(),
            pc_address: 0x1000,
            status: ExecutionStatus::Failed(error.to_string()),
            source_file: None,
            source_line: None,
            is_inline: None,
            value_diagnostics: Vec::new(),
        }],
        trace_ids: vec![],
    };

    let result = ScriptEditor::format_compilation_results(
        &compilation_details,
        Some("trace observe_value"),
        &emoji_config,
    );

    assert!(
        result.contains(error),
        "multiline diagnostic was lost: {result}"
    );
}

#[test]
fn display_limits_remain_successful_and_are_visible_in_trace_details() {
    let note = ghostscope_protocol::ValueDiagnostic {
        path: "request.name".to_string(),
        type_name: "String".to_string(),
        reason: ghostscope_protocol::ValueDiagnosticReason::LayoutUnsupported,
        detail: "missing pointer and length".to_string(),
    };
    let details = ScriptCompilationDetails {
        trace_ids: vec![3],
        total_count: 1,
        success_count: 1,
        failed_count: 0,
        results: vec![ScriptExecutionResult {
            target_name: "handle_request".to_string(),
            binary_path: "/app".to_string(),
            pc_address: 0x1234,
            status: ExecutionStatus::Success,
            source_file: None,
            source_line: None,
            is_inline: None,
            value_diagnostics: vec![note.clone()],
        }],
    };
    let output = ScriptEditor::format_compilation_results(&details, None, &EmojiConfig::new(false));
    assert!(output.contains("1 successful"));
    assert!(output.contains("request.name: contents unavailable"));
    assert!(output.contains("docs/value-diagnostics.md#layout-unsupported"));
    let loaded = ghostscope_ui::events::TraceLoadDetail {
        target: "handle_request".to_string(),
        trace_id: Some(3),
        status: ghostscope_ui::events::LoadStatus::Created,
        error: None,
        value_diagnostics: vec![note.clone()],
    };
    assert!(loaded.value_diagnostic_messages()[0]
        .contains("trace #3 (handle_request): request.name: contents unavailable"));
    let batch = ghostscope_ui::components::command_panel::ResponseFormatter::format_batch_load_summary_styled(
        "traces.gs", 1, 1, 0, 0, &[loaded],
    )
    .iter()
    .map(|line| line.to_string())
    .collect::<Vec<_>>()
    .join("\n");
    assert!(batch.find("trace #3").unwrap() < batch.find("request.name").unwrap());
    let status = ghostscope_ui::events::RuntimeStatus::TraceInfo {
        trace_id: 3,
        target: "handle_request".to_string(),
        status: ghostscope_ui::events::TraceStatus::Active,
        pid: Some(1),
        host_pid: None,
        binary: "/app".to_string(),
        script_preview: None,
        pc: 0x1234,
        value_diagnostics: vec![note],
    };
    let plain = status.format_trace_info().unwrap();
    let styled = status
        .format_trace_info_styled()
        .unwrap()
        .iter()
        .map(|line| line.to_string())
        .collect::<Vec<_>>()
        .join("\n");
    for output in [plain, styled] {
        assert!(output.contains("request.name: contents unavailable"));
        assert!(output.contains("missing pointer and length"));
        assert!(output.contains("docs/value-diagnostics.md#layout-unsupported"));
    }
}

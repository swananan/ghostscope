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
            },
            ScriptExecutionResult {
                target_name: "test.c:20".to_string(),
                binary_path: "/path/to/binary".to_string(),
                pc_address: 0x2000,
                status: ExecutionStatus::Success,
            },
            ScriptExecutionResult {
                target_name: "test.c:30".to_string(),
                binary_path: "/path/to/binary".to_string(),
                pc_address: 0x0,
                status: ExecutionStatus::Failed("Error".to_string()),
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

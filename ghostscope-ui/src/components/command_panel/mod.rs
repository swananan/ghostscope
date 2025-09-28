pub mod command_parser;
pub mod file_completion;
pub mod history_manager;
pub mod input_handler;
pub mod optimized_input;
pub mod optimized_renderer;
pub mod response_formatter;
pub mod script_editor;
pub mod syntax_highlighter;
pub mod trace_persistence;

pub use command_parser::CommandParser;
pub use history_manager::{AutoSuggestionState, CommandHistory, HistorySearchState};
pub use input_handler::InputHandler;
pub use optimized_input::OptimizedInputHandler;
pub use optimized_renderer::OptimizedRenderer;
pub use response_formatter::ResponseFormatter;
pub use script_editor::ScriptEditor;
pub use syntax_highlighter::SyntaxHighlighter;

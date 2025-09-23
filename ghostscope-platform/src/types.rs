/// Basic error types for platform-specific operations
#[derive(Debug, Clone)]
pub enum PlatformError {
    /// Cannot determine prologue end - parameters may be optimized
    PrologueAnalysisFailed(String),
    /// Parameter optimization detected
    ParameterOptimized(String),
    /// Evaluation failed
    EvaluationFailed(String),
    /// Unsupported architecture
    UnsupportedArchitecture(String),
}

impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PlatformError::PrologueAnalysisFailed(msg) => {
                write!(f, "Prologue analysis failed: {msg}")
            }
            PlatformError::ParameterOptimized(msg) => write!(f, "Parameter optimized: {msg}"),
            PlatformError::EvaluationFailed(msg) => write!(f, "Evaluation failed: {msg}"),
            PlatformError::UnsupportedArchitecture(msg) => {
                write!(f, "Unsupported architecture: {msg}")
            }
        }
    }
}

impl std::error::Error for PlatformError {}

/// Source location information for debugging
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file_path: String,
    pub line_number: u32,
    pub column: Option<u32>,
}

/// Simplified context for code reading operations
pub trait CodeReader {
    /// Read code bytes from the specified address
    fn read_code_bytes(&self, address: u64, size: usize) -> Option<Vec<u8>>;

    /// Get source location information for the given address
    fn get_source_location_slow(&self, address: u64) -> Option<SourceLocation>;

    /// Find the next is_stmt=true address after the given function start address
    /// This is used for prologue detection following GDB's approach
    fn find_next_stmt_address(&self, function_start: u64) -> Option<u64>;
}

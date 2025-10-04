/// Loader error types
#[derive(Debug, thiserror::Error)]
pub enum LoaderError {
    #[error("Aya error: {0}")]
    Aya(#[from] aya::EbpfError),

    #[error("Program error: {0}")]
    Program(#[from] aya::programs::ProgramError),

    #[error("Map not found: {0}")]
    MapNotFound(String),

    #[error("Loader error: {0}")]
    Generic(String),
}

pub type Result<T> = std::result::Result<T, LoaderError>;

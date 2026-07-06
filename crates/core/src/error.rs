use thiserror::Error;

/// Core result type for AutomateSTIG operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Core error types for AutomateSTIG.
#[derive(Error, Debug)]
pub enum Error {
    #[error("STIG not found: {0}")]
    StigNotFound(String),

    #[error("Parse error: {format} - {message}")]
    ParseError { format: String, message: String },

    #[error("Answer file error: {0}")]
    AnswerFileError(String),

    #[error("STIG library error: {0}")]
    LibraryError(String),

    #[error("Integrity check failed: expected {expected}, got {actual}")]
    IntegrityError { expected: String, actual: String },

    #[error("Signature verification failed: {0}")]
    SignatureError(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_norway::Error),

    #[error("{0}")]
    Other(String),
}

use thiserror::Error;

pub type ParseResult<T> = std::result::Result<T, ParseError>;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid CKLB format: {0}")]
    InvalidCklb(String),

    #[error("XML parse error: {0}")]
    XmlError(String),

    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

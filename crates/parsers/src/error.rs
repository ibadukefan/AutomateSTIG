use thiserror::Error;

pub type ParseResult<T> = std::result::Result<T, ParseError>;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid CKL format: {0}")]
    InvalidCkl(String),

    #[error("Invalid CKLB format: {0}")]
    InvalidCklb(String),

    #[error("Invalid XCCDF format: {0}")]
    InvalidXccdf(String),

    #[error("Missing required element: {element} in {context}")]
    MissingElement { element: String, context: String },

    #[error("XML parse error: {0}")]
    XmlError(String),

    #[error("JSON parse error: {0}")]
    JsonError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}

use thiserror::Error;

#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("IoError error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Other(String),
}

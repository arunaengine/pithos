use crate::helpers::chacha_poly1305::ChaChaPoly1305Error;
use crate::helpers::crypt4gh::Crypt4GHError;
use crate::helpers::x25519_keys::CryptError;
use crate::helpers::zstd::ZstdError;
use crate::model::deserialization::DeserializationError;
use crate::model::serialization::SerializationError;
use std::io;
use std::time::SystemTimeError;
use thiserror::Error;

/// Custom top-level error type for all of Pithos
#[derive(Error, Debug)]
pub enum PithosError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Conversion error: {0}")]
    Conversion(String),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Failed to strip prefix: {0}")]
    StripPrefix(#[from] std::path::StripPrefixError),
    #[error("Walkdir error: {0}")]
    WalkDir(#[from] walkdir::Error),
    #[error("FastCDC error: {0}")]
    FastCDC(#[from] fastcdc::v2020::Error),
    #[error("Serialization error: {0:?}")]
    Serialization(#[from] SerializationError),
    #[error("Deserialization error: {0:?}")]
    Deserialization(#[from] DeserializationError),
    #[error("Crypt error: {0}")]
    Crypt(#[from] CryptError),
    #[error("Crypt4GH error: {0}")]
    Crypt4GH(#[from] Crypt4GHError),
    #[error("Encryption error: {0}")]
    Cipher(#[from] ChaChaPoly1305Error),
    #[error("Decryption error: {0}")]
    Compression(#[from] ZstdError),
    #[error("Invalid block data state: {0}")]
    InvalidBlockDataState(String),
    #[error("Block hash not found: {0:?}")]
    BlockHashNotFound([u8; 32]),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File already exists: {0}")]
    DuplicateFileId(String),
    #[error("Relation id already occupied: {0}")]
    RelationIdOccupied(u64),
    #[error("Path already occupied: {0}")]
    PathOccupied(String),
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),
    #[error("No recipient section found for the provided private key")]
    NoMatchingRecipient,
    #[error("Invalid recipient data state: {0}")]
    InvalidRecipientDataState(String),
    #[error("Other error: {0}")]
    Other(String),
}

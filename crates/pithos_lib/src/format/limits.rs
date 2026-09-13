use std::io::Error as IoError;
use std::string::FromUtf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DeserializationError {
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("Invalid enum value: {0}")]
    InvalidEnumValue(u8),
    #[error("Invalid marker: {0}")]
    InvalidMarker(String),
    #[error("Invalid option")]
    InvalidOption,
    #[error("Invalid length")]
    InvalidLength,
    #[error("reserved processing bits are set: {0:#04x}")]
    InvalidProcessingFlags(u8),
    #[error("duplicate encoded recipient key")]
    DuplicateRecipientKey,
    #[error("duplicate encoded block reference")]
    DuplicateBlockReference,
    #[error("duplicate encoded recipient file id")]
    DuplicateRecipientFileId,
    #[error("{field} exceeds limit {limit}: {actual}")]
    LimitExceeded {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("allocation failed for {field}: {size}")]
    AllocationFailed { field: &'static str, size: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct DeserializationLimits {
    pub max_string_bytes: u64,
    pub max_opaque_bytes: u64,
    pub max_collection_entries: u64,
    pub max_file_entries: u64,
    pub max_block_descriptors: u64,
    pub max_block_references: u64,
    pub max_references: u64,
    pub max_relationships: u64,
}

impl Default for DeserializationLimits {
    fn default() -> Self {
        Self {
            max_string_bytes: 1024 * 1024,
            max_opaque_bytes: 64 * 1024 * 1024,
            max_collection_entries: 1_000_000,
            max_file_entries: 1_000_000,
            max_block_descriptors: 1_000_000,
            max_block_references: 1_000_000,
            max_references: 1_000_000,
            max_relationships: 1_000_000,
        }
    }
}

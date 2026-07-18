use crate::helpers::chacha_poly1305::ChaChaPoly1305Error;
use crate::helpers::crypt4gh::Crypt4GHError;
use crate::helpers::x25519_keys::CryptError;
use crate::helpers::zstd::ZstdError;
use crate::model::deserialization::DeserializationError;
use crate::model::serialization::SerializationError;
use rocraters::ro_crate::read::CrateReadError;
use std::io;
use std::path::PathBuf;
use std::time::SystemTimeError;
use thiserror::Error;
use zip::result::ZipError;

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
    #[error("Invalid directory marker: expected {expected:?}, got {actual:?}")]
    InvalidDirectoryMarker { expected: [u8; 8], actual: [u8; 8] },
    #[error("Directory length mismatch: expected {expected}, got {actual}")]
    DirectoryLengthMismatch { expected: u64, actual: u64 },
    #[error("Directory checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    DirectoryChecksumMismatch { expected: u32, actual: u32 },
    #[error("Directory parser consumption mismatch: expected {expected}, got {actual}")]
    DirectoryConsumptionMismatch { expected: u64, actual: u64 },
    #[error("Crypt error: {0}")]
    Crypt(#[from] CryptError),
    #[error("Crypt4GH error: {0}")]
    Crypt4GH(#[from] Crypt4GHError),
    #[error("Encryption error: {0}")]
    Cipher(#[from] ChaChaPoly1305Error),
    #[error("Decryption error: {0}")]
    Compression(#[from] ZstdError),
    #[error("RO-Crate parse or validation error: {0}")]
    RoCrate(#[from] CrateReadError),
    #[error("ZIP archive error: {0}")]
    Zip(#[from] ZipError),
    #[error("Invalid RO-Crate source {path}: expected {expected}")]
    InvalidRoCrateSource {
        path: PathBuf,
        expected: &'static str,
    },
    #[error("RO-Crate metadata file is missing from {0}")]
    MissingRoCrateMetadata(PathBuf),
    #[error("Unsafe ZIP member path: {0}")]
    UnsafeZipPath(String),
    #[error("Duplicate ZIP member path after normalization: {0}")]
    DuplicateZipPath(String),
    #[error("ZIP member path conflicts with a required directory: {0}")]
    ZipPathConflict(String),
    #[error("Overlapping ZIP members are not supported: {0}")]
    OverlappingZipEntries(PathBuf),
    #[error("Encrypted ZIP member is not supported: {0}")]
    EncryptedZipEntry(String),
    #[error("Unsupported ZIP entry type or compression for {0}")]
    UnsupportedZipEntry(String),
    #[error("Invalid block data state: {0}")]
    InvalidBlockDataState(String),
    #[error("Block hash not found: {0:?}")]
    BlockHashNotFound([u8; 32]),
    #[error("Block size mismatch: expected {expected}, got {actual}")]
    BlockSizeMismatch { expected: u64, actual: u64 },
    #[error("Block hash mismatch: expected {expected:?}, got {actual:?}")]
    BlockHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File already exists: {0}")]
    DuplicateFileId(String),
    #[error("Relation id already occupied: {0}")]
    RelationIdOccupied(u64),
    #[error("Path already occupied: {0}")]
    PathOccupied(String),
    #[error("Invalid archive path {path}: {reason}")]
    InvalidArchivePath { path: String, reason: String },
    #[error("Invalid symlink target {target} for {path}: {reason}")]
    InvalidSymlinkTarget {
        path: String,
        target: String,
        reason: String,
    },
    #[error("Invalid symlink entry {path}: {reason}")]
    InvalidSymlinkEntry { path: String, reason: String },
    #[error("Extraction collision at {path}: {reason}")]
    ExtractionCollision { path: String, reason: String },
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),
    #[error("No recipient section found for the provided private key")]
    NoMatchingRecipient,
    #[error("Invalid recipient data state: {0}")]
    InvalidRecipientDataState(String),
    #[error("Other error: {0}")]
    Other(String),
}

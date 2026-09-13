use crate::crypto::CryptoError;
use crate::source::SourceError;
use std::io;
use thiserror::Error;

pub use crate::format::error::SerializationError;
pub use crate::format::limits::DeserializationError;

/// Custom top-level error type for all of Pithos
#[derive(Error, Debug)]
pub enum PithosError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("archive source error: {0}")]
    Source(#[from] SourceError),
    #[error("FastCDC error: {0}")]
    FastCDC(#[from] fastcdc::v2020::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] SerializationError),
    #[error("deserialization error: {0}")]
    Deserialization(#[from] DeserializationError),
    #[error("Unsupported file version: supported {supported:#06x}, actual {actual:#06x}")]
    UnsupportedFileVersion { supported: u16, actual: u16 },
    #[error("Invalid directory marker: expected {expected:?}, got {actual:?}")]
    InvalidDirectoryMarker { expected: [u8; 8], actual: [u8; 8] },
    #[error("Directory length mismatch: expected {expected}, got {actual}")]
    DirectoryLengthMismatch { expected: u64, actual: u64 },
    #[error("Directory checksum mismatch: expected {expected:#010x}, got {actual:#010x}")]
    DirectoryChecksumMismatch { expected: u32, actual: u32 },
    #[error("Directory parser consumption mismatch: expected {expected}, got {actual}")]
    DirectoryConsumptionMismatch { expected: u64, actual: u64 },
    #[error("{field} exceeds limit {limit}: {actual}")]
    LimitExceeded {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("allocation failed for {field}: {size}")]
    AllocationFailed { field: &'static str, size: u64 },
    #[error("invalid directory range while {operation}")]
    InvalidDirectoryRange { operation: &'static str },
    #[error("invalid directory chain while {operation}")]
    InvalidDirectoryChain { operation: &'static str },
    #[error("Crypt error: {0}")]
    Crypt(#[from] CryptoError),
    #[error("{operation} failed: {source}")]
    Compression {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("Invalid block data state: {0}")]
    InvalidBlockDataState(String),
    #[error("invalid block descriptor: {0}")]
    InvalidBlockDescriptor(&'static str),
    #[error("invalid entry combination for {path}: {reason}")]
    InvalidEntryCombination { path: String, reason: String },
    #[error("content is unavailable with the supplied access keys")]
    ContentUnavailable,
    #[error("append snapshot does not contain file id {0}")]
    SnapshotFileIdNotFound(u64),
    #[error("content for snapshot file id {0} is unavailable with the supplied access keys")]
    SnapshotContentUnavailable(u64),
    #[error("snapshot file id {0} is a directory and has no content key")]
    SnapshotDirectoryHasNoContent(u64),
    #[error("snapshot file id {0} is a symlink and has no content key")]
    SnapshotSymlinkHasNoContent(u64),
    #[error("external block source required")]
    ExternalBlockSourceRequired,
    #[error("external block framing error: {0}")]
    ExternalBlockFraming(String),
    #[error("Block hash not found: {0:?}")]
    BlockHashNotFound([u8; 32]),
    #[error("duplicate encoded block hash")]
    DuplicateBlockHash,
    #[error("duplicate encoded sender key")]
    DuplicateSenderKey,
    #[error("duplicate encoded recipient key")]
    DuplicateRecipientKey,
    #[error("duplicate encoded block reference")]
    DuplicateBlockReference,
    #[error("duplicate encoded recipient file id")]
    DuplicateRecipientFileId,
    #[error("reserved processing bits are set: {0:#04x}")]
    ReservedProcessingBits(u8),
    #[error("conflicting relationship definition for id {0}")]
    ConflictingRelationshipDefinition(u64),
    #[error("invalid relationship definition for id {id}: {reason}")]
    InvalidRelationshipDefinition { id: u64, reason: String },
    #[error("invalid permissions: {0:#o}")]
    InvalidPermissions(u32),
    #[error("unknown relationship id {0}")]
    UnknownRelationshipId(u64),
    #[error("missing reference target file id {0}")]
    MissingReferenceTarget(u64),
    #[error("missing block descriptor")]
    MissingBlockDescriptor,
    #[error(
        "accessible file size does not match its block sizes: expected {expected}, actual {actual}"
    )]
    AccessibleFileSizeMismatch { expected: u64, actual: u64 },
    #[error("conflicting recovered file key")]
    ConflictingRecoveredFileKey,
    #[error("conflicting recipient grant")]
    ConflictingRecipientGrant,
    #[error("invalid half-open read range {start}..{end} for file size {file_size}")]
    InvalidReadRange {
        start: u64,
        end: u64,
        file_size: u64,
    },
    #[error("Block size mismatch: expected {expected}, got {actual}")]
    BlockSizeMismatch { expected: u64, actual: u64 },
    #[error("Block hash mismatch: expected {expected:?}, got {actual:?}")]
    BlockHashMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    #[error(
        "Block index conflict for hash {hash:?}: existing original size {existing_original_size}, new original size {new_original_size}"
    )]
    BlockIndexConflict {
        hash: [u8; 32],
        existing_original_size: u64,
        new_original_size: u64,
    },
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("File already exists: {0}")]
    DuplicateFileId(String),
    #[error("File ID allocation is exhausted")]
    FileIdExhausted,
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
    #[error("No recipient section found for the provided private key")]
    NoMatchingRecipient,
    #[error("Invalid recipient data state: {0}")]
    InvalidRecipientDataState(String),
    #[error("archive creation requires at least one recipient")]
    WriterRequiresRecipient,
    #[error("granting reader access requires at least one file or metadata id")]
    GrantRequiresFileId,
    #[error("invalid CDC configuration {min_size},{avg_size},{max_size}")]
    InvalidCdcConfig {
        min_size: usize,
        avg_size: usize,
        max_size: usize,
    },
    #[error("writer is poisoned")]
    WriterPoisoned,
    #[error("streamed content size overflow")]
    WriterSizeOverflow,
    #[error("streamed content size mismatch: expected {expected}, actual {actual}")]
    WriterExpectedSizeMismatch { expected: u64, actual: u64 },
    #[error("content entry has an unsealed block list")]
    WriterUnsealedBlockList,
    #[error("recipient record has an unsealed file-key list")]
    WriterUnsealedRecipientList,
    #[error("directory or symlink has block-key material")]
    WriterNoContentHasBlockMaterial,
    #[error("append failed after mutation but was rolled back: {source}")]
    AppendRolledBack {
        #[source]
        source: Box<PithosError>,
    },
    #[error(
        "append failed after mutation and rollback failed (original length {original_len}, observed length {observed_len}): original failure: {source}; rollback failure: {rollback}"
    )]
    AppendRollbackFailed {
        #[source]
        source: Box<PithosError>,
        rollback: io::Error,
        original_len: u64,
        observed_len: u64,
    },
    #[error("planned IDs are only valid for append writers")]
    PlannedIdsRequireAppendWriter,
    #[error("grant child must not contain file entries or block descriptors")]
    GrantChildContainsContent,
    #[error("granting reader access requires an append snapshot")]
    GrantRequiresAppendSnapshot,
    #[error("file manifest entry has no retained source")]
    MissingManifestSource,
    #[error("append plan entry count does not match manifest")]
    AppendPlanLengthMismatch,
}

//! Linux filesystem adapters.
//!
//! Ingestion, extraction, append, and reader grants are Linux-only host operations.
//! They keep no-follow traversal, retained source identity, metadata normalization,
//! and filesystem error context out of the core archive and format layers. Extraction
//! stages regular files and publishes without clobbering an existing destination.
//! On Linux, symlink permission bits are retained as archive metadata but are not
//! applied to the symlink itself. Append and grants use an advisory lock that coordinates
//! only participating writers.

mod append;
mod extraction;
pub mod ingest;

use crate::archive::WriterError;
use crate::error::PithosError;
use std::io;
use std::path::PathBuf;
use thiserror::Error;

pub use append::{append_files, grant_readers};

/// Actionable failures from Linux filesystem adapter operations.
///
/// Each variant retains the attempted operation and relevant host or archive path,
/// and preserves the underlying source error where one exists. This adapter error
/// deliberately remains distinct from core [`PithosError`].
#[derive(Debug, Error)]
pub enum FsError {
    #[error("filesystem {operation} failed for {path}: {source}")]
    Host {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("path is not valid UTF-8: {path}")]
    InvalidUtf8Path { path: PathBuf },
    #[error("filesystem {operation} failed while deriving {path}: {source}")]
    StripPrefix {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::path::StripPrefixError,
    },
    #[error(
        "filesystem {operation} failed for archive entry {archive_path} in destination {destination}: {source}"
    )]
    Operation {
        operation: &'static str,
        archive_path: String,
        destination: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "filesystem extraction collision for archive entry {archive_path} in destination {destination}: {reason}"
    )]
    ExtractionCollision {
        archive_path: String,
        destination: PathBuf,
        reason: &'static str,
    },
    #[error(
        "archive {operation} failed for archive entry {archive_path} in destination {destination}: {source}"
    )]
    Archive {
        operation: &'static str,
        archive_path: String,
        destination: PathBuf,
        #[source]
        source: Box<PithosError>,
    },
    #[error("filesystem {operation} failed for {path}: {source}")]
    Core {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: PithosError,
    },
    #[error("filesystem {operation} failed for archive entry {archive_path}: {source}")]
    Writer {
        operation: &'static str,
        archive_path: String,
        #[source]
        source: WriterError,
    },
    #[error("append source resolves to the archive being modified: {path}")]
    AppendSourceIsArchive { path: PathBuf },
    #[error("append requires at least one filesystem input")]
    AppendRequiresInput,
    #[error("append is locked by another cooperating writer: {path}")]
    AppendLocked { path: PathBuf },
    #[error("unsupported filesystem entry {path}: {kind}")]
    UnsupportedEntry { path: PathBuf, kind: &'static str },
}

pub use extraction::{
    ExtractionOptions, extract, extract_all, extract_all_with_options, extract_with_options,
};

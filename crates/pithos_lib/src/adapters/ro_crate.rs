//! RO-Crate presentation adapter.
//!
//! Upstream `ro-crate-rs` owns graph and schema parsing. This adapter separately
//! owns Pithos source identity, path, metadata, limit, and writer-conversion policy;
//! its errors retain operation, path, ZIP member, and index context.

use crate::archive::validate_symlink_target;
use crate::archive::{
    ArchivePath, ArchiveWriter, EntryMetadata, EntryReference, ProcessingOptions, WriterError,
};
use crate::error::PithosError;
use crate::format::file_entry::VALID_PERMISSION_BITS;
use cap_std::fs::{
    Dir, File as CapFile, MetadataExt as CapMetadataExt, PermissionsExt as CapPermissionsExt,
};
use cap_std::time::{SystemClock, SystemTime};
use rocraters::ro_crate::read::CrateReadError;
use rocraters::ro_crate::read::read_crate_obj;
pub use rocraters::ro_crate::rocrate::RoCrate;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Cursor, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use zip::result::ZipError;
use zip::{CompressionMethod, ZipArchive};

pub const RO_CRATE_METADATA_FILE: &str = "ro-crate-metadata.json";

const PARSE_WITHOUT_VALIDATION: i8 = 0;
const MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SYMLINK_TARGET_BYTES: u64 = 16 * 1024;

/// Actionable failures from RO-Crate directory, ZIP, and conversion operations.
#[derive(Debug, Error)]
pub enum RoCrateError {
    #[error("RO-Crate {operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("RO-Crate {operation} failed for {path}: {source}")]
    Zip {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: ZipError,
    },
    #[error(
        "RO-Crate {operation} failed for ZIP {archive} member {member} at index {index}: {source}"
    )]
    ZipMember {
        operation: &'static str,
        archive: PathBuf,
        index: usize,
        member: String,
        #[source]
        source: ZipError,
    },
    #[error(
        "RO-Crate {operation} failed for ZIP {archive} member {member} at index {index}: {source}"
    )]
    ZipMemberIo {
        operation: &'static str,
        archive: PathBuf,
        index: usize,
        member: String,
        #[source]
        source: std::io::Error,
    },
    #[error("RO-Crate {operation} failed for {path}: {source}")]
    DirectoryFileWriter {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: WriterError,
    },
    #[error("RO-Crate {operation} failed for {path}: {source}")]
    DirectoryCore {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: PithosError,
    },
    #[error(
        "RO-Crate {operation} failed for ZIP {archive} member {member} at index {index}: {source}"
    )]
    ZipMemberWriter {
        operation: &'static str,
        archive: Box<PathBuf>,
        index: usize,
        member: Box<String>,
        #[source]
        source: WriterError,
    },
    #[error(
        "RO-Crate {operation} failed for ZIP {archive} member {member} at index {index}: {source}"
    )]
    ZipMemberCore {
        operation: &'static str,
        archive: Box<PathBuf>,
        index: usize,
        member: Box<String>,
        #[source]
        source: PithosError,
    },
    #[error("RO-Crate {operation} failed for ZIP {archive} synthetic path {path}: {source}")]
    ZipSyntheticWriter {
        operation: &'static str,
        archive: Box<PathBuf>,
        path: String,
        #[source]
        source: WriterError,
    },
    #[error("RO-Crate {operation} failed for {path}: {source}")]
    Parser {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: CrateReadError,
    },
    #[error(
        "RO-Crate {operation} failed for ZIP {archive} member {member} at index {index}: {source}"
    )]
    ZipMemberParser {
        operation: &'static str,
        archive: Box<PathBuf>,
        index: usize,
        member: Box<String>,
        #[source]
        source: CrateReadError,
    },
    #[error("RO-Crate core operation failed: {0}")]
    Core(#[from] PithosError),
    #[error("RO-Crate writer conversion failed: {0}")]
    Writer(#[from] WriterError),
    #[error("invalid RO-Crate source {path}: expected {expected}")]
    InvalidSource {
        path: PathBuf,
        expected: &'static str,
    },
    #[error(
        "invalid RO-Crate ZIP source {archive} member {member} at index {index}: expected {expected}"
    )]
    ZipMemberInvalidSource {
        archive: PathBuf,
        index: usize,
        member: String,
        expected: &'static str,
    },
    #[error("RO-Crate metadata file is missing from {path}")]
    MissingMetadata { path: PathBuf },
    #[error("unsafe ZIP member path {member} in {archive} at index {index}")]
    UnsafeZipPath {
        archive: PathBuf,
        index: usize,
        member: String,
    },
    #[error("ZIP member name in {archive} at index {index} is not valid UTF-8: {member}")]
    InvalidZipEntryName {
        archive: PathBuf,
        index: usize,
        member: String,
    },
    #[error("duplicate ZIP member path {path} in {archive} member {member} at index {index}")]
    DuplicateZipPath {
        archive: PathBuf,
        index: usize,
        member: String,
        path: String,
    },
    #[error(
        "ZIP member path {path} conflicts with a required directory in {archive} member {member} at index {index}"
    )]
    ZipPathConflict {
        archive: PathBuf,
        index: usize,
        member: String,
        path: String,
    },
    #[error("overlapping ZIP members are not supported in {path}")]
    OverlappingZipEntries { path: PathBuf },
    #[error("encrypted ZIP member is not supported in {archive} at index {index}: {member}")]
    EncryptedZipEntry {
        archive: PathBuf,
        index: usize,
        member: String,
    },
    #[error("unsupported ZIP entry type or compression in {archive} at index {index}: {member}")]
    UnsupportedZipEntry {
        archive: PathBuf,
        index: usize,
        member: String,
    },
    #[error("RO-Crate {operation} exceeds the {limit}-byte limit for {path}: {actual}")]
    ContentLimit {
        operation: &'static str,
        path: PathBuf,
        limit: u64,
        actual: u64,
    },
    #[error(
        "RO-Crate {operation} exceeds the {limit}-byte limit for ZIP {archive} member {member} at index {index}: {actual}"
    )]
    ZipMemberLimit {
        operation: &'static str,
        archive: PathBuf,
        index: usize,
        member: String,
        limit: u64,
        actual: u64,
    },
}

enum BoundedReadError {
    Io(std::io::Error),
    Limit { limit: u64, actual: u64 },
}

fn read_limited<R: Read>(reader: &mut R, limit: u64) -> Result<Vec<u8>, BoundedReadError> {
    let capacity = usize::try_from(limit.min(64 * 1024)).unwrap_or(64 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = [0u8; 8192];
    loop {
        let remaining = limit.saturating_sub(bytes.len() as u64);
        let request = usize::try_from(remaining.saturating_add(1))
            .unwrap_or(buffer.len())
            .min(buffer.len());
        let count = reader
            .read(&mut buffer[..request])
            .map_err(BoundedReadError::Io)?;
        if count == 0 {
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.len() as u64 > limit {
            return Err(BoundedReadError::Limit {
                limit,
                actual: bytes.len() as u64,
            });
        }
    }
}

fn read_directory_limited<R: Read>(
    reader: &mut R,
    expected_size: u64,
    limit: u64,
    operation: &'static str,
    path: PathBuf,
) -> Result<Vec<u8>, RoCrateError> {
    if expected_size > limit {
        return Err(RoCrateError::ContentLimit {
            operation,
            path,
            limit,
            actual: expected_size,
        });
    }
    read_limited(reader, limit).map_err(|error| match error {
        BoundedReadError::Io(source) => RoCrateError::Io {
            operation,
            path,
            source,
        },
        BoundedReadError::Limit { limit, actual } => RoCrateError::ContentLimit {
            operation,
            path,
            limit,
            actual,
        },
    })
}

fn read_zip_limited<R: Read>(
    reader: &mut R,
    expected_size: u64,
    limit: u64,
    operation: &'static str,
    archive: PathBuf,
    index: usize,
    member: String,
) -> Result<Vec<u8>, RoCrateError> {
    if expected_size > limit {
        return Err(RoCrateError::ZipMemberLimit {
            operation,
            archive,
            index,
            member,
            limit,
            actual: expected_size,
        });
    }
    read_limited(reader, limit).map_err(|error| match error {
        BoundedReadError::Io(source) => RoCrateError::ZipMemberIo {
            operation,
            archive,
            index,
            member,
            source,
        },
        BoundedReadError::Limit { limit, actual } => RoCrateError::ZipMemberLimit {
            operation,
            archive,
            index,
            member,
            limit,
            actual,
        },
    })
}

fn open_directory_no_follow(path: &Path) -> std::io::Result<Dir> {
    rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(|fd| Dir::from_std_file(File::from(fd)))
}

fn open_directory_at_no_follow(parent: &Dir, name: &Path) -> std::io::Result<Dir> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(|fd| Dir::from_std_file(File::from(fd)))
}

fn open_file_at_no_follow(parent: &Dir, name: &Path) -> std::io::Result<CapFile> {
    rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(|fd| CapFile::from_std(File::from(fd)))
}

fn same_cap_identity(left: &cap_std::fs::Metadata, right: &cap_std::fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

fn read_symlink_at_limited(parent: &Dir, name: &Path) -> Result<Vec<u8>, std::io::Error> {
    let name = CString::new(name.as_os_str().as_bytes())?;
    let mut bytes = vec![0; MAX_SYMLINK_TARGET_BYTES as usize + 1];
    // The fixed limit + 1 buffer prevents a raced replacement from growing an
    // otherwise inspected symlink target beyond the adapter's allocation bound.
    let count = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(std::io::Error::last_os_error());
    }
    bytes.truncate(count as usize);
    Ok(bytes)
}

fn archive_path(path: &Path) -> Result<ArchivePath, RoCrateError> {
    let display_path = path.to_str().ok_or_else(|| RoCrateError::InvalidSource {
        path: path.to_path_buf(),
        expected: "UTF-8 archive path",
    })?;
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(PithosError::InvalidArchivePath {
                path: display_path.to_owned(),
                reason: "archive paths must contain only normal components".into(),
            }
            .into());
        };
        components.push(
            component
                .to_str()
                .ok_or_else(|| RoCrateError::InvalidSource {
                    path: path.to_path_buf(),
                    expected: "UTF-8 archive path",
                })?,
        );
    }
    Ok(ArchivePath::new(components.join("/"))?)
}

fn host_metadata(metadata: &cap_std::fs::Metadata) -> EntryMetadata {
    let timestamp = |value: Result<SystemTime, std::io::Error>| {
        value
            .ok()
            .and_then(|time| time.duration_since(SystemClock::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs())
    };
    EntryMetadata::new(
        timestamp(metadata.created()),
        timestamp(metadata.modified()),
        metadata.permissions().mode() & VALID_PERMISSION_BITS,
    )
}

/// The kind of retained physical source used to load an RO-Crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoCrateSource {
    Directory,
    Zip,
}

/// An upstream RO-Crate graph together with the exact inspected physical source.
///
/// This value deliberately cannot be cloned: conversion consumes the retained
/// file handles or ZIP archive rather than reopening the supplied path.
pub struct LoadedRoCrate {
    ro_crate: RoCrate,
    source: LoadedSource,
}

impl fmt::Debug for LoadedRoCrate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoadedRoCrate")
            .field("source_kind", &self.source_kind())
            .finish_non_exhaustive()
    }
}

impl LoadedRoCrate {
    /// Inspect the graph produced by the upstream RO-Crate parser.
    pub fn ro_crate(&self) -> &RoCrate {
        &self.ro_crate
    }

    /// Return the kind of source retained for conversion.
    pub fn source_kind(&self) -> RoCrateSource {
        match &self.source {
            LoadedSource::Directory(_) => RoCrateSource::Directory,
            LoadedSource::Zip(_) => RoCrateSource::Zip,
        }
    }
}

enum LoadedSource {
    Directory(LoadedDirectory),
    Zip(LoadedZip),
}

struct LoadedDirectory {
    // Keep the opened root capability as the identity of the inspected tree.
    _root: Dir,
    manifest: RoCrateDirectoryManifest,
}

struct LoadedZip {
    archive: ZipArchive<File>,
    manifest: RoCrateZipManifest,
}

struct MetadataDescriptor {
    inner_path: String,
    metadata: EntryMetadata,
    expected_size: u64,
    bytes: Vec<u8>,
    source: MetadataSource,
}

enum MetadataSource {
    // Metadata is emitted from retained bytes, but retain its opened handle so
    // the directory manifest owns every regular source it inspected.
    Directory { _source: CapFile, path: PathBuf },
    Zip(ZipEntrySource),
}

enum DirectoryEntryKind {
    Directory,
    File { expected_size: u64, source: CapFile },
    Symlink { target: String },
}

struct DirectoryEntryDescriptor {
    inner_path: String,
    metadata: EntryMetadata,
    source_path: PathBuf,
    kind: DirectoryEntryKind,
}

struct RoCrateDirectoryManifest {
    metadata: MetadataDescriptor,
    entries: Vec<DirectoryEntryDescriptor>,
}

#[derive(Clone)]
struct ZipEntrySource {
    archive_index: usize,
    member: String,
}

#[derive(Clone, PartialEq, Eq)]
enum ZipEntryKind {
    Directory,
    File { expected_size: u64 },
    Symlink { target: String },
}

#[derive(Clone)]
struct ZipEntryDescriptor {
    inner_path: String,
    metadata: EntryMetadata,
    source: Option<ZipEntrySource>,
    kind: ZipEntryKind,
}

struct RoCrateZipManifest {
    source: PathBuf,
    metadata: MetadataDescriptor,
    entries: Vec<ZipEntryDescriptor>,
}

fn directory_kind_rank(kind: &DirectoryEntryKind) -> u8 {
    match kind {
        DirectoryEntryKind::Directory => 0,
        DirectoryEntryKind::File { .. } => 1,
        DirectoryEntryKind::Symlink { .. } => 2,
    }
}

fn zip_kind_rank(kind: &ZipEntryKind) -> u8 {
    match kind {
        ZipEntryKind::Directory => 0,
        ZipEntryKind::File { .. } => 1,
        ZipEntryKind::Symlink { .. } => 2,
    }
}

/// Convert a loaded RO-Crate through the typed writer boundary.
///
/// Conversion consumes `loaded`, ensuring content always comes from the
/// directory handles or ZIP archive retained at load time.
pub fn write_ro_crate<W: Write>(
    writer: &mut ArchiveWriter<W>,
    loaded: LoadedRoCrate,
    processing: ProcessingOptions,
) -> Result<(), RoCrateError> {
    match loaded.source {
        LoadedSource::Directory(directory) => {
            write_ro_crate_directory(writer, directory.manifest, processing)?;
        }
        LoadedSource::Zip(mut zip) => {
            write_ro_crate_zip_archive(writer, &mut zip.archive, zip.manifest, processing)?;
        }
    }
    Ok(())
}

fn write_metadata<W: Write>(
    writer: &mut ArchiveWriter<W>,
    metadata: MetadataDescriptor,
    processing: ProcessingOptions,
) -> Result<u64, WriterError> {
    Ok(writer
        .add_metadata(
            ArchivePath::new(&metadata.inner_path)?,
            metadata.metadata,
            processing,
            Some(metadata.expected_size),
            Cursor::new(metadata.bytes),
        )?
        .id)
}

fn write_ro_crate_directory<W: Write>(
    writer: &mut ArchiveWriter<W>,
    manifest: RoCrateDirectoryManifest,
    processing: ProcessingOptions,
) -> Result<(), RoCrateError> {
    let metadata_path = match &manifest.metadata.source {
        MetadataSource::Directory { path, .. } => path.clone(),
        MetadataSource::Zip(_) => unreachable!("directory manifests retain directory metadata"),
    };
    let metadata_id = write_metadata(writer, manifest.metadata, processing).map_err(|source| {
        RoCrateError::DirectoryFileWriter {
            operation: "convert retained directory metadata",
            path: metadata_path,
            source,
        }
    })?;
    for DirectoryEntryDescriptor {
        inner_path,
        metadata,
        source_path,
        kind,
    } in manifest.entries
    {
        let path = ArchivePath::new(&inner_path)?;
        match kind {
            DirectoryEntryKind::Directory => {
                writer.add_directory(path, metadata).map_err(|source| {
                    RoCrateError::DirectoryFileWriter {
                        operation: "convert retained directory entry",
                        path: source_path,
                        source,
                    }
                })?;
            }
            DirectoryEntryKind::File {
                expected_size,
                source,
            } => {
                writer
                    .add_file(
                        path,
                        metadata.with_references(vec![EntryReference {
                            target_file_id: metadata_id,
                            relationship: 0,
                        }]),
                        processing,
                        Some(expected_size),
                        source,
                    )
                    .map_err(|source| RoCrateError::DirectoryFileWriter {
                        operation: "convert retained directory file",
                        path: source_path,
                        source,
                    })?;
            }
            DirectoryEntryKind::Symlink { target } => {
                writer
                    .add_symlink(path, metadata, target)
                    .map_err(|source| RoCrateError::DirectoryFileWriter {
                        operation: "convert retained directory entry",
                        path: source_path,
                        source,
                    })?;
            }
        }
    }
    Ok(())
}

fn write_ro_crate_zip_archive<W: Write, R: Read + Seek>(
    writer: &mut ArchiveWriter<W>,
    archive: &mut ZipArchive<R>,
    manifest: RoCrateZipManifest,
    processing: ProcessingOptions,
) -> Result<(), RoCrateError> {
    let RoCrateZipManifest {
        source,
        metadata,
        entries,
    } = manifest;
    let metadata_source = match &metadata.source {
        MetadataSource::Directory { .. } => unreachable!("ZIP manifests retain ZIP metadata"),
        MetadataSource::Zip(source) => source.clone(),
    };
    let metadata_id = write_metadata(writer, metadata, processing).map_err(|writer_error| {
        RoCrateError::ZipMemberWriter {
            operation: "convert retained ZIP metadata",
            archive: Box::new(source.clone()),
            index: metadata_source.archive_index,
            member: Box::new(metadata_source.member),
            source: writer_error,
        }
    })?;
    for ZipEntryDescriptor {
        inner_path,
        metadata,
        source: entry_source,
        kind,
    } in entries
    {
        let path = ArchivePath::new(&inner_path)?;
        match kind {
            ZipEntryKind::Directory => {
                writer.add_directory(path, metadata).map_err(
                    |writer_error| match entry_source {
                        Some(entry_source) => RoCrateError::ZipMemberWriter {
                            operation: "convert retained ZIP entry",
                            archive: Box::new(source.clone()),
                            index: entry_source.archive_index,
                            member: Box::new(entry_source.member),
                            source: writer_error,
                        },
                        None => RoCrateError::ZipSyntheticWriter {
                            operation: "convert synthetic ZIP parent",
                            archive: Box::new(source.clone()),
                            path: inner_path.clone(),
                            source: writer_error,
                        },
                    },
                )?;
            }
            ZipEntryKind::File { expected_size } => {
                let entry_source =
                    entry_source.expect("retained ZIP files retain their source member");
                let zip_member = archive
                    .by_index(entry_source.archive_index)
                    .map_err(|error| RoCrateError::ZipMember {
                        operation: "open retained ZIP member",
                        archive: source.clone(),
                        index: entry_source.archive_index,
                        member: entry_source.member.clone(),
                        source: error,
                    })?;
                writer
                    .add_file(
                        path,
                        metadata.with_references(vec![EntryReference {
                            target_file_id: metadata_id,
                            relationship: 0,
                        }]),
                        processing,
                        Some(expected_size),
                        zip_member,
                    )
                    .map_err(|writer_error| RoCrateError::ZipMemberWriter {
                        operation: "convert retained ZIP member",
                        archive: Box::new(source.clone()),
                        index: entry_source.archive_index,
                        member: Box::new(entry_source.member),
                        source: writer_error,
                    })?;
            }
            ZipEntryKind::Symlink { target } => {
                writer
                    .add_symlink(path, metadata, target)
                    .map_err(|writer_error| match entry_source {
                        Some(entry_source) => RoCrateError::ZipMemberWriter {
                            operation: "convert retained ZIP entry",
                            archive: Box::new(source.clone()),
                            index: entry_source.archive_index,
                            member: Box::new(entry_source.member),
                            source: writer_error,
                        },
                        None => RoCrateError::Writer(writer_error),
                    })?;
            }
        }
    }
    Ok(())
}

/// Load a directory RO-Crate, retaining all inspected regular-file handles.
pub fn read_ro_crate_directory(path: impl AsRef<Path>) -> Result<LoadedRoCrate, RoCrateError> {
    let source = path.as_ref().to_path_buf();
    let inspected =
        std::fs::symlink_metadata(&source).map_err(|source_error| RoCrateError::Io {
            operation: "inspect directory RO-Crate",
            path: source.clone(),
            source: source_error,
        })?;
    let root = open_directory_no_follow(&source).map_err(|source_error| RoCrateError::Io {
        operation: "open directory RO-Crate",
        path: source.clone(),
        source: source_error,
    })?;
    let opened = root
        .symlink_metadata(".")
        .map_err(|source_error| RoCrateError::Io {
            operation: "inspect opened directory RO-Crate",
            path: source.clone(),
            source: source_error,
        })?;
    if !inspected.file_type().is_dir()
        || !opened.file_type().is_dir()
        || inspected.dev() != opened.dev()
        || inspected.ino() != opened.ino()
    {
        return Err(RoCrateError::InvalidSource {
            path: source,
            expected: "stable directory",
        });
    }
    let mut manifest = inspect_ro_crate_directory_manifest(&root, &source)?;
    let metadata_path = source.join(RO_CRATE_METADATA_FILE);
    let json = std::str::from_utf8(&manifest.metadata.bytes).map_err(|error| RoCrateError::Io {
        operation: "decode RO-Crate metadata",
        path: metadata_path.clone(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
    })?;
    let ro_crate = read_crate_obj(json, PARSE_WITHOUT_VALIDATION).map_err(|source_error| {
        RoCrateError::Parser {
            operation: "parse RO-Crate metadata",
            path: metadata_path,
            source: source_error,
        }
    })?;

    // The parser only borrows these bytes; retain them for metadata-first output.
    manifest.metadata.bytes.shrink_to_fit();
    Ok(LoadedRoCrate {
        ro_crate,
        source: LoadedSource::Directory(LoadedDirectory {
            _root: root,
            manifest,
        }),
    })
}

/// Load a ZIP RO-Crate, retaining its opened archive and validated member indexes.
pub fn read_ro_crate_zip(path: impl AsRef<Path>) -> Result<LoadedRoCrate, RoCrateError> {
    let source = path.as_ref().to_path_buf();
    let inspected =
        std::fs::symlink_metadata(&source).map_err(|source_error| RoCrateError::Io {
            operation: "inspect ZIP archive",
            path: source.clone(),
            source: source_error,
        })?;
    let file = rustix::fs::open(
        &source,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(File::from)
    .map_err(|source_error| RoCrateError::Io {
        operation: "open ZIP archive",
        path: source.clone(),
        source: source_error,
    })?;
    let opened = file.metadata().map_err(|source_error| RoCrateError::Io {
        operation: "inspect opened ZIP archive",
        path: source.clone(),
        source: source_error,
    })?;
    if !inspected.file_type().is_file()
        || !opened.file_type().is_file()
        || inspected.dev() != opened.dev()
        || inspected.ino() != opened.ino()
    {
        return Err(RoCrateError::InvalidSource {
            path: source,
            expected: "ZIP file",
        });
    }
    let mut archive = ZipArchive::new(file).map_err(|zip_error| RoCrateError::Zip {
        operation: "open ZIP archive",
        path: source.clone(),
        source: zip_error,
    })?;
    let mut manifest = inspect_ro_crate_zip_archive_manifest(&mut archive, source.clone())?;
    let metadata_source = match &manifest.metadata.source {
        MetadataSource::Directory { .. } => unreachable!("ZIP manifests retain ZIP metadata"),
        MetadataSource::Zip(metadata_source) => metadata_source.clone(),
    };
    let json = std::str::from_utf8(&manifest.metadata.bytes).map_err(|error| {
        RoCrateError::ZipMemberIo {
            operation: "decode RO-Crate metadata",
            archive: source.clone(),
            index: metadata_source.archive_index,
            member: metadata_source.member.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        }
    })?;
    let ro_crate = read_crate_obj(json, PARSE_WITHOUT_VALIDATION).map_err(|source_error| {
        RoCrateError::ZipMemberParser {
            operation: "parse RO-Crate metadata",
            archive: Box::new(source.clone()),
            index: metadata_source.archive_index,
            member: Box::new(metadata_source.member),
            source: source_error,
        }
    })?;

    manifest.metadata.bytes.shrink_to_fit();
    Ok(LoadedRoCrate {
        ro_crate,
        source: LoadedSource::Zip(LoadedZip { archive, manifest }),
    })
}

fn inspect_ro_crate_directory_manifest(
    root: &Dir,
    source: &Path,
) -> Result<RoCrateDirectoryManifest, RoCrateError> {
    let mut explicit_entries = BTreeMap::new();
    collect_directory_entries(root, source, Path::new(""), &mut explicit_entries)?;
    let metadata = explicit_entries
        .remove(RO_CRATE_METADATA_FILE)
        .ok_or_else(|| RoCrateError::MissingMetadata {
            path: source.to_path_buf(),
        })?;
    let (expected_size, bytes, retained_source) = match metadata.kind {
        DirectoryEntryKind::File {
            expected_size,
            source: mut metadata_source,
            ..
        } => {
            let metadata_path = source.join(RO_CRATE_METADATA_FILE);
            let bytes = read_directory_limited(
                &mut metadata_source,
                expected_size,
                MAX_METADATA_BYTES,
                "read RO-Crate metadata",
                metadata_path.clone(),
            )?;
            let actual_size =
                u64::try_from(bytes.len()).map_err(|_| RoCrateError::DirectoryCore {
                    operation: "verify RO-Crate metadata size",
                    path: metadata_path.clone(),
                    source: PithosError::WriterSizeOverflow,
                })?;
            if actual_size != expected_size {
                return Err(RoCrateError::DirectoryCore {
                    operation: "verify RO-Crate metadata size",
                    path: metadata_path,
                    source: PithosError::WriterExpectedSizeMismatch {
                        expected: expected_size,
                        actual: actual_size,
                    },
                });
            }
            (expected_size, bytes, Some(metadata_source))
        }
        DirectoryEntryKind::Directory | DirectoryEntryKind::Symlink { .. } => {
            return Err(RoCrateError::InvalidSource {
                path: source.join(RO_CRATE_METADATA_FILE),
                expected: "regular metadata file",
            });
        }
    };
    let metadata = MetadataDescriptor {
        inner_path: metadata.inner_path,
        metadata: metadata.metadata,
        expected_size,
        bytes,
        source: MetadataSource::Directory {
            _source: retained_source.expect("directory metadata is a retained regular file"),
            path: source.join(RO_CRATE_METADATA_FILE),
        },
    };
    let mut entries = explicit_entries.into_values().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        directory_kind_rank(&left.kind)
            .cmp(&directory_kind_rank(&right.kind))
            .then_with(|| {
                left.inner_path
                    .to_lowercase()
                    .cmp(&right.inner_path.to_lowercase())
            })
            .then_with(|| left.inner_path.cmp(&right.inner_path))
    });
    Ok(RoCrateDirectoryManifest { metadata, entries })
}

fn collect_directory_entries(
    directory: &Dir,
    source_root: &Path,
    prefix: &Path,
    entries: &mut BTreeMap<String, DirectoryEntryDescriptor>,
) -> Result<(), RoCrateError> {
    let mut pending = vec![(
        (directory.try_clone()).map_err(|source| RoCrateError::Io {
            operation: "retain RO-Crate directory",
            path: source_root.join(prefix),
            source,
        })?,
        prefix.to_path_buf(),
    )];
    while let Some((directory, prefix)) = pending.pop() {
        let directory_path = source_root.join(&prefix);
        let mut children = directory
            .read_dir(".")
            .map_err(|source| RoCrateError::Io {
                operation: "read RO-Crate directory",
                path: directory_path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| RoCrateError::Io {
                operation: "read RO-Crate directory entry",
                path: directory_path,
                source,
            })?;
        children.sort_by_key(|entry| entry.file_name());
        let mut child_directories = Vec::new();
        for child in children {
            let relative = prefix.join(child.file_name());
            let source_path = source_root.join(&relative);
            let path = archive_path(&relative).map_err(|error| match error {
                RoCrateError::Core(source) => RoCrateError::DirectoryCore {
                    operation: "validate RO-Crate path",
                    path: source_path.clone(),
                    source,
                },
                RoCrateError::InvalidSource { expected, .. } => RoCrateError::InvalidSource {
                    path: source_path.clone(),
                    expected,
                },
                error => error,
            })?;
            let inner_path = path.as_str().to_owned();
            let host = directory
                .symlink_metadata(child.file_name())
                .map_err(|source| RoCrateError::Io {
                    operation: "inspect RO-Crate entry",
                    path: source_path.clone(),
                    source,
                })?;
            let kind = if host.file_type().is_dir() {
                let child_directory =
                    open_directory_at_no_follow(&directory, Path::new(&child.file_name()))
                        .map_err(|source| RoCrateError::Io {
                            operation: "open RO-Crate directory",
                            path: source_path.clone(),
                            source,
                        })?;
                let opened =
                    child_directory
                        .symlink_metadata(".")
                        .map_err(|source| RoCrateError::Io {
                            operation: "inspect opened RO-Crate directory",
                            path: source_path.clone(),
                            source,
                        })?;
                if !opened.file_type().is_dir() || !same_cap_identity(&host, &opened) {
                    return Err(RoCrateError::InvalidSource {
                        path: source_path,
                        expected: "stable directory",
                    });
                }
                child_directories.push((child_directory, relative));
                DirectoryEntryKind::Directory
            } else if host.file_type().is_file() {
                let source = open_file_at_no_follow(&directory, Path::new(&child.file_name()))
                    .map_err(|source| RoCrateError::Io {
                        operation: "open RO-Crate file",
                        path: source_path.clone(),
                        source,
                    })?;
                let opened = source.metadata().map_err(|source| RoCrateError::Io {
                    operation: "inspect opened RO-Crate file",
                    path: source_path.clone(),
                    source,
                })?;
                if !opened.file_type().is_file() || !same_cap_identity(&host, &opened) {
                    return Err(RoCrateError::InvalidSource {
                        path: source_path,
                        expected: "stable regular file",
                    });
                }
                DirectoryEntryKind::File {
                    expected_size: opened.len(),
                    source,
                }
            } else if host.file_type().is_symlink() {
                if host.len() > MAX_SYMLINK_TARGET_BYTES {
                    return Err(RoCrateError::ContentLimit {
                        operation: "read RO-Crate symlink",
                        path: source_path,
                        limit: MAX_SYMLINK_TARGET_BYTES,
                        actual: host.len(),
                    });
                }
                let target_bytes =
                    read_symlink_at_limited(&directory, Path::new(&child.file_name())).map_err(
                        |source| RoCrateError::Io {
                            operation: "read RO-Crate symlink",
                            path: source_path.clone(),
                            source,
                        },
                    )?;
                if target_bytes.len() as u64 > MAX_SYMLINK_TARGET_BYTES {
                    return Err(RoCrateError::ContentLimit {
                        operation: "read RO-Crate symlink",
                        path: source_path,
                        limit: MAX_SYMLINK_TARGET_BYTES,
                        actual: target_bytes.len() as u64,
                    });
                }
                let target =
                    String::from_utf8(target_bytes).map_err(|source| RoCrateError::Io {
                        operation: "decode RO-Crate symlink",
                        path: source_path.clone(),
                        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
                    })?;
                let current = directory
                    .symlink_metadata(child.file_name())
                    .map_err(|source| RoCrateError::Io {
                        operation: "inspect read RO-Crate symlink",
                        path: source_path.clone(),
                        source,
                    })?;
                if !current.file_type().is_symlink() || !same_cap_identity(&host, &current) {
                    return Err(RoCrateError::InvalidSource {
                        path: source_path,
                        expected: "stable symlink",
                    });
                }
                validate_symlink_target(&inner_path, &target).map_err(|source| {
                    RoCrateError::DirectoryCore {
                        operation: "validate RO-Crate symlink target",
                        path: source_path.clone(),
                        source,
                    }
                })?;
                DirectoryEntryKind::Symlink { target }
            } else {
                return Err(RoCrateError::InvalidSource {
                    path: source_path,
                    expected: "regular file, directory, or symlink",
                });
            };
            let descriptor = DirectoryEntryDescriptor {
                inner_path: inner_path.clone(),
                metadata: host_metadata(&host),
                source_path: source_path.clone(),
                kind,
            };
            if entries.insert(inner_path.clone(), descriptor).is_some() {
                return Err(RoCrateError::InvalidSource {
                    path: source_path,
                    expected: "unique archive path",
                });
            }
        }
        pending.extend(child_directories.into_iter().rev());
    }
    Ok(())
}

fn raw_zip_path(name: &str, is_directory: bool) -> Result<String, ()> {
    if name.is_empty()
        || name.starts_with(['/', '\\'])
        || name.contains('\\')
        || name.as_bytes().get(1).is_some_and(|byte| *byte == b':')
        || name.as_bytes().contains(&0)
    {
        return Err(());
    }
    let path = if is_directory {
        name.strip_suffix('/').ok_or(())?
    } else {
        name
    };
    if path.is_empty()
        || path.ends_with('/')
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(());
    }
    Ok(path.to_owned())
}

fn zip_timestamp<R: Read + ?Sized>(entry: &zip::read::ZipFile<'_, R>) -> u64 {
    let Some(date_time) = entry.last_modified() else {
        return 0;
    };
    if !date_time.is_valid() {
        return 0;
    }
    let year = date_time.year();
    let mut days = 0i64;
    for current_year in 1970u16..year {
        days += if current_year % 4 == 0 && (current_year % 100 != 0 || current_year % 400 == 0) {
            366
        } else {
            365
        };
    }
    const DAYS_BEFORE_MONTH: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    days += DAYS_BEFORE_MONTH[usize::from(date_time.month() - 1)];
    if date_time.month() > 2 && (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) {
        days += 1;
    }
    days += i64::from(date_time.day() - 1);
    let timestamp = days * 86_400
        + i64::from(date_time.hour()) * 3_600
        + i64::from(date_time.minute()) * 60
        + i64::from(date_time.second());
    u64::try_from(timestamp).unwrap_or(0)
}

fn inspect_ro_crate_zip_archive_manifest<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    source: PathBuf,
) -> Result<RoCrateZipManifest, RoCrateError> {
    if archive
        .has_overlapping_files()
        .map_err(|error| RoCrateError::Zip {
            operation: "inspect ZIP overlap",
            path: source.clone(),
            source: error,
        })?
    {
        return Err(RoCrateError::OverlappingZipEntries { path: source });
    }
    let mut explicit_entries = BTreeMap::new();
    for archive_index in 0..archive.len() {
        let descriptor = {
            let mut entry =
                archive
                    .by_index(archive_index)
                    .map_err(|error| RoCrateError::ZipMember {
                        operation: "inspect ZIP member",
                        archive: source.clone(),
                        index: archive_index,
                        member: "<unknown>".to_string(),
                        source: error,
                    })?;
            let entry_name = std::str::from_utf8(entry.name_raw())
                .map_err(|_| RoCrateError::InvalidZipEntryName {
                    archive: source.clone(),
                    index: archive_index,
                    member: String::from_utf8_lossy(entry.name_raw()).into_owned(),
                })?
                .to_owned();
            if entry.encrypted() {
                return Err(RoCrateError::EncryptedZipEntry {
                    archive: source.clone(),
                    index: archive_index,
                    member: entry_name,
                });
            }
            if !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            ) {
                return Err(RoCrateError::UnsupportedZipEntry {
                    archive: source.clone(),
                    index: archive_index,
                    member: entry_name,
                });
            }
            let inner_path = raw_zip_path(&entry_name, entry.is_dir()).map_err(|_| {
                RoCrateError::UnsafeZipPath {
                    archive: source.clone(),
                    index: archive_index,
                    member: entry_name.clone(),
                }
            })?;
            ArchivePath::new(&inner_path).map_err(|_| RoCrateError::UnsafeZipPath {
                archive: source.clone(),
                index: archive_index,
                member: entry_name.clone(),
            })?;
            let kind = if entry.is_dir() {
                ZipEntryKind::Directory
            } else if entry.is_symlink() {
                let expected_size = entry.size();
                let target = String::from_utf8(read_zip_limited(
                    &mut entry,
                    expected_size,
                    MAX_SYMLINK_TARGET_BYTES,
                    "read ZIP symlink target",
                    source.clone(),
                    archive_index,
                    entry_name.clone(),
                )?)
                .map_err(|error| RoCrateError::ZipMemberIo {
                    operation: "decode ZIP symlink target",
                    archive: source.clone(),
                    index: archive_index,
                    member: entry_name.clone(),
                    source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
                })?;
                validate_symlink_target(&inner_path, &target).map_err(|source_error| {
                    RoCrateError::ZipMemberCore {
                        operation: "validate ZIP symlink target",
                        archive: Box::new(source.clone()),
                        index: archive_index,
                        member: Box::new(entry_name.clone()),
                        source: source_error,
                    }
                })?;
                ZipEntryKind::Symlink { target }
            } else if entry.is_file() {
                ZipEntryKind::File {
                    expected_size: entry.size(),
                }
            } else {
                return Err(RoCrateError::UnsupportedZipEntry {
                    archive: source.clone(),
                    index: archive_index,
                    member: entry_name,
                });
            };
            let default_permissions = match kind {
                ZipEntryKind::Directory => 0o755,
                ZipEntryKind::File { .. } | ZipEntryKind::Symlink { .. } => 0o644,
            };
            ZipEntryDescriptor {
                inner_path,
                metadata: EntryMetadata::new(
                    zip_timestamp(&entry),
                    zip_timestamp(&entry),
                    entry.unix_mode().unwrap_or(default_permissions) & VALID_PERMISSION_BITS,
                ),
                source: Some(ZipEntrySource {
                    archive_index,
                    member: entry_name,
                }),
                kind,
            }
        };
        if explicit_entries
            .insert(descriptor.inner_path.clone(), descriptor.clone())
            .is_some()
        {
            return Err(RoCrateError::DuplicateZipPath {
                archive: source.clone(),
                index: descriptor
                    .source
                    .as_ref()
                    .expect("explicit ZIP entries retain their source")
                    .archive_index,
                member: descriptor
                    .source
                    .as_ref()
                    .expect("explicit ZIP entries retain their source")
                    .member
                    .clone(),
                path: descriptor.inner_path,
            });
        }
    }
    let paths = explicit_entries.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        let mut parent = path.as_str();
        while let Some((parent_path, _)) = parent.rsplit_once('/') {
            if let Some(existing) = explicit_entries.get(parent_path) {
                if existing.kind != ZipEntryKind::Directory {
                    return Err(RoCrateError::ZipPathConflict {
                        archive: source.clone(),
                        index: existing
                            .source
                            .as_ref()
                            .expect("explicit ZIP entries retain their source")
                            .archive_index,
                        member: existing
                            .source
                            .as_ref()
                            .expect("explicit ZIP entries retain their source")
                            .member
                            .clone(),
                        path: parent_path.to_string(),
                    });
                }
            } else {
                explicit_entries.insert(
                    parent_path.to_string(),
                    ZipEntryDescriptor {
                        inner_path: parent_path.to_string(),
                        metadata: EntryMetadata::new(0, 0, 0o755),
                        source: None,
                        kind: ZipEntryKind::Directory,
                    },
                );
            }
            parent = parent_path;
        }
    }
    let metadata = explicit_entries
        .remove(RO_CRATE_METADATA_FILE)
        .ok_or_else(|| RoCrateError::MissingMetadata {
            path: source.clone(),
        })?;
    let (metadata_source, expected_size) = match (metadata.kind, metadata.source) {
        (ZipEntryKind::File { expected_size }, Some(source)) => (source, expected_size),
        (ZipEntryKind::Directory | ZipEntryKind::Symlink { .. }, Some(member_source)) => {
            return Err(RoCrateError::ZipMemberInvalidSource {
                archive: source,
                index: member_source.archive_index,
                member: member_source.member,
                expected: "regular metadata file",
            });
        }
        (ZipEntryKind::Directory | ZipEntryKind::Symlink { .. }, None) => {
            unreachable!("ZIP metadata is an explicit member")
        }
        (ZipEntryKind::File { .. }, None) => unreachable!("ZIP metadata is an explicit member"),
    };
    let mut metadata_member = archive
        .by_index(metadata_source.archive_index)
        .map_err(|error| RoCrateError::ZipMember {
            operation: "open RO-Crate metadata member",
            archive: source.clone(),
            index: metadata_source.archive_index,
            member: metadata_source.member.clone(),
            source: error,
        })?;
    let bytes = read_zip_limited(
        &mut metadata_member,
        expected_size,
        MAX_METADATA_BYTES,
        "read RO-Crate metadata member",
        source.clone(),
        metadata_source.archive_index,
        metadata_source.member.clone(),
    )?;
    let actual_size = u64::try_from(bytes.len()).map_err(|_| RoCrateError::ZipMemberCore {
        operation: "verify RO-Crate metadata size",
        archive: Box::new(source.clone()),
        index: metadata_source.archive_index,
        member: Box::new(metadata_source.member.clone()),
        source: PithosError::WriterSizeOverflow,
    })?;
    if actual_size != expected_size {
        return Err(RoCrateError::ZipMemberCore {
            operation: "verify RO-Crate metadata size",
            archive: Box::new(source.clone()),
            index: metadata_source.archive_index,
            member: Box::new(metadata_source.member.clone()),
            source: PithosError::WriterExpectedSizeMismatch {
                expected: expected_size,
                actual: actual_size,
            },
        });
    }
    let metadata = MetadataDescriptor {
        inner_path: metadata.inner_path,
        metadata: metadata.metadata,
        expected_size,
        bytes,
        source: MetadataSource::Zip(metadata_source),
    };
    let mut entries = explicit_entries.into_values().collect::<Vec<_>>();
    entries.sort_by(|left, right| {
        zip_kind_rank(&left.kind)
            .cmp(&zip_kind_rank(&right.kind))
            .then_with(|| {
                left.inner_path
                    .to_lowercase()
                    .cmp(&right.inner_path.to_lowercase())
            })
            .then_with(|| left.inner_path.cmp(&right.inner_path))
    });
    Ok(RoCrateZipManifest {
        source,
        metadata,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{CdcConfig, WriteOptions};
    use crate::crypto::PrivateKey;
    use std::cell::Cell;
    use std::io::{Cursor, SeekFrom};
    use std::rc::Rc;

    struct BoundedReader {
        inner: Cursor<Vec<u8>>,
        maximum_request: usize,
        largest_request: Rc<Cell<usize>>,
        reads: Rc<Cell<usize>>,
    }

    impl Read for BoundedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if buffer.len() > self.maximum_request {
                return Err(std::io::Error::other(
                    "ZIP member read exceeded stream bound",
                ));
            }
            self.largest_request
                .set(self.largest_request.get().max(buffer.len()));
            self.reads.set(self.reads.get() + 1);
            self.inner.read(buffer)
        }
    }

    impl Seek for BoundedReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.inner.seek(position)
        }
    }

    #[test]
    fn zip_member_conversion_reads_large_content_in_bounded_chunks() {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("ro-crate-metadata.json", options).unwrap();
        zip.write_all(b"{}").unwrap();
        zip.start_file("large.bin", options).unwrap();
        let mut state = 1u32;
        let payload = (0..(1024 * 1024 + 123))
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect::<Vec<_>>();
        zip.write_all(&payload).unwrap();
        let bytes = zip.finish().unwrap().into_inner();
        let largest_request = Rc::new(Cell::new(0));
        let reads = Rc::new(Cell::new(0));
        let reader = BoundedReader {
            inner: Cursor::new(bytes),
            maximum_request: 64 * 1024,
            largest_request: Rc::clone(&largest_request),
            reads: Rc::clone(&reads),
        };
        let mut archive = ZipArchive::new(reader).unwrap();
        let manifest =
            inspect_ro_crate_zip_archive_manifest(&mut archive, PathBuf::from("bounded.zip"))
                .unwrap();
        let sender = PrivateKey::generate();
        let mut writer = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
                .with_cdc(CdcConfig::new(64, 256, 1024).unwrap()),
        )
        .unwrap();
        write_ro_crate_zip_archive(
            &mut writer,
            &mut archive,
            manifest,
            ProcessingOptions::new(false, 0).unwrap(),
        )
        .unwrap();
        writer.finish().unwrap();
        assert!(reads.get() > 1);
        assert!(largest_request.get() <= 64 * 1024);
    }
}

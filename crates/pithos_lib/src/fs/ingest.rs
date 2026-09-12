use crate::archive::validate_symlink_target;
use crate::archive::{
    AppendSnapshot, ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriterError,
};
use crate::error::PithosError;
use crate::fs::FsError;
use cap_std::fs::{
    Dir, FileTypeExt as CapFileTypeExt, MetadataExt as CapMetadataExt,
    PermissionsExt as CapPermissionsExt,
};
use cap_std::time::{SystemClock, SystemTime as CapSystemTime};
use rustix::fs::{Mode, OFlags};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

fn archive_path(path: &Path) -> Result<ArchivePath, FsError> {
    let display_path = path.to_str().ok_or_else(|| FsError::InvalidUtf8Path {
        path: path.to_path_buf(),
    })?;
    let mut components = Vec::new();
    for component in path.components() {
        let Component::Normal(component) = component else {
            return Err(FsError::Core {
                operation: "validate archive path",
                path: path.to_path_buf(),
                source: PithosError::InvalidArchivePath {
                    path: display_path.to_owned(),
                    reason: "archive paths must contain only normal components".into(),
                },
            });
        };
        components.push(component.to_str().ok_or_else(|| FsError::InvalidUtf8Path {
            path: path.to_path_buf(),
        })?);
    }
    ArchivePath::new(components.join("/")).map_err(|source| FsError::Core {
        operation: "validate archive path",
        path: path.to_path_buf(),
        source,
    })
}

fn symlink_target(path: PathBuf) -> Result<String, FsError> {
    path.to_str()
        .map(str::to_owned)
        .ok_or(FsError::InvalidUtf8Path { path })
}

fn metadata(metadata: &fs::Metadata) -> EntryMetadata {
    let timestamp = |value: Result<SystemTime, std::io::Error>| {
        value
            .ok()
            .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs())
    };
    EntryMetadata::new(
        timestamp(metadata.created()),
        timestamp(metadata.modified()),
        metadata.permissions().mode() & 0o7777,
    )
}

fn cap_metadata(metadata: &cap_std::fs::Metadata) -> EntryMetadata {
    let timestamp = |value: Result<CapSystemTime, std::io::Error>| {
        value
            .ok()
            .and_then(|time| time.duration_since(SystemClock::UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_secs())
    };
    EntryMetadata::new(
        timestamp(metadata.created()),
        timestamp(metadata.modified()),
        metadata.permissions().mode() & 0o7777,
    )
}

fn open_regular_file_no_follow(path: &Path) -> std::io::Result<File> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(File::from)
}

fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type().is_file()
        && right.file_type().is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
}

fn open_directory_no_follow(path: &Path) -> std::io::Result<Dir> {
    rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .map(|fd| Dir::from_std_file(File::from(fd)))
}

fn open_at_no_follow(parent: &Dir, name: &Path, directory: bool) -> std::io::Result<File> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let flags = if directory {
        flags | OFlags::DIRECTORY
    } else {
        flags
    };
    rustix::fs::openat(parent, name, flags, Mode::empty())
        .map_err(std::io::Error::from)
        .map(File::from)
}

fn same_cap_file_identity(left: &cap_std::fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino()
}

enum ManifestKind {
    File { expected_size: u64 },
    Directory,
    Symlink { target: String },
}

struct ManifestEntry {
    source: Option<PathBuf>,
    source_key: Option<u64>,
    path: ArchivePath,
    metadata: EntryMetadata,
    kind: ManifestKind,
}

/// A complete, validated filesystem-to-archive mapping.
///
/// Synthetic directory parents use deterministic zero timestamps and mode 0755.
pub struct InputManifest {
    entries: Vec<ManifestEntry>,
    sources: BTreeMap<u64, File>,
}

impl InputManifest {
    /// Materialize the already validated manifest with typed writer operations.
    /// A filesystem race after preflight is still reported to the caller.
    pub fn ingest<W: std::io::Write>(
        &self,
        writer: &mut ArchiveWriter<W>,
        processing: ProcessingOptions,
    ) -> Result<(), WriterError> {
        for entry in &self.entries {
            match &entry.kind {
                ManifestKind::File { expected_size } => {
                    let source = self.source(entry)?;
                    writer.add_file(
                        entry.path.clone(),
                        entry.metadata.clone(),
                        processing,
                        Some(*expected_size),
                        source.try_clone().map_err(PithosError::Io)?,
                    )?;
                }
                ManifestKind::Directory => {
                    writer.add_directory(entry.path.clone(), entry.metadata.clone())?;
                }
                ManifestKind::Symlink { target } => {
                    writer.add_symlink(
                        entry.path.clone(),
                        entry.metadata.clone(),
                        target.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }

    /// Executes a preassigned append plan. The ID assertion occurs before a source is cloned
    /// or read, so a stale plan cannot consume filesystem content.
    pub(crate) fn ingest_planned<W: std::io::Write>(
        &self,
        ids: &[u64],
        writer: &mut ArchiveWriter<W>,
        processing: ProcessingOptions,
    ) -> Result<(), WriterError> {
        if ids.len() != self.entries.len() {
            return Err(PithosError::AppendPlanLengthMismatch.into());
        }
        writer.prepare_planned_ids(ids)?;
        for (entry, id) in self.entries.iter().zip(ids) {
            match &entry.kind {
                ManifestKind::File { expected_size } => {
                    let source = self.source(entry)?;
                    writer.add_file_planned(
                        *id,
                        entry.path.clone(),
                        entry.metadata.clone(),
                        processing,
                        Some(*expected_size),
                        source.try_clone().map_err(PithosError::Io)?,
                    )?;
                }
                ManifestKind::Directory => {
                    writer.add_directory_planned(
                        *id,
                        entry.path.clone(),
                        entry.metadata.clone(),
                    )?;
                }
                ManifestKind::Symlink { target } => {
                    writer.add_symlink_planned(
                        *id,
                        entry.path.clone(),
                        entry.metadata.clone(),
                        target.clone(),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn source(&self, entry: &ManifestEntry) -> Result<&File, WriterError> {
        entry
            .source_key
            .and_then(|key| self.sources.get(&key))
            .ok_or_else(|| PithosError::MissingManifestSource.into())
    }

    pub(crate) fn source_with_identity(&self, device: u64, inode: u64) -> Option<&Path> {
        self.entries.iter().find_map(|entry| match &entry.kind {
            ManifestKind::File { .. } => {
                let metadata = self.source(entry).ok()?.metadata().ok()?;
                (metadata.dev() == device && metadata.ino() == inode)
                    .then_some(entry.source.as_deref())
                    .flatten()
            }
            ManifestKind::Directory | ManifestKind::Symlink { .. } => None,
        })
    }

    /// Check every planned entry against the complete validated ancestor before streaming.
    pub(crate) fn validate_append(
        &self,
        snapshot: &AppendSnapshot,
    ) -> Result<Vec<u64>, PithosError> {
        let entry_count =
            u64::try_from(self.entries.len()).map_err(|_| PithosError::FileIdExhausted)?;
        if snapshot
            .maximum_id()
            .is_some_and(|id| id.0.checked_add(entry_count).is_none())
        {
            return Err(PithosError::FileIdExhausted);
        }
        let mut next_id = snapshot
            .maximum_id()
            .map_or(Some(0), |id| id.0.checked_add(1));
        let mut ids = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            snapshot.ensure_path_available(&entry.path)?;
            snapshot.ensure_candidate_hierarchy(
                &entry.path,
                matches!(&entry.kind, ManifestKind::Directory),
            )?;
            let id = next_id.ok_or(PithosError::FileIdExhausted)?;
            ids.push(id);
            next_id = id.checked_add(1);
        }
        Ok(ids)
    }
}

fn manifest_entry(
    source: PathBuf,
    path: ArchivePath,
    sources: &mut BTreeMap<u64, File>,
    next_source_key: &mut u64,
) -> Result<ManifestEntry, FsError> {
    let host = fs::symlink_metadata(&source).map_err(|source_error| FsError::Host {
        operation: "inspect input",
        path: source.clone(),
        source: source_error,
    })?;
    let (metadata, kind, source_key) = if host.file_type().is_dir() {
        (metadata(&host), ManifestKind::Directory, None)
    } else if host.file_type().is_symlink() {
        let target =
            symlink_target(
                fs::read_link(&source).map_err(|source_error| FsError::Host {
                    operation: "read symlink",
                    path: source.clone(),
                    source: source_error,
                })?,
            )?;
        validate_symlink_target(path.as_str(), &target).map_err(|source_error| FsError::Core {
            operation: "validate symlink",
            path: source.clone(),
            source: source_error,
        })?;
        (metadata(&host), ManifestKind::Symlink { target }, None)
    } else if host.file_type().is_file() {
        let file = open_regular_file_no_follow(&source).map_err(|source_error| FsError::Host {
            operation: "open input",
            path: source.clone(),
            source: source_error,
        })?;
        let opened = file.metadata().map_err(|source_error| FsError::Host {
            operation: "inspect input",
            path: source.clone(),
            source: source_error,
        })?;
        if !same_file_identity(&host, &opened) {
            return Err(FsError::UnsupportedEntry {
                path: source,
                kind: "entry changed while opening",
            });
        }
        let expected_size = opened.len();
        let source_key = *next_source_key;
        *next_source_key = source_key.checked_add(1).ok_or_else(|| FsError::Core {
            operation: "allocate source identity",
            path: source.clone(),
            source: PithosError::FileIdExhausted,
        })?;
        sources.insert(source_key, file);
        (
            metadata(&opened),
            ManifestKind::File { expected_size },
            Some(source_key),
        )
    } else {
        let kind = if host.file_type().is_fifo() {
            "FIFO"
        } else if host.file_type().is_socket() {
            "socket"
        } else if host.file_type().is_block_device() {
            "block device"
        } else if host.file_type().is_char_device() {
            "character device"
        } else {
            "special entry"
        };
        return Err(FsError::UnsupportedEntry { path: source, kind });
    };
    Ok(ManifestEntry {
        source: Some(source),
        source_key,
        path,
        metadata,
        kind,
    })
}

fn collect_directory_manifest(
    directory: &Dir,
    source_root: &Path,
    prefix: &Path,
    entries: &mut BTreeMap<ArchivePath, ManifestEntry>,
    sources: &mut BTreeMap<u64, File>,
    next_source_key: &mut u64,
) -> Result<(), FsError> {
    let mut pending = vec![(
        (directory.try_clone()).map_err(|source| FsError::Host {
            operation: "retain input directory",
            path: source_root.join(prefix),
            source,
        })?,
        prefix.to_path_buf(),
    )];
    while let Some((directory, prefix)) = pending.pop() {
        let directory_path = source_root.join(&prefix);
        let mut children = directory
            .read_dir(".")
            .map_err(|source| FsError::Host {
                operation: "read input directory",
                path: directory_path.clone(),
                source,
            })?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|source| FsError::Host {
                operation: "read input directory entry",
                path: directory_path,
                source,
            })?;
        children.sort_by_key(|entry| entry.file_name());
        let mut child_directories = Vec::new();
        for child in children {
            let name = child.file_name();
            let relative = prefix.join(&name);
            let source = source_root.join(&relative);
            let path = archive_path(&relative)?;
            let host = directory
                .symlink_metadata(&name)
                .map_err(|source_error| FsError::Host {
                    operation: "inspect input",
                    path: source.clone(),
                    source: source_error,
                })?;
            let entry = if host.file_type().is_dir() {
                let opened = open_at_no_follow(&directory, Path::new(&name), true).map_err(
                    |source_error| FsError::Host {
                        operation: "open input directory",
                        path: source.clone(),
                        source: source_error,
                    },
                )?;
                let opened_metadata = opened.metadata().map_err(|source_error| FsError::Host {
                    operation: "inspect opened input directory",
                    path: source.clone(),
                    source: source_error,
                })?;
                if !opened_metadata.file_type().is_dir()
                    || !same_cap_file_identity(&host, &opened_metadata)
                {
                    return Err(FsError::UnsupportedEntry {
                        path: source,
                        kind: "entry changed while opening",
                    });
                }
                child_directories.push((Dir::from_std_file(opened), relative));
                ManifestEntry {
                    source: Some(source),
                    source_key: None,
                    path,
                    metadata: metadata(&opened_metadata),
                    kind: ManifestKind::Directory,
                }
            } else if host.file_type().is_file() {
                let file = open_at_no_follow(&directory, Path::new(&name), false).map_err(
                    |source_error| FsError::Host {
                        operation: "open input",
                        path: source.clone(),
                        source: source_error,
                    },
                )?;
                let opened = file.metadata().map_err(|source_error| FsError::Host {
                    operation: "inspect opened input",
                    path: source.clone(),
                    source: source_error,
                })?;
                if !opened.file_type().is_file() || !same_cap_file_identity(&host, &opened) {
                    return Err(FsError::UnsupportedEntry {
                        path: source,
                        kind: "entry changed while opening",
                    });
                }
                let source_key = *next_source_key;
                *next_source_key = source_key.checked_add(1).ok_or_else(|| FsError::Core {
                    operation: "allocate source identity",
                    path: source.clone(),
                    source: PithosError::FileIdExhausted,
                })?;
                sources.insert(source_key, file);
                ManifestEntry {
                    source: Some(source),
                    source_key: Some(source_key),
                    path,
                    metadata: metadata(&opened),
                    kind: ManifestKind::File {
                        expected_size: opened.len(),
                    },
                }
            } else if host.file_type().is_symlink() {
                let target = symlink_target(directory.read_link_contents(&name).map_err(
                    |source_error| FsError::Host {
                        operation: "read symlink",
                        path: source.clone(),
                        source: source_error,
                    },
                )?)?;
                let current =
                    directory
                        .symlink_metadata(&name)
                        .map_err(|source_error| FsError::Host {
                            operation: "inspect read symlink",
                            path: source.clone(),
                            source: source_error,
                        })?;
                if !current.file_type().is_symlink()
                    || current.dev() != host.dev()
                    || current.ino() != host.ino()
                {
                    return Err(FsError::UnsupportedEntry {
                        path: source,
                        kind: "entry changed while reading symlink",
                    });
                }
                validate_symlink_target(path.as_str(), &target).map_err(|source_error| {
                    FsError::Core {
                        operation: "validate symlink",
                        path: source.clone(),
                        source: source_error,
                    }
                })?;
                ManifestEntry {
                    source: Some(source),
                    source_key: None,
                    path,
                    metadata: cap_metadata(&host),
                    kind: ManifestKind::Symlink { target },
                }
            } else {
                let kind = if host.file_type().is_fifo() {
                    "FIFO"
                } else if host.file_type().is_socket() {
                    "socket"
                } else if host.file_type().is_block_device() {
                    "block device"
                } else if host.file_type().is_char_device() {
                    "character device"
                } else {
                    "special entry"
                };
                return Err(FsError::UnsupportedEntry { path: source, kind });
            };
            insert_entry(entries, entry)?;
        }
        pending.extend(child_directories.into_iter().rev());
    }
    Ok(())
}

fn insert_entry(
    entries: &mut BTreeMap<ArchivePath, ManifestEntry>,
    entry: ManifestEntry,
) -> Result<(), FsError> {
    let path = entry.path.clone();
    if let Some(existing) = entries.get(&path) {
        if matches!(&existing.kind, ManifestKind::Directory)
            != matches!(&entry.kind, ManifestKind::Directory)
        {
            return Err(FsError::Core {
                operation: "validate input hierarchy",
                path: PathBuf::from(path.as_str()),
                source: PithosError::InvalidArchivePath {
                    path: path.as_str().to_owned(),
                    reason: "directory conflicts with a non-directory entry".into(),
                },
            });
        }
        return Err(FsError::Core {
            operation: "validate input hierarchy",
            path: PathBuf::from(path.as_str()),
            source: PithosError::PathOccupied(path.as_str().to_owned()),
        });
    }
    entries.insert(path, entry);
    Ok(())
}

fn add_synthetic_parents(
    entries: &mut BTreeMap<ArchivePath, ManifestEntry>,
) -> Result<(), FsError> {
    let paths = entries.keys().cloned().collect::<Vec<_>>();
    for path in paths {
        let components = path.as_str().split('/').collect::<Vec<_>>();
        for depth in 1..components.len() {
            let parent = ArchivePath::new(components[..depth].join("/")).map_err(|source| {
                FsError::Core {
                    operation: "construct synthetic parent",
                    path: PathBuf::from(path.as_str()),
                    source,
                }
            })?;
            match entries.get(&parent) {
                Some(ManifestEntry {
                    kind: ManifestKind::Directory,
                    ..
                }) => {}
                Some(_) => {
                    return Err(FsError::Core {
                        operation: "validate input hierarchy",
                        path: PathBuf::from(path.as_str()),
                        source: PithosError::InvalidArchivePath {
                            path: path.as_str().to_owned(),
                            reason: format!(
                                "non-directory entry {} is an ancestor",
                                parent.as_str()
                            ),
                        },
                    });
                }
                None => {
                    entries.insert(
                        parent.clone(),
                        ManifestEntry {
                            source: None,
                            source_key: None,
                            path: parent,
                            metadata: EntryMetadata::new(0, 0, 0o755),
                            kind: ManifestKind::Directory,
                        },
                    );
                }
            }
        }
    }
    Ok(())
}

fn validate_hierarchy(entries: &BTreeMap<ArchivePath, ManifestEntry>) -> Result<(), FsError> {
    let mut ordered = entries.iter();
    let Some((mut previous_path, mut previous_entry)) = ordered.next() else {
        return Ok(());
    };
    for (path, entry) in ordered {
        if !matches!(&previous_entry.kind, ManifestKind::Directory)
            && previous_path.is_ancestor_of(path)
        {
            return Err(FsError::Core {
                operation: "validate input hierarchy",
                path: PathBuf::from(previous_path.as_str()),
                source: PithosError::InvalidArchivePath {
                    path: previous_path.as_str().to_owned(),
                    reason: "a non-directory entry has descendants".into(),
                },
            });
        }
        previous_path = path;
        previous_entry = entry;
    }
    Ok(())
}

/// Build and validate the complete create-side filesystem manifest without
/// opening an output sink.
pub fn build_input_manifest(inputs: &[PathBuf]) -> Result<InputManifest, FsError> {
    let mut manifest = BTreeMap::new();
    let mut sources = BTreeMap::new();
    let mut next_source_key = 0;
    for source in inputs {
        let root = fs::symlink_metadata(source).map_err(|source_error| FsError::Host {
            operation: "inspect input",
            path: source.clone(),
            source: source_error,
        })?;
        // The root directory is not an archive entry, but its metadata must still
        // be readable before output creation.
        let _ = metadata(&root);
        if root.file_type().is_dir() {
            let directory =
                open_directory_no_follow(source).map_err(|source_error| FsError::Host {
                    operation: "open input directory",
                    path: source.clone(),
                    source: source_error,
                })?;
            let opened = directory
                .symlink_metadata(".")
                .map_err(|source_error| FsError::Host {
                    operation: "inspect opened input directory",
                    path: source.clone(),
                    source: source_error,
                })?;
            if !opened.file_type().is_dir()
                || root.dev() != opened.dev()
                || root.ino() != opened.ino()
            {
                return Err(FsError::UnsupportedEntry {
                    path: source.clone(),
                    kind: "entry changed while opening",
                });
            }
            collect_directory_manifest(
                &directory,
                source,
                Path::new(""),
                &mut manifest,
                &mut sources,
                &mut next_source_key,
            )?;
        } else {
            let name = source.file_name().ok_or_else(|| FsError::InvalidUtf8Path {
                path: source.clone(),
            })?;
            let path = archive_path(Path::new(name))?;
            insert_entry(
                &mut manifest,
                manifest_entry(source.clone(), path, &mut sources, &mut next_source_key)?,
            )?;
        }
    }
    add_synthetic_parents(&mut manifest)?;
    validate_hierarchy(&manifest)?;
    Ok(InputManifest {
        entries: manifest.into_values().collect(),
        sources,
    })
}

/// Ingest one filesystem entry using its validated archive path.
pub fn ingest_path<W: std::io::Write>(
    writer: &mut ArchiveWriter<W>,
    source: &Path,
    path: ArchivePath,
    processing: ProcessingOptions,
) -> Result<(), FsError> {
    let mut sources = BTreeMap::new();
    let entry = manifest_entry(source.to_path_buf(), path, &mut sources, &mut 0)?;
    InputManifest {
        entries: vec![entry],
        sources,
    }
    .ingest(writer, processing)
    .map_err(|source| FsError::Writer {
        operation: "ingest input",
        archive_path: "input".to_owned(),
        source,
    })
}

/// Ingest a directory recursively after validating its complete manifest.
pub fn ingest_directory<W: std::io::Write>(
    writer: &mut ArchiveWriter<W>,
    source: &Path,
    processing: ProcessingOptions,
) -> Result<(), FsError> {
    let archive_path = source.display().to_string();
    build_input_manifest(&[source.to_path_buf()])?
        .ingest(writer, processing)
        .map_err(|source| FsError::Writer {
            operation: "ingest directory",
            archive_path,
            source,
        })
}

/// Validate the complete create-side filesystem manifest without opening an
/// output sink. Prefer [`build_input_manifest`] when the manifest will be used.
pub fn validate_input_manifest(inputs: &[PathBuf]) -> Result<(), FsError> {
    build_input_manifest(inputs).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_parents_are_deterministic() {
        let path = ArchivePath::new("nested/child/file").unwrap();
        let mut entries = BTreeMap::new();
        entries.insert(
            path.clone(),
            ManifestEntry {
                source: Some(PathBuf::from("file")),
                source_key: None,
                path,
                metadata: EntryMetadata::new(1, 2, 0o644),
                kind: ManifestKind::File { expected_size: 0 },
            },
        );

        add_synthetic_parents(&mut entries).unwrap();

        let paths = entries.keys().map(|path| path.as_str()).collect::<Vec<_>>();
        assert_eq!(paths, ["nested", "nested/child", "nested/child/file"]);
        for path in ["nested", "nested/child"] {
            let entry = entries.get(&ArchivePath::new(path).unwrap()).unwrap();
            assert!(entry.source.is_none());
            assert!(matches!(&entry.kind, ManifestKind::Directory));
            assert_eq!(entry.metadata, EntryMetadata::new(0, 0, 0o755));
        }
    }
}

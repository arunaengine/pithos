use crate::error::PithosError;
use rocraters::ro_crate::read::{read_crate, read_crate_obj};
pub use rocraters::ro_crate::rocrate::RoCrate;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use zip::{CompressionMethod, ZipArchive};

pub const RO_CRATE_METADATA_FILE: &str = "ro-crate-metadata.json";

const VALIDATE_AND_WARN: i8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoCrateSource {
    Directory(PathBuf),
    Zip(PathBuf),
}

#[derive(Debug, Clone)]
pub struct LoadedRoCrate {
    pub ro_crate: RoCrate,
    pub source: RoCrateSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipEntryKind {
    Directory,
    File,
    Symlink,
}

#[derive(Debug, Clone)]
pub(crate) struct ZipEntryDescriptor {
    pub archive_index: Option<usize>,
    pub inner_path: String,
    pub kind: ZipEntryKind,
    pub uncompressed_size: u64,
    pub timestamp: u64,
    pub permissions: u32,
}

#[derive(Debug)]
pub(crate) struct RoCrateZipManifest {
    pub metadata: ZipEntryDescriptor,
    pub entries: Vec<ZipEntryDescriptor>,
}

pub fn read_ro_crate_directory(path: impl AsRef<Path>) -> Result<LoadedRoCrate, PithosError> {
    let source = path.as_ref().to_path_buf();
    let source_metadata = std::fs::symlink_metadata(&source)?;
    if !source_metadata.is_dir() {
        return Err(PithosError::InvalidRoCrateSource {
            path: source,
            expected: "directory",
        });
    }

    let metadata_path = source.join(RO_CRATE_METADATA_FILE);
    let metadata =
        std::fs::symlink_metadata(&metadata_path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => PithosError::MissingRoCrateMetadata(source.clone()),
            _ => PithosError::Io(error),
        })?;
    if !metadata.file_type().is_file() {
        return Err(PithosError::InvalidRoCrateSource {
            path: metadata_path,
            expected: "regular metadata file",
        });
    }

    let ro_crate = read_crate(&metadata_path, VALIDATE_AND_WARN)?;
    Ok(LoadedRoCrate {
        ro_crate,
        source: RoCrateSource::Directory(source),
    })
}

pub fn read_ro_crate_zip(path: impl AsRef<Path>) -> Result<LoadedRoCrate, PithosError> {
    let source = path.as_ref().to_path_buf();
    let source_metadata = std::fs::symlink_metadata(&source)?;
    if !source_metadata.file_type().is_file() {
        return Err(PithosError::InvalidRoCrateSource {
            path: source,
            expected: "ZIP file",
        });
    }

    let manifest = inspect_ro_crate_zip_manifest(&source)?;
    let metadata_index = manifest
        .metadata
        .archive_index
        .ok_or_else(|| PithosError::MissingRoCrateMetadata(source.clone()))?;

    let mut archive = ZipArchive::new(File::open(&source)?)?;
    let mut metadata = archive.by_index(metadata_index)?;
    let mut json = String::new();
    metadata.read_to_string(&mut json)?;
    let ro_crate = read_crate_obj(&json, VALIDATE_AND_WARN)?;

    Ok(LoadedRoCrate {
        ro_crate,
        source: RoCrateSource::Zip(source),
    })
}

fn normalize_zip_path(path: &Path) -> Result<String, ()> {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            Component::Normal(component) => {
                components.push(component.to_str().ok_or(())?.to_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if components.pop().is_none() {
                    return Err(());
                }
            }
            Component::RootDir | Component::Prefix(_) => return Err(()),
        }
    }

    if components.is_empty() {
        return Err(());
    }

    Ok(components.join("/"))
}

fn has_forbidden_zip_root_or_prefix(path: &Path, name: &str) -> bool {
    if path
        .components()
        .any(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
    {
        return true;
    }

    // ZIP paths use Windows-style syntax even when the host is Unix.
    name.starts_with('/')
        || name.starts_with('\\')
        || name.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

fn zip_timestamp<R: std::io::Read + ?Sized>(entry: &zip::read::ZipFile<'_, R>) -> u64 {
    let Some(date_time) = entry.last_modified() else {
        return 0;
    };
    if !date_time.is_valid() {
        return 0;
    }

    // ZIP DOS timestamps have no timezone. Treating them as UTC makes the
    // stored value stable across machines and extraction environments.
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
    if timestamp < 0 { 0 } else { timestamp as u64 }
}

fn zip_entry_kind_rank(kind: ZipEntryKind) -> u8 {
    match kind {
        ZipEntryKind::Directory => 0,
        ZipEntryKind::File => 1,
        ZipEntryKind::Symlink => 2,
    }
}

pub(crate) fn inspect_ro_crate_zip_manifest(
    path: impl AsRef<Path>,
) -> Result<RoCrateZipManifest, PithosError> {
    let source = path.as_ref().to_path_buf();
    let file = File::open(&source)?;
    let mut archive = ZipArchive::new(file)?;

    if archive.has_overlapping_files()? {
        return Err(PithosError::OverlappingZipEntries(source));
    }

    let mut explicit_entries = BTreeMap::new();
    let mut metadata = None;

    for archive_index in 0..archive.len() {
        let descriptor = {
            let entry = archive.by_index(archive_index)?;
            let entry_name = entry.name().to_string();

            if entry.encrypted() {
                return Err(PithosError::EncryptedZipEntry(entry_name));
            }
            if !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            ) {
                return Err(PithosError::UnsupportedZipEntry(entry_name));
            }

            let enclosed_name = entry
                .enclosed_name()
                .ok_or_else(|| PithosError::UnsafeZipPath(entry_name.clone()))?;
            if entry_name.as_bytes().contains(&0)
                || has_forbidden_zip_root_or_prefix(&enclosed_name, &entry_name)
            {
                return Err(PithosError::UnsafeZipPath(entry_name.clone()));
            }
            let inner_path = normalize_zip_path(&enclosed_name)
                .map_err(|_| PithosError::UnsafeZipPath(entry_name.clone()))?;

            let kind = if entry.is_dir() {
                ZipEntryKind::Directory
            } else if entry.is_symlink() {
                ZipEntryKind::Symlink
            } else if entry.is_file() {
                ZipEntryKind::File
            } else {
                return Err(PithosError::UnsupportedZipEntry(entry_name));
            };

            let default_permissions = match kind {
                ZipEntryKind::Directory => 0o755,
                ZipEntryKind::File | ZipEntryKind::Symlink => 0o644,
            };
            ZipEntryDescriptor {
                archive_index: Some(archive_index),
                inner_path,
                kind,
                uncompressed_size: if matches!(kind, ZipEntryKind::Directory) {
                    0
                } else {
                    entry.size()
                },
                timestamp: zip_timestamp(&entry),
                permissions: match entry.unix_mode() {
                    Some(permissions) => permissions,
                    None => default_permissions,
                },
            }
        };

        if explicit_entries
            .insert(descriptor.inner_path.clone(), descriptor.clone())
            .is_some()
        {
            return Err(PithosError::DuplicateZipPath(descriptor.inner_path));
        }

        if descriptor.inner_path == RO_CRATE_METADATA_FILE {
            if descriptor.kind == ZipEntryKind::File {
                metadata = Some(descriptor);
            } else {
                return Err(PithosError::InvalidRoCrateSource {
                    path: source.join(RO_CRATE_METADATA_FILE),
                    expected: "regular metadata file",
                });
            }
        }
    }

    let explicit_paths: Vec<String> = explicit_entries.keys().cloned().collect();
    for path in explicit_paths {
        let mut parent = path.as_str();
        while let Some((parent_path, _)) = parent.rsplit_once('/') {
            if let Some(existing) = explicit_entries.get(parent_path) {
                if existing.kind != ZipEntryKind::Directory {
                    return Err(PithosError::ZipPathConflict(parent_path.to_string()));
                }
            } else {
                explicit_entries.insert(
                    parent_path.to_string(),
                    ZipEntryDescriptor {
                        archive_index: None,
                        inner_path: parent_path.to_string(),
                        kind: ZipEntryKind::Directory,
                        uncompressed_size: 0,
                        timestamp: 0,
                        permissions: 0o755,
                    },
                );
            }
            parent = parent_path;
        }
    }

    let metadata = metadata.ok_or_else(|| PithosError::MissingRoCrateMetadata(source.clone()))?;

    let mut entries: Vec<_> = explicit_entries
        .into_values()
        .filter(|entry| entry.inner_path != RO_CRATE_METADATA_FILE)
        .collect();
    entries.sort_by(|left, right| {
        zip_entry_kind_rank(left.kind)
            .cmp(&zip_entry_kind_rank(right.kind))
            .then_with(|| {
                left.inner_path
                    .to_lowercase()
                    .cmp(&right.inner_path.to_lowercase())
            })
            .then_with(|| left.inner_path.cmp(&right.inner_path))
    });

    Ok(RoCrateZipManifest { metadata, entries })
}

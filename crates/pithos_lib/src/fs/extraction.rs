use super::FsError;
use crate::archive::{Archive, EntryKind, ExternalBlockResolver};
use crate::source::ArchiveSource;
use cap_std::fs::Dir;
use rustix::fs::{AtFlags, Mode, OFlags, fchmod, linkat, openat};
use std::cmp::Reverse;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

/// Options controlling filesystem extraction behavior.
#[derive(Clone, Copy, Debug, Default)]
pub struct ExtractionOptions {
    special_permissions: bool,
}

impl ExtractionOptions {
    /// Opt in to restoring setuid, setgid, and sticky permission bits.
    pub fn with_special_permissions(mut self) -> Self {
        self.special_permissions = true;
        self
    }
}

fn applied_mode(stored_permissions: u32, options: ExtractionOptions) -> Mode {
    let mask = if options.special_permissions {
        0o7777
    } else {
        0o0777
    };
    Mode::from(stored_permissions & mask)
}

fn open_dir_no_follow(parent: &Dir, component: &Path) -> io::Result<Dir> {
    rustix::fs::openat(
        parent,
        component,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .map(|fd| Dir::from_std_file(std::fs::File::from(fd)))
}

/// Extract one validated archive entry through a capability-confined destination.
pub fn extract<S, E>(
    archive: &Archive<S, E>,
    archive_path: &str,
    destination: &Path,
) -> Result<(), FsError>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    extract_with_options(
        archive,
        archive_path,
        destination,
        ExtractionOptions::default(),
    )
}

/// Extract one validated archive entry with explicit extraction options.
pub fn extract_with_options<S, E>(
    archive: &Archive<S, E>,
    archive_path: &str,
    destination: &Path,
    options: ExtractionOptions,
) -> Result<(), FsError>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    let entry = archive
        .entry(archive_path)
        .map_err(|source| FsError::Archive {
            operation: "look up",
            archive_path: archive_path.to_owned(),
            destination: destination.to_path_buf(),
            source: Box::new(source),
        })?
        .ok_or_else(|| FsError::Archive {
            operation: "look up",
            archive_path: archive_path.to_owned(),
            destination: destination.to_path_buf(),
            source: Box::new(crate::error::PithosError::FileNotFound(
                archive_path.to_owned(),
            )),
        })?;
    let root = ExtractionRoot::open(destination, true, archive_path)?;
    let mode = applied_mode(entry.permissions, options);
    match entry.kind {
        EntryKind::File { .. } | EntryKind::Metadata { .. } => {
            let pending = root.pending_file(archive_path)?;
            let mut writer = pending.writer(archive_path)?;
            archive
                .copy_to(archive_path, &mut writer)
                .map_err(|source| root.archive_error("copy", archive_path, source))?;
            pending.commit(archive_path, mode)?;
        }
        EntryKind::Directory => root.create_dir(archive_path, mode)?,
        EntryKind::Symlink { target } => root.create_symlink(archive_path, &target)?,
    }
    Ok(())
}

/// Extract every archive entry in declaration order through one destination root.
pub fn extract_all<S, E>(archive: &Archive<S, E>, destination: &Path) -> Result<(), FsError>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    extract_all_with_options(archive, destination, ExtractionOptions::default())
}

/// Extract every archive entry in declaration order with explicit options.
pub fn extract_all_with_options<S, E>(
    archive: &Archive<S, E>,
    destination: &Path,
    options: ExtractionOptions,
) -> Result<(), FsError>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    let root = ExtractionRoot::open(destination, true, "<all>")?;
    let mut directories = Vec::new();

    for entry in archive.entries() {
        let path = entry.path;
        let mode = applied_mode(entry.permissions, options);
        match entry.kind {
            EntryKind::File { .. } | EntryKind::Metadata { .. } => {
                let pending = root.pending_file(&path)?;
                let mut writer = pending.writer(&path)?;
                archive
                    .copy_to(&path, &mut writer)
                    .map_err(|source| root.archive_error("copy", &path, source))?;
                pending.commit(&path, mode)?;
            }
            EntryKind::Directory => {
                let directory = root.create_dir_open(&path)?;
                fchmod(&directory, Mode::RWXU).map_err(|source| {
                    root.operation("set temporary directory permissions", &path, source.into())
                })?;
                directories.push(PendingDirectory {
                    path,
                    directory,
                    mode,
                });
            }
            EntryKind::Symlink { target } => root.create_symlink(&path, &target)?,
        }
    }

    directories.sort_by_key(|directory| Reverse(directory.path.split('/').count()));
    for directory in directories {
        fchmod(&directory.directory, directory.mode).map_err(|source| {
            root.operation("set directory permissions", &directory.path, source.into())
        })?;
    }
    Ok(())
}

pub(crate) struct ExtractionRoot {
    root: Dir,
    destination: PathBuf,
}

impl ExtractionRoot {
    pub(crate) fn open(path: &Path, create: bool, archive_path: &str) -> Result<Self, FsError> {
        let base = if path.is_absolute() {
            Path::new("/")
        } else {
            Path::new(".")
        };
        let mut root = rustix::fs::open(
            base,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)
        .map(|fd| Dir::from_std_file(std::fs::File::from(fd)))
        .map_err(|source| FsError::Operation {
            operation: "open destination",
            archive_path: archive_path.to_owned(),
            destination: path.to_path_buf(),
            source,
        })?;
        for component in path.components() {
            let Component::Normal(component) = component else {
                if matches!(component, Component::ParentDir) {
                    return Err(FsError::Operation {
                        operation: "open destination",
                        archive_path: archive_path.to_owned(),
                        destination: path.to_path_buf(),
                        source: io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "destination path contains parent traversal",
                        ),
                    });
                }
                continue;
            };
            let component = Path::new(component);
            root = match open_dir_no_follow(&root, component) {
                Ok(directory) => directory,
                Err(error) if create && error.kind() == io::ErrorKind::NotFound => {
                    match root.create_dir(component) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(source) => {
                            return Err(FsError::Operation {
                                operation: "create destination",
                                archive_path: archive_path.to_owned(),
                                destination: path.to_path_buf(),
                                source,
                            });
                        }
                    }
                    open_dir_no_follow(&root, component).map_err(|source| FsError::Operation {
                        operation: "open destination",
                        archive_path: archive_path.to_owned(),
                        destination: path.to_path_buf(),
                        source,
                    })?
                }
                Err(source) => {
                    return Err(FsError::Operation {
                        operation: "open destination",
                        archive_path: archive_path.to_owned(),
                        destination: path.to_path_buf(),
                        source,
                    });
                }
            };
        }
        Ok(Self {
            root,
            destination: path.to_path_buf(),
        })
    }

    fn operation(&self, operation: &'static str, archive_path: &str, source: io::Error) -> FsError {
        FsError::Operation {
            operation,
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            source,
        }
    }

    fn archive_error(
        &self,
        operation: &'static str,
        archive_path: &str,
        source: crate::error::PithosError,
    ) -> FsError {
        FsError::Archive {
            operation,
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            source: Box::new(source),
        }
    }

    fn collision(&self, archive_path: &str, reason: &'static str) -> FsError {
        FsError::ExtractionCollision {
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            reason,
        }
    }

    fn parents(&self, path: &str) -> Result<(Dir, String), FsError> {
        let mut components = path.split('/').peekable();
        let final_name = components
            .next_back()
            .ok_or_else(|| self.collision(path, "empty final component"))?;
        let mut dir = self
            .root
            .try_clone()
            .map_err(|source| self.operation("open destination parent", path, source))?;
        for component in components {
            if component.is_empty() || component == "." || component == ".." {
                return Err(self.collision(path, "invalid component"));
            }
            match open_dir_no_follow(&dir, Path::new(component)) {
                Ok(child) => dir = child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    match dir.create_dir(component) {
                        Ok(()) => {}
                        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                        Err(source) => {
                            return Err(self.operation("create destination parent", path, source));
                        }
                    }
                    dir = open_dir_no_follow(&dir, Path::new(component)).map_err(|source| {
                        self.operation("open destination parent", path, source)
                    })?;
                }
                Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
                    return Err(self.collision(path, "parent is a symlink"));
                }
                Err(source) if source.kind() == io::ErrorKind::NotADirectory => {
                    return Err(self.collision(path, "parent is not a directory"));
                }
                Err(source) => return Err(self.operation("open destination parent", path, source)),
            }
        }
        Ok((dir, final_name.to_string()))
    }

    fn create_dir_open(&self, path: &str) -> Result<Dir, FsError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => Err(self.collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent
                    .create_dir(&name)
                    .map_err(|source| self.operation("create directory", path, source))?;
                open_dir_no_follow(&parent, Path::new(&name))
                    .map_err(|source| self.operation("open directory", path, source))
            }
            Err(source) => Err(self.operation("inspect destination entry", path, source)),
        }
    }

    fn create_dir(&self, path: &str, mode: Mode) -> Result<(), FsError> {
        let directory = self.create_dir_open(path)?;
        fchmod(&directory, mode)
            .map_err(|source| self.operation("set directory permissions", path, source.into()))
    }

    pub(crate) fn create_symlink(&self, path: &str, target: &str) -> Result<(), FsError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(self.collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(self.operation("inspect destination entry", path, source)),
        }
        parent
            .symlink(target, &name)
            .map_err(|source| self.operation("create symlink", path, source))
    }

    pub(crate) fn pending_file(&self, path: &str) -> Result<PendingFile, FsError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(self.collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => return Err(self.operation("inspect destination entry", path, source)),
        }
        let file = openat(
            &parent,
            ".",
            OFlags::WRONLY | OFlags::TMPFILE | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH,
        )
        .map_err(io::Error::from)
        .map(std::fs::File::from)
        .map(cap_std::fs::File::from_std)
        .map_err(|source| self.operation("stage file", path, source))?;
        Ok(PendingFile {
            parent,
            final_name: name,
            file,
            destination: self.destination.clone(),
        })
    }
}

pub(crate) struct PendingFile {
    parent: Dir,
    final_name: String,
    file: cap_std::fs::File,
    destination: PathBuf,
}

impl PendingFile {
    pub(crate) fn writer(&self, archive_path: &str) -> Result<cap_std::fs::File, FsError> {
        self.file.try_clone().map_err(|source| FsError::Operation {
            operation: "open staged file",
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            source,
        })
    }

    pub(crate) fn commit(self, archive_path: &str, mode: Mode) -> Result<(), FsError> {
        fchmod(&self.file, mode).map_err(|source| FsError::Operation {
            operation: "set staged file permissions",
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            source: source.into(),
        })?;
        self.file.sync_all().map_err(|source| FsError::Operation {
            operation: "sync staged file",
            archive_path: archive_path.to_owned(),
            destination: self.destination.clone(),
            source,
        })?;
        match linkat(
            &self.file,
            "",
            &self.parent,
            &self.final_name,
            AtFlags::EMPTY_PATH,
        ) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(FsError::ExtractionCollision {
                    archive_path: archive_path.to_owned(),
                    destination: self.destination.clone(),
                    reason: "final entry already exists",
                })
            }
            Err(source) => Err(FsError::Operation {
                operation: "publish staged file",
                archive_path: archive_path.to_owned(),
                destination: self.destination.clone(),
                source: source.into(),
            }),
        }
    }
}

struct PendingDirectory {
    path: String,
    directory: Dir,
    mode: Mode,
}

impl Write for PendingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staged_file_is_removed_after_sink_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ExtractionRoot::open(temporary.path(), false, "data").unwrap();
        let mut pending = root.pending_file("data").unwrap();
        pending.file = cap_std::fs::File::from_std(std::fs::File::open("/dev/null").unwrap());

        assert!(
            pending
                .writer("data")
                .unwrap()
                .write_all(b"content")
                .is_err()
        );
        drop(pending);

        assert!(!temporary.path().join("data").exists());
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
    }

    #[test]
    fn staged_file_is_removed_after_commit_collision() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ExtractionRoot::open(temporary.path(), false, "data").unwrap();
        let pending = root.pending_file("data").unwrap();
        pending
            .writer("data")
            .unwrap()
            .write_all(b"content")
            .unwrap();
        std::fs::write(temporary.path().join("data"), b"sentinel").unwrap();

        assert!(matches!(
            pending.commit("data", Mode::RUSR | Mode::WUSR),
            Err(FsError::ExtractionCollision { .. })
        ));

        assert_eq!(
            std::fs::read(temporary.path().join("data")).unwrap(),
            b"sentinel"
        );
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 1);
    }

    #[test]
    fn staged_file_publication_uses_the_retained_anonymous_file() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ExtractionRoot::open(temporary.path(), false, "data").unwrap();
        let pending = root.pending_file("data").unwrap();
        pending
            .writer("data")
            .unwrap()
            .write_all(b"verified")
            .unwrap();
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);

        pending.commit("data", Mode::RUSR | Mode::WUSR).unwrap();

        assert_eq!(
            std::fs::read(temporary.path().join("data")).unwrap(),
            b"verified"
        );
    }

    #[test]
    fn extraction_modes_strip_special_bits_unless_explicitly_enabled() {
        assert_eq!(
            applied_mode(0o7777, ExtractionOptions::default()).bits(),
            0o0777
        );
        assert_eq!(
            applied_mode(
                0o7777,
                ExtractionOptions::default().with_special_permissions(),
            )
            .bits(),
            0o7777
        );
    }

    #[test]
    fn staged_file_mode_failure_prevents_publication() {
        let temporary = tempfile::tempdir().unwrap();
        let root = ExtractionRoot::open(temporary.path(), false, "data").unwrap();
        let mut pending = root.pending_file("data").unwrap();
        pending.file = cap_std::fs::File::from_std(std::fs::File::open("/dev/null").unwrap());

        assert!(matches!(
            pending.commit("data", Mode::RUSR),
            Err(FsError::Operation {
                operation: "set staged file permissions",
                ..
            })
        ));
        assert!(!temporary.path().join("data").exists());
    }

    #[test]
    fn destination_root_rejects_parent_traversal() {
        let Err(error) = ExtractionRoot::open(Path::new(".."), true, "data") else {
            panic!("parent traversal unexpectedly opened as a destination root");
        };

        assert!(matches!(
            error,
            FsError::Operation {
                operation: "open destination",
                ..
            }
        ));
    }
}

use crate::error::PithosError;
use cap_std::fs::{Dir, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn collision(path: &str, reason: impl Into<String>) -> PithosError {
    PithosError::ExtractionCollision {
        path: path.into(),
        reason: reason.into(),
    }
}

pub(crate) struct ExtractionRoot {
    root: Dir,
}

impl ExtractionRoot {
    pub(crate) fn open(path: &Path, create: bool) -> Result<Self, PithosError> {
        if create {
            std::fs::create_dir_all(path)?;
        }
        Ok(Self {
            root: Dir::open_ambient_dir(path, cap_std::ambient_authority())?,
        })
    }

    fn parents(&self, path: &str) -> Result<(Dir, String), PithosError> {
        let mut components = path.split('/').peekable();
        let final_name = components
            .next_back()
            .ok_or_else(|| collision(path, "empty final component"))?;
        let mut dir = self.root.try_clone()?;
        for component in components {
            if component.is_empty() || component == "." || component == ".." {
                return Err(collision(path, "invalid component"));
            }
            match dir.symlink_metadata(component) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(collision(path, "parent is a symlink"));
                }
                Ok(metadata) if !metadata.is_dir() => {
                    return Err(collision(path, "parent is not a directory"));
                }
                Ok(_) => dir = dir.open_dir(component)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    dir.create_dir(component)?;
                    dir = dir.open_dir(component)?;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok((dir, final_name.to_string()))
    }

    pub(crate) fn create_dir(&self, path: &str) -> Result<(), PithosError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => Err(collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                parent.create_dir(&name).map_err(Into::into)
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn create_symlink(&self, path: &str, target: &str) -> Result<(), PithosError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        parent.symlink(target, &name).map_err(Into::into)
    }

    pub(crate) fn pending_file(&self, path: &str) -> Result<PendingFile, PithosError> {
        let (parent, name) = self.parents(path)?;
        match parent.symlink_metadata(&name) {
            Ok(_) => return Err(collision(path, "final entry already exists")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let pid = std::process::id();
        loop {
            let temp =
                format! {".pithos-tmp-{pid}-{}", TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)};
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            match parent.open_with(&temp, &options) {
                Ok(file) => {
                    return Ok(PendingFile {
                        parent,
                        temp,
                        final_name: name,
                        file,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }
}

pub(crate) struct PendingFile {
    parent: Dir,
    temp: String,
    final_name: String,
    file: cap_std::fs::File,
}

impl PendingFile {
    pub(crate) fn writer(&self) -> Result<cap_std::fs::File, PithosError> {
        Ok(self.file.try_clone()?)
    }

    pub(crate) fn commit(mut self) -> Result<(), PithosError> {
        self.file.sync_all()?;
        match self
            .parent
            .hard_link(&self.temp, &self.parent, &self.final_name)
        {
            Ok(()) => {
                self.parent.remove_file(&self.temp)?;
                self.temp.clear();
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(collision(&self.final_name, "final entry already exists"))
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl Write for PendingFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl Drop for PendingFile {
    fn drop(&mut self) {
        if !self.temp.is_empty() {
            let _ = self.parent.remove_file(&self.temp);
        }
    }
}

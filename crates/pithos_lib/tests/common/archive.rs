use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::source::FileSource;
use std::path::Path;

#[allow(dead_code)] // Integration targets compile this shared module independently.
pub fn open(path: &Path, keys: AccessKeys) -> Archive<FileSource> {
    Archive::open(
        FileSource::open(path).unwrap(),
        OpenOptions::default().with_access_keys(keys),
    )
    .unwrap()
}

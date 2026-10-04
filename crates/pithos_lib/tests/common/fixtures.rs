use super::keys::{private_key, public_key};
use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriteOptions,
};
use std::fs::File;
use std::path::PathBuf;

#[allow(dead_code)] // Integration targets compile this shared module independently.
pub fn fixture(directory: &tempfile::TempDir, recipient: &str) -> PathBuf {
    let path = directory.path().join("fixture.pith");
    let sender = private_key("sender");
    let recipient = public_key(recipient);
    let mut writer = ArchiveWriter::create(
        File::create(&path).unwrap(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(29),
            std::io::Cursor::new(b"public archive reader fixture"),
        )
        .unwrap();
    writer.finish().unwrap();
    path
}

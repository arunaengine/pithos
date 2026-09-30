use super::{
    archive::open,
    keys::{private_key, public_key},
};
use pithos_lib::archive::{
    AccessKeys, AppendOptions, Archive, ArchivePath, ArchiveWriter, CdcConfig, EntryMetadata,
    ProcessingOptions, WriteOptions,
};
use pithos_lib::fs::{FsError, append_files, grant_readers};
use pithos_lib::source::FileSource;
use std::fs::File;
use std::io::Cursor;
use std::path::{Path, PathBuf};

#[allow(dead_code)]
pub const SELECTED_ID: u64 = 3;
#[allow(dead_code)]
pub const WITHHELD_ID: u64 = 4;
#[allow(dead_code)]
pub const DIRECTORY_ID: u64 = 2;

#[allow(dead_code)]
pub struct AppendFixture {
    pub archive: PathBuf,
}

impl AppendFixture {
    #[allow(dead_code)]
    pub fn open_as(&self, key: &str) -> Archive<FileSource> {
        open(&self.archive, AccessKeys::new().with_key(private_key(key)))
    }

    #[allow(dead_code)]
    pub fn append_source(&self, name: &str, contents: &[u8]) -> PathBuf {
        let source = self.archive.parent().unwrap().join(name);
        std::fs::write(&source, contents).unwrap();
        source
    }
}

#[allow(dead_code)]
pub fn append_fixture(temporary: &tempfile::TempDir) -> AppendFixture {
    let archive = temporary.path().join("append-base.pith");
    let sender = private_key("sender");
    let sender_public = sender.public_key();
    let mut writer = ArchiveWriter::create(
        File::create(&archive).unwrap(),
        WriteOptions::new(sender, vec![sender_public, public_key("recipient1")]),
    )
    .unwrap();
    assert_eq!(
        writer
            .add_file(
                ArchivePath::new("older.txt").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 2).unwrap(),
                None,
                Cursor::new(b"older base payload"),
            )
            .unwrap()
            .id,
        0
    );
    assert_eq!(
        writer
            .add_file(
                ArchivePath::new("older-withheld.txt").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 2).unwrap(),
                None,
                Cursor::new(b"older withheld payload"),
            )
            .unwrap()
            .id,
        1
    );
    assert_eq!(
        writer
            .add_directory(
                ArchivePath::new("records").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap()
            .id,
        DIRECTORY_ID
    );
    writer.finish().unwrap();
    let selected = archive.parent().unwrap().join("selected.txt");
    let withheld = archive.parent().unwrap().join("withheld.txt");
    std::fs::write(&selected, b"selected base payload").unwrap();
    std::fs::write(&withheld, b"withheld base payload").unwrap();
    append(&archive, vec![selected, withheld]).unwrap();
    AppendFixture { archive }
}

#[allow(dead_code)]
pub fn append(archive: &Path, sources: Vec<PathBuf>) -> Result<(), FsError> {
    append_with_cdc(archive, CdcConfig::default(), sources)
}

#[allow(dead_code)]
pub fn append_with_cdc(
    archive: &Path,
    cdc: CdcConfig,
    sources: Vec<PathBuf>,
) -> Result<(), FsError> {
    append_files(
        archive,
        AppendOptions::new(
            private_key("sender"),
            vec![public_key("sender"), public_key("recipient1")],
        )
        .with_cdc(cdc),
        &sources,
    )
    .map(|_| ())
}

#[allow(dead_code)]
pub fn archive_with_entry(temporary: &tempfile::TempDir, path: &str) -> PathBuf {
    let archive = temporary.path().join("hierarchy.pith");
    let sender = private_key("sender");
    let mut writer = ArchiveWriter::create(
        File::create(&archive).unwrap(),
        WriteOptions::new(sender, vec![public_key("sender"), public_key("recipient1")]),
    )
    .unwrap();
    for (index, _) in path.match_indices('/') {
        writer
            .add_directory(
                ArchivePath::new(&path[..index]).unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
    }
    writer
        .add_file(
            ArchivePath::new(path).unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 2).unwrap(),
            None,
            Cursor::new(b"existing"),
        )
        .unwrap();
    writer.finish().unwrap();
    archive
}

#[allow(dead_code)]
pub fn archive_with_symlink(temporary: &tempfile::TempDir) -> PathBuf {
    let archive = temporary.path().join("symlink.pith");
    let sender = private_key("sender");
    let mut writer = ArchiveWriter::create(
        File::create(&archive).unwrap(),
        WriteOptions::new(sender, vec![public_key("sender"), public_key("recipient1")]),
    )
    .unwrap();
    writer
        .add_symlink(
            ArchivePath::new("link").unwrap(),
            EntryMetadata::new(0, 0, 0o777),
            "target",
        )
        .unwrap();
    writer.finish().unwrap();
    archive
}

#[allow(dead_code)]
pub fn grant(
    archive: &Path,
    sender: &str,
    recipients: Vec<&str>,
    ids: Vec<u64>,
) -> Result<(), FsError> {
    grant_readers(
        archive,
        AppendOptions::new(
            private_key(sender),
            recipients.into_iter().map(public_key).collect(),
        ),
        &ids,
    )
    .map(|_| ())
}

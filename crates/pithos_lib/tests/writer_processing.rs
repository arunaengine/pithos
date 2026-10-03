mod common;

use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, CdcConfig, Chunking, EntryMetadata,
    OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::MemorySource;
use std::io::{self, Cursor, Write};

#[test]
fn repeated_identical_chunks_round_trip_in_order() {
    let sender = PrivateKey::generate();
    let reader = sender.duplicate();
    let data = vec![0u8; 2 * 1024];
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![reader.public_key()]).with_chunking(
            Chunking::ContentDefined(CdcConfig::new(64, 256, 1024).unwrap()),
        ),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("repeated.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(data.len() as u64),
            Cursor::new(&data),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )
    .unwrap();
    let mut full = Vec::new();
    archive.copy_to("repeated.bin", &mut full).unwrap();
    assert_eq!(full, data);
    let mut range = Vec::new();
    archive
        .copy_range_to("repeated.bin", 900..1150, &mut range)
        .unwrap();
    assert_eq!(range, data[900..1150]);
}

#[test]
fn committed_actual_size_and_descriptor_are_readable_through_archive() {
    let sender = PrivateKey::generate();
    let reader = sender.duplicate();
    let recipient = sender.public_key();
    let mut writer =
        ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            None,
            Cursor::new(b"descriptor-backed payload"),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )
    .unwrap();
    assert!(matches!(
        archive.entry("data").unwrap().unwrap().kind,
        pithos_lib::archive::EntryKind::File { size: 25, .. }
    ));
    let mut copied = Vec::new();
    archive.copy_to("data", &mut copied).unwrap();
    assert_eq!(copied, b"descriptor-backed payload");
}

#[derive(Debug, Default)]
struct ShortSink(Vec<u8>);

impl Write for ShortSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let accepted = bytes.len().min(3);
        self.0.extend_from_slice(&bytes[..accepted]);
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn short_writes_are_counted_and_completed_without_saturating_offsets() {
    let sender = PrivateKey::generate();
    let reader = sender.duplicate();
    let recipient = sender.public_key();
    let mut writer = ArchiveWriter::create(
        ShortSink::default(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            None,
            Cursor::new(b"short writes"),
        )
        .unwrap();
    let sink = writer.finish().unwrap();
    let archive = Archive::open(
        MemorySource::new(sink.0),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )
    .unwrap();
    assert!(archive.entry("data").unwrap().is_some());
    let mut copied = Vec::new();
    archive.copy_to("data", &mut copied).unwrap();
    assert_eq!(copied, b"short writes");
}

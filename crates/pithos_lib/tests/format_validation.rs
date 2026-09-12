use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryMetadata, EntryReference, OpenLimits,
    OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::error::PithosError;
use pithos_lib::source::MemorySource;

#[test]
fn public_open_rejects_invalid_header() {
    assert!(matches!(
        Archive::open(MemorySource::new(&b"NOTPIT"[..]), OpenOptions::default()),
        Err(PithosError::Deserialization(_))
    ));
}

#[test]
fn public_open_rejects_a_footer_claiming_an_impossible_directory() {
    let mut bytes = b"PITH\x01\x00".to_vec();
    bytes.extend_from_slice(&u64::MAX.to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        Archive::open(MemorySource::new(bytes), OpenOptions::default()),
        Err(PithosError::LimitExceeded {
            field: "directory",
            ..
        })
    ));
}

#[test]
fn public_open_rejects_the_legacy_varint_header() {
    let (mut bytes, _) = archive_with_entries(Vec::new());
    bytes[..6].copy_from_slice(b"PITH\x80\x02");

    assert!(matches!(
        Archive::open(MemorySource::new(bytes), OpenOptions::default()),
        Err(PithosError::UnsupportedFileVersion {
            supported: 0x0100,
            actual: 0x8002,
        })
    ));
}

fn archive_with_entries(entries: Vec<(&str, EntryMetadata)>) -> (Vec<u8>, PrivateKey) {
    let sender = PrivateKey::generate();
    let recipient = sender.duplicate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![recipient.public_key()]),
    )
    .unwrap();
    for (index, (path, metadata)) in entries.into_iter().enumerate() {
        let content = [u8::try_from(index).unwrap()];
        writer
            .add_file(
                ArchivePath::new(path).unwrap(),
                metadata,
                ProcessingOptions::new(false, 0).unwrap(),
                Some(content.len() as u64),
                std::io::Cursor::new(content),
            )
            .unwrap();
    }
    (writer.finish().unwrap(), recipient)
}

#[test]
fn open_limits_reject_oversized_entry_descriptor_reference_and_relationship_counts() {
    let cases = [
        (
            OpenLimits {
                max_entries: 1,
                ..OpenLimits::default()
            },
            archive_with_entries(vec![
                ("first", EntryMetadata::new(0, 0, 0o644)),
                ("second", EntryMetadata::new(0, 0, 0o644)),
            ]),
        ),
        (
            OpenLimits {
                max_descriptors: 1,
                ..OpenLimits::default()
            },
            archive_with_entries(vec![
                ("first", EntryMetadata::new(0, 0, 0o644)),
                ("second", EntryMetadata::new(0, 0, 0o644)),
            ]),
        ),
        (
            OpenLimits {
                max_references: 0,
                ..OpenLimits::default()
            },
            archive_with_entries(vec![
                ("first", EntryMetadata::new(0, 0, 0o644)),
                (
                    "second",
                    EntryMetadata::new(0, 0, 0o644).with_references(vec![EntryReference {
                        target_file_id: 0,
                        relationship: 0,
                    }]),
                ),
            ]),
        ),
        (
            OpenLimits {
                max_relationships: 0,
                ..OpenLimits::default()
            },
            archive_with_entries(vec![
                ("first", EntryMetadata::new(0, 0, 0o644)),
                (
                    "second",
                    EntryMetadata::new(0, 0, 0o644).with_references(vec![EntryReference {
                        target_file_id: 0,
                        relationship: 0,
                    }]),
                ),
            ]),
        ),
    ];

    for (limits, (bytes, recipient)) in cases {
        let result = Archive::open(
            MemorySource::new(bytes),
            OpenOptions::default()
                .with_limits(limits)
                .with_access_keys(AccessKeys::new().with_key(recipient)),
        );
        match result {
            Err(PithosError::LimitExceeded { .. } | PithosError::Deserialization(_)) => {}
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("oversized directory unexpectedly opened"),
        }
    }
}

#[test]
fn adversarial_wire_path_order_stays_within_open_limits() {
    let sender = PrivateKey::generate();
    let recipient = sender.duplicate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![recipient.public_key()]),
    )
    .unwrap();
    writer
        .add_directory(
            ArchivePath::new("root").unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    for index in (0..100).rev() {
        writer
            .add_directory(
                ArchivePath::new(format!("root/{index:03}")).unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
    }
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default()
            .with_limits(OpenLimits {
                max_entries: 101,
                ..OpenLimits::default()
            })
            .with_access_keys(AccessKeys::new().with_key(recipient)),
    )
    .unwrap();
    assert_eq!(archive.entries().len(), 101);
}

mod common;

use common::util::{fixture, open, private_key, public_key};
use pithos_lib::adapters::crypt4gh::{self, Crypt4GHError};
use pithos_lib::archive::{
    AccessKeys, ArchivePath, ArchiveWriter, EntryKind, EntryMetadata, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::fs::extract;

#[test]
fn public_reader_lists_copies_ranges_extracts_and_exports() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let entry = archive.entry("data").unwrap().unwrap();
    assert!(matches!(
        entry.kind,
        EntryKind::File {
            available: true,
            ..
        }
    ));
    assert_eq!(entry.permissions, 0o644);

    let mut full = Vec::new();
    archive.copy_to("data", &mut full).unwrap();
    assert_eq!(full, b"public archive reader fixture");
    let mut range = Vec::new();
    archive.copy_range_to("data", 7..14, &mut range).unwrap();
    assert_eq!(range, b"archive");

    let output = temporary.path().join("out");
    extract(&archive, "data", &output).unwrap();
    assert_eq!(std::fs::read(output.join("data")).unwrap(), full);

    let mut exported = Vec::new();
    crypt4gh::export(
        &archive,
        "data",
        vec![public_key("recipient2")],
        &mut exported,
    )
    .unwrap();
    assert!(exported.starts_with(b"crypt4gh"));
    assert!(exported.len() > full.len());
}

#[test]
fn unavailable_content_is_visible_and_invalid_ranges_fail_before_copy() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let archive = open(&path, AccessKeys::new());
    assert!(matches!(
        archive.entries().next().unwrap().kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));
    assert!(matches!(
        archive.copy_to("data", &mut Vec::new()),
        Err(PithosError::ContentUnavailable)
    ));

    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    assert!(matches!(
        archive.copy_range_to("data", 99..100, &mut Vec::new()),
        Err(PithosError::InvalidReadRange { .. })
    ));
}

#[test]
fn crypt4gh_export_rejects_zero_recipients_before_sink_output() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let mut exported = Vec::new();
    let error = crypt4gh::export(&archive, "data", Vec::new(), &mut exported).unwrap_err();
    assert!(
        (&error as &(dyn std::error::Error + 'static))
            .downcast_ref::<Crypt4GHError>()
            .is_some()
    );
    assert!(exported.is_empty());
}

#[test]
fn public_reader_accepts_empty_eof_ranges_and_rejects_reversed_ranges() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let size = match archive.entry("data").unwrap().unwrap().kind {
        EntryKind::File { size, .. } => size,
        _ => panic!("fixture data entry must be a file"),
    };
    let mut output = Vec::new();
    archive
        .copy_range_to("data", size..size, &mut output)
        .unwrap();
    assert!(output.is_empty());
    assert!(matches!(
        archive.copy_range_to(
            "data",
            std::ops::Range { start: 2, end: 1 },
            &mut Vec::new()
        ),
        Err(PithosError::InvalidReadRange { .. })
    ));
}

#[test]
fn extraction_is_no_clobber_no_follow_and_staged() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("archive.pith");
    let sender = private_key("sender");
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(&path).unwrap(),
        WriteOptions::new(sender, vec![public_key("recipient1")]),
    )
    .unwrap();
    writer
        .add_directory(
            ArchivePath::new("nested").unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    for (path, content) in [
        ("data", b"payload".as_slice()),
        ("nested/data", b"nested payload"),
    ] {
        writer
            .add_file(
                ArchivePath::new(path).unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 0).unwrap(),
                Some(content.len() as u64),
                std::io::Cursor::new(content),
            )
            .unwrap();
    }
    writer.finish().unwrap();
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let root = temporary.path().join("output");
    std::fs::create_dir(&root).unwrap();
    std::fs::write(root.join("data"), b"unchanged").unwrap();
    assert!(extract(&archive, "data", &root).is_err());
    assert_eq!(std::fs::read(root.join("data")).unwrap(), b"unchanged");
    std::fs::remove_file(root.join("data")).unwrap();
    let outside = temporary.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("nested")).unwrap();
    assert!(extract(&archive, "nested/data", &root).is_err());
    assert!(!outside.join("data").exists());
}

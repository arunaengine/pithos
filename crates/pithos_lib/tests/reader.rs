mod common;

use common::util::{fixture, open, private_key, public_key};
use pithos_lib::adapters::crypt4gh::{self, Crypt4GHError};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, Chunking, EntryKind, EntryMetadata,
    OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::fs::{ExtractionOptions, extract, extract_all, extract_all_with_options};
use pithos_lib::source::MemorySource;

const PITHOS_0_7_FIXTURES: [&str; 2] = [
    "tests/data/pithos-0.7.0.pith",
    "tests/data/pithos-0.7.3.pith",
];

#[test]
fn pithos_0_7_archives_read_with_their_content_and_metadata() {
    for fixture in PITHOS_0_7_FIXTURES {
        let path = std::path::Path::new(fixture);
        let archive = open(path, AccessKeys::new().with_key(private_key("recipient1")));
        assert_eq!(archive.view().version(), 0x8002, "{fixture}");
        let files: [(&str, &[u8]); 4] = [
            ("alpha.txt", b"alpha\n"),
            ("data/empty.txt", b""),
            ("data/raw/beta.txt", b"beta\n"),
            ("gamma.txt", b"gamma\n"),
        ];
        for (path, expected) in files {
            let mut content = Vec::new();
            archive.copy_to(path, &mut content).unwrap();
            assert_eq!(content, expected, "{fixture} {path}");
        }
        let alpha = archive.entry("alpha.txt").unwrap().unwrap();
        assert_eq!(alpha.permissions, 0o600, "{fixture}");
        let data = archive.entry("data").unwrap().unwrap();
        assert!(matches!(data.kind, EntryKind::Directory));
        assert_eq!(data.permissions, 0o750, "{fixture}");
        let link = archive.entry("data/link").unwrap().unwrap();
        assert!(matches!(link.kind, EntryKind::Symlink { ref target } if target == "raw/beta.txt"));
    }
}

#[test]
fn pithos_0_7_archives_reject_a_changed_directory() {
    for fixture in PITHOS_0_7_FIXTURES {
        let mut bytes = std::fs::read(fixture).unwrap();
        let path = bytes
            .windows(8)
            .rposition(|window| window == b"data/raw")
            .unwrap();
        bytes[path] ^= 1;
        let options = OpenOptions::default()
            .with_access_keys(AccessKeys::new().with_key(private_key("recipient1")));
        assert!(
            matches!(
                Archive::open(MemorySource::new(bytes), options),
                Err(PithosError::DirectoryChecksumMismatch { .. })
            ),
            "{fixture}"
        );
    }
}

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
    writer
        .add_symlink(
            ArchivePath::new("dangling").unwrap(),
            EntryMetadata::new(0, 0, 0o777),
            "missing",
        )
        .unwrap();
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
    extract(&archive, "dangling", &root).unwrap();
    assert_eq!(
        std::fs::read_link(root.join("dangling")).unwrap(),
        std::path::Path::new("missing")
    );

    let batch = temporary.path().join("batch");
    std::fs::create_dir(&batch).unwrap();
    extract_all(&archive, &batch).unwrap();
    assert_eq!(std::fs::read(batch.join("data")).unwrap(), b"payload");
    assert_eq!(
        std::fs::read(batch.join("nested/data")).unwrap(),
        b"nested payload"
    );
    assert_eq!(
        std::fs::read_link(batch.join("dangling")).unwrap(),
        std::path::Path::new("missing")
    );
    assert!(extract_all(&archive, &batch).is_err());
    assert_eq!(std::fs::read(batch.join("data")).unwrap(), b"payload");

    let batch_no_follow = temporary.path().join("batch-no-follow");
    std::fs::create_dir(&batch_no_follow).unwrap();
    std::os::unix::fs::symlink(&outside, batch_no_follow.join("nested")).unwrap();
    assert!(
        extract_all_with_options(&archive, &batch_no_follow, ExtractionOptions::default(),)
            .is_err()
    );
    assert!(!outside.join("data").exists());
}

#[test]
fn ranges_near_offset_checkpoints_and_at_the_tail_match_the_full_read() {
    // 3,000 encrypted 16-byte blocks and a short last block span two checkpoints of 1,024.
    let content = (0..3_000u64 * 16 + 5)
        .map(|byte| (byte % 251) as u8)
        .collect::<Vec<u8>>();
    let sender = private_key("sender");
    let options = WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
        .with_chunking(Chunking::Fixed(16));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content.clone()),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    let mut full = Vec::new();
    archive.copy_to("data", &mut full).unwrap();
    assert!(full == content);

    let edge = 1_024 * 16;
    let len = content.len() as u64;
    for range in [
        edge - 1..edge,
        edge..edge + 1,
        edge - 3..edge + 3,
        2 * edge - 16..2 * edge + 16,
        2 * edge..len,
        len - 5..len,
        len - 21..len,
        len - 1..len,
        len..len,
        edge..edge,
    ] {
        let mut output = Vec::new();
        archive
            .copy_range_to("data", range.clone(), &mut output)
            .unwrap();
        assert!(
            output == content[range.start as usize..range.end as usize],
            "range {range:?}"
        );
    }
}

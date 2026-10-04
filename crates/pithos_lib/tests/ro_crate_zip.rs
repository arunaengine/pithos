mod common;

use common::ro_crate::{
    conversion_error, duplicate_conversion_error, metadata, write_loaded, write_raw_zip,
};
use common::util::{open, private_key};
use pithos_lib::adapters::ro_crate::{
    RO_CRATE_METADATA_FILE, RoCrateError, RoCrateSource, read_ro_crate_zip,
};
use pithos_lib::archive::{AccessKeys, CdcConfig, Chunking, EntryKind, WriterError};
use pithos_lib::error::PithosError;
use std::fs;
use std::io::{Seek, SeekFrom, Write};

#[test]
fn loaded_zip_converts_from_retained_open_archive_after_path_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("crate.zip");
    let original_metadata = metadata(&["data.bin"]).replace("Test Crate", "Original Crate");
    write_raw_zip(
        &source,
        &[
            (
                b"ro-crate-metadata.json",
                original_metadata.as_bytes(),
                0o100644,
            ),
            (b"data.bin", b"original", 0o100644),
        ],
    );

    let loaded = read_ro_crate_zip(&source).unwrap();
    fs::rename(&source, temporary.path().join("original.zip")).unwrap();
    let replacement_metadata =
        metadata(&["data.bin", "replacement-only.bin"]).replace("Test Crate", "Replacement Crate");
    write_raw_zip(
        &source,
        &[
            (
                b"ro-crate-metadata.json",
                replacement_metadata.as_bytes(),
                0o100644,
            ),
            (b"data.bin", b"replaced", 0o100644),
            (b"replacement-only.bin", b"replacement", 0o100644),
        ],
    );

    let output = temporary.path().join("retained-zip.pith");
    write_loaded(&output, loaded, Chunking::default());
    let archive = open(
        &output,
        AccessKeys::new().with_key(private_key("recipient1")),
    );
    let mut archived_metadata = Vec::new();
    archive
        .copy_to("ro-crate-metadata.json", &mut archived_metadata)
        .unwrap();
    let mut data = Vec::new();
    archive.copy_to("data.bin", &mut data).unwrap();

    assert_eq!(archived_metadata, original_metadata.as_bytes());
    assert_eq!(data, b"original");
    assert!(archive.entry("replacement-only.bin").unwrap().is_none());
}

#[test]
fn retained_zip_conversion_failure_has_archive_member_index_and_source_context() {
    const LOCAL_HEADER_LEN: u64 = 30;

    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("crate.zip");
    let crate_metadata = metadata(&["data.bin"]);
    write_raw_zip(
        &archive_path,
        &[
            (
                RO_CRATE_METADATA_FILE.as_bytes(),
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"data.bin", b"original", 0o100644),
        ],
    );
    let loaded = read_ro_crate_zip(&archive_path).unwrap();

    let data_offset = LOCAL_HEADER_LEN
        + u64::try_from(RO_CRATE_METADATA_FILE.len()).unwrap()
        + u64::try_from(crate_metadata.len()).unwrap()
        + LOCAL_HEADER_LEN
        + u64::try_from(b"data.bin".len()).unwrap();
    let mut archive = fs::OpenOptions::new()
        .write(true)
        .open(&archive_path)
        .unwrap();
    archive.seek(SeekFrom::Start(data_offset)).unwrap();
    archive.write_all(b"X").unwrap();
    archive.flush().unwrap();
    drop(archive);

    let error = conversion_error(loaded);
    let message = error.to_string();
    assert!(message.contains("convert retained ZIP member"));
    assert!(message.contains(archive_path.to_str().unwrap()));
    assert!(message.contains("member data.bin"));
    assert!(message.contains("index 1"));
    let writer_error = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<WriterError>())
        .expect("retained-member context must expose WriterError as its source");
    assert!(std::error::Error::source(writer_error).is_some());
}

#[test]
fn zip_metadata_directory_and_symlink_failures_keep_member_context() {
    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("crate.zip");
    let crate_metadata = metadata(&[]);
    write_raw_zip(
        &archive_path,
        &[
            (
                RO_CRATE_METADATA_FILE.as_bytes(),
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"nested/", b"", 0o040755),
            (b"link", b"missing", 0o120777),
        ],
    );

    for (entry, operation, member, index) in [
        (
            RO_CRATE_METADATA_FILE,
            "convert retained ZIP metadata",
            RO_CRATE_METADATA_FILE,
            0,
        ),
        ("nested", "convert retained ZIP entry", "nested/", 1),
        ("link", "convert retained ZIP entry", "link", 2),
    ] {
        let error = duplicate_conversion_error(read_ro_crate_zip(&archive_path).unwrap(), entry);
        let message = error.to_string();
        assert!(message.contains(operation), "unexpected error: {message}");
        assert!(
            message.contains(archive_path.to_str().unwrap()),
            "unexpected error: {message}"
        );
        assert!(message.contains(&format!("member {member}")));
        assert!(message.contains(&format!("index {index}")));
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<WriterError>())
                .is_some()
        );
    }

    let synthetic_archive = temporary.path().join("synthetic-parent.zip");
    let synthetic_metadata = metadata(&["nested/file"]);
    write_raw_zip(
        &synthetic_archive,
        &[
            (
                RO_CRATE_METADATA_FILE.as_bytes(),
                synthetic_metadata.as_bytes(),
                0o100644,
            ),
            (b"nested/file", b"content", 0o100644),
        ],
    );
    let error =
        duplicate_conversion_error(read_ro_crate_zip(&synthetic_archive).unwrap(), "nested");
    let message = error.to_string();
    assert!(message.contains("convert synthetic ZIP parent"));
    assert!(message.contains(synthetic_archive.to_str().unwrap()));
    assert!(message.contains("nested"));
    assert!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<WriterError>())
            .is_some()
    );
}

#[test]
fn typed_zip_conversion_streams_large_multiblock_member_and_round_trips() {
    let temporary = tempfile::tempdir().unwrap();
    let zip = temporary.path().join("large.zip");
    let mut state = 1u32;
    let payload = (0..(1024 * 1024 + 123))
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect::<Vec<_>>();
    let crate_metadata = metadata(&["large.bin"]);
    write_raw_zip(
        &zip,
        &[
            (
                b"ro-crate-metadata.json",
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"large.bin", &payload, 0o100644),
        ],
    );

    let output = temporary.path().join("large.pith");
    write_loaded(
        &output,
        read_ro_crate_zip(&zip).unwrap(),
        Chunking::ContentDefined(CdcConfig::new(64, 256, 1024).unwrap()),
    );
    let archive = open(
        &output,
        AccessKeys::new().with_key(private_key("recipient1")),
    );
    assert_eq!(
        archive.entry("large.bin").unwrap().unwrap().kind,
        EntryKind::File {
            size: payload.len() as u64,
            available: true
        }
    );
    let mut copied = Vec::new();
    archive.copy_to("large.bin", &mut copied).unwrap();
    assert_eq!(copied, payload);
}

#[test]
fn typed_zip_conversion_rejects_unsafe_paths_duplicates_conflicts_and_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let crate_metadata = metadata(&[]);
    for (name, entries, expected) in [
        (
            "traversal.zip",
            vec![(b"../escape".as_slice(), b"x".as_slice(), 0o100644)],
            "unsafe",
        ),
        (
            "duplicate.zip",
            vec![
                (b"duplicate".as_slice(), b"one".as_slice(), 0o100644),
                (b"./duplicate".as_slice(), b"two".as_slice(), 0o100644),
            ],
            "unsafe",
        ),
        (
            "conflict.zip",
            vec![
                (b"nested".as_slice(), b"file".as_slice(), 0o100644),
                (b"nested/file".as_slice(), b"child".as_slice(), 0o100644),
            ],
            "conflict",
        ),
        (
            "absolute-link.zip",
            vec![(b"link".as_slice(), b"/outside".as_slice(), 0o120777)],
            "link",
        ),
        (
            "escaping-link.zip",
            vec![(b"link".as_slice(), b"../outside".as_slice(), 0o120777)],
            "link",
        ),
        (
            "invalid-link.zip",
            vec![(b"link".as_slice(), b"target/".as_slice(), 0o120777)],
            "link",
        ),
    ] {
        let path = temporary.path().join(name);
        let mut full_entries = vec![(
            b"ro-crate-metadata.json".as_slice(),
            crate_metadata.as_bytes(),
            0o100644,
        )];
        full_entries.extend(entries);
        write_raw_zip(&path, &full_entries);
        let error = read_ro_crate_zip(&path).unwrap_err();
        match expected {
            "unsafe" => assert!(matches!(error, RoCrateError::UnsafeZipPath { .. })),
            "conflict" => assert!(matches!(error, RoCrateError::ZipPathConflict { .. })),
            "link" => {
                let message = error.to_string();
                assert!(message.contains(path.to_str().unwrap()), "{message}");
                assert!(message.contains("member link"), "{message}");
                assert!(message.contains("index 1"), "{message}");
                assert!(
                    std::error::Error::source(&error)
                        .and_then(|source| source.downcast_ref::<PithosError>())
                        .is_some()
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn zip_loader_rejects_member_names_that_require_normalization() {
    let temporary = tempfile::tempdir().unwrap();
    let crate_metadata = metadata(&[]);
    let parent = temporary.path().join("parent-component.zip");
    write_raw_zip(
        &parent,
        &[(
            b"nested/../ro-crate-metadata.json",
            crate_metadata.as_bytes(),
            0o100644,
        )],
    );
    assert!(matches!(
        read_ro_crate_zip(&parent),
        Err(RoCrateError::UnsafeZipPath { .. })
    ));
    let current = temporary.path().join("current-component.zip");
    write_raw_zip(
        &current,
        &[
            (
                b"ro-crate-metadata.json",
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"./payload", b"content", 0o100644),
        ],
    );
    assert!(matches!(
        read_ro_crate_zip(&current),
        Err(RoCrateError::UnsafeZipPath { .. })
    ));
    for (index, name) in [
        b"nested//payload".as_slice(),
        b"nested\\payload",
        b"C:payload",
    ]
    .into_iter()
    .enumerate()
    {
        let path = temporary.path().join(format!("invalid-{index}.zip"));
        write_raw_zip(
            &path,
            &[
                (
                    b"ro-crate-metadata.json",
                    crate_metadata.as_bytes(),
                    0o100644,
                ),
                (name, b"content", 0o100644),
            ],
        );
        assert!(matches!(
            read_ro_crate_zip(&path),
            Err(RoCrateError::UnsafeZipPath { .. })
        ));
    }
}

#[test]
fn typed_zip_conversion_rejects_raw_invalid_utf8_member_names_and_malformed_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let invalid_name = temporary.path().join("invalid-name.zip");
    write_raw_zip(
        &invalid_name,
        &[
            (
                b"ro-crate-metadata.json",
                metadata(&[]).as_bytes(),
                0o100644,
            ),
            (b"invalid-\xff", b"content", 0o100644),
        ],
    );
    assert!(matches!(
        read_ro_crate_zip(&invalid_name),
        Err(RoCrateError::InvalidZipEntryName { index: 1, .. })
    ));
    let malformed = temporary.path().join("malformed.zip");
    write_raw_zip(
        &malformed,
        &[(b"ro-crate-metadata.json", b"not JSON", 0o100644)],
    );
    let error = read_ro_crate_zip(&malformed).unwrap_err();
    let message = error.to_string();
    assert!(message.contains(malformed.to_str().unwrap()), "{message}");
    assert!(
        message.contains("member ro-crate-metadata.json"),
        "{message}"
    );
    assert!(message.contains("index 0"), "{message}");
    assert!(matches!(error, RoCrateError::ZipMemberParser { .. }));
}

// Upstream ro-crate-rs parser and graph assertions.
#[test]
fn parser_preserves_a_synthetic_zip_fixture_graph_source_and_permissions() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("fixture.zip");
    let crate_metadata = metadata(&["data.bin", "notes.txt"]);
    write_raw_zip(
        &path,
        &[
            (
                RO_CRATE_METADATA_FILE.as_bytes(),
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"data.bin", b"repository-owned binary fixture", 0o100644),
            (b"notes.txt", b"repository-owned text fixture", 0o100600),
        ],
    );

    assert_eq!(
        zip::ZipArchive::new(fs::File::open(&path).unwrap())
            .unwrap()
            .len(),
        3
    );
    let loaded = read_ro_crate_zip(&path).unwrap();
    assert_eq!(loaded.source_kind(), RoCrateSource::Zip);
    assert!(!loaded.ro_crate().graph.is_empty());

    let output = temporary.path().join("fixture.pith");
    write_loaded(&output, loaded, Chunking::default());
    let archive = open(
        &output,
        AccessKeys::new().with_key(private_key("recipient1")),
    );
    assert_eq!(
        archive.entry("data.bin").unwrap().unwrap().permissions,
        0o644
    );
    assert_eq!(
        archive.entry("notes.txt").unwrap().unwrap().permissions,
        0o600
    );
}

#[test]
fn zip_parser_rejects_invalid_archives_and_non_root_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let invalid = temporary.path().join("invalid.zip");
    fs::write(&invalid, b"not a ZIP archive").unwrap();
    let error = read_ro_crate_zip(&invalid).unwrap_err();
    assert!(
        std::any::type_name_of_val(&error).ends_with("RoCrateError"),
        "RO-Crate operations must return their adapter error directly"
    );
    assert!(std::error::Error::source(&error).is_some());
    assert!(error.to_string().contains(invalid.to_str().unwrap()));
    assert!(error.to_string().contains("open ZIP archive"));
    let missing = temporary.path().join("missing.zip");
    write_raw_zip(&missing, &[(b"data.txt", b"data", 0o100644)]);
    assert!(matches!(
        read_ro_crate_zip(&missing),
        Err(RoCrateError::MissingMetadata { .. })
    ));
    let wrapped = temporary.path().join("wrapped.zip");
    write_raw_zip(
        &wrapped,
        &[(
            b"wrapper/ro-crate-metadata.json",
            metadata(&[]).as_bytes(),
            0o100644,
        )],
    );
    assert!(matches!(
        read_ro_crate_zip(&wrapped),
        Err(RoCrateError::MissingMetadata { .. })
    ));
}

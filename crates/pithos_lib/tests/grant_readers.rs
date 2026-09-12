mod common;

use common::append::{
    DIRECTORY_ID, SELECTED_ID, WITHHELD_ID, append_fixture, archive_with_symlink, grant,
};
use common::util::{open, private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, AppendOptions, ArchivePath, ArchiveWriter, EntryKind, EntryMetadata,
    ProcessingOptions, WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::fs::{FsError, grant_readers};
use std::fs::File;
use std::io::Cursor;
use std::os::unix::fs::symlink;

#[test]
fn direct_grant_rejects_a_symlink_archive_target_without_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let alias = temporary.path().join("archive-link.pith");
    symlink(&fixture.archive, &alias).unwrap();
    let before = std::fs::read(&fixture.archive).unwrap();

    assert!(grant(&alias, "sender", vec!["recipient2"], vec![SELECTED_ID],).is_err());
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), before);
}

#[test]
fn direct_grant_reader_workflow_succeeds_for_a_selected_file() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);

    grant(
        &fixture.archive,
        "sender",
        vec!["recipient2"],
        vec![SELECTED_ID],
    )
    .unwrap();

    let archive = fixture.open_as("recipient2");
    assert!(matches!(
        archive.entry("selected.txt").unwrap().unwrap().kind,
        EntryKind::File {
            available: true,
            ..
        }
    ));
}

#[test]
fn grant_observation_reports_actual_snapshot_reads_and_metadata_tail() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let observation = grant_readers(
        &fixture.archive,
        AppendOptions::new(private_key("sender"), vec![public_key("recipient2")]),
        &[SELECTED_ID],
    )
    .unwrap();

    assert!(observation.source_read_count > 0);
    assert!(observation.source_read_bytes > 0);
    assert!(observation.final_archive_bytes > observation.base_archive_bytes);
}

#[test]
fn newly_authorized_reader_can_access_selected_files() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);

    grant(
        &fixture.archive,
        "sender",
        vec!["recipient2"],
        vec![SELECTED_ID],
    )
    .unwrap();

    let mut contents = Vec::new();
    fixture
        .open_as("recipient2")
        .copy_to("selected.txt", &mut contents)
        .unwrap();
    assert_eq!(contents, b"selected base payload");
}

#[test]
fn selective_grant_leaves_unselected_files_unavailable() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);

    grant(
        &fixture.archive,
        "sender",
        vec!["recipient2"],
        vec![SELECTED_ID],
    )
    .unwrap();

    assert!(matches!(
        fixture
            .open_as("recipient2")
            .copy_to("withheld.txt", &mut Vec::new()),
        Err(PithosError::ContentUnavailable)
    ));
}

#[test]
fn an_existing_authorized_recipient_can_regrant_but_an_unrelated_key_cannot() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);

    grant(
        &fixture.archive,
        "recipient1",
        vec!["recipient2"],
        vec![SELECTED_ID],
    )
    .unwrap();
    assert!(
        fixture
            .open_as("recipient2")
            .copy_to("selected.txt", &mut Vec::new())
            .is_ok()
    );

    let original = std::fs::read(&fixture.archive).unwrap();
    assert!(
        grant(
            &fixture.archive,
            "recipient2",
            vec!["sender"],
            vec![WITHHELD_ID],
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_a_missing_file_id() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(
            &fixture.archive,
            "sender",
            vec!["recipient2"],
            vec![u64::MAX],
        ),
        Err(FsError::Core {
            source: PithosError::SnapshotFileIdNotFound(u64::MAX),
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_duplicate_recipients() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(
            &fixture.archive,
            "sender",
            vec!["recipient2", "recipient2"],
            vec![SELECTED_ID],
        ),
        Err(FsError::Core {
            source: PithosError::DuplicateRecipientKey,
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_duplicate_file_ids() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(
            &fixture.archive,
            "sender",
            vec!["recipient1"],
            vec![SELECTED_ID, SELECTED_ID],
        ),
        Err(FsError::Core {
            source: PithosError::DuplicateRecipientFileId,
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_non_content_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(
            &fixture.archive,
            "sender",
            vec!["recipient2"],
            vec![DIRECTORY_ID],
        ),
        Err(FsError::Core {
            source: PithosError::SnapshotDirectoryHasNoContent(DIRECTORY_ID),
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_empty_recipients_or_ids_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(&fixture.archive, "sender", vec![], vec![SELECTED_ID]),
        Err(FsError::Core {
            source: PithosError::WriterRequiresRecipient,
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
    assert!(matches!(
        grant(&fixture.archive, "sender", vec!["recipient2"], vec![]),
        Err(FsError::Core {
            source: PithosError::GrantRequiresFileId,
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn grant_rejects_unavailable_and_symlink_ids_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        grant(
            &fixture.archive,
            "recipient2",
            vec!["sender"],
            vec![SELECTED_ID],
        ),
        Err(FsError::Core {
            source: PithosError::SnapshotContentUnavailable(SELECTED_ID),
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);

    let archive = archive_with_symlink(&temporary);
    let original = std::fs::read(&archive).unwrap();
    assert!(matches!(
        grant(&archive, "sender", vec!["recipient2"], vec![0]),
        Err(FsError::Core {
            source: PithosError::SnapshotSymlinkHasNoContent(0),
            ..
        })
    ));
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}

#[test]
fn grant_allows_metadata_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let archive = temporary.path().join("metadata.pith");
    let sender = private_key("sender");
    let mut writer = ArchiveWriter::create(
        File::create(&archive).unwrap(),
        WriteOptions::new(sender, vec![public_key("sender"), public_key("recipient1")]),
    )
    .unwrap();
    writer
        .add_metadata(
            ArchivePath::new("description.json").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 2).unwrap(),
            None,
            Cursor::new(b"metadata payload"),
        )
        .unwrap();
    writer.finish().unwrap();

    grant(&archive, "sender", vec!["recipient2"], vec![0]).unwrap();
    let mut contents = Vec::new();
    open(
        &archive,
        AccessKeys::new().with_key(private_key("recipient2")),
    )
    .copy_to("description.json", &mut contents)
    .unwrap();
    assert_eq!(contents, b"metadata payload");
}

#[test]
fn grant_multiple_ids_to_multiple_recipients_in_one_metadata_only_child() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let prefix = std::fs::read(&fixture.archive).unwrap();

    grant(
        &fixture.archive,
        "sender",
        vec!["recipient1", "recipient2"],
        vec![SELECTED_ID, WITHHELD_ID],
    )
    .unwrap();

    for reader in ["recipient1", "recipient2"] {
        let archive = fixture.open_as(reader);
        for path in ["selected.txt", "withheld.txt"] {
            assert!(archive.copy_to(path, &mut Vec::new()).is_ok());
        }
    }

    let updated = std::fs::read(&fixture.archive).unwrap();
    assert!(updated.starts_with(&prefix));
    assert_eq!(
        updated
            .windows(6)
            .filter(|window| *window == b"PITH\x01\x00")
            .count(),
        1
    );
}

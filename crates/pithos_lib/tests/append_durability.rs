mod common;

use common::append::{append, append_fixture};
use common::util::{private_key, public_key};
use pithos_lib::archive::{AppendDurability, AppendOptions};
use pithos_lib::fs::{FsError, append_files};
use std::fs::OpenOptions;
use std::os::unix::fs::symlink;

#[test]
fn append_keeps_the_existing_archive_prefix_unchanged() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();
    let source = fixture.append_source("appended.txt", b"appended payload");

    append(&fixture.archive, vec![source]).unwrap();

    let updated = std::fs::read(&fixture.archive).unwrap();
    assert!(updated.starts_with(&original));
    assert!(
        fixture
            .open_as("recipient1")
            .entry("appended.txt")
            .unwrap()
            .is_some()
    );
}

#[test]
fn append_observation_reports_actual_snapshot_reads_and_tail_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("observed.txt", b"observed append payload");
    let observation = append_files(
        &fixture.archive,
        AppendOptions::new(
            private_key("sender"),
            vec![public_key("sender"), public_key("recipient1")],
        ),
        &[source],
    )
    .unwrap();

    assert!(observation.source_read_count > 0);
    assert!(observation.source_read_bytes > 0);
    assert!(observation.final_archive_bytes > observation.base_archive_bytes);
    assert_eq!(
        observation.final_archive_bytes - observation.base_archive_bytes,
        std::fs::metadata(&fixture.archive).unwrap().len() - observation.base_archive_bytes
    );
}

#[test]
fn append_rejects_an_empty_manifest_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(append(&fixture.archive, Vec::new()).is_err());
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn append_rejects_the_archive_itself_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();

    assert!(matches!(
        append(&fixture.archive, vec![fixture.archive.clone()]),
        Err(FsError::AppendSourceIsArchive { .. })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn direct_append_rejects_a_symlink_archive_target_without_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let alias = temporary.path().join("archive-link.pith");
    symlink(&fixture.archive, &alias).unwrap();
    let source = fixture.append_source("through-link.txt", b"must not append");
    let before = std::fs::read(&fixture.archive).unwrap();

    assert!(append(&alias, vec![source]).is_err());
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), before);
}

#[cfg(unix)]
#[test]
fn direct_append_and_grant_reject_lock_contention_without_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();
    let source = fixture.append_source("locked.txt", b"locked append payload");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&fixture.archive)
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();

    assert!(matches!(
        append(&fixture.archive, vec![source]),
        Err(FsError::AppendLocked { path }) if path == fixture.archive
    ));
    assert!(matches!(
        common::append::grant(
            &fixture.archive,
            "sender",
            vec!["recipient2"],
            vec![common::append::SELECTED_ID],
        ),
        Err(FsError::AppendLocked { path }) if path == fixture.archive
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn sync_all_durability_publishes_a_readable_child() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("durable.txt", b"durable append payload");

    append_files(
        &fixture.archive,
        AppendOptions::new(
            private_key("sender"),
            vec![public_key("sender"), public_key("recipient1")],
        )
        .with_durability(AppendDurability::SyncAll),
        &[source],
    )
    .unwrap();

    let mut contents = Vec::new();
    fixture
        .open_as("recipient1")
        .copy_to("durable.txt", &mut contents)
        .unwrap();
    assert_eq!(contents, b"durable append payload");
}

#[test]
fn manifest_failure_before_mutation_preserves_the_original_archive() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let present = fixture.append_source("present.txt", b"written before the failed source");
    let missing = temporary.path().join("missing.txt");

    let original = std::fs::read(&fixture.archive).unwrap();
    assert!(append(&fixture.archive, vec![present, missing]).is_err());
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

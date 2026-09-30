#[path = "../benches/workloads.rs"]
mod workloads;

use pithos_lib::archive::{AccessKeys, Archive, EntryKind, OpenOptions};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::{FileSource, MemorySource};

fn open_memory(bytes: Vec<u8>, key: PrivateKey) -> Archive<MemorySource> {
    Archive::open(
        MemorySource::new(bytes),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(key)),
    )
    .unwrap()
}

#[test]
fn incremental_workload_declares_the_ancestor_first() {
    let sender = PrivateKey::generate();
    let ancestor = open_memory(
        workloads::build_incremental(sender.duplicate(), sender.public_key(), 1_000),
        sender,
    );
    assert_eq!(ancestor.entries().len(), 1_001);
    assert_eq!(
        ancestor.entry("root").unwrap().unwrap().kind,
        EntryKind::Directory
    );
}

#[test]
fn metadata_workload_contains_real_content_pairs_and_references() {
    let sender = PrivateKey::generate();
    let archive = open_memory(
        workloads::build_metadata_pairs(sender.duplicate(), sender.public_key(), 100),
        sender,
    );
    let entries = archive.entries().collect::<Vec<_>>();
    assert_eq!(entries.len(), 200);
    assert_eq!(
        entries
            .iter()
            .filter(|entry| matches!(entry.kind, EntryKind::Metadata { .. }))
            .count(),
        100
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| matches!(entry.kind, EntryKind::File { .. }))
            .count(),
        100
    );
    assert_eq!(
        entries
            .iter()
            .filter(|entry| entry.references.len() == 1)
            .count(),
        100
    );
}

#[test]
fn conflicts_are_hierarchy_conflicts_against_one_thousand_entries() {
    let sender = PrivateKey::generate();
    for direction in [
        workloads::ConflictDirection::ExistingAncestor,
        workloads::ConflictDirection::MissingAncestor,
    ] {
        let mut fixture = workloads::build_conflict_fixture(
            sender.duplicate(),
            sender.public_key(),
            1_000,
            direction,
        );
        assert_ne!(fixture.candidate, "root/child-000000");
        assert!(matches!(
            workloads::reject_conflict(&mut fixture),
            pithos_lib::error::PithosError::InvalidArchivePath { .. }
        ));
        fixture
            .writer
            .add_directory(
                pithos_lib::archive::ArchivePath::new("still-usable").unwrap(),
                pithos_lib::archive::EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
    }
}

#[test]
fn extraction_workload_materializes_all_one_hundred_files() {
    let sender = PrivateKey::generate();
    let fixture = workloads::build_extraction_fixture(sender.duplicate(), sender.public_key());
    let destination = tempfile::tempdir().unwrap();
    assert_eq!(
        workloads::extract_all(&fixture, destination.path()),
        (workloads::EXTRACTION_COUNT * workloads::EXTRACTION_PAYLOAD_BYTES) as u64
    );
    assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 100);
    assert_eq!(
        std::fs::read(destination.path().join("entry-000099"))
            .unwrap()
            .len(),
        workloads::EXTRACTION_PAYLOAD_BYTES
    );
}

#[test]
fn open_merge_fixture_has_two_generations_and_entries_from_both() {
    let sender = PrivateKey::generate();
    let fixture = workloads::build_chain_fixture(sender.duplicate(), sender.public_key());
    let bytes = std::fs::read(&fixture.archive_path).unwrap();
    assert_eq!(
        bytes
            .windows(8)
            .filter(|window| *window == b"PITHOSDR")
            .count(),
        2
    );
    let archive = Archive::open(
        FileSource::open(&fixture.archive_path).unwrap(),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    assert!(archive.entry("ancestor.bin").unwrap().is_some());
    assert!(archive.entry("child.bin").unwrap().is_some());
}

#[test]
fn append_scaling_fixture_contains_every_generation_and_planned_entry() {
    let sender = PrivateKey::generate();
    let fixture =
        workloads::build_append_scaling_fixture(sender.duplicate(), sender.public_key(), 10, 4);
    let bytes = std::fs::read(&fixture.archive_path).unwrap();
    assert_eq!(
        bytes
            .windows(8)
            .filter(|window| *window == b"PITHOSDR")
            .count(),
        11
    );
    let archive = Archive::open(
        FileSource::open(&fixture.archive_path).unwrap(),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    assert_eq!(archive.entries().len(), 41);
    for path in [
        "ancestor.bin",
        "generation-0000-entry-0000.bin",
        "generation-0009-entry-0003.bin",
    ] {
        assert!(archive.entry(path).unwrap().is_some(), "missing {path}");
    }
}

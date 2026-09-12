mod common;

use common::append::{WITHHELD_ID, append, append_fixture, append_with_cdc, archive_with_entry};
use pithos_lib::archive::CdcConfig;
use pithos_lib::error::PithosError;
use pithos_lib::fs::FsError;

#[test]
fn direct_append_file_workflow_adds_a_file() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("appended.txt", b"appended payload");

    append(&fixture.archive, vec![source]).unwrap();

    let archive = fixture.open_as("recipient1");
    let mut contents = Vec::new();
    archive.copy_to("appended.txt", &mut contents).unwrap();
    assert_eq!(contents, b"appended payload");
}

#[cfg(unix)]
#[test]
fn append_rejects_hard_link_aliases_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();
    let alias = temporary.path().join("archive-alias.pith");
    std::fs::hard_link(&fixture.archive, &alias).unwrap();

    assert!(matches!(
        append(&fixture.archive, vec![alias]),
        Err(FsError::AppendSourceIsArchive { .. })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[cfg(unix)]
#[test]
fn append_rejects_recursive_hard_link_aliases_before_mutation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();
    let input = temporary.path().join("input");
    std::fs::create_dir(&input).unwrap();
    std::fs::write(input.join("ordinary.txt"), b"ordinary input").unwrap();
    std::fs::hard_link(&fixture.archive, input.join("archive-alias.pith")).unwrap();

    assert!(matches!(
        append(&fixture.archive, vec![input]),
        Err(FsError::AppendSourceIsArchive { .. })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn append_links_the_parent_directory_to_existing_entries() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("appended.txt", b"appended payload");

    append(&fixture.archive, vec![source]).unwrap();

    let archive = fixture.open_as("recipient1");
    assert!(archive.entry("selected.txt").unwrap().is_some());
    assert!(archive.entry("appended.txt").unwrap().is_some());
}

#[test]
fn append_reuses_the_earliest_compatible_block_across_three_generations() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let prefix = std::fs::read(&fixture.archive).unwrap();
    let source = fixture.append_source("reused.txt", b"selected base payload");

    append(&fixture.archive, vec![source]).unwrap();

    let appended = std::fs::read(&fixture.archive).unwrap();
    let suffix = &appended[prefix.len()..];
    assert!(!suffix.windows(4).any(|window| window == b"BLCK"));
    let archive = fixture.open_as("recipient1");
    let mut contents = Vec::new();
    archive.copy_to("reused.txt", &mut contents).unwrap();
    assert_eq!(contents, b"selected base payload");
}

#[test]
fn append_continues_file_id_allocation() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("appended.txt", b"appended payload");

    append(&fixture.archive, vec![source]).unwrap();

    let archive = fixture.open_as("recipient1");
    assert_eq!(
        archive.entry("appended.txt").unwrap().unwrap().id,
        WITHHELD_ID + 1
    );
}

#[test]
fn append_rejects_active_child_duplicate_paths() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let source = fixture.append_source("duplicate.txt", b"duplicate payload");

    let original = std::fs::read(&fixture.archive).unwrap();
    assert!(matches!(
        append(&fixture.archive, vec![source.clone(), source]),
        Err(FsError::Core {
            source: PithosError::PathOccupied(_),
            ..
        })
    ));
    assert_eq!(std::fs::read(&fixture.archive).unwrap(), original);
}

#[test]
fn append_rejects_ancestor_hierarchy_conflicts_in_both_directions() {
    let temporary = tempfile::tempdir().unwrap();
    let archive = archive_with_entry(&temporary, "child");
    let original = std::fs::read(&archive).unwrap();
    let root = temporary.path().join("root");
    std::fs::create_dir_all(root.join("child")).unwrap();
    std::fs::write(root.join("child/leaf"), b"new").unwrap();
    assert!(append(&archive, vec![root]).is_err());
    assert_eq!(std::fs::read(&archive).unwrap(), original);

    let temporary = tempfile::tempdir().unwrap();
    let archive = archive_with_entry(&temporary, "parent/child");
    let original = std::fs::read(&archive).unwrap();
    let source = temporary.path().join("parent");
    std::fs::write(&source, b"new").unwrap();
    assert!(append(&archive, vec![source]).is_err());
    assert_eq!(std::fs::read(&archive).unwrap(), original);
}

#[test]
fn append_streams_multiblock_content_and_writes_one_child_directory_without_a_header() {
    let temporary = tempfile::tempdir().unwrap();
    let fixture = append_fixture(&temporary);
    let original = std::fs::read(&fixture.archive).unwrap();
    let source = fixture.append_source(
        "multiblock.bin",
        &(0..8192u32).flat_map(u32::to_le_bytes).collect::<Vec<_>>(),
    );

    append_with_cdc(
        &fixture.archive,
        CdcConfig::new(64, 256, 1024).unwrap(),
        vec![source],
    )
    .unwrap();

    let updated = std::fs::read(&fixture.archive).unwrap();
    let suffix = &updated[original.len()..];
    assert!(
        suffix
            .windows(4)
            .filter(|window| *window == b"BLCK")
            .count()
            > 1
    );
    assert_eq!(
        suffix
            .windows(8)
            .filter(|window| *window == b"PITHOSDR")
            .count(),
        1
    );
    assert_eq!(
        updated
            .windows(6)
            .filter(|window| *window == b"PITH\x01\x00")
            .count(),
        1
    );
    let mut contents = Vec::new();
    fixture
        .open_as("recipient1")
        .copy_to("multiblock.bin", &mut contents)
        .unwrap();
    assert_eq!(contents.len(), 8192 * 4);
}

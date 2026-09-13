use crate::archive::{AppendSnapshot, ArchivePath};
use crate::error::PithosError;
use crate::format::directory::DirectoryEntries;
use crate::format::file_entry::{BlockDataState, FileEntry, FileType, VALID_PERMISSION_BITS};
use std::collections::HashMap;

fn invalid_path(path: &str, reason: impl Into<String>) -> PithosError {
    PithosError::InvalidArchivePath {
        path: path.to_string(),
        reason: reason.into(),
    }
}

pub(crate) fn validate_entry_path(path: &str) -> Result<(), PithosError> {
    if path.is_empty() {
        return Err(invalid_path(path, "path is empty"));
    }
    if path.contains('\0') {
        return Err(invalid_path(path, "NUL is not allowed"));
    }
    if path.contains('\\') {
        return Err(invalid_path(path, "backslash is not allowed"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(invalid_path(path, "path must not start or end with /"));
    }
    if path.as_bytes().get(1) == Some(&b':') {
        return Err(invalid_path(path, "drive forms are not allowed"));
    }
    for component in path.split('/') {
        if component.is_empty() {
            return Err(invalid_path(path, "empty path components are not allowed"));
        }
        if component == "." || component == ".." {
            return Err(invalid_path(path, "dot components are not allowed"));
        }
    }
    Ok(())
}

pub(crate) fn validate_symlink_target(path: &str, target: &str) -> Result<(), PithosError> {
    validate_entry_path(path).map_err(|error| PithosError::InvalidSymlinkTarget {
        path: path.to_string(),
        target: target.to_string(),
        reason: error.to_string(),
    })?;
    if target.is_empty() {
        return Err(PithosError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string(),
            reason: "target is empty".into(),
        });
    }
    if target.contains('\0') || target.contains('\\') {
        return Err(PithosError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string(),
            reason: "invalid separator or NUL".into(),
        });
    }
    if target.starts_with('/') || target.as_bytes().get(1) == Some(&b':') {
        return Err(PithosError::InvalidSymlinkTarget {
            path: path.to_string(),
            target: target.to_string(),
            reason: "absolute or drive target".into(),
        });
    }
    let mut depth = path.split('/').count() - 1;
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            return Err(PithosError::InvalidSymlinkTarget {
                path: path.to_string(),
                target: target.to_string(),
                reason: "empty or dot component".into(),
            });
        }
        if component == ".." {
            if depth == 0 {
                return Err(PithosError::InvalidSymlinkTarget {
                    path: path.to_string(),
                    target: target.to_string(),
                    reason: "target escapes archive root".into(),
                });
            }
            depth -= 1;
        } else {
            depth += 1;
        }
    }
    Ok(())
}

pub(crate) fn validate_entry(path: &str, entry: &FileEntry) -> Result<(), PithosError> {
    validate_entry_path(path)?;
    if entry.permissions & !VALID_PERMISSION_BITS != 0 {
        return Err(PithosError::InvalidPermissions(entry.permissions));
    }
    match entry.file_type {
        FileType::Data | FileType::Metadata => {
            if entry.symlink_target.is_some() {
                return Err(PithosError::InvalidSymlinkEntry {
                    path: path.into(),
                    reason: "non-symlink has a target".into(),
                });
            }
        }
        FileType::Directory => {
            if entry.file_size != 0 {
                return Err(PithosError::InvalidEntryCombination {
                    path: path.into(),
                    reason: "directory has nonzero file size".into(),
                });
            }
            if entry.symlink_target.is_some() {
                return Err(PithosError::InvalidSymlinkEntry {
                    path: path.into(),
                    reason: "non-symlink has a target".into(),
                });
            }
            if !matches!(&entry.block_data, BlockDataState::Decrypted(blocks) if blocks.is_empty())
            {
                return Err(PithosError::InvalidBlockDataState(
                    "directory has block material".into(),
                ));
            }
        }
        FileType::Symlink => {
            if entry.file_size != 0 {
                return Err(PithosError::InvalidEntryCombination {
                    path: path.into(),
                    reason: "symlink has nonzero file size".into(),
                });
            }
            let target = entry.symlink_target.as_deref().ok_or_else(|| {
                PithosError::InvalidSymlinkEntry {
                    path: path.into(),
                    reason: "missing target".into(),
                }
            })?;
            if !matches!(&entry.block_data, BlockDataState::Decrypted(blocks) if blocks.is_empty())
            {
                return Err(PithosError::InvalidSymlinkEntry {
                    path: path.into(),
                    reason: "symlink has block material".into(),
                });
            }
            validate_symlink_target(path, target)?;
        }
    }
    Ok(())
}

fn validate_candidate_hierarchy(
    map: &DirectoryEntries,
    snapshot: Option<&AppendSnapshot>,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    for (index, _) in path.match_indices('/') {
        let ancestor = &path[..index];
        if let Some(existing) = map.get_by_path(ancestor) {
            if existing.file_type != FileType::Directory {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("file entry {ancestor} is an ancestor"),
                });
            }
            continue;
        }
        let ancestor_path = ArchivePath::new(ancestor)?;
        match snapshot.and_then(|snapshot| snapshot.entry_at_path(&ancestor_path)) {
            Some(existing)
                if !matches!(
                    existing.kind,
                    crate::archive::snapshot::SnapshotEntryKind::Directory
                ) =>
            {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("file entry {ancestor} is an ancestor"),
                });
            }
            Some(_) => {}
            None => {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("missing directory ancestor {ancestor}"),
                });
            }
        }
    }

    if entry.file_type != FileType::Directory
        && let Some(successor) = map.first_path_after(path)
        && successor.starts_with(path)
        && successor.as_bytes().get(path.len()) == Some(&b'/')
    {
        return Err(PithosError::InvalidArchivePath {
            path: path.into(),
            reason: format!("entry is an ancestor of {successor}"),
        });
    }

    Ok(())
}

#[cfg(test)]
pub(crate) fn validate_existing_candidate(
    map: &DirectoryEntries,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    validate_candidate_hierarchy(map, None, path, entry)
}

pub(crate) fn validate_new_candidate(
    map: &DirectoryEntries,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    if map.get_by_path(path).is_some() {
        return Err(PithosError::PathOccupied(format!(
            "File path already occupied: {path}"
        )));
    }
    validate_candidate_hierarchy(map, None, path, entry)
}

pub(crate) fn validate_new_candidate_with_snapshot(
    map: &DirectoryEntries,
    path: &str,
    entry: &FileEntry,
    snapshot: &AppendSnapshot,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    if map.get_by_path(path).is_some() {
        return Err(PithosError::PathOccupied(format!(
            "File path already occupied: {path}"
        )));
    }
    validate_candidate_hierarchy(map, Some(snapshot), path, entry)
}

pub(crate) fn validate_directory_entries(map: &DirectoryEntries) -> Result<(), PithosError> {
    for (_, path, entry) in map.iter() {
        validate_entry(path, entry)?;
    }

    validate_directory_entry_hierarchy(map)
}

pub(crate) fn validate_directory_entry_hierarchy(
    map: &DirectoryEntries,
) -> Result<(), PithosError> {
    let mut earlier: HashMap<&str, &FileEntry> = HashMap::new();
    for (_, path, entry) in map.iter() {
        for (offset, _) in path.match_indices('/') {
            let ancestor = &path[..offset];
            if let Some(existing) = earlier.get(ancestor) {
                if existing.file_type != FileType::Directory {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.into(),
                        reason: format!("file entry {ancestor} is an ancestor"),
                    });
                }
            } else if map.get_by_path(ancestor).is_some() {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("ancestor {ancestor} is declared after its child"),
                });
            }
        }
        earlier.insert(path, entry);
    }
    Ok(())
}

pub(crate) fn validate_directory_entry_hierarchy_complete(
    map: &DirectoryEntries,
) -> Result<(), PithosError> {
    let mut earlier: HashMap<&str, &FileEntry> = HashMap::new();
    for (_, path, entry) in map.iter() {
        for (offset, _) in path.match_indices('/') {
            let ancestor = &path[..offset];
            let Some(existing) = earlier.get(ancestor) else {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("missing directory ancestor {ancestor}"),
                });
            };
            if existing.file_type != FileType::Directory {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("file entry {ancestor} is an ancestor"),
                });
            }
        }
        earlier.insert(path, entry);
    }
    Ok(())
}

pub(crate) fn validate_directory_entry_hierarchy_with_snapshot(
    map: &DirectoryEntries,
    snapshot: &AppendSnapshot,
) -> Result<(), PithosError> {
    let mut earlier: HashMap<&str, &FileEntry> = HashMap::new();
    for (_, path, entry) in map.iter() {
        for (offset, _) in path.match_indices('/') {
            let ancestor = &path[..offset];
            if let Some(existing) = earlier.get(ancestor) {
                if existing.file_type != FileType::Directory {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.into(),
                        reason: format!("file entry {ancestor} is an ancestor"),
                    });
                }
                continue;
            }
            let ancestor_path = ArchivePath::new(ancestor)?;
            match snapshot.entry_at_path(&ancestor_path) {
                Some(existing)
                    if !matches!(
                        existing.kind,
                        crate::archive::snapshot::SnapshotEntryKind::Directory
                    ) =>
                {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.into(),
                        reason: format!("file entry {ancestor} is an ancestor"),
                    });
                }
                Some(_) => {}
                None => {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.into(),
                        reason: format!("missing directory ancestor {ancestor}"),
                    });
                }
            }
        }
        earlier.insert(path, entry);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(file_type: FileType, target: Option<&str>, blocks: BlockDataState) -> FileEntry {
        configured_entry(file_type, target, blocks, 0, 0o644)
    }

    fn configured_entry(
        file_type: FileType,
        target: Option<&str>,
        blocks: BlockDataState,
        file_size: u64,
        permissions: u32,
    ) -> FileEntry {
        FileEntry {
            file_type,
            block_data: blocks,
            created: 0,
            modified: 0,
            file_size,
            permissions,
            references: vec![],
            symlink_target: target.map(str::to_owned),
        }
    }

    #[test]
    fn archive_path_valid_entry_corpus() {
        for path in ["file", "nested/file", "ユニコード/file"] {
            assert!(validate_entry_path(path).is_ok());
        }
    }
    #[test]
    fn archive_path_invalid_entry_corpus() {
        for path in [
            "",
            "/file",
            "file/",
            "a//b",
            "a/./b",
            "a/../b",
            "a\\b",
            "C:",
            "C:/x",
            "\\\\server\\x",
            "a\0b",
        ] {
            assert!(validate_entry_path(path).is_err(), "{path:?}");
        }
    }
    #[test]
    fn archive_path_symlink_target_corpus() {
        for target in ["target", "nested/target", "../target", "../dangling"] {
            assert!(validate_symlink_target("nested/link", target).is_ok());
        }
        for target in [
            "",
            ".",
            "target/.",
            "target//child",
            "target/",
            "a\0b",
            "a\\b",
            "/absolute",
            "C:",
            "C:/target",
            "\\\\server\\target",
            "../target",
            "../../target",
        ] {
            assert!(
                validate_symlink_target("link", target).is_err(),
                "{target:?}"
            );
        }
        assert!(validate_symlink_target("", "target").is_err());
        assert!(validate_symlink_target("bad//link", "target").is_err());
        assert!(validate_symlink_target("bad/../link", "target").is_err());
    }

    #[test]
    fn archive_path_entry_invariants_corpus() {
        assert!(
            validate_entry(
                "link",
                &entry(
                    FileType::Symlink,
                    None,
                    BlockDataState::Decrypted(vec![].into())
                )
            )
            .is_err()
        );
        assert!(
            validate_entry(
                "file",
                &entry(
                    FileType::Data,
                    Some("target"),
                    BlockDataState::Decrypted(vec![].into())
                )
            )
            .is_err()
        );
        assert!(
            validate_entry(
                "link",
                &entry(
                    FileType::Symlink,
                    Some("target"),
                    BlockDataState::Decrypted(vec![([0; 32], [0; 32])].into())
                )
            )
            .is_err()
        );
        assert!(
            validate_entry(
                "link",
                &entry(
                    FileType::Symlink,
                    Some("target"),
                    BlockDataState::Encrypted(vec![])
                )
            )
            .is_err()
        );
    }

    #[test]
    fn entry_semantics_cover_every_file_type_combination() {
        for valid in [
            configured_entry(
                FileType::Data,
                None,
                BlockDataState::Encrypted(vec![1]),
                12,
                0o644,
            ),
            configured_entry(
                FileType::Metadata,
                None,
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o600,
            ),
            configured_entry(
                FileType::Directory,
                None,
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o755,
            ),
            configured_entry(
                FileType::Symlink,
                Some("target"),
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o777,
            ),
        ] {
            assert!(validate_entry("entry", &valid).is_ok(), "{valid:?}");
        }

        for invalid in [
            configured_entry(
                FileType::Data,
                Some("target"),
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o644,
            ),
            configured_entry(
                FileType::Metadata,
                Some("target"),
                BlockDataState::Encrypted(vec![]),
                0,
                0o644,
            ),
            configured_entry(
                FileType::Directory,
                None,
                BlockDataState::Encrypted(vec![]),
                0,
                0o755,
            ),
            configured_entry(
                FileType::Directory,
                None,
                BlockDataState::Decrypted(vec![([1; 32], [2; 32])].into()),
                0,
                0o755,
            ),
            configured_entry(
                FileType::Directory,
                Some("target"),
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o755,
            ),
            configured_entry(
                FileType::Directory,
                None,
                BlockDataState::Decrypted(vec![].into()),
                1,
                0o755,
            ),
            configured_entry(
                FileType::Symlink,
                None,
                BlockDataState::Decrypted(vec![].into()),
                0,
                0o777,
            ),
            configured_entry(
                FileType::Symlink,
                Some("target"),
                BlockDataState::Encrypted(vec![]),
                0,
                0o777,
            ),
            configured_entry(
                FileType::Symlink,
                Some("target"),
                BlockDataState::Decrypted(vec![([1; 32], [2; 32])].into()),
                0,
                0o777,
            ),
            configured_entry(
                FileType::Symlink,
                Some("target"),
                BlockDataState::Decrypted(vec![].into()),
                1,
                0o777,
            ),
        ] {
            assert!(validate_entry("entry", &invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn entry_permissions_accept_only_the_defined_twelve_bits() {
        for permissions in [0, 0o7777] {
            let entry = configured_entry(
                FileType::Data,
                None,
                BlockDataState::Encrypted(vec![]),
                0,
                permissions,
            );
            assert!(validate_entry("entry", &entry).is_ok(), "{permissions:#o}");
        }
        for permissions in [0o10000, u32::MAX] {
            let entry = configured_entry(
                FileType::Data,
                None,
                BlockDataState::Encrypted(vec![]),
                0,
                permissions,
            );
            assert!(validate_entry("entry", &entry).is_err(), "{permissions:#o}");
        }
    }

    #[test]
    fn archive_path_candidate_and_map_conflicts_are_order_independent() {
        let file = entry(
            FileType::Data,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );
        let link = entry(
            FileType::Symlink,
            Some("target"),
            BlockDataState::Decrypted(vec![].into()),
        );
        let directory = entry(
            FileType::Directory,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );

        for (ancestor_path, ancestor) in [("a", file.clone()), ("a", link.clone())] {
            for order in [0, 1] {
                let mut map = DirectoryEntries::new();
                if order == 0 {
                    map.insert(0, ancestor_path, ancestor.clone()).unwrap();
                    map.insert(1, "a/child", file.clone()).unwrap();
                } else {
                    map.insert(0, "a/child", file.clone()).unwrap();
                    map.insert(1, ancestor_path, ancestor.clone()).unwrap();
                }
                assert!(validate_directory_entries(&map).is_err());
            }
        }

        for order in [0, 1] {
            let mut map = DirectoryEntries::new();
            if order == 0 {
                map.insert(0, "a/child", file.clone()).unwrap();
                map.insert(1, "a", file.clone()).unwrap();
            } else {
                map.insert(0, "a", file.clone()).unwrap();
                map.insert(1, "a/child", file.clone()).unwrap();
            }
            assert!(validate_directory_entries(&map).is_err());
        }

        let mut parent_first = DirectoryEntries::new();
        parent_first.insert(0, "a", directory.clone()).unwrap();
        parent_first.insert(1, "a/child", file.clone()).unwrap();
        assert!(validate_directory_entries(&parent_first).is_ok());

        let mut child_first = DirectoryEntries::new();
        child_first.insert(0, "a/child", file.clone()).unwrap();
        child_first.insert(1, "a", directory.clone()).unwrap();
        assert!(validate_directory_entries(&child_first).is_err());
    }

    #[test]
    fn archive_path_candidate_validation_handles_component_boundaries_and_depth() {
        let file = entry(
            FileType::Data,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );
        let directory = entry(
            FileType::Directory,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );

        let mut map = DirectoryEntries::new();
        map.insert(0, "a", file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a/child", &file).is_err());

        let mut map = DirectoryEntries::new();
        map.insert(0, "a/child", file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a", &file).is_err());

        let mut map = DirectoryEntries::new();
        map.insert(0, "a", directory.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a/child", &file).is_ok());

        let map = DirectoryEntries::new();
        assert!(validate_new_candidate(&map, "a/child", &file).is_err());
        assert!(validate_new_candidate(&map, "a/b/child", &file).is_err());

        let mut map = DirectoryEntries::new();
        for (id, path) in [(0, "ab"), (1, "a!"), (2, "a.b"), (3, "a/child")] {
            map.insert(id, path, file.clone()).unwrap();
        }
        assert!(validate_new_candidate(&map, "a", &file).is_err());
        assert!(validate_new_candidate(&map, "a!x", &file).is_ok());
        assert!(validate_new_candidate(&map, "a.bx", &file).is_ok());
        assert!(validate_new_candidate(&map, "abx", &file).is_ok());

        let mut map = DirectoryEntries::new();
        map.insert(0, "ユニコード", file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "ユニコード/子", &file).is_err());

        let deep = (0..64)
            .map(|part| format!("part{part}"))
            .collect::<Vec<_>>();
        let ancestor = deep.join("/");
        let descendant = format!("{ancestor}/leaf");
        let mut map = DirectoryEntries::new();
        map.insert(0, descendant, file.clone()).unwrap();
        assert!(validate_new_candidate(&map, &ancestor, &file).is_err());
    }

    #[test]
    fn archive_path_existing_and_new_candidate_exact_path_semantics() {
        let file = entry(
            FileType::Data,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );
        let mut map = DirectoryEntries::new();
        map.insert(0, "occupied", file.clone()).unwrap();

        assert!(validate_existing_candidate(&map, "occupied", &file).is_ok());
        assert!(matches!(
            validate_new_candidate(&map, "occupied", &file),
            Err(PithosError::PathOccupied(message)) if message == "File path already occupied: occupied"
        ));
    }

    #[test]
    fn archive_path_component_order_keeps_descendants_adjacent() {
        let file = entry(
            FileType::Data,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );
        let mut map = DirectoryEntries::new();
        for (id, path) in [(0, "a"), (1, "a!"), (2, "a/child")] {
            map.insert(id, path, file.clone()).unwrap();
        }

        assert_eq!(
            map.iter_ordered().map(|(path, _)| path).collect::<Vec<_>>(),
            ["a", "a/child", "a!"]
        );
        assert!(validate_directory_entries(&map).is_err());
    }

    #[test]
    fn descending_insertions_produce_component_path_order() {
        let file = entry(
            FileType::Data,
            None,
            BlockDataState::Decrypted(vec![].into()),
        );
        let mut map = DirectoryEntries::new();
        for id in (0..10_000u64).rev() {
            map.insert(id, format!("entry-{id:05}"), file.clone())
                .unwrap();
        }

        assert_eq!(map.first_path_after("entry-04999"), Some("entry-05000"));
        assert_eq!(
            map.iter_ordered().next().map(|(path, _)| path),
            Some("entry-00000")
        );
    }
}

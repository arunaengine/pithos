use crate::error::PithosError;
use crate::helpers::file_entry_map::FileEntryMap;
use crate::model::structs::{BlockDataState, FileEntry, FileType};

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
    match (&entry.file_type, &entry.symlink_target, &entry.block_data) {
        (FileType::Symlink, Some(target), BlockDataState::Decrypted(blocks))
            if blocks.is_empty() =>
        {
            validate_symlink_target(path, target)
        }
        (FileType::Symlink, None, _) => Err(PithosError::InvalidSymlinkEntry {
            path: path.into(),
            reason: "missing target".into(),
        }),
        (FileType::Symlink, Some(_), BlockDataState::Decrypted(blocks)) if !blocks.is_empty() => {
            Err(PithosError::InvalidSymlinkEntry {
                path: path.into(),
                reason: "symlink has block references".into(),
            })
        }
        (FileType::Symlink, Some(_), BlockDataState::Encrypted(_)) => {
            Err(PithosError::InvalidSymlinkEntry {
                path: path.into(),
                reason: "encrypted symlink block data".into(),
            })
        }
        (_, Some(_), _) => Err(PithosError::InvalidSymlinkEntry {
            path: path.into(),
            reason: "non-symlink has a target".into(),
        }),
        _ => Ok(()),
    }
}

fn validate_candidate_hierarchy(
    map: &FileEntryMap,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    for (index, _) in path.match_indices('/') {
        let ancestor = &path[..index];
        if map
            .get_by_path(ancestor)
            .is_some_and(|existing| existing.file_type != FileType::Directory)
        {
            return Err(PithosError::InvalidArchivePath {
                path: path.into(),
                reason: format!("file entry {ancestor} is an ancestor"),
            });
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

pub(crate) fn validate_existing_candidate(
    map: &FileEntryMap,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    validate_candidate_hierarchy(map, path, entry)
}

pub(crate) fn validate_new_candidate(
    map: &FileEntryMap,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    if map.get_by_path(path).is_some() {
        return Err(PithosError::PathOccupied(format!(
            "File path already occupied: {path}"
        )));
    }
    validate_candidate_hierarchy(map, path, entry)
}

pub(crate) fn validate_map(map: &FileEntryMap) -> Result<(), PithosError> {
    for (_, path, entry) in map {
        validate_entry(path, entry)?;
    }

    validate_hierarchy(map)
}

pub(crate) fn validate_hierarchy(map: &FileEntryMap) -> Result<(), PithosError> {
    let mut entries = map.iter_ordered();
    let Some((mut previous_path, mut previous_entry)) = entries.next() else {
        return Ok(());
    };

    for (path, entry) in entries {
        if previous_entry.file_type != FileType::Directory
            && path.starts_with(previous_path)
            && path.as_bytes().get(previous_path.len()) == Some(&b'/')
        {
            return Err(PithosError::InvalidArchivePath {
                path: previous_path.into(),
                reason: format!("entry is an ancestor of {path}"),
            });
        }

        previous_path = path;
        previous_entry = entry;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::file_entry_map::Key;

    fn entry(file_type: FileType, target: Option<&str>, blocks: BlockDataState) -> FileEntry {
        FileEntry {
            file_type,
            block_data: blocks,
            created: 0,
            modified: 0,
            file_size: 0,
            permissions: 0o644,
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
                &entry(FileType::Symlink, None, BlockDataState::Decrypted(vec![]))
            )
            .is_err()
        );
        assert!(
            validate_entry(
                "file",
                &entry(
                    FileType::Data,
                    Some("target"),
                    BlockDataState::Decrypted(vec![])
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
                    BlockDataState::Decrypted(vec![([0; 32], [0; 32])])
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
    fn archive_path_candidate_and_map_conflicts_are_order_independent() {
        let file = entry(FileType::Data, None, BlockDataState::Decrypted(vec![]));
        let link = entry(
            FileType::Symlink,
            Some("target"),
            BlockDataState::Decrypted(vec![]),
        );
        let directory = entry(FileType::Directory, None, BlockDataState::Decrypted(vec![]));

        for (ancestor_path, ancestor) in [("a", file.clone()), ("a", link.clone())] {
            for order in [0, 1] {
                let mut map = FileEntryMap::new();
                if order == 0 {
                    map.insert(Key::new(0, ancestor_path), ancestor.clone())
                        .unwrap();
                    map.insert(Key::new(1, "a/child"), file.clone()).unwrap();
                } else {
                    map.insert(Key::new(0, "a/child"), file.clone()).unwrap();
                    map.insert(Key::new(1, ancestor_path), ancestor.clone())
                        .unwrap();
                }
                assert!(validate_map(&map).is_err());
            }
        }

        for order in [0, 1] {
            let mut map = FileEntryMap::new();
            if order == 0 {
                map.insert(Key::new(0, "a/child"), file.clone()).unwrap();
                map.insert(Key::new(1, "a"), file.clone()).unwrap();
            } else {
                map.insert(Key::new(0, "a"), file.clone()).unwrap();
                map.insert(Key::new(1, "a/child"), file.clone()).unwrap();
            }
            assert!(validate_map(&map).is_err());
        }

        for order in [0, 1] {
            let mut map = FileEntryMap::new();
            if order == 0 {
                map.insert(Key::new(0, "a"), directory.clone()).unwrap();
                map.insert(Key::new(1, "a/child"), file.clone()).unwrap();
            } else {
                map.insert(Key::new(0, "a/child"), file.clone()).unwrap();
                map.insert(Key::new(1, "a"), directory.clone()).unwrap();
            }
            assert!(validate_map(&map).is_ok());
        }
    }

    #[test]
    fn archive_path_candidate_validation_handles_component_boundaries_and_depth() {
        let file = entry(FileType::Data, None, BlockDataState::Decrypted(vec![]));
        let directory = entry(FileType::Directory, None, BlockDataState::Decrypted(vec![]));

        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, "a"), file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a/child", &file).is_err());

        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, "a/child"), file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a", &file).is_err());

        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, "a"), directory.clone()).unwrap();
        assert!(validate_new_candidate(&map, "a/child", &file).is_ok());

        let mut map = FileEntryMap::new();
        for (id, path) in [(0, "ab"), (1, "a!"), (2, "a.b"), (3, "a/child")] {
            map.insert(Key::new(id, path), file.clone()).unwrap();
        }
        assert!(validate_new_candidate(&map, "a", &file).is_err());
        assert!(validate_new_candidate(&map, "a!x", &file).is_ok());
        assert!(validate_new_candidate(&map, "a.bx", &file).is_ok());
        assert!(validate_new_candidate(&map, "abx", &file).is_ok());

        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, "ユニコード"), file.clone()).unwrap();
        assert!(validate_new_candidate(&map, "ユニコード/子", &file).is_err());

        let deep = (0..64)
            .map(|part| format!("part{part}"))
            .collect::<Vec<_>>();
        let ancestor = deep.join("/");
        let descendant = format!("{ancestor}/leaf");
        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, descendant), file.clone()).unwrap();
        assert!(validate_new_candidate(&map, &ancestor, &file).is_err());
    }

    #[test]
    fn archive_path_existing_and_new_candidate_exact_path_semantics() {
        let file = entry(FileType::Data, None, BlockDataState::Decrypted(vec![]));
        let mut map = FileEntryMap::new();
        map.insert(Key::new(0, "occupied"), file.clone()).unwrap();

        assert!(validate_existing_candidate(&map, "occupied", &file).is_ok());
        assert!(matches!(
            validate_new_candidate(&map, "occupied", &file),
            Err(PithosError::PathOccupied(message)) if message == "File path already occupied: occupied"
        ));
    }

    #[test]
    fn archive_path_component_order_keeps_descendants_adjacent() {
        let file = entry(FileType::Data, None, BlockDataState::Decrypted(vec![]));
        let mut map = FileEntryMap::new();
        for (id, path) in [(0, "a"), (1, "a!"), (2, "a/child")] {
            map.insert(Key::new(id, path), file.clone()).unwrap();
        }

        assert_eq!(
            map.iter_ordered().map(|(path, _)| path).collect::<Vec<_>>(),
            ["a", "a/child", "a!"]
        );
        assert!(validate_map(&map).is_err());
    }
}

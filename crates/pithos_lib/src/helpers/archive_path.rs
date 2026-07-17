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

pub(crate) fn validate_candidate(
    map: &FileEntryMap,
    path: &str,
    entry: &FileEntry,
) -> Result<(), PithosError> {
    validate_entry(path, entry)?;
    for (_, existing, existing_entry) in map {
        if path == existing {
            continue;
        }
        if path.starts_with(existing)
            && path.as_bytes().get(existing.len()) == Some(&b'/')
            && existing_entry.file_type != FileType::Directory
        {
            return Err(PithosError::InvalidArchivePath {
                path: path.into(),
                reason: format!("file entry {existing} is an ancestor"),
            });
        }
        if existing.starts_with(path)
            && existing.as_bytes().get(path.len()) == Some(&b'/')
            && entry.file_type != FileType::Directory
        {
            return Err(PithosError::InvalidArchivePath {
                path: path.into(),
                reason: format!("entry is an ancestor of {existing}"),
            });
        }
    }
    Ok(())
}

pub(crate) fn validate_map(map: &FileEntryMap) -> Result<(), PithosError> {
    for (_, path, entry) in map {
        validate_candidate(&FileEntryMap::new(), path, entry)?;
    }
    for (_, path, entry) in map {
        for (_, other, _) in map {
            if path != other
                && other.starts_with(path)
                && other.as_bytes().get(path.len()) == Some(&b'/')
                && entry.file_type != FileType::Directory
            {
                return Err(PithosError::InvalidArchivePath {
                    path: path.into(),
                    reason: format!("entry is an ancestor of {other}"),
                });
            }
        }
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
}

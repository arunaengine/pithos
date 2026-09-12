use crate::archive::access::ResolvedAccess;
use crate::archive::index::{ArchiveIndex, build_effective_index};
use crate::archive::types::{
    ArchivePath, BlockDescriptor, BlockHash, Entry, FileId, Span, ValidatedSegment,
};
use crate::archive::validation::IndexLimits;
use crate::crypto::FileKey;
use crate::error::PithosError;
use indexmap::IndexMap;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

/// The secret-contained state needed to safely plan a direct append or grant.
///
/// This is intentionally derived only from a fully opened archive. It retains validated
/// segments for pure prospective merge, but not the source, wire directories, or reader facade.
pub(crate) struct AppendSnapshot {
    archive_len: u64,
    terminal_directory: Span,
    maximum_id: Option<FileId>,
    descriptors: IndexMap<BlockHash, BlockDescriptor>,
    entries: BTreeMap<FileId, SnapshotEntry>,
    paths: HashMap<Arc<str>, FileId>,
    hierarchy: BTreeMap<ArchivePath, FileId>,
    relationships: BTreeMap<u64, Arc<str>>,
    segments: Vec<ValidatedSegment>,
    index_limits: IndexLimits,
    access: ResolvedAccess,
}

pub(crate) struct SnapshotEntry {
    #[cfg(test)]
    pub(crate) id: FileId,
    #[cfg(test)]
    pub(crate) path: ArchivePath,
    pub(crate) kind: SnapshotEntryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SnapshotEntryKind {
    File,
    Metadata,
    Directory,
    Symlink,
}

impl AppendSnapshot {
    pub(crate) fn new(
        archive_len: u64,
        terminal_directory: Span,
        index: ArchiveIndex,
        segments: Vec<ValidatedSegment>,
        index_limits: IndexLimits,
        access: ResolvedAccess,
    ) -> Self {
        let relationships = index
            .relationships()
            .map(|(id, name)| (id.0, Arc::from(name)))
            .collect();
        let (index_entries, descriptors, maximum_id) = index.into_append_snapshot_parts();
        let mut entries = BTreeMap::new();
        let mut paths = HashMap::new();
        let mut hierarchy = BTreeMap::new();
        for entry in index_entries {
            let kind = snapshot_entry_kind(&entry.entry);
            let id = entry.id;
            let path_key = Arc::from(entry.path.as_str());
            hierarchy.insert(entry.path.clone(), id);
            entries.insert(
                id,
                SnapshotEntry {
                    #[cfg(test)]
                    id,
                    #[cfg(test)]
                    path: entry.path,
                    kind,
                },
            );
            paths.insert(path_key, id);
        }
        Self {
            archive_len,
            terminal_directory,
            maximum_id,
            descriptors,
            entries,
            paths,
            hierarchy,
            relationships,
            segments,
            index_limits,
            access,
        }
    }

    pub(crate) fn archive_len(&self) -> u64 {
        self.archive_len
    }

    pub(crate) fn terminal_directory(&self) -> Span {
        self.terminal_directory
    }

    pub(crate) fn maximum_id(&self) -> Option<FileId> {
        self.maximum_id
    }

    pub(crate) fn descriptor(&self, hash: BlockHash) -> Option<&BlockDescriptor> {
        self.descriptors.get(&hash)
    }

    pub(crate) fn entry(&self, id: FileId) -> Option<&SnapshotEntry> {
        self.entries.get(&id)
    }

    pub(crate) fn entry_at_path(&self, path: &ArchivePath) -> Option<&SnapshotEntry> {
        self.paths
            .get(path.as_str())
            .and_then(|id| self.entries.get(id))
    }

    pub(crate) fn ensure_path_available(&self, path: &ArchivePath) -> Result<(), PithosError> {
        if self.paths.contains_key(path.as_str()) {
            return Err(PithosError::PathOccupied(path.as_str().to_owned()));
        }
        Ok(())
    }

    pub(crate) fn ensure_id_available(&self, id: FileId) -> Result<(), PithosError> {
        if self.entries.contains_key(&id) {
            return Err(PithosError::DuplicateFileId(format!(
                "File id already occupied: {}",
                id.0
            )));
        }
        Ok(())
    }

    pub(crate) fn ensure_candidate_hierarchy(
        &self,
        path: &ArchivePath,
        is_directory: bool,
    ) -> Result<(), PithosError> {
        for (index, _) in path.as_str().match_indices('/') {
            let ancestor = ArchivePath::new(&path.as_str()[..index])?;
            if let Some(entry) = self.entry_at_path(&ancestor)
                && entry.kind != SnapshotEntryKind::Directory
            {
                return Err(PithosError::InvalidArchivePath {
                    path: path.as_str().to_owned(),
                    reason: format!("file entry {} is an ancestor", ancestor.as_str()),
                });
            }
        }
        self.ensure_candidate_successor(path, is_directory)
    }

    pub(crate) fn ensure_candidate_successor(
        &self,
        path: &ArchivePath,
        is_directory: bool,
    ) -> Result<(), PithosError> {
        if !is_directory
            && let Some((successor, _)) = self.hierarchy.range(path.clone()..).next()
            && path.is_ancestor_of(successor)
        {
            return Err(PithosError::InvalidArchivePath {
                path: path.as_str().to_owned(),
                reason: format!("entry is an ancestor of {}", successor.as_str()),
            });
        }
        Ok(())
    }

    pub(crate) fn validate_child_relationships(
        &self,
        relationships: &[(u64, &str)],
    ) -> Result<(), PithosError> {
        for (id, name) in relationships {
            if let Some(existing) = self.relationships.get(id)
                && existing.as_ref() != *name
            {
                return Err(PithosError::ConflictingRelationshipDefinition(*id));
            }
        }
        Ok(())
    }

    pub(crate) fn has_relationship(&self, id: u64) -> bool {
        self.relationships.contains_key(&id)
    }

    /// Runs the normal pure merge against the immutable ancestor chain before publication.
    pub(crate) fn validate_prospective_child(
        &self,
        child: ValidatedSegment,
    ) -> Result<(), PithosError> {
        let archive_len = child.span.end();
        let mut segments = self.segments.clone();
        segments.push(child);
        build_effective_index(&segments, archive_len, self.index_limits).map(|_| ())
    }

    /// Borrows an opaque, zeroizing recovered file key only for content entries.
    pub(crate) fn with_file_key<T>(
        &self,
        id: FileId,
        operation: impl FnOnce(&FileKey) -> T,
    ) -> Result<T, PithosError> {
        let entry = self
            .entries
            .get(&id)
            .ok_or(PithosError::SnapshotFileIdNotFound(id.0))?;
        match entry.kind {
            SnapshotEntryKind::Directory => {
                return Err(PithosError::SnapshotDirectoryHasNoContent(id.0));
            }
            SnapshotEntryKind::Symlink => {
                return Err(PithosError::SnapshotSymlinkHasNoContent(id.0));
            }
            SnapshotEntryKind::File | SnapshotEntryKind::Metadata => {}
        }
        self.access
            .with_file_key(id, operation)
            .ok_or(PithosError::SnapshotContentUnavailable(id.0))
    }
}

fn snapshot_entry_kind(entry: &Entry) -> SnapshotEntryKind {
    match entry {
        Entry::File(_) => SnapshotEntryKind::File,
        Entry::Metadata(_) => SnapshotEntryKind::Metadata,
        Entry::Directory(_) => SnapshotEntryKind::Directory,
        Entry::Symlink { .. } => SnapshotEntryKind::Symlink,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{
        AccessKeys, Archive, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions,
        WriteOptions,
    };
    use crate::crypto::{PrivateKey, parse_private_pem};
    use crate::error::PithosError;
    use crate::format::limits::DeserializationLimits;
    use crate::source::MemorySource;
    use std::io::{Cursor, Write};
    use std::sync::Arc;

    fn private(name: &str) -> PrivateKey {
        parse_private_pem(&std::fs::read(format!("tests/data/keys/{name}_private.pem")).unwrap())
            .unwrap()
    }

    fn archive_with_entries() -> (Vec<u8>, PrivateKey, PrivateKey) {
        let sender = private("sender");
        let sender_access = sender.duplicate();
        let recipient = private("recipient1");
        let recipient_public = recipient.public_key();
        let mut writer = ArchiveWriter::create(
            Cursor::new(Vec::new()),
            WriteOptions::new(sender, vec![sender_access.public_key(), recipient_public]),
        )
        .unwrap();
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 0).unwrap(),
                Some(4),
                Cursor::new(b"data"),
            )
            .unwrap();
        writer
            .add_directory(
                ArchivePath::new("directory").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        writer
            .add_symlink(
                ArchivePath::new("link").unwrap(),
                EntryMetadata::new(0, 0, 0o777),
                "data",
            )
            .unwrap();
        (
            writer.finish().unwrap().into_inner(),
            sender_access,
            recipient,
        )
    }

    fn open(bytes: Vec<u8>, keys: AccessKeys) -> Archive<MemorySource> {
        Archive::open(
            MemorySource::new(Arc::<[u8]>::from(bytes)),
            OpenOptions::default().with_access_keys(keys),
        )
        .unwrap()
    }

    #[test]
    fn snapshot_records_archive_length_terminal_span_and_maximum_id() {
        let (bytes, _sender, recipient) = archive_with_entries();
        let snapshot =
            open(bytes.clone(), AccessKeys::new().with_key(recipient)).into_append_snapshot();
        let terminal_len =
            u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());

        assert_eq!(snapshot.archive_len(), bytes.len() as u64);
        assert_eq!(snapshot.terminal_directory().len(), terminal_len);
        assert_eq!(snapshot.terminal_directory().end(), snapshot.archive_len());
        assert_eq!(snapshot.maximum_id(), Some(FileId(2)));
    }

    #[test]
    fn snapshot_creation_consumes_archive_and_moves_recovered_access() {
        fn consume(archive: Archive<MemorySource>) -> AppendSnapshot {
            archive.into_append_snapshot()
        }

        let (bytes, _sender, recipient) = archive_with_entries();
        let snapshot = consume(open(bytes, AccessKeys::new().with_key(recipient)));
        assert!(snapshot.with_file_key(FileId(0), |_| ()).is_ok());
    }

    #[test]
    fn snapshot_checks_existing_paths_ids_and_content_kinds() {
        let (bytes, _sender, recipient) = archive_with_entries();
        let snapshot = open(bytes, AccessKeys::new().with_key(recipient)).into_append_snapshot();

        assert!(matches!(
            snapshot.ensure_path_available(&ArchivePath::new("data").unwrap()),
            Err(PithosError::PathOccupied(path)) if path == "data"
        ));
        assert!(
            snapshot
                .ensure_path_available(&ArchivePath::new("new").unwrap())
                .is_ok()
        );
        let entry = snapshot
            .entry_at_path(&ArchivePath::new("directory").unwrap())
            .unwrap();
        assert_eq!(entry.id, FileId(1));
        assert_eq!(entry.path.as_str(), "directory");
        assert_eq!(entry.kind, SnapshotEntryKind::Directory);
        assert_eq!(
            snapshot.entry(FileId(2)).unwrap().kind,
            SnapshotEntryKind::Symlink
        );
        assert!(matches!(
            snapshot.ensure_id_available(FileId(0)),
            Err(PithosError::DuplicateFileId(_))
        ));
        assert!(snapshot.ensure_id_available(FileId(3)).is_ok());
        assert!(matches!(
            snapshot.with_file_key(FileId(1), |_| ()),
            Err(PithosError::SnapshotDirectoryHasNoContent(1))
        ));
        assert!(matches!(
            snapshot.with_file_key(FileId(2), |_| ()),
            Err(PithosError::SnapshotSymlinkHasNoContent(2))
        ));
    }

    #[test]
    fn snapshot_keeps_the_earliest_effective_descriptor() {
        let sender = private("sender");
        let recipient = private("recipient1");
        let mut writer = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(sender.duplicate(), vec![recipient.public_key()]),
        )
        .unwrap();
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 0).unwrap(),
                Some(4),
                Cursor::new(b"data"),
            )
            .unwrap();
        let first = writer.finish().unwrap();
        let first_len =
            u64::from_be_bytes(first[first.len() - 12..first.len() - 4].try_into().unwrap());
        let first_start = first.len() - usize::try_from(first_len).unwrap();
        let first_directory = crate::format::codec::decode_directory(
            &mut Cursor::new(&first[first_start..]),
            &DeserializationLimits::default(),
        )
        .unwrap();
        let (hash, earliest) = first_directory.blocks.first().unwrap();
        let hash = *hash;
        let earliest_stored_size = earliest.stored_size;

        let snapshot = open(
            first.clone(),
            AccessKeys::new().with_key(recipient.duplicate()),
        )
        .into_append_snapshot();
        let child = ArchiveWriter::append(
            Vec::new(),
            sender,
            vec![recipient.public_key()],
            crate::archive::CdcConfig::default(),
            snapshot,
        )
        .unwrap()
        .finish()
        .unwrap();
        let mut bytes = first;
        bytes.extend_from_slice(&child);
        let len = u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());
        let start = bytes.len() - usize::try_from(len).unwrap();
        let mut directory = crate::format::codec::decode_directory(
            &mut Cursor::new(&bytes[start..]),
            &DeserializationLimits::default(),
        )
        .unwrap();
        let hash = BlockHash(hash);
        let mut newer = earliest.clone();
        newer.stored_size -= 1;
        directory.blocks.insert(hash.0, newer);
        crate::format::codec::update_directory_len(&mut directory).unwrap();
        crate::format::codec::update_directory_crc(&mut directory).unwrap();
        let mut replacement = Vec::new();
        crate::format::codec::encode_directory(&directory, &mut replacement).unwrap();
        bytes.truncate(start);
        bytes.write_all(&replacement).unwrap();

        let snapshot = open(bytes, AccessKeys::new().with_key(recipient)).into_append_snapshot();
        assert_eq!(
            snapshot.descriptor(hash).unwrap().stored_size,
            earliest_stored_size
        );
    }

    #[test]
    fn snapshot_borrows_recovered_keys_for_sender_and_recipient_access() {
        let (bytes, sender, recipient) = archive_with_entries();
        let sender_key = open(bytes.clone(), AccessKeys::new().with_key(sender))
            .into_append_snapshot()
            .with_file_key(FileId(0), |key| *key.expose_for_protocol())
            .unwrap();
        let recipient_key = open(bytes, AccessKeys::new().with_key(recipient))
            .into_append_snapshot()
            .with_file_key(FileId(0), |key| *key.expose_for_protocol())
            .unwrap();
        assert_eq!(sender_key, recipient_key);
    }

    #[test]
    fn snapshot_rejects_missing_wrong_and_unavailable_file_keys() {
        let (bytes, _sender, _recipient) = archive_with_entries();
        let unavailable = open(bytes.clone(), AccessKeys::new()).into_append_snapshot();
        let wrong =
            open(bytes, AccessKeys::new().with_key(private("recipient2"))).into_append_snapshot();

        assert!(matches!(
            unavailable.with_file_key(FileId(99), |_| ()),
            Err(PithosError::SnapshotFileIdNotFound(99))
        ));
        assert!(matches!(
            unavailable.with_file_key(FileId(0), |_| ()),
            Err(PithosError::SnapshotContentUnavailable(0))
        ));
        assert!(matches!(
            wrong.with_file_key(FileId(0), |_| ()),
            Err(PithosError::SnapshotContentUnavailable(0))
        ));
    }
}

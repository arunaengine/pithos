use crate::archive::types::{BlockHash, FileId};
use crate::crypto::{BlockKey, FileKey};
use crate::error::PithosError;
use crate::format::file_entry::BlockDataEntry;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Recovered file secrets have one crate-private owner and never enter an index.
pub(crate) struct ResolvedAccess {
    /// Boxed keys stay in place when the map rearranges its nodes, so no stale copy remains.
    keys: BTreeMap<FileId, Box<FileKey>>,
    /// The decoded block list of each file, in file order. It is moved here, not copied.
    block_keys: BTreeMap<FileId, Zeroizing<Vec<BlockDataEntry>>>,
    provenance: BTreeMap<FileId, AccessProvenance>,
    /// Piece key ids of each file whose block list was sealed in pieces.
    pieces: BTreeMap<FileId, Vec<FileId>>,
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct AccessProvenance {
    pub(crate) segment: usize,
    pub(crate) recovery_order: usize,
    pub(crate) access_key: usize,
    pub(crate) sender_section: usize,
    pub(crate) recipient_section: usize,
}

impl ResolvedAccess {
    pub(crate) fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            block_keys: BTreeMap::new(),
            provenance: BTreeMap::new(),
            pieces: BTreeMap::new(),
        }
    }

    pub(crate) fn insert(
        &mut self,
        id: FileId,
        key: &[u8; 32],
        provenance: AccessProvenance,
    ) -> Result<(), PithosError> {
        match self.keys.get(&id) {
            Some(existing) if existing.expose_for_protocol() != key => {
                Err(PithosError::ConflictingRecoveredFileKey)
            }
            Some(_) => {
                if provenance < self.provenance[&id] {
                    self.provenance.insert(id, provenance);
                }
                Ok(())
            }
            None => {
                self.keys.insert(id, Box::new(FileKey::from_protocol(key)));
                self.provenance.insert(id, provenance);
                Ok(())
            }
        }
    }

    pub(crate) fn key(&self, id: FileId) -> Option<&FileKey> {
        self.keys.get(&id).map(Box::as_ref)
    }

    #[cfg(feature = "crypt4gh")]
    pub(crate) fn provenance(&self, id: FileId) -> Option<AccessProvenance> {
        self.provenance.get(&id).copied()
    }

    pub(crate) fn insert_pieces(&mut self, id: FileId, key_ids: Vec<FileId>) {
        self.pieces.insert(id, key_ids);
    }

    /// The keys a reader grant for `id` must carry: its file key, or every piece key.
    pub(crate) fn grant_keys(&self, id: FileId) -> Option<Vec<(FileId, &FileKey)>> {
        match self.pieces.get(&id) {
            Some(key_ids) => key_ids
                .iter()
                .map(|key_id| self.key(*key_id).map(|key| (*key_id, key)))
                .collect(),
            None => self.key(id).map(|key| vec![(id, key)]),
        }
    }

    pub(crate) fn insert_block_keys(
        &mut self,
        id: FileId,
        entries: Zeroizing<Vec<BlockDataEntry>>,
    ) {
        self.block_keys.insert(id, entries);
    }

    /// The key of the block at `position` in the block list of `id`, if it has `hash`.
    pub(crate) fn block_key(
        &self,
        id: FileId,
        position: usize,
        hash: BlockHash,
    ) -> Option<BlockKey> {
        self.block_keys
            .get(&id)
            .and_then(|entries| entries.get(position))
            .filter(|(entry_hash, _)| *entry_hash == hash.0)
            .map(|(_, key)| BlockKey::from_protocol(key))
    }
}

use super::access::ResolvedAccess;
use super::index::ArchiveIndex;
use super::planning::{PlannedBlock, ReadPlan};
#[cfg(feature = "crypt4gh")]
use super::reader::AccessKeys;
use super::reader::{ArchiveEntry, ContentAvailability, OpenLimits, archive_entry};
use super::snapshot::AppendSnapshot;
use super::types::{ArchivePath, FileId, ReadRange, Span, ValidatedSegment};
use super::validation::IndexLimits;
use crate::block;
use crate::error::PithosError;
use crate::format::block::{BlockIndexEntry, BlockLocation, ProcessingFlags};
use crate::format::header::FormatVersion;
use std::collections::BTreeMap;
use std::ops::Range;
use zeroize::Zeroizing;

/// Validated archive metadata without a byte source.
///
/// A view is the result of opening an archive. It lists entries and plans content reads, but
/// holds no source: callers fetch block bytes themselves and pass them back for decoding.
pub struct ArchiveView {
    pub(super) archive_len: u64,
    pub(super) version: FormatVersion,
    pub(super) metadata_digest: [u8; 32],
    pub(super) terminal_directory: Span,
    pub(super) index: ArchiveIndex,
    pub(super) segments: Vec<ValidatedSegment>,
    pub(super) index_limits: IndexLimits,
    pub(super) access: ResolvedAccess,
    #[cfg(feature = "crypt4gh")]
    pub(super) access_keys: AccessKeys,
    pub(super) limits: OpenLimits,
    pub(super) content_availability: BTreeMap<FileId, ContentAvailability>,
}

impl ArchiveView {
    /// BLAKE3 over the hashes of every directory, from the base to the terminal directory.
    /// Keeping it in trusted storage lets a later open detect changed metadata.
    pub fn metadata_digest(&self) -> [u8; 32] {
        self.metadata_digest
    }

    /// The format version stored in the file header: `0x0100` for 1.0, `0x0101` for 1.1.
    pub fn version(&self) -> u16 {
        self.version.wire()
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = ArchiveEntry> + '_ {
        self.index
            .entries()
            .map(|entry| archive_entry(&self.index, entry, &self.content_availability))
    }

    pub fn entry(&self, path: &str) -> Result<Option<ArchiveEntry>, PithosError> {
        let path = ArchivePath::new(path)?;
        Ok(self
            .index
            .entry_at_path(&path)
            .map(|entry| archive_entry(&self.index, entry, &self.content_availability)))
    }

    /// Plans a read of `range` within the content of `path`.
    ///
    /// Fails before any block is planned when the content is unavailable or needs an
    /// unsupported feature.
    pub fn plan_range(&self, path: &str, range: Range<u64>) -> Result<ReadPlan<'_>, PithosError> {
        let (id, size) = self.content_id(path)?;
        let range = ReadRange::new(range, size)?;
        self.require_content_available(id)?;
        self.plan(id, range)
    }

    pub(crate) fn plan(&self, id: FileId, range: ReadRange) -> Result<ReadPlan<'_>, PithosError> {
        ReadPlan::new(&self.index, id, range, self.block_limits())
    }

    /// Decodes one planned block from its stored bytes, `BLCK` followed by the payload.
    ///
    /// Checks the marker, the sizes, decryption, decompression and the block identity, and
    /// returns the whole verified block. This is CPU work without I/O, so callers may run it
    /// on a blocking pool.
    pub fn decode_block(
        &self,
        block: &PlannedBlock,
        stored: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, PithosError> {
        let expected = block.framed_len();
        if stored.len() as u64 != expected {
            return Err(PithosError::BlockSizeMismatch {
                expected,
                actual: stored.len() as u64,
            });
        }
        let (mut marker, payload) = stored.split_at(4);
        crate::format::block::decode_block_marker(&mut marker)?;
        let key = self
            .access
            .block_key(block.file, block.hash)
            .ok_or(PithosError::ContentUnavailable)?;
        let meta = BlockIndexEntry {
            offset: 0,
            stored_size: block.descriptor.stored_size,
            original_size: block.descriptor.original_size,
            flags: ProcessingFlags::from_byte(block.descriptor.processing.to_byte()),
            location: BlockLocation::Local,
        };
        block::verify(
            Zeroizing::new(payload.to_vec()),
            key,
            block.hash.0,
            &meta,
            self.block_limits(),
        )
    }

    pub(crate) fn block_limits(&self) -> block::Limits {
        block::Limits {
            max_stored_bytes: self.limits.max_stored_block_bytes,
            max_decoded_bytes: self.limits.max_decoded_block_bytes,
        }
    }

    /// Transfers the validated state to append and grant planning.
    pub(crate) fn into_append_snapshot(self) -> AppendSnapshot {
        let Self {
            archive_len,
            version,
            terminal_directory,
            index,
            segments,
            index_limits,
            access,
            ..
        } = self;
        AppendSnapshot::new(
            archive_len,
            version,
            terminal_directory,
            index,
            segments,
            index_limits,
            access,
        )
    }

    pub(crate) fn content_id(&self, path: &str) -> Result<(FileId, u64), PithosError> {
        let path = ArchivePath::new(path)?;
        let entry = self
            .index
            .entry_at_path(&path)
            .ok_or_else(|| PithosError::FileNotFound(path.as_str().to_owned()))?;
        let content = entry.entry.content().ok_or_else(|| {
            PithosError::InvalidBlockDataState("only data/metadata entries have content".into())
        })?;
        Ok((entry.id, content.size))
    }

    #[cfg(feature = "crypt4gh")]
    pub(crate) fn content_size(&self, id: FileId) -> Result<u64, PithosError> {
        self.index
            .entry(id)
            .and_then(|entry| entry.entry.content())
            .map(|content| content.size)
            .ok_or_else(|| {
                PithosError::InvalidBlockDataState("only data/metadata entries have content".into())
            })
    }

    pub(crate) fn require_content_available(&self, id: FileId) -> Result<(), PithosError> {
        match self.content_availability.get(&id).copied() {
            Some(ContentAvailability::Available) => Ok(()),
            Some(ContentAvailability::MissingAccess) => Err(PithosError::ContentUnavailable),
            Some(ContentAvailability::Unsupported(feature)) => {
                Err(PithosError::UnsupportedFeature(feature))
            }
            None => Err(PithosError::InvalidBlockDataState(
                "only data/metadata entries have content".into(),
            )),
        }
    }
}

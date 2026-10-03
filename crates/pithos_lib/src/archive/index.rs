use crate::archive::types::{
    ArchivePath, BlockDescriptor, BlockHash, ContentState, Entry, FileId, RelationId, SegmentEntry,
    Span, ValidatedSegment,
};
use crate::archive::validation::{IndexLimits, SegmentCounts, validate_aggregate, validate_entry};
use crate::error::PithosError;
use crate::format::header::FileHeader;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IndexedEntry {
    pub(crate) id: FileId,
    pub(crate) path: ArchivePath,
    pub(crate) entry: Entry,
}

/// Immutable effective archive state. Its private fields contain no secrets.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ArchiveIndex {
    entries: Vec<IndexedEntry>,
    by_id: BTreeMap<FileId, usize>,
    by_path: HashMap<Arc<str>, usize>,
    hierarchy: BTreeMap<ArchivePath, usize>,
    /// Sorted by hash, so lookups need no hash table next to the descriptors.
    descriptors: Vec<(BlockHash, BlockDescriptor)>,
    relationships: BTreeMap<RelationId, Arc<str>>,
    segment_spans: BTreeSet<Span>,
    counts: SegmentCounts,
    maximum_id: Option<FileId>,
}

impl ArchiveIndex {
    pub(crate) fn entries(&self) -> impl ExactSizeIterator<Item = &IndexedEntry> {
        self.entries.iter()
    }

    pub(crate) fn entry(&self, id: FileId) -> Option<&IndexedEntry> {
        self.by_id
            .get(&id)
            .and_then(|index| self.entries.get(*index))
    }

    pub(crate) fn entry_at_path(&self, path: &ArchivePath) -> Option<&IndexedEntry> {
        self.by_path
            .get(path.as_str())
            .and_then(|index| self.entries.get(*index))
    }

    #[cfg(test)]
    pub(crate) fn hierarchy(&self) -> impl Iterator<Item = &IndexedEntry> {
        self.hierarchy
            .values()
            .filter_map(|index| self.entries.get(*index))
    }

    pub(crate) fn descriptor(&self, hash: BlockHash) -> Option<&BlockDescriptor> {
        find_descriptor(&self.descriptors, hash)
    }

    pub(crate) fn relationships(&self) -> impl Iterator<Item = (RelationId, &str)> {
        self.relationships
            .iter()
            .map(|(id, name)| (*id, name.as_ref()))
    }

    pub(crate) fn relationship(&self, id: RelationId) -> Option<&str> {
        self.relationships.get(&id).map(Arc::as_ref)
    }

    pub(crate) fn maximum_id(&self) -> Option<FileId> {
        self.maximum_id
    }

    /// Piece key ids share the file id space, so new file ids must stay above them.
    pub(crate) fn cover_piece_keys(&mut self, maximum_piece_key: Option<FileId>) {
        self.maximum_id = self.maximum_id.max(maximum_piece_key);
    }

    /// Runs the normal merge of `child` as the next segment on a copy of this index.
    pub(crate) fn validate_child(
        &self,
        child: ValidatedSegment,
        limits: IndexLimits,
    ) -> Result<(), PithosError> {
        let mut counts = self.counts;
        counts.add(&child);
        counts.check(limits)?;
        let archive_len = child.span.end();
        let mut index = self.clone();
        index.counts = counts;
        index.absorb(child, archive_len)?;
        index.finish()
    }

    fn new(counts: SegmentCounts) -> Self {
        Self {
            entries: Vec::new(),
            by_id: BTreeMap::new(),
            by_path: HashMap::new(),
            hierarchy: BTreeMap::new(),
            descriptors: Vec::new(),
            relationships: BTreeMap::new(),
            segment_spans: BTreeSet::new(),
            counts,
            maximum_id: None,
        }
    }

    /// Checks one more segment against the earlier ones and moves its contents in.
    fn absorb(&mut self, segment: ValidatedSegment, archive_len: u64) -> Result<(), PithosError> {
        validate_segment_chain(&segment, &self.segment_spans)?;
        let block_region = block_data_region(&segment)?;
        self.segment_spans.insert(segment.span);
        for (id, name) in segment.relationships {
            match self.relationships.get(&id) {
                Some(existing) if existing.as_ref() != name.as_ref() => {
                    return Err(PithosError::ConflictingRelationshipDefinition(id.0));
                }
                Some(_) => {}
                None => {
                    self.relationships.insert(id, name);
                }
            }
        }
        self.absorb_descriptors(segment.descriptors, archive_len, block_region)?;
        for SegmentEntry { id, path, entry } in segment.entries {
            validate_entry(&path, &entry)?;
            if self.by_id.contains_key(&id) {
                return Err(PithosError::DuplicateFileId(format!(
                    "File id already occupied: {}",
                    id.0
                )));
            }
            if self.by_path.contains_key(path.as_str()) {
                return Err(PithosError::PathOccupied(format!(
                    "File path already occupied: {}",
                    path.as_str()
                )));
            }
            for (offset, _) in path.as_str().match_indices('/') {
                let ancestor = &path.as_str()[..offset];
                let Some(ancestor_index) = self.by_path.get(ancestor) else {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.as_str().into(),
                        reason: format!("missing directory ancestor {ancestor}"),
                    });
                };
                if !self.entries[*ancestor_index].entry.is_directory() {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.as_str().into(),
                        reason: format!("file entry {ancestor} is an ancestor"),
                    });
                }
            }
            let index = self.entries.len();
            self.by_id.insert(id, index);
            self.by_path.insert(Arc::from(path.as_str()), index);
            self.hierarchy.insert(path.clone(), index);
            self.entries.push(IndexedEntry { id, path, entry });
        }
        Ok(())
    }

    /// Keeps the earliest descriptor of each block. A later one must agree on the plaintext
    /// size. The first segment's list is moved in without a copy.
    fn absorb_descriptors(
        &mut self,
        mut descriptors: Vec<(BlockHash, BlockDescriptor)>,
        archive_len: u64,
        block_region: Span,
    ) -> Result<(), PithosError> {
        descriptors.sort_unstable_by_key(|(hash, _)| *hash);
        for (hash, descriptor) in &descriptors {
            match self.descriptor(*hash) {
                // The current format defines compatibility by identity and plaintext size only.
                Some(existing) if existing.original_size != descriptor.original_size => {
                    return Err(PithosError::BlockIndexConflict {
                        hash: hash.0,
                        existing_original_size: existing.original_size,
                        new_original_size: descriptor.original_size,
                    });
                }
                Some(_) => {}
                None => validate_descriptor(descriptor, archive_len, block_region)?,
            }
        }
        if self.descriptors.is_empty() {
            self.descriptors = descriptors;
            return Ok(());
        }
        descriptors.retain(|(hash, _)| find_descriptor(&self.descriptors, *hash).is_none());
        self.descriptors
            .try_reserve_exact(descriptors.len())
            .map_err(|_| PithosError::AllocationFailed {
                field: "block descriptors",
                size: descriptors.len() as u64,
            })?;
        self.descriptors.append(&mut descriptors);
        self.descriptors.sort_unstable_by_key(|(hash, _)| *hash);
        Ok(())
    }

    /// Runs the checks that need every segment.
    fn finish(&mut self) -> Result<(), PithosError> {
        let mut local_spans = self
            .descriptors
            .iter()
            .filter_map(|(_, descriptor)| match descriptor.location {
                crate::archive::types::BlockLocation::Local(span) => Some(span),
                crate::archive::types::BlockLocation::External(_) => None,
            })
            .collect::<Vec<_>>();
        local_spans.sort_unstable_by_key(|span| span.start());
        if local_spans
            .windows(2)
            .any(|spans| spans[0].overlaps(spans[1]))
        {
            return Err(PithosError::InvalidDirectoryRange {
                operation: "validate block overlap",
            });
        }
        drop(local_spans);
        validate_references_and_content(
            &self.entries,
            &self.by_id,
            &self.relationships,
            &self.descriptors,
        )?;
        self.maximum_id = self
            .maximum_id
            .max(self.entries.iter().map(|entry| entry.id).max());
        Ok(())
    }
}

fn find_descriptor(
    descriptors: &[(BlockHash, BlockDescriptor)],
    hash: BlockHash,
) -> Option<&BlockDescriptor> {
    descriptors
        .binary_search_by_key(&hash, |(hash, _)| *hash)
        .ok()
        .map(|index| &descriptors[index].1)
}

/// Builds a new effective index, moving the contents of `segments` into it.
pub(crate) fn build_effective_index(
    segments: Vec<ValidatedSegment>,
    archive_len: u64,
    limits: IndexLimits,
) -> Result<ArchiveIndex, PithosError> {
    let counts = validate_aggregate(&segments, limits)?;
    let mut index = ArchiveIndex::new(counts);
    for segment in segments {
        index.absorb(segment, archive_len)?;
    }
    index.finish()?;
    Ok(index)
}

fn validate_segment_chain(
    segment: &ValidatedSegment,
    earlier: &BTreeSet<Span>,
) -> Result<(), PithosError> {
    if let Some(parent) = segment.parent {
        if !earlier.contains(&parent) || parent.end() > segment.span.start() {
            return Err(PithosError::InvalidDirectoryChain {
                operation: "validate parent ordering",
            });
        }
    } else if !earlier.is_empty() {
        return Err(PithosError::InvalidDirectoryChain {
            operation: "validate root segment",
        });
    }
    let previous_overlaps = earlier
        .range(..segment.span)
        .next_back()
        .is_some_and(|span| span.overlaps(segment.span));
    let next_overlaps = earlier
        .range(segment.span..)
        .next()
        .is_some_and(|span| span.overlaps(segment.span));
    if previous_overlaps || next_overlaps {
        return Err(PithosError::InvalidDirectoryChain {
            operation: "validate segment overlap",
        });
    }
    Ok(())
}

fn block_data_region(segment: &ValidatedSegment) -> Result<Span, PithosError> {
    let start = segment
        .parent
        .map_or(FileHeader::ENCODED_LEN as u64, Span::end);
    let end = segment.span.start();
    let len = end
        .checked_sub(start)
        .ok_or(PithosError::InvalidDirectoryRange {
            operation: "validate block data region",
        })?;
    Span::new(start, len)
}

fn validate_descriptor(
    descriptor: &BlockDescriptor,
    archive_len: u64,
    block_region: Span,
) -> Result<(), PithosError> {
    if let crate::archive::types::BlockLocation::Local(span) = descriptor.location
        && (span.start() < block_region.start()
            || span.end() > block_region.end()
            || span.end() > archive_len)
    {
        return Err(PithosError::InvalidDirectoryRange {
            operation: "validate block extent",
        });
    }
    Ok(())
}

fn validate_references_and_content(
    entries: &[IndexedEntry],
    by_id: &BTreeMap<FileId, usize>,
    relationships: &BTreeMap<RelationId, Arc<str>>,
    descriptors: &[(BlockHash, BlockDescriptor)],
) -> Result<(), PithosError> {
    for indexed in entries {
        for reference in &indexed.entry.metadata().references {
            if !relationships.contains_key(&reference.relationship) {
                return Err(PithosError::UnknownRelationshipId(reference.relationship.0));
            }
            if !by_id.contains_key(&reference.target) {
                return Err(PithosError::MissingReferenceTarget(reference.target.0));
            }
        }
        let Some(content) = indexed.entry.content() else {
            continue;
        };
        let ContentState::Available(blocks) = &content.content else {
            continue;
        };
        let actual = blocks.iter().try_fold(0u64, |total, hash| {
            let descriptor =
                find_descriptor(descriptors, hash).ok_or(PithosError::MissingBlockDescriptor)?;
            total.checked_add(descriptor.original_size).ok_or(
                PithosError::AccessibleFileSizeMismatch {
                    expected: content.size,
                    actual: u64::MAX,
                },
            )
        })?;
        if actual != content.size {
            return Err(PithosError::AccessibleFileSizeMismatch {
                expected: content.size,
                actual,
            });
        }
    }
    Ok(())
}

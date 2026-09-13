use crate::archive::planning::{ReadPlan, full_file_plan, range_plan};
use crate::archive::types::{
    ArchivePath, BlockDescriptor, BlockHash, ContentState, Entry, FileId, ReadRange, RelationId,
    SegmentEntry, Span, ValidatedSegment,
};
use crate::archive::validation::{IndexLimits, validate_aggregate, validate_entry};
use crate::error::PithosError;
use crate::format::wire::FileHeader;
use indexmap::IndexMap;
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
    descriptors: IndexMap<BlockHash, BlockDescriptor>,
    relationships: BTreeMap<RelationId, Arc<str>>,
    segment_spans: Vec<Span>,
    local_spans: Vec<Span>,
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
        self.descriptors.get(&hash)
    }

    pub(crate) fn relationships(&self) -> impl Iterator<Item = (RelationId, &str)> {
        self.relationships
            .iter()
            .map(|(id, name)| (*id, name.as_ref()))
    }

    pub(crate) fn relationship(&self, id: RelationId) -> Option<&str> {
        self.relationships.get(&id).map(Arc::as_ref)
    }

    pub(crate) fn local_block_spans(&self) -> impl Iterator<Item = Span> + '_ {
        self.local_spans.iter().copied()
    }

    #[cfg(test)]
    pub(crate) fn maximum_id(&self) -> Option<FileId> {
        self.maximum_id
    }

    /// Transfers only the effective state needed to form an append snapshot.
    pub(crate) fn into_append_snapshot_parts(
        self,
    ) -> (
        Vec<IndexedEntry>,
        IndexMap<BlockHash, BlockDescriptor>,
        Option<FileId>,
    ) {
        (self.entries, self.descriptors, self.maximum_id)
    }

    pub(crate) fn full_file_plan(&self, id: FileId) -> Result<ReadPlan, PithosError> {
        full_file_plan(self, id)
    }

    pub(crate) fn range_plan(&self, id: FileId, range: ReadRange) -> Result<ReadPlan, PithosError> {
        range_plan(self, id, range)
    }
}

/// Builds a new effective index. Inputs are only borrowed and are unchanged on every error.
pub(crate) fn build_effective_index(
    segments: &[ValidatedSegment],
    archive_len: u64,
    limits: IndexLimits,
) -> Result<ArchiveIndex, PithosError> {
    validate_aggregate(segments, limits)?;
    let mut entries: Vec<IndexedEntry> = Vec::new();
    let mut by_id = BTreeMap::new();
    let mut by_path: HashMap<Arc<str>, usize> = HashMap::new();
    let mut hierarchy = BTreeMap::new();
    let mut descriptors: IndexMap<BlockHash, BlockDescriptor> = IndexMap::new();
    let mut relationships: BTreeMap<RelationId, Arc<str>> = BTreeMap::new();
    let mut segment_spans = BTreeSet::new();

    for segment in segments {
        validate_segment_chain(segment, &segment_spans)?;
        let block_region = block_data_region(segment)?;
        segment_spans.insert(segment.span);
        for (id, name) in &segment.relationships {
            match relationships.get(id) {
                Some(existing) if existing.as_ref() != name.as_ref() => {
                    return Err(PithosError::ConflictingRelationshipDefinition(id.0));
                }
                Some(_) => {}
                None => {
                    relationships.insert(*id, Arc::clone(name));
                }
            }
        }
        for (hash, descriptor) in &segment.descriptors {
            if let Some(existing) = descriptors.get(hash) {
                // The current format defines compatibility by identity and plaintext size only.
                if existing.original_size != descriptor.original_size {
                    return Err(PithosError::BlockIndexConflict {
                        hash: hash.0,
                        existing_original_size: existing.original_size,
                        new_original_size: descriptor.original_size,
                    });
                }
            } else {
                validate_descriptor(descriptor, archive_len, block_region)?;
                descriptors.insert(*hash, descriptor.clone());
            }
        }
        for SegmentEntry { id, path, entry } in &segment.entries {
            validate_entry(path, entry)?;
            if by_id.contains_key(id) {
                return Err(PithosError::DuplicateFileId(format!(
                    "File id already occupied: {}",
                    id.0
                )));
            }
            if by_path.contains_key(path.as_str()) {
                return Err(PithosError::PathOccupied(format!(
                    "File path already occupied: {}",
                    path.as_str()
                )));
            }
            for (offset, _) in path.as_str().match_indices('/') {
                let ancestor = &path.as_str()[..offset];
                let Some(ancestor_index) = by_path.get(ancestor) else {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.as_str().into(),
                        reason: format!("missing directory ancestor {ancestor}"),
                    });
                };
                if !entries[*ancestor_index].entry.is_directory() {
                    return Err(PithosError::InvalidArchivePath {
                        path: path.as_str().into(),
                        reason: format!("file entry {ancestor} is an ancestor"),
                    });
                }
            }
            let index = entries.len();
            entries.push(IndexedEntry {
                id: *id,
                path: path.clone(),
                entry: entry.clone(),
            });
            by_id.insert(*id, index);
            by_path.insert(Arc::from(path.as_str()), index);
            hierarchy.insert(path.clone(), index);
        }
    }

    let segment_spans = segment_spans.into_iter().collect::<Vec<_>>();
    let mut local_spans = descriptors
        .values()
        .filter_map(|descriptor| match descriptor.location {
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
    validate_references_and_content(&entries, &by_id, &relationships, &descriptors)?;
    let maximum_id = entries.iter().map(|entry| entry.id).max();
    Ok(ArchiveIndex {
        entries,
        by_id,
        by_path,
        hierarchy,
        descriptors,
        relationships,
        segment_spans,
        local_spans,
        maximum_id,
    })
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
    descriptors: &IndexMap<BlockHash, BlockDescriptor>,
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
            let descriptor = descriptors
                .get(&hash)
                .ok_or(PithosError::MissingBlockDescriptor)?;
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

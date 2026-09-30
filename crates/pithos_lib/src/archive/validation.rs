use crate::archive::types::{
    ArchivePath, BlockDescriptor, BlockHash, BlockLocation, ContentEntry, ContentState, Entry,
    EntryMetadata, ExternalLocation, FileId, Processing, RecipientPair, Reference, RelationId,
    SegmentEntry, Span, ValidatedSegment,
};
use crate::error::PithosError;
use crate::format::block::BlockLocation as FormatBlockLocation;
use crate::format::directory::{Directory, STANDARD_RELATIONSHIPS};
use crate::format::file_entry::{BlockDataState, FileEntry, FileType};
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub(crate) struct IndexLimits {
    pub(crate) max_entries: u64,
    pub(crate) max_descriptors: u64,
    pub(crate) max_references: u64,
    pub(crate) max_relationships: u64,
    pub(crate) max_segments: u64,
}

impl Default for IndexLimits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_descriptors: 1_000_000,
            max_references: 1_000_000,
            max_relationships: 1_000_000,
            max_segments: 1025,
        }
    }
}

pub(crate) fn validated_segment_from_directory(
    directory: &Directory,
    span: Span,
    parent: Option<Span>,
) -> Result<ValidatedSegment, PithosError> {
    let mut entries = Vec::new();
    let mut entry_ids = HashSet::new();
    for (id, path, file_entry) in directory.files.iter() {
        if !entry_ids.insert(id) {
            return Err(PithosError::DuplicateFileId(format!(
                "File id already occupied: {id}"
            )));
        }
        let path = ArchivePath::new(path)?;
        let entry = entry_from_file_entry(path.as_str(), file_entry)?;
        entries.push(SegmentEntry {
            id: FileId(id),
            path,
            entry,
        });
    }
    validate_relationships(directory)?;
    let mut descriptors = Vec::new();
    for (hash, block_index_entry) in &directory.blocks {
        let processing = Processing::from_byte(block_index_entry.flags.0)?;
        if matches!(block_index_entry.location, FormatBlockLocation::Local)
            && processing.to_byte() & 0x08 != 0
            && block_index_entry.stored_size < 28
        {
            return Err(PithosError::InvalidBlockDescriptor(
                "encrypted local block payload is shorter than 28 bytes",
            ));
        }
        let stored_size_with_marker = block_index_entry.stored_size.checked_add(4).ok_or(
            PithosError::InvalidDirectoryRange {
                operation: "validate block range",
            },
        )?;
        let location = match &block_index_entry.location {
            FormatBlockLocation::Local => BlockLocation::Local(Span::new(
                block_index_entry.offset,
                stored_size_with_marker,
            )?),
            FormatBlockLocation::External { url } => {
                BlockLocation::External(ExternalLocation::new(url))
            }
        };
        descriptors.push((
            BlockHash(*hash),
            BlockDescriptor {
                stored_size: block_index_entry.stored_size,
                original_size: block_index_entry.original_size,
                processing,
                location,
            },
        ));
    }
    let mut relationships = Vec::new();
    let mut relation_names: BTreeMap<u64, String> = BTreeMap::new();
    for (id, name) in &directory.relations {
        match relation_names.get(id) {
            Some(existing) if existing != name => {
                return Err(PithosError::ConflictingRelationshipDefinition(*id));
            }
            Some(_) => {}
            None => {
                relation_names.insert(*id, name.clone());
                relationships.push((RelationId(*id), Arc::from(name.as_str())));
            }
        }
    }
    let recipient_pairs: Vec<RecipientPair> = directory
        .encryption
        .iter()
        .flat_map(|(sender, section)| {
            section
                .recipients
                .keys()
                .map(move |recipient| (*sender, *recipient))
        })
        .collect();
    Ok(ValidatedSegment {
        span,
        parent,
        entries,
        descriptors,
        relationships,
        recipient_pairs,
    })
}

fn entry_from_file_entry(path: &str, file_entry: &FileEntry) -> Result<Entry, PithosError> {
    crate::archive::path_validation::validate_entry(path, file_entry)?;
    let metadata = EntryMetadata {
        created: file_entry.created,
        modified: file_entry.modified,
        permissions: file_entry.permissions,
        references: file_entry
            .references
            .iter()
            .map(|reference| Reference {
                target: FileId(reference.target_file_id),
                relationship: RelationId(reference.relationship),
            })
            .collect(),
    };
    let content = || match &file_entry.block_data {
        BlockDataState::Decrypted(blocks) => {
            ContentState::Available(crate::archive::types::BlockReferences::new(
                blocks.iter().map(|(hash, _)| BlockHash(*hash)).collect(),
            ))
        }
        BlockDataState::Encrypted(_) => ContentState::Unavailable,
    };
    match file_entry.file_type {
        FileType::Data => Ok(Entry::File(ContentEntry {
            metadata,
            size: file_entry.file_size,
            content: content(),
        })),
        FileType::Metadata => Ok(Entry::Metadata(ContentEntry {
            metadata,
            size: file_entry.file_size,
            content: content(),
        })),
        FileType::Directory => Ok(Entry::Directory(metadata)),
        FileType::Symlink => {
            let target = file_entry
                .symlink_target
                .as_deref()
                .expect("validated symlink entry has a target");
            Ok(Entry::Symlink {
                metadata,
                target: Arc::from(target),
            })
        }
    }
}

pub(crate) fn validate_relationships(directory: &Directory) -> Result<(), PithosError> {
    let mut next_standard = 0usize;
    for (id, name) in &directory.relations {
        match *id {
            0..=9 => {
                let expected = STANDARD_RELATIONSHIPS[*id as usize].1;
                if name != expected {
                    return Err(PithosError::InvalidRelationshipDefinition {
                        id: *id,
                        reason: format!("expected standard name {expected:?}"),
                    });
                }
                if directory.parent_directory_offset.is_none() && *id != next_standard as u64 {
                    return Err(PithosError::InvalidRelationshipDefinition {
                        id: *id,
                        reason: "standard definitions are out of order".into(),
                    });
                }
                next_standard += 1;
            }
            10..=999 => {
                return Err(PithosError::InvalidRelationshipDefinition {
                    id: *id,
                    reason: "relationship id is reserved".into(),
                });
            }
            _ if name.is_empty() => {
                return Err(PithosError::InvalidRelationshipDefinition {
                    id: *id,
                    reason: "custom relationship name is empty".into(),
                });
            }
            _ => {}
        }
    }
    if directory.parent_directory_offset.is_none() && next_standard != 10 {
        let id = next_standard as u64;
        return Err(PithosError::InvalidRelationshipDefinition {
            id,
            reason: "base directory is missing a standard definition".into(),
        });
    }
    Ok(())
}

pub(crate) fn validate_entry(path: &ArchivePath, entry: &Entry) -> Result<(), PithosError> {
    if let Entry::Symlink { target, .. } = entry {
        validate_symlink_target(path, target)?;
    }
    Ok(())
}

fn validate_symlink_target(path: &ArchivePath, target: &str) -> Result<(), PithosError> {
    if target.is_empty()
        || target.contains('\0')
        || target.contains('\\')
        || target.starts_with('/')
        || target.as_bytes().get(1) == Some(&b':')
    {
        return Err(invalid_target(path, target, "invalid target"));
    }
    let mut depth = path.as_str().split('/').count().saturating_sub(1);
    for component in target.split('/') {
        if component.is_empty() || component == "." {
            return Err(invalid_target(path, target, "empty or dot component"));
        }
        if component == ".." {
            if depth == 0 {
                return Err(invalid_target(path, target, "target escapes archive root"));
            }
            depth -= 1;
        } else {
            depth += 1;
        }
    }
    Ok(())
}

fn invalid_target(path: &ArchivePath, target: &str, reason: &str) -> PithosError {
    PithosError::InvalidSymlinkTarget {
        path: path.as_str().into(),
        target: target.into(),
        reason: reason.into(),
    }
}

pub(crate) fn validate_aggregate(
    segments: &[ValidatedSegment],
    limits: IndexLimits,
) -> Result<(), PithosError> {
    if segments.len() as u64 > limits.max_segments {
        return Err(PithosError::LimitExceeded {
            field: "directory segments",
            limit: limits.max_segments,
            actual: segments.len() as u64,
        });
    }
    let (entries, descriptors, references, relationships) = segments.iter().try_fold(
        (0u64, 0u64, 0u64, 0u64),
        |(entries, descriptors, references, relationships), segment| {
            let entry_count = u64::try_from(segment.entries.len()).unwrap_or(u64::MAX);
            let descriptor_count = u64::try_from(segment.descriptors.len()).unwrap_or(u64::MAX);
            let reference_count = segment
                .entries
                .iter()
                .try_fold(0u64, |total, entry| {
                    total.checked_add(
                        u64::try_from(entry.entry.metadata().references.len()).unwrap_or(u64::MAX),
                    )
                })
                .ok_or(PithosError::LimitExceeded {
                    field: "references",
                    limit: limits.max_references,
                    actual: u64::MAX,
                })?;
            Ok::<_, PithosError>((
                entries.saturating_add(entry_count),
                descriptors.saturating_add(descriptor_count),
                references.saturating_add(reference_count),
                relationships
                    .saturating_add(u64::try_from(segment.relationships.len()).unwrap_or(u64::MAX)),
            ))
        },
    )?;
    for (field, actual, limit) in [
        ("entries", entries, limits.max_entries),
        ("block descriptors", descriptors, limits.max_descriptors),
        ("references", references, limits.max_references),
        (
            "relationship definitions",
            relationships,
            limits.max_relationships,
        ),
    ] {
        if actual > limit {
            return Err(PithosError::LimitExceeded {
                field,
                limit,
                actual,
            });
        }
    }
    Ok(())
}

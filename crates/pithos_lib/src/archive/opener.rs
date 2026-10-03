use super::access::ResolvedAccess;
use super::index::build_effective_index;
use super::reader::{
    AccessKeys, OpenLimits, classify_content_availability, resolve_block_lists, resolve_recipients,
    validate_piece_keys,
};
use super::types::{FileId, Span, ValidatedSegment};
use super::validated_segment_from_directory;
use super::validation::IndexLimits;
use super::view::ArchiveView;
use crate::error::PithosError;
use crate::format::directory::Directory;
use crate::format::header::FormatVersion;
use std::collections::HashMap;

/// The open settings that matter for metadata. External resolution is a read-time concern.
pub(super) struct OpenSettings {
    pub(super) limits: OpenLimits,
    pub(super) keys: AccessKeys,
    pub(super) expected_metadata_digest: Option<[u8; 32]>,
    pub(super) external_enabled: bool,
}

/// Directories decoded so far, from the terminal one back toward the base.
pub(super) struct DecodedChain {
    pub(super) version: FormatVersion,
    pub(super) terminal: Span,
    pub(super) raw: Vec<(Directory, Span)>,
    pub(super) remaining_block_references: u64,
    pub(super) directory_hashes: Vec<[u8; 32]>,
}

/// Runs every metadata check after the whole chain is decoded and builds the view.
pub(super) fn complete_open(
    archive_len: u64,
    settings: &mut OpenSettings,
    chain: DecodedChain,
) -> Result<ArchiveView, PithosError> {
    let DecodedChain {
        version,
        terminal,
        mut raw,
        mut remaining_block_references,
        mut directory_hashes,
    } = chain;
    let limits = settings.limits;
    raw.reverse();
    directory_hashes.reverse();
    let metadata_digest = crate::archive::metadata_digest(&directory_hashes);
    if settings
        .expected_metadata_digest
        .is_some_and(|expected| expected != metadata_digest)
    {
        return Err(PithosError::MetadataDigestMismatch);
    }
    let maximum_piece_key = validate_piece_keys(version, &raw)?;

    let mut first_grants = HashMap::new();
    for (directory, _) in &raw {
        for (sender, section) in &directory.encryption {
            for (recipient, recipient_section) in &section.recipients {
                let pair = (*sender, *recipient);
                if let Some(first) = first_grants.get(&pair)
                    && *first != &recipient_section.recipient_data
                {
                    return Err(PithosError::ConflictingRecipientGrant);
                }
                first_grants
                    .entry(pair)
                    .or_insert(&recipient_section.recipient_data);
            }
        }
    }

    let mut access = ResolvedAccess::new();
    let mut recovery_order = 0usize;
    for (segment, (directory, _)) in raw.iter().enumerate() {
        resolve_recipients(
            version,
            directory,
            &settings.keys,
            segment,
            &mut recovery_order,
            &mut access,
            limits,
        )?;
    }

    let mut segments: Vec<ValidatedSegment> = Vec::new();
    for (segment_index, (directory, span)) in raw.into_iter().enumerate() {
        let mut directory = directory;
        resolve_block_lists(
            &mut directory,
            &mut access,
            &mut remaining_block_references,
            limits,
        )?;
        let parent = segment_index
            .checked_sub(1)
            .map(|index| segments[index].span);
        segments.push(validated_segment_from_directory(
            version, &directory, span, parent,
        )?);
    }
    let index_limits = IndexLimits {
        max_entries: limits.max_entries,
        max_descriptors: limits.max_descriptors,
        max_references: limits.max_references,
        max_relationships: limits.max_relationships,
        max_segments: limits.max_parent_directories.saturating_add(1),
    };
    let mut index = build_effective_index(&segments, archive_len, index_limits)?;
    index.cover_piece_keys(maximum_piece_key.map(FileId));
    let content_availability = classify_content_availability(&index, settings.external_enabled)?;
    Ok(ArchiveView {
        archive_len,
        version,
        metadata_digest,
        terminal_directory: terminal,
        index,
        segments,
        index_limits,
        access,
        #[cfg(feature = "crypt4gh")]
        access_keys: std::mem::take(&mut settings.keys),
        limits,
        content_availability,
    })
}

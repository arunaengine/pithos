use super::{
    AccessProvenance, AppendSnapshot, FileId, ResolvedAccess, Span, build_effective_index,
    decode_validated_directory, validated_segment_from_directory,
};
use crate::archive::index::ArchiveIndex;
use crate::archive::types::{
    ArchivePath, BlockHash, BlockLocation, ContentState, Entry, ExternalLocation, ReadRange,
    ValidatedSegment,
};
use crate::archive::validation::IndexLimits;
use crate::block;
use crate::crypto::{self, FileKey, PrivateKey};
use crate::error::PithosError;
use crate::format::block::{
    BlockIndexEntry, BlockLocation as FormatBlockLocation, ProcessingFlags,
};
use crate::format::directory::Directory;
use crate::format::encryption::RecipientData;
use crate::format::file_entry::{BlockDataEntry, BlockDataState};
use crate::format::header::FileHeader;
use crate::format::limits::DeserializationLimits;
use crate::source::ArchiveSource;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write;
use std::sync::Arc;

/// Distinguishes archive failures from a presentation callback failure without
/// making the archive core depend on the callback's error type.
pub(crate) enum ContentOperationError<E> {
    Core(PithosError),
    Callback(E),
}
use std::ops::Range;
use x25519_dalek::PublicKey as DalekPublicKey;
use zeroize::Zeroizing;

#[derive(Default)]
struct DecodedDirectoryCounts {
    entries: u64,
    descriptors: u64,
    references: u64,
    direct_references: u64,
    relationships: u64,
}

impl DecodedDirectoryCounts {
    fn record(&mut self, directory: &Directory) {
        self.entries += directory.files.len() as u64;
        self.descriptors += directory.blocks.len() as u64;
        self.references += directory
            .files
            .iter()
            .map(|(_, _, file)| file.references.len() as u64)
            .sum::<u64>();
        self.direct_references += directory
            .files
            .iter()
            .map(|(_, _, file)| match &file.block_data {
                BlockDataState::Decrypted(entries) => entries.len() as u64,
                BlockDataState::Encrypted(_) => 0,
            })
            .sum::<u64>();
        self.relationships += directory.relations.len() as u64;
    }
}

/// Limits enforced before directory data is retained or expensive metadata work begins.
#[derive(Clone, Copy, Debug)]
pub struct OpenLimits {
    pub max_directory_bytes: u64,
    pub max_total_directory_bytes: u64,
    pub max_parent_directories: u64,
    pub max_entries: u64,
    pub max_descriptors: u64,
    pub max_references: u64,
    pub max_relationships: u64,
    pub max_accessible_block_references: u64,
    pub max_opaque_metadata_bytes: u64,
    pub max_stored_block_bytes: u64,
    pub max_decoded_block_bytes: u64,
}

impl Default for OpenLimits {
    fn default() -> Self {
        Self {
            max_directory_bytes: 64 * 1024 * 1024,
            max_total_directory_bytes: 256 * 1024 * 1024,
            max_parent_directories: 1024,
            max_entries: 1_000_000,
            max_descriptors: 1_000_000,
            max_references: 1_000_000,
            max_relationships: 1_000_000,
            max_accessible_block_references: 1_000_000,
            max_opaque_metadata_bytes: 64 * 1024 * 1024,
            max_stored_block_bytes: 64 * 1024 * 1024,
            max_decoded_block_bytes: 64 * 1024 * 1024,
        }
    }
}

/// A finite ordered set of recipient keys used while opening encrypted metadata.
#[derive(Default)]
#[allow(clippy::vec_box)] // Stable allocations prevent stale secret copies when the key list grows.
pub struct AccessKeys(Vec<Box<PrivateKey>>);

impl AccessKeys {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_key(mut self, key: PrivateKey) -> Self {
        self.0.push(Box::new(key));
        self
    }

    pub fn push(&mut self, key: PrivateKey) {
        self.0.push(Box::new(key));
    }
}

/// Resolves an opaque external block location to exactly one framed `BLCK` value.
///
/// The resolver owns interpretation of the opaque location and selection of concrete
/// access targets. It must call the supplied policy before its initial access and before
/// every redirect. The [`ExternalLocation`] is archive-owned opaque data and is not
/// necessarily itself a concrete policy target.
pub trait ExternalBlockResolver {
    fn resolve(
        &self,
        policy: &dyn ExternalBlockAccessPolicy,
        location: &ExternalLocation,
        expected_len: u64,
        max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError>;
}

/// Describes a feature that prevents content access without changing archive structure.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ArchiveFeature {
    Compression,
    BlockEncryption,
    EncryptedBlockList,
    EncryptedRecipientList,
    ExternalStorage,
}

/// Decides whether an external resolver may access a concrete target.
///
/// Resolvers select concrete targets from an opaque [`ExternalLocation`] and must call
/// this policy before the initial access and before every redirect. The policy is not
/// called by the archive core for the opaque location itself.
pub trait ExternalBlockAccessPolicy: Send + Sync {
    fn allows(&self, target: &str) -> bool;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContentAvailability {
    Available,
    MissingAccess,
    Unsupported(ArchiveFeature),
}

/// The default resolver rejects external block reads.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoExternalBlocks;

impl ExternalBlockResolver for NoExternalBlocks {
    fn resolve(
        &self,
        _policy: &dyn ExternalBlockAccessPolicy,
        _location: &ExternalLocation,
        _expected_len: u64,
        _max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError> {
        Err(PithosError::UnsupportedFeature(
            ArchiveFeature::ExternalStorage,
        ))
    }
}

/// Options consumed by the single validated archive open boundary.
pub struct OpenOptions<E = NoExternalBlocks> {
    limits: OpenLimits,
    keys: AccessKeys,
    external: E,
    external_resolver_supplied: bool,
    external_access_policy: Option<Arc<dyn ExternalBlockAccessPolicy>>,
}

impl Default for OpenOptions<NoExternalBlocks> {
    fn default() -> Self {
        Self {
            limits: OpenLimits::default(),
            keys: AccessKeys::default(),
            external: NoExternalBlocks,
            external_resolver_supplied: false,
            external_access_policy: None,
        }
    }
}

impl<E> OpenOptions<E> {
    pub fn with_limits(mut self, limits: OpenLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn with_access_keys(mut self, keys: AccessKeys) -> Self {
        self.keys = keys;
        self
    }

    pub fn with_external_resolver<T>(self, external: T) -> OpenOptions<T> {
        OpenOptions {
            limits: self.limits,
            keys: self.keys,
            external,
            external_resolver_supplied: true,
            external_access_policy: self.external_access_policy,
        }
    }

    pub fn with_external_access_policy(
        mut self,
        policy: Arc<dyn ExternalBlockAccessPolicy>,
    ) -> Self {
        self.external_access_policy = Some(policy);
        self
    }
}

/// Public, secret-free entry shape returned by an opened archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EntryKind {
    File { size: u64, available: bool },
    Metadata { size: u64, available: bool },
    Directory,
    Symlink { target: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveEntry {
    pub id: u64,
    pub path: String,
    pub kind: EntryKind,
    pub created: u64,
    pub modified: u64,
    pub permissions: u32,
    pub references: Vec<ArchiveReference>,
}

/// A secret-free resolved relationship attached to an immutable archive entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArchiveReference {
    pub target_id: u64,
    pub relationship: String,
}

/// Immutable validated archive state. Payload bytes are deliberately verified lazily.
///
/// `copy_to` and `copy_range_to` verify a complete block before writing any bytes
/// from that block. A generic sink can therefore contain earlier verified blocks
/// when a later block fails. Filesystem extraction is provided by [`crate::fs::extract`],
/// which stages each regular-file output before publication.
pub struct Archive<S, E = NoExternalBlocks> {
    source: S,
    external: E,
    external_access_policy: Option<Arc<dyn ExternalBlockAccessPolicy>>,
    archive_len: u64,
    terminal_directory: Span,
    index: ArchiveIndex,
    segments: Vec<ValidatedSegment>,
    index_limits: IndexLimits,
    access: ResolvedAccess,
    access_keys: AccessKeys,
    limits: OpenLimits,
    content_availability: BTreeMap<FileId, ContentAvailability>,
}

impl<S, E> Archive<S, E>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    /// Opens, frames, validates, resolves access metadata, and indexes an archive.
    pub fn open(source: S, options: OpenOptions<E>) -> Result<Self, PithosError> {
        let archive_len = source.len()?;
        let mut header = [0; FileHeader::ENCODED_LEN];
        source.read_exact_at(0, &mut header)?;
        let header = crate::format::header::decode_header(&mut header.as_slice())?;
        if header.version != FileHeader::SUPPORTED_VERSION {
            return Err(PithosError::UnsupportedFileVersion {
                supported: FileHeader::SUPPORTED_VERSION,
                actual: header.version,
            });
        }

        let (terminal_start, terminal_len) = terminal_span(&source, archive_len, options.limits)?;
        let mut raw = Vec::new();
        let mut total_directory_bytes = 0u64;
        let mut next = Some((terminal_start, terminal_len));
        let mut child_start = archive_len;
        let mut visited = HashSet::new();
        let mut decoded = DecodedDirectoryCounts::default();
        let mut remaining_block_references = options.limits.max_accessible_block_references;
        while let Some((start, len)) = next {
            validate_directory_len(len, options.limits)?;
            if raw.len() as u64 > options.limits.max_parent_directories {
                return Err(PithosError::LimitExceeded {
                    field: "parent directories",
                    limit: options.limits.max_parent_directories,
                    actual: raw.len() as u64,
                });
            }
            let span = Span::new(start, len)?;
            if span.end() > child_start || !visited.insert((start, len)) {
                return Err(PithosError::InvalidDirectoryChain {
                    operation: "validate parent ordering",
                });
            }
            total_directory_bytes =
                total_directory_bytes
                    .checked_add(len)
                    .ok_or(PithosError::LimitExceeded {
                        field: "total directory bytes",
                        limit: options.limits.max_total_directory_bytes,
                        actual: u64::MAX,
                    })?;
            if total_directory_bytes > options.limits.max_total_directory_bytes {
                return Err(PithosError::LimitExceeded {
                    field: "total directory bytes",
                    limit: options.limits.max_total_directory_bytes,
                    actual: total_directory_bytes,
                });
            }
            let bytes = Zeroizing::new(read_source(&source, start, len, "directory")?);
            let directory = decode_validated_directory(
                &bytes,
                &remaining_deserialization_limits(options.limits, &decoded),
                &mut remaining_block_references,
            )?;
            decoded.record(&directory);
            next = directory.parent_directory_offset;
            child_start = start;
            raw.push((directory, span));
        }
        raw.reverse();

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
                directory,
                &options.keys,
                segment,
                &mut recovery_order,
                &mut access,
                options.limits,
            )?;
        }

        let mut segments: Vec<ValidatedSegment> = Vec::new();
        for (segment_index, (directory, span)) in raw.into_iter().enumerate() {
            let mut directory = directory;
            resolve_block_lists(
                &mut directory,
                &mut access,
                &mut remaining_block_references,
                options.limits,
            )?;
            let parent = segment_index
                .checked_sub(1)
                .map(|index| segments[index].span);
            segments.push(validated_segment_from_directory(&directory, span, parent)?);
        }
        let index_limits = IndexLimits {
            max_entries: options.limits.max_entries,
            max_descriptors: options.limits.max_descriptors,
            max_references: options.limits.max_references,
            max_relationships: options.limits.max_relationships,
            max_segments: options.limits.max_parent_directories.saturating_add(1),
        };
        let index = build_effective_index(&segments, archive_len, index_limits)?;
        let content_availability = classify_content_availability(
            &index,
            options.external_resolver_supplied,
            options.external_access_policy.is_some(),
        )?;
        for span in index.local_block_spans() {
            let mut marker = [0; 4];
            source.read_exact_at(span.start(), &mut marker)?;
            crate::format::block::decode_block_marker(&mut marker.as_slice())?;
        }

        Ok(Self {
            source,
            external: options.external,
            external_access_policy: options.external_access_policy,
            archive_len,
            terminal_directory: Span::new(terminal_start, terminal_len)?,
            index,
            segments,
            index_limits,
            access,
            access_keys: options.keys,
            limits: options.limits,
            content_availability,
        })
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = ArchiveEntry> + '_ {
        self.index
            .entries()
            .map(|entry| archive_entry(&self.index, entry, &self.content_availability))
    }

    /// Consumes the reader and transfers its validated state to append/grant planning.
    pub(crate) fn into_append_snapshot(self) -> AppendSnapshot {
        let Self {
            archive_len,
            terminal_directory,
            index,
            segments,
            index_limits,
            access,
            ..
        } = self;
        AppendSnapshot::new(
            archive_len,
            terminal_directory,
            index,
            segments,
            index_limits,
            access,
        )
    }

    pub fn entry(&self, path: &str) -> Result<Option<ArchiveEntry>, PithosError> {
        let path = ArchivePath::new(path)?;
        Ok(self
            .index
            .entry_at_path(&path)
            .map(|entry| archive_entry(&self.index, entry, &self.content_availability)))
    }

    pub fn copy_to<W: Write + ?Sized>(&self, path: &str, sink: &mut W) -> Result<(), PithosError> {
        let (id, _) = self.content_id(path)?;
        self.require_content_available(id)?;
        self.copy_plan(id, self.index.full_file_plan(id)?, sink)
    }

    pub fn copy_range_to<W: Write + ?Sized>(
        &self,
        path: &str,
        range: Range<u64>,
        sink: &mut W,
    ) -> Result<(), PithosError> {
        let (id, size) = self.content_id(path)?;
        let range = ReadRange::new(range, size)?;
        self.require_content_available(id)?;
        self.copy_plan(id, self.index.range_plan(id, range)?, sink)
    }

    pub(crate) fn with_crypt4gh_content<T, CallbackError>(
        &self,
        path: &str,
        operation: impl FnOnce(FileId, &PrivateKey, &FileKey) -> Result<T, CallbackError>,
    ) -> Result<T, ContentOperationError<CallbackError>> {
        let (id, _) = self.content_id(path).map_err(ContentOperationError::Core)?;
        self.require_content_available(id)
            .map_err(ContentOperationError::Core)?;
        let key = self
            .access
            .key(id)
            .ok_or(PithosError::ContentUnavailable)
            .map_err(ContentOperationError::Core)?;
        let provenance = self
            .access
            .provenance(id)
            .ok_or(PithosError::ContentUnavailable)
            .map_err(ContentOperationError::Core)?;
        let reader = self
            .access_keys
            .0
            .get(provenance.access_key)
            .ok_or(PithosError::ContentUnavailable)
            .map_err(ContentOperationError::Core)?;
        operation(id, reader, key).map_err(ContentOperationError::Callback)
    }

    pub(crate) fn for_each_verified_file_block<CallbackError>(
        &self,
        id: FileId,
        mut operation: impl FnMut(Zeroizing<Vec<u8>>) -> Result<(), CallbackError>,
    ) -> Result<(), ContentOperationError<CallbackError>> {
        self.require_content_available(id)
            .map_err(ContentOperationError::Core)?;
        let plan = self
            .index
            .full_file_plan(id)
            .map_err(ContentOperationError::Core)?;
        for block in plan.blocks {
            let plaintext = self
                .verified_block(id, &block)
                .map_err(ContentOperationError::Core)?;
            operation(plaintext).map_err(ContentOperationError::Callback)?;
        }
        Ok(())
    }

    fn content_id(&self, path: &str) -> Result<(FileId, u64), PithosError> {
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

    fn copy_plan<W: Write + ?Sized>(
        &self,
        id: FileId,
        plan: super::planning::ReadPlan,
        sink: &mut W,
    ) -> Result<(), PithosError> {
        for block in plan.blocks {
            let plaintext = self.verified_block(id, &block)?;
            sink.write_all(&plaintext[block.output])?;
        }
        Ok(())
    }

    fn verified_block(
        &self,
        id: FileId,
        planned: &super::planning::PlannedBlock,
    ) -> Result<Zeroizing<Vec<u8>>, PithosError> {
        if planned.descriptor.stored_size > self.limits.max_stored_block_bytes {
            return Err(PithosError::LimitExceeded {
                field: "stored block",
                limit: self.limits.max_stored_block_bytes,
                actual: planned.descriptor.stored_size,
            });
        }
        if planned.descriptor.original_size > self.limits.max_decoded_block_bytes {
            return Err(PithosError::LimitExceeded {
                field: "decoded block",
                limit: self.limits.max_decoded_block_bytes,
                actual: planned.descriptor.original_size,
            });
        }
        let stored = match &planned.descriptor.location {
            BlockLocation::Local(span) => {
                let mut marker = [0; 4];
                self.source.read_exact_at(span.start(), &mut marker)?;
                crate::format::block::decode_block_marker(&mut marker.as_slice())?;
                let payload_start =
                    span.start()
                        .checked_add(4)
                        .ok_or(PithosError::InvalidDirectoryRange {
                            operation: "read block payload",
                        })?;
                read_source(
                    &self.source,
                    payload_start,
                    planned.descriptor.stored_size,
                    "block",
                )?
            }
            BlockLocation::External(location) => {
                let expected_len =
                    planned
                        .descriptor
                        .stored_size
                        .checked_add(4)
                        .ok_or_else(|| {
                            PithosError::ExternalBlockFraming("response size overflow".into())
                        })?;
                let response = self.external.resolve(
                    self.external_access_policy.as_deref().ok_or(
                        PithosError::UnsupportedFeature(ArchiveFeature::ExternalStorage),
                    )?,
                    location,
                    expected_len,
                    self.limits
                        .max_stored_block_bytes
                        .checked_add(4)
                        .ok_or_else(|| {
                            PithosError::ExternalBlockFraming("response policy overflow".into())
                        })?,
                )?;
                if response.len() as u64 != expected_len {
                    return Err(PithosError::ExternalBlockFraming(
                        "response does not match expected size".into(),
                    ));
                }
                let (mut marker, stored) = response.split_at(4);
                crate::format::block::decode_block_marker(&mut marker)?;
                stored.to_vec()
            }
        };
        let meta = BlockIndexEntry {
            offset: 0,
            stored_size: planned.descriptor.stored_size,
            original_size: planned.descriptor.original_size,
            flags: ProcessingFlags::from_byte(planned.descriptor.processing.to_byte()),
            location: FormatBlockLocation::Local,
        };
        let key = self
            .access
            .block_key(id, planned.hash)
            .ok_or(PithosError::ContentUnavailable)?;
        block::verify(
            stored,
            key,
            planned.hash.0,
            &meta,
            block::Limits {
                max_stored_bytes: self.limits.max_stored_block_bytes,
                max_decoded_bytes: self.limits.max_decoded_block_bytes,
            },
        )
    }
}

fn entry_kind(
    entry: &Entry,
    id: FileId,
    content_availability: &BTreeMap<FileId, ContentAvailability>,
) -> EntryKind {
    match entry {
        Entry::File(content) => EntryKind::File {
            size: content.size,
            available: matches!(
                content_availability.get(&id),
                Some(ContentAvailability::Available)
            ),
        },
        Entry::Metadata(content) => EntryKind::Metadata {
            size: content.size,
            available: matches!(
                content_availability.get(&id),
                Some(ContentAvailability::Available)
            ),
        },
        Entry::Directory(_) => EntryKind::Directory,
        Entry::Symlink { target, .. } => EntryKind::Symlink {
            target: target.to_string(),
        },
    }
}

fn archive_entry(
    index: &ArchiveIndex,
    entry: &super::index::IndexedEntry,
    content_availability: &BTreeMap<FileId, ContentAvailability>,
) -> ArchiveEntry {
    let metadata = entry.entry.metadata();
    ArchiveEntry {
        id: entry.id.0,
        path: entry.path.as_str().to_owned(),
        kind: entry_kind(&entry.entry, entry.id, content_availability),
        created: metadata.created,
        modified: metadata.modified,
        permissions: metadata.permissions,
        references: metadata
            .references
            .iter()
            .map(|reference| ArchiveReference {
                target_id: reference.target.0,
                relationship: index
                    .relationship(reference.relationship)
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("unknown:{}", reference.relationship.0)),
            })
            .collect(),
    }
}

fn classify_content_availability(
    index: &ArchiveIndex,
    external_resolver_supplied: bool,
    external_access_policy_supplied: bool,
) -> Result<BTreeMap<FileId, ContentAvailability>, PithosError> {
    let external_supported = external_resolver_supplied && external_access_policy_supplied;
    let mut availability = BTreeMap::new();
    for entry in index.entries() {
        let Some(content) = entry.entry.content() else {
            continue;
        };
        let state = match &content.content {
            ContentState::Unavailable => ContentAvailability::MissingAccess,
            ContentState::Available(references) => {
                let has_external_block = references.iter().any(|hash| {
                    matches!(
                        index.descriptor(hash),
                        Some(crate::archive::types::BlockDescriptor {
                            location: BlockLocation::External(_),
                            ..
                        })
                    )
                });
                if has_external_block && !external_supported {
                    ContentAvailability::Unsupported(ArchiveFeature::ExternalStorage)
                } else {
                    ContentAvailability::Available
                }
            }
        };
        availability.insert(entry.id, state);
    }
    Ok(availability)
}

fn deserialization_limits(limits: OpenLimits) -> DeserializationLimits {
    DeserializationLimits {
        max_collection_entries: limits.max_entries,
        max_file_entries: limits.max_entries,
        max_block_descriptors: limits.max_descriptors,
        max_block_references: limits.max_accessible_block_references,
        max_references: limits.max_references,
        max_relationships: limits.max_relationships,
        max_opaque_bytes: limits.max_opaque_metadata_bytes,
        ..DeserializationLimits::default()
    }
}

fn remaining_deserialization_limits(
    limits: OpenLimits,
    decoded: &DecodedDirectoryCounts,
) -> DeserializationLimits {
    let mut remaining = deserialization_limits(limits);
    remaining.max_file_entries = remaining.max_file_entries.saturating_sub(decoded.entries);
    remaining.max_block_descriptors = remaining
        .max_block_descriptors
        .saturating_sub(decoded.descriptors);
    remaining.max_block_references = remaining
        .max_block_references
        .saturating_sub(decoded.direct_references);
    remaining.max_references = remaining.max_references.saturating_sub(decoded.references);
    remaining.max_relationships = remaining
        .max_relationships
        .saturating_sub(decoded.relationships);
    remaining
}

fn terminal_span<S: ArchiveSource>(
    source: &S,
    archive_len: u64,
    limits: OpenLimits,
) -> Result<(u64, u64), PithosError> {
    if archive_len < 12 {
        return Err(PithosError::InvalidDirectoryRange {
            operation: "read directory footer",
        });
    }
    let mut footer = [0; 12];
    source.read_exact_at(archive_len - 12, &mut footer)?;
    let len = u64::from_be_bytes(footer[..8].try_into().expect("fixed footer length"));
    validate_directory_len(len, limits)?;
    let start = archive_len
        .checked_sub(len)
        .ok_or(PithosError::InvalidDirectoryRange {
            operation: "validate terminal directory",
        })?;
    Ok((start, len))
}

fn validate_directory_len(len: u64, limits: OpenLimits) -> Result<(), PithosError> {
    if len < 25 {
        return Err(PithosError::DirectoryLengthMismatch {
            expected: 25,
            actual: len,
        });
    }
    if len > limits.max_directory_bytes {
        return Err(PithosError::LimitExceeded {
            field: "directory",
            limit: limits.max_directory_bytes,
            actual: len,
        });
    }
    Ok(())
}

fn read_source<S: ArchiveSource>(
    source: &S,
    offset: u64,
    len: u64,
    field: &'static str,
) -> Result<Vec<u8>, PithosError> {
    let len = usize::try_from(len)
        .map_err(|_| PithosError::InvalidDirectoryRange { operation: field })?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| PithosError::AllocationFailed {
            field,
            size: len as u64,
        })?;
    bytes.resize(len, 0);
    source.read_exact_at(offset, &mut bytes)?;
    Ok(bytes)
}

fn resolve_recipients(
    directory: &Directory,
    keys: &AccessKeys,
    segment: usize,
    recovery_order: &mut usize,
    access: &mut ResolvedAccess,
    limits: OpenLimits,
) -> Result<(), PithosError> {
    let decoded_limits = deserialization_limits(limits);
    for (access_key, key) in keys.0.iter().enumerate() {
        let secret = key.as_dalek_static_secret();
        let recipient = DalekPublicKey::from(&secret).to_bytes();
        for (sender_section, (sender, section)) in directory.encryption.iter().enumerate() {
            let candidates: Vec<(&[u8; 32], &RecipientData)> = if sender == &recipient {
                section
                    .recipients
                    .iter()
                    .map(|(recipient, section)| (recipient, &section.recipient_data))
                    .collect()
            } else {
                section
                    .recipients
                    .get(&recipient)
                    .map(|section| vec![(sender, &section.recipient_data)])
                    .unwrap_or_default()
            };
            for (recipient_section, (peer, data)) in candidates.into_iter().enumerate() {
                let shared = crypto::derive_shared(secret.as_bytes(), peer)?;
                let entries = match data {
                    RecipientData::Encrypted(bytes) => {
                        let plaintext = crypto::unwrap_recipient_list(&shared, bytes)?;
                        crate::format::encryption::decode_decrypted_recipient_list(
                            &plaintext,
                            &decoded_limits,
                        )?
                    }
                    RecipientData::Decrypted(entries) => entries.clone(),
                };
                for (file_id, file_key) in entries.iter() {
                    access.insert(
                        FileId(*file_id),
                        file_key,
                        AccessProvenance {
                            segment,
                            recovery_order: *recovery_order,
                            access_key,
                            sender_section,
                            recipient_section,
                        },
                    )?;
                    *recovery_order = recovery_order.saturating_add(1);
                }
            }
        }
    }
    Ok(())
}

fn resolve_block_lists(
    directory: &mut Directory,
    access: &mut ResolvedAccess,
    remaining_block_references: &mut u64,
    limits: OpenLimits,
) -> Result<(), PithosError> {
    directory.files.try_for_each_mut(|id, file| {
        let file_id = FileId(id);
        match &file.block_data {
            BlockDataState::Decrypted(entries) => {
                record_block_keys(access, file_id, entries);
            }
            BlockDataState::Encrypted(bytes) => {
                let Some(file_key) = access.key(file_id) else {
                    return Ok(());
                };
                let mut decoded_limits = deserialization_limits(limits);
                decoded_limits.max_block_references = *remaining_block_references;
                let plaintext = crypto::open_file_block_list(file_key, bytes)?;
                let entries = crate::format::file_entry::decode_decrypted_block_list_with_budget(
                    &plaintext,
                    &decoded_limits,
                    remaining_block_references,
                )?;
                record_block_keys(access, file_id, &entries);
                file.block_data = BlockDataState::Decrypted(entries);
            }
        }
        Ok(())
    })
}

fn record_block_keys(access: &mut ResolvedAccess, file_id: FileId, entries: &[BlockDataEntry]) {
    access.insert_block_keys(
        file_id,
        entries.iter().map(|(hash, key)| (BlockHash(*hash), key)),
    );
}

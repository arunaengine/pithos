use super::opener::{ArchiveOpener, OpenSettings};
use super::planning::{BlockRequest, PlannedBlock, ReadPlan};
use super::{AccessProvenance, AppendSnapshot, ArchiveView, FileId, ResolvedAccess, Span};
use crate::archive::index::ArchiveIndex;
use crate::archive::types::{BlockLocation, ContentState, Entry, ExternalLocation, ReadRange};
#[cfg(feature = "crypt4gh")]
use crate::crypto::FileKey;
use crate::crypto::{self, PrivateKey};
use crate::error::PithosError;
use crate::format::directory::Directory;
use crate::format::encryption::RecipientData;
use crate::format::file_entry::BlockDataState;
use crate::format::header::FormatVersion;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::source::ArchiveSource;
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::sync::Arc;

/// Distinguishes archive failures from a presentation callback failure without
/// making the archive core depend on the callback's error type.
#[cfg(feature = "crypt4gh")]
pub(crate) enum ContentOperationError<E> {
    Core(PithosError),
    Callback(E),
}
use std::ops::Range;
use x25519_dalek::PublicKey as DalekPublicKey;
use zeroize::Zeroizing;

#[derive(Default)]
pub(super) struct DecodedDirectoryCounts {
    entries: u64,
    descriptors: u64,
    references: u64,
    direct_references: u64,
    relationships: u64,
}

impl DecodedDirectoryCounts {
    pub(super) fn record(&mut self, directory: &Directory) {
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
                BlockDataState::Encrypted(_) | BlockDataState::Pieces(_) => 0,
            })
            .sum::<u64>();
        self.relationships += directory.relations.len() as u64;
    }
}

/// The default limit for one decoded block, which also bounds fixed writer block sizes.
pub(crate) const DEFAULT_MAX_DECODED_BLOCK_BYTES: u64 = 64 * 1024 * 1024;

/// Limits enforced before directory data is retained or expensive metadata work begins.
/// The defaults admit one 5 TiB file stored in 4 MiB blocks.
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
            max_directory_bytes: 256 * 1024 * 1024,
            max_total_directory_bytes: 512 * 1024 * 1024,
            max_parent_directories: 1024,
            max_entries: 1_000_000,
            max_descriptors: 2_097_152,
            max_references: 1_000_000,
            max_relationships: 1_000_000,
            max_accessible_block_references: 2_097_152,
            max_opaque_metadata_bytes: 128 * 1024 * 1024,
            // The worst case of a block at the decoded limit: the zstd bound plus nonce and tag.
            max_stored_block_bytes: zstd::zstd_safe::compress_bound(
                DEFAULT_MAX_DECODED_BLOCK_BYTES as usize,
            ) as u64
                + 28,
            max_decoded_block_bytes: DEFAULT_MAX_DECODED_BLOCK_BYTES,
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
pub(super) enum ContentAvailability {
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
    expected_metadata_digest: Option<[u8; 32]>,
}

impl Default for OpenOptions<NoExternalBlocks> {
    fn default() -> Self {
        Self {
            limits: OpenLimits::default(),
            keys: AccessKeys::default(),
            external: NoExternalBlocks,
            external_resolver_supplied: false,
            external_access_policy: None,
            expected_metadata_digest: None,
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
            expected_metadata_digest: self.expected_metadata_digest,
        }
    }

    /// Requires the archive's metadata digest to equal `digest`, for example a value kept in
    /// trusted storage. A mismatch fails before any metadata is decrypted or used.
    pub fn with_expected_metadata_digest(mut self, digest: [u8; 32]) -> Self {
        self.expected_metadata_digest = Some(digest);
        self
    }

    pub fn with_external_access_policy(
        mut self,
        policy: Arc<dyn ExternalBlockAccessPolicy>,
    ) -> Self {
        self.external_access_policy = Some(policy);
        self
    }

    /// Splits off the read-time external resolver and access policy.
    pub(super) fn into_parts(
        self,
    ) -> (OpenSettings, E, Option<Arc<dyn ExternalBlockAccessPolicy>>) {
        let settings = OpenSettings {
            limits: self.limits,
            keys: self.keys,
            expected_metadata_digest: self.expected_metadata_digest,
            external_enabled: self.external_resolver_supplied
                && self.external_access_policy.is_some(),
        };
        (settings, self.external, self.external_access_policy)
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
    view: ArchiveView,
}

impl<S, E> Archive<S, E>
where
    S: ArchiveSource,
    E: ExternalBlockResolver,
{
    /// Opens, frames, validates, resolves access metadata, and indexes an archive.
    pub fn open(source: S, options: OpenOptions<E>) -> Result<Self, PithosError> {
        let archive_len = source.len()?;
        let (settings, external, external_access_policy) = options.into_parts();
        let mut opener = ArchiveOpener::with_settings(archive_len, settings)?;
        while let Some(request) = opener.request() {
            let response = read_source(&source, request.offset(), request.len(), "directory")?;
            opener.feed(request, response)?;
        }
        let view = opener.finish()?;
        Ok(Self {
            source,
            external,
            external_access_policy,
            view,
        })
    }

    /// BLAKE3 over the hashes of every directory, from the base to the terminal directory.
    /// Keeping it in trusted storage lets a later open detect changed metadata.
    pub fn metadata_digest(&self) -> [u8; 32] {
        self.view.metadata_digest()
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = ArchiveEntry> + '_ {
        self.view.entries()
    }

    /// The validated metadata, for planning reads without this reader's source.
    pub fn view(&self) -> &ArchiveView {
        &self.view
    }

    /// Consumes the reader and transfers its validated state to append/grant planning.
    pub(crate) fn into_append_snapshot(self) -> AppendSnapshot {
        self.view.into_append_snapshot()
    }

    pub fn entry(&self, path: &str) -> Result<Option<ArchiveEntry>, PithosError> {
        self.view.entry(path)
    }

    pub fn copy_to<W: Write + ?Sized>(&self, path: &str, sink: &mut W) -> Result<(), PithosError> {
        let (id, size) = self.view.content_id(path)?;
        self.require_content_available(id)?;
        self.copy_plan(self.view.plan(id, ReadRange::new(0..size, size)?)?, sink)
    }

    pub fn copy_range_to<W: Write + ?Sized>(
        &self,
        path: &str,
        range: Range<u64>,
        sink: &mut W,
    ) -> Result<(), PithosError> {
        self.copy_plan(self.view.plan_range(path, range)?, sink)
    }

    #[cfg(feature = "crypt4gh")]
    pub(crate) fn with_crypt4gh_content<T, CallbackError>(
        &self,
        path: &str,
        operation: impl FnOnce(FileId, &PrivateKey, &FileKey) -> Result<T, CallbackError>,
    ) -> Result<T, ContentOperationError<CallbackError>> {
        let (id, _) = self
            .view
            .content_id(path)
            .map_err(ContentOperationError::Core)?;
        self.require_content_available(id)
            .map_err(ContentOperationError::Core)?;
        let fresh_key;
        let (key, key_owner) = match self.view.access.key(id) {
            Some(key) => (key, id),
            None => {
                // A file sealed in pieces has no file key, so the export gets a fresh one.
                let first_piece = self
                    .view
                    .access
                    .grant_keys(id)
                    .and_then(|keys| keys.first().map(|(key_id, _)| *key_id))
                    .ok_or(PithosError::ContentUnavailable)
                    .map_err(ContentOperationError::Core)?;
                fresh_key = FileKey::from_bytes(x25519_dalek::StaticSecret::random().to_bytes());
                (&fresh_key, first_piece)
            }
        };
        let provenance = self
            .view
            .access
            .provenance(key_owner)
            .ok_or(PithosError::ContentUnavailable)
            .map_err(ContentOperationError::Core)?;
        let reader = self
            .view
            .access_keys
            .0
            .get(provenance.access_key)
            .ok_or(PithosError::ContentUnavailable)
            .map_err(ContentOperationError::Core)?;
        operation(id, reader, key).map_err(ContentOperationError::Callback)
    }

    #[cfg(feature = "crypt4gh")]
    pub(crate) fn for_each_verified_file_block<CallbackError>(
        &self,
        id: FileId,
        mut operation: impl FnMut(Zeroizing<Vec<u8>>) -> Result<(), CallbackError>,
    ) -> Result<(), ContentOperationError<CallbackError>> {
        self.require_content_available(id)
            .map_err(ContentOperationError::Core)?;
        let size = self
            .view
            .content_size(id)
            .map_err(ContentOperationError::Core)?;
        let plan = ReadRange::new(0..size, size)
            .and_then(|range| self.view.plan(id, range))
            .map_err(ContentOperationError::Core)?;
        for block in plan {
            let plaintext = block
                .and_then(|block| self.verified_block(&block))
                .map_err(ContentOperationError::Core)?;
            operation(plaintext).map_err(ContentOperationError::Callback)?;
        }
        Ok(())
    }

    pub(crate) fn require_content_available(&self, id: FileId) -> Result<(), PithosError> {
        self.view.require_content_available(id)
    }

    fn copy_plan<W: Write + ?Sized>(
        &self,
        plan: ReadPlan<'_>,
        sink: &mut W,
    ) -> Result<(), PithosError> {
        for block in plan {
            let block = block?;
            let plaintext = self.verified_block(&block)?;
            sink.write_all(&plaintext[block.output()])?;
        }
        Ok(())
    }

    /// Fetches one planned block with a single read and verifies it.
    fn verified_block(&self, block: &PlannedBlock) -> Result<Zeroizing<Vec<u8>>, PithosError> {
        let stored = match block.request() {
            BlockRequest::Local { offset, len } => read_source(&self.source, offset, len, "block")?,
            BlockRequest::External { location, len } => {
                let response = self.external.resolve(
                    self.external_access_policy.as_deref().ok_or(
                        PithosError::UnsupportedFeature(ArchiveFeature::ExternalStorage),
                    )?,
                    &location,
                    len,
                    self.view
                        .limits
                        .max_stored_block_bytes
                        .checked_add(4)
                        .ok_or_else(|| {
                            PithosError::ExternalBlockFraming("response policy overflow".into())
                        })?,
                )?;
                if response.len() as u64 != len {
                    return Err(PithosError::ExternalBlockFraming(
                        "response does not match expected size".into(),
                    ));
                }
                response
            }
        };
        self.view.decode_block(block, &Zeroizing::new(stored))
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

pub(super) fn archive_entry(
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

pub(super) fn classify_content_availability(
    index: &ArchiveIndex,
    external_supported: bool,
) -> Result<BTreeMap<FileId, ContentAvailability>, PithosError> {
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

pub(super) fn remaining_deserialization_limits(
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

pub(super) fn validate_directory_len(len: u64, limits: OpenLimits) -> Result<(), PithosError> {
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

pub(super) fn resolve_recipients(
    version: FormatVersion,
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
            // Each candidate is the grant's peer key, its recipient key, and its data.
            let candidates: Vec<(&[u8; 32], &[u8; 32], &RecipientData)> = if sender == &recipient {
                section
                    .recipients
                    .iter()
                    .map(|(recipient, section)| (recipient, recipient, &section.recipient_data))
                    .collect()
            } else {
                section
                    .recipients
                    .get(&recipient)
                    .map(|section| vec![(sender, &recipient, &section.recipient_data)])
                    .unwrap_or_default()
            };
            for (recipient_section, (peer, grant_recipient, data)) in
                candidates.into_iter().enumerate()
            {
                let shared = crypto::derive_shared(secret.as_bytes(), peer)?;
                let decrypted;
                let entries = match data {
                    RecipientData::Encrypted(bytes) => {
                        let nonce = crypto::sealed_nonce(bytes)?;
                        let shared = crypto::grant_wrapping_key(
                            version,
                            shared,
                            sender,
                            grant_recipient,
                            &nonce,
                        );
                        let plaintext = crypto::unwrap_recipient_list(&shared, bytes)?;
                        decrypted = crate::format::encryption::decode_decrypted_recipient_list(
                            &plaintext,
                            &decoded_limits,
                        )?;
                        &decrypted
                    }
                    // A plaintext list is read in place, so its keys are not copied.
                    RecipientData::Decrypted(entries) => entries,
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

pub(super) fn resolve_block_lists(
    directory: &mut Directory,
    access: &mut ResolvedAccess,
    remaining_block_references: &mut u64,
    limits: OpenLimits,
) -> Result<(), PithosError> {
    directory.files.try_for_each_mut(|id, file| {
        let file_id = FileId(id);
        match &mut file.block_data {
            BlockDataState::Decrypted(_) => {}
            BlockDataState::Pieces(pieces) => {
                if pieces
                    .iter()
                    .any(|piece| access.key(FileId(piece.key_id)).is_none())
                {
                    return Ok(());
                }
                let key_ids = pieces.iter().map(|piece| FileId(piece.key_id)).collect();
                let pieces = std::mem::take(pieces);
                // The room for every piece is reserved once, so the keys never move to a new
                // buffer. Each sealed piece and each plaintext is dropped after decoding.
                let capacity = pieces.iter().try_fold(0u64, |total, piece| {
                    total.checked_add(crate::format::file_entry::sealed_block_list_capacity(
                        piece.sealed.len(),
                    ) as u64)
                });
                let capacity = match capacity {
                    Some(capacity) if capacity <= *remaining_block_references => capacity,
                    actual => {
                        return Err(DeserializationError::LimitExceeded {
                            field: "block references",
                            limit: *remaining_block_references,
                            actual: actual.unwrap_or(u64::MAX),
                        }
                        .into());
                    }
                };
                let mut entries = Zeroizing::new(Vec::new());
                crate::format::primitives::reserve_secret(
                    &mut entries,
                    capacity as usize,
                    "block references",
                )?;
                for piece in pieces {
                    let key = access
                        .key(FileId(piece.key_id))
                        .expect("every piece key was checked above");
                    let mut decoded_limits = deserialization_limits(limits);
                    decoded_limits.max_block_references = *remaining_block_references;
                    let plaintext = crypto::open_file_block_list(key, piece.sealed)?;
                    crate::format::file_entry::append_decrypted_block_list(
                        &plaintext,
                        &decoded_limits,
                        remaining_block_references,
                        &mut entries,
                    )?;
                }
                crate::format::file_entry::validate_unique_block_references(&entries)?;
                access.insert_pieces(file_id, key_ids);
                file.block_data = BlockDataState::Decrypted(entries);
            }
            BlockDataState::Encrypted(bytes) => {
                let Some(file_key) = access.key(file_id) else {
                    return Ok(());
                };
                let mut decoded_limits = deserialization_limits(limits);
                decoded_limits.max_block_references = *remaining_block_references;
                let plaintext = crypto::open_file_block_list(file_key, std::mem::take(bytes))?;
                let entries = crate::format::file_entry::decode_decrypted_block_list_with_budget(
                    &plaintext,
                    &decoded_limits,
                    remaining_block_references,
                )?;
                file.block_data = BlockDataState::Decrypted(entries);
            }
        }
        Ok(())
    })
}

/// Checks the version 1.1 piece rules across the selected chain. Returns the largest piece
/// key id, which new file ids must stay above.
pub(super) fn validate_piece_keys(
    version: FormatVersion,
    raw: &[(Directory, Span)],
) -> Result<Option<u64>, PithosError> {
    let mut file_ids = HashSet::new();
    let mut piece_keys = HashSet::new();
    for (directory, _) in raw {
        for (id, _, file) in directory.files.iter() {
            file_ids.insert(id);
            if let BlockDataState::Pieces(pieces) = &file.block_data {
                if version == FormatVersion::V1_0 {
                    return Err(PithosError::UnsupportedBlockListPieces);
                }
                for piece in pieces {
                    if !piece_keys.insert(piece.key_id) {
                        return Err(PithosError::PieceKeyIdConflict(piece.key_id));
                    }
                }
            }
        }
    }
    if let Some(conflict) = piece_keys.iter().find(|key_id| file_ids.contains(*key_id)) {
        return Err(PithosError::PieceKeyIdConflict(*conflict));
    }
    Ok(piece_keys.into_iter().max())
}

/// Moves every decoded block list into `access`, so each recovered key is kept once.
pub(super) fn move_block_keys(
    directory: &mut Directory,
    access: &mut ResolvedAccess,
) -> Result<(), PithosError> {
    directory.files.try_for_each_mut(|id, file| {
        if let BlockDataState::Decrypted(entries) = &mut file.block_data {
            access.insert_block_keys(FileId(id), std::mem::take(entries));
        }
        Ok(())
    })
}

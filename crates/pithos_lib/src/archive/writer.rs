//! Streaming archive construction with a consuming publication boundary.

use crate::archive::path_validation::{
    validate_new_candidate_with_snapshot, validate_wire_hierarchy_complete,
    validate_wire_hierarchy_with_snapshot,
};
use crate::archive::validation::validate_relationships;
use crate::archive::{AppendSnapshot, ArchivePath, FileId, Span, segment_from_wire};
use crate::archive::{validate_new_candidate, validate_symlink_target};
use crate::block;
use crate::crypto::{FileKey, PrivateKey, PublicKey};
use crate::error::PithosError;
use crate::format::codec;
use crate::format::entries::WireEntries;
use crate::format::wire::{
    BlockDataState, BlockHeader, BlockIndexEntry, BlockLocation, EncryptionSection, FileEntry,
    FileHeader, FileType, ProcessingFlags, RecipientData, Reference,
};
use fastcdc::v2020::{Normalization, StreamCDC};
use indexmap::IndexMap;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use thiserror::Error;
use x25519_dalek::{PublicKey as LegacyPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Validated content-defined chunking parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CdcConfig {
    min_size: usize,
    avg_size: usize,
    max_size: usize,
}

impl CdcConfig {
    /// The characterized current FastCDC defaults, always using level-one normalization.
    pub const DEFAULT: Self = Self {
        min_size: fastcdc::v2020::MINIMUM_MAX,
        avg_size: fastcdc::v2020::AVERAGE_MAX,
        max_size: fastcdc::v2020::MAXIMUM_MAX,
    };

    pub fn new(min_size: usize, avg_size: usize, max_size: usize) -> Result<Self, PithosError> {
        if !(fastcdc::v2020::MINIMUM_MIN..=fastcdc::v2020::MINIMUM_MAX).contains(&min_size)
            || !(fastcdc::v2020::AVERAGE_MIN..=fastcdc::v2020::AVERAGE_MAX).contains(&avg_size)
            || !(fastcdc::v2020::MAXIMUM_MIN..=fastcdc::v2020::MAXIMUM_MAX).contains(&max_size)
            || min_size > avg_size
            || avg_size > max_size
        {
            return Err(PithosError::InvalidCdcConfig {
                min_size,
                avg_size,
                max_size,
            });
        }
        Ok(Self {
            min_size,
            avg_size,
            max_size,
        })
    }

    pub fn min_size(self) -> usize {
        self.min_size
    }
    pub fn avg_size(self) -> usize {
        self.avg_size
    }
    pub fn max_size(self) -> usize {
        self.max_size
    }
}

impl Default for CdcConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Per-block processing requested for a content entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessingOptions {
    encrypted: bool,
    compression_level: u8,
}

impl ProcessingOptions {
    pub(crate) const fn append_default() -> Self {
        Self {
            encrypted: true,
            compression_level: 2,
        }
    }

    pub fn new(encrypted: bool, compression_level: u8) -> Result<Self, PithosError> {
        if compression_level > 7 {
            return Err(PithosError::ReservedProcessingBits(compression_level));
        }
        Ok(Self {
            encrypted,
            compression_level,
        })
    }

    pub fn encrypted(self) -> bool {
        self.encrypted
    }
    pub fn compression_level(self) -> u8 {
        self.compression_level
    }

    fn flags(self) -> ProcessingFlags {
        ProcessingFlags::new(self.encrypted, Some(self.compression_level))
    }
}

impl Default for ProcessingOptions {
    fn default() -> Self {
        Self {
            encrypted: true,
            compression_level: 3,
        }
    }
}

/// Caller-supplied, host-independent metadata for an archive entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    pub created: u64,
    pub modified: u64,
    pub permissions: u32,
    pub references: Vec<EntryReference>,
}

impl EntryMetadata {
    pub fn new(created: u64, modified: u64, permissions: u32) -> Self {
        Self {
            created,
            modified,
            permissions,
            references: Vec::new(),
        }
    }

    pub fn with_references(mut self, references: Vec<EntryReference>) -> Self {
        self.references = references;
        self
    }
}

/// A validated reference to a previously staged entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryReference {
    pub target_file_id: u64,
    pub relationship: u64,
}

/// The identifier assigned after an entry delta has been committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrittenEntry {
    pub id: u64,
}

enum WriteMode {
    Base,
    Encrypted {
        sender: PrivateKey,
        recipients: Vec<PublicKey>,
    },
}

/// Creation options for a base or encrypted archive.
pub struct WriteOptions {
    mode: WriteMode,
    cdc: CdcConfig,
}

impl WriteOptions {
    pub fn new(sender: PrivateKey, recipients: Vec<PublicKey>) -> Self {
        Self {
            mode: WriteMode::Encrypted { sender, recipients },
            cdc: CdcConfig::default(),
        }
    }

    pub fn base() -> Self {
        Self {
            mode: WriteMode::Base,
            cdc: CdcConfig::default(),
        }
    }

    pub fn with_cdc(mut self, cdc: CdcConfig) -> Self {
        self.cdc = cdc;
        self
    }

    /// Check all creation metadata before taking ownership of an output sink.
    pub fn validate(&self) -> Result<(), PithosError> {
        if let WriteMode::Encrypted { recipients, .. } = &self.mode {
            if recipients.is_empty() {
                return Err(PithosError::WriterRequiresRecipient);
            }
            let mut unique_recipients = HashSet::with_capacity(recipients.len());
            if recipients
                .iter()
                .any(|recipient| !unique_recipients.insert(recipient))
            {
                return Err(PithosError::DuplicateRecipientKey);
            }
        }
        Ok(())
    }
}

/// A creation error that returns the non-published sink to its owner.
pub struct CreateError<W> {
    error: PithosError,
    sink: W,
}

impl<W> CreateError<W> {
    pub fn error(&self) -> &PithosError {
        &self.error
    }
    pub fn into_incomplete(self) -> W {
        self.sink
    }
    pub fn into_parts(self) -> (PithosError, W) {
        (self.error, self.sink)
    }
}

impl<W> std::fmt::Display for CreateError<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<W> std::fmt::Debug for CreateError<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CreateError")
            .field("error", &self.error)
            .field("sink", &"[REDACTED]")
            .finish()
    }
}

impl<W> std::error::Error for CreateError<W> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// A finalization error that returns the incomplete sink. It never denotes publication.
pub struct FinishError<W> {
    error: PithosError,
    sink: W,
}

impl<W> FinishError<W> {
    pub fn error(&self) -> &PithosError {
        &self.error
    }
    pub fn into_incomplete(self) -> W {
        self.sink
    }
    pub fn into_parts(self) -> (PithosError, W) {
        (self.error, self.sink)
    }
}

impl<W> std::fmt::Display for FinishError<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(formatter)
    }
}

impl<W> std::fmt::Debug for FinishError<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FinishError")
            .field("error", &self.error)
            .field("sink", &"[REDACTED]")
            .finish()
    }
}

impl<W> std::error::Error for FinishError<W> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[derive(Debug, Error)]
pub enum WriterError {
    #[error("writer is poisoned; recover only with into_incomplete")]
    Poisoned,
    #[error("{0}")]
    Pithos(
        #[from]
        #[source]
        PithosError,
    ),
}

/// A failed recovery attempt retains an open writer, which can only be dropped
/// rather than finalized. `into_incomplete` is intentionally poisoned-only.
pub struct IncompleteWriter<W: Write>(ArchiveWriter<W>);

impl<W: Write> std::fmt::Debug for IncompleteWriter<W> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("IncompleteWriter(..)")
    }
}

trait WriterRuntime {
    fn file_key(&mut self) -> Result<FileKey, PithosError>;
    fn block_nonce(&mut self) -> Result<[u8; 12], PithosError>;
    fn block_list_nonce(&mut self) -> Result<[u8; 12], PithosError>;
    fn recipient_list_nonce(&mut self) -> Result<[u8; 12], PithosError>;
    fn encode_block(
        &mut self,
        plaintext: &[u8],
        flags: ProcessingFlags,
        nonce: [u8; 12],
    ) -> Result<block::EncodedBlock, PithosError>;
    fn seal_block_list(
        &mut self,
        block_data: &mut BlockDataState,
        file_key: &FileKey,
        nonce: [u8; 12],
    ) -> Result<(), PithosError>;
    fn seal_recipient_list(
        &mut self,
        recipient_data: &mut RecipientData,
        shared_key: crate::crypto::SharedSecret,
        nonce: [u8; 12],
    ) -> Result<(), PithosError>;
}

struct ProductionRuntime;

impl WriterRuntime for ProductionRuntime {
    fn file_key(&mut self) -> Result<FileKey, PithosError> {
        Ok(FileKey::from_bytes(StaticSecret::random().to_bytes()))
    }

    fn block_nonce(&mut self) -> Result<[u8; 12], PithosError> {
        Ok(crate::crypto::random_nonce())
    }

    fn block_list_nonce(&mut self) -> Result<[u8; 12], PithosError> {
        Ok(crate::crypto::random_nonce())
    }

    fn recipient_list_nonce(&mut self) -> Result<[u8; 12], PithosError> {
        Ok(crate::crypto::random_nonce())
    }

    fn encode_block(
        &mut self,
        plaintext: &[u8],
        flags: ProcessingFlags,
        nonce: [u8; 12],
    ) -> Result<block::EncodedBlock, PithosError> {
        block::encode(plaintext, flags, nonce)
    }

    fn seal_block_list(
        &mut self,
        block_data: &mut BlockDataState,
        file_key: &FileKey,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        block_data.encrypt_with_nonce(file_key, nonce)
    }

    fn seal_recipient_list(
        &mut self,
        recipient_data: &mut RecipientData,
        shared_key: crate::crypto::SharedSecret,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        recipient_data.encrypt_with_secret_and_nonce(shared_key, nonce)
    }
}

struct CountingSink<W> {
    sink: W,
    offset: u64,
}

/// One fully prepared archive entry publication. It owns all data that may allocate
/// or fail before the live directory is touched.
struct EntryDelta {
    id: u64,
    path: ArchivePath,
    entry: FileEntry,
    descriptors: IndexMap<[u8; 32], BlockIndexEntry>,
    recipient_access: Option<(u64, FileKey)>,
}

trait Reservable {
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError>;
}

impl<T> Reservable for Vec<T> {
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        Vec::try_reserve(self, additional).map_err(|_| allocation_failed(field, additional))
    }
}

impl<T: zeroize::Zeroize> Reservable for Zeroizing<Vec<T>> {
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        self.try_reserve(additional)
            .map_err(|_| allocation_failed(field, additional))
    }
}

impl<T, S> Reservable for HashSet<T, S>
where
    T: Eq + std::hash::Hash,
    S: std::hash::BuildHasher,
{
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        HashSet::try_reserve(self, additional).map_err(|_| allocation_failed(field, additional))
    }
}

impl<K, V, S> Reservable for HashMap<K, V, S>
where
    K: Eq + std::hash::Hash,
    S: std::hash::BuildHasher,
{
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        HashMap::try_reserve(self, additional).map_err(|_| allocation_failed(field, additional))
    }
}

impl<K, V, S> Reservable for IndexMap<K, V, S>
where
    S: std::hash::BuildHasher,
{
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        IndexMap::try_reserve(self, additional).map_err(|_| allocation_failed(field, additional))
    }
}

fn reserve(
    collection: &mut impl Reservable,
    additional: usize,
    field: &'static str,
) -> Result<(), PithosError> {
    collection.reserve_capacity(additional, field)
}

fn allocation_failed(field: &'static str, size: usize) -> PithosError {
    PithosError::AllocationFailed {
        field,
        size: u64::try_from(size).unwrap_or(u64::MAX),
    }
}

fn append_block_reference(
    entry: &mut FileEntry,
    hash: [u8; 32],
    key: &crate::crypto::BlockKey,
) -> Result<(), PithosError> {
    let BlockDataState::Decrypted(references) = &mut entry.block_data else {
        return Err(PithosError::InvalidBlockDataState(
            "block data already/still encrypted".into(),
        ));
    };
    reserve(references, 1, "entry block references")?;
    references.push((hash, *key.expose_for_protocol()));
    Ok(())
}

impl<W> CountingSink<W> {
    fn into_inner(self) -> W {
        self.sink
    }
}

impl<W: Write> Write for CountingSink<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let accepted = self.sink.write(bytes)?;
        if accepted > bytes.len() {
            return Err(io::Error::other("sink accepted more bytes than requested"));
        }
        let accepted = u64::try_from(accepted)
            .map_err(|_| io::Error::other("archive output offset does not fit u64"))?;
        self.offset = self
            .offset
            .checked_add(accepted)
            .ok_or_else(|| io::Error::other("archive output offset overflow"))?;
        usize::try_from(accepted)
            .map_err(|_| io::Error::other("sink accepted byte count does not fit usize"))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }
}

/// A streaming archive writer. Dropping it leaves an intentionally incomplete sink.
pub struct ArchiveWriter<W: Write> {
    mode: ArchiveWriterMode,
    cdc: CdcConfig,
    sink: CountingSink<W>,
    directory: crate::format::wire::Directory,
    poisoned: bool,
    runtime: Box<dyn WriterRuntime>,
    append_snapshot: Option<AppendSnapshot>,
    append_next_id: Option<Option<u64>>,
    planned_ids: Option<HashSet<u64>>,
    granted_access_ids: Option<HashSet<u64>>,
}

enum ArchiveWriterMode {
    Base,
    Encrypted { sender: StaticSecret },
}

impl ArchiveWriterMode {
    fn is_base(&self) -> bool {
        matches!(self, Self::Base)
    }
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
struct MetadataSnapshot {
    files: usize,
    descriptors: usize,
    next_id: Option<u64>,
    recipient_records: usize,
}

impl<W: Write> ArchiveWriter<W> {
    /// Writes exactly one current-format header before returning an open writer.
    pub fn create(sink: W, options: WriteOptions) -> Result<Self, CreateError<W>> {
        if let Err(error) = options.validate() {
            return Err(CreateError { error, sink });
        }
        let WriteOptions { mode, cdc } = options;
        let (mode, encryption) = match mode {
            WriteMode::Base => (ArchiveWriterMode::Base, IndexMap::new()),
            WriteMode::Encrypted { sender, recipients } => {
                let sender = sender.into_dalek_static_secret();
                let recipients = recipients
                    .into_iter()
                    .map(PublicKey::into_dalek_public_key)
                    .collect::<Vec<_>>();
                let encryption = IndexMap::from_iter([(
                    LegacyPublicKey::from(&sender).to_bytes(),
                    EncryptionSection::new(&recipients),
                )]);
                (ArchiveWriterMode::Encrypted { sender }, encryption)
            }
        };
        let directory = crate::format::wire::Directory::new(None, WireEntries::new(), encryption);
        let mut sink = CountingSink { sink, offset: 0 };
        if let Err(error) = codec::encode_header(&FileHeader::default(), &mut sink) {
            return Err(CreateError {
                error: error.into(),
                sink: sink.into_inner(),
            });
        }
        Ok(Self {
            mode,
            cdc,
            sink,
            directory,
            poisoned: false,
            runtime: Box::new(ProductionRuntime),
            append_snapshot: None,
            append_next_id: None,
            planned_ids: None,
            granted_access_ids: None,
        })
    }

    /// Seeds a child directory for the direct appender.
    /// It intentionally writes no header and retains ancestor state only for
    /// validation and block reuse, never for child-directory serialization.
    pub(crate) fn append(
        sink: W,
        sender: PrivateKey,
        recipients: Vec<PublicKey>,
        cdc: CdcConfig,
        snapshot: AppendSnapshot,
    ) -> Result<Self, PithosError> {
        WriteOptions::new(sender.duplicate(), recipients.clone()).validate()?;
        let sender = sender.into_dalek_static_secret();
        let recipients = recipients
            .into_iter()
            .map(PublicKey::into_dalek_public_key)
            .collect::<Vec<_>>();
        let parent = snapshot.terminal_directory();
        let maximum_id = snapshot.maximum_id();
        let files = WireEntries::with_maximum_id(maximum_id.map_or(0, |id| id.0));
        let encryption = IndexMap::from_iter([(
            LegacyPublicKey::from(&sender).to_bytes(),
            EncryptionSection::new(&recipients),
        )]);
        let directory = crate::format::wire::Directory::new(
            Some((parent.start(), parent.len())),
            files,
            encryption,
        );
        Ok(Self {
            mode: ArchiveWriterMode::Encrypted { sender },
            cdc,
            sink: CountingSink {
                sink,
                offset: snapshot.archive_len(),
            },
            directory,
            poisoned: false,
            runtime: Box::new(ProductionRuntime),
            append_next_id: Some(maximum_id.map(|id| id.0.checked_add(1)).unwrap_or(Some(0))),
            append_snapshot: Some(snapshot),
            planned_ids: None,
            granted_access_ids: None,
        })
    }

    #[cfg(test)]
    fn with_test_runtime(
        sink: W,
        options: WriteOptions,
        runtime: Box<dyn WriterRuntime>,
        initial_offset: u64,
    ) -> Result<Self, CreateError<W>> {
        let mut writer = Self::create(sink, options)?;
        writer.runtime = runtime;
        writer.sink.offset = initial_offset;
        Ok(writer)
    }

    pub fn add_file<R: Read>(
        &mut self,
        path: ArchivePath,
        metadata: EntryMetadata,
        processing: ProcessingOptions,
        expected_size: Option<u64>,
        content: R,
    ) -> Result<WrittenEntry, WriterError> {
        self.add_content(
            FileType::Data,
            path,
            metadata,
            processing,
            expected_size,
            content,
        )
    }

    pub(crate) fn add_file_planned<R: Read>(
        &mut self,
        expected_id: u64,
        path: ArchivePath,
        metadata: EntryMetadata,
        processing: ProcessingOptions,
        expected_size: Option<u64>,
        content: R,
    ) -> Result<WrittenEntry, WriterError> {
        self.assert_planned_id(expected_id)?;
        self.add_file(path, metadata, processing, expected_size, content)
    }

    pub(crate) fn prepare_planned_ids(&mut self, ids: &[u64]) -> Result<(), WriterError> {
        let Some(Some(mut next)) = self.append_next_id else {
            return Err(PithosError::PlannedIdsRequireAppendWriter.into());
        };
        let mut planned = HashSet::with_capacity(ids.len());
        for (index, id) in ids.iter().enumerate() {
            if *id != next || !planned.insert(*id) {
                return Err(PithosError::DuplicateFileId(format!(
                    "planned file id {id} does not match append allocation"
                ))
                .into());
            }
            if index + 1 < ids.len() {
                next = next.checked_add(1).ok_or(PithosError::FileIdExhausted)?;
            }
        }
        self.planned_ids = Some(planned);
        Ok(())
    }

    pub fn add_metadata<R: Read>(
        &mut self,
        path: ArchivePath,
        metadata: EntryMetadata,
        processing: ProcessingOptions,
        expected_size: Option<u64>,
        content: R,
    ) -> Result<WrittenEntry, WriterError> {
        self.add_content(
            FileType::Metadata,
            path,
            metadata,
            processing,
            expected_size,
            content,
        )
    }

    pub fn add_directory(
        &mut self,
        path: ArchivePath,
        metadata: EntryMetadata,
    ) -> Result<WrittenEntry, WriterError> {
        self.ensure_open()?;
        let delta = self.stage_entry(FileType::Directory, path, metadata, 0, None)?;
        self.prepare_delta(&delta)?;
        Ok(self.commit_delta(delta))
    }

    pub(crate) fn add_directory_planned(
        &mut self,
        expected_id: u64,
        path: ArchivePath,
        metadata: EntryMetadata,
    ) -> Result<WrittenEntry, WriterError> {
        self.assert_planned_id(expected_id)?;
        self.add_directory(path, metadata)
    }

    pub fn add_symlink(
        &mut self,
        path: ArchivePath,
        metadata: EntryMetadata,
        target: impl Into<String>,
    ) -> Result<WrittenEntry, WriterError> {
        self.ensure_open()?;
        let target = target.into();
        validate_symlink_target(path.as_str(), &target)?;
        let delta = self.stage_entry(FileType::Symlink, path, metadata, 0, Some(target))?;
        self.prepare_delta(&delta)?;
        Ok(self.commit_delta(delta))
    }

    pub(crate) fn add_symlink_planned(
        &mut self,
        expected_id: u64,
        path: ArchivePath,
        metadata: EntryMetadata,
        target: impl Into<String>,
    ) -> Result<WrittenEntry, WriterError> {
        self.assert_planned_id(expected_id)?;
        self.add_symlink(path, metadata, target)
    }

    /// Adds recovered ancestor content keys to every recipient of an otherwise empty child.
    /// The snapshot retains the sole zeroizing key owner; plaintext is only borrowed while the
    /// transient recipient records are assembled for sealing during `finish`.
    pub(crate) fn grant_file_keys(&mut self, ids: &[FileId]) -> Result<(), PithosError> {
        self.ensure_open().map_err(|error| match error {
            WriterError::Pithos(error) => error,
            WriterError::Poisoned => PithosError::WriterPoisoned,
        })?;
        if ids.is_empty() {
            return Err(PithosError::GrantRequiresFileId);
        }
        if !self.directory.files.is_empty() || !self.directory.blocks.is_empty() {
            return Err(PithosError::GrantChildContainsContent);
        }
        let snapshot = self
            .append_snapshot
            .as_ref()
            .ok_or(PithosError::GrantRequiresAppendSnapshot)?;
        let mut granted_ids = HashSet::with_capacity(ids.len());
        for id in ids {
            if !granted_ids.insert(id.0) {
                return Err(PithosError::DuplicateRecipientFileId);
            }
            snapshot.with_file_key(*id, |_| ())?;
        }
        for section in self.directory.encryption.values_mut() {
            for recipient in section.recipients.values_mut() {
                let RecipientData::Decrypted(records) = &mut recipient.recipient_data else {
                    return Err(PithosError::WriterUnsealedRecipientList);
                };
                reserve(records, ids.len(), "recipient access records")?;
            }
        }
        let mut recipients = self
            .directory
            .encryption
            .values_mut()
            .flat_map(|section| section.recipients.values_mut())
            .collect::<Vec<_>>();
        for id in ids {
            snapshot.with_file_key(*id, |key| {
                let record_key = Zeroizing::new(*key.expose_for_protocol());
                for recipient in &mut recipients {
                    let RecipientData::Decrypted(records) = &mut recipient.recipient_data else {
                        unreachable!("recipient lists were validated before grant publication");
                    };
                    records.push((id.0, *record_key));
                }
            })?;
        }
        self.granted_access_ids = Some(granted_ids);
        Ok(())
    }

    fn add_content<R: Read>(
        &mut self,
        file_type: FileType,
        path: ArchivePath,
        metadata: EntryMetadata,
        processing: ProcessingOptions,
        expected_size: Option<u64>,
        content: R,
    ) -> Result<WrittenEntry, WriterError> {
        self.ensure_open()?;
        if self.mode.is_base() && (processing.encrypted() || processing.compression_level() != 0) {
            return Err(PithosError::BaseWriterRequiresPlainProcessing.into());
        }
        let mut delta = self.stage_entry(file_type, path, metadata, 0, None)?;
        let mut stream = StreamCDC::with_level(
            content,
            self.cdc.min_size,
            self.cdc.avg_size,
            self.cdc.max_size,
            Normalization::Level1,
        );
        let mut size = 0u64;
        let mut block_references = HashMap::new();
        for chunk in &mut stream {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(error) => return self.poison(error.into()),
            };
            let chunk_data = Zeroizing::new(chunk.data);
            size = match size.checked_add(chunk.length as u64) {
                Some(size) => size,
                None => return self.poison(PithosError::WriterSizeOverflow),
            };
            let nonce = match self.runtime.block_nonce() {
                Ok(nonce) => nonce,
                Err(error) => return self.poison(error),
            };
            let encoded = match self
                .runtime
                .encode_block(&chunk_data, processing.flags(), nonce)
            {
                Ok(encoded) => encoded,
                Err(error) => return self.poison(error),
            };
            let hash = encoded.hash;
            if let Err(error) = reserve(&mut block_references, 1, "block references") {
                return self.poison(error);
            }
            if block_references
                .insert(hash, *encoded.key.expose_for_protocol())
                .is_some_and(|existing| existing != *encoded.key.expose_for_protocol())
            {
                return self.poison(PithosError::DuplicateBlockReference);
            }
            if let Err(error) = append_block_reference(&mut delta.entry, hash, &encoded.key) {
                return self.poison(error);
            }
            if let Some(existing) = self.directory.blocks.get(&hash) {
                if existing.original_size != chunk.length as u64 {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk.length as u64,
                    });
                }
                continue;
            }
            if let Some(existing) = self
                .append_snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.descriptor(crate::archive::types::BlockHash(hash)))
            {
                if existing.original_size != chunk.length as u64 {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk.length as u64,
                    });
                }
                continue;
            }
            if let Some(existing) = delta.descriptors.get(&hash) {
                if existing.original_size != chunk.length as u64 {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk.length as u64,
                    });
                }
                continue;
            }
            let descriptor = BlockIndexEntry {
                offset: self.sink.offset,
                stored_size: match u64::try_from(encoded.stored.len()) {
                    Ok(size) => size,
                    Err(_) => return self.poison(PithosError::WriterSizeOverflow),
                },
                original_size: chunk.length as u64,
                flags: encoded.flags,
                location: BlockLocation::Local,
            };
            if let Err(error) = reserve(&mut delta.descriptors, 1, "new block descriptors") {
                return self.poison(error);
            }
            if let Err(error) = self.write_block(&encoded.stored) {
                return self.poison(error);
            }
            delta.descriptors.insert(hash, descriptor);
        }
        if expected_size.is_some_and(|expected| expected != size) {
            return self.poison(PithosError::WriterExpectedSizeMismatch {
                expected: expected_size.unwrap(),
                actual: size,
            });
        }
        delta.entry.file_size = size;
        if let Err(error) = self.validate_unsealed_content(&delta) {
            return self.poison(error);
        }
        if !self.mode.is_base() {
            let file_key = match self.runtime.file_key() {
                Ok(file_key) => file_key,
                Err(error) => return self.poison(error),
            };
            let nonce = match self.runtime.block_list_nonce() {
                Ok(nonce) => nonce,
                Err(error) => return self.poison(error),
            };
            if let Err(error) =
                self.runtime
                    .seal_block_list(&mut delta.entry.block_data, &file_key, nonce)
            {
                return self.poison(error);
            }
            delta.recipient_access = Some((delta.id, file_key));
        }
        // Block bytes may already be orphaned on failure, so preparation failures
        // poison while every live metadata collection remains unchanged.
        if let Err(error) = self.prepare_delta(&delta) {
            return self.poison(error);
        }
        Ok(self.commit_delta(delta))
    }

    fn entry(
        &self,
        file_type: FileType,
        metadata: EntryMetadata,
        size: u64,
        target: Option<String>,
    ) -> FileEntry {
        FileEntry {
            file_type,
            block_data: BlockDataState::Decrypted(Zeroizing::new(Vec::new())),
            created: metadata.created,
            modified: metadata.modified,
            file_size: size,
            permissions: metadata.permissions,
            references: metadata
                .references
                .into_iter()
                .map(|reference| Reference {
                    target_file_id: reference.target_file_id,
                    relationship: reference.relationship,
                })
                .collect(),
            symlink_target: target,
        }
    }

    fn validate_candidate(&self, path: &ArchivePath, entry: &FileEntry) -> Result<(), PithosError> {
        if let Some(snapshot) = &self.append_snapshot {
            snapshot.ensure_path_available(path)?;
            snapshot.ensure_candidate_successor(path, entry.file_type == FileType::Directory)?;
            validate_new_candidate_with_snapshot(
                &self.directory.files,
                path.as_str(),
                entry,
                snapshot,
            )?;
        } else {
            validate_new_candidate(&self.directory.files, path.as_str(), entry)?;
        }
        for reference in &entry.references {
            let child_has_relationship = self
                .directory
                .relations
                .iter()
                .any(|(id, _)| *id == reference.relationship);
            let ancestor_has_relationship = self
                .append_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.has_relationship(reference.relationship));
            if !child_has_relationship && !ancestor_has_relationship {
                return Err(PithosError::UnknownRelationshipId(reference.relationship));
            }
            let child_has_target = self
                .directory
                .get_file_by_id(reference.target_file_id)
                .is_some();
            let ancestor_has_target = self
                .append_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.entry(FileId(reference.target_file_id)).is_some());
            let planned_has_target = self
                .planned_ids
                .as_ref()
                .is_some_and(|ids| ids.contains(&reference.target_file_id));
            if !child_has_target && !ancestor_has_target && !planned_has_target {
                return Err(PithosError::MissingReferenceTarget(
                    reference.target_file_id,
                ));
            }
        }
        Ok(())
    }

    fn assert_planned_id(&self, expected_id: u64) -> Result<(), WriterError> {
        let Some(next_id) = self.append_next_id else {
            return Err(PithosError::PlannedIdsRequireAppendWriter.into());
        };
        match next_id {
            Some(actual) if actual == expected_id => Ok(()),
            Some(actual) => Err(PithosError::DuplicateFileId(format!(
                "planned file id {expected_id} does not match next append id {actual}"
            ))
            .into()),
            None => Err(PithosError::FileIdExhausted.into()),
        }
    }

    fn stage_entry(
        &self,
        file_type: FileType,
        path: ArchivePath,
        metadata: EntryMetadata,
        size: u64,
        target: Option<String>,
    ) -> Result<EntryDelta, WriterError> {
        let entry = self.entry(file_type, metadata, size, target);
        self.validate_candidate(&path, &entry)?;
        let id = match self.append_next_id {
            Some(Some(id)) => id,
            Some(None) => return Err(PithosError::FileIdExhausted.into()),
            None => self.directory.next_free_file_index()?,
        };
        if let Some(snapshot) = &self.append_snapshot {
            snapshot.ensure_id_available(FileId(id))?;
        }
        Ok(EntryDelta {
            id,
            path,
            entry,
            descriptors: IndexMap::new(),
            recipient_access: None,
        })
    }

    /// Validate every insertion and reserve every live allocation before publication.
    fn prepare_delta(&mut self, delta: &EntryDelta) -> Result<(), PithosError> {
        self.validate_candidate(&delta.path, &delta.entry)?;
        self.directory
            .files
            .prevalidate_insert(delta.id, delta.path.as_str())?;
        for (hash, descriptor) in &delta.descriptors {
            if let Some(existing) = self.directory.blocks.get(hash) {
                return Err(PithosError::BlockIndexConflict {
                    hash: *hash,
                    existing_original_size: existing.original_size,
                    new_original_size: descriptor.original_size,
                });
            }
        }
        self.directory.files.reserve_one()?;
        reserve(
            &mut self.directory.blocks,
            delta.descriptors.len(),
            "archive block descriptors",
        )?;
        if delta.recipient_access.is_some() {
            for section in self.directory.encryption.values_mut() {
                for recipient in section.recipients.values_mut() {
                    if let RecipientData::Decrypted(records) = &mut recipient.recipient_data {
                        reserve(records, 1, "recipient access records")?;
                    }
                }
            }
        }
        Ok(())
    }

    /// Verify the just-streamed plaintext block list before its keys are sealed.
    fn validate_unsealed_content(&self, delta: &EntryDelta) -> Result<(), PithosError> {
        let BlockDataState::Decrypted(references) = &delta.entry.block_data else {
            return Err(PithosError::WriterUnsealedBlockList);
        };
        let mut keys = HashMap::with_capacity(references.len());
        let actual = references.iter().try_fold(0u64, |total, (hash, key)| {
            if keys
                .insert(*hash, *key)
                .is_some_and(|existing| existing != *key)
            {
                return Err(PithosError::DuplicateBlockReference);
            }
            let descriptor_size = delta
                .descriptors
                .get(hash)
                .map(|descriptor| descriptor.original_size)
                .or_else(|| {
                    self.directory
                        .blocks
                        .get(hash)
                        .map(|descriptor| descriptor.original_size)
                })
                .or_else(|| {
                    self.append_snapshot
                        .as_ref()
                        .and_then(|snapshot| {
                            snapshot.descriptor(crate::archive::types::BlockHash(*hash))
                        })
                        .map(|descriptor| descriptor.original_size)
                })
                .ok_or(PithosError::MissingBlockDescriptor)?;
            total
                .checked_add(descriptor_size)
                .ok_or(PithosError::AccessibleFileSizeMismatch {
                    expected: delta.entry.file_size,
                    actual: u64::MAX,
                })
        })?;
        if actual != delta.entry.file_size {
            return Err(PithosError::AccessibleFileSizeMismatch {
                expected: delta.entry.file_size,
                actual,
            });
        }
        Ok(())
    }

    /// All capacity and collision checks happen in `prepare_delta`, making this
    /// publication allocation-free and infallible.
    fn commit_delta(&mut self, delta: EntryDelta) -> WrittenEntry {
        let id = delta.id;
        for (hash, descriptor) in delta.descriptors {
            debug_assert!(!self.directory.blocks.contains_key(&hash));
            self.directory.blocks.insert(hash, descriptor);
        }
        self.directory
            .files
            .insert_prepared(id, delta.path.as_str(), delta.entry);
        if let Some((id, access)) = delta.recipient_access {
            for section in self.directory.encryption.values_mut() {
                for recipient in section.recipients.values_mut() {
                    if let RecipientData::Decrypted(records) = &mut recipient.recipient_data {
                        records.push((id, *access.expose_for_protocol()));
                    }
                }
            }
        }
        if let Some(next_id) = &mut self.append_next_id {
            *next_id = id.checked_add(1);
        }
        WrittenEntry { id }
    }

    fn write_block(&mut self, bytes: &[u8]) -> Result<(), PithosError> {
        codec::encode_block_marker(&BlockHeader::default(), &mut self.sink)?;
        self.sink.write_all(bytes)?;
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), WriterError> {
        if self.poisoned {
            Err(WriterError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn poison<T>(&mut self, error: PithosError) -> Result<T, WriterError> {
        self.poisoned = true;
        Err(error.into())
    }

    #[cfg(test)]
    fn metadata_snapshot(&self) -> MetadataSnapshot {
        MetadataSnapshot {
            files: self.directory.files.len(),
            descriptors: self.directory.blocks.len(),
            next_id: self.directory.next_free_file_index().ok(),
            recipient_records: self
                .directory
                .encryption
                .values()
                .flat_map(|section| section.recipients.values())
                .map(|recipient| match &recipient.recipient_data {
                    RecipientData::Decrypted(records) => records.len(),
                    RecipientData::Encrypted(_) => 0,
                })
                .sum(),
        }
    }

    /// Recover the sink only after a poisoned operation. An open writer must be
    /// finalized or dropped; it cannot be relabeled as an incomplete recovery.
    pub fn into_incomplete(self) -> Result<W, Box<IncompleteWriter<W>>> {
        if self.poisoned {
            Ok(self.sink.into_inner())
        } else {
            Err(Box::new(IncompleteWriter(self)))
        }
    }

    /// Validate, write the one terminal directory, flush, and return the completed sink.
    pub fn finish(mut self) -> Result<W, FinishError<W>> {
        let result = (|| -> Result<(), PithosError> {
            if self.poisoned {
                return Err(PithosError::WriterPoisoned);
            }
            self.validate_entry_state()?;
            self.validate_required_access_records()?;
            self.seal_recipient_lists()?;
            self.validate_publishable()?;
            codec::update_directory_len(&mut self.directory)?;
            codec::update_directory_crc(&mut self.directory)?;
            if let Some(snapshot) = &self.append_snapshot {
                let span = Span::new(self.sink.offset, self.directory.dir_len)?;
                let child =
                    segment_from_wire(&self.directory, span, Some(snapshot.terminal_directory()))?;
                snapshot.validate_prospective_child(child)?;
            }
            codec::encode_directory(&self.directory, &mut self.sink)?;
            self.sink.flush()?;
            Ok(())
        })();
        match result {
            Ok(()) => Ok(self.sink.into_inner()),
            Err(error) => Err(FinishError {
                error,
                sink: self.sink.into_inner(),
            }),
        }
    }

    fn validate_publishable(&self) -> Result<(), PithosError> {
        self.validate_entry_state()?;
        validate_relationships(&self.directory)?;
        if self.mode.is_base() && !self.directory.encryption.is_empty() {
            return Err(PithosError::InvalidRecipientDataState(
                "base writer has an encryption map".into(),
            ));
        }
        if let Some(snapshot) = &self.append_snapshot {
            snapshot.validate_prospective_recipient_pairs(&self.directory.encryption)?;
            let relationships = self
                .directory
                .relations
                .iter()
                .map(|(id, name)| (*id, name.as_str()))
                .collect::<Vec<_>>();
            snapshot.validate_child_relationships(&relationships)?;
        }
        if !self.mode.is_base() {
            for section in self.directory.encryption.values() {
                for recipient in section.recipients.values() {
                    if matches!(recipient.recipient_data, RecipientData::Decrypted(_)) {
                        return Err(PithosError::WriterUnsealedRecipientList);
                    }
                }
            }
        }
        Ok(())
    }

    fn seal_recipient_lists(&mut self) -> Result<(), PithosError> {
        let ArchiveWriterMode::Encrypted { sender } = &self.mode else {
            return Ok(());
        };
        let sender_public = LegacyPublicKey::from(sender).to_bytes();
        let Some(section) = self.directory.encryption.get_mut(&sender_public) else {
            return Ok(());
        };
        for (recipient_key, recipient) in &mut section.recipients {
            let recipient_key = LegacyPublicKey::from(*recipient_key);
            let shared_key =
                crate::crypto::derive_shared(sender.as_bytes(), recipient_key.as_bytes())?;
            let nonce = self.runtime.recipient_list_nonce()?;
            self.runtime
                .seal_recipient_list(&mut recipient.recipient_data, shared_key, nonce)?;
        }
        Ok(())
    }

    fn validate_entry_state(&self) -> Result<(), PithosError> {
        for (_, _, entry) in self.directory.files.iter() {
            match entry.file_type {
                FileType::Data | FileType::Metadata => {
                    let valid = if self.mode.is_base() {
                        matches!(entry.block_data, BlockDataState::Decrypted(_))
                    } else {
                        matches!(entry.block_data, BlockDataState::Encrypted(_))
                    };
                    if !valid {
                        return Err(if self.mode.is_base() {
                            PithosError::InvalidBlockDataState(
                                "base content must have a decrypted block list".into(),
                            )
                        } else {
                            PithosError::WriterUnsealedBlockList
                        });
                    }
                }
                FileType::Directory | FileType::Symlink => match &entry.block_data {
                    BlockDataState::Decrypted(entries) if entries.is_empty() => {}
                    _ => return Err(PithosError::WriterNoContentHasBlockMaterial),
                },
            }
        }
        for (_, path, entry) in self.directory.files.iter() {
            crate::archive::path_validation::validate_entry(path, entry)?;
        }
        if let Some(snapshot) = &self.append_snapshot {
            validate_wire_hierarchy_with_snapshot(&self.directory.files, snapshot)?;
        } else {
            validate_wire_hierarchy_complete(&self.directory.files)?;
        }
        self.directory
            .validate_references_and_accessible_blocks_with(
                |id| {
                    self.directory.get_file_by_id(id).is_some()
                        || self
                            .append_snapshot
                            .as_ref()
                            .is_some_and(|snapshot| snapshot.entry(FileId(id)).is_some())
                },
                |relationship| {
                    self.append_snapshot
                        .as_ref()
                        .is_some_and(|snapshot| snapshot.has_relationship(relationship))
                },
                |hash| {
                    self.directory
                        .blocks
                        .get(&hash)
                        .map(|descriptor| descriptor.original_size)
                        .or_else(|| {
                            self.append_snapshot
                                .as_ref()
                                .and_then(|snapshot| {
                                    snapshot.descriptor(crate::archive::types::BlockHash(hash))
                                })
                                .map(|descriptor| descriptor.original_size)
                        })
                },
            )?;
        Ok(())
    }

    fn validate_required_access_records(&self) -> Result<(), PithosError> {
        if self.mode.is_base() {
            return if self.directory.encryption.is_empty() {
                Ok(())
            } else {
                Err(PithosError::InvalidRecipientDataState(
                    "base writer has recipient access records".into(),
                ))
            };
        }
        let mut content_ids = self
            .directory
            .files
            .iter()
            .filter_map(|(id, _, entry)| {
                matches!(entry.file_type, FileType::Data | FileType::Metadata).then_some(id)
            })
            .collect::<HashSet<_>>();
        if let Some(granted_ids) = &self.granted_access_ids {
            content_ids.extend(granted_ids);
        }
        for section in self.directory.encryption.values() {
            for recipient in section.recipients.values() {
                let RecipientData::Decrypted(records) = &recipient.recipient_data else {
                    return Err(PithosError::WriterUnsealedRecipientList);
                };
                let ids = records.iter().map(|(id, _)| *id).collect::<HashSet<_>>();
                if ids.len() != records.len() || ids != content_ids {
                    return Err(PithosError::WriterUnsealedRecipientList);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{AccessKeys, Archive, OpenOptions};
    use crate::crypto::PrivateKey;
    use crate::format::limits::DeserializationLimits;
    use crate::source::MemorySource;
    use std::io::Cursor;
    use std::sync::Arc;

    #[derive(Clone, Copy, Eq, PartialEq)]
    enum RuntimeOperation {
        FileKey,
        BlockNonce,
        BlockEncoding,
        BlockListNonce,
        BlockListSealing,
        RecipientListNonce,
        RecipientListSealing,
    }

    impl RuntimeOperation {
        const fn index(self) -> usize {
            match self {
                Self::FileKey => 0,
                Self::BlockNonce => 1,
                Self::BlockEncoding => 2,
                Self::BlockListNonce => 3,
                Self::BlockListSealing => 4,
                Self::RecipientListNonce => 5,
                Self::RecipientListSealing => 6,
            }
        }
    }

    struct TestRuntime {
        file_key: [u8; 32],
        failure: Option<(RuntimeOperation, usize)>,
        calls: [usize; 7],
    }

    impl TestRuntime {
        fn new(failure: Option<(RuntimeOperation, usize)>) -> Self {
            Self {
                file_key: [8; 32],
                failure,
                calls: [0; 7],
            }
        }

        fn operation(&mut self, operation: RuntimeOperation) -> Result<usize, PithosError> {
            let index = operation.index();
            let call = self.calls[index];
            self.calls[index] += 1;
            if self.failure == Some((operation, call)) {
                return Err(PithosError::Io(io::Error::other(
                    "writer runtime failure injected for testing",
                )));
            }
            Ok(call)
        }

        fn nonce(&mut self, operation: RuntimeOperation) -> Result<[u8; 12], PithosError> {
            let call = self.operation(operation)?;
            let mut nonce = [operation.index() as u8; 12];
            nonce[11] = u8::try_from(call).unwrap();
            Ok(nonce)
        }
    }

    impl WriterRuntime for TestRuntime {
        fn file_key(&mut self) -> Result<FileKey, PithosError> {
            self.operation(RuntimeOperation::FileKey)?;
            Ok(FileKey::from_bytes(self.file_key))
        }

        fn block_nonce(&mut self) -> Result<[u8; 12], PithosError> {
            self.nonce(RuntimeOperation::BlockNonce)
        }

        fn block_list_nonce(&mut self) -> Result<[u8; 12], PithosError> {
            self.nonce(RuntimeOperation::BlockListNonce)
        }

        fn recipient_list_nonce(&mut self) -> Result<[u8; 12], PithosError> {
            self.nonce(RuntimeOperation::RecipientListNonce)
        }

        fn encode_block(
            &mut self,
            plaintext: &[u8],
            flags: ProcessingFlags,
            nonce: [u8; 12],
        ) -> Result<block::EncodedBlock, PithosError> {
            self.operation(RuntimeOperation::BlockEncoding)?;
            block::encode(plaintext, flags, nonce)
        }

        fn seal_block_list(
            &mut self,
            block_data: &mut BlockDataState,
            file_key: &FileKey,
            nonce: [u8; 12],
        ) -> Result<(), PithosError> {
            self.operation(RuntimeOperation::BlockListSealing)?;
            block_data.encrypt_with_nonce(file_key, nonce)
        }

        fn seal_recipient_list(
            &mut self,
            recipient_data: &mut RecipientData,
            shared_key: crate::crypto::SharedSecret,
            nonce: [u8; 12],
        ) -> Result<(), PithosError> {
            self.operation(RuntimeOperation::RecipientListSealing)?;
            recipient_data.encrypt_with_secret_and_nonce(shared_key, nonce)
        }
    }

    fn options() -> WriteOptions {
        let sender = PrivateKey::generate();
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
    }

    fn deterministic_options() -> WriteOptions {
        let sender = PrivateKey::from_dalek_static_secret(&StaticSecret::from([3; 32]));
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
    }

    fn content_writer(failure: Option<(RuntimeOperation, usize)>) -> ArchiveWriter<Vec<u8>> {
        ArchiveWriter::with_test_runtime(
            Vec::new(),
            deterministic_options().with_cdc(CdcConfig::new(64, 256, 1024).unwrap()),
            Box::new(TestRuntime::new(failure)),
            0,
        )
        .unwrap()
    }

    fn add_test_content(writer: &mut ArchiveWriter<Vec<u8>>) -> Result<WrittenEntry, WriterError> {
        let mut state = 1u32;
        let content = (0..4096)
            .map(|_| {
                state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (state >> 24) as u8
            })
            .collect::<Vec<_>>();
        writer.add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            None,
            Cursor::new(content),
        )
    }

    #[test]
    fn injected_transform_failure_poison_preserves_live_directory() {
        let mut writer = ArchiveWriter::with_test_runtime(
            Vec::new(),
            options(),
            Box::new(TestRuntime::new(Some((RuntimeOperation::BlockEncoding, 0)))),
            0,
        )
        .unwrap();
        assert!(
            writer
                .add_file(
                    ArchivePath::new("data").unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    ProcessingOptions::default(),
                    None,
                    Cursor::new(b"content"),
                )
                .is_err()
        );
        assert_eq!(writer.metadata_snapshot().files, 0);
        assert_eq!(writer.metadata_snapshot().descriptors, 0);
        assert!(writer.into_incomplete().is_ok());
    }

    #[test]
    fn selected_content_runtime_failures_poison_without_publishing_metadata() {
        for failure in [
            (RuntimeOperation::BlockNonce, 0),
            (RuntimeOperation::BlockEncoding, 1),
            (RuntimeOperation::FileKey, 0),
            (RuntimeOperation::BlockListNonce, 0),
            (RuntimeOperation::BlockListSealing, 0),
        ] {
            let mut writer = content_writer(Some(failure));
            let before = writer.metadata_snapshot();
            assert!(add_test_content(&mut writer).is_err());
            assert_eq!(writer.metadata_snapshot(), before);
            assert!(writer.poisoned);
            assert!(matches!(
                writer.add_directory(
                    ArchivePath::new("later").unwrap(),
                    EntryMetadata::new(0, 0, 0o755),
                ),
                Err(WriterError::Poisoned)
            ));
            assert!(writer.into_incomplete().is_ok());
        }
    }

    #[test]
    fn recipient_runtime_failures_return_an_incomplete_sink() {
        for failure in [
            (RuntimeOperation::RecipientListNonce, 0),
            (RuntimeOperation::RecipientListSealing, 0),
        ] {
            let mut writer = content_writer(Some(failure));
            add_test_content(&mut writer).unwrap();
            let error = writer.finish().unwrap_err();
            assert!(matches!(error.error(), PithosError::Io(_)));
            let sink = error.into_incomplete();
            assert_eq!(&sink[..4], b"PITH");
            assert!(!sink.windows(8).any(|window| window == b"PITHOSDR"));
        }
    }

    #[test]
    fn deterministic_runtime_produces_identical_complete_archives() {
        // This is the executable deterministic-writer vector; it replaces controlled-vectors.toml.
        fn write() -> Vec<u8> {
            let mut writer = content_writer(None);
            add_test_content(&mut writer).unwrap();
            writer.finish().unwrap()
        }

        let archive = write();
        assert_eq!(
            blake3::hash(&archive).to_hex().as_str(),
            "ed87c4bc6481475e5d1a2af8906b75728231c451e1db93fca3aa4318efcdbf49"
        );
        assert_eq!(&archive[..6], b"PITH\x01\x00");
        assert_eq!(
            archive
                .windows(8)
                .filter(|window| *window == b"PITHOSDR")
                .count(),
            1
        );
        assert_eq!(archive, write());
    }

    #[test]
    fn invalid_transient_states_cannot_be_published() {
        let mut writer = content_writer(None);
        add_test_content(&mut writer).unwrap();
        writer
            .directory
            .files
            .try_for_each_mut(|_, entry| {
                entry.block_data = BlockDataState::Decrypted(Zeroizing::new(Vec::new()));
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(
            writer.validate_publishable(),
            Err(PithosError::WriterUnsealedBlockList)
        ));

        let mut writer = content_writer(None);
        writer
            .add_directory(
                ArchivePath::new("directory").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        writer
            .directory
            .files
            .try_for_each_mut(|_, entry| {
                entry.block_data = BlockDataState::Encrypted(vec![1]);
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(matches!(
            writer.validate_publishable(),
            Err(PithosError::WriterNoContentHasBlockMaterial)
        ));

        let mut writer = content_writer(None);
        add_test_content(&mut writer).unwrap();
        let recipient = writer
            .directory
            .encryption
            .values_mut()
            .next()
            .unwrap()
            .recipients
            .values_mut()
            .next()
            .unwrap();
        recipient.recipient_data = RecipientData::Decrypted(Zeroizing::new(Vec::new()));
        assert!(matches!(
            writer.validate_publishable(),
            Err(PithosError::WriterUnsealedRecipientList)
        ));
    }

    #[test]
    fn writer_publication_revalidates_entry_and_relationship_semantics() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        let before = writer.metadata_snapshot();
        assert!(
            writer
                .add_directory(
                    ArchivePath::new("invalid-permissions").unwrap(),
                    EntryMetadata::new(0, 0, 0o10000),
                )
                .is_err()
        );
        assert_eq!(writer.metadata_snapshot(), before);

        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        writer
            .add_directory(
                ArchivePath::new("directory").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        writer
            .directory
            .files
            .try_for_each_mut(|_, entry| {
                entry.file_size = 1;
                Ok::<_, ()>(())
            })
            .unwrap();
        assert!(writer.finish().is_err());

        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        writer.directory.relations[0].1 = "describes".into();
        assert!(writer.finish().is_err());
    }

    #[test]
    fn writer_publication_revalidates_stored_hierarchy_order() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        let child = writer.entry(
            FileType::Directory,
            EntryMetadata::new(0, 0, 0o755),
            0,
            None,
        );
        let parent = writer.entry(
            FileType::Directory,
            EntryMetadata::new(0, 0, 0o755),
            0,
            None,
        );
        writer
            .directory
            .files
            .insert(0, "parent/child", child)
            .unwrap();
        writer.directory.files.insert(1, "parent", parent).unwrap();
        assert!(writer.finish().is_err());
    }

    #[test]
    fn append_writer_accepts_an_inherited_directory_ancestor() {
        let sender = PrivateKey::generate();
        let mut parent = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
        )
        .unwrap();
        parent
            .add_directory(
                ArchivePath::new("parent").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        let mut bytes = parent.finish().unwrap();
        let snapshot = Archive::open(
            MemorySource::new(Arc::<[u8]>::from(bytes.clone())),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
        )
        .unwrap()
        .into_append_snapshot();
        let mut child = ArchiveWriter::append(
            Vec::new(),
            PrivateKey::generate(),
            vec![sender.public_key()],
            CdcConfig::default(),
            snapshot,
        )
        .unwrap();
        child
            .add_file(
                ArchivePath::new("parent/child").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(0),
                Cursor::new([]),
            )
            .unwrap();
        bytes.extend(child.finish().unwrap());
        let archive = Archive::open(
            MemorySource::new(Arc::<[u8]>::from(bytes)),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
        )
        .unwrap();
        assert!(archive.entries().any(|entry| entry.path == "parent/child"));
    }

    #[test]
    fn failed_content_delta_preserves_all_live_metadata_and_next_id() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        let before = writer.metadata_snapshot();
        assert!(matches!(
            writer.add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(99),
                Cursor::new(b"actual"),
            ),
            Err(WriterError::Pithos(
                PithosError::WriterExpectedSizeMismatch { .. }
            ))
        ));
        assert_eq!(writer.metadata_snapshot(), before);
        assert!(writer.poisoned);
    }

    #[test]
    fn directory_and_symlink_validation_failures_preserve_live_metadata() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        writer
            .add_directory(
                ArchivePath::new("parent").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        let before = writer.metadata_snapshot();
        assert!(
            writer
                .add_directory(
                    ArchivePath::new("parent").unwrap(),
                    EntryMetadata::new(0, 0, 0o755),
                )
                .is_err()
        );
        assert_eq!(writer.metadata_snapshot(), before);
        assert!(
            writer
                .add_symlink(
                    ArchivePath::new("parent/link").unwrap(),
                    EntryMetadata::new(0, 0, 0o777),
                    "../../outside",
                )
                .is_err()
        );
        assert_eq!(writer.metadata_snapshot(), before);
        assert!(!writer.poisoned);
    }

    #[test]
    fn repeated_compatible_descriptor_keeps_the_earliest_descriptor() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        for path in ["first", "second"] {
            writer
                .add_file(
                    ArchivePath::new(path).unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    ProcessingOptions::new(false, 0).unwrap(),
                    Some(4),
                    Cursor::new(b"same"),
                )
                .unwrap();
        }
        assert_eq!(writer.directory.blocks.len(), 1);
        let descriptor = writer.directory.blocks.values().next().unwrap();
        assert_eq!(descriptor.offset, 6);
        assert_eq!(descriptor.original_size, 4);
    }

    #[test]
    fn compression_profiles_round_trip_with_current_flags_and_empty_content() {
        let mut state = 0x243f_6a88_u32;
        let incompressible = (0..16 * 1024)
            .map(|index| {
                state = state
                    .wrapping_mul(1_664_525)
                    .wrapping_add(1_013_904_223)
                    .rotate_left((index % 31) as u32);
                (state ^ index as u32).to_le_bytes()[index % 4]
            })
            .collect::<Vec<_>>();

        for payload in [vec![b'A'; 16 * 1024], incompressible] {
            for compression in 0..=7 {
                for encrypted in [false, true] {
                    let recipient = PrivateKey::generate();
                    let mut writer = ArchiveWriter::create(
                        Vec::new(),
                        WriteOptions::new(PrivateKey::generate(), vec![recipient.public_key()]),
                    )
                    .unwrap();
                    writer
                        .add_file(
                            ArchivePath::new("data").unwrap(),
                            EntryMetadata::new(0, 0, 0o644),
                            ProcessingOptions::new(encrypted, compression).unwrap(),
                            Some(payload.len() as u64),
                            Cursor::new(&payload),
                        )
                        .unwrap();
                    for descriptor in writer.directory.blocks.values() {
                        assert_eq!(descriptor.flags.is_encrypted(), encrypted);
                        let level = descriptor.flags.get_compression_level();
                        assert!(level == 0 || level == compression);
                    }
                    let bytes = writer.finish().unwrap();
                    let archive = Archive::open(
                        MemorySource::new(bytes),
                        OpenOptions::default()
                            .with_access_keys(AccessKeys::new().with_key(recipient)),
                    )
                    .unwrap();
                    let mut copied = Vec::new();
                    archive.copy_to("data", &mut copied).unwrap();
                    assert_eq!(copied, payload);
                }
            }
        }

        let recipient = PrivateKey::generate();
        let mut writer = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(PrivateKey::generate(), vec![recipient.public_key()]),
        )
        .unwrap();
        writer
            .add_file(
                ArchivePath::new("empty").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(0),
                Cursor::new([]),
            )
            .unwrap();
        assert!(writer.directory.blocks.is_empty());
        let bytes = writer.finish().unwrap();
        let archive = Archive::open(
            MemorySource::new(bytes),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(recipient)),
        )
        .unwrap();
        let mut copied = Vec::new();
        archive.copy_to("empty", &mut copied).unwrap();
        assert!(copied.is_empty());
    }

    #[test]
    fn counter_overflow_is_not_saturated() {
        let mut writer = ArchiveWriter::with_test_runtime(
            Vec::new(),
            options(),
            Box::new(TestRuntime::new(None)),
            u64::MAX,
        )
        .unwrap();
        assert!(
            writer
                .add_file(
                    ArchivePath::new("data").unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    ProcessingOptions::new(false, 0).unwrap(),
                    None,
                    Cursor::new(b"content"),
                )
                .is_err()
        );
        assert!(writer.poisoned);
        assert_eq!(writer.directory.files.iter().count(), 0);
        assert!(writer.into_incomplete().is_ok());
    }

    #[test]
    fn file_id_exhaustion_does_not_mutate_or_poison_before_streaming() {
        let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
        writer.directory.files = WireEntries::with_maximum_id(u64::MAX);
        assert!(matches!(
            writer.add_directory(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            ),
            Err(WriterError::Pithos(PithosError::FileIdExhausted))
        ));
        assert!(!writer.poisoned);
        assert_eq!(writer.directory.files.iter().count(), 0);
    }

    #[test]
    fn grant_child_is_metadata_only_and_seals_selected_recovered_keys() {
        let sender = PrivateKey::generate();
        let recipient = PrivateKey::generate();
        let mut writer = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
        )
        .unwrap();
        for path in ["first", "second"] {
            writer
                .add_file(
                    ArchivePath::new(path).unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    ProcessingOptions::new(true, 0).unwrap(),
                    None,
                    Cursor::new(path.as_bytes()),
                )
                .unwrap();
        }
        let prefix = writer.finish().unwrap();
        let snapshot = Archive::open(
            MemorySource::new(Arc::<[u8]>::from(prefix.clone())),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
        )
        .unwrap()
        .into_append_snapshot();
        let parent = snapshot.terminal_directory();
        let mut child = ArchiveWriter::append(
            Vec::new(),
            sender,
            vec![recipient.public_key()],
            CdcConfig::default(),
            snapshot,
        )
        .unwrap();
        child.grant_file_keys(&[FileId(0), FileId(1)]).unwrap();
        assert!(child.directory.files.is_empty());
        assert!(child.directory.blocks.is_empty());
        assert_eq!(
            child.directory.parent_directory_offset,
            Some((parent.start(), parent.len()))
        );
        let transient_recipient_data = &child
            .directory
            .encryption
            .values()
            .next()
            .unwrap()
            .recipients
            .values()
            .next()
            .unwrap()
            .recipient_data;
        assert!(matches!(
            transient_recipient_data,
            RecipientData::Decrypted(records) if records.iter().map(|(id, _)| *id).eq([0, 1])
        ));

        let bytes = child.finish().unwrap();
        let directory =
            codec::decode_directory(&mut Cursor::new(&bytes), &DeserializationLimits::default())
                .unwrap();
        assert_eq!(directory.files.len(), 0);
        assert_eq!(directory.blocks.len(), 0);
        assert_eq!(directory.encryption.len(), 1);
        let sealed_recipient_data = &directory
            .encryption
            .values()
            .next()
            .unwrap()
            .recipients
            .values()
            .next()
            .unwrap()
            .recipient_data;
        assert!(matches!(sealed_recipient_data, RecipientData::Encrypted(_)));
    }

    #[test]
    fn planned_append_ids_reject_mismatches_before_content_io_and_allow_forward_references() {
        struct PanicRead;
        impl Read for PanicRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                panic!("planned ID mismatch read content")
            }
        }

        let sender = PrivateKey::generate();
        let recipient = sender.public_key();
        let mut parent = ArchiveWriter::create(
            Vec::new(),
            WriteOptions::new(sender.duplicate(), vec![recipient]),
        )
        .unwrap();
        parent
            .add_file(
                ArchivePath::new("ancestor").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(0),
                Cursor::new([]),
            )
            .unwrap();
        let snapshot = Archive::open(
            MemorySource::new(Arc::<[u8]>::from(parent.finish().unwrap())),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
        )
        .unwrap()
        .into_append_snapshot();
        let mut child = ArchiveWriter::append(
            Vec::new(),
            PrivateKey::generate(),
            vec![recipient],
            CdcConfig::default(),
            snapshot,
        )
        .unwrap();
        child.prepare_planned_ids(&[1, 2]).unwrap();
        assert!(matches!(
            child.add_file_planned(
                2,
                ArchivePath::new("never-read").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                None,
                PanicRead,
            ),
            Err(WriterError::Pithos(PithosError::DuplicateFileId(_)))
        ));
        child
            .add_file_planned(
                1,
                ArchivePath::new("first").unwrap(),
                EntryMetadata::new(0, 0, 0o644).with_references(vec![EntryReference {
                    target_file_id: 2,
                    relationship: 0,
                }]),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(0),
                Cursor::new([]),
            )
            .unwrap();
        child
            .add_file_planned(
                2,
                ArchivePath::new("second").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(0),
                Cursor::new([]),
            )
            .unwrap();
        assert!(child.finish().is_ok());
    }

    #[test]
    fn planned_append_ids_allow_u64_max_only_as_the_final_id() {
        let mut writer = content_writer(None);
        writer.append_next_id = Some(Some(u64::MAX));

        writer.prepare_planned_ids(&[u64::MAX]).unwrap();
        assert!(matches!(
            writer.prepare_planned_ids(&[u64::MAX, 0]),
            Err(WriterError::Pithos(PithosError::FileIdExhausted))
        ));
    }
}

//! Streaming archive construction with a consuming publication boundary.

use crate::archive::path_validation::{
    validate_directory_entry_hierarchy_complete, validate_directory_entry_hierarchy_with_snapshot,
    validate_new_candidate_with_snapshot,
};
use crate::archive::reader::DEFAULT_MAX_DECODED_BLOCK_BYTES;
use crate::archive::types::Processing;
use crate::archive::validation::validate_relationships;
use crate::archive::{AppendSnapshot, ArchivePath, FileId, Span, validated_segment_from_directory};
use crate::archive::{validate_new_candidate, validate_symlink_target};
use crate::block;
use crate::crypto::{FileKey, PrivateKey, PublicKey};
use crate::error::PithosError;
use crate::format::block::{BlockHeader, BlockIndexEntry, BlockLocation, ProcessingFlags};
use crate::format::directory::{Directory, DirectoryEntries};
use crate::format::encryption::{EncryptionSection, RecipientData};
use crate::format::error::SerializationError;
use crate::format::file_entry::{BlockDataState, FileEntry, FileType, Reference};
use crate::format::header::FormatVersion;
use crate::format::{directory, header};
use fastcdc::v2020::{FastCDC, Normalization};
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

    /// The length of the first FastCDC block of `data`, with level-one normalization.
    pub(crate) fn first_cut(self, data: &[u8]) -> usize {
        let (min, avg, max) = (self.min_size, self.avg_size, self.max_size);
        FastCDC::with_level(data, min, avg, max, Normalization::Level1)
            .cut(0, data.len())
            .1
    }
}

impl Default for CdcConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// How streamed content is split into blocks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Chunking {
    /// Blocks of exactly this many bytes. Only the last block of a file may be shorter.
    /// The size must be between 1 byte and the default reader limit for one decoded block.
    Fixed(usize),
    /// FastCDC boundaries chosen from the content, so shifted content can still deduplicate.
    ContentDefined(CdcConfig),
}

impl Chunking {
    /// The default fixed block size of 4 MiB.
    pub const DEFAULT_BLOCK_SIZE: usize = 4 * 1024 * 1024;

    pub(crate) fn validate(self) -> Result<(), PithosError> {
        match self {
            Self::Fixed(size) => validate_block_size(size),
            Self::ContentDefined(_) => Ok(()),
        }
    }
}

impl Default for Chunking {
    fn default() -> Self {
        Self::Fixed(Self::DEFAULT_BLOCK_SIZE)
    }
}

pub(crate) fn validate_block_size(size: usize) -> Result<(), PithosError> {
    if size == 0 || size as u64 > DEFAULT_MAX_DECODED_BLOCK_BYTES {
        return Err(PithosError::InvalidBlockSize(size));
    }
    Ok(())
}

/// Splits streamed content into block plaintexts.
enum Chunker<R: Read> {
    Fixed {
        content: R,
        size: usize,
        block: Zeroizing<Vec<u8>>,
    },
    ContentDefined {
        content: R,
        cdc: CdcConfig,
        buffer: Zeroizing<Vec<u8>>,
        cut: usize,
        ended: bool,
    },
}

impl<R: Read> Chunker<R> {
    fn new(content: R, chunking: Chunking) -> Self {
        match chunking {
            Chunking::Fixed(size) => Self::Fixed {
                content,
                size,
                block: Zeroizing::new(Vec::new()),
            },
            Chunking::ContentDefined(cdc) => Self::ContentDefined {
                content,
                cdc,
                buffer: Zeroizing::new(Vec::new()),
                cut: 0,
                ended: false,
            },
        }
    }

    /// Returns the next block, or `None` at the end of the content.
    fn next_block(&mut self) -> Result<Option<&[u8]>, PithosError> {
        match self {
            Self::Fixed {
                content,
                size,
                block,
            } => {
                // Reserving the whole block once keeps plaintext from being copied on growth.
                block.clear();
                block.reserve_exact(*size);
                content.by_ref().take(*size as u64).read_to_end(block)?;
                Ok((!block.is_empty()).then_some(block.as_slice()))
            }
            Self::ContentDefined {
                content,
                cdc,
                buffer,
                cut,
                ended,
            } => {
                // Like `StreamCDC`, this cuts only with a full buffer or at the end of the content.
                buffer.drain(..std::mem::take(cut));
                if !*ended {
                    let missing = cdc.max_size - buffer.len();
                    buffer.reserve_exact(missing);
                    content.by_ref().take(missing as u64).read_to_end(buffer)?;
                    // A short fill means a read returned 0. Like `StreamCDC`, it is the end.
                    *ended = buffer.len() < cdc.max_size;
                }
                if buffer.is_empty() {
                    return Ok(None);
                }
                *cut = cdc.first_cut(buffer);
                Ok(Some(&buffer[..*cut]))
            }
        }
    }
}

/// How the key of each encrypted block is chosen.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BlockKeyMode {
    /// The key is derived from the block plaintext, so equal blocks are stored once.
    #[default]
    ContentDerived,
    /// Every stored block gets a fresh random key and a keyed block hash (version 1.1).
    /// Equal blocks are stored again, and their equality stays hidden.
    Unique,
}

/// The AEAD cipher that seals each new encrypted block payload.
///
/// The cipher belongs to each stored block, not to the archive. A content-derived block that
/// reuses an existing descriptor keeps that descriptor's cipher, so an archive may mix ciphers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PayloadCipher {
    #[default]
    ChaCha20Poly1305,
    /// AES-256-GCM under a key derived from the block key (version 1.1).
    Aes256Gcm,
}

/// Per-block processing requested for a content entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessingOptions {
    encrypted: bool,
    compression_level: u8,
    key_mode: BlockKeyMode,
    cipher: PayloadCipher,
}

impl ProcessingOptions {
    pub(crate) const fn append_default() -> Self {
        Self {
            encrypted: true,
            compression_level: 2,
            key_mode: BlockKeyMode::ContentDerived,
            cipher: PayloadCipher::ChaCha20Poly1305,
        }
    }

    pub fn new(encrypted: bool, compression_level: u8) -> Result<Self, PithosError> {
        if compression_level > 7 {
            return Err(PithosError::ReservedProcessingBits(compression_level));
        }
        Ok(Self {
            encrypted,
            compression_level,
            key_mode: BlockKeyMode::ContentDerived,
            cipher: PayloadCipher::ChaCha20Poly1305,
        })
    }

    /// Selects the key mode. [`BlockKeyMode::Unique`] requires encryption, and writing it
    /// requires a version 1.1 archive.
    pub fn with_key_mode(self, key_mode: BlockKeyMode) -> Result<Self, PithosError> {
        let options = Self { key_mode, ..self };
        options.validate_for(FormatVersion::V1_1)?;
        Ok(options)
    }

    /// Selects the payload cipher. [`PayloadCipher::Aes256Gcm`] requires encryption, and
    /// writing it requires a version 1.1 archive.
    pub fn with_cipher(self, cipher: PayloadCipher) -> Result<Self, PithosError> {
        let options = Self { cipher, ..self };
        options.validate_for(FormatVersion::V1_1)?;
        Ok(options)
    }

    pub fn encrypted(self) -> bool {
        self.encrypted
    }
    pub fn compression_level(self) -> u8 {
        self.compression_level
    }
    pub fn key_mode(self) -> BlockKeyMode {
        self.key_mode
    }
    pub fn cipher(self) -> PayloadCipher {
        self.cipher
    }

    pub(crate) fn flags(self) -> ProcessingFlags {
        let mut flags = ProcessingFlags::new(self.encrypted, Some(self.compression_level));
        flags.set_unique_key(self.key_mode == BlockKeyMode::Unique);
        flags.set_aes_256_gcm(self.cipher == PayloadCipher::Aes256Gcm);
        flags
    }

    /// Checks that an archive of `version` may store blocks with these options.
    pub(crate) fn validate_for(self, version: FormatVersion) -> Result<(), PithosError> {
        Processing::from_byte(self.flags().0, version).map(|_| ())
    }
}

impl Default for ProcessingOptions {
    fn default() -> Self {
        Self {
            encrypted: true,
            compression_level: 3,
            key_mode: BlockKeyMode::ContentDerived,
            cipher: PayloadCipher::ChaCha20Poly1305,
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
    chunking: Chunking,
}

impl WriteOptions {
    pub fn new(sender: PrivateKey, recipients: Vec<PublicKey>) -> Self {
        Self {
            mode: WriteMode::Encrypted { sender, recipients },
            chunking: Chunking::default(),
        }
    }

    pub fn base() -> Self {
        Self {
            mode: WriteMode::Base,
            chunking: Chunking::default(),
        }
    }

    /// Selects how content is split into blocks. The default is [`Chunking::default`].
    pub fn with_chunking(mut self, chunking: Chunking) -> Self {
        self.chunking = chunking;
        self
    }

    /// Check all creation metadata before taking ownership of an output sink.
    pub fn validate(&self) -> Result<(), PithosError> {
        self.chunking.validate()?;
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

impl<T: Copy + zeroize::Zeroize> Reservable for Zeroizing<Vec<T>> {
    fn reserve_capacity(
        &mut self,
        additional: usize,
        field: &'static str,
    ) -> Result<(), PithosError> {
        crate::format::primitives::reserve_secret(self, additional, field)
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

/// Appends one block reference. `positions` maps each hash to its first position rather than
/// to its key, so the map keeps no secret copies.
fn append_block_reference(
    entry: &mut FileEntry,
    positions: &mut HashMap<[u8; 32], usize>,
    hash: [u8; 32],
    key: &crate::crypto::BlockKey,
) -> Result<(), PithosError> {
    let BlockDataState::Decrypted(references) = &mut entry.block_data else {
        return Err(PithosError::InvalidBlockDataState(
            "block data already/still encrypted".into(),
        ));
    };
    reserve(positions, 1, "block references")?;
    reserve(references, 1, "entry block references")?;
    let position = *positions.entry(hash).or_insert(references.len());
    if position < references.len() && references[position].1 != *key.expose_for_protocol() {
        return Err(PithosError::DuplicateBlockReference);
    }
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
    version: FormatVersion,
    chunking: Chunking,
    sink: CountingSink<W>,
    directory: Directory,
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
        let WriteOptions { mode, chunking } = options;
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
        let directory = Directory::new(None, DirectoryEntries::new(), encryption);
        let mut sink = CountingSink { sink, offset: 0 };
        if let Err(error) = header::encode_header(&FormatVersion::CURRENT.header(), &mut sink) {
            return Err(CreateError {
                error: error.into(),
                sink: sink.into_inner(),
            });
        }
        Ok(Self {
            mode,
            version: FormatVersion::CURRENT,
            chunking,
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
        chunking: Chunking,
        snapshot: AppendSnapshot,
    ) -> Result<Self, PithosError> {
        WriteOptions::new(sender.duplicate(), recipients.clone())
            .with_chunking(chunking)
            .validate()?;
        let sender = sender.into_dalek_static_secret();
        let recipients = recipients
            .into_iter()
            .map(PublicKey::into_dalek_public_key)
            .collect::<Vec<_>>();
        let parent = snapshot.terminal_directory();
        let maximum_id = snapshot.maximum_id();
        let files = DirectoryEntries::with_maximum_id(maximum_id.map_or(0, |id| id.0));
        let encryption = IndexMap::from_iter([(
            LegacyPublicKey::from(&sender).to_bytes(),
            EncryptionSection::new(&recipients),
        )]);
        let directory = Directory::new(Some((parent.start(), parent.len())), files, encryption);
        Ok(Self {
            mode: ArchiveWriterMode::Encrypted { sender },
            version: snapshot.version(),
            chunking,
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
        let mut requested_ids = HashSet::with_capacity(ids.len());
        let mut granted_ids = HashSet::with_capacity(ids.len());
        for id in ids {
            if !requested_ids.insert(id.0) {
                return Err(PithosError::DuplicateRecipientFileId);
            }
            snapshot.with_grant_keys(*id, |keys| {
                granted_ids.extend(keys.iter().map(|(key_id, _)| key_id.0));
            })?;
        }
        for section in self.directory.encryption.values_mut() {
            for recipient in section.recipients.values_mut() {
                let RecipientData::Decrypted(records) = &mut recipient.recipient_data else {
                    return Err(PithosError::WriterUnsealedRecipientList);
                };
                reserve(records, granted_ids.len(), "recipient access records")?;
            }
        }
        let mut recipients = self
            .directory
            .encryption
            .values_mut()
            .flat_map(|section| section.recipients.values_mut())
            .collect::<Vec<_>>();
        for id in ids {
            snapshot.with_grant_keys(*id, |keys| {
                for (key_id, key) in keys {
                    let record_key = Zeroizing::new(*key.expose_for_protocol());
                    for recipient in &mut recipients {
                        let RecipientData::Decrypted(records) = &mut recipient.recipient_data
                        else {
                            unreachable!("recipient lists were validated before grant publication");
                        };
                        records.push((key_id.0, *record_key));
                    }
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
        processing.validate_for(self.version)?;
        let mut delta = self.stage_entry(file_type, path, metadata, 0, None)?;
        let mut chunker = Chunker::new(content, self.chunking);
        let mut size = 0u64;
        let mut block_references = HashMap::new();
        loop {
            let chunk_data = match chunker.next_block() {
                Ok(Some(chunk_data)) => chunk_data,
                Ok(None) => break,
                Err(error) => return self.poison(error),
            };
            let chunk_len = chunk_data.len() as u64;
            size = match size.checked_add(chunk_len) {
                Some(size) => size,
                None => return self.poison(PithosError::WriterSizeOverflow),
            };
            let nonce = match self.runtime.block_nonce() {
                Ok(nonce) => nonce,
                Err(error) => return self.poison(error),
            };
            let encoded = match self
                .runtime
                .encode_block(chunk_data, processing.flags(), nonce)
            {
                Ok(encoded) => encoded,
                Err(error) => return self.poison(error),
            };
            let hash = encoded.hash;
            if let Err(error) =
                append_block_reference(&mut delta.entry, &mut block_references, hash, &encoded.key)
            {
                return self.poison(error);
            }
            if let Some(existing) = self.directory.blocks.get(&hash) {
                if existing.original_size != chunk_len {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk_len,
                    });
                }
                continue;
            }
            if let Some(existing) = self
                .append_snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.descriptor(crate::archive::types::BlockHash(hash)))
            {
                if existing.original_size != chunk_len {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk_len,
                    });
                }
                continue;
            }
            if let Some(existing) = delta.descriptors.get(&hash) {
                if existing.original_size != chunk_len {
                    return self.poison(PithosError::BlockIndexConflict {
                        hash,
                        existing_original_size: existing.original_size,
                        new_original_size: chunk_len,
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
                original_size: chunk_len,
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
        crate::format::file_entry::validate_unique_block_references(references)?;
        let actual = references.iter().try_fold(0u64, |total, (hash, _)| {
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
        crate::format::block::encode_block_marker(&BlockHeader::default(), &mut self.sink)?;
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
            if let Some(snapshot) = &self.append_snapshot {
                // Count the directory length without keeping its bytes during validation.
                let mut counter = CountingSink {
                    sink: io::sink(),
                    offset: 0,
                };
                directory::encode_directory(&self.directory, &mut counter)?;
                let span = Span::new(self.sink.offset, counter.offset)?;
                let child = validated_segment_from_directory(
                    self.version,
                    &self.directory,
                    span,
                    Some(snapshot.terminal_directory()),
                )?;
                snapshot.validate_prospective_child(child)?;
            }
            let bytes = directory::encode_complete_directory(&self.directory)?;
            self.sink
                .write_all(&bytes)
                .map_err(SerializationError::from)?;
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
            let shared = crate::crypto::derive_shared(sender.as_bytes(), recipient_key)?;
            let nonce = self.runtime.recipient_list_nonce()?;
            let shared_key = crate::crypto::grant_wrapping_key(
                self.version,
                shared,
                &sender_public,
                recipient_key,
                &nonce,
            );
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
            validate_directory_entry_hierarchy_with_snapshot(&self.directory.files, snapshot)?;
        } else {
            validate_directory_entry_hierarchy_complete(&self.directory.files)?;
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
            deterministic_options().with_chunking(Chunking::ContentDefined(
                CdcConfig::new(64, 256, 1024).unwrap(),
            )),
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
    fn recipient_grants_follow_the_archive_version_rules() {
        for (version, other) in [
            (FormatVersion::V1_0, FormatVersion::V1_1),
            (FormatVersion::V1_1, FormatVersion::V1_0),
        ] {
            let sender = PrivateKey::generate();
            let mut writer = ArchiveWriter::create(
                Vec::new(),
                WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
            )
            .unwrap();
            writer.version = version;
            writer
                .add_file(
                    ArchivePath::new("data").unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    ProcessingOptions::default(),
                    None,
                    Cursor::new(b"content"),
                )
                .unwrap();
            let mut bytes = writer.finish().unwrap();
            bytes[4..6].copy_from_slice(&version.wire().to_be_bytes());
            let open = |bytes: Vec<u8>| {
                Archive::open(
                    MemorySource::new(bytes),
                    OpenOptions::default()
                        .with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
                )
            };
            let mut output = Vec::new();
            open(bytes.clone())
                .unwrap()
                .copy_to("data", &mut output)
                .unwrap();
            assert_eq!(output, b"content");

            bytes[4..6].copy_from_slice(&other.wire().to_be_bytes());
            assert!(
                open(bytes).is_err(),
                "{other:?} rules opened a {version:?} grant"
            );
        }
    }

    #[test]
    fn version_1_0_writers_reject_version_1_1_processing_before_writing_blocks() {
        let unique = ProcessingOptions::default()
            .with_key_mode(BlockKeyMode::Unique)
            .unwrap();
        let aes = ProcessingOptions::default()
            .with_cipher(PayloadCipher::Aes256Gcm)
            .unwrap();
        for processing in [unique, aes] {
            let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
            writer.version = FormatVersion::V1_0;
            assert!(matches!(
                writer.add_file(
                    ArchivePath::new("data").unwrap(),
                    EntryMetadata::new(0, 0, 0o644),
                    processing,
                    None,
                    Cursor::new(b"content"),
                ),
                Err(WriterError::Pithos(
                    PithosError::UnsupportedProcessingFlags(_)
                ))
            ));
            assert!(!writer.poisoned);
            assert_eq!(writer.sink.offset, header::FileHeader::ENCODED_LEN as u64);
            assert_eq!(writer.metadata_snapshot().descriptors, 0);
        }
    }

    #[test]
    fn version_1_1_processing_options_require_encryption() {
        let plain = ProcessingOptions::new(false, 0).unwrap();
        assert!(matches!(
            plain.with_key_mode(BlockKeyMode::Unique),
            Err(PithosError::ProcessingRequiresEncryption(0x10))
        ));
        assert!(matches!(
            plain.with_cipher(PayloadCipher::Aes256Gcm),
            Err(PithosError::ProcessingRequiresEncryption(0x20))
        ));
        let both = ProcessingOptions::new(true, 5)
            .unwrap()
            .with_key_mode(BlockKeyMode::Unique)
            .unwrap()
            .with_cipher(PayloadCipher::Aes256Gcm)
            .unwrap();
        assert_eq!(both.key_mode(), BlockKeyMode::Unique);
        assert_eq!(both.cipher(), PayloadCipher::Aes256Gcm);
        assert_eq!(both.flags().0, 0x3d);
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
            "e2a3b75a71ab0e1db03f0e1b5fa9a9f183822248616397e6d727455eb7730eb2"
        );
        assert_eq!(&archive[..6], b"PITH\x01\x01");
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
            Chunking::default(),
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
        writer.directory.files = DirectoryEntries::with_maximum_id(u64::MAX);
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
            Chunking::default(),
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
        let directory = directory::decode_directory(
            &mut Cursor::new(&bytes),
            &DeserializationLimits::default(),
        )
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
            Chunking::default(),
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

    /// Yields one byte per read call.
    struct ByteReader<'a>(&'a [u8]);

    impl Read for ByteReader<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match (self.0.split_first(), buffer.first_mut()) {
                (Some((first, rest)), Some(target)) => {
                    *target = *first;
                    self.0 = rest;
                    Ok(1)
                }
                _ => Ok(0),
            }
        }
    }

    /// The plaintext hash and size of every block written for `content`, in order.
    fn written_blocks(chunking: Chunking, content: impl Read) -> Vec<([u8; 32], u64)> {
        let options = options().with_chunking(chunking);
        let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 0).unwrap(),
                None,
                content,
            )
            .unwrap();
        let blocks = writer.directory.blocks.iter();
        blocks
            .map(|(hash, block)| (*hash, block.original_size))
            .collect()
    }

    #[test]
    fn fixed_blocks_ignore_read_sizes_and_end_with_one_short_block() {
        let fixed = Chunking::Fixed(1000);
        let content = (0..2500u32)
            .map(|index| (index * 7) as u8)
            .collect::<Vec<_>>();
        for content in [&content[..], &content[..2000]] {
            let expected = content
                .chunks(1000)
                .map(|chunk| (*blake3::hash(chunk).as_bytes(), chunk.len() as u64))
                .collect::<Vec<_>>();
            assert_eq!(written_blocks(fixed, Cursor::new(content)), expected);
            assert_eq!(written_blocks(fixed, ByteReader(content)), expected);
        }
    }

    /// Pseudo-random bytes, so no two content-defined blocks are equal.
    fn noise(len: usize) -> Vec<u8> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// The plaintext hash and size of every `StreamCDC` block of `content`, in order.
    fn stream_blocks(cdc: CdcConfig, content: impl Read) -> Vec<([u8; 32], u64)> {
        let (min, avg, max) = (cdc.min_size, cdc.avg_size, cdc.max_size);
        let stream =
            fastcdc::v2020::StreamCDC::with_level(content, min, avg, max, Normalization::Level1);
        stream
            .map(|chunk| {
                let chunk = chunk.unwrap();
                (*blake3::hash(&chunk.data).as_bytes(), chunk.length as u64)
            })
            .collect()
    }

    #[test]
    fn content_defined_blocks_match_stream_cdc() {
        let content = noise(20_000);
        let cdc = CdcConfig::new(64, 256, 1024).unwrap();
        let expected = stream_blocks(cdc, Cursor::new(&content));
        assert!(expected.len() > 20);
        let chunking = Chunking::ContentDefined(cdc);
        assert_eq!(written_blocks(chunking, Cursor::new(&content)), expected);
        assert_eq!(written_blocks(chunking, ByteReader(&content)), expected);
    }

    /// Answers reads from fixed steps: bytes, an empty step for one end of input, or a failure.
    struct Steps(std::collections::VecDeque<io::Result<Vec<u8>>>);

    impl Read for Steps {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front() {
                None => Ok(0),
                Some(Err(error)) => Err(error),
                Some(Ok(mut data)) => {
                    let count = data.len().min(buffer.len());
                    buffer[..count].copy_from_slice(&data[..count]);
                    if count < data.len() {
                        self.0.push_front(Ok(data.split_off(count)));
                    }
                    Ok(count)
                }
            }
        }
    }

    #[test]
    fn content_defined_reads_stop_at_the_end() {
        let first = noise(500);
        let steps = |last| Steps([Ok(first.clone()), Ok(Vec::new()), last].into());
        let cdc = CdcConfig::new(64, 256, 1024).unwrap();
        let expected = stream_blocks(cdc, steps(Ok(noise(500))));
        assert_eq!(expected.iter().map(|block| block.1).sum::<u64>(), 500);
        let chunking = Chunking::ContentDefined(cdc);
        assert_eq!(written_blocks(chunking, steps(Ok(noise(500)))), expected);
        let failing = steps(Err(io::Error::other("read after the end")));
        assert_eq!(written_blocks(chunking, failing), expected);
    }

    #[test]
    fn fixed_block_sizes_are_validated_before_header_output() {
        assert_eq!(
            WriteOptions::base().chunking,
            Chunking::Fixed(4 * 1024 * 1024)
        );
        let largest = 64 * 1024 * 1024;
        for size in [0, largest + 1] {
            let options = options().with_chunking(Chunking::Fixed(size));
            let error = ArchiveWriter::create(Vec::new(), options).err().unwrap();
            assert!(
                matches!(error.error(), PithosError::InvalidBlockSize(actual) if *actual == size)
            );
            assert!(error.into_incomplete().is_empty());
        }
        let options = options().with_chunking(Chunking::Fixed(largest));
        assert!(ArchiveWriter::create(Vec::new(), options).is_ok());
    }
}

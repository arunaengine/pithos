//! Independently sealed parts of one file, joined later without opening any key.
//!
//! A [`PieceEncoder`] encodes the blocks of one part and seals its block list under a fresh
//! piece key granted to the recipients. The resulting [`Piece`] holds no secret, so it can be
//! stored and later joined by [`compose`] into a version 1.1 archive with one data file.

use crate::archive::content_tree::{self, ContentTree, Subtree, TreeHasher};
use crate::archive::path_validation::validate_entry;
use crate::archive::types::{ArchivePath, Processing};
use crate::archive::writer::{BlockKeyMode, CdcConfig, Chunking, EntryMetadata, ProcessingOptions};
use crate::block;
use crate::crypto::{self, FileKey, PublicKey};
use crate::error::PithosError;
use crate::format::block::{BlockIndexEntry, BlockLocation, ProcessingFlags};
use crate::format::directory::{Directory, DirectoryEntries, encode_complete_directory};
use crate::format::encryption::{EncryptionSection, RecipientData, RecipientSection};
use crate::format::file_entry::{
    BlockDataEntry, BlockDataState, BlockListPiece, FileEntry, FileType,
    encode_decrypted_block_list,
};
use crate::format::header::{FileHeader, FormatVersion, encode_header};
use crate::format::limits::DeserializationError;
use indexmap::IndexMap;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::collections::HashSet;
use std::io::{Cursor, Read};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroizing;

const PIECE_MAGIC: &[u8; 8] = b"PITHPIEC";
/// Version 2 adds the optional content tree; version 1 records still decode.
const PIECE_RECORD_VERSION: u8 = 2;
const BLOCK_MARKER_LEN: u64 = 4;

/// Location and size of one encoded block inside its piece.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PieceBlock {
    pub(crate) hash: [u8; 32],
    /// Offset of the block's `BLCK` marker from the start of the piece bytes.
    pub(crate) offset: u64,
    pub(crate) stored_size: u64,
    pub(crate) original_size: u64,
    pub(crate) flags: ProcessingFlags,
}

/// One sealed part of a file. It contains no key material: block keys are inside the sealed
/// block list, and the piece key exists only inside the recipient grants.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Piece {
    pub(crate) key_id: u64,
    pub(crate) original_size: u64,
    pub(crate) stored_len: u64,
    pub(crate) blocks: Vec<PieceBlock>,
    pub(crate) sealed_list: Vec<u8>,
    pub(crate) sender: [u8; 32],
    pub(crate) grants: Vec<([u8; 32], Vec<u8>)>,
    pub(crate) content: Option<ContentTree>,
}

/// Encodes the blocks of one piece. The caller appends every returned byte string, in order,
/// to the piece's stored bytes.
///
/// [`PieceEncoder::write`] and [`PieceEncoder::flush`] split the content with the configured
/// [`Chunking`], fixed 4 MiB blocks by default. [`PieceEncoder::push`] encodes caller-chosen blocks.
///
/// The encoder also records BLAKE3 subtree chaining values of the piece plaintext, so that
/// [`Composition::content_hash`] can report the whole-file BLAKE3. They are plaintext
/// fingerprints like convergent block hashes, so with [`BlockKeyMode::Unique`] they are off
/// unless [`PieceEncoder::with_content_hash`] turns them on.
pub struct PieceEncoder {
    key_id: u64,
    recipients: Vec<[u8; 32]>,
    flags: ProcessingFlags,
    entries: Zeroizing<Vec<BlockDataEntry>>,
    blocks: Vec<PieceBlock>,
    seen: HashSet<[u8; 32]>,
    stored_len: u64,
    original_size: u64,
    chunking: Chunking,
    pending: Zeroizing<Vec<u8>>,
    content_offset: u64,
    tree: Option<TreeHasher>,
}

impl PieceEncoder {
    /// Starts a piece whose key will be granted to `recipients` under `key_id`.
    /// Key ids must be at least 1, because the composed file uses file id 0.
    pub fn new(
        key_id: u64,
        recipients: Vec<PublicKey>,
        processing: ProcessingOptions,
    ) -> Result<Self, PithosError> {
        if key_id == 0 {
            return Err(PithosError::PieceKeyIdConflict(0));
        }
        if recipients.is_empty() {
            return Err(PithosError::WriterRequiresRecipient);
        }
        processing.validate_for(FormatVersion::V1_1)?;
        let recipients = distinct_keys(recipients)?;
        Ok(Self {
            key_id,
            recipients,
            flags: processing.flags(),
            entries: Zeroizing::new(Vec::new()),
            blocks: Vec::new(),
            seen: HashSet::new(),
            stored_len: 0,
            original_size: 0,
            chunking: Chunking::default(),
            pending: Zeroizing::new(Vec::new()),
            content_offset: 0,
            tree: (processing.key_mode() != BlockKeyMode::Unique).then(|| TreeHasher::new(0)),
        })
    }

    /// Sets the absolute file offset of this piece's first plaintext byte. The default is 0.
    /// The offset must be a multiple of 1024, the BLAKE3 chunk length, and must be set before
    /// any content is added.
    pub fn with_content_offset(mut self, offset: u64) -> Result<Self, PithosError> {
        self.ensure_no_content()?;
        if !offset.is_multiple_of(blake3::CHUNK_LEN as u64) {
            return Err(PithosError::InvalidContentOffset(offset));
        }
        self.content_offset = offset;
        if self.tree.is_some() {
            self.tree = Some(TreeHasher::new(offset));
        }
        Ok(self)
    }

    /// Turns the recorded subtree chaining values on or off before any content is added.
    pub fn with_content_hash(mut self, record: bool) -> Result<Self, PithosError> {
        self.ensure_no_content()?;
        self.tree = record.then(|| TreeHasher::new(self.content_offset));
        Ok(self)
    }

    fn ensure_no_content(&self) -> Result<(), PithosError> {
        if self.original_size != 0 || !self.pending.is_empty() {
            return Err(PithosError::PieceContentStarted);
        }
        Ok(())
    }

    /// Sets fixed blocks of `size` bytes for [`PieceEncoder::write`]. The default is 4 MiB.
    /// Fails once content was added, because buffered bytes assume the old size.
    pub fn with_block_size(self, size: usize) -> Result<Self, PithosError> {
        self.with_chunking(Chunking::Fixed(size))
    }

    /// Sets how [`PieceEncoder::write`] splits content into blocks. The default is fixed 4 MiB.
    /// FastCDC gives the same blocks as [`ArchiveWriter`](crate::archive::ArchiveWriter) for the
    /// same content. Fails once content was added.
    pub fn with_chunking(mut self, chunking: Chunking) -> Result<Self, PithosError> {
        self.ensure_no_content()?;
        chunking.validate()?;
        self.chunking = chunking;
        Ok(self)
    }

    /// Adds content and returns the stored bytes of every block it completes.
    /// Block boundaries do not depend on how the content is split across calls.
    /// After the last write, call [`PieceEncoder::flush`] for the final blocks.
    pub fn write(&mut self, mut content: &[u8]) -> Result<Vec<u8>, PithosError> {
        let mut stored = Vec::new();
        let (buffer_size, cdc) = match self.chunking {
            Chunking::Fixed(size) => (size, None),
            Chunking::ContentDefined(cdc) => (cdc.max_size(), Some(cdc)),
        };
        while !content.is_empty() {
            if cdc.is_none() && self.pending.is_empty() && content.len() >= buffer_size {
                let (block, rest) = content.split_at(buffer_size);
                stored.extend(self.encode(block)?);
                content = rest;
                continue;
            }
            let missing = buffer_size - self.pending.len();
            // Reserving the rest of the buffer once keeps plaintext from being copied on growth.
            self.pending.reserve_exact(missing);
            let take = missing.min(content.len());
            self.pending.extend_from_slice(&content[..take]);
            content = &content[take..];
            if self.pending.len() == buffer_size {
                stored.extend(match cdc {
                    Some(cdc) => self.cut_block(cdc)?,
                    None => self.flush()?,
                });
            }
        }
        Ok(stored)
    }

    /// Encodes the bytes buffered by [`PieceEncoder::write`] as the final blocks, if there are any.
    pub fn flush(&mut self) -> Result<Vec<u8>, PithosError> {
        let Chunking::ContentDefined(cdc) = self.chunking else {
            if self.pending.is_empty() {
                return Ok(Vec::new());
            }
            let block = std::mem::take(&mut self.pending);
            let stored = self.encode(&block);
            self.pending = block;
            self.pending.clear();
            return stored;
        };
        let mut stored = Vec::new();
        while !self.pending.is_empty() {
            stored.extend(self.cut_block(cdc)?);
        }
        Ok(stored)
    }

    /// Encodes the first FastCDC block of the buffered bytes and removes it from the buffer.
    /// Like `StreamCDC`, it cuts only with a full buffer or at the end of the content.
    fn cut_block(&mut self, cdc: CdcConfig) -> Result<Vec<u8>, PithosError> {
        let end = cdc.first_cut(&self.pending);
        let block = std::mem::take(&mut self.pending);
        let stored = self.encode(&block[..end]);
        self.pending = block;
        self.pending.drain(..end);
        stored
    }

    /// Encodes one non-empty block and returns `BLCK || payload` to append to the piece.
    /// With content-derived keys, a block that repeats an earlier block of this piece returns
    /// no bytes. With unique keys, every block is stored.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PithosError> {
        if !self.pending.is_empty() {
            return Err(PithosError::UnflushedPieceBytes);
        }
        self.encode(plaintext)
    }

    fn encode(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PithosError> {
        if plaintext.is_empty() {
            return Err(PithosError::InvalidBlockDescriptor(
                "piece blocks must not be empty",
            ));
        }
        let encoded = block::encode(plaintext, self.flags, crypto::random_nonce())?;
        let original_size = plaintext.len() as u64;
        self.original_size = checked_add(self.original_size, original_size)?;
        if let Some(tree) = &mut self.tree {
            checked_add(self.content_offset, self.original_size)?;
            tree.update(plaintext);
        }
        crate::format::primitives::reserve_secret(&mut self.entries, 1, "block references")?;
        self.entries
            .push((encoded.hash, *encoded.key.expose_for_protocol()));
        if !self.seen.insert(encoded.hash) {
            return Ok(Vec::new());
        }
        let stored_size = encoded.stored.len() as u64;
        self.blocks.push(PieceBlock {
            hash: encoded.hash,
            offset: self.stored_len,
            stored_size,
            original_size,
            flags: encoded.flags,
        });
        let total = checked_add(BLOCK_MARKER_LEN, stored_size)?;
        self.stored_len = checked_add(self.stored_len, total)?;
        let mut bytes = Vec::with_capacity(encoded.stored.len() + 4);
        bytes.extend_from_slice(b"BLCK");
        bytes.extend_from_slice(&encoded.stored);
        Ok(bytes)
    }

    /// Seals the block list under a fresh piece key and grants that key to every recipient.
    /// Fails if written bytes were not flushed.
    pub fn finish(self) -> Result<Piece, PithosError> {
        if !self.pending.is_empty() {
            return Err(PithosError::UnflushedPieceBytes);
        }
        let piece_key = FileKey::from_bytes(StaticSecret::random().to_bytes());
        // An exact capacity keeps the plaintext list from moving to a new buffer while written.
        let mut list = Zeroizing::new(Vec::with_capacity(10 + self.entries.len() * 64));
        encode_decrypted_block_list(&self.entries, &mut *list)?;
        let sealed_list =
            crypto::seal_file_block_list_with_nonce(&piece_key, &list, crypto::random_nonce())?;

        let sender = StaticSecret::random();
        let sender_public = DalekPublicKey::from(&sender).to_bytes();
        // Written straight from the borrowed key into reserved room, so no plain copy remains.
        let mut records = Zeroizing::new(Vec::with_capacity(1 + 10 + 32));
        records.push(1);
        records.write_varint(self.key_id)?;
        records.extend_from_slice(piece_key.expose_for_protocol());
        let mut grants = Vec::with_capacity(self.recipients.len());
        for recipient in &self.recipients {
            let nonce = crypto::random_nonce();
            let key = crypto::grant_wrapping_key(
                FormatVersion::V1_1,
                crypto::derive_shared(sender.as_bytes(), recipient)?,
                &sender_public,
                recipient,
                &nonce,
            );
            grants.push((
                *recipient,
                crypto::wrap_recipient_list_with_nonce(&key, &records, nonce)?,
            ));
        }
        Ok(Piece {
            key_id: self.key_id,
            original_size: self.original_size,
            stored_len: self.stored_len,
            blocks: self.blocks,
            sealed_list,
            sender: sender_public,
            grants,
            content: self.tree.map(TreeHasher::finish),
        })
    }
}

impl Piece {
    pub fn key_id(&self) -> u64 {
        self.key_id
    }

    /// Plaintext bytes covered by this piece, counting repeated blocks each time.
    pub fn original_size(&self) -> u64 {
        self.original_size
    }

    /// Length of the stored bytes the encoder returned for this piece.
    pub fn stored_len(&self) -> u64 {
        self.stored_len
    }

    /// Encodes this record for storage until composition. The encoding is stable for one
    /// record version and is not part of the archive format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(PIECE_MAGIC);
        bytes.push(PIECE_RECORD_VERSION);
        for value in [
            self.key_id,
            self.original_size,
            self.stored_len,
            self.blocks.len() as u64,
        ] {
            write_uleb(&mut bytes, value);
        }
        for block in &self.blocks {
            bytes.extend_from_slice(&block.hash);
            write_uleb(&mut bytes, block.offset);
            write_uleb(&mut bytes, block.stored_size);
            write_uleb(&mut bytes, block.original_size);
            bytes.push(block.flags.0);
        }
        write_uleb(&mut bytes, self.sealed_list.len() as u64);
        bytes.extend_from_slice(&self.sealed_list);
        bytes.extend_from_slice(&self.sender);
        write_uleb(&mut bytes, self.grants.len() as u64);
        for (recipient, wrapped) in &self.grants {
            bytes.extend_from_slice(recipient);
            write_uleb(&mut bytes, wrapped.len() as u64);
            bytes.extend_from_slice(wrapped);
        }
        let Some(tree) = &self.content else {
            bytes.push(0);
            return bytes;
        };
        bytes.push(1);
        write_uleb(&mut bytes, tree.offset);
        write_uleb(&mut bytes, tree.subtrees.len() as u64);
        for subtree in &tree.subtrees {
            write_uleb(&mut bytes, subtree.offset);
            write_uleb(&mut bytes, subtree.len);
            bytes.extend_from_slice(&subtree.value);
        }
        match tree.root {
            Some(root) => {
                bytes.push(1);
                bytes.extend_from_slice(&root);
            }
            None => bytes.push(0),
        }
        bytes
    }

    /// Decodes a record from [`Piece::to_bytes`] and checks that its blocks are contiguous.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PithosError> {
        let mut reader = Cursor::new(bytes);
        if read_vec(&mut reader, PIECE_MAGIC.len())? != PIECE_MAGIC {
            return Err(PithosError::InvalidPieceRecord);
        }
        let version = read_vec(&mut reader, 1)?[0];
        if !(1..=PIECE_RECORD_VERSION).contains(&version) {
            return Err(PithosError::InvalidPieceRecord);
        }
        let key_id = read_uleb(&mut reader)?;
        let original_size = read_uleb(&mut reader)?;
        let stored_len = read_uleb(&mut reader)?;
        let block_count = read_count(&mut reader, 32 + 4)?;
        let mut blocks = Vec::with_capacity(block_count);
        let mut offset = 0u64;
        for _ in 0..block_count {
            let block = PieceBlock {
                hash: read_array(&mut reader)?,
                offset: read_uleb(&mut reader)?,
                stored_size: read_uleb(&mut reader)?,
                original_size: read_uleb(&mut reader)?,
                flags: ProcessingFlags::from_byte(read_vec(&mut reader, 1)?[0]),
            };
            if block.offset != offset
                || Processing::from_byte(block.flags.0, FormatVersion::V1_1).is_err()
            {
                return Err(PithosError::InvalidPieceRecord);
            }
            offset = checked_add(offset, checked_add(BLOCK_MARKER_LEN, block.stored_size)?)?;
            blocks.push(block);
        }
        let list_len = read_count(&mut reader, 1)?;
        let sealed_list = read_vec(&mut reader, list_len)?;
        let sender = read_array(&mut reader)?;
        crypto::validate_x25519_public_key(&sender)?;
        let grant_count = read_count(&mut reader, 32 + 1)?;
        let mut grants = Vec::with_capacity(grant_count);
        for _ in 0..grant_count {
            let recipient = read_array(&mut reader)?;
            crypto::validate_x25519_public_key(&recipient)?;
            let len = read_count(&mut reader, 1)?;
            grants.push((recipient, read_vec(&mut reader, len)?));
        }
        let content = match version {
            1 => None,
            _ => read_content_tree(&mut reader, original_size)?,
        };
        if offset != stored_len
            || reader.position() != bytes.len() as u64
            || key_id == 0
            || grants.is_empty()
        {
            return Err(PithosError::InvalidPieceRecord);
        }
        Ok(Self {
            key_id,
            original_size,
            stored_len,
            blocks,
            sealed_list,
            sender,
            grants,
            content,
        })
    }
}

fn read_content_tree(
    reader: &mut Cursor<&[u8]>,
    original_size: u64,
) -> Result<Option<ContentTree>, PithosError> {
    match read_vec(reader, 1)?[0] {
        0 => return Ok(None),
        1 => {}
        _ => return Err(PithosError::InvalidPieceRecord),
    }
    let offset = read_uleb(reader)?;
    let count = read_count(reader, 2 + 32)?;
    let mut subtrees = Vec::with_capacity(count);
    for _ in 0..count {
        subtrees.push(Subtree {
            offset: read_uleb(reader)?,
            len: read_uleb(reader)?,
            value: read_array(reader)?,
        });
    }
    let root = match read_vec(reader, 1)?[0] {
        0 => None,
        1 => Some(read_array(reader)?),
        _ => return Err(PithosError::InvalidPieceRecord),
    };
    let tree = ContentTree {
        offset,
        subtrees,
        root,
    };
    if !tree.is_valid(original_size) {
        return Err(PithosError::InvalidPieceRecord);
    }
    Ok(Some(tree))
}

fn write_uleb(bytes: &mut Vec<u8>, value: u64) {
    bytes
        .write_varint(value)
        .expect("writing to a vector cannot fail");
}

fn read_uleb(reader: &mut Cursor<&[u8]>) -> Result<u64, PithosError> {
    reader
        .read_varint::<u64>()
        .map_err(|_| PithosError::InvalidPieceRecord)
}

fn read_vec(reader: &mut Cursor<&[u8]>, len: usize) -> Result<Vec<u8>, PithosError> {
    let mut value = vec![0; len];
    reader
        .read_exact(&mut value)
        .map_err(|_| PithosError::InvalidPieceRecord)?;
    Ok(value)
}

fn read_array(reader: &mut Cursor<&[u8]>) -> Result<[u8; 32], PithosError> {
    let mut value = [0; 32];
    reader
        .read_exact(&mut value)
        .map_err(|_| PithosError::InvalidPieceRecord)?;
    Ok(value)
}

/// Reads a count whose items need at least `item_len` bytes each, so it cannot over-allocate.
fn read_count(reader: &mut Cursor<&[u8]>, item_len: u64) -> Result<usize, PithosError> {
    let count = read_uleb(reader)?;
    let remaining = reader.get_ref().len() as u64 - reader.position();
    if count
        .checked_mul(item_len)
        .is_none_or(|needed| needed > remaining)
    {
        return Err(PithosError::InvalidPieceRecord);
    }
    usize::try_from(count).map_err(|_| PithosError::InvalidPieceRecord)
}

/// The raw keys of `recipients`. A key given twice is rejected.
pub(crate) fn distinct_keys(recipients: Vec<PublicKey>) -> Result<Vec<[u8; 32]>, PithosError> {
    let recipients = recipients
        .into_iter()
        .map(|recipient| recipient.into_dalek_public_key().to_bytes())
        .collect::<Vec<_>>();
    let mut unique = HashSet::with_capacity(recipients.len());
    if recipients
        .iter()
        .any(|recipient| !unique.insert(*recipient))
    {
        return Err(PithosError::DuplicateRecipientKey);
    }
    Ok(recipients)
}

/// The file header of a version 1.1 archive.
pub(crate) fn v1_1_header() -> [u8; FileHeader::ENCODED_LEN] {
    let mut header = [0; FileHeader::ENCODED_LEN];
    encode_header(&FormatVersion::V1_1.header(), &mut header.as_mut_slice())
        .expect("the header fits its fixed length");
    header
}

fn checked_add(left: u64, right: u64) -> Result<u64, PithosError> {
    left.checked_add(right)
        .ok_or(PithosError::InvalidDirectoryRange {
            operation: "add piece sizes",
        })
}

/// A composed version 1.1 archive. Write [`Composition::header`], then the stored bytes of
/// every piece in order (at [`Composition::piece_offsets`]), then the directory.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Composition {
    piece_offsets: Vec<u64>,
    directory: Vec<u8>,
    archive_len: u64,
    content_hash: Option<[u8; 32]>,
}

impl Composition {
    pub fn header(&self) -> [u8; FileHeader::ENCODED_LEN] {
        v1_1_header()
    }

    /// Archive offset at which each piece's stored bytes start.
    pub fn piece_offsets(&self) -> &[u64] {
        &self.piece_offsets
    }

    pub fn directory(&self) -> &[u8] {
        &self.directory
    }

    pub fn archive_len(&self) -> u64 {
        self.archive_len
    }

    /// The BLAKE3 hash of the whole composed file, or `None` when the pieces do not allow it.
    ///
    /// It is known when every piece recorded subtree chaining values, the recorded offsets
    /// are the running sums of the piece sizes from 0, and each piece's values cover it
    /// exactly. The value is only as trustworthy as the stored piece records, which hold no
    /// proof of the plaintext. A full read of the composed file confirms it.
    pub fn content_hash(&self) -> Option<[u8; 32]> {
        self.content_hash
    }

    /// The digest [`crate::archive::Archive::metadata_digest`] reports for this archive.
    pub fn metadata_digest(&self) -> [u8; 32] {
        crate::archive::metadata_digest(&[*blake3::hash(&self.directory).as_bytes()])
    }
}

/// Joins pieces, in content order, into an archive with one data file at `path`.
/// It opens no key, so it works without access to the content. Key ids must increase,
/// and `path` must be at the archive root because the archive declares no directories.
pub fn compose(
    path: ArchivePath,
    metadata: EntryMetadata,
    pieces: &[Piece],
) -> Result<Composition, PithosError> {
    if path.as_str().contains('/') {
        return Err(PithosError::InvalidArchivePath {
            path: path.as_str().to_owned(),
            reason: "a composed file must be at the archive root".into(),
        });
    }
    if let Some(reference) = metadata.references.first() {
        return Err(PithosError::MissingReferenceTarget(
            reference.target_file_id,
        ));
    }
    let mut piece_offsets = Vec::with_capacity(pieces.len());
    let mut offset = FileHeader::ENCODED_LEN as u64;
    let mut file_size = 0u64;
    let mut blocks: IndexMap<[u8; 32], BlockIndexEntry> = IndexMap::new();
    let mut encryption = IndexMap::new();
    let mut previous_key = 0u64;
    for piece in pieces {
        if piece.key_id <= previous_key {
            return Err(DeserializationError::UnorderedPieceKeys.into());
        }
        previous_key = piece.key_id;
        piece_offsets.push(offset);
        for block in &piece.blocks {
            let entry = BlockIndexEntry {
                offset: checked_add(offset, block.offset)?,
                stored_size: block.stored_size,
                original_size: block.original_size,
                flags: block.flags,
                location: BlockLocation::Local,
            };
            // Equal hashes have equal convergent keys, so the first stored copy serves all.
            // Unique-key hashes are keyed with random keys and do not repeat.
            match blocks.get(&block.hash) {
                Some(existing) if existing.original_size != entry.original_size => {
                    return Err(PithosError::BlockIndexConflict {
                        hash: block.hash,
                        existing_original_size: existing.original_size,
                        new_original_size: entry.original_size,
                    });
                }
                Some(_) => {}
                None => {
                    blocks.insert(block.hash, entry);
                }
            }
        }
        let recipients = piece
            .grants
            .iter()
            .map(|(recipient, wrapped)| {
                let data = RecipientData::Encrypted(wrapped.clone());
                (
                    *recipient,
                    RecipientSection {
                        recipient_data: data,
                    },
                )
            })
            .collect();
        if encryption
            .insert(piece.sender, EncryptionSection { recipients })
            .is_some()
        {
            return Err(PithosError::DuplicateSenderKey);
        }
        offset = checked_add(offset, piece.stored_len)?;
        file_size = checked_add(file_size, piece.original_size)?;
    }

    let entry = FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Pieces(
            pieces
                .iter()
                .map(|piece| BlockListPiece {
                    key_id: piece.key_id,
                    sealed: piece.sealed_list.clone(),
                })
                .collect(),
        ),
        created: metadata.created,
        modified: metadata.modified,
        file_size,
        permissions: metadata.permissions,
        references: Vec::new(),
        symlink_target: None,
    };
    validate_entry(path.as_str(), &entry)?;
    let mut files = DirectoryEntries::new();
    files.insert(0, path.as_str(), entry)?;
    let mut directory = Directory::new(None, files, encryption);
    directory.blocks = blocks;
    let bytes = encode_complete_directory(&directory)?;
    Ok(Composition {
        content_hash: content_tree::file_hash(
            pieces
                .iter()
                .map(|piece| (piece.content.as_ref(), piece.original_size)),
        ),
        piece_offsets,
        archive_len: checked_add(offset, bytes.len() as u64)?,
        directory: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{BlockKeyMode, PayloadCipher};

    #[test]
    fn piece_records_carry_version_1_1_flags_and_reject_invalid_ones() {
        let recipient = crate::crypto::PrivateKey::generate().public_key();
        let processing = ProcessingOptions::new(true, 0)
            .unwrap()
            .with_key_mode(BlockKeyMode::Unique)
            .unwrap()
            .with_cipher(PayloadCipher::Aes256Gcm)
            .unwrap();
        let mut encoder = PieceEncoder::new(1, vec![recipient], processing).unwrap();
        encoder.push(b"unique block").unwrap();
        let mut piece = encoder.finish().unwrap();
        assert_eq!(piece.blocks[0].flags.0, 0x38);
        assert_eq!(Piece::from_bytes(&piece.to_bytes()).unwrap(), piece);
        for flags in [0x10, 0x20, 0x40] {
            piece.blocks[0].flags = ProcessingFlags(flags);
            assert!(matches!(
                Piece::from_bytes(&piece.to_bytes()),
                Err(PithosError::InvalidPieceRecord)
            ));
        }
    }

    #[test]
    fn version_1_records_decode_without_a_content_tree_and_bad_trees_are_rejected() {
        let recipient = crate::crypto::PrivateKey::generate().public_key();
        let processing = ProcessingOptions::new(true, 0).unwrap();
        let encoder = PieceEncoder::new(1, vec![recipient], processing).unwrap();
        let mut encoder = encoder.with_content_hash(false).unwrap();
        encoder.push(b"version one block").unwrap();
        let piece = encoder.finish().unwrap();
        let mut version_1 = piece.to_bytes();
        assert_eq!(version_1.pop(), Some(0));
        version_1[PIECE_MAGIC.len()] = 1;
        assert_eq!(Piece::from_bytes(&version_1).unwrap(), piece);

        let encoder = PieceEncoder::new(1, vec![recipient], processing).unwrap();
        let mut encoder = encoder.with_content_offset(2048).unwrap();
        encoder.push(&[3; 3000]).unwrap();
        let piece = encoder.finish().unwrap();
        assert_eq!(Piece::from_bytes(&piece.to_bytes()).unwrap(), piece);
        let changes: [fn(&mut ContentTree); 4] = [
            |tree| tree.offset += 1024,
            |tree| tree.subtrees[0].len += 1,
            |tree| tree.root = Some([0; 32]),
            |tree| {
                tree.subtrees.pop();
            },
        ];
        for change in changes {
            let mut invalid = piece.clone();
            change(invalid.content.as_mut().unwrap());
            assert!(matches!(
                Piece::from_bytes(&invalid.to_bytes()),
                Err(PithosError::InvalidPieceRecord)
            ));
        }
    }

    #[test]
    fn piece_records_reject_non_contributory_keys() {
        let recipient = crate::crypto::PrivateKey::generate().public_key();
        let processing = ProcessingOptions::new(true, 0).unwrap();
        let mut encoder = PieceEncoder::new(1, vec![recipient], processing).unwrap();
        encoder.push(b"piece").unwrap();
        let piece = encoder.finish().unwrap();
        assert_eq!(Piece::from_bytes(&piece.to_bytes()).unwrap(), piece);
        let mut sender = piece.clone();
        sender.sender = [0; 32];
        let mut grant = piece;
        grant.grants[0].0 = [0; 32];
        for damaged in [sender, grant] {
            assert!(matches!(
                Piece::from_bytes(&damaged.to_bytes()),
                Err(PithosError::Crypt(
                    crate::crypto::CryptoError::NonContributoryPublicKey
                ))
            ));
        }
    }

    #[test]
    fn written_fragments_give_the_same_fastcdc_blocks_as_the_archive_writer() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let content = (0..20_000)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect::<Vec<_>>();
        let cdc = CdcConfig::new(64, 256, 1024).unwrap();
        let stream = fastcdc::v2020::StreamCDC::with_level(
            Cursor::new(&content),
            cdc.min_size(),
            cdc.avg_size(),
            cdc.max_size(),
            fastcdc::v2020::Normalization::Level1,
        );
        let expected = stream
            .map(|chunk| chunk.unwrap().length as u64)
            .collect::<Vec<_>>();
        assert!(expected.len() > 20);
        let recipient = crate::crypto::PrivateKey::generate().public_key();
        let processing = ProcessingOptions::new(true, 0).unwrap();
        let encoder = || PieceEncoder::new(1, vec![recipient], processing).unwrap();
        for fragment in [1, 7, 1000, 4096, content.len()] {
            let chunking = Chunking::ContentDefined(cdc);
            let mut written = encoder().with_chunking(chunking).unwrap();
            let mut stored = 0;
            for part in content.chunks(fragment) {
                stored += written.write(part).unwrap().len();
            }
            stored += written.flush().unwrap().len();
            let piece = written.finish().unwrap();
            let sizes = piece.blocks.iter().map(|block| block.original_size);
            assert_eq!(sizes.collect::<Vec<_>>(), expected, "{fragment}");
            assert_eq!(piece.stored_len, stored as u64);
        }

        let mut started = encoder();
        started.write(b"pending").unwrap();
        assert!(matches!(
            started.with_chunking(Chunking::ContentDefined(cdc)),
            Err(PithosError::PieceContentStarted)
        ));
    }

    #[test]
    fn written_fragments_give_the_same_fixed_blocks_as_pushed_blocks() {
        let content = (0..2500u32)
            .map(|index| (index * 7) as u8)
            .collect::<Vec<_>>();
        let encoder = || {
            let recipient = crate::crypto::PrivateKey::generate().public_key();
            let processing = ProcessingOptions::new(true, 0).unwrap();
            let encoder = PieceEncoder::new(1, vec![recipient], processing).unwrap();
            encoder.with_block_size(1000).unwrap()
        };
        let mut pushed = encoder();
        for block in content.chunks(1000) {
            pushed.push(block).unwrap();
        }
        let expected = pushed.finish().unwrap().blocks;
        assert_eq!(expected.len(), 3);
        for fragment in [1, 7, 1000, 4096] {
            let mut written = encoder();
            let mut stored = 0;
            for part in content.chunks(fragment) {
                stored += written.write(part).unwrap().len();
            }
            assert!(matches!(
                written.push(b"block"),
                Err(PithosError::UnflushedPieceBytes)
            ));
            stored += written.flush().unwrap().len();
            assert!(written.flush().unwrap().is_empty());
            let piece = written.finish().unwrap();
            assert_eq!(piece.blocks, expected);
            assert_eq!(piece.stored_len, stored as u64);
        }

        let mut unflushed = encoder();
        unflushed.write(b"short").unwrap();
        assert!(matches!(
            unflushed.finish(),
            Err(PithosError::UnflushedPieceBytes)
        ));
        assert!(matches!(
            encoder().with_block_size(0),
            Err(PithosError::InvalidBlockSize(0))
        ));
        let mut started = encoder();
        started.write(b"pending").unwrap();
        assert!(matches!(
            started.with_block_size(4),
            Err(PithosError::PieceContentStarted)
        ));
    }
}

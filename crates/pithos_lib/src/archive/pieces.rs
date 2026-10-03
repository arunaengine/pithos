//! Independently sealed parts of one file, joined later without opening any key.
//!
//! A [`PieceEncoder`] encodes the blocks of one part and seals its block list under a fresh
//! piece key granted to the recipients. The resulting [`Piece`] holds no secret, so it can be
//! stored and later joined into a version 1.1 archive with one data file.

use crate::archive::writer::ProcessingOptions;
use crate::block;
use crate::crypto::{self, FileKey, PublicKey};
use crate::error::PithosError;
use crate::format::block::ProcessingFlags;
use crate::format::encryption::encode_decrypted_recipient_list;
use crate::format::file_entry::{BlockDataEntry, encode_decrypted_block_list};
use crate::format::header::FormatVersion;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::collections::HashSet;
use std::io::{Cursor, Read};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroizing;

const PIECE_MAGIC: &[u8; 8] = b"PITHPIEC";
const PIECE_RECORD_VERSION: u8 = 1;
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
}

/// Encodes the blocks of one piece. The caller chooses block boundaries and appends every
/// returned byte string, in order, to the piece's stored bytes.
pub struct PieceEncoder {
    key_id: u64,
    recipients: Vec<[u8; 32]>,
    flags: ProcessingFlags,
    entries: Zeroizing<Vec<BlockDataEntry>>,
    blocks: Vec<PieceBlock>,
    seen: HashSet<[u8; 32]>,
    stored_len: u64,
    original_size: u64,
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
        Ok(Self {
            key_id,
            recipients,
            flags: processing.flags(),
            entries: Zeroizing::new(Vec::new()),
            blocks: Vec::new(),
            seen: HashSet::new(),
            stored_len: 0,
            original_size: 0,
        })
    }

    /// Encodes one non-empty block and returns `BLCK || payload` to append to the piece.
    /// A block that repeats an earlier block of this piece returns no bytes.
    pub fn push(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, PithosError> {
        if plaintext.is_empty() {
            return Err(PithosError::InvalidBlockDescriptor(
                "piece blocks must not be empty",
            ));
        }
        let encoded = block::encode(plaintext, self.flags, crypto::random_nonce())?;
        let original_size = plaintext.len() as u64;
        self.original_size = checked_add(self.original_size, original_size)?;
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
    pub fn finish(self) -> Result<Piece, PithosError> {
        let piece_key = FileKey::from_bytes(StaticSecret::random().to_bytes());
        let mut list = Zeroizing::new(Vec::new());
        encode_decrypted_block_list(&self.entries, &mut *list)?;
        let sealed_list =
            crypto::seal_file_block_list_with_nonce(&piece_key, &list, crypto::random_nonce())?;

        let sender = StaticSecret::random();
        let sender_public = DalekPublicKey::from(&sender).to_bytes();
        let mut records = Zeroizing::new(Vec::new());
        encode_decrypted_recipient_list(
            &[(self.key_id, *piece_key.expose_for_protocol())],
            &mut *records,
        )?;
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
        bytes
    }

    /// Decodes a record from [`Piece::to_bytes`] and checks that its blocks are contiguous.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PithosError> {
        let mut reader = Cursor::new(bytes);
        if read_vec(&mut reader, PIECE_MAGIC.len())? != PIECE_MAGIC
            || read_vec(&mut reader, 1)? != [PIECE_RECORD_VERSION]
        {
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
            if block.offset != offset || block.flags.has_reserved_bits() {
                return Err(PithosError::InvalidPieceRecord);
            }
            offset = checked_add(offset, checked_add(BLOCK_MARKER_LEN, block.stored_size)?)?;
            blocks.push(block);
        }
        let list_len = read_count(&mut reader, 1)?;
        let sealed_list = read_vec(&mut reader, list_len)?;
        let sender = read_array(&mut reader)?;
        let grant_count = read_count(&mut reader, 32 + 1)?;
        let mut grants = Vec::with_capacity(grant_count);
        for _ in 0..grant_count {
            let recipient = read_array(&mut reader)?;
            let len = read_count(&mut reader, 1)?;
            grants.push((recipient, read_vec(&mut reader, len)?));
        }
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
        })
    }
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

fn checked_add(left: u64, right: u64) -> Result<u64, PithosError> {
    left.checked_add(right)
        .ok_or(PithosError::InvalidDirectoryRange {
            operation: "add piece sizes",
        })
}

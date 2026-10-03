use crate::crypto::{self, FileKey};
use crate::error::PithosError;
use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::primitives::{
    bounded_len, decode_string, reserve, reserve_secret, write_len_prefix,
};
use integer_encoding::{VarIntReader, VarIntWriter};
use std::fmt::{Display, Formatter};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub(crate) const VALID_PERMISSION_BITS: u32 = 0o7777;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    Directory = 0,
    Data = 1,
    Metadata = 2,
    Symlink = 3,
}

/// A block's content hash and the key used to encrypt its content.
pub type BlockDataEntry = ([u8; 32], [u8; 32]);

/// Transient block-list state used while encoding or opening a directory.
/// Decrypted block keys are crate-private.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum BlockDataState {
    Encrypted(Vec<u8>),
    Decrypted(Zeroizing<Vec<BlockDataEntry>>),
    /// Version 1.1: a block list sealed in independent pieces, concatenated in stored order.
    Pieces(Vec<BlockListPiece>),
}

/// One sealed part of a file's block list, opened with the key granted for `key_id`.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct BlockListPiece {
    pub(crate) key_id: u64,
    pub(crate) sealed: Vec<u8>,
}

impl std::fmt::Debug for BlockDataState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted(bytes) => formatter
                .debug_tuple("Encrypted")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Decrypted(entries) => formatter
                .debug_tuple("Decrypted")
                .field(&format_args!("{} block keys [REDACTED]", entries.len()))
                .finish(),
            Self::Pieces(pieces) => formatter
                .debug_tuple("Pieces")
                .field(&format_args!("{} pieces", pieces.len()))
                .finish(),
        }
    }
}

impl BlockDataState {
    pub(crate) fn encrypt_with_nonce(
        &mut self,
        key: &FileKey,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        match &self {
            BlockDataState::Encrypted(_) | BlockDataState::Pieces(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block already encrypted.".to_string(),
                ));
            }
            BlockDataState::Decrypted(entries) => {
                let mut data_bytes = Zeroizing::new(Vec::with_capacity(10 + entries.len() * 64));
                encode_decrypted_block_list(entries, &mut *data_bytes)?;
                let encrypted_data =
                    crypto::seal_file_block_list_with_nonce(key, &data_bytes, nonce)?;
                *self = BlockDataState::Encrypted(encrypted_data)
            }
        };
        Ok(())
    }
}

/// Rejects a hash listed with two different keys. Sorting indices keeps the extra memory at
/// one index per entry instead of a copy of the list.
pub(crate) fn validate_unique_block_references(
    entries: &[BlockDataEntry],
) -> Result<(), PithosError> {
    if has_conflicting_keys(entries) {
        return Err(PithosError::DuplicateBlockReference);
    }
    Ok(())
}

fn has_conflicting_keys(entries: &[BlockDataEntry]) -> bool {
    let mut order = (0..entries.len()).collect::<Vec<_>>();
    order.sort_unstable_by(|left, right| entries[*left].0.cmp(&entries[*right].0));
    order.windows(2).any(|pair| {
        let (left, right) = (&entries[pair[0]], &entries[pair[1]]);
        left.0 == right.0 && left.1 != right.1
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_type: FileType,
    pub(crate) block_data: BlockDataState,
    pub created: u64,
    pub modified: u64,
    pub file_size: u64,
    pub permissions: u32,
    pub references: Vec<Reference>,
    pub symlink_target: Option<String>,
}

impl Display for FileEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:<12} {:?}\n", "Type:", self.file_type))?;
        match &self.block_data {
            BlockDataState::Encrypted(_) => f.write_str("Blocks:      Encrypted\n")?,
            BlockDataState::Decrypted(_) => f.write_str("Blocks:      Decrypted\n")?,
            BlockDataState::Pieces(_) => f.write_str("Blocks:      Encrypted pieces\n")?,
        }
        f.write_str(&format!("{:<12} {}\n", "Created:", self.created))?;
        f.write_str(&format!("{:<12} {}\n", "Modified:", self.modified))?;
        f.write_str(&format!("{:<12} {}\n", "Size:", self.file_size))?;
        f.write_str(&format!("{:<12} {:o}\n", "Permissions:", self.permissions))?;
        f.write_str(&format!("{:<12} {:?}\n", "References:", self.references))?;
        if let Some(target) = &self.symlink_target {
            f.write_str(&format!("{:<12} {target}\n", "Target:"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub target_file_id: u64,
    pub relationship: u64,
}

fn encode_file_type<W: Write>(
    file_type: &FileType,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_all(&[*file_type as u8])?;
    Ok(())
}

pub(crate) fn decode_file_type<R: Read>(reader: &mut R) -> Result<FileType, DeserializationError> {
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        0 => Ok(FileType::Directory),
        1 => Ok(FileType::Data),
        2 => Ok(FileType::Metadata),
        3 => Ok(FileType::Symlink),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

fn encode_reference<W: Write>(
    reference: &Reference,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_varint(reference.target_file_id)?;
    writer.write_varint(reference.relationship)?;
    Ok(())
}

fn decode_reference<R: Read>(reader: &mut R) -> Result<Reference, DeserializationError> {
    Ok(Reference {
        target_file_id: reader.read_varint::<u64>()?,
        relationship: reader.read_varint::<u64>()?,
    })
}

fn encode_block_data<W: Write>(
    data: &BlockDataState,
    writer: &mut W,
) -> Result<(), SerializationError> {
    match data {
        BlockDataState::Encrypted(bytes) => {
            writer.write_all(&[0])?;
            write_len_prefix(writer, bytes.len())?;
            writer.write_all(bytes)?;
        }
        BlockDataState::Decrypted(entries) => {
            writer.write_all(&[1])?;
            encode_decrypted_block_list(entries, writer)?;
        }
        BlockDataState::Pieces(pieces) => {
            writer.write_all(&[2])?;
            write_len_prefix(writer, pieces.len())?;
            for piece in pieces {
                writer.write_varint(piece.key_id)?;
                write_len_prefix(writer, piece.sealed.len())?;
                writer.write_all(&piece.sealed)?;
            }
        }
    }
    Ok(())
}

fn decode_block_data<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<BlockDataState, DeserializationError> {
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        0 => {
            let len = bounded_len(
                reader.read_varint::<u64>()?,
                limits.max_opaque_bytes,
                "encrypted block",
            )?;
            let mut bytes = Vec::new();
            reserve(&mut bytes, len, "encrypted block")?;
            bytes.resize(len, 0);
            reader.read_exact(&mut bytes)?;
            Ok(BlockDataState::Encrypted(bytes))
        }
        1 => Ok(BlockDataState::Decrypted(
            decode_decrypted_block_list_reader_with_budget(
                reader,
                limits,
                remaining_block_references,
            )?,
        )),
        2 => decode_pieces(reader, limits).map(BlockDataState::Pieces),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

fn decode_pieces<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<Vec<BlockListPiece>, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "block list pieces",
    )?;
    let mut pieces: Vec<BlockListPiece> = Vec::new();
    reserve(&mut pieces, count, "block list pieces")?;
    for _ in 0..count {
        let key_id = reader.read_varint::<u64>()?;
        if pieces.last().is_some_and(|last| last.key_id >= key_id) {
            return Err(DeserializationError::UnorderedPieceKeys);
        }
        let len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_opaque_bytes,
            "sealed block list piece",
        )?;
        let mut sealed = Vec::new();
        reserve(&mut sealed, len, "sealed block list piece")?;
        sealed.resize(len, 0);
        reader.read_exact(&mut sealed)?;
        pieces.push(BlockListPiece { key_id, sealed });
    }
    Ok(pieces)
}

pub(crate) fn encode_file_entry<W: Write>(
    entry: &FileEntry,
    writer: &mut W,
) -> Result<(), SerializationError> {
    encode_file_type(&entry.file_type, writer)?;
    encode_block_data(&entry.block_data, writer)?;
    writer.write_varint(entry.created)?;
    writer.write_varint(entry.modified)?;
    writer.write_varint(entry.file_size)?;
    writer.write_varint(entry.permissions)?;
    write_len_prefix(writer, entry.references.len())?;
    for reference in &entry.references {
        encode_reference(reference, writer)?;
    }
    match &entry.symlink_target {
        Some(target) => {
            writer.write_all(&[1])?;
            crate::format::primitives::encode_string(writer, target)?;
        }
        None => writer.write_all(&[0])?,
    }
    Ok(())
}

pub(crate) fn decode_file_entry<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_references: &mut u64,
    remaining_block_references: &mut u64,
) -> Result<FileEntry, DeserializationError> {
    let file_type = decode_file_type(reader)?;
    let block_data = decode_block_data(reader, limits, remaining_block_references)?;
    let created = reader.read_varint::<u64>()?;
    let modified = reader.read_varint::<u64>()?;
    let file_size = reader.read_varint::<u64>()?;
    let permissions = reader.read_varint::<u32>()?;
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        *remaining_references,
        "references",
    )?;
    *remaining_references -= count as u64;
    let mut references = Vec::new();
    reserve(&mut references, count, "references")?;
    for _ in 0..count {
        references.push(decode_reference(reader)?);
    }
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    let symlink_target = match tag[0] {
        0 => None,
        1 => Some(decode_string(reader, limits)?),
        _ => return Err(DeserializationError::InvalidOption),
    };
    Ok(FileEntry {
        file_type,
        block_data,
        created,
        modified,
        file_size,
        permissions,
        references,
        symlink_target,
    })
}

pub(crate) fn encode_decrypted_block_list<W: Write>(
    entries: &[BlockDataEntry],
    writer: &mut W,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, entries.len())?;
    for (hash, key) in entries {
        writer.write_all(hash)?;
        writer.write_all(key)?;
    }
    Ok(())
}

fn decode_decrypted_block_list_reader_with_budget<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<Zeroizing<Vec<BlockDataEntry>>, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_block_references.min(*remaining_block_references),
        "block references",
    )?;
    *remaining_block_references -= count as u64;
    let mut entries = Zeroizing::new(Vec::new());
    read_block_entries(reader, count, &mut entries)?;
    if has_conflicting_keys(&entries) {
        return Err(DeserializationError::DuplicateBlockReference);
    }
    Ok(entries)
}

/// The nonce and tag around a sealed block list.
const SEALED_LIST_OVERHEAD: usize = 28;

/// The number of entries a sealed list of `sealed_len` bytes holds. Each entry takes 64 bytes
/// after a count of one to ten bytes, so this is exact for every well-formed list.
pub(crate) fn sealed_block_list_capacity(sealed_len: usize) -> usize {
    sealed_len.saturating_sub(SEALED_LIST_OVERHEAD + 1) / BLOCK_ENTRY_LEN
}

const BLOCK_ENTRY_LEN: usize = 64;

/// Reads the entry count of a decrypted list and checks it against the bytes that follow
/// before anything is allocated.
fn read_list_count(
    reader: &mut std::io::Cursor<&[u8]>,
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<usize, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_block_references.min(*remaining_block_references),
        "block references",
    )?;
    let available = reader.get_ref().len() as u64 - reader.position();
    if (count as u64).checked_mul(BLOCK_ENTRY_LEN as u64) != Some(available) {
        return Err(DeserializationError::InvalidLength);
    }
    *remaining_block_references -= count as u64;
    Ok(count)
}

/// Reads `count` entries straight into reserved slots, so keys leave no temporary copies.
fn read_block_entries<R: Read>(
    reader: &mut R,
    count: usize,
    entries: &mut Zeroizing<Vec<BlockDataEntry>>,
) -> Result<(), DeserializationError> {
    reserve_secret(entries, count, "block references")?;
    for _ in 0..count {
        entries.push(([0; 32], [0; 32]));
        let entry = entries.last_mut().expect("just pushed block entry");
        reader.read_exact(&mut entry.0)?;
        reader.read_exact(&mut entry.1)?;
    }
    Ok(())
}

/// Appends one decrypted block list to `entries`. The caller reserves the room for every
/// piece first and checks the combined list for conflicting keys.
pub(crate) fn append_decrypted_block_list(
    bytes: &[u8],
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
    entries: &mut Zeroizing<Vec<BlockDataEntry>>,
) -> Result<(), DeserializationError> {
    let mut reader = std::io::Cursor::new(bytes);
    let count = read_list_count(&mut reader, limits, remaining_block_references)?;
    read_block_entries(&mut reader, count, entries)
}

pub(crate) fn decode_decrypted_block_list_with_budget(
    bytes: &[u8],
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<Zeroizing<Vec<BlockDataEntry>>, DeserializationError> {
    let mut entries = Zeroizing::new(Vec::new());
    append_decrypted_block_list(bytes, limits, remaining_block_references, &mut entries)?;
    if has_conflicting_keys(&entries) {
        return Err(DeserializationError::DuplicateBlockReference);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_list_pieces_round_trip_and_require_increasing_key_ids() {
        let limits = DeserializationLimits::default();
        let pieces = BlockDataState::Pieces(vec![
            BlockListPiece {
                key_id: 1,
                sealed: vec![7; 28],
            },
            BlockListPiece {
                key_id: 300,
                sealed: vec![8; 30],
            },
        ]);
        let mut encoded = Vec::new();
        encode_block_data(&pieces, &mut encoded).unwrap();
        assert_eq!(&encoded[..3], &[2, 2, 1]);
        let mut budget = limits.max_block_references;
        assert_eq!(
            decode_block_data(&mut encoded.as_slice(), &limits, &mut budget).unwrap(),
            pieces
        );

        for key_ids in [[3, 3], [4, 3]] {
            let mut unordered = vec![2, 2];
            for key_id in key_ids {
                unordered.extend_from_slice(&[key_id, 1, 0]);
            }
            assert!(matches!(
                decode_block_data(&mut unordered.as_slice(), &limits, &mut budget),
                Err(DeserializationError::UnorderedPieceKeys)
            ));
        }
        assert!(matches!(
            decode_block_data(&mut [3u8, 0].as_slice(), &limits, &mut budget),
            Err(DeserializationError::InvalidEnumValue(3))
        ));
    }

    #[test]
    fn authenticated_lists_require_exact_consumption_and_unique_keys() {
        let limits = DeserializationLimits::default();
        let mut budget = limits.max_block_references;
        assert!(matches!(
            decode_decrypted_block_list_with_budget(&[0, 0], &limits, &mut budget),
            Err(DeserializationError::InvalidLength)
        ));
        let mut duplicate = vec![2];
        duplicate.extend_from_slice(&[1; 32]);
        duplicate.extend_from_slice(&[2; 32]);
        duplicate.extend_from_slice(&[1; 32]);
        duplicate.extend_from_slice(&[3; 32]);
        let mut budget = limits.max_block_references;
        assert!(matches!(
            decode_decrypted_block_list_with_budget(&duplicate, &limits, &mut budget),
            Err(DeserializationError::DuplicateBlockReference)
        ));
        let mut repeated = vec![2];
        repeated.extend_from_slice(&[1; 32]);
        repeated.extend_from_slice(&[2; 32]);
        repeated.extend_from_slice(&[1; 32]);
        repeated.extend_from_slice(&[2; 32]);
        let mut budget = limits.max_block_references;
        assert_eq!(
            decode_decrypted_block_list_with_budget(&repeated, &limits, &mut budget)
                .unwrap()
                .len(),
            2
        );
    }

    fn sealed_list(count: usize) -> Vec<u8> {
        let entries = (0..count)
            .map(|index| ([index as u8; 32], [1; 32]))
            .collect::<Vec<_>>();
        let mut plaintext = Vec::new();
        encode_decrypted_block_list(&entries, &mut plaintext).unwrap();
        crypto::seal_file_block_list_with_nonce(&FileKey::from_bytes([2; 32]), &plaintext, [3; 12])
            .unwrap()
    }

    #[test]
    fn piece_lists_fill_one_reservation_without_moving() {
        for count in [0, 1, 127, 128, 300] {
            assert_eq!(sealed_block_list_capacity(sealed_list(count).len()), count);
        }
        let limits = DeserializationLimits::default();
        let mut budget = limits.max_block_references;
        let lists = [sealed_list(127), sealed_list(130)];
        let capacity = lists
            .iter()
            .map(|sealed| sealed_block_list_capacity(sealed.len()))
            .sum();
        let mut entries = Zeroizing::new(Vec::new());
        reserve_secret(&mut entries, capacity, "block references").unwrap();
        let buffer = entries.as_ptr();
        for sealed in &lists {
            let plaintext =
                crypto::open_file_block_list(&FileKey::from_bytes([2; 32]), sealed.clone())
                    .unwrap();
            append_decrypted_block_list(&plaintext, &limits, &mut budget, &mut entries).unwrap();
        }
        assert_eq!(entries.len(), 257);
        assert_eq!(entries.as_ptr(), buffer);
    }

    #[test]
    fn list_counts_must_match_the_remaining_bytes_before_allocation() {
        let limits = DeserializationLimits::default();
        let mut budget = limits.max_block_references;
        let mut claimed = Vec::new();
        claimed.write_varint(1_000_000u64).unwrap();
        claimed.extend_from_slice(&[0; 64]);
        assert!(matches!(
            decode_decrypted_block_list_with_budget(&claimed, &limits, &mut budget),
            Err(DeserializationError::InvalidLength)
        ));
        assert_eq!(budget, limits.max_block_references);
        let mut entries = Zeroizing::new(Vec::new());
        assert!(matches!(
            append_decrypted_block_list(&claimed, &limits, &mut budget, &mut entries),
            Err(DeserializationError::InvalidLength)
        ));
        assert_eq!(entries.capacity(), 0);
    }

    #[test]
    fn permission_field_uses_u32_varint_width() {
        assert!(
            (&[0x80, 0x80, 0x80, 0x80, 0x10][..])
                .read_varint::<u32>()
                .is_err()
        );
    }

    #[test]
    fn transient_plaintext_key_lists_have_drop_zeroization_contracts() {
        use zeroize::ZeroizeOnDrop;
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<Zeroizing<Vec<BlockDataEntry>>>();
        assert_zeroize_on_drop::<crate::format::encryption::RecipientKeyList>();
    }
}

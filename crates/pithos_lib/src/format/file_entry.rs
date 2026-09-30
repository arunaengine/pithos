use crate::crypto::{self, FileKey};
use crate::error::PithosError;
use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::primitives::{bounded_len, decode_string, reserve, write_len_prefix};
use integer_encoding::{VarIntReader, VarIntWriter};
use std::collections::HashMap;
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
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block already encrypted.".to_string(),
                ));
            }
            BlockDataState::Decrypted(entries) => {
                let mut data_bytes = Zeroizing::new(Vec::with_capacity(1 + entries.len() * 64));
                encode_decrypted_block_list(entries, &mut *data_bytes)?;
                let encrypted_data =
                    crypto::seal_file_block_list_with_nonce(key, &data_bytes, nonce)?;
                *self = BlockDataState::Encrypted(encrypted_data)
            }
        };
        Ok(())
    }
}

pub(crate) fn validate_unique_block_references(
    entries: &[BlockDataEntry],
) -> Result<(), PithosError> {
    let mut keys = HashMap::with_capacity(entries.len());
    for (hash, key) in entries {
        if keys
            .insert(*hash, *key)
            .is_some_and(|existing| existing != *key)
        {
            return Err(PithosError::DuplicateBlockReference);
        }
    }
    Ok(())
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
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
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
    reserve(&mut entries, count, "block references")?;
    let mut keys = HashMap::with_capacity(count);
    for _ in 0..count {
        let mut hash = [0; 32];
        reader.read_exact(&mut hash)?;
        let mut key = [0; 32];
        reader.read_exact(&mut key)?;
        if keys
            .insert(hash, key)
            .is_some_and(|existing| existing != key)
        {
            return Err(DeserializationError::DuplicateBlockReference);
        }
        entries.push((hash, key));
    }
    Ok(entries)
}

pub(crate) fn decode_decrypted_block_list_with_budget(
    bytes: &[u8],
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<Zeroizing<Vec<BlockDataEntry>>, DeserializationError> {
    let mut reader = std::io::Cursor::new(bytes);
    let entries = decode_decrypted_block_list_reader_with_budget(
        &mut reader,
        limits,
        remaining_block_references,
    )?;
    if reader.position() != bytes.len() as u64 {
        return Err(DeserializationError::InvalidLength);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

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

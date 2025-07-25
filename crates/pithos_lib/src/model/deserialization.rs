// Deserialization implementations for PITHOS structs and enums.
// Extracted from helpers/structs.rs for modularity.
//
// - Varint decoding uses integer_encoding::VarIntReader
// - Multi-byte values use big-endian decoding
// - Strings: UTF-8 with varint length prefix
// - Error handling via DeserializationError

use crate::helpers::chacha_poly1305::{decrypt_chunk, encrypt_chunk};
use crate::model::structs::*;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::io::{Error as IoError, Read, Write};
use byteorder::ReadBytesExt;
use thiserror::Error;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zstd::zstd_safe::WriteBuf;

/// Custom error type for deserialization operations
#[derive(Error, Debug)]
pub enum DeserializationError {
    /// I/O error during deserialization
    #[error("I/O error: {0}")]
    Io(IoError),
    /// UTF-8 decoding error
    #[error("UTF-8 decoding error: {0}")]
    Utf8(std::string::FromUtf8Error),
    /// Invalid enum value encountered
    #[error("Invalid enum value: {0}")]
    InvalidEnumValue(u8),
    /// Invalid option encountered
    #[error("Invalid option")]
    InvalidOption,
    /// Invalid length encountered
    #[error("Invalid length")]
    InvalidLength,
}

impl From<IoError> for DeserializationError {
    fn from(e: IoError) -> Self {
        DeserializationError::Io(e)
    }
}
impl From<std::string::FromUtf8Error> for DeserializationError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        DeserializationError::Utf8(e)
    }
}

// Helper: decode big-endian u16/u32/u64
pub fn decode_u16_be<R: Read>(reader: &mut R) -> Result<u16, DeserializationError> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}
pub fn decode_u32_be<R: Read>(reader: &mut R) -> Result<u32, DeserializationError> {
    let mut buf = [0u8; 4];
    reader.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}
pub fn decode_u64_be<R: Read>(reader: &mut R) -> Result<u64, DeserializationError> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf)?;
    Ok(u64::from_be_bytes(buf))
}

// Helper: decode string (UTF-8 with varint length prefix)
pub fn decode_string<R: Read>(reader: &mut R) -> Result<String, DeserializationError> {
    let len = reader.read_varint::<u64>()?;
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

// FileHeader
impl FileHeader {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        let version = decode_u16_be(reader)?;
        Ok(FileHeader { magic, version })
    }
}

// BlockHeader
impl BlockHeader {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut marker = [0u8; 4];
        reader.read_exact(&mut marker)?;
        Ok(BlockHeader { marker })
    }
}

// ProcessingFlags
impl ProcessingFlags {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(ProcessingFlags(buf[0]))
    }
}

// BlockLocation
impl BlockLocation {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(BlockLocation::Local),
            1 => {
                let url = decode_string(reader)?;
                Ok(BlockLocation::External { url })
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }
}

// BlockIndexEntry
impl BlockIndexEntry {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let index = reader.read_varint::<u64>()?;
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let offset = reader.read_varint::<u64>()?;
        let stored_size = reader.read_varint::<u64>()?;
        let original_size = reader.read_varint::<u64>()?;
        let flags = ProcessingFlags::deserialize(reader)?;
        let location = BlockLocation::deserialize(reader)?;
        Ok(BlockIndexEntry {
            index,
            hash,
            offset,
            stored_size,
            original_size,
            flags,
            location,
        })
    }
}

// Directory
impl Directory {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut identifier = [0u8; 8];
        reader.read_exact(&mut identifier)?;
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        let parent_directory_offset = match tag[0] {
            0 => None,
            1 => {
                let start = reader.read_varint::<u64>()?;
                let len = reader.read_varint::<u64>()?;
                Some((start, len))
            }
            _ => return Err(DeserializationError::InvalidOption),
        };
        let files_len = reader.read_varint::<u64>()?;
        let mut files = Vec::with_capacity(files_len as usize);
        for _ in 0..files_len {
            files.push(FileEntry::deserialize(reader)?);
        }
        let blocks_len = reader.read_varint::<u64>()?;
        let mut blocks = Vec::with_capacity(blocks_len as usize);
        for _ in 0..blocks_len {
            blocks.push(BlockIndexEntry::deserialize(reader)?);
        }
        let relations_len = reader.read_varint::<u64>()?;
        let mut relations = Vec::with_capacity(relations_len as usize);
        for _ in 0..relations_len {
            let idx = reader.read_varint::<u64>()?;
            let name = decode_string(reader)?;
            relations.push((idx, name));
        }
        let encryption_len = reader.read_varint::<u64>()?;
        let mut encryption = Vec::with_capacity(encryption_len as usize);
        for _ in 0..encryption_len {
            encryption.push(EncryptionSection::deserialize(reader)?);
        }
        let dir_len = reader.read_varint::<u64>()?;
        let crc32 = decode_u32_be(reader)?;
        Ok(Directory {
            identifier,
            parent_directory_offset,
            files,
            blocks,
            relations,
            encryption,
            dir_len,
            crc32,
        })
    }
}

// FileType
impl FileType {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            0 => Ok(FileType::Data),
            1 => Ok(FileType::Metadata),
            2 => Ok(FileType::Directory),
            3 => Ok(FileType::Symlink),
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }
}

// BlockDataState
impl BlockDataState {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => {
                let len = reader.read_varint::<u64>()?;
                let mut buf = vec![0u8; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(BlockDataState::Encrypted(buf))
            }
            1 => {
                let list_len = reader.read_varint::<u64>()?;
                let mut list = Vec::with_capacity(list_len as usize);
                for _ in 0..list_len {
                    let idx = reader.read_varint::<u64>()?;
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    list.push((idx, hash));
                }
                Ok(BlockDataState::Decrypted(list))
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }
}

// FileEntry
impl FileEntry {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let file_id = reader.read_varint::<u64>()?;
        let path = decode_string(reader)?;
        let file_type = FileType::deserialize(reader)?;
        let block_data = BlockDataState::deserialize(reader)?;
        let created = decode_u64_be(reader)?;
        let modified = decode_u64_be(reader)?;
        let file_size = reader.read_varint::<u64>()?;
        let permissions = decode_u32_be(reader)?;
        let refs_len = reader.read_varint::<u64>()?;
        let mut references = Vec::with_capacity(refs_len as usize);
        for _ in 0..refs_len {
            references.push(Reference::deserialize(reader)?);
        }
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        let symlink_target = match tag[0] {
            0 => None,
            1 => Some(decode_string(reader)?),
            _ => return Err(DeserializationError::InvalidOption),
        };
        Ok(FileEntry {
            file_id,
            path,
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
}

// Reference
impl Reference {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let target_file_id = reader.read_varint::<u64>()?;
        let relationship = reader.read_varint::<u64>()?;
        Ok(Reference {
            target_file_id,
            relationship,
        })
    }
}

// EncryptionSection
impl EncryptionSection {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut sender_public_key = [0u8; 32];
        reader.read_exact(&mut sender_public_key)?;
        let recipients_len = reader.read_varint::<u64>()?;
        let mut recipients = Vec::with_capacity(recipients_len as usize);
        for _ in 0..recipients_len {
            recipients.push(RecipientSection::deserialize(reader)?);
        }
        Ok(EncryptionSection {
            sender_public_key,
            recipients,
        })
    }
}

// RecipientData
impl RecipientData {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;

        match tag[0] {
            0 => {
                let len = reader.read_varint::<u64>()?;
                let mut buf = vec![0u8; len as usize];
                reader.read_exact(&mut buf)?;
                Ok(RecipientData::Encrypted(buf))
            }
            1 => {
                let list_len = reader.read_varint::<u64>()?;
                dbg!(&list_len);
                let mut list = Vec::with_capacity(list_len as usize);
                for _ in 0..list_len {
                    let mut idx_buf = [0u8; 8];
                    reader.read_exact(&mut idx_buf)?;
                    let idx = u64::from_be_bytes(idx_buf); //reader.read_varint::<u64>()?;
                    dbg!(&idx);
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    list.push((idx, hash));
                }
                Ok(RecipientData::Decrypted(list))
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }

    pub fn decrypt(&mut self, shared_key: &SharedSecret) -> anyhow::Result<()> {
        match &self {
            RecipientData::Decrypted(_) => {
                // Do nothing, already decrypted
            }
            RecipientData::Encrypted(enc_data) => {
                let dec_data = decrypt_chunk(enc_data, shared_key.as_bytes())?;
                dbg!(dec_data.len());
                let recipient_data = RecipientData::deserialize(&mut dec_data.as_slice())?;
                dbg!(&recipient_data);

                *self = recipient_data
            }
        };

        Ok(())
    }
}

// RecipientSection
impl RecipientSection {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut recipient_public_key = [0u8; 32];
        reader.read_exact(&mut recipient_public_key)?;
        let recipient_data = RecipientData::deserialize(reader)?;
        Ok(RecipientSection {
            recipient_public_key,
            recipient_data,
        })
    }
}

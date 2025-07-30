// Deserialization implementations for PITHOS structs and enums.
// Extracted from helpers/structs.rs for modularity.
//
// - Varint decoding uses integer_encoding::VarIntReader
// - Multi-byte values use big-endian decoding
// - Strings: UTF-8 with varint length prefix
// - Error handling via DeserializationError

use crate::helpers::chacha_poly1305::decrypt_chunk;
use crate::model::structs::*;
use byteorder::{BigEndian, ReadBytesExt};
use integer_encoding::VarIntReader;
use std::io::{Error as IoError, Read};
use thiserror::Error;
use x25519_dalek::SharedSecret;

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
    #[error("Invalid marker: {0}")]
    InvalidMarker(String),
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

// Helper: decode string (UTF-8 with varint length prefix)
pub fn decode_string<R: Read>(reader: &mut R) -> Result<String, DeserializationError> {
    let len = reader.read_varint()?;
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

// FileHeader
impl FileHeader {
    const FILE_HEADER_MARKER: [u8; 4] = *b"PITH";

    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut marker = [0u8; 4];
        reader.read_exact(&mut marker)?;

        // Validate correct file header marker
        if marker != Self::FILE_HEADER_MARKER {
            return Err(DeserializationError::InvalidMarker(format!(
                "Read invalid block marker {marker:?}"
            )));
        }

        let version: u16 = reader.read_varint()?;
        Ok(FileHeader {
            magic: marker,
            version,
        })
    }
}

// BlockHeader
impl BlockHeader {
    const BLOCK_HEADER_MARKER: [u8; 4] = *b"BLCK";
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut marker = [0u8; 4];
        reader.read_exact(&mut marker)?;

        if marker != Self::BLOCK_HEADER_MARKER {
            return Err(DeserializationError::InvalidMarker(format!(
                "Read invalid block marker {marker:?}"
            )));
        }

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
        let index: u64 = reader.read_varint()?;
        let mut hash = [0u8; 32];
        reader.read_exact(&mut hash)?;
        let offset: u64 = reader.read_varint()?;
        let stored_size: u64 = reader.read_varint()?;
        let original_size: u64 = reader.read_varint()?;
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
        // Read static directory identifier
        let mut identifier = [0u8; 8];
        reader.read_exact(&mut identifier)?;

        // Read parent directory offset
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

        // Read file entries
        let files_len = reader.read_varint()?;
        let mut files = Vec::with_capacity(files_len);
        for _ in 0..files_len {
            files.push(FileEntry::deserialize(reader)?);
        }

        let blocks_len = reader.read_varint()?;
        let mut blocks = Vec::with_capacity(blocks_len);
        for _ in 0..blocks_len {
            blocks.push(BlockIndexEntry::deserialize(reader)?);
        }

        let relations_len = reader.read_varint()?;
        let mut relations = Vec::with_capacity(relations_len);
        for _ in 0..relations_len {
            let idx = reader.read_varint::<u64>()?;
            let name = decode_string(reader)?;
            relations.push((idx, name));
        }

        let encryption_len = reader.read_varint()?;
        let mut encryption = Vec::with_capacity(encryption_len);
        for _ in 0..encryption_len {
            encryption.push(EncryptionSection::deserialize(reader)?);
        }

        let dir_len = reader.read_u64::<BigEndian>()?;
        let crc32 = reader.read_u32::<BigEndian>()?;

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
                let len = reader.read_varint()?;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                Ok(BlockDataState::Encrypted(buf))
            }
            1 => {
                let list_len = reader.read_varint()?;
                let mut list = Vec::with_capacity(list_len);
                for _ in 0..list_len {
                    let idx: u64 = reader.read_varint()?;
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    list.push((idx, hash));
                }
                Ok(BlockDataState::Decrypted(list))
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }

    pub fn deserialize_block_index<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<(u64, [u8; 32])>, DeserializationError> {
        let list_len = reader.read_varint()?;
        let mut list = Vec::with_capacity(list_len);
        for _ in 0..list_len {
            let idx: u64 = reader.read_varint()?;
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            list.push((idx, key));
        }

        Ok(list)
    }

    pub fn decrypt(&mut self, key: &[u8; 32]) -> anyhow::Result<()> {
        match &self {
            BlockDataState::Encrypted(data) => {
                let decrypted_bytes = decrypt_chunk(data, key)?;
                let block_data_entries =
                    self.deserialize_block_index(&mut decrypted_bytes.as_slice())?;

                *self = BlockDataState::Decrypted(block_data_entries);
            }
            BlockDataState::Decrypted(_) => {
                // Nothing to do
            }
        }

        Ok(())
    }
}

// FileEntry
impl FileEntry {
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let file_id: u64 = reader.read_varint()?;
        let path = decode_string(reader)?;
        let file_type = FileType::deserialize(reader)?;
        let block_data = BlockDataState::deserialize(reader)?;
        let created: u64 = reader.read_varint()?;
        let modified: u64 = reader.read_varint()?;
        let file_size: u64 = reader.read_varint()?;
        let permissions: u32 = reader.read_varint()?;
        let refs_len = reader.read_varint()?;
        let mut references = Vec::with_capacity(refs_len);
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
        let target_file_id: u64 = reader.read_varint()?;
        let relationship: u64 = reader.read_varint()?;
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

        let recipients_len = reader.read_varint()?;
        let mut recipients = Vec::with_capacity(recipients_len);
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
                let len = reader.read_varint()?;
                let mut buf = vec![0u8; len];
                reader.read_exact(&mut buf)?;
                Ok(RecipientData::Encrypted(buf))
            }
            1 => {
                let list_len = reader.read_varint()?;
                let mut list = Vec::with_capacity(list_len);
                for _ in 0..list_len {
                    let idx: u64 = reader.read_varint()?;
                    let mut key = [0u8; 32];
                    reader.read_exact(&mut key)?;
                    list.push((idx, key));
                }
                Ok(RecipientData::Decrypted(list))
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }

    pub fn deserialize_decrypted_list<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<(u64, [u8; 32])>, DeserializationError> {
        let list_len = reader.read_varint()?;
        let mut list = Vec::with_capacity(list_len);
        for _ in 0..list_len {
            let idx: u64 = reader.read_varint()?;
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            list.push((idx, key));
        }

        Ok(list)
    }

    pub fn decrypt(&mut self, shared_key: &SharedSecret) -> anyhow::Result<Vec<(u64, [u8; 32])>> {
        let entries = match &self {
            RecipientData::Decrypted(entries) => entries.clone(),
            RecipientData::Encrypted(enc_data) => {
                let dec_data = decrypt_chunk(enc_data, shared_key.as_bytes())?;
                let entries = self.deserialize_decrypted_list(&mut dec_data.as_slice())?;

                *self = RecipientData::Decrypted(entries.clone());
                entries
            }
        };

        Ok(entries)
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

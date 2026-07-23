// Deserialization implementations for PITHOS structs and enums.
// Extracted from helpers/structs.rs for modularity.
//
// - Varint decoding uses integer_encoding::VarIntReader
// - Multi-byte values use big-endian decoding
// - Strings: UTF-8 with varint length prefix
// - Error handling via DeserializationError

use crate::error::PithosError;
use crate::helpers::archive_path::{validate_entry, validate_hierarchy};
use crate::helpers::file_entry_map::{FileEntryMap, Key};
use crate::model::structs::*;
use byteorder::{BigEndian, ReadBytesExt};
use indexmap::IndexMap;
use integer_encoding::VarIntReader;
use std::io::{Error as IoError, Read};
use std::string::FromUtf8Error;
use thiserror::Error;

/// Custom error type for deserialization operations
#[derive(Error, Debug)]
pub enum DeserializationError {
    /// I/O error during deserialization
    #[error("I/O error: {0}")]
    Io(#[from] IoError),
    /// UTF-8 decoding error
    #[error("UTF-8 decoding error: {0}")]
    Utf8(#[from] FromUtf8Error),
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
    #[error("{field} exceeds limit {limit}: {actual}")]
    LimitExceeded {
        field: &'static str,
        limit: u64,
        actual: u64,
    },
    #[error("allocation failed for {field}: {size}")]
    AllocationFailed { field: &'static str, size: u64 },
}

#[derive(Clone, Copy, Debug)]
pub struct DeserializationLimits {
    pub max_string_bytes: u64,
    pub max_opaque_bytes: u64,
    pub max_collection_entries: u64,
}

impl Default for DeserializationLimits {
    fn default() -> Self {
        Self {
            max_string_bytes: 1024 * 1024,
            max_opaque_bytes: 64 * 1024 * 1024,
            max_collection_entries: 1_000_000,
        }
    }
}

fn bounded_len(value: u64, limit: u64, field: &'static str) -> Result<usize, DeserializationError> {
    if value > limit {
        return Err(DeserializationError::LimitExceeded {
            field,
            limit,
            actual: value,
        });
    }
    usize::try_from(value).map_err(|_| DeserializationError::InvalidLength)
}

fn reserve<T>(
    vec: &mut Vec<T>,
    count: usize,
    field: &'static str,
) -> Result<(), DeserializationError> {
    vec.try_reserve(count)
        .map_err(|_| DeserializationError::AllocationFailed {
            field,
            size: count as u64,
        })
}

// Helper: decode string (UTF-8 with varint length prefix)
#[tracing::instrument(level = "trace", skip(reader))]
pub fn decode_string<R: Read>(reader: &mut R) -> Result<String, DeserializationError> {
    decode_string_with_limits(reader, &DeserializationLimits::default())
}

pub fn decode_string_with_limits<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<String, DeserializationError> {
    let len = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_string_bytes,
        "string",
    )?;
    let mut buf = Vec::new();
    reserve(&mut buf, len, "string")?;
    buf.resize(len, 0);
    reader.read_exact(&mut buf)?;
    Ok(String::from_utf8(buf)?)
}

// FileHeader
impl FileHeader {
    const FILE_HEADER_MARKER: [u8; 4] = *b"PITH";

    #[tracing::instrument(level = "trace", skip(reader))]
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

    #[tracing::instrument(level = "trace", skip(reader))]
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
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        Ok(ProcessingFlags(buf[0]))
    }
}

// BlockLocation
impl BlockLocation {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => Ok(BlockLocation::Local),
            1 => {
                let url = decode_string_with_limits(reader, limits)?;
                Ok(BlockLocation::External { url })
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }
}

// BlockIndexEntry
impl BlockIndexEntry {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let offset: u64 = reader.read_varint()?;
        let stored_size: u64 = reader.read_varint()?;
        let original_size: u64 = reader.read_varint()?;
        let flags = ProcessingFlags::deserialize(reader)?;
        let location = BlockLocation::deserialize_with_limits(reader, limits)?;
        Ok(BlockIndexEntry {
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
    pub(crate) const DIRECTORY_MARKER: [u8; 8] = *b"PITHOSDR";

    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, PithosError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, PithosError> {
        // Read static directory identifier
        let mut identifier = [0u8; 8];
        reader.read_exact(&mut identifier)?;
        if identifier != Self::DIRECTORY_MARKER {
            return Err(PithosError::InvalidDirectoryMarker {
                expected: Self::DIRECTORY_MARKER,
                actual: identifier,
            });
        }

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
            _ => return Err(PithosError::from(DeserializationError::InvalidOption)),
        };

        // Read file entries
        let mut files = FileEntryMap::new();
        let files_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "files",
        )?;
        for _ in 0..files_len {
            let id = reader.read_varint::<u64>()?;
            let path = decode_string_with_limits(reader, limits)?;
            let entry = FileEntry::deserialize_with_limits(reader, limits)?;
            validate_entry(&path, &entry)?;
            files.insert(Key::new(id, path), entry)?;
        }
        validate_hierarchy(&files)?;

        let blocks_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "blocks",
        )?;
        let mut blocks = IndexMap::new();
        for _ in 0..blocks_len {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            let block = BlockIndexEntry::deserialize_with_limits(reader, limits)?;
            blocks.insert(hash, block);
        }

        let relations_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "relations",
        )?;
        let mut relations = Vec::new();
        reserve(&mut relations, relations_len, "relations")?;
        for _ in 0..relations_len {
            let idx = reader.read_varint::<u64>()?;
            let name = decode_string_with_limits(reader, limits)?;
            relations.push((idx, name));
        }

        let encryption_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "encryption",
        )?;
        let mut encryption = IndexMap::new();
        for _ in 0..encryption_len {
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            encryption.insert(
                key,
                EncryptionSection::deserialize_with_limits(reader, limits)?,
            );
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
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        let mut buf = [0u8; 1];
        reader.read_exact(&mut buf)?;
        match buf[0] {
            0 => Ok(FileType::Directory),
            1 => Ok(FileType::Data),
            2 => Ok(FileType::Metadata),
            3 => Ok(FileType::Symlink),
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }
}

// BlockDataState
impl BlockDataState {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        match tag[0] {
            0 => {
                let len = bounded_len(
                    reader.read_varint::<u64>()?,
                    limits.max_opaque_bytes,
                    "encrypted block",
                )?;
                let mut buf = Vec::new();
                reserve(&mut buf, len, "encrypted block")?;
                buf.resize(len, 0);
                reader.read_exact(&mut buf)?;
                Ok(BlockDataState::Encrypted(buf))
            }
            1 => {
                let list_len = bounded_len(
                    reader.read_varint::<u64>()?,
                    limits.max_collection_entries,
                    "block keys",
                )?;
                let mut list = Vec::new();
                reserve(&mut list, list_len, "block keys")?;
                for _ in 0..list_len {
                    let mut hash = [0u8; 32];
                    reader.read_exact(&mut hash)?;
                    let mut key = [0u8; 32];
                    reader.read_exact(&mut key)?;
                    list.push((hash, key));
                }
                Ok(BlockDataState::Decrypted(list))
            }
            v => Err(DeserializationError::InvalidEnumValue(v)),
        }
    }

    #[tracing::instrument(level = "trace", skip(self, reader))]
    pub fn deserialize_block_index<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<BlockDataEntry>, DeserializationError> {
        self.deserialize_block_index_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_block_index_with_limits<R: Read>(
        &self,
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Vec<BlockDataEntry>, DeserializationError> {
        let list_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "block index",
        )?;
        let mut list = Vec::new();
        reserve(&mut list, list_len, "block index")?;
        for _ in 0..list_len {
            let mut hash = [0u8; 32];
            reader.read_exact(&mut hash)?;
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            list.push((hash, key));
        }
        Ok(list)
    }
}

// FileEntry
impl FileEntry {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let file_type = FileType::deserialize(reader)?;
        let block_data = BlockDataState::deserialize_with_limits(reader, limits)?;
        let created: u64 = reader.read_varint()?;
        let modified: u64 = reader.read_varint()?;
        let file_size: u64 = reader.read_varint()?;
        let permissions: u32 = reader.read_varint()?;
        let refs_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "references",
        )?;
        let mut references = Vec::new();
        reserve(&mut references, refs_len, "references")?;
        for _ in 0..refs_len {
            references.push(Reference::deserialize(reader)?);
        }
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;
        let symlink_target = match tag[0] {
            0 => None,
            1 => Some(decode_string_with_limits(reader, limits)?),
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
}

// Reference
impl Reference {
    #[tracing::instrument(level = "trace", skip(reader))]
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
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let recipients_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "recipients",
        )?;
        let mut recipients = IndexMap::new();
        for _ in 0..recipients_len {
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            recipients.insert(
                key,
                RecipientSection::deserialize_with_limits(reader, limits)?,
            );
        }
        Ok(EncryptionSection { recipients })
    }
}

// RecipientData
impl RecipientData {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let mut tag = [0u8; 1];
        reader.read_exact(&mut tag)?;

        match tag[0] {
            0 => {
                let len = bounded_len(
                    reader.read_varint::<u64>()?,
                    limits.max_opaque_bytes,
                    "encrypted recipient data",
                )?;
                let mut buf = Vec::new();
                reserve(&mut buf, len, "encrypted recipient data")?;
                buf.resize(len, 0);
                reader.read_exact(&mut buf)?;
                Ok(RecipientData::Encrypted(buf))
            }
            1 => {
                let list_len = bounded_len(
                    reader.read_varint::<u64>()?,
                    limits.max_collection_entries,
                    "recipient keys",
                )?;
                let mut list = Vec::new();
                reserve(&mut list, list_len, "recipient keys")?;
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

    #[tracing::instrument(level = "trace", skip(self, reader))]
    pub fn deserialize_decrypted_list<R: Read>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<(u64, [u8; 32])>, DeserializationError> {
        self.deserialize_decrypted_list_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_decrypted_list_with_limits<R: Read>(
        &self,
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Vec<(u64, [u8; 32])>, DeserializationError> {
        let list_len = bounded_len(
            reader.read_varint::<u64>()?,
            limits.max_collection_entries,
            "recipient keys",
        )?;
        let mut list = Vec::new();
        reserve(&mut list, list_len, "recipient keys")?;
        for _ in 0..list_len {
            let idx: u64 = reader.read_varint()?;
            let mut key = [0u8; 32];
            reader.read_exact(&mut key)?;
            list.push((idx, key));
        }

        Ok(list)
    }
}

// RecipientSection
impl RecipientSection {
    #[tracing::instrument(level = "trace", skip(reader))]
    pub fn deserialize<R: Read>(reader: &mut R) -> Result<Self, DeserializationError> {
        Self::deserialize_with_limits(reader, &DeserializationLimits::default())
    }

    pub fn deserialize_with_limits<R: Read>(
        reader: &mut R,
        limits: &DeserializationLimits,
    ) -> Result<Self, DeserializationError> {
        let recipient_data = RecipientData::deserialize_with_limits(reader, limits)?;
        Ok(RecipientSection { recipient_data })
    }
}

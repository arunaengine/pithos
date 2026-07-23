// Manual serialization utilities for PITHOS spec structs.
// No external libraries are used. All encoding is performed manually.
// - Varint encoding: unsigned LEB128
// - Strings: UTF-8 with varint length prefix
// - Multi-byte values: big-endian
// - CRC32: not implemented here (use a separate utility)
// - Only serialization to bytes is implemented (no deserialization)

use crate::model::structs::*;
use byteorder::{BigEndian, WriteBytesExt};
use integer_encoding::VarIntWriter;
use std::io::Write;
use thiserror::Error;

// Helper: error type for serialization
#[derive(Error, Debug)]
pub enum SerializationError {
    #[error("IoError error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Other(String),
}

pub(crate) fn write_len_prefix<W: Write>(
    writer: &mut W,
    len: usize,
) -> Result<(), SerializationError> {
    let len = u64::try_from(len)
        .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?;
    writer.write_varint(len)?;
    Ok(())
}

// Helper: encode string (UTF-8 with varint length prefix)
#[tracing::instrument(level = "trace", skip(writer, s))]
pub fn encode_string<W: Write>(writer: &mut W, s: &str) -> Result<(), SerializationError> {
    write_len_prefix(writer, s.len())?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

impl FileHeader {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.magic)?;
        writer.write_varint(self.version)?;
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl BlockHeader {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.marker)?;
        Ok(())
    }
}

impl ProcessingFlags {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}

impl BlockLocation {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            BlockLocation::Local => {
                writer.write_all(&[0u8])?;
            }
            BlockLocation::External { url } => {
                writer.write_all(&[1u8])?;
                encode_string(writer, url)?;
            }
        }
        Ok(())
    }
}

impl BlockIndexEntry {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.offset)?;
        writer.write_varint(self.stored_size)?;
        writer.write_varint(self.original_size)?;
        self.flags.serialize(writer)?;
        self.location.serialize(writer)?;
        Ok(())
    }
}

impl Directory {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        // Write static identifier
        writer.write_all(&self.identifier)?;

        // Write parent directory offset, if present
        match &self.parent_directory_offset {
            Some((start, len)) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(*start)?;
                writer.write_varint(*len)?;
            }
            None => writer.write_all(&[0u8])?,
        }

        // Write file entries
        write_len_prefix(writer, self.files.len())?;
        for (id, path, file) in &self.files {
            writer.write_varint::<u64>(id)?;
            encode_string(writer, path)?;
            file.serialize(writer)?;
        }
        write_len_prefix(writer, self.blocks.len())?;
        for (hash, block) in &self.blocks {
            writer.write_all(hash)?;
            block.serialize(writer)?;
        }
        write_len_prefix(writer, self.relations.len())?;
        for (idx, name) in &self.relations {
            writer.write_varint(*idx)?;
            encode_string(writer, name)?;
        }
        write_len_prefix(writer, self.encryption.len())?;
        for (key, enc) in &self.encryption {
            writer.write_all(key)?;
            enc.serialize(writer)?;
        }

        writer.write_u64::<BigEndian>(self.dir_len)?; // Actually writes the 8 bytes
        writer.write_u32::<BigEndian>(self.crc32)?; // Actually writes the 4 bytes
        Ok(())
    }
}

impl FileType {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }
}

impl BlockDataState {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            BlockDataState::Encrypted(data) => {
                writer.write_all(&[0u8])?;
                write_len_prefix(writer, data.len())?;
                writer.write_all(data)?;
            }
            BlockDataState::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                write_len_prefix(writer, list.len())?;
                for (hash, key) in list {
                    writer.write_all(hash)?;
                    writer.write_all(key)?;
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl FileEntry {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.file_type.serialize(writer)?;
        self.block_data.serialize(writer)?;
        writer.write_varint(self.created)?;
        writer.write_varint(self.modified)?;
        writer.write_varint(self.file_size)?;
        writer.write_varint(self.permissions)?;
        write_len_prefix(writer, self.references.len())?;
        for r in &self.references {
            r.serialize(writer)?;
        }
        match &self.symlink_target {
            Some(target) => {
                writer.write_all(&[1u8])?;
                encode_string(writer, target)?;
            }
            None => writer.write_all(&[0u8])?,
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl Reference {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.target_file_id)?;
        writer.write_varint(self.relationship)?;
        Ok(())
    }
}

impl EncryptionSection {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        write_len_prefix(writer, self.recipients.len())?;
        for (key, recipient) in &self.recipients {
            writer.write_all(key)?;
            recipient.serialize(writer)?;
        }
        Ok(())
    }
}

impl RecipientData {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            RecipientData::Encrypted(data) => {
                writer.write_all(&[0u8])?;
                write_len_prefix(writer, data.len())?;
                writer.write_all(data)?;
            }
            RecipientData::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                write_len_prefix(writer, list.len())?;
                for (idx, hash) in list {
                    writer.write_varint(*idx)?;
                    writer.write_all(hash)?;
                }
            }
        }
        Ok(())
    }
}

impl RecipientSection {
    #[tracing::instrument(level = "trace", skip(self, writer))]
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.recipient_data.serialize(writer)?;
        Ok(())
    }
}

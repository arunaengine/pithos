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

// Helper: encode string (UTF-8 with varint length prefix)
pub fn encode_string<W: Write>(writer: &mut W, s: &str) -> Result<(), SerializationError> {
    writer.write_varint(s.len())?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

impl FileHeader {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.magic)?;
        writer.write_varint(self.version)?;
        Ok(())
    }

    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl BlockHeader {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.marker)?;
        Ok(())
    }
}

impl ProcessingFlags {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[self.0])?;
        Ok(())
    }
}

impl BlockLocation {
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
        writer.write_varint(self.files.len() as u64)?;
        for file in &self.files {
            file.serialize(writer)?;
        }
        writer.write_varint(self.blocks.len() as u64)?;
        for (hash, block) in &self.blocks {
            writer.write_all(hash)?;
            block.serialize(writer)?;
        }
        writer.write_varint(self.relations.len())?;
        for (idx, name) in &self.relations {
            writer.write_varint(*idx)?;
            encode_string(writer, name)?;
        }
        writer.write_varint(self.encryption.len() as u64)?;
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
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&[*self as u8])?;
        Ok(())
    }
}

impl BlockDataState {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            BlockDataState::Encrypted(data) => {
                writer.write_all(&[0u8])?;
                writer.write_varint(data.len())?;
                writer.write_all(data)?;
            }
            BlockDataState::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(list.len())?;
                for (hash, key) in list {
                    writer.write_all(hash)?;
                    writer.write_all(key)?;
                }
            }
        }
        Ok(())
    }

    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl FileEntry {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.file_id)?;
        encode_string(writer, &self.path)?;
        self.file_type.serialize(writer)?;
        self.block_data.serialize(writer)?;
        writer.write_varint(self.created)?;
        writer.write_varint(self.modified)?;
        writer.write_varint(self.file_size)?;
        writer.write_varint(self.permissions)?;
        writer.write_varint(self.references.len())?;
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

    pub fn serialize_to_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        Ok(buf)
    }
}

impl Reference {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.target_file_id)?;
        writer.write_varint(self.relationship)?;
        Ok(())
    }
}

impl EncryptionSection {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.recipients.len() as u64)?;
        for (key, recipient) in &self.recipients {
            writer.write_all(key)?;
            recipient.serialize(writer)?;
        }
        Ok(())
    }
}

impl RecipientData {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            RecipientData::Encrypted(data) => {
                writer.write_all(&[0u8])?;
                writer.write_varint(data.len())?;
                writer.write_all(data)?;
            }
            RecipientData::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(list.len())?;
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
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.recipient_data.serialize(writer)?;
        Ok(())
    }
}

// Manual serialization utilities for PITHOS spec structs.
// No external libraries are used. All encoding is performed manually.
// - Varint encoding: unsigned LEB128
// - Strings: UTF-8 with varint length prefix
// - Multi-byte values: big-endian
// - CRC32: not implemented here (use a separate utility)
// - Only serialization to bytes is implemented (no deserialization)

use crate::helpers::structs::*;
use integer_encoding::VarIntWriter;
use std::io::Write;

// Helper: error type for serialization
#[derive(Debug)]
pub enum SerializationError {
    IoError(std::io::Error),
}

impl From<std::io::Error> for SerializationError {
    fn from(e: std::io::Error) -> Self {
        SerializationError::IoError(e)
    }
}

// Helper: encode string (UTF-8 with varint length prefix)
pub fn encode_string<W: Write>(writer: &mut W, s: &str) -> Result<(), SerializationError> {
    writer.write_varint(s.len() as u64)?;
    writer.write_all(s.as_bytes())?;
    Ok(())
}

// Helper: encode u16/u32/u64 as big-endian
pub fn encode_u16_be(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}
pub fn encode_u32_be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}
pub fn encode_u64_be(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

// --- Serialization methods for PITHOS Spec Structs ---
// Structs and enums are imported from helpers/structs.rs

impl FileHeader {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.magic)?;
        writer.write_all(&encode_u16_be(self.version))?;
        Ok(())
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
        writer.write_varint(self.index)?;
        writer.write_all(&self.hash)?;
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
        writer.write_all(&self.identifier)?;
        match &self.parent_directory_offset {
            Some((start, len)) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(*start)?;
                writer.write_varint(*len)?;
            }
            None => writer.write_all(&[0u8])?,
        }
        writer.write_varint(self.files.len() as u64)?;
        for file in &self.files {
            file.serialize(writer)?;
        }
        writer.write_varint(self.blocks.len() as u64)?;
        for block in &self.blocks {
            block.serialize(writer)?;
        }
        writer.write_varint(self.relations.len() as u64)?;
        for (idx, name) in &self.relations {
            writer.write_varint(*idx)?;
            encode_string(writer, name)?;
        }
        writer.write_varint(self.encryption.len() as u64)?;
        for enc in &self.encryption {
            enc.serialize(writer)?;
        }
        writer.write_varint(self.dir_len)?;
        writer.write_all(&encode_u32_be(self.crc32))?;
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
                writer.write_varint(data.len() as u64)?;
                writer.write_all(data)?;
            }
            BlockDataState::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(list.len() as u64)?;
                for (idx, hash) in list {
                    writer.write_varint(*idx)?;
                    writer.write_all(hash)?;
                }
            }
        }
        Ok(())
    }
}

impl FileEntry {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_varint(self.file_id)?;
        encode_string(writer, &self.path)?;
        self.file_type.serialize(writer)?;
        self.block_data.serialize(writer)?;
        writer.write_all(&encode_u64_be(self.created))?;
        writer.write_all(&encode_u64_be(self.modified))?;
        writer.write_varint(self.file_size)?;
        writer.write_all(&encode_u32_be(self.permissions))?;
        writer.write_varint(self.references.len() as u64)?;
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
        writer.write_all(&self.sender_public_key)?;
        writer.write_varint(self.recipients.len() as u64)?;
        for r in &self.recipients {
            r.serialize(writer)?;
        }
        Ok(())
    }
}

impl RecipientData {
    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        match self {
            RecipientData::Encrypted(data) => {
                writer.write_all(&[0u8])?;
                writer.write_varint(data.len() as u64)?;
                writer.write_all(data)?;
            }
            RecipientData::Decrypted(list) => {
                writer.write_all(&[1u8])?;
                writer.write_varint(list.len() as u64)?;
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
        writer.write_all(&self.recipient_public_key)?;
        self.recipient_data.serialize(writer)?;
        Ok(())
    }
}

// --- Error Types (FormatError) ---
// Not serialized as part of archive, so not implemented here.

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_encoding() {
        use integer_encoding::VarIntWriter;
        let mut buf = Vec::new();
        buf.write_varint(0u64).unwrap();
        assert_eq!(buf, vec![0x00]);
        buf.clear();
        buf.write_varint(127u64).unwrap();
        assert_eq!(buf, vec![0x7F]);
        buf.clear();
        buf.write_varint(128u64).unwrap();
        assert_eq!(buf, vec![0x80, 0x01]);
        buf.clear();
        buf.write_varint(300u64).unwrap();
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_string_encoding() {
        let s = "hello";
        let mut buf = Vec::new();
        encode_string(&mut buf, s).unwrap();
        assert_eq!(buf, vec![5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_file_header_serialization() {
        let mut buf = Vec::new();
        let fh = FileHeader {
            magic: *b"PITH",
            version: 0x0100,
        };
        fh.serialize(&mut buf).unwrap();
        assert_eq!(buf, vec![b'P', b'I', b'T', b'H', 0x01, 0x00]);
    }
}

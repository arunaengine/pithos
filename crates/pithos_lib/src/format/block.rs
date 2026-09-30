use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::primitives::{decode_string, encode_string};
use integer_encoding::{VarIntReader, VarIntWriter};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub marker: [u8; 4], // MUST be b"BLCK"
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader { marker: *b"BLCK" }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessingFlags(pub u8);

impl ProcessingFlags {
    const COMPRESSION_MASK: u8 = 0b0000_0111;
    const ENCRYPTION_MASK: u8 = 0b0000_1000;
    pub const RESERVED_MASK: u8 = 0b1111_0000;

    pub fn new(encrypted: bool, compression_level: Option<u8>) -> Self {
        let mut flags = ProcessingFlags(0b0);
        match compression_level {
            Some(level) => {
                if level > Self::COMPRESSION_MASK {
                    flags.set_compression_level(Self::COMPRESSION_MASK)
                } else {
                    flags.set_compression_level(level)
                }
            }
            None => flags.set_compression_level(3),
        }
        flags.set_encryption(encrypted);
        flags
    }

    pub fn from_byte(byte: u8) -> Self {
        ProcessingFlags(byte)
    }

    pub fn has_reserved_bits(&self) -> bool {
        self.0 & Self::RESERVED_MASK != 0
    }

    pub fn set_encryption(&mut self, encrypted: bool) {
        if encrypted {
            self.0 |= Self::ENCRYPTION_MASK;
        } else {
            self.0 &= !Self::ENCRYPTION_MASK;
        }
    }

    pub fn is_encrypted(&self) -> bool {
        (self.0 & Self::ENCRYPTION_MASK) != 0
    }

    pub fn set_compression_level(&mut self, mut compression_level: u8) {
        compression_level = if compression_level > Self::COMPRESSION_MASK {
            Self::COMPRESSION_MASK
        } else {
            compression_level
        };
        self.0 = (self.0 & !Self::COMPRESSION_MASK) | (compression_level & Self::COMPRESSION_MASK);
    }

    pub fn get_compression_level(&self) -> u8 {
        self.0 & Self::COMPRESSION_MASK
    }
}

impl Default for ProcessingFlags {
    fn default() -> Self {
        ProcessingFlags::new(true, None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLocation {
    Local,
    External { url: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub offset: u64,
    pub stored_size: u64,
    pub original_size: u64,
    pub flags: ProcessingFlags,
    pub location: BlockLocation,
}

pub(crate) fn encode_block_marker<W: Write>(
    header: &BlockHeader,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_all(&header.marker)?;
    Ok(())
}

pub(crate) fn decode_block_marker<R: Read>(
    reader: &mut R,
) -> Result<BlockHeader, DeserializationError> {
    let mut marker = [0; 4];
    reader.read_exact(&mut marker)?;
    if marker != *b"BLCK" {
        return Err(DeserializationError::InvalidMarker(format!(
            "Read invalid block marker {marker:?}"
        )));
    }
    Ok(BlockHeader { marker })
}

pub(crate) fn encode_flags<W: Write>(
    flags: &ProcessingFlags,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_all(&[flags.0])?;
    Ok(())
}

pub(crate) fn decode_flags<R: Read>(
    reader: &mut R,
) -> Result<ProcessingFlags, DeserializationError> {
    let mut byte = [0];
    reader.read_exact(&mut byte)?;
    let flags = ProcessingFlags::from_byte(byte[0]);
    if flags.has_reserved_bits() {
        return Err(DeserializationError::InvalidProcessingFlags(byte[0]));
    }
    Ok(flags)
}

fn encode_location<W: Write>(
    location: &BlockLocation,
    writer: &mut W,
) -> Result<(), SerializationError> {
    match location {
        BlockLocation::Local => writer.write_all(&[0])?,
        BlockLocation::External { url } => {
            writer.write_all(&[1])?;
            encode_string(writer, url)?;
        }
    }
    Ok(())
}

fn decode_location<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<BlockLocation, DeserializationError> {
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        0 => Ok(BlockLocation::Local),
        1 => Ok(BlockLocation::External {
            url: decode_string(reader, limits)?,
        }),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

pub(crate) fn encode_block_index_entry<W: Write>(
    entry: &BlockIndexEntry,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_varint(entry.offset)?;
    writer.write_varint(entry.stored_size)?;
    writer.write_varint(entry.original_size)?;
    encode_flags(&entry.flags, writer)?;
    encode_location(&entry.location, writer)
}

pub(crate) fn decode_block_index_entry<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<BlockIndexEntry, DeserializationError> {
    Ok(BlockIndexEntry {
        offset: reader.read_varint::<u64>()?,
        stored_size: reader.read_varint::<u64>()?,
        original_size: reader.read_varint::<u64>()?,
        flags: decode_flags(reader)?,
        location: decode_location(reader, limits)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_markers_reject_wrong_tags() {
        assert!(matches!(
            decode_block_marker(&mut &b"BLOK"[..]),
            Err(DeserializationError::InvalidMarker(_))
        ));
    }
}

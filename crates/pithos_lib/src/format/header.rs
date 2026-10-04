use crate::format::error::SerializationError;
use crate::format::limits::DeserializationError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4], // MUST be b"PITH"
    pub version: u16,   // Format version (0x0100 for 1.0, 0x0101 for 1.1)
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            magic: *b"PITH",
            version: FormatVersion::CURRENT.wire(),
        }
    }
}

impl FileHeader {
    pub const ENCODED_LEN: usize = 6;
}

/// The wire rules of one archive. An append keeps the version of the archive it extends.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FormatVersion {
    /// Pithos 0.7, read only. It stored version 1.0 as ULEB128 `80 02`, which reads as `0x8002`.
    V0_7,
    V1_0,
    V1_1,
}

impl FormatVersion {
    /// The version every new archive is written with.
    pub(crate) const CURRENT: Self = Self::V1_1;

    pub(crate) fn from_wire(version: u16) -> Option<Self> {
        match version {
            0x8002 => Some(Self::V0_7),
            0x0100 => Some(Self::V1_0),
            0x0101 => Some(Self::V1_1),
            _ => None,
        }
    }

    pub(crate) fn wire(self) -> u16 {
        match self {
            Self::V0_7 => 0x8002,
            Self::V1_0 => 0x0100,
            Self::V1_1 => 0x0101,
        }
    }

    pub(crate) fn header(self) -> FileHeader {
        FileHeader {
            magic: *b"PITH",
            version: self.wire(),
        }
    }
}

pub(crate) fn encode_header<W: Write>(
    header: &FileHeader,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_all(&header.magic)?;
    writer.write_u16::<BigEndian>(header.version)?;
    Ok(())
}

pub(crate) fn decode_header<R: Read>(reader: &mut R) -> Result<FileHeader, DeserializationError> {
    let mut magic = [0; 4];
    reader.read_exact(&mut magic)?;
    if magic != *b"PITH" {
        return Err(DeserializationError::InvalidMarker(format!(
            "Read invalid file marker {magic:?}"
        )));
    }
    Ok(FileHeader {
        magic,
        version: reader.read_u16::<BigEndian>()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_header_uses_the_fixed_width_encoding_for_both_versions() {
        let mut encoded = Vec::new();
        encode_header(&FileHeader::default(), &mut encoded).unwrap();
        assert_eq!(encoded, b"PITH\x01\x01");

        let decoded = decode_header(&mut encoded.as_slice()).unwrap();
        assert_eq!(
            FormatVersion::from_wire(decoded.version),
            Some(FormatVersion::V1_1)
        );
        let mut legacy = Vec::new();
        encode_header(&FormatVersion::V1_0.header(), &mut legacy).unwrap();
        assert_eq!(legacy, b"PITH\x01\x00");
        assert_eq!(FormatVersion::from_wire(0x0102), None);

        let error = decode_header(&mut &b"POTX\x01\x00"[..]).unwrap_err();
        assert!(error.to_string().contains("file marker"));
    }
}

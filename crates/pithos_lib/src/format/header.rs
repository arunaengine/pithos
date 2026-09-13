use crate::format::error::SerializationError;
use crate::format::limits::DeserializationError;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4], // MUST be b"PITH"
    pub version: u16,   // Format version (e.g., 0x0100 for 1.0)
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            magic: *b"PITH",
            version: Self::SUPPORTED_VERSION,
        }
    }
}

impl FileHeader {
    pub const ENCODED_LEN: usize = 6;
    pub const SUPPORTED_VERSION: u16 = 0x0100;
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
    fn file_header_uses_the_fixed_width_1_0_encoding() {
        let mut encoded = Vec::new();
        encode_header(&FileHeader::default(), &mut encoded).unwrap();
        assert_eq!(encoded, b"PITH\x01\x00");

        let decoded = decode_header(&mut encoded.as_slice()).unwrap();
        assert_eq!(decoded.version, 0x0100);

        let error = decode_header(&mut &b"POTX\x01\x00"[..]).unwrap_err();
        assert!(error.to_string().contains("file marker"));
    }
}

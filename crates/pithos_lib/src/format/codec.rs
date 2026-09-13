use crate::error::PithosError;
use crate::format::entries::WireEntries;
use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::wire::RecipientKeyList;
use crate::format::wire::*;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use crc32fast::Hasher;
use indexmap::IndexMap;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Read, Write};
use zeroize::Zeroizing;

const DIRECTORY_MARKER: [u8; 8] = *b"PITHOSDR";
const MIN_DIRECTORY_LEN: usize = 25;

pub(crate) fn write_len_prefix<W: Write>(
    writer: &mut W,
    len: usize,
) -> Result<(), SerializationError> {
    writer.write_varint(
        u64::try_from(len)
            .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?,
    )?;
    Ok(())
}

pub(crate) fn encode_string<W: Write>(
    writer: &mut W,
    value: &str,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, value.len())?;
    writer.write_all(value.as_bytes())?;
    Ok(())
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
    output: &mut Vec<T>,
    count: usize,
    field: &'static str,
) -> Result<(), DeserializationError> {
    output
        .try_reserve(count)
        .map_err(|_| DeserializationError::AllocationFailed {
            field,
            size: count as u64,
        })
}

pub(crate) fn decode_string<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<String, DeserializationError> {
    let len = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_string_bytes,
        "string",
    )?;
    let mut bytes = Vec::new();
    reserve(&mut bytes, len, "string")?;
    bytes.resize(len, 0);
    reader.read_exact(&mut bytes)?;
    Ok(String::from_utf8(bytes)?)
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
            write_len_prefix(writer, entries.len())?;
            for (hash, key) in entries.iter() {
                writer.write_all(hash)?;
                writer.write_all(key)?;
            }
        }
    }
    Ok(())
}

fn decode_block_data<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
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
            decode_decrypted_block_list_reader(reader, limits)?,
        )),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

fn encode_file_entry<W: Write>(
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
            encode_string(writer, target)?;
        }
        None => writer.write_all(&[0])?,
    }
    Ok(())
}

fn decode_file_entry<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_references: &mut u64,
) -> Result<FileEntry, DeserializationError> {
    let file_type = decode_file_type(reader)?;
    let block_data = decode_block_data(reader, limits)?;
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

fn encode_recipient_data<W: Write>(
    data: &RecipientData,
    writer: &mut W,
) -> Result<(), SerializationError> {
    match data {
        RecipientData::Encrypted(bytes) => {
            writer.write_all(&[0])?;
            write_len_prefix(writer, bytes.len())?;
            writer.write_all(bytes)?;
        }
        RecipientData::Decrypted(entries) => {
            writer.write_all(&[1])?;
            encode_decrypted_recipient_list(entries, writer)?;
        }
    }
    Ok(())
}

fn decode_recipient_data<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<RecipientData, DeserializationError> {
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        0 => {
            let len = bounded_len(
                reader.read_varint::<u64>()?,
                limits.max_opaque_bytes,
                "encrypted recipient data",
            )?;
            let mut bytes = Vec::new();
            reserve(&mut bytes, len, "encrypted recipient data")?;
            bytes.resize(len, 0);
            reader.read_exact(&mut bytes)?;
            Ok(RecipientData::Encrypted(bytes))
        }
        1 => Ok(RecipientData::Decrypted(
            decode_decrypted_recipient_list_reader(reader, limits)?,
        )),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

fn encode_encryption_section<W: Write>(
    section: &EncryptionSection,
    writer: &mut W,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, section.recipients.len())?;
    for (key, recipient) in &section.recipients {
        writer.write_all(key)?;
        encode_recipient_data(&recipient.recipient_data, writer)?;
    }
    Ok(())
}

fn decode_encryption_section<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<EncryptionSection, PithosError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "recipients",
    )?;
    let mut recipients = IndexMap::new();
    for _ in 0..count {
        let mut key = [0; 32];
        reader.read_exact(&mut key)?;
        crate::crypto::validate_x25519_public_key(&key)?;
        if recipients.contains_key(&key) {
            return Err(DeserializationError::DuplicateRecipientKey.into());
        }
        recipients.insert(
            key,
            RecipientSection {
                recipient_data: decode_recipient_data(reader, limits)?,
            },
        );
    }
    Ok(EncryptionSection { recipients })
}

pub(crate) fn encode_directory<W: Write>(
    directory: &Directory,
    writer: &mut W,
) -> Result<(), SerializationError> {
    writer.write_all(&directory.identifier)?;
    match directory.parent_directory_offset {
        Some((start, len)) => {
            writer.write_all(&[1])?;
            writer.write_varint(start)?;
            writer.write_varint(len)?;
        }
        None => writer.write_all(&[0])?,
    }
    write_len_prefix(writer, directory.files.len())?;
    for (id, path, entry) in directory.files.iter() {
        writer.write_varint::<u64>(id)?;
        encode_string(writer, path)?;
        encode_file_entry(entry, writer)?;
    }
    write_len_prefix(writer, directory.blocks.len())?;
    for (hash, entry) in &directory.blocks {
        writer.write_all(hash)?;
        encode_block_index_entry(entry, writer)?;
    }
    write_len_prefix(writer, directory.relations.len())?;
    for (id, name) in &directory.relations {
        writer.write_varint(*id)?;
        encode_string(writer, name)?;
    }
    write_len_prefix(writer, directory.encryption.len())?;
    for (key, section) in &directory.encryption {
        writer.write_all(key)?;
        encode_encryption_section(section, writer)?;
    }
    writer.write_u64::<BigEndian>(directory.dir_len)?;
    writer.write_u32::<BigEndian>(directory.crc32)?;
    Ok(())
}

pub(crate) fn decode_directory<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<Directory, PithosError> {
    let mut identifier = [0; 8];
    reader.read_exact(&mut identifier)?;
    if identifier != DIRECTORY_MARKER {
        return Err(PithosError::InvalidDirectoryMarker {
            expected: DIRECTORY_MARKER,
            actual: identifier,
        });
    }
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    let parent_directory_offset = match tag[0] {
        0 => None,
        1 => Some((
            reader
                .read_varint::<u64>()
                .map_err(DeserializationError::from)?,
            reader
                .read_varint::<u64>()
                .map_err(DeserializationError::from)?,
        )),
        _ => return Err(DeserializationError::InvalidOption.into()),
    };
    let file_count = bounded_len(
        reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?,
        limits.max_file_entries,
        "files",
    )?;
    let mut files = WireEntries::new();
    let mut remaining_references = limits.max_references;
    for _ in 0..file_count {
        let id = reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?;
        let path = decode_string(reader, limits)?;
        files.insert(
            id,
            path,
            decode_file_entry(reader, limits, &mut remaining_references)?,
        )?;
    }
    let block_count = bounded_len(
        reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?,
        limits.max_block_descriptors,
        "blocks",
    )?;
    let mut blocks = IndexMap::new();
    for _ in 0..block_count {
        let mut hash = [0; 32];
        reader.read_exact(&mut hash)?;
        if blocks.contains_key(&hash) {
            return Err(PithosError::DuplicateBlockHash);
        }
        blocks.insert(hash, decode_block_index_entry(reader, limits)?);
    }
    let relation_count = bounded_len(
        reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?,
        limits.max_relationships,
        "relations",
    )?;
    let mut relations = Vec::new();
    reserve(&mut relations, relation_count, "relations")?;
    let mut relation_ids = HashSet::new();
    for _ in 0..relation_count {
        let id = reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?;
        let name = decode_string(reader, limits)?;
        if !relation_ids.insert(id) {
            return Err(PithosError::ConflictingRelationshipDefinition(id));
        }
        relations.push((id, name));
    }
    let encryption_count = bounded_len(
        reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?,
        limits.max_collection_entries,
        "encryption",
    )?;
    let mut encryption = IndexMap::new();
    for _ in 0..encryption_count {
        let mut key = [0; 32];
        reader.read_exact(&mut key)?;
        crate::crypto::validate_x25519_public_key(&key)?;
        if encryption.contains_key(&key) {
            return Err(PithosError::DuplicateSenderKey);
        }
        encryption.insert(key, decode_encryption_section(reader, limits)?);
    }
    let directory = Directory {
        identifier,
        parent_directory_offset,
        files,
        blocks,
        relations,
        encryption,
        dir_len: reader.read_u64::<BigEndian>()?,
        crc32: reader.read_u32::<BigEndian>()?,
    };
    crate::archive::validate_wire_map(&directory.files)?;
    Ok(directory)
}

pub(crate) fn decode_complete_directory(
    bytes: &[u8],
    limits: &DeserializationLimits,
) -> Result<Directory, PithosError> {
    if bytes.len() < MIN_DIRECTORY_LEN {
        return Err(PithosError::DirectoryLengthMismatch {
            expected: MIN_DIRECTORY_LEN as u64,
            actual: bytes.len() as u64,
        });
    }
    let actual_marker: [u8; 8] = bytes[..8]
        .try_into()
        .expect("checked directory minimum length");
    if actual_marker != DIRECTORY_MARKER {
        return Err(PithosError::InvalidDirectoryMarker {
            expected: DIRECTORY_MARKER,
            actual: actual_marker,
        });
    }
    let encoded_len = u64::from_be_bytes(
        bytes[bytes.len() - 12..bytes.len() - 4]
            .try_into()
            .expect("checked directory footer"),
    );
    if encoded_len != bytes.len() as u64 {
        return Err(PithosError::DirectoryLengthMismatch {
            expected: bytes.len() as u64,
            actual: encoded_len,
        });
    }
    let encoded_crc = u32::from_be_bytes(
        bytes[bytes.len() - 4..]
            .try_into()
            .expect("checked directory footer"),
    );
    let computed_crc = crc32fast::hash(&bytes[..bytes.len() - 4]);
    if encoded_crc != computed_crc {
        return Err(PithosError::DirectoryChecksumMismatch {
            expected: computed_crc,
            actual: encoded_crc,
        });
    }
    let mut reader = Cursor::new(bytes);
    let directory = decode_directory(&mut reader, limits)?;
    if reader.position() != bytes.len() as u64 {
        return Err(PithosError::DirectoryConsumptionMismatch {
            expected: bytes.len() as u64,
            actual: reader.position(),
        });
    }
    Ok(directory)
}

pub(crate) fn update_directory_len(directory: &mut Directory) -> Result<(), SerializationError> {
    let mut bytes = Vec::new();
    encode_directory(directory, &mut bytes)?;
    directory.dir_len = u64::try_from(bytes.len())
        .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?;
    Ok(())
}

pub(crate) fn update_directory_crc(directory: &mut Directory) -> Result<(), SerializationError> {
    let mut bytes = Vec::new();
    encode_directory(directory, &mut bytes)?;
    let mut hasher = Hasher::new();
    hasher.update(&bytes[..bytes.len() - 4]);
    directory.crc32 = hasher.finalize();
    Ok(())
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

pub(crate) fn decode_decrypted_block_list_reader<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<Zeroizing<Vec<BlockDataEntry>>, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "block index",
    )?;
    let mut entries = Zeroizing::new(Vec::new());
    reserve(&mut entries, count, "block index")?;
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

pub(crate) fn decode_decrypted_block_list(
    bytes: &[u8],
    limits: &DeserializationLimits,
) -> Result<Zeroizing<Vec<BlockDataEntry>>, DeserializationError> {
    let mut reader = Cursor::new(bytes);
    let entries = decode_decrypted_block_list_reader(&mut reader, limits)?;
    if reader.position() != bytes.len() as u64 {
        return Err(DeserializationError::InvalidLength);
    }
    Ok(entries)
}

pub(crate) fn encode_decrypted_recipient_list<W: Write>(
    entries: &[(u64, [u8; 32])],
    writer: &mut W,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, entries.len())?;
    for (id, key) in entries {
        writer.write_varint(*id)?;
        writer.write_all(key)?;
    }
    Ok(())
}

pub(crate) fn decode_decrypted_recipient_list_reader<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<RecipientKeyList, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "recipient keys",
    )?;
    let mut entries = Zeroizing::new(Vec::new());
    reserve(&mut entries, count, "recipient keys")?;
    let mut keys = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = reader.read_varint::<u64>()?;
        entries.push((id, [0; 32]));
        reader.read_exact(&mut entries.last_mut().expect("just pushed file key").1)?;
        let key = entries.last().expect("just pushed file key").1;
        if keys.insert(id, key).is_some_and(|existing| existing != key) {
            return Err(DeserializationError::DuplicateRecipientFileId);
        }
    }
    Ok(entries)
}

pub(crate) fn decode_decrypted_recipient_list(
    bytes: &[u8],
    limits: &DeserializationLimits,
) -> Result<RecipientKeyList, DeserializationError> {
    let mut reader = Cursor::new(bytes);
    let entries = decode_decrypted_recipient_list_reader(&mut reader, limits)?;
    if reader.position() != bytes.len() as u64 {
        return Err(DeserializationError::InvalidLength);
    }
    Ok(entries)
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

    #[test]
    fn typed_uleb128_accepts_bounded_non_minimal_values() {
        for (mut encoded, expected) in [
            (&[0x00][..], 0_u64),
            (&[0x7f][..], 127),
            (&[0x80, 0x01][..], 128),
            (&[0x80, 0x00][..], 0),
            (&[0x81, 0x00][..], 1),
        ] {
            assert_eq!(encoded.read_varint::<u64>().unwrap(), expected);
        }
    }

    #[test]
    fn typed_uleb128_rejects_truncated_and_width_overflowing_values() {
        assert!((&[0x80][..]).read_varint::<u64>().is_err());
        assert!(
            (&[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02][..])
                .read_varint::<u64>()
                .is_err()
        );
        assert!(
            (&[
                0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
            ][..])
                .read_varint::<u64>()
                .is_err()
        );
        assert!(
            (&[0x80, 0x80, 0x80, 0x80, 0x10][..])
                .read_varint::<u32>()
                .is_err()
        );
    }

    #[test]
    fn decrypted_recipient_lists_retain_exact_duplicates_but_reject_conflicts() {
        let limits = DeserializationLimits::default();
        let mut repeated = vec![2, 7];
        repeated.extend_from_slice(&[3; 32]);
        repeated.push(7);
        repeated.extend_from_slice(&[3; 32]);
        assert_eq!(
            decode_decrypted_recipient_list(&repeated, &limits)
                .unwrap()
                .as_slice(),
            &[(7, [3; 32]), (7, [3; 32])]
        );

        let mut conflicting = vec![2, 7];
        conflicting.extend_from_slice(&[3; 32]);
        conflicting.push(7);
        conflicting.extend_from_slice(&[4; 32]);
        assert!(matches!(
            decode_decrypted_recipient_list(&conflicting, &limits),
            Err(DeserializationError::DuplicateRecipientFileId)
        ));
    }

    #[test]
    fn complete_directory_rejects_bad_footer_and_trailing_bytes() {
        let bytes = vec![
            0x50, 0x49, 0x54, 0x48, 0x4f, 0x53, 0x44, 0x52, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0x19, 0xb1, 0x67, 0x40, 0x81,
        ];
        assert!(decode_complete_directory(&bytes, &DeserializationLimits::default()).is_ok());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(matches!(
            decode_complete_directory(&trailing, &DeserializationLimits::default()),
            Err(PithosError::DirectoryLengthMismatch { .. })
        ));
        let mut corrupt = bytes;
        corrupt[0] = b'X';
        assert!(matches!(
            decode_complete_directory(&corrupt, &DeserializationLimits::default()),
            Err(PithosError::InvalidDirectoryMarker { .. })
        ));
    }

    #[test]
    fn header_and_block_markers_reject_wrong_tags() {
        assert!(matches!(
            decode_header(&mut &b"POT\x80"[..]),
            Err(DeserializationError::InvalidMarker(_))
        ));
        assert!(matches!(
            decode_block_marker(&mut &b"BLOK"[..]),
            Err(DeserializationError::InvalidMarker(_))
        ));
    }

    #[test]
    fn authenticated_lists_require_exact_consumption_and_unique_keys() {
        let limits = DeserializationLimits::default();
        assert!(matches!(
            decode_decrypted_block_list(&[0, 0], &limits),
            Err(DeserializationError::InvalidLength)
        ));
        let mut duplicate = vec![2];
        duplicate.extend_from_slice(&[1; 32]);
        duplicate.extend_from_slice(&[2; 32]);
        duplicate.extend_from_slice(&[1; 32]);
        duplicate.extend_from_slice(&[3; 32]);
        assert!(matches!(
            decode_decrypted_block_list(&duplicate, &limits),
            Err(DeserializationError::DuplicateBlockReference)
        ));
        let mut repeated = vec![2];
        repeated.extend_from_slice(&[1; 32]);
        repeated.extend_from_slice(&[2; 32]);
        repeated.extend_from_slice(&[1; 32]);
        repeated.extend_from_slice(&[2; 32]);
        assert_eq!(
            decode_decrypted_block_list(&repeated, &limits)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn directory_rejects_duplicate_relationship_definitions() {
        let mut directory = Directory {
            identifier: DIRECTORY_MARKER,
            parent_directory_offset: None,
            blocks: IndexMap::new(),
            files: WireEntries::new(),
            relations: vec![(7, "same".to_owned()), (7, "same".to_owned())],
            encryption: IndexMap::new(),
            dir_len: 0,
            crc32: 0,
        };
        update_directory_len(&mut directory).unwrap();
        update_directory_crc(&mut directory).unwrap();
        let mut bytes = Vec::new();
        encode_directory(&directory, &mut bytes).unwrap();

        assert!(matches!(
            decode_complete_directory(&bytes, &DeserializationLimits::default()),
            Err(PithosError::ConflictingRelationshipDefinition(7))
        ));
    }
}

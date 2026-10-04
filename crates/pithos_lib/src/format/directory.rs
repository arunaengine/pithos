use crate::crypto;
use crate::error::PithosError;
use crate::format::block::{BlockIndexEntry, decode_block_index_entry, encode_block_index_entry};
use crate::format::encryption::{
    EncryptionSection, decode_encryption_section, encode_encryption_section,
};
use crate::format::error::SerializationError;
use crate::format::file_entry::{
    BlockDataState, FileEntry, FileType, VALID_PERMISSION_BITS, decode_file_entry,
    encode_file_entry, validate_unique_block_references,
};
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::primitives::{
    bounded_len, decode_string, encode_string, reserve, write_len_prefix,
};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use indexmap::IndexMap;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::io::{Cursor, Read, Write};
use std::ops::Bound::Excluded;
use std::sync::Arc;

const DIRECTORY_MARKER: [u8; 8] = *b"PITHOSDR";
const MIN_DIRECTORY_LEN: usize = 25;

#[derive(Clone, Debug, Eq, PartialEq)]
struct OrderedPath(Arc<str>);

impl Ord for OrderedPath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.split('/').cmp(other.0.split('/'))
    }
}

impl PartialOrd for OrderedPath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DirectoryEntry {
    id: u64,
    path: Arc<str>,
    entry: FileEntry,
}

/// Format-owned entries with stable serialization order and private indexes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DirectoryEntries {
    by_id: IndexMap<u64, usize>,
    by_path: IndexMap<Arc<str>, usize>,
    ordered_paths: BTreeMap<OrderedPath, usize>,
    entries: Vec<DirectoryEntry>,
    maximum_id: u64,
}

impl DirectoryEntries {
    pub(crate) fn new() -> Self {
        Self::with_maximum_id(0)
    }

    pub(crate) fn with_maximum_id(maximum_id: u64) -> Self {
        Self {
            by_id: IndexMap::new(),
            by_path: IndexMap::new(),
            ordered_paths: BTreeMap::new(),
            entries: Vec::new(),
            maximum_id,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn get_by_id(&self, id: u64) -> Option<&FileEntry> {
        self.by_id
            .get(&id)
            .and_then(|index| self.entries.get(*index))
            .map(|entry| &entry.entry)
    }

    pub(crate) fn get_by_path(&self, path: &str) -> Option<&FileEntry> {
        self.by_path
            .get(path)
            .and_then(|index| self.entries.get(*index))
            .map(|entry| &entry.entry)
    }

    pub(crate) fn first_path_after(&self, path: &str) -> Option<&str> {
        let query = OrderedPath(Arc::from(path));
        self.ordered_paths
            .range((Excluded(query), std::ops::Bound::Unbounded))
            .next()
            .map(|(path, _)| path.0.as_ref())
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = (u64, &str, &FileEntry)> + '_ {
        self.entries
            .iter()
            .map(|entry| (entry.id, entry.path.as_ref(), &entry.entry))
    }

    #[cfg(test)]
    pub(crate) fn iter_ordered(&self) -> impl Iterator<Item = (&str, &FileEntry)> + '_ {
        self.ordered_paths
            .iter()
            .map(|(path, index)| (path.0.as_ref(), &self.entries[*index].entry))
    }

    pub(crate) fn try_for_each_mut<E>(
        &mut self,
        mut operation: impl FnMut(u64, &mut FileEntry) -> Result<(), E>,
    ) -> Result<(), E> {
        for entry in &mut self.entries {
            operation(entry.id, &mut entry.entry)?;
        }
        Ok(())
    }

    pub(crate) fn next_free_id(&self, has_parent: bool) -> Result<u64, PithosError> {
        if self.maximum_id == 0 && self.entries.is_empty() {
            Ok(u64::from(has_parent))
        } else {
            self.maximum_id
                .checked_add(1)
                .ok_or(PithosError::FileIdExhausted)
        }
    }

    pub(crate) fn prevalidate_insert(&self, id: u64, path: &str) -> Result<(), PithosError> {
        if self.by_id.contains_key(&id) {
            return Err(PithosError::DuplicateFileId(format!(
                "File id already occupied: {id}"
            )));
        }
        if self.by_path.contains_key(path) {
            return Err(PithosError::PathOccupied(format!(
                "File path already occupied: {path}"
            )));
        }
        Ok(())
    }

    pub(crate) fn reserve_one(&mut self) -> Result<(), PithosError> {
        let size = self
            .entries
            .len()
            .checked_add(1)
            .ok_or(PithosError::AllocationFailed {
                field: "file entries",
                size: u64::MAX,
            })?;
        self.by_id
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entry ids", size))?;
        self.by_path
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entry paths", size))?;
        self.entries
            .try_reserve(1)
            .map_err(|_| allocation_failed("file entries", size))
    }

    /// Insert only after validation and reservation of the vector-backed indexes.
    pub(crate) fn insert_prepared(&mut self, id: u64, path: impl Into<Arc<str>>, entry: FileEntry) {
        let path = path.into();
        debug_assert!(self.prevalidate_insert(id, &path).is_ok());
        let ordered = OrderedPath(Arc::clone(&path));
        let index = self.entries.len();
        self.entries.push(DirectoryEntry {
            id,
            path: Arc::clone(&path),
            entry,
        });
        self.by_id.insert(id, index);
        self.by_path.insert(path, index);
        self.ordered_paths.insert(ordered, index);
        self.maximum_id = self.maximum_id.max(id);
    }

    pub(crate) fn insert(
        &mut self,
        id: u64,
        path: impl Into<Arc<str>>,
        entry: FileEntry,
    ) -> Result<(), PithosError> {
        let path = path.into();
        self.prevalidate_insert(id, &path)?;
        self.reserve_one()?;
        self.insert_prepared(id, path, entry);
        Ok(())
    }
}

fn allocation_failed(field: &'static str, size: usize) -> PithosError {
    PithosError::AllocationFailed {
        field,
        size: u64::try_from(size).unwrap_or(u64::MAX),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub identifier: [u8; 8],
    pub parent_directory_offset: Option<(u64, u64)>,
    pub blocks: IndexMap<[u8; 32], BlockIndexEntry>,
    pub files: DirectoryEntries,
    pub relations: Vec<(u64, String)>,
    pub encryption: IndexMap<[u8; 32], EncryptionSection>,
    pub dir_len: u64,
    pub crc32: u32,
}

pub(crate) const STANDARD_RELATIONSHIPS: [(u64, &str); 10] = [
    (0, "DESCRIBES"),
    (1, "ANNOTATES"),
    (2, "DERIVED_FROM"),
    (3, "SOURCE_OF"),
    (4, "PREVIOUS_VERSION"),
    (5, "NEXT_VERSION"),
    (6, "PART_OF"),
    (7, "CONTAINS"),
    (8, "INPUT_TO"),
    (9, "OUTPUT_FROM"),
];

/// The names Pithos 0.7 stored for the standard relationships, in ID order.
const RELATIONSHIP_NAMES_0_7: [&str; 10] = [
    "Describes",
    "Annotates",
    "Derived_From",
    "Source_Of",
    "Previous_Version",
    "Next_Version",
    "Part_of",
    "Contains",
    "Input_To",
    "Output_From",
];

/// Rewrites a decoded Pithos 0.7 directory into its version 1.0 form: standard relationship
/// names, permissions without file type bits, and size 0 for directories and symlinks.
fn upgrade_0_7_directory(directory: &mut Directory) {
    for (id, name) in &mut directory.relations {
        let index = usize::try_from(*id).unwrap_or(usize::MAX);
        if RELATIONSHIP_NAMES_0_7.get(index) == Some(&name.as_str()) {
            *name = STANDARD_RELATIONSHIPS[index].1.to_owned();
        }
    }
    let Ok(()) = directory
        .files
        .try_for_each_mut::<std::convert::Infallible>(|_, entry| {
            entry.permissions &= VALID_PERMISSION_BITS;
            if matches!(entry.file_type, FileType::Directory | FileType::Symlink) {
                entry.file_size = 0;
            }
            Ok(())
        });
}

/// The CRC-32 that Pithos 0.7.0 stored. It covers the parent option only when present, the file,
/// block and encryption items without their counts, the relationships with their count, and the
/// directory length as ULEB128. Returns `None` when the bytes do not decode.
fn checksum_0_7_0(bytes: &[u8], limits: &DeserializationLimits) -> Option<u32> {
    let body = &bytes[..bytes.len() - 12];
    let mut reader = Cursor::new(body);
    reader.set_position(DIRECTORY_MARKER.len() as u64);
    let mut hasher = crc32fast::Hasher::new();
    let cover = |hasher: &mut crc32fast::Hasher, start: u64, reader: &Cursor<&[u8]>| {
        hasher.update(&body[start as usize..reader.position() as usize]);
    };
    let start = reader.position();
    if reader.read_u8().ok()? == 1 {
        reader.read_varint::<u64>().ok()?;
        reader.read_varint::<u64>().ok()?;
        cover(&mut hasher, start, &reader);
    }
    let mut references = limits.max_references;
    let mut block_references = limits.max_block_references;
    let files = bounded_len(reader.read_varint().ok()?, limits.max_file_entries, "files").ok()?;
    let start = reader.position();
    for _ in 0..files {
        reader.read_varint::<u64>().ok()?;
        decode_string(&mut reader, limits).ok()?;
        decode_file_entry(&mut reader, limits, &mut references, &mut block_references).ok()?;
    }
    cover(&mut hasher, start, &reader);
    let blocks = bounded_len(
        reader.read_varint().ok()?,
        limits.max_block_descriptors,
        "blocks",
    );
    let start = reader.position();
    for _ in 0..blocks.ok()? {
        reader.read_exact(&mut [0; 32]).ok()?;
        decode_block_index_entry(&mut reader, limits).ok()?;
    }
    cover(&mut hasher, start, &reader);
    let start = reader.position();
    let relations = bounded_len(
        reader.read_varint().ok()?,
        limits.max_relationships,
        "relations",
    );
    for _ in 0..relations.ok()? {
        reader.read_varint::<u64>().ok()?;
        decode_string(&mut reader, limits).ok()?;
    }
    cover(&mut hasher, start, &reader);
    let limit = limits.max_collection_entries;
    let sections = bounded_len(reader.read_varint().ok()?, limit, "encryption").ok()?;
    let start = reader.position();
    for _ in 0..sections {
        reader.read_exact(&mut [0; 32]).ok()?;
        decode_encryption_section(&mut reader, limits).ok()?;
    }
    cover(&mut hasher, start, &reader);
    if reader.position() != body.len() as u64 {
        return None;
    }
    let mut length = Vec::new();
    length.write_varint(bytes.len() as u64).ok()?;
    hasher.update(&length);
    Some(hasher.finalize())
}

impl Directory {
    pub(crate) fn new(
        parent_directory_offset: Option<(u64, u64)>,
        files: DirectoryEntries,
        encryption: IndexMap<[u8; 32], EncryptionSection>,
    ) -> Self {
        let relations = if parent_directory_offset.is_none() {
            STANDARD_RELATIONSHIPS
                .iter()
                .map(|(id, name)| (*id, (*name).to_owned()))
                .collect()
        } else {
            Vec::new()
        };
        Self {
            identifier: DIRECTORY_MARKER,
            parent_directory_offset,
            files,
            blocks: IndexMap::new(),
            relations,
            encryption,
            dir_len: 0,
            crc32: 0,
        }
    }

    pub(crate) fn validate_references_and_accessible_blocks_with(
        &self,
        has_entry: impl Fn(u64) -> bool,
        has_relationship: impl Fn(u64) -> bool,
        block_size: impl Fn([u8; 32]) -> Option<u64>,
    ) -> Result<(), PithosError> {
        let relationship_ids = self
            .relations
            .iter()
            .map(|(id, _)| *id)
            .collect::<HashSet<_>>();
        for (_, _, file) in self.files.iter() {
            for reference in &file.references {
                if !relationship_ids.contains(&reference.relationship)
                    && !has_relationship(reference.relationship)
                {
                    return Err(PithosError::UnknownRelationshipId(reference.relationship));
                }
                if !has_entry(reference.target_file_id) {
                    return Err(PithosError::MissingReferenceTarget(
                        reference.target_file_id,
                    ));
                }
            }
            if !matches!(file.file_type, FileType::Data | FileType::Metadata) {
                continue;
            }
            if let BlockDataState::Decrypted(references) = &file.block_data {
                validate_unique_block_references(references)?;
                let actual = references.iter().try_fold(0u64, |total, (hash, _)| {
                    let original_size =
                        block_size(*hash).ok_or(PithosError::MissingBlockDescriptor)?;
                    total.checked_add(original_size).ok_or(
                        PithosError::AccessibleFileSizeMismatch {
                            expected: file.file_size,
                            actual: u64::MAX,
                        },
                    )
                })?;
                if actual != file.file_size {
                    return Err(PithosError::AccessibleFileSizeMismatch {
                        expected: file.file_size,
                        actual,
                    });
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn next_free_file_index(&self) -> Result<u64, PithosError> {
        self.files
            .next_free_id(self.parent_directory_offset.is_some())
    }

    #[tracing::instrument(level = "trace", skip(self, file_id))]
    pub fn get_file_by_id(&self, file_id: u64) -> Option<&FileEntry> {
        self.files.get_by_id(file_id)
    }
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

#[allow(dead_code)]
pub(crate) fn decode_directory<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<Directory, PithosError> {
    let mut remaining_block_references = limits.max_block_references;
    decode_directory_with_budget(reader, limits, &mut remaining_block_references)
}

/// Receives the block descriptors of a directory while it is decoded.
pub(crate) trait BlockSink {
    /// Prepares for the declared number of descriptors before the first one is decoded.
    fn reserve(&mut self, count: usize) -> Result<(), PithosError>;
    fn insert(&mut self, hash: [u8; 32], entry: BlockIndexEntry) -> Result<(), PithosError>;
}

impl BlockSink for IndexMap<[u8; 32], BlockIndexEntry> {
    fn reserve(&mut self, _count: usize) -> Result<(), PithosError> {
        Ok(())
    }

    fn insert(&mut self, hash: [u8; 32], entry: BlockIndexEntry) -> Result<(), PithosError> {
        if self.contains_key(&hash) {
            return Err(PithosError::DuplicateBlockHash);
        }
        IndexMap::insert(self, hash, entry);
        Ok(())
    }
}

pub(crate) fn decode_directory_with_budget<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
) -> Result<Directory, PithosError> {
    let mut blocks = IndexMap::new();
    let mut directory =
        decode_directory_with_sink(reader, limits, remaining_block_references, &mut blocks)?;
    directory.blocks = blocks;
    Ok(directory)
}

/// Decodes a directory but hands its block descriptors to `blocks`, so the returned
/// directory has none.
fn decode_directory_with_sink<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
    blocks: &mut impl BlockSink,
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
    let mut files = DirectoryEntries::new();
    let mut remaining_references = limits.max_references;
    for _ in 0..file_count {
        let id = reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?;
        let path = decode_string(reader, limits)?;
        files.insert(
            id,
            path,
            decode_file_entry(
                reader,
                limits,
                &mut remaining_references,
                remaining_block_references,
            )?,
        )?;
    }
    let block_count = bounded_len(
        reader
            .read_varint::<u64>()
            .map_err(DeserializationError::from)?,
        limits.max_block_descriptors,
        "blocks",
    )?;
    blocks.reserve(block_count)?;
    for _ in 0..block_count {
        let mut hash = [0; 32];
        reader.read_exact(&mut hash)?;
        blocks.insert(hash, decode_block_index_entry(reader, limits)?)?;
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
        crypto::validate_x25519_public_key(&key)?;
        if encryption.contains_key(&key) {
            return Err(PithosError::DuplicateSenderKey);
        }
        encryption.insert(key, decode_encryption_section(reader, limits)?);
    }
    Ok(Directory {
        identifier,
        parent_directory_offset,
        files,
        blocks: IndexMap::new(),
        relations,
        encryption,
        dir_len: reader.read_u64::<BigEndian>()?,
        crc32: reader.read_u32::<BigEndian>()?,
    })
}

#[allow(dead_code)]
pub(crate) fn decode_complete_directory(
    bytes: &[u8],
    limits: &DeserializationLimits,
) -> Result<Directory, PithosError> {
    decode_complete_directory_with_validation(bytes, limits, false, |_| Ok(()))
}

pub(crate) fn decode_complete_directory_with_validation(
    bytes: &[u8],
    limits: &DeserializationLimits,
    pithos_0_7: bool,
    validate: impl Fn(&Directory) -> Result<(), PithosError>,
) -> Result<Directory, PithosError> {
    let mut remaining_block_references = limits.max_block_references;
    let mut blocks = IndexMap::new();
    let mut directory = decode_complete_directory_with_validation_and_budget(
        bytes,
        limits,
        &mut remaining_block_references,
        &mut blocks,
        pithos_0_7,
        validate,
    )?;
    directory.blocks = blocks;
    Ok(directory)
}

/// Decodes and checks a complete directory. Its block descriptors go to `blocks`.
/// With `pithos_0_7`, it also accepts the Pithos 0.7.0 checksum and returns the version 1.0 form.
pub(crate) fn decode_complete_directory_with_validation_and_budget(
    bytes: &[u8],
    limits: &DeserializationLimits,
    remaining_block_references: &mut u64,
    blocks: &mut impl BlockSink,
    pithos_0_7: bool,
    validate: impl Fn(&Directory) -> Result<(), PithosError>,
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
    if encoded_crc != computed_crc
        && !(pithos_0_7 && checksum_0_7_0(bytes, limits) == Some(encoded_crc))
    {
        return Err(PithosError::DirectoryChecksumMismatch {
            expected: computed_crc,
            actual: encoded_crc,
        });
    }
    let mut reader = Cursor::new(bytes);
    let mut directory =
        decode_directory_with_sink(&mut reader, limits, remaining_block_references, blocks)?;
    if pithos_0_7 {
        upgrade_0_7_directory(&mut directory);
    }
    validate(&directory)?;
    if reader.position() != bytes.len() as u64 {
        return Err(PithosError::DirectoryConsumptionMismatch {
            expected: bytes.len() as u64,
            actual: reader.position(),
        });
    }
    Ok(directory)
}

/// Encodes a directory once and writes its real length and CRC into the encoded footer.
pub(crate) fn encode_complete_directory(
    directory: &Directory,
) -> Result<Vec<u8>, SerializationError> {
    let mut bytes = Vec::new();
    encode_directory(directory, &mut bytes)?;
    let len = bytes.len();
    let dir_len = u64::try_from(len)
        .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?;
    bytes[len - 12..len - 4].copy_from_slice(&dir_len.to_be_bytes());
    let crc32 = crc32fast::hash(&bytes[..len - 4]);
    bytes[len - 4..].copy_from_slice(&crc32.to_be_bytes());
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn update_directory_len(directory: &mut Directory) -> Result<(), SerializationError> {
    let mut bytes = Vec::new();
    encode_directory(directory, &mut bytes)?;
    directory.dir_len = u64::try_from(bytes.len())
        .map_err(|_| SerializationError::Other("length does not fit in u64".to_string()))?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn update_directory_crc(directory: &mut Directory) -> Result<(), SerializationError> {
    let mut bytes = Vec::new();
    encode_directory(directory, &mut bytes)?;
    directory.crc32 = crc32fast::hash(&bytes[..bytes.len() - 4]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn complete_directory_reports_entry_semantics_before_trailing_body_data() {
        let mut files = DirectoryEntries::new();
        files
            .insert(
                0,
                "/invalid",
                FileEntry {
                    file_type: FileType::Directory,
                    block_data: BlockDataState::Decrypted(Vec::new().into()),
                    created: 0,
                    modified: 0,
                    file_size: 0,
                    permissions: 0o755,
                    references: Vec::new(),
                    symlink_target: None,
                },
            )
            .unwrap();
        let mut directory = Directory::new(None, files, IndexMap::new());
        update_directory_len(&mut directory).unwrap();
        update_directory_crc(&mut directory).unwrap();
        let mut bytes = Vec::new();
        encode_directory(&directory, &mut bytes).unwrap();

        let footer = bytes.len() - 12;
        bytes.insert(footer, 0xff);
        let directory_len = bytes.len() as u64;
        let footer = bytes.len() - 12;
        bytes[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
        let checksum = crc32fast::hash(&bytes[..bytes.len() - 4]);
        let crc_offset = bytes.len() - 4;
        bytes[crc_offset..].copy_from_slice(&checksum.to_be_bytes());

        assert!(matches!(
            decode_complete_directory_with_validation(
                &bytes,
                &DeserializationLimits::default(),
                false,
                |directory| {
                    if directory.files.get_by_path("/invalid").is_some() {
                        Err(PithosError::InvalidArchivePath {
                            path: "/invalid".into(),
                            reason: "test".into(),
                        })
                    } else {
                        Ok(())
                    }
                }
            ),
            Err(PithosError::InvalidArchivePath { path, .. }) if path == "/invalid"
        ));
    }

    #[test]
    fn directory_rejects_duplicate_relationship_definitions() {
        let mut directory = Directory {
            identifier: DIRECTORY_MARKER,
            parent_directory_offset: None,
            blocks: IndexMap::new(),
            files: DirectoryEntries::new(),
            relations: vec![(7, "same".to_owned()), (7, "same".to_owned())],
            encryption: IndexMap::new(),
            dir_len: 0,
            crc32: 0,
        };
        let complete = encode_complete_directory(&directory).unwrap();
        update_directory_len(&mut directory).unwrap();
        update_directory_crc(&mut directory).unwrap();
        let mut bytes = Vec::new();
        encode_directory(&directory, &mut bytes).unwrap();
        assert_eq!(complete, bytes);

        assert!(matches!(
            decode_complete_directory(&bytes, &DeserializationLimits::default()),
            Err(PithosError::ConflictingRelationshipDefinition(7))
        ));
    }
}

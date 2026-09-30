use crate::error::PithosError;
use std::cmp::Ordering;
use std::fmt::{Debug, Formatter};
use std::ops::Range;
use std::sync::Arc;

#[derive(Clone, Eq, Hash, PartialEq)]
pub struct ArchivePath(Arc<str>);

impl ArchivePath {
    pub fn new(path: impl AsRef<str>) -> Result<Self, PithosError> {
        let path = path.as_ref();
        if path.is_empty() {
            return Err(invalid_path(path, "path is empty"));
        }
        if path.contains('\0') {
            return Err(invalid_path(path, "NUL is not allowed"));
        }
        if path.contains('\\') {
            return Err(invalid_path(path, "backslash is not allowed"));
        }
        if path.starts_with('/') || path.ends_with('/') {
            return Err(invalid_path(path, "path must not start or end with /"));
        }
        if path.as_bytes().get(1) == Some(&b':') {
            return Err(invalid_path(path, "drive forms are not allowed"));
        }
        if path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid_path(
                path,
                "empty or dot path components are not allowed",
            ));
        }
        Ok(Self(Arc::from(path)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn is_ancestor_of(&self, other: &Self) -> bool {
        other
            .as_str()
            .strip_prefix(self.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
    }
}

impl Debug for ArchivePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ArchivePath").field(&self.as_str()).finish()
    }
}

impl Ord for ArchivePath {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().split('/').cmp(other.as_str().split('/'))
    }
}

impl PartialOrd for ArchivePath {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn invalid_path(path: &str, reason: impl Into<String>) -> PithosError {
    PithosError::InvalidArchivePath {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct FileId(pub(crate) u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RelationId(pub(crate) u64);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct BlockHash(pub(crate) [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Span {
    start: u64,
    end: u64,
}

impl Span {
    pub(crate) fn new(start: u64, len: u64) -> Result<Self, PithosError> {
        let end = start
            .checked_add(len)
            .ok_or(PithosError::InvalidDirectoryRange {
                operation: "construct span",
            })?;
        Ok(Self { start, end })
    }

    pub(crate) fn start(self) -> u64 {
        self.start
    }

    pub(crate) fn end(self) -> u64 {
        self.end
    }

    pub(crate) fn len(self) -> u64 {
        self.end - self.start
    }

    pub(crate) fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReadRange {
    start: u64,
    end: u64,
}

impl ReadRange {
    pub(crate) fn new(range: Range<u64>, file_size: u64) -> Result<Self, PithosError> {
        if range.start > range.end || range.end > file_size {
            return Err(PithosError::InvalidReadRange {
                start: range.start,
                end: range.end,
                file_size,
            });
        }
        Ok(Self {
            start: range.start,
            end: range.end,
        })
    }

    pub(crate) fn start(self) -> u64 {
        self.start
    }

    pub(crate) fn end(self) -> u64 {
        self.end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Compression(u8);

impl Compression {
    pub(crate) fn new(level: u8) -> Result<Self, PithosError> {
        if level <= 7 {
            Ok(Self(level))
        } else {
            Err(PithosError::ReservedProcessingBits(level))
        }
    }

    pub(crate) fn level(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Processing {
    compression: Compression,
    encrypted: bool,
}

impl Processing {
    pub(crate) fn from_byte(value: u8) -> Result<Self, PithosError> {
        if value & 0xf0 != 0 {
            return Err(PithosError::ReservedProcessingBits(value));
        }
        Ok(Self {
            compression: Compression::new(value & 0x07)?,
            encrypted: value & 0x08 != 0,
        })
    }

    pub(crate) fn to_byte(self) -> u8 {
        self.compression.level() | (u8::from(self.encrypted) << 3)
    }
}

#[derive(Clone, Eq, PartialEq)]
pub struct ExternalLocation(Arc<str>);

impl ExternalLocation {
    pub(crate) fn new(value: impl AsRef<str>) -> Self {
        Self(Arc::from(value.as_ref()))
    }

    /// The archive-owned opaque location passed to an external resolver.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Debug for ExternalLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalLocation(..)")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BlockLocation {
    Local(Span),
    External(ExternalLocation),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockDescriptor {
    pub(crate) stored_size: u64,
    pub(crate) original_size: u64,
    pub(crate) processing: Processing,
    pub(crate) location: BlockLocation,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Reference {
    pub(crate) target: FileId,
    pub(crate) relationship: RelationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EntryMetadata {
    pub(crate) created: u64,
    pub(crate) modified: u64,
    pub(crate) permissions: u32,
    pub(crate) references: Vec<Reference>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct BlockReferences(Vec<BlockHash>);

impl BlockReferences {
    pub(crate) fn new(blocks: Vec<BlockHash>) -> Self {
        Self(blocks)
    }

    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = BlockHash> + '_ {
        self.0.iter().copied()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ContentState {
    Available(BlockReferences),
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContentEntry {
    pub(crate) metadata: EntryMetadata,
    pub(crate) size: u64,
    pub(crate) content: ContentState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Entry {
    File(ContentEntry),
    Metadata(ContentEntry),
    Directory(EntryMetadata),
    Symlink {
        metadata: EntryMetadata,
        target: Arc<str>,
    },
}

impl Entry {
    pub(crate) fn metadata(&self) -> &EntryMetadata {
        match self {
            Self::File(content) | Self::Metadata(content) => &content.metadata,
            Self::Directory(metadata) | Self::Symlink { metadata, .. } => metadata,
        }
    }

    pub(crate) fn content(&self) -> Option<&ContentEntry> {
        match self {
            Self::File(content) | Self::Metadata(content) => Some(content),
            Self::Directory(_) | Self::Symlink { .. } => None,
        }
    }

    pub(crate) fn is_directory(&self) -> bool {
        matches!(self, Self::Directory(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SegmentEntry {
    pub(crate) id: FileId,
    pub(crate) path: ArchivePath,
    pub(crate) entry: Entry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedSegment {
    pub(crate) span: Span,
    pub(crate) parent: Option<Span>,
    pub(crate) entries: Vec<SegmentEntry>,
    pub(crate) descriptors: Vec<(BlockHash, BlockDescriptor)>,
    pub(crate) relationships: Vec<(RelationId, Arc<str>)>,
    pub(crate) recipient_pairs: Vec<RecipientPair>,
}

pub(crate) type RecipientPair = ([u8; 32], [u8; 32]);

use crate::archive::index::ArchiveIndex;
use crate::archive::types::{
    BlockDescriptor, BlockHash, BlockLocation, ContentState, Entry, ExternalLocation, FileId,
    ReadRange,
};
use crate::block;
use crate::error::PithosError;
use std::ops::Range;

/// One block of a planned read.
///
/// The token keeps the file, block identity and descriptor needed to decode the block. A block
/// must be completely verified before its `output` slice is released.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedBlock {
    pub(crate) file: FileId,
    pub(crate) hash: BlockHash,
    pub(crate) descriptor: BlockDescriptor,
    pub(crate) output: Range<usize>,
}

/// The stored bytes of one planned block: `BLCK` followed by the payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlockRequest {
    /// A span of this archive.
    Local { offset: u64, len: u64 },
    /// An opaque location that only an external resolver can read.
    External {
        location: ExternalLocation,
        len: u64,
    },
}

impl PlannedBlock {
    /// Where to fetch the block. One request covers the marker and the payload.
    pub fn request(&self) -> BlockRequest {
        let len = self.framed_len();
        match &self.descriptor.location {
            BlockLocation::Local(span) => BlockRequest::Local {
                offset: span.start(),
                len,
            },
            BlockLocation::External(location) => BlockRequest::External {
                location: location.clone(),
                len,
            },
        }
    }

    /// The part of the decoded block that belongs to the planned range.
    pub fn output(&self) -> Range<usize> {
        self.output.clone()
    }

    /// The marker plus the payload. Plans check the stored size limit, so this cannot overflow.
    pub(crate) fn framed_len(&self) -> u64 {
        self.descriptor.stored_size.saturating_add(4)
    }
}

/// A lazy read plan: the blocks that intersect a range, in file order.
///
/// File order can differ from storage order because blocks are shared, so offsets of
/// consecutive blocks need not increase. Each block is checked against the block limits before
/// it is yielded. The plan ends after its first error.
pub struct ReadPlan<'a> {
    index: &'a ArchiveIndex,
    file: FileId,
    references: std::slice::Iter<'a, BlockHash>,
    cursor: u64,
    range: ReadRange,
    limits: block::Limits,
}

impl<'a> ReadPlan<'a> {
    pub(crate) fn new(
        index: &'a ArchiveIndex,
        file: FileId,
        range: ReadRange,
        limits: block::Limits,
    ) -> Result<Self, PithosError> {
        let content = index
            .entry(file)
            .and_then(|entry| match &entry.entry {
                Entry::File(content) | Entry::Metadata(content) => Some(content),
                Entry::Directory(_) | Entry::Symlink { .. } => None,
            })
            .ok_or_else(|| {
                PithosError::InvalidBlockDataState("only data/metadata entries have content".into())
            })?;
        let ContentState::Available(references) = &content.content else {
            return Err(PithosError::ContentUnavailable);
        };
        let references = if range.start() < range.end() {
            references.as_slice()
        } else {
            &[]
        };
        Ok(Self {
            index,
            file,
            references: references.iter(),
            cursor: 0,
            range,
            limits,
        })
    }

    /// Plans the block at the cursor, or returns `None` when it lies before the range.
    fn step(&mut self, hash: BlockHash) -> Result<Option<PlannedBlock>, PithosError> {
        let descriptor = self
            .index
            .descriptor(hash)
            .ok_or(PithosError::MissingBlockDescriptor)?;
        let start = self.cursor;
        let end = start.checked_add(descriptor.original_size).ok_or(
            PithosError::InvalidDirectoryRange {
                operation: "sum block sizes",
            },
        )?;
        self.cursor = end;
        if start >= self.range.end() {
            self.references = [].iter();
            return Ok(None);
        }
        if end <= self.range.start() {
            return Ok(None);
        }
        if descriptor.stored_size > self.limits.max_stored_bytes {
            return Err(PithosError::LimitExceeded {
                field: "stored block",
                limit: self.limits.max_stored_bytes,
                actual: descriptor.stored_size,
            });
        }
        if descriptor.original_size > self.limits.max_decoded_bytes {
            return Err(PithosError::LimitExceeded {
                field: "decoded block",
                limit: self.limits.max_decoded_bytes,
                actual: descriptor.original_size,
            });
        }
        let convert = |value: u64| {
            usize::try_from(value).map_err(|_| PithosError::InvalidDirectoryRange {
                operation: "convert range index",
            })
        };
        let output_start = convert(self.range.start().saturating_sub(start))?;
        let output_end = convert(self.range.end().min(end) - start)?;
        Ok(Some(PlannedBlock {
            file: self.file,
            hash,
            descriptor: descriptor.clone(),
            output: output_start..output_end,
        }))
    }
}

impl Iterator for ReadPlan<'_> {
    type Item = Result<PlannedBlock, PithosError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&hash) = self.references.next() {
            match self.step(hash) {
                Ok(Some(block)) => return Some(Ok(block)),
                Ok(None) => {}
                Err(error) => {
                    self.references = [].iter();
                    return Some(Err(error));
                }
            }
        }
        None
    }
}

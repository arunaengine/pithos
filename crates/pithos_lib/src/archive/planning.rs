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
    /// The position of the block in the file's block list.
    pub(crate) position: usize,
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

    fn local_span(&self) -> Option<(u64, u64)> {
        match &self.descriptor.location {
            BlockLocation::Local(span) => Some((span.start(), self.framed_len())),
            BlockLocation::External(_) => None,
        }
    }

    /// The marker plus the payload. Plans check the stored size limit, so this cannot overflow.
    pub(crate) fn framed_len(&self) -> u64 {
        self.descriptor.stored_size.saturating_add(4)
    }

    /// Whether `other` decodes to the same plaintext: the same file, identity and descriptor.
    pub(crate) fn same_block(&self, other: &Self) -> bool {
        self.file == other.file && self.hash == other.hash && self.descriptor == other.descriptor
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
    references: std::iter::Enumerate<std::slice::Iter<'a, BlockHash>>,
    /// The position of the first reference left in `references`.
    pub(super) first_position: usize,
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
        // The plan starts at the last offset checkpoint before the range.
        let (first_position, cursor) = references.start_near(range.start());
        let references = if range.start() < range.end() {
            &references.as_slice()[first_position..]
        } else {
            &[]
        };
        Ok(Self {
            index,
            file,
            references: references.iter().enumerate(),
            first_position,
            cursor,
            range,
            limits,
        })
    }

    /// Plans the block at the cursor, or returns `None` when it lies before the range.
    fn step(
        &mut self,
        position: usize,
        hash: BlockHash,
    ) -> Result<Option<PlannedBlock>, PithosError> {
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
            self.references = [].iter().enumerate();
            return Ok(None);
        }
        if end <= self.range.start() {
            return Ok(None);
        }
        check_block_limits(descriptor, self.limits)?;
        let convert = |value: u64| {
            usize::try_from(value).map_err(|_| PithosError::InvalidDirectoryRange {
                operation: "convert range index",
            })
        };
        let output_start = convert(self.range.start().saturating_sub(start))?;
        let output_end = convert(self.range.end().min(end) - start)?;
        Ok(Some(PlannedBlock {
            file: self.file,
            position,
            hash,
            descriptor: descriptor.clone(),
            output: output_start..output_end,
        }))
    }
}

/// Checks a block against the stored and decoded size limits.
pub(crate) fn check_block_limits(
    descriptor: &BlockDescriptor,
    limits: block::Limits,
) -> Result<(), PithosError> {
    if descriptor.stored_size > limits.max_stored_bytes {
        return Err(PithosError::LimitExceeded {
            field: "stored block",
            limit: limits.max_stored_bytes,
            actual: descriptor.stored_size,
        });
    }
    if descriptor.original_size > limits.max_decoded_bytes {
        return Err(PithosError::LimitExceeded {
            field: "decoded block",
            limit: limits.max_decoded_bytes,
            actual: descriptor.original_size,
        });
    }
    Ok(())
}

impl Iterator for ReadPlan<'_> {
    type Item = Result<PlannedBlock, PithosError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((offset, &hash)) = self.references.next() {
            match self.step(self.first_position + offset, hash) {
                Ok(Some(block)) => return Some(Ok(block)),
                Ok(None) => {}
                Err(error) => {
                    self.references = [].iter().enumerate();
                    return Some(Err(error));
                }
            }
        }
        None
    }
}

impl<'a> ReadPlan<'a> {
    /// Groups consecutive local blocks whose spans are contiguous in storage into one request
    /// of at most `max_bytes`. A block that repeats the span of the block before it joins the
    /// batch without adding bytes, so the span is fetched once. A larger block and every
    /// external block form their own batch.
    pub fn batches(self, max_bytes: u64) -> BlockBatches<'a> {
        BlockBatches {
            plan: self,
            max_bytes,
            pending: None,
        }
    }
}

/// Consecutive planned blocks that one request can fetch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlockBatch {
    blocks: Vec<PlannedBlock>,
}

impl BlockBatch {
    /// One request covering every block of the batch.
    pub fn request(&self) -> BlockRequest {
        let mut request = self.blocks[0].request();
        if let BlockRequest::Local { len, .. } = &mut request {
            *len = self.stored_len();
        }
        request
    }

    /// The stored bytes of the batch. A block that repeats the span before it adds none.
    fn stored_len(&self) -> u64 {
        let mut previous = None;
        self.blocks
            .iter()
            .filter(|block| {
                let span = block.local_span();
                let repeat = span.is_some() && span == previous;
                previous = span;
                !repeat
            })
            .map(PlannedBlock::framed_len)
            .sum()
    }

    pub fn blocks(&self) -> &[PlannedBlock] {
        &self.blocks
    }

    /// Pairs each block with its stored bytes from a response to [`BlockBatch::request`].
    /// A repeated block gets the same bytes as the block before it.
    pub fn split<'b>(
        &'b self,
        response: &'b [u8],
    ) -> Result<impl Iterator<Item = (&'b PlannedBlock, &'b [u8])>, PithosError> {
        let expected = self.stored_len();
        if response.len() as u64 != expected {
            return Err(PithosError::BlockSizeMismatch {
                expected,
                actual: response.len() as u64,
            });
        }
        let mut rest = response;
        let mut last = None;
        Ok(self.blocks.iter().map(move |block| {
            if let Some((span, stored)) = last
                && block.local_span() == Some(span)
            {
                return (block, stored);
            }
            let (stored, tail) = rest.split_at(block.framed_len() as usize);
            rest = tail;
            last = block.local_span().map(|span| (span, stored));
            (block, stored)
        }))
    }
}

/// The batches of a read plan, in file order. See [`ReadPlan::batches`].
pub struct BlockBatches<'a> {
    plan: ReadPlan<'a>,
    max_bytes: u64,
    pending: Option<Result<PlannedBlock, PithosError>>,
}

/// Most planned blocks in one batch. Repeated blocks add no bytes, so this bounds their count.
pub const MAX_BATCH_BLOCKS: usize = 1024;

impl Iterator for BlockBatches<'_> {
    type Item = Result<BlockBatch, PithosError>;

    fn next(&mut self) -> Option<Self::Item> {
        let first = match self.pending.take().or_else(|| self.plan.next())? {
            Ok(block) => block,
            Err(error) => return Some(Err(error)),
        };
        let Some((offset, len)) = first.local_span() else {
            // A repeated external block could reuse the response, but the async stream detects
            // repeats by local span only, so joining external repeats needs a change there too.
            return Some(Ok(BlockBatch {
                blocks: vec![first],
            }));
        };
        let (mut last, mut end, mut total) = (offset, offset + len, len);
        let mut blocks = vec![first];
        while blocks.len() < MAX_BATCH_BLOCKS {
            let Some(next) = self.plan.next() else {
                break;
            };
            match next.as_ref().map(PlannedBlock::local_span) {
                Ok(Some((offset, len))) if offset == last && offset + len == end => {
                    blocks.extend(next.ok());
                }
                Ok(Some((offset, len))) if offset == end && total + len <= self.max_bytes => {
                    last = offset;
                    end += len;
                    total += len;
                    blocks.extend(next.ok());
                }
                _ => {
                    self.pending = Some(next);
                    break;
                }
            }
        }
        Some(Ok(BlockBatch { blocks }))
    }
}

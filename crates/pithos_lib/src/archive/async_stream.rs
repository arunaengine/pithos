use super::async_reader::{AsyncArchive, AsyncExternalBlockResolver, BlockingHook};
use super::planning::{BatchCursor, BlockBatch, BlockBatches, BlockRequest, PlannedBlock};
use super::view::ArchiveView;
use crate::error::PithosError;
use crate::format::block::ProcessingFlags;
use crate::source::AsyncArchiveSource;
use futures_core::Stream;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use zeroize::Zeroizing;

/// Bounds for one range stream.
///
/// Each request reserves its response, the planned output of its blocks, and the largest
/// working set of decoding one of them: the payload copy, the decrypted bytes of an encrypted
/// compressed block, the decoded block and a copy of a partial output. After decoding, the
/// request keeps only its planned output in buffers of exactly that size, which are released
/// as the chunks are delivered.
///
/// Adjacent blocks share a request only while the whole reservation fits `max_buffered_bytes`.
/// A request that does not fit next to the work already buffered waits. The only request that
/// may exceed the bound is a single block whose own reservation is larger; it starts alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadLimits {
    /// Source or external requests that may be outstanding at once. Zero counts as one.
    pub max_in_flight: usize,
    /// The total reservation of all batches that are fetched, decoded or waiting for delivery.
    pub max_buffered_bytes: u64,
    /// Adjacent local blocks are coalesced into one request of at most this many bytes.
    pub max_request_bytes: u64,
}

impl Default for ReadLimits {
    fn default() -> Self {
        Self {
            max_in_flight: 8,
            max_buffered_bytes: 128 * 1024 * 1024,
            max_request_bytes: 8 * 1024 * 1024,
        }
    }
}

type Pending<'a, T> = Pin<Box<dyn Future<Output = Result<T, PithosError>> + Send + 'a>>;

enum State<'a> {
    Fetching(Pending<'a, Vec<u8>>, Vec<PlannedBlock>),
    Decoding(Pending<'a, Vec<Zeroizing<Vec<u8>>>>),
    Ready(VecDeque<Zeroizing<Vec<u8>>>),
    Failed(PithosError),
    Taken,
}

struct Slot<'a> {
    reserved: u64,
    state: State<'a>,
}

/// Verified plaintext chunks of a range, in file order. See [`AsyncArchive::read_range`].
pub struct RangeStream<'a, S, E, B> {
    engine: Engine<'a, &'a AsyncArchive<S, E, B>, BlockBatches<'a>>,
}

impl<'a, S, E, B> RangeStream<'a, S, E, B>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    pub(super) fn new(
        archive: &'a AsyncArchive<S, E, B>,
        batches: BlockBatches<'a>,
        limits: ReadLimits,
    ) -> Self {
        Self {
            engine: Engine::new(archive, batches, limits),
        }
    }

    /// The bytes currently reserved by requests that are fetched, decoded or waiting for
    /// delivery, as described in [`ReadLimits`].
    pub fn buffered_bytes(&self) -> u64 {
        self.engine.buffered
    }
}

/// A [`RangeStream`] that shares the archive instead of borrowing it.
/// See [`AsyncArchive::read_range_owned`].
pub struct OwnedRangeStream<S, E, B> {
    engine: Engine<'static, Arc<AsyncArchive<S, E, B>>, SharedBatches>,
}

impl<S, E, B> OwnedRangeStream<S, E, B>
where
    S: AsyncArchiveSource + 'static,
    E: AsyncExternalBlockResolver + 'static,
    B: BlockingHook + 'static,
{
    pub(super) fn new(
        archive: Arc<AsyncArchive<S, E, B>>,
        cursor: BatchCursor,
        limits: ReadLimits,
    ) -> Self {
        let batches = SharedBatches {
            view: Arc::clone(&archive.view),
            cursor,
        };
        Self {
            engine: Engine::new(archive, batches, limits),
        }
    }

    /// The bytes currently reserved, as in [`RangeStream::buffered_bytes`].
    pub fn buffered_bytes(&self) -> u64 {
        self.engine.buffered
    }
}

/// The batches of a plan over a shared view, planned one at a time.
struct SharedBatches {
    view: Arc<ArchiveView>,
    cursor: BatchCursor,
}

impl Iterator for SharedBatches {
    type Item = Result<BlockBatch, PithosError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cursor.next_batch(&self.view.index)
    }
}

/// How a stream reaches its archive: borrowed, or shared by an owned stream.
trait Reader<'a> {
    fn fetch(&self, request: BlockRequest) -> Pending<'a, Vec<u8>>;

    fn decode(
        &self,
        blocks: Vec<PlannedBlock>,
        stored: Zeroizing<Vec<u8>>,
    ) -> Pending<'a, Vec<Zeroizing<Vec<u8>>>>;
}

impl<'a, S, E, B> Reader<'a> for &'a AsyncArchive<S, E, B>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    fn fetch(&self, request: BlockRequest) -> Pending<'a, Vec<u8>> {
        Box::pin(AsyncArchive::fetch(*self, request))
    }

    fn decode(
        &self,
        blocks: Vec<PlannedBlock>,
        stored: Zeroizing<Vec<u8>>,
    ) -> Pending<'a, Vec<Zeroizing<Vec<u8>>>> {
        let archive: &'a AsyncArchive<S, E, B> = self;
        let view = Arc::clone(&archive.view);
        Box::pin(
            archive
                .hook
                .spawn_blocking(move || decode_group(&view, &blocks, &stored)),
        )
    }
}

impl<S, E, B> Reader<'static> for Arc<AsyncArchive<S, E, B>>
where
    S: AsyncArchiveSource + 'static,
    E: AsyncExternalBlockResolver + 'static,
    B: BlockingHook + 'static,
{
    fn fetch(&self, request: BlockRequest) -> Pending<'static, Vec<u8>> {
        let archive = Arc::clone(self);
        Box::pin(async move { AsyncArchive::fetch(&archive, request).await })
    }

    fn decode(
        &self,
        blocks: Vec<PlannedBlock>,
        stored: Zeroizing<Vec<u8>>,
    ) -> Pending<'static, Vec<Zeroizing<Vec<u8>>>> {
        let archive = Arc::clone(self);
        Box::pin(async move {
            let view = Arc::clone(&archive.view);
            archive
                .hook
                .spawn_blocking(move || decode_group(&view, &blocks, &stored))
                .await
        })
    }
}

/// The ordering, bounds and cancellation shared by both range streams.
struct Engine<'a, R, P> {
    reader: R,
    batches: Option<P>,
    waiting: VecDeque<Group>,
    slots: VecDeque<Slot<'a>>,
    limits: ReadLimits,
    buffered: u64,
    fetching: usize,
}

impl<'a, R, P> Engine<'a, R, P>
where
    R: Reader<'a>,
    P: Iterator<Item = Result<BlockBatch, PithosError>>,
{
    fn new(reader: R, batches: P, limits: ReadLimits) -> Self {
        Self {
            reader,
            batches: Some(batches),
            waiting: VecDeque::new(),
            slots: VecDeque::new(),
            limits,
            buffered: 0,
            fetching: 0,
        }
    }

    /// Starts requests while the in-flight and byte bounds allow. Returns whether any started.
    fn admit(&mut self) -> bool {
        let mut admitted = false;
        while self.fetching < self.limits.max_in_flight.max(1) {
            if self.waiting.is_empty() {
                match self.batches.as_mut().and_then(Iterator::next) {
                    Some(Ok(batch)) => {
                        self.waiting = split(&batch, self.limits.max_buffered_bytes);
                    }
                    Some(Err(error)) => {
                        self.batches = None;
                        self.slots.push_back(Slot {
                            reserved: 0,
                            state: State::Failed(error),
                        });
                        return true;
                    }
                    None => {
                        self.batches = None;
                        break;
                    }
                }
            }
            let Some(group) = self.waiting.pop_front() else {
                continue;
            };
            let reserved = group.reserved();
            if !self.slots.is_empty()
                && self.buffered.saturating_add(reserved) > self.limits.max_buffered_bytes
            {
                self.waiting.push_front(group);
                break;
            }
            self.buffered = self.buffered.saturating_add(reserved);
            self.fetching += 1;
            let fetch = self.reader.fetch(group.request());
            self.slots.push_back(Slot {
                reserved,
                state: State::Fetching(fetch, group.blocks),
            });
            admitted = true;
        }
        admitted
    }

    /// Polls every outstanding fetch and decode. Returns whether any of them completed.
    fn poll_slots(&mut self, cx: &mut Context<'_>) -> bool {
        let mut progressed = false;
        let mut failed = false;
        for slot in &mut self.slots {
            let next = match &mut slot.state {
                State::Fetching(fetch, _) => match fetch.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        self.fetching -= 1;
                        let State::Fetching(_, blocks) =
                            std::mem::replace(&mut slot.state, State::Taken)
                        else {
                            unreachable!("the slot was fetching");
                        };
                        match result {
                            Ok(stored) => {
                                State::Decoding(self.reader.decode(blocks, Zeroizing::new(stored)))
                            }
                            Err(error) => State::Failed(error),
                        }
                    }
                    Poll::Pending => continue,
                },
                State::Decoding(decode) => match decode.as_mut().poll(cx) {
                    Poll::Ready(Ok(chunks)) => {
                        let kept = chunks.iter().map(retained).sum::<u64>();
                        self.buffered = self.buffered - slot.reserved + kept;
                        slot.reserved = kept;
                        State::Ready(chunks.into())
                    }
                    Poll::Ready(Err(error)) => State::Failed(error),
                    Poll::Pending => continue,
                },
                State::Ready(_) | State::Failed(_) | State::Taken => continue,
            };
            if matches!(next, State::Failed(_)) {
                self.buffered -= slot.reserved;
                slot.reserved = 0;
                failed = true;
            }
            slot.state = next;
            progressed = true;
        }
        if failed {
            self.batches = None;
            self.waiting.clear();
        }
        progressed
    }

    /// Delivers the next chunk in file order, if the first batch has one ready.
    fn deliver(&mut self) -> Option<Option<Result<Vec<u8>, PithosError>>> {
        let Some(slot) = self.slots.front_mut() else {
            let finished = self.batches.is_none() && self.waiting.is_empty();
            return finished.then_some(None);
        };
        let item = match &mut slot.state {
            State::Ready(chunks) => match chunks.pop_front() {
                Some(mut chunk) => {
                    slot.reserved -= retained(&chunk);
                    self.buffered -= retained(&chunk);
                    // Only the delivered chunk leaves its wiping wrapper.
                    Ok(std::mem::take(&mut *chunk))
                }
                None => {
                    self.buffered -= slot.reserved;
                    self.slots.pop_front();
                    return None;
                }
            },
            State::Failed(_) => {
                let State::Failed(error) = std::mem::replace(&mut slot.state, State::Taken) else {
                    unreachable!("the slot failed");
                };
                // Dropping the remaining slots cancels their requests and frees their bytes.
                self.slots.clear();
                self.buffered = 0;
                self.batches = None;
                self.waiting.clear();
                Err(error)
            }
            State::Fetching(..) | State::Decoding(_) | State::Taken => return None,
        };
        if let Some(slot) = self.slots.front()
            && matches!(&slot.state, State::Ready(chunks) if chunks.is_empty())
        {
            self.buffered -= slot.reserved;
            self.slots.pop_front();
        }
        Some(Some(item))
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<Vec<u8>, PithosError>>> {
        loop {
            let started = self.admit();
            let progressed = self.poll_slots(cx);
            let before = self.slots.len();
            if let Some(item) = self.deliver() {
                return Poll::Ready(item);
            }
            if !started && !progressed && self.slots.len() == before {
                return Poll::Pending;
            }
        }
    }
}

impl<S, E, B> Stream for RangeStream<'_, S, E, B>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    type Item = Result<Vec<u8>, PithosError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().engine.poll_next(cx)
    }
}

impl<S, E, B> Stream for OwnedRangeStream<S, E, B>
where
    S: AsyncArchiveSource + 'static,
    E: AsyncExternalBlockResolver + 'static,
    B: BlockingHook + 'static,
{
    type Item = Result<Vec<u8>, PithosError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().engine.poll_next(cx)
    }
}

/// Adjacent planned blocks fetched by one request, with the parts of their reservation.
#[derive(Default)]
struct Group {
    blocks: Vec<PlannedBlock>,
    response: u64,
    output: u64,
    working: u64,
    last: Option<PlannedBlock>,
}

impl Group {
    /// The bytes this request may hold at once. See [`ReadLimits`].
    fn reserved(&self) -> u64 {
        self.response
            .saturating_add(self.output)
            .saturating_add(self.working)
    }

    fn push(&mut self, block: PlannedBlock) {
        let framed = block.framed_len();
        let original = block.descriptor.original_size;
        let output = block.output.len() as u64;
        let flags = ProcessingFlags::from_byte(block.descriptor.processing.to_byte());
        // Decrypting before decompressing holds the payload copy and the decrypted bytes.
        let decrypted = if flags.is_encrypted() && flags.get_compression_level() > 0 {
            framed
        } else {
            0
        };
        let partial = if output == original { 0 } else { output };
        let working = framed
            .saturating_add(decrypted)
            .saturating_add(original)
            .saturating_add(partial);
        // A block that repeats the request before it reuses the bytes already fetched.
        if !self.last.as_ref().is_some_and(|last| block.repeats(last)) {
            self.response = self.response.saturating_add(framed);
        }
        self.output = self.output.saturating_add(output);
        self.working = self.working.max(working);
        self.last = Some(block.clone());
        self.blocks.push(block);
    }

    fn request(&self) -> BlockRequest {
        let mut request = self.blocks[0].request();
        if let BlockRequest::Local { len, .. } = &mut request {
            *len = self.response;
        }
        request
    }
}

/// Splits a batch into requests whose reservation fits `max_bytes`, keeping file order.
/// A block that does not fit even alone becomes a request of its own.
fn split(batch: &BlockBatch, max_bytes: u64) -> VecDeque<Group> {
    let mut groups = VecDeque::new();
    let mut current = Group::default();
    for block in batch.blocks() {
        let mut candidate = Group {
            blocks: Vec::new(),
            last: current.last.clone(),
            ..current
        };
        candidate.push(block.clone());
        if !current.blocks.is_empty() && candidate.reserved() > max_bytes {
            groups.push_back(std::mem::take(&mut current));
        }
        current.push(block.clone());
    }
    if !current.blocks.is_empty() {
        groups.push_back(current);
    }
    groups
}

/// The bytes a delivered chunk holds: its capacity, not only its length.
fn retained(chunk: &Zeroizing<Vec<u8>>) -> u64 {
    chunk.capacity() as u64
}

/// Decodes every block of a request and keeps only the planned output of each.
fn decode_group(
    view: &ArchiveView,
    blocks: &[PlannedBlock],
    stored: &[u8],
) -> Result<Vec<Zeroizing<Vec<u8>>>, PithosError> {
    let mut previous: Option<&PlannedBlock> = None;
    let expected = blocks
        .iter()
        .filter(|block| {
            let repeat = previous.is_some_and(|previous| block.repeats(previous));
            previous = Some(block);
            !repeat
        })
        .map(PlannedBlock::framed_len)
        .sum::<u64>();
    if stored.len() as u64 != expected {
        return Err(PithosError::BlockSizeMismatch {
            expected,
            actual: stored.len() as u64,
        });
    }
    let mut chunks = Vec::with_capacity(blocks.len());
    let mut rest = stored;
    let mut last: Option<(&PlannedBlock, &[u8])> = None;
    for block in blocks {
        let bytes = match last {
            Some((previous, bytes)) if block.repeats(previous) => bytes,
            _ => {
                let (bytes, tail) = rest.split_at(block.framed_len() as usize);
                rest = tail;
                bytes
            }
        };
        last = Some((block, bytes));
        let plaintext = view.decode_block(block, bytes)?;
        let output = block.output();
        let whole = output.start == 0 && output.end == plaintext.len();
        // A buffer with spare capacity is copied, so a chunk keeps only its planned bytes.
        chunks.push(if whole && plaintext.capacity() == plaintext.len() {
            plaintext
        } else {
            Zeroizing::new(plaintext[output].to_vec())
        });
    }
    Ok(chunks)
}

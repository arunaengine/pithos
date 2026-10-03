use super::async_reader::{AsyncArchive, AsyncExternalBlockResolver, BlockingHook};
use super::planning::{BlockBatch, BlockBatches};
use super::view::ArchiveView;
use crate::error::PithosError;
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
/// A batch reserves its response length, one more copy of its largest stored block (the payload
/// copy made while decoding), the decoded size of its blocks, and the planned output of blocks
/// that are only partly in the range. After decoding, the batch keeps only its planned output,
/// which is released as the chunks are delivered. A batch that does not fit next to the work
/// already buffered waits; when nothing else is buffered it starts alone, even if it is larger.
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
    Fetching(Pending<'a, Vec<u8>>, BlockBatch),
    Decoding(Pending<'a, Vec<Vec<u8>>>),
    Ready(VecDeque<Vec<u8>>),
    Failed(PithosError),
    Taken,
}

struct Slot<'a> {
    reserved: u64,
    state: State<'a>,
}

/// Verified plaintext chunks of a range, in file order. See [`AsyncArchive::read_range`].
pub struct RangeStream<'a, S, E, B> {
    archive: &'a AsyncArchive<S, E, B>,
    batches: Option<BlockBatches<'a>>,
    waiting: Option<(BlockBatch, u64)>,
    slots: VecDeque<Slot<'a>>,
    limits: ReadLimits,
    buffered: u64,
    fetching: usize,
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
            archive,
            batches: Some(batches),
            waiting: None,
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
            let (batch, reserved) = match self.waiting.take() {
                Some(next) => next,
                None => match self.batches.as_mut().and_then(Iterator::next) {
                    Some(Ok(batch)) => {
                        let reserved = reservation(&batch);
                        (batch, reserved)
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
                },
            };
            if !self.slots.is_empty()
                && self.buffered.saturating_add(reserved) > self.limits.max_buffered_bytes
            {
                self.waiting = Some((batch, reserved));
                break;
            }
            self.buffered = self.buffered.saturating_add(reserved);
            self.fetching += 1;
            let fetch = Box::pin(self.archive.fetch(batch.request()));
            self.slots.push_back(Slot {
                reserved,
                state: State::Fetching(fetch, batch),
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
            let next =
                match &mut slot.state {
                    State::Fetching(fetch, _) => match fetch.as_mut().poll(cx) {
                        Poll::Ready(result) => {
                            self.fetching -= 1;
                            let State::Fetching(_, batch) =
                                std::mem::replace(&mut slot.state, State::Taken)
                            else {
                                unreachable!("the slot was fetching");
                            };
                            match result {
                                Ok(stored) => {
                                    let view = Arc::clone(&self.archive.view);
                                    let stored = Zeroizing::new(stored);
                                    State::Decoding(Box::pin(self.archive.hook.spawn_blocking(
                                        move || decode_batch(&view, &batch, &stored),
                                    )))
                                }
                                Err(error) => State::Failed(error),
                            }
                        }
                        Poll::Pending => continue,
                    },
                    State::Decoding(decode) => match decode.as_mut().poll(cx) {
                        Poll::Ready(Ok(chunks)) => {
                            let kept = chunks.iter().map(|chunk| chunk.len() as u64).sum::<u64>();
                            self.buffered -= slot.reserved - kept;
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
            self.waiting = None;
        }
        progressed
    }

    /// Delivers the next chunk in file order, if the first batch has one ready.
    fn deliver(&mut self) -> Option<Option<Result<Vec<u8>, PithosError>>> {
        let Some(slot) = self.slots.front_mut() else {
            let finished = self.batches.is_none() && self.waiting.is_none();
            return finished.then_some(None);
        };
        let item = match &mut slot.state {
            State::Ready(chunks) => match chunks.pop_front() {
                Some(chunk) => {
                    slot.reserved -= chunk.len() as u64;
                    self.buffered -= chunk.len() as u64;
                    Ok(chunk)
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
                // Dropping the remaining slots cancels their requests.
                self.slots.clear();
                self.batches = None;
                self.waiting = None;
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
}

impl<S, E, B> Stream for RangeStream<'_, S, E, B>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    type Item = Result<Vec<u8>, PithosError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            let started = this.admit();
            let progressed = this.poll_slots(cx);
            let before = this.slots.len();
            if let Some(item) = this.deliver() {
                return Poll::Ready(item);
            }
            if !started && !progressed && this.slots.len() == before {
                return Poll::Pending;
            }
        }
    }
}

/// The bytes a batch may hold at once. See [`ReadLimits`].
fn reservation(batch: &BlockBatch) -> u64 {
    batch.blocks().iter().fold(
        batch
            .blocks()
            .iter()
            .map(|block| block.framed_len())
            .max()
            .unwrap_or(0),
        |total, block| {
            let output = block.output.len() as u64;
            let partial = if output == block.descriptor.original_size {
                0
            } else {
                output
            };
            total
                .saturating_add(block.framed_len())
                .saturating_add(block.descriptor.original_size)
                .saturating_add(partial)
        },
    )
}

/// Decodes every block of a batch and keeps only the planned output of each.
fn decode_batch(
    view: &ArchiveView,
    batch: &BlockBatch,
    stored: &[u8],
) -> Result<Vec<Vec<u8>>, PithosError> {
    let mut chunks = Vec::with_capacity(batch.blocks().len());
    for (block, bytes) in batch.split(stored)? {
        let mut plaintext = view.decode_block(block, bytes)?;
        let output = block.output();
        chunks.push(if output.start == 0 && output.end == plaintext.len() {
            std::mem::take(&mut *plaintext)
        } else {
            plaintext[output].to_vec()
        });
    }
    Ok(chunks)
}

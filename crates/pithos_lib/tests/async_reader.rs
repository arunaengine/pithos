mod common;

use common::keys::private_key;
use futures_core::Stream;
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, AsyncArchive, BlockingHook, Chunking,
    EntryMetadata, OpenOptions, ProcessingOptions, ReadLimits, WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::source::{AsyncArchiveSource, MemorySource, SourceError};
use std::future::Future;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

/// How the test source answers reads.
#[derive(Clone, Copy, Debug)]
enum Mode {
    Ready,
    /// Each read returns `Pending` once, so several reads overlap.
    YieldOnce,
    /// Reads complete only while `Probe::completions` allows it.
    Gated,
    /// Responses are one byte longer or shorter than requested.
    Resize(isize),
}

#[derive(Default)]
struct Probe {
    reads: Mutex<Vec<(u64, u64)>>,
    len_calls: AtomicUsize,
    outstanding: AtomicUsize,
    max_outstanding: AtomicUsize,
    cancelled: AtomicUsize,
    completions: AtomicUsize,
    delivered: AtomicUsize,
    /// Reads issued while opening, which `max_ahead` ignores.
    baseline: AtomicUsize,
    max_ahead: AtomicUsize,
}

struct TestSource {
    bytes: Arc<[u8]>,
    probe: Arc<Probe>,
    mode: Arc<Mutex<Mode>>,
}

impl TestSource {
    fn new(bytes: &[u8]) -> (Self, Arc<Probe>, Arc<Mutex<Mode>>) {
        let probe = Arc::new(Probe::default());
        let mode = Arc::new(Mutex::new(Mode::Ready));
        let source = Self {
            bytes: Arc::from(bytes),
            probe: Arc::clone(&probe),
            mode: Arc::clone(&mode),
        };
        (source, probe, mode)
    }
}

impl AsyncArchiveSource for TestSource {
    async fn len(&self) -> Result<u64, SourceError> {
        self.probe.len_calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.bytes.len() as u64)
    }

    fn read_at(
        &self,
        offset: u64,
        len: u64,
    ) -> impl Future<Output = Result<Vec<u8>, SourceError>> + Send {
        let mode = *self.mode.lock().unwrap();
        let mut reads = self.probe.reads.lock().unwrap();
        reads.push((offset, len));
        let ahead = reads.len().saturating_sub(
            self.probe.baseline.load(Ordering::SeqCst)
                + self.probe.delivered.load(Ordering::SeqCst),
        );
        self.probe.max_ahead.fetch_max(ahead, Ordering::SeqCst);
        let outstanding = self.probe.outstanding.fetch_add(1, Ordering::SeqCst) + 1;
        self.probe
            .max_outstanding
            .fetch_max(outstanding, Ordering::SeqCst);
        let end = match mode {
            Mode::Resize(delta) => (offset + len).saturating_add_signed(delta as i64),
            _ => offset + len,
        };
        Read {
            probe: Arc::clone(&self.probe),
            response: Some(self.bytes[offset as usize..end as usize].to_vec()),
            mode,
            yielded: false,
        }
    }

    fn revision(&self) -> Option<&str> {
        Some("etag-1")
    }
}

/// A read that records completion and cancellation.
struct Read {
    probe: Arc<Probe>,
    response: Option<Vec<u8>>,
    mode: Mode,
    yielded: bool,
}

impl Future for Read {
    type Output = Result<Vec<u8>, SourceError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.mode {
            Mode::YieldOnce if !this.yielded => {
                this.yielded = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Mode::Gated => {
                let allowed = this.probe.completions.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |count| count.checked_sub(1),
                );
                if allowed.is_err() {
                    return Poll::Pending;
                }
            }
            _ => {}
        }
        this.probe.outstanding.fetch_sub(1, Ordering::SeqCst);
        Poll::Ready(Ok(this.response.take().unwrap()))
    }
}

impl Drop for Read {
    fn drop(&mut self) {
        if self.response.is_some() {
            self.probe.outstanding.fetch_sub(1, Ordering::SeqCst);
            self.probe.cancelled.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Runs inline and counts its calls.
#[derive(Clone, Default)]
struct CountingHook(Arc<AtomicUsize>);

impl BlockingHook for CountingHook {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.0.fetch_add(1, Ordering::SeqCst);
        std::future::ready(task())
    }
}

/// Drives a future whose wakeups all happen during its own polls.
fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..1_000_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the future made no progress");
}

fn next<S: Stream + Unpin>(stream: &mut S) -> Poll<Option<S::Item>> {
    Pin::new(stream).poll_next(&mut Context::from_waker(Waker::noop()))
}

/// Collects a stream, counting delivered chunks in `probe`.
fn drain<S>(mut stream: S, probe: &Probe) -> (Vec<u8>, Option<PithosError>)
where
    S: Stream<Item = Result<Vec<u8>, PithosError>> + Unpin,
{
    let mut output = Vec::new();
    for _ in 0..1_000_000 {
        match next(&mut stream) {
            Poll::Ready(Some(Ok(chunk))) => {
                probe.delivered.fetch_add(1, Ordering::SeqCst);
                output.extend_from_slice(&chunk);
            }
            Poll::Ready(Some(Err(error))) => {
                assert!(matches!(next(&mut stream), Poll::Ready(None)));
                return (output, Some(error));
            }
            Poll::Ready(None) => return (output, None),
            Poll::Pending => {}
        }
    }
    panic!("the stream made no progress");
}

fn content(count: u64) -> Vec<u8> {
    (0..count)
        .flat_map(|block| [block.to_be_bytes(), (!block).to_be_bytes()])
        .flatten()
        .collect()
}

/// An archive with `count` 16-byte blocks in one file "data".
fn blocks(count: u64, encrypted: bool) -> Vec<u8> {
    let options = if encrypted {
        let sender = private_key("sender");
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
    } else {
        WriteOptions::base()
    };
    let mut writer =
        ArchiveWriter::create(Vec::new(), options.with_chunking(Chunking::Fixed(16))).unwrap();
    let content = content(count);
    let processing = if encrypted {
        ProcessingOptions::new(true, 3)
    } else {
        ProcessingOptions::new(false, 0)
    };
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            processing.unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content),
        )
        .unwrap();
    writer.finish().unwrap()
}

fn sender() -> OpenOptions {
    OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key("sender")))
}

fn open(
    bytes: &[u8],
    limits: ReadLimits,
) -> (AsyncArchive<TestSource>, Arc<Probe>, Arc<Mutex<Mode>>) {
    let (source, probe, mode) = TestSource::new(bytes);
    let archive = block_on(AsyncArchive::open(source, OpenOptions::default(), None)).unwrap();
    let opened = probe.reads.lock().unwrap().len();
    probe.baseline.store(opened, Ordering::SeqCst);
    probe.max_ahead.store(0, Ordering::SeqCst);
    (archive.with_read_limits(limits), probe, mode)
}

/// Single-block requests that reserve 20 + 20 + 16 bytes each.
fn single_blocks(max_in_flight: usize, max_buffered_bytes: u64) -> ReadLimits {
    ReadLimits {
        max_in_flight,
        max_buffered_bytes,
        max_request_bytes: 20,
    }
}

#[test]
fn async_reads_equal_the_sync_archive() {
    let bytes = blocks(64, true);
    let sync = Archive::open(MemorySource::new(bytes.clone()), sender()).unwrap();
    let (source, probe, mode) = TestSource::new(&bytes);
    *mode.lock().unwrap() = Mode::YieldOnce;
    let archive = block_on(AsyncArchive::open(source, sender(), None))
        .unwrap()
        .with_read_limits(ReadLimits {
            max_in_flight: 3,
            max_buffered_bytes: 4096,
            max_request_bytes: 200,
        });
    assert_eq!(archive.metadata_digest(), sync.metadata_digest());
    assert_eq!(
        archive.entries().collect::<Vec<_>>(),
        sync.entries().collect::<Vec<_>>()
    );
    for range in [0..1024, 0..0, 5..37, 16..32, 1000..1024, 17..18] {
        let mut expected = Vec::new();
        sync.copy_range_to("data", range.clone(), &mut expected)
            .unwrap();
        let (output, error) = drain(archive.read_range("data", range.clone()).unwrap(), &probe);
        assert!(error.is_none(), "{range:?}: {error:?}");
        assert_eq!(output, expected, "{range:?}");
    }
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    assert!(archive.read_range("data", 0..1025).is_err());
    assert!(archive.read_range("missing", 0..1).is_err());
}

#[test]
fn open_requests_do_not_depend_on_the_block_count() {
    for count in [4, 1_000] {
        let bytes = blocks(count, false);
        let (source, probe, _) = TestSource::new(&bytes);
        let len = bytes.len() as u64;
        let archive = block_on(AsyncArchive::open(
            source,
            OpenOptions::default(),
            Some(len),
        ))
        .unwrap();
        assert_eq!(probe.reads.lock().unwrap().len(), 3, "{count} blocks");
        assert_eq!(probe.len_calls.load(Ordering::SeqCst), 0);
        assert_eq!(archive.view().version(), 0x0101);
    }
    let (_, probe, _) = open(&blocks(4, false), ReadLimits::default());
    assert_eq!(probe.len_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn reads_respect_the_in_flight_bound() {
    let bytes = blocks(32, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(2, 1 << 20));
    *mode.lock().unwrap() = Mode::YieldOnce;
    let (output, error) = drain(archive.read_range("data", 0..512).unwrap(), &probe);
    assert!(error.is_none());
    assert_eq!(output, content(32));
    assert_eq!(probe.max_outstanding.load(Ordering::SeqCst), 2);
    assert_eq!(probe.reads.lock().unwrap().len(), 3 + 32);
}

#[test]
fn reads_respect_the_buffered_byte_bound() {
    let bytes = blocks(32, false);
    // One reservation, then less than one: each request waits for the previous chunk.
    for max_buffered_bytes in [56, 1] {
        let (archive, probe, mode) = open(&bytes, single_blocks(8, max_buffered_bytes));
        *mode.lock().unwrap() = Mode::YieldOnce;
        let (output, error) = drain(archive.read_range("data", 0..512).unwrap(), &probe);
        assert!(error.is_none());
        assert_eq!(output, content(32));
        assert_eq!(
            probe.max_ahead.load(Ordering::SeqCst),
            1,
            "{max_buffered_bytes}"
        );
    }
    // Each undelivered block holds at least its 16 output bytes and a new request 56 bytes.
    let (archive, probe, _) = open(&bytes, single_blocks(100, 560));
    let (output, _) = drain(archive.read_range("data", 0..512).unwrap(), &probe);
    assert_eq!(output, content(32));
    let ahead = probe.max_ahead.load(Ordering::SeqCst);
    assert!((10..=(560 - 56) / 16 + 1).contains(&ahead), "{ahead}");
}

#[test]
fn dropping_a_stream_cancels_outstanding_requests() {
    let bytes = blocks(16, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(4, 1 << 20));
    *mode.lock().unwrap() = Mode::Gated;
    let mut stream = archive.read_range("data", 0..256).unwrap();
    assert!(next(&mut stream).is_pending());
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 4);
    probe.completions.store(1, Ordering::SeqCst);
    let Poll::Ready(Some(Ok(first))) = next(&mut stream) else {
        panic!("the first block was released");
    };
    assert_eq!(first, content(1));
    // The completed request was replaced before the chunk was released.
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 4);
    drop(stream);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    assert_eq!(probe.cancelled.load(Ordering::SeqCst), 4);
    assert_eq!(probe.reads.lock().unwrap().len(), 3 + 5);
}

#[test]
fn wrong_response_lengths_fail_without_output() {
    let bytes = blocks(8, false);
    for delta in [1, -1] {
        let (archive, probe, mode) = open(&bytes, ReadLimits::default());
        *mode.lock().unwrap() = Mode::Resize(delta);
        let (output, error) = drain(archive.read_range("data", 0..128).unwrap(), &probe);
        assert!(output.is_empty());
        let Some(PithosError::Source(SourceError::ResponseLength {
            expected,
            actual,
            revision,
            ..
        })) = error
        else {
            panic!("unexpected result {error:?}");
        };
        assert_eq!(actual as i64 - expected as i64, delta as i64);
        assert_eq!(revision.as_deref(), Some("etag-1"));

        let (source, _, mode) = TestSource::new(&bytes);
        *mode.lock().unwrap() = Mode::Resize(delta);
        let result = block_on(AsyncArchive::open(source, OpenOptions::default(), None));
        assert!(matches!(
            result,
            Err(PithosError::Source(SourceError::ResponseLength { .. }))
        ));
    }
}

#[test]
fn the_blocking_hook_runs_open_and_decode() {
    let bytes = blocks(8, true);
    let hook = CountingHook::default();
    let (source, probe, _) = TestSource::new(&bytes);
    let archive = block_on(AsyncArchive::open_with_hook(
        source,
        sender(),
        None,
        hook.clone(),
    ))
    .unwrap()
    .with_read_limits(single_blocks(2, 1 << 20));
    // The header, the footer and the one directory.
    assert_eq!(hook.0.load(Ordering::SeqCst), 3);
    let (output, error) = drain(archive.read_range("data", 0..128).unwrap(), &probe);
    assert!(error.is_none());
    assert_eq!(output, content(8));
    assert_eq!(hook.0.load(Ordering::SeqCst), 3 + 8);
}

struct TokioBlocking;

impl BlockingHook for TokioBlocking {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let handle = tokio::task::spawn_blocking(task);
        async move {
            match handle.await {
                Ok(output) => output,
                Err(error) => std::panic::resume_unwind(error.into_panic()),
            }
        }
    }
}

fn assert_send<T: Send>(value: T) -> T {
    value
}

#[test]
fn a_tokio_blocking_pool_reads_like_the_sync_archive() {
    let bytes = blocks(64, true);
    let sync = Archive::open(MemorySource::new(bytes.clone()), sender()).unwrap();
    let mut expected = Vec::new();
    sync.copy_to("data", &mut expected).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let output = runtime.block_on(async {
        let (source, _, mode) = TestSource::new(&bytes);
        *mode.lock().unwrap() = Mode::YieldOnce;
        let open = assert_send(AsyncArchive::open_with_hook(
            source,
            sender(),
            None,
            TokioBlocking,
        ));
        let archive = open.await.unwrap();
        let mut stream = assert_send(archive.read_range("data", 0..1024).unwrap());
        let mut output = Vec::new();
        while let Some(chunk) = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
        {
            output.extend_from_slice(&chunk.unwrap());
        }
        output
    });
    assert_eq!(output, expected);
}

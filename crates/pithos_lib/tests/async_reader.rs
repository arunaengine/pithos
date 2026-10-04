mod common;

use common::keys::private_key;
use futures_core::Stream;
use pithos_lib::archive::{
    AccessKeys, Archive, ArchiveFeature, ArchivePath, ArchiveWriter, AsyncArchive,
    AsyncExternalBlockResolver, BlockRequest, BlockingHook, Chunking, EntryKind, EntryMetadata,
    ExternalBlockAccessPolicy, ExternalLocation, MAX_BATCH_BLOCKS, NoExternalBlocks, OpenLimits,
    OpenOptions, ProcessingOptions, ReadLimits, WriteOptions,
};
use pithos_lib::error::PithosError;
use pithos_lib::source::{AsyncArchiveSource, MemorySource, SourceError};
use std::collections::HashSet;
use std::future::Future;
use std::ops::Range;
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// How the test source answers reads.
#[derive(Clone, Copy, Debug)]
enum Mode {
    Ready,
    /// Each read returns `Pending` once, so several reads overlap.
    YieldOnce,
    /// A read completes once its offset is in `Probe::released`, and fails if it is also in
    /// `Probe::failing`.
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
    released: Mutex<HashSet<u64>>,
    failing: Mutex<HashSet<u64>>,
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
            offset,
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
    offset: u64,
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
            Mode::Gated if !this.probe.released.lock().unwrap().contains(&this.offset) => {
                return Poll::Pending;
            }
            _ => {}
        }
        this.probe.outstanding.fetch_sub(1, Ordering::SeqCst);
        let response = this.response.take().unwrap();
        if this.probe.failing.lock().unwrap().contains(&this.offset) {
            return Poll::Ready(Err(SourceError::Remote {
                offset: this.offset,
                message: "injected failure".into(),
            }));
        }
        Poll::Ready(Ok(response))
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

/// One planned block: its stored offset, framed length, decoded size and planned output.
#[derive(Clone, Copy, Debug)]
struct Planned {
    offset: u64,
    framed: u64,
    output: u64,
}

fn planned<E, B>(archive: &AsyncArchive<TestSource, E, B>, range: Range<u64>) -> Vec<Planned>
where
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    archive
        .view()
        .plan_range("data", range)
        .unwrap()
        .map(|block| {
            let block = block.unwrap();
            let BlockRequest::Local { offset, len } = block.request() else {
                panic!("unexpected external block");
            };
            Planned {
                offset,
                framed: len,
                output: block.output().len() as u64,
            }
        })
        .collect()
}

fn release(probe: &Probe, offset: u64) {
    probe.released.lock().unwrap().insert(offset);
}

/// Hook tasks run only once their call index is released, or all of them while `open` is set.
#[derive(Default)]
struct HookGate {
    open: std::sync::atomic::AtomicBool,
    started: AtomicUsize,
    finished: AtomicUsize,
    dropped: AtomicUsize,
    released: Mutex<HashSet<usize>>,
}

#[derive(Clone, Default)]
struct GatedHook(Arc<HookGate>);

impl BlockingHook for GatedHook {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        GatedTask {
            index: self.0.started.fetch_add(1, Ordering::SeqCst),
            gate: Arc::clone(&self.0),
            task: Some(Box::new(task)),
        }
    }
}

struct GatedTask<F> {
    index: usize,
    gate: Arc<HookGate>,
    task: Option<Box<F>>,
}

impl<F: FnOnce() -> T, T> Future for GatedTask<F> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<T> {
        let this = self.get_mut();
        let released = this.gate.open.load(Ordering::SeqCst)
            || this.gate.released.lock().unwrap().contains(&this.index);
        if !released {
            return Poll::Pending;
        }
        let output = (this.task.take().unwrap())();
        this.gate.finished.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(output)
    }
}

impl<F> Drop for GatedTask<F> {
    fn drop(&mut self) {
        if self.task.is_some() {
            self.gate.dropped.fetch_add(1, Ordering::SeqCst);
        }
    }
}

/// Opens with a hook that runs the open steps and then holds every decode.
fn open_gated(
    bytes: &[u8],
    limits: ReadLimits,
) -> (
    AsyncArchive<TestSource, NoExternalBlocks, GatedHook>,
    Arc<Probe>,
    GatedHook,
) {
    let (source, probe, mode) = TestSource::new(bytes);
    let hook = GatedHook::default();
    hook.0.open.store(true, Ordering::SeqCst);
    let archive = block_on(AsyncArchive::open_with_hook(
        source,
        OpenOptions::default(),
        None,
        hook.clone(),
    ))
    .unwrap()
    .with_read_limits(limits);
    hook.0.open.store(false, Ordering::SeqCst);
    *mode.lock().unwrap() = Mode::Gated;
    (archive, probe, hook)
}

/// Blocks of 4096 bytes that are zero except for their index, so they compress well.
fn compressible(count: u64) -> Vec<u8> {
    (0..count)
        .flat_map(|block| {
            let mut bytes = vec![0; 4096];
            bytes[..8].copy_from_slice(&block.to_be_bytes());
            bytes
        })
        .collect()
}

fn compressed_blocks(count: u64, encrypted: bool) -> Vec<u8> {
    let sender = private_key("sender");
    let options = WriteOptions::new(sender.duplicate(), vec![sender.public_key()])
        .with_chunking(Chunking::Fixed(4096));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    let content = compressible(count);
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(encrypted, 3).unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content),
        )
        .unwrap();
    writer.finish().unwrap()
}

/// The documented reservation of one request over full, encrypted and compressed blocks.
fn reservation(blocks: &[Planned]) -> u64 {
    let response = blocks.iter().map(|block| block.framed).sum::<u64>();
    let output = blocks.iter().map(|block| block.output).sum::<u64>();
    let working = blocks
        .iter()
        .map(|block| 2 * block.framed + block.output)
        .max()
        .unwrap();
    response + output + working
}

fn sender() -> OpenOptions {
    OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key("sender")))
}

fn open(
    bytes: &[u8],
    limits: ReadLimits,
) -> (AsyncArchive<TestSource>, Arc<Probe>, Arc<Mutex<Mode>>) {
    open_as(bytes, OpenOptions::default(), limits)
}

fn open_as(
    bytes: &[u8],
    options: OpenOptions,
    limits: ReadLimits,
) -> (AsyncArchive<TestSource>, Arc<Probe>, Arc<Mutex<Mode>>) {
    let (source, probe, mode) = TestSource::new(bytes);
    let archive = block_on(AsyncArchive::open(source, options, None)).unwrap();
    let opened = probe.reads.lock().unwrap().len();
    probe.baseline.store(opened, Ordering::SeqCst);
    probe.max_ahead.store(0, Ordering::SeqCst);
    (archive.with_read_limits(limits), probe, mode)
}

/// Single-block requests that reserve 20 + 16 + (20 + 16) bytes each.
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
    for max_buffered_bytes in [72, 1] {
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
    // Each undelivered block holds at least its 16 output bytes and a new request 72 bytes.
    let (archive, probe, _) = open(&bytes, single_blocks(100, 720));
    let (output, _) = drain(archive.read_range("data", 0..512).unwrap(), &probe);
    assert_eq!(output, content(32));
    let ahead = probe.max_ahead.load(Ordering::SeqCst);
    assert!((10..=(720 - 72) / 16 + 1).contains(&ahead), "{ahead}");
}

#[test]
fn dropping_a_stream_cancels_outstanding_requests() {
    let bytes = blocks(16, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(4, 1 << 20));
    *mode.lock().unwrap() = Mode::Gated;
    let mut stream = archive.read_range("data", 0..256).unwrap();
    assert!(next(&mut stream).is_pending());
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 4);
    release(&probe, planned(&archive, 0..16)[0].offset);
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

const SPEC: &str = include_str!("../../../spec/PITHOS_1.1.0_draft.md");
const INITIAL_TARGET: &str = "https://storage.test/initial";
const REDIRECT_TARGET: &str = "https://storage.test/redirect";

/// CV-LOCAL-HELLO-279 with its block moved to the opaque external location "x".
fn external_hello() -> Vec<u8> {
    let start = SPEC.find("#### CV-LOCAL-HELLO-279").unwrap();
    let block = SPEC[start..].split("```text\n").nth(1).unwrap();
    let mut bytes = block
        .split("```")
        .next()
        .unwrap()
        .lines()
        .flat_map(|line| line.split_once(": ").unwrap().1.split_whitespace())
        .map(|hex| u8::from_str_radix(hex, 16).unwrap())
        .collect::<Vec<u8>>();
    bytes.splice(143..=143, [1, 1, b'x']);
    let footer = bytes.len() - 12;
    let directory_len = (bytes.len() - 15) as u64;
    bytes[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
    let checksum = crc32fast::hash(&bytes[15..bytes.len() - 4]);
    let crc = bytes.len() - 4;
    bytes[crc..].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

struct RecordingPolicy {
    checks: Mutex<Vec<String>>,
    denied: Option<&'static str>,
}

impl ExternalBlockAccessPolicy for RecordingPolicy {
    fn allows(&self, target: &str) -> bool {
        self.checks.lock().unwrap().push(target.to_owned());
        self.denied != Some(target)
    }
}

/// Follows one redirect and answers with a fixed response.
struct RedirectingResolver {
    response: Vec<u8>,
    calls: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl AsyncExternalBlockResolver for RedirectingResolver {
    async fn resolve(
        &self,
        policy: &dyn ExternalBlockAccessPolicy,
        location: &ExternalLocation,
        expected_len: u64,
        max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError> {
        assert_eq!(location.as_str(), "x");
        for target in [INITIAL_TARGET, REDIRECT_TARGET] {
            if !policy.allows(target) {
                return Err(PithosError::ExternalBlockAccessDenied);
            }
        }
        self.calls
            .lock()
            .unwrap()
            .push((expected_len, max_response_size));
        Ok(self.response.clone())
    }
}

/// The result of one external read, the policy checks and the resolver calls.
struct ExternalRead {
    result: Result<Vec<u8>, PithosError>,
    checks: Vec<String>,
    calls: Vec<(u64, u64)>,
}

fn external_read(
    response: &[u8],
    denied: Option<&'static str>,
    range: std::ops::Range<u64>,
) -> ExternalRead {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let policy = Arc::new(RecordingPolicy {
        checks: Mutex::new(Vec::new()),
        denied,
    });
    let resolver = RedirectingResolver {
        response: response.to_vec(),
        calls: Arc::clone(&calls),
    };
    let options = OpenOptions::default()
        .with_external_resolver(resolver)
        .with_external_access_policy(policy.clone());
    let (source, probe, _) = TestSource::new(&external_hello());
    let archive = block_on(AsyncArchive::open(source, options, None)).unwrap();
    let (output, error) = drain(archive.read_range("hello", range).unwrap(), &probe);
    assert!(error.is_none() || output.is_empty());
    let result = error.map_or(Ok(output), Err);
    let checks = policy.checks.lock().unwrap().clone();
    let calls = calls.lock().unwrap().clone();
    ExternalRead {
        result,
        checks,
        calls,
    }
}

#[test]
fn external_blocks_need_a_resolver_and_a_policy() {
    let bytes = external_hello();
    let (source, _, _) = TestSource::new(&bytes);
    let disabled = block_on(AsyncArchive::open(source, OpenOptions::default(), None)).unwrap();
    assert!(matches!(
        disabled.entry("hello").unwrap().unwrap().kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));
    assert!(matches!(
        disabled.read_range("hello", 0..5),
        Err(PithosError::UnsupportedFeature(
            ArchiveFeature::ExternalStorage
        ))
    ));

    let (source, _, _) = TestSource::new(&bytes);
    let resolver = RedirectingResolver {
        response: b"BLCKhello".to_vec(),
        calls: Arc::default(),
    };
    let options = OpenOptions::default().with_external_resolver(resolver);
    let without_policy = block_on(AsyncArchive::open(source, options, None)).unwrap();
    assert!(without_policy.read_range("hello", 0..5).is_err());
}

#[test]
fn external_blocks_are_read_through_the_async_resolver() {
    let max_response_size = OpenLimits::default().max_stored_block_bytes + 4;
    let ExternalRead {
        result,
        checks,
        calls,
    } = external_read(b"BLCKhello", None, 1..4);
    assert_eq!(result.unwrap(), b"ell");
    assert_eq!(checks, [INITIAL_TARGET, REDIRECT_TARGET]);
    assert_eq!(calls, [(9, max_response_size)]);

    let ExternalRead {
        result,
        checks,
        calls,
    } = external_read(b"BLCKhello", Some(REDIRECT_TARGET), 0..5);
    assert!(matches!(
        result,
        Err(PithosError::ExternalBlockAccessDenied)
    ));
    assert_eq!(checks, [INITIAL_TARGET, REDIRECT_TARGET]);
    assert!(calls.is_empty());

    for response in [&b"BLCKhello!"[..], b"BLCKhell"] {
        let ExternalRead { result, .. } = external_read(response, None, 0..5);
        assert!(matches!(result, Err(PithosError::ExternalBlockFraming(_))));
    }
    let ExternalRead { result, .. } = external_read(b"BLCKjello", None, 0..5);
    assert!(matches!(result, Err(PithosError::BlockHashMismatch { .. })));
}

#[test]
fn reads_completed_in_reverse_are_delivered_in_file_order() {
    let bytes = blocks(8, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(4, 1 << 20));
    *mode.lock().unwrap() = Mode::Gated;
    let blocks = planned(&archive, 0..64);
    let mut stream = archive.read_range("data", 0..64).unwrap();
    assert!(next(&mut stream).is_pending());
    for block in blocks[1..].iter().rev() {
        release(&probe, block.offset);
        assert!(next(&mut stream).is_pending());
    }
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 1);
    release(&probe, blocks[0].offset);
    for block in 0..4 {
        let Poll::Ready(Some(Ok(chunk))) = next(&mut stream) else {
            panic!("block {block} was released");
        };
        assert_eq!(chunk, content(block + 1)[block as usize * 16..]);
    }
    assert!(matches!(next(&mut stream), Poll::Ready(None)));
}

#[test]
fn decodes_completed_in_reverse_are_delivered_in_file_order() {
    let bytes = blocks(4, false);
    let (archive, probe, hook) = open_gated(&bytes, single_blocks(4, 1 << 20));
    for block in planned(&archive, 0..64) {
        release(&probe, block.offset);
    }
    let mut stream = archive.read_range("data", 0..64).unwrap();
    assert!(next(&mut stream).is_pending());
    assert_eq!(hook.0.started.load(Ordering::SeqCst), 3 + 4);
    for index in (4..7).rev() {
        hook.0.released.lock().unwrap().insert(index);
        assert!(next(&mut stream).is_pending());
    }
    assert_eq!(hook.0.finished.load(Ordering::SeqCst), 3 + 3);
    hook.0.released.lock().unwrap().insert(3);
    let (output, error) = drain(stream, &probe);
    assert!(error.is_none());
    assert_eq!(output, content(4));
}

#[test]
fn a_later_failure_ends_the_stream_after_the_earlier_output() {
    let bytes = blocks(8, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(4, 1 << 20));
    *mode.lock().unwrap() = Mode::Gated;
    let blocks = planned(&archive, 0..128);
    probe.failing.lock().unwrap().insert(blocks[2].offset);
    let mut stream = archive.read_range("data", 0..128).unwrap();
    assert!(next(&mut stream).is_pending());
    release(&probe, blocks[2].offset);
    assert!(next(&mut stream).is_pending());
    release(&probe, blocks[1].offset);
    assert!(next(&mut stream).is_pending());
    release(&probe, blocks[0].offset);
    let (output, error) = drain(&mut stream, &probe);
    assert_eq!(output, content(2));
    assert!(matches!(
        error,
        Some(PithosError::Source(SourceError::Remote { offset, .. })) if offset == blocks[2].offset
    ));
    assert_eq!(stream.buffered_bytes(), 0);
    assert!(matches!(next(&mut stream), Poll::Ready(None)));
    assert_eq!(stream.buffered_bytes(), 0);
    // The pending sibling was cancelled and no request started after the failure.
    assert_eq!(probe.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    assert_eq!(probe.reads.lock().unwrap().len(), 3 + 4);
}

#[test]
fn dropping_a_stream_during_a_decode_drops_the_hook_task() {
    let bytes = blocks(8, false);
    let (archive, probe, hook) = open_gated(&bytes, single_blocks(4, 1 << 20));
    let first = planned(&archive, 0..16)[0];
    release(&probe, first.offset);
    let mut stream = archive.read_range("data", 0..128).unwrap();
    assert!(next(&mut stream).is_pending());
    assert_eq!(hook.0.started.load(Ordering::SeqCst), 3 + 1);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 4);
    drop(stream);
    assert_eq!(hook.0.dropped.load(Ordering::SeqCst), 1);
    assert_eq!(hook.0.finished.load(Ordering::SeqCst), 3);
    assert_eq!(probe.cancelled.load(Ordering::SeqCst), 4);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
}

#[test]
fn compressed_blocks_share_a_request_only_within_the_byte_bound() {
    let bytes = compressed_blocks(32, true);
    let limits = ReadLimits {
        max_in_flight: 8,
        max_buffered_bytes: 40_000,
        max_request_bytes: 1 << 20,
    };
    let (archive, probe, _) = open_as(&bytes, sender(), limits);
    let blocks = planned(&archive, 0..32 * 4096);
    // Compression is kept: every block stores far fewer bytes than it decodes to.
    assert!(blocks.iter().all(|block| block.framed * 10 < block.output));
    let mut stream = archive.read_range("data", 0..32 * 4096).unwrap();
    let mut output = Vec::new();
    let mut peak = 0;
    while let Poll::Ready(Some(chunk)) = next(&mut stream) {
        peak = peak.max(stream.buffered_bytes());
        output.extend_from_slice(&chunk.unwrap());
    }
    assert!(matches!(next(&mut stream), Poll::Ready(None)));
    assert_eq!(output, compressible(32));
    assert!(peak > 0 && peak <= limits.max_buffered_bytes, "{peak}");
    let reads = probe.reads.lock().unwrap()[3..].to_vec();
    assert!(reads.len() > 1 && reads.len() < blocks.len(), "{reads:?}");
    let mut rest = &blocks[..];
    for (offset, len) in reads {
        let count = rest
            .iter()
            .scan(0, |total, block| {
                *total += block.framed;
                Some(*total)
            })
            .position(|total| total == len)
            .unwrap()
            + 1;
        assert_eq!(rest[0].offset, offset);
        assert!(reservation(&rest[..count]) <= limits.max_buffered_bytes);
        rest = &rest[count..];
    }
    assert!(rest.is_empty());

    // A bound below one block still reads, one block per request.
    let limits = ReadLimits {
        max_buffered_bytes: 100,
        ..limits
    };
    let (archive, probe, _) = open_as(&bytes, sender(), limits);
    let (output, error) = drain(archive.read_range("data", 0..32 * 4096).unwrap(), &probe);
    assert!(error.is_none());
    assert_eq!(output, compressible(32));
    let reads = probe.reads.lock().unwrap()[3..].to_vec();
    assert_eq!(reads.len(), blocks.len());
    assert!(
        reads
            .iter()
            .zip(&blocks)
            .all(|(read, block)| read.1 == block.framed)
    );
}

#[test]
fn encrypted_compressed_blocks_reserve_the_decrypted_bytes() {
    for encrypted in [true, false] {
        let bytes = compressed_blocks(4, encrypted);
        let (archive, probe, mode) = open_as(&bytes, sender(), single_blocks(1, 1 << 20));
        *mode.lock().unwrap() = Mode::Gated;
        let block = planned(&archive, 0..4096)[0];
        assert!(block.framed * 10 < block.output);
        let mut stream = archive.read_range("data", 0..4096).unwrap();
        assert!(next(&mut stream).is_pending());
        let decrypted = if encrypted { block.framed } else { 0 };
        let expected = block.framed + block.output + (block.framed + decrypted + block.output);
        assert_eq!(stream.buffered_bytes(), expected, "encrypted {encrypted}");
        release(&probe, block.offset);
        let (output, error) = drain(stream, &probe);
        assert!(error.is_none());
        assert_eq!(output, compressible(1));
    }
}

#[test]
fn repeated_adjacent_blocks_are_read_in_file_order() {
    // Blocks A B B B C: the writer stores B once, right after A, and C after B.
    let content = [[0u8; 16], [1; 16], [1; 16], [1; 16], [2; 16]].concat();
    let key = private_key("sender");
    let options = WriteOptions::new(key.duplicate(), vec![key.public_key()])
        .with_chunking(Chunking::Fixed(16));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content.clone()),
        )
        .unwrap();
    let bytes = writer.finish().unwrap();
    for (max_buffered_bytes, range) in [(1 << 20, 0..80), (1 << 20, 20..60), (1, 0..80)] {
        let limits = ReadLimits {
            max_in_flight: 4,
            max_buffered_bytes,
            max_request_bytes: 1024,
        };
        let (archive, probe, _) = open_as(&bytes, sender(), limits);
        let (output, error) = drain(archive.read_range("data", range.clone()).unwrap(), &probe);
        assert!(error.is_none(), "{error:?}");
        assert_eq!(output, content[range.start as usize..range.end as usize]);
        // Each request covers distinct stored bytes of the archive.
        let reads = probe.reads.lock().unwrap()[3..].to_vec();
        let stored = planned(&archive, range.clone())
            .iter()
            .map(|block| (block.offset, block.framed))
            .collect::<HashSet<_>>();
        assert!(reads.len() <= planned(&archive, range).len());
        for (offset, len) in reads {
            let covered = stored
                .iter()
                .filter(|(start, framed)| *start >= offset && start + framed <= offset + len)
                .map(|(_, framed)| framed)
                .sum::<u64>();
            assert_eq!(covered, len);
        }
    }
}

#[test]
fn encrypted_repeated_blocks_retain_only_their_output() {
    // One stored 16-byte block repeated past the batch cap.
    let count = MAX_BATCH_BLOCKS + 100;
    let content = [7u8; 16].repeat(count);
    let key = private_key("sender");
    let options = WriteOptions::new(key.duplicate(), vec![key.public_key()])
        .with_chunking(Chunking::Fixed(16));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(content.len() as u64),
            std::io::Cursor::new(content.clone()),
        )
        .unwrap();
    let bytes = writer.finish().unwrap();
    let limits = ReadLimits {
        max_in_flight: 4,
        max_buffered_bytes: 20_000,
        max_request_bytes: 1024,
    };
    let (archive, probe, mode) = open_as(&bytes, sender(), limits);
    *mode.lock().unwrap() = Mode::YieldOnce;
    let mut stream = archive.read_range("data", 0..content.len() as u64).unwrap();
    let mut output = Vec::new();
    let mut peak = 0;
    while let Poll::Ready(Some(chunk)) = next(&mut stream) {
        let chunk = chunk.unwrap();
        assert_eq!(chunk.capacity(), chunk.len());
        peak = peak.max(stream.buffered_bytes());
        output.extend_from_slice(&chunk);
    }
    assert!(matches!(next(&mut stream), Poll::Ready(None)));
    assert_eq!(output, content);
    assert!(
        peak > 16 * 1024 && peak <= limits.max_buffered_bytes,
        "{peak}"
    );
    // Both batches were outstanding at once, and each fetched the stored block once.
    assert_eq!(probe.reads.lock().unwrap()[3..].len(), 2);
    assert_eq!(probe.max_outstanding.load(Ordering::SeqCst), 2);
}

/// A generous cap that turns a lost signal into a failure instead of a hang.
const HANG_CAP: Duration = Duration::from_secs(60);

/// What a worker thread reports and waits for.
struct WorkerSignals {
    started: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    /// Whether the reader still received the result.
    finished: mpsc::Sender<bool>,
}

/// Runs tasks inline until `threaded` is set, then each on its own thread once released.
#[derive(Clone)]
struct WorkerHook {
    threaded: Arc<AtomicBool>,
    signals: Arc<WorkerSignals>,
    workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl BlockingHook for WorkerHook {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        if self.threaded.load(Ordering::SeqCst) {
            let signals = Arc::clone(&self.signals);
            let worker = std::thread::spawn(move || {
                signals.started.send(()).unwrap();
                signals
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(HANG_CAP)
                    .unwrap();
                let delivered = sender.send(task()).is_ok();
                signals.finished.send(delivered).unwrap();
            });
            self.workers.lock().unwrap().push(worker);
        } else {
            sender.send(task()).unwrap();
        }
        std::future::poll_fn(move |_| match receiver.try_recv() {
            Ok(output) => Poll::Ready(output),
            Err(mpsc::TryRecvError::Empty) => Poll::Pending,
            Err(mpsc::TryRecvError::Disconnected) => panic!("the worker stopped"),
        })
    }
}

#[test]
fn dropping_a_stream_while_a_worker_decodes_discards_the_result() {
    let bytes = blocks(8, true);
    let (started, started_signal) = mpsc::channel();
    let (release, release_signal) = mpsc::channel();
    let (finished, finished_signal) = mpsc::channel();
    let hook = WorkerHook {
        threaded: Arc::default(),
        signals: Arc::new(WorkerSignals {
            started,
            release: Mutex::new(release_signal),
            finished,
        }),
        workers: Arc::default(),
    };
    let (source, probe, _) = TestSource::new(&bytes);
    let archive = block_on(AsyncArchive::open_with_hook(
        source,
        sender(),
        None,
        hook.clone(),
    ))
    .unwrap()
    .with_read_limits(single_blocks(1, 1));
    hook.threaded.store(true, Ordering::SeqCst);
    let mut stream = archive.read_range("data", 0..128).unwrap();
    assert!(next(&mut stream).is_pending());
    started_signal.recv_timeout(HANG_CAP).unwrap();
    drop(stream);
    release.send(()).unwrap();
    // The worker completed, but nobody received its result.
    assert!(!finished_signal.recv_timeout(HANG_CAP).unwrap());
    let workers = std::mem::take(&mut *hook.workers.lock().unwrap());
    assert_eq!(workers.len(), 1);
    for worker in workers {
        worker.join().unwrap();
    }
    // Only the test and the archive still hold the hook state, and the archive reads again.
    assert_eq!(Arc::strong_count(&hook.signals), 2);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    hook.threaded.store(false, Ordering::SeqCst);
    let (output, error) = drain(archive.read_range("data", 0..128).unwrap(), &probe);
    assert!(error.is_none());
    assert_eq!(output, content(8));
}

fn assert_owned<T: Send + 'static>(value: T) -> T {
    value
}

#[test]
fn owned_streams_equal_borrowed_streams() {
    let bytes = blocks(64, true);
    let (source, probe, mode) = TestSource::new(&bytes);
    *mode.lock().unwrap() = Mode::YieldOnce;
    let archive = block_on(AsyncArchive::open(source, sender(), None))
        .unwrap()
        .with_read_limits(ReadLimits {
            max_in_flight: 3,
            max_buffered_bytes: 4096,
            max_request_bytes: 200,
        });
    let archive = Arc::new(archive);
    for range in [0..1024, 0..0, 5..37, 16..32, 1000..1024, 17..18] {
        let start = probe.reads.lock().unwrap().len();
        let borrowed = drain(archive.read_range("data", range.clone()).unwrap(), &probe);
        let middle = probe.reads.lock().unwrap().len();
        let stream = Arc::clone(&archive)
            .read_range_owned("data", range.clone())
            .unwrap();
        let owned = drain(assert_owned(stream), &probe);
        assert!(borrowed.1.is_none() && owned.1.is_none(), "{range:?}");
        assert_eq!(owned.0, borrowed.0, "{range:?}");
        assert_eq!(
            owned.0,
            content(64)[range.start as usize..range.end as usize]
        );
        // Both streams issue the same requests in the same order.
        let reads = probe.reads.lock().unwrap();
        assert_eq!(reads[start..middle], reads[middle..], "{range:?}");
    }
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    assert!(
        Arc::clone(&archive)
            .read_range_owned("data", 0..1025)
            .is_err()
    );
    assert!(
        Arc::clone(&archive)
            .read_range_owned("missing", 0..1)
            .is_err()
    );
    assert_eq!(Arc::strong_count(&archive), 1);
}

#[test]
fn owned_streams_run_in_spawned_tokio_tasks() {
    let bytes = blocks(64, true);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let output = runtime.block_on(async {
        let (source, _, mode) = TestSource::new(&bytes);
        *mode.lock().unwrap() = Mode::YieldOnce;
        let archive = AsyncArchive::open_with_hook(source, sender(), None, TokioBlocking)
            .await
            .unwrap();
        let mut stream = Arc::new(archive)
            .read_range_owned("data", 16..1000)
            .unwrap();
        let task = tokio::spawn(async move {
            let mut output = Vec::new();
            while let Some(chunk) =
                std::future::poll_fn(|cx| Pin::new(&mut stream).poll_next(cx)).await
            {
                output.extend_from_slice(&chunk.unwrap());
            }
            output
        });
        task.await.unwrap()
    });
    assert_eq!(output, content(64)[16..1000]);
}

#[test]
fn dropping_an_owned_stream_cancels_outstanding_requests() {
    let bytes = blocks(16, false);
    let (archive, probe, mode) = open(&bytes, single_blocks(4, 1 << 20));
    *mode.lock().unwrap() = Mode::Gated;
    let archive = Arc::new(archive);
    let mut stream = Arc::clone(&archive)
        .read_range_owned("data", 0..256)
        .unwrap();
    assert!(next(&mut stream).is_pending());
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 4);
    // The stream and each of its four requests hold the archive.
    assert_eq!(Arc::strong_count(&archive), 1 + 1 + 4);
    drop(stream);
    assert_eq!(probe.outstanding.load(Ordering::SeqCst), 0);
    assert_eq!(probe.cancelled.load(Ordering::SeqCst), 4);
    assert_eq!(Arc::strong_count(&archive), 1);
}

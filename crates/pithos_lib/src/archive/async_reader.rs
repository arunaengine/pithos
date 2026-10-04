use super::async_stream::{OwnedRangeStream, RangeStream, ReadLimits};
use super::opener::ArchiveOpener;
use super::planning::BlockRequest;
use super::reader::{
    ArchiveEntry, ArchiveFeature, ExternalBlockAccessPolicy, NoExternalBlocks, OpenOptions,
};
use super::types::ExternalLocation;
use super::view::ArchiveView;
use crate::error::PithosError;
use crate::source::{AsyncArchiveSource, SourceError};
use std::future::Future;
use std::ops::Range;
use std::sync::Arc;

/// Resolves an opaque external block location to exactly one framed `BLCK` value without
/// blocking.
///
/// The contract equals [`ExternalBlockResolver`](super::ExternalBlockResolver): external reads
/// are enabled only when both a resolver and an access policy are supplied, the resolver must
/// call the policy before its initial access and before every redirect, and it must not accept
/// a response larger than `max_response_size`. The reader rejects a response whose length is
/// not `expected_len`.
pub trait AsyncExternalBlockResolver: Send + Sync {
    fn resolve(
        &self,
        policy: &dyn ExternalBlockAccessPolicy,
        location: &ExternalLocation,
        expected_len: u64,
        max_response_size: u64,
    ) -> impl Future<Output = Result<Vec<u8>, PithosError>> + Send;
}

impl AsyncExternalBlockResolver for NoExternalBlocks {
    fn resolve(
        &self,
        _policy: &dyn ExternalBlockAccessPolicy,
        _location: &ExternalLocation,
        _expected_len: u64,
        _max_response_size: u64,
    ) -> impl Future<Output = Result<Vec<u8>, PithosError>> + Send {
        std::future::ready(Err(PithosError::UnsupportedFeature(
            ArchiveFeature::ExternalStorage,
        )))
    }
}

/// Runs CPU work, such as decryption, hashing, decompression and index building, away from
/// the async executor.
///
/// With Tokio, forward to `tokio::task::spawn_blocking` and resume a panic from the join error.
/// Work that was already handed over may still finish after its future is dropped; the reader
/// then discards the result.
pub trait BlockingHook: Send + Sync {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static;
}

/// Runs CPU work inline on the polling task.
///
/// Suitable only for small archives and small reads: a large directory or block stalls the
/// executor thread while it is decoded.
#[derive(Clone, Copy, Debug, Default)]
pub struct InlineBlocking;

impl BlockingHook for InlineBlocking {
    fn spawn_blocking<F, T>(&self, task: F) -> impl Future<Output = T> + Send
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        std::future::ready(task())
    }
}

/// An archive opened from an [`AsyncArchiveSource`].
///
/// Opening issues the requests of [`ArchiveOpener`] one after the other: the header, the
/// footer and each directory. Their count does not depend on the number of blocks. Every
/// directory is decoded through the [`BlockingHook`].
pub struct AsyncArchive<S, E = NoExternalBlocks, B = InlineBlocking> {
    source: S,
    external: E,
    external_access_policy: Option<Arc<dyn ExternalBlockAccessPolicy>>,
    pub(super) hook: B,
    pub(super) view: Arc<ArchiveView>,
    limits: ReadLimits,
}

impl<S, E> AsyncArchive<S, E, InlineBlocking>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
{
    /// Opens an archive and decodes its metadata inline. See [`AsyncArchive::open_with_hook`].
    pub async fn open(
        source: S,
        options: OpenOptions<E>,
        known_len: Option<u64>,
    ) -> Result<Self, PithosError> {
        Self::open_with_hook(source, options, known_len, InlineBlocking).await
    }
}

impl<S, E, B> AsyncArchive<S, E, B>
where
    S: AsyncArchiveSource,
    E: AsyncExternalBlockResolver,
    B: BlockingHook,
{
    /// Opens an archive and runs every metadata step through `hook`.
    ///
    /// `known_len` skips the length request when the caller already knows the object size.
    /// It must be the length of the revision the source serves.
    pub async fn open_with_hook(
        source: S,
        options: OpenOptions<E>,
        known_len: Option<u64>,
        hook: B,
    ) -> Result<Self, PithosError> {
        let archive_len = match known_len {
            Some(len) => len,
            None => source.len().await?,
        };
        let (settings, external, external_access_policy) = options.into_parts();
        let mut opener = ArchiveOpener::with_settings(archive_len, settings)?;
        while let Some(request) = opener.request() {
            let response = read_exact(&source, request.offset(), request.len()).await?;
            let (returned, result) = hook
                .spawn_blocking(move || {
                    let result = opener.feed(request, response);
                    (opener, result)
                })
                .await;
            opener = returned;
            result?;
        }
        Ok(Self {
            source,
            external,
            external_access_policy,
            hook,
            view: Arc::new(opener.finish()?),
            limits: ReadLimits::default(),
        })
    }

    /// Replaces the bounds used by later range reads.
    pub fn with_read_limits(mut self, limits: ReadLimits) -> Self {
        self.limits = limits;
        self
    }

    /// BLAKE3 over the hashes of every directory, from the base to the terminal directory.
    pub fn metadata_digest(&self) -> [u8; 32] {
        self.view.metadata_digest()
    }

    pub fn entries(&self) -> impl ExactSizeIterator<Item = ArchiveEntry> + '_ {
        self.view.entries()
    }

    pub fn entry(&self, path: &str) -> Result<Option<ArchiveEntry>, PithosError> {
        self.view.entry(path)
    }

    /// The validated metadata, for planning reads without this reader.
    pub fn view(&self) -> &ArchiveView {
        &self.view
    }

    /// Streams the verified plaintext of `range` within the content of `path`, in file order.
    ///
    /// Path, range and availability errors are returned before any request. Each item is the
    /// planned part of one completely verified block. The stream ends after its first error.
    /// Dropping it cancels every outstanding request. For a `'static` stream, use
    /// [`AsyncArchive::read_range_owned`].
    pub fn read_range(
        &self,
        path: &str,
        range: Range<u64>,
    ) -> Result<RangeStream<'_, S, E, B>, PithosError> {
        let plan = self.view.plan_range(path, range)?;
        Ok(RangeStream::new(
            self,
            plan.batches(self.limits.max_request_bytes),
            self.limits,
        ))
    }

    /// Streams like [`AsyncArchive::read_range`], but the stream holds the shared archive
    /// instead of a borrow. It is `Send + 'static`, so a server handler can return it as a
    /// response body or move it into a task. Dropping it cancels every outstanding request.
    pub fn read_range_owned(
        self: Arc<Self>,
        path: &str,
        range: Range<u64>,
    ) -> Result<OwnedRangeStream<S, E, B>, PithosError>
    where
        S: 'static,
        E: 'static,
        B: 'static,
    {
        let cursor = self
            .view
            .plan_range(path, range)?
            .batches(self.limits.max_request_bytes)
            .detach();
        let limits = self.limits;
        Ok(OwnedRangeStream::new(self, cursor, limits))
    }

    /// Fetches the stored bytes of one batch request.
    pub(super) async fn fetch(&self, request: BlockRequest) -> Result<Vec<u8>, PithosError> {
        match request {
            BlockRequest::Local { offset, len } => Ok(read_exact(&self.source, offset, len).await?),
            BlockRequest::External { location, len } => {
                let policy = self.external_access_policy.as_deref().ok_or(
                    PithosError::UnsupportedFeature(ArchiveFeature::ExternalStorage),
                )?;
                let max_response_size = self
                    .view
                    .limits
                    .max_stored_block_bytes
                    .checked_add(4)
                    .ok_or_else(|| {
                        PithosError::ExternalBlockFraming("response policy overflow".into())
                    })?;
                let response = self
                    .external
                    .resolve(policy, &location, len, max_response_size)
                    .await?;
                if response.len() as u64 != len {
                    return Err(PithosError::ExternalBlockFraming(
                        "response does not match expected size".into(),
                    ));
                }
                Ok(response)
            }
        }
    }
}

/// Reads one exact range and rejects responses of any other length.
async fn read_exact<S: AsyncArchiveSource>(
    source: &S,
    offset: u64,
    len: u64,
) -> Result<Vec<u8>, SourceError> {
    let response = source.read_at(offset, len).await?;
    if response.len() as u64 != len {
        return Err(SourceError::ResponseLength {
            offset,
            expected: len,
            actual: response.len() as u64,
            revision: source.revision().map(str::to_owned),
        });
    }
    Ok(response)
}

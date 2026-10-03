use super::reader::{ArchiveFeature, ExternalBlockAccessPolicy, NoExternalBlocks};
use super::types::ExternalLocation;
use crate::error::PithosError;
use std::future::Future;

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

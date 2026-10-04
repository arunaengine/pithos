use super::SourceError;
use std::future::Future;

/// An immutable, positioned byte source read without blocking.
///
/// The source must present one immutable object revision for the whole open and every later
/// read. Archive metadata and blocks are verified, but changed bytes between reads can still
/// turn a valid archive into errors. A store with versioned objects should pin the revision it
/// opened, for example with a conditional range request, and fail once the object changes.
/// [`AsyncArchiveSource::revision`] names that revision in length errors.
///
/// Every response must be exactly the requested length. The reader rejects shorter and longer
/// responses before it uses them.
#[allow(clippy::len_without_is_empty)] // Matches the synchronous source contract.
pub trait AsyncArchiveSource: Send + Sync {
    /// The archive length in bytes. Callers that already know it can skip this call.
    fn len(&self) -> impl Future<Output = Result<u64, SourceError>> + Send;

    /// Reads exactly `len` bytes starting at `offset`.
    fn read_at(
        &self,
        offset: u64,
        len: u64,
    ) -> impl Future<Output = Result<Vec<u8>, SourceError>> + Send;

    /// An optional caller-chosen name of the object revision, such as an entity tag.
    fn revision(&self) -> Option<&str> {
        None
    }
}

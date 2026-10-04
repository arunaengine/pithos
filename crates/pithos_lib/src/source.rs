use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(feature = "async")]
mod async_source;
#[cfg(feature = "async")]
pub use async_source::AsyncArchiveSource;

/// Context for acquisition failures at the fixed, offset-based archive boundary.
#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source {operation} for {path}: {source}")]
    PathIo {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("source {operation} at offset {offset}: {source}")]
    Io {
        operation: &'static str,
        offset: u64,
        #[source]
        source: io::Error,
    },
    #[error("source EOF at offset {offset}: needed {expected} bytes, received {actual}")]
    UnexpectedEof {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    #[error("source range overflows at offset {offset} for {length} bytes")]
    RangeOverflow { offset: u64, length: usize },
    #[error("remote range at offset {offset}: {message}")]
    Remote { offset: u64, message: String },
    #[error(
        "source response at offset {offset} (revision {revision:?}): expected {expected} bytes, received {actual}"
    )]
    ResponseLength {
        offset: u64,
        expected: u64,
        actual: u64,
        revision: Option<String>,
    },
}

/// An immutable, positioned byte source for an archive.
#[allow(clippy::len_without_is_empty)] // The fixed public contract is intentionally just length plus positioned exact read.
pub trait ArchiveSource {
    fn len(&self) -> Result<u64, SourceError>;
    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError>;
}

/// Linux positioned-file archive source.
pub struct FileSource {
    file: File,
    length: u64,
}

impl FileSource {
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self, SourceError> {
        let path = path.as_ref();
        let file = File::open(path).map_err(|source| SourceError::PathIo {
            operation: "open",
            path: path.to_path_buf(),
            source,
        })?;
        let length = file
            .metadata()
            .map_err(|source| SourceError::PathIo {
                operation: "metadata",
                path: path.to_path_buf(),
                source,
            })?
            .len();
        Ok(Self { file, length })
    }

    pub(crate) fn from_file(file: File) -> Result<Self, SourceError> {
        let length = file
            .metadata()
            .map_err(|source| SourceError::Io {
                operation: "metadata",
                offset: 0,
                source,
            })?
            .len();
        Ok(Self { file, length })
    }
}

impl ArchiveSource for FileSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.length)
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
        let _ = offset
            .checked_add(buffer.len() as u64)
            .ok_or(SourceError::RangeOverflow {
                offset,
                length: buffer.len(),
            })?;
        let mut read = 0;
        while read != buffer.len() {
            let position = offset
                .checked_add(read as u64)
                .ok_or(SourceError::RangeOverflow {
                    offset,
                    length: buffer.len(),
                })?;
            let count = self
                .file
                .read_at(&mut buffer[read..], position)
                .map_err(|source| SourceError::Io {
                    operation: "read",
                    offset: position,
                    source,
                })?;
            if count == 0 {
                return Err(SourceError::UnexpectedEof {
                    offset,
                    expected: buffer.len(),
                    actual: read,
                });
            }
            read += count;
        }
        Ok(())
    }
}

#[derive(Clone)]
/// Immutable in-memory archive source.
pub struct MemorySource {
    bytes: Arc<[u8]>,
}

impl MemorySource {
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            bytes: bytes.into(),
        }
    }
}

impl ArchiveSource for MemorySource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
        let end = offset
            .checked_add(buffer.len() as u64)
            .ok_or(SourceError::RangeOverflow {
                offset,
                length: buffer.len(),
            })?;
        let start = usize::try_from(offset).map_err(|_| SourceError::RangeOverflow {
            offset,
            length: buffer.len(),
        })?;
        let end = usize::try_from(end).map_err(|_| SourceError::RangeOverflow {
            offset,
            length: buffer.len(),
        })?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or(SourceError::UnexpectedEof {
                offset,
                expected: buffer.len(),
                actual: self.bytes.len().saturating_sub(start),
            })?;
        buffer.copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn assert_send_sync<T: Send + Sync>() {}

    /// Blocking range prototype for source-equivalence tests. It deliberately
    /// owns returned bytes and has no transport policy.
    struct RemoteRangeSource<F> {
        length: u64,
        fetch: F,
    }

    impl<F> RemoteRangeSource<F> {
        fn new(length: u64, fetch: F) -> Self {
            Self { length, fetch }
        }
    }

    impl<F> ArchiveSource for RemoteRangeSource<F>
    where
        F: Fn(u64, usize) -> Result<Vec<u8>, SourceError>,
    {
        fn len(&self) -> Result<u64, SourceError> {
            Ok(self.length)
        }

        fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
            let end =
                offset
                    .checked_add(buffer.len() as u64)
                    .ok_or(SourceError::RangeOverflow {
                        offset,
                        length: buffer.len(),
                    })?;
            if end > self.length {
                return Err(SourceError::UnexpectedEof {
                    offset,
                    expected: buffer.len(),
                    actual: self.length.saturating_sub(offset) as usize,
                });
            }
            let response = (self.fetch)(offset, buffer.len())?;
            if response.len() != buffer.len() {
                return Err(SourceError::UnexpectedEof {
                    offset,
                    expected: buffer.len(),
                    actual: response.len(),
                });
            }
            buffer.copy_from_slice(&response);
            Ok(())
        }
    }

    #[test]
    fn memory_source_is_exact_and_concurrent() {
        assert_send_sync::<MemorySource>();
        let source = Arc::new(MemorySource::new(Arc::<[u8]>::from(&b"abcdef"[..])));
        let handles = (0..4).map(|_| {
            let source = Arc::clone(&source);
            std::thread::spawn(move || {
                let mut output = [0; 3];
                source.read_exact_at(2, &mut output).unwrap();
                output
            })
        });
        for handle in handles {
            assert_eq!(handle.join().unwrap(), *b"cde");
        }
        let mut output = [0; 2];
        assert!(matches!(
            source.read_exact_at(5, &mut output),
            Err(SourceError::UnexpectedEof { offset: 5, .. })
        ));
        assert_eq!(source.len().unwrap(), 6);
    }

    #[test]
    fn remote_range_maps_exact_requests_and_short_responses() {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&requests);
        let source = RemoteRangeSource::new(6, move |offset, length| {
            captured.lock().unwrap().push((offset, length));
            Ok(b"cde".to_vec())
        });
        let mut output = [0; 3];
        source.read_exact_at(2, &mut output).unwrap();
        assert_eq!(output, *b"cde");
        assert_eq!(*requests.lock().unwrap(), vec![(2, 3)]);

        let short = RemoteRangeSource::new(6, |_offset, _length| Ok(vec![1]));
        assert!(matches!(
            short.read_exact_at(2, &mut output),
            Err(SourceError::UnexpectedEof { actual: 1, .. })
        ));

        let failure = RemoteRangeSource::new(6, |offset, _length| {
            Err(SourceError::Remote {
                offset,
                message: "transport failed".into(),
            })
        });
        assert!(matches!(
            failure.read_exact_at(2, &mut output),
            Err(SourceError::Remote { offset: 2, .. })
        ));
    }

    #[test]
    fn file_source_reports_contextual_eof() {
        let temporary = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temporary.path(), b"abc").unwrap();
        let source = FileSource::open(temporary.path()).unwrap();
        let mut output = [0; 4];
        assert!(matches!(
            source.read_exact_at(0, &mut output),
            Err(SourceError::UnexpectedEof {
                offset: 0,
                actual: 3,
                ..
            })
        ));
    }
}

use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryKind, EntryMetadata, OpenOptions,
    ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::error::PithosError;
use pithos_lib::source::{ArchiveSource, FileSource, MemorySource, SourceError};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

fn private_key() -> PrivateKey {
    pithos_lib::crypto::parse_private_pem(
        &std::fs::read("tests/data/keys/recipient1_private.pem").unwrap(),
    )
    .unwrap()
}

fn options() -> OpenOptions {
    OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private_key()))
}

#[test]
fn file_source_open_errors_include_the_requested_path() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("distinct-missing-archive.pith");

    let error = match FileSource::open(&missing) {
        Ok(_) => panic!("missing source unexpectedly opened"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(missing.to_str().unwrap()));
    assert!(std::error::Error::source(&error).is_some());
}

fn fixture(temporary: &tempfile::TempDir) -> std::path::PathBuf {
    let sender = pithos_lib::crypto::parse_private_pem(
        &std::fs::read("tests/data/keys/sender_private.pem").unwrap(),
    )
    .unwrap();
    let recipient = pithos_lib::crypto::parse_public_pem(
        &std::fs::read("tests/data/keys/recipient1_public.pem").unwrap(),
    )
    .unwrap();
    let path = temporary.path().join("fixture.pith");
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(&path).unwrap(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 0).unwrap(),
            Some(23),
            std::io::Cursor::new(b"verified source fixture"),
        )
        .unwrap();
    writer.finish().unwrap();
    path
}

#[test]
fn file_and_memory_sources_produce_the_same_validated_index() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary);
    let file = Archive::open(FileSource::open(&path).unwrap(), options()).unwrap();
    let memory = Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(path).unwrap())),
        options(),
    )
    .unwrap();
    assert_eq!(
        file.entries().collect::<Vec<_>>(),
        memory.entries().collect::<Vec<_>>()
    );
}

struct Fragmented(Arc<[u8]>);

impl ArchiveSource for Fragmented {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.0.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        let start = usize::try_from(offset).map_err(|_| SourceError::RangeOverflow {
            offset,
            length: output.len(),
        })?;
        let end = start
            .checked_add(output.len())
            .ok_or(SourceError::RangeOverflow {
                offset,
                length: output.len(),
            })?;
        let input = self.0.get(start..end).ok_or(SourceError::UnexpectedEof {
            offset,
            expected: output.len(),
            actual: self.0.len().saturating_sub(start),
        })?;
        for (target, source) in output.iter_mut().zip(input) {
            *target = *source;
        }
        Ok(())
    }
}

struct CountingSource {
    bytes: Arc<[u8]>,
    reads: Arc<AtomicUsize>,
}

struct InconsistentLength(Arc<[u8]>);

impl ArchiveSource for InconsistentLength {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.0.len() as u64 + 1)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        Fragmented(Arc::clone(&self.0)).read_exact_at(offset, output)
    }
}

struct FailingSource;

impl ArchiveSource for FailingSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(64)
    }

    fn read_exact_at(&self, offset: u64, _output: &mut [u8]) -> Result<(), SourceError> {
        Err(SourceError::Remote {
            offset,
            message: "injected transport failure".into(),
        })
    }
}

impl ArchiveSource for CountingSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        Fragmented(Arc::clone(&self.bytes)).read_exact_at(offset, output)
    }
}

#[test]
fn fragmented_source_is_equivalent_and_source_errors_keep_context() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary);
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    let archive = Archive::open(Fragmented(Arc::clone(&bytes)), options()).unwrap();
    assert_eq!(archive.entries().count(), 1);

    let error = match Archive::open(MemorySource::new(&bytes[..4]), options()) {
        Ok(_) => panic!("truncated source must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, PithosError::InvalidDirectoryRange { .. }));
}

#[test]
fn unavailable_entries_remain_visible_and_invalid_ranges_do_not_read() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary);
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    let archive = Archive::open(
        CountingSource {
            bytes: Arc::clone(&bytes),
            reads: Arc::new(AtomicUsize::new(0)),
        },
        OpenOptions::default(),
    )
    .unwrap();
    let entry = archive.entries().next().unwrap();
    assert!(matches!(
        entry.kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));

    let reads = Arc::new(AtomicUsize::new(0));
    let archive = Archive::open(
        CountingSource {
            bytes,
            reads: Arc::clone(&reads),
        },
        options(),
    )
    .unwrap();
    let before = reads.load(Ordering::Relaxed);
    assert!(
        archive
            .copy_range_to("data", 99..100, &mut Vec::new())
            .is_err()
    );
    assert_eq!(reads.load(Ordering::Relaxed), before);
}

#[test]
fn short_inconsistent_and_failing_sources_keep_their_acquisition_context() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary);
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    assert!(matches!(
        Archive::open(InconsistentLength(bytes), options()),
        Err(PithosError::Source(SourceError::UnexpectedEof { .. }))
    ));
    assert!(matches!(
        Archive::open(FailingSource, options()),
        Err(PithosError::Source(SourceError::Remote { offset: 0, .. }))
    ));
}

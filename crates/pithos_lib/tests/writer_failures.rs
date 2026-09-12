mod common;

use common::writer::options;
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, CdcConfig, EntryKind, EntryMetadata,
    OpenOptions, ProcessingOptions, WriteOptions, WriterError,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::error::PithosError;
use pithos_lib::source::MemorySource;
use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

struct SensitiveDebugSink {
    writes: usize,
}
impl std::fmt::Debug for SensitiveDebugSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SINK_PLAINTEXT_SENTINEL")
    }
}
impl Write for SensitiveDebugSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes > 2 {
            return Err(io::Error::other("sink failure"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_errors_redact_caller_owned_sink_debug_output() {
    let sender = PrivateKey::generate();
    let create = match ArchiveWriter::create(
        SensitiveDebugSink { writes: 0 },
        WriteOptions::new(sender, Vec::new()),
    ) {
        Ok(_) => panic!("empty recipients must fail"),
        Err(error) => error,
    };
    assert!(!format!("{create:?}").contains("SINK_PLAINTEXT_SENTINEL"));
    let finish = ArchiveWriter::create(SensitiveDebugSink { writes: 0 }, options())
        .unwrap()
        .finish()
        .unwrap_err();
    assert!(!format!("{finish:?}").contains("SINK_PLAINTEXT_SENTINEL"));
    assert!(
        std::error::Error::source(&create)
            .and_then(|source| source.downcast_ref::<PithosError>())
            .is_some()
    );
    assert!(
        std::error::Error::source(&finish)
            .and_then(|source| source.downcast_ref::<PithosError>())
            .is_some()
    );
}

#[test]
fn pre_stream_validation_error_leaves_writer_usable_and_actual_size_is_published() {
    let sender = PrivateKey::generate();
    let reader = sender.duplicate();
    let recipient = sender.public_key();
    let mut writer =
        ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap();
    writer
        .add_directory(
            ArchivePath::new("parent").unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    assert!(
        writer
            .add_directory(
                ArchivePath::new("parent").unwrap(),
                EntryMetadata::new(0, 0, 0o755)
            )
            .is_err()
    );
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::default(),
            None,
            Cursor::new(b"actual size"),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )
    .unwrap();
    assert!(matches!(
        archive.entry("data").unwrap().unwrap().kind,
        EntryKind::File { size: 11, .. }
    ));
}

#[test]
fn actual_size_is_derived_and_expected_size_mismatch_poisons() {
    let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
    let error = writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(9),
            Cursor::new(b"actual"),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        WriterError::Pithos(PithosError::WriterExpectedSizeMismatch {
            expected: 9,
            actual: 6
        })
    ));
    assert!(matches!(
        writer.finish().unwrap_err().error(),
        PithosError::WriterPoisoned
    ));
}

struct FailingReader;
impl Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("source failure"))
    }
}

struct PanicOnRead;
impl Read for PanicOnRead {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        panic!("hierarchy validation read content")
    }
}

#[test]
fn missing_parent_fails_before_content_read_and_leaves_writer_usable() {
    let sender = PrivateKey::generate();
    let reader = sender.duplicate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![reader.public_key()]),
    )
    .unwrap();

    assert!(
        writer
            .add_file(
                ArchivePath::new("parent/child").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                None,
                PanicOnRead,
            )
            .is_err()
    );
    writer
        .add_directory(
            ArchivePath::new("parent").unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    writer
        .add_file(
            ArchivePath::new("parent/child").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(2),
            Cursor::new(b"ok"),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(reader)),
    )
    .unwrap();
    let mut output = Vec::new();
    archive.copy_to("parent/child", &mut output).unwrap();
    assert_eq!(output, b"ok");
}
struct ReaderAfterBytes {
    bytes: Vec<u8>,
    served: bool,
}
impl Read for ReaderAfterBytes {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.served {
            return Err(io::Error::other("source failure after blocks"));
        }
        self.served = true;
        let length = output.len().min(self.bytes.len());
        output[..length].copy_from_slice(&self.bytes[..length]);
        Ok(length)
    }
}

#[test]
fn post_stream_input_failure_poisons_and_recovers_only_incomplete_sink() {
    let mut writer = ArchiveWriter::create(Vec::new(), options()).unwrap();
    assert!(
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                FailingReader
            )
            .is_err()
    );
    assert!(matches!(
        writer.add_directory(
            ArchivePath::new("later").unwrap(),
            EntryMetadata::new(0, 0, 0o755)
        ),
        Err(WriterError::Poisoned)
    ));
    let bytes = writer.into_incomplete().unwrap();
    assert_eq!(&bytes[..4], b"PITH");
    assert!(!bytes.windows(8).any(|window| window == b"PITHOSDR"));
}

#[test]
fn input_failure_between_emitted_blocks_poisons_the_writer() {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let mut state = 1u32;
    let bytes = (0..4096)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 24) as u8
        })
        .collect();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender, vec![recipient]).with_cdc(CdcConfig::new(64, 256, 1024).unwrap()),
    )
    .unwrap();
    assert!(
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                ReaderAfterBytes {
                    bytes,
                    served: false
                }
            )
            .is_err()
    );
    assert!(matches!(
        writer.add_directory(
            ArchivePath::new("later").unwrap(),
            EntryMetadata::new(0, 0, 0o755)
        ),
        Err(WriterError::Poisoned)
    ));
    let bytes = writer.into_incomplete().unwrap();
    assert!(bytes.windows(4).any(|window| window == b"BLCK"));
    assert!(!bytes.windows(8).any(|window| window == b"PITHOSDR"));
}

#[derive(Debug)]
struct FailAfterHeader {
    bytes: Vec<u8>,
    writes: usize,
}
impl Write for FailAfterHeader {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes > 2 {
            return Err(io::Error::other("sink failure"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn sink_failure_after_stream_start_poisoned_writer_returns_incomplete_sink() {
    let sink = FailAfterHeader {
        bytes: Vec::new(),
        writes: 0,
    };
    let mut writer = ArchiveWriter::create(sink, options()).unwrap();
    assert!(
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                Cursor::new(b"payload")
            )
            .is_err()
    );
    let sink = writer.into_incomplete().unwrap();
    assert_eq!(&sink.bytes[..4], b"PITH");
}

#[test]
fn block_marker_failure_poisons_and_returns_the_incomplete_sink() {
    let sink = FailAfterHeader {
        bytes: Vec::new(),
        writes: 0,
    };
    let mut writer = ArchiveWriter::create(sink, options()).unwrap();
    assert!(
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                Cursor::new(b"payload")
            )
            .is_err()
    );
    let sink = writer.into_incomplete().unwrap();
    assert_eq!(&sink.bytes[..4], b"PITH");
    assert!(!sink.bytes.windows(4).any(|window| window == b"BLCK"));
}

#[test]
fn directory_write_failure_returns_an_incomplete_sink() {
    let sink = FailAfterHeader {
        bytes: Vec::new(),
        writes: 0,
    };
    let error = ArchiveWriter::create(sink, options())
        .unwrap()
        .finish()
        .unwrap_err();
    let mut source = std::error::Error::source(error.error());
    let mut found_sink_failure = false;
    while let Some(error) = source {
        found_sink_failure |= error.to_string().contains("sink failure");
        source = error.source();
    }
    assert!(found_sink_failure, "the underlying sink failure was lost");
    assert!(matches!(error.error(), PithosError::Serialization(_)));
    let sink = error.into_incomplete();
    assert_eq!(&sink.bytes[..4], b"PITH");
    assert!(!sink.bytes.windows(8).any(|window| window == b"PITHOSDR"));
}

#[derive(Debug)]
struct FailDuringDirectory {
    bytes: Vec<u8>,
    writes: usize,
}
impl Write for FailDuringDirectory {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes == 5 {
            return Err(io::Error::other("mid-directory failure"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn mid_directory_failure_returns_an_incomplete_sink() {
    let error = ArchiveWriter::create(
        FailDuringDirectory {
            bytes: Vec::new(),
            writes: 0,
        },
        options(),
    )
    .unwrap()
    .finish()
    .unwrap_err();
    let sink = error.into_incomplete();
    assert_eq!(&sink.bytes[..4], b"PITH");
    assert!(sink.bytes.windows(8).any(|window| window == b"PITHOSDR"));
}

#[derive(Debug)]
struct FailPayload {
    bytes: Vec<u8>,
    writes: usize,
}
impl Write for FailPayload {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes > 3 {
            return Err(io::Error::other("payload failure"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn payload_write_failure_poisons_the_writer() {
    let sink = FailPayload {
        bytes: Vec::new(),
        writes: 0,
    };
    let mut writer = ArchiveWriter::create(sink, options()).unwrap();
    assert!(
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                Cursor::new(b"payload")
            )
            .is_err()
    );
    let sink = writer.into_incomplete().unwrap();
    assert!(sink.bytes.windows(4).any(|window| window == b"BLCK"));
}

#[derive(Debug)]
struct FlushFail(Vec<u8>);
impl Write for FlushFail {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failure"))
    }
}
#[test]
fn flush_failure_returns_an_incomplete_sink_without_claiming_durability() {
    let error = ArchiveWriter::create(FlushFail(Vec::new()), options())
        .unwrap()
        .finish()
        .unwrap_err();
    assert!(matches!(error.error(), PithosError::Io(_)));
    assert!(
        error
            .into_incomplete()
            .0
            .windows(8)
            .any(|window| window == b"PITHOSDR")
    );
}

#[derive(Clone, Debug)]
struct SharedSink(Rc<RefCell<Vec<u8>>>);
impl Write for SharedSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
#[test]
fn dropping_an_open_writer_cannot_publish_a_complete_archive() {
    let bytes = Rc::new(RefCell::new(Vec::new()));
    {
        let _writer = ArchiveWriter::create(SharedSink(Rc::clone(&bytes)), options()).unwrap();
    }
    let bytes = bytes.borrow();
    assert_eq!(&bytes[..4], b"PITH");
    assert!(!bytes.windows(8).any(|window| window == b"PITHOSDR"));
}

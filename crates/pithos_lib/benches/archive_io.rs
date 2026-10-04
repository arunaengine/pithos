mod support;
mod workloads;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::{ArchiveSource, FileSource, SourceError};
use std::hint::black_box;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

const PAYLOAD_LEN: usize = 1024 * 1024;

struct Counters {
    reads: AtomicU64,
    bytes: AtomicU64,
}

impl Counters {
    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.bytes.store(0, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.reads.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }
}

struct CountingSource {
    source: FileSource,
    counters: Arc<Counters>,
}

impl ArchiveSource for CountingSource {
    fn len(&self) -> Result<u64, SourceError> {
        self.source.len()
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
        self.source.read_exact_at(offset, buffer)?;
        self.counters.reads.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(buffer.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

struct Fixture {
    temporary: tempfile::TempDir,
    archive_path: PathBuf,
    sender: PrivateKey,
    archive_bytes: u64,
}

fn payload() -> Vec<u8> {
    (0..PAYLOAD_LEN).map(|index| (index % 251) as u8).collect()
}

fn write_archive(
    path: &Path,
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    bytes: &[u8],
) {
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(path).unwrap(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::default(),
            Some(bytes.len() as u64),
            Cursor::new(bytes),
        )
        .unwrap();
    writer.finish().unwrap();
}

fn fixture(sender: PrivateKey, recipient: pithos_lib::crypto::PublicKey, bytes: &[u8]) -> Fixture {
    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("archive.pith");
    write_archive(&archive_path, sender.duplicate(), recipient, bytes);
    workloads::append_child_generation(&archive_path, temporary.path(), &sender, recipient);
    let archive_bytes = std::fs::metadata(&archive_path).unwrap().len();
    Fixture {
        temporary,
        archive_path,
        sender,
        archive_bytes,
    }
}

fn open_counting(fixture: &Fixture) -> (Archive<CountingSource>, Arc<Counters>) {
    let counters = Arc::new(Counters {
        reads: AtomicU64::new(0),
        bytes: AtomicU64::new(0),
    });
    let source = CountingSource {
        source: FileSource::open(&fixture.archive_path).unwrap(),
        counters: Arc::clone(&counters),
    };
    let archive = Archive::open(
        source,
        OpenOptions::default()
            .with_access_keys(AccessKeys::new().with_key(fixture.sender.duplicate())),
    )
    .unwrap();
    counters.reset();
    (archive, counters)
}

fn read_run(fixture: &Fixture, range: Option<std::ops::Range<u64>>) -> (u64, u64, u64) {
    let (archive, counters) = open_counting(fixture);
    let mut sink = support::CountingSink::default();
    match range {
        Some(range) => archive.copy_range_to("data", range, &mut sink).unwrap(),
        None => archive.copy_to("data", &mut sink).unwrap(),
    }
    let (reads, bytes) = counters.snapshot();
    (sink.0, reads, bytes)
}

fn bench_archive_io(c: &mut Criterion) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let payload = payload();
    let fixture = fixture(sender, recipient, &payload);
    let archive_bytes = fixture.archive_bytes;

    let create_temporary = tempfile::tempdir().unwrap();
    let create_path = create_temporary.path().join("created.pith");
    support::measure(
        "archive_io/sequential-create",
        "payload, temporary directory, and key prepared outside create",
        || {
            write_archive(
                &create_path,
                fixture.sender.duplicate(),
                recipient,
                &payload,
            )
        },
        |_| support::Metrics::archive(std::fs::metadata(&create_path).unwrap().len()),
    );
    c.bench_function("archive_io/sequential-create", |b| {
        b.iter_batched(
            || (tempfile::tempdir().unwrap(), fixture.sender.duplicate()),
            |(temporary, key)| {
                let path = temporary.path().join("created.pith");
                write_archive(&path, key, recipient, &payload);
                black_box(temporary)
            },
            BatchSize::SmallInput,
        )
    });

    support::measure(
        "archive_io/open-merge",
        "two-generation archive prebuilt; FileSource open and directory-chain merge are the workload",
        || {
            let counters = Arc::new(Counters {
                reads: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
            });
            let source = CountingSource {
                source: FileSource::open(&fixture.archive_path).unwrap(),
                counters: Arc::clone(&counters),
            };
            let archive = Archive::open(
                source,
                OpenOptions::default()
                    .with_access_keys(AccessKeys::new().with_key(fixture.sender.duplicate())),
            )
            .unwrap();
            (archive, counters)
        },
        |(_, counters)| {
            let (reads, bytes) = counters.snapshot();
            assert!(
                reads >= 4,
                "open-merge must read both directory generations"
            );
            support::Metrics {
                archive_bytes,
                output_bytes: 0,
                source_read_count: Some(reads),
                source_read_bytes: Some(bytes),
                bytes_appended: None,
                dedup_signal: None,
            }
        },
    );
    c.bench_function("archive_io/open-merge", |b| {
        b.iter(|| {
            let counters = Arc::new(Counters {
                reads: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
            });
            let source = CountingSource {
                source: FileSource::open(&fixture.archive_path).unwrap(),
                counters,
            };
            black_box(
                Archive::open(
                    source,
                    OpenOptions::default()
                        .with_access_keys(AccessKeys::new().with_key(fixture.sender.duplicate())),
                )
                .unwrap(),
            );
        })
    });

    for (name, range) in [
        ("sequential-full-read", None),
        ("range-prefix", Some(0..4096)),
        (
            "range-middle",
            Some((PAYLOAD_LEN as u64 / 2)..(PAYLOAD_LEN as u64 / 2 + 4096)),
        ),
        ("range-tiny", Some(17..18)),
        ("range-full", Some(0..PAYLOAD_LEN as u64)),
    ] {
        let workload = format!("archive_io/{name}");
        support::measure(
            &workload,
            "archive opened from FileSource before read",
            || read_run(&fixture, range.clone()),
            |(output_bytes, reads, bytes)| support::Metrics {
                archive_bytes,
                output_bytes: *output_bytes,
                source_read_count: Some(*reads),
                source_read_bytes: Some(*bytes),
                bytes_appended: None,
                dedup_signal: None,
            },
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || open_counting(&fixture),
                |(archive, _)| {
                    let mut sink = support::CountingSink::default();
                    match range.clone() {
                        Some(range) => archive.copy_range_to("data", range, &mut sink).unwrap(),
                        None => archive.copy_to("data", &mut sink).unwrap(),
                    }
                    (archive, black_box(sink.0))
                },
                BatchSize::SmallInput,
            )
        });
    }
    black_box(&fixture.temporary);
}

criterion_group!(archive_io, bench_archive_io);
criterion_main!(archive_io);

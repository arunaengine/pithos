mod support;
mod workloads;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::source::MemorySource;
use std::hint::black_box;
use std::io::Cursor;

const EMPTY: [u8; 0] = [];
const DUPLICATE: [u8; 1] = *b"x";

fn writer(sender: PrivateKey, recipient: pithos_lib::crypto::PublicKey) -> ArchiveWriter<Vec<u8>> {
    ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap()
}

fn add_file(writer: &mut ArchiveWriter<Vec<u8>>, path: String, bytes: &'static [u8]) {
    writer
        .add_file(
            ArchivePath::new(path).unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(bytes.len() as u64),
            Cursor::new(bytes),
        )
        .unwrap();
}

fn build_flat(
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    count: usize,
) -> Vec<u8> {
    let mut writer = writer(sender, recipient);
    for index in 0..count {
        add_file(&mut writer, format!("entry-{index:06}"), &EMPTY);
    }
    writer.finish().unwrap()
}

fn build_duplicate(
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    count: usize,
) -> Vec<u8> {
    let mut writer = writer(sender, recipient);
    for index in 0..count {
        add_file(&mut writer, format!("duplicate-{index:06}"), &DUPLICATE);
    }
    writer.finish().unwrap()
}

fn build_deep(
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    depth: usize,
) -> Vec<u8> {
    let mut writer = writer(sender, recipient);
    let mut path = String::new();
    for index in 0..depth {
        if !path.is_empty() {
            path.push('/');
        }
        path.push_str(&format!("level-{index:04}"));
        writer
            .add_directory(
                ArchivePath::new(&path).unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
    }
    writer.finish().unwrap()
}

fn bench_build(
    c: &mut Criterion,
    name: String,
    sender: &PrivateKey,
    operation: impl Fn(PrivateKey) -> Vec<u8> + Copy,
) {
    support::measure(
        &name,
        "key prepared outside operation",
        || operation(sender.duplicate()),
        |bytes| support::Metrics::archive(bytes.len() as u64),
    );
    c.bench_function(&name, |b| {
        b.iter_batched(
            || sender.duplicate(),
            |sender| black_box(operation(sender)),
            BatchSize::SmallInput,
        )
    });
}

fn bench_archive_path(c: &mut Criterion) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    for count in [1_000, 10_000] {
        bench_build(c, format!("archive_path/flat/{count}"), &sender, |key| {
            build_flat(key, recipient, count)
        });
        bench_build(
            c,
            format!("archive_path/duplicate/{count}"),
            &sender,
            |key| build_duplicate(key, recipient, count),
        );
    }
    for count in [1_000, 10_000] {
        let workload = format!("archive_path/flat-index-open/{count}");
        let archive_bytes = build_flat(sender.duplicate(), recipient, count);
        let archive_len = archive_bytes.len() as u64;
        support::measure(
            &workload,
            "flat archive and access key prepared; cloning the in-memory source and open construct and validate the effective index",
            || {
                Archive::open(
                    MemorySource::new(archive_bytes.clone()),
                    OpenOptions::default()
                        .with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
                )
                .unwrap()
            },
            |_| support::Metrics::archive(archive_len),
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || archive_bytes.clone(),
                |bytes| {
                    black_box(
                        Archive::open(
                            MemorySource::new(bytes),
                            OpenOptions::default()
                                .with_access_keys(AccessKeys::new().with_key(sender.duplicate())),
                        )
                        .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
    if std::env::var_os("PITHOS_BENCH_100K").is_some() {
        for (name, operation) in [
            (
                "flat",
                build_flat as fn(PrivateKey, pithos_lib::crypto::PublicKey, usize) -> Vec<u8>,
            ),
            ("duplicate", build_duplicate),
        ] {
            bench_build(c, format!("archive_path/{name}/100000"), &sender, |key| {
                operation(key, recipient, 100_000)
            });
        }
    }
    for depth in [10, 100, 1_000] {
        bench_build(c, format!("archive_path/deep/{depth}"), &sender, |key| {
            build_deep(key, recipient, depth)
        });
    }
    for (name, direction) in [
        (
            "existing-ancestor",
            workloads::ConflictDirection::ExistingAncestor,
        ),
        (
            "missing-ancestor",
            workloads::ConflictDirection::MissingAncestor,
        ),
    ] {
        let workload = format!("archive_path/conflicts/{name}/1000");
        let mut fixture =
            workloads::build_conflict_fixture(sender.duplicate(), recipient, 1_000, direction);
        support::measure(
            &workload,
            "1000-entry writer prepared; one hierarchy rejection is measured",
            || workloads::reject_conflict(&mut fixture),
            |_| support::Metrics::operation(),
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || {
                    workloads::build_conflict_fixture(
                        sender.duplicate(),
                        recipient,
                        1_000,
                        direction,
                    )
                },
                |mut fixture| black_box(workloads::reject_conflict(&mut fixture)),
                BatchSize::SmallInput,
            )
        });
    }
    bench_build(
        c,
        "archive_path/incremental/ancestor-first/1000".into(),
        &sender,
        |key| workloads::build_incremental(key, recipient, 1_000),
    );
    for count in [100, 1_000] {
        bench_build(
            c,
            format!("archive_path/metadata-heavy/{count}"),
            &sender,
            |key| workloads::build_metadata_pairs(key, recipient, count),
        );
    }
    let extraction = workloads::build_extraction_fixture(sender.duplicate(), recipient);
    let destination = tempfile::tempdir().unwrap();
    let archive_bytes = extraction.archive_bytes;
    support::measure(
        "archive_path/extraction/100",
        "100-entry archive and empty destination prepared before filesystem extraction",
        || workloads::extract_all(&extraction, destination.path()),
        |output_bytes| support::Metrics {
            archive_bytes,
            output_bytes: *output_bytes,
            source_read_count: None,
            source_read_bytes: None,
            bytes_appended: None,
            dedup_signal: None,
        },
    );
    c.bench_function("archive_path/extraction/100", |b| {
        b.iter_batched(
            || {
                (
                    workloads::build_extraction_fixture(sender.duplicate(), recipient),
                    tempfile::tempdir().unwrap(),
                )
            },
            |(fixture, destination)| {
                let output = black_box(workloads::extract_all(&fixture, destination.path()));
                (fixture, destination, output)
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(archive_path, bench_archive_path);
criterion_main!(archive_path);

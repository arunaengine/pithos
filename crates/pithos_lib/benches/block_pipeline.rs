mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pithos_lib::archive::{
    ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use std::hint::black_box;
use std::io::{Cursor, Read};

struct VirtualReader {
    remaining: u64,
    state: u64,
}

impl VirtualReader {
    fn new(length: u64) -> Self {
        Self {
            remaining: length,
            state: 0x9e37_79b9_7f4a_7c15,
        }
    }
}

impl Read for VirtualReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let count = self.remaining.min(buffer.len() as u64) as usize;
        for byte in &mut buffer[..count] {
            *byte = support::next_deterministic_byte(&mut self.state);
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}

fn write_block_pipeline_archive(
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    bytes: &[u8],
) -> u64 {
    let mut writer = ArchiveWriter::create(
        support::CountingSink::default(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("block").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 3).unwrap(),
            Some(bytes.len() as u64),
            Cursor::new(bytes),
        )
        .unwrap();
    writer.finish().unwrap().0
}

fn write_streamed_archive(
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    logical_bytes: u64,
) -> u64 {
    let mut writer = ArchiveWriter::create(
        support::CountingSink::default(),
        WriteOptions::new(sender, vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("streamed.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 3).unwrap(),
            Some(logical_bytes),
            VirtualReader::new(logical_bytes),
        )
        .unwrap();
    writer.finish().unwrap().0
}

fn bench_transforms(c: &mut Criterion) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let compressible = vec![b'a'; 64 * 1024];
    let incompressible = support::deterministic_bytes(0x9e37_79b9_7f4a_7c15, 64 * 1024);
    for (name, bytes) in [
        ("compressible", &compressible),
        ("incompressible", &incompressible),
    ] {
        let workload = format!("block_pipeline/{name}");
        support::measure(
            &workload,
            "payload and key prepared before transform",
            || write_block_pipeline_archive(sender.duplicate(), recipient, bytes),
            |archive_bytes| support::Metrics::archive(*archive_bytes),
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || sender.duplicate(),
                |key| black_box(write_block_pipeline_archive(key, recipient, bytes)),
                BatchSize::SmallInput,
            );
        });
    }
    {
        let (name, logical_bytes) = ("streamed-quick", 8 * 1024 * 1024);
        let workload = format!("block_pipeline/{name}");
        support::measure(
            &workload,
            "virtual reader and discard sink; logical bytes are never allocated together",
            || write_streamed_archive(sender.duplicate(), recipient, logical_bytes),
            |archive_bytes| support::Metrics::archive(*archive_bytes),
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || sender.duplicate(),
                |key| black_box(write_streamed_archive(key, recipient, logical_bytes)),
                BatchSize::SmallInput,
            );
        });
    }
    if std::env::var_os("PITHOS_BENCH_LARGE_STREAM").is_some() {
        let logical_bytes = 64 * 1024 * 1024;
        support::measure(
            "block_pipeline/streamed-large",
            "env-gated virtual reader and discard sink",
            || write_streamed_archive(sender.duplicate(), recipient, logical_bytes),
            |archive_bytes| support::Metrics::archive(*archive_bytes),
        );
        c.bench_function("block_pipeline/streamed-large", |b| {
            b.iter_batched(
                || sender.duplicate(),
                |key| black_box(write_streamed_archive(key, recipient, logical_bytes)),
                BatchSize::SmallInput,
            );
        });
    }
}

criterion_group!(block_pipeline, bench_transforms);
criterion_main!(block_pipeline);

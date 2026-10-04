mod support;
mod workloads;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pithos_lib::archive::{
    AppendObservation, AppendOptions, ArchivePath, ArchiveWriter, EntryMetadata, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::fs::append_files;
use std::hint::black_box;
use std::io::Cursor;
use std::path::PathBuf;

const INPUT_BYTES: usize = 1024 * 1024;

struct AppendContext {
    temporary: tempfile::TempDir,
    archive_path: PathBuf,
    input_path: PathBuf,
    sender: PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    base_bytes: u64,
    input_bytes: u64,
    observation: Option<AppendObservation>,
}

fn prepare_append(
    sender: &PrivateKey,
    recipient: pithos_lib::crypto::PublicKey,
    duplicate: bool,
) -> AppendContext {
    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("archive.pith");
    let input_path = temporary.path().join("append.bin");
    let base = support::deterministic_bytes(0, INPUT_BYTES);
    let input = if duplicate {
        base.clone()
    } else {
        support::deterministic_bytes(1, INPUT_BYTES)
    };
    std::fs::write(&input_path, &input).unwrap();
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(&archive_path).unwrap(),
        WriteOptions::new(sender.duplicate(), vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("base.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::default(),
            Some(base.len() as u64),
            Cursor::new(base),
        )
        .unwrap();
    writer.finish().unwrap();
    let base_bytes = std::fs::metadata(&archive_path).unwrap().len();
    AppendContext {
        temporary,
        archive_path,
        input_path,
        sender: sender.duplicate(),
        recipient,
        base_bytes,
        input_bytes: input.len() as u64,
        observation: None,
    }
}

fn append_workflow(mut context: AppendContext) -> AppendContext {
    let _temporary = &context.temporary;
    context.observation = Some(
        append_files(
            &context.archive_path,
            AppendOptions::new(context.sender.duplicate(), vec![context.recipient]),
            std::slice::from_ref(&context.input_path),
        )
        .unwrap(),
    );
    context
}

fn bench_append(c: &mut Criterion) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    for (name, duplicate) in [("new-content", false), ("deduplicated-content", true)] {
        let workload = format!("append/{name}");
        let context = prepare_append(&sender, recipient, duplicate);
        support::measure(
            &workload,
            "base archive, input file, and keys prepared before supported locked direct append",
            || append_workflow(context),
            |context| {
                let final_bytes = std::fs::metadata(&context.archive_path).unwrap().len();
                let bytes_appended = final_bytes - context.base_bytes;
                let observation = context.observation.unwrap();
                assert_eq!(observation.base_archive_bytes, context.base_bytes);
                assert_eq!(observation.final_archive_bytes, final_bytes);
                support::Metrics {
                    archive_bytes: final_bytes,
                    output_bytes: bytes_appended,
                    source_read_count: Some(observation.source_read_count),
                    source_read_bytes: Some(observation.source_read_bytes),
                    bytes_appended: Some(bytes_appended),
                    dedup_signal: Some(bytes_appended < context.input_bytes),
                }
            },
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                || prepare_append(&sender, recipient, duplicate),
                |context| black_box(append_workflow(context)),
                BatchSize::SmallInput,
            )
        });
    }

    for generations in [1usize, 10, 100] {
        let workload = format!("append/multigeneration/{generations}");
        let prepare = || {
            let fixture = workloads::build_append_scaling_fixture(
                sender.duplicate(),
                recipient,
                generations,
                1,
            );
            let input = fixture.temporary.path().join("final-append.bin");
            std::fs::write(&input, b"final append benchmark payload").unwrap();
            (fixture, input)
        };
        let (measured_fixture, measured_input) = prepare();
        support::measure(
            &workload,
            "multigeneration archive and final input prepared before one supported locked direct append",
            move || {
                let original = measured_fixture.archive_bytes;
                let observation = append_files(
                    &measured_fixture.archive_path,
                    AppendOptions::new(
                        measured_fixture.sender.duplicate(),
                        vec![measured_fixture.recipient],
                    ),
                    &[measured_input],
                )
                .unwrap();
                (measured_fixture, original, observation)
            },
            |(fixture, original, observation)| {
                let final_bytes = std::fs::metadata(&fixture.archive_path).unwrap().len();
                let tail_bytes = final_bytes - *original;
                support::Metrics {
                    archive_bytes: final_bytes,
                    output_bytes: tail_bytes,
                    source_read_count: Some(observation.source_read_count),
                    source_read_bytes: Some(observation.source_read_bytes),
                    bytes_appended: Some(tail_bytes),
                    dedup_signal: Some(false),
                }
            },
        );
        c.bench_function(&workload, |b| {
            b.iter_batched(
                prepare,
                |(fixture, input)| {
                    black_box(
                        append_files(
                            &fixture.archive_path,
                            AppendOptions::new(fixture.sender.duplicate(), vec![fixture.recipient]),
                            &[input],
                        )
                        .unwrap(),
                    )
                },
                BatchSize::SmallInput,
            )
        });
    }
}

criterion_group!(append, bench_append);
criterion_main!(append);

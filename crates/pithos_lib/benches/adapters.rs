mod support;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use pithos_lib::adapters::crypt4gh;
use pithos_lib::adapters::ro_crate::{
    LoadedRoCrate, read_ro_crate_directory, read_ro_crate_zip, write_ro_crate,
};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, CdcConfig, Chunking, EntryMetadata,
    OpenOptions, ProcessingOptions, WriteOptions,
};
use pithos_lib::crypto::{PrivateKey, PublicKey};
use pithos_lib::source::FileSource;
use std::hint::black_box;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};

const DIRECTORY_PAYLOAD_BYTES: usize = 64 * 1024;
const LARGE_MEMBER_BYTES: usize = 1024 * 1024;
const ARCHIVE_ENTRY_PATH: &str = "verified.bin";

struct CrateFixture {
    temporary: tempfile::TempDir,
    path: PathBuf,
}

struct ArchiveFixture {
    temporary: tempfile::TempDir,
    path: PathBuf,
    recipient: PrivateKey,
    archive_bytes: u64,
}

fn metadata(member: &str) -> String {
    format!(
        r#"{{"@context":"https://w3id.org/ro/crate/1.2/context","@graph":[{{"@id":"ro-crate-metadata.json","@type":"CreativeWork","conformsTo":{{"@id":"https://w3id.org/ro/crate/1.2"}},"about":{{"@id":"./"}}}},{{"@id":"./","@type":"Dataset","name":"Adapter benchmark crate","description":"Deterministic adapter benchmark input","datePublished":"2024-01-01","license":"MIT","hasPart":[{{"@id":"{member}"}}]}},{{"@id":"{member}","@type":"File"}}]}}"#
    )
}

fn directory_fixture() -> CrateFixture {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("directory-crate");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("ro-crate-metadata.json"), metadata("content.bin")).unwrap();
    std::fs::write(
        path.join("content.bin"),
        support::deterministic_bytes(1, DIRECTORY_PAYLOAD_BYTES),
    )
    .unwrap();
    CrateFixture { temporary, path }
}

fn zip_fixture() -> CrateFixture {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("large-crate.zip");
    let payload = support::deterministic_bytes(1, LARGE_MEMBER_BYTES);
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("ro-crate-metadata.json", options).unwrap();
    zip.write_all(metadata("large.bin").as_bytes()).unwrap();
    zip.start_file("large.bin", options).unwrap();
    zip.write_all(&payload).unwrap();
    zip.finish().unwrap();
    CrateFixture { temporary, path }
}

fn write_archive_fixture(path: &Path, sender: PrivateKey, recipient: PublicKey) {
    let payload = support::deterministic_bytes(1, LARGE_MEMBER_BYTES);
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(path).unwrap(),
        WriteOptions::new(sender, vec![recipient]).with_chunking(Chunking::ContentDefined(
            CdcConfig::new(64, 256, 1024).unwrap(),
        )),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new(ARCHIVE_ENTRY_PATH).unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::default(),
            Some(payload.len() as u64),
            Cursor::new(payload),
        )
        .unwrap();
    writer.finish().unwrap();
}

fn archive_fixture() -> ArchiveFixture {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("verified.pith");
    let sender = PrivateKey::generate();
    let recipient = PrivateKey::generate();
    write_archive_fixture(&path, sender, recipient.public_key());
    let archive_bytes = std::fs::metadata(&path).unwrap().len();
    ArchiveFixture {
        temporary,
        path,
        recipient,
        archive_bytes,
    }
}

fn convert_ro_crate(
    loaded: LoadedRoCrate,
    sender: PrivateKey,
    recipient: PublicKey,
    cdc: CdcConfig,
) -> u64 {
    let mut writer = ArchiveWriter::create(
        support::CountingSink::default(),
        WriteOptions::new(sender, vec![recipient]).with_chunking(Chunking::ContentDefined(cdc)),
    )
    .unwrap();
    write_ro_crate(&mut writer, loaded, ProcessingOptions::default()).unwrap();
    writer.finish().unwrap().0
}

fn open_archive(fixture: &ArchiveFixture) -> Archive<FileSource> {
    Archive::open(
        FileSource::open(&fixture.path).unwrap(),
        OpenOptions::default()
            .with_access_keys(AccessKeys::new().with_key(fixture.recipient.duplicate())),
    )
    .unwrap()
}

fn export_crypt4gh(
    archive: Archive<FileSource>,
    recipients: Vec<PublicKey>,
    mut sink: support::CountingSink,
) -> u64 {
    crypt4gh::export(&archive, ARCHIVE_ENTRY_PATH, recipients, &mut sink).unwrap();
    sink.0
}

fn bench_adapters(c: &mut Criterion) {
    let sender = PrivateKey::generate();
    let recipient = sender.public_key();
    let cdc = CdcConfig::new(64, 256, 1024).unwrap();

    let directory = directory_fixture();
    let directory_workload = "adapters/ro-crate-directory-conversion";
    let loaded = read_ro_crate_directory(&directory.path).unwrap();
    let directory_sender = sender.duplicate();
    support::measure(
        directory_workload,
        "directory fixture, keys, and retained RO-Crate source loaded before conversion",
        || convert_ro_crate(loaded, directory_sender, recipient, cdc),
        |output_bytes| support::Metrics::archive(*output_bytes),
    );
    c.bench_function(directory_workload, |b| {
        b.iter_batched(
            || {
                (
                    read_ro_crate_directory(&directory.path).unwrap(),
                    sender.duplicate(),
                )
            },
            |(loaded, sender)| black_box(convert_ro_crate(loaded, sender, recipient, cdc)),
            BatchSize::SmallInput,
        )
    });

    let zip = zip_fixture();
    let zip_workload = "adapters/ro-crate-zip-large-member";
    let loaded = read_ro_crate_zip(&zip.path).unwrap();
    let zip_sender = sender.duplicate();
    support::measure(
        zip_workload,
        "1 MiB ZIP fixture, keys, and retained RO-Crate source loaded before bounded conversion",
        || convert_ro_crate(loaded, zip_sender, recipient, cdc),
        |output_bytes| support::Metrics::archive(*output_bytes),
    );
    c.bench_function(zip_workload, |b| {
        b.iter_batched(
            || (read_ro_crate_zip(&zip.path).unwrap(), sender.duplicate()),
            |(loaded, sender)| black_box(convert_ro_crate(loaded, sender, recipient, cdc)),
            BatchSize::SmallInput,
        )
    });

    let archive = archive_fixture();
    let export_recipient = PrivateKey::generate().public_key();
    let export_workload = "adapters/crypt4gh-export";
    let opened = open_archive(&archive);
    let recipients = vec![export_recipient];
    let sink = support::CountingSink::default();
    support::measure(
        export_workload,
        "verified archive opened and fresh counted output sink prepared before Crypt4GH export",
        || export_crypt4gh(opened, recipients, sink),
        |output_bytes| support::Metrics {
            archive_bytes: archive.archive_bytes,
            output_bytes: *output_bytes,
            source_read_count: None,
            source_read_bytes: None,
            bytes_appended: None,
            dedup_signal: None,
        },
    );
    c.bench_function(export_workload, |b| {
        b.iter_batched(
            || {
                (
                    open_archive(&archive),
                    vec![export_recipient],
                    support::CountingSink::default(),
                )
            },
            |(opened, recipients, sink)| black_box(export_crypt4gh(opened, recipients, sink)),
            BatchSize::SmallInput,
        )
    });

    black_box((&directory.temporary, &zip.temporary, &archive.temporary));
}

criterion_group!(adapters, bench_adapters);
criterion_main!(adapters);

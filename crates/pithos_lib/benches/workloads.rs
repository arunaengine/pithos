use pithos_lib::archive::{
    AccessKeys, AppendOptions, Archive, ArchivePath, ArchiveWriter, EntryMetadata, EntryReference,
    OpenOptions, ProcessingOptions, WriteOptions, WriterError,
};
use pithos_lib::crypto::{PrivateKey, PublicKey};
use pithos_lib::error::PithosError;
use pithos_lib::fs::{append_files, extract};
use pithos_lib::source::MemorySource;
use std::io::Cursor;
use std::path::{Path, PathBuf};

#[allow(dead_code)] // Used by the archive-path target and its fixture contract test.
pub const EXTRACTION_COUNT: usize = 100;
#[allow(dead_code)] // Used by the archive-path target and its fixture contract test.
pub const EXTRACTION_PAYLOAD_BYTES: usize = 1024;
#[allow(dead_code)] // Flat workloads use empty files when they include this module.
const EMPTY: [u8; 0] = [];
#[allow(dead_code)] // Metadata workloads use this fixed payload when they include this module.
const METADATA_JSON: &[u8] = br#"{"type":"benchmark-metadata"}"#;
#[allow(dead_code)] // Extraction workloads use this fixed payload when they include this module.
const EXTRACTION_PAYLOAD: [u8; EXTRACTION_PAYLOAD_BYTES] = [b'e'; EXTRACTION_PAYLOAD_BYTES];

#[allow(dead_code)] // Only archive-path benchmarks hierarchy-conflict directions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConflictDirection {
    ExistingAncestor,
    MissingAncestor,
}

#[allow(dead_code)] // Shared fixture builders use this only in targets that create archives.
fn writer(sender: PrivateKey, recipient: PublicKey) -> ArchiveWriter<Vec<u8>> {
    ArchiveWriter::create(Vec::new(), WriteOptions::new(sender, vec![recipient])).unwrap()
}

#[allow(dead_code)] // Shared fixture builders use this only in targets that create archives.
fn add_file(
    writer: &mut ArchiveWriter<Vec<u8>>,
    path: String,
    metadata: EntryMetadata,
    bytes: &'static [u8],
) {
    writer
        .add_file(
            ArchivePath::new(path).unwrap(),
            metadata,
            ProcessingOptions::new(false, 0).unwrap(),
            Some(bytes.len() as u64),
            Cursor::new(bytes),
        )
        .unwrap();
}

#[allow(dead_code)] // Only archive-path benchmarks incremental insertion.
pub fn build_incremental(sender: PrivateKey, recipient: PublicKey, count: usize) -> Vec<u8> {
    let mut writer = writer(sender, recipient);
    writer
        .add_directory(
            ArchivePath::new("root").unwrap(),
            EntryMetadata::new(0, 0, 0o755),
        )
        .unwrap();
    for index in 0..count {
        add_file(
            &mut writer,
            format!("root/entry-{index:06}"),
            EntryMetadata::new(0, 0, 0o644),
            &EMPTY,
        );
    }
    writer.finish().unwrap()
}

#[allow(dead_code)] // Only archive-path benchmarks metadata/data pairs.
pub fn build_metadata_pairs(sender: PrivateKey, recipient: PublicKey, count: usize) -> Vec<u8> {
    let mut writer = writer(sender, recipient);
    for index in 0..count {
        let metadata = writer
            .add_metadata(
                ArchivePath::new(format!("entry-{index:06}.meta")).unwrap(),
                EntryMetadata::new(index as u64, index as u64, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(METADATA_JSON.len() as u64),
                Cursor::new(METADATA_JSON),
            )
            .unwrap();
        add_file(
            &mut writer,
            format!("entry-{index:06}.data"),
            EntryMetadata::new(index as u64, index as u64, 0o644).with_references(vec![
                EntryReference {
                    target_file_id: metadata.id,
                    relationship: 0,
                },
            ]),
            &EMPTY,
        );
    }
    writer.finish().unwrap()
}

#[allow(dead_code)] // Only archive-path benchmarks hierarchy-conflict rejection.
pub struct ConflictFixture {
    pub writer: ArchiveWriter<Vec<u8>>,
    pub candidate: String,
}

#[allow(dead_code)] // Only archive-path benchmarks hierarchy-conflict setup.
pub fn build_conflict_fixture(
    sender: PrivateKey,
    recipient: PublicKey,
    count: usize,
    direction: ConflictDirection,
) -> ConflictFixture {
    assert!(count > 0);
    let mut writer = writer(sender, recipient);
    let candidate = match direction {
        ConflictDirection::ExistingAncestor => {
            add_file(
                &mut writer,
                "root".into(),
                EntryMetadata::new(0, 0, 0o644),
                &EMPTY,
            );
            for index in 1..count {
                add_file(
                    &mut writer,
                    format!("filler-{index:06}"),
                    EntryMetadata::new(0, 0, 0o644),
                    &EMPTY,
                );
            }
            "root/child".into()
        }
        ConflictDirection::MissingAncestor => {
            for index in 0..count {
                add_file(
                    &mut writer,
                    format!("filler-{index:06}"),
                    EntryMetadata::new(0, 0, 0o644),
                    &EMPTY,
                );
            }
            "root/child".into()
        }
    };
    ConflictFixture { writer, candidate }
}

#[allow(dead_code)] // Only archive-path benchmarks hierarchy-conflict rejection.
pub fn reject_conflict(fixture: &mut ConflictFixture) -> PithosError {
    match fixture.writer.add_file(
        ArchivePath::new(&fixture.candidate).unwrap(),
        EntryMetadata::new(0, 0, 0o644),
        ProcessingOptions::new(false, 0).unwrap(),
        Some(0),
        Cursor::new(&EMPTY),
    ) {
        Err(WriterError::Pithos(error @ PithosError::InvalidArchivePath { .. })) => error,
        other => panic!("expected hierarchy conflict, got {other:?}"),
    }
}

#[allow(dead_code)] // Only archive-path benchmarks extraction.
pub struct ExtractionFixture {
    pub archive: Archive<MemorySource>,
    pub archive_bytes: u64,
    pub paths: Vec<String>,
}

#[allow(dead_code)] // Only archive-path benchmarks extraction setup.
pub fn build_extraction_fixture(sender: PrivateKey, recipient: PublicKey) -> ExtractionFixture {
    let mut writer = writer(sender.duplicate(), recipient);
    let mut paths = Vec::with_capacity(EXTRACTION_COUNT);
    for index in 0..EXTRACTION_COUNT {
        let path = format!("entry-{index:06}");
        add_file(
            &mut writer,
            path.clone(),
            EntryMetadata::new(0, 0, 0o644),
            &EXTRACTION_PAYLOAD,
        );
        paths.push(path);
    }
    let bytes = writer.finish().unwrap();
    let archive_bytes = bytes.len() as u64;
    let archive = Archive::open(
        MemorySource::new(bytes),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    ExtractionFixture {
        archive,
        archive_bytes,
        paths,
    }
}

#[allow(dead_code)] // Only archive-path benchmarks extraction.
pub fn extract_all(fixture: &ExtractionFixture, destination: &Path) -> u64 {
    for path in &fixture.paths {
        extract(&fixture.archive, path, destination).unwrap();
    }
    (fixture.paths.len() * EXTRACTION_PAYLOAD_BYTES) as u64
}

#[allow(dead_code)] // Archive I/O uses this while append uses the larger scaling fixture.
pub struct ChainFixture {
    pub temporary: tempfile::TempDir,
    pub archive_path: PathBuf,
    pub sender: PrivateKey,
    pub recipient: PublicKey,
    pub archive_bytes: u64,
}

#[allow(dead_code)] // Archive I/O uses this to create the two-generation open fixture.
pub fn append_child_generation(
    archive_path: &Path,
    input_root: &Path,
    sender: &PrivateKey,
    recipient: PublicKey,
) {
    let child = input_root.join("child.bin");
    std::fs::write(&child, b"child").unwrap();
    append_files(
        archive_path,
        AppendOptions::new(sender.duplicate(), vec![recipient]),
        &[child],
    )
    .unwrap();
}

#[allow(dead_code)] // The fixture contract test validates this smaller append chain.
pub fn build_chain_fixture(sender: PrivateKey, recipient: PublicKey) -> ChainFixture {
    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("chain.pith");
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(&archive_path).unwrap(),
        WriteOptions::new(sender.duplicate(), vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("ancestor.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(8),
            Cursor::new(b"ancestor"),
        )
        .unwrap();
    writer.finish().unwrap();
    append_child_generation(&archive_path, temporary.path(), &sender, recipient);
    let archive_bytes = std::fs::metadata(&archive_path).unwrap().len();
    ChainFixture {
        temporary,
        archive_path,
        sender,
        recipient,
        archive_bytes,
    }
}

/// Builds a supported direct-append chain with every generation in its own terminal directory.
/// Input creation is deliberately separate from the append operations so benchmark setup remains
/// outside the measured final append.
#[allow(dead_code)] // Only append benchmarks multigeneration scaling.
pub fn build_append_scaling_fixture(
    sender: PrivateKey,
    recipient: PublicKey,
    generations: usize,
    entries_per_generation: usize,
) -> ChainFixture {
    let temporary = tempfile::tempdir().unwrap();
    let archive_path = temporary.path().join("append-scaling.pith");
    let mut writer = ArchiveWriter::create(
        std::fs::File::create(&archive_path).unwrap(),
        WriteOptions::new(sender.duplicate(), vec![recipient]),
    )
    .unwrap();
    writer
        .add_file(
            ArchivePath::new("ancestor.bin").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(8),
            Cursor::new(b"ancestor"),
        )
        .unwrap();
    writer.finish().unwrap();

    for generation in 0..generations {
        let input_root = temporary.path().join(format!("input-{generation:04}"));
        std::fs::create_dir(&input_root).unwrap();
        let inputs = (0..entries_per_generation)
            .map(|entry| {
                let name = format!("generation-{generation:04}-entry-{entry:04}.bin");
                let path = input_root.join(&name);
                std::fs::write(&path, format!("{generation:04}:{entry:04}")).unwrap();
                path
            })
            .collect::<Vec<_>>();
        append_files(
            &archive_path,
            AppendOptions::new(sender.duplicate(), vec![recipient]),
            &inputs,
        )
        .unwrap();
    }
    let archive_bytes = std::fs::metadata(&archive_path).unwrap().len();
    ChainFixture {
        temporary,
        archive_path,
        sender,
        recipient,
        archive_bytes,
    }
}

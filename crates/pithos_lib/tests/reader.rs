pub mod common;

use crate::common::util::{create_pithos_writer, load_test_keys, write_dummy_pithos};
use pithos_lib::error::PithosError;
use pithos_lib::helpers::chacha_poly1305::decrypt_chunk;
use pithos_lib::helpers::crypt4gh::{
    CRYPT4GH_ENCRYPTED_BLOCK_SIZE, Crypt4GHError, Crypt4GHHeader, Packet, PacketData,
};
use pithos_lib::helpers::directory::DirectoryBuilder;
use pithos_lib::helpers::file_entry_map::Key;
use pithos_lib::helpers::ro_crate::{RoCrateSource, read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithosreader::{ExternalBlockSource, PithosReaderSimple, ReaderLimits};
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::deserialization::DeserializationError;
use pithos_lib::model::structs::{
    BlockDataState, BlockLocation, FileEntry, FileHeader, FileType, Reference,
};
use rocraters::ro_crate::graph_vector::GraphVector;
use rocraters::ro_crate::read::CrateReadError;
use rocraters::ro_crate::schema::RoCrateSchemaVersion;
use std::fs::{File, OpenOptions, read, read_to_string, write};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use x25519_dalek::StaticSecret;

fn reader_key() -> StaticSecret {
    private_key_from_pem_bytes(
        std::fs::read("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_slice(),
    )
    .unwrap()
}

fn empty_entry(file_type: FileType, target: Option<&str>) -> FileEntry {
    FileEntry {
        file_type,
        block_data: BlockDataState::Decrypted(vec![]),
        created: 0,
        modified: 0,
        file_size: 0,
        permissions: 0o644,
        references: vec![],
        symlink_target: target.map(str::to_owned),
    }
}

fn caller_directory(
    archive: &Path,
    entry_path: &str,
    file_type: FileType,
    target: Option<&str>,
) -> (PithosReaderSimple, pithos_lib::model::structs::Directory) {
    let mut reader = PithosReaderSimple::new_with_key(archive, reader_key()).unwrap();
    let (mut directory, _) = reader.read_directory().unwrap();
    directory
        .files
        .insert(Key::new(9000, entry_path), empty_entry(file_type, target))
        .unwrap();
    (reader, directory)
}

#[test]
fn test_reader_rejects_invalid_header_magic_during_construction() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    bytes[0] = b'X';
    write(&archive, bytes).unwrap();

    let error = match PithosReaderSimple::new_with_key(&archive, reader_key()) {
        Ok(_) => panic!("reader construction must reject an invalid header magic"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        PithosError::Deserialization(DeserializationError::InvalidMarker(_))
    ));
}

#[test]
fn test_reader_rejects_invalid_header_version_during_construction() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    bytes[4..6].copy_from_slice(&[0x80, 0x04]);
    write(&archive, bytes).unwrap();

    let error = match PithosReaderSimple::new_with_key(&archive, reader_key()) {
        Ok(_) => panic!("reader construction must reject an unsupported header version"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("0x0100"),
        "missing supported version: {message}"
    );
    assert!(
        message.contains("0x0200"),
        "missing actual version: {message}"
    );
}

fn write_zip_entry(path: &Path, name: &str, content: &[u8]) {
    let file = File::create(path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    archive
        .start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(content).unwrap();
    archive.finish().unwrap();
}

fn append_empty_directory(path: &Path) {
    let (writer_key, _, reader_key) = load_test_keys();
    let mut writer = PithosWriter::new_from_file(writer_key, vec![reader_key], None, path).unwrap();
    writer.write_directory().unwrap();
    drop(writer);
}

fn complete_test_directory(parent: Option<(u64, u64)>) -> Vec<u8> {
    let mut directory = pithos_lib::model::structs::Directory {
        identifier: *b"PITHOSDR",
        parent_directory_offset: parent,
        files: pithos_lib::helpers::file_entry_map::FileEntryMap::new(),
        blocks: indexmap::IndexMap::new(),
        relations: vec![],
        encryption: indexmap::IndexMap::new(),
        dir_len: 0,
        crc32: 0,
    };
    let mut bytes = Vec::new();
    directory.serialize(&mut bytes).unwrap();
    directory.dir_len = bytes.len() as u64;
    bytes.clear();
    directory.serialize(&mut bytes).unwrap();
    let crc_start = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..crc_start]);
    bytes[crc_start..].copy_from_slice(&crc.to_be_bytes());
    bytes
}

fn directory_bounds(bytes: &[u8]) -> (usize, usize) {
    let length =
        u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap()) as usize;
    (bytes.len() - length, length)
}

fn write_identity_integrity_archive(
    temp_dir: &TempDir,
) -> (
    PathBuf,
    StaticSecret,
    pithos_lib::model::structs::Directory,
    [u8; 32],
) {
    let (archive, key, mut writer) = create_pithos_writer(temp_dir, None);
    writer.write_file_header().unwrap();
    writer
        .process_input(InputFile {
            file_type: FileType::Data,
            inner_path: "integrity.txt".into(),
            data: Content::Raw("deterministic integrity payload".into()),
            metadata: None,
            encrypt: false,
            compression_level: Some(0),
        })
        .unwrap();
    writer.write_directory().unwrap();
    drop(writer);

    let mut reader = PithosReaderSimple::new_with_key(&archive, key.clone()).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    let file_entry = directory.get_file_by_path("integrity.txt").unwrap();
    let hash = match &file_entry.block_data {
        BlockDataState::Decrypted(blocks) => blocks[0].0,
        BlockDataState::Encrypted(_) => panic!("identity archive has encrypted block data"),
    };
    (archive, key, directory, hash)
}

fn mutate_block_payload(
    archive: &Path,
    directory: &pithos_lib::model::structs::Directory,
    hash: [u8; 32],
) {
    let block = directory.blocks.get(&hash).unwrap();
    let mut bytes = read(archive).unwrap();
    let offset = block.offset as usize;
    assert_eq!(&bytes[offset..offset + 4], b"BLCK");
    bytes[offset + 4] ^= 1;
    write(archive, bytes).unwrap();
}

fn external_directory(
    mut directory: pithos_lib::model::structs::Directory,
    hash: [u8; 32],
) -> pithos_lib::model::structs::Directory {
    let block = directory.blocks.get_mut(&hash).unwrap();
    block.location = BlockLocation::External {
        url: "https://invalid.invalid/external-block".into(),
    };
    block.offset = u64::MAX;
    directory
}

struct RecordingExternalSource {
    response: Vec<u8>,
    requested_url: Arc<Mutex<Option<String>>>,
    requested_max: Arc<Mutex<Option<u64>>>,
}

struct SharedWriter(Arc<Mutex<Vec<u8>>>);

impl Write for SharedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl ExternalBlockSource for RecordingExternalSource {
    fn open(&self, url: &str, max_response_size: u64) -> Result<Box<dyn Read>, PithosError> {
        *self.requested_url.lock().unwrap() = Some(url.to_owned());
        *self.requested_max.lock().unwrap() = Some(max_response_size);
        Ok(Box::new(Cursor::new(self.response.clone())))
    }
}

fn external_block_bytes(
    archive: &Path,
    directory: &pithos_lib::model::structs::Directory,
    hash: [u8; 32],
) -> Vec<u8> {
    let block = directory.blocks.get(&hash).unwrap();
    let bytes = read(archive).unwrap();
    let start = block.offset as usize;
    let end = start + 4 + block.stored_size as usize;
    bytes[start..end].to_vec()
}

#[test]
fn test_external_blocks_use_injected_source_for_all_paths() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    let valid_response = external_block_bytes(&archive, &directory, hash);
    let directory = external_directory(directory, hash);
    let requested_url = Arc::new(Mutex::new(None));
    let requested_max = Arc::new(Mutex::new(None));
    let source = RecordingExternalSource {
        response: valid_response.clone(),
        requested_url: requested_url.clone(),
        requested_max: requested_max.clone(),
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key.clone())
        .unwrap()
        .with_external_block_source(Box::new(source));
    let output = temp_dir.path().join("external-full-success.txt");
    reader
        .read_file("integrity.txt", &directory, Some(&output), None)
        .unwrap();
    assert_eq!(read(&output).unwrap(), b"deterministic integrity payload");
    assert_eq!(
        requested_url.lock().unwrap().as_deref(),
        Some("https://invalid.invalid/external-block")
    );
    assert_eq!(
        *requested_max.lock().unwrap(),
        Some(4 + directory.blocks.get(&hash).unwrap().stored_size + 1)
    );

    let source = RecordingExternalSource {
        response: valid_response.clone(),
        requested_url: Arc::new(Mutex::new(None)),
        requested_max: Arc::new(Mutex::new(None)),
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key.clone())
        .unwrap()
        .with_external_block_source(Box::new(source));
    let range_bytes = Arc::new(Mutex::new(Vec::new()));
    let mut range_output: Box<dyn Write> = Box::new(SharedWriter(range_bytes.clone()));
    let file_entry = directory.get_file_by_path("integrity.txt").unwrap();
    reader
        .read_data_range_to_sink(2..10, file_entry, &directory.blocks, &mut range_output)
        .unwrap();
    assert_eq!(*range_bytes.lock().unwrap(), b"terminis");

    let recipient = public_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient2_public.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let source = RecordingExternalSource {
        response: valid_response,
        requested_url: Arc::new(Mutex::new(None)),
        requested_max: Arc::new(Mutex::new(None)),
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .with_external_block_source(Box::new(source));
    let crypt4gh_output = Arc::new(Mutex::new(Vec::new()));
    reader
        .read_file_to_crypt4gh(
            "integrity.txt",
            &directory,
            vec![recipient],
            Some(Box::new(SharedWriter(crypt4gh_output.clone()))),
        )
        .unwrap();
    assert!(!crypt4gh_output.lock().unwrap().is_empty());
}

#[test]
fn test_external_blocks_reject_invalid_framing_without_plaintext() {
    let cases = [
        (
            b"BLCK".to_vec(),
            "external block framing error: short block payload",
        ),
        (
            [b"BLCK".as_slice(), b"deterministic integrity payload", b"x"].concat(),
            "external block framing error: response exceeds expected size",
        ),
        (
            [b"NOPE".as_slice(), b"deterministic integrity payload"].concat(),
            "external block framing error: invalid block marker",
        ),
    ];
    for (response, expected_error) in cases {
        let temp_dir = TempDir::new().unwrap();
        let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
        let directory = external_directory(directory, hash);
        let source = RecordingExternalSource {
            response,
            requested_url: Arc::new(Mutex::new(None)),
            requested_max: Arc::new(Mutex::new(None)),
        };
        let output = temp_dir.path().join("invalid-external.txt");
        let mut reader = PithosReaderSimple::new_with_key(&archive, key)
            .unwrap()
            .with_external_block_source(Box::new(source));
        let result = reader.read_file("integrity.txt", &directory, Some(&output), None);
        assert!(result.unwrap_err().to_string().contains(expected_error));
        assert!(!output.exists());
    }
}

#[test]
fn test_external_blocks_fail_closed_without_source() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    let directory = external_directory(directory, hash);

    let full_output = temp_dir.path().join("external-full.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key.clone()).unwrap();
    let full_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        reader.read_file("integrity.txt", &directory, Some(&full_output), None)
    }))
    .map_err(|panic| {
        let message = panic
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| panic.downcast_ref::<&str>().map(ToString::to_string))
            .unwrap_or_else(|| "unknown panic".into());
        PithosError::Other(message)
    })
    .and_then(|result| result);
    assert_eq!(
        full_result.unwrap_err().to_string(),
        "external block source required"
    );
    assert!(!full_output.exists());

    let range_output = temp_dir.path().join("external-range.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key.clone()).unwrap();
    let range_result = reader.read_file(
        "integrity.txt",
        &directory,
        Some(&range_output),
        #[allow(clippy::single_range_in_vec_init)]
        Some(vec![0..1]),
    );
    assert_eq!(
        range_result.unwrap_err().to_string(),
        "external block source required"
    );
    assert!(!range_output.exists());

    let recipient = public_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient2_public.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();
    let crypt4gh_result = reader.read_file_to_crypt4gh(
        "integrity.txt",
        &directory,
        vec![recipient],
        Some(Box::new(Vec::<u8>::new())),
    );
    assert_eq!(
        crypt4gh_result.unwrap_err().to_string(),
        "external block source required"
    );
}

#[test]
fn test_block_integrity_valid_identity_read() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, _) = write_identity_integrity_archive(&temp_dir);
    let output = temp_dir.path().join("valid.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();

    reader
        .read_file("integrity.txt", &directory, Some(&output), None)
        .unwrap();
    assert_eq!(read(&output).unwrap(), b"deterministic integrity payload");
}

#[test]
fn test_block_integrity_full_read_rejects_corruption_without_commit() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    mutate_block_payload(&archive, &directory, hash);
    let output = temp_dir.path().join("corrupt-full.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();

    assert!(matches!(
        reader.read_file("integrity.txt", &directory, Some(&output), None),
        Err(PithosError::BlockHashMismatch { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn test_block_integrity_range_read_rejects_corruption_without_commit() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    mutate_block_payload(&archive, &directory, hash);
    let output = temp_dir.path().join("corrupt-range.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();

    assert!(matches!(
        reader.read_file(
            "integrity.txt",
            &directory,
            Some(&output),
            #[allow(clippy::single_range_in_vec_init)]
            Some(vec![0..1]),
        ),
        Err(PithosError::BlockHashMismatch { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn test_block_integrity_crypt4gh_rejects_corruption_before_block_output() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    mutate_block_payload(&archive, &directory, hash);
    let recipient = public_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient2_public.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let output = temp_dir.path().join("corrupt.crypt4gh");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();
    let sink = Box::new(File::create(&output).unwrap());

    assert!(matches!(
        reader.read_file_to_crypt4gh("integrity.txt", &directory, vec![recipient], Some(sink)),
        Err(PithosError::BlockHashMismatch { .. })
    ));
    let output_bytes = read(&output).unwrap();
    let header = Crypt4GHHeader::try_from(output_bytes.as_slice()).unwrap();
    let header_len = 16
        + header
            .header_packets
            .iter()
            .map(|packet| packet.length as usize)
            .sum::<usize>();
    assert_eq!(output_bytes.len(), header_len);
}

#[test]
fn test_block_integrity_size_mismatch_precedes_output() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, mut directory, hash) = write_identity_integrity_archive(&temp_dir);
    directory.blocks.get_mut(&hash).unwrap().original_size += 1;
    let output = temp_dir.path().join("wrong-size.txt");
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();

    assert!(matches!(
        reader.read_file("integrity.txt", &directory, Some(&output), None),
        Err(PithosError::BlockSizeMismatch { .. })
    ));
    assert!(!output.exists());
}

#[test]
fn test_directory_integrity_valid_terminal_archive() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();

    assert!(reader.read_directory().is_ok());
}

#[test]
fn test_reader_reads_directory_built_without_manual_length_update() {
    let temp_dir = TempDir::new().unwrap();
    let directory = DirectoryBuilder::new()
        .set_relations(vec![])
        .build()
        .unwrap();
    let archive = temp_dir.path().join("builder-directory.pith");
    let mut bytes = FileHeader::default().serialize_to_bytes().unwrap();
    directory.serialize(&mut bytes).unwrap();
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    let (read_directory, _) = reader.read_directory().unwrap();

    assert_eq!(read_directory, directory);
}

#[test]
fn test_directory_integrity_terminal_marker_mutation() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    let (start, _) = directory_bounds(&bytes);
    bytes[start] ^= 1;
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::InvalidDirectoryMarker { .. })
    ));
}

#[test]
fn test_directory_integrity_terminal_crc_mutation() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::DirectoryChecksumMismatch { .. })
    ));
}

#[test]
fn test_directory_integrity_rejects_extra_unconsumed_byte() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    let (start, length) = directory_bounds(&bytes);
    let mut directory = bytes.split_off(start);
    directory.insert(directory.len() - 12, 0);
    let new_length = (length + 1) as u64;
    let footer_start = directory.len() - 12;
    directory[footer_start..footer_start + 8].copy_from_slice(&new_length.to_be_bytes());
    let crc_start = directory.len() - 4;
    let crc = crc32fast::hash(&directory[..crc_start]);
    directory[crc_start..].copy_from_slice(&crc.to_be_bytes());
    bytes.extend_from_slice(&directory);
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::DirectoryConsumptionMismatch { .. })
    ));
}

#[test]
fn test_directory_integrity_valid_append_chain() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    append_empty_directory(&archive);

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    assert!(reader.read_directory().is_ok());
}

#[test]
fn test_robust_terminal_footer_max_length_returns_error() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut bytes = read(&archive).unwrap();
    let footer_start = bytes.len() - 12;
    bytes[footer_start..footer_start + 8].copy_from_slice(&u64::MAX.to_be_bytes());
    write(&archive, bytes).unwrap();

    let result = PithosReaderSimple::new_with_key(&archive, reader_key())
        .unwrap()
        .read_directory();
    assert!(matches!(
        result,
        Err(PithosError::LimitExceeded {
            field: "directory",
            ..
        })
    ));
}

#[test]
fn test_robust_overlapping_parent_is_rejected_as_invalid_chain() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    append_empty_directory(&archive);
    let bytes = read(&archive).unwrap();
    let (final_start, final_length) = directory_bounds(&bytes);
    let mut final_directory = pithos_lib::model::structs::Directory::deserialize(
        &mut std::io::Cursor::new(&bytes[final_start..]),
    )
    .unwrap();
    final_directory.parent_directory_offset = Some(((final_start + 1) as u64, final_length as u64));
    final_directory.dir_len = 0;
    final_directory.crc32 = 0;
    let mut replacement = Vec::new();
    final_directory.serialize(&mut replacement).unwrap();
    final_directory.dir_len = replacement.len() as u64;
    replacement.clear();
    final_directory.serialize(&mut replacement).unwrap();
    let crc = crc32fast::hash(&replacement[..replacement.len() - 4]);
    let crc_start = replacement.len() - 4;
    replacement[crc_start..].copy_from_slice(&crc.to_be_bytes());
    let mut archive_bytes = bytes[..final_start].to_vec();
    archive_bytes.extend_from_slice(&replacement);
    write(&archive, archive_bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    let error = reader.read_directory().unwrap_err();
    assert!(error.to_string().contains("chain"));
}

#[test]
fn test_robust_parent_boundary_uses_immediate_child() {
    let temp_dir = TempDir::new().unwrap();
    let middle = complete_test_directory(None);
    let oldest = complete_test_directory(Some((33, middle.len() as u64)));
    let terminal = complete_test_directory(Some((6, oldest.len() as u64)));
    assert_eq!(oldest.len(), 27);
    assert_eq!(middle.len(), 25);
    let archive = temp_dir.path().join("three-directories.pithos");
    let mut bytes = FileHeader::default().serialize_to_bytes().unwrap();
    bytes.extend_from_slice(&oldest);
    bytes.extend_from_slice(&middle);
    bytes.extend_from_slice(&terminal);
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    let error = reader.read_directory().unwrap_err();
    assert!(
        matches!(error, PithosError::InvalidDirectoryChain(_)),
        "unexpected chain fixture error: {error:?}"
    );
}

#[test]
fn test_robust_oversized_stored_block_returns_error_without_commit() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, mut directory, _) = write_identity_integrity_archive(&temp_dir);
    let hash = match directory
        .get_file_by_path("integrity.txt")
        .unwrap()
        .block_data
        .clone()
    {
        BlockDataState::Decrypted(blocks) => blocks[0].0,
        BlockDataState::Encrypted(_) => unreachable!(),
    };
    directory.blocks.get_mut(&hash).unwrap().stored_size = u64::MAX;
    let output = temp_dir.path().join("oversized.txt");
    let result = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .read_file("integrity.txt", &directory, Some(&output), None);
    assert!(matches!(
        result,
        Err(PithosError::LimitExceeded {
            field: "stored block",
            ..
        })
    ));
    assert!(!output.exists());
}

#[test]
fn test_robust_zero_crypt4gh_packet_length_returns_error() {
    let mut bytes = Vec::from(b"crypt4gh".as_slice());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 68]);
    let result = Crypt4GHHeader::try_from(bytes.as_slice());
    assert!(matches!(result, Err(Crypt4GHError::FromBytesError(_))));
}

#[test]
fn test_robust_skipped_range_enforces_decoded_block_limit() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    let file_entry = directory.get_file_by_path("integrity.txt").unwrap();
    let block_end = directory.blocks.get(&hash).unwrap().original_size;
    let limits = ReaderLimits {
        max_decoded_block_bytes: 0,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .with_limits(limits);
    let mut sink: Box<dyn Write> = Box::new(Vec::<u8>::new());
    assert!(matches!(
        reader.read_data_range_to_sink(
            block_end..block_end + 1,
            file_entry,
            &directory.blocks,
            &mut sink,
        ),
        Err(PithosError::LimitExceeded {
            field: "decoded block",
            ..
        })
    ));
}

#[test]
fn test_robust_skipped_range_enforces_stored_block_limit() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, hash) = write_identity_integrity_archive(&temp_dir);
    let file_entry = directory.get_file_by_path("integrity.txt").unwrap();
    let block_end = directory.blocks.get(&hash).unwrap().original_size;
    let limits = ReaderLimits {
        max_stored_block_bytes: 0,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .with_limits(limits);
    let mut sink: Box<dyn Write> = Box::new(Vec::<u8>::new());
    assert!(matches!(
        reader.read_data_range_to_sink(
            block_end..block_end + 1,
            file_entry,
            &directory.blocks,
            &mut sink,
        ),
        Err(PithosError::LimitExceeded {
            field: "stored block",
            ..
        })
    ));
}

#[test]
fn test_robust_configured_directory_limit_returns_limit_error() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let limits = ReaderLimits {
        max_directory_bytes: 24,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key())
        .unwrap()
        .with_limits(limits);
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::LimitExceeded {
            field: "directory",
            ..
        })
    ));
}

#[test]
fn test_robust_configured_stored_block_limit_returns_limit_error() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, _) = write_identity_integrity_archive(&temp_dir);
    let limits = ReaderLimits {
        max_stored_block_bytes: 0,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .with_limits(limits);
    assert!(matches!(
        reader.read_file("integrity.txt", &directory, None, None),
        Err(PithosError::LimitExceeded {
            field: "stored block",
            ..
        })
    ));
}

#[test]
fn test_robust_configured_decoded_block_limit_returns_limit_error() {
    let temp_dir = TempDir::new().unwrap();
    let (archive, key, directory, _) = write_identity_integrity_archive(&temp_dir);
    let limits = ReaderLimits {
        max_decoded_block_bytes: 0,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, key)
        .unwrap()
        .with_limits(limits);
    assert!(matches!(
        reader.read_file("integrity.txt", &directory, None, None),
        Err(PithosError::LimitExceeded {
            field: "decoded block",
            ..
        })
    ));
}

#[test]
fn test_robust_configured_parent_depth_returns_limit_error() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    append_empty_directory(&archive);
    let limits = ReaderLimits {
        max_parent_directories: 0,
        ..ReaderLimits::default()
    };
    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key())
        .unwrap()
        .with_limits(limits);
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::LimitExceeded {
            field: "parent directories",
            ..
        })
    ));
}

#[test]
fn test_directory_integrity_parent_embedded_length_mismatch() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    append_empty_directory(&archive);
    let mut bytes = read(&archive).unwrap();
    let (final_start, final_length) = directory_bounds(&bytes);
    let final_directory = &bytes[final_start..final_start + final_length];
    let mut cursor = std::io::Cursor::new(final_directory);
    let directory = pithos_lib::model::structs::Directory::deserialize(&mut cursor).unwrap();
    let (parent_start, parent_length) = directory.parent_directory_offset.unwrap();
    let parent_start = parent_start as usize;
    let parent_length = parent_length as usize;
    let parent = &mut bytes[parent_start..parent_start + parent_length];
    parent[parent_length - 12..parent_length - 4]
        .copy_from_slice(&((parent_length + 1) as u64).to_be_bytes());
    let crc = crc32fast::hash(&parent[..parent_length - 4]);
    parent[parent_length - 4..].copy_from_slice(&crc.to_be_bytes());
    write(&archive, bytes).unwrap();

    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();
    assert!(matches!(
        reader.read_directory(),
        Err(PithosError::DirectoryLengthMismatch { .. })
    ));
}

#[test]
fn test_reader_single_file() {
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, false, false);
    let key_pem = PathBuf::from("tests/data/keys/recipient1_private.pem".to_string());

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    let inner_paths = reader.read_file_paths(&directory).unwrap();

    assert_eq!(inner_paths.len(), 1);
    assert_eq!(inner_paths[0].0, FileType::Data);
    assert_eq!(inner_paths[0].1, "t8.shakespeare.txt");
}

#[test]
fn test_safe_extraction_rejects_caller_constructed_unsafe_paths() {
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, false, false);
    let key = private_key_from_pem_bytes(
        std::fs::read("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(&pithos_file, key).unwrap();
    let (mut directory, _) = reader.read_directory().unwrap();
    let entry = FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(vec![]),
        created: 0,
        modified: 0,
        file_size: 0,
        permissions: 0o644,
        references: vec![],
        symlink_target: None,
    };
    directory
        .files
        .insert(Key::new(999, "../outside"), entry.clone())
        .unwrap();
    directory
        .files
        .insert(Key::new(1000, "/absolute"), entry)
        .unwrap();
    let output = temp_dir.path().join("output");
    std::fs::create_dir(&output).unwrap();
    assert!(
        reader
            .read_file("../outside", &directory, Some(&output), None)
            .is_err()
    );
    assert!(
        reader
            .read_file("/absolute", &directory, Some(&output), None)
            .is_err()
    );
    assert!(!temp_dir.path().join("outside").exists());
}

#[test]
fn test_safe_extraction_rejects_preexisting_parent_symlink() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let outside = temp.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::os::unix::fs::symlink(&outside, output.join("nested")).unwrap();
    let (mut reader, directory) = caller_directory(&archive, "nested/file", FileType::Data, None);
    assert!(
        reader
            .read_file("nested/file", &directory, Some(&output), None)
            .is_err()
    );
    assert!(!outside.join("file").exists());
}

#[test]
fn test_safe_extraction_rejects_existing_final_symlink() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let outside = temp.path().join("outside");
    std::fs::write(&outside, b"unchanged").unwrap();
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::os::unix::fs::symlink(&outside, output.join("file")).unwrap();
    let (mut reader, directory) = caller_directory(&archive, "file", FileType::Data, None);
    assert!(
        reader
            .read_file("file", &directory, Some(&output), None)
            .is_err()
    );
    assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
}

#[test]
fn test_safe_extraction_rejects_existing_final_regular_file() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    std::fs::write(output.join("file"), b"unchanged").unwrap();
    let (mut reader, directory) = caller_directory(&archive, "file", FileType::Data, None);
    assert!(
        reader
            .read_file("file", &directory, Some(&output), None)
            .is_err()
    );
    assert_eq!(std::fs::read(output.join("file")).unwrap(), b"unchanged");
}

#[test]
fn test_safe_extraction_rejects_existing_final_directory_for_data() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir_all(output.join("file")).unwrap();
    let (mut reader, directory) = caller_directory(&archive, "file", FileType::Data, None);
    assert!(
        reader
            .read_file("file", &directory, Some(&output), None)
            .is_err()
    );
    assert!(output.join("file").is_dir());
}

#[test]
fn test_safe_extraction_cleans_pending_file_after_read_failure() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let (mut reader, mut directory) = caller_directory(&archive, "failed", FileType::Data, None);
    for (_, path, entry) in directory.files.iter_mut() {
        if path == "failed" {
            entry.block_data = BlockDataState::Decrypted(vec![([9; 32], [0; 32])]);
        }
    }
    assert!(
        reader
            .read_file("failed", &directory, Some(&output), None)
            .is_err()
    );
    assert!(!output.join("failed").exists());
    assert!(!std::fs::read_dir(&output).unwrap().any(|item| {
        item.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".pithos-tmp-")
    }));
}

#[test]
fn test_safe_extraction_extracts_safe_nested_regular_file() {
    let temp = TempDir::new().unwrap();
    let (archive, key, mut writer) = create_pithos_writer(&temp, None);
    writer.write_file_header().unwrap();
    writer
        .process_input(InputFile {
            file_type: FileType::Data,
            inner_path: "nested/file".into(),
            data: Content::Raw("nested payload".into()),
            metadata: None,
            encrypt: false,
            compression_level: Some(0),
        })
        .unwrap();
    writer.write_directory().unwrap();
    let mut reader = PithosReaderSimple::new_with_key(&archive, key).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    reader
        .read_file("nested/file", &directory, Some(&output), None)
        .unwrap();
    assert_eq!(
        std::fs::read(output.join("nested/file")).unwrap(),
        b"nested payload"
    );
}

#[test]
fn test_safe_extraction_creates_contained_and_dangling_symlinks() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir_all(output.join("nested")).unwrap();
    let (mut reader, mut directory) = caller_directory(
        &archive,
        "nested/link",
        FileType::Symlink,
        Some("../target"),
    );
    directory
        .files
        .insert(
            Key::new(9001, "dangling"),
            empty_entry(FileType::Symlink, Some("missing/target")),
        )
        .unwrap();
    reader
        .read_file("nested/link", &directory, Some(&output), None)
        .unwrap();
    reader
        .read_file("dangling", &directory, Some(&output), None)
        .unwrap();
    assert_eq!(
        std::fs::read_link(output.join("nested/link")).unwrap(),
        PathBuf::from("../target")
    );
    assert_eq!(
        std::fs::read_link(output.join("dangling")).unwrap(),
        PathBuf::from("missing/target")
    );
}

#[test]
fn test_safe_extraction_rejects_caller_constructed_ancestor_conflict() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let (mut reader, mut directory) = caller_directory(&archive, "a", FileType::Data, None);
    directory
        .files
        .insert(Key::new(9001, "a/child"), empty_entry(FileType::Data, None))
        .unwrap();
    assert!(
        reader
            .read_file("a", &directory, Some(&output), None)
            .is_err()
    );
    assert!(!output.join("a").exists());
}

#[test]
fn test_reader_targeted_validation_rejects_reverse_caller_ancestor_conflict() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let (mut reader, mut directory) = caller_directory(&archive, "a/child", FileType::Data, None);
    directory
        .files
        .insert(Key::new(9001, "a"), empty_entry(FileType::Data, None))
        .unwrap();
    assert!(
        reader
            .read_file("a/child", &directory, Some(&output), None)
            .is_err()
    );
    assert!(!output.join("a/child").exists());
}

#[test]
fn test_reader_reads_unrelated_entries_without_full_map_revalidation() {
    let temp = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp, false, false);
    let output = temp.path().join("output");
    std::fs::create_dir(&output).unwrap();
    let (mut reader, mut directory) = caller_directory(&archive, "safe", FileType::Data, None);
    directory
        .files
        .insert(
            Key::new(9001, "conflict"),
            empty_entry(FileType::Data, None),
        )
        .unwrap();
    directory
        .files
        .insert(
            Key::new(9002, "conflict/child"),
            empty_entry(FileType::Data, None),
        )
        .unwrap();

    reader
        .read_file("safe", &directory, Some(&output), None)
        .unwrap();
    assert!(output.join("safe").exists());
}

#[test]
fn test_reader_hides_files_without_keys() {
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, false, false);
    let unauthorized_key = StaticSecret::from([0x42; 32]);

    let mut reader = PithosReaderSimple::new_with_key(pithos_file, unauthorized_key).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    assert!(directory.files.is_empty());
    assert!(reader.read_file_paths(&directory).unwrap().is_empty());
}

#[test]
fn test_reader_file_ranges() {
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, false, false);
    let key_pem = PathBuf::from("tests/data/keys/recipient1_private.pem".to_string());

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    let temp_dir = TempDir::new().unwrap();
    let outfile_single = temp_dir.path().join("range.txt");
    let outfile_multi = temp_dir.path().join("ranges.txt");
    if directory.get_file_by_path("t8.shakespeare.txt").is_some() {
        reader
            .read_file(
                "t8.shakespeare.txt",
                &directory,
                Some(&outfile_single),
                #[allow(clippy::single_range_in_vec_init)]
                Some(vec![261..272]),
            )
            .unwrap();
        assert_eq!("Shakespeare", read_to_string(outfile_single).unwrap());

        reader
            .read_file(
                "t8.shakespeare.txt",
                &directory,
                Some(&outfile_multi),
                Some(vec![261..272, 1434..1441]),
            )
            .unwrap();
        assert_eq!("Shakespeare Etexts", read_to_string(outfile_multi).unwrap());
    }
}

#[test]
fn test_reader_multiple_files() {
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, true, true);
    let key_pem = PathBuf::from("tests/data/keys/recipient1_private.pem".to_string());

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    let inner_paths = reader.read_file_paths(&directory).unwrap();

    assert_eq!(inner_paths.len(), 4);

    assert_eq!(inner_paths[0].0, FileType::Metadata);
    assert_eq!(inner_paths[0].1, "t8.shakespeare.txt.meta");
    assert_eq!(inner_paths[1].0, FileType::Data);
    assert_eq!(inner_paths[1].1, "t8.shakespeare.txt");

    assert_eq!(inner_paths[2].0, FileType::Metadata);
    assert_eq!(inner_paths[2].1, "SRR33138449.fastq.meta");
    assert_eq!(inner_paths[3].0, FileType::Data);
    assert_eq!(inner_paths[3].1, "SRR33138449.fastq");

    let file_entry = directory.get_file_by_path("t8.shakespeare.txt").unwrap();
    let reference = Reference {
        target_file_id: 0,
        relationship: 0,
    };
    assert!(file_entry.references.contains(&reference));

    let file_entry = directory.get_file_by_path("SRR33138449.fastq").unwrap();
    let reference = Reference {
        target_file_id: 2,
        relationship: 0,
    };
    assert!(file_entry.references.contains(&reference));
}

#[test]
fn test_rocrate_read_directory_1_2() {
    let loaded = read_ro_crate_directory("tests/data/dummy_dir").unwrap();
    assert_eq!(
        loaded.source,
        RoCrateSource::Directory(PathBuf::from("tests/data/dummy_dir"))
    );

    let mut expected_data_entity_ids = vec![
        "conclusions.txt",
        "dummy_results.txt",
        "dataset/",
        "literature/",
    ];
    let mut data_entity_ids = loaded
        .ro_crate
        .graph
        .iter()
        .filter_map(|entity| match entity {
            GraphVector::DataEntity(entity) => Some(entity.id.as_str()),
            _ => None,
        })
        .collect::<Vec<&str>>();
    data_entity_ids.sort_unstable();
    expected_data_entity_ids.sort_unstable();
    assert_eq!(data_entity_ids, expected_data_entity_ids);

    let mut contextual_entity_ids = loaded
        .ro_crate
        .graph
        .iter()
        .filter_map(|entity| match entity {
            GraphVector::ContextualEntity(entity) => Some(entity.id.as_str()),
            _ => None,
        })
        .collect::<Vec<&str>>();
    contextual_entity_ids.sort_unstable();
    let mut expected_contextual_entity_ids = vec![
        "mailto:josiah.carberry@example.com",
        "https://orcid.org/0000-0002-1825-0097",
    ];
    expected_contextual_entity_ids.sort_unstable();
    assert_eq!(contextual_entity_ids, expected_contextual_entity_ids);

    assert_eq!(
        loaded
            .ro_crate
            .graph
            .iter()
            .filter(|entity| matches!(entity, GraphVector::MetadataDescriptor(_)))
            .count(),
        1
    );
    assert_eq!(
        loaded
            .ro_crate
            .graph
            .iter()
            .filter(|entity| matches!(entity, GraphVector::RootDataEntity(_)))
            .count(),
        1
    );
    assert_eq!(
        loaded.ro_crate.get_rocrate_version(),
        Some(RoCrateSchemaVersion::V1_2)
    );
}

#[test]
fn test_rocrate_read_zip_1_1() {
    let loaded = read_ro_crate_zip("tests/data/ro-crate.zip").unwrap();

    assert_eq!(
        loaded.source,
        RoCrateSource::Zip(PathBuf::from("tests/data/ro-crate.zip"))
    );
    assert!(!loaded.ro_crate.graph.is_empty());
}

#[test]
fn test_rocrate_directory_requires_metadata() {
    let temp_dir = TempDir::new().unwrap();

    let error = read_ro_crate_directory(temp_dir.path()).unwrap_err();

    assert!(matches!(error, PithosError::MissingRoCrateMetadata(_)));
}

#[test]
fn test_rocrate_rejects_incomplete_root() {
    let temp_dir = TempDir::new().unwrap();
    let metadata_path = temp_dir.path().join("ro-crate-metadata.json");
    let metadata = r#"{
      "@context": "https://w3id.org/ro/crate/1.2/context",
      "@graph": [
        {
          "@id": "ro-crate-metadata.json",
          "@type": "CreativeWork",
          "conformsTo": {"@id": "https://w3id.org/ro/crate/1.2"},
          "about": {"@id": "./"}
        },
        {
          "@id": "./",
          "@type": "Dataset"
        }
      ]
    }"#;
    std::fs::write(metadata_path, metadata).unwrap();

    let error = read_ro_crate_directory(temp_dir.path()).unwrap_err();

    assert!(matches!(
        error,
        PithosError::RoCrate(CrateReadError::JsonError(_))
    ));
}

#[test]
fn test_rocrate_zip_returns_error_for_invalid_archive() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("invalid.zip");
    std::fs::write(&zip_path, b"not a ZIP archive").unwrap();

    let error = read_ro_crate_zip(&zip_path).unwrap_err();

    assert!(matches!(error, PithosError::Zip(_)));
}

#[test]
fn test_rocrate_zip_requires_root_metadata() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("without-metadata.zip");
    write_zip_entry(&zip_path, "data.txt", b"data");

    let error = read_ro_crate_zip(&zip_path).unwrap_err();

    assert!(matches!(error, PithosError::MissingRoCrateMetadata(_)));
}

#[test]
fn test_rocrate_zip_rejects_metadata_below_wrapper_directory() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("wrapped.zip");
    write_zip_entry(
        &zip_path,
        "wrapper/ro-crate-metadata.json",
        br#"{"@context":"https://w3id.org/ro/crate/1.1/context","@graph":[]}"#,
    );

    let error = read_ro_crate_zip(&zip_path).unwrap_err();

    assert!(matches!(error, PithosError::MissingRoCrateMetadata(_)));
}

#[test]
fn test_read_to_crypt4gh() {
    // Prepare Pithos file
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = write_dummy_pithos(&temp_dir, false, false);
    let reader_key_pem = PathBuf::from("tests/data/keys/recipient1_private.pem".to_string());

    // Read recipient public key
    let recipient_pem_content = read_to_string("tests/data/keys/recipient2_public.pem").unwrap();
    let recipient_key = public_key_from_pem_bytes(recipient_pem_content.as_bytes()).unwrap();

    // Export file in Crypt4GH format
    let mut reader = PithosReaderSimple::new(pithos_file, reader_key_pem).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    let crypt4gh_output_path = temp_dir.path().join("t8.shakespeare.crypt4gh");
    let crypt4gh_output = Box::new(
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&crypt4gh_output_path)
            .unwrap(),
    );
    reader
        .read_file_to_crypt4gh(
            "t8.shakespeare.txt",
            &directory,
            vec![recipient_key],
            Some(crypt4gh_output),
        )
        .unwrap();

    // Read recipient private key
    let reader_pem_content = read_to_string("tests/data/keys/recipient2_private.pem").unwrap();
    let reader_key = private_key_from_pem_bytes(reader_pem_content.as_bytes()).unwrap();

    // Read Crypt4GH file and deserialize/decrypt header
    let mut buffer = Vec::new();
    let mut input = File::open(&crypt4gh_output_path).unwrap();
    input.read_to_end(&mut buffer).unwrap();

    let mut header = Crypt4GHHeader::try_from(buffer.as_slice()).unwrap();
    let block_start: u64 = 16 // Magic bytes + version + packet count
        + header
            .header_packets
            .iter()
            .map(|hp| hp.length as u64)
            .sum::<u64>();
    let mut data_key = None;
    'outer: for header_packet in header.header_packets.iter_mut() {
        header_packet.decrypt(&reader_key).unwrap();
        if let PacketData::Decrypted(packets) = &header_packet.packet_data {
            for packet in packets {
                if let Packet::Encryption(encryption_packet) = packet {
                    data_key = Some(*encryption_packet.get_encryption_key());
                    break 'outer;
                }
            }
        }
    }
    let data_key = data_key.unwrap();

    // Decrypt blocks and write to file
    input.seek(SeekFrom::Start(block_start)).unwrap();

    let raw_output_file = temp_dir.path().join("t8.shakespeare.txt");
    let mut output = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&raw_output_file)
        .unwrap();

    let mut buffer = [0u8; CRYPT4GH_ENCRYPTED_BLOCK_SIZE];
    let mut buffer_pos = 0;
    loop {
        // Read data into the remaining space in buffer
        let bytes_read = input.read(&mut buffer[buffer_pos..]).unwrap();
        if bytes_read == 0 {
            // End of file - process any remaining data in buffer
            if buffer_pos > 0 {
                let raw = decrypt_chunk(&buffer[..buffer_pos], &data_key).unwrap();
                output.write_all(raw.as_slice()).unwrap();
            }
            break;
        }
        buffer_pos += bytes_read;

        // If buffer is full, process it and reset
        if buffer_pos == CRYPT4GH_ENCRYPTED_BLOCK_SIZE {
            let raw = decrypt_chunk(&buffer, &data_key).unwrap();
            output.write_all(raw.as_slice()).unwrap();
            buffer_pos = 0;
        }
    }

    let original_content = read_to_string("tests/data/t8.shakespeare.sample.txt").unwrap();
    let decrypted_content = read_to_string(&raw_output_file).unwrap();
    assert_eq!(original_content, decrypted_content);
}

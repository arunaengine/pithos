pub mod common;

use crate::common::util::{create_pithos_writer, load_test_keys, write_dummy_pithos};
use pithos_lib::error::PithosError;
use pithos_lib::helpers::chacha_poly1305::decrypt_chunk;
use pithos_lib::helpers::crypt4gh::{
    CRYPT4GH_ENCRYPTED_BLOCK_SIZE, Crypt4GHHeader, Packet, PacketData,
};
use pithos_lib::helpers::file_entry_map::Key;
use pithos_lib::helpers::ro_crate::{RoCrateSource, read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::{BlockDataState, FileEntry, FileType, Reference};
use rocraters::ro_crate::graph_vector::GraphVector;
use rocraters::ro_crate::read::CrateReadError;
use rocraters::ro_crate::schema::RoCrateSchemaVersion;
use std::fs::{File, OpenOptions, read, read_to_string, write};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
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

fn directory_bounds(bytes: &[u8]) -> (usize, usize) {
    let length =
        u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap()) as usize;
    (bytes.len() - length, length)
}

#[test]
fn test_directory_integrity_valid_terminal_archive() {
    let temp_dir = TempDir::new().unwrap();
    let archive = write_dummy_pithos(&temp_dir, false, false);
    let mut reader = PithosReaderSimple::new_with_key(&archive, reader_key()).unwrap();

    assert!(reader.read_directory().is_ok());
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

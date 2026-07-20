pub mod common;

use crate::common::util::write_dummy_pithos;
use pithos_lib::error::PithosError;
use pithos_lib::helpers::chacha_poly1305::decrypt_chunk;
use pithos_lib::helpers::crypt4gh::{
    CRYPT4GH_ENCRYPTED_BLOCK_SIZE, Crypt4GHHeader, Packet, PacketData,
};
use pithos_lib::helpers::ro_crate::{RoCrateSource, read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::model::structs::{FileType, Reference};
use rocraters::ro_crate::graph_vector::GraphVector;
use rocraters::ro_crate::read::CrateReadError;
use rocraters::ro_crate::schema::RoCrateSchemaVersion;
use std::fs::{File, OpenOptions, read_to_string};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use x25519_dalek::StaticSecret;

fn write_zip_entry(path: &Path, name: &str, content: &[u8]) {
    let file = File::create(path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    archive
        .start_file(name, zip::write::SimpleFileOptions::default())
        .unwrap();
    archive.write_all(content).unwrap();
    archive.finish().unwrap();
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

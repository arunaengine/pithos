pub mod common;

use crate::common::util::{extract_zip, load_test_keys};
use pithos_lib::helpers::file_entry_map::KeyQuery;
use pithos_lib::helpers::ro_crate::read_ro_crate_directory;
use pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes;
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::FileType;
use rocrate::{ROCrate, ROCrateBuilder};
use std::fs::{File, create_dir_all, read_to_string};
use tempfile::TempDir;

fn _create_test_crate() -> ROCrate {
    ROCrateBuilder::new()
        .with_name("Test Crate")
        .with_description("A test RO-Crate for writer testing")
        .with_license("MIT")
        .add_file("data/test.txt")
        .with_name("Test File")
        .with_encoding_format("text/plain")
        .with_content_size(12)
        .finish()
        .add_person("person1")
        .with_name("Test Person")
        .with_email("test@example.com")
        .finish()
        .with_author("person1")
        .build_unchecked()
}

#[test]
fn test_single_file() {
    // Dummy file
    let input_file = InputFile {
        file_type: FileType::Data,
        inner_path: "t8.shakespeare.txt".to_string(),
        data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
        metadata: None,
        encrypt: true,
        compression_level: Some(7),
    };

    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();

    // Prepare PithosWriter
    let temp_dir = TempDir::new().unwrap();
    let outfile = File::create(temp_dir.path().join("single.pith")).unwrap();
    let mut writer = PithosWriter::new(sender_key, vec![r1_key], None, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input(input_file).unwrap();
    writer.write_directory().unwrap();
}

#[test]
fn test_append_single_file() {
    // Dummy file
    let input_file = InputFile {
        file_type: FileType::Data,
        inner_path: "t8.shakespeare.txt".to_string(),
        data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
        metadata: None,
        encrypt: true,
        compression_level: Some(7),
    };

    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();

    // Prepare PithosWriter
    let temp_dir = TempDir::new().unwrap();
    let pithos_file_path = temp_dir.path().join("single.append.pith");
    let outfile = File::create(&pithos_file_path).unwrap();
    let mut writer = PithosWriter::new(sender_key, vec![r1_key], None, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input(input_file).unwrap();
    writer.write_directory().unwrap();

    // Dummy file to append
    let input_file = InputFile {
        file_type: FileType::Data,
        inner_path: "SRR33138449.sample.fastq".to_string(),
        data: Content::File("tests/data/SRR33138449.sample.fastq".to_string()),
        metadata: None,
        encrypt: true,
        compression_level: Some(3),
    };

    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();

    // Prepare PithosWriter from existing Pithos file
    let reader_keys = vec![r1_key];
    let mut writer =
        PithosWriter::new_from_file(sender_key, reader_keys, None, &pithos_file_path).unwrap();

    writer.process_input(input_file).unwrap();
    writer.write_directory().unwrap();

    // Read Pithos directory
    let reader_secret = private_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(pithos_file_path, reader_secret).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    assert_eq!(directory.files.len(), 2);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(0)).unwrap();
    assert_eq!(key.id(), 0);
    assert_eq!(key.path(), "t8.shakespeare.txt");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 79463);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(1)).unwrap();
    assert_eq!(key.id(), 1);
    assert_eq!(key.path(), "SRR33138449.sample.fastq");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 342848);
}

#[test]
fn test_multiple_files() {
    // Dummy files with metadata
    let input_files = vec![
        InputFile {
            file_type: FileType::Data,
            inner_path: "SRR33138449.fastq".to_string(),
            data: Content::File("tests/data/SRR33138449.sample.fastq".to_string()),
            metadata: Some(Content::Raw(
                r#"{
                  "@id": "SRR33138449.fastq",
                  "@type": "File",
                  "name": "SRR33138449 run sequencing reads",
                  "description": "Something something description"
                }"#
                .to_string(),
            )),
            encrypt: true,
            compression_level: Some(1),
        },
        InputFile {
            file_type: FileType::Data,
            inner_path: "t8.shakespeare.txt".to_string(),
            data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
            metadata: Some(Content::Raw(
                r#"{"@id": "t8.shakespeare.txt","@type": "File"}"#.to_string(),
            )),
            encrypt: true,
            compression_level: Some(7),
        },
    ];

    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();

    // Prepare input for writer
    let temp_dir = TempDir::new().unwrap();
    let outfile = File::create(temp_dir.path().join("multifile.pith")).unwrap();
    let mut writer = PithosWriter::new(sender_key, vec![r1_key], None, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input_files(input_files).unwrap();
    writer.write_directory().unwrap();
}

#[test]
fn test_append_multiple_files() {
    // Dummy files
    let input_files = vec![
        InputFile {
            file_type: FileType::Data,
            inner_path: "SRR33138449.fastq".to_string(),
            data: Content::File("tests/data/SRR33138449.sample.fastq".to_string()),
            metadata: None,
            encrypt: true,
            compression_level: Some(1),
        },
        InputFile {
            file_type: FileType::Data,
            inner_path: "t8.shakespeare.txt".to_string(),
            data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
            metadata: None,
            encrypt: true,
            compression_level: Some(7),
        },
    ];

    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();
    let reader_keys = vec![r1_key];

    // Prepare PithosWriter
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("multifile.append.pith");
    let outfile = File::create(&file_path).unwrap();
    let mut writer = PithosWriter::new(
        sender_key.clone(),
        reader_keys.clone(),
        None,
        Box::new(outfile),
    )
    .unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input_files(input_files).unwrap();
    writer.write_directory().unwrap();

    // Dummy files
    let append_files = vec![
        InputFile {
            file_type: FileType::Data,
            inner_path: "conclusions.txt".to_string(),
            data: Content::File("tests/data/dummy_dir/conclusions.txt".to_string()),
            metadata: None,
            encrypt: true,
            compression_level: Some(3),
        },
        InputFile {
            file_type: FileType::Data,
            inner_path: "dummy_results.txt".to_string(),
            data: Content::File("tests/data/dummy_dir/dummy_results.txt".to_string()),
            metadata: None,
            encrypt: true,
            compression_level: Some(3),
        },
    ];

    // Prepare PithosWriter
    let mut writer =
        PithosWriter::new_from_file(sender_key, reader_keys, None, &file_path).unwrap();

    // Append files
    writer.process_input_files(append_files).unwrap();
    writer.write_directory().unwrap();

    // Read directory and validate
    let reader_secret = private_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(file_path, reader_secret).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    assert_eq!(directory.files.len(), 4);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(0)).unwrap();
    assert_eq!(key.id(), 0);
    assert_eq!(key.path(), "SRR33138449.fastq");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 342848);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(1)).unwrap();
    assert_eq!(key.id(), 1);
    assert_eq!(key.path(), "t8.shakespeare.txt");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 79463);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(2)).unwrap();
    assert_eq!(key.id(), 2);
    assert_eq!(key.path(), "conclusions.txt");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 91);

    let (key, entry) = directory.files.get_entry(&KeyQuery::Id(3)).unwrap();
    assert_eq!(key.id(), 3);
    assert_eq!(key.path(), "dummy_results.txt");
    assert_eq!(entry.file_type, FileType::Data);
    assert_eq!(entry.file_size, 558);
}

#[test]
fn test_directory() {
    // Load dummy keys
    let (sender_key, r1_key, _) = load_test_keys();

    // Prepare PithosWriter
    let input_directory = "tests/data/dummy_dir";
    let temp_dir = TempDir::new().unwrap();
    let file_path = temp_dir.path().join("directory.pith");
    let outfile = File::create(&file_path).unwrap();

    let mut writer = PithosWriter::new(sender_key, vec![r1_key], None, Box::new(outfile)).unwrap();
    writer.write_file_header().unwrap();
    writer
        .process_directory(input_directory.to_string(), None)
        .unwrap();
    writer.write_directory().unwrap();

    // Read directory and validate
    let reader_secret = private_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(file_path, reader_secret).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    assert_eq!(directory.files.len(), 8);

    for (id, path, filetype, size) in vec![
        (0, "dataset", FileType::Directory, 0),
        (
            1,
            "dataset/brain_gene_expression_data",
            FileType::Directory,
            0,
        ),
        (2, "literature", FileType::Directory, 0),
        (3, "conclusions.txt", FileType::Data, 91),
        (
            4,
            "dataset/brain_gene_expression_data/brain_data_assession_number.txt",
            FileType::Data,
            29,
        ),
        (5, "dummy_results.txt", FileType::Data, 558),
        (
            6,
            "literature/Hodges06_human_brain_Affy.pdf",
            FileType::Data,
            359786,
        ),
        (7, "ro-crate-metadata.json", FileType::Data, 2748),
    ] {
        let (key, entry) = directory.files.get_entry(&KeyQuery::Id(id)).unwrap();
        assert_eq!(key.id(), id);
        assert_eq!(key.path(), path);
        assert_eq!(entry.file_type, filetype);

        if entry.file_type != FileType::Directory {
            assert_eq!(entry.file_size, size);
        }
    }
}

#[test]
fn test_rocrate_conversion() {
    // Some paths
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = temp_dir.path().join("ro-crate.pith");
    let ro_crate_dir = temp_dir.path().join("ro-crate");

    // Prepare RO-Crate dir
    create_dir_all(&ro_crate_dir).unwrap();
    extract_zip(
        File::open("tests/data/ro-crate.zip").unwrap(),
        &ro_crate_dir,
    );

    // Writer prelude
    let ro_crate = read_ro_crate_directory(ro_crate_dir).unwrap();
    let (sender_key, r1_key, _) = load_test_keys();
    let outfile = Box::new(File::create(&pithos_file).unwrap());
    let mut writer = PithosWriter::new(sender_key, vec![r1_key], None, outfile).unwrap();

    // Convert parsed RO-Crate to Pithos file
    writer.write_file_header().unwrap();
    writer.process_ro_crate(&ro_crate).unwrap();
    writer.write_directory().unwrap();

    // Read Pithos and validate FileEntries
    let reader_secret = private_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(pithos_file, reader_secret).unwrap();
    let (directory, _) = reader.read_directory().unwrap();

    assert_eq!(directory.files.len(), 7);

    // First file in index has to be ro-crate-metadata.json
    let (key, _) = directory.files.get_entry(&KeyQuery::Id(0)).unwrap();
    assert_eq!("ro-crate-metadata.json", key.path());
}

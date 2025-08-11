pub mod common;

use pithos_lib::helpers::ro_crate::read_ro_crate_directory;
use pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes;
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::FileType;
use rocrate::{ROCrate, ROCrateBuilder};
use std::fs::File;
use tempfile::TempDir;

fn create_test_crate() -> ROCrate {
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
fn test_rocrate_conversion() {
    // Writer prelude
    let temp_dir = TempDir::new().unwrap();
    let pithos_file = temp_dir.path().join("rocrate.pith");
    let ro_crate = read_ro_crate_directory(
        "/home/jhochmuth/Aruna/v3/pithos/ro-crate/ccc7e082-35d3-49fe-81dd-affc2e8632f7_2/",
    )
    .unwrap();
    let (s_key, r_key) = common::util::load_test_keys();
    let outfile = Box::new(File::create(&pithos_file).unwrap());
    let mut writer = PithosWriter::new(s_key, vec![r_key], outfile).unwrap();

    // Convert RO-Crate directory to Pithos file
    writer.write_file_header().unwrap();
    writer.process_ro_crate(&ro_crate).unwrap();
    writer.write_directory().unwrap();

    // Read Pithos and validate FileEntries
    let reader_secret = private_key_from_pem_bytes(
        std::fs::read_to_string("tests/data/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let mut reader = PithosReaderSimple::new_with_key(pithos_file, reader_secret).unwrap();
    let directory = reader.read_directory().unwrap();
}

#[test]
fn test_writer_single_file() {
    use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
    use std::fs::read_to_string;

    // Dummy file
    let input_file = InputFile {
        file_type: FileType::Data,
        file_path: "t8.shakespeare.txt".to_string(),
        data: Content::File("/tmp/t8.shakespeare.txt".to_string()),
        metadata: None,
        encrypt: true,
        compression_level: Some(7),
    };

    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient public key
    let recipient_pem_content = read_to_string("tests/data/recipient1_public.pem").unwrap();
    let reader_key = public_key_from_pem_bytes(recipient_pem_content.as_bytes()).unwrap();

    // Prepare input for writer
    let reader_keys = vec![reader_key];
    let outfile = File::create("/tmp/file.pith").unwrap();

    let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input(input_file).unwrap();
    writer.write_directory().unwrap();
}

#[test]
fn test_writer_multiple_files() {
    use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
    use std::fs::read_to_string;

    // Dummy file
    let input_files = vec![
        InputFile {
            file_type: FileType::Data,
            file_path: "SRR33138449.fastq".to_string(),
            data: Content::File("/tmp/SRR33138449.fastq".to_string()),
            metadata: Some(Content::Raw(
                r#"{
  "@id": "SRR33138449.fastq",
  "@type": "File",
  "name": "SRR33138449 run sequencing reads",
  "description": "Something something description",
}"#
                .to_string(),
            )),
            encrypt: true,
            compression_level: Some(1),
        },
        InputFile {
            file_type: FileType::Data,
            file_path: "t8.shakespeare.txt".to_string(),
            data: Content::File("/tmp/t8.shakespeare.txt".to_string()),
            metadata: Some(Content::Raw(
                r#"{"@id": "t8.shakespeare.txt","@type": "File"}"#.to_string(),
            )),
            encrypt: true,
            compression_level: Some(7),
        },
    ];

    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient public key
    let recipient_pem_content = read_to_string("tests/data/recipient1_public.pem").unwrap();
    let reader_key = public_key_from_pem_bytes(recipient_pem_content.as_bytes()).unwrap();

    // Prepare input for writer
    let reader_keys = vec![reader_key];
    let outfile = File::create("/tmp/files.pith").unwrap();

    let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input_files(input_files).unwrap();
    writer.write_directory().unwrap();
}

#[test]
fn test_directory_writer() {
    use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
    use std::fs::read_to_string;

    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient public key
    let recipient_pem_content = read_to_string("tests/data/recipient1_public.pem").unwrap();
    let reader_key = public_key_from_pem_bytes(recipient_pem_content.as_bytes()).unwrap();

    // Prepare input for writer
    let reader_keys = vec![reader_key];
    let input_directory =
        "/home/jhochmuth/Aruna/v3/pithos/ro-crate/ccc7e082-35d3-49fe-81dd-affc2e8632f7_2";
    let outfile = File::create("/tmp/directory.pith").unwrap();
    let ro_crate_meta = read_ro_crate_directory(input_directory).unwrap();

    let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();
    writer
        .process_directory(input_directory.to_string(), Some(&ro_crate_meta))
        .unwrap();

    return;

    /*
    // Process directory
    writer.write_file_header().unwrap();
    writer
        .process_directory("/tmp/demo-results/", false)
        .unwrap();
    writer.write_directory().unwrap();
    */
}

#[test]
fn test_append_writer() {}

use pithos_lib::error::PithosError;
use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::{Directory, FileType, Reference};
use std::fs::{File, read, read_to_string};
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use x25519_dalek::{PublicKey, StaticSecret};

pub type ComparablePithosEntry = (String, FileType, u64, Vec<Reference>);

pub fn load_test_keys() -> (StaticSecret, PublicKey, PublicKey) {
    // Read sender private key
    let sender_pem_content = read_to_string("tests/data/keys/sender_private.pem").unwrap();
    let writer_key = private_key_from_pem_bytes(sender_pem_content.as_bytes()).unwrap();

    // Read recipient 1 public key
    let recipient1_pem_content = read_to_string("tests/data/keys/recipient1_public.pem").unwrap();
    let reader_key_01 = public_key_from_pem_bytes(recipient1_pem_content.as_bytes()).unwrap();

    // Read recipient 2 public key
    let recipient2_pem_content = read_to_string("tests/data/keys/recipient2_public.pem").unwrap();
    let reader_key_02 = public_key_from_pem_bytes(recipient2_pem_content.as_bytes()).unwrap();

    (writer_key, reader_key_01, reader_key_02)
}

pub fn minimal_ro_crate_metadata(has_part: &[&str]) -> String {
    let parts = has_part
        .iter()
        .map(|path| format!(r#"{{"@id":"{path}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let entities = has_part
        .iter()
        .map(|path| format!(r#"{{"@id":"{path}","@type":"File"}}"#))
        .collect::<Vec<_>>()
        .join(",");

    let entity_suffix = if entities.is_empty() {
        String::new()
    } else {
        format!(",{entities}")
    };
    format!(
        r#"{{"@context":"https://w3id.org/ro/crate/1.2/context","@graph":[{{"@id":"ro-crate-metadata.json","@type":"CreativeWork","conformsTo":{{"@id":"https://w3id.org/ro/crate/1.2"}},"about":{{"@id":"./"}}}},{{"@id":"./","@type":"Dataset","name":"Test Crate","description":"A test RO-Crate","datePublished":"2024-01-01","license":"MIT","hasPart":[{parts}]}}{entity_suffix}]}}"#
    )
}

pub fn write_zip_entries(path: &Path, entries: &[(&str, &[u8], zip::write::SimpleFileOptions)]) {
    let file = File::create(path).unwrap();
    let mut archive = zip::ZipWriter::new(file);
    for (name, bytes, options) in entries {
        archive.start_file(*name, *options).unwrap();
        archive.write_all(bytes).unwrap();
    }
    archive.finish().unwrap();
}

pub fn create_pithos_writer(
    temp_dir: &TempDir,
    cdc: Option<(usize, usize, usize)>,
) -> (PathBuf, StaticSecret, PithosWriter) {
    let (sender_key, reader_public_key, _) = load_test_keys();
    let reader_key = private_key_from_pem_bytes(
        read_to_string("tests/data/keys/recipient1_private.pem")
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let path = temp_dir.path().join("converted.pith");
    let writer = PithosWriter::new(
        sender_key,
        vec![reader_public_key],
        cdc,
        Box::new(File::create(&path).unwrap()),
    )
    .unwrap();
    (path, reader_key, writer)
}

pub fn read_pithos_directory(
    path: &Path,
    reader_key: &StaticSecret,
) -> Result<(Directory, Vec<ComparablePithosEntry>), PithosError> {
    let mut reader = PithosReaderSimple::new_with_key(path, reader_key.clone())?;
    let (directory, _) = reader.read_directory()?;
    let mut entries = directory
        .files
        .iter()
        .map(|(_, path, entry)| {
            (
                path.to_string(),
                entry.file_type,
                entry.file_size,
                entry.references.clone(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok((directory, entries))
}

pub fn extract_pithos_entry(
    path: &Path,
    reader_key: &StaticSecret,
    inner_path: &str,
    temp_dir: &TempDir,
) -> Vec<u8> {
    let mut reader = PithosReaderSimple::new_with_key(path, reader_key.clone()).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    let output_path = temp_dir.path().join("extracted-entry");
    reader
        .read_file(inner_path, &directory, Some(&output_path), None)
        .unwrap();
    read(output_path).unwrap()
}

pub fn write_dummy_pithos(temp_dir: &TempDir, multifile: bool, metadata: bool) -> PathBuf {
    // Dummy file(s)
    let mut input_files = vec![InputFile {
        file_type: FileType::Data,
        inner_path: "t8.shakespeare.txt".to_string(),
        data: Content::File("tests/data/t8.shakespeare.sample.txt".to_string()),
        metadata: if metadata {
            Some(Content::Raw(r#"{"foo":"bar"}"#.to_string()))
        } else {
            None
        },
        encrypt: true,
        compression_level: Some(3),
    }];

    if multifile {
        input_files.push(InputFile {
            file_type: FileType::Data,
            inner_path: "SRR33138449.fastq".to_string(),
            data: Content::File("tests/data/SRR33138449.sample.fastq".to_string()),
            metadata: if metadata {
                Some(Content::Raw(r#"{"bar":"baz"}"#.to_string()))
            } else {
                None
            },
            encrypt: true,
            compression_level: Some(3),
        })
    }

    // Load dummy keys
    let (sender_key, r1_key, r2_key) = load_test_keys();

    // Prepare input for writer
    let file_path = temp_dir.path().join("dummy.pith");
    let outfile = File::create(&file_path).unwrap();
    let mut writer =
        PithosWriter::new(sender_key, vec![r1_key, r2_key], None, Box::new(outfile)).unwrap();

    // Process
    writer.write_file_header().unwrap();
    writer.process_input_files(input_files).unwrap();
    writer.write_directory().unwrap();

    file_path
}

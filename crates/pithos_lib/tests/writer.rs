pub mod common;

use crate::common::util::{
    create_pithos_writer, extract_pithos_entry, load_test_keys, minimal_ro_crate_metadata,
    read_pithos_directory, write_zip_entries,
};
use pithos_lib::error::PithosError;
use pithos_lib::helpers::file_entry_map::KeyQuery;
use pithos_lib::helpers::ro_crate::{LoadedRoCrate, read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes;
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::{Content, InputFile, PithosWriter};
use pithos_lib::model::structs::{FileType, Reference};
use std::fs::{
    File, copy, create_dir_all, read, read_dir, read_link, read_to_string, remove_file,
    symlink_metadata, write,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use x25519_dalek::StaticSecret;

fn copy_directory(source: &Path, destination: &Path) {
    create_dir_all(destination).unwrap();
    for item in read_dir(source).unwrap() {
        let item = item.unwrap();
        let source_path = item.path();
        let destination_path = destination.join(item.file_name());
        if item.file_type().unwrap().is_dir() {
            copy_directory(&source_path, &destination_path);
        } else {
            copy(&source_path, &destination_path).unwrap();
        }
    }
}

fn convert_ro_crate(
    temp_dir: &TempDir,
    loaded: &LoadedRoCrate,
    cdc: Option<(usize, usize, usize)>,
) -> (PathBuf, StaticSecret) {
    let (path, reader_key, mut writer) = create_pithos_writer(temp_dir, cdc);
    writer.write_file_header().unwrap();
    writer.process_ro_crate(loaded).unwrap();
    writer.write_directory().unwrap();
    (path, reader_key)
}

fn metadata_reference() -> Reference {
    Reference {
        target_file_id: 0,
        relationship: 0,
    }
}

fn read_zip_member(path: &Path, name: &str) -> Vec<u8> {
    let mut archive = zip::ZipArchive::new(File::open(path).unwrap()).unwrap();
    let mut member = archive.by_name(name).unwrap();
    let mut bytes = Vec::new();
    member.read_to_end(&mut bytes).unwrap();
    bytes
}

fn write_raw_zip(path: &Path, entries: &[(&str, &[u8], u32)], overlap_duplicates: bool) {
    let mut archive = Vec::new();
    let mut central_directory = Vec::new();
    let mut offsets = Vec::with_capacity(entries.len());
    for (index, (name, content, permissions)) in entries.iter().enumerate() {
        let entry_name = *name;
        let name = entry_name.as_bytes();
        let content = *content;
        let offset = archive.len() as u32;
        offsets.push(offset);
        let checksum = crc32fast::hash(content);

        archive.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        archive.extend_from_slice(&20u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(&checksum.to_le_bytes());
        archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(content.len() as u32).to_le_bytes());
        archive.extend_from_slice(&(name.len() as u16).to_le_bytes());
        archive.extend_from_slice(&0u16.to_le_bytes());
        archive.extend_from_slice(name);
        archive.extend_from_slice(content);

        central_directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&20u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&checksum.to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(content.len() as u32).to_le_bytes());
        central_directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        central_directory.extend_from_slice(&0u16.to_le_bytes());
        let central_offset = if overlap_duplicates {
            entries[..index]
                .iter()
                .position(|(previous_name, _, _)| {
                    previous_name.trim_start_matches("./") == entry_name.trim_start_matches("./")
                })
                .map(|position| offsets[position])
                .unwrap_or(offset)
        } else {
            offset
        };
        central_directory.extend_from_slice(&(*permissions << 16).to_le_bytes());
        central_directory.extend_from_slice(&central_offset.to_le_bytes());
        central_directory.extend_from_slice(name);
    }

    let central_offset = archive.len() as u32;
    archive.extend_from_slice(&central_directory);
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    archive.extend_from_slice(&(central_directory.len() as u32).to_le_bytes());
    archive.extend_from_slice(&central_offset.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    write(path, archive).unwrap();
}

fn write_duplicate_zip(path: &Path, entries: &[(&str, &[u8])]) {
    let entries = entries
        .iter()
        .map(|(name, content)| (*name, *content, 0))
        .collect::<Vec<_>>();
    write_raw_zip(path, &entries, true);
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
    writer.process_directory(input_directory).unwrap();
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
        (7, "ro-crate-metadata.json", FileType::Data, 2953),
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
fn test_rocrate_directory_conversion() {
    let temp_dir = TempDir::new().unwrap();
    let loaded = read_ro_crate_directory("tests/data/dummy_dir").unwrap();
    let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, None);
    let (directory, entries) = read_pithos_directory(&pithos_path, &reader_key).unwrap();

    assert_eq!(entries.len(), 8);
    assert_eq!(
        entries
            .iter()
            .map(|(path, _, _, _)| path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "conclusions.txt",
            "dataset",
            "dataset/brain_gene_expression_data",
            "dataset/brain_gene_expression_data/brain_data_assession_number.txt",
            "dummy_results.txt",
            "literature",
            "literature/Hodges06_human_brain_Affy.pdf",
            "ro-crate-metadata.json",
        ]
    );

    let metadata = directory
        .get_file_by_path("ro-crate-metadata.json")
        .unwrap();
    assert_eq!(
        directory.files.get_id_by_path("ro-crate-metadata.json"),
        Some(0)
    );
    assert_eq!(metadata.file_type, FileType::Metadata);
    assert_eq!(metadata.file_size, 2953);
    assert_eq!(
        extract_pithos_entry(
            &pithos_path,
            &reader_key,
            "ro-crate-metadata.json",
            &temp_dir
        ),
        read("tests/data/dummy_dir/ro-crate-metadata.json").unwrap()
    );

    for path in [
        "dataset",
        "dataset/brain_gene_expression_data",
        "literature",
    ] {
        let entry = directory.get_file_by_path(path).unwrap();
        assert_eq!(entry.file_type, FileType::Directory);
        assert!(entry.references.is_empty());
    }
    for path in [
        "conclusions.txt",
        "dataset/brain_gene_expression_data/brain_data_assession_number.txt",
        "dummy_results.txt",
        "literature/Hodges06_human_brain_Affy.pdf",
    ] {
        let entry = directory.get_file_by_path(path).unwrap();
        assert_eq!(entry.file_type, FileType::Data);
        assert!(entry.references.contains(&metadata_reference()));
    }
    for (path, size) in [
        ("conclusions.txt", 91),
        (
            "dataset/brain_gene_expression_data/brain_data_assession_number.txt",
            29,
        ),
        ("dummy_results.txt", 558),
        ("literature/Hodges06_human_brain_Affy.pdf", 359786),
    ] {
        assert_eq!(directory.get_file_by_path(path).unwrap().file_size, size);
    }
}

#[test]
fn test_rocrate_directory_links_unlisted_files() {
    let temp_dir = TempDir::new().unwrap();
    let source = temp_dir.path().join("crate");
    copy_directory(Path::new("tests/data/dummy_dir"), &source);
    write(source.join("unlisted.txt"), b"not in @graph").unwrap();
    create_dir_all(source.join("nested")).unwrap();
    write(
        source.join("nested/ro-crate-metadata.json.backup"),
        b"ordinary data",
    )
    .unwrap();

    let loaded = read_ro_crate_directory(&source).unwrap();
    let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, None);
    let (directory, _) = read_pithos_directory(&pithos_path, &reader_key).unwrap();

    for path in ["unlisted.txt", "nested/ro-crate-metadata.json.backup"] {
        let entry = directory.get_file_by_path(path).unwrap();
        assert_eq!(entry.file_type, FileType::Data);
        assert!(entry.references.contains(&metadata_reference()));
    }
    assert_eq!(
        extract_pithos_entry(&pithos_path, &reader_key, "unlisted.txt", &temp_dir),
        b"not in @graph"
    );
}

#[test]
fn test_rocrate_directory_requires_exact_metadata_path() {
    let temp_dir = TempDir::new().unwrap();
    let source = temp_dir.path().join("crate");
    copy_directory(Path::new("tests/data/dummy_dir"), &source);
    remove_file(source.join("ro-crate-metadata.json")).unwrap();
    create_dir_all(source.join("wrapper")).unwrap();
    write(
        source.join("wrapper/ro-crate-metadata.json"),
        minimal_ro_crate_metadata(&[]),
    )
    .unwrap();

    let error = read_ro_crate_directory(&source).unwrap_err();
    assert!(matches!(error, PithosError::MissingRoCrateMetadata(_)));

    let empty = TempDir::new().unwrap();
    let error = read_ro_crate_directory(empty.path()).unwrap_err();
    assert!(matches!(error, PithosError::MissingRoCrateMetadata(_)));
}

#[test]
fn test_rocrate_zip_conversion() {
    let temp_dir = TempDir::new().unwrap();
    let loaded = read_ro_crate_zip("tests/data/ro-crate.zip").unwrap();
    let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, None);
    let (directory, entries) = read_pithos_directory(&pithos_path, &reader_key).unwrap();

    assert_eq!(entries.len(), 7);
    let metadata = directory
        .get_file_by_path("ro-crate-metadata.json")
        .unwrap();
    assert_eq!(
        directory.files.get_id_by_path("ro-crate-metadata.json"),
        Some(0)
    );
    assert_eq!(metadata.file_type, FileType::Metadata);
    assert_eq!(metadata.file_size, 15509);
    assert_eq!(
        extract_pithos_entry(
            &pithos_path,
            &reader_key,
            "ro-crate-metadata.json",
            &temp_dir
        ),
        read_zip_member(
            Path::new("tests/data/ro-crate.zip"),
            "ro-crate-metadata.json"
        )
    );

    for (path, entry) in directory.files.iter().map(|(_, path, entry)| (path, entry)) {
        if entry.file_type == FileType::Data {
            assert!(entry.references.contains(&metadata_reference()), "{path}");
        } else if entry.file_type == FileType::Directory {
            assert!(entry.references.is_empty(), "{path}");
        }
    }
}

#[test]
fn test_rocrate_zip_synthesizes_parent_directories() {
    let metadata = minimal_ro_crate_metadata(&["nested/file.txt"]);
    let options = zip::write::SimpleFileOptions::default();

    for explicit_directory in [false, true] {
        let temp_dir = TempDir::new().unwrap();
        let zip_path = temp_dir.path().join("crate.zip");
        let mut entries = vec![
            ("ro-crate-metadata.json", metadata.as_bytes(), options),
            ("nested/file.txt", b"payload".as_slice(), options),
        ];
        if explicit_directory {
            entries.push(("nested/", b"".as_slice(), options));
        }
        write_zip_entries(&zip_path, &entries);

        let loaded = read_ro_crate_zip(&zip_path).unwrap();
        let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, None);
        let (directory, entries) = read_pithos_directory(&pithos_path, &reader_key).unwrap();

        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries
                .iter()
                .filter(
                    |(path, file_type, _, _)| path == "nested" && *file_type == FileType::Directory
                )
                .count(),
            1
        );
        assert_eq!(
            directory
                .get_file_by_path("nested/file.txt")
                .unwrap()
                .file_size,
            7
        );
    }
}

#[test]
fn test_rocrate_zip_preserves_and_extracts_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("symlink.zip");
    let target = temp_dir.path().join("outside-target");
    let target_string = target.to_string_lossy().into_owned();
    let metadata = minimal_ro_crate_metadata(&[]);
    write_raw_zip(
        &zip_path,
        &[
            ("ro-crate-metadata.json", metadata.as_bytes(), 0),
            ("link", target_string.as_bytes(), 0o120777),
        ],
        false,
    );

    let loaded = read_ro_crate_zip(&zip_path).unwrap();
    let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, None);
    let (directory, _) = read_pithos_directory(&pithos_path, &reader_key).unwrap();
    let entry = directory.get_file_by_path("link").unwrap();

    assert_eq!(entry.file_type, FileType::Symlink);
    assert_eq!(
        entry.symlink_target.as_deref(),
        Some(target_string.as_str())
    );
    assert!(entry.references.is_empty());

    let output_dir = temp_dir.path().join("extracted");
    create_dir_all(&output_dir).unwrap();
    let mut reader = PithosReaderSimple::new_with_key(&pithos_path, reader_key).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    reader
        .read_file("link", &directory, Some(&output_dir), None)
        .unwrap();

    assert_eq!(read_link(output_dir.join("link")).unwrap(), target);
    assert!(symlink_metadata(temp_dir.path().join("outside-target")).is_err());
}

#[test]
fn test_rocrate_zip_rejects_unsafe_path() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("unsafe.zip");
    let metadata = minimal_ro_crate_metadata(&[]);
    write_zip_entries(
        &zip_path,
        &[
            (
                "ro-crate-metadata.json",
                metadata.as_bytes(),
                zip::write::SimpleFileOptions::default(),
            ),
            (
                "../escape.txt",
                b"escape",
                zip::write::SimpleFileOptions::default(),
            ),
        ],
    );

    let error = read_ro_crate_zip(&zip_path).unwrap_err();
    assert!(matches!(error, PithosError::UnsafeZipPath(_)));
}

#[test]
fn test_rocrate_zip_rejects_duplicate_path() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("duplicate.zip");
    let metadata = minimal_ro_crate_metadata(&[]);
    write_duplicate_zip(
        &zip_path,
        &[
            ("ro-crate-metadata.json", metadata.as_bytes()),
            ("duplicate.txt", b"one"),
            ("./duplicate.txt", b"two"),
        ],
    );

    let error = read_ro_crate_zip(&zip_path).unwrap_err();
    assert!(matches!(error, PithosError::OverlappingZipEntries(_)));
}

#[test]
fn test_rocrate_zip_rejects_path_conflict() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("conflict.zip");
    let metadata = minimal_ro_crate_metadata(&[]);
    write_zip_entries(
        &zip_path,
        &[
            (
                "ro-crate-metadata.json",
                metadata.as_bytes(),
                zip::write::SimpleFileOptions::default(),
            ),
            ("nested", b"file", zip::write::SimpleFileOptions::default()),
            (
                "nested/file.txt",
                b"payload",
                zip::write::SimpleFileOptions::default(),
            ),
        ],
    );

    let error = read_ro_crate_zip(&zip_path).unwrap_err();
    assert!(matches!(error, PithosError::ZipPathConflict(path) if path == "nested"));
}

#[test]
fn test_rocrate_directory_zip_parity() {
    let temp_dir = TempDir::new().unwrap();
    let directory_source = temp_dir.path().join("directory-crate");
    create_dir_all(directory_source.join("nested")).unwrap();
    let metadata = minimal_ro_crate_metadata(&["nested/file.txt"]);
    write(directory_source.join("ro-crate-metadata.json"), &metadata).unwrap();
    write(directory_source.join("nested/file.txt"), b"nested payload").unwrap();
    write(directory_source.join("unlisted.txt"), b"unlisted payload").unwrap();

    let zip_path = temp_dir.path().join("parity.zip");
    write_zip_entries(
        &zip_path,
        &[
            (
                "ro-crate-metadata.json",
                metadata.as_bytes(),
                zip::write::SimpleFileOptions::default(),
            ),
            (
                "nested/file.txt",
                b"nested payload",
                zip::write::SimpleFileOptions::default(),
            ),
            (
                "unlisted.txt",
                b"unlisted payload",
                zip::write::SimpleFileOptions::default(),
            ),
        ],
    );

    let directory_loaded = read_ro_crate_directory(&directory_source).unwrap();
    let zip_loaded = read_ro_crate_zip(&zip_path).unwrap();
    let (directory_pithos, directory_key) = convert_ro_crate(&temp_dir, &directory_loaded, None);
    let (zip_pithos, zip_key) = convert_ro_crate(&temp_dir, &zip_loaded, None);
    let (directory, directory_entries) =
        read_pithos_directory(&directory_pithos, &directory_key).unwrap();
    let (zip_directory, zip_entries) = read_pithos_directory(&zip_pithos, &zip_key).unwrap();

    assert_eq!(directory_entries, zip_entries);
    for path in ["ro-crate-metadata.json", "nested/file.txt", "unlisted.txt"] {
        let directory_bytes =
            extract_pithos_entry(&directory_pithos, &directory_key, path, &temp_dir);
        let zip_bytes = extract_pithos_entry(&zip_pithos, &zip_key, path, &temp_dir);
        assert_eq!(directory_bytes, zip_bytes, "{path}");
    }
    assert_eq!(
        directory.get_file_by_path("nested").unwrap().file_type,
        FileType::Directory
    );
    assert_eq!(
        zip_directory.get_file_by_path("nested").unwrap().file_type,
        FileType::Directory
    );
}

#[test]
fn test_rocrate_zip_streams_multichunk_file() {
    let temp_dir = TempDir::new().unwrap();
    let zip_path = temp_dir.path().join("large.zip");
    let metadata = minimal_ro_crate_metadata(&["large.bin"]);
    let payload = (0..(1024 * 1024 + 123))
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    write_zip_entries(
        &zip_path,
        &[
            (
                "ro-crate-metadata.json",
                metadata.as_bytes(),
                zip::write::SimpleFileOptions::default(),
            ),
            (
                "large.bin",
                &payload,
                zip::write::SimpleFileOptions::default(),
            ),
        ],
    );

    let loaded = read_ro_crate_zip(&zip_path).unwrap();
    let (pithos_path, reader_key) = convert_ro_crate(&temp_dir, &loaded, Some((1024, 4096, 8192)));
    let (directory, _) = read_pithos_directory(&pithos_path, &reader_key).unwrap();
    let entry = directory.get_file_by_path("large.bin").unwrap();
    assert_eq!(entry.file_size, payload.len() as u64);
    assert!(entry.references.contains(&metadata_reference()));
    assert_eq!(
        extract_pithos_entry(&pithos_path, &reader_key, "large.bin", &temp_dir),
        payload
    );
}

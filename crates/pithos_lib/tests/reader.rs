use pithos_lib::helpers::ro_crate::{read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use std::path::PathBuf;

#[test]
fn test_reader_single_file() {
    let pithos_file = "/tmp/file.pith".to_string();
    let key_pem = "tests/data/recipient1_private.pem".to_string();

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let directory = reader.read_directory().unwrap();

    dbg!(reader.read_file_paths(&directory).unwrap());
}

#[test]
fn test_reader_single_file_range() {
    let pithos_file = "/tmp/file.pith".to_string();
    let key_pem = "tests/data/recipient1_private.pem".to_string();
    let output_path = PathBuf::from("/tmp/output/");

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let directory = reader.read_directory().unwrap();

    if let Some(entry) = directory.get_file_by_path("t8.shakespeare.txt") {
        reader
            .read_file(
                &entry.path,
                &directory,
                Some(&output_path),
                Some(12000..200000),
            )
            .unwrap()
    }
}

#[test]
fn test_reader() {
    let pithos_file = "/tmp/rocrate.pith".to_string();
    let output_directory = "/tmp/output/";
    let key_pem = "tests/data/recipient1_private.pem".to_string();

    let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
    let directory = reader.read_directory().unwrap();
    directory
        .files
        .iter()
        .for_each(|f| println!("{} - {} - {:?}", f.file_id, f.path, f.references));

    // Write all files available in the directory
    let output_path = PathBuf::from(output_directory);
    for inner_file in &directory.files {
        reader
            .read_file(&inner_file.path, &directory, Some(&output_path), None)
            .unwrap();
    }
}

#[test]
fn test_rocrate_read_directory() {
    //dbg!(read_ro_crate_meta("/tmp/my-project/ro-crate-metadata.json").unwrap());
    //dbg!(read_ro_crate_directory("/tmp/my-project/").unwrap());
    //dbg!(read_ro_crate_meta("/home/jhochmuth/Aruna/v3/pithos/ro-crate/ro-crate-metadata.json").unwrap());
    dbg!(
        read_ro_crate_directory(
            "/home/jhochmuth/Aruna/v3/pithos/ro-crate/ccc7e082-35d3-49fe-81dd-affc2e8632f7/"
        )
        .unwrap()
    );
}

#[test]
fn test_rocrate_read_zip() {
    dbg!("Start test test_rocrate_read_zip");
    //let rocrate = read_ro_crate_meta("/tmp/my-project/ro-crate-metadata.json").unwrap();
    let rocrate = read_ro_crate_zip(
        "/home/jhochmuth/Aruna/v3/pithos/ro-crate/ccc7e082-35d3-49fe-81dd-affc2e8632f7.zip",
    )
    .unwrap();
    dbg!(&rocrate);
}

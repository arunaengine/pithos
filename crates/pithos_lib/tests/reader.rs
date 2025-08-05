#[cfg(test)]
mod tests {
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

        if let Some(entry) = directory.get_file_entry("t8.shakespeare.txt") {
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
        let pithos_file = "/tmp/directory.pith".to_string();
        let output_directory = "/tmp/output/";
        let key_pem = "tests/data/recipient1_private.pem".to_string();

        let mut reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();
        let directory = reader.read_directory().unwrap();

        // Write all files available in the directory
        let output_path = PathBuf::from(output_directory);
        for inner_file in &directory.files {
            reader
                .read_file(&inner_file.path, &directory, Some(&output_path), None)
                .unwrap();
        }
    }
}

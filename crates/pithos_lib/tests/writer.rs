#[cfg(test)]
mod tests {
    use pithos_lib::io::pithoswriter::{FileMeta, InputFile, PithosWriter};
    use pithos_lib::model::structs::FileType;
    use std::fs::File;

    #[test]
    fn test_writer_single_file() {
        // Dummy file
        let input_file = InputFile {
            file_path: "/tmp/t8.shakespeare.txt".to_string(),
            file_type: FileType::Data,
            file_meta: None,
            encrypt: true,
            compression_level: Some(7),
        };
        /*
        let input_file = InputFile {
            file_path: "/tmp/SRR33138449.fastq".to_string(),
            file_type: FileType::Directory,
            file_meta: Some(FileMeta::Content(
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
        };
        */

        // Read sender private key
        let sender_pem_content = std::fs::read_to_string("tests/data/sender_private.pem").unwrap();
        let writer_key = pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes(
            sender_pem_content.as_bytes(),
        )
        .unwrap();

        // Read recipient public key
        let recipient_pem_content =
            std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
        let reader_key = pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
            recipient_pem_content.as_bytes(),
        )
        .unwrap();

        // Prepare input for writer
        let reader_keys = vec![reader_key];
        let outfile = File::create("/tmp/file.pith").unwrap();

        let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();

        // Process
        writer.write_file_header().unwrap();
        writer.process_input(input_file, Some("/tmp/")).unwrap();
        writer.write_directory().unwrap();
    }

    #[test]
    fn test_writer_multiple_files() {
        // Dummy file
        let input_files = vec![
            InputFile {
                file_path: "/tmp/SRR33138449.fastq".to_string(),
                file_type: FileType::Directory,
                file_meta: Some(FileMeta::Content(
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
                file_path: "/tmp/t8.shakespeare.txt".to_string(),
                file_type: FileType::Data,
                file_meta: Some(FileMeta::Content(
                    r#"{"@id": "t8.shakespeare.txt","@type": "File"}"#.to_string(),
                )),
                encrypt: true,
                compression_level: Some(7),
            },
        ];

        // Read sender private key
        let sender_pem_content = std::fs::read_to_string("tests/data/sender_private.pem").unwrap();
        let writer_key = pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes(
            sender_pem_content.as_bytes(),
        )
        .unwrap();

        // Read recipient public key
        let recipient_pem_content =
            std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
        let reader_key = pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
            recipient_pem_content.as_bytes(),
        )
        .unwrap();

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
        // Read sender private key
        let sender_pem_content = std::fs::read_to_string("tests/data/sender_private.pem").unwrap();
        let writer_key = pithos_lib::helpers::x25519_keys::private_key_from_pem_bytes(
            sender_pem_content.as_bytes(),
        )
        .unwrap();

        // Read recipient public key
        let recipient_pem_content =
            std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
        let reader_key = pithos_lib::helpers::x25519_keys::public_key_from_pem_bytes(
            recipient_pem_content.as_bytes(),
        )
        .unwrap();

        // Prepare input for writer
        let reader_keys = vec![reader_key];
        let outfile = File::create("/tmp/directory.pith").unwrap();

        let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();

        // Process directory
        writer.write_file_header().unwrap();
        writer.process_directory("/tmp/demo-results/").unwrap();
        writer.write_directory().unwrap();
    }

    #[test]
    fn test_append_writer() {}
}

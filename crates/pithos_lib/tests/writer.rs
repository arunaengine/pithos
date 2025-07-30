#[cfg(test)]
mod tests {
    use pithos_lib::io::pithoswriter::PithosWriter;
    use std::fs::File;

    #[test]
    fn test_writer() {
        // Dummy file
        let file_with_metadata = pithos_lib::io::pithoswriter::FileWithMetadata {
            file_path: "/tmp/sample.file".to_string(),
            file_name: "sample.file".to_string(),
            file_metadata: "{'foo': 'bar'}".to_string(),
            encrypted: true,
            compression_level: Some(3),
        };

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
        let outfile = File::create("/tmp/test.pith").unwrap();

        let mut writer = PithosWriter::new(writer_key, reader_keys, Box::new(outfile)).unwrap();

        // Process files
        //TODO: Provide config / file to key association
        writer.process_files(vec![file_with_metadata]).unwrap();
    }
}

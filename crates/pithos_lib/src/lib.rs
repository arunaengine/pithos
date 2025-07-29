pub mod helpers;
pub mod io;
pub mod model;

#[cfg(test)]
mod tests {
    use crate::io::pithosreader::PithosReaderSimple;
    use crate::io::pithoswriter::PithosWriter;
    use std::fs::File;

    #[test]
    fn test_writer() {
        let file_with_metadata = crate::io::pithoswriter::FileWithMetadata {
            file_path: "/tmp/t8.shakespeare.txt".to_string(),
            file_name: "t8.shakespeare.txt".to_string(),
            file_metadata: "{'foo': 'bar'}".to_string(),
            encrypted: true,
            compression_level: None,
        };

        let sender_pem_content = std::fs::read_to_string("tests/data/sender_private.pem").unwrap();
        let writer_key =
            crate::helpers::x25519_keys::private_key_from_pem_bytes(sender_pem_content.as_bytes())
                .unwrap();

        let recipient_pem_content =
            std::fs::read_to_string("tests/data/recipient1_public.pem").unwrap();
        let reader_key = crate::helpers::x25519_keys::public_key_from_pem_bytes(
            recipient_pem_content.as_bytes(),
        )
        .unwrap();
        let reader_keys = vec![reader_key]; //vec![PublicKey::from(&EphemeralSecret::random_from_rng(OsRng))];

        let outfile = File::create("/tmp/test.pith").unwrap();

        let mut writer = PithosWriter::new(
            writer_key,
            reader_keys,
            vec![file_with_metadata],
            Box::new(outfile),
        );

        writer.run().unwrap();
    }

    #[test]
    fn test_reader() {
        let pithos_file = "/tmp/test.pith".to_string();
        let key_pem = "tests/data/recipient1_private.pem".to_string();

        let mut pithos_reader = PithosReaderSimple::new(pithos_file, key_pem).unwrap();

        let dir = pithos_reader.read_directory().unwrap();
        println!("{:#?}", dir)
    }
}

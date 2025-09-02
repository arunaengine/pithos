use pithos_lib::helpers::chacha_poly1305::decrypt_chunk;
use pithos_lib::helpers::crypt4gh::{
    CRYPT4GH_ENCRYPTED_BLOCK_SIZE, Crypt4GHHeader, Packet, PacketData,
};
use pithos_lib::helpers::ro_crate::{read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::helpers::x25519_keys::{private_key_from_pem_bytes, public_key_from_pem_bytes};
use pithos_lib::io::pithosreader::PithosReaderSimple;
use std::fs::{File, OpenOptions, read_to_string};
use std::io::{Read, Seek, SeekFrom, Write};
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

#[test]
fn test_read_to_crypt4gh() {
    let pithos_file = "/tmp/t8.shakespeare.pith".to_string();
    let output = Box::new(
        OpenOptions::new()
            .create(true)
            .write(true)
            .open("/tmp/t8.shakespeare.crypt4gh")
            .unwrap(),
    );

    // Path to reader pem file
    let reader_key_pem = "tests/data/recipient1_private.pem".to_string();

    // Read recipient public key
    let recipient_pem_content = read_to_string("tests/data/recipient2_public.pem").unwrap();
    let recipient_key = public_key_from_pem_bytes(recipient_pem_content.as_bytes()).unwrap();

    // Export file in Crypt4GH format
    let mut reader = PithosReaderSimple::new(pithos_file, reader_key_pem).unwrap();
    let (directory, _) = reader.read_directory().unwrap();
    reader
        .read_file_to_crypt4gh(
            "t8.shakespeare.txt",
            &directory,
            vec![&recipient_key],
            Some(output),
        )
        .unwrap();

    // Read recipient private key
    let reader_pem_content = read_to_string("tests/data/recipient2_private.pem").unwrap();
    let reader_key = private_key_from_pem_bytes(reader_pem_content.as_bytes()).unwrap();

    // Read Crypt4GH file and deserialize/decrypt header
    let mut buffer = Vec::new();
    let mut input = File::open("/tmp/t8.shakespeare.crypt4gh").unwrap();
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
                    data_key = Some(encryption_packet.get_encryption_key().clone());
                    break 'outer;
                }
            }
        }
    }
    let data_key = data_key.unwrap();

    // Decrypt blocks and write to file
    input.seek(SeekFrom::Start(block_start)).unwrap();
    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .open("/tmp/t8.shakespeare.raw")
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
}

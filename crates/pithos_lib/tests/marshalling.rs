#[cfg(test)]
mod marshalling_tests {
    use pithos_lib::model::structs::*;
    use pithos_lib::helpers::x25519_keys::generate_private_key;
    use std::io::Cursor;
    use x25519_dalek::PublicKey;
    use pithos_lib::model::serialization::encode_string;

    #[test]
    fn test_varint_encoding() {
        use integer_encoding::VarIntWriter;
        let mut buf = Vec::new();
        buf.write_varint(0u64).unwrap();
        assert_eq!(buf, vec![0x00]);
        buf.clear();
        buf.write_varint(127u64).unwrap();
        assert_eq!(buf, vec![0x7F]);
        buf.clear();
        buf.write_varint(128u64).unwrap();
        assert_eq!(buf, vec![0x80, 0x01]);
        buf.clear();
        buf.write_varint(300u64).unwrap();
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn test_string_encoding() {
        let s = "hello";
        let mut buf = Vec::new();
        encode_string(&mut buf, s).unwrap();
        assert_eq!(buf, vec![5, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn file_header_roundtrip() {
        let original = FileHeader::default();
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = FileHeader::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_header_roundtrip() {
        let original = BlockHeader { marker: *b"BLCK" };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = BlockHeader::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn processing_flags_roundtrip() {
        let original = ProcessingFlags(0xAB);
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = ProcessingFlags::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn block_location_roundtrip() {
        let local = BlockLocation::Local;
        let external = BlockLocation::External {
            url: "https://example.com".to_string(),
        };

        let mut buf = Vec::new();
        local.serialize(&mut buf).unwrap();
        let decoded = BlockLocation::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(local, decoded);

        buf.clear();
        external.serialize(&mut buf).unwrap();
        let decoded = BlockLocation::deserialize(&mut Cursor::new(&buf)).unwrap();
        assert_eq!(external, decoded);
    }

    #[test]
    fn block_index_entry_roundtrip() {
        let original = BlockIndexEntry {
            index: 42,
            hash: [1u8; 32],
            offset: 100,
            stored_size: 200,
            original_size: 300,
            flags: ProcessingFlags(0x01),
            location: BlockLocation::External {
                url: "url".to_string(),
            },
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = BlockIndexEntry::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn directory_roundtrip() {
        let file_entry = FileEntry {
            file_id: 1,
            path: "file.txt".to_string(),
            file_type: FileType::Data,
            block_data: BlockDataState::Decrypted(vec![(1, [2u8; 32])]),
            created: 123,
            modified: 456,
            file_size: 789,
            permissions: 0xFFFF_FFFF,
            references: vec![Reference {
                target_file_id: 2,
                relationship: 3,
            }],
            symlink_target: Some("target".to_string()),
        };
        let block_index = BlockIndexEntry {
            index: 1,
            hash: [3u8; 32],
            offset: 4,
            stored_size: 5,
            original_size: 6,
            flags: ProcessingFlags(7),
            location: BlockLocation::Local,
        };
        let enc_section = EncryptionSection {
            sender_public_key: [4u8; 32],
            recipients: vec![RecipientSection {
                recipient_public_key: [5u8; 32],
                recipient_data: RecipientData::Decrypted(vec![(6, [7u8; 32])]),
            }],
        };
        let original = Directory {
            identifier: *b"PITHOSDR",
            parent_directory_offset: Some((10, 20)),
            files: vec![file_entry.clone()],
            blocks: vec![block_index.clone()],
            relations: vec![(1, "rel".to_string())],
            encryption: vec![enc_section.clone()],
            dir_len: 12345,
            crc32: 67890,
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = Directory::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn file_type_roundtrip() {
        for ft in [
            FileType::Data,
            FileType::Metadata,
            FileType::Directory,
            FileType::Symlink,
        ] {
            let mut buf = Vec::new();
            ft.serialize(&mut buf).unwrap();
            let decoded = FileType::deserialize(&mut Cursor::new(buf)).unwrap();
            assert_eq!(ft, decoded);
        }
    }

    #[test]
    fn block_data_state_roundtrip() {
        let decrypted = BlockDataState::Decrypted(vec![(42, [1u8; 32]), (43, [2u8; 32])]);
        let encrypted = BlockDataState::Encrypted(vec![1, 2, 3, 4, 5]);
        for bds in [decrypted, encrypted] {
            let mut buf = Vec::new();
            bds.serialize(&mut buf).unwrap();
            let decoded = BlockDataState::deserialize(&mut Cursor::new(buf)).unwrap();
            assert_eq!(bds, decoded);
        }
    }

    #[test]
    fn file_entry_roundtrip() {
        let original = FileEntry {
            file_id: 123,
            path: "foo/bar.txt".to_string(),
            file_type: FileType::Symlink,
            block_data: BlockDataState::Decrypted(vec![(1, [2u8; 32])]),
            created: 111,
            modified: 222,
            file_size: 333,
            permissions: 444,
            references: vec![Reference {
                target_file_id: 555,
                relationship: 666,
            }],
            symlink_target: None,
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = FileEntry::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn reference_roundtrip() {
        let original = Reference {
            target_file_id: 1,
            relationship: 2,
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = Reference::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encryption_section_roundtrip() {
        let recipient = RecipientSection {
            recipient_public_key: [1u8; 32],
            recipient_data: RecipientData::Decrypted(vec![(2, [3u8; 32])]),
        };
        let original = EncryptionSection {
            sender_public_key: [4u8; 32],
            recipients: vec![recipient],
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = EncryptionSection::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn recipient_data_roundtrip() {
        let sender_key = generate_private_key().unwrap();
        let recipient_key = generate_private_key().unwrap();
        let shared_key = sender_key.diffie_hellman(&PublicKey::from(&recipient_key));
        let rand_key = generate_private_key().unwrap();

        // Create RecipientData
        let entry = (1u64, rand_key.to_bytes());
        let mut recipient_data = RecipientData::Decrypted(vec![entry]);

        // Encrypt RecipientData
        recipient_data.encrypt(&shared_key).unwrap();
        assert!(matches!(recipient_data, RecipientData::Encrypted { .. }));

        //Decrypt RecipientData
        recipient_data.decrypt(&shared_key).unwrap();
        match recipient_data {
            RecipientData::Encrypted(_) => panic!("Invalid recipient data state"),
            RecipientData::Decrypted(entries) => {
                assert_eq!(entries, vec![entry])
            }
        }
    }

    #[test]
    fn recipient_section_roundtrip() {
        let original = RecipientSection {
            recipient_public_key: [1u8; 32],
            recipient_data: RecipientData::Decrypted(vec![(2, [3u8; 32])]),
        };
        let mut buf = Vec::new();
        original.serialize(&mut buf).unwrap();
        let decoded = RecipientSection::deserialize(&mut Cursor::new(buf)).unwrap();
        assert_eq!(original, decoded);
    }
}

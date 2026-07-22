use indexmap::IndexMap;
use pithos_lib::error::PithosError;
use pithos_lib::helpers::directory::DirectoryBuilder;
use pithos_lib::helpers::file_entry_map::{FileEntryMap, Key};
use pithos_lib::helpers::x25519_keys::generate_private_key;
use pithos_lib::model::deserialization::{DeserializationError, DeserializationLimits};
use pithos_lib::model::serialization::encode_string;
use pithos_lib::model::structs::*;
use std::io::Cursor;
use x25519_dalek::PublicKey;

#[test]
fn robust_overlong_zero_file_count_is_accepted() {
    let mut bytes = hex_bytes("504954484f53445200000000000000000000000019b1674081");
    bytes.splice(9..10, [0x80, 0x00]);
    let length = bytes.len() as u64;
    let footer_start = bytes.len() - 12;
    bytes[footer_start..footer_start + 8].copy_from_slice(&length.to_be_bytes());
    let crc_start = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[..crc_start]);
    bytes[crc_start..].copy_from_slice(&crc.to_be_bytes());

    let directory = Directory::deserialize(&mut Cursor::new(bytes)).unwrap();
    assert!(directory.files.is_empty());
}

#[test]
fn robust_typed_narrow_overflow_is_rejected() {
    let mut bytes = b"PITH".to_vec();
    use integer_encoding::VarIntWriter;
    bytes.write_varint(u64::from(u16::MAX) + 1).unwrap();

    assert!(FileHeader::deserialize(&mut Cursor::new(bytes)).is_err());
}

#[test]
fn robust_u64_tenth_byte_overflow_is_rejected() {
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];

    assert!(BlockIndexEntry::deserialize(&mut Cursor::new(bytes)).is_err());
}

#[test]
fn robust_unterminated_varint_is_rejected() {
    let bytes = [b'P', b'I', b'T', b'H', 0x80];

    assert!(FileHeader::deserialize(&mut Cursor::new(bytes)).is_err());
}

#[test]
fn robust_maximum_typed_values_roundtrip() {
    let header = FileHeader {
        magic: *b"PITH",
        version: u16::MAX,
    };
    let mut header_bytes = Vec::new();
    header.serialize(&mut header_bytes).unwrap();
    assert_eq!(
        FileHeader::deserialize(&mut Cursor::new(header_bytes)).unwrap(),
        header
    );

    let entry = FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(vec![]),
        created: u64::MAX,
        modified: u64::MAX,
        file_size: u64::MAX,
        permissions: u32::MAX,
        references: vec![],
        symlink_target: None,
    };
    let mut entry_bytes = Vec::new();
    entry.serialize(&mut entry_bytes).unwrap();
    assert_eq!(
        FileEntry::deserialize(&mut Cursor::new(entry_bytes)).unwrap(),
        entry
    );
}

#[test]
fn robust_over_policy_file_count_is_rejected_before_entry_parsing() {
    let mut bytes = hex_bytes("504954484f53445200");
    use integer_encoding::VarIntWriter;
    bytes.write_varint(1_000_001u64).unwrap();

    let error = Directory::deserialize(&mut Cursor::new(bytes)).unwrap_err();
    assert!(error.to_string().contains("limit"));
}

#[test]
fn robust_custom_collection_limit_applies_to_blocks() {
    let directory = Directory {
        identifier: *b"PITHOSDR",
        parent_directory_offset: None,
        files: FileEntryMap::new(),
        blocks: IndexMap::from_iter([(
            [1u8; 32],
            BlockIndexEntry {
                offset: 0,
                stored_size: 0,
                original_size: 0,
                flags: ProcessingFlags(0),
                location: BlockLocation::Local,
            },
        )]),
        relations: vec![],
        encryption: IndexMap::new(),
        dir_len: 0,
        crc32: 0,
    };
    let mut bytes = Vec::new();
    directory.serialize(&mut bytes).unwrap();
    let limits = DeserializationLimits {
        max_collection_entries: 0,
        ..DeserializationLimits::default()
    };

    let error = Directory::deserialize_with_limits(&mut Cursor::new(bytes), &limits).unwrap_err();
    assert!(error.to_string().contains("blocks"));
}

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
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(vec![([1u8; 32], [2u8; 32])]),
        created: 123,
        modified: 456,
        file_size: 789,
        permissions: 0o644,
        references: vec![Reference {
            target_file_id: 2,
            relationship: 3,
        }],
        symlink_target: None,
    };
    let block_index = BlockIndexEntry {
        offset: 4,
        stored_size: 5,
        original_size: 6,
        flags: ProcessingFlags(7),
        location: BlockLocation::Local,
    };
    let enc_section = IndexMap::from_iter([(
        [4u8; 32],
        EncryptionSection {
            recipients: IndexMap::from_iter([(
                [5u8; 32],
                RecipientSection {
                    recipient_data: RecipientData::Decrypted(vec![(6, [7u8; 32])]),
                },
            )]),
        },
    )]);

    let mut files = FileEntryMap::new();
    files.insert(Key::new(0, "file.txt"), file_entry).unwrap();

    let original = Directory {
        identifier: *b"PITHOSDR",
        parent_directory_offset: None,
        files,
        blocks: IndexMap::from_iter([([1u8; 32], block_index)]),
        relations: vec![(1, "rel".to_string())],
        encryption: enc_section,
        dir_len: 12345,
        crc32: 67890,
    };

    let mut buf = Vec::new();
    original.serialize(&mut buf).unwrap();
    let decoded = Directory::deserialize(&mut Cursor::new(buf)).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn directory_integrity_crc_matches_serialized_prefix() {
    let file_entry = FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(vec![]),
        created: 0,
        modified: 0,
        file_size: 0,
        permissions: 0o644,
        references: vec![],
        symlink_target: None,
    };
    let block_index = BlockIndexEntry {
        offset: 0,
        stored_size: 0,
        original_size: 0,
        flags: ProcessingFlags(0),
        location: BlockLocation::Local,
    };
    let mut files = FileEntryMap::new();
    files.insert(Key::new(0, "file.txt"), file_entry).unwrap();
    let blocks = IndexMap::from_iter([([1u8; 32], block_index)]);

    let directory = DirectoryBuilder::new()
        .files(files)
        .blocks(blocks)
        .build()
        .unwrap();
    let mut serialized = Vec::new();
    directory.serialize(&mut serialized).unwrap();
    assert_eq!(
        directory.crc32,
        crc32fast::hash(&serialized[..serialized.len() - 4])
    );
}

fn assert_builder_directory_integrity(directory: &Directory) {
    let mut serialized = Vec::new();
    directory.serialize(&mut serialized).unwrap();

    assert_eq!(directory.dir_len, serialized.len() as u64);
    assert_eq!(
        u64::from_be_bytes(
            serialized[serialized.len() - 12..serialized.len() - 4]
                .try_into()
                .unwrap()
        ),
        directory.dir_len
    );
    assert_eq!(
        directory.crc32,
        crc32fast::hash(&serialized[..serialized.len() - 4])
    );
}

#[test]
fn directory_builder_sets_integrity_for_empty_directory() {
    let directory = DirectoryBuilder::new()
        .set_relations(vec![])
        .build()
        .unwrap();

    assert!(directory.files.is_empty());
    assert!(directory.relations.is_empty());
    assert_builder_directory_integrity(&directory);
}

#[test]
fn directory_builder_sets_integrity_for_default_relations() {
    let directory = DirectoryBuilder::new().build().unwrap();

    assert_eq!(directory.relations.len(), 10);
    assert_builder_directory_integrity(&directory);
}

#[test]
fn directory_builder_sets_integrity_for_populated_directory() {
    let mut files = FileEntryMap::new();
    files
        .insert(Key::new(7, "file.txt"), plain_entry(None))
        .unwrap();
    let blocks = IndexMap::from_iter([(
        [1u8; 32],
        BlockIndexEntry {
            offset: 4,
            stored_size: 5,
            original_size: 6,
            flags: ProcessingFlags(0),
            location: BlockLocation::Local,
        },
    )]);
    let directory = DirectoryBuilder::new()
        .files(files)
        .blocks(blocks)
        .set_relations(vec![(42, "Related".into())])
        .build()
        .unwrap();

    assert_eq!(directory.files.len(), 1);
    assert_eq!(directory.blocks.len(), 1);
    assert_eq!(directory.relations, vec![(42, "Related".into())]);
    assert_builder_directory_integrity(&directory);
}

#[test]
fn directory_builder_sets_integrity_for_encrypted_directory() {
    let sender_key = generate_private_key().unwrap();
    let recipient_key = generate_private_key().unwrap();
    let mut recipient_data = RecipientData::Decrypted(vec![(7, [3u8; 32])]);
    recipient_data
        .encrypt(&sender_key.diffie_hellman(&PublicKey::from(&recipient_key)))
        .unwrap();
    let directory = DirectoryBuilder::new()
        .encryption(IndexMap::from_iter([(
            PublicKey::from(&sender_key).to_bytes(),
            EncryptionSection {
                recipients: IndexMap::from_iter([(
                    PublicKey::from(&recipient_key).to_bytes(),
                    RecipientSection { recipient_data },
                )]),
            },
        )]))
        .build()
        .unwrap();

    assert!(matches!(
        directory
            .encryption
            .values()
            .next()
            .unwrap()
            .recipients
            .values()
            .next()
            .unwrap()
            .recipient_data,
        RecipientData::Encrypted(_)
    ));
    assert_builder_directory_integrity(&directory);
}

#[test]
fn directory_integrity_minimal_vector_matches_specification() {
    let directory = Directory {
        identifier: *b"PITHOSDR",
        parent_directory_offset: None,
        files: FileEntryMap::new(),
        blocks: IndexMap::new(),
        relations: vec![],
        encryption: IndexMap::new(),
        dir_len: 25,
        crc32: 0,
    };
    let mut prefix = Vec::new();
    directory.serialize(&mut prefix).unwrap();
    let crc = crc32fast::hash(&prefix[..prefix.len() - 4]);
    let mut complete = prefix.clone();
    let crc_start = complete.len() - 4;
    complete[crc_start..].copy_from_slice(&crc.to_be_bytes());

    assert_eq!(crc, 0xb1674081);
    assert_eq!(
        complete,
        hex_bytes("504954484f53445200000000000000000000000019b1674081")
    );
}

#[test]
fn directory_integrity_deserialization_rejects_invalid_marker() {
    let mut bytes = hex_bytes("504954484f53445200000000000000000000000019b1674081");
    bytes[..8].copy_from_slice(b"INVALID!");
    let error = Directory::deserialize(&mut Cursor::new(bytes)).unwrap_err();

    assert!(matches!(error, PithosError::InvalidDirectoryMarker { .. }));
}

fn hex_bytes(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn serialized_directory(path: &str, entry: FileEntry) -> Vec<u8> {
    let mut files = FileEntryMap::new();
    files.insert(Key::new(0, path), entry).unwrap();
    let directory = DirectoryBuilder::new().files(files).build().unwrap();
    let mut bytes = Vec::new();
    directory.serialize(&mut bytes).unwrap();
    bytes
}

fn plain_entry(target: Option<&str>) -> FileEntry {
    FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(vec![]),
        created: 0,
        modified: 0,
        file_size: 0,
        permissions: 0o644,
        references: vec![],
        symlink_target: target.map(str::to_owned),
    }
}

#[test]
fn directory_deserialization_rejects_unsafe_entry_paths() {
    for path in ["../outside", "/absolute", "nested//file", "C:/file"] {
        assert!(
            Directory::deserialize(&mut Cursor::new(serialized_directory(
                path,
                plain_entry(None)
            )))
            .is_err()
        );
    }
}

#[test]
fn directory_deserialization_rejects_missing_inconsistent_symlink_targets() {
    let mut missing = plain_entry(None);
    missing.file_type = FileType::Symlink;
    assert!(
        Directory::deserialize(&mut Cursor::new(serialized_directory("link", missing))).is_err()
    );
    assert!(
        Directory::deserialize(&mut Cursor::new(serialized_directory(
            "file",
            plain_entry(Some("target"))
        )))
        .is_err()
    );
    let mut blocks = plain_entry(Some("target"));
    blocks.file_type = FileType::Symlink;
    blocks.block_data = BlockDataState::Decrypted(vec![([0; 32], [0; 32])]);
    assert!(
        Directory::deserialize(&mut Cursor::new(serialized_directory("link", blocks))).is_err()
    );
    let mut encrypted = plain_entry(Some("target"));
    encrypted.file_type = FileType::Symlink;
    encrypted.block_data = BlockDataState::Encrypted(vec![]);
    assert!(
        Directory::deserialize(&mut Cursor::new(serialized_directory("link", encrypted))).is_err()
    );
}

#[test]
fn directory_deserialization_rejects_unsafe_symlink_targets() {
    let mut link = plain_entry(Some("../outside"));
    link.file_type = FileType::Symlink;
    assert!(Directory::deserialize(&mut Cursor::new(serialized_directory("link", link))).is_err());
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
    let decrypted =
        BlockDataState::Decrypted(vec![([42u8; 32], [1u8; 32]), ([43u8; 32], [2u8; 32])]);
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
        //file_id: 123,
        //path: "foo/bar.txt".to_string(),
        file_type: FileType::Symlink,
        block_data: BlockDataState::Decrypted(vec![([1u8; 32], [2u8; 32])]),
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
        recipient_data: RecipientData::Decrypted(vec![(2, [3u8; 32])]),
    };
    let original = EncryptionSection {
        recipients: IndexMap::from_iter([([1u8; 32], recipient)]),
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
fn block_data_state_decrypt_with_limits_rejects_oversized_block_index() {
    let key = [7u8; 32];
    let mut block_data =
        BlockDataState::Decrypted(vec![([1u8; 32], [2u8; 32]), ([3u8; 32], [4u8; 32])]);
    block_data.encrypt(key).unwrap();
    let limits = DeserializationLimits {
        max_collection_entries: 1,
        ..DeserializationLimits::default()
    };

    let error = block_data.decrypt_with_limits(&key, &limits).unwrap_err();
    assert!(matches!(
        error,
        PithosError::Deserialization(DeserializationError::LimitExceeded {
            field: "block index",
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn recipient_data_decrypt_with_limits_rejects_oversized_recipient_keys() {
    let sender_key = generate_private_key().unwrap();
    let recipient_key = generate_private_key().unwrap();
    let shared_key = sender_key.diffie_hellman(&PublicKey::from(&recipient_key));
    let mut recipient_data = RecipientData::Decrypted(vec![(1, [2u8; 32]), (3, [4u8; 32])]);
    recipient_data.encrypt(&shared_key).unwrap();
    let limits = DeserializationLimits {
        max_collection_entries: 1,
        ..DeserializationLimits::default()
    };

    let error = recipient_data
        .decrypt_with_limits(&shared_key, &limits)
        .unwrap_err();
    assert!(matches!(
        error,
        PithosError::Deserialization(DeserializationError::LimitExceeded {
            field: "recipient keys",
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn directory_decrypt_with_limits_recipient_path_propagates_recipient_limit() {
    let sender_key = generate_private_key().unwrap();
    let recipient_key = generate_private_key().unwrap();
    let shared_key = sender_key.diffie_hellman(&PublicKey::from(&recipient_key));
    let mut recipient_data = RecipientData::Decrypted(vec![(1, [2u8; 32]), (3, [4u8; 32])]);
    recipient_data.encrypt(&shared_key).unwrap();
    let mut directory = Directory {
        identifier: *b"PITHOSDR",
        parent_directory_offset: None,
        files: FileEntryMap::new(),
        blocks: IndexMap::new(),
        relations: vec![],
        encryption: IndexMap::from_iter([(
            PublicKey::from(&sender_key).to_bytes(),
            EncryptionSection {
                recipients: IndexMap::from_iter([(
                    PublicKey::from(&recipient_key).to_bytes(),
                    RecipientSection { recipient_data },
                )]),
            },
        )]),
        dir_len: 0,
        crc32: 0,
    };
    let limits = DeserializationLimits {
        max_collection_entries: 1,
        ..DeserializationLimits::default()
    };

    let error = directory
        .decrypt_recipient_with_limits(&sender_key, &limits)
        .unwrap_err();
    assert!(matches!(
        error,
        PithosError::Deserialization(DeserializationError::LimitExceeded {
            field: "recipient keys",
            limit: 1,
            actual: 2,
        })
    ));
}

#[test]
fn decrypt_with_limits_default_wrappers_decrypt_small_payloads() {
    let block_key = [7u8; 32];
    let mut block_data = BlockDataState::Decrypted(vec![([1u8; 32], [2u8; 32])]);
    block_data.encrypt(block_key).unwrap();
    block_data.decrypt(&block_key).unwrap();
    assert!(matches!(block_data, BlockDataState::Decrypted(entries) if entries.len() == 1));

    let sender_key = generate_private_key().unwrap();
    let recipient_key = generate_private_key().unwrap();
    let shared_key = sender_key.diffie_hellman(&PublicKey::from(&recipient_key));
    let mut recipient_data = RecipientData::Decrypted(vec![(1, [2u8; 32])]);
    recipient_data.encrypt(&shared_key).unwrap();
    recipient_data.decrypt(&shared_key).unwrap();
    assert!(matches!(recipient_data, RecipientData::Decrypted(entries) if entries.len() == 1));
}

#[test]
fn recipient_section_roundtrip() {
    let original = RecipientSection {
        recipient_data: RecipientData::Decrypted(vec![(2, [3u8; 32])]),
    };
    let mut buf = Vec::new();
    original.serialize(&mut buf).unwrap();
    let decoded = RecipientSection::deserialize(&mut Cursor::new(buf)).unwrap();
    assert_eq!(original, decoded);
}

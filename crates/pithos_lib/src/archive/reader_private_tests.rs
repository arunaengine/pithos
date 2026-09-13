use super::reader::{
    AccessKeys, Archive, EntryKind, ExternalBlockResolver, OpenLimits, OpenOptions,
};
use crate::archive::{
    ArchivePath, ArchiveWriter, CdcConfig, EntryMetadata, ProcessingOptions, WriteOptions,
};
use crate::crypto::{self, PrivateKey, PublicKey};
use crate::error::PithosError;
use crate::format::limits::DeserializationLimits;
use crate::format::wire::{
    BlockDataState, BlockLocation, Directory, EncryptionSection, FileType, RecipientData,
    RecipientSection,
};
use crate::source::{ArchiveSource, MemorySource, SourceError};
use indexmap::IndexMap;
use std::fs::File;
use std::io::{Cursor, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroizing;

fn private(name: &str) -> PrivateKey {
    crate::crypto::parse_private_pem(
        &std::fs::read(format!("tests/data/keys/{name}_private.pem")).unwrap(),
    )
    .unwrap()
}

fn public(name: &str) -> PublicKey {
    crate::crypto::parse_public_pem(
        &std::fs::read(format!("tests/data/keys/{name}_public.pem")).unwrap(),
    )
    .unwrap()
}

fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
    fixture_with("archive reader private fixture", 0)
}

fn empty_fixture() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("empty.pith");
    let writer = ArchiveWriter::create(
        File::create(&path).unwrap(),
        WriteOptions::new(private("sender"), vec![public("recipient1")]),
    )
    .unwrap();
    writer.finish().unwrap();
    (temp, path)
}

fn fixture_with(content: &str, compression_level: u8) -> (tempfile::TempDir, PathBuf) {
    fixture_with_encryption(content, compression_level, true)
}

fn fixture_with_encryption(
    content: &str,
    compression_level: u8,
    encrypt: bool,
) -> (tempfile::TempDir, PathBuf) {
    fixture_with_options(content, compression_level, encrypt, None)
}

fn fixture_with_options(
    content: &str,
    compression_level: u8,
    encrypt: bool,
    cdc: Option<CdcConfig>,
) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("archive.pith");
    let options = WriteOptions::new(private("sender"), vec![public("recipient1")]);
    let options = match cdc {
        Some(cdc) => options.with_cdc(cdc),
        None => options,
    };
    let mut writer = ArchiveWriter::create(File::create(&path).unwrap(), options).unwrap();
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(encrypt, compression_level).unwrap(),
            Some(content.len() as u64),
            Cursor::new(content.as_bytes()),
        )
        .unwrap();
    writer.finish().unwrap();
    (temp, path)
}

fn fixture_entries(entries: &[(&str, &str)]) -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("entries.pith");
    let mut writer = ArchiveWriter::create(
        File::create(&path).unwrap(),
        WriteOptions::new(private("sender"), vec![public("recipient1")]),
    )
    .unwrap();
    for (path, content) in entries {
        writer
            .add_file(
                ArchivePath::new(*path).unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(true, 0).unwrap(),
                Some(content.len() as u64),
                Cursor::new(content.as_bytes()),
            )
            .unwrap();
    }
    writer.finish().unwrap();
    (temp, path)
}

fn open_path(path: &Path, keys: AccessKeys) -> Archive<MemorySource> {
    Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(path).unwrap())),
        OpenOptions::default().with_access_keys(keys),
    )
    .unwrap()
}

fn directory_bounds(bytes: &[u8]) -> (usize, usize) {
    let len = u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());
    let len = usize::try_from(len).unwrap();
    (bytes.len() - len, len)
}

fn rewrite_terminal_directory(path: &Path, mutate: impl FnOnce(&mut Directory)) {
    let mut archive = std::fs::read(path).unwrap();
    let (start, _) = directory_bounds(&archive);
    let mut directory = crate::format::codec::decode_directory(
        &mut Cursor::new(&archive[start..]),
        &DeserializationLimits::default(),
    )
    .unwrap();
    mutate(&mut directory);
    crate::format::codec::update_directory_len(&mut directory).unwrap();
    crate::format::codec::update_directory_crc(&mut directory).unwrap();
    let mut replacement = Vec::new();
    crate::format::codec::encode_directory(&directory, &mut replacement).unwrap();
    archive.truncate(start);
    archive.extend_from_slice(&replacement);
    std::fs::write(path, archive).unwrap();
}

fn decode_terminal_directory(path: &Path) -> Directory {
    let archive = std::fs::read(path).unwrap();
    let (start, _) = directory_bounds(&archive);
    crate::format::codec::decode_directory(
        &mut Cursor::new(&archive[start..]),
        &DeserializationLimits::default(),
    )
    .unwrap()
}

fn append_empty_directory(path: &Path, relations: Option<Vec<(u64, String)>>) {
    let mut archive = std::fs::read(path).unwrap();
    let (parent_start, parent_len) = directory_bounds(&archive);
    let mut directory = Directory::new(
        Some((parent_start as u64, parent_len as u64)),
        crate::format::entries::WireEntries::new(),
        IndexMap::new(),
    );
    if let Some(relations) = relations {
        directory.relations = relations;
    }
    crate::format::codec::update_directory_len(&mut directory).unwrap();
    crate::format::codec::update_directory_crc(&mut directory).unwrap();
    crate::format::codec::encode_directory(&directory, &mut archive).unwrap();
    std::fs::write(path, archive).unwrap();
}

fn append_recipient_directory(path: &Path, mutate: impl FnOnce(&mut RecipientData)) {
    let mut archive = std::fs::read(path).unwrap();
    let (parent_start, parent_len) = directory_bounds(&archive);
    let parent = crate::format::codec::decode_directory(
        &mut Cursor::new(&archive[parent_start..]),
        &DeserializationLimits::default(),
    )
    .unwrap();
    let (sender, section) = parent.encryption.first().unwrap();
    let (recipient, recipient_section) = section.recipients.first().unwrap();
    let mut recipient_data = recipient_section.recipient_data.clone();
    mutate(&mut recipient_data);
    let encryption = IndexMap::from_iter([(
        *sender,
        EncryptionSection {
            recipients: IndexMap::from_iter([(*recipient, RecipientSection { recipient_data })]),
        },
    )]);
    let mut child = Directory::new(
        Some((parent_start as u64, parent_len as u64)),
        crate::format::entries::WireEntries::new(),
        encryption,
    );
    crate::format::codec::update_directory_len(&mut child).unwrap();
    crate::format::codec::update_directory_crc(&mut child).unwrap();
    crate::format::codec::encode_directory(&child, &mut archive).unwrap();
    std::fs::write(path, archive).unwrap();
}

fn set_base_recipient_records(path: &Path, records: Vec<(u64, [u8; 32])>) {
    rewrite_terminal_directory(path, |directory| {
        directory
            .encryption
            .first_mut()
            .unwrap()
            .1
            .recipients
            .first_mut()
            .unwrap()
            .1
            .recipient_data = RecipientData::Decrypted(Zeroizing::new(records));
    });
}

fn make_terminal_recipient_count_and_id_non_minimal(path: &Path, id: u8, key: u8) {
    let mut archive = std::fs::read(path).unwrap();
    let (start, _) = directory_bounds(&archive);
    let pattern = [vec![1, 1, id], vec![key; 32]].concat();
    let relative = archive[start..]
        .windows(pattern.len())
        .position(|window| window == pattern)
        .expect("terminal decrypted recipient record");
    let record = start + relative;
    archive.splice(record + 1..record + 3, [0x81, 0x00, id | 0x80, 0x00]);
    let directory_len = (archive.len() - start) as u64;
    let footer = archive.len() - 12;
    archive[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
    let checksum = crc32fast::hash(&archive[start..archive.len() - 4]);
    let crc_offset = archive.len() - 4;
    archive[crc_offset..].copy_from_slice(&checksum.to_be_bytes());
    std::fs::write(path, archive).unwrap();
}

fn assert_conflicting_recipient_grant(path: &Path) {
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    for with_matching_key in [false, true] {
        let options = if with_matching_key {
            OpenOptions::default()
                .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
        } else {
            OpenOptions::default()
        };
        let error = match Archive::open(MemorySource::new(Arc::clone(&bytes)), options) {
            Ok(_) => panic!("conflicting recipient grant was accepted"),
            Err(error) => error,
        };
        assert_eq!(format!("{error:?}"), "ConflictingRecipientGrant");
    }
}

fn open_without_keys(path: &Path) -> Result<Archive<MemorySource>, PithosError> {
    Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(path).unwrap())),
        OpenOptions::default(),
    )
}

fn first_block(path: &Path) -> (u64, u64) {
    let bytes = std::fs::read(path).unwrap();
    let (start, _) = directory_bounds(&bytes);
    let directory = crate::format::codec::decode_directory(
        &mut Cursor::new(&bytes[start..]),
        &DeserializationLimits::default(),
    )
    .unwrap();
    let block = directory.blocks.first().unwrap().1;
    (block.offset, block.stored_size)
}

fn corrupt_payload(path: &Path, byte: usize) {
    let (offset, stored) = first_block(path);
    assert!(byte < stored as usize);
    let mut bytes = std::fs::read(path).unwrap();
    bytes[offset as usize + 4 + byte] ^= 1;
    std::fs::write(path, bytes).unwrap();
}

fn assert_copy_failure_without_sink(path: &Path) {
    let archive = open_path(path, AccessKeys::new().with_key(private("recipient1")));
    let mut sink = RecordingSink(Vec::new());
    assert!(archive.copy_to("data", &mut sink).is_err());
    assert!(sink.0.is_empty());
}

struct RecordingSink(Vec<u8>);

impl Write for RecordingSink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

struct RecordingSource {
    bytes: Arc<[u8]>,
    reads: Arc<Mutex<Vec<(u64, usize)>>>,
}

impl ArchiveSource for RecordingSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }

    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        self.reads.lock().unwrap().push((offset, output.len()));
        MemorySource::new(Arc::clone(&self.bytes)).read_exact_at(offset, output)
    }
}

#[test]
fn writers_emit_only_the_required_standard_relationship_table() {
    let (_temporary, path) = fixture();
    let expected = [
        (0, "DESCRIBES"),
        (1, "ANNOTATES"),
        (2, "DERIVED_FROM"),
        (3, "SOURCE_OF"),
        (4, "PREVIOUS_VERSION"),
        (5, "NEXT_VERSION"),
        (6, "PART_OF"),
        (7, "CONTAINS"),
        (8, "INPUT_TO"),
        (9, "OUTPUT_FROM"),
    ];
    assert_eq!(
        decode_terminal_directory(&path)
            .relations
            .iter()
            .map(|(id, name)| (*id, name.as_str()))
            .collect::<Vec<_>>(),
        expected
    );

    append_empty_directory(&path, None);
    assert!(decode_terminal_directory(&path).relations.is_empty());
    open_without_keys(&path).unwrap();
}

#[test]
fn archive_rejects_invalid_base_standard_relationship_tables() {
    let mutations: [fn(&mut Directory); 3] = [
        |directory| directory.relations.clear(),
        |directory| directory.relations[0].1 = "describes".into(),
        |directory| directory.relations.swap(0, 1),
    ];
    for mutate in mutations {
        let (_temporary, path) = fixture();
        rewrite_terminal_directory(&path, mutate);
        assert!(open_without_keys(&path).is_err());
    }
}

#[test]
fn archive_validates_custom_relationship_ids_and_names() {
    for relation in [(10, "CUSTOM"), (999, "CUSTOM"), (1000, "")] {
        let (_temporary, path) = fixture();
        rewrite_terminal_directory(&path, |directory| {
            directory.relations.push((relation.0, relation.1.into()));
        });
        assert!(open_without_keys(&path).is_err(), "{relation:?}");
    }

    let (_temporary, path) = fixture();
    rewrite_terminal_directory(&path, |directory| {
        directory.relations.push((1000, "CUSTOM".into()));
    });
    open_without_keys(&path).unwrap();
}

#[test]
fn appended_standard_relationship_repeats_must_match() {
    let (_temporary, exact) = fixture();
    append_empty_directory(&exact, Some(vec![(0, "DESCRIBES".into())]));
    open_without_keys(&exact).unwrap();

    let (_temporary, conflicting) = fixture();
    append_empty_directory(&conflicting, Some(vec![(0, "describes".into())]));
    assert!(open_without_keys(&conflicting).is_err());
}

#[test]
fn archive_rejects_no_content_sizes_and_undefined_permission_bits() {
    let mutations: [fn(&mut crate::format::wire::FileEntry); 3] = [
        |entry| {
            entry.file_type = FileType::Directory;
            entry.block_data = BlockDataState::Decrypted(Vec::new().into());
            entry.file_size = 1;
            entry.symlink_target = None;
        },
        |entry| {
            entry.file_type = FileType::Symlink;
            entry.block_data = BlockDataState::Decrypted(Vec::new().into());
            entry.file_size = 1;
            entry.symlink_target = Some("target".into());
        },
        |entry| entry.permissions = 0x1000,
    ];
    for mutate in mutations {
        let (_temporary, path) = fixture();
        rewrite_terminal_directory(&path, |directory| {
            directory
                .files
                .try_for_each_mut(|_, entry| {
                    mutate(entry);
                    Ok::<_, ()>(())
                })
                .unwrap();
        });
        assert!(open_without_keys(&path).is_err());
    }
}

#[derive(Clone)]
struct CountingResolver {
    response: Arc<[u8]>,
    calls: Arc<AtomicUsize>,
    expected: Arc<Mutex<Vec<(u64, u64)>>>,
}

impl ExternalBlockResolver for CountingResolver {
    fn resolve(
        &self,
        _location: &super::types::ExternalLocation,
        expected_len: u64,
        max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.expected
            .lock()
            .unwrap()
            .push((expected_len, max_response_size));
        Ok(self.response.to_vec())
    }
}

fn as_external(path: &Path) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap();
    let (offset, stored) = first_block(path);
    let response = bytes[offset as usize..offset as usize + 4 + stored as usize].to_vec();
    rewrite_terminal_directory(path, |directory| {
        let block = directory.blocks.first_mut().unwrap().1;
        block.location = BlockLocation::External {
            url: "test:external".into(),
        };
        block.offset = u64::MAX;
    });
    response
}

struct CountingSource {
    bytes: Arc<[u8]>,
    reads: Arc<AtomicUsize>,
}
impl ArchiveSource for CountingSource {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(self.bytes.len() as u64)
    }
    fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), SourceError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let start = usize::try_from(offset).map_err(|_| SourceError::RangeOverflow {
            offset,
            length: output.len(),
        })?;
        let input =
            self.bytes
                .get(start..start + output.len())
                .ok_or(SourceError::UnexpectedEof {
                    offset,
                    expected: output.len(),
                    actual: self.bytes.len().saturating_sub(start),
                })?;
        output.copy_from_slice(input);
        Ok(())
    }
}

#[test]
fn archive_open_copy_range_unavailable_and_limits_are_boundary_checked() {
    let (_temp, path) = fixture();
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    let reads = Arc::new(AtomicUsize::new(0));
    let archive = Archive::open(
        CountingSource {
            bytes: Arc::clone(&bytes),
            reads: Arc::clone(&reads),
        },
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private("recipient1"))),
    )
    .unwrap();
    let mut output = Vec::new();
    archive.copy_to("data", &mut output).unwrap();
    assert_eq!(output, b"archive reader private fixture");
    let before = reads.load(Ordering::Relaxed);
    archive
        .copy_range_to("data", 0..0, &mut Vec::new())
        .unwrap();
    assert_eq!(reads.load(Ordering::Relaxed), before);
    assert!(
        archive
            .copy_range_to("data", 99..100, &mut Vec::new())
            .is_err()
    );
    assert_eq!(reads.load(Ordering::Relaxed), before);
    let unavailable = Archive::open(MemorySource::new(bytes), OpenOptions::default()).unwrap();
    assert!(matches!(
        unavailable.entries().next().unwrap().kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));
}

#[test]
fn archive_opens_terminal_entries_preserving_entry_order_and_unavailable_entries() {
    let (_temporary, path) = fixture_entries(&[("first", "one"), ("second", "two")]);
    let archive = open_path(&path, AccessKeys::new().with_key(private("recipient1")));
    let entries = archive.entries().collect::<Vec<_>>();
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    assert_eq!(entries[0].permissions, 0o644);
    assert_eq!(entries[0].created, 0);
    assert_eq!(entries[0].modified, 0);
    assert!(matches!(
        entries[0].kind,
        EntryKind::File {
            available: true,
            ..
        }
    ));

    let unavailable = open_path(&path, AccessKeys::new());
    assert!(matches!(
        unavailable.entries().next().unwrap().kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));
}

#[test]
fn archive_distinguishes_missing_and_wrong_keys_from_matching_metadata_corruption() {
    let (_temporary, path) = fixture();
    for keys in [
        AccessKeys::new(),
        AccessKeys::new().with_key(private("recipient2")),
    ] {
        let archive = open_path(&path, keys);
        assert!(matches!(
            archive.copy_to("data", &mut Vec::new()),
            Err(PithosError::ContentUnavailable)
        ));
    }

    let (_temporary, envelope) = fixture();
    rewrite_terminal_directory(&envelope, |directory| {
        let recipient = directory
            .encryption
            .values_mut()
            .next()
            .unwrap()
            .recipients
            .values_mut()
            .next()
            .unwrap();
        if let RecipientData::Encrypted(bytes) = &mut recipient.recipient_data {
            bytes[0] ^= 1;
        }
    });
    assert!(matches!(
        Archive::open(
            MemorySource::new(Arc::<[u8]>::from(std::fs::read(envelope).unwrap())),
            OpenOptions::default()
                .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
        ),
        Err(PithosError::Crypt(_))
    ));

    let (_temporary, blocks) = fixture();
    rewrite_terminal_directory(&blocks, |directory| {
        directory
            .files
            .try_for_each_mut(|_, file| {
                if let BlockDataState::Encrypted(bytes) = &mut file.block_data {
                    bytes[0] ^= 1;
                }
                Ok::<_, ()>(())
            })
            .unwrap();
    });
    assert!(matches!(
        Archive::open(
            MemorySource::new(Arc::<[u8]>::from(std::fs::read(blocks).unwrap())),
            OpenOptions::default()
                .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
        ),
        Err(PithosError::Crypt(_))
    ));
}

#[test]
fn archive_rejects_conflicting_recovered_file_keys_at_open() {
    let (_temporary, path) = fixture();
    let reader = private("recipient1").into_dalek_static_secret();
    rewrite_terminal_directory(&path, |directory| {
        let sender = StaticSecret::from([9; 32]);
        let recipient = DalekPublicKey::from(&reader);
        let shared = sender.diffie_hellman(&recipient);
        let mut plaintext = vec![1, 0];
        plaintext.extend_from_slice(&[0x77; 32]);
        let encrypted = crypto::seal_crypt4gh_payload(shared.as_bytes(), &plaintext).unwrap();
        directory.encryption.insert(
            DalekPublicKey::from(&sender).to_bytes(),
            EncryptionSection {
                recipients: IndexMap::from_iter([(
                    recipient.to_bytes(),
                    RecipientSection {
                        recipient_data: RecipientData::Encrypted(encrypted),
                    },
                )]),
            },
        );
    });
    assert!(matches!(
        Archive::open(
            MemorySource::new(Arc::<[u8]>::from(std::fs::read(path).unwrap())),
            OpenOptions::default()
                .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
        ),
        Err(PithosError::ConflictingRecoveredFileKey)
    ));
}

#[test]
fn archive_validates_every_encoded_sender_and_recipient_key_without_access_keys() {
    for sender_is_invalid in [true, false] {
        let (_temporary, path) = empty_fixture();
        rewrite_terminal_directory(&path, |directory| {
            if sender_is_invalid {
                let section = directory.encryption.first().unwrap().1.clone();
                directory.encryption.clear();
                directory.encryption.insert([0; 32], section);
            } else {
                let section = directory.encryption.first_mut().unwrap().1;
                let recipient = section.recipients.first().unwrap().1.clone();
                section.recipients.clear();
                section.recipients.insert([0; 32], recipient);
            }
        });

        assert!(matches!(
            open_without_keys(&path),
            Err(PithosError::Crypt(
                crypto::CryptoError::NonContributoryPublicKey
            ))
        ));
    }
}

#[test]
fn structurally_equal_encrypted_recipient_grants_repeat_with_or_without_access_keys() {
    let (_temporary, path) = empty_fixture();
    append_recipient_directory(&path, |_| {});
    open_without_keys(&path).unwrap();
    open_path(&path, AccessKeys::new().with_key(private("recipient1")));
}

#[test]
fn encrypted_recipient_grant_conflicts_are_key_independent_and_compare_all_bytes() {
    for mutate_last_byte in [false, true] {
        let (_temporary, path) = empty_fixture();
        append_recipient_directory(&path, |data| {
            let RecipientData::Encrypted(bytes) = data else {
                panic!("writer recipient grant was not sealed");
            };
            let index = if mutate_last_byte { bytes.len() - 1 } else { 0 };
            bytes[index] ^= 1;
        });
        assert_conflicting_recipient_grant(&path);
    }
}

#[test]
fn decrypted_recipient_grants_compare_decoded_order_and_accept_non_minimal_uleb128() {
    let first = (7, [0x5a; 32]);
    let second = (8, [0xa5; 32]);

    let (_temporary, equal) = empty_fixture();
    set_base_recipient_records(&equal, vec![first]);
    append_recipient_directory(&equal, |_| {});
    make_terminal_recipient_count_and_id_non_minimal(&equal, 7, 0x5a);
    open_without_keys(&equal).unwrap();
    open_path(&equal, AccessKeys::new().with_key(private("recipient1")));

    let (_temporary, conflicting) = empty_fixture();
    set_base_recipient_records(&conflicting, vec![first, second]);
    append_recipient_directory(&conflicting, |data| {
        let RecipientData::Decrypted(records) = data else {
            panic!("test grant was unexpectedly encrypted");
        };
        records.reverse();
    });
    assert_conflicting_recipient_grant(&conflicting);
}

#[test]
fn recipient_grant_variants_must_match_across_directories() {
    let (_temporary, path) = empty_fixture();
    set_base_recipient_records(&path, Vec::new());
    append_recipient_directory(&path, |data| {
        *data = RecipientData::Encrypted(Vec::new());
    });
    assert_conflicting_recipient_grant(&path);
}

#[test]
fn archive_ranges_are_half_open_and_invalid_ranges_do_not_acquire_payload() {
    let (_temporary, path) = fixture_with("0123456789abcdef", 0);
    let bytes = Arc::<[u8]>::from(std::fs::read(path).unwrap());
    let reads = Arc::new(AtomicUsize::new(0));
    let archive = Archive::open(
        CountingSource {
            bytes,
            reads: Arc::clone(&reads),
        },
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private("recipient1"))),
    )
    .unwrap();
    for (range, expected) in [
        (0..4, b"0123".as_slice()),
        (4..12, b"456789ab".as_slice()),
        (12..16, b"cdef".as_slice()),
        (16..16, b"".as_slice()),
    ] {
        let mut sink = Vec::new();
        archive.copy_range_to("data", range, &mut sink).unwrap();
        assert_eq!(sink, expected);
    }
    let before = reads.load(Ordering::Relaxed);
    for range in [Range { start: 8, end: 7 }, 17..17, 0..17] {
        assert!(matches!(
            archive.copy_range_to("data", range, &mut Vec::new()),
            Err(PithosError::InvalidReadRange { .. })
        ));
    }
    assert_eq!(reads.load(Ordering::Relaxed), before);
}

#[test]
fn archive_ranges_verify_and_slice_every_intersecting_multiblock_payload() {
    let content = (0..512)
        .map(|index| format!("{index:08x}-unique-cdc-payload-"))
        .collect::<String>();
    let (_temporary, path) = fixture_with_options(
        &content,
        0,
        true,
        Some(CdcConfig::new(64, 256, 1024).unwrap()),
    );
    let archive = open_path(&path, AccessKeys::new().with_key(private("recipient1")));
    let ranges = [
        0..31,
        91..511,
        (content.len() - 71) as u64..content.len() as u64,
    ];
    for range in ranges {
        let mut output = Vec::new();
        archive
            .copy_range_to("data", range.clone(), &mut output)
            .unwrap();
        assert_eq!(
            output,
            content.as_bytes()[range.start as usize..range.end as usize]
        );
    }
}

#[test]
fn archive_rejects_bad_nonce_tag_and_ciphertext_before_sink_output() {
    for byte in [0, 12, 28] {
        let (_temporary, path) = fixture_with(
            "encrypted payload long enough for every corruption position",
            0,
        );
        corrupt_payload(&path, byte);
        assert_copy_failure_without_sink(&path);
    }
}

#[test]
fn archive_rejects_bad_compressed_payload_before_sink_output() {
    let (_temporary, path) =
        fixture_with_encryption(&"repeated block payload ".repeat(512), 3, false);
    corrupt_payload(&path, 0);
    let archive = open_path(&path, AccessKeys::new().with_key(private("recipient1")));
    let mut sink = RecordingSink(Vec::new());
    let error = archive.copy_to("data", &mut sink).unwrap_err();
    assert!(sink.0.is_empty());
    assert!(error.to_string().contains("decompress block"));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn archive_rejects_descriptor_size_mismatches_before_sink_output() {
    let (_temporary, path) = fixture();
    rewrite_terminal_directory(&path, |directory| {
        let block = directory.blocks.first_mut().unwrap().1;
        block.original_size += 1;
        directory
            .files
            .try_for_each_mut(|_, file| {
                file.file_size += 1;
                Ok::<_, ()>(())
            })
            .unwrap();
    });
    let archive = open_path(&path, AccessKeys::new().with_key(private("recipient1")));
    let mut sink = RecordingSink(Vec::new());
    assert!(archive.copy_to("data", &mut sink).is_err());
    assert!(sink.0.is_empty());
}

#[test]
fn archive_rejects_plaintext_hash_mismatches_before_sink_output() {
    let (_temporary, hash) = fixture_with_encryption("plaintext hash verification", 0, false);
    corrupt_payload(&hash, 0);
    let archive = open_path(&hash, AccessKeys::new().with_key(private("recipient1")));
    let mut sink = RecordingSink(Vec::new());
    assert!(matches!(
        archive.copy_to("data", &mut sink),
        Err(PithosError::BlockHashMismatch { .. })
    ));
    assert!(sink.0.is_empty());
}

#[test]
fn archive_rejects_stored_size_failures_before_sink_output() {
    let (_temporary, stored) = fixture();
    rewrite_terminal_directory(&stored, |directory| {
        directory.blocks.first_mut().unwrap().1.stored_size -= 1
    });
    assert_copy_failure_without_sink(&stored);
}

#[test]
fn archive_open_validates_local_markers_without_reading_payloads_or_access_keys() {
    let (_temporary, path) = fixture_with("marker validation payload", 0);
    let (offset, stored_size) = first_block(&path);
    let bytes = Arc::<[u8]>::from(std::fs::read(&path).unwrap());
    let reads = Arc::new(Mutex::new(Vec::new()));
    Archive::open(
        RecordingSource {
            bytes,
            reads: Arc::clone(&reads),
        },
        OpenOptions::default(),
    )
    .unwrap();
    let reads = reads.lock().unwrap();
    assert!(
        reads.contains(&(offset, 4)),
        "local marker was not read at open"
    );
    let payload_start = offset + 4;
    let payload_end = payload_start + stored_size;
    assert!(
        reads.iter().all(|(start, len)| {
            let end = start.saturating_add(*len as u64);
            end <= payload_start || *start >= payload_end
        }),
        "archive open read local payload bytes"
    );
}

#[test]
fn archive_open_rejects_missing_or_changed_local_block_markers_without_access_keys() {
    for missing in [false, true] {
        let (_temporary, path) = fixture_with("invalid marker payload", 0);
        if missing {
            rewrite_terminal_directory(&path, |directory| {
                let descriptor = directory.blocks.first_mut().unwrap().1;
                descriptor.offset += 1;
                descriptor.stored_size -= 1;
            });
        } else {
            let (offset, _) = first_block(&path);
            let mut bytes = std::fs::read(&path).unwrap();
            bytes[offset as usize..offset as usize + 4].copy_from_slice(b"NOPE");
            std::fs::write(&path, bytes).unwrap();
        }

        let error = match open_without_keys(&path) {
            Ok(_) => panic!("archive with an invalid local block marker opened"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("block marker"));
    }
}

#[test]
fn encrypted_local_descriptor_stored_size_has_a_28_byte_minimum() {
    for stored_size in [0, 27] {
        let (_temporary, path) = fixture_with("encrypted descriptor size boundary", 0);
        rewrite_terminal_directory(&path, |directory| {
            let descriptor = directory.blocks.first_mut().unwrap().1;
            assert!(descriptor.flags.is_encrypted());
            descriptor.stored_size = stored_size;
        });
        let error = match open_without_keys(&path) {
            Ok(_) => panic!("encrypted descriptor with stored size {stored_size} opened"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("block descriptor"));
    }

    let (_temporary, path) = fixture_with("encrypted descriptor size boundary", 0);
    rewrite_terminal_directory(&path, |directory| {
        let descriptor = directory.blocks.first_mut().unwrap().1;
        assert!(descriptor.flags.is_encrypted());
        descriptor.stored_size = 28;
    });
    open_without_keys(&path).unwrap();
}

#[test]
fn archive_external_blocks_validate_exact_framing_and_share_read_paths() {
    let (temporary, path) = fixture();
    let response = as_external(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let expected = Arc::new(Mutex::new(Vec::new()));
    let resolver = CountingResolver {
        response: Arc::from(response.clone()),
        calls: Arc::clone(&calls),
        expected: Arc::clone(&expected),
    };
    let archive = Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(&path).unwrap())),
        OpenOptions::default()
            .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
            .with_external_resolver(resolver),
    )
    .unwrap();
    let mut full = Vec::new();
    archive.copy_to("data", &mut full).unwrap();
    let mut range = Vec::new();
    archive.copy_range_to("data", 1..4, &mut range).unwrap();
    let output = temporary.path().join("external-output");
    extract(&archive, "data", &output).unwrap();
    let mut crypt4gh = Vec::new();
    crypt4gh::export(&archive, "data", vec![public("recipient2")], &mut crypt4gh).unwrap();
    assert_eq!(std::fs::read(output.join("data")).unwrap(), full);
    assert_eq!(range, &full[1..4]);
    assert!(!crypt4gh.is_empty());
    assert_eq!(calls.load(Ordering::Relaxed), 4);
    let (expected_len, policy) = expected.lock().unwrap()[0];
    assert_eq!(expected_len, response.len() as u64);
    assert_eq!(policy, OpenLimits::default().max_stored_block_bytes + 4);

    let missing = Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(&path).unwrap())),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(private("recipient1"))),
    )
    .unwrap();
    assert!(matches!(
        missing.copy_to("data", &mut Vec::new()),
        Err(PithosError::ExternalBlockSourceRequired)
    ));
    let mut corrupt = response.clone();
    corrupt[4] ^= 1;
    for response in [
        vec![b'B'; 3],
        [b"BLCK".as_slice(), &response, b"x"].concat(),
        [b"NOPE".as_slice(), &response[4..]].concat(),
        corrupt,
    ] {
        let resolver = CountingResolver {
            response: Arc::from(response),
            calls: Arc::new(AtomicUsize::new(0)),
            expected: Arc::new(Mutex::new(Vec::new())),
        };
        let archive = Archive::open(
            MemorySource::new(Arc::<[u8]>::from(std::fs::read(&path).unwrap())),
            OpenOptions::default()
                .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
                .with_external_resolver(resolver),
        )
        .unwrap();
        assert!(archive.copy_to("data", &mut Vec::new()).is_err());
    }
}

#[test]
fn archive_block_limits_reject_before_local_or_external_acquisition() {
    let (_temporary, path) = fixture();
    let bytes = Arc::<[u8]>::from(std::fs::read(&path).unwrap());
    let reads = Arc::new(AtomicUsize::new(0));
    let limits = OpenLimits {
        max_stored_block_bytes: 0,
        ..OpenLimits::default()
    };
    let archive = Archive::open(
        CountingSource {
            bytes: Arc::clone(&bytes),
            reads: Arc::clone(&reads),
        },
        OpenOptions::default()
            .with_limits(limits)
            .with_access_keys(AccessKeys::new().with_key(private("recipient1"))),
    )
    .unwrap();
    let before = reads.load(Ordering::Relaxed);
    assert!(matches!(
        archive.copy_to("data", &mut Vec::new()),
        Err(PithosError::LimitExceeded {
            field: "stored block",
            ..
        })
    ));
    assert_eq!(reads.load(Ordering::Relaxed), before);

    let response = as_external(&path);
    let calls = Arc::new(AtomicUsize::new(0));
    let resolver = CountingResolver {
        response: Arc::from(response),
        calls: Arc::clone(&calls),
        expected: Arc::new(Mutex::new(Vec::new())),
    };
    let archive = Archive::open(
        MemorySource::new(Arc::<[u8]>::from(std::fs::read(path).unwrap())),
        OpenOptions::default()
            .with_limits(limits)
            .with_access_keys(AccessKeys::new().with_key(private("recipient1")))
            .with_external_resolver(resolver),
    )
    .unwrap();
    assert!(matches!(
        archive.copy_to("data", &mut Vec::new()),
        Err(PithosError::LimitExceeded {
            field: "stored block",
            ..
        })
    ));
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    let reads = Arc::new(AtomicUsize::new(0));
    let limits = OpenLimits {
        max_decoded_block_bytes: 0,
        ..OpenLimits::default()
    };
    let archive = Archive::open(
        CountingSource {
            bytes,
            reads: Arc::clone(&reads),
        },
        OpenOptions::default()
            .with_limits(limits)
            .with_access_keys(AccessKeys::new().with_key(private("recipient1"))),
    )
    .unwrap();
    let before = reads.load(Ordering::Relaxed);
    assert!(matches!(
        archive.copy_to("data", &mut Vec::new()),
        Err(PithosError::LimitExceeded {
            field: "decoded block",
            ..
        })
    ));
    assert_eq!(reads.load(Ordering::Relaxed), before);
}
use crate::adapters::crypt4gh;
use crate::fs::extract;

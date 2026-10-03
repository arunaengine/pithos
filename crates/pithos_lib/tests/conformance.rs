//! Conformance matrix for the version 1.1 rules, using only the public API.

mod common;

use common::util::{private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, AppendOptions, Archive, ArchivePath, ArchiveWriter, BlockKeyMode, Chunking,
    EntryKind, EntryMetadata, OpenOptions, PayloadCipher, Piece, PieceEncoder, ProcessingOptions,
    WriteOptions, compose,
};
use pithos_lib::error::{DeserializationError, PithosError};
use pithos_lib::fs::{append_files, grant_readers};
use pithos_lib::source::MemorySource;
use std::io::Cursor;
use std::path::{Path, PathBuf};

const BLOCK: usize = 1024;
/// `BLCK`, a 12-byte nonce, one uncompressed block and a 16-byte tag.
const STORED_BLOCK: usize = 4 + 12 + BLOCK + 16;

fn content(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31) ^ seed ^ (index >> 8) as u8)
        .collect()
}

fn keys(names: &[&str]) -> AccessKeys {
    names.iter().fold(AccessKeys::new(), |keys, name| {
        keys.with_key(private_key(name))
    })
}

fn open(bytes: Vec<u8>, keys: AccessKeys) -> Archive<MemorySource> {
    Archive::open(
        MemorySource::new(bytes),
        OpenOptions::default().with_access_keys(keys),
    )
    .unwrap()
}

fn read(archive: &Archive<MemorySource>, path: &str) -> Vec<u8> {
    let mut output = Vec::new();
    archive.copy_to(path, &mut output).unwrap();
    output
}

fn available(archive: &Archive<MemorySource>, path: &str) -> bool {
    match archive.entry(path).unwrap().unwrap().kind {
        EntryKind::File { available, .. } | EntryKind::Metadata { available, .. } => available,
        other => panic!("{path} is not content: {other:?}"),
    }
}

fn encrypted(level: u8) -> ProcessingOptions {
    ProcessingOptions::new(true, level).unwrap()
}

fn aes(options: ProcessingOptions) -> ProcessingOptions {
    options.with_cipher(PayloadCipher::Aes256Gcm).unwrap()
}

fn unique(options: ProcessingOptions) -> ProcessingOptions {
    options.with_key_mode(BlockKeyMode::Unique).unwrap()
}

/// Writes an encrypted archive in 1 KiB blocks, one file per `(path, processing, content)`.
fn write_archive(files: &[(&str, ProcessingOptions, &[u8])]) -> Vec<u8> {
    let options = WriteOptions::new(private_key("sender"), vec![public_key("recipient1")])
        .with_chunking(Chunking::Fixed(BLOCK));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    for (path, processing, bytes) in files {
        writer
            .add_file(
                ArchivePath::new(path).unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                *processing,
                None,
                Cursor::new(bytes),
            )
            .unwrap();
    }
    writer.finish().unwrap()
}

/// A plain base archive with one file. Its descriptor is easy to patch.
fn plain_archive(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::base()).unwrap();
    writer
        .add_file(
            ArchivePath::new(path).unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            None,
            Cursor::new(bytes),
        )
        .unwrap();
    writer.finish().unwrap()
}

fn set_version(bytes: &mut [u8], minor: u8) {
    assert_eq!(&bytes[..5], b"PITH\x01");
    bytes[5] = minor;
}

fn terminal_directory_start(bytes: &[u8]) -> usize {
    let footer = &bytes[bytes.len() - 12..];
    bytes.len() - u64::from_be_bytes(footer[..8].try_into().unwrap()) as usize
}

fn read_uleb(bytes: &[u8], position: &mut usize) -> u64 {
    let mut value = 0;
    for shift in (0..64).step_by(7) {
        let byte = bytes[*position];
        *position += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return value;
        }
    }
    panic!("unterminated ULEB128");
}

/// Replaces the flags of the descriptor for `hash` in the terminal directory and refreshes
/// the CRC. The descriptor follows the block-list copy of the hash, so it is the last one.
fn patch_flags(bytes: &mut [u8], hash: [u8; 32], flags: u8) {
    let start = terminal_directory_start(bytes);
    let directory = &bytes[start..];
    let found = directory
        .windows(32)
        .rposition(|window| window == hash)
        .unwrap();
    let mut position = start + found + 32;
    for _ in 0..3 {
        read_uleb(bytes, &mut position);
    }
    bytes[position] = flags;
    refresh_crc(bytes);
}

fn refresh_crc(bytes: &mut [u8]) {
    let start = terminal_directory_start(bytes);
    let crc_at = bytes.len() - 4;
    let crc = crc32fast::hash(&bytes[start..crc_at]);
    bytes[crc_at..].copy_from_slice(&crc.to_be_bytes());
}

fn piece(key_id: u64, recipients: &[&str], processing: ProcessingOptions, part: &[u8]) -> Part {
    let recipients = recipients.iter().map(|name| public_key(name)).collect();
    let encoder = PieceEncoder::new(key_id, recipients, processing).unwrap();
    encode_piece(encoder.with_block_size(1000).unwrap(), part)
}

/// Writes `part` in fragments that match neither blocks nor BLAKE3 chunks.
fn encode_piece(mut encoder: PieceEncoder, part: &[u8]) -> Part {
    let mut stored = Vec::new();
    for fragment in part.chunks(333) {
        stored.extend(encoder.write(fragment).unwrap());
    }
    stored.extend(encoder.flush().unwrap());
    Part {
        stored,
        piece: encoder.finish().unwrap(),
    }
}

struct Part {
    stored: Vec<u8>,
    piece: Piece,
}

/// Composes the parts from their stored records only, as a node without keys would.
fn assemble(parts: &[Part]) -> (Vec<u8>, Option<[u8; 32]>) {
    let pieces = parts
        .iter()
        .map(|part| Piece::from_bytes(&part.piece.to_bytes()).unwrap())
        .collect::<Vec<_>>();
    let composition = compose(
        ArchivePath::new("object").unwrap(),
        EntryMetadata::new(0, 0, 0o644),
        &pieces,
    )
    .unwrap();
    let mut archive = composition.header().to_vec();
    for part in parts {
        archive.extend_from_slice(&part.stored);
    }
    archive.extend_from_slice(composition.directory());
    assert_eq!(archive.len() as u64, composition.archive_len());
    (archive, composition.content_hash())
}

fn write_temporary(directory: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn one_archive_and_one_file_mix_both_ciphers() {
    let shared = content(1, BLOCK);
    let chacha_file = [shared.clone(), content(2, BLOCK)].concat();
    let aes_file = [shared.clone(), content(3, BLOCK)].concat();
    let bytes = write_archive(&[
        ("chacha", encrypted(0), &chacha_file),
        ("aes", aes(encrypted(0)), &aes_file),
    ]);
    // The AES-256-GCM file reuses the ChaCha20-Poly1305 descriptor of the shared block, so
    // the archive is one stored block smaller than with distinct content.
    let distinct = write_archive(&[
        ("chacha", encrypted(0), &chacha_file),
        (
            "aes",
            aes(encrypted(0)),
            &[content(4, BLOCK), content(3, BLOCK)].concat(),
        ),
    ]);
    assert!(distinct.len() >= bytes.len() + STORED_BLOCK);

    let archive = open(bytes.clone(), keys(&["recipient1"]));
    assert_eq!(read(&archive, "chacha"), chacha_file);
    assert_eq!(read(&archive, "aes"), aes_file);
    let mut range = Vec::new();
    archive
        .copy_range_to("aes", 1000..1100, &mut range)
        .unwrap();
    assert_eq!(range, aes_file[1000..1100]);

    // An AES-256-GCM append reuses the base block that is sealed with ChaCha20-Poly1305:
    // the appended segment holds only the new short block and the directory.
    let temporary = tempfile::tempdir().unwrap();
    let path = write_temporary(temporary.path(), "archive.pith", &bytes);
    let appended = [shared, content(5, 300)].concat();
    let source = write_temporary(temporary.path(), "appended", &appended);
    append_files(
        &path,
        AppendOptions::new(private_key("sender"), vec![public_key("recipient1")])
            .with_chunking(Chunking::Fixed(BLOCK))
            .with_processing(aes(encrypted(0))),
        &[source],
    )
    .unwrap();
    let grown = std::fs::read(&path).unwrap();
    assert!(grown.len() < bytes.len() + STORED_BLOCK + (4 + 12 + 300 + 16));
    let archive = open(grown, keys(&["recipient1"]));
    assert_eq!(read(&archive, "chacha"), chacha_file);
    assert_eq!(read(&archive, "aes"), aes_file);
    assert_eq!(read(&archive, "appended"), appended);
}

#[test]
fn unique_keys_with_aes_store_every_block_and_read_back() {
    let repeated = content(6, BLOCK);
    let file = [
        repeated.clone(),
        repeated.clone(),
        content(7, BLOCK),
        repeated,
        content(8, 100),
    ]
    .concat();
    let short_block = 4 + 12 + 100 + 16;
    let convergent = write_archive(&[("first", aes(encrypted(0)), &file)]);
    let processing = unique(aes(encrypted(0)));
    let one = write_archive(&[("first", processing, &file)]);
    let two = write_archive(&[("first", processing, &file), ("second", processing, &file)]);
    // No repeat is deduplicated, within a file or across files.
    assert!(one.len() >= convergent.len() + 2 * STORED_BLOCK);
    assert!(two.len() >= one.len() + 4 * STORED_BLOCK + short_block);

    let compressed = unique(aes(encrypted(3)));
    let three = write_archive(&[("first", compressed, &file), ("second", processing, &file)]);
    for bytes in [two, three] {
        let archive = open(bytes, keys(&["recipient1"]));
        for path in ["first", "second"] {
            assert_eq!(read(&archive, path), file);
            let mut range = Vec::new();
            archive.copy_range_to(path, 1000..3100, &mut range).unwrap();
            assert_eq!(range, file[1000..3100]);
        }
    }
}

#[test]
fn invalid_flag_combinations_are_rejected_in_both_versions() {
    let plaintext = content(9, 40);
    let hash = *blake3::hash(&plaintext).as_bytes();
    let patched = |minor: u8, flags: u8| {
        let mut bytes = plain_archive("data", &plaintext);
        set_version(&mut bytes, minor);
        patch_flags(&mut bytes, hash, flags);
        Archive::open(MemorySource::new(bytes), OpenOptions::default())
    };
    for minor in [0, 1] {
        // Bit 4 or 5 without encryption, and the reserved bits 6 and 7.
        for flags in [0x10, 0x20, 0x30, 0x13, 0x40, 0x80, 0xc8] {
            assert!(
                matches!(
                    patched(minor, flags),
                    Err(PithosError::ProcessingRequiresEncryption(_)
                        | PithosError::UnsupportedProcessingFlags(_)
                        | PithosError::Deserialization(
                            DeserializationError::InvalidProcessingFlags(_)
                        ))
                ),
                "version 1.{minor} accepted {flags:#04x}"
            );
        }
        for flags in [0x00, 0x03, 0x08] {
            assert!(patched(minor, flags).is_ok(), "{minor} {flags:#04x}");
        }
    }
    // Either bit with encryption is valid only in version 1.1.
    for flags in [0x18, 0x28, 0x38, 0x3b] {
        assert!(matches!(
            patched(0, flags),
            Err(PithosError::UnsupportedProcessingFlags(_))
        ));
        // The payload is plain, so decryption fails before any output.
        let archive = patched(1, flags).unwrap();
        let mut output = Vec::new();
        assert!(archive.copy_to("data", &mut output).is_err());
        assert!(output.is_empty());
    }

    // Block lists sealed in pieces are valid only in version 1.1.
    let (mut bytes, _) = assemble(&[piece(1, &["recipient1"], encrypted(0), b"piece")]);
    set_version(&mut bytes, 0);
    assert!(matches!(
        Archive::open(MemorySource::new(bytes), OpenOptions::default()),
        Err(PithosError::UnsupportedBlockListPieces)
    ));

    let plain = ProcessingOptions::new(false, 0).unwrap();
    assert!(matches!(
        plain.with_key_mode(BlockKeyMode::Unique),
        Err(PithosError::ProcessingRequiresEncryption(0x10))
    ));
    assert!(matches!(
        plain.with_cipher(PayloadCipher::Aes256Gcm),
        Err(PithosError::ProcessingRequiresEncryption(0x20))
    ));
}

#[test]
fn version_1_0_archives_keep_the_1_0_grant_rules() {
    let temporary = tempfile::tempdir().unwrap();
    let mut base = plain_archive("base.txt", b"base payload");
    set_version(&mut base, 0);
    let path = write_temporary(temporary.path(), "legacy.pith", &base);
    let source = write_temporary(temporary.path(), "appended.txt", b"appended payload");
    append_files(
        &path,
        AppendOptions::new(private_key("sender"), vec![public_key("recipient1")]),
        &[source],
    )
    .unwrap();
    grant_readers(
        &path,
        AppendOptions::new(private_key("recipient1"), vec![public_key("recipient2")]),
        &[1],
    )
    .unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    assert_eq!(&bytes[..6], b"PITH\x01\x00");
    for reader in ["recipient1", "recipient2"] {
        let archive = open(bytes.clone(), keys(&[reader]));
        assert_eq!(read(&archive, "base.txt"), b"base payload");
        assert_eq!(read(&archive, "appended.txt"), b"appended payload");
    }

    // Under the version 1.1 rules the same grants derive other keys and open nothing.
    set_version(&mut bytes, 1);
    for reader in ["recipient1", "recipient2"] {
        assert_no_access(&bytes, reader, "appended.txt");
    }

    // The reverse holds for a version 1.1 grant read under the version 1.0 rules.
    let mut current = write_archive(&[("data", encrypted(0), b"current payload")]);
    assert_eq!(&current[..6], b"PITH\x01\x01");
    assert_eq!(
        read(&open(current.clone(), keys(&["recipient1"])), "data"),
        b"current payload"
    );
    set_version(&mut current, 0);
    assert_no_access(&current, "recipient1", "data");
}

/// A grant that fails authentication for its recipient either fails the open or leaves the
/// content unavailable. Both outcomes release nothing.
fn assert_no_access(bytes: &[u8], reader: &str, path: &str) {
    match Archive::open(
        MemorySource::new(bytes.to_vec()),
        OpenOptions::default().with_access_keys(keys(&[reader])),
    ) {
        Ok(archive) => assert!(!available(&archive, path)),
        Err(error) => assert!(matches!(error, PithosError::Crypt(_)), "{error:?}"),
    }
}

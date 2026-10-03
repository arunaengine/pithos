mod common;

use common::util::{private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, AppendOptions, Archive, ArchivePath, BlockKeyMode, EntryKind, EntryMetadata,
    OpenOptions, Piece, PieceEncoder, ProcessingOptions, compose,
};
use pithos_lib::error::{DeserializationError, PithosError};
use pithos_lib::source::MemorySource;

const BLOCK: usize = 1000;

/// Encodes `content` as one piece in fixed blocks and returns its stored bytes and record.
fn encode(key_id: u64, content: &[u8]) -> (Vec<u8>, Piece) {
    encode_with(key_id, content, ProcessingOptions::new(true, 3).unwrap())
}

fn encode_with(key_id: u64, content: &[u8], processing: ProcessingOptions) -> (Vec<u8>, Piece) {
    let mut encoder =
        PieceEncoder::new(key_id, vec![public_key("recipient1")], processing).unwrap();
    let mut stored = Vec::new();
    for block in content.chunks(BLOCK) {
        stored.extend(encoder.push(block).unwrap());
    }
    (stored, encoder.finish().unwrap())
}

/// Composes the pieces from their stored records only, as a node without keys would.
fn assemble(parts: &[(Vec<u8>, Piece)]) -> Vec<u8> {
    let pieces = parts
        .iter()
        .map(|(_, piece)| Piece::from_bytes(&piece.to_bytes()).unwrap())
        .collect::<Vec<_>>();
    let composition = compose(
        ArchivePath::new("object").unwrap(),
        EntryMetadata::new(1, 2, 0o640),
        &pieces,
    )
    .unwrap();
    let mut archive = composition.header().to_vec();
    for ((stored, _), offset) in parts.iter().zip(composition.piece_offsets()) {
        assert_eq!(archive.len() as u64, *offset);
        archive.extend_from_slice(stored);
    }
    archive.extend_from_slice(composition.directory());
    assert_eq!(archive.len() as u64, composition.archive_len());
    archive
}

fn open(bytes: Vec<u8>, keys: AccessKeys) -> Archive<MemorySource> {
    Archive::open(
        MemorySource::new(bytes),
        OpenOptions::default().with_access_keys(keys),
    )
    .unwrap()
}

fn recipient() -> AccessKeys {
    AccessKeys::new().with_key(private_key("recipient1"))
}

fn content(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31) ^ seed)
        .collect()
}

#[test]
fn composed_pieces_read_back_as_one_file_with_ranges_across_pieces() {
    let first = content(1, 2500);
    let second = [content(2, 1000), content(1, 1000)].concat();
    let third = content(3, 10);
    let parts = vec![encode(1, &first), encode(4, &second), encode(9, &third)];
    let archive = open(assemble(&parts), recipient());
    let expected = [first, second, third].concat();

    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert_eq!(output, expected);

    let mut range = Vec::new();
    archive
        .copy_range_to("object", 2400..3600, &mut range)
        .unwrap();
    assert_eq!(range, expected[2400..3600]);
    let entry = archive.entry("object").unwrap().unwrap();
    assert_eq!(entry.permissions, 0o640);
    assert!(matches!(
        entry.kind,
        EntryKind::File {
            size: 4510,
            available: true
        }
    ));
}

#[test]
fn unique_key_pieces_store_every_block_and_compose_with_convergent_pieces() {
    let repeated = [content(8, BLOCK), content(8, BLOCK)].concat();
    let convergent = ProcessingOptions::new(true, 0).unwrap();
    let unique = convergent.with_key_mode(BlockKeyMode::Unique).unwrap();
    let parts = vec![
        encode_with(1, &repeated, unique),
        encode_with(2, &repeated, convergent),
        encode_with(3, &repeated, unique),
    ];
    // Each stored block is `BLCK`, a nonce, the plaintext and a tag. Unique keys store both
    // copies; convergent keys store the repeat once.
    let stored_block = (4 + 12 + BLOCK + 16) as u64;
    assert_eq!(parts[0].1.stored_len(), 2 * stored_block);
    assert_eq!(parts[1].1.stored_len(), stored_block);
    assert_eq!(parts[2].1.stored_len(), 2 * stored_block);
    let archive = open(assemble(&parts), recipient());
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert_eq!(output, repeated.repeat(3));
}

#[test]
fn the_composition_digest_guards_the_metadata_on_open() {
    let parts = vec![encode(1, &content(1, 1500))];
    let pieces = parts
        .iter()
        .map(|(_, piece)| piece.clone())
        .collect::<Vec<_>>();
    let digest = compose(
        ArchivePath::new("object").unwrap(),
        EntryMetadata::new(1, 2, 0o640),
        &pieces,
    )
    .unwrap()
    .metadata_digest();
    let bytes = assemble(&parts);
    let opened = Archive::open(
        MemorySource::new(bytes.clone()),
        OpenOptions::default()
            .with_access_keys(recipient())
            .with_expected_metadata_digest(digest),
    )
    .unwrap();
    assert_eq!(opened.metadata_digest(), digest);

    let mut wrong = digest;
    wrong[0] ^= 1;
    assert!(matches!(
        Archive::open(
            MemorySource::new(bytes),
            OpenOptions::default().with_expected_metadata_digest(wrong),
        ),
        Err(PithosError::MetadataDigestMismatch)
    ));
}

#[test]
fn a_reader_without_a_granted_key_sees_unavailable_content() {
    let parts = vec![encode(1, &content(1, 1500))];
    let bytes = assemble(&parts);
    for keys in [
        AccessKeys::new(),
        AccessKeys::new().with_key(private_key("recipient2")),
    ] {
        let archive = open(bytes.clone(), keys);
        assert!(matches!(
            archive.entry("object").unwrap().unwrap().kind,
            EntryKind::File {
                available: false,
                ..
            }
        ));
        assert!(archive.copy_to("object", &mut Vec::new()).is_err());
    }
}

#[test]
fn an_empty_composition_is_an_empty_file() {
    let archive = open(assemble(&[]), recipient());
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert!(output.is_empty());
}

#[test]
fn composition_requires_increasing_key_ids_and_a_root_path() {
    let (_, low) = encode(2, b"low");
    let (_, high) = encode(5, b"high");
    for pieces in [
        vec![high.clone(), low.clone()],
        vec![low.clone(), low.clone()],
    ] {
        assert!(matches!(
            compose(
                ArchivePath::new("object").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                &pieces,
            ),
            Err(PithosError::Deserialization(
                DeserializationError::UnorderedPieceKeys
            ))
        ));
    }
    assert!(matches!(
        compose(
            ArchivePath::new("nested/object").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            &[low],
        ),
        Err(PithosError::InvalidArchivePath { .. })
    ));
    assert!(matches!(
        PieceEncoder::new(
            0,
            vec![public_key("recipient1")],
            ProcessingOptions::default()
        ),
        Err(PithosError::PieceKeyIdConflict(0))
    ));
}

#[test]
fn piece_records_round_trip_and_reject_damage() {
    let (_, piece) = encode(3, &content(7, 2100));
    let bytes = piece.to_bytes();
    assert_eq!(Piece::from_bytes(&bytes).unwrap(), piece);
    assert_eq!(piece.key_id(), 3);
    assert_eq!(piece.original_size(), 2100);
    for damaged in [
        bytes[..bytes.len() - 1].to_vec(),
        [bytes.as_slice(), &[0]].concat(),
        [b"PITHPIEX".as_slice(), &bytes[8..]].concat(),
    ] {
        assert!(matches!(
            Piece::from_bytes(&damaged),
            Err(PithosError::InvalidPieceRecord)
        ));
    }
}

#[test]
fn a_reader_grant_for_a_composed_file_carries_every_piece_key() {
    let first = content(4, 1200);
    let second = content(5, 800);
    let parts = vec![encode(2, &first), encode(3, &second)];
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("composed.pith");
    std::fs::write(&path, assemble(&parts)).unwrap();

    pithos_lib::fs::grant_readers(
        &path,
        AppendOptions::new(private_key("recipient1"), vec![public_key("recipient2")]),
        &[0],
    )
    .unwrap();
    let archive = open(
        std::fs::read(&path).unwrap(),
        AccessKeys::new().with_key(private_key("recipient2")),
    );
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert_eq!(output, [first, second].concat());
}

#[cfg(feature = "crypt4gh")]
#[test]
fn a_composed_file_exports_to_crypt4gh_with_a_fresh_data_key() {
    let parts = vec![encode(1, &content(6, 900)), encode(2, &content(7, 600))];
    let archive = open(assemble(&parts), recipient());
    let mut exported = Vec::new();
    pithos_lib::adapters::crypt4gh::export(
        &archive,
        "object",
        vec![public_key("recipient2")],
        &mut exported,
    )
    .unwrap();
    assert!(exported.starts_with(b"crypt4gh"));
    // One recipient packet, then one segment: nonce, 1500 ciphertext bytes and a tag.
    let header_len = 16 + u32::from_le_bytes(exported[16..20].try_into().unwrap()) as usize;
    assert_eq!(exported.len(), header_len + 12 + 1500 + 16);
}

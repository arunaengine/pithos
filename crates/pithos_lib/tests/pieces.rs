mod common;

use common::util::{private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, EntryKind, EntryMetadata, OpenOptions, Piece, PieceEncoder,
    ProcessingOptions, compose,
};
use pithos_lib::error::{DeserializationError, PithosError};
use pithos_lib::source::MemorySource;

const BLOCK: usize = 1000;

/// Encodes `content` as one piece in fixed blocks and returns its stored bytes and record.
fn encode(key_id: u64, content: &[u8]) -> (Vec<u8>, Piece) {
    let mut encoder = PieceEncoder::new(
        key_id,
        vec![public_key("recipient1")],
        ProcessingOptions::new(true, 3).unwrap(),
    )
    .unwrap();
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

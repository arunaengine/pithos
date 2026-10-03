mod common;

use common::util::public_key;
use pithos_lib::archive::{Piece, PieceEncoder, ProcessingOptions};
use pithos_lib::error::PithosError;

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

fn content(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| (index as u8).wrapping_mul(31) ^ seed)
        .collect()
}

#[test]
fn piece_encoders_reject_the_composed_file_id() {
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

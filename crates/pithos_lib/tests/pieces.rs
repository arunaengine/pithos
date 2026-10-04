mod common;

use common::util::{private_key, public_key};
use pithos_lib::archive::{
    AccessKeys, AppendOptions, Archive, ArchivePath, ArchiveWriter, BlockKeyMode, BlockListForm,
    CdcConfig, Chunking, EntryKind, EntryMetadata, GrantReplacement, OpenOptions, PayloadCipher,
    Piece, PieceEncoder, ProcessingOptions, WriteOptions, compose,
};
use pithos_lib::error::{DeserializationError, PithosError};
use pithos_lib::source::{ArchiveSource, MemorySource, SourceError};

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
fn pieces_with_different_ciphers_and_key_modes_compose_into_one_file() {
    let shared = content(9, BLOCK);
    let chacha = ProcessingOptions::new(true, 0).unwrap();
    let aes = chacha.with_cipher(PayloadCipher::Aes256Gcm).unwrap();
    let unique_aes = aes.with_key_mode(BlockKeyMode::Unique).unwrap();
    let parts = vec![
        encode_with(1, &[shared.clone(), content(1, 500)].concat(), aes),
        encode_with(2, &[content(2, BLOCK), shared.clone()].concat(), chacha),
        encode_with(3, &[shared.clone(), shared.clone()].concat(), unique_aes),
    ];
    // The ChaCha20-Poly1305 piece reads its shared block from the AES-256-GCM piece.
    let archive = open(assemble(&parts), recipient());
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    let expected = [
        shared.clone(),
        content(1, 500),
        content(2, BLOCK),
        shared.clone(),
        shared.clone(),
        shared,
    ]
    .concat();
    assert_eq!(output, expected);
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

/// One 5 TiB file at 4 MiB blocks has 1,310,720 blocks. Tiny blocks give the same directory
/// shape, and the default open limits must admit it. A single piece holds the whole list, as
/// when one upload part covers the object. Offsets are smaller than real ones, so the real
/// directory is about 8 bytes per block larger.
#[test]
#[ignore = "slow in debug builds (about 5 minutes, 8 seconds with --release); run with --ignored"]
fn a_composition_with_the_block_count_of_5_tib_opens_with_default_limits() {
    const BLOCKS: u32 = 1_310_720;
    const PIECES: u32 = 1;
    let per_piece = BLOCKS / PIECES;
    let parts = (0..PIECES)
        .map(|piece| {
            let processing = ProcessingOptions::new(true, 0).unwrap();
            let mut encoder = PieceEncoder::new(
                u64::from(piece) + 1,
                vec![public_key("recipient1")],
                processing,
            )
            .unwrap();
            let mut stored = Vec::new();
            for block in piece * per_piece..(piece + 1) * per_piece {
                stored.extend(encoder.push(&block.to_be_bytes()).unwrap());
            }
            (stored, encoder.finish().unwrap())
        })
        .collect::<Vec<_>>();
    let archive = open(assemble(&parts), recipient());
    let entry = archive.entry("object").unwrap().unwrap();
    assert!(matches!(
        entry.kind,
        EntryKind::File {
            size,
            available: true
        } if size == u64::from(BLOCKS) * 4
    ));
    let mut tail = Vec::new();
    let end = u64::from(BLOCKS) * 4;
    archive
        .copy_range_to("object", end - 8..end, &mut tail)
        .unwrap();
    assert_eq!(
        tail,
        [(BLOCKS - 2).to_be_bytes(), (BLOCKS - 1).to_be_bytes()].concat()
    );
}

/// Encodes one part at `offset` in fragments that do not match blocks or BLAKE3 chunks, and
/// returns its record after a storage round trip.
fn hashed_piece(key_id: u64, offset: u64, part: &[u8], processing: ProcessingOptions) -> Piece {
    let mut encoder = PieceEncoder::new(key_id, vec![public_key("recipient1")], processing)
        .unwrap()
        .with_block_size(BLOCK)
        .unwrap()
        .with_content_offset(offset)
        .unwrap();
    for fragment in part.chunks(777) {
        encoder.write(fragment).unwrap();
    }
    encoder.flush().unwrap();
    Piece::from_bytes(&encoder.finish().unwrap().to_bytes()).unwrap()
}

/// Encodes consecutive parts of `file` with the given sizes at their running offsets.
fn hashed_parts(file: &[u8], sizes: &[usize]) -> Vec<Piece> {
    let mut offset = 0;
    let processing = ProcessingOptions::new(true, 3).unwrap();
    let mut pieces = Vec::new();
    for (index, size) in sizes.iter().enumerate() {
        let part = &file[offset..offset + size];
        pieces.push(hashed_piece(
            index as u64 + 1,
            offset as u64,
            part,
            processing,
        ));
        offset += size;
    }
    assert_eq!(offset, file.len());
    pieces
}

fn content_hash(pieces: &[Piece]) -> Option<[u8; 32]> {
    let path = ArchivePath::new("object").unwrap();
    compose(path, EntryMetadata::new(0, 0, 0o644), pieces)
        .unwrap()
        .content_hash()
}

#[test]
fn content_hash_of_aligned_parts_is_the_blake3_of_the_file() {
    let file = content(5, 700_000);
    let part = 200 * 1024;
    let equal = [part, part, part, 700_000 - 3 * part];
    let varied = [3072, 1024, 70 * 1024, 0, 5120, 128 * 1024, 488_032];
    for sizes in [&equal[..], &varied[..]] {
        let pieces = hashed_parts(&file, sizes);
        assert_eq!(content_hash(&pieces), Some(*blake3::hash(&file).as_bytes()));
    }
}

#[test]
fn content_defined_pieces_compose_with_the_file_content_hash() {
    let file = content(7, 300_000);
    let chunking = Chunking::ContentDefined(CdcConfig::new(1024, 4096, 16_384).unwrap());
    let processing = ProcessingOptions::new(true, 3).unwrap();
    let mut parts = Vec::new();
    for (key_id, range) in [(1, 0..102_400), (2, 102_400..file.len())] {
        let mut encoder = PieceEncoder::new(key_id, vec![public_key("recipient1")], processing)
            .unwrap()
            .with_chunking(chunking)
            .unwrap()
            .with_content_offset(range.start as u64)
            .unwrap();
        let mut stored = Vec::new();
        for fragment in file[range].chunks(5000) {
            stored.extend(encoder.write(fragment).unwrap());
        }
        stored.extend(encoder.flush().unwrap());
        parts.push((stored, encoder.finish().unwrap()));
    }
    let pieces = parts.iter().map(|(_, piece)| piece.clone());
    let expected = *blake3::hash(&file).as_bytes();
    assert_eq!(content_hash(&pieces.collect::<Vec<_>>()), Some(expected));

    let archive = open(assemble(&parts), recipient());
    let mut output = Vec::new();
    archive.copy_to("object", &mut output).unwrap();
    assert_eq!(output, file);
}

#[test]
fn content_hash_of_one_piece_and_of_an_empty_file() {
    let file = content(6, 131_079);
    for len in [0, 1, 500, 1024, 1025, 65_536, 131_079] {
        let pieces = hashed_parts(&file[..len], &[len]);
        let expected = *blake3::hash(&file[..len]).as_bytes();
        assert_eq!(content_hash(&pieces), Some(expected), "{len}");
    }
    assert_eq!(content_hash(&[]), Some(*blake3::hash(b"").as_bytes()));
}

#[test]
fn content_hash_is_unknown_for_wrong_offsets_or_missing_values() {
    let file = content(7, 5000);
    let processing = ProcessingOptions::new(true, 0).unwrap();
    let first = hashed_piece(1, 0, &file[..1024], processing);
    let wrong = hashed_piece(2, 2048, &file[1024..], processing);
    assert_eq!(content_hash(&[first.clone(), wrong]), None);
    let second = hashed_piece(2, 1024, &file[1024..], processing);
    assert_eq!(content_hash(std::slice::from_ref(&second)), None);
    assert!(content_hash(&[first.clone(), second]).is_some());

    let encoder = PieceEncoder::new(2, vec![public_key("recipient1")], processing).unwrap();
    let mut encoder = encoder.with_content_hash(false).unwrap();
    encoder.push(&file[1024..]).unwrap();
    assert_eq!(content_hash(&[first, encoder.finish().unwrap()]), None);

    let encoder = || PieceEncoder::new(1, vec![public_key("recipient1")], processing).unwrap();
    assert!(matches!(
        encoder().with_content_offset(1000),
        Err(PithosError::InvalidContentOffset(1000))
    ));
    let mut started = encoder();
    started.write(b"content").unwrap();
    assert!(matches!(
        started.with_content_offset(0),
        Err(PithosError::PieceContentStarted)
    ));
}

#[test]
fn unique_key_pieces_record_no_content_hash_unless_asked() {
    let file = content(8, 3000);
    let unique = ProcessingOptions::new(true, 0)
        .unwrap()
        .with_key_mode(BlockKeyMode::Unique)
        .unwrap();
    assert_eq!(content_hash(&[hashed_piece(1, 0, &file, unique)]), None);
    let mut encoder = PieceEncoder::new(1, vec![public_key("recipient1")], unique)
        .unwrap()
        .with_content_hash(true)
        .unwrap();
    encoder.push(&file).unwrap();
    let piece = Piece::from_bytes(&encoder.finish().unwrap().to_bytes()).unwrap();
    assert_eq!(
        content_hash(&[piece]),
        Some(*blake3::hash(&file).as_bytes())
    );
}

#[test]
fn entries_report_how_their_block_list_is_stored() {
    let composed = open(assemble(&[encode(1, b"pieces")]), recipient());
    assert_eq!(
        composed.entry("object").unwrap().unwrap().block_list,
        Some(BlockListForm::Pieces)
    );

    for (options, form) in [
        (WriteOptions::base(), BlockListForm::Plain),
        (
            WriteOptions::new(private_key("recipient1"), vec![public_key("recipient1")]),
            BlockListForm::Sealed,
        ),
    ] {
        let plain = form == BlockListForm::Plain;
        let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
        writer
            .add_directory(
                ArchivePath::new("folder").unwrap(),
                EntryMetadata::new(0, 0, 0o755),
            )
            .unwrap();
        writer
            .add_file(
                ArchivePath::new("folder/data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(!plain, 0).unwrap(),
                None,
                std::io::Cursor::new(b"content"),
            )
            .unwrap();
        let archive = open(writer.finish().unwrap(), recipient());
        assert_eq!(
            archive.entry("folder/data").unwrap().unwrap().block_list,
            Some(form)
        );
        assert_eq!(archive.entry("folder").unwrap().unwrap().block_list, None);
    }
}

/// Plans grants for recipient2 only, from an archive opened with recipient1's key.
fn replace_grants(bytes: &[u8]) -> Result<GrantReplacement, PithosError> {
    let archive = open(bytes.to_vec(), recipient());
    let directory = &bytes[archive.view().directory_range().start as usize..];
    archive
        .view()
        .replace_grants(directory, vec![public_key("recipient2")])
}

/// Replaces the grants of `bytes` and checks the new archive and both readers.
fn check_replaced_grants(bytes: Vec<u8>, path: &str, expected: &[u8]) {
    let plan = replace_grants(&bytes).unwrap();
    let range = plan.copy_range();
    let mut replaced = plan.header().to_vec();
    replaced.extend_from_slice(&bytes[range.start as usize..range.end as usize]);
    replaced.extend_from_slice(plan.directory());
    assert_eq!(replaced.len() as u64, plan.archive_len());
    // The header and every stored block keep their bytes and offsets.
    let old = open(bytes.clone(), recipient());
    assert_eq!(range.end, old.view().directory_range().start);
    assert_eq!(replaced[..range.end as usize], bytes[..range.end as usize]);
    assert_ne!(plan.metadata_digest(), old.metadata_digest());

    let reader = AccessKeys::new().with_key(private_key("recipient2"));
    let options = OpenOptions::default().with_access_keys(reader);
    let source = MemorySource::new(replaced.clone());
    let archive = Archive::open(
        source,
        options.with_expected_metadata_digest(plan.metadata_digest()),
    )
    .unwrap();
    let mut output = Vec::new();
    archive.copy_to(path, &mut output).unwrap();
    assert_eq!(output, expected);
    let stale = OpenOptions::default().with_expected_metadata_digest(old.metadata_digest());
    assert!(matches!(
        Archive::open(MemorySource::new(replaced.clone()), stale),
        Err(PithosError::MetadataDigestMismatch)
    ));
    let former = open(replaced, recipient());
    assert!(matches!(
        former.copy_to(path, &mut Vec::new()),
        Err(PithosError::ContentUnavailable)
    ));
}

#[test]
fn replaced_grants_move_piece_keys_to_a_new_reader() {
    let first = content(6, 2500);
    let second = content(7, 900);
    let parts = vec![encode(2, &first), encode(5, &second)];
    check_replaced_grants(assemble(&parts), "object", &[first, second].concat());
}

#[test]
fn replaced_grants_move_a_file_key_to_a_new_reader() {
    let options = WriteOptions::new(private_key("sender"), vec![public_key("recipient1")]);
    let options = options.with_chunking(Chunking::Fixed(BLOCK));
    let mut writer = ArchiveWriter::create(Vec::new(), options).unwrap();
    let data = content(8, 3000);
    writer
        .add_file(
            ArchivePath::new("data").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(true, 3).unwrap(),
            None,
            std::io::Cursor::new(&data),
        )
        .unwrap();
    check_replaced_grants(writer.finish().unwrap(), "data", &data);
}

#[test]
fn grant_replacement_rejects_unsupported_archives_and_missing_keys() {
    let bytes = assemble(&[encode(1, &content(9, 1500))]);
    let without_keys = open(bytes.clone(), AccessKeys::new());
    let directory = &bytes[without_keys.view().directory_range().start as usize..];
    assert!(matches!(
        without_keys
            .view()
            .replace_grants(directory, vec![public_key("recipient2")]),
        Err(PithosError::ContentUnavailable)
    ));
    let archive = open(bytes.clone(), recipient());
    assert!(matches!(
        archive
            .view()
            .replace_grants(&bytes, vec![public_key("recipient2")]),
        Err(PithosError::MetadataDigestMismatch)
    ));

    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("appended.pith");
    std::fs::write(&path, &bytes).unwrap();
    pithos_lib::fs::grant_readers(
        &path,
        AppendOptions::new(private_key("recipient1"), vec![public_key("recipient2")]),
        &[0],
    )
    .unwrap();
    let older = std::fs::read("tests/data/pithos-0.7.0.pith").unwrap();
    for bytes in [std::fs::read(&path).unwrap(), older] {
        assert!(matches!(
            replace_grants(&bytes),
            Err(PithosError::GrantReplacementUnsupported)
        ));
    }
}

/// Serves an archive with its directory moved to the end of a `u64::MAX` byte object.
struct AtEnd {
    bytes: Vec<u8>,
    directory: usize,
}

impl ArchiveSource for AtEnd {
    fn len(&self) -> Result<u64, SourceError> {
        Ok(u64::MAX)
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
        let tail_start = u64::MAX - (self.bytes.len() - self.directory) as u64;
        let start = match offset.checked_sub(tail_start) {
            Some(position) => self.directory + position as usize,
            None => offset as usize,
        };
        buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
        Ok(())
    }
}

#[test]
fn grant_replacement_rejects_an_archive_length_overflow() {
    let bytes = assemble(&[encode(1, &content(9, 1500))]);
    let directory = open(bytes.clone(), recipient())
        .view()
        .directory_range()
        .start as usize;
    let source = AtEnd {
        bytes: bytes.clone(),
        directory,
    };
    let options = OpenOptions::default().with_access_keys(recipient());
    let archive = Archive::open(source, options).unwrap();
    // Two recipients make the new directory larger than the old one.
    let recipients = vec![public_key("recipient2"), public_key("sender")];
    assert!(matches!(
        archive
            .view()
            .replace_grants(&bytes[directory..], recipients),
        Err(PithosError::InvalidDirectoryRange { .. })
    ));
}

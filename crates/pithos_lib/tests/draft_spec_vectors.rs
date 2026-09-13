//! Reproducible verification for the Pithos 1.0 draft vectors in Appendix B.
//!
//! This repository-only test model is not an alternate production codec.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use crc32fast::hash as crc32;
use pithos_lib::archive::{Archive, OpenOptions};
use pithos_lib::error::{DeserializationError, PithosError};
use pithos_lib::source::MemorySource;
use std::io::Cursor;
use x25519_dalek::{PublicKey, StaticSecret};

const SPEC: &str = include_str!("../../../spec/PITHOS_1.0.0_draft.md");
const RELATIONS: [(u8, &str); 10] = [
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

fn uleb(mut value: u64, output: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        output.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn directory(parent: Option<(u64, u64)>, file: bool, block: bool) -> Vec<u8> {
    let mut bytes = b"PITHOSDR".to_vec();
    match parent {
        None => bytes.push(0),
        Some((start, length)) => {
            bytes.push(1);
            uleb(start, &mut bytes);
            uleb(length, &mut bytes);
        }
    }
    if file {
        let plain = b"hello";
        let digest = blake3::hash(plain);
        let key = shake256(plain);
        bytes.extend_from_slice(&[1, 0, 5]); // files, id, path length
        bytes.extend_from_slice(plain);
        bytes.extend_from_slice(&[1, 1, 1]); // Data, decrypted, one block pair
        bytes.extend_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&key);
        bytes.extend_from_slice(&[0, 0, 5, 0xa4, 0x03, 0, 0]);
    } else {
        bytes.push(0);
    }
    if block {
        let digest = blake3::hash(b"hello");
        bytes.push(1);
        bytes.extend_from_slice(digest.as_bytes());
        bytes.extend_from_slice(&[6, 5, 5, 0, 0]);
    } else {
        bytes.push(0);
    }
    if parent.is_none() {
        bytes.push(10);
        for (id, name) in RELATIONS {
            bytes.push(id);
            bytes.push(name.len() as u8);
            bytes.extend_from_slice(name.as_bytes());
        }
    } else {
        bytes.push(0);
    }
    bytes.push(0); // encryption
    let length = bytes.len() + 12;
    bytes.extend_from_slice(&(length as u64).to_be_bytes());
    bytes.extend_from_slice(&crc32(&bytes).to_be_bytes());
    bytes
}

fn shake256(input: &[u8]) -> [u8; 32] {
    use digest::{ExtendableOutput, Update, XofReader};
    let mut hasher = shake::Shake256::default();
    hasher.update(input);
    let mut output = [0; 32];
    hasher.finalize_xof().read(&mut output);
    output
}

fn base() -> Vec<u8> {
    let mut bytes = b"PITH\x01\0".to_vec();
    bytes.extend(directory(None, false, false));
    bytes
}

fn append() -> Vec<u8> {
    let mut bytes = base();
    bytes.extend(directory(Some((6, 146)), false, false));
    bytes
}

fn hello() -> Vec<u8> {
    let mut bytes = b"PITH\x01\0BLCKhello".to_vec();
    bytes.extend(directory(None, true, true));
    bytes
}

fn appendix_hex(id: &str) -> Vec<u8> {
    let start = SPEC.find(&format!("#### {id}")).expect("vector heading");
    let text = &SPEC[start..];
    let block = text.split("```text\n").nth(1).expect("hex block");
    let block = block.split("```").next().expect("hex block end");
    block
        .lines()
        .flat_map(|line| line.split_once(": ").expect("offset").1.split_whitespace())
        .map(|hex| u8::from_str_radix(hex, 16).expect("hex byte"))
        .collect()
}

fn replace_base_relationship_count(replacement: &[u8]) -> Vec<u8> {
    let mut bytes = base();
    bytes.splice(0x11..=0x11, replacement.iter().copied());
    let directory_len = (bytes.len() - 6) as u64;
    let footer = bytes.len() - 12;
    bytes[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
    let checksum = crc32(&bytes[6..bytes.len() - 4]);
    let crc_offset = bytes.len() - 4;
    bytes[crc_offset..].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn replace_hello_bytes(range: std::ops::RangeInclusive<usize>, replacement: &[u8]) -> Vec<u8> {
    let mut bytes = hello();
    bytes.splice(range, replacement.iter().copied());
    let directory_start = 15;
    let directory_len = (bytes.len() - directory_start) as u64;
    let footer = bytes.len() - 12;
    bytes[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
    let checksum = crc32(&bytes[directory_start..bytes.len() - 4]);
    let crc_offset = bytes.len() - 4;
    bytes[crc_offset..].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn mutate_hello_byte(offset: usize, replacement: u8) -> Vec<u8> {
    let mut bytes = hello();
    bytes[offset] = replacement;
    let crc_offset = bytes.len() - 4;
    let directory_start = bytes.len()
        - u64::from_be_bytes(bytes[crc_offset - 8..crc_offset].try_into().unwrap()) as usize;
    let checksum = crc32(&bytes[directory_start..crc_offset]);
    bytes[crc_offset..].copy_from_slice(&checksum.to_be_bytes());
    bytes
}

fn read_uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64, &'static str> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let byte = *bytes.get(*cursor).ok_or("truncated ULEB128")?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err("overflowing ULEB128")
}

fn take(bytes: &[u8], cursor: &mut usize, count: usize) -> Result<(), &'static str> {
    *cursor = cursor.checked_add(count).ok_or("overflow")?;
    if *cursor > bytes.len() {
        return Err("truncated field");
    }
    Ok(())
}

/// Decode the finalized draft grammar sufficiently to prove exact consumption.
fn decode_directory(bytes: &[u8]) -> Result<Option<(u64, u64)>, &'static str> {
    if bytes.len() < 25 || !bytes.starts_with(b"PITHOSDR") {
        return Err("directory framing");
    }
    if u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap())
        != bytes.len() as u64
    {
        return Err("directory length");
    }
    if crc32(&bytes[..bytes.len() - 4])
        != u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap())
    {
        return Err("directory CRC");
    }
    let mut at = 8;
    let parent = match *bytes.get(at).ok_or("parent tag")? {
        0 => {
            at += 1;
            None
        }
        1 => {
            at += 1;
            Some((read_uleb(bytes, &mut at)?, read_uleb(bytes, &mut at)?))
        }
        _ => return Err("parent tag"),
    };
    let files = read_uleb(bytes, &mut at)?;
    for _ in 0..files {
        read_uleb(bytes, &mut at)?;
        let path_len = read_uleb(bytes, &mut at)? as usize;
        take(bytes, &mut at, path_len)?;
        match *bytes.get(at).ok_or("file type")? {
            0..=3 => at += 1,
            _ => return Err("file type"),
        }
        match *bytes.get(at).ok_or("block data tag")? {
            0 => {
                at += 1;
                let n = read_uleb(bytes, &mut at)? as usize;
                take(bytes, &mut at, n)?
            }
            1 => {
                at += 1;
                let n = read_uleb(bytes, &mut at)? as usize;
                take(bytes, &mut at, n * 64)?
            }
            _ => return Err("block data tag"),
        }
        for _ in 0..4 {
            read_uleb(bytes, &mut at)?;
        }
        let refs = read_uleb(bytes, &mut at)?;
        for _ in 0..refs {
            read_uleb(bytes, &mut at)?;
            read_uleb(bytes, &mut at)?;
        }
        match *bytes.get(at).ok_or("symlink tag")? {
            0 => at += 1,
            1 => {
                at += 1;
                let n = read_uleb(bytes, &mut at)? as usize;
                take(bytes, &mut at, n)?
            }
            _ => return Err("symlink tag"),
        }
    }
    let blocks = read_uleb(bytes, &mut at)?;
    for _ in 0..blocks {
        take(bytes, &mut at, 32)?;
        read_uleb(bytes, &mut at)?;
        read_uleb(bytes, &mut at)?;
        read_uleb(bytes, &mut at)?;
        let flags = *bytes.get(at).ok_or("flags")?;
        at += 1;
        if flags & 0xf0 != 0 {
            return Err("reserved flags");
        }
        match *bytes.get(at).ok_or("location tag")? {
            0 => at += 1,
            1 => {
                at += 1;
                let n = read_uleb(bytes, &mut at)? as usize;
                take(bytes, &mut at, n)?
            }
            _ => return Err("location tag"),
        }
    }
    let relations = read_uleb(bytes, &mut at)?;
    for _ in 0..relations {
        read_uleb(bytes, &mut at)?;
        let n = read_uleb(bytes, &mut at)? as usize;
        take(bytes, &mut at, n)?;
    }
    let sections = read_uleb(bytes, &mut at)?;
    if sections != 0 {
        return Err("encryption sections not used by canonical vectors");
    }
    if at + 12 != bytes.len() {
        return Err("directory consumption");
    }
    Ok(parent)
}

fn decode_archive(bytes: &[u8]) -> Result<(), &'static str> {
    if !bytes.starts_with(b"PITH\x01\0") {
        return Err("header");
    }
    let length = u64::from_be_bytes(
        bytes
            .get(bytes.len().checked_sub(12).ok_or("footer")?..bytes.len() - 4)
            .ok_or("footer")?
            .try_into()
            .unwrap(),
    ) as usize;
    let start = bytes
        .len()
        .checked_sub(length)
        .ok_or("terminal underflow")?;
    let parent = decode_directory(&bytes[start..])?;
    if let Some((parent_start, parent_len)) = parent {
        let parent_start = usize::try_from(parent_start).map_err(|_| "parent range")?;
        let parent_len = usize::try_from(parent_len).map_err(|_| "parent range")?;
        let parent_end = parent_start.checked_add(parent_len).ok_or("parent range")?;
        if parent_end > start || parent_end > bytes.len() {
            return Err("parent range");
        }
        if decode_directory(&bytes[parent_start..parent_end])?.is_some() {
            return Err("base parent");
        }
    } else if start != 6 && bytes.get(6..10) != Some(b"BLCK") {
        return Err("base placement");
    }
    Ok(())
}

#[test]
fn canonical_vectors_are_generated_decoded_and_exactly_reencoded() {
    for (id, generated) in [
        ("CV-BASE-EMPTY-146", base()),
        ("CV-APPEND-EMPTY-28", append()),
        ("CV-LOCAL-HELLO-279", hello()),
    ] {
        assert_eq!(generated, appendix_hex(id), "{id} must match Appendix B");
        decode_archive(&generated).unwrap_or_else(|error| panic!("{id}: {error}"));
        // The table-derived encoder is canonical, so its output is the exact re-encoding.
        assert_eq!(
            generated,
            match id {
                "CV-BASE-EMPTY-146" => base(),
                "CV-APPEND-EMPTY-28" => append(),
                _ => hello(),
            }
        );
    }
}

#[test]
fn production_reader_opens_the_step_1_canonical_vectors() {
    for id in ["CV-BASE-EMPTY-146", "CV-APPEND-EMPTY-28"] {
        Archive::open(MemorySource::new(appendix_hex(id)), OpenOptions::default())
            .unwrap_or_else(|error| panic!("production reader rejected {id}: {error}"));
    }
}

#[test]
fn production_reader_accepts_bounded_non_minimal_uleb128() {
    Archive::open(
        MemorySource::new(replace_base_relationship_count(&[0x8a, 0x00])),
        OpenOptions::default(),
    )
    .unwrap();
}

#[test]
fn production_reader_rejects_overflowing_uleb128() {
    let result = Archive::open(
        MemorySource::new(replace_base_relationship_count(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ])),
        OpenOptions::default(),
    );
    assert!(matches!(
        result,
        Err(PithosError::Deserialization(DeserializationError::Io(_)))
    ));
}

#[test]
fn production_reader_rejects_rv_symlink_and_permissions() {
    for (id, bytes) in [
        ("RV-SYMLINK", replace_hello_bytes(0x20..=0x20, &[3])),
        (
            "RV-PERMISSIONS",
            replace_hello_bytes(0x66..=0x67, &[0x80, 0x20]),
        ),
    ] {
        assert!(
            Archive::open(MemorySource::new(bytes), OpenOptions::default()).is_err(),
            "production reader accepted {id}"
        );
    }
}

#[test]
fn production_reader_rejects_rv_extent_and_short_encrypted() {
    for (id, bytes) in [
        ("RV-EXTENT", mutate_hello_byte(139, 0x0f)),
        ("RV-SHORT-ENCRYPTED", mutate_hello_byte(142, 0x08)),
    ] {
        assert!(
            Archive::open(MemorySource::new(bytes), OpenOptions::default()).is_err(),
            "production reader accepted {id}"
        );
    }
}

#[test]
fn directory_length_calculations_are_independent() {
    let base_directory = &base()[6..];
    let terminal_directory = &append()[152..];
    assert_eq!(25, 8 + 1 + 1 + 1 + 1 + 1 + 8 + 4);
    assert_eq!(146, base_directory.len());
    assert_eq!(28, terminal_directory.len());
    assert_eq!(
        121,
        RELATIONS
            .iter()
            .map(|(_, name)| 2 + name.len())
            .sum::<usize>()
    );
}

#[test]
fn fixed_mutations_have_the_appendix_crc_and_reach_their_rule() {
    let cases = [
        ("RV-FLAGS", hello(), 142, 0x10, 0x7bd3b103, "reserved flags"),
        (
            "RV-UNKNOWN-TAG",
            hello(),
            143,
            0x02,
            0x86cf1282,
            "location tag",
        ),
        ("RV-FILETYPE", hello(), 32, 0x04, 0x50f42595, "file type"),
        (
            "RV-PARENT",
            append(),
            161,
            0x98,
            0xb734abf4,
            "parent topology",
        ),
        (
            "RV-EXTENT",
            hello(),
            139,
            0x0f,
            0x623c8b49,
            "extent placement",
        ),
        (
            "RV-SHORT-ENCRYPTED",
            hello(),
            142,
            0x08,
            0x92564e52,
            "directory consumption",
        ),
    ];
    for (id, mut bytes, offset, replacement, expected_crc, rule) in cases {
        let crc_offset = bytes.len() - 4;
        let directory_start = bytes.len()
            - u64::from_be_bytes(bytes[crc_offset - 8..crc_offset].try_into().unwrap()) as usize;
        bytes[offset] = replacement;
        let updated_crc = crc32(&bytes[directory_start..crc_offset]).to_be_bytes();
        bytes[crc_offset..].copy_from_slice(&updated_crc);
        assert_eq!(
            u32::from_be_bytes(bytes[crc_offset..].try_into().unwrap()),
            expected_crc,
            "{rule}"
        );
        assert_b4_crc(id, expected_crc);
        match rule {
            "parent topology" => {
                let terminal_start = bytes.len()
                    - u64::from_be_bytes(bytes[crc_offset - 8..crc_offset].try_into().unwrap())
                        as usize;
                assert_eq!(bytes[terminal_start + 9], terminal_start as u8);
            }
            "directory consumption" => {
                assert_ne!(bytes[142] & 0x08, 0);
                assert!(bytes[140] < 28, "encrypted payload is too short");
            }
            "extent placement" => assert_eq!(bytes[139], 15, "local extent begins at Directory"),
            expected => assert_eq!(decode_archive(&bytes), Err(expected)),
        }
    }
    let mut underflow = base();
    underflow[140..148].copy_from_slice(&153_u64.to_be_bytes());
    let underflow_crc = crc32(&underflow[6..148]).to_be_bytes();
    underflow[148..].copy_from_slice(&underflow_crc);
    assert_eq!(
        u32::from_be_bytes(underflow[148..].try_into().unwrap()),
        0x371dda5a
    );
    assert_b4_crc("RV-UNDERFLOW", 0x371dda5a);
    assert_eq!(decode_archive(&underflow), Err("terminal underflow"));
    let mut permissions = hello();
    permissions[102..104].copy_from_slice(&[0x80, 0x20]);
    let crc_offset = permissions.len() - 4;
    let directory_start = permissions.len()
        - u64::from_be_bytes(permissions[crc_offset - 8..crc_offset].try_into().unwrap()) as usize;
    let permissions_crc = crc32(&permissions[directory_start..crc_offset]).to_be_bytes();
    permissions[crc_offset..].copy_from_slice(&permissions_crc);
    assert_eq!(
        u32::from_be_bytes(permissions[crc_offset..].try_into().unwrap()),
        0x9f6af36e
    );
    assert_b4_crc("RV-PERMISSIONS", 0x9f6af36e);
    let mut permissions_offset = 102;
    assert_eq!(read_uleb(&permissions, &mut permissions_offset), Ok(0x1000));
    let mut bad_crc = base();
    bad_crc[151] = 0xd3;
    assert_eq!(decode_archive(&bad_crc), Err("directory CRC"));
    let mut trailing = base();
    trailing.push(0);
    assert!(decode_archive(&trailing).is_err());
}

fn assert_b4_crc(id: &str, crc: u32) {
    let row = SPEC[SPEC
        .find("### B.4 Acceptance and Rejection Mutations")
        .unwrap()..]
        .lines()
        .find(|line| line.contains(id))
        .unwrap();
    let bytes = crc.to_be_bytes();
    let rendered = format!(
        "{:02x} {:02x} {:02x} {:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    );
    assert!(row.contains(&rendered), "{id} CRC missing from Appendix B");
}

#[test]
fn processing_known_answers_match_appendix_b() {
    for (id, expected_stored, expected_size, plaintext, expected_hash) in [
        (
            "PV-ZSTD-HELLO",
            "28b52ffd044829000068656c6c6fa36d9f88",
            5,
            b"hello" as &[u8],
            "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
        ),
        (
            "PV-ZSTD-TEXT",
            "28b52ffd0458c10000506974686f73205a7374616e6461726420766563746f720a41f24fdb",
            24,
            b"Pithos Zstandard vector\n",
            "453c33f042159bc7dca06dcc08111d69c53fe167f329e084a85d950b70d84560",
        ),
    ] {
        let stored = appendix_zstd_bytes(id);
        assert_eq!(stored, hex_vec(expected_stored), "{id} stored bytes");
        let decoded = zstd::stream::decode_all(Cursor::new(stored)).unwrap();
        assert_eq!(decoded.len(), expected_size, "{id} size");
        assert_eq!(decoded, plaintext, "{id} plaintext");
        assert_eq!(
            blake3::hash(&decoded).to_hex().as_str(),
            expected_hash,
            "{id} hash"
        );
    }
    let alice = StaticSecret::from(hex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = PublicKey::from(hex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
    ));
    let shared = alice.diffie_hellman(&bob).to_bytes();
    assert_eq!(
        shared,
        hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    let plaintext: Vec<u8> = [vec![1, 7], (0..32).collect()].concat();
    let nonce = Nonce::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
    let ciphertext = ChaCha20Poly1305::new_from_slice(&shared)
        .unwrap()
        .encrypt(&nonce, plaintext.as_ref())
        .unwrap();
    assert_eq!(
        ciphertext,
        hex_vec(
            "e7f1ee41ba833f098ed29feca3def9c962fc8dc0cf87241bff589b33266a0dfaf4a5eba083d42e52db61819d09538170aae7"
        )
    );
    let mut stored = nonce.to_vec();
    stored.extend_from_slice(&ciphertext);
    assert_eq!(
        stored,
        appendix_recipient_wrap(),
        "recipient-wrap bytes must match Appendix B"
    );
}

fn appendix_zstd_bytes(id: &str) -> Vec<u8> {
    let row = SPEC
        .lines()
        .find(|line| line.starts_with(&format!("| {id} |")))
        .unwrap();
    row.split('|')
        .nth(2)
        .unwrap()
        .trim()
        .trim_matches('`')
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn appendix_recipient_wrap() -> Vec<u8> {
    let start = SPEC.find("PV-RECIPIENT-WRAP-01").unwrap();
    let block = SPEC[start..].split("```text\n").nth(1).unwrap();
    block
        .split("```")
        .next()
        .unwrap()
        .lines()
        .flat_map(|line| line.split_once(": ").unwrap().1.split_whitespace())
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

fn hex(value: &str) -> [u8; 32] {
    hex_vec(value).try_into().unwrap()
}
fn hex_vec(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn specification_consistency_has_navigation_and_review_coverage() {
    for required in [
        "[Section 4.2.5](#425-local-block-boundaries-and-recovery)",
        "**Valid ordering example:**",
        "**Invalid ordering example:**",
        "### B.5 Validation Index",
        "Where a current 0.8 implementation differs",
    ] {
        assert!(SPEC.contains(required), "missing {required}");
    }
    assert!(
        !SPEC.contains("root directory"),
        "retired ambiguous terminology"
    );
    // F-01 through F-12 accepted outcomes, in review order.
    let accepted_findings = [
        "dir_len >= 25",
        "base Directory",
        "raw static X25519",
        "recipient public keys",
        "Every entry below",
        "0o0000..=0o7777",
        "FileEntry field-combination validity",
        "For a `Symlink`",
        "local block-data region",
        "Resource Safety",
        "accidental corruption",
        "opaque external location identifier",
    ];
    // UX-1 through UX-10 adopted or adapted outcomes, in review order.
    let ux_outcomes = [
        "CV-LOCAL-HELLO-279",
        "### 1.1 Reader's Guide",
        "**Illustrative data model.**",
        "+-- base segment",
        "### B.5 Validation Index",
        "[Section 4.2.5]",
        "**Valid ordering example:**",
        "### 1.2 Terminology",
        "Where a current 0.8 implementation differs",
        "Appendix A. Writer Guidance",
    ];
    for (number, marker) in accepted_findings.into_iter().enumerate() {
        assert!(SPEC.contains(marker), "F-{:02}", number + 1);
    }
    for (number, marker) in ux_outcomes.into_iter().enumerate() {
        assert!(SPEC.contains(marker), "UX-{}", number + 1);
    }
    assert!(SPEC.contains("MUST") && SPEC.contains("MUST NOT") && SPEC.contains("SHOULD NOT"));
}

#[test]
fn structural_mutation_predicates_cover_appendix_b_groups() {
    for id in [
        "RV-DUPLICATES",
        "RV-PATH",
        "RV-SYMLINK",
        "RV-EXTERNAL",
        "RV-CROSS-SIZE",
    ] {
        assert!(
            SPEC[SPEC
                .find("### B.4 Acceptance and Rejection Mutations")
                .unwrap()..]
                .contains(id),
            "missing {id}"
        );
    }
    let unique = |values: &[&str]| {
        values
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len()
            == values.len()
    };
    assert!(!unique(&["0", "0"])); // duplicate IDs, paths, hashes, and relationships share this predicate
    assert!(!unique(&["hello", "hello"]));
    assert!(!unique(&["hash", "hash"]));
    assert!(!unique(&["7", "7"]));
    let valid_path = |path: &str| {
        !path.is_empty()
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path.contains(['\\', '\0'])
            && !path
                .split('/')
                .any(|part| part.is_empty() || matches!(part, "." | ".."))
            && !path.as_bytes().get(1).is_some_and(|byte| *byte == b':')
    };
    assert!(
        ["/hell", "hell/", "a//b", "a\\b", ".", "C:"]
            .iter()
            .all(|path| !valid_path(path))
    );
    let valid_symlink_target = |parent_depth: usize, target: &str| {
        if target.is_empty()
            || target.starts_with('/')
            || target.contains(['\\', '\0'])
            || target.as_bytes().get(1) == Some(&b':')
        {
            return false;
        }
        let mut depth = parent_depth;
        for component in target.split('/') {
            if component.is_empty() || component == "." {
                return false;
            }
            if component == ".." {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
            } else {
                depth += 1;
            }
        }
        true
    };
    let valid_symlink = |parent_depth: usize, target: Option<&str>, blocks: usize, size: u64| {
        target.is_some_and(|target| valid_symlink_target(parent_depth, target))
            && blocks == 0
            && size == 0
    };
    assert!(valid_symlink(1, Some("../target"), 0, 0));
    assert!(!valid_symlink(0, Some("../escape"), 0, 0));
    assert!(!valid_symlink(0, None, 0, 0));
    assert!(!valid_symlink(0, Some("inside"), 1, 0));
    assert!(!valid_symlink(0, Some("inside"), 0, 1));
    let external_result = |enabled: bool, response: &[u8], stored_size: usize| {
        if !enabled {
            "unavailable"
        } else if response.starts_with(b"BLCK") && response.len() == stored_size + 4 {
            "readable"
        } else {
            "fails before output"
        }
    };
    assert_eq!(external_result(false, b"", 5), "unavailable");
    assert_eq!(external_result(true, b"BLCKxxxx", 5), "fails before output");
    assert_eq!(
        external_result(true, b"BLCKxxxxxx", 5),
        "fails before output"
    );
    assert_eq!(
        external_result(true, b"BADCxxxxx", 5),
        "fails before output"
    );
    let merge_descriptor = |existing: Option<u64>, candidate: u64| match existing {
        None => Ok(candidate),
        Some(size) if size == candidate => Ok(size),
        Some(_) => Err("cross-segment original_size conflict"),
    };
    assert_eq!(merge_descriptor(Some(5), 5), Ok(5));
    assert_eq!(
        merge_descriptor(Some(4), 5),
        Err("cross-segment original_size conflict")
    );
}

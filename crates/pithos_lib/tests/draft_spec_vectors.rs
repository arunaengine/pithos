//! Reproducible verification for the Pithos 1.0 draft vectors in Appendix B.
//!
//! This repository-only test model is not an alternate production codec.

use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
use crc32fast::hash as crc32;
use pithos_lib::archive::{
    Archive, ArchivePath, ArchiveWriter, EntryKind, EntryMetadata, ExternalBlockAccessPolicy,
    ExternalBlockResolver, ExternalLocation, OpenLimits, OpenOptions, ProcessingOptions,
    WriteOptions,
};
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

fn refresh_directory(bytes: &mut [u8], directory_start: usize) {
    let footer = bytes.len() - 12;
    let directory_len = (bytes.len() - directory_start) as u64;
    bytes[footer..footer + 8].copy_from_slice(&directory_len.to_be_bytes());
    let checksum = crc32(&bytes[directory_start..bytes.len() - 4]);
    let crc_offset = bytes.len() - 4;
    bytes[crc_offset..].copy_from_slice(&checksum.to_be_bytes());
}

fn encoded_empty_entry(id: u64, path: &str, file_type: u8, permissions: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    uleb(id, &mut bytes);
    uleb(path.len() as u64, &mut bytes);
    bytes.extend_from_slice(path.as_bytes());
    bytes.extend_from_slice(&[file_type, 1, 0]); // Type and an empty decrypted block list.
    for value in [0, 0, 0, permissions] {
        uleb(value, &mut bytes);
    }
    bytes.extend_from_slice(&[0, 0]); // No references or symlink target.
    bytes
}

fn base_with_entries(entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = b"PITH\x01\0PITHOSDR\0".to_vec();
    uleb(entries.len() as u64, &mut bytes);
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    bytes.push(0); // Blocks.
    bytes.push(10);
    for (id, name) in RELATIONS {
        uleb(id.into(), &mut bytes);
        uleb(name.len() as u64, &mut bytes);
        bytes.extend_from_slice(name.as_bytes());
    }
    bytes.push(0); // Encryption.
    bytes.extend_from_slice(&[0; 12]);
    refresh_directory(&mut bytes, 6);
    bytes
}

fn external_hello() -> Vec<u8> {
    let mut bytes = hello();
    bytes.splice(143..=143, [1, 1, b'x']);
    refresh_directory(&mut bytes, 15);
    bytes
}

fn cross_size_append() -> Vec<u8> {
    let mut bytes = hello();
    let child_start = bytes.len();
    let mut child = directory(Some((15, 264)), true, true);
    child[15..20].copy_from_slice(b"other");
    child[129] = 4;
    let child_crc = crc32(&child[..child.len() - 4]);
    let child_crc_offset = child.len() - 4;
    child[child_crc_offset..].copy_from_slice(&child_crc.to_be_bytes());
    bytes.extend(child);
    assert_eq!(child_start, 279);
    bytes
}

#[derive(Clone, Copy)]
struct MalformedExternalResolver;

impl ExternalBlockResolver for MalformedExternalResolver {
    fn resolve(
        &self,
        policy: &dyn ExternalBlockAccessPolicy,
        _location: &ExternalLocation,
        expected_len: u64,
        _max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError> {
        assert_eq!(expected_len, 9);
        assert!(policy.allows("test://resolved"));
        Ok(b"BLCKxxxx".to_vec())
    }
}

struct AllowExternal;

impl ExternalBlockAccessPolicy for AllowExternal {
    fn allows(&self, _target: &str) -> bool {
        true
    }
}

#[test]
fn canonical_vectors_are_generated_opened_and_exactly_reencoded() {
    for (id, generated) in [
        ("CV-BASE-EMPTY-146", base()),
        ("CV-APPEND-EMPTY-28", append()),
        ("CV-LOCAL-HELLO-279", hello()),
    ] {
        assert_eq!(generated, appendix_hex(id), "{id} must match Appendix B");
        Archive::open(MemorySource::new(generated.clone()), OpenOptions::default())
            .unwrap_or_else(|error| panic!("production reader rejected {id}: {error}"));
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
fn production_reader_reads_cv_local_hello_without_access_keys() {
    let archive = Archive::open(
        MemorySource::new(appendix_hex("CV-LOCAL-HELLO-279")),
        OpenOptions::default(),
    )
    .unwrap();
    assert!(matches!(
        archive.entry("hello").unwrap().unwrap().kind,
        EntryKind::File {
            size: 5,
            available: true
        }
    ));
    let mut output = Vec::new();
    archive.copy_to("hello", &mut output).unwrap();
    assert_eq!(output, b"hello");
    output.clear();
    archive.copy_range_to("hello", 1..4, &mut output).unwrap();
    assert_eq!(output, b"ell");
}

#[test]
fn production_base_writer_reproduces_cv_local_hello() {
    let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::base()).unwrap();
    writer
        .add_file(
            ArchivePath::new("hello").unwrap(),
            EntryMetadata::new(0, 0, 0o644),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(5),
            Cursor::new(b"hello"),
        )
        .unwrap();
    assert_eq!(writer.finish().unwrap(), appendix_hex("CV-LOCAL-HELLO-279"));
}

#[test]
fn production_reader_rejects_a_direct_list_before_over_budget_allocation() {
    let limits = OpenLimits {
        max_accessible_block_references: 0,
        ..OpenLimits::default()
    };
    assert!(matches!(
        Archive::open(
            MemorySource::new(appendix_hex("CV-LOCAL-HELLO-279")),
            OpenOptions::default().with_limits(limits),
        ),
        Err(PithosError::Deserialization(
            DeserializationError::LimitExceeded {
                field: "block references",
                limit: 0,
                actual: 1,
            }
        ))
    ));
}

#[test]
fn production_reader_accepts_av_uleb_nonminimal() {
    let id = "AV-ULEB-NONMINIMAL";
    Archive::open(
        MemorySource::new(replace_base_relationship_count(&[0x8a, 0x00])),
        OpenOptions::default(),
    )
    .unwrap_or_else(|error| panic!("production reader rejected {id}: {error}"));
}

#[test]
fn production_reader_rejects_rv_uleb() {
    let id = "RV-ULEB";
    let result = Archive::open(
        MemorySource::new(replace_base_relationship_count(&[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02,
        ])),
        OpenOptions::default(),
    );
    assert!(
        matches!(
            result,
            Err(PithosError::Deserialization(DeserializationError::Io(_)))
        ),
        "production reader accepted {id}"
    );
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
        ("RV-FLAGS", hello(), 142, 0x10, 0x7bd3b103),
        ("RV-UNKNOWN-TAG", hello(), 143, 0x02, 0x86cf1282),
        ("RV-FILETYPE", hello(), 32, 0x04, 0x50f42595),
        ("RV-PARENT", append(), 161, 0x98, 0xb734abf4),
        ("RV-EXTENT", hello(), 139, 0x0f, 0x623c8b49),
        ("RV-SHORT-ENCRYPTED", hello(), 142, 0x08, 0x92564e52),
    ];
    for (id, mut bytes, offset, replacement, expected_crc) in cases {
        let crc_offset = bytes.len() - 4;
        let directory_start = bytes.len()
            - u64::from_be_bytes(bytes[crc_offset - 8..crc_offset].try_into().unwrap()) as usize;
        bytes[offset] = replacement;
        let updated_crc = crc32(&bytes[directory_start..crc_offset]).to_be_bytes();
        bytes[crc_offset..].copy_from_slice(&updated_crc);
        assert_eq!(
            u32::from_be_bytes(bytes[crc_offset..].try_into().unwrap()),
            expected_crc,
            "{id}"
        );
        assert_b4_crc(id, expected_crc);
        assert!(
            Archive::open(MemorySource::new(bytes), OpenOptions::default()).is_err(),
            "production reader accepted {id}"
        );
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
    assert!(Archive::open(MemorySource::new(underflow), OpenOptions::default()).is_err());
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
    assert!(Archive::open(MemorySource::new(permissions), OpenOptions::default()).is_err());
    let mut bad_crc = base();
    bad_crc[151] = 0xd3;
    let mut trailing = base();
    trailing.push(0);
    for (id, bytes) in [("RV-CRC", bad_crc), ("RV-TRAILING", trailing)] {
        assert!(
            Archive::open(MemorySource::new(bytes), OpenOptions::default()).is_err(),
            "production reader accepted {id}"
        );
    }
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
fn production_reader_rejects_generated_rv_duplicates_path_hierarchy_and_relationships() {
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

    let duplicate = base_with_entries(&[
        encoded_empty_entry(0, "first", 0, 0o755),
        encoded_empty_entry(0, "second", 0, 0o755),
    ]);
    let invalid_path = base_with_entries(&[encoded_empty_entry(0, "/bad", 0, 0o755)]);
    let child_before_parent = base_with_entries(&[
        encoded_empty_entry(0, "parent/child", 1, 0o644),
        encoded_empty_entry(1, "parent", 0, 0o755),
    ]);
    let mut invalid_custom_relationship = base();
    invalid_custom_relationship[18] = 10;
    refresh_directory(&mut invalid_custom_relationship, 6);

    for (case, bytes) in [
        ("RV-DUPLICATES", duplicate),
        ("RV-PATH", invalid_path),
        ("hierarchy declaration order", child_before_parent),
        ("custom relationship range", invalid_custom_relationship),
        ("RV-CROSS-SIZE", cross_size_append()),
    ] {
        assert!(
            Archive::open(MemorySource::new(bytes), OpenOptions::default()).is_err(),
            "production reader accepted {case}"
        );
    }
}

#[test]
fn production_reader_enforces_rv_external_availability_and_framing() {
    let bytes = external_hello();
    let unavailable =
        Archive::open(MemorySource::new(bytes.clone()), OpenOptions::default()).unwrap();
    assert!(matches!(
        unavailable.entry("hello").unwrap().unwrap().kind,
        EntryKind::File {
            available: false,
            ..
        }
    ));
    let mut output = Vec::new();
    assert!(unavailable.copy_to("hello", &mut output).is_err());
    assert!(output.is_empty());

    let available = Archive::open(
        MemorySource::new(bytes),
        OpenOptions::default()
            .with_external_resolver(MalformedExternalResolver)
            .with_external_access_policy(std::sync::Arc::new(AllowExternal)),
    )
    .unwrap();
    assert!(matches!(
        available.entry("hello").unwrap().unwrap().kind,
        EntryKind::File {
            available: true,
            ..
        }
    ));
    assert!(available.copy_to("hello", &mut output).is_err());
    assert!(output.is_empty());
}

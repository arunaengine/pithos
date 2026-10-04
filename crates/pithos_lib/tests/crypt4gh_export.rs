mod common;

use common::util::{fixture, open, private_key, public_key};
use pithos_lib::adapters::crypt4gh;
use pithos_lib::archive::AccessKeys;

#[test]
fn crypt4gh_export_writes_only_its_header_before_a_source_block_fails() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let mut bytes = std::fs::read(&path).unwrap();
    let marker = bytes
        .windows(4)
        .position(|window| window == b"BLCK")
        .expect("fixture must contain a block");
    bytes[marker + 4] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    let archive = open(&path, AccessKeys::new().with_key(private_key("recipient1")));
    let mut output = Vec::new();
    assert!(
        crypt4gh::export(
            &archive,
            "data",
            vec![public_key("recipient2")],
            &mut output
        )
        .is_err()
    );
    let header_len = 16 + u32::from_le_bytes(output[16..20].try_into().unwrap()) as usize;
    assert_eq!(output.len(), header_len);
}

mod common;

use common::util::{fixture, private_key};
use pithos_lib::archive::{AccessKeys, Archive, OpenOptions};
use pithos_lib::source::FileSource;

#[test]
fn public_archive_rejects_a_bad_block_marker_when_the_block_is_read() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let mut bytes = std::fs::read(&path).unwrap();
    let marker = bytes
        .windows(4)
        .position(|window| window == b"BLCK")
        .unwrap();
    bytes[marker] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    let keys = AccessKeys::new().with_key(private_key("recipient1"));
    let archive = Archive::open(
        FileSource::open(&path).unwrap(),
        OpenOptions::default().with_access_keys(keys),
    )
    .expect("opening validates metadata only");
    let error = archive.copy_to("data", &mut Vec::new()).unwrap_err();
    assert!(error.to_string().contains("block marker"), "{error}");
}

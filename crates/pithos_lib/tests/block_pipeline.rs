mod common;

use common::util::fixture;
use pithos_lib::archive::{Archive, OpenOptions};
use pithos_lib::source::FileSource;

#[test]
fn public_archive_rejects_a_bad_block_marker_during_keyless_open() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let mut bytes = std::fs::read(&path).unwrap();
    let marker = bytes
        .windows(4)
        .position(|window| window == b"BLCK")
        .unwrap();
    bytes[marker] ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(
        Archive::open(FileSource::open(&path).unwrap(), OpenOptions::default()).is_err(),
        "bad local marker was accepted during keyless open"
    );
}

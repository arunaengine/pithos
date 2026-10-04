mod common;

use common::util::{fixture, open, private_key};
use pithos_lib::archive::AccessKeys;
use pithos_lib::error::PithosError;

#[test]
fn no_key_and_wrong_key_preserve_the_same_visible_entry_shape() {
    let temporary = tempfile::tempdir().unwrap();
    let path = fixture(&temporary, "recipient1");
    let no_key = open(&path, AccessKeys::new());
    let wrong_key = open(&path, AccessKeys::new().with_key(private_key("recipient2")));
    assert_eq!(
        no_key.entries().collect::<Vec<_>>(),
        wrong_key.entries().collect::<Vec<_>>()
    );
    for archive in [&no_key, &wrong_key] {
        assert!(matches!(
            archive.copy_to("data", &mut Vec::new()),
            Err(PithosError::ContentUnavailable)
        ));
    }
}

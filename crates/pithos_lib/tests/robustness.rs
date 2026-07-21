use pithos_lib::error::PithosError;
use pithos_lib::helpers::directory::DirectoryBuilder;
use pithos_lib::helpers::file_entry_map::FileEntryMap;
use pithos_lib::io::pithosreader::PithosReaderSimple;
use pithos_lib::io::pithoswriter::Content;
use pithos_lib::model::structs::{BlockDataState, FileEntry, FileType, Reference};
use std::error::Error;
use x25519_dalek::StaticSecret;

#[test]
fn new_with_keys_returns_error_instead_of_panicking() {
    let result = PithosReaderSimple::new_with_keys(
        "/nonexistent-pithos-robustness-test",
        Vec::<StaticSecret>::new(),
    );

    assert!(matches!(
        result,
        Err(PithosError::UnsupportedMultipleReaderKeys)
    ));
}

#[test]
fn reference_content_returns_error_instead_of_panicking() {
    let reference = Reference {
        target_file_id: 0,
        relationship: 0,
    };

    let result = FileEntry::new_from_content(FileType::Data, &Content::Reference(reference));

    assert!(matches!(
        result,
        Err(PithosError::UnsupportedReferenceContent)
    ));
}

#[test]
fn exhausted_file_ids_return_error_instead_of_panicking() -> Result<(), Box<dyn Error>> {
    let mut directory = DirectoryBuilder::new()
        .files(FileEntryMap::new_with_max(u64::MAX))
        .build()?;
    let file_entry = FileEntry {
        file_type: FileType::Data,
        block_data: BlockDataState::Decrypted(Vec::new()),
        created: 0,
        modified: 0,
        file_size: 0,
        permissions: 0o644,
        references: Vec::new(),
        symlink_target: None,
    };

    let result = directory.add_file("exhausted", &file_entry);

    assert!(matches!(result, Err(PithosError::FileIdExhausted)));
    Ok(())
}

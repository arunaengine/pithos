mod common;

use common::ro_crate::{metadata, write_loaded, write_raw_zip};
use common::util::{open, private_key};
use pithos_lib::adapters::ro_crate::{read_ro_crate_directory, read_ro_crate_zip};
use pithos_lib::archive::{AccessKeys, ArchiveEntry, Chunking, EntryKind};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

type SemanticEntry = (String, EntryKind, Vec<(u64, String)>);

fn semantic_entries(path: &Path) -> Vec<SemanticEntry> {
    let archive = open(path, AccessKeys::new().with_key(private_key("recipient1")));
    let mut entries = archive
        .entries()
        .map(|entry: ArchiveEntry| {
            (
                entry.path,
                entry.kind,
                entry
                    .references
                    .into_iter()
                    .map(|reference| (reference.target_id, reference.relationship))
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

#[test]
fn typed_directory_and_zip_conversion_have_semantic_parity_and_extract() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("directory-crate");
    fs::create_dir_all(source.join("nested")).unwrap();
    let crate_metadata = metadata(&["nested/file.txt", "unlisted.txt"]);
    fs::write(source.join("ro-crate-metadata.json"), &crate_metadata).unwrap();
    fs::write(source.join("nested/file.txt"), b"nested payload").unwrap();
    fs::write(source.join("unlisted.txt"), b"unlisted payload").unwrap();
    symlink("nested/file.txt", source.join("link")).unwrap();

    let zip = temporary.path().join("crate.zip");
    write_raw_zip(
        &zip,
        &[
            (
                b"ro-crate-metadata.json",
                crate_metadata.as_bytes(),
                0o100644,
            ),
            (b"nested/file.txt", b"nested payload", 0o100644),
            (b"unlisted.txt", b"unlisted payload", 0o100644),
            (b"link", b"nested/file.txt", 0o120777),
        ],
    );

    let directory_output = temporary.path().join("directory.pith");
    let zip_output = temporary.path().join("zip.pith");
    write_loaded(
        &directory_output,
        read_ro_crate_directory(&source).unwrap(),
        Chunking::default(),
    );
    write_loaded(
        &zip_output,
        read_ro_crate_zip(&zip).unwrap(),
        Chunking::default(),
    );

    assert_eq!(
        semantic_entries(&directory_output),
        semantic_entries(&zip_output)
    );
    let archive = open(
        &zip_output,
        AccessKeys::new().with_key(private_key("recipient1")),
    );
    let nested = archive.entry("nested").unwrap().unwrap();
    assert_eq!(nested.kind, EntryKind::Directory);
    let mut content = Vec::new();
    archive.copy_to("nested/file.txt", &mut content).unwrap();
    assert_eq!(content, b"nested payload");
    assert_eq!(
        archive
            .entry("nested/file.txt")
            .unwrap()
            .unwrap()
            .permissions,
        0o644
    );
    let extracted = temporary.path().join("extracted");
    fs::create_dir(&extracted).unwrap();
    pithos_lib::fs::extract(&archive, "nested", &extracted).unwrap();
    pithos_lib::fs::extract(&archive, "nested/file.txt", &extracted).unwrap();
    pithos_lib::fs::extract(&archive, "link", &extracted).unwrap();
    assert_eq!(
        fs::read(extracted.join("nested/file.txt")).unwrap(),
        b"nested payload"
    );
    assert_eq!(
        fs::read_link(extracted.join("link")).unwrap(),
        Path::new("nested/file.txt")
    );
}

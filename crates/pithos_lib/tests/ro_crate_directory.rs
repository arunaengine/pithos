mod common;

use common::ro_crate::{conversion_error, duplicate_conversion_error, metadata, write_loaded};
use common::util::{open, private_key};
use pithos_lib::adapters::ro_crate::{
    RO_CRATE_METADATA_FILE, RoCrateError, RoCrateSource, read_ro_crate_directory,
};
use pithos_lib::archive::{AccessKeys, Chunking, WriterError};
use pithos_lib::error::PithosError;
use rocraters::ro_crate::graph_vector::GraphVector;
use rocraters::ro_crate::read::CrateReadError;
use rocraters::ro_crate::schema::RoCrateSchemaVersion;
use std::fs;
use std::os::unix::fs::symlink;

#[test]
fn loaded_directory_converts_from_retained_sources_after_path_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("crate");
    fs::create_dir(&source).unwrap();
    let original_metadata = metadata(&["data.bin"]).replace("Test Crate", "Original Crate");
    fs::write(source.join("ro-crate-metadata.json"), &original_metadata).unwrap();
    fs::write(source.join("data.bin"), b"original").unwrap();

    let loaded = read_ro_crate_directory(&source).unwrap();
    fs::rename(&source, temporary.path().join("original-crate")).unwrap();
    fs::create_dir(&source).unwrap();
    let replacement_metadata =
        metadata(&["data.bin", "replacement-only.bin"]).replace("Test Crate", "Replacement Crate");
    fs::write(source.join("ro-crate-metadata.json"), replacement_metadata).unwrap();
    fs::write(source.join("data.bin"), b"replaced").unwrap();
    fs::write(source.join("replacement-only.bin"), b"replacement").unwrap();

    let output = temporary.path().join("retained-directory.pith");
    write_loaded(&output, loaded, Chunking::default());
    let archive = open(
        &output,
        AccessKeys::new().with_key(private_key("recipient1")),
    );
    let mut archived_metadata = Vec::new();
    archive
        .copy_to("ro-crate-metadata.json", &mut archived_metadata)
        .unwrap();
    let mut data = Vec::new();
    archive.copy_to("data.bin", &mut data).unwrap();

    assert_eq!(archived_metadata, original_metadata.as_bytes());
    assert_eq!(data, b"original");
    assert!(archive.entry("replacement-only.bin").unwrap().is_none());
}

#[test]
fn retained_directory_conversion_failure_has_physical_path_and_source_context() {
    let temporary = tempfile::tempdir().unwrap();
    let crate_path = temporary.path().join("crate");
    let data_path = crate_path.join("data.bin");
    fs::create_dir(&crate_path).unwrap();
    fs::write(
        crate_path.join(RO_CRATE_METADATA_FILE),
        metadata(&["data.bin"]),
    )
    .unwrap();
    fs::write(&data_path, b"original").unwrap();
    let loaded = read_ro_crate_directory(&crate_path).unwrap();

    fs::write(&data_path, []).unwrap();

    let error = conversion_error(loaded);
    let message = error.to_string();
    assert!(message.contains("convert retained directory file"));
    assert!(message.contains(data_path.to_str().unwrap()));
    let writer_error = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<WriterError>())
        .expect("retained-file context must expose WriterError as its source");
    let core_error = std::error::Error::source(writer_error)
        .and_then(|source| source.downcast_ref::<PithosError>())
        .expect("WriterError must expose its core source");
    assert!(matches!(
        core_error,
        PithosError::WriterExpectedSizeMismatch {
            expected: 8,
            actual: 0
        }
    ));
}

#[test]
fn directory_metadata_directory_and_symlink_failures_keep_physical_context() {
    let temporary = tempfile::tempdir().unwrap();
    let crate_path = temporary.path().join("crate");
    fs::create_dir_all(crate_path.join("nested")).unwrap();
    fs::write(crate_path.join(RO_CRATE_METADATA_FILE), metadata(&[])).unwrap();
    symlink("missing", crate_path.join("link")).unwrap();

    for (entry, operation, physical) in [
        (
            RO_CRATE_METADATA_FILE,
            "convert retained directory metadata",
            crate_path.join(RO_CRATE_METADATA_FILE),
        ),
        (
            "nested",
            "convert retained directory entry",
            crate_path.join("nested"),
        ),
        (
            "link",
            "convert retained directory entry",
            crate_path.join("link"),
        ),
    ] {
        let error =
            duplicate_conversion_error(read_ro_crate_directory(&crate_path).unwrap(), entry);
        let message = error.to_string();
        assert!(message.contains(operation), "unexpected error: {message}");
        assert!(
            message.contains(physical.to_str().unwrap()),
            "unexpected error: {message}"
        );
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<WriterError>())
                .is_some()
        );
    }
}

#[test]
fn typed_directory_conversion_rejects_unsafe_symlink_targets_before_content_write() {
    let temporary = tempfile::tempdir().unwrap();
    for (name, target) in [
        ("absolute", "/outside"),
        ("escaping", "../outside"),
        ("invalid", "target/"),
    ] {
        let source = temporary.path().join(name);
        fs::create_dir(&source).unwrap();
        fs::write(source.join("ro-crate-metadata.json"), metadata(&[])).unwrap();
        symlink(target, source.join("link")).unwrap();
        let error = read_ro_crate_directory(&source).unwrap_err();
        let physical = source.join("link");
        let message = error.to_string();
        assert!(message.contains(physical.to_str().unwrap()), "{message}");
        assert!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<PithosError>())
                .is_some()
        );
    }
}

// Upstream ro-crate-rs parser and graph assertions.
#[test]
fn parser_preserves_the_fixture_graph_and_schema_version() {
    let loaded = read_ro_crate_directory("tests/data/dummy_dir").unwrap();
    assert_eq!(loaded.source_kind(), RoCrateSource::Directory);

    let mut data_ids = loaded
        .ro_crate()
        .graph
        .iter()
        .filter_map(|entity| match entity {
            GraphVector::DataEntity(entity) => Some(entity.id.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    data_ids.sort_unstable();
    assert_eq!(
        data_ids,
        [
            "conclusions.txt",
            "dataset/",
            "dummy_results.txt",
            "literature/"
        ]
    );

    let mut contextual_ids = loaded
        .ro_crate()
        .graph
        .iter()
        .filter_map(|entity| match entity {
            GraphVector::ContextualEntity(entity) => Some(entity.id.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    contextual_ids.sort_unstable();
    assert_eq!(
        contextual_ids,
        [
            "https://orcid.org/0000-0002-1825-0097",
            "mailto:josiah.carberry@example.com"
        ]
    );
    assert_eq!(
        loaded
            .ro_crate()
            .graph
            .iter()
            .filter(|entity| matches!(entity, GraphVector::MetadataDescriptor(_)))
            .count(),
        1
    );
    assert_eq!(
        loaded
            .ro_crate()
            .graph
            .iter()
            .filter(|entity| matches!(entity, GraphVector::RootDataEntity(_)))
            .count(),
        1
    );
    assert_eq!(
        loaded.ro_crate().get_rocrate_version(),
        Some(RoCrateSchemaVersion::V1_2)
    );
}

#[test]
fn directory_parser_requires_exact_root_metadata_and_complete_root_fields() {
    let temporary = tempfile::tempdir().unwrap();
    let not_directory = temporary.path().join("not-a-directory");
    fs::write(&not_directory, b"file").unwrap();
    let error = read_ro_crate_directory(&not_directory).unwrap_err();
    assert!(error.to_string().contains("open directory RO-Crate"));
    assert!(error.to_string().contains(not_directory.to_str().unwrap()));

    assert!(matches!(
        read_ro_crate_directory(temporary.path()),
        Err(RoCrateError::MissingMetadata { .. })
    ));

    let wrapper = temporary.path().join("wrapper");
    fs::create_dir(&wrapper).unwrap();
    fs::write(wrapper.join("ro-crate-metadata.json"), metadata(&[])).unwrap();
    assert!(matches!(
        read_ro_crate_directory(temporary.path()),
        Err(RoCrateError::MissingMetadata { .. })
    ));

    fs::write(
        temporary.path().join("ro-crate-metadata.json"),
        r#"{
          "@context": "https://w3id.org/ro/crate/1.2/context",
          "@graph": [
            {
              "@id": "ro-crate-metadata.json",
              "@type": "CreativeWork",
              "conformsTo": {"@id": "https://w3id.org/ro/crate/1.2"},
              "about": {"@id": "./"}
            },
            {"@id": "./", "@type": "Dataset"}
          ]
        }"#,
    )
    .unwrap();
    let error = read_ro_crate_directory(temporary.path()).unwrap_err();
    assert!(matches!(
        std::error::Error::source(&error)
            .and_then(|source| source.downcast_ref::<CrateReadError>()),
        Some(CrateReadError::JsonError(_))
    ));
    assert!(error.to_string().contains("missing field `name`"));
    assert!(error.to_string().contains("parse RO-Crate metadata"));
    assert!(
        error.to_string().contains(
            temporary
                .path()
                .join("ro-crate-metadata.json")
                .to_str()
                .unwrap()
        )
    );
}

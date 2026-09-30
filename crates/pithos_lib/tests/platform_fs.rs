use pithos_lib::archive::{
    AccessKeys, Archive, ArchivePath, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions,
    WriteOptions,
};
use pithos_lib::crypto::PrivateKey;
use pithos_lib::fs::ingest::{InputManifest, build_input_manifest};
use pithos_lib::fs::{ExtractionOptions, FsError, extract, extract_all, extract_with_options};
use pithos_lib::source::MemorySource;
use std::fs::{self, File, FileTimes};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

fn write_manifest(manifest: &InputManifest) -> Archive<MemorySource> {
    let sender = PrivateKey::generate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
    )
    .unwrap();
    manifest
        .ingest(&mut writer, ProcessingOptions::default())
        .unwrap();
    Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap()
}

#[test]
fn ingestion_records_only_linux_permission_bits() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("mode.bin");
    fs::write(&input, b"mode").unwrap();
    fs::set_permissions(&input, fs::Permissions::from_mode(0o640)).unwrap();

    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let entry = archive.entry("mode.bin").unwrap().unwrap();

    assert_eq!(entry.permissions, 0o640);
}

#[test]
fn ingestion_normalizes_pre_epoch_timestamps_to_zero() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("pre-epoch.bin");
    fs::write(&input, b"timestamp").unwrap();
    File::options()
        .write(true)
        .open(&input)
        .unwrap()
        .set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH - Duration::from_secs(1)))
        .unwrap();

    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let entry = archive.entry("pre-epoch.bin").unwrap().unwrap();

    assert_eq!(entry.modified, 0);
}

#[test]
fn ingestion_rejects_unix_sockets_with_typed_path_context() {
    let temporary = tempfile::tempdir().unwrap();
    let socket = temporary.path().join("input.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();

    let error = match build_input_manifest(std::slice::from_ref(&socket)) {
        Ok(_) => panic!("socket ingestion unexpectedly succeeded"),
        Err(error) => error,
    };

    let error = (&error as &(dyn std::error::Error + 'static))
        .downcast_ref::<FsError>()
        .expect("filesystem operations must return FsError directly");
    assert!(matches!(
        error,
        FsError::UnsupportedEntry { path, kind }
            if path == &socket && *kind == "socket"
    ));
}

#[test]
fn ingestion_rejects_fifos_with_typed_path_context() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    let fifo = source.join("input.fifo");
    fs::create_dir(&source).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, rustix::fs::Mode::RWXU).unwrap();

    let error = match build_input_manifest(&[source]) {
        Ok(_) => panic!("FIFO ingestion unexpectedly succeeded"),
        Err(error) => error,
    };
    let error = (&error as &(dyn std::error::Error + 'static))
        .downcast_ref::<FsError>()
        .expect("filesystem operations must return FsError directly");
    assert!(matches!(
        error,
        FsError::UnsupportedEntry { path, kind }
            if path == &fifo && *kind == "FIFO"
    ));
}

#[test]
fn extraction_preserves_files_directories_and_contained_dangling_symlinks() {
    let temporary = tempfile::tempdir().unwrap();
    let source = temporary.path().join("source");
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::write(source.join("payload.bin"), b"payload").unwrap();
    std::os::unix::fs::symlink("../payload.bin", source.join("nested/live")).unwrap();
    std::os::unix::fs::symlink("../missing.bin", source.join("nested/dangling")).unwrap();
    let archive = write_manifest(&build_input_manifest(&[source]).unwrap());
    let output = temporary.path().join("output");

    for path in ["nested", "payload.bin", "nested/live", "nested/dangling"] {
        extract(&archive, path, &output).unwrap();
    }

    assert!(
        fs::symlink_metadata(output.join("nested"))
            .unwrap()
            .is_dir()
    );
    assert_eq!(fs::read(output.join("payload.bin")).unwrap(), b"payload");
    assert_eq!(
        fs::read_link(output.join("nested/live")).unwrap(),
        Path::new("../payload.bin")
    );
    assert_eq!(
        fs::read_link(output.join("nested/dangling")).unwrap(),
        Path::new("../missing.bin")
    );
    assert!(fs::metadata(output.join("nested/dangling")).is_err());
    assert!(!output.join("missing.bin").exists());
}

#[test]
fn extraction_applies_exact_ordinary_modes_without_restoring_timestamps() {
    let sender = PrivateKey::generate();
    let mut writer = ArchiveWriter::create(
        Vec::new(),
        WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
    )
    .unwrap();
    writer
        .add_directory(
            ArchivePath::new("directory").unwrap(),
            EntryMetadata::new(1, 1, 0o751),
        )
        .unwrap();
    writer
        .add_file(
            ArchivePath::new("data.bin").unwrap(),
            EntryMetadata::new(1, 1, 0o411),
            ProcessingOptions::default(),
            Some(7),
            std::io::Cursor::new(b"content"),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    extract(&archive, "data.bin", temporary.path()).unwrap();
    extract(&archive, "directory", temporary.path()).unwrap();

    let output = temporary.path().join("data.bin");
    assert_eq!(fs::read(&output).unwrap(), b"content");
    let metadata = fs::metadata(output).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o7777, 0o411);
    assert_eq!(
        fs::metadata(temporary.path().join("directory"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o751
    );
    assert!(
        metadata
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            > 1
    );
}

#[test]
fn extraction_strips_special_bits_by_default_and_can_restore_sticky_directories() {
    let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::base()).unwrap();
    writer
        .add_file(
            ArchivePath::new("special-file").unwrap(),
            EntryMetadata::new(0, 0, 0o6754),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(4),
            std::io::Cursor::new(b"mode"),
        )
        .unwrap();
    writer
        .add_directory(
            ArchivePath::new("sticky-default").unwrap(),
            EntryMetadata::new(0, 0, 0o1751),
        )
        .unwrap();
    writer
        .add_directory(
            ArchivePath::new("sticky-opt-in").unwrap(),
            EntryMetadata::new(0, 0, 0o1755),
        )
        .unwrap();
    let archive = Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default(),
    )
    .unwrap();
    let temporary = tempfile::tempdir().unwrap();

    extract(&archive, "special-file", temporary.path()).unwrap();
    extract(&archive, "sticky-default", temporary.path()).unwrap();
    extract_with_options(
        &archive,
        "sticky-opt-in",
        temporary.path(),
        ExtractionOptions::default().with_special_permissions(),
    )
    .unwrap();

    for (path, expected) in [
        ("special-file", 0o754),
        ("sticky-default", 0o751),
        ("sticky-opt-in", 0o1755),
    ] {
        assert_eq!(
            fs::symlink_metadata(temporary.path().join(path))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            expected
        );
    }
}

fn restrictive_directory_archive() -> Archive<MemorySource> {
    let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::base()).unwrap();
    writer
        .add_directory(
            ArchivePath::new("locked").unwrap(),
            EntryMetadata::new(0, 0, 0o555),
        )
        .unwrap();
    writer
        .add_file(
            ArchivePath::new("locked/child").unwrap(),
            EntryMetadata::new(0, 0, 0o640),
            ProcessingOptions::new(false, 0).unwrap(),
            Some(5),
            std::io::Cursor::new(b"child"),
        )
        .unwrap();
    Archive::open(
        MemorySource::new(writer.finish().unwrap()),
        OpenOptions::default(),
    )
    .unwrap()
}

#[test]
fn batch_extraction_defers_restrictive_directory_modes_until_children_exist() {
    let temporary = tempfile::tempdir().unwrap();
    extract_all(&restrictive_directory_archive(), temporary.path()).unwrap();
    assert_eq!(
        fs::read(temporary.path().join("locked/child")).unwrap(),
        b"child"
    );
    assert_eq!(
        fs::metadata(temporary.path().join("locked"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o555
    );
    assert_eq!(
        fs::metadata(temporary.path().join("locked/child"))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777,
        0o640
    );
}

#[test]
fn batch_extraction_restores_modes_under_restrictive_umask() {
    const CHILD: &str = "PITHOS_TEST_RESTRICTIVE_UMASK";
    if std::env::var_os(CHILD).is_some() {
        // This process runs only this test, so changing its process-global umask is isolated.
        unsafe { libc::umask(0o077) };
        let temporary = tempfile::tempdir().unwrap();
        extract_all(&restrictive_directory_archive(), temporary.path()).unwrap();
        assert_eq!(
            fs::metadata(temporary.path().join("locked"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            fs::metadata(temporary.path().join("locked/child"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o640
        );
        return;
    }

    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "batch_extraction_restores_modes_under_restrictive_umask",
            "--nocapture",
        ])
        .env(CHILD, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn extraction_rejects_a_symlink_in_the_destination_root_path() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("payload.bin");
    fs::write(&input, b"payload").unwrap();
    let archive = write_manifest(&build_input_manifest(&[input]).unwrap());
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let redirect = temporary.path().join("redirect");
    std::os::unix::fs::symlink(&outside, &redirect).unwrap();
    let destination = redirect.join("created-through-link");

    assert!(extract(&archive, "payload.bin", &destination).is_err());
    assert!(!outside.join("created-through-link").exists());
}

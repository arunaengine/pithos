use crate::archive::{
    AccessKeys, AppendDurability, AppendObservation, AppendOptions, AppendSnapshot, Archive,
    ArchiveWriter, FileId, OpenOptions, WriterError,
};
use crate::crypto::PrivateKey;
use crate::error::PithosError;
use crate::fs::FsError;
use crate::fs::ingest::{InputManifest, build_input_manifest};
use crate::source::{ArchiveSource, FileSource, SourceError};
use rustix::fs::{FlockOperation, Mode, OFlags, flock};
use std::fs::File;
use std::io::{self, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AppendFailurePoint {
    AfterMarker,
    AfterPayload,
    DuringDirectory,
    Flush,
    SyncAll,
    RollbackTruncate,
    RollbackFlush,
    MetadataQuery,
}

struct AppendSource {
    source: FileSource,
    reads: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

impl ArchiveSource for AppendSource {
    fn len(&self) -> Result<u64, SourceError> {
        self.source.len()
    }

    fn read_exact_at(&self, offset: u64, buffer: &mut [u8]) -> Result<(), SourceError> {
        self.source.read_exact_at(offset, buffer)?;
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(buffer.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

/// Metadata-first direct append inputs. Open handles remain in the manifest until execution.
struct AppendSpec {
    options: AppendOptions,
    files: Vec<PathBuf>,
}

struct AppendPlan {
    manifest: InputManifest,
    ids: Vec<u64>,
}

impl AppendPlan {
    fn build(
        spec: &AppendSpec,
        snapshot: &AppendSnapshot,
        archive_device: u64,
        archive_inode: u64,
    ) -> Result<Self, FsError> {
        let manifest = build_input_manifest(&spec.files)?;
        if let Some(path) = manifest.source_with_identity(archive_device, archive_inode) {
            return Err(FsError::AppendSourceIsArchive {
                path: path.to_path_buf(),
            });
        }
        let ids = manifest
            .validate_append(snapshot)
            .map_err(|source| FsError::Core {
                operation: "validate append plan",
                path: spec.files.first().cloned().unwrap_or_default(),
                source,
            })?;
        Ok(Self { manifest, ids })
    }
}

/// Append filesystem entries in one child directory.
///
/// The target is opened once, then held under a nonblocking advisory exclusive lock
/// through validation, publication, durability handling, and any rollback attempt.
/// The lock coordinates only processes that use this protocol. All knowable input
/// conflicts are validated before content is read or the archive is mutated; a
/// successful append writes one child directory and never a second header.
///
/// [`AppendDurability::Flush`] flushes the completed child directory. [`AppendDurability::SyncAll`]
/// additionally requests filesystem durability with `sync_all`. After a mutation-time
/// failure, the implementation attempts to truncate to the original length and flush
/// while retaining the lock. A successful restoration reports `AppendRolledBack`; a
/// failed truncation or rollback flush reports `AppendRollbackFailed` with both causes.
/// Neither mode promises atomic publication, crash-universal durability, or recovery
/// after process termination, storage failure, or power loss.
pub fn append_files(
    archive: &Path,
    options: AppendOptions,
    files: &[PathBuf],
) -> Result<AppendObservation, FsError> {
    append_files_impl(
        archive,
        options,
        files,
        #[cfg(test)]
        None,
    )
}

#[cfg(test)]
fn append_files_with_injected_failure(
    archive: &Path,
    options: AppendOptions,
    files: &[PathBuf],
    failure: AppendFailurePoint,
) -> Result<AppendObservation, FsError> {
    append_files_impl(archive, options, files, Some(failure))
}

fn append_files_impl(
    archive: &Path,
    options: AppendOptions,
    files: &[PathBuf],
    #[cfg(test)] failure: Option<AppendFailurePoint>,
) -> Result<AppendObservation, FsError> {
    if files.is_empty() {
        return Err(FsError::AppendRequiresInput);
    }
    let spec = AppendSpec {
        options,
        files: files.to_vec(),
    };

    let mut locked = open_locked(archive)?;
    spec.options
        .validate_recipients()
        .map_err(|source| append_error("validate append recipients", archive, source))?;
    let archive_metadata = locked.metadata().map_err(|source| FsError::Host {
        operation: "inspect archive",
        path: archive.to_path_buf(),
        source,
    })?;
    let original_len = archive_metadata.len();
    let reads = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let snapshot = open_snapshot(
        &locked,
        spec.options.access_key.duplicate(),
        Arc::clone(&reads),
        Arc::clone(&bytes),
    )
    .map_err(|source| append_error("open append snapshot", archive, source))?;
    let plan = AppendPlan::build(
        &spec,
        &snapshot,
        archive_metadata.dev(),
        archive_metadata.ino(),
    )?;
    let wrapping_sender = fresh_wrapping_sender(&snapshot, &spec.options);
    let recipients = spec.options.recipients_with_access_key();
    let mutated = Arc::new(AtomicBool::new(false));

    let AppendSpec { options, .. } = spec;
    let result = (|| {
        let mut sink = AppendSink::new(
            locked.try_clone()?,
            #[cfg(test)]
            failure,
            Arc::clone(&mutated),
        );
        sink.seek(SeekFrom::Start(original_len))?;
        let mut writer =
            ArchiveWriter::append(sink, wrapping_sender, recipients, options.cdc, snapshot)?;
        plan.manifest
            .ingest_planned(&plan.ids, &mut writer, options.processing)
            .map_err(writer_error)?;
        let mut sink = writer.finish().map_err(|error| error.into_parts().0)?;
        if options.durability == AppendDurability::SyncAll {
            sink.sync_all()?;
        }
        let final_archive_bytes = sink.metadata()?.len();
        Ok::<(AppendSink, u64), PithosError>((sink, final_archive_bytes))
    })();

    match result {
        Ok((_, final_archive_bytes)) => Ok(AppendObservation {
            source_read_count: reads.load(Ordering::Relaxed),
            source_read_bytes: bytes.load(Ordering::Relaxed),
            base_archive_bytes: original_len,
            final_archive_bytes,
        }),
        Err(error) => {
            let source = rollback_if_mutated(
                &mut locked,
                original_len,
                #[cfg(test)]
                failure,
                mutated.load(Ordering::Relaxed),
                error,
            );
            Err(append_error("append archive", archive, source))
        }
    }
}

/// Add recipient access records in one metadata-only child directory.
///
/// This follows the same opened-target advisory locking, durability, and best-effort
/// rollback contract as [`append_files`]. It validates requested entry IDs while the
/// lock is held and writes no content blocks or second archive header.
pub fn grant_readers(
    archive: &Path,
    options: AppendOptions,
    ids: &[u64],
) -> Result<AppendObservation, FsError> {
    let mut locked = open_locked(archive)?;
    options
        .validate_recipients()
        .map_err(|source| append_error("validate grant recipients", archive, source))?;
    let original_len = locked
        .metadata()
        .map_err(|source| FsError::Host {
            operation: "inspect archive",
            path: archive.to_path_buf(),
            source,
        })?
        .len();
    let reads = Arc::new(AtomicU64::new(0));
    let bytes = Arc::new(AtomicU64::new(0));
    let snapshot = open_snapshot(
        &locked,
        options.access_key.duplicate(),
        Arc::clone(&reads),
        Arc::clone(&bytes),
    )
    .map_err(|source| append_error("open grant snapshot", archive, source))?;
    validate_grant_ids(&snapshot, ids)
        .map_err(|source| append_error("validate grant ids", archive, source))?;
    let wrapping_sender = fresh_wrapping_sender(&snapshot, &options);
    let recipients = options.recipients_with_access_key();
    let mutated = Arc::new(AtomicBool::new(false));

    let result = (|| {
        let mut sink = AppendSink::new(
            locked.try_clone()?,
            #[cfg(test)]
            None,
            Arc::clone(&mutated),
        );
        sink.seek(SeekFrom::Start(original_len))?;
        let mut writer =
            ArchiveWriter::append(sink, wrapping_sender, recipients, options.cdc, snapshot)?;
        writer.grant_file_keys(&ids.iter().copied().map(FileId).collect::<Vec<_>>())?;
        let mut sink = writer.finish().map_err(|error| error.into_parts().0)?;
        if options.durability == AppendDurability::SyncAll {
            sink.sync_all()?;
        }
        let final_archive_bytes = sink.metadata()?.len();
        Ok::<(AppendSink, u64), PithosError>((sink, final_archive_bytes))
    })();

    match result {
        Ok((_, final_archive_bytes)) => Ok(AppendObservation {
            source_read_count: reads.load(Ordering::Relaxed),
            source_read_bytes: bytes.load(Ordering::Relaxed),
            base_archive_bytes: original_len,
            final_archive_bytes,
        }),
        Err(error) => {
            let source = rollback_if_mutated(
                &mut locked,
                original_len,
                #[cfg(test)]
                None,
                mutated.load(Ordering::Relaxed),
                error,
            );
            Err(append_error("grant archive access", archive, source))
        }
    }
}

fn open_locked(path: &Path) -> Result<File, FsError> {
    let file = rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(io::Error::from)
    .map(File::from)
    .map_err(|source| FsError::Host {
        operation: "open archive",
        path: path.to_path_buf(),
        source,
    })?;
    // Keep this description locked through validation, publication, and any rollback.
    match flock(&file, FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(file),
        Err(rustix::io::Errno::WOULDBLOCK) => Err(FsError::AppendLocked {
            path: path.to_path_buf(),
        }),
        Err(error) => Err(FsError::Host {
            operation: "lock archive",
            path: path.to_path_buf(),
            source: io::Error::from_raw_os_error(error.raw_os_error()),
        }),
    }
}

fn open_snapshot(
    locked: &File,
    sender: crate::crypto::PrivateKey,
    reads: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
) -> Result<AppendSnapshot, PithosError> {
    Archive::open(
        AppendSource {
            source: FileSource::from_file(locked.try_clone()?)?,
            reads,
            bytes,
        },
        OpenOptions::default().with_access_keys(AccessKeys::new().with_key(sender)),
    )
    .map(Archive::into_append_snapshot)
}

fn fresh_wrapping_sender(snapshot: &AppendSnapshot, options: &AppendOptions) -> PrivateKey {
    let recipients = options.recipients_with_access_key();
    let access_public = options.access_key.public_key();
    loop {
        let sender = PrivateKey::generate();
        let sender_public = sender.public_key();
        if sender_public != access_public
            && !snapshot.sender_pair_is_occupied(
                sender_public.into_dalek_public_key().to_bytes(),
                &recipients,
            )
        {
            return sender;
        }
    }
}

fn validate_grant_ids(snapshot: &AppendSnapshot, ids: &[u64]) -> Result<(), PithosError> {
    if ids.is_empty() {
        return Err(PithosError::GrantRequiresFileId);
    }
    let mut unique = std::collections::HashSet::with_capacity(ids.len());
    for id in ids {
        if !unique.insert(*id) {
            return Err(PithosError::DuplicateRecipientFileId);
        }
        snapshot.with_file_key(FileId(*id), |_| ())?;
    }
    Ok(())
}

fn writer_error(error: WriterError) -> PithosError {
    match error {
        WriterError::Pithos(error) => error,
        WriterError::Poisoned => PithosError::WriterPoisoned,
    }
}

fn append_error(operation: &'static str, path: &Path, source: PithosError) -> FsError {
    FsError::Core {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn rollback_if_mutated(
    locked: &mut File,
    original_len: u64,
    #[cfg(test)] failure: Option<AppendFailurePoint>,
    mutated: bool,
    error: PithosError,
) -> PithosError {
    #[cfg(test)]
    let observed_len = if failure == Some(AppendFailurePoint::MetadataQuery) {
        Err(io::Error::other(
            "injected append rollback metadata query failure",
        ))
    } else {
        locked.metadata().map(|metadata| metadata.len())
    }
    .unwrap_or(original_len);
    #[cfg(not(test))]
    let observed_len = locked
        .metadata()
        .map(|metadata| metadata.len())
        .unwrap_or(original_len);
    if !mutated && observed_len == original_len {
        return error;
    }

    // A failed child is never publication: restore the validated prefix before unlocking.
    #[cfg(test)]
    let rollback = if failure == Some(AppendFailurePoint::RollbackTruncate) {
        Err(io::Error::other(
            "injected append rollback truncation failure",
        ))
    } else if failure == Some(AppendFailurePoint::RollbackFlush) {
        locked
            .set_len(original_len)
            .and_then(|()| Err(io::Error::other("injected append rollback flush failure")))
    } else {
        locked.set_len(original_len).and_then(|()| locked.flush())
    };
    #[cfg(not(test))]
    let rollback = locked.set_len(original_len).and_then(|()| locked.flush());
    match rollback {
        Ok(()) => PithosError::AppendRolledBack {
            source: Box::new(error),
        },
        Err(rollback) => PithosError::AppendRollbackFailed {
            source: Box::new(error),
            rollback,
            original_len,
            observed_len,
        },
    }
}

struct AppendSink {
    file: File,
    mutated: Arc<AtomicBool>,
    #[cfg(test)]
    failure: Option<AppendFailurePoint>,
    #[cfg(test)]
    after_block_marker: bool,
}

impl AppendSink {
    fn new(
        file: File,
        #[cfg(test)] failure: Option<AppendFailurePoint>,
        mutated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            file,
            mutated,
            #[cfg(test)]
            failure,
            #[cfg(test)]
            after_block_marker: false,
        }
    }

    fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.file.metadata()
    }

    fn sync_all(&mut self) -> Result<(), PithosError> {
        #[cfg(test)]
        if self.failure == Some(AppendFailurePoint::SyncAll) {
            return Err(PithosError::Io(io::Error::other(
                "injected append sync-all failure",
            )));
        }
        self.file.sync_all().map_err(PithosError::Io)
    }
}

impl Write for AppendSink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let accepted = self.file.write(bytes)?;
        if accepted > 0 {
            self.mutated.store(true, Ordering::Relaxed);
        }
        #[cfg(test)]
        if accepted == bytes.len() {
            let is_marker = bytes == b"BLCK";
            let is_directory = bytes == b"PITHOSDR";
            let after_payload = self.after_block_marker && !is_marker;
            self.after_block_marker = is_marker;
            let fail = match self.failure {
                Some(AppendFailurePoint::AfterMarker) if is_marker => true,
                Some(
                    AppendFailurePoint::AfterPayload
                    | AppendFailurePoint::RollbackTruncate
                    | AppendFailurePoint::RollbackFlush
                    | AppendFailurePoint::MetadataQuery,
                ) if after_payload => true,
                Some(AppendFailurePoint::DuringDirectory) if is_directory => true,
                _ => false,
            };
            if fail {
                return Err(io::Error::other("injected append write failure"));
            }
        }
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()?;
        #[cfg(test)]
        if self.failure == Some(AppendFailurePoint::Flush) {
            return Err(io::Error::other("injected append flush failure"));
        }
        Ok(())
    }
}

impl Seek for AppendSink {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.file.seek(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{AccessKeys, ArchivePath, EntryMetadata, ProcessingOptions, WriteOptions};
    use crate::crypto::PrivateKey;
    use crate::format::limits::DeserializationLimits;
    use crate::source::FileSource;
    use std::io::Cursor;
    use x25519_dalek::PublicKey as DalekPublicKey;

    struct AppendFixture {
        archive: PathBuf,
        sender: PrivateKey,
    }

    impl AppendFixture {
        fn append_source(&self, name: &str, contents: &[u8]) -> PathBuf {
            let source = self.archive.parent().unwrap().join(name);
            std::fs::write(&source, contents).unwrap();
            source
        }

        fn open(&self) -> Archive<FileSource> {
            Archive::open(
                FileSource::open(&self.archive).unwrap(),
                OpenOptions::default()
                    .with_access_keys(AccessKeys::new().with_key(self.sender.duplicate())),
            )
            .unwrap()
        }

        fn options(&self, durability: AppendDurability) -> AppendOptions {
            AppendOptions::new(self.sender.duplicate(), vec![self.sender.public_key()])
                .with_durability(durability)
        }
    }

    fn append_fixture(temporary: &tempfile::TempDir) -> AppendFixture {
        let archive = temporary.path().join("append.pith");
        let sender = PrivateKey::generate();
        let mut writer = ArchiveWriter::create(
            File::create(&archive).unwrap(),
            WriteOptions::new(sender.duplicate(), vec![sender.public_key()]),
        )
        .unwrap();
        writer
            .add_file(
                ArchivePath::new("base.txt").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::append_default(),
                None,
                Cursor::new(b"base append payload"),
            )
            .unwrap();
        drop(writer.finish().unwrap());
        AppendFixture { archive, sender }
    }

    fn terminal_directory(path: &Path) -> crate::format::directory::Directory {
        let bytes = std::fs::read(path).unwrap();
        let directory_len =
            u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());
        let directory_start = bytes.len() - usize::try_from(directory_len).unwrap();
        crate::format::directory::decode_directory(
            &mut Cursor::new(&bytes[directory_start..]),
            &DeserializationLimits::default(),
        )
        .unwrap()
    }

    #[test]
    fn append_and_grant_use_fresh_senders_and_retain_the_access_key_as_a_recipient() {
        let temporary = tempfile::tempdir().unwrap();
        let fixture = append_fixture(&temporary);
        let access_public =
            DalekPublicKey::from(&fixture.sender.as_dalek_static_secret()).to_bytes();
        let base_sender = *terminal_directory(&fixture.archive)
            .encryption
            .first()
            .unwrap()
            .0;
        let other = PrivateKey::generate();
        let source = fixture.append_source("appended.txt", b"appended through a fresh sender");

        append_files(
            &fixture.archive,
            AppendOptions::new(fixture.sender.duplicate(), vec![other.public_key()]),
            &[source],
        )
        .unwrap();
        let child = terminal_directory(&fixture.archive);
        let child_sender = *child.encryption.first().unwrap().0;
        assert_ne!(child_sender, base_sender);
        assert_ne!(child_sender, access_public);
        assert!(
            child
                .encryption
                .first()
                .unwrap()
                .1
                .recipients
                .contains_key(&access_public)
        );
        fixture
            .open()
            .copy_to("appended.txt", &mut Vec::new())
            .unwrap();

        grant_readers(
            &fixture.archive,
            AppendOptions::new(fixture.sender.duplicate(), vec![other.public_key()]),
            &[0],
        )
        .unwrap();
        let grant = terminal_directory(&fixture.archive);
        let grant_sender = *grant.encryption.first().unwrap().0;
        assert_ne!(grant_sender, base_sender);
        assert_ne!(grant_sender, child_sender);
        assert_ne!(grant_sender, access_public);
        assert!(
            grant
                .encryption
                .first()
                .unwrap()
                .1
                .recipients
                .contains_key(&access_public)
        );

        let archive = Archive::open(
            FileSource::open(&fixture.archive).unwrap(),
            OpenOptions::default().with_access_keys(AccessKeys::new().with_key(other)),
        )
        .unwrap();
        archive.copy_to("base.txt", &mut Vec::new()).unwrap();
        archive.copy_to("appended.txt", &mut Vec::new()).unwrap();
    }

    #[test]
    fn conflicting_ancestor_relationship_is_rejected_before_mutation() {
        let temporary = tempfile::tempdir().unwrap();
        let archive_path = temporary.path().join("relationships.pith");
        let input_path = temporary.path().join("appended.txt");
        std::fs::write(&input_path, b"appended relationship payload").unwrap();
        let sender = PrivateKey::generate();
        let recipient = sender.public_key();
        let mut writer = ArchiveWriter::create(
            File::create(&archive_path).unwrap(),
            WriteOptions::new(sender.duplicate(), vec![recipient]),
        )
        .unwrap();
        writer
            .add_file(
                ArchivePath::new("base.txt").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::default(),
                None,
                Cursor::new(b"base relationship payload"),
            )
            .unwrap();
        drop(writer.finish().unwrap());

        let mut bytes = std::fs::read(&archive_path).unwrap();
        let directory_len =
            u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());
        let directory_start = bytes.len() - usize::try_from(directory_len).unwrap();
        let mut directory = crate::format::directory::decode_directory(
            &mut Cursor::new(&bytes[directory_start..]),
            &DeserializationLimits::default(),
        )
        .unwrap();
        directory.relations[0].1 = "Conflicts_With_Default".into();
        crate::format::directory::update_directory_len(&mut directory).unwrap();
        crate::format::directory::update_directory_crc(&mut directory).unwrap();
        let mut replacement = Vec::new();
        crate::format::directory::encode_directory(&directory, &mut replacement).unwrap();
        bytes.truncate(directory_start);
        bytes.extend_from_slice(&replacement);
        std::fs::write(&archive_path, &bytes).unwrap();
        let original = bytes;

        let error = append_files(
            &archive_path,
            AppendOptions::new(sender, vec![recipient]),
            &[input_path],
        )
        .unwrap_err();
        assert!(matches!(error, FsError::Core { .. }));
        assert!(
            error
                .to_string()
                .contains("invalid relationship definition")
        );
        assert_eq!(std::fs::read(&archive_path).unwrap(), original);
    }

    #[test]
    fn post_mutation_failures_roll_back_to_byte_identical_original_content() {
        for (point, durability) in [
            (AppendFailurePoint::AfterMarker, AppendDurability::Flush),
            (AppendFailurePoint::AfterPayload, AppendDurability::Flush),
            (AppendFailurePoint::DuringDirectory, AppendDurability::Flush),
            (AppendFailurePoint::Flush, AppendDurability::Flush),
            (AppendFailurePoint::SyncAll, AppendDurability::SyncAll),
            (AppendFailurePoint::MetadataQuery, AppendDurability::Flush),
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let fixture = append_fixture(&temporary);
            let original = std::fs::read(&fixture.archive).unwrap();
            let source = fixture.append_source("rollback.txt", b"rollback append payload");

            let error = append_files_with_injected_failure(
                &fixture.archive,
                fixture.options(durability),
                &[source],
                point,
            )
            .unwrap_err();

            assert!(
                matches!(
                    error,
                    FsError::Core {
                        source: PithosError::AppendRolledBack { .. },
                        ..
                    }
                ),
                "unexpected error at {point:?}: {error:?}"
            );
            assert_eq!(
                std::fs::read(&fixture.archive).unwrap(),
                original,
                "rollback at {point:?} did not restore the original bytes"
            );
            fixture.open();
        }
    }

    #[test]
    fn rollback_failure_reports_both_failures_recovery_lengths_and_no_secrets() {
        for point in [
            AppendFailurePoint::RollbackTruncate,
            AppendFailurePoint::RollbackFlush,
        ] {
            let temporary = tempfile::tempdir().unwrap();
            let fixture = append_fixture(&temporary);
            let original_len = std::fs::metadata(&fixture.archive).unwrap().len();
            let source =
                fixture.append_source("rollback-failure.txt", b"ROLLBACK_PLAINTEXT_SENTINEL");

            let error = append_files_with_injected_failure(
                &fixture.archive,
                fixture.options(AppendDurability::Flush),
                &[source],
                point,
            )
            .unwrap_err();
            let message = error.to_string();
            let debug = format!("{error:?}");

            assert!(matches!(
                error,
                FsError::Core {
                    source: PithosError::AppendRollbackFailed {
                        original_len: reported_original,
                        observed_len,
                        ..
                    },
                    ..
                } if reported_original == original_len && observed_len > original_len
            ));
            assert!(
                message.contains("injected append write failure"),
                "{message}"
            );
            assert!(message.contains("injected append rollback"), "{message}");
            assert!(message.contains(&original_len.to_string()), "{message}");
            for secret in ["ROLLBACK_PLAINTEXT_SENTINEL", "PRIVATE KEY"] {
                assert!(!message.contains(secret), "{message}");
                assert!(!debug.contains(secret), "{debug}");
            }
        }
    }
}

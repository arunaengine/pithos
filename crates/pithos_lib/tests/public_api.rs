use pithos_lib::adapters::{crypt4gh::Crypt4GHError, ro_crate::RoCrateError};
use pithos_lib::archive::{
    AccessKeys, AppendDurability, AppendObservation, AppendOptions, Archive, ArchiveFeature,
    ArchivePath, ArchiveReference, ArchiveWriter, CdcConfig, CreateError, EntryKind, EntryMetadata,
    EntryReference, ExternalBlockAccessPolicy, ExternalBlockResolver, ExternalLocation,
    FinishError, IncompleteWriter, NoExternalBlocks, OpenLimits, OpenOptions, ProcessingOptions,
    WriteOptions, WriterError, WrittenEntry,
};
use pithos_lib::crypto::{CryptoError, PrivateKey, PublicKey};
use pithos_lib::error::PithosError;
use pithos_lib::fs::{FsError, ingest::InputManifest};
use pithos_lib::source::{ArchiveSource, FileSource, MemorySource, SourceError};

fn assert_send_sync<T: Send + Sync>() {}

#[derive(Clone, Copy)]
struct SendSyncResolver;

impl ExternalBlockResolver for SendSyncResolver {
    fn resolve(
        &self,
        _policy: &dyn ExternalBlockAccessPolicy,
        _location: &ExternalLocation,
        _expected_len: u64,
        _max_response_size: u64,
    ) -> Result<Vec<u8>, PithosError> {
        Err(PithosError::ExternalBlockAccessDenied)
    }
}

#[derive(Clone, Copy)]
struct SendSyncPolicy;

impl ExternalBlockAccessPolicy for SendSyncPolicy {
    fn allows(&self, _target: &str) -> bool {
        true
    }
}

#[test]
fn standard_archive_configurations_are_send_and_sync() {
    assert_send_sync::<FileSource>();
    assert_send_sync::<MemorySource>();
    assert_send_sync::<Archive<MemorySource, NoExternalBlocks>>();
    assert_send_sync::<Archive<MemorySource, SendSyncResolver>>();
    assert_send_sync::<SendSyncPolicy>();
    assert_send_sync::<std::sync::Arc<dyn ExternalBlockAccessPolicy>>();
    let _ = OpenOptions::default().with_access_keys(AccessKeys::new());
    let _ = OpenOptions::default()
        .with_external_access_policy(std::sync::Arc::new(SendSyncPolicy))
        .with_external_resolver(SendSyncResolver);
    let _ = OpenOptions::default()
        .with_external_resolver(SendSyncResolver)
        .with_external_access_policy(std::sync::Arc::new(SendSyncPolicy));
    let _ = WriteOptions::base();
}

#[test]
fn selected_08_api_imports_compile() {
    let _ = std::any::TypeId::of::<AppendDurability>();
    let _ = std::any::TypeId::of::<AppendObservation>();
    let _ = std::any::TypeId::of::<AppendOptions>();
    let _ = std::any::TypeId::of::<ArchivePath>();
    let _ = std::any::TypeId::of::<ArchiveFeature>();
    let _ = std::any::TypeId::of::<ArchiveReference>();
    let _ = std::any::TypeId::of::<ArchiveWriter<Vec<u8>>>();
    let _ = std::any::TypeId::of::<CdcConfig>();
    let _ = std::any::TypeId::of::<CreateError<Vec<u8>>>();
    let _ = std::any::TypeId::of::<EntryKind>();
    let _ = std::any::TypeId::of::<EntryMetadata>();
    let _ = std::any::TypeId::of::<EntryReference>();
    let _ = std::any::TypeId::of::<FinishError<Vec<u8>>>();
    let _ = std::any::TypeId::of::<IncompleteWriter<Vec<u8>>>();
    let _ = std::any::TypeId::of::<OpenLimits>();
    let _ = std::any::TypeId::of::<ProcessingOptions>();
    let _ = std::any::TypeId::of::<WriteOptions>();
    let _ = std::any::TypeId::of::<WriterError>();
    let _ = std::any::TypeId::of::<WrittenEntry>();
    let _ = std::any::TypeId::of::<PrivateKey>();
    let _ = std::any::TypeId::of::<PublicKey>();
    let _ = std::any::TypeId::of::<CryptoError>();
    let _ = std::any::TypeId::of::<FsError>();
    let _ = std::any::TypeId::of::<InputManifest>();
    let _ = std::any::TypeId::of::<SourceError>();
    let _ = std::any::TypeId::of::<Crypt4GHError>();
    let _ = std::any::TypeId::of::<RoCrateError>();

    fn assert_source<T: ArchiveSource>() {}
    assert_source::<FileSource>();
    assert_source::<MemorySource>();
}

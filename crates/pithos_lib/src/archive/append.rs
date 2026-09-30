use super::{CdcConfig, ProcessingOptions, WriteOptions};
use crate::crypto::{PrivateKey, PublicKey};
use crate::error::PithosError;

/// Durability requested after a child directory has been flushed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppendDurability {
    /// Flush the terminal directory to the supplied file handle.
    Flush,
    /// Flush the terminal directory and request `sync_all` from the filesystem.
    SyncAll,
}

/// Options for a direct filesystem append.
pub struct AppendOptions {
    /// Private key used to open the existing archive and authorize the append.
    pub(crate) access_key: PrivateKey,
    pub(crate) recipients: Vec<PublicKey>,
    pub(crate) cdc: CdcConfig,
    pub(crate) durability: AppendDurability,
    pub(crate) processing: ProcessingOptions,
}

impl AppendOptions {
    /// Creates append options using `access_key` to open and authorize the existing archive.
    /// A fresh wrapping sender is generated for each child during filesystem append operations.
    pub fn new(access_key: PrivateKey, recipients: Vec<PublicKey>) -> Self {
        Self {
            access_key,
            recipients,
            cdc: CdcConfig::default(),
            durability: AppendDurability::Flush,
            processing: ProcessingOptions::append_default(),
        }
    }

    pub fn with_cdc(mut self, cdc: CdcConfig) -> Self {
        self.cdc = cdc;
        self
    }

    pub fn with_durability(mut self, durability: AppendDurability) -> Self {
        self.durability = durability;
        self
    }

    pub(crate) fn validate_recipients(&self) -> Result<(), PithosError> {
        WriteOptions::new(self.access_key.duplicate(), self.recipients.clone()).validate()
    }

    pub(crate) fn recipients_with_access_key(&self) -> Vec<PublicKey> {
        let access_public = self.access_key.public_key();
        let mut recipients = self.recipients.clone();
        if !recipients.contains(&access_public) {
            recipients.push(access_public);
        }
        recipients
    }
}

/// Measurements collected while validating and extending an archive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendObservation {
    pub source_read_count: u64,
    pub source_read_bytes: u64,
    pub base_archive_bytes: u64,
    pub final_archive_bytes: u64,
}

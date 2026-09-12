use crate::crypto::{self, FileKey, SharedSecret};
use std::fmt::{Display, Formatter};
use zeroize::Zeroizing;

use crate::error::PithosError;
use crate::format::entries::WireEntries;
use indexmap::IndexMap;
use x25519_dalek::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4], // MUST be b"PITH"
    pub version: u16,   // Format version (e.g., 0x0100 for 1.0)
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            magic: *b"PITH",
            version: Self::SUPPORTED_VERSION,
        }
    }
}

impl FileHeader {
    pub const ENCODED_LEN: usize = 6;
    pub const SUPPORTED_VERSION: u16 = 0x0100;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    pub marker: [u8; 4], // MUST be b"BLCK"
}

impl Default for BlockHeader {
    fn default() -> Self {
        BlockHeader { marker: *b"BLCK" }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessingFlags(pub u8);

impl ProcessingFlags {
    // Compression level can be set from 0-7 with the first three bits
    // 0 = Uncompressed
    // 7 = Highest compression
    const COMPRESSION_MASK: u8 = 0b0000_0111;

    // Encryption is indicated with the 4th bit
    const ENCRYPTION_MASK: u8 = 0b0000_1000;
    pub const RESERVED_MASK: u8 = 0b1111_0000;

    pub fn new(encrypted: bool, compression_level: Option<u8>) -> Self {
        // Init
        let mut flags = ProcessingFlags(0b0);

        // Set compression level
        match compression_level {
            Some(level) => {
                if level > Self::COMPRESSION_MASK {
                    flags.set_compression_level(Self::COMPRESSION_MASK) // Cap at maximum
                } else {
                    flags.set_compression_level(level)
                }
            }
            None => flags.set_compression_level(3), // Default
        }

        // Set encryption
        flags.set_encryption(encrypted);
        flags
    }

    pub fn from_byte(byte: u8) -> Self {
        ProcessingFlags(byte)
    }

    pub fn has_reserved_bits(&self) -> bool {
        self.0 & Self::RESERVED_MASK != 0
    }

    pub fn set_encryption(&mut self, encrypted: bool) {
        if encrypted {
            self.0 |= Self::ENCRYPTION_MASK; // Set bit for encryption
        } else {
            self.0 &= !Self::ENCRYPTION_MASK; // Clear bit for encryption
        }
    }

    // New function to check if encryption is enabled
    pub fn is_encrypted(&self) -> bool {
        (self.0 & Self::ENCRYPTION_MASK) != 0
    }

    pub fn set_compression_level(&mut self, mut compression_level: u8) {
        // Sanitize
        compression_level = if compression_level > Self::COMPRESSION_MASK {
            Self::COMPRESSION_MASK
        } else {
            compression_level
        };

        // Only use the lowest 3 bits (0-7)
        self.0 = (self.0 & !Self::COMPRESSION_MASK) | (compression_level & Self::COMPRESSION_MASK);
    }

    pub fn get_compression_level(&self) -> u8 {
        self.0 & Self::COMPRESSION_MASK
    }
}

impl Default for ProcessingFlags {
    fn default() -> Self {
        ProcessingFlags::new(true, None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLocation {
    Local,                    // Block data at specified offset in this file
    External { url: String }, // URL to external storage
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub offset: u64,             // varint
    pub stored_size: u64,        // varint
    pub original_size: u64,      // varint
    pub flags: ProcessingFlags,  // Compression, encryption settings
    pub location: BlockLocation, // Where block data resides
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub identifier: [u8; 8],                               // MUST be b"PITHOSDR"
    pub parent_directory_offset: Option<(u64, u64)>,       // (start, len) varint
    pub blocks: IndexMap<[u8; 32], BlockIndexEntry>,       // Blocks in this segment
    pub files: WireEntries,                                // Files in this segment
    pub relations: Vec<(u64, String)>,                     // Relation idx, relationname/id
    pub encryption: IndexMap<[u8; 32], EncryptionSection>, // (Sender's X25519 public key, section with recipients)
    pub dir_len: u64,
    pub crc32: u32, // CRC32 of all preceding fields
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    Directory = 0,
    Data = 1,
    Metadata = 2,
    Symlink = 3,
    // 4-255 reserved
}

/// A block's content hash and the key used to encrypt its content.
pub type BlockDataEntry = ([u8; 32], [u8; 32]);
pub(crate) type RecipientKeyList = Zeroizing<Vec<(u64, [u8; 32])>>;

/// Transient writer/reader wire state. Decrypted block keys are crate-private.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum BlockDataState {
    Encrypted(Vec<u8>),                        // Chacha + nonce (Random key)
    Decrypted(Zeroizing<Vec<BlockDataEntry>>), // BLAKE3 hash / Shake256 hash
}

impl std::fmt::Debug for BlockDataState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted(bytes) => formatter
                .debug_tuple("Encrypted")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Decrypted(entries) => formatter
                .debug_tuple("Decrypted")
                .field(&format_args!("{} block keys [REDACTED]", entries.len()))
                .finish(),
        }
    }
}

impl BlockDataState {
    pub(crate) fn encrypt_with_nonce(
        &mut self,
        key: &FileKey,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        match &self {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block already encrypted.".to_string(),
                ));
            }
            BlockDataState::Decrypted(entries) => {
                let mut data_bytes = Zeroizing::new(Vec::with_capacity(1 + entries.len() * 64));
                crate::format::codec::encode_decrypted_block_list(entries, &mut *data_bytes)?;
                let encrypted_data =
                    crypto::seal_file_block_list_with_nonce(key, &data_bytes, nonce)?;

                *self = BlockDataState::Encrypted(encrypted_data)
            }
        };

        Ok(())
    }
}

pub(crate) fn validate_unique_block_references(
    entries: &[BlockDataEntry],
) -> Result<(), PithosError> {
    let mut keys = std::collections::HashMap::with_capacity(entries.len());
    for (hash, key) in entries {
        if keys
            .insert(*hash, *key)
            .is_some_and(|existing| existing != *key)
        {
            return Err(PithosError::DuplicateBlockReference);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_type: FileType,
    pub(crate) block_data: BlockDataState,
    pub created: u64,
    pub modified: u64,
    pub file_size: u64,
    pub permissions: u32,
    pub references: Vec<Reference>,
    pub symlink_target: Option<String>, // Target path for symlinks
}

impl Display for FileEntry {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&format!("{:<12} {:?}\n", "Type:", self.file_type))?;
        match &self.block_data {
            BlockDataState::Encrypted(_) => f.write_str("Blocks:      Encrypted\n")?,
            BlockDataState::Decrypted(_) => f.write_str("Blocks:      Decrypted\n")?,
        }
        f.write_str(&format!("{:<12} {}\n", "Created:", self.created))?;
        f.write_str(&format!("{:<12} {}\n", "Modified:", self.modified))?;
        f.write_str(&format!("{:<12} {}\n", "Size:", self.file_size))?;
        f.write_str(&format!("{:<12} {:o}\n", "Permissions:", self.permissions))?;
        f.write_str(&format!("{:<12} {:?}\n", "References:", self.references))?;

        if let Some(target) = &self.symlink_target {
            f.write_str(&format!("{:<12} {target}\n", "Target:"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub target_file_id: u64, // varint
    pub relationship: u64,   // varint
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    // Recipient's X25519 public key, Recipient file list
    pub recipients: IndexMap<[u8; 32], RecipientSection>,
}

impl EncryptionSection {
    #[tracing::instrument(level = "trace", skip(recipient_pubkeys))]
    pub fn new(recipient_pubkeys: &[PublicKey]) -> Self {
        EncryptionSection {
            recipients: IndexMap::from_iter(
                recipient_pubkeys
                    .iter()
                    .map(|key| {
                        (
                            key.to_bytes(),
                            RecipientSection {
                                recipient_data: RecipientData::Decrypted(
                                    Zeroizing::new(Vec::new()),
                                ),
                            },
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSection {
    pub(crate) recipient_data: RecipientData, // Encrypted FileKeyEntry list
}

/// Transient writer/reader wire state. Recovered file keys are crate-private.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RecipientData {
    Encrypted(Vec<u8>), // Chacha + nonce (Shared key PrivKey Writer <--> PubKey Reader)
    Decrypted(RecipientKeyList), // Fileindex / Random key to decrypt BlockDataState
}

impl std::fmt::Debug for RecipientData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted(bytes) => formatter
                .debug_tuple("Encrypted")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Decrypted(entries) => formatter
                .debug_tuple("Decrypted")
                .field(&format_args!("{} file keys [REDACTED]", entries.len()))
                .finish(),
        }
    }
}

impl RecipientData {
    pub(crate) fn encrypt_with_secret_and_nonce(
        &mut self,
        shared_key: SharedSecret,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        match &self {
            RecipientData::Encrypted(_) => {
                return Err(PithosError::InvalidRecipientDataState(
                    "Recipient data already encrypted".to_string(),
                ));
            }
            RecipientData::Decrypted(entries) => {
                let mut data_bytes = Zeroizing::new(Vec::with_capacity(1 + entries.len() * 40));
                crate::format::codec::encode_decrypted_recipient_list(entries, &mut *data_bytes)?;

                let encrypted_data =
                    crypto::wrap_recipient_list_with_nonce(&shared_key, &data_bytes, nonce)?;

                *self = RecipientData::Encrypted(encrypted_data)
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod zeroization_tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn transient_plaintext_key_lists_have_drop_zeroization_contracts() {
        assert_zeroize_on_drop::<Zeroizing<Vec<BlockDataEntry>>>();
        assert_zeroize_on_drop::<Zeroizing<Vec<(u64, [u8; 32])>>>();
    }
}

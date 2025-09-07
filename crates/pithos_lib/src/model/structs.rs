use crate::helpers::chacha_poly1305::{decrypt_chunk, encrypt_chunk};
use crate::io::pithoswriter::Content;
use crate::io::util::{current_timestamp, get_symlink_target};

use crate::error::PithosError;
use indexmap::IndexMap;
use integer_encoding::VarIntWriter;
use rocrate::DataEntity;
use rocrate::entity::EntityTrait;
use std::fs::{Metadata, symlink_metadata};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;
use x25519_dalek::{PublicKey, SharedSecret};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub magic: [u8; 4], // MUST be b"PITH"
    pub version: u16,   // Format version (e.g., 0x0100 for 1.0)
}

impl Default for FileHeader {
    fn default() -> Self {
        FileHeader {
            magic: *b"PITH",
            version: 0x0100,
        }
    }
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
        // Init with byte
        let mut flags = ProcessingFlags(byte);
        // Clear unused bits
        flags.0 &= !(Self::COMPRESSION_MASK | Self::ENCRYPTION_MASK);
        flags
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
    //pub index: u64,              // varint
    //pub hash: [u8; 32],          // Blake3 hash
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
    pub files: Vec<FileEntry>,                             // Files in this segment
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

impl TryFrom<&Metadata> for FileType {
    type Error = PithosError;

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        Ok(if value.is_file() {
            FileType::Data
        } else if value.is_dir() {
            FileType::Directory
        } else if value.is_symlink() {
            FileType::Symlink
        } else {
            return Err(PithosError::Conversion(format!(
                "Invalid input file type: {:?}",
                value.file_type()
            )));
        })
    }
}

impl TryFrom<&DataEntity> for FileType {
    type Error = PithosError;

    fn try_from(value: &DataEntity) -> Result<Self, Self::Error> {
        if value.entity_type().contains(&"File".to_string()) {
            Ok(FileType::Data)
        } else if value.entity_type().contains(&"Dataset".to_string()) {
            Ok(FileType::Directory)
        } else {
            Err(PithosError::InvalidFileType(format!(
                "Data entity must have type File or Dataset: {:?}",
                value.entity_type()
            )))
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockDataState {
    Encrypted(Vec<u8>),                   // Chacha + nonce (Random key)
    Decrypted(Vec<([u8; 32], [u8; 32])>), // BLAKE3 hash / Shake256 hash
}

impl BlockDataState {
    pub fn encrypt(&mut self, key: [u8; 32]) -> Result<(), PithosError> {
        match &self {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block already encrypted.".to_string(),
                ));
            }
            BlockDataState::Decrypted(entries) => {
                let mut data_bytes = Vec::new();
                data_bytes.write_varint(entries.len())?;
                for (hash, key) in entries {
                    data_bytes.write_all(hash)?;
                    data_bytes.write_all(key)?;
                }
                let encrypted_data = encrypt_chunk(data_bytes.as_slice(), b"", &key)?;

                *self = BlockDataState::Encrypted(encrypted_data.to_vec())
            }
        };

        Ok(())
    }

    pub fn decrypt(&mut self, key: &[u8; 32]) -> Result<(), PithosError> {
        match &self {
            BlockDataState::Encrypted(data) => {
                let decrypted_bytes = decrypt_chunk(data, key)?;
                let block_data_entries =
                    self.deserialize_block_index(&mut decrypted_bytes.as_slice())?;

                *self = BlockDataState::Decrypted(block_data_entries);
            }
            BlockDataState::Decrypted(_) => {
                // Nothing to do
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_id: u64,
    pub path: String,
    pub file_type: FileType,
    pub block_data: BlockDataState,
    pub created: u64,
    pub modified: u64,
    pub file_size: u64,
    pub permissions: u32,
    pub references: Vec<Reference>,
    pub symlink_target: Option<String>, // Target path for symlinks
}

impl FileEntry {
    pub fn new(
        file_id: Option<u64>,
        file_type: FileType,
        disk_path: &str,
        pithos_path: &str,
        metadata: &Metadata,
    ) -> Result<Self, PithosError> {
        Ok(FileEntry {
            file_id: file_id.unwrap_or(0),
            path: pithos_path.to_string(),
            file_type,
            block_data: BlockDataState::Decrypted(vec![]),
            created: metadata
                .created()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            modified: metadata
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            file_size: metadata.len(),
            permissions: metadata.permissions().mode(),
            references: vec![],
            symlink_target: if file_type == FileType::Symlink {
                Some(std::fs::read_link(disk_path)?.to_string_lossy().to_string())
            } else {
                None
            },
        })
    }

    pub fn new_ext(
        file_id: Option<u64>,
        file_type: FileType,
        disk_path: &str,
        pithos_path: &str,
        created: Option<SystemTime>,
        modified: Option<SystemTime>,
        permissions: Option<u32>,
        references: Vec<Reference>,
        file_size: Option<u64>,
    ) -> Result<Self, PithosError> {
        Ok(FileEntry {
            file_id: file_id.unwrap_or(0),
            path: pithos_path.to_string(),
            file_type,
            block_data: BlockDataState::Decrypted(vec![]),
            created: created
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            modified: modified
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            file_size: file_size.unwrap_or(0),
            permissions: permissions.unwrap_or(0o644),
            references,
            symlink_target: if file_type == FileType::Symlink {
                Some(std::fs::read_link(disk_path)?.to_string_lossy().to_string())
            } else {
                None
            },
        })
    }

    pub fn new_from_content(
        file_id: Option<u64>,
        file_type: FileType,
        pithos_path: &str,
        content: &Content,
    ) -> Result<Self, PithosError> {
        Ok(match content {
            Content::File(disk_path) => {
                let file_metadata = symlink_metadata(disk_path)?;
                FileEntry::new(file_id, file_type, disk_path, pithos_path, &file_metadata)?
            }
            Content::Raw(raw_content) => {
                let current_timestamp = current_timestamp()?;
                FileEntry {
                    file_id: file_id.unwrap_or(0),
                    path: pithos_path.to_string(),
                    file_type,
                    block_data: BlockDataState::Decrypted(vec![]),
                    created: current_timestamp,
                    modified: current_timestamp,
                    file_size: raw_content.len() as u64,
                    permissions: 0o644,
                    references: vec![],
                    symlink_target: None,
                }
            }
            Content::Reference(_) => {
                unimplemented!("Currently FileEntry cannot be created from Content::Reference")
            }
        })
    }

    pub fn new_from_file(
        file_id: u64,
        path: String,
        file: &std::fs::File,
        metadata: Metadata,
    ) -> Result<Self, PithosError> {
        // Evaluate file type and create file entry
        let file_type = FileType::try_from(&metadata)?;
        Ok(FileEntry {
            file_id,
            path: path.clone(),
            file_type,
            block_data: BlockDataState::Decrypted(Vec::new()),
            created: metadata
                .created()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            modified: metadata
                .modified()
                .unwrap_or(SystemTime::UNIX_EPOCH)
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
            file_size: metadata.len(),
            permissions: metadata.permissions().mode(),
            references: vec![],
            symlink_target: if file_type == FileType::Symlink {
                Some(get_symlink_target(file)?)
            } else {
                None
            },
        })
    }

    pub fn meta_from(other_file: &FileEntry, meta_length: u64) -> Result<Self, PithosError> {
        Ok(FileEntry {
            file_id: other_file.file_id - 1,
            path: format!("{}.meta", other_file.path),
            file_type: FileType::Metadata,
            block_data: BlockDataState::Decrypted(Vec::new()),
            created: current_timestamp()?, // Just inherit from other file?
            modified: current_timestamp()?, // Just inherit from other file?
            file_size: meta_length,
            permissions: other_file.permissions,
            references: vec![Reference {
                target_file_id: other_file.file_id,
                relationship: 0,
            }],
            symlink_target: None,
        })
    }

    pub fn set_file_id(&mut self, file_id: u64) {
        self.file_id = file_id;
    }

    pub fn add_block_data(&mut self, entry: ([u8; 32], [u8; 32])) -> Result<(), PithosError> {
        match self.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block data already/still encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(ref mut entries) => {
                entries.push(entry);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    pub target_file_id: u64, // varint
    pub relationship: u64,   // varint
}

impl TryFrom<&mut FileEntry> for Reference {
    type Error = PithosError;

    fn try_from(value: &mut FileEntry) -> Result<Self, Self::Error> {
        Ok(Reference {
            target_file_id: value.file_id,
            relationship: match value.file_type {
                FileType::Directory => 6, // PART_OF
                FileType::Data => 7,      // DERIVED_FROM
                FileType::Metadata => 0,  // DESCRIBES
                FileType::Symlink => 3,   // SOURCE
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    // Recipient's X25519 public key, Recipient file list
    pub recipients: IndexMap<[u8; 32], RecipientSection>,
}

impl EncryptionSection {
    pub fn new(recipient_pubkeys: &[PublicKey]) -> Self {
        EncryptionSection {
            recipients: IndexMap::from_iter(
                recipient_pubkeys
                    .iter()
                    .map(|key| {
                        (
                            key.to_bytes(),
                            RecipientSection {
                                recipient_data: RecipientData::Decrypted(Vec::new()),
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
    pub recipient_data: RecipientData, // Encrypted FileKeyEntry list
}

impl RecipientSection {
    pub fn add_file_to_recipient(&mut self, entry: (u64, [u8; 32])) -> Result<(), PithosError> {
        match self.recipient_data {
            RecipientData::Encrypted(_) => Err(PithosError::InvalidRecipientDataState(
                "Cannot add file entry to encrypted recipient data".to_string(),
            )),
            RecipientData::Decrypted(ref mut entries) => {
                let _: () = entries.push(entry);
                Ok(())
            }
        }
    }

    pub fn encrypt(&mut self, shared_key: SharedSecret) -> Result<(), PithosError> {
        match &self.recipient_data {
            RecipientData::Encrypted(_) => {
                return Err(PithosError::InvalidRecipientDataState(
                    "Recipient data already encrypted".to_string(),
                ));
            }
            RecipientData::Decrypted(entries) => {
                let mut data_bytes = Vec::new();
                data_bytes.write_varint(entries.len())?;
                for (idx, key) in entries {
                    data_bytes.write_varint(*idx)?;
                    data_bytes.write_all(key)?;
                }

                let encrypted_data =
                    encrypt_chunk(data_bytes.as_slice(), b"", shared_key.as_bytes())?;

                self.recipient_data = RecipientData::Encrypted(encrypted_data.to_vec())
            }
        };

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientData {
    Encrypted(Vec<u8>), // Chacha + nonce (Shared key PrivKey Writer <--> PubKey Reader)
    Decrypted(Vec<(u64, [u8; 32])>), // Fileindex / Random key to decrypt BlockDataState
}

impl RecipientData {
    pub fn encrypt(&mut self, shared_key: &SharedSecret) -> Result<(), PithosError> {
        match &self {
            RecipientData::Encrypted(_) => {
                return Err(PithosError::InvalidRecipientDataState(
                    "Recipient data already encrypted".to_string(),
                ));
            }
            RecipientData::Decrypted(entries) => {
                let mut data_bytes = Vec::new();
                data_bytes.write_varint(entries.len())?;
                for (idx, key) in entries {
                    data_bytes.write_varint(*idx)?;
                    data_bytes.write_all(key)?;
                }

                let encrypted_data =
                    encrypt_chunk(data_bytes.as_slice(), b"", shared_key.as_bytes())?;

                *self = RecipientData::Encrypted(encrypted_data.to_vec())
            }
        };

        Ok(())
    }

    pub fn decrypt(
        &mut self,
        shared_key: &SharedSecret,
    ) -> Result<Vec<(u64, [u8; 32])>, PithosError> {
        let entries = match &self {
            RecipientData::Decrypted(entries) => entries.clone(),
            RecipientData::Encrypted(enc_data) => {
                let dec_data = decrypt_chunk(enc_data, shared_key.as_bytes())?;
                let entries = self.deserialize_decrypted_list(&mut dec_data.as_slice())?;

                *self = RecipientData::Decrypted(entries.clone());
                entries
            }
        };

        Ok(entries)
    }
}

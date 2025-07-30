// Struct and enum definitions for PITHOS serialization.
// Extracted from serialization.rs for modularity.
//
// Import deserialization implementations from helpers/deserialization.rs
pub use crate::model::deserialization::*;

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
    const COMPRESSION_MASK: u8    = 0b0000_0111;

    // Encryption is toggled with the 4th bit
    const ENCRYPTION_MASK: u8     = 0b0000_1000;
    
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

    pub fn set_compression_level(&mut self, compression_level: u8) {
        // Only use the lowest 3 bits (0-7)
        self.0 = (self.0 & !Self::COMPRESSION_MASK) | (compression_level & Self::COMPRESSION_MASK);
    }

    pub fn get_compression_level(&self) -> u8 {
        self.0 & Self::COMPRESSION_MASK
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockLocation {
    Local,                    // Block data at specified offset in this file
    External { url: String }, // URL to external storage //TODO: Auth?
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndexEntry {
    pub index: u64,              // varint
    pub hash: [u8; 32],          // Blake3 hash
    pub offset: u64,             // varint
    pub stored_size: u64,        // varint
    pub original_size: u64,      // varint
    pub flags: ProcessingFlags,  // Compression, encryption settings
    pub location: BlockLocation, // Where block data resides
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub identifier: [u8; 8],                         // MUST be b"PITHOSDR"
    pub parent_directory_offset: Option<(u64, u64)>, // (start, len) varint
    pub files: Vec<FileEntry>,                       // Files in this segment
    pub blocks: Vec<BlockIndexEntry>,                // Blocks in this segment
    pub relations: Vec<(u64, String)>,               // Relation idx, relationname/id
    pub encryption: Vec<EncryptionSection>,
    pub dir_len: u64,
    pub crc32: u32, // CRC32 of all preceding fields
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Data = 0,
    Metadata = 1,
    Directory = 2,
    Symlink = 3,
    // 4-255 reserved
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockDataState {
    Encrypted(Vec<u8>),              // Chacha + nonce (Random key)
    Decrypted(Vec<(u64, [u8; 32])>), // Index / Shake256 hash
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub file_id: u64,        // varint
    pub path: String,        // UTF-8 + varint
    pub file_type: FileType, // u8
    pub block_data: BlockDataState,
    pub created: u64,                   // u64 (BE)
    pub modified: u64,                  // u64 (BE)
    pub file_size: u64,                 // varint
    pub permissions: u32,               // u32 (BE)
    pub references: Vec<Reference>,     // Data->Metadata references only
    pub symlink_target: Option<String>, // Target path for symlinks
}

impl FileEntry {
    pub fn new(file_id: u64, path: &str, metadata: Metadata) -> Result<Self, SystemTimeError> {
        Ok(FileEntry {
            file_id,
            path: path.to_string(),
            file_type: FileType::Data, //TODO: Directory ingestion
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
            symlink_target: None,
        })
    }

    pub fn add_block_data(&mut self, entry: (u64, [u8; 32])) -> Result<(), PithosWriterError> {
        match self.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosWriterError::InvalidBlockDataState(
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    pub sender_public_key: [u8; 32],       // X25519 public key
    pub recipients: Vec<RecipientSection>, // Per-recipient data
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecipientData {
    Encrypted(Vec<u8>), // Chacha + nonce (Shared key PrivKey Writer <--> PubKey Reader)
    Decrypted(Vec<(u64, [u8; 32])>), // Fileindex / Random key to decrypt BlockDataState
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSection {
    pub recipient_public_key: [u8; 32], // Recipient's X25519 public key
    pub recipient_data: RecipientData,  // Encrypted FileKeyEntry list
}

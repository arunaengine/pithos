use crate::helpers::notifications::DirOrFileIdx;
use crate::helpers::structs::{EncryptionKey, FileContext, Range};
use anyhow::{anyhow, Result};
use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use chacha20poly1305::{AeadCore, Nonce};
use crypto_kx::{Keypair, PublicKey, SecretKey};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::Display;

pub const ZSTD_MAGIC_BYTES: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_0: [u8; 4] = [0x50, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_1: [u8; 4] = [0x51, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_2: [u8; 4] = [0x52, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_3: [u8; 4] = [0x53, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_4: [u8; 4] = [0x54, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_5: [u8; 4] = [0x55, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_6: [u8; 4] = [0x56, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_7: [u8; 4] = [0x57, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_8: [u8; 4] = [0x58, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_9: [u8; 4] = [0x59, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_10: [u8; 4] = [0x5A, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_11: [u8; 4] = [0x5B, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_12: [u8; 4] = [0x5C, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_13: [u8; 4] = [0x5D, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_14: [u8; 4] = [0x5E, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_SKIPPABLE_15: [u8; 4] = [0x5F, 0x2A, 0x4D, 0x18];
pub const ZSTD_MAGIC_BYTES_ALL: [[u8; 4]; 17] = [
    ZSTD_MAGIC_BYTES,
    ZSTD_MAGIC_BYTES_SKIPPABLE_0,
    ZSTD_MAGIC_BYTES_SKIPPABLE_1,
    ZSTD_MAGIC_BYTES_SKIPPABLE_2,
    ZSTD_MAGIC_BYTES_SKIPPABLE_3,
    ZSTD_MAGIC_BYTES_SKIPPABLE_4,
    ZSTD_MAGIC_BYTES_SKIPPABLE_5,
    ZSTD_MAGIC_BYTES_SKIPPABLE_6,
    ZSTD_MAGIC_BYTES_SKIPPABLE_7,
    ZSTD_MAGIC_BYTES_SKIPPABLE_8,
    ZSTD_MAGIC_BYTES_SKIPPABLE_9,
    ZSTD_MAGIC_BYTES_SKIPPABLE_10,
    ZSTD_MAGIC_BYTES_SKIPPABLE_11,
    ZSTD_MAGIC_BYTES_SKIPPABLE_12,
    ZSTD_MAGIC_BYTES_SKIPPABLE_13,
    ZSTD_MAGIC_BYTES_SKIPPABLE_14,
    ZSTD_MAGIC_BYTES_SKIPPABLE_15,
];

pub const EOF_META_LEN: usize = 73;

// -------------- EndOfFileMetadata --------------

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct EndOfFileMetadata {
    // 73 Bytes
    pub magic_bytes: [u8; 4], // Should be 0x50, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub version: u8,
    pub raw_file_size: u64,
    pub disk_file_size: u64,
    pub disk_hash_sha256: [u8; 32], // Everything except disk_hash_sha256 is expected to be 0
    pub toc_len: u64,
    pub encryption_len: u64,
}

impl Display for EndOfFileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "==== EndOfFileMetadata ====")?;
        writeln!(f, "Len: {}", self.len)?;
        writeln!(f, "Version: {}", self.version)?;
        writeln!(f, "Raw file size: {}", self.raw_file_size)?;
        writeln!(f, "Disk file size: {}", self.disk_file_size)?;
        writeln!(f, "Disk hash SHA256: {:?}", self.disk_hash_sha256)?;
        writeln!(f, "ToC len: {:?}", self.toc_len)?;
        writeln!(f, "Encryption Info len: {:?}", self.encryption_len)?;
        Ok(())
    }
}

impl Default for EndOfFileMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl EndOfFileMetadata {
    pub fn new() -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_0,
            len: EOF_META_LEN as u32,
            version: 1,
            raw_file_size: 0,
            disk_file_size: 0,
            disk_hash_sha256: [0; 32],
            toc_len: 0,
            encryption_len: 0,
        }
    }
}

// -------------- EncryptionMetadata --------------

#[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptionMetadata {
    pub magic_bytes: [u8; 4], // Should be 0x51, 0x2A, 0x4D, 0x18
    pub len: u32,             // Required for zstd skippable frame
    pub packets: Vec<EncryptionPacket>,
}

impl Default for EncryptionMetadata {
    fn default() -> Self {
        Self::new()
    }
}

impl EncryptionMetadata {
    pub fn new() -> Self {
        EncryptionMetadata {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_1,
            len: 0,
            packets: vec![],
        }
    }

    pub fn add_packet(&mut self, packet: EncryptionPacket) {
        self.len += packet.len();
        self.packets.push(packet);
    }
}

impl
    TryFrom<(
        Option<[u8; 32]>, // Writer private key if provided
        &HashMap<[u8; 32], HashMap<[u8; 32], DirOrFileIdx>>,
    )> for EncryptionMetadata
{
    type Error = anyhow::Error;

    fn try_from(
        value: (
            Option<[u8; 32]>,
            &HashMap<[u8; 32], HashMap<[u8; 32], DirOrFileIdx>>,
        ),
    ) -> Result<Self> {
        let mut packets = vec![];
        let mut len = 0;
        for (pubkey, keylist) in value.1 {
            let decrypted_key = DecryptedKeys {
                keys: keylist.iter().map(|(k, v)| (*k, *v)).collect(),
            };
            let packet = decrypted_key.encrypt(*pubkey, value.0)?;
            len += packet.len();
            packets.push(packet);
        }

        Ok(EncryptionMetadata {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_1,
            len,
            packets,
        })
    }
}

// Key <-> Index: LastUse
// F0, F1, F2, F3
// K0 -> F0, F1 -> DirOrFileIdx::File(1)
// K2 -> F2, F3 -> DirOrFileIdx::File(3)
#[derive(Debug, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct DecryptedKeys {
    pub keys: Vec<([u8; 32], DirOrFileIdx)>,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct EncryptionPacket {
    pub pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub keys: Vec<u8>,
    pub mac: [u8; 16],
}

impl EncryptionPacket {
    fn len(&self) -> u32 {
        (32 + 12 + self.keys.len() + 16) as u32
    }

    pub fn decrypt(self, private_key: &[u8; 32]) -> Option<DecryptedKeys> {
        let keypair = Keypair::from(SecretKey::from(*private_key));
        let writers_pub_key = PublicKey::from(self.pubkey);
        let session_key = keypair.session_keys_from(&writers_pub_key).rx;

        // Re-combine payload and mac before decryption
        let encrypted_payload = [self.keys, self.mac.to_vec()].concat();
        let decrypted = ChaCha20Poly1305::new_from_slice(session_key.as_ref().as_slice())
            .ok()?
            .decrypt(
                Nonce::from_slice(self.nonce.as_ref()),
                encrypted_payload.as_slice(),
            )
            .ok()?;

        borsh::from_slice(&decrypted).ok()
    }
}

impl DecryptedKeys {
    pub fn encrypt(
        &self,
        readers_pubkey: [u8; 32],
        writers_private_key: Option<[u8; 32]>,
    ) -> Result<EncryptionPacket> {
        let keypair = match writers_private_key {
            Some(key) => Keypair::from(SecretKey::from(key)),
            None => Keypair::generate(&mut OsRng),
        };
        let readers_pub_key = PublicKey::from(readers_pubkey);
        let session_key = keypair.session_keys_to(&readers_pub_key).tx;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let as_bytes = borsh::to_vec(&self)?;

        let data: Vec<u8> = ChaCha20Poly1305::new_from_slice(session_key.as_ref().as_slice())
            .map_err(|_| anyhow!("Invalid key length"))?
            .encrypt(&nonce, as_bytes.as_slice())
            .map_err(|_| anyhow!("Error while encrypting keys"))?;
        let (data, mac) = data.split_at(data.len() - 16);

        Ok(EncryptionPacket {
            pubkey: *keypair.public().as_ref(),
            nonce: nonce.as_slice().try_into()?,
            keys: data.to_vec(),
            mac: mac.try_into()?,
        })
    }

    pub fn add_keys(&mut self, other_keys: DecryptedKeys) {
        self.keys = self
            .keys
            .clone()
            .into_iter()
            .interleave(other_keys.keys)
            .collect_vec();
        self.keys.dedup();
    }
}

// -------------- FileContextHeader --------------

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize,  PartialEq, Debug, Clone, Eq, PartialOrd, Ord)]
pub struct FileInfo {
    pub uid: Option<u64>,   // UserId
    pub gid: Option<u64>,   // GroupId
    pub mode: Option<u32>,  // Octal like mode
    pub mtime: Option<u64>, // Created at
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Debug, Clone, Eq, PartialOrd, Ord)]
pub struct Hashes {
    pub sha256: Option<[u8; 32]>,
    pub md5: Option<[u8; 16]>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, PartialEq, Debug, Clone, Eq, PartialOrd, Ord)]
pub struct SymlinkContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
}

#[derive(BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Eq, PartialOrd, Ord, PartialEq, Debug)]
pub struct CustomRange {
    pub tag: String,
    pub start: u64,
    pub end: u64,
}

#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct FileContextHeader {
    pub file_path: String, // FilePath empty = SKIP
    pub raw_size: u64,
    pub file_start: u64,
    pub file_end: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub block_scale: u32, // ChaCha / Compression block scale, should be a multiple of 65536 (default = 1);
    pub index_list: Option<Vec<u32>>, // Compressed size of every chunk in order (only if compressed); MAX: 83_886_080, Max raw Blocksize 4GiB
    pub file_info: Option<FileInfo>,
    pub hashes: Option<Hashes>,
    pub metadata: Option<String>,
    pub symlinks: Option<Vec<SymlinkContextHeader>>,
    pub custom_ranges: Option<Vec<CustomRange>>,
}

impl FileContextHeader {
    pub fn try_into_file_context(self, idx: usize) -> Result<FileContext> {
        Ok(FileContext {
            idx,
            file_path: self.file_path,
            compressed_size: self.file_end - self.file_start,
            decompressed_size: self.raw_size,
            uid: self.file_info.as_ref().and_then(|x| x.uid),
            gid: self.file_info.as_ref().and_then(|x| x.gid),
            mode: self.file_info.as_ref().and_then(|x| x.mode),
            mtime: self.file_info.as_ref().and_then(|x| x.mtime),
            compression: self.compressed,
            chunk_multiplier: Some(self.block_scale),
            encryption_key: EncryptionKey::None,
            recipients_pubkeys: vec![],
            is_dir: false,
            symlink_target: None,
            expected_sha256: self
                .hashes
                .as_ref()
                .and_then(|x| x.sha256.and_then(|x| Some(hex::encode(x.as_slice())))),
            expected_md5: self
                .hashes
                .as_ref()
                .and_then(|x| x.md5.and_then(|x| Some(hex::encode(x.as_slice())))),
            semantic_metadata: self.metadata,
            custom_ranges: self.custom_ranges,
        })
    }

    #[allow(dead_code)]
    pub fn get_range_and_filter_by_range(&self, range: Range) -> (Range, Vec<u64>) {
        let mut edit_list = vec![];
        let size = range.to - range.from;
        let mut new_range = Range { from: 0, to: 0 };
        let mut start_block = 0;
        let mut end_block = 0;
        let block_size = if self.encrypted {
            self.block_scale as u64 * (65536 + 28)
        } else {
            self.block_scale as u64 * 65536
        };
        if self.compressed {
            if let Some(idx_list) = self.index_list.as_ref() {
                let mut sum = 0;
                for (i, r) in idx_list.iter().enumerate() {
                    sum += *r as u64;
                    if sum >= range.from {
                        if edit_list.is_empty() {
                            start_block = i as u64;
                            edit_list.push(range.from.saturating_sub(sum - *r as u64));
                        }
                    }
                    if sum >= range.to {
                        end_block = (i as u64) + 1;
                        break;
                    }
                }
            }
        } else {
            start_block = range.from / 65536;
            end_block = (range.to / 65536) + 1;
            edit_list.push(range.from % 65536);
        }

        edit_list.push(size);

        new_range.from = start_block * block_size;
        new_range.to = end_block * block_size;
        (new_range, edit_list)
    }
}

impl TryFrom<FileContext> for FileContextHeader {
    type Error = anyhow::Error;

    fn try_from(ctx: FileContext) -> Result<Self> {
        Ok(Self {
            file_path: ctx.file_path.clone(),
            raw_size: ctx.decompressed_size,
            file_start: 0,
            file_end: 0,
            compressed: ctx.compression,
            encrypted: ctx.encryption_key.data_encrypted(),
            block_scale: ctx.chunk_multiplier.unwrap_or(1),
            index_list: None,
            file_info: Option::from(&ctx),
            hashes: ctx.get_hashes()?,
            metadata: ctx.semantic_metadata,
            symlinks: None,
            custom_ranges: ctx.custom_ranges,
        })
    }
}

impl FileContextHeader {
    pub fn update_range(&mut self, offset: u64) -> u64 {
        self.file_start = offset;
        let tmp_end = self.file_end;
        self.file_end = tmp_end + offset;

        tmp_end
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DirContextHeader {
    pub file_path: String, // FileName /foo/bar/
    pub file_info: Option<FileInfo>,
    pub symlinks: Option<Vec<SymlinkContextHeader>>,
    pub metadata: Option<String>,
}

impl From<FileContext> for DirContextHeader {
    fn from(ctx: FileContext) -> Self {
        Self {
            file_path: ctx.file_path.clone(),
            file_info: Option::from(&ctx),
            symlinks: None,
            metadata: ctx.semantic_metadata,
        }
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize,  Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileContextVariants {
    FileDecrypted(FileContextHeader),
    FileEncrypted(Vec<u8>),
}

impl FileContextVariants {
    pub fn encrypt(&mut self, key: &Option<[u8; 32]>) -> Result<()> {
        if let Some(key) = key {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let as_bytes = borsh::to_vec(self)?;
            let data: Vec<u8> = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("Invalid key length"))?
                .encrypt(&nonce, as_bytes.as_slice())
                .map_err(|_| anyhow!("Error while encrypting keys"))?;
            *self = FileContextVariants::FileEncrypted(
                nonce.to_vec().into_iter().chain(data).collect(),
            );
        }
        Ok(())
    }

    pub fn decrypt(&mut self, key: [u8; 32]) -> Option<()> {
        if let FileContextVariants::FileEncrypted(data) = self {
            let (nonce, data) = data.split_at(12);
            let decrypted: Vec<u8> = ChaCha20Poly1305::new_from_slice(key.as_slice())
                .ok()?
                .decrypt(Nonce::from_slice(nonce), data)
                .ok()?;
            let deserialized: FileContextVariants = borsh::from_slice(&decrypted).ok()?;
            *self = deserialized;
        }
        Some(())
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, FileContextVariants::FileEncrypted(_))
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum DirContextVariants {
    DirDecrypted(DirContextHeader),
    DirEncrypted(Vec<u8>),
}

impl DirContextVariants {
    pub fn encrypt(&mut self, key: &Option<[u8; 32]>) -> Result<()> {
        if let Some(key) = key {
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let as_bytes = borsh::to_vec(self)?;
            let data: Vec<u8> = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| anyhow!("Invalid key length"))?
                .encrypt(&nonce, as_bytes.as_slice())
                .map_err(|_| anyhow!("Error while encrypting keys"))?;
            *self = DirContextVariants::DirEncrypted(nonce.into_iter().chain(data).collect());
        }
        Ok(())
    }

    pub fn decrypt(&mut self, key: [u8; 32]) -> Option<()> {
        if let DirContextVariants::DirEncrypted(data) = self {
            let (nonce, data) = data.split_at(12);
            let decrypted: Vec<u8> = ChaCha20Poly1305::new_from_slice(key.as_slice())
                .ok()?
                .decrypt(Nonce::from_slice(nonce), data)
                .ok()?;

            let deserialized: DirContextVariants = borsh::from_slice(&decrypted).ok()?;
            *self = deserialized;
        }
        Some(())
    }
    pub fn is_encrypted(&self) -> bool {
        matches!(self, DirContextVariants::DirEncrypted(_))
    }
}

#[derive(BorshDeserialize, BorshSerialize, Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TableOfContents {
    pub magic_bytes: [u8; 4], // Should be 0x53, 0x2A, 0x4D, 0x18
    pub len: u32,
    pub directories: Vec<DirContextVariants>,
    pub files: Vec<FileContextVariants>,
}

impl Default for TableOfContents {
    fn default() -> Self {
        Self::new()
    }
}

impl TableOfContents {
    pub fn new() -> Self {
        Self {
            magic_bytes: ZSTD_MAGIC_BYTES_SKIPPABLE_2,
            len: 0,
            directories: Vec::new(),
            files: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::default;

    use super::*;
    use crate::helpers::structs::Range;

    #[test]
    fn test_file_context_header_try_into_file_context() {
        let file_context_header = FileContextHeader {
            file_path: "test".to_string(),
            raw_size: 100,
            file_start: 0,
            file_end: 100,
            compressed: false,
            encrypted: false,
            block_scale: 1,
            index_list: None,
            file_info: None,
            hashes: None,
            metadata: None,
            symlinks: None,
            custom_ranges: None,
        };
        let file_context = file_context_header.try_into_file_context(0).unwrap();
        assert_eq!(file_context.idx, 0);
        assert_eq!(file_context.file_path, "test");
        assert_eq!(file_context.compressed_size, 100);
        assert_eq!(file_context.decompressed_size, 100);
        assert_eq!(file_context.compression, false);
        assert_eq!(file_context.chunk_multiplier, Some(1));
        assert_eq!(file_context.encryption_key, EncryptionKey::None);
        assert_eq!(file_context.is_dir, false);
        assert_eq!(file_context.symlink_target, None);
        assert_eq!(file_context.expected_sha256, None);
        assert_eq!(file_context.expected_md5, None);
        assert_eq!(file_context.semantic_metadata, None);
        assert_eq!(file_context.custom_ranges, None);
    }

    #[test]
    fn test_file_context_header_get_range_and_filter_by_range() {
        let file_context_header = FileContextHeader {
            file_path: "test".to_string(),
            raw_size: 128000,
            file_start: 0,
            file_end: 128000,
            compressed: false,
            encrypted: false,
            block_scale: 1,
            ..default::Default::default()
        };
        let (range, edit_list) =
            file_context_header.get_range_and_filter_by_range(Range { from: 0, to: 100 });
        assert_eq!(range.from, 0);
        assert_eq!(range.to, 65536);
        assert_eq!(edit_list, vec![0, 100]);

        let file_context_header = FileContextHeader {
            file_path: "test".to_string(),
            raw_size: 128000,
            file_start: 0,
            file_end: 128000,
            compressed: true,
            encrypted: true,
            block_scale: 1,
            index_list: Some(vec![50, 123455]),
            ..default::Default::default()
        };
        let (range, edit_list) = file_context_header.get_range_and_filter_by_range(Range {
            from: 100,
            to: 1000,
        });
        assert_eq!(range.from, 65564);
        assert_eq!(range.to, 65564 * 2);
        assert_eq!(edit_list, vec![50, 900]);
    }
}

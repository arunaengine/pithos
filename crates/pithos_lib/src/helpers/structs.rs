use std::os::unix::fs::MetadataExt;
use std::{num::ParseIntError, path::PathBuf};

use crate::pithos::structs::{CustomRange, FileInfo, Hashes};
use anyhow::{anyhow, bail, Result};
use tokio::fs::{read_link, File};
use tokio_util::io::ReaderStream;

#[derive(Debug, PartialEq, Default, Clone)]
pub enum ProbeResult {
    #[default]
    Unknown,
    Compression,
    NoCompression,
}

#[derive(Eq, PartialEq, PartialOrd, Ord, Clone, Copy, Debug)]
pub struct Range {
    pub from: u64,
    pub to: u64,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum EncryptionKey {
    #[default]
    None,
    Same([u8; 32]),
    DataOnly([u8; 32]),
    Individual(([u8; 32], [u8; 32])),
}

impl EncryptionKey {
    pub fn new_same_key(key: [u8; 32]) -> Self {
        EncryptionKey::Same(key)
    }

    pub fn new_data_only_key(key: [u8; 32]) -> Self {
        EncryptionKey::DataOnly(key)
    }

    pub fn new_individual_key(key: [u8; 32], key2: [u8; 32]) -> Self {
        EncryptionKey::Individual((key, key2))
    }

    pub fn data_encrypted(&self) -> bool {
        match self {
            EncryptionKey::None => false,
            EncryptionKey::Same(_) => true,
            EncryptionKey::DataOnly(_) => true,
            EncryptionKey::Individual((_, _)) => true,
        }
    }

    pub fn get_data_key(&self) -> Option<[u8; 32]> {
        match self {
            EncryptionKey::None => None,
            EncryptionKey::Same(key) => Some(*key),
            EncryptionKey::DataOnly(key) => Some(*key),
            EncryptionKey::Individual((key, _)) => Some(*key),
        }
    }

    pub fn into_keys(&self) -> Vec<[u8; 32]> {
        let result: Vec<[u8; 32]> = match &self {
            EncryptionKey::None => vec![],
            EncryptionKey::Same(key) => vec![*key],
            EncryptionKey::DataOnly(key) => vec![*key],
            EncryptionKey::Individual((key, key2)) => {
                vec![*key, *key2]
            }
        };

        result
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub struct FileContext {
    pub idx: usize,
    // FileName
    pub file_path: String,
    // Input size compressed
    pub compressed_size: u64,
    // Filesize decompressed
    pub decompressed_size: u64,
    // UserId
    pub uid: Option<u64>,
    // GroupId
    pub gid: Option<u64>,
    // Octal like mode
    pub mode: Option<u32>,
    // Created at
    pub mtime: Option<u64>,
    // Should this file be skipped by decompressors
    pub compression: bool,
    // ChunkMultiplier num or 1
    pub chunk_multiplier: Option<u32>,
    // Encryption Key(s)
    pub encryption_key: EncryptionKey,
    // Recipients pubkeys
    pub recipients_pubkeys: Vec<[u8; 32]>,
    // Is this file a directory
    pub is_dir: bool,
    // Is this file a symlink
    pub symlink_target: Option<String>,
    // Expected SHA256 hash
    pub expected_sha256: Option<String>,
    // Expected MD5 hash
    pub expected_md5: Option<String>,
    // Semantic Metadata
    pub semantic_metadata: Option<String>,
    // Custom Ranges
    pub custom_ranges: Option<Vec<CustomRange>>,
}

impl From<FileContext> for Option<FileInfo> {
    fn from(val: FileContext) -> Self {
        if val.uid.is_some() || val.gid.is_some() || val.mode.is_some() || val.mtime.is_some() {
            return Some(FileInfo {
                uid: val.uid,
                gid: val.gid,
                mode: val.mode,
                mtime: val.mtime,
            });
        }
        None
    }
}

impl From<&FileContext> for Option<FileInfo> {
    fn from(value: &FileContext) -> Self {
        if value.uid.is_some()
            || value.gid.is_some()
            || value.mode.is_some()
            || value.mtime.is_some()
        {
            return Some(FileInfo {
                uid: value.uid,
                gid: value.gid,
                mode: value.mode,
                mtime: value.mtime,
            });
        }
        None
    }
}

impl FileContext {
    #[tracing::instrument(level = "trace", skip(self))]
    pub fn get_hashes(&self) -> Result<Option<Hashes>> {
        if self.expected_sha256.is_none() && self.expected_sha256.is_none() {
            return Ok(None);
        }

        let mut hashes = Hashes {
            sha256: None,
            md5: None,
        };

        // Validate hash lengths?

        if let Some(sha256) = &self.expected_sha256 {
            let sha256_bytes: [u8; 32] = decode_hex(sha256)?
                .try_into()
                .map_err(|_| anyhow!("Provided SHA256 has invalid length"))?;
            hashes.sha256 = Some(sha256_bytes);
        }
        if let Some(md5) = &self.expected_md5 {
            let md5_bytes: [u8; 16] = decode_hex(md5)?
                .try_into()
                .map_err(|_| anyhow!("Provided MD5 has invalid length"))?;
            hashes.md5 = Some(md5_bytes)
        }

        Ok(Some(hashes))
    }

    pub async fn from_meta(
        idx: usize,
        file_path: &PathBuf,
        encryption_keys: (Option<[u8; 32]>, Option<[u8; 32]>),
        public_keys: Vec<[u8; 32]>,
    ) -> Result<(FileContext, ReaderStream<File>)> {
        let input_file = File::open(file_path).await?;
        let file_metadata = input_file.metadata().await?;

        // Evaluate file type
        let symlink_target = if file_metadata.file_type().is_symlink() {
            Some(
                read_link(file_path)
                    .await?
                    .to_str()
                    .ok_or_else(|| anyhow!("Path to string conversion failed"))?
                    .to_string(),
            )
        } else {
            None
        };

        // Evaluate keys
        let enc_keys = match (encryption_keys.0, encryption_keys.1) {
            (Some(data_key), Some(meta_key)) => {
                if data_key == meta_key {
                    EncryptionKey::Same(data_key)
                } else {
                    EncryptionKey::Individual((data_key, meta_key))
                }
            }
            (Some(data_key), None) => EncryptionKey::DataOnly(data_key),
            (None, Some(meta_key)) => EncryptionKey::Same(meta_key), // ???
            (None, None) => EncryptionKey::None,
        };

        Ok((
            FileContext {
                idx,
                file_path: file_path.file_name().unwrap().to_str().unwrap().to_string(),
                compressed_size: file_metadata.len(),
                decompressed_size: file_metadata.len(),
                uid: Some(file_metadata.uid().into()),
                gid: Some(file_metadata.gid().into()),
                mode: Some(file_metadata.mode()),
                mtime: Some(file_metadata.mtime() as u64),
                compression: false,
                chunk_multiplier: None,
                encryption_key: enc_keys,
                recipients_pubkeys: public_keys,
                is_dir: file_metadata.file_type().is_dir(),
                symlink_target,
                expected_sha256: None,
                expected_md5: None,
                semantic_metadata: None,
                custom_ranges: None,
            },
            ReaderStream::new(input_file),
        ))
    }
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let result: Result<Vec<u8>, ParseIntError> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect();

    match result {
        Ok(bytes) => Ok(bytes),
        Err(err) => bail!(err),
    }
}

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::helpers::chacha_poly1305::{ChaChaPoly1305Error, decrypt_chunk};
use crate::helpers::x25519_keys::{CryptError, private_key_from_pem_bytes};
use crate::helpers::zstd::{ZstdError, decompress_data};
use crate::model::deserialization::DeserializationError;
use crate::model::structs::{BlockDataState, BlockHeader, Directory, FileEntry};

use x25519_dalek::StaticSecret;

/// Error type for PithosReader operations
#[derive(Debug, thiserror::Error)]
pub enum PithosReaderError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Deserialization error: {0:?}")]
    Deserialization(#[from] DeserializationError),
    #[error("Crypt error: {0}")]
    Crypt(#[from] CryptError),
    #[error("Decryption error: {0}")]
    Decryption(#[from] ChaChaPoly1305Error),
    #[error("Compression error: {0}")]
    Compression(#[from] ZstdError),
    #[error("No matching recipient section found for the provided private key")]
    NoMatchingRecipient,
    #[error("Block key not found for block index {0}")]
    BlockKeyNotFound(u64),
    #[error("Block not found for file block index {0}")]
    BlockNotFound(u64),
    #[error("Invalid block data state for file block index {0}")]
    InvalidBlockDataState(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub struct PithosReaderSimple {
    /// Underlying file handle for the Pithos archive
    file: File,
    /// User's private key
    private_key: StaticSecret,
}

impl PithosReaderSimple {
    /// Open a Pithos archive and prepare for reading
    pub fn new<P: AsRef<Path>>(
        pithos_path: P,
        private_key_pem_path: P,
    ) -> Result<Self, PithosReaderError> {
        // Open the Pithos file
        let file = File::open(&pithos_path)?;

        // Read and parse the PEM-encoded private key
        let pem_content = std::fs::read_to_string(private_key_pem_path)?;
        let private_key = private_key_from_pem_bytes(pem_content.as_bytes())?;

        Ok(Self { file, private_key })
    }

    pub fn read_directory(&mut self) -> Result<Directory, PithosReaderError> {
        // Read last 12 bytes for crc32 and directory length
        let file_len = self.file.metadata()?.len();
        if file_len < 12 {
            return Err(PithosReaderError::Other(
                "File too small for directory footer".to_string(),
            ));
        }
        self.file.seek(SeekFrom::End(-12))?;
        let mut footer = [0u8; 12];
        self.file.read_exact(&mut footer)?;

        let dir_len = u64::from_be_bytes(footer[..8].try_into().map_err(|_| {
            PithosReaderError::Other("Failed to deserialize directory length".to_string())
        })?);

        // Last 4 bytes: crc32, next 8 bytes: directory length (u64, BE)
        let _crc32 = u32::from_be_bytes(footer[8..12].try_into().map_err(|_| {
            PithosReaderError::Other("Failed to deserialize crc32 checksum".to_string())
        })?);

        self.file.seek(SeekFrom::End(0 - dir_len as i64))?;
        let mut dir_buf = vec![0u8; dir_len as usize];
        self.file.read_exact(&mut dir_buf)?;

        let mut directory = Directory::deserialize(&mut dir_buf.as_slice())?;

        // Decrypt file indices in recipient sections
        let mut available_file_indices = HashMap::new();
        let decrypted_file_indices =
            directory
                .decrypt_recipient(&self.private_key)
                .map_err(|_| {
                    PithosReaderError::Other("Failed to decrypt recipient data".to_string())
                })?;
        available_file_indices.extend(decrypted_file_indices);

        // Remove all files from directory which cannot be decrypted
        directory.files.retain_mut(|file| match file.block_data {
            BlockDataState::Decrypted(_) => true,
            BlockDataState::Encrypted(_) => {
                if let Some(block_key) = available_file_indices.get(&file.file_id) {
                    file.block_data.decrypt(block_key).is_ok()
                } else {
                    false
                }
            }
        });

        //TODO: Refactor in cli
        let outfile = File::create("/tmp/test.out")?;
        let inner_file = directory.files.first().expect("No file available");

        self.read_file(inner_file.path.clone(), &directory, Box::new(outfile))?;

        Ok(directory)
    }

    pub fn read_file_list(&self) -> Result<Vec<FileEntry>, PithosReaderError> {
        todo!()
    }

    pub fn read_file(
        &mut self,
        path: String,
        directory: &Directory,
        mut sink: Box<dyn Write>,
    ) -> Result<(), PithosReaderError> {
        let file_entry = directory
            .files
            .iter()
            .find(|file| file.path == path)
            .ok_or_else(|| PithosReaderError::FileNotFound(path))?;

        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::InvalidBlockDataState(
                    "Block data is encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                for (idx, key) in blocks {
                    let block_meta = directory
                        .blocks
                        .iter()
                        .find(|block| block.index == *idx)
                        .ok_or_else(|| PithosReaderError::BlockKeyNotFound(*idx))?;

                    self.file.seek(SeekFrom::Start(block_meta.offset))?;

                    // Read block header for block start validation
                    let mut block_header = [0u8; 4];
                    self.file.read_exact(&mut block_header)?;
                    BlockHeader::deserialize(&mut block_header.as_slice())?;

                    // Read block data
                    let mut block_buf = vec![0u8; block_meta.stored_size as usize];
                    self.file.read_exact(&mut block_buf)?;

                    // Decrypt and decompress according to ProcessingFlags
                    if block_meta.flags.is_encrypted() {
                        block_buf = decrypt_chunk(&block_buf, key)?;
                    }

                    if block_meta.flags.get_compression_level() > 0 {
                        block_buf = decompress_data(&block_buf, block_meta.original_size)?;
                    }

                    sink.write_all(&block_buf)?;
                }
            }
        }

        Ok(())
    }
}

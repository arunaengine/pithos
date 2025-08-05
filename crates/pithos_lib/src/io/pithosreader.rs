use crate::helpers::chacha_poly1305::{ChaChaPoly1305Error, decrypt_chunk};
use crate::helpers::x25519_keys::{CryptError, private_key_from_pem_bytes};
use crate::helpers::zstd::{ZstdError, decompress_data};
use crate::model::deserialization::DeserializationError;
use crate::model::structs::{
    BlockDataState, BlockHeader, BlockIndexEntry, Directory, FileEntry, FileType,
};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};

use crate::io::util::{create_dir, create_symlink};
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

        // Deserialize full directory
        let mut directory = Directory::deserialize(&mut dir_buf.as_slice())?;

        // Decrypt file indices in recipient sections
        let mut available_file_keys = HashMap::new();
        let decrypted_file_indices =
            directory
                .decrypt_recipient(&self.private_key)
                .map_err(|_| {
                    PithosReaderError::Other("Failed to decrypt recipient data".to_string())
                })?;
        available_file_keys.extend(decrypted_file_indices);

        // Remove all files from directory which cannot be decrypted
        directory.files.retain_mut(|file| match file.block_data {
            BlockDataState::Decrypted(_) => true,
            BlockDataState::Encrypted(_) => {
                if let Some(block_key) = available_file_keys.get(&file.file_id) {
                    file.block_data.decrypt(block_key).is_ok()
                } else {
                    false
                }
            }
        });

        Ok(directory)
    }

    pub fn read_file_paths(
        &self,
        directory: &Directory,
    ) -> Result<Vec<(FileType, String)>, PithosReaderError> {
        Ok(directory
            .files
            .iter()
            .map(|f| (f.file_type, f.path.clone()))
            .collect())
    }

    pub fn read_file(
        &mut self,
        inner_path: &str,
        directory: &Directory,
        output_path: Option<&PathBuf>,
        range: Option<Range<u64>>,
    ) -> Result<(), PithosReaderError> {
        let file_entry = directory
            .files
            .iter()
            .find(|file| file.path == inner_path)
            .ok_or(PithosReaderError::FileNotFound(inner_path.to_string()))?;

        match &file_entry.file_type {
            FileType::Data | FileType::Metadata => {
                // Create output file and write file blocks
                let output_file = File::create(if let Some(base_dir) = output_path {
                    base_dir.join(inner_path)
                } else {
                    std::env::current_dir()?.join(inner_path)
                })?;

                if let Some(range) = range {
                    self.read_data_range_to_sink(
                        range,
                        file_entry,
                        &directory.blocks,
                        Box::new(output_file),
                    )?;
                } else {
                    self.read_data_to_sink(file_entry, &directory.blocks, Box::new(output_file))?;
                }
            }
            FileType::Directory => {
                // Create directory (parent?)
                create_dir(&file_entry.path, output_path)?;
            }
            FileType::Symlink => {
                // Create symlink (UNIX only)
                create_symlink(
                    &file_entry.path,
                    file_entry
                        .symlink_target
                        .as_ref()
                        .expect("Symlink has no target"),
                    output_path,
                )?;
            }
        }

        Ok(())
    }

    fn read_data_to_sink(
        &mut self,
        file_entry: &FileEntry,
        block_index: &Vec<BlockIndexEntry>,
        mut sink: Box<dyn Write>,
    ) -> Result<(), PithosReaderError> {
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::InvalidBlockDataState(
                    "Block data is encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                for (idx, key) in blocks {
                    let block_meta = block_index
                        .iter()
                        .find(|block| block.index == *idx)
                        .ok_or(PithosReaderError::BlockKeyNotFound(*idx))?;

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

    pub fn read_data_range_to_sink(
        &mut self,
        byte_range: Range<u64>,
        file_entry: &FileEntry,
        block_index: &Vec<BlockIndexEntry>,
        mut sink: Box<dyn Write>,
    ) -> Result<(), PithosReaderError> {
        let mut block_byte_sum = 0;

        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::InvalidBlockDataState(
                    "Block data is still encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                for (idx, key) in blocks {
                    let block_meta = block_index
                        .iter()
                        .find(|block| block.index == *idx)
                        .ok_or(PithosReaderError::BlockKeyNotFound(*idx))?;

                    let block_start = block_byte_sum;
                    let block_end = block_byte_sum + block_meta.original_size;
                    block_byte_sum = block_end;

                    // If block ends before start of range; Discard block
                    if block_end <= byte_range.start {
                        continue;
                    }

                    // If block starts after end of range; Stop loop
                    if block_start >= byte_range.end {
                        break;
                    }

                    // Read block header for block start validation
                    self.file.seek(SeekFrom::Start(block_meta.offset))?;
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

                    // Calculate the range within this block to write
                    let write_start = if byte_range.start > block_start {
                        (byte_range.start - block_start) as usize
                    } else {
                        0
                    };
                    let write_end = if byte_range.end < block_end {
                        (byte_range.end - block_start) as usize
                    } else {
                        block_buf.len()
                    };

                    // Write only the relevant slice of the block
                    sink.write_all(&block_buf[write_start..write_end])?;

                    // If we've written enough bytes, stop
                    if block_end >= byte_range.end {
                        break;
                    }
                }
            }
        }

        Ok(())
    }
}

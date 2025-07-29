use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use crate::helpers::chacha_poly1305::{decrypt_chunk, ChaChaPoly1305Error};
use crate::helpers::x25519_keys::{derive_shared_key, private_key_from_pem_bytes, CryptError};
use crate::helpers::zstd::{decompress_data, ZstdError};
use crate::model::deserialization::DeserializationError;
use crate::model::structs::{BlockDataState, Directory, FileEntry, RecipientData};

use x25519_dalek::{PublicKey, StaticSecret};

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
    InvalidBlockDataState(u64),
    #[error("Other error: {0}")]
    Other(String),
}

/// Holds decrypted recipient data for block decryption
#[derive(Debug, Clone)]
struct DecryptedRecipientData {
    /// Maps block index to block key ([u8; 32])
    block_keys: std::collections::HashMap<u64, [u8; 32]>,
}

pub struct PithosReaderSimple {
    /// Underlying file handle for the Pithos archive
    file: File,
    /// User's private key
    private_key: StaticSecret,
    /// User's public key (derived from private)
    public_key: PublicKey,
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
        let mut pem_bytes = Vec::new();
        File::open(&private_key_pem_path)?.read_to_end(&mut pem_bytes)?;
        let private_key = private_key_from_pem_bytes(&pem_bytes)?;
        let public_key = PublicKey::from(&private_key);

        Ok(Self {
            file,
            private_key,
            public_key,
        })
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
        dbg!(&dir_buf.len());

        let mut directory = Directory::deserialize(&mut dir_buf.as_slice())?;

        // Decrypt file indices in recipient sections
        let mut available_file_indices = HashMap::new();
        let decrypted_file_indices = directory
            .decrypt_recipient_section(&self.private_key)
            .map_err(|_| {
                PithosReaderError::Other("Failed to decrypt recipient data".to_string())
            })?;
        available_file_indices.extend(decrypted_file_indices);

    /// Extract a file by path, returning its fully decrypted and decompressed contents
    pub fn extract_file(&mut self, path: &str) -> Result<Vec<u8>, PithosReaderError> {
        // Find FileEntry by path
        let file_entry = self
            .directory
            .files
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| PithosReaderError::Other(format!("File not found: {}", path)))?;

        // Only support Data and Metadata files for extraction
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::Other(
                    "Unexpected BlockDataState::Encrypted at file level".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                let mut result = Vec::with_capacity(file_entry.file_size as usize);
                for (block_idx, _block_key) in blocks {
                    // Find the corresponding BlockIndexEntry
                    let block_index_entry = self
                        .directory
                        .blocks
                        .iter()
                        .find(|b| b.index == *block_idx)
                        .ok_or(PithosReaderError::BlockNotFound(*block_idx))?;

                    // Get the key for this block from recipient_data
                    let block_key = self
                        .recipient_data
                        .as_ref()
                        .and_then(|rd| rd.block_keys.get(block_idx))
                        .ok_or(PithosReaderError::BlockKeyNotFound(*block_idx))?;

                    // Seek to the block offset and read the encrypted block data
                    self.file
                        .seek(SeekFrom::Start(block_index_entry.offset))
                        .map_err(PithosReaderError::Io)?;
                    let mut enc_block = vec![0u8; block_index_entry.stored_size as usize];
                    self.file
                        .read_exact(&mut enc_block)
                        .map_err(PithosReaderError::Io)?;

                    // Decrypt the block
                    let decrypted_block = decrypt_chunk(&enc_block, block_key)
                        .map_err(PithosReaderError::Decryption)?;

                    // Decompress if needed
                    let is_compressed = (block_index_entry.flags.0 & 0b1) != 0;
                    let block_data = if is_compressed {
                        decompress_data(&decrypted_block, block_index_entry.original_size)
                            .map_err(PithosReaderError::Compression)?
                    } else {
                        decrypted_block.to_vec()
                    };

                    result.extend_from_slice(&block_data);
                }
                Ok(result)
            }
        }
    }

    /// Extract a range of a file by path, returning the specified range of bytes (decrypted and decompressed)
    pub fn extract_file_range(
        &mut self,
        path: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, PithosReaderError> {
        // Implementation will:
        // - Find FileEntry by path
        // - For each block, locate in file, decrypt, decompress if needed
        // - Return only the requested range of bytes
        // Find FileEntry by path
        let file_entry = self
            .directory
            .files
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| PithosReaderError::Other(format!("File not found: {}", path)))?;

        // Only support Data and Metadata files for extraction
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::Other(
                    "Unexpected BlockDataState::Encrypted at file level".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                // First, reconstruct the full file as in extract_file
                let mut full_file = Vec::with_capacity(file_entry.file_size as usize);
                for (block_idx, _block_key) in blocks {
                    // Find the corresponding BlockIndexEntry
                    let block_index_entry = self
                        .directory
                        .blocks
                        .iter()
                        .find(|b| b.index == *block_idx)
                        .ok_or(PithosReaderError::BlockNotFound(*block_idx))?;

                    // Get the key for this block from recipient_data
                    let block_key = self
                        .recipient_data
                        .as_ref()
                        .and_then(|rd| rd.block_keys.get(block_idx))
                        .ok_or(PithosReaderError::BlockKeyNotFound(*block_idx))?;

                    // Seek to the block offset and read the encrypted block data
                    self.file
                        .seek(SeekFrom::Start(block_index_entry.offset))
                        .map_err(PithosReaderError::Io)?;
                    let mut enc_block = vec![0u8; block_index_entry.stored_size as usize];
                    self.file
                        .read_exact(&mut enc_block)
                        .map_err(PithosReaderError::Io)?;

                    // Decrypt the block
                    let decrypted_block = decrypt_chunk(&enc_block, block_key)
                        .map_err(PithosReaderError::Decryption)?;

                    // Decompress if needed
                    let is_compressed = (block_index_entry.flags.0 & 0b1) != 0;
                    let block_data = if is_compressed {
                        decompress_data(&decrypted_block, block_index_entry.original_size)
                            .map_err(PithosReaderError::Compression)?
                    } else {
                        decrypted_block.to_vec()
                    };

                    full_file.extend_from_slice(&block_data);
                }

                // Now, extract the requested range
                let file_len = full_file.len() as u64;
                if offset >= file_len {
                    return Ok(Vec::new());
                }
                let end = std::cmp::min(offset + length, file_len);
                Ok(full_file[offset as usize..end as usize].to_vec())
            }
        }
    }

    /*
    /// Extract a file by path as a streaming reader (for large files)
    pub fn extract_file_stream(
        &mut self,
        path: &str,
    ) -> Result<PithosFileStream, PithosReaderError> {
        // Find FileEntry by path
        let file_entry = self
            .directory
            .files
            .iter()
            .find(|f| f.path == path)
            .ok_or_else(|| PithosReaderError::Other(format!("File not found: {}", path)))?;

        // Only support Data and Metadata files for extraction
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosReaderError::Other(
                    "Unexpected BlockDataState::Encrypted at file level".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                let block_indices: Vec<u64> = blocks.iter().map(|(idx, _)| *idx).collect();
                Ok(PithosFileStream {
                    reader: self,
                    file_entry,
                    block_indices,
                    current_block: 0,
                    current_block_data: None,
                })
            }
        }
    }
    */
}

/// Streaming reader for a file inside the Pithos archive
pub struct PithosFileStream<'a> {
    // Reference to the parent reader and file/block info
    reader: &'a mut PithosReader,
    file_entry: &'a FileEntry,
    block_indices: Vec<u64>,
    current_block: usize,
    current_block_data: Option<std::io::Cursor<Vec<u8>>>,
}

impl<'a> Read for PithosFileStream<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut total_read = 0;

        loop {
            // If we have current block data, read from it
            if let Some(ref mut cursor) = self.current_block_data {
                let n = cursor.read(&mut buf[total_read..])?;
                total_read += n;
                if total_read == buf.len() {
                    return Ok(total_read);
                }
                // If this block is exhausted, move to next
                if cursor.position() as usize == cursor.get_ref().len() {
                    self.current_block_data = None;
                    self.current_block += 1;
                } else {
                    // Still data left in this block
                    continue;
                }
            } else {
                // Load next block if available
                if self.current_block >= self.block_indices.len() {
                    // No more blocks
                    return if total_read > 0 {
                        Ok(total_read)
                    } else {
                        Ok(0)
                    };
                }
                let block_idx = self.block_indices[self.current_block];
                // Find the corresponding BlockIndexEntry
                let block_index_entry = self
                    .reader
                    .directory
                    .blocks
                    .iter()
                    .find(|b| b.index == block_idx)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Block not found: {}", block_idx),
                        )
                    })?;

                // Get the key for this block from recipient_data
                let block_key = self
                    .reader
                    .recipient_data
                    .as_ref()
                    .and_then(|rd| rd.block_keys.get(&block_idx))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::Other,
                            format!("Block key not found: {}", block_idx),
                        )
                    })?;

                // Seek to the block offset and read the encrypted block data
                self.reader
                    .file
                    .seek(SeekFrom::Start(block_index_entry.offset))
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                let mut enc_block = vec![0u8; block_index_entry.stored_size as usize];
                self.reader
                    .file
                    .read_exact(&mut enc_block)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                // Decrypt the block
                let decrypted_block = decrypt_chunk(&enc_block, block_key).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("Decryption error: {:?}", e))
                })?;

                // Decompress if needed
                let is_compressed = (block_index_entry.flags.0 & 0b1) != 0;
                let block_data = if is_compressed {
                    decompress_data(&decrypted_block, block_index_entry.original_size).map_err(
                        |e| {
                            io::Error::new(
                                io::ErrorKind::Other,
                                format!("Compression error: {:?}", e),
                            )
                        },
                    )?
                } else {
                    decrypted_block.to_vec()
                };

                self.current_block_data = Some(std::io::Cursor::new(block_data));
                // Loop will continue and try to read from the new block
            }
        }
    }
}

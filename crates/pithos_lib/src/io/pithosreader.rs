use crate::error::PithosError;
use crate::helpers::chacha_poly1305::{decrypt_chunk, encrypt_chunk};
use crate::helpers::crypt4gh::{CRYPT4GH_BLOCK_SIZE, Crypt4GHHeader, HeaderPacket};
use crate::helpers::x25519_keys::private_key_from_pem_bytes;
use crate::helpers::zstd::decompress_data;
use crate::io::util::{create_dir, create_symlink};
use crate::model::structs::{
    BlockDataState, BlockHeader, BlockIndexEntry, BlockLocation, Directory, FileEntry, FileType,
};
use indexmap::IndexMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct PithosReaderSimple {
    /// Underlying file handle for the Pithos archive
    file: File,
    /// User's private key
    private_key: StaticSecret,
}

impl PithosReaderSimple {
    /// Open a Pithos archive and prepare for reading
    #[tracing::instrument(level = "trace", skip(pithos_path, private_key_pem_path))]
    pub fn new<P: AsRef<Path>>(
        pithos_path: P,
        private_key_pem_path: P,
    ) -> Result<Self, PithosError> {
        // Open the Pithos file
        let file = File::open(&pithos_path)?;

        // Read and parse the PEM-encoded private key
        let pem_content = std::fs::read_to_string(private_key_pem_path)?;
        let private_key = private_key_from_pem_bytes(pem_content.as_bytes())?;

        Ok(Self { file, private_key })
    }

    /// Init a simple Pithos reader
    #[tracing::instrument(level = "trace", skip(pithos_path, private_key))]
    pub fn new_with_key<P: AsRef<Path>>(
        pithos_path: P,
        private_key: StaticSecret,
    ) -> Result<Self, PithosError> {
        // Open the Pithos file
        let file = File::open(&pithos_path)?;

        Ok(Self { file, private_key })
    }

    /// Init a simple Pithos reader
    #[tracing::instrument(level = "trace", skip(_pithos_path, _private_key))]
    pub fn new_with_keys<P: AsRef<Path>>(
        _pithos_path: P,
        _private_key: Vec<StaticSecret>,
    ) -> Result<Self, PithosError> {
        unimplemented!("Multiple reader keys");
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn read_directory(&mut self) -> Result<(Directory, (u64, u64)), PithosError> {
        // Read last 12 bytes for crc32 and directory length
        let file_len = self.file.metadata()?.len();
        if file_len < 25 {
            return Err(PithosError::Other(
                "File too small for directory footer".to_string(),
            ));
        }
        self.file.seek(SeekFrom::End(-12))?;
        let mut footer = [0u8; 12];
        self.file.read_exact(&mut footer)?;

        let parent_dir_len = u64::from_be_bytes(footer[..8].try_into().map_err(|_| {
            PithosError::Conversion("Failed to convert directory length bytes to u64".to_string())
        })?);
        let parent_dir_start = file_len - parent_dir_len;

        // Last 4 bytes: crc32, next 8 bytes: directory length (u64, BE)
        let _crc32 = u32::from_be_bytes(footer[8..12].try_into().map_err(|_| {
            PithosError::Conversion("Failed to convert crc32 checksum bytes to u32".to_string())
        })?);

        self.file.seek(SeekFrom::End(0 - parent_dir_len as i64))?;
        let mut dir_buf = vec![0u8; parent_dir_len as usize];
        self.file.read_exact(&mut dir_buf)?;

        // Deserialize full directory
        let mut available_file_keys = HashMap::new();
        let mut directory = Directory::deserialize(&mut dir_buf.as_slice())?;
        available_file_keys.extend(directory.decrypt_recipient(&self.private_key)?);

        // Merge with parent directories
        while let Some((start, len)) = directory.parent_directory_offset {
            // Read parent directory
            self.file.seek(SeekFrom::Start(start))?;
            let mut dir_buf = vec![0u8; len as usize];
            self.file.read_exact(&mut dir_buf)?;
            let mut older_directory = Directory::deserialize(&mut dir_buf.as_slice())?;
            available_file_keys.extend(older_directory.decrypt_recipient(&self.private_key)?);

            // Merge directories and swap
            older_directory.merge(directory)?;
            directory = older_directory;
        }

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

        Ok((directory, (parent_dir_start, parent_dir_len)))
    }

    #[tracing::instrument(level = "trace", skip(self, directory))]
    pub fn read_file_paths(
        &self,
        directory: &Directory,
    ) -> Result<Vec<(FileType, String)>, PithosError> {
        Ok(directory
            .files
            .iter()
            .map(|f| (f.file_type, f.path.clone()))
            .collect())
    }

    #[tracing::instrument(
        level = "trace",
        skip(self, inner_path, directory, output_path, ranges)
    )]
    pub fn read_file(
        &mut self,
        inner_path: &str,
        directory: &Directory,
        output_path: Option<&PathBuf>,
        ranges: Option<Vec<Range<u64>>>,
    ) -> Result<(), PithosError> {
        let file_entry = directory
            .files
            .iter()
            .find(|file| file.path == inner_path)
            .ok_or(PithosError::FileNotFound(inner_path.to_string()))?;

        match &file_entry.file_type {
            FileType::Data | FileType::Metadata => {
                // Write output
                let mut output_target: Box<dyn Write> = if let Some(dest) = output_path {
                    let target = if dest.is_dir() {
                        &dest.join(inner_path)
                    } else {
                        dest
                    };

                    Box::new(File::create(target).map_err(PithosError::Io)?)
                } else {
                    Box::new(io::stdout())
                };

                if let Some(ranges) = ranges {
                    for range in ranges {
                        self.read_data_range_to_sink(
                            range,
                            file_entry,
                            &directory.blocks,
                            &mut output_target,
                        )?;
                    }
                } else {
                    self.read_data_to_sink(file_entry, &directory.blocks, output_target)?;
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

    #[tracing::instrument(level = "trace", skip(self, inner_path, directory, output))]
    pub fn read_file_to_crypt4gh(
        &mut self,
        inner_path: &str,
        directory: &Directory,
        reader_keys: Vec<PublicKey>,
        output: Option<Box<dyn Write>>,
    ) -> Result<(), PithosError> {
        // Fetch file entry from directory
        let file_entry = directory
            .get_file_by_path(inner_path)
            .ok_or(PithosError::FileNotFound(inner_path.to_string()))?;

        // Validate file type
        if ![FileType::Data, FileType::Metadata].contains(&file_entry.file_type) {
            return Err(PithosError::InvalidFileType(
                "Only data/metadata files can be exported to Crypt4GH".to_string(),
            ));
        }

        // Generate Crypt4GH header packets from keys
        let data_key = directory
            .get_file_encryption_key(file_entry.file_id)
            .ok_or(PithosError::FileNotFound(format!(
                "Could not extract key for file: {}",
                inner_path
            )))?;
        let packets = HeaderPacket::from_pithos(&self.private_key, reader_keys, &data_key)
            .map_err(|e| {
                PithosError::Conversion(format!("Conversion to header packet failed: {e})"))
            })?;

        // Init output sink
        let mut sink = if let Some(sink) = output {
            sink
        } else {
            Box::new(io::stdout())
        };

        // Write Crypt4GH header
        let header = Crypt4GHHeader::new(packets);
        let header_bytes: Vec<u8> = header.try_into()?;
        sink.write_all(&header_bytes)?;

        // Load blocks and write data in 64kb blocks
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Cannot read encrypted block data".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                let mut buffer = Vec::with_capacity(65536); // 64kb buffer
                for (hash, key) in blocks {
                    // Fetch block meta from directory
                    let block_meta = directory
                        .blocks
                        .get(hash)
                        .ok_or(PithosError::BlockHashNotFound(*hash))?;

                    // Jump to begin of block in file
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

                    // Write chunk data in 64KiB ChaCha20Poly1305 encrypted blocks
                    let mut chunk_offset = 0;
                    while chunk_offset < block_buf.len() {
                        let remaining_chunk = &block_buf[chunk_offset..];
                        let remaining_buffer = CRYPT4GH_BLOCK_SIZE - buffer.len();

                        if remaining_chunk.len() <= remaining_buffer {
                            // Chunk fits in remaining buffer space
                            buffer.extend_from_slice(remaining_chunk);
                            chunk_offset = block_buf.len(); // Consumed the entire chunk

                            // Check if buffer is full
                            if buffer.len() == CRYPT4GH_BLOCK_SIZE {
                                let encrypted = encrypt_chunk(&buffer, b"", &data_key)?;
                                sink.write_all(&encrypted)?;
                                //sink.write_all(&encrypt_chunk(&buffer, b"", &data_key)?)?;
                                buffer.clear();
                            }
                        } else if buffer.is_empty() && remaining_chunk.len() > CRYPT4GH_BLOCK_SIZE {
                            // Large chunk that exceeds buffer capacity -> Process in buffer-sized pieces
                            let chunk_to_process = &remaining_chunk[..CRYPT4GH_BLOCK_SIZE];
                            let encrypted = encrypt_chunk(chunk_to_process, b"", &data_key)?;
                            sink.write_all(&encrypted)?;
                            //sink.write_all(&encrypt_chunk(&chunk_to_process, b"", &data_key)?)?;
                            chunk_offset += CRYPT4GH_BLOCK_SIZE;
                        } else {
                            // Fill remaining buffer space with part of the chunk
                            let bytes_to_take = remaining_buffer;
                            buffer.extend_from_slice(&remaining_chunk[..bytes_to_take]);
                            chunk_offset += bytes_to_take;

                            // Buffer is now full
                            let encrypted = encrypt_chunk(&buffer, b"", &data_key)?;
                            sink.write_all(&encrypted)?;
                            buffer.clear();
                        }
                    }
                }

                // Write partial filled buffer if is not empty
                if !buffer.is_empty() {
                    let encrypted = encrypt_chunk(&buffer, b"", &data_key)?;
                    sink.write_all(&encrypted)?;
                    //sink.write_all(&encrypt_chunk(&buffer, b"", &data_key)?)?;
                    buffer.clear()
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, file_entry, block_index, sink))]
    fn read_data_to_sink(
        &mut self,
        file_entry: &FileEntry,
        block_index: &IndexMap<[u8; 32], BlockIndexEntry>,
        mut sink: Box<dyn Write>,
    ) -> Result<(), PithosError> {
        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block data is encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                for (hash, key) in blocks {
                    // Fetch block meta from directory
                    let block_meta = block_index
                        .get(hash)
                        .ok_or(PithosError::BlockHashNotFound(*hash))?;

                    let mut block_header = [0u8; 4];
                    let mut block_data = vec![0u8; block_meta.stored_size as usize];
                    match &block_meta.location {
                        BlockLocation::Local => {
                            self.file.seek(SeekFrom::Start(block_meta.offset))?;
                            // Read block header for block start validation
                            self.file.read_exact(&mut block_header)?;
                            BlockHeader::deserialize(&mut block_header.as_slice())?;
                            // Read block data
                            self.file.read_exact(&mut block_data)?;
                        }
                        BlockLocation::External { url } => {
                            let mut response = reqwest::blocking::get(url).unwrap();
                            // Read block header for block start validation
                            response.read_exact(&mut block_header)?;
                            BlockHeader::deserialize(&mut block_header.as_slice())?;
                            // Read block data
                            self.file.read_exact(&mut block_data)?;
                        }
                    }

                    // Decrypt and decompress according to ProcessingFlags
                    if block_meta.flags.is_encrypted() {
                        block_data = decrypt_chunk(&block_data, key)?;
                    }
                    if block_meta.flags.get_compression_level() > 0 {
                        block_data = decompress_data(&block_data, block_meta.original_size)?;
                    }

                    sink.write_all(&block_data)?;
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, byte_range, file_entry, block_index, sink))]
    pub fn read_data_range_to_sink(
        &mut self,
        byte_range: Range<u64>,
        file_entry: &FileEntry,
        block_index: &IndexMap<[u8; 32], BlockIndexEntry>,
        sink: &mut Box<dyn Write>,
    ) -> Result<(), PithosError> {
        let mut block_byte_sum = 0;

        match &file_entry.block_data {
            BlockDataState::Encrypted(_) => {
                return Err(PithosError::InvalidBlockDataState(
                    "Block data is still encrypted".to_string(),
                ));
            }
            BlockDataState::Decrypted(blocks) => {
                for (hash, key) in blocks {
                    // Fetch block meta from directory
                    let block_meta = block_index
                        .get(hash)
                        .ok_or(PithosError::BlockHashNotFound(*hash))?;

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

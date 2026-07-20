use crate::error::PithosError;
use crate::helpers::archive_path::{validate_entry, validate_map};
use crate::helpers::chacha_poly1305::{decrypt_chunk, encrypt_chunk};
use crate::helpers::crypt4gh::{CRYPT4GH_BLOCK_SIZE, Crypt4GHHeader, HeaderPacket};
use crate::helpers::file_entry_map::KeyQuery;
use crate::helpers::x25519_keys::private_key_from_pem_bytes;
use crate::helpers::zstd::decompress_data;
use crate::io::extraction::ExtractionRoot;
use crate::model::deserialization::DeserializationLimits;
use crate::model::structs::{
    BlockDataState, BlockHeader, BlockIndexEntry, BlockLocation, Directory, FileEntry, FileType,
};
use crc32fast::hash;
use indexmap::IndexMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Copy, Debug)]
pub struct ReaderLimits {
    pub max_directory_bytes: u64,
    pub max_parent_directories: u64,
    pub max_stored_block_bytes: u64,
    pub max_decoded_block_bytes: u64,
    pub deserialization: DeserializationLimits,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            max_directory_bytes: 64 * 1024 * 1024,
            max_parent_directories: 1024,
            max_stored_block_bytes: 64 * 1024 * 1024,
            max_decoded_block_bytes: 64 * 1024 * 1024,
            deserialization: DeserializationLimits::default(),
        }
    }
}

pub struct PithosReaderSimple {
    /// Underlying file handle for the Pithos archive
    file: File,
    /// User's private key
    private_key: StaticSecret,
    limits: ReaderLimits,
}

impl PithosReaderSimple {
    fn decode_and_verify_block(
        stored_bytes: Vec<u8>,
        key: &[u8; 32],
        expected_hash: &[u8; 32],
        block_meta: &BlockIndexEntry,
        limits: &ReaderLimits,
    ) -> Result<Vec<u8>, PithosError> {
        if block_meta.original_size > limits.max_decoded_block_bytes {
            return Err(PithosError::LimitExceeded {
                field: "decoded block",
                limit: limits.max_decoded_block_bytes,
                actual: block_meta.original_size,
            });
        }
        let mut plaintext = if block_meta.flags.is_encrypted() {
            decrypt_chunk(&stored_bytes, key)?
        } else {
            stored_bytes
        };
        if block_meta.flags.get_compression_level() > 0 {
            plaintext = decompress_data(&plaintext, block_meta.original_size)?;
        }

        let actual_size = plaintext.len() as u64;
        if actual_size != block_meta.original_size {
            return Err(PithosError::BlockSizeMismatch {
                expected: block_meta.original_size,
                actual: actual_size,
            });
        }

        let actual_hash = *blake3::hash(&plaintext).as_bytes();
        if actual_hash != *expected_hash {
            return Err(PithosError::BlockHashMismatch {
                expected: *expected_hash,
                actual: actual_hash,
            });
        }

        Ok(plaintext)
    }

    fn checked_stored_size(
        meta: &BlockIndexEntry,
        limits: &ReaderLimits,
    ) -> Result<usize, PithosError> {
        if meta.stored_size > limits.max_stored_block_bytes {
            return Err(PithosError::LimitExceeded {
                field: "stored block",
                limit: limits.max_stored_block_bytes,
                actual: meta.stored_size,
            });
        }
        if meta.original_size > limits.max_decoded_block_bytes {
            return Err(PithosError::LimitExceeded {
                field: "decoded block",
                limit: limits.max_decoded_block_bytes,
                actual: meta.original_size,
            });
        }
        usize::try_from(meta.stored_size).map_err(|_| {
            PithosError::InvalidDirectoryRange("stored block size does not fit platform".into())
        })
    }

    fn zeroed_buffer(size: usize, field: &'static str) -> Result<Vec<u8>, PithosError> {
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(size)
            .map_err(|_| PithosError::AllocationFailed {
                field,
                size: size as u64,
            })?;
        buffer.resize(size, 0);
        Ok(buffer)
    }

    fn validate_local_block_range(&self, meta: &BlockIndexEntry) -> Result<(), PithosError> {
        let end = meta
            .offset
            .checked_add(4)
            .and_then(|value| value.checked_add(meta.stored_size))
            .ok_or_else(|| PithosError::InvalidDirectoryRange("block range overflow".into()))?;
        if end > self.file.metadata()?.len() {
            return Err(PithosError::InvalidDirectoryRange(
                "block range exceeds archive".into(),
            ));
        }
        Ok(())
    }

    fn parse_directory(bytes: &[u8], limits: &ReaderLimits) -> Result<Directory, PithosError> {
        if bytes.len() < 25 {
            return Err(PithosError::DirectoryLengthMismatch {
                expected: 25,
                actual: bytes.len() as u64,
            });
        }
        if bytes[..8] != Directory::DIRECTORY_MARKER {
            return Err(PithosError::InvalidDirectoryMarker {
                expected: Directory::DIRECTORY_MARKER,
                actual: bytes[..8].try_into().unwrap(),
            });
        }
        let expected_len =
            u64::from_be_bytes(bytes[bytes.len() - 12..bytes.len() - 4].try_into().unwrap());
        if expected_len != bytes.len() as u64 {
            return Err(PithosError::DirectoryLengthMismatch {
                expected: bytes.len() as u64,
                actual: expected_len,
            });
        }
        let expected_crc = u32::from_be_bytes(bytes[bytes.len() - 4..].try_into().unwrap());
        let actual_crc = hash(&bytes[..bytes.len() - 4]);
        if expected_crc != actual_crc {
            return Err(PithosError::DirectoryChecksumMismatch {
                expected: actual_crc,
                actual: expected_crc,
            });
        }
        let mut cursor = Cursor::new(bytes);
        let directory = Directory::deserialize_with_limits(&mut cursor, &limits.deserialization)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(PithosError::DirectoryConsumptionMismatch {
                expected: bytes.len() as u64,
                actual: cursor.position(),
            });
        }
        Ok(directory)
    }

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

        Ok(Self {
            file,
            private_key,
            limits: ReaderLimits::default(),
        })
    }

    /// Init a simple Pithos reader
    #[tracing::instrument(level = "trace", skip(pithos_path, private_key))]
    pub fn new_with_key<P: AsRef<Path>>(
        pithos_path: P,
        private_key: StaticSecret,
    ) -> Result<Self, PithosError> {
        // Open the Pithos file
        let file = File::open(&pithos_path)?;

        Ok(Self {
            file,
            private_key,
            limits: ReaderLimits::default(),
        })
    }

    pub fn with_limits(mut self, limits: ReaderLimits) -> Self {
        self.limits = limits;
        self
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
        if parent_dir_len < 25 {
            return Err(PithosError::DirectoryLengthMismatch {
                expected: 25,
                actual: parent_dir_len,
            });
        }
        if parent_dir_len > self.limits.max_directory_bytes {
            return Err(PithosError::LimitExceeded {
                field: "directory",
                limit: self.limits.max_directory_bytes,
                actual: parent_dir_len,
            });
        }
        let parent_dir_start = file_len.checked_sub(parent_dir_len).ok_or_else(|| {
            PithosError::InvalidDirectoryRange("terminal directory exceeds archive".into())
        })?;
        let parent_dir_len_usize = usize::try_from(parent_dir_len).map_err(|_| {
            PithosError::InvalidDirectoryRange("directory length does not fit platform".into())
        })?;

        self.file.seek(SeekFrom::Start(parent_dir_start))?;
        let mut dir_buf = Vec::new();
        dir_buf
            .try_reserve_exact(parent_dir_len_usize)
            .map_err(|_| PithosError::LimitExceeded {
                field: "directory allocation",
                limit: self.limits.max_directory_bytes,
                actual: parent_dir_len,
            })?;
        dir_buf.resize(parent_dir_len_usize, 0);
        self.file.read_exact(&mut dir_buf)?;

        // Deserialize full directory
        let mut available_file_keys = HashMap::new();
        let mut directory = Self::parse_directory(&dir_buf, &self.limits)?;
        available_file_keys.extend(
            directory
                .decrypt_recipient_with_limits(&self.private_key, &self.limits.deserialization)?,
        );

        // Merge with parent directories
        let mut visited = std::collections::HashSet::new();
        let mut depth = 0u64;
        let mut child_start = parent_dir_start;
        while let Some((start, len)) = directory.parent_directory_offset {
            depth = depth
                .checked_add(1)
                .ok_or_else(|| PithosError::InvalidDirectoryChain("depth overflow".into()))?;
            if depth > self.limits.max_parent_directories {
                return Err(PithosError::LimitExceeded {
                    field: "parent directories",
                    limit: self.limits.max_parent_directories,
                    actual: depth,
                });
            }
            if len < 25 || len > self.limits.max_directory_bytes {
                return Err(PithosError::InvalidDirectoryRange(
                    "parent length out of bounds".into(),
                ));
            }
            let end = start.checked_add(len).ok_or_else(|| {
                PithosError::InvalidDirectoryRange("parent range overflow".into())
            })?;
            if end > child_start || !visited.insert((start, len)) {
                return Err(PithosError::InvalidDirectoryChain(
                    "parent must be backward and nonoverlapping".into(),
                ));
            }
            let len_usize = usize::try_from(len).map_err(|_| {
                PithosError::InvalidDirectoryRange("parent length does not fit platform".into())
            })?;
            // Read parent directory
            self.file.seek(SeekFrom::Start(start))?;
            let mut dir_buf = Vec::new();
            dir_buf
                .try_reserve_exact(len_usize)
                .map_err(|_| PithosError::LimitExceeded {
                    field: "directory allocation",
                    limit: self.limits.max_directory_bytes,
                    actual: len,
                })?;
            dir_buf.resize(len_usize, 0);
            self.file.read_exact(&mut dir_buf)?;
            let mut older_directory = Self::parse_directory(&dir_buf, &self.limits)?;
            available_file_keys.extend(
                older_directory.decrypt_recipient_with_limits(
                    &self.private_key,
                    &self.limits.deserialization,
                )?,
            );
            child_start = start;

            // Merge directories and swap
            older_directory.merge(directory)?;
            directory = older_directory;
        }

        // Remove entries whose encrypted block indexes are unavailable to this reader.
        directory
            .files
            .retain_mut(|id, path, file| match &mut file.block_data {
                BlockDataState::Decrypted(_) => true,
                BlockDataState::Encrypted(_) => match available_file_keys.get(&id) {
                    Some(block_key) => match file
                        .block_data
                        .decrypt_with_limits(block_key, &self.limits.deserialization)
                    {
                        Ok(_) => {
                            tracing::info!("Successfully decrypted {path}");
                            true
                        }
                        Err(_) => {
                            tracing::warn!("Could not decrypt {path}");
                            false
                        }
                    },
                    None => false,
                },
            })?;
        validate_map(&directory.files)?;

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
            .map(|(_, p, f)| (f.file_type, p.to_owned()))
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
        validate_map(&directory.files)?;
        validate_entry(
            inner_path,
            directory
                .files
                .get(&KeyQuery::Path(inner_path.to_string()))
                .ok_or(PithosError::FileNotFound(inner_path.to_string()))?,
        )?;
        let file_entry = directory
            .files
            .get(&KeyQuery::Path(inner_path.to_string()))
            .ok_or(PithosError::FileNotFound(inner_path.to_string()))?;

        match &file_entry.file_type {
            FileType::Data | FileType::Metadata => {
                if output_path.is_none() {
                    let mut output_target: Box<dyn Write> = Box::new(io::stdout());
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
                    return Ok(());
                }
                let dest = output_path.unwrap();
                let (root_path, final_path, create_root) = if dest.is_dir() {
                    (dest.as_path(), inner_path.to_string(), false)
                } else {
                    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
                    let name =
                        dest.file_name()
                            .and_then(|name| name.to_str())
                            .ok_or_else(|| {
                                PithosError::Conversion("Invalid output file name".into())
                            })?;
                    (parent, name.to_string(), false)
                };
                let root = ExtractionRoot::open(root_path, create_root)?;
                let pending = root.pending_file(&final_path)?;
                let mut output_target: Box<dyn Write> = Box::new(pending.writer()?);
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
                pending.commit()?;
            }
            FileType::Directory => {
                let root_path = output_path
                    .map(PathBuf::as_path)
                    .unwrap_or_else(|| Path::new("."));
                ExtractionRoot::open(root_path, true)?.create_dir(inner_path)?;
            }
            FileType::Symlink => {
                let target = file_entry.symlink_target.as_deref().ok_or_else(|| {
                    PithosError::InvalidSymlinkEntry {
                        path: inner_path.into(),
                        reason: "missing target".into(),
                    }
                })?;
                let root_path = output_path
                    .map(PathBuf::as_path)
                    .unwrap_or_else(|| Path::new("."));
                ExtractionRoot::open(root_path, true)?.create_symlink(inner_path, target)?;
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
        let file_id = directory.files.get_id_by_path(inner_path).ok_or_else(|| {
            PithosError::Other(format!("Could not find file id for {inner_path}"))
        })?;
        let data_key =
            directory
                .get_file_encryption_key(file_id)
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
                    let stored_size = Self::checked_stored_size(block_meta, &self.limits)?;
                    self.validate_local_block_range(block_meta)?;
                    self.file.seek(SeekFrom::Start(block_meta.offset))?;

                    // Read block header for block start validation
                    let mut block_header = [0u8; 4];
                    self.file.read_exact(&mut block_header)?;
                    BlockHeader::deserialize(&mut block_header.as_slice())?;

                    // Read block data
                    let mut block_buf = Self::zeroed_buffer(stored_size, "stored block")?;
                    self.file.read_exact(&mut block_buf)?;

                    block_buf = Self::decode_and_verify_block(
                        block_buf,
                        key,
                        hash,
                        block_meta,
                        &self.limits,
                    )?;

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
                    let stored_size = Self::checked_stored_size(block_meta, &self.limits)?;
                    let mut block_data = Self::zeroed_buffer(stored_size, "stored block")?;
                    match &block_meta.location {
                        BlockLocation::Local => {
                            self.validate_local_block_range(block_meta)?;
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

                    block_data = Self::decode_and_verify_block(
                        block_data,
                        key,
                        hash,
                        block_meta,
                        &self.limits,
                    )?;

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
        let mut block_byte_sum: u64 = 0;

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

                    let stored_size = Self::checked_stored_size(block_meta, &self.limits)?;
                    let block_start = block_byte_sum;
                    let block_end = block_byte_sum
                        .checked_add(block_meta.original_size)
                        .ok_or_else(|| {
                            PithosError::InvalidDirectoryRange("range block size overflow".into())
                        })?;
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
                    self.validate_local_block_range(block_meta)?;
                    self.file.seek(SeekFrom::Start(block_meta.offset))?;
                    let mut block_header = [0u8; 4];
                    self.file.read_exact(&mut block_header)?;
                    BlockHeader::deserialize(&mut block_header.as_slice())?;

                    // Read block data
                    let mut block_buf = Self::zeroed_buffer(stored_size, "stored block")?;
                    self.file.read_exact(&mut block_buf)?;

                    block_buf = Self::decode_and_verify_block(
                        block_buf,
                        key,
                        hash,
                        block_meta,
                        &self.limits,
                    )?;

                    // Calculate the range within this block to write
                    let write_start = if byte_range.start > block_start {
                        usize::try_from(byte_range.start - block_start).map_err(|_| {
                            PithosError::InvalidDirectoryRange(
                                "range index does not fit platform".into(),
                            )
                        })?
                    } else {
                        0
                    };
                    let write_end = if byte_range.end < block_end {
                        usize::try_from(byte_range.end - block_start).map_err(|_| {
                            PithosError::InvalidDirectoryRange(
                                "range index does not fit platform".into(),
                            )
                        })?
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

use crate::helpers::chacha_poly1305::ChaChaPoly1305Error;
use crate::helpers::directory::DirectoryBuilder;
use crate::helpers::hash::Hasher;
use crate::helpers::x25519_keys::CryptError;
use crate::helpers::zstd::{ZstdError, map_to_zstd_level};
use crate::io::pithosreader::PithosReaderError;
use crate::model::serialization::SerializationError;
use crate::model::structs::{
    BlockHeader, BlockIndexEntry, BlockLocation, Directory, EncryptionSection, FileEntry, FileType,
    ProcessingFlags, RecipientData, RecipientSection, Reference,
};
use crate::{
    helpers::{
        chacha_poly1305::encrypt_chunk,
        zstd::{compress_data, probe_compression_ratio},
    },
    model::structs::FileHeader,
};
use fastcdc::v2020::{ChunkData, StreamCDC};
use rand_core::OsRng;
use std::fs::{File, symlink_metadata};
use std::io;
use std::io::{Read, Write};
use std::path::Path;
use std::time::SystemTimeError;
use x25519_dalek::{PublicKey, StaticSecret};

/// Error type for PithosReader operations
#[derive(Debug, thiserror::Error)]
pub enum PithosWriterError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
    #[error("Failed to strip prefix: {0}")]
    StripPrefix(#[from] std::path::StripPrefixError),
    #[error("Walkdir error: {0}")]
    Walkdir(#[from] walkdir::Error),
    #[error("FastCDC error: {0}")]
    FastCDC(#[from] fastcdc::v2020::Error),
    #[error("Serialization error: {0:?}")]
    Serialization(#[from] SerializationError),
    #[error("Crypt error: {0}")]
    Crypt(#[from] CryptError),
    #[error("Encryption error: {0}")]
    Encryption(#[from] ChaChaPoly1305Error),
    #[error("Compression error: {0}")]
    Compression(#[from] ZstdError),
    #[error("Path already occupied: {0}")]
    PathOccupied(String),
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Invalid file type: {0}")]
    InvalidFileType(String),
    #[error("Invalid block data state: {0}")]
    InvalidBlockDataState(String),
    #[error("Invalid recipient data state: {0}")]
    InvalidRecipientDataState(String),
    #[error("System time error: {0}")]
    SystemTimeError(#[from] SystemTimeError),
    #[error("Other error: {0}")]
    Other(String),
}

pub enum FileMeta {
    File(String),    // Path to file with metadata content
    Content(String), // File metadata as string content
}

pub struct InputFile {
    pub file_path: String,
    pub file_type: FileType,
    pub file_meta: Option<FileMeta>,
    pub encrypt: bool,
    pub compression_level: Option<u8>,
}

pub struct PithosWriter {
    // Input
    writer_key: StaticSecret, //TODO: Multiple sender keys for individual EncryptionSections
    reader_keys: Vec<PublicKey>, //TODO: Individual assignment of files to recipients
    sink: Box<dyn Write>,

    // Processing
    directory: Directory,
    chunk_idx: u64,
    file_idx: u64,
    written_bytes: u64,
}

impl PithosWriter {
    pub fn new(
        writer_key: StaticSecret,
        reader_keys: Vec<PublicKey>,
        sink: Box<dyn Write>,
    ) -> Result<Self, PithosWriterError> {
        // Init encryption section
        let encryption_sections = vec![EncryptionSection {
            sender_public_key: PublicKey::from(&writer_key).to_bytes(),
            recipients: reader_keys
                .iter()
                .map(|key| RecipientSection {
                    recipient_public_key: key.to_bytes(),
                    recipient_data: RecipientData::Decrypted(Vec::new()),
                })
                .collect(),
        }];

        Ok(PithosWriter {
            writer_key,
            reader_keys,
            sink,
            directory: DirectoryBuilder::new()
                .encryption(encryption_sections)
                .build()?,
            chunk_idx: 0,
            file_idx: 0,
            written_bytes: 0,
        })
    }

    pub fn new_from_file() -> Result<Self, PithosReaderError> {
        //TODO: Read directory from file
        //TODO: Do stuff
        todo!()
    }

    /* ----- Processing ---------- */
    /// Processes a single data chunk (block) for storage.
    ///
    /// # Arguments
    /// * `chunk` - Mutable reference to the `ChunkData` containing the block's raw data.
    /// * `processing_flags` - Reference to `ProcessingFlags` specifying compression and encryption options.
    ///
    /// # Returns
    /// Returns a tuple containing:
    /// * `BlockIndexEntry` - Metadata about the processed block for indexing.
    /// * `[u8; 32]` - The SHAKE256 hash of the block data.
    ///
    /// # Errors
    /// Returns `PithosWriterError` if any step fails.
    pub fn process_block(
        &mut self,
        chunk: &mut ChunkData,
        processing_flags: &ProcessingFlags,
    ) -> Result<(BlockIndexEntry, [u8; 32]), PithosWriterError> {
        // Calculate block hashes
        let mut hasher = Hasher::new();
        hasher.update(&chunk.data);
        let hashes = hasher.finalize();

        // Check if block already exists in directory
        if let Some(index) = self.directory.block_exists(hashes.blake3) {
            // Add block to FileEntry and continue with next chunk
            //file_entry.add_block_data((index, hashes.shake256))?;
            return Ok((index, hashes.shake256));
        }

        // Init BlockIndexEntry
        let mut block_index_entry = BlockIndexEntry {
            index: self.chunk_idx,
            hash: *hashes.blake3.as_bytes(),
            offset: self.written_bytes,
            stored_size: chunk.data.len() as u64,
            original_size: chunk.length as u64,
            flags: *processing_flags,
            location: BlockLocation::Local, //TODO: Remote files
        };

        // Compression
        let compression_level = map_to_zstd_level(processing_flags);
        if compression_level > 0
            && probe_compression_ratio(&chunk.data, Some(compression_level))? < 0.85
        {
            chunk.data = compress_data(chunk.data.as_slice(), None)?;
        } else {
            // No compression. But why? 15% is better than nothing.
            block_index_entry.flags.set_compression_level(0);
        }

        // Encryption
        if processing_flags.is_encrypted() {
            chunk.data = encrypt_chunk(chunk.data.as_slice(), b"", &hashes.shake256)?;
        }

        // Update stored size to processed block length
        block_index_entry.stored_size = chunk.data.len() as u64;

        Ok((block_index_entry, hashes.shake256))
    }

    /// Processes an entire file and adds it to the directory index.
    ///
    /// This function splits the file content into chunks using FastCDC, processes each chunk,
    /// writes the processed blocks to the sink, and updates the file entry and directory index
    /// accordingly. After all chunks are processed, the block index for the file is encrypted and
    /// the file entry is added to the directory. A reference to the processed file is returned.
    ///
    /// # Arguments
    /// * `file_entry` - Mutable reference to a `FileEntry` representing the file's metadata and block index.
    /// * `processing_flags` - Reference to `ProcessingFlags` specifying compression and encryption options.
    /// * `content` - Boxed trait object implementing `Read`, representing the file's content stream.
    ///
    /// # Returns
    /// Returns a `Reference` struct describing the relationship and ID of the processed file.
    ///
    /// # Errors
    /// Returns `PithosWriterError` if any step fails.
    pub fn process_file_entry(
        &mut self,
        file_entry: &mut FileEntry,
        processing_flags: &ProcessingFlags,
        content: Box<dyn Read>,
    ) -> Result<Reference, PithosWriterError> {
        // Split file content in chunks
        //TODO: Configurable
        let fastcdc_stream = StreamCDC::with_level(
            content,
            fastcdc::v2020::MINIMUM_MAX, //65536,   //1024,
            fastcdc::v2020::AVERAGE_MAX, //262144,  //4096,
            fastcdc::v2020::MAXIMUM_MAX, //1048576, //16384,
            fastcdc::v2020::Normalization::Level1,
        );

        // Iterate over CDC blocks
        for result in fastcdc_stream {
            // Process chunk
            let mut chunk = result?;
            let (block_index_entry, key) = self.process_block(&mut chunk, processing_flags)?;

            // Write block; Add block to file entry; Add block to index in directory
            self.write_block(&chunk.data)?;
            file_entry.add_block_data((block_index_entry.index, key))?;
            self.directory.add_block_to_index(block_index_entry);

            // Increment chunk index
            self.chunk_idx = self.chunk_idx.saturating_add(1);
        }

        // Create random key and encrypt file block index
        let enc_key = StaticSecret::random_from_rng(OsRng).to_bytes();
        file_entry.block_data.encrypt(enc_key)?;

        // Add file entry to directory
        self.directory.add_file_to_index(file_entry)?;
        self.directory
            .add_file_to_all_recipients((self.file_idx, enc_key));

        // Increment file index
        self.file_idx = self.file_idx.saturating_add(1);

        Ok(Reference {
            target_file_id: file_entry.file_id,
            relationship: match &file_entry.file_type {
                FileType::Data => 7,      // CONTAINS
                FileType::Metadata => 0,  // DESCRIBES
                FileType::Directory => 6, // PART_OF
                FileType::Symlink => 3,   // SOURCE_OF
            },
        })
    }

    pub fn process_input(
        &mut self,
        file: InputFile,
        strip_prefix: Option<&str>,
    ) -> Result<(), PithosWriterError> {
        // File input prelude
        let file_metadata = symlink_metadata(&file.file_path)?;
        let processing_flags = ProcessingFlags::new(file.encrypt, file.compression_level);
        let relative_path = if let Some(prefix) = strip_prefix {
            if let Some(stripped) = file.file_path.strip_prefix(prefix) {
                stripped
            } else {
                file.file_path.as_ref()
            }
        } else {
            file.file_path.as_ref()
        };

        let mut file_entry = FileEntry::new(
            self.file_idx,
            file.file_type,
            &file.file_path,
            relative_path,
            &file_metadata,
        )
        .map_err(|e| PithosWriterError::Other(e.to_string()))?;

        // Process metadata as individual file
        if let Some(metadata) = file.file_meta {
            let handle: Box<dyn Read> = match metadata {
                FileMeta::File(path) => Box::new(File::open(&path)?),
                FileMeta::Content(content) => Box::new(io::Cursor::new(content.into_bytes())),
            };
            let mut meta_file_entry = FileEntry::meta_from(&file_entry, file_metadata.len())?;
            let meta_processing_flags = ProcessingFlags::new(file.encrypt, file.compression_level);

            // Process and add reference to data file entry
            let reference =
                self.process_file_entry(&mut meta_file_entry, &meta_processing_flags, handle)?;
            file_entry.references.push(reference);
        }

        // Individual processing depending on file type
        match file.file_type {
            FileType::Directory | FileType::Symlink => {
                self.directory.add_file_to_index(&mut file_entry)?;
                self.file_idx = self.file_idx.saturating_add(1);
            }
            FileType::Data | FileType::Metadata => {
                self.process_file_entry(
                    &mut file_entry,
                    &processing_flags,
                    Box::new(File::open(&file.file_path)?),
                )?;
            }
        }

        // Supi
        Ok(())
    }

    #[allow(dead_code)]
    pub fn process_input_files(&mut self, files: Vec<InputFile>) -> Result<(), PithosWriterError> {
        for file in files {
            self.process_input(file, None)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn process_directory<P: AsRef<Path>>(
        &mut self,
        directory: P,
    ) -> Result<(), PithosWriterError> {
        // Walk directory and create file entries
        let mut entries = Vec::new();
        for entry in walkdir::WalkDir::new(&directory)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            let relative_path = entry
                .path()
                .strip_prefix(&directory)?
                .to_string_lossy()
                .to_string();

            if relative_path.is_empty() {
                continue; // Skip empty paths
            }

            // Store necessary info
            let input_file = InputFile {
                file_path: entry.path().to_string_lossy().to_string(),
                file_type: FileType::try_from(&symlink_metadata(entry.path())?)?,
                file_meta: None,
                encrypt: true,
                compression_level: Some(3),
            };
            entries.push(input_file);
        }

        // Sort directories to front and then by path
        entries.sort_by(|a, b| {
            if a.file_type == b.file_type {
                return a.file_path.to_lowercase().cmp(&b.file_path.to_lowercase());
            }
            a.file_type.cmp(&b.file_type)
        });

        // Process files
        let prefix = directory.as_ref().to_str().expect("non-utf8 path");
        for entry in entries {
            self.process_input(entry, Some(prefix))?;
        }

        Ok(())
    }

    pub fn process_directories<P: AsRef<Path>>(
        &mut self,
        directories: Vec<P>,
    ) -> Result<(), PithosWriterError> {
        for directory in directories {
            self.process_directory(directory)?
        }

        Ok(())
    }

    // Append to an existing Pithos file
    // Should only be used after existing pithos file was loaded:
    //   - Omits the file header
    //   - Also writes a new directory with offset to parent directory
    pub fn append_files(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    pub fn compress_block(
        &self,
        mut block: Vec<u8>,
        compression_level: u8,
    ) -> Result<Vec<u8>, ZstdError> {
        // Compress chunk
        let chunk_sample = if block.len() > 8192 {
            &block[..8192]
        } else {
            &block
        };

        if probe_compression_ratio(chunk_sample, Some(compression_level as i32))? < 0.85 {
            block = compress_data(&block, Some(compression_level as i32))?;
        }
        Ok(block)
    }

    /* ----- Write to sink ---------- */
    pub fn write_file_header(&mut self) -> Result<(), SerializationError> {
        FileHeader::default().serialize(&mut self.sink)?;
        self.written_bytes = self.written_bytes.saturating_add(6);
        Ok(())
    }

    pub fn write_block(&mut self, block: &[u8]) -> Result<(), SerializationError> {
        // Write BlockHeader
        BlockHeader::default().serialize(&mut self.sink)?;
        self.written_bytes = self.written_bytes.saturating_add(4); // Add BlockHeader length

        // Write block data
        self.sink.write_all(block)?;
        self.written_bytes = self.written_bytes.saturating_add(block.len() as u64);

        Ok(())
    }

    pub fn write_directory(&mut self) -> Result<(), SerializationError> {
        // Update len and crc32
        self.directory.update_len()?;
        self.directory.update_crc32()?;

        // Write directory
        self.directory.serialize(&mut self.sink)?;

        Ok(())
    }
}

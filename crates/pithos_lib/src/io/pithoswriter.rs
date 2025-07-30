use crate::helpers::chacha_poly1305::ChaChaPoly1305Error;
use crate::helpers::directory::DirectoryBuilder;
use crate::helpers::hash::Hasher;
use crate::helpers::x25519_keys::CryptError;
use crate::helpers::zstd::{ZstdError, map_to_zstd_level};
use crate::model::serialization::SerializationError;
use crate::model::structs::{
    BlockHeader, BlockIndexEntry, BlockLocation, Directory, EncryptionSection, FileEntry,
    ProcessingFlags, RecipientData, RecipientSection,
};
use crate::{
    helpers::{
        chacha_poly1305::encrypt_chunk,
        zstd::{compress_data, probe_compression_ratio},
    },
    model::structs::FileHeader,
};
use fastcdc::v2020::StreamCDC;
use rand_core::OsRng;
use std::fs::File;
use std::io;
use std::io::Write;
use x25519_dalek::{PublicKey, StaticSecret};

/// Error type for PithosReader operations
#[derive(Debug, thiserror::Error)]
pub enum PithosWriterError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),
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
    #[error("File not found: {0}")]
    FileNotFound(String),
    #[error("Invalid block data state: {0}")]
    InvalidBlockDataState(String),
    #[error("Invalid recipient data state: {0}")]
    InvalidRecipientDataState(String),
    #[error("Other error: {0}")]
    Other(String),
}

pub struct FileWithMetadata {
    pub file_path: String,
    pub file_name: String,
    pub file_metadata: String,
    pub encrypted: bool,
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

    pub fn new_from_file() -> anyhow::Result<Self> {
        //TODO: Read directory from file
        //TODO: Do stuff
        todo!()
    }

    // Create a new Pithos file from the input
    pub fn process_files(&mut self, files: Vec<FileWithMetadata>) -> Result<(), PithosWriterError> {
        // Write file header
        self.write_file_header()?;

        // Write files in CDC blocks
        for file in files.iter() {
            let file_handle = File::open(&file.file_path)?;
            let file_metadata = file_handle.metadata()?;
            let mut file_entry = FileEntry::new(self.file_idx, &file.file_path, file_metadata)
                .map_err(|e| PithosWriterError::Other(e.to_string()))?;
            let flags = ProcessingFlags::new(file.encrypted, file.compression_level);

            // Init FastCDC stream
            //TODO: Configurable
            let fastcdc_stream = StreamCDC::with_level(
                file_handle,
                65536,   //1024,
                262144,  //4096,
                1048576, //16384,
                fastcdc::v2020::Normalization::Level1,
            );

            // Iterate over CDC blocks
            for result in fastcdc_stream {
                let mut chunk = result?;

                // Calculate block hashes
                let mut hasher = Hasher::new();
                hasher.update(&chunk.data);
                let hashes = hasher.finalize();

                // Check if block already exists
                if let Some(index) = self.directory.block_exists(hashes.blake3) {
                    // Add block to FileEntry and continue with next chunk
                    file_entry.add_block_data((index, hashes.shake256))?;
                    continue;
                }

                // Init BlockIndexEntry
                let mut block_index_entry = BlockIndexEntry {
                    index: self.chunk_idx,
                    hash: *hashes.blake3.as_bytes(),
                    offset: self.written_bytes,
                    stored_size: chunk.data.len() as u64,
                    original_size: chunk.length as u64,
                    flags,
                    location: BlockLocation::Local, //TODO: Remote files
                };

                // Compression
                let compression_level = map_to_zstd_level(flags);
                if compression_level > 0
                    && probe_compression_ratio(&chunk.data, Some(compression_level))? < 0.85
                {
                    chunk.data = compress_data(chunk.data.as_slice(), None)?;
                } else {
                    // No compression. But why? 15% is better than nothing.
                    block_index_entry.flags.set_compression_level(0);
                }

                // Encryption
                if flags.is_encrypted() {
                    chunk.data = encrypt_chunk(chunk.data.as_slice(), b"", &hashes.shake256)?;
                }

                // Update stored size to processed block length
                block_index_entry.stored_size = chunk.data.len() as u64;

                // Write block; Add block to file entry; Add block to index in directory
                self.write_block(&chunk.data)?;
                file_entry.add_block_data((block_index_entry.index, hashes.shake256))?;
                self.directory.add_block_to_index(block_index_entry);
            }

            // Create random key and encrypt file block index
            let enc_key = StaticSecret::random_from_rng(OsRng).to_bytes();
            file_entry.block_data.encrypt(enc_key)?;

            // Add file entry to directory
            self.directory.add_file_to_index(file_entry);
            self.directory
                .add_file_to_all_recipients((self.file_idx, enc_key));

            // Increment file index
            self.file_idx = self.file_idx.saturating_add(1);
        }

        // Encrypt recipient data
        self.directory.encrypt_recipients(&self.writer_key)?;

        // Finish directory and write into sink
        self.directory.update_len()?;
        self.directory.update_crc32()?;
        self.directory.serialize(&mut self.sink)?;

        Ok(())
    }

    // Append to an existing Pithos file
    // Should only be used after existing pithos file was loaded:
    //   - Omits the file header
    //   - Writes a new directory with offset to parent directory
    pub fn append_files(&mut self) -> anyhow::Result<()> {
        todo!()
    }

    pub fn write_file_header(&mut self) -> Result<(), SerializationError> {
        FileHeader::default().serialize(&mut self.sink)?;
        self.written_bytes = self.written_bytes.saturating_add(6);
        Ok(())
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

        if probe_compression_ratio(&chunk_sample, Some(compression_level as i32))? < 0.85 {
            block = compress_data(&block, Some(compression_level as i32))?;
        }
        Ok(block)
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

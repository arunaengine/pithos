use bytes::BytesMut;
use fastcdc::v2020::StreamCDC;
use rand_core::OsRng;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::time::SystemTime;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::helpers::hash::Hasher;
use crate::model::structs::{
    BlockDataState, BlockHeader, BlockIndexEntry, BlockLocation, Directory, EncryptionSection,
    FileEntry, FileType, ProcessingFlags, RecipientData, RecipientSection,
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
    writer_key: StaticSecret,
    reader_keys: Vec<PublicKey>,
    files: Vec<FileWithMetadata>,
    sink: Box<dyn Write>,
}

impl PithosWriter {
    pub fn new(
        writer_key: StaticSecret,
        reader_keys: Vec<PublicKey>,
        files: Vec<FileWithMetadata>,
        sink: Box<dyn Write>,
    ) -> Self {
        PithosWriter {
            writer_key,
            reader_keys,
            files,
            sink,
        }
    }

    pub fn run(&mut self) -> anyhow::Result<()> {
        // Write file header
        let file_header = FileHeader::default().serialize_to_bytes()?;
        self.sink.write_all(&file_header)?;

        // Init directory and hashmap for easier EncryptionSection collection
        let mut directory = Directory::new()?;
        let mut encryption_sections: HashMap<[u8; 32], Vec<RecipientSection>> =
            HashMap::from_iter([(
                self.writer_key.to_bytes(),
                self.reader_keys
                    .iter()
                    .map(|k| RecipientSection {
                        recipient_public_key: k.to_bytes(),
                        recipient_data: RecipientData::Decrypted(Vec::new()),
                    })
                    .collect(),
            )]);

        // Write blocks and update directory
        let mut file_index = 0u64;
        let mut chunk_index = 0u64;
        let mut written_bytes = file_header.len() as u64;

        for file in &mut self.files {
            let file_handle = File::open(&file.file_path)?;
            let file_metadata = file_handle.metadata()?;
            let mut file_entry = FileEntry {
                file_id: file_index,
                path: file.file_name.clone(),
                file_type: FileType::Data, //TODO: Directory ingestion
                block_data: BlockDataState::Decrypted(vec![]),
                created: file_metadata
                    .created()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                modified: file_metadata
                    .modified()
                    .unwrap_or(SystemTime::UNIX_EPOCH)
                    .duration_since(SystemTime::UNIX_EPOCH)?
                    .as_secs(),
                file_size: file_metadata.len(),
                permissions: file_metadata.permissions().mode(),
                references: vec![],
                symlink_target: None,
            };

            let mut fastcdc_stream = StreamCDC::with_level(
                file_handle,
                65536,   //1024,
                262144,  //4096,
                1048576, //16384,
                fastcdc::v2020::Normalization::Level1,
            );
            while let Some(res) = fastcdc_stream.next() {
                match res {
                    Ok(chunk) => {
                        // Create mutable version of chunk data
                        let mut processed_chunk = BytesMut::from(chunk.data.as_slice());

                        // Compress chunk
                        let chunk_sample = if chunk.data.len() > 8192 {
                            &chunk.data[..8192]
                        } else {
                            &chunk.data
                        };
                        if probe_compression_ratio(&chunk_sample, None)
                            .map_err(|e| anyhow::anyhow!("Compression probe failed: {}", e))?
                            < 0.85
                        {
                            processed_chunk = BytesMut::from(
                                compress_data(&chunk.data, None)
                                    .map_err(|e| anyhow::anyhow!("Compression failed: {}", e))?
                                    .as_slice(),
                            );
                        }

                        // Calculate chunk hash
                        let mut hasher = Hasher::new();
                        hasher.update(&processed_chunk);
                        let hashes = hasher.finalize();
                        processed_chunk = encrypt_chunk(&processed_chunk, b"", &hashes.shake256)
                            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?
                            .into();

                        // Create BlockIndexEntry
                        //TODO: Block deduplication -> Iterate over existing chunks and compare hash
                        let block_index_entry = BlockIndexEntry {
                            index: chunk_index,
                            hash: *hashes.blake3.as_bytes(),
                            offset: written_bytes,
                            stored_size: processed_chunk.len() as u64,
                            original_size: chunk.length as u64,
                            flags: ProcessingFlags(0b0000_1110), //TODO: Configurable/Dynamic compression level
                            location: BlockLocation::Local,      //TODO: Remote files
                        };

                        // Write block
                        BlockHeader::default().serialize(&mut self.sink)?;
                        self.sink.write_all(&processed_chunk)?;
                        written_bytes =
                            written_bytes.saturating_add(4 + processed_chunk.len() as u64);

                        // Modify FileIndexEntry
                        match file_entry.block_data {
                            BlockDataState::Encrypted(_) => {
                                return Err(anyhow::anyhow!("Invalid BlockDataState::Encrypted"))
                            }
                            BlockDataState::Decrypted(ref mut blocks) => {
                                blocks.push((chunk_index, hashes.shake256))
                            }
                        }

                        // Add BlockIndexEntry to directory
                        directory.blocks.push(block_index_entry);

                        // Increment block counter
                        chunk_index = chunk_index.saturating_add(1);
                    }
                    Err(e) => {
                        //TODO: Error Handling
                        eprintln!("Error processing chunk: {}", e);
                        break; // Handle error as needed
                    }
                }
            }

            // Create random key and encrypt file block index
            let enc_key = StaticSecret::random_from_rng(OsRng).to_bytes();
            file_entry.block_data.encrypt(enc_key)?;

            // Add file entry to directory
            directory.files.push(file_entry);

            // Add to (currently all) recipient sections
            //TODO: Populate different encryption sections individually
            if let Some(sections) = encryption_sections.get_mut(&self.writer_key.to_bytes()) {
                for section in sections {
                    match section.recipient_data {
                        RecipientData::Encrypted(_) => {
                            return Err(anyhow::anyhow!("Invalid RecipientData state."))
                        }
                        RecipientData::Decrypted(ref mut entries) => {
                            entries.push((file_index, enc_key))
                        }
                    }
                }
            }

            // Increment file index
            file_index = file_index.saturating_add(1);
        }

        // Encrypt recipient data and integrate into directory
        //TODO: Multiple sender keys
        if let Some(sections) = encryption_sections.get_mut(&self.writer_key.to_bytes()) {
            // Create encryption section for sender key
            let mut enc_section = EncryptionSection {
                sender_public_key: PublicKey::from(&self.writer_key).to_bytes(),
                recipients: vec![],
            };

            // Add recipient sections to encryption section
            for section in sections {
                section.encrypt(&self.writer_key)?;
                enc_section.recipients.push(section.clone());
            }

            // Add encryption section to directory
            directory.encryption.push(enc_section);
        }

        // Finish directory and write into sink
        directory.update_len()?;
        directory.update_crc32()?;
        directory.serialize(&mut self.sink)?;

        Ok(())
    }

    pub fn write_header() -> anyhow::Result<()> {
        Ok(())
    }
}

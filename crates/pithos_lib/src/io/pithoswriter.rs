use crate::error::PithosError;
use crate::helpers::archive_path::{validate_candidate, validate_map};
use crate::helpers::directory::DirectoryBuilder;
use crate::helpers::file_entry_map::{FileEntryMap, Key};
use crate::helpers::hash::{Hasher, Hashes};
use crate::helpers::ro_crate::{
    LoadedRoCrate, RO_CRATE_METADATA_FILE, RoCrateSource, ZipEntryDescriptor, ZipEntryKind,
    inspect_ro_crate_zip_manifest,
};
use crate::helpers::zstd::{ZstdError, map_to_zstd_level};
use crate::io::pithosreader::PithosReaderSimple;
use crate::io::util::{create_stream_cdc, extract_filename};
use crate::model::serialization::SerializationError;
use crate::model::structs::{
    BlockHeader, BlockIndexEntry, BlockLocation, Directory, EncryptionSection, FileEntry, FileType,
    ProcessingFlags, Reference,
};
use crate::{
    helpers::{
        chacha_poly1305::encrypt_chunk,
        zstd::{compress_data, probe_compression_ratio},
    },
    model::structs::FileHeader,
};
use fastcdc::v2020::ChunkData;
use indexmap::IndexMap;
use std::fs;
use std::fs::{File, symlink_metadata};
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};
use zip::ZipArchive;

#[derive(Debug)]
pub enum Content {
    File(String),         // Path to file with content
    Raw(String),          // Raw string content
    Reference(Reference), // Reference to already existing file entry (Data -> copies BlockIndex; Metadata -> )
}

#[derive(Debug)]
pub struct InputFile {
    pub file_type: FileType,
    pub data: Content,
    pub metadata: Option<Content>,
    pub inner_path: String, // Internal path
    pub encrypt: bool,
    pub compression_level: Option<u8>,
}

impl TryFrom<&PathBuf> for InputFile {
    type Error = PithosError;

    fn try_from(file_path: &PathBuf) -> Result<Self, Self::Error> {
        let metadata = symlink_metadata(file_path)?;
        let file_type = FileType::try_from(&metadata)?;
        let file_path_str = file_path
            .to_str()
            .ok_or(PithosError::Conversion(
                "Invalid UTF-8 in file path".to_string(),
            ))?
            .to_string();
        let inner_path = match &file_type {
            FileType::Directory => file_path_str.as_str(),
            _ => extract_filename(&file_path_str).expect("Input file is missing file name."),
        };

        Ok(InputFile {
            file_type,
            inner_path: inner_path.to_string(),
            data: if file_type == FileType::Data
                || file_type == FileType::Directory
                || file_type == FileType::Symlink
            {
                Content::File(file_path_str)
            } else {
                Content::Raw("".to_string())
            },
            metadata: None,
            encrypt: true,
            compression_level: Some(2),
        })
    }
}

fn collect_directory_entries(directory: &Path) -> Result<Vec<InputFile>, PithosError> {
    if !directory.is_dir() {
        return Err(PithosError::Conversion(format!(
            "Input path is not a directory: {}",
            directory.display()
        )));
    }

    let mut entries = Vec::new();
    for entry in walkdir::WalkDir::new(directory) {
        let entry = entry?;
        let relative_path = entry.path().strip_prefix(directory)?;

        if relative_path.as_os_str().is_empty() {
            continue;
        }

        let inner_path = relative_path
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .ok_or(PithosError::Conversion(
                        "Invalid UTF-8 in file path".to_string(),
                    ))
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        let file_type = FileType::try_from(&symlink_metadata(entry.path())?)?;
        let file_path = entry
            .path()
            .to_str()
            .ok_or(PithosError::Conversion(
                "Invalid UTF-8 in file path".to_string(),
            ))?
            .to_string();

        entries.push(InputFile {
            file_type,
            inner_path,
            data: Content::File(file_path),
            metadata: None,
            encrypt: true,
            compression_level: Some(2),
        });
    }

    entries.sort_by(|a, b| {
        a.file_type
            .cmp(&b.file_type)
            .then_with(|| {
                a.inner_path
                    .to_lowercase()
                    .cmp(&b.inner_path.to_lowercase())
            })
            .then_with(|| a.inner_path.cmp(&b.inner_path))
    });

    Ok(entries)
}

fn file_entry_from_ro_crate_zip_descriptor(descriptor: &ZipEntryDescriptor) -> FileEntry {
    let file_type = match descriptor.kind {
        ZipEntryKind::Directory => FileType::Directory,
        ZipEntryKind::File => FileType::Data,
        ZipEntryKind::Symlink => FileType::Symlink,
    };

    FileEntry::new_from_archive(
        file_type,
        descriptor.uncompressed_size,
        descriptor.timestamp,
        descriptor.timestamp,
        descriptor.permissions,
        None,
    )
}

pub struct PithosWriter {
    // Input
    writer_key: StaticSecret, //TODO: Multiple sender keys for individual EncryptionSections
    cdc: Option<(usize, usize, usize)>,
    sink: Box<dyn Write>,

    // Processing
    directory: Directory, // Single or merged from multiple
    written_bytes: u64,
}

impl PithosWriter {
    #[tracing::instrument(level = "trace", skip(writer_key, reader_keys, cdc, sink))]
    pub fn new(
        writer_key: StaticSecret,
        reader_keys: Vec<PublicKey>,
        cdc: Option<(usize, usize, usize)>,
        sink: Box<dyn Write>,
    ) -> Result<Self, PithosError> {
        // Init encryption section
        let encryption_sections = IndexMap::from_iter([(
            PublicKey::from(&writer_key).to_bytes(),
            EncryptionSection::new(&reader_keys),
        )]);

        Ok(PithosWriter {
            writer_key,
            cdc,
            sink,
            directory: DirectoryBuilder::new()
                .encryption(encryption_sections)
                .build()?,
            written_bytes: 0,
        })
    }

    #[tracing::instrument(level = "trace", skip(writer_key, reader_keys, cdc, pithos_file))]
    pub fn new_from_file<P: AsRef<Path>>(
        writer_key: StaticSecret,
        reader_keys: Vec<PublicKey>,
        cdc: Option<(usize, usize, usize)>,
        pithos_file: P,
    ) -> Result<Self, PithosError> {
        // Read existing directories
        let mut reader = PithosReaderSimple::new_with_key(&pithos_file, writer_key.clone())?;
        let (directory, offset) = reader.read_directory()?;

        // Open Pithos file in append write mode
        let file = fs::OpenOptions::new()
            //.read(true) //?
            .append(true)
            .open(pithos_file)?;
        let written_bytes = file.metadata()?.len();
        let sink = Box::new(file);

        Ok(PithosWriter {
            directory: DirectoryBuilder::new()
                .parent_directory_offset(Some(offset))
                .files(FileEntryMap::new_with_max(
                    directory.files.get_current_max_id(),
                ))
                .encryption(IndexMap::from_iter([(
                    PublicKey::from(&writer_key).to_bytes(),
                    EncryptionSection::new(&reader_keys),
                )]))
                .build()?,
            written_bytes,
            writer_key,
            cdc,
            sink,
        })
    }

    pub fn get_directory_mut(&mut self) -> &mut Directory {
        &mut self.directory
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
    #[tracing::instrument(level = "trace", skip(self, chunk, processing_flags))]
    pub fn process_block(
        &mut self,
        chunk: &mut ChunkData,
        processing_flags: &ProcessingFlags,
    ) -> Result<(BlockIndexEntry, Hashes, bool), PithosError> {
        // Calculate block hashes
        let mut hasher = Hasher::new();
        hasher.update(&chunk.data);
        let hashes = hasher.finalize();

        // Check if block already exists in directory
        if let Some(entry) = self.directory.block_hash_exists(&hashes.blake3) {
            // Return already existing block entry
            return Ok((entry, hashes, true));
        }

        // Init BlockIndexEntry
        let mut block_index_entry = BlockIndexEntry {
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
            chunk.data = compress_data(chunk.data.as_slice(), Some(compression_level))?;
        } else {
            // No compression, as the input is likely to have high entropy
            block_index_entry.flags.set_compression_level(0);
        }

        // Encryption
        if processing_flags.is_encrypted() {
            chunk.data = encrypt_chunk(chunk.data.as_slice(), b"", &hashes.shake256)?;
        }

        // Update stored size to processed block length
        block_index_entry.stored_size = chunk.data.len() as u64;

        Ok((block_index_entry, hashes, false))
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
    /// * `content` - Reader representing the file's content stream.
    ///
    /// # Returns
    /// Returns a `Reference` struct describing the relationship and ID of the processed file.
    ///
    /// # Errors
    /// Returns `PithosWriterError` if any step fails.
    #[tracing::instrument(level = "trace", skip(self, file_entry, processing_flags, content))]
    pub fn process_file_entry<R: Read>(
        &mut self,
        entry_path: &str,
        file_entry: &mut FileEntry,
        processing_flags: &ProcessingFlags,
        content: R,
    ) -> Result<Reference, PithosError> {
        validate_candidate(&self.directory.files, entry_path, file_entry)?;
        // Directory or Symlink FileEntry are just added to Pithos directory
        let file_entry_key = Key::new(
            self.directory.next_free_file_index(),
            entry_path.to_string(),
        );

        if [FileType::Directory, FileType::Symlink].contains(&file_entry.file_type) {
            self.directory
                .add_file_to_index(&file_entry_key, file_entry)?;

            return Reference::try_from((&file_entry_key, file_entry));
        }

        // Split content in chunks
        let fastcdc_stream = create_stream_cdc(content, self.cdc);

        // Iterate over CDC blocks
        for result in fastcdc_stream {
            // Process chunk
            let mut chunk = result?;
            let (block_entry, hashes, deduplicated) =
                self.process_block(&mut chunk, processing_flags)?;

            // Add block to file entry
            file_entry.add_block_data((*hashes.blake3.as_bytes(), hashes.shake256))?;
            if !deduplicated {
                // If block is no duplicate write block into sink and add to directory index
                self.write_block(&chunk.data)?;
                self.directory
                    .add_block_to_index(*hashes.blake3.as_bytes(), block_entry)?;
            }
        }

        // Create random key and encrypt file block index
        let enc_key = StaticSecret::random().to_bytes();
        file_entry.block_data.encrypt(enc_key)?;

        // Add file entry to directory
        self.directory
            .add_file_to_index(&file_entry_key, file_entry)?;
        self.directory
            .add_file_to_all_recipients((file_entry_key.id(), enc_key));

        // Return reference according to FileType
        Reference::try_from((&file_entry_key, file_entry))
    }

    #[tracing::instrument(level = "trace", skip(self, input))]
    pub fn process_input(&mut self, input: InputFile) -> Result<Reference, PithosError> {
        let data_check = FileEntry::new_from_content(input.file_type, &input.data)?;
        validate_candidate(&self.directory.files, &input.inner_path, &data_check)?;
        let mut preflight = self.directory.files.clone();
        preflight.insert(
            Key::new(preflight.next_free_id(false), input.inner_path.clone()),
            data_check.clone(),
        )?;
        if let Some(metadata) = &input.metadata
            && !matches!(metadata, Content::Reference(_))
        {
            let metadata_check = FileEntry::new_from_content(FileType::Metadata, metadata)?;
            validate_candidate(
                &preflight,
                &format!("{}.meta", input.inner_path),
                &metadata_check,
            )?;
        }
        // Create FileEntry with its ProcessingFlags from data file input
        let mut data_file = data_check;
        let processing_flags = ProcessingFlags::new(input.encrypt, input.compression_level);

        // First process metadata to add reference
        if let Some(metadata) = input.metadata {
            let meta_file_path = &format!("{}.meta", input.inner_path);

            let reference = match &metadata {
                Content::File(disk_path) => {
                    let mut meta_file = FileEntry::new_from_content(FileType::Metadata, &metadata)?;
                    let handle = File::open(disk_path)?;
                    self.process_file_entry(
                        meta_file_path,
                        &mut meta_file,
                        &processing_flags,
                        handle,
                    )?
                }
                Content::Raw(raw_content) => {
                    let mut meta_file = FileEntry::new_from_content(FileType::Metadata, &metadata)?;
                    let handle = Cursor::new(raw_content.clone().into_bytes());
                    self.process_file_entry(
                        meta_file_path,
                        &mut meta_file,
                        &processing_flags,
                        handle,
                    )?
                }
                Content::Reference(reference) => reference.clone(),
            };

            data_file.references.push(reference);
        }

        // Process data FileEntry
        let data_reference = match input.data {
            Content::File(disk_path)
                if [FileType::Data, FileType::Metadata].contains(&input.file_type) =>
            {
                let handle = File::open(disk_path)?;
                self.process_file_entry(
                    &input.inner_path,
                    &mut data_file,
                    &processing_flags,
                    handle,
                )?
            }
            Content::File(_) => self.process_file_entry(
                &input.inner_path,
                &mut data_file,
                &processing_flags,
                Cursor::new(Vec::<u8>::new()),
            )?,
            Content::Raw(raw_content) => {
                let handle = Cursor::new(raw_content.into_bytes());
                self.process_file_entry(
                    &input.inner_path,
                    &mut data_file,
                    &processing_flags,
                    handle,
                )?
            }
            Content::Reference(reference) => {
                // Clone content (block_data) into new FileEntry
                let ref_fe = self
                    .directory
                    .get_file_by_id(reference.target_file_id)
                    .ok_or(PithosError::FileNotFound(format!(
                        "Could not find reference. FileEntry with id {} does not exist.",
                        reference.target_file_id
                    )))?;
                data_file.block_data = ref_fe.block_data.clone();

                // Fetch encryption key of referenced file
                // Add file entry to directory and make it available for all recipients
                if let Some(enc_key) = self
                    .directory
                    .get_file_encryption_key(reference.target_file_id)
                {
                    let file_entry_key =
                        Key::new(self.directory.next_free_file_index(), &input.inner_path);
                    self.directory.add_file(&input.inner_path, &data_file)?;
                    self.directory
                        .add_file_to_all_recipients((file_entry_key.id(), enc_key));

                    Reference::try_from((&file_entry_key, &mut data_file))?
                } else {
                    return Err(PithosError::FileNotFound(format!(
                        "Could not extract key for file: {}",
                        input.inner_path
                    )));
                }
            }
        };

        Ok(data_reference)
    }

    #[tracing::instrument(level = "trace", skip(self, files))]
    pub fn process_input_files(&mut self, files: Vec<InputFile>) -> Result<(), PithosError> {
        for file in files {
            tracing::info!("Processing [{:?}] {}", file.file_type, file.inner_path);
            match file.file_type {
                FileType::Directory => self.process_directory(file.inner_path)?,
                _ => {
                    self.process_input(file)?;
                }
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, directory))]
    pub fn process_directory<P: AsRef<Path>>(&mut self, directory: P) -> Result<(), PithosError> {
        for entry in collect_directory_entries(directory.as_ref())? {
            tracing::info!("Processing [{:?}] {}", entry.file_type, entry.inner_path);
            self.process_input(entry)?;
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, directories))]
    pub fn process_directories<P: AsRef<Path>>(
        &mut self,
        directories: Vec<P>,
    ) -> Result<(), PithosError> {
        for directory in directories {
            self.process_directory(directory)?
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, block, compression_level))]
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

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn write_file_header(&mut self) -> Result<(), SerializationError> {
        FileHeader::default().serialize(&mut self.sink)?;
        self.written_bytes = self.written_bytes.saturating_add(6);
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, block))]
    pub fn write_block(&mut self, block: &[u8]) -> Result<(), SerializationError> {
        // Write BlockHeader
        BlockHeader::default().serialize(&mut self.sink)?;
        self.written_bytes = self.written_bytes.saturating_add(4); // Add BlockHeader length

        // Write block data
        self.sink.write_all(block)?;
        self.written_bytes = self.written_bytes.saturating_add(block.len() as u64);

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn write_directory(&mut self) -> Result<(), PithosError> {
        validate_map(&self.directory.files)?;
        // Encrypt recipients of writer section
        self.directory.encrypt_recipients(&self.writer_key)?;

        // Update len and crc32
        self.directory.update_len()?;
        self.directory.update_crc32()?;

        // Write directory
        self.directory.serialize(&mut self.sink)?;

        Ok(())
    }

    fn process_ro_crate_directory(&mut self, directory: &Path) -> Result<(), PithosError> {
        let mut entries = collect_directory_entries(directory)?;
        let metadata_index = entries
            .iter()
            .position(|entry| entry.inner_path == RO_CRATE_METADATA_FILE)
            .ok_or_else(|| PithosError::MissingRoCrateMetadata(directory.to_path_buf()))?;

        if entries[metadata_index].file_type != FileType::Data {
            return Err(PithosError::InvalidRoCrateSource {
                path: directory.join(RO_CRATE_METADATA_FILE),
                expected: "regular metadata file",
            });
        }

        let mut metadata = entries.remove(metadata_index);
        metadata.file_type = FileType::Metadata;
        let metadata_reference = self.process_input(metadata)?;

        for mut entry in entries {
            if entry.file_type == FileType::Data {
                entry.metadata = Some(Content::Reference(metadata_reference.clone()));
            }
            self.process_input(entry)?;
        }

        Ok(())
    }

    fn process_ro_crate_zip(&mut self, path: &Path) -> Result<(), PithosError> {
        let manifest = inspect_ro_crate_zip_manifest(path)?;
        let metadata = manifest.metadata.clone();
        let metadata_index = metadata
            .archive_index
            .ok_or_else(|| PithosError::MissingRoCrateMetadata(path.to_path_buf()))?;
        let mut archive = ZipArchive::new(File::open(path)?)?;
        let processing_flags = ProcessingFlags::new(true, Some(2));

        let mut metadata_file_entry = file_entry_from_ro_crate_zip_descriptor(&metadata);
        metadata_file_entry.file_type = FileType::Metadata;
        let metadata_reference = {
            let member = archive.by_index(metadata_index)?;
            self.process_file_entry(
                &metadata.inner_path,
                &mut metadata_file_entry,
                &processing_flags,
                member,
            )?
        };

        for descriptor in manifest.entries {
            let mut file_entry = file_entry_from_ro_crate_zip_descriptor(&descriptor);
            if file_entry.file_type == FileType::Data {
                file_entry.references.push(metadata_reference.clone());
            }

            match descriptor.kind {
                ZipEntryKind::Directory => {
                    self.process_file_entry(
                        &descriptor.inner_path,
                        &mut file_entry,
                        &processing_flags,
                        Cursor::new(Vec::<u8>::new()),
                    )?;
                }
                ZipEntryKind::File => {
                    let index = descriptor.archive_index.ok_or_else(|| {
                        PithosError::UnsupportedZipEntry(descriptor.inner_path.clone())
                    })?;
                    {
                        let member = archive.by_index(index)?;
                        self.process_file_entry(
                            &descriptor.inner_path,
                            &mut file_entry,
                            &processing_flags,
                            member,
                        )?;
                    }
                }
                ZipEntryKind::Symlink => {
                    let index = descriptor.archive_index.ok_or_else(|| {
                        PithosError::UnsupportedZipEntry(descriptor.inner_path.clone())
                    })?;
                    let target = {
                        let mut member = archive.by_index(index)?;
                        let mut target = String::new();
                        member.read_to_string(&mut target)?;
                        target
                    };
                    file_entry.symlink_target = Some(target);
                    self.process_file_entry(
                        &descriptor.inner_path,
                        &mut file_entry,
                        &processing_flags,
                        Cursor::new(Vec::<u8>::new()),
                    )?;
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, loaded))]
    pub fn process_ro_crate(&mut self, loaded: &LoadedRoCrate) -> Result<(), PithosError> {
        match &loaded.source {
            RoCrateSource::Directory(path) => self.process_ro_crate_directory(path),
            RoCrateSource::Zip(path) => self.process_ro_crate_zip(path),
        }
    }
}

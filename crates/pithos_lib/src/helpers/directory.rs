use crate::error::PithosError;
use crate::model::serialization::encode_string;
use crate::model::structs::{RecipientData, RecipientSection};
use crate::model::{
    serialization::SerializationError,
    structs::{BlockIndexEntry, Directory, EncryptionSection, FileEntry},
};
use crc32fast::Hasher;
use indexmap::IndexMap;
use indexmap::map::Entry;
use integer_encoding::VarIntWriter;
use std::io::Write;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct DirectoryBuilder {
    identifier: [u8; 8],
    parent_directory_offset: Option<(u64, u64)>,
    files: Vec<FileEntry>,
    blocks: IndexMap<[u8; 32], BlockIndexEntry>,
    relations: Vec<(u64, String)>,
    encryption: IndexMap<[u8; 32], EncryptionSection>,
    dir_len: u64,
}

impl Default for DirectoryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryBuilder {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> Self {
        DirectoryBuilder {
            identifier: *b"PITHOSDR",
            parent_directory_offset: None,
            files: vec![],
            blocks: IndexMap::new(),
            relations: vec![],
            encryption: IndexMap::new(),
            dir_len: 8,
        }
    }

    #[tracing::instrument(level = "trace", skip(self, offset))]
    pub fn parent_directory_offset(mut self, offset: Option<(u64, u64)>) -> Self {
        self.parent_directory_offset = offset;
        self
    }

    #[tracing::instrument(level = "trace", skip(self, files))]
    pub fn files(mut self, files: Vec<FileEntry>) -> Self {
        self.files = files;
        self
    }

    #[tracing::instrument(level = "trace", skip(self, blocks))]
    pub fn blocks(mut self, blocks: IndexMap<[u8; 32], BlockIndexEntry>) -> Self {
        self.blocks = blocks;
        self
    }

    #[tracing::instrument(level = "trace", skip(self, relations))]
    pub fn relations(mut self, relations: Vec<(u64, String)>) -> Self {
        self.relations = relations;
        self
    }

    #[tracing::instrument(level = "trace", skip(self, encryption))]
    pub fn encryption(mut self, encryption: IndexMap<[u8; 32], EncryptionSection>) -> Self {
        self.encryption = encryption;
        self
    }

    #[tracing::instrument(level = "trace", skip(self, dir_len))]
    pub fn dir_len(mut self, dir_len: u64) -> Self {
        self.dir_len = dir_len;
        self
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn build(self) -> Result<Directory, SerializationError> {
        // Calculate CRC32 of all fields using bincode serialization
        let mut buf = Vec::new();
        if let Some((start, len)) = self.parent_directory_offset {
            buf.extend(&[1u8]);
            buf.write_varint(start)?;
            buf.write_varint(len)?;
        }
        for file in &self.files {
            file.serialize(&mut buf)?
        }
        for (hash, block) in &self.blocks {
            buf.write_all(hash)?;
            block.serialize(&mut buf)?
        }
        buf.write_varint(self.relations.len() as u64)?;
        for (idx, name) in &self.relations {
            buf.write_varint(*idx)?;
            encode_string(&mut buf, name)?;
        }
        for (key, enc) in &self.encryption {
            buf.write_all(key)?;
            enc.serialize(&mut buf)?
        }
        buf.write_varint(self.dir_len)?;

        // Calculate CRC32 checksum
        let mut hasher = Hasher::new();
        hasher.update(&buf);
        let checksum = hasher.finalize();

        Ok(Directory {
            identifier: self.identifier,
            parent_directory_offset: self.parent_directory_offset,
            files: self.files,
            blocks: self.blocks,
            relations: self.relations,
            encryption: self.encryption,
            dir_len: self.dir_len,
            crc32: checksum,
        })
    }
}

impl Directory {
    #[tracing::instrument(level = "trace", skip())]
    pub fn new() -> Result<Self, SerializationError> {
        DirectoryBuilder::new().build()
    }

    #[tracing::instrument(level = "trace", skip(self, newer_directory))]
    pub fn merge(&mut self, newer_directory: Directory) -> Result<(), PithosError> {
        // Append files (also checks for duplicate file_id and path duplicates)
        self.add_files_to_index(newer_directory.files)?;

        // Append blocks
        self.add_blocks_to_index(newer_directory.blocks)?;

        // Append relations
        self.add_relation_definitions(newer_directory.relations)?;

        // Merge encryption sections
        //  - Merge sections that can be decrypted
        //  - Drop encryption sections which already exist ???
        for (section_key, new_section) in newer_directory.encryption {
            match self.encryption.entry(section_key) {
                Entry::Occupied(ref mut entry) => {
                    // Encryption section does not exist -> merge decrypted recipients
                    for (recipient_key, new_recipient) in new_section.recipients {
                        match entry.get_mut().recipients.get_mut(&recipient_key) {
                            Some(existing_recipient) => {
                                merge_recipient_data(
                                    &mut existing_recipient.recipient_data,
                                    new_recipient.recipient_data,
                                );
                            }
                            None => {
                                entry
                                    .get_mut()
                                    .recipients
                                    .insert(recipient_key, new_recipient);
                            }
                        }
                    }
                }
                Entry::Vacant(entry) => {
                    // Encryption section does not exist -> insert
                    entry.insert(new_section);
                    return Ok(());
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, hash))]
    pub fn block_hash_exists(&mut self, hash: &blake3::Hash) -> Option<BlockIndexEntry> {
        if let Entry::Occupied(entry) = self.blocks.entry(*hash.as_bytes()) {
            Some(entry.get().clone())
        } else {
            None
        }
    }

    #[tracing::instrument(level = "trace", skip(self, block_index_entries))]
    pub fn add_blocks_to_index(
        &mut self,
        block_index_entries: IndexMap<[u8; 32], BlockIndexEntry>,
    ) -> Result<(), PithosError> {
        for (hash, block) in block_index_entries {
            self.add_block_to_index(hash, block)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, block_hash, block_entry))]
    pub fn add_block_to_index(
        &mut self,
        block_hash: [u8; 32],
        block_entry: BlockIndexEntry,
    ) -> Result<(), PithosError> {
        self.blocks.insert(block_hash, block_entry);
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, file_entry))]
    pub fn add_file_to_index(&mut self, file_entry: &FileEntry) -> Result<(), PithosError> {
        // Check for file_id or path duplicates
        for file in &self.files {
            if file.file_id == file_entry.file_id || file.path == file_entry.path {
                return Err(PithosError::PathOccupied(file_entry.path.clone()));
            }
        }

        self.files.push(file_entry.clone());
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, file_entries))]
    pub fn add_files_to_index(&mut self, file_entries: Vec<FileEntry>) -> Result<(), PithosError> {
        for entry in file_entries {
            self.add_file_to_index(&entry)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, writer_key, reader_key, file_entry))]
    pub fn add_file_to_recipient(
        &mut self,
        writer_key: &StaticSecret,
        reader_key: &PublicKey,
        file_entry: (u64, [u8; 32]), // (file index, encryption key)
    ) -> Result<(), PithosError> {
        let _: () = match self.encryption.entry(*writer_key.as_bytes()) {
            Entry::Occupied(ref mut entry) => {
                match entry.get_mut().recipients.entry(reader_key.to_bytes()) {
                    Entry::Occupied(ref mut entry) => {
                        entry.get_mut().add_file_to_recipient(file_entry)?
                    }
                    Entry::Vacant(vacant) => {
                        vacant.insert(RecipientSection {
                            recipient_data: RecipientData::Decrypted(vec![]),
                        });
                    }
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(EncryptionSection {
                    recipients: IndexMap::from_iter([(
                        reader_key.to_bytes(),
                        RecipientSection {
                            recipient_data: RecipientData::Decrypted(vec![]),
                        },
                    )]),
                });
            }
        };
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, entry))]
    pub fn add_file_to_all_recipients(&mut self, entry: (u64, [u8; 32])) {
        for (_, e_section) in self.encryption.iter_mut() {
            for (_, r_section) in e_section.recipients.iter_mut() {
                match r_section.recipient_data {
                    RecipientData::Encrypted(_) => {
                        // Won't add files to encrypted sections ¯\_(ツ)_/¯
                    }
                    RecipientData::Decrypted(ref mut entries) => {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    #[tracing::instrument(level = "trace", skip(self, relation))]
    pub fn add_relation_definition(&mut self, relation: (u64, String)) -> Result<(), PithosError> {
        for existing_relation in &self.relations {
            if existing_relation.0 == relation.0 {
                return Err(PithosError::RelationIdOccupied(relation.0));
            }
        }

        self.relations.push(relation);
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, relations))]
    pub fn add_relation_definitions(
        &mut self,
        relations: Vec<(u64, String)>,
    ) -> Result<(), PithosError> {
        for relation in relations {
            self.add_relation_definition(relation)?;
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn next_free_file_index(&self) -> u64 {
        if let Some(idx) = self.files.iter().max_by_key(|file| file.file_id) {
            idx.file_id + 1
        } else {
            0
        }
    }

    #[tracing::instrument(level = "trace", skip(self, path))]
    pub fn get_file_by_path(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|file| file.path == path)
    }

    #[tracing::instrument(level = "trace", skip(self, file_id))]
    pub fn get_file_by_id(&self, file_id: u64) -> Option<&FileEntry> {
        self.files.iter().find(|file| file.file_id == file_id)
    }

    // Checks only decrypted recipient sections
    #[tracing::instrument(level = "trace", skip(self, file_id))]
    pub fn get_file_encryption_key(&self, file_id: u64) -> Option<[u8; 32]> {
        for (_, e_section) in &self.encryption {
            for (_, r_section) in &e_section.recipients {
                if let RecipientData::Decrypted(entries) = &r_section.recipient_data
                    && let Some((_, key)) = entries.iter().find(|(k, _)| *k == file_id)
                {
                    return Some(*key);
                }
            }
        }
        None
    }

    #[tracing::instrument(level = "trace", skip(self, writer_key))]
    pub fn encrypt_recipients(&mut self, writer_key: &StaticSecret) -> Result<(), PithosError> {
        let writer_pubkey = PublicKey::from(writer_key);
        for (sender_pubkey, e_section) in self.encryption.iter_mut() {
            if writer_pubkey.as_bytes() == sender_pubkey {
                for (recipient_pubkey, r_section) in e_section.recipients.iter_mut() {
                    let reader_pubkey = PublicKey::from(*recipient_pubkey);
                    let shared_key = writer_key.diffie_hellman(&reader_pubkey);
                    r_section.recipient_data.encrypt(&shared_key)?;
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, reader_key))]
    pub fn decrypt_recipient(
        &mut self,
        reader_key: &StaticSecret,
    ) -> Result<Vec<(u64, [u8; 32])>, PithosError> {
        // Store for decrypted sections
        let mut available_file_indices = Vec::<(u64, [u8; 32])>::new();
        let reader_pubkey = PublicKey::from(reader_key);

        // Check if key is sender key -> Decrypt complete encryption section
        if let Entry::Occupied(mut entry) = self.encryption.entry(*reader_pubkey.as_bytes()) {
            for (key, r_section) in entry.get_mut().recipients.iter_mut() {
                let shared_key = reader_key.diffie_hellman(&PublicKey::from(*key));
                match &r_section.recipient_data {
                    RecipientData::Encrypted(_) => {
                        let entries = r_section.recipient_data.decrypt(&shared_key)?;
                        available_file_indices.extend(entries);
                    }
                    RecipientData::Decrypted(entries) => {
                        available_file_indices.extend(entries);
                    }
                }
            }
        }

        // Iterate available encryption sections as the key still could be used as recipient in other sections
        for (sender_pubkey, e_section) in self.encryption.iter_mut() {
            let sender_pubkey = PublicKey::from(*sender_pubkey);

            // Skip section if reader key is from sender -> Already decrypted above
            if sender_pubkey == reader_pubkey {
                continue;
            }

            let shared_key = reader_key.diffie_hellman(&sender_pubkey);

            match e_section.recipients.entry(*reader_pubkey.as_bytes()) {
                Entry::Occupied(ref mut entry) => match &entry.get().recipient_data {
                    RecipientData::Encrypted(_) => {
                        let entries = entry.get_mut().recipient_data.decrypt(&shared_key)?;
                        available_file_indices.extend(entries);
                    }
                    RecipientData::Decrypted(entries) => {
                        available_file_indices.extend(entries);
                    }
                },
                Entry::Vacant(_) => {
                    // Recipient does not exist in encryption section
                }
            }
        }

        Ok(available_file_indices)
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn update_len(&mut self) -> Result<(), SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        self.dir_len = buf.len() as u64;
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self))]
    pub fn update_crc32(&mut self) -> Result<(), SerializationError> {
        let mut buf = Vec::new();
        if let Some((start, len)) = self.parent_directory_offset {
            buf.extend(&[1u8]);
            buf.write_varint(start)?;
            buf.write_varint(len)?;
        }
        for file in &self.files {
            file.serialize(&mut buf)?
        }
        for (hash, block) in &self.blocks {
            buf.write_all(hash)?;
            block.serialize(&mut buf)?
        }
        buf.write_varint(self.relations.len() as u64)?;
        for (idx, name) in &self.relations {
            buf.write_varint(*idx)?;
            encode_string(&mut buf, name)?;
        }
        for (key, enc) in &self.encryption {
            buf.write_all(key)?;
            enc.serialize(&mut buf)?
        }
        buf.write_varint(self.dir_len)?;

        // Calculate CRC32 checksum
        let mut hasher = Hasher::new();
        hasher.update(&buf);
        self.crc32 = hasher.finalize();

        Ok(())
    }
}

#[tracing::instrument(level = "trace", skip(existing, new))]
fn merge_recipient_data(existing: &mut RecipientData, new: RecipientData) {
    if let (RecipientData::Decrypted(existing_files), RecipientData::Decrypted(new_files)) =
        (existing, new)
    {
        existing_files.extend(new_files);
    }
}

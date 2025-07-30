use crate::io::pithosreader::PithosReaderError;
use crate::io::pithoswriter::PithosWriterError;
use crate::model::serialization::encode_string;
use crate::model::structs::RecipientData;
use crate::model::{
    serialization::SerializationError,
    structs::{BlockIndexEntry, Directory, EncryptionSection, FileEntry},
};
use crc32fast::Hasher;
use integer_encoding::VarIntWriter;
use x25519_dalek::{PublicKey, StaticSecret};

pub struct DirectoryBuilder {
    identifier: [u8; 8],
    parent_directory_offset: Option<(u64, u64)>,
    files: Vec<FileEntry>,
    blocks: Vec<BlockIndexEntry>,
    relations: Vec<(u64, String)>,
    encryption: Vec<EncryptionSection>,
    dir_len: u64,
}

impl DirectoryBuilder {
    pub fn new() -> Self {
        DirectoryBuilder {
            identifier: *b"PITHOSDR",
            parent_directory_offset: None,
            files: vec![],
            blocks: vec![],
            relations: vec![],
            encryption: vec![],
            dir_len: 8,
        }
    }

    pub fn parent_directory_offset(mut self, offset: Option<(u64, u64)>) -> Self {
        self.parent_directory_offset = offset;
        self
    }

    pub fn files(mut self, files: Vec<FileEntry>) -> Self {
        self.files = files;
        self
    }

    pub fn blocks(mut self, blocks: Vec<BlockIndexEntry>) -> Self {
        self.blocks = blocks;
        self
    }

    pub fn relations(mut self, relations: Vec<(u64, String)>) -> Self {
        self.relations = relations;
        self
    }

    pub fn encryption(mut self, encryption: Vec<EncryptionSection>) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn dir_len(mut self, dir_len: u64) -> Self {
        self.dir_len = dir_len;
        self
    }

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
        for block in &self.blocks {
            block.serialize(&mut buf)?
        }
        buf.write_varint(self.relations.len() as u64)?;
        for (idx, name) in &self.relations {
            buf.write_varint(*idx)?;
            encode_string(&mut buf, name)?;
        }
        for enc in &self.encryption {
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
    pub fn new() -> Result<Self, SerializationError> {
        DirectoryBuilder::new().build()
    }

    pub fn add_block_to_index(&mut self, block_index_entry: BlockIndexEntry) {
        self.blocks.push(block_index_entry)
    }

    pub fn block_exists(&self, hash: blake3::Hash) -> Option<u64> {
        for block in &self.blocks {
            if &block.hash == hash.as_bytes() {
                return Some(block.index);
            }
        }
        None
    }

    pub fn add_file_to_index(&mut self, file_entry: FileEntry) {
        self.files.push(file_entry);
    }

    pub fn add_file_to_recipient(
        &mut self,
        writer_key: &StaticSecret,
        reader_key: &PublicKey,
        entry: (u64, [u8; 32]), // (file index, encryption key)
    ) -> Result<(), PithosWriterError> {
        let writer_pubkey = PublicKey::from(writer_key);
        for e_section in self.encryption.iter_mut() {
            if writer_pubkey.to_bytes() == e_section.sender_public_key {
                for r_section in e_section.recipients.iter_mut() {
                    if reader_key.to_bytes() == r_section.recipient_public_key {
                        return match r_section.recipient_data {
                            RecipientData::Encrypted(_) => {
                                Err(PithosWriterError::InvalidBlockDataState(
                                    "Block data already/still encrypted".to_string(),
                                ))
                            }
                            RecipientData::Decrypted(ref mut entries) => {
                                entries.push(entry);
                                Ok(())
                            }
                        };
                    }
                }
            }
        }

        Err(PithosWriterError::Other(
            "Recipient section not found".to_string(),
        ))
    }

    pub fn add_file_to_all_recipients(&mut self, entry: (u64, [u8; 32])) {
        for e_section in self.encryption.iter_mut() {
            for r_section in e_section.recipients.iter_mut() {
                match r_section.recipient_data {
                    RecipientData::Encrypted(_) => {
                        // Won't add to encrypted sections ¯\_(ツ)_/¯
                    }
                    RecipientData::Decrypted(ref mut entries) => {
                        entries.push(entry);
                    }
                }
            }
        }
    }

    pub fn encrypt_recipients(
        &mut self,
        writer_key: &StaticSecret,
    ) -> Result<(), PithosWriterError> {
        let writer_pubkey = PublicKey::from(writer_key);
        for e_section in self.encryption.iter_mut() {
            if writer_pubkey.as_bytes() == &e_section.sender_public_key {
                for r_section in e_section.recipients.iter_mut() {
                    let reader_pubkey = PublicKey::from(r_section.recipient_public_key);
                    let shared_key = writer_key.diffie_hellman(&reader_pubkey);
                    r_section.recipient_data.encrypt(&shared_key)?;
                }
            }
        }

        Ok(())
    }

    pub fn decrypt_recipient(
        &mut self,
        reader_key: &StaticSecret,
    ) -> anyhow::Result<Vec<(u64, [u8; 32])>> {
        // Store for decrypted sections
        let mut available_file_indices = Vec::<(u64, [u8; 32])>::new();
        let reader_pubkey = PublicKey::from(reader_key);

        // Iterate available encryption sections
        for e_section in self.encryption.iter_mut() {
            let sender_pubkey = PublicKey::from(e_section.sender_public_key);
            let shared_key = reader_key.diffie_hellman(&sender_pubkey);

            // Try decrypt users recipient data
            for r_section in e_section.recipients.iter_mut() {
                if reader_pubkey.as_bytes() == &r_section.recipient_public_key {
                    match &r_section.recipient_data {
                        RecipientData::Encrypted(_) => {
                            let entries = r_section
                                .recipient_data
                                .decrypt(&shared_key)
                                .map_err(|e| PithosReaderError::Other(e.to_string()))?;
                            available_file_indices.extend(entries);
                        }
                        RecipientData::Decrypted(entries) => {
                            available_file_indices.extend(entries);
                        }
                    }
                }
            }
        }

        Ok(available_file_indices)
    }

    pub fn update_len(&mut self) -> Result<(), SerializationError> {
        let mut buf = Vec::new();
        self.serialize(&mut buf)?;
        self.dir_len = buf.len() as u64;
        Ok(())
    }

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
        for block in &self.blocks {
            block.serialize(&mut buf)?
        }
        buf.write_varint(self.relations.len() as u64)?;
        for (idx, name) in &self.relations {
            buf.write_varint(*idx)?;
            encode_string(&mut buf, name)?;
        }
        for enc in &self.encryption {
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

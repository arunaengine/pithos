use crate::io::pithosreader::PithosReaderError;
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

    pub fn add_block_data(&mut self) {
        todo!()
    }

    pub fn add_file_to_recipient(&mut self) {
        todo!()
    }

    pub fn decrypt_recipient_section(
        &mut self,
        reader_key: &StaticSecret,
    ) -> anyhow::Result<Vec<(u64, [u8; 32])>> {
        // Store for decrypted sections
        let mut available_file_indices = Vec::<(u64, [u8; 32])>::new();

        //
        for e_section in self.encryption.iter_mut() {
            let sender_pubkey = PublicKey::from(e_section.sender_public_key);
            let shared_key = reader_key.diffie_hellman(&sender_pubkey);

            for r_section in e_section.recipients.iter_mut() {
                if let RecipientData::Encrypted(_) = r_section.recipient_data {
                    r_section.recipient_data.decrypt(&shared_key).map_err(|e| {
                        dbg!(&e);
                        PithosReaderError::Other(e.to_string())
                    })?;

                    if let RecipientData::Decrypted(entries) = &r_section.recipient_data {
                        available_file_indices.extend(entries);
                    }
                }
            }
        }

        Ok(available_file_indices)
    }
}

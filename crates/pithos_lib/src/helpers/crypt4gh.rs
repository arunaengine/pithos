use crate::io::pithosreader::PithosReaderError;
use crate::model::serialization::SerializationError;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, Nonce};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use std::io::{Cursor, Read, Write};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CRYPT4GH_HEADER_MAGIC: [u8; 8] = [0x63, 0x72, 0x79, 0x70, 0x74, 0x34, 0x67, 0x68]; // "crypt4gh"
pub const CRYPT4GH_HEADER_VERSION: u32 = 1;
pub const CRYPT4GH_BLOCK_SIZE: usize = 65536;
pub const CRYPT4GH_ENCRYPTED_BLOCK_SIZE: usize = 65564;

#[derive(Debug, Error)]
pub enum Crypt4GHError {
    #[error("Unable to parse `{0}` from bytes")]
    FromBytesError(String),
    #[error("Invalid value for spec: `{0}`")]
    InvalidSpec(String),
    #[error("Unable to decrypt: `{0}`")]
    DecryptionError(String),
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Unable to encrypt: `{0}`")]
    EncryptionError(String),
}

pub struct Crypt4GHHeader {
    pub magic: [u8; 8],    // Magic string to identify Crypt4GH format
    pub version: u32,      // Version of the format currently le 1
    pub packet_count: u32, // Size of the encrypted header
    pub header_packets: Vec<HeaderPacket>,
}

impl Crypt4GHHeader {
    pub fn new(header_packets: Vec<HeaderPacket>) -> Self {
        Crypt4GHHeader {
            magic: CRYPT4GH_HEADER_MAGIC,
            version: CRYPT4GH_HEADER_VERSION,
            packet_count: header_packets.len() as u32,
            header_packets,
        }
    }

    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_all(&self.magic)?;
        writer.write_u32::<LittleEndian>(self.version)?;
        writer.write_u32::<LittleEndian>(self.packet_count)?; // Actually writes the 4 bytes
        writer.write_u32::<LittleEndian>(self.header_packets.len() as u32)?;
        for packet in &self.header_packets {
            packet.serialize(writer)?;
        }
        Ok(())
    }
}

pub struct HeaderPacket {
    pub length: u32,             // Length of the packet
    encryption_method: u32,      // Currently only 0 (Chacha20-Poly1305)
    writers_pubkey: [u8; 32],    // Writer's public key
    nonce: [u8; 12],             // Nonce for encryption
    pub packet_data: PacketData, // Encryption or editlist packet
    mac: [u8; 16],               // Message Authentication Code (MAC)
}

impl HeaderPacket {
    pub fn from_pithos(
        sender_key: &StaticSecret,
        reader_keys: Vec<&PublicKey>,
        data_key: &[u8; 32],
    ) -> Result<Vec<HeaderPacket>, PithosReaderError> {
        let sender_pubkey = PublicKey::from(sender_key);
        let mut header_packets = vec![];
        for reader in reader_keys {
            let session_key = sender_key.diffie_hellman(&reader);
            let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
            let mut packet_data =
                PacketData::Decrypted(vec![Packet::Encryption(EncryptionPacket {
                    packet_type: 0,
                    encryption_method: 0,
                    encryption_key: *data_key,
                })]);
            let mac = packet_data.encrypt(session_key.as_bytes(), &nonce)?;
            let header_packet = HeaderPacket {
                length: 4 + 4 + 32 + 12 + packet_data.get_len() as u32 + 16,
                encryption_method: 0,
                writers_pubkey: sender_pubkey.to_bytes(),
                nonce: nonce.into(),
                packet_data,
                mac,
            };

            header_packets.push(header_packet);
        }

        Ok(header_packets)
    }

    pub fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        writer.write_u32::<LittleEndian>(self.length)?;
        writer.write_u32::<LittleEndian>(self.encryption_method)?;
        writer.write_all(&self.writers_pubkey)?;
        writer.write_all(&self.nonce)?;

        match &self.packet_data {
            PacketData::Encrypted(data) => {
                writer.write_all(data)?;
            }
            PacketData::Decrypted(_) => {
                return Err(SerializationError::Other(
                    "Packet data not encrypted".to_string(),
                ));
            }
        }

        writer.write_all(&self.mac)?;
        Ok(())
    }
}

pub enum PacketData {
    Encrypted(Vec<u8>),
    Decrypted(Vec<Packet>),
}

impl PacketData {
    pub fn get_len(&self) -> usize {
        match self {
            Self::Encrypted(enc_data) => enc_data.len(),
            Self::Decrypted(dec_data) => {
                let mut len = 0;
                for packet in dec_data {
                    match packet {
                        Packet::Encryption(_) => {
                            len += 4 + 4 + 32;
                        }
                        Packet::EditList(edit_packet) => {
                            len += 4 + 4 + 8 * edit_packet.num_length as usize;
                        }
                    }
                }
                len
            }
        }
    }
}

pub enum Packet {
    Encryption(EncryptionPacket),
    EditList(EditListPacket),
}

pub struct EncryptionPacket {
    packet_type: u32,         // 0 (Encryption)
    encryption_method: u32,   // 0 (Chacha20-Poly1305)
    encryption_key: [u8; 32], // 32 bytes encryption key
}

impl EncryptionPacket {
    pub fn get_encryption_key(&self) -> &[u8; 32] {
        &self.encryption_key
    }
}

pub struct EditListPacket {
    packet_type: u32, // 1
    num_length: u32,  // Number of edits
    edits: Vec<u64>,  // List of edits
}

impl TryFrom<&[u8]> for Crypt4GHHeader {
    type Error = Crypt4GHError;
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let mut header = Crypt4GHHeader {
            magic: [0; 8],
            version: 0,
            packet_count: 0,
            header_packets: Vec::new(),
        };
        let mut cursor = Cursor::new(bytes);
        cursor
            .read_exact(&mut header.magic)
            .map_err(|_| Crypt4GHError::FromBytesError("magic bytes".to_string()))?;
        if header.magic != CRYPT4GH_HEADER_MAGIC {
            return Err(Crypt4GHError::InvalidSpec("magic bytes".to_string()));
        }
        header.version = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("version".to_string()))?;
        if header.version != CRYPT4GH_HEADER_VERSION {
            return Err(Crypt4GHError::InvalidSpec("version".to_string()));
        }
        header.packet_count = cursor
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("header size".to_string()))?;
        //dbg!(&header.packet_count, &cursor.position());

        for _ in 0..header.packet_count {
            let len = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| Crypt4GHError::FromBytesError("packet length".to_string()))?;
            let mut buf = vec![0; len as usize - 4]; // u32 of length already read
            cursor
                .read_exact(&mut buf)
                .map_err(|_| Crypt4GHError::FromBytesError("packet data".to_string()))?;
            header
                .header_packets
                .push(HeaderPacket::from_buf(buf, len as usize)?);
        }

        Ok(header)
    }
}

impl TryInto<Vec<u8>> for Crypt4GHHeader {
    type Error = Crypt4GHError;
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.magic);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&self.packet_count.to_le_bytes());
        for packet in self.header_packets {
            bytes.extend_from_slice(&packet.length.to_le_bytes());
            bytes.extend_from_slice(&packet.encryption_method.to_le_bytes());
            bytes.extend_from_slice(&packet.writers_pubkey);
            bytes.extend_from_slice(&packet.nonce);
            match packet.packet_data {
                PacketData::Encrypted(enc_data) => {
                    bytes.extend_from_slice(&enc_data);
                }
                PacketData::Decrypted(_) => {
                    "packet data is not encrypted".to_string();
                }
            }
            bytes.extend_from_slice(&packet.mac);
        }
        Ok(bytes)
    }
}

impl HeaderPacket {
    pub fn new(packets: Vec<Packet>) -> Self {
        HeaderPacket {
            length: 0,
            encryption_method: 0,
            writers_pubkey: [0; 32],
            nonce: [0; 12],
            packet_data: PacketData::Decrypted(packets),
            mac: [0; 16],
        }
    }

    pub fn from_buf(bytes: Vec<u8>, len: usize) -> Result<Self, Crypt4GHError> {
        let mut bytes = Cursor::new(bytes);
        let encryption_method = bytes
            .read_u32::<LittleEndian>()
            .map_err(|_| Crypt4GHError::FromBytesError("encryption method".to_string()))?;
        let mut writers_pubkey = [0; 32];
        bytes
            .read_exact(&mut writers_pubkey)
            .map_err(|_| Crypt4GHError::FromBytesError("writer's public key".to_string()))?;
        let mut nonce = [0; 12];
        bytes
            .read_exact(&mut nonce)
            .map_err(|_| Crypt4GHError::FromBytesError("nonce".to_string()))?;

        let mut packet_data = Vec::new();
        bytes
            .read_to_end(&mut packet_data)
            .map_err(|_| Crypt4GHError::FromBytesError("packet data and mac".to_string()))?;
        let (enc, mac) = packet_data.split_at(packet_data.len() - 16);
        let encrypted_packet_data = PacketData::Encrypted(enc.to_vec());

        Ok(HeaderPacket {
            length: u32::try_from(len)
                .map_err(|_| Crypt4GHError::FromBytesError("header packet length".to_string()))?,
            encryption_method,
            writers_pubkey,
            nonce,
            packet_data: encrypted_packet_data,
            mac: mac
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("packet mac".to_string()))?,
        })
    }

    pub fn decrypt(&mut self, readers_private_key: &StaticSecret) -> Result<(), Crypt4GHError> {
        let writers_pub_key = PublicKey::from(self.writers_pubkey);
        let session_key = readers_private_key.diffie_hellman(&writers_pub_key);
        self.packet_data
            .decrypt(session_key.as_bytes(), &self.nonce, &self.mac)?;
        Ok(())
    }

    pub fn encrypt(
        &mut self,
        readers_pubkey: PublicKey,
        writers_private_key: Option<StaticSecret>,
    ) -> Result<(), Crypt4GHError> {
        let sender_key = match writers_private_key {
            Some(key) => StaticSecret::from(key),
            None => StaticSecret::random_from_rng(&mut OsRng),
        };

        let session_key = sender_key.diffie_hellman(&readers_pubkey);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        self.mac = self.packet_data.encrypt(session_key.as_bytes(), &nonce)?;
        self.writers_pubkey = PublicKey::from(&sender_key).to_bytes();
        self.nonce = nonce.into();
        self.length = (4 + 4 + 32 + 12 + self.packet_data.get_len() + 16)
            .try_into()
            .map_err(|_| Crypt4GHError::EncryptionError("header packet length".to_string()))?;
        Ok(())
    }
}

impl PacketData {
    pub fn encrypt(
        &mut self,
        session_key: &[u8; 32],
        nonce: &Nonce,
    ) -> Result<[u8; 16], Crypt4GHError> {
        if let Self::Decrypted(dec_data) = &self {
            let mut enc_data = Vec::new();
            for packet in dec_data {
                match packet {
                    Packet::Encryption(enc_packet) => {
                        enc_data.extend_from_slice(&enc_packet.packet_type.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_method.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_key);
                    }
                    Packet::EditList(edit_packet) => {
                        enc_data.extend_from_slice(&edit_packet.packet_type.to_le_bytes());
                        enc_data.extend_from_slice(&edit_packet.num_length.to_le_bytes());
                        for edit in &edit_packet.edits {
                            enc_data.extend_from_slice(&edit.to_le_bytes());
                        }
                    }
                }
            }

            //println!("Encrypt packet data with: {:?}", session_key);
            let encrypted = ChaCha20Poly1305::new_from_slice(session_key)
                .map_err(|_| Crypt4GHError::EncryptionError("Initialize cipher".to_string()))?
                .encrypt(nonce, enc_data.as_slice())
                .map_err(|_| Crypt4GHError::EncryptionError("Encrypt chunk failed".to_string()))?;
            *self = Self::Encrypted(encrypted[..encrypted.len() - 16].to_vec());
            let mac: [u8; 16] = encrypted[encrypted.len() - 16..]
                .try_into()
                .map_err(|_| Crypt4GHError::EncryptionError("packet mac".to_string()))?;
            //println!("{:?}\n{:?}\n{:?}", enc_data, encrypted, mac);
            Ok(mac)
        } else {
            Err(Crypt4GHError::EncryptionError(
                "packet data is already encrypted".to_string(),
            ))
        }
    }

    pub fn decrypt(
        &mut self,
        session_key: &[u8; 32],
        nonce: &[u8; 12],
        mac: &[u8; 16],
    ) -> Result<(), Crypt4GHError> {
        if let Self::Encrypted(enc_data) = &self {
            //println!("Decrypt packet data with: {:?}", session_key);
            let dec_data = [enc_data.as_slice(), mac.as_slice()].concat();
            //println!("To decrypt: {:?}", dec_data);

            let decrypted_bytes = ChaCha20Poly1305::new_from_slice(session_key)
                .map_err(|e| {
                    Crypt4GHError::DecryptionError(format!("initialize decryptor: {}", e))
                })?
                .decrypt(nonce.into(), dec_data.as_slice())
                .map_err(|e| Crypt4GHError::DecryptionFailed)?;

            *self = Self::Decrypted(Self::packet_from_bytes(&decrypted_bytes)?);
        } else {
            return Err(Crypt4GHError::DecryptionError(
                "packet data is not encrypted".to_string(),
            ));
        }
        Ok(())
    }

    pub fn packet_from_bytes(bytes: &[u8]) -> Result<Vec<Packet>, Crypt4GHError> {
        let mut cursor = Cursor::new(bytes);
        let mut packets = Vec::new();
        let mut found_edit = false;
        while cursor.position() < bytes.len() as u64 {
            let packet_type = cursor
                .read_u32::<LittleEndian>()
                .map_err(|_| Crypt4GHError::FromBytesError("packet type".to_string()))?;

            match packet_type {
                0 => {
                    let encryption_method = cursor.read_u32::<LittleEndian>().map_err(|_| {
                        Crypt4GHError::FromBytesError("encryption method".to_string())
                    })?;
                    if encryption_method != 0 {
                        return Err(Crypt4GHError::InvalidSpec(
                            "unsupported encryption method".to_string(),
                        ));
                    }
                    let mut encryption_key = [0; 32];
                    cursor
                        .read_exact(&mut encryption_key)
                        .map_err(|_| Crypt4GHError::FromBytesError("encryption key".to_string()))?;
                    packets.push(Packet::Encryption(EncryptionPacket {
                        packet_type,
                        encryption_method,
                        encryption_key,
                    }));
                }
                1 => {
                    if found_edit {
                        return Err(Crypt4GHError::InvalidSpec(
                            "multiple edit lists not allowed".to_string(),
                        ));
                    }
                    let num_length = cursor.read_u32::<LittleEndian>().map_err(|_| {
                        Crypt4GHError::FromBytesError("number of edits".to_string())
                    })?;
                    let mut edits = Vec::new();
                    for _ in 0..num_length {
                        edits.push(
                            cursor
                                .read_u64::<LittleEndian>()
                                .map_err(|_| Crypt4GHError::FromBytesError("edit".to_string()))?,
                        );
                    }
                    packets.push(Packet::EditList(EditListPacket {
                        packet_type,
                        num_length,
                        edits,
                    }));
                    found_edit = true;
                }
                _ => {
                    return Err(Crypt4GHError::FromBytesError(
                        "invalid packet type".to_string(),
                    ));
                }
            }
        }
        Ok(packets)
    }
}

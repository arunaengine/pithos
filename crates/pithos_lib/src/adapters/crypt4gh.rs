//! Crypt4GH presentation adapter.
//!
//! This module is the supported Crypt4GH header parser and serializer authority.
//! Its errors retain archive paths and operations without formatting keys, decrypted
//! packet contents, or plaintext.

use crate::archive::{Archive, ContentOperationError, ExternalBlockResolver};
use crate::crypto::{self, PrivateKey, PublicKey};
use crate::error::PithosError;
use blake2::{Blake2b512, Digest};
use byteorder::{LittleEndian, WriteBytesExt};
use chacha20poly1305::aead::{Aead, Generate};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use std::io::Write;
use thiserror::Error;
use x25519_dalek::PublicKey as DalekPublicKey;
use zeroize::{Zeroize, Zeroizing};

pub const CRYPT4GH_HEADER_MAGIC: [u8; 8] = [0x63, 0x72, 0x79, 0x70, 0x74, 0x34, 0x67, 0x68]; // "crypt4gh"
pub const CRYPT4GH_HEADER_VERSION: u32 = 1;
pub const CRYPT4GH_BLOCK_SIZE: usize = 65536;
pub const CRYPT4GH_ENCRYPTED_BLOCK_SIZE: usize = 65564;
const PACKET_LENGTH_FIELD_SIZE: usize = size_of::<u32>();
const MIN_PACKET_BODY_LENGTH: usize = size_of::<u32>() + 32 + 12 + 16;
const MIN_PACKET_LENGTH: usize = PACKET_LENGTH_FIELD_SIZE + MIN_PACKET_BODY_LENGTH;

fn derive_ga4gh_header_key(
    shared_secret: &[u8; 32],
    reader_public_key: &[u8; 32],
    writer_public_key: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut digest = Blake2b512::new();
    digest.update(shared_secret);
    digest.update(reader_public_key);
    digest.update(writer_public_key);
    let digest = digest.finalize();
    let mut header_key = Zeroizing::new([0; 32]);
    header_key.copy_from_slice(&digest[..32]);
    header_key
}

/// Exports one verified archive entry using the established Crypt4GH framing.
///
/// The export validates archive content before encrypting it and reports archive,
/// cryptographic, and sink failures with operation context. New headers use the
/// GA4GH KDF. Plain content, which no reader key protects, gets a fresh writer key.
pub fn export<S, E, W>(
    archive: &Archive<S, E>,
    path: &str,
    recipients: Vec<PublicKey>,
    sink: &mut W,
) -> Result<(), Crypt4GHError>
where
    S: crate::source::ArchiveSource,
    E: ExternalBlockResolver,
    W: Write + ?Sized,
{
    if recipients.is_empty() {
        return Err(Crypt4GHError::InvalidSpec(
            "at least one recipient is required".to_string(),
        ));
    }

    match archive.with_crypt4gh_content(path, |id, sender, file_key| {
        let packets = HeaderPacket::from_pithos(
            sender,
            recipients
                .into_iter()
                .map(PublicKey::into_dalek_public_key)
                .collect(),
            file_key.expose_for_protocol(),
        )?;
        Crypt4GHHeader::new(packets)?.serialize(sink)?;

        let mut pending = Zeroizing::new(Vec::with_capacity(CRYPT4GH_BLOCK_SIZE));
        archive
            .for_each_verified_file_block(id, |plaintext| {
                let mut offset = 0;
                while offset < plaintext.len() {
                    let available = CRYPT4GH_BLOCK_SIZE - pending.len();
                    let count = available.min(plaintext.len() - offset);
                    pending.extend_from_slice(&plaintext[offset..offset + count]);
                    offset += count;
                    if pending.len() == CRYPT4GH_BLOCK_SIZE {
                        sink.write_all(
                            &crypto::seal_crypt4gh_payload(
                                file_key.expose_for_protocol(),
                                &pending,
                            )
                            .map_err(|source| {
                                Crypt4GHError::Crypto {
                                    operation: "encrypt payload",
                                    source,
                                }
                            })?,
                        )
                        .map_err(|source| Crypt4GHError::Sink {
                            operation: "write payload",
                            source,
                        })?;
                        pending.zeroize();
                    }
                }
                Ok(())
            })
            .map_err(|error| match error {
                ContentOperationError::Core(source) => Crypt4GHError::Archive {
                    operation: "read verified archive content",
                    path: path.to_owned(),
                    source,
                },
                ContentOperationError::Callback(error) => error,
            })?;
        if !pending.is_empty() {
            sink.write_all(
                &crypto::seal_crypt4gh_payload(file_key.expose_for_protocol(), &pending).map_err(
                    |source| Crypt4GHError::Crypto {
                        operation: "encrypt payload",
                        source,
                    },
                )?,
            )
            .map_err(|source| Crypt4GHError::Sink {
                operation: "write payload",
                source,
            })?;
        }
        Ok(())
    }) {
        Ok(()) => Ok(()),
        Err(ContentOperationError::Core(source)) => Err(Crypt4GHError::Archive {
            operation: "access archive content",
            path: path.to_owned(),
            source,
        }),
        Err(ContentOperationError::Callback(error)) => Err(error),
    }
}

#[derive(Debug, Error)]
pub enum Crypt4GHError {
    #[error("Crypt4GH archive {operation} failed for {path}: {source}")]
    Archive {
        operation: &'static str,
        path: String,
        #[source]
        source: PithosError,
    },
    #[error("Crypt4GH {operation} failed: {source}")]
    Sink {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("Crypt4GH {operation} failed: {source}")]
    Crypto {
        operation: &'static str,
        #[source]
        source: crate::crypto::CryptoError,
    },
    #[error("Unable to parse `{0}` from bytes")]
    FromBytesError(String),
    #[error("Invalid value for spec: `{0}`")]
    InvalidSpec(String),
    #[error("Unable to encrypt: `{0}`")]
    EncryptionError(String),
    #[error("Unable to serialize: {0}")]
    Serialization(#[from] std::io::Error),
}

pub(crate) struct Crypt4GHHeader {
    magic: [u8; 8],
    version: u32,
    header_packets: Vec<HeaderPacket>,
}

impl Crypt4GHHeader {
    fn new(header_packets: Vec<HeaderPacket>) -> Result<Self, Crypt4GHError> {
        checked_packet_count(header_packets.len())?;
        Ok(Crypt4GHHeader {
            magic: CRYPT4GH_HEADER_MAGIC,
            version: CRYPT4GH_HEADER_VERSION,
            header_packets,
        })
    }

    #[tracing::instrument(level = "trace", skip(self, writer))]
    fn serialize<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), Crypt4GHError> {
        if self.magic != CRYPT4GH_HEADER_MAGIC {
            return Err(Crypt4GHError::InvalidSpec("magic bytes".to_string()));
        }
        if self.version != CRYPT4GH_HEADER_VERSION {
            return Err(Crypt4GHError::InvalidSpec("version".to_string()));
        }
        let packet_count = checked_packet_count(self.header_packets.len())?;
        for packet in &self.header_packets {
            packet.validate_serializable()?;
        }
        writer.write_all(&self.magic)?;
        writer.write_u32::<LittleEndian>(self.version)?;
        writer.write_u32::<LittleEndian>(packet_count)?;
        for packet in &self.header_packets {
            packet.serialize(writer)?;
        }
        Ok(())
    }
}

fn checked_packet_count(len: usize) -> Result<u32, Crypt4GHError> {
    u32::try_from(len).map_err(|_| Crypt4GHError::InvalidSpec("packet count".to_string()))
}

struct HeaderPacket {
    length: u32,
    encryption_method: u32,   // Currently only 0 (Chacha20-Poly1305)
    writers_pubkey: [u8; 32], // Writer's public key
    nonce: [u8; 12],          // Nonce for encryption
    packet_data: PacketData,
    mac: [u8; 16], // Message Authentication Code (MAC)
}

impl HeaderPacket {
    #[tracing::instrument(level = "trace", skip(sender_key, reader_keys, data_key))]
    fn from_pithos(
        sender_key: &PrivateKey,
        reader_keys: Vec<DalekPublicKey>,
        data_key: &[u8; 32],
    ) -> Result<Vec<HeaderPacket>, Crypt4GHError> {
        let sender_key = sender_key.as_dalek_static_secret();
        let sender_pubkey = DalekPublicKey::from(&sender_key);
        let mut header_packets = vec![];
        for reader in reader_keys {
            let session_key = crypto::derive_shared(sender_key.as_bytes(), reader.as_bytes())
                .map_err(|source| Crypt4GHError::Crypto {
                    operation: "derive header session key",
                    source,
                })?;
            let header_key = derive_ga4gh_header_key(
                session_key.expose_for_protocol(),
                reader.as_bytes(),
                sender_pubkey.as_bytes(),
            );
            let nonce = Nonce::generate();
            let mut packet_data =
                PacketData::Decrypted(vec![Packet::Encryption(EncryptionPacket {
                    packet_type: 0,
                    encryption_method: 0,
                    encryption_key: Box::new(Zeroizing::new(*data_key)),
                })]);
            let mac = packet_data.encrypt(&header_key, &nonce)?;
            let header_packet = HeaderPacket {
                length: u32::try_from(
                    MIN_PACKET_LENGTH
                        .checked_add(packet_data.serialized_len()?)
                        .ok_or_else(|| {
                            Crypt4GHError::EncryptionError("header packet length".to_string())
                        })?,
                )
                .map_err(|_| Crypt4GHError::EncryptionError("header packet length".to_string()))?,
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

    #[tracing::instrument(level = "trace", skip(self))]
    fn validate_serializable(&self) -> Result<(), Crypt4GHError> {
        let PacketData::Encrypted(data) = &self.packet_data else {
            return Err(Crypt4GHError::InvalidSpec(
                "packet data is not encrypted".to_string(),
            ));
        };
        let expected_length = MIN_PACKET_LENGTH
            .checked_add(data.len())
            .ok_or_else(|| Crypt4GHError::InvalidSpec("header packet length".to_string()))?;
        let expected_length = u32::try_from(expected_length)
            .map_err(|_| Crypt4GHError::InvalidSpec("header packet length".to_string()))?;
        if self.length != expected_length {
            return Err(Crypt4GHError::InvalidSpec(
                "header packet length".to_string(),
            ));
        }
        if self.encryption_method != 0 {
            return Err(Crypt4GHError::InvalidSpec(
                "unsupported encryption method".to_string(),
            ));
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, writer))]
    fn serialize<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), Crypt4GHError> {
        self.validate_serializable()?;
        writer.write_u32::<LittleEndian>(self.length)?;
        writer.write_u32::<LittleEndian>(self.encryption_method)?;
        writer.write_all(&self.writers_pubkey)?;
        writer.write_all(&self.nonce)?;

        match &self.packet_data {
            PacketData::Encrypted(data) => {
                writer.write_all(data)?;
            }
            PacketData::Decrypted(_) => {
                return Err(Crypt4GHError::InvalidSpec(
                    "packet data is not encrypted".to_string(),
                ));
            }
        }

        writer.write_all(&self.mac)?;
        Ok(())
    }
}

enum PacketData {
    Encrypted(Vec<u8>),
    Decrypted(Vec<Packet>),
}

impl PacketData {
    #[tracing::instrument(level = "trace", skip(self))]
    fn serialized_len(&self) -> Result<usize, Crypt4GHError> {
        match self {
            Self::Encrypted(enc_data) => Ok(enc_data.len()),
            Self::Decrypted(packets) => packets
                .len()
                .checked_mul(40)
                .ok_or_else(|| Crypt4GHError::EncryptionError("packet data length".to_string())),
        }
    }
}

enum Packet {
    Encryption(EncryptionPacket),
}

struct EncryptionPacket {
    packet_type: u32,                         // 0 (Encryption)
    encryption_method: u32,                   // 0 (Chacha20-Poly1305)
    encryption_key: Box<Zeroizing<[u8; 32]>>, // 32 bytes encryption key
}

impl TryFrom<&[u8]> for Crypt4GHHeader {
    type Error = Crypt4GHError;

    #[tracing::instrument(level = "trace", skip(bytes))]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        const PREFIX_LENGTH: usize = 16;
        if bytes.len() < PREFIX_LENGTH {
            return Err(Crypt4GHError::FromBytesError("header prefix".to_string()));
        }
        let magic: [u8; 8] = bytes[..8]
            .try_into()
            .map_err(|_| Crypt4GHError::FromBytesError("magic bytes".to_string()))?;
        if magic != CRYPT4GH_HEADER_MAGIC {
            return Err(Crypt4GHError::InvalidSpec("magic bytes".to_string()));
        }
        let version = u32::from_le_bytes(
            bytes[8..12]
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("version".to_string()))?,
        );
        if version != CRYPT4GH_HEADER_VERSION {
            return Err(Crypt4GHError::InvalidSpec("version".to_string()));
        }
        let packet_count = u32::from_le_bytes(
            bytes[12..16]
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("packet count".to_string()))?,
        );
        let packet_count_usize = usize::try_from(packet_count)
            .map_err(|_| Crypt4GHError::FromBytesError("packet count".to_string()))?;
        let minimum_packet_bytes = packet_count_usize
            .checked_mul(MIN_PACKET_LENGTH)
            .ok_or_else(|| Crypt4GHError::FromBytesError("packet count".to_string()))?;
        let minimum_total = PREFIX_LENGTH
            .checked_add(minimum_packet_bytes)
            .ok_or_else(|| Crypt4GHError::FromBytesError("packet count".to_string()))?;
        if minimum_total > bytes.len() {
            return Err(Crypt4GHError::FromBytesError(
                "packet count exceeds header".to_string(),
            ));
        }
        let mut header_packets = Vec::new();
        header_packets
            .try_reserve_exact(packet_count_usize)
            .map_err(|_| Crypt4GHError::FromBytesError("packet allocation".to_string()))?;

        let mut offset = PREFIX_LENGTH;
        for _ in 0..packet_count_usize {
            let length_end = offset
                .checked_add(PACKET_LENGTH_FIELD_SIZE)
                .ok_or_else(|| Crypt4GHError::FromBytesError("packet position".to_string()))?;
            let length: [u8; PACKET_LENGTH_FIELD_SIZE] = bytes
                .get(offset..length_end)
                .ok_or_else(|| Crypt4GHError::FromBytesError("packet length".to_string()))?
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("packet length".to_string()))?;
            let len = usize::try_from(u32::from_le_bytes(length))
                .map_err(|_| Crypt4GHError::FromBytesError("packet length".to_string()))?;
            if len < MIN_PACKET_LENGTH {
                return Err(Crypt4GHError::FromBytesError(
                    "packet length below minimum".to_string(),
                ));
            }
            let end = offset
                .checked_add(len)
                .ok_or_else(|| Crypt4GHError::FromBytesError("packet length".to_string()))?;
            let packet = bytes.get(length_end..end).ok_or_else(|| {
                Crypt4GHError::FromBytesError("packet exceeds header".to_string())
            })?;
            let mut packet_bytes = Vec::new();
            packet_bytes
                .try_reserve_exact(packet.len())
                .map_err(|_| Crypt4GHError::FromBytesError("packet allocation".to_string()))?;
            packet_bytes.extend_from_slice(packet);
            header_packets.push(HeaderPacket::from_buf(packet_bytes, len)?);
            offset = end;
        }
        if offset != bytes.len() {
            return Err(Crypt4GHError::FromBytesError(
                "trailing header bytes".to_string(),
            ));
        }
        Ok(Crypt4GHHeader {
            magic,
            version,
            header_packets,
        })
    }
}

impl TryInto<Vec<u8>> for Crypt4GHHeader {
    type Error = Crypt4GHError;

    #[tracing::instrument(level = "trace", skip(self))]
    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        let capacity = self
            .header_packets
            .iter()
            .try_fold(16usize, |size, packet| {
                size.checked_add(
                    usize::try_from(packet.length)
                        .map_err(|_| Crypt4GHError::InvalidSpec("header length".to_string()))?,
                )
                .ok_or_else(|| Crypt4GHError::InvalidSpec("header length".to_string()))
            })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| Crypt4GHError::FromBytesError("header allocation".to_string()))?;
        self.serialize(&mut bytes)?;
        Ok(bytes)
    }
}

impl HeaderPacket {
    #[tracing::instrument(level = "trace", skip(bytes, len))]
    fn from_buf(bytes: Vec<u8>, len: usize) -> Result<Self, Crypt4GHError> {
        let packet_bytes = len
            .checked_sub(PACKET_LENGTH_FIELD_SIZE)
            .ok_or_else(|| Crypt4GHError::FromBytesError("packet length".to_string()))?;
        if len < MIN_PACKET_LENGTH
            || bytes.len() != packet_bytes
            || bytes.len() < MIN_PACKET_BODY_LENGTH
        {
            return Err(Crypt4GHError::FromBytesError(
                "packet is too short".to_string(),
            ));
        }
        let encryption_method = u32::from_le_bytes(
            bytes[..4]
                .try_into()
                .map_err(|_| Crypt4GHError::FromBytesError("encryption method".to_string()))?,
        );
        if encryption_method != 0 {
            return Err(Crypt4GHError::InvalidSpec(
                "unsupported encryption method".to_string(),
            ));
        }
        let writers_pubkey = bytes[4..36]
            .try_into()
            .map_err(|_| Crypt4GHError::FromBytesError("writer's public key".to_string()))?;
        let nonce = bytes[36..48]
            .try_into()
            .map_err(|_| Crypt4GHError::FromBytesError("nonce".to_string()))?;
        let mac_start = bytes
            .len()
            .checked_sub(16)
            .ok_or_else(|| Crypt4GHError::FromBytesError("packet MAC".to_string()))?;
        let encrypted_len = mac_start
            .checked_sub(48)
            .ok_or_else(|| Crypt4GHError::FromBytesError("packet data".to_string()))?;
        let mut encrypted_data = Vec::new();
        encrypted_data
            .try_reserve_exact(encrypted_len)
            .map_err(|_| Crypt4GHError::FromBytesError("packet data allocation".to_string()))?;
        encrypted_data.extend_from_slice(&bytes[48..mac_start]);
        let mac = bytes[mac_start..]
            .try_into()
            .map_err(|_| Crypt4GHError::FromBytesError("packet mac".to_string()))?;

        Ok(HeaderPacket {
            length: u32::try_from(len)
                .map_err(|_| Crypt4GHError::FromBytesError("header packet length".to_string()))?,
            encryption_method,
            writers_pubkey,
            nonce,
            packet_data: PacketData::Encrypted(encrypted_data),
            mac,
        })
    }
}

impl PacketData {
    #[tracing::instrument(level = "trace", skip(self, session_key, nonce))]
    fn encrypt(
        &mut self,
        session_key: &[u8; 32],
        nonce: &Nonce,
    ) -> Result<[u8; 16], Crypt4GHError> {
        let serialized_len = self.serialized_len()?;
        if let Self::Decrypted(dec_data) = &self {
            let mut enc_data = Zeroizing::new(Vec::new());
            enc_data.try_reserve_exact(serialized_len).map_err(|_| {
                Crypt4GHError::EncryptionError("packet data allocation".to_string())
            })?;
            for packet in dec_data {
                match packet {
                    Packet::Encryption(enc_packet) => {
                        enc_data.extend_from_slice(&enc_packet.packet_type.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_method.to_le_bytes());
                        enc_data.extend_from_slice(&enc_packet.encryption_key[..]);
                    }
                }
            }

            let encrypted = ChaCha20Poly1305::new_from_slice(session_key)
                .map_err(|_| Crypt4GHError::EncryptionError("Cipher init failed".to_string()))?
                .encrypt(nonce, enc_data.as_slice())
                .map_err(|_| Crypt4GHError::EncryptionError("Encrypt chunk failed".to_string()))?;
            let mac_start = encrypted.len().checked_sub(16).ok_or_else(|| {
                Crypt4GHError::EncryptionError("packet data MAC extraction".to_string())
            })?;
            let (ciphertext, mac) = encrypted.split_at(mac_start);
            let mac: [u8; 16] = mac.try_into().map_err(|_| {
                Crypt4GHError::EncryptionError("packet data MAC extraction".to_string())
            })?;
            *self = Self::Encrypted(ciphertext.to_vec());
            Ok(mac)
        } else {
            Err(Crypt4GHError::EncryptionError(
                "Packet data is already encrypted".to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod zeroization_tests {
    use super::*;
    use zeroize::ZeroizeOnDrop;

    fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

    #[test]
    fn encryption_packets_use_stable_zeroizing_key_owners() {
        assert_zeroize_on_drop::<Zeroizing<[u8; 32]>>();
        let packet = EncryptionPacket {
            packet_type: 0,
            encryption_method: 0,
            encryption_key: Box::new(Zeroizing::new([7; 32])),
        };
        drop(packet);
    }

    #[test]
    fn packet_count_overflow_is_rejected_instead_of_saturated() {
        assert!(matches!(
            checked_packet_count(usize::MAX),
            Err(Crypt4GHError::InvalidSpec(_))
        ));
    }

    #[test]
    fn ga4gh_header_kdf_uses_blake2b_512_then_truncates() {
        let shared_secret = [
            0x81, 0x17, 0x55, 0x85, 0x38, 0x36, 0x37, 0xdf, 0x2a, 0xdb, 0xed, 0xe3, 0xa0, 0x36,
            0x18, 0xf7, 0x48, 0xf8, 0x53, 0x6c, 0xb6, 0xba, 0x16, 0xa4, 0xdf, 0x1d, 0xcc, 0x77,
            0x50, 0x73, 0x52, 0x77,
        ];
        let reader_public_key = [
            0x59, 0xef, 0xb4, 0x0e, 0xa7, 0x75, 0xf8, 0x6c, 0xe8, 0x67, 0xfc, 0x3a, 0x20, 0xa1,
            0xad, 0x08, 0xe3, 0x2f, 0xd0, 0xff, 0x5b, 0x1e, 0xf0, 0xff, 0xa4, 0x9f, 0xf1, 0x03,
            0xf5, 0xca, 0x06, 0x2e,
        ];
        let writer_public_key = [
            0xda, 0x06, 0x03, 0xbe, 0x1b, 0xf9, 0x86, 0xa5, 0x73, 0x79, 0xe6, 0xe5, 0xa3, 0x63,
            0xe3, 0xb4, 0x7b, 0xf8, 0x5f, 0x81, 0xaf, 0xdd, 0x4e, 0x00, 0xf7, 0x1f, 0x63, 0x3a,
            0x94, 0x58, 0xe4, 0x59,
        ];
        let expected = [
            0x80, 0x60, 0x43, 0x6a, 0xdc, 0x0c, 0xbe, 0x9a, 0x3e, 0x6a, 0xae, 0x26, 0x39, 0x91,
            0x1f, 0x8a, 0xe0, 0x0f, 0x50, 0xb2, 0x85, 0xe3, 0x6c, 0x0b, 0x12, 0x57, 0x5d, 0x88,
            0x9f, 0x4a, 0x4d, 0xb1,
        ];

        assert_eq!(
            *derive_ga4gh_header_key(&shared_secret, &reader_public_key, &writer_public_key),
            expected
        );
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::archive::{
        ArchivePath, ArchiveWriter, EntryMetadata, OpenOptions, ProcessingOptions, WriteOptions,
    };
    use crate::source::MemorySource;

    /// Decrypts an export to one recipient with that recipient's key.
    fn decrypt(exported: &[u8], recipient: &PrivateKey) -> Vec<u8> {
        let header_len = 16 + u32::from_le_bytes(exported[16..20].try_into().unwrap()) as usize;
        let header = Crypt4GHHeader::try_from(&exported[..header_len]).unwrap();
        let [packet] = header.header_packets.as_slice() else {
            panic!("the export has one recipient packet");
        };
        let PacketData::Encrypted(sealed) = &packet.packet_data else {
            panic!("a parsed packet is encrypted");
        };
        let writer = &packet.writers_pubkey;
        let secret = recipient.as_dalek_static_secret().to_bytes();
        let shared = crypto::derive_shared(&secret, writer).unwrap();
        let reader = recipient.public_key().into_dalek_public_key().to_bytes();
        let header_key = derive_ga4gh_header_key(shared.expose_for_protocol(), &reader, writer);
        let packet_data = ChaCha20Poly1305::new_from_slice(&*header_key)
            .unwrap()
            .decrypt(
                &Nonce::from(packet.nonce),
                [sealed.as_slice(), packet.mac.as_slice()]
                    .concat()
                    .as_slice(),
            )
            .unwrap();
        let data_key = ChaCha20Poly1305::new_from_slice(&packet_data[8..40]).unwrap();
        exported[header_len..]
            .chunks(CRYPT4GH_ENCRYPTED_BLOCK_SIZE)
            .flat_map(|segment| {
                let nonce: [u8; 12] = segment[..12].try_into().unwrap();
                data_key
                    .decrypt(&Nonce::from(nonce), &segment[12..])
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn plain_content_round_trips() {
        let content = (0..100_000u32)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut writer = ArchiveWriter::create(Vec::new(), WriteOptions::base()).unwrap();
        writer
            .add_file(
                ArchivePath::new("data").unwrap(),
                EntryMetadata::new(0, 0, 0o644),
                ProcessingOptions::new(false, 0).unwrap(),
                Some(content.len() as u64),
                std::io::Cursor::new(&content),
            )
            .unwrap();
        let source = MemorySource::new(writer.finish().unwrap());
        let archive = Archive::open(source, OpenOptions::default()).unwrap();
        let mut copied = Vec::new();
        archive.copy_to("data", &mut copied).unwrap();
        assert_eq!(copied, content);

        let recipient = PrivateKey::generate();
        let mut exported = Vec::new();
        export(
            &archive,
            "data",
            vec![recipient.public_key()],
            &mut exported,
        )
        .unwrap();
        assert_eq!(decrypt(&exported, &recipient), content);
    }
}

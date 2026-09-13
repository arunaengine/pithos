use crate::crypto::{self, SharedSecret};
use crate::error::PithosError;
use crate::format::error::SerializationError;
use crate::format::limits::{DeserializationError, DeserializationLimits};
use crate::format::primitives::{bounded_len, reserve, write_len_prefix};
use indexmap::IndexMap;
use integer_encoding::{VarIntReader, VarIntWriter};
use std::collections::HashMap;
use std::io::{Read, Write};
use x25519_dalek::PublicKey;
use zeroize::Zeroizing;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionSection {
    pub recipients: IndexMap<[u8; 32], RecipientSection>,
}

impl EncryptionSection {
    #[tracing::instrument(level = "trace", skip(recipient_pubkeys))]
    pub fn new(recipient_pubkeys: &[PublicKey]) -> Self {
        EncryptionSection {
            recipients: IndexMap::from_iter(
                recipient_pubkeys
                    .iter()
                    .map(|key| {
                        (
                            key.to_bytes(),
                            RecipientSection {
                                recipient_data: RecipientData::Decrypted(
                                    Zeroizing::new(Vec::new()),
                                ),
                            },
                        )
                    })
                    .collect::<Vec<_>>(),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientSection {
    pub(crate) recipient_data: RecipientData,
}

pub(crate) type RecipientKeyList = Zeroizing<Vec<(u64, [u8; 32])>>;

/// Transient recipient-list state used while encoding or opening a directory.
/// Recovered file keys are crate-private.
#[derive(Clone, PartialEq, Eq)]
pub(crate) enum RecipientData {
    Encrypted(Vec<u8>),
    Decrypted(RecipientKeyList),
}

impl std::fmt::Debug for RecipientData {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted(bytes) => formatter
                .debug_tuple("Encrypted")
                .field(&format_args!("{} bytes", bytes.len()))
                .finish(),
            Self::Decrypted(entries) => formatter
                .debug_tuple("Decrypted")
                .field(&format_args!("{} file keys [REDACTED]", entries.len()))
                .finish(),
        }
    }
}

impl RecipientData {
    pub(crate) fn encrypt_with_secret_and_nonce(
        &mut self,
        shared_key: SharedSecret,
        nonce: [u8; 12],
    ) -> Result<(), PithosError> {
        match &self {
            RecipientData::Encrypted(_) => {
                return Err(PithosError::InvalidRecipientDataState(
                    "Recipient data already encrypted".to_string(),
                ));
            }
            RecipientData::Decrypted(entries) => {
                let mut data_bytes = Zeroizing::new(Vec::with_capacity(1 + entries.len() * 40));
                encode_decrypted_recipient_list(entries, &mut *data_bytes)?;
                let encrypted_data =
                    crypto::wrap_recipient_list_with_nonce(&shared_key, &data_bytes, nonce)?;
                *self = RecipientData::Encrypted(encrypted_data)
            }
        };
        Ok(())
    }
}

fn encode_recipient_data<W: Write>(
    data: &RecipientData,
    writer: &mut W,
) -> Result<(), SerializationError> {
    match data {
        RecipientData::Encrypted(bytes) => {
            writer.write_all(&[0])?;
            write_len_prefix(writer, bytes.len())?;
            writer.write_all(bytes)?;
        }
        RecipientData::Decrypted(entries) => {
            writer.write_all(&[1])?;
            encode_decrypted_recipient_list(entries, writer)?;
        }
    }
    Ok(())
}

fn decode_recipient_data<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<RecipientData, DeserializationError> {
    let mut tag = [0];
    reader.read_exact(&mut tag)?;
    match tag[0] {
        0 => {
            let len = bounded_len(
                reader.read_varint::<u64>()?,
                limits.max_opaque_bytes,
                "encrypted recipient data",
            )?;
            let mut bytes = Vec::new();
            reserve(&mut bytes, len, "encrypted recipient data")?;
            bytes.resize(len, 0);
            reader.read_exact(&mut bytes)?;
            Ok(RecipientData::Encrypted(bytes))
        }
        1 => Ok(RecipientData::Decrypted(
            decode_decrypted_recipient_list_reader(reader, limits)?,
        )),
        value => Err(DeserializationError::InvalidEnumValue(value)),
    }
}

pub(crate) fn encode_encryption_section<W: Write>(
    section: &EncryptionSection,
    writer: &mut W,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, section.recipients.len())?;
    for (key, recipient) in &section.recipients {
        writer.write_all(key)?;
        encode_recipient_data(&recipient.recipient_data, writer)?;
    }
    Ok(())
}

pub(crate) fn decode_encryption_section<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<EncryptionSection, PithosError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "recipients",
    )?;
    let mut recipients = IndexMap::new();
    for _ in 0..count {
        let mut key = [0; 32];
        reader.read_exact(&mut key)?;
        crypto::validate_x25519_public_key(&key)?;
        if recipients.contains_key(&key) {
            return Err(DeserializationError::DuplicateRecipientKey.into());
        }
        recipients.insert(
            key,
            RecipientSection {
                recipient_data: decode_recipient_data(reader, limits)?,
            },
        );
    }
    Ok(EncryptionSection { recipients })
}

pub(crate) fn encode_decrypted_recipient_list<W: Write>(
    entries: &[(u64, [u8; 32])],
    writer: &mut W,
) -> Result<(), SerializationError> {
    write_len_prefix(writer, entries.len())?;
    for (id, key) in entries {
        writer.write_varint(*id)?;
        writer.write_all(key)?;
    }
    Ok(())
}

pub(crate) fn decode_decrypted_recipient_list_reader<R: Read>(
    reader: &mut R,
    limits: &DeserializationLimits,
) -> Result<RecipientKeyList, DeserializationError> {
    let count = bounded_len(
        reader.read_varint::<u64>()?,
        limits.max_collection_entries,
        "recipient keys",
    )?;
    let mut entries = Zeroizing::new(Vec::new());
    reserve(&mut entries, count, "recipient keys")?;
    let mut keys = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = reader.read_varint::<u64>()?;
        entries.push((id, [0; 32]));
        reader.read_exact(&mut entries.last_mut().expect("just pushed file key").1)?;
        let key = entries.last().expect("just pushed file key").1;
        if keys.insert(id, key).is_some_and(|existing| existing != key) {
            return Err(DeserializationError::DuplicateRecipientFileId);
        }
    }
    Ok(entries)
}

pub(crate) fn decode_decrypted_recipient_list(
    bytes: &[u8],
    limits: &DeserializationLimits,
) -> Result<RecipientKeyList, DeserializationError> {
    let mut reader = std::io::Cursor::new(bytes);
    let entries = decode_decrypted_recipient_list_reader(&mut reader, limits)?;
    if reader.position() != bytes.len() as u64 {
        return Err(DeserializationError::InvalidLength);
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypted_recipient_lists_retain_exact_duplicates_but_reject_conflicts() {
        let limits = DeserializationLimits::default();
        let mut repeated = vec![2, 7];
        repeated.extend_from_slice(&[3; 32]);
        repeated.push(7);
        repeated.extend_from_slice(&[3; 32]);
        assert_eq!(
            decode_decrypted_recipient_list(&repeated, &limits)
                .unwrap()
                .as_slice(),
            &[(7, [3; 32]), (7, [3; 32])]
        );

        let mut conflicting = vec![2, 7];
        conflicting.extend_from_slice(&[3; 32]);
        conflicting.push(7);
        conflicting.extend_from_slice(&[4; 32]);
        assert!(matches!(
            decode_decrypted_recipient_list(&conflicting, &limits),
            Err(DeserializationError::DuplicateRecipientFileId)
        ));
    }
}

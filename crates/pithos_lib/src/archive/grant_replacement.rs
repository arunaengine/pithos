//! Replaces the reader grants of an archive without re-encoding its content.

use super::pieces::{distinct_keys, v1_1_header};
use super::reader::deserialization_limits;
use super::types::FileId;
use super::view::ArchiveView;
use crate::crypto::{self, PublicKey};
use crate::error::PithosError;
use crate::format::directory::{
    Directory, decode_complete_directory_with_validation, encode_complete_directory,
};
use crate::format::encryption::{
    EncryptionSection, RecipientData, RecipientSection, encode_decrypted_recipient_list,
};
use crate::format::file_entry::BlockDataState;
use crate::format::header::{FileHeader, FormatVersion};
use indexmap::IndexMap;
use std::ops::Range;
use x25519_dalek::{PublicKey as DalekPublicKey, StaticSecret};
use zeroize::Zeroizing;

/// An archive that grants the keys of an existing archive only to new recipients.
///
/// Write [`GrantReplacement::header`], then the old archive bytes in
/// [`GrantReplacement::copy_range`] unchanged, then [`GrantReplacement::directory`].
/// It holds no key material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantReplacement {
    copy_range: Range<u64>,
    directory: Vec<u8>,
    archive_len: u64,
}

impl GrantReplacement {
    pub fn header(&self) -> [u8; FileHeader::ENCODED_LEN] {
        v1_1_header()
    }

    /// The block region of the old archive. Its bytes keep their offsets in the new archive.
    pub fn copy_range(&self) -> Range<u64> {
        self.copy_range.clone()
    }

    pub fn directory(&self) -> &[u8] {
        &self.directory
    }

    pub fn archive_len(&self) -> u64 {
        self.archive_len
    }

    /// The digest the new archive reports on open, for
    /// [`crate::archive::OpenOptions::with_expected_metadata_digest`].
    pub fn metadata_digest(&self) -> [u8; 32] {
        crate::archive::metadata_digest(&[*blake3::hash(&self.directory).as_bytes()])
    }
}

impl ArchiveView {
    /// The byte range of the terminal directory, which [`ArchiveView::replace_grants`] needs.
    pub fn directory_range(&self) -> Range<u64> {
        self.terminal_directory.start()..self.terminal_directory.end()
    }

    /// Plans a copy of this archive that grants every file and piece key this view recovered
    /// only to `recipients`, under a fresh sender key and version 1.1 grant keys.
    ///
    /// `directory` must hold the stored bytes at [`ArchiveView::directory_range`]; they must
    /// match the metadata digest. Every block payload and sealed block list stays unchanged.
    /// Fails with [`PithosError::GrantReplacementUnsupported`] unless the archive is version
    /// 1.1 with one directory, and with [`PithosError::ContentUnavailable`] when a key needed
    /// by a sealed block list was not recovered.
    pub fn replace_grants(
        &self,
        directory: &[u8],
        recipients: Vec<PublicKey>,
    ) -> Result<GrantReplacement, PithosError> {
        if self.version != FormatVersion::V1_1 || self.index.directory_count() != 1 {
            return Err(PithosError::GrantReplacementUnsupported);
        }
        if recipients.is_empty() {
            return Err(PithosError::WriterRequiresRecipient);
        }
        let recipients = distinct_keys(recipients)?;
        let hash = *blake3::hash(directory).as_bytes();
        if crate::archive::metadata_digest(&[hash]) != self.metadata_digest {
            return Err(PithosError::MetadataDigestMismatch);
        }
        let limits = deserialization_limits(self.limits);
        let mut directory =
            decode_complete_directory_with_validation(directory, &limits, false, |_| Ok(()))?;
        let list = self.key_list(&directory)?;
        directory.encryption = grant(&list, &recipients)?;
        let directory = encode_complete_directory(&directory)?;
        let copy_range = FileHeader::ENCODED_LEN as u64..self.terminal_directory.start();
        let archive_len = copy_range.end.checked_add(directory.len() as u64).ok_or(
            PithosError::InvalidDirectoryRange {
                operation: "add the replacement directory length",
            },
        )?;
        Ok(GrantReplacement {
            archive_len,
            copy_range,
            directory,
        })
    }

    /// Encodes the recipient list of every key that a sealed block list of `directory` needs.
    fn key_list(&self, directory: &Directory) -> Result<Zeroizing<Vec<u8>>, PithosError> {
        let mut ids = Vec::new();
        for (id, _, file) in directory.files.iter() {
            match &file.block_data {
                BlockDataState::Encrypted(_) => ids.push(id),
                BlockDataState::Pieces(pieces) => ids.extend(pieces.iter().map(|p| p.key_id)),
                BlockDataState::Decrypted(_) => {}
            }
        }
        // Exact capacities keep the keys from moving to new buffers while they are written.
        let mut records = Zeroizing::new(Vec::with_capacity(ids.len()));
        for id in ids {
            let key = self.access.key(FileId(id));
            let key = key.ok_or(PithosError::ContentUnavailable)?;
            records.push((id, *key.expose_for_protocol()));
        }
        let mut list = Zeroizing::new(Vec::with_capacity(10 + records.len() * 42));
        encode_decrypted_recipient_list(&records, &mut *list)?;
        Ok(list)
    }
}

/// Seals `list` for every recipient under one fresh sender key.
fn grant(
    list: &[u8],
    recipients: &[[u8; 32]],
) -> Result<IndexMap<[u8; 32], EncryptionSection>, PithosError> {
    let sender = StaticSecret::random();
    let sender_public = DalekPublicKey::from(&sender).to_bytes();
    let mut sections = IndexMap::with_capacity(recipients.len());
    for recipient in recipients {
        let nonce = crypto::random_nonce();
        let key = crypto::grant_wrapping_key(
            FormatVersion::V1_1,
            crypto::derive_shared(sender.as_bytes(), recipient)?,
            &sender_public,
            recipient,
            &nonce,
        );
        let wrapped = crypto::wrap_recipient_list_with_nonce(&key, list, nonce)?;
        let recipient_data = RecipientData::Encrypted(wrapped);
        sections.insert(*recipient, RecipientSection { recipient_data });
    }
    let section = EncryptionSection {
        recipients: sections,
    };
    Ok(IndexMap::from([(sender_public, section)]))
}

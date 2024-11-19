use crate::helpers::notifications::DirOrFileIdx;
use crate::pithos::structs::{
    DecryptedKeys, DirContextVariants, EndOfFileMetadata, FileContextVariants, TableOfContents,
};
use crate::pithos::structs::{EncryptionMetadata, EOF_META_LEN};
use anyhow::anyhow;
use anyhow::Result;
use serde::{Deserialize, Serialize};

pub enum FooterParserState {
    Empty,
    Raw,
    Missing(usize), // Only valid for ToC and Enc
    Decoded,
}

pub struct FooterParser<'a> {
    buffer: Vec<u8>,
    pub state: FooterParserState,
    keys: Vec<&'a [u8; 32]>,
    eof_metadata: Option<EndOfFileMetadata>,
    encryption_keys: Option<DecryptedKeys>,
    table_of_contents: Option<TableOfContents>,
    raw_toc: Option<TableOfContents>,
    raw_encryption_packets: Option<EncryptionMetadata>,
}

impl<'a> TryFrom<FooterParser<'a>> for Footer {
    type Error = anyhow::Error;
    fn try_from(value: FooterParser) -> Result<Self, Self::Error> {
        match value.state {
            FooterParserState::Decoded => Ok(Footer {
                eof_metadata: value
                    .eof_metadata
                    .ok_or_else(|| anyhow!("EOF Metadata not found"))?,
                encryption_keys: value.encryption_keys,
                table_of_contents: value
                    .table_of_contents
                    .ok_or_else(|| anyhow!("Table of Contents not found"))?,
                raw_toc: value
                    .raw_toc
                    .ok_or_else(|| anyhow!("Table of Contents not found"))?,
                raw_encryption_packets: value.raw_encryption_packets,
            }),
            _ => Err(anyhow!("Invalid State: Footer not yet decoded")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Footer {
    pub eof_metadata: EndOfFileMetadata,
    pub encryption_keys: Option<DecryptedKeys>,
    pub table_of_contents: TableOfContents,
    pub raw_toc: TableOfContents,
    pub raw_encryption_packets: Option<EncryptionMetadata>,
}

impl<'a> FooterParser<'a> {
    #[tracing::instrument(level = "trace", skip(bytes))]
    pub fn new(bytes: &[u8]) -> Result<FooterParser> {
        if bytes.len() < EOF_META_LEN {
            return Err(anyhow!("Invalid format, not enough bytes"));
        }
        Ok(FooterParser {
            buffer: bytes.to_vec(),
            state: FooterParserState::Raw,
            keys: vec![],
            eof_metadata: None,
            encryption_keys: None,
            table_of_contents: None,
            raw_toc: None,
            raw_encryption_packets: None,
        })
    }

    #[tracing::instrument(level = "trace", skip(self, readers_private_key))]
    pub fn add_recipient(mut self, readers_private_key: &'a [u8; 32]) -> FooterParser<'a> {
        self.keys.push(readers_private_key);
        FooterParser { ..self }
    }

    #[tracing::instrument(level = "trace", skip(self, bytes))]
    pub fn add_bytes(mut self, bytes: &'a [u8]) -> Result<FooterParser<'a>> {
        match self.state {
            FooterParserState::Empty => Ok(FooterParser {
                buffer: bytes.to_vec(),
                state: FooterParserState::Raw,
                ..self
            }),
            FooterParserState::Raw => {
                self.buffer.extend_from_slice(bytes);
                Ok(FooterParser { ..self })
            }
            FooterParserState::Missing(missing) => {
                if bytes.len() != missing {
                    return Err(anyhow!(
                        "Invalid format, expected {} bytes, got {}",
                        missing,
                        bytes.len()
                    ));
                }
                self.buffer.extend_from_slice(bytes);
                Ok(FooterParser {
                    state: FooterParserState::Raw,
                    ..self
                })
            }
            FooterParserState::Decoded => Err(anyhow!("Invalid State: Already decoded")),
        }
    }

    #[tracing::instrument(err, level = "trace", skip(self))]
    pub fn parse(mut self) -> Result<FooterParser<'a>> {
        match self.state {
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Raw => {
                // Parse EOF Metadata
                let (enc_len, toc_len) = if let Some(eof_metadata) = &self.eof_metadata {
                    (eof_metadata.encryption_len, eof_metadata.toc_len)
                } else {
                    let eof_metadata = self.parse_eof_md()?; // buf.len - 73
                    let encryption_len = eof_metadata.encryption_len;
                    let toc_len = eof_metadata.toc_len;

                    // Evaluate if bytes are missing for full footer parsing
                    if (self.buffer.len() as u64) < (encryption_len + toc_len) {
                        let missing = (encryption_len + toc_len) - self.buffer.len() as u64;
                        return Ok(FooterParser {
                            state: FooterParserState::Missing(missing as usize),
                            ..self
                        });
                    }

                    self.eof_metadata = Some(eof_metadata);
                    (encryption_len, toc_len)
                };

                // Parse Encryption Metadata
                if self.encryption_keys.is_none() {
                    self.parse_encryption_metadata(enc_len)?;
                };

                // Parse Table of Contents
                self.parse_table_of_contents(toc_len)?;

                // Set state to decoded
                self.state = FooterParserState::Decoded;

                Ok(self)
            }
            FooterParserState::Missing(_) => Err(anyhow!("Missing bytes.")),
            FooterParserState::Decoded => Ok(self),
        }
    }

    fn parse_eof_md(&mut self) -> Result<EndOfFileMetadata> {
        match self.state {
            FooterParserState::Empty => Err(anyhow!("Empty footer")),
            FooterParserState::Raw => {
                let (remaining, md) = self.buffer.split_at(self.buffer.len() - EOF_META_LEN);
                let eof_md = borsh::from_slice(md)?;
                self.buffer = remaining.to_vec();
                Ok(eof_md)
            }
            FooterParserState::Missing(_) => Err(anyhow!("Invalid State: Missing bytes")),
            FooterParserState::Decoded => Err(anyhow!("Invalid State: Decoded")),
        }
    }

    fn parse_encryption_metadata(&mut self, len_enc: u64) -> Result<()> {
        let (remaining, md) = self.buffer.split_at(self.buffer.len() - len_enc as usize);
        let encryption_data: EncryptionMetadata = borsh::from_slice(md)?;

        self.raw_encryption_packets = Some(encryption_data.clone());

        for key in self.keys.clone() {
            for packet in encryption_data.packets.clone() {
                if let Some(decrypted_keys) = packet.decrypt(key) {
                    if let Some(keys) = &mut self.encryption_keys {
                        keys.add_keys(decrypted_keys)
                    } else {
                        self.encryption_keys = Some(decrypted_keys);
                    }
                }
            }
        }
        self.buffer = remaining.to_vec();
        Ok(())
    }

    fn parse_table_of_contents(&mut self, len_toc: u64) -> Result<()> {
        let (remaining, md) = self.buffer.split_at(self.buffer.len() - len_toc as usize);
        let mut table_of_contents: TableOfContents = borsh::from_slice(md)?;

        self.raw_toc = Some(table_of_contents.clone());

        for (idx, dir_ctx) in table_of_contents.directories.iter_mut().enumerate() {
            if let DirContextVariants::DirEncrypted(_) = dir_ctx {
                for (key, key_idx) in self
                    .encryption_keys
                    .as_ref()
                    .ok_or_else(|| anyhow!("No keys available"))?
                    .keys
                    .clone()
                {
                    if let DirOrFileIdx::Dir(last_used_idx) = key_idx {
                        if idx <= last_used_idx {
                            dir_ctx.decrypt(key);
                        }
                    }
                }
            }
        }

        for (idx, file_ctx) in table_of_contents.files.iter_mut().enumerate() {
            if let FileContextVariants::FileEncrypted(_) = file_ctx {
                for (key, key_idx) in self
                    .encryption_keys
                    .as_ref()
                    .ok_or_else(|| anyhow!("No keys available"))?
                    .keys
                    .clone()
                {
                    if let DirOrFileIdx::File(last_used_idx) = key_idx {
                        if idx <= last_used_idx {
                            file_ctx.decrypt(key);
                        }
                    }
                }
            }
        }

        table_of_contents
            .directories
            .retain(|var| !var.is_encrypted());

        table_of_contents.files.retain(|var| !var.is_encrypted());

        self.table_of_contents = Some(table_of_contents);
        self.buffer = remaining.to_vec();
        Ok(())
    }
}

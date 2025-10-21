use crate::helpers::notifications::{DirOrFileIdx, HashType, Message, Notifier};
use crate::helpers::structs::{EncryptionKey, FileContext};
use crate::pithos::structs::{
    DirContextHeader, DirContextVariants, EncryptionMetadata, EndOfFileMetadata, FileContextHeader,
    FileContextVariants, Hashes, SymlinkContextHeader, TableOfContents,
};
use crate::transformer::Transformer;
use crate::transformer::TransformerType;
use anyhow::Result;
use anyhow::{anyhow, bail};
use async_channel::{Receiver, Sender, TryRecvError};
use byteorder::{ByteOrder, LittleEndian};
use bytes::BufMut;
use digest::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::error;

pub struct FooterGenerator {
    hasher: Sha256,
    counter: u64,
    raw_counter: u64,
    directories: Vec<(Option<[u8; 32]>, DirContextHeader)>,
    files: Vec<(Option<[u8; 32]>, FileContextHeader)>,
    path_table: HashMap<String, DirOrFileIdx>,
    unassigned_symlinks: Vec<FileContext>,
    writer_private_key: Option<[u8; 32]>,
    encryption_keys: HashMap<[u8; 32], HashMap<[u8; 32], DirOrFileIdx>>, // <Reader PubKey, List of encryption keys>
    notifier: Option<Arc<Notifier>>,
    msg_receiver: Option<Receiver<Message>>,
    idx: Option<usize>,
    finished: bool,
}

impl FooterGenerator {
    #[tracing::instrument(level = "trace", skip(writer_private_key))]
    #[allow(dead_code)]
    pub fn new(writer_private_key: Option<[u8; 32]>) -> FooterGenerator {
        FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            raw_counter: 0,
            directories: Vec::new(),
            files: Vec::new(),
            path_table: HashMap::default(),
            unassigned_symlinks: vec![],
            writer_private_key,
            encryption_keys: HashMap::new(),
            notifier: None,
            msg_receiver: None,
            idx: None,
            finished: false,
        }
    }

    pub fn new_with_ctx(ctx: FileContext) -> Result<FooterGenerator> {
        let mut map = HashMap::new();
        for pubkey in &ctx.recipients_pubkeys {
            match &ctx.encryption_key {
                EncryptionKey::None => {}
                EncryptionKey::Same(enc_key) => {
                    map.insert(
                        *pubkey,
                        HashMap::from([(*enc_key, DirOrFileIdx::from(&ctx))]),
                    );
                }
                EncryptionKey::DataOnly(enc_key) => {
                    map.insert(
                        *pubkey,
                        HashMap::from([(*enc_key, DirOrFileIdx::from(&ctx))]),
                    );
                }
                // Data key necessary if is_dir?
                EncryptionKey::Individual((data, meta)) => {
                    map.insert(
                        *pubkey,
                        HashMap::from([
                            (*data, DirOrFileIdx::from(&ctx)),
                            (*meta, DirOrFileIdx::from(&ctx)),
                        ]),
                    );
                }
            }
        }

        Ok(FooterGenerator {
            hasher: Sha256::new(),
            counter: 0,
            raw_counter: 0,
            directories: Vec::new(),
            files: Vec::new(),
            path_table: HashMap::default(),
            unassigned_symlinks: vec![],
            writer_private_key: None,
            encryption_keys: map,
            notifier: None,
            msg_receiver: None,
            idx: None,
            finished: false,
        })
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<bool> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => return Ok(true),
                    Ok(Message::FileContext(ctx)) => {
                        // Update raw counter
                        self.raw_counter += ctx.decompressed_size;

                        // Collect encryption keys
                        for recipient in &ctx.recipients_pubkeys {
                            let entry = self.encryption_keys.entry(*recipient).or_default();
                            for key in ctx.encryption_key.into_keys() {
                                if let Some(inner) = entry.get_mut(&key) {
                                    if inner.get_idx() < ctx.idx {
                                        *inner = DirOrFileIdx::from(&ctx);
                                    }
                                } else {
                                    entry.insert(key, DirOrFileIdx::from(&ctx));
                                }
                            }
                        }

                        // Get metadata key if available
                        let m_key: Option<[u8; 32]> = match &ctx.encryption_key {
                            EncryptionKey::Same(key) => Some(key.as_slice().try_into()?),
                            EncryptionKey::Individual((_, key)) => Some(key.as_slice().try_into()?),
                            _ => None,
                        };

                        if ctx.is_dir {
                            self.path_table
                                .insert(ctx.file_path.clone(), DirOrFileIdx::Dir(ctx.idx));
                            self.directories.push((m_key, ctx.into()))
                        } else if ctx.symlink_target.is_none() {
                            self.path_table
                                .insert(ctx.file_path.clone(), DirOrFileIdx::File(ctx.idx));
                            self.files.push((m_key, ctx.try_into()?))
                        } else if let Some(idx) = self
                            .path_table
                            .get(ctx.symlink_target.as_ref().ok_or_else(|| anyhow!(""))?)
                        {
                            match idx {
                                DirOrFileIdx::File(idx) => {
                                    let (_, mut_ctx) =
                                        self.files.get_mut(*idx).ok_or_else(|| {
                                            anyhow!("FileContextHeader does not exist")
                                        })?;
                                    let symlink_ctx = SymlinkContextHeader {
                                        file_path: ctx.file_path.clone(),
                                        file_info: ctx.into(),
                                    };
                                    if let Some(symlinks) = mut_ctx.symlinks.as_mut() {
                                        symlinks.push(symlink_ctx)
                                    } else {
                                        mut_ctx.symlinks = Some(vec![symlink_ctx])
                                    }
                                }
                                DirOrFileIdx::Dir(idx) => {
                                    let (_, mut_ctx) =
                                        self.directories.get_mut(*idx).ok_or_else(|| {
                                            anyhow!("DirContextHeader does not exist")
                                        })?;
                                    let symlink_ctx = SymlinkContextHeader {
                                        file_path: ctx.file_path.clone(),
                                        file_info: ctx.into(),
                                    };
                                    if let Some(symlinks) = mut_ctx.symlinks.as_mut() {
                                        symlinks.push(symlink_ctx)
                                    } else {
                                        mut_ctx.symlinks = Some(vec![symlink_ctx])
                                    }
                                }
                            }
                        } else {
                            self.unassigned_symlinks.push(ctx)
                        }
                    }
                    Ok(Message::CompressionInfo(compression_info)) => {
                        let (_, mut_ctx) = self
                            .files
                            .get_mut(compression_info.idx)
                            .ok_or_else(|| anyhow!("FileContextHeader does not exist"))?;
                        mut_ctx.compressed = compression_info.compression;
                        if mut_ctx.raw_size == 0 {
                            mut_ctx.raw_size = compression_info.raw_size;
                        } else if mut_ctx.raw_size != compression_info.raw_size {
                            error!(
                                ctx_raw = mut_ctx.raw_size,
                                comp_raw = compression_info.raw_size,
                                "Raw size does not match file disk size"
                            );
                            bail!("Compression size does not match file disk size");
                        }
                        mut_ctx.file_end = compression_info.compressed_size;
                        mut_ctx.index_list = compression_info.chunk_infos;
                    }
                    Ok(Message::Hash((hash_type, hash, idx))) => {
                        if let Some(idx) = idx {
                            let (_, mut_ctx) = self
                                .files
                                .get_mut(idx)
                                .ok_or_else(|| anyhow!("FileContextHeader does not exist"))?;
                            match hash_type {
                                HashType::Sha256 => {
                                    let sha256_bytes: [u8; 32] = hash.try_into().map_err(|_| {
                                        anyhow!("Provided SHA256 has invalid length")
                                    })?;
                                    if let Some(Hashes {
                                        sha256: Some(hash), ..
                                    }) = mut_ctx.hashes
                                    {
                                        if hash != sha256_bytes {
                                            bail!("SHA256 hash mismatch");
                                        }
                                    } else if let Some(Hashes { sha256: None, md5 }) =
                                        mut_ctx.hashes
                                    {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: Some(sha256_bytes),
                                            md5,
                                        });
                                    } else {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: Some(sha256_bytes),
                                            md5: None,
                                        });
                                    }
                                }
                                HashType::Md5 => {
                                    let md5_bytes: [u8; 16] = hash
                                        .try_into()
                                        .map_err(|_| anyhow!("Provided MD5 has invalid length"))?;
                                    if let Some(Hashes {
                                        md5: Some(hash), ..
                                    }) = mut_ctx.hashes
                                    {
                                        if hash != md5_bytes {
                                            bail!("SHA256 hash mismatch");
                                        }
                                    } else if let Some(Hashes { md5: None, sha256 }) =
                                        mut_ctx.hashes
                                    {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256,
                                            md5: Some(md5_bytes),
                                        });
                                    } else {
                                        mut_ctx.hashes = Some(Hashes {
                                            sha256: None,
                                            md5: Some(md5_bytes),
                                        });
                                    }
                                }
                                HashType::Other(_) => {
                                    bail!("Other hashes currently not supported")
                                }
                            };
                        }
                    }
                    Ok(Message::WriterKey(key)) => {
                        self.writer_private_key = Some(key.as_slice().try_into()?)
                    }
                    Ok(_) => {}
                    Err(TryRecvError::Empty) => {
                        break;
                    }
                    Err(TryRecvError::Closed) => {
                        error!("Message receiver closed");
                        return Err(anyhow!("Message receiver closed"));
                    }
                }
            }
        }
        Ok(false)
    }
}

#[async_trait::async_trait]
impl Transformer for FooterGenerator {
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::FooterGenerator, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        // Update overall hash & size counter
        self.hasher.update(buf.as_ref());
        self.counter += buf.len() as u64;
        match self.process_messages() {
            Ok(finished) => {
                if finished && !self.finished {
                    let mut eof_meta = EndOfFileMetadata::new();

                    // Prepare TableOfContents
                    let mut toc = TableOfContents::new();
                    for (key, dir_ctx) in self.directories.clone() {
                        let mut variant = DirContextVariants::DirDecrypted(dir_ctx);
                        variant.encrypt(&key)?;
                        toc.directories.push(variant)
                    }
                    let mut offset = 0;
                    for (key, mut file_ctx) in self.files.clone() {
                        offset += file_ctx.update_range(offset);
                        let mut variant = FileContextVariants::FileDecrypted(file_ctx);
                        variant.encrypt(&key)?;
                        toc.files.push(variant);
                    }
                    let mut toc_bytes = borsh::to_vec(&toc)?;
                    eof_meta.toc_len = toc_bytes.len() as u64;

                    self.counter += toc_bytes.len() as u64;

                    // Inject TableOfContents bytes length into serialized TableOfContents
                    LittleEndian::write_u32_into(
                        &[(toc_bytes.len() - 8).try_into()?],
                        &mut toc_bytes[4..8],
                    );

                    // Update full file hash and write TableOfContents
                    self.hasher.update(toc_bytes.as_slice());
                    buf.put(toc_bytes.as_slice());

                    // Write Encryption Metadata
                    let enc_meta = EncryptionMetadata::try_from((
                        self.writer_private_key,
                        &self.encryption_keys,
                    ))?;
                    let enc_meta_bytes = borsh::to_vec(&enc_meta)?;
                    eof_meta.encryption_len = enc_meta_bytes.len() as u64;
                    self.counter += enc_meta_bytes.len() as u64;
                    self.hasher.update(enc_meta_bytes.as_slice());
                    buf.put(enc_meta_bytes.as_slice());

                    // Write EndOfFileMetadata
                    eof_meta.raw_file_size = self.raw_counter;
                    self.counter += 73;
                    eof_meta.disk_file_size = self.counter;
                    let mut eof_meta_bytes = borsh::to_vec(&eof_meta)?;
                    self.hasher.update(eof_meta_bytes.as_slice());
                    eof_meta.disk_hash_sha256 = self.hasher.finalize_reset().into();
                    eof_meta_bytes = borsh::to_vec(&eof_meta)?;
                    buf.put(eof_meta_bytes.as_slice());

                    if let Some(notifier) = &self.notifier {
                        notifier.send_next(
                            self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                            Message::Finished,
                        )?;
                    }
                    self.finished = true;
                }
            }
            Err(err) => {
                return Err(anyhow!(
                    "[FooterGenerator] Error processing messages: {}",
                    err
                ))
            }
        }
        Ok(())
    }

    #[tracing::instrument(level = "trace", skip(self, notifier))]
    #[inline]
    async fn set_notifier(&mut self, notifier: Arc<Notifier>) -> Result<()> {
        self.notifier = Some(notifier);
        Ok(())
    }
}

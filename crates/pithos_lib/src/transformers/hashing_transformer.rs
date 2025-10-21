use crate::helpers::notifications::{HashType, Message, Notifier};
use crate::transformer::{Transformer, TransformerType};
use anyhow::anyhow;
use anyhow::Result;
use async_channel::{Receiver, Sender, TryRecvError};
use digest::{Digest, FixedOutputReset};
use std::collections::VecDeque;
use std::sync::Arc;
use tracing::error;

pub struct HashingTransformer<T: Digest + Send + FixedOutputReset> {
    idx: Option<usize>,
    hasher: T,
    hasher_type: String,
    counter: u64,
    file_queue: Option<VecDeque<(usize, u64)>>,
    msg_receiver: Option<Receiver<Message>>,
    notifier: Option<Arc<Notifier>>,
    back_channel: Option<Sender<String>>,
    finished: bool,
}

impl<T> HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(hasher))]
    #[allow(dead_code)]
    pub fn new(hasher: T, hasher_type: String, file_specific: bool) -> HashingTransformer<T> {
        let (file_queue, counter) = if file_specific {
            (Some(VecDeque::new()), 0)
        } else {
            (None, u64::MAX)
        };

        HashingTransformer {
            idx: None,
            hasher,
            hasher_type,
            counter,
            file_queue,
            msg_receiver: None,
            notifier: None,
            back_channel: None,
            finished: false,
        }
    }

    #[tracing::instrument(level = "trace", skip(hasher))]
    #[allow(dead_code)]
    pub fn new_with_backchannel(
        hasher: T,
        hasher_type: String,
    ) -> (HashingTransformer<T>, Receiver<String>) {
        let (sx, rx) = async_channel::bounded(1);

        (
            HashingTransformer {
                idx: None,
                hasher,
                hasher_type,
                counter: u64::MAX,
                file_queue: None,
                msg_receiver: None,
                notifier: None,
                back_channel: Some(sx),
                finished: false,
            },
            rx,
        )
    }

    #[tracing::instrument(level = "trace", skip(self))]
    fn process_messages(&mut self) -> Result<(bool, bool)> {
        if let Some(rx) = &self.msg_receiver {
            loop {
                match rx.try_recv() {
                    Ok(Message::Finished) => {
                        return Ok((true, false));
                    }
                    Ok(Message::ShouldFlush) => return Ok((false, true)),
                    Ok(Message::FileContext(ctx)) => {
                        if !ctx.is_dir && ctx.symlink_target.is_none() {
                            if let Some(queue) = self.file_queue.as_mut() {
                                queue.push_back((ctx.idx, ctx.decompressed_size));
                                if self.counter == 0 {
                                    self.counter = ctx.decompressed_size;
                                }
                            }
                        }
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
        Ok((false, false))
    }

    async fn next_file(&mut self, init_next: &[u8]) -> Result<()> {
        self.finished = false;
        if let Some(queue) = self.file_queue.as_mut() {
            if let Some((idx, _)) = queue.pop_front() {
                let finished_hash = self.hasher.finalize_reset().to_vec();
                let hashertype = match self.hasher_type.as_str() {
                    "sha256" => HashType::Sha256,
                    "md5" => HashType::Md5,
                    a => HashType::Other(a.to_string()),
                };
                if let Some(notifier) = &self.notifier {
                    notifier.send_all_type(
                        TransformerType::FooterGenerator,
                        Message::Hash((hashertype.clone(), finished_hash.clone(), Some(idx))),
                    )?;
                }
            }
            if let Some((_, size)) = queue.front() {
                self.counter = *size;
            }
            if !init_next.is_empty() {
                Digest::update(&mut self.hasher, init_next);
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<T> Transformer for HashingTransformer<T>
where
    T: Digest + Send + Sync + FixedOutputReset,
{
    #[tracing::instrument(level = "trace", skip(self))]
    async fn initialize(&mut self, idx: usize) -> (TransformerType, Sender<Message>) {
        self.idx = Some(idx);
        let (sx, rx) = async_channel::bounded(10);
        self.msg_receiver = Some(rx);
        (TransformerType::Hashing, sx)
    }

    #[tracing::instrument(level = "trace", skip(self, buf))]
    async fn process_bytes(&mut self, buf: &mut bytes::BytesMut) -> Result<()> {
        let Ok((finished, should_flush)) = self.process_messages() else {
            return Err(anyhow!("[HashingTransformer] Error processing messages"));
        };
        self.counter -= buf.len() as u64;
        if self.counter == 0 {
            let to_keep = buf.len() + self.counter as usize;
            Digest::update(&mut self.hasher, buf.get(0..to_keep).unwrap_or_default());
            self.next_file(buf.get(to_keep..).unwrap_or_default())
                .await?;
        } else {
            Digest::update(&mut self.hasher, &buf);
        }

        if finished || should_flush {
            if let Some(notifier) = self.notifier.clone() {
                if self.file_queue.is_some() && self.back_channel.is_none() {
                    self.next_file(&[]).await?;
                } else if finished {
                    if !self.finished {
                        let finished_hash = self.hasher.finalize_reset().to_vec();
                        let hashertype = match self.hasher_type.as_str() {
                            "sha256" => HashType::Sha256,
                            "md5" => HashType::Md5,
                            a => HashType::Other(a.to_string()),
                        };
                        notifier.send_all_type(
                            TransformerType::FooterGenerator,
                            Message::Hash((hashertype.clone(), finished_hash.clone(), None)),
                        )?;

                        if let Some(sx) = &self.back_channel {
                            sx.try_send(hex::encode(finished_hash))?;
                        }
                        self.finished = true;
                    }
                    notifier.send_next(
                        self.idx.ok_or_else(|| anyhow!("Missing idx"))?,
                        Message::Finished,
                    )?;
                }
                //notifier.send_read_writer(Message::Hash((hashertype, finished_hash)))?; // No need to send out anymore?
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

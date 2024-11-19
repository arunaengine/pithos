use crate::helpers::structs::FileContext;
use crate::transformer::TransformerType;
use async_channel::Sender;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::sync::RwLock;

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum HashType {
    Sha256,
    Md5,
    Other(String),
}

#[derive(Clone, Debug)]
pub struct CompressionInfo {
    pub idx: usize,
    pub raw_size: u64,
    pub compressed_size: u64,
    pub compression: bool,
    pub chunk_infos: Option<Vec<u32>>,
}

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Hash, BorshDeserialize, BorshSerialize, Serialize, Deserialize, PartialOrd, Ord,
)]
pub enum DirOrFileIdx {
    Dir(usize),
    File(usize),
}

impl DirOrFileIdx {
    pub fn get_idx(&self) -> usize {
        match self {
            Self::Dir(idx) => *idx,
            Self::File(idx) => *idx,
        }
    }
}

impl From<&FileContext> for DirOrFileIdx {
    fn from(value: &FileContext) -> Self {
        if value.is_dir {
            Self::Dir(value.idx)
        } else {
            Self::File(value.idx)
        }
    }
}

#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Message {
    Completed,
    Finished,
    FileContext(FileContext),
    Hash((HashType, Vec<u8>, Option<usize>)), // HashType, Hash, Optional idx of file
    WriterKey(Vec<u8>),
    SizeInfo(u64),
    CompressionInfo(CompressionInfo),
    EditList(Vec<u64>),
    ShouldFlush,
    Skip,
    Custom((String, Vec<u8>)),
}

#[derive(Debug)]
pub struct Notifier {
    read_writer: Sender<Message>,
    notifiers: RwLock<Vec<(TransformerType, Sender<Message>)>>,
}

impl Notifier {
    pub fn new(read_writer: Sender<Message>) -> Self {
        Self {
            read_writer,
            notifiers: RwLock::new(Vec::new()),
        }
    }

    pub fn add_transformer(&self, trans: (TransformerType, Sender<Message>)) {
        self.notifiers.write().unwrap().push(trans);
    }

    #[tracing::instrument(err)]
    pub fn send_next(&self, idx: usize, message: Message) -> anyhow::Result<()> {
        if idx + 1 < self.notifiers.read().unwrap().len() {
            self.notifiers.read().unwrap()[idx + 1]
                .1
                .try_send(message)?;
        }
        Ok(())
    }

    #[tracing::instrument(err)]
    pub fn send_first(&self, message: Message) -> anyhow::Result<()> {
        if let Some((_, sender)) = self.notifiers.read().unwrap().first() {
            sender.try_send(message)?;
        }
        Ok(())
    }

    #[tracing::instrument(err)]
    pub fn send_next_type(
        &self,
        idx: usize,
        trans_type: TransformerType,
        message: Message,
    ) -> anyhow::Result<()> {
        for (trans, sender) in self.notifiers.read().unwrap()[idx..]
            .iter()
            .chain(self.notifiers.read().unwrap().iter())
        {
            if trans == &trans_type {
                sender.try_send(message)?;
                break;
            }
        }
        Ok(())
    }

    #[tracing::instrument(err)]
    pub fn send_all_type(
        &self,
        trans_type: TransformerType,
        message: Message,
    ) -> anyhow::Result<()> {
        for (trans, sender) in self.notifiers.read().unwrap().iter() {
            if trans == &trans_type {
                sender.try_send(message.clone())?;
            }
        }
        Ok(())
    }

    #[tracing::instrument(err)]
    pub fn send_all(&self, message: Message) -> anyhow::Result<()> {
        for (_, sender) in self.notifiers.read().unwrap().iter() {
            sender.try_send(message.clone())?;
        }
        Ok(())
    }

    #[tracing::instrument(err)]
    pub fn send_read_writer(&self, message: Message) -> anyhow::Result<()> {
        self.read_writer.try_send(message)?;
        Ok(())
    }
}
